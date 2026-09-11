"""Curated Loop (RYL / ryl_beta) tools for the unified multi-DB router.

WHY THESE ARE ROUTER-LOCAL AND NOT `domain`-ROUTED
--------------------------------------------------
The `loop` domain is a *proxy*: the router forwards a tool NAME to a
`topmate-postgres-mcp` sidecar pinned on ryl-beta-host, and the sidecar's own
code executes it. So a new `@mcp.tool` that took `domain='loop'` would proxy a
name the pinned sidecar has never heard of and fail until that image is rebuilt
and re-rolled over SSM (scripts/provision_loop_domain.sh).

These tools instead COMPOSE SQL here and send it to the sidecar as
`execute_sql`, which the sidecar already has. The sidecar's local pool *is*
ryl_beta, so no `domain` needs to travel with it. Net effect: the tools work the
moment the router rolls, with zero sidecar change. That is the whole reason this
module builds SQL strings rather than declaring domain-aware tools.

CONSEQUENCE: SQL IS ASSEMBLED AS TEXT, SO EVERY INTERPOLATION IS VALIDATED
--------------------------------------------------------------------------
`execute_sql` takes a string, so there is no bind-parameter channel to the
sidecar. Every value that reaches a query goes through `uuid_arg`, `int_arg`,
`text_arg` or `enum_arg` below. Nothing else may be interpolated. `text_arg`
escapes quotes and backslashes and is only ever used inside a quoted literal.

SAFETY RULES THIS MODULE ENFORCES (a reviewer should hold it to these)
---------------------------------------------------------------------
1. Every tool that returns consumer PII takes a MANDATORY creator_id and filters
   on it. There is no per-tool scoping anywhere upstream in this repo -- any
   authenticated caller reaching the router gets full rows -- so the scope has to
   be in the query itself.
2. Every query carries a bounded LIMIT. Callers cannot raise it past the per-tool
   ceiling; `int_arg` clamps rather than trusting the input.
3. No query reads a column this domain has proven dead. See DEAD_COLUMNS.
4. "Engaged" has exactly ONE definition, ENGAGED_PRED, reused everywhere, and the
   tools state whether they are counting ROWS or PEOPLE.
5. Single statement, no semicolons: the proxy path runs readonly_guard first,
   which rejects multi-statement payloads and anything not starting with
   select/with. Avoid `substring(x from '...')` -- the guard's parser rejects the
   inner FROM.
"""

from __future__ import annotations

import re
import uuid as _uuid_mod

# Columns that exist, look authoritative, and are always the same value for a
# real creator. Reading any of these produces a confident wrong answer, which is
# the failure mode this domain has already shipped twice. Verified 2026-09-10
# against a live creator with 12 campaigns and 4,608 campaign_consumers rows.
DEAD_COLUMNS = {
    "campaign_consumers.interest_level": "'unknown' on 4608/4608 rows. Nobody is ever 'interested' by this column. Use reply sentiment + counters.",
    "campaign_consumers.engagement_score": "0.0 on 4608/4608 rows. Never populated. Rank on the counters instead.",
    "consumers.whatsapp": "NULL on all 6374 of this creator's consumers even though 111 people replied over WhatsApp. Use consumers.phone.",
    "campaign_consumers.meetings_booked": "Set to 1 for 126 people while the meetings table held 0 rows for that creator "
    "and only 4 conversions were paid. Not evidence of a meeting; surfaced as a flag, never as a tier.",
    "campaigns.total_messages_opened / total_messages_clicked / credit_spend": "0 across all 2293 campaigns DB-wide.",
    "campaigns.leads_converted": "Summed to 9 for a creator with 4 real payments. Recount from campaign_conversions with counts_as_booking.",
}

# ONE definition, reused by every tool. Person-level: aggregate per consumer_id
# first, then apply. `last_engaged_at` is included because 1465 rows carry it,
# but it is backfill-contaminated (58 people have it with no open/click/reply),
# so it only ever qualifies someone as COOL, never higher.
ENGAGED_PRED = "(o > 0 OR k > 0 OR r > 0 OR b > 0 OR le IS NOT NULL)"

# Suppression stack. The obvious fields (consumers.unsubscribed_at /
# archived_at / campaign_consumers.status) flagged only 6 people for a creator
# who had 66 real unsubscribes recorded in email_suppressions, so the
# suppression tables are the authoritative source and must be joined.
_SUPPRESSED_PRED = """(
    cn.unsubscribed_at IS NOT NULL
 OR cn.archived_at IS NOT NULL
 OR EXISTS (SELECT 1 FROM email_suppressions es
             WHERE lower(es.email) = lower(cn.email)
               AND (es.expires_at IS NULL OR es.expires_at > now()))
 OR EXISTS (SELECT 1 FROM do_not_call d
             WHERE d.creator_id = '{cid}'
               AND (d.consumer_id = a.consumer_id
                    OR d.phone_digits = regexp_replace(coalesce(cn.phone, ''), '\\D', '', 'g')))
)"""

_UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


class LoopArgError(ValueError):
    """Raised for an argument that must never reach a composed SQL string."""


def uuid_arg(value: str, field: str) -> str:
    """Return `value` only if it is a real UUID. This is the injection boundary."""
    v = (value or "").strip()
    if not _UUID_RE.match(v):
        raise LoopArgError(f"{field} must be a UUID, got {len(v)} chars")
    try:
        _uuid_mod.UUID(v)
    except Exception as exc:
        raise LoopArgError(f"{field} is not a valid UUID") from exc
    return v


def int_arg(value: int | None, default: int, maximum: int) -> int:
    """Clamp into [1, maximum] rather than trusting the caller.

    An unbounded `limit` is not a bound: loop_engaged_audience can return name,
    email and phone for >1,200 people, so the ceiling is enforced here and the
    caller cannot raise it.
    """
    try:
        n = int(default if value is None else value)
    except (TypeError, ValueError):
        n = default
    return max(1, min(n, maximum))


def text_arg(value: str, field: str, maxlen: int = 200) -> str:
    """Escape for use INSIDE a single-quoted SQL literal. Never use bare."""
    v = (value or "").strip()
    if not v:
        raise LoopArgError(f"{field} must not be empty")
    if len(v) > maxlen:
        raise LoopArgError(f"{field} must be <= {maxlen} chars")
    if "\x00" in v:
        raise LoopArgError(f"{field} contains a null byte")
    return v.replace("\\", "\\\\").replace("'", "''")


def enum_arg(value: str, allowed: set[str], field: str) -> str:
    v = (value or "").strip().lower()
    if v not in allowed:
        raise LoopArgError(f"{field} must be one of {sorted(allowed)}")
    return v


def _campaign_filter(campaign_id: str | None) -> str:
    """Optional extra scope INSIDE the mandatory creator scope, never instead of it."""
    if not campaign_id:
        return ""
    return f" AND c.id = '{uuid_arg(campaign_id, 'campaign_id')}'"


# --------------------------------------------------------------------------
# Reusable CTEs. Person-level aggregation happens ONCE, here, so no tool can
# accidentally count enrolment ROWS as PEOPLE. For one live creator that is the
# difference between 4,608 and 3,293.
# --------------------------------------------------------------------------
def _base_ctes(cid: str, campaign_id: str | None = None) -> str:
    cf = _campaign_filter(campaign_id)
    return f"""
WITH agg AS (
  SELECT cc.consumer_id,
         sum(cc.emails_sent) AS sent, sum(cc.emails_opened) AS o, sum(cc.emails_clicked) AS k,
         sum(cc.replies_received) AS r, sum(cc.meetings_booked) AS b,
         max(cc.last_engaged_at) AS le, count(*) AS ncamp,
         bool_or(c.name LIKE 'Live Projects%') AS lpb,
         bool_or(c.name LIKE 'Job Placement%') AS jpm
  FROM campaign_consumers cc
  JOIN campaigns c ON c.id = cc.campaign_id
  WHERE c.creator_id = '{cid}'{cf}
  GROUP BY 1
),
sent AS (
  SELECT ce.consumer_id,
         bool_or(ce.sentiment = 'positive') AS pos,
         bool_or(ce.sentiment = 'neutral')  AS neu,
         bool_or(ce.sentiment = 'negative') AS neg
  FROM campaign_events ce
  JOIN campaigns c ON c.id = ce.campaign_id
  WHERE c.creator_id = '{cid}'{cf} AND ce.event_type = 'reply_received'
  GROUP BY 1
),
paid AS (
  SELECT DISTINCT consumer_id FROM campaign_conversions
  WHERE creator_id = '{cid}' AND counts_as_booking
)"""


# `tier` is computed in exactly one place. meetings_booked is deliberately NOT a
# tier input (see DEAD_COLUMNS); it rides along as a flag so a caller can see it
# without being misled by it.
_TIER_EXPR = """CASE
    WHEN p.consumer_id IS NOT NULL OR coalesce(s.pos, false) THEN 'HOT'
    WHEN a.k > 0 OR coalesce(s.neu, false)                   THEN 'WARM'
    WHEN a.o > 0 OR a.le IS NOT NULL                         THEN 'COOL'
    ELSE 'NONE'
  END"""

_SENTIMENT_EXPR = """CASE
    WHEN coalesce(s.pos, false) THEN 'positive'
    WHEN coalesce(s.neg, false) AND coalesce(s.neu, false) THEN 'mixed'
    WHEN coalesce(s.neg, false) THEN 'negative'
    WHEN coalesce(s.neu, false) THEN 'neutral'
    ELSE ''
  END"""

# A negative-only replier is someone who pushed back and never showed positive
# intent and never paid. They are engaged but must not appear in an outreach list.
_NEG_ONLY = "(coalesce(s.neg, false) AND NOT coalesce(s.pos, false) AND p.consumer_id IS NULL)"


def find_creator_sql(topmate_user_id: int | None, email: str | None, name: str | None, limit: int) -> str:
    """Resolve a human identifier to a Loop creator UUID.

    Honours the LOOP-371 split-brain: `creators.topmate_user_id` (bigint) and
    `creators.settings->>'topmate_user_id'` (JSON) can disagree after the
    backfill, so BOTH are checked plus creator_topmate_aliases, and the
    disagreement is surfaced as `split_brain` rather than silently picking one.
    """
    where: list[str] = []
    if topmate_user_id is not None:
        tid = int(topmate_user_id)
        where.append(f"cr.topmate_user_id = {tid}")
        where.append(f"cr.settings->>'topmate_user_id' = '{tid}'")
        where.append(f"cr.id IN (SELECT creator_id FROM creator_topmate_aliases WHERE topmate_user_id = {tid})")
    if email:
        where.append(f"lower(cr.email) = lower('{text_arg(email, 'email')}')")
    if name:
        where.append(f"cr.name ILIKE '%{text_arg(name, 'name')}%'")
    if not where:
        raise LoopArgError("pass at least one of topmate_user_id, email, name")
    return f"""
SELECT cr.id AS creator_id, cr.name, cr.email, cr.phone,
       cr.topmate_user_id,
       cr.settings->>'topmate_user_id' AS topmate_user_id_json,
       (cr.topmate_user_id IS NOT NULL
        AND cr.settings->>'topmate_user_id' IS NOT NULL
        AND cr.topmate_user_id::text <> cr.settings->>'topmate_user_id') AS split_brain,
       cr.plan_tier, cr.status, cr.banned_at, cr.created_at,
       (SELECT count(*) FROM campaigns c WHERE c.creator_id = cr.id) AS campaigns
FROM creators cr
WHERE ({" OR ".join(where)})
ORDER BY cr.created_at DESC
LIMIT {int_arg(limit, 25, 100)}"""


def creator_overview_sql(creator_id: str) -> str:
    """One row. Column names state their unit (ROWS vs PEOPLE) on purpose."""
    cid = uuid_arg(creator_id, "creator_id")
    return f"""{_base_ctes(cid)}
SELECT
  (SELECT count(*) FROM campaigns WHERE creator_id = '{cid}')                        AS campaigns,
  (SELECT count(*) FROM campaigns WHERE creator_id = '{cid}' AND status = 'active')  AS campaigns_active,
  (SELECT count(*) FROM campaigns WHERE creator_id = '{cid}' AND auto_paused_at IS NOT NULL) AS campaigns_auto_paused,
  (SELECT count(*) FROM agg)                                                         AS enrolled_PEOPLE,
  (SELECT sum(ncamp) FROM agg)                                                       AS enrolment_ROWS,
  (SELECT count(*) FROM agg WHERE sent > 0)                                          AS contacted_PEOPLE,
  (SELECT count(*) FROM agg a WHERE {ENGAGED_PRED})                                  AS engaged_PEOPLE,
  (SELECT count(*) FROM agg WHERE o > 0)                                             AS opened_PEOPLE,
  (SELECT count(*) FROM agg WHERE k > 0)                                             AS clicked_PEOPLE,
  (SELECT count(*) FROM agg WHERE r > 0)                                             AS replied_PEOPLE,
  (SELECT count(*) FROM paid)                                                        AS paid_PEOPLE,
  (SELECT coalesce(sum(price), 0) FROM campaign_conversions
     WHERE creator_id = '{cid}' AND counts_as_booking)                               AS paid_revenue,
  (SELECT count(*) FROM campaign_conversions WHERE creator_id = '{cid}')             AS conversion_rows_incl_FAILED,
  (SELECT coalesce(sum(price), 0) FROM campaign_conversions WHERE creator_id = '{cid}') AS revenue_if_unfiltered_DO_NOT_QUOTE,
  (SELECT coalesce(sum(leads_converted), 0) FROM campaigns WHERE creator_id = '{cid}') AS campaigns_leads_converted_MIRROR_OVERSTATES,
  (SELECT coalesce(-sum(credits), 0) FROM creator_credit_transactions
     WHERE creator_id = '{cid}' AND credits < 0)                                     AS credits_burned_GROSS,
  (SELECT coalesce(-sum(credits), 0) FROM creator_credit_transactions
     WHERE creator_id = '{cid}')                                                     AS credits_net_of_grants,
  (SELECT count(*) FROM escalations WHERE creator_id = '{cid}' AND resolved_at IS NULL) AS escalations_open
LIMIT 1"""


def campaigns_sql(creator_id: str, limit: int) -> str:
    cid = uuid_arg(creator_id, "creator_id")
    return f"""
SELECT c.id AS campaign_id, c.name, c.status, c.campaign_type, c.channels::text AS channels,
       c.total_leads, c.leads_contacted, c.total_messages_sent, c.total_replies,
       c.leads_engaged AS leads_engaged_MIRROR, c.leads_converted AS leads_converted_MIRROR,
       (SELECT count(*) FROM campaign_conversions cv
          WHERE cv.campaign_id = c.id AND cv.counts_as_booking)   AS paid_ACTUAL,
       c.auto_paused_at, c.auto_paused_reason,
       c.created_at, c.started_at, c.completed_at
FROM campaigns c
WHERE c.creator_id = '{cid}'
ORDER BY c.created_at
LIMIT {int_arg(limit, 100, 500)}"""


def campaign_funnel_sql(creator_id: str, campaign_id: str | None) -> str:
    """Person-level funnel. Counts PEOPLE at every stage, never enrolment rows."""
    cid = uuid_arg(creator_id, "creator_id")
    return f"""{_base_ctes(cid, campaign_id)}
SELECT count(*)                                             AS enrolled_PEOPLE,
       count(*) FILTER (WHERE a.sent > 0)                   AS contacted,
       count(*) FILTER (WHERE a.o > 0)                      AS opened,
       count(*) FILTER (WHERE a.k > 0)                      AS clicked,
       count(*) FILTER (WHERE a.r > 0)                      AS replied,
       count(*) FILTER (WHERE coalesce(s.pos, false))        AS replied_positive,
       count(*) FILTER (WHERE coalesce(s.neu, false))        AS replied_neutral,
       count(*) FILTER (WHERE coalesce(s.neg, false))        AS replied_negative,
       count(*) FILTER (WHERE a.b > 0)                      AS booking_flag_UNVERIFIED,
       count(*) FILTER (WHERE p.consumer_id IS NOT NULL)     AS paid,
       count(*) FILTER (WHERE {_TIER_EXPR} = 'HOT')          AS tier_hot,
       count(*) FILTER (WHERE {_TIER_EXPR} = 'WARM')         AS tier_warm,
       count(*) FILTER (WHERE {_TIER_EXPR} = 'COOL')         AS tier_cool
FROM agg a
LEFT JOIN sent s ON s.consumer_id = a.consumer_id
LEFT JOIN paid p ON p.consumer_id = a.consumer_id
LIMIT 1"""


def engaged_audience_sql(
    creator_id: str,
    tier: str | None,
    campaign_id: str | None,
    include_suppressed: bool,
    limit: int,
    after_id: str | None,
) -> str:
    """The outreach list: one row per PERSON with contact details.

    Bounded, creator-scoped, keyset-paginated on consumer_id (stable across
    pages, unlike OFFSET over a non-unique sort -- OFFSET paging over this set
    returned a duplicate boundary row in testing).

    `include_suppressed=False` (the default) removes anyone on an active email
    suppression, on this creator's do_not_call list, unsubscribed, archived, or
    whose only reply was negative. For one live creator that is 118 + 1 + 43
    people the obvious columns alone would have missed.
    """
    cid = uuid_arg(creator_id, "creator_id")
    clauses = [ENGAGED_PRED]
    if tier:
        t = enum_arg(tier, {"hot", "warm", "cool", "interested"}, "tier").upper()
        clauses.append(f"{_TIER_EXPR} IN ('HOT', 'WARM')" if t == "INTERESTED" else f"{_TIER_EXPR} = '{t}'")
    if not include_suppressed:
        clauses.append(f"NOT {_SUPPRESSED_PRED.format(cid=cid)}")
        clauses.append(f"NOT {_NEG_ONLY}")
    if after_id:
        clauses.append(f"cn.id > '{uuid_arg(after_id, 'after_id')}'")
    return f"""{_base_ctes(cid, campaign_id)}
SELECT cn.id AS consumer_id, cn.name, cn.email, cn.phone,
       {_TIER_EXPR} AS tier,
       {_SENTIMENT_EXPR} AS reply_sentiment,
       (p.consumer_id IS NOT NULL) AS paid,
       a.o AS opens, a.k AS clicks, a.r AS replies,
       a.b AS booking_flag_UNVERIFIED, a.ncamp AS campaigns,
       CASE WHEN a.lpb AND a.jpm THEN 'both' WHEN a.lpb THEN 'LiveProjects'
            WHEN a.jpm THEN 'JobPlacement' ELSE 'other' END AS program,
       a.le AS last_engaged_at, cn.title, cn.company, cn.location
FROM agg a
JOIN consumers cn ON cn.id = a.consumer_id
LEFT JOIN sent s ON s.consumer_id = a.consumer_id
LEFT JOIN paid p ON p.consumer_id = a.consumer_id
WHERE {" AND ".join(clauses)}
ORDER BY cn.id
LIMIT {int_arg(limit, 100, 500)}"""


def replies_sql(creator_id: str, campaign_id: str | None, sentiment: str | None, limit: int) -> str:
    """Actual reply text. The sentiment LABEL is unreliable -- read the text.

    Live counter-examples for one creator: an obscene personal attack was
    labelled 'neutral' because a later message said "Tell me more", and an
    insurance-company auto-responder was labelled 'positive'.
    """
    cid = uuid_arg(creator_id, "creator_id")
    extra = ""
    if sentiment:
        extra = f" AND ce.sentiment = '{enum_arg(sentiment, {'positive', 'neutral', 'negative'}, 'sentiment')}'"
    return f"""
SELECT cn.name, cn.email, cn.phone, ce.channel, ce.sentiment AS sentiment_UNRELIABLE,
       ce.timestamp AS replied_at, c.name AS campaign,
       left(regexp_replace(coalesce(ce.reply_content, ''), '\\s+', ' ', 'g'), 400) AS reply_text
FROM campaign_events ce
JOIN campaigns c  ON c.id = ce.campaign_id
JOIN consumers cn ON cn.id = ce.consumer_id
WHERE c.creator_id = '{cid}'{_campaign_filter(campaign_id)}
  AND ce.event_type = 'reply_received'{extra}
ORDER BY ce.timestamp DESC
LIMIT {int_arg(limit, 100, 500)}"""


def conversion_evidence_sql(creator_id: str) -> str:
    """Per-conversion attribution evidence, not just a count.

    Every conversion this domain records is `attributed_via='identity'` (matched
    on email/phone), which credits any purchase by a campaign member whether or
    not the campaign caused it. The independent corroboration is a click on a
    Loop-generated short_link whose target service matches the service bought,
    so this returns both and lets the reader judge. `booked_expert_id` is NULL on
    every row -- Loop never records which expert received the booking -- so the
    link target is also returned as the only in-domain evidence of routing.
    """
    cid = uuid_arg(creator_id, "creator_id")
    return f"""
SELECT cn.name, cn.email, cv.price, cv.currency,
       cv.service_id AS paid_service_id, cv.service_title,
       cv.stage, cv.source_status, cv.counts_as_booking,
       cv.attributed_via, cv.attributed_channel, cv.on_pitch,
       cv.booked_at, c.name AS attributed_campaign,
       cv.booked_expert_id AS booked_expert_id_ALWAYS_NULL,
       (SELECT count(*) FROM short_links sl
          WHERE sl.consumer_id = cv.consumer_id AND sl.link_type = 'cta' AND sl.click_count > 0) AS cta_links_clicked,
       (SELECT coalesce(sum(sl.click_count), 0) FROM short_links sl
          WHERE sl.consumer_id = cv.consumer_id AND sl.link_type = 'cta')                        AS cta_clicks_total,
       (SELECT string_agg(DISTINCT split_part(split_part(sl.target_url, 'cloud/', 2), '?', 1), ',')
          FROM short_links sl
          WHERE sl.consumer_id = cv.consumer_id AND sl.link_type = 'cta' AND sl.click_count > 0) AS clicked_service_paths,
       (SELECT count(*) FROM messages m
          JOIN conversations cvs ON cvs.id = m.conversation_id
          WHERE cvs.consumer_id = cv.consumer_id AND m.sender IN ('human', 'user'))              AS inbound_messages
FROM campaign_conversions cv
JOIN consumers cn ON cn.id = cv.consumer_id
LEFT JOIN campaigns c ON c.id = cv.campaign_id
WHERE cv.creator_id = '{cid}'
ORDER BY cv.counts_as_booking DESC, cv.booked_at
LIMIT 200"""


def deliverability_sql(creator_id: str, campaign_id: str | None, days: int) -> str:
    """Send outcomes with deferrals separated from real drops.

    A deferral is a retry, not a failure. Lumping them together made a throttled
    campaign read as broken: 2,461 of 3,056 non-sent rows for one creator were
    deferrals.
    """
    cid = uuid_arg(creator_id, "creator_id")
    d = int_arg(days, 30, 365)
    cf = f" AND sa.campaign_id = '{uuid_arg(campaign_id, 'campaign_id')}'" if campaign_id else ""
    return f"""
SELECT sa.channel,
       CASE sa.outcome WHEN 'defer' THEN 'RETRY (not a failure)'
                       WHEN 'drop'  THEN 'HARD DROP'
                       WHEN 'sent'  THEN 'SENT'
                       ELSE sa.outcome END AS outcome_class,
       sa.outcome, coalesce(sa.reason, '-') AS reason,
       count(*) AS attempts, count(DISTINCT sa.consumer_id) AS people,
       max(sa.attempted_at) AS last_at
FROM send_attempts sa
WHERE sa.creator_id = '{cid}'{cf}
  AND sa.attempted_at >= now() - interval '{d} days'
GROUP BY 1, 2, 3, 4
ORDER BY (sa.outcome = 'drop') DESC, count(*) DESC
LIMIT 200"""


def suppressions_sql(creator_id: str, limit: int) -> str:
    """Who among this creator's audience is suppressed, and why.

    `paused` is read as a boolean, not as a row count: counting rows in
    creator_outbound_pause reports a creator who was paused and later resumed as
    still paused.
    """
    cid = uuid_arg(creator_id, "creator_id")
    return f"""
SELECT cn.name, cn.email, cn.phone,
       es.reason AS email_suppression_reason, es.source AS email_suppression_source,
       es.first_seen_at AS suppressed_at, es.expires_at,
       (d.consumer_id IS NOT NULL OR d.phone_digits IS NOT NULL) AS on_do_not_call,
       d.reason AS do_not_call_reason,
       cn.unsubscribed_at, cn.archived_at, cn.email_status
FROM consumers cn
LEFT JOIN email_suppressions es
       ON lower(es.email) = lower(cn.email)
      AND (es.expires_at IS NULL OR es.expires_at > now())
LEFT JOIN do_not_call d
       ON d.creator_id = '{cid}'
      AND (d.consumer_id = cn.id
           OR d.phone_digits = regexp_replace(coalesce(cn.phone, ''), '\\D', '', 'g'))
WHERE cn.creator_id = '{cid}'
  AND (es.email IS NOT NULL OR d.id IS NOT NULL OR cn.unsubscribed_at IS NOT NULL OR cn.archived_at IS NOT NULL)
ORDER BY es.first_seen_at DESC NULLS LAST
LIMIT {int_arg(limit, 100, 500)}"""


def credits_sql(creator_id: str) -> str:
    """Gross burn and net separately. `credits_burned` alone is gross, not net."""
    cid = uuid_arg(creator_id, "creator_id")
    return f"""
SELECT b.balance, b.plan_tier AS plan_tier_AUTHORITATIVE,
       (SELECT coalesce(-sum(credits), 0) FROM creator_credit_transactions
          WHERE creator_id = '{cid}' AND credits < 0)   AS burned_GROSS,
       (SELECT coalesce(sum(credits), 0) FROM creator_credit_transactions
          WHERE creator_id = '{cid}' AND credits > 0)   AS granted_and_refunded,
       (SELECT coalesce(-sum(credits), 0) FROM creator_credit_transactions
          WHERE creator_id = '{cid}')                   AS net,
       (SELECT count(*) FILTER (WHERE paused) FROM creator_outbound_pause
          WHERE creator_id = '{cid}')                   AS currently_paused,
       (SELECT count(*) FROM creator_outbound_pause
          WHERE creator_id = '{cid}')                   AS pause_config_rows
FROM creator_credit_balances b
WHERE b.creator_id = '{cid}'
LIMIT 10"""


def conversation_thread_sql(creator_id: str, consumer_id: str, limit: int) -> str:
    """Full two-way thread for ONE consumer, scoped to the creator who owns them."""
    cid = uuid_arg(creator_id, "creator_id")
    sid = uuid_arg(consumer_id, "consumer_id")
    return f"""
SELECT cn.name, m.channel, m.sender, m.sender_name, m.created_at,
       left(regexp_replace(coalesce(m.text, ''), '\\s+', ' ', 'g'), 1000) AS message
FROM messages m
JOIN conversations cvs ON cvs.id = m.conversation_id
JOIN consumers cn      ON cn.id = cvs.consumer_id
WHERE cvs.consumer_id = '{sid}'
  AND cvs.creator_id = '{cid}'
  AND cn.creator_id = '{cid}'
ORDER BY m.created_at
LIMIT {int_arg(limit, 100, 400)}"""


def sequence_dropoff_sql(creator_id: str, campaign_id: str | None) -> str:
    """Where people stall in the follow-up sequence."""
    cid = uuid_arg(creator_id, "creator_id")
    return f"""
SELECT cc.current_sequence_step AS step,
       count(*) AS at_step,
       count(*) FILTER (WHERE cc.emails_opened > 0)    AS opened,
       count(*) FILTER (WHERE cc.emails_clicked > 0)   AS clicked,
       count(*) FILTER (WHERE cc.replies_received > 0) AS replied,
       count(*) FILTER (WHERE cc.status <> 'enrolled') AS exited,
       count(*) FILTER (WHERE cc.emails_bounced > 0)   AS bounced
FROM campaign_consumers cc
JOIN campaigns c ON c.id = cc.campaign_id
WHERE c.creator_id = '{cid}'{_campaign_filter(campaign_id)}
GROUP BY 1
ORDER BY 1
LIMIT 100"""


def lead_lists_sql(creator_id: str, limit: int) -> str:
    cid = uuid_arg(creator_id, "creator_id")
    return f"""
SELECT ll.id AS lead_list_id, ll.name, ll.created_at,
       (SELECT count(*) FROM lead_list_members m WHERE m.lead_list_id = ll.id) AS members
FROM lead_lists ll
WHERE ll.creator_id = '{cid}'
ORDER BY ll.created_at DESC
LIMIT {int_arg(limit, 100, 500)}"""


def lead_state_sql(creator_id: str, campaign_id: str | None) -> str:
    """Aggregate over lead_state.funnel_stage.

    This is the live replacement for `consumers.consumer_stage`, which is a
    constant for a real creator and therefore useless as a segment.
    """
    cid = uuid_arg(creator_id, "creator_id")
    cf = f" AND ls.campaign_id = '{uuid_arg(campaign_id, 'campaign_id')}'" if campaign_id else ""
    return f"""
SELECT coalesce(ls.funnel_stage, '(none)') AS funnel_stage, ls.status,
       count(*) AS rows_at_stage, count(DISTINCT ls.consumer_id) AS people,
       max(ls.funnel_stage_at) AS last_at
FROM lead_state ls
WHERE ls.creator_id = '{cid}'{cf}
GROUP BY 1, 2
ORDER BY count(*) DESC
LIMIT 200"""


# --------------------------------------------------------------------------
# Curated prose. Router-local on purpose: the loop sidecar runs this same image,
# so proxying a guide tool would return the SIDECAR's pinned copy of this text
# labelled as authoritative. Prose has no dependency on which DB is queried.
# --------------------------------------------------------------------------
LOOP_CAMPAIGN_PLAYBOOK = {
    "database": "ryl_beta (RYL/Loop outbound engine, AWS RDS ap-south-1, reached via the loop-mcp sidecar)",
    "start_here": "Resolve a person to a Loop creator UUID with loop_find_creator. Every other Loop tool requires that UUID and is scoped to it.",
    "tool_map": {
        "loop_find_creator": "human identifier -> Loop creator UUID (handles the LOOP-371 split-brain)",
        "loop_creator_overview": "one-row health check: campaigns, people, engaged, paid, revenue, credits, escalations",
        "loop_campaigns": "campaign roster with real paid counts beside the mirror counters",
        "loop_campaign_funnel": "enrolled -> contacted -> opened -> clicked -> replied -> paid, counted in PEOPLE",
        "loop_engaged_audience": "the outreach list with contact details, suppression-filtered and tiered",
        "loop_replies": "actual reply text; read this rather than trusting the sentiment label",
        "loop_conversion_evidence": "per-conversion attribution evidence, including tracked-link clicks",
        "loop_deliverability": "send outcomes with deferrals separated from hard drops",
        "loop_suppressions": "who is suppressed and why",
        "loop_credits": "balance, gross burn, net",
        "loop_conversation_thread": "full two-way thread for one consumer",
        "loop_sequence_dropoff": "where people stall in the follow-up sequence",
        "loop_lead_lists": "lead lists and their sizes",
        "loop_lead_state": "funnel_stage aggregate (use instead of consumers.consumer_stage)",
    },
    "tiers": {
        "HOT": "paid a booking that counts, or replied with positive sentiment",
        "WARM": "clicked a link, or replied with neutral sentiment",
        "COOL": "opened only",
        "excluded_from_outreach": "suppressed, on do_not_call, unsubscribed, archived, or whose only reply was negative",
    },
    "dead_columns_do_not_read": DEAD_COLUMNS,
    "gotchas": [
        "Count PEOPLE, not enrolment rows. One creator's 4,608 campaign_consumers rows were 3,293 distinct people; "
        "1,294 of them were in more than one campaign.",
        "campaign_conversions is mostly failures. Always filter counts_as_booking. Unfiltered price summed to 484,979 "
        "against 104,996 real, because 17 of 21 rows were payment_failed and 11 came from one buyer retrying.",
        "Attribution is identity-matched, not click-matched. Every conversion carries attributed_via='identity', so it "
        "credits any purchase by a campaign member. Corroborate with a short_links CTA click whose target service "
        "matches the service actually bought.",
        "booked_expert_id is NULL on every conversion row. Loop does not record which expert received the booking; "
        "the short_link target path is the only in-domain signal of routing.",
        "The sentiment label is unreliable in both directions. Verified: an obscene personal attack labelled 'neutral', "
        "and a business auto-responder labelled 'positive'. Read reply_text before contacting anyone.",
        "Suppression lives in email_suppressions and do_not_call, not in consumers.unsubscribed_at. For one creator the "
        "obvious columns flagged 6 people against 66 real unsubscribes.",
        "A 'clicked' signal can be an unsubscribe click. There are zero open/click rows in campaign_events, so "
        "emails_clicked has no link provenance; treat click-only as WARM at best.",
        "Deferrals are retries, not failures. Splitting them out turned an apparent 3,056-failure campaign into 595 real hard drops.",
        "campaigns.leads_engaged and leads_converted are app-maintained mirrors and drift. One creator's "
        "leads_converted summed to 9 against 4 real payments. Recount from campaign_conversions.",
    ],
}
