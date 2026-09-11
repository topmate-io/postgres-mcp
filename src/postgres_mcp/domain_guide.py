"""Curated per-domain schema + business-logic guide (LOOP-664 M3, spec §6)."""

from __future__ import annotations

ROUTING_TABLE = {
    "tm": "Topmate core: bookings, users, GMV, expert earnings.",
    "igdm": "Instagram Auto-DM V2: connections, automations, DM sequences/logs, subscriptions.",
    "fin_ledger": "Finance ledger: accounts, ledger_entries, holds, v1_snapshots, reconciliation.",
    "fin_payment": "Finance payments: payment_intents, subscriptions, settlements, v2_user_cutover.",
    "fin_payout": "Finance payouts: withdrawal_requests, bank_accounts, tds, fraud/KYC checks.",
    "loop": "RYL/Loop agents platform: creators, campaigns, leads/consumers, credit billing, conversations/escalations.",
}

MULTI_DOMAIN_GUIDE = {
    "tm": {
        "database": "topmate_db_prod",
        "purpose": "Topmate core monolith.",
        "gotchas": [
            "all_bookings_new (matview) uses created_time/expert_earning/book_currency; booking_booking uses created/expert_earnings/currency.",
            "Use get_topmate_schema_guide for full tm detail.",
        ],
    },
    "igdm": {
        "database": "instagram_auto_dm",
        "purpose": "Live Instagram Auto-DM V2 (~5.5k connections, ~8.1k automations).",
        "key_tables": {
            "instagram_connections": "root entity; join key user_id (String) — NOT deprecated topmate_user_id",
            "automations": "unified rule/sequence (is_active = rule on)",
            "dm_sequences": "per-(automation,user) funnel: opening->follow_gate->email->final->followup",
            "dm_logs": "outbound DM attempts",
            "instagram_subscriptions": "billing mirror; status='active' = paying (can drift from transactions-v2)",
            "agent_runs": "agentic path (when connections.ryl_brain_enabled=true)",
        },
        "gotchas": [
            "'active' is three things: connections.status='connected' (OAuth) != automations.is_active != subscription 'active'.",
            "brain vs rule are mutually exclusive per connection; brain-enabled -> look in agent_runs, not dm_sequences.",
            "ConnectionStatus: connected|disconnected|expired|error.",
        ],
    },
    "fin_ledger": {
        "database": "ledger_db",
        "purpose": "Double-entry ledger.",
        "key_tables": {
            "accounts": "available = balance - hold_amount; balance is denormalized (never SUM ledger_entries)",
            "ledger_entries": "immutable double-entry rows",
            "holds": "active->released|expired",
            "v1_snapshots": "frozen V1 cutover snapshot; expert_id is Integer",
        },
        "gotchas": [
            "Money is NUMERIC(20,6) MAJOR units (rupees/dollars), NOT paise.",
            "Negative balance is legitimate for account_type='gateway_settlement' and refund/reversal sources.",
        ],
    },
    "fin_payment": {
        "database": "payment_db",
        "purpose": "Payment orchestration + V1->V2 cutover state.",
        "key_tables": {
            "payment_intents": "PaymentState: pending|processing|paid|failed|cancelled|refunded|...",
            "v2_user_cutover": "per-user routing; expert_id Integer; check enabled/status/phase*",
            "subscriptions": "subscription lifecycle",
        },
        "gotchas": [
            "Lifetime earnings = v1_snapshots.v1_lifetime_earnings (frozen, ledger_db) + post-cutover ledger entries.",
            "shadow_* tables are parallel-run validation, NOT live routing state.",
        ],
    },
    "fin_payout": {
        "database": "payout_db",
        "purpose": "Withdrawals, bank accounts, TDS, fraud/KYC.",
        "key_tables": {
            "withdrawal_requests": "WithdrawalState: pending->verifying->approved|rejected|manual_review->processing->completed->reversed",
            "bank_accounts": "*_enc columns are AES ciphertext (unreadable); *_last4 are safe",
            "tds_records": "Section 194-O withholding",
            "verification_records": "KYC/Didit; decision_data is sensitive JSONB",
        },
        "gotchas": [
            "user_id/expert_id type drift: String(64) most tables, Integer in v1_snapshots/v2_user_cutover, UUID in suspicious_activity_reports.",
        ],
    },
    "loop": {
        "database": "ryl_beta",
        "purpose": "RYL (Loop) outbound-agent platform: creator accounts, lead/consumer CRM, campaigns, conversations, credit billing.",
        # [T] = tenant-isolation RLS; readable only because mcp_readonly has BYPASSRLS.
        "key_tables": {
            "creator_credit_balances": "[T] canonical billing state, PK=creator_id; plan_tier here is authoritative",
            "creator_credit_transactions": "[T] append-only credit ledger; cancellation is a new row, never a mutation",
            "creators": "tenant/account row; plan_tier is a stale mirror; status is moderation, not billing",
            "kelviq_subscription_mirror": "gateway-side snapshot; drifts from creator_credit_balances, see gotchas",
            "consumers": "[T] lead/contact per creator; lead_status (funnel) vs email_status (deliverability)",
            "campaigns": "[T] the live campaign entity; carries denormalized funnel counters",
            "campaign_consumers": "[T] per-lead enrollment + engagement counters; PARTITION BY HASH(campaign_id)",
            "campaign_events": "[T] per-campaign interaction log; PARTITION BY RANGE(timestamp)",
            "conversations": "[T] channel-agnostic header (creator_id, consumer_id, channel, held_by)",
            "conversation_events": "[T] canonical append-only timeline; messages is a projection of it",
            "messages": "[T] in/outbound rows; campaign_id is a write-time attribution snapshot",
            "escalations": "creator attention queue: hand_raise|reply_awaiting|vip_signal|stalled",
        },
        "gotchas": [
            "A ZERO FROM A [T] TABLE MEANS BROKEN AUTH, NOT NO DATA. 25 of 131 tables carry tenant-isolation RLS keyed on current_setting('app.creator_id'); this domain reads them only because mcp_readonly holds BYPASSRLS. Any session without it (a fresh role, a psql window, a rebuilt role) matches zero rows and returns an EMPTY SUCCESS, never an error. If a [T] table reports 0, verify with pg_stat_user_tables.n_live_tup before reporting the number — on 2026-07-28 this silently turned 4847 paying-tier rows into a confident 'paying_creators: 0'.",
            "Paying creators = creator_credit_balances.plan_tier NOT IN ('free','trial'); PK is creator_id so COUNT(*) is already distinct. creators.plan_tier is a mirror that flaps stale for hours after a plan change — never count off it.",
            "Exclude tiers by name, never enumerate paid ones. Vocab changed twice (legacy starter/growth/business -> free/basic/pro/enterprise) and old strings survive: as of 2026-07-28 the live mix is free 4613, basic 143, pro 89, and 2 stragglers still on 'starter' that a basic|pro whitelist would drop. Note plan_tier='trial' is a legacy pre-Kelviq free tier, NOT mid-paid-trial — a real trial keeps its paid tier plus trial_started_at/trial_expires_at.",
            "creator_credit_balances and kelviq_subscription_mirror disagree by design and by a lot (234 paying tiers vs 57 'active' gateway rows on 2026-07-28). balances is the entitlement Loop actually enforces; the mirror is a gateway snapshot whose creator_id is NULL on ~96% of rows (customer_id has three shapes: ryl_<uuid> legacy, tm_<topmate_user_id> canonical, tm_<uuid> mis-minted 2026-07-10). Use balances for 'who is paying'; use the mirror only for gateway state, count its rows rather than COUNT(DISTINCT creator_id), and read disappeared_at (not status) as the cancellation signal.",
            "creator_credit_transactions is append-only (Postgres RULEs block UPDATE/DELETE); cancellation is a new type='plan_cancellation' row. Grant types multiplied (plan_grant/plan_activation_grant/plan_renewal_grant/...) to dodge uniq_plan_grant_per_month — filtering type='plan_grant' alone undercounts.",
            "escalations.loop_id FKs to campaigns.id, NOT loops.id. `loops` is a parallel dead schema with zero API references; joining loop_id -> loops.id silently returns nothing.",
            "tm join key: creators.topmate_user_id (BigInteger) and creators.settings->>'topmate_user_id' (JSON) can disagree (LOOP-371 split-brain backfill). Read the column first, fall back to the JSON key — never one source alone.",
            "Archived creators are not a flag: their email is rewritten to '%@deleted.local'. That is independent of creators.status (active|banned|suspended), so a live-creator filter needs BOTH email NOT LIKE '%@deleted.local' AND a status check.",
            "Denormalized counters (campaigns.total_leads, campaign_consumers.emails_sent, consumers.total_spend, ...) are app-maintained running totals — re-summing campaign_events against them double-counts. Moot while those tables are RLS-gated.",
            "For campaigns and engagement, call get_loop_campaign_guide and prefer the loop_* tools over hand-written SQL. "
            "They carry the tier definitions, the suppression stack, and the columns that are always the same value and "
            "must not be read: campaign_consumers.interest_level and engagement_score are constant on every row, and "
            "meetings_booked is set without a matching meeting. That list lives in ONE place, loop_tools.DEAD_COLUMNS, "
            "so it is not restated here and cannot drift from it.",
        ],
    },
}

CROSS_DOMAIN_NOTE = (
    "fin_ledger/fin_payment/fin_payout, igdm and loop are separate RDS instances — no SQL joins "
    "across them. To correlate one creator, run one execute_sql per domain and stitch on "
    "user_id/expert_id in-model, minding the String/Integer/UUID type drift. loop is keyed by its "
    "own creator UUID; bridge to tm via creators.topmate_user_id."
)


def build_schema_guide(enabled_domains: list[str]) -> dict:
    domains = {d: MULTI_DOMAIN_GUIDE[d] for d in enabled_domains if d in MULTI_DOMAIN_GUIDE}
    routing = {d: ROUTING_TABLE[d] for d in enabled_domains if d in ROUTING_TABLE}
    # The cross-domain "no SQL joins across RDS instances" caveat only makes sense when more
    # than one domain is reachable; when only tm is enabled it's noise, so drop it.
    cross_domain = CROSS_DOMAIN_NOTE if len(enabled_domains) > 1 else ""
    return {"routing": routing, "cross_domain": cross_domain, "domains": domains}
