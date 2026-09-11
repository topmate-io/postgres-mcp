"""The curated Loop tools compose SQL as TEXT, so these tests guard the seams.

`execute_sql` on the loop sidecar takes a string, which means there is no
bind-parameter channel and every interpolated value is a potential injection
site. The first group of tests pins that boundary. The rest pin the three things
this domain has actually got wrong in production: reading a column that is always
the same value, counting enrolment rows as if they were people, and handing back
contact details for people who had already opted out.
"""

import json

import pytest

from postgres_mcp import domain_registry
from postgres_mcp import downstream_client
from postgres_mcp import loop_tools
from postgres_mcp import readonly_guard
from postgres_mcp import server

CID = "11111111-2222-3333-4444-555555555555"
CAMPAIGN = "66666666-7777-8888-9999-aaaaaaaaaaaa"
CONSUMER = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"


def _text(resp):
    return "".join(getattr(c, "text", "") for c in resp)


def _all_sql():
    """Every SQL a tool can emit, named, so a failure says which builder broke."""
    return {
        "find_creator_tmid": loop_tools.find_creator_sql(42261, None, None, 25),
        "find_creator_email": loop_tools.find_creator_sql(None, "a@b.com", None, 25),
        "find_creator_name": loop_tools.find_creator_sql(None, None, "Some Name", 25),
        "creator_overview": loop_tools.creator_overview_sql(CID),
        "campaigns": loop_tools.campaigns_sql(CID, 100),
        "funnel": loop_tools.campaign_funnel_sql(CID, None),
        "funnel_scoped": loop_tools.campaign_funnel_sql(CID, CAMPAIGN),
        "audience": loop_tools.engaged_audience_sql(CID, None, None, False, 100, None),
        "audience_hot": loop_tools.engaged_audience_sql(CID, "hot", CAMPAIGN, False, 10, CONSUMER),
        "audience_interested": loop_tools.engaged_audience_sql(CID, "interested", None, False, 10, None),
        "audience_incl_supp": loop_tools.engaged_audience_sql(CID, None, None, True, 10, None),
        "replies": loop_tools.replies_sql(CID, None, None, 100),
        "replies_pos": loop_tools.replies_sql(CID, CAMPAIGN, "positive", 10),
        "conversion_evidence": loop_tools.conversion_evidence_sql(CID),
        "deliverability": loop_tools.deliverability_sql(CID, None, 30),
        "suppressions": loop_tools.suppressions_sql(CID, 100),
        "credits": loop_tools.credits_sql(CID),
        "thread": loop_tools.conversation_thread_sql(CID, CONSUMER, 100),
        "sequence": loop_tools.sequence_dropoff_sql(CID, None),
        "lead_lists": loop_tools.lead_lists_sql(CID, 100),
        "lead_state": loop_tools.lead_state_sql(CID, None),
    }


# --------------------------------------------------------------------------
# Injection boundary
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad",
    [
        "' OR 1=1 --",
        f"{CID}' OR '1'='1",
        "; DROP TABLE consumers",
        f"{CID}; SELECT 1",
        "",
        "   ",
        "not-a-uuid",
        "11111111-2222-3333-4444-55555555555",  # one char short
        "11111111222233334444555555555555",  # right length, no dashes, not a UUID
    ],
)
def test_uuid_arg_refuses_anything_that_is_not_a_uuid(bad):
    with pytest.raises(loop_tools.LoopArgError):
        loop_tools.uuid_arg(bad, "creator_id")


def test_uuid_arg_accepts_a_real_uuid_and_returns_it_unchanged():
    assert loop_tools.uuid_arg(CID, "creator_id") == CID
    assert loop_tools.uuid_arg(f"  {CID}  ", "creator_id") == CID


def test_every_builder_refuses_a_non_uuid_creator_id():
    # The scope argument is the one an attacker would aim at, so no builder may
    # accept a creator_id it did not validate.
    for name, fn in [
        ("creator_overview", lambda c: loop_tools.creator_overview_sql(c)),
        ("campaigns", lambda c: loop_tools.campaigns_sql(c, 10)),
        ("funnel", lambda c: loop_tools.campaign_funnel_sql(c, None)),
        ("audience", lambda c: loop_tools.engaged_audience_sql(c, None, None, False, 10, None)),
        ("replies", lambda c: loop_tools.replies_sql(c, None, None, 10)),
        ("conversion_evidence", lambda c: loop_tools.conversion_evidence_sql(c)),
        ("deliverability", lambda c: loop_tools.deliverability_sql(c, None, 30)),
        ("suppressions", lambda c: loop_tools.suppressions_sql(c, 10)),
        ("credits", lambda c: loop_tools.credits_sql(c)),
        ("thread", lambda c: loop_tools.conversation_thread_sql(c, CONSUMER, 10)),
        ("sequence", lambda c: loop_tools.sequence_dropoff_sql(c, None)),
        ("lead_lists", lambda c: loop_tools.lead_lists_sql(c, 10)),
        ("lead_state", lambda c: loop_tools.lead_state_sql(c, None)),
    ]:
        with pytest.raises(loop_tools.LoopArgError, match="creator_id"):
            fn("' OR 1=1 --")
        assert name  # name is only for the failure message


def test_campaign_and_consumer_ids_are_validated_too():
    with pytest.raises(loop_tools.LoopArgError, match="campaign_id"):
        loop_tools.campaign_funnel_sql(CID, "'; DROP TABLE campaigns --")
    with pytest.raises(loop_tools.LoopArgError, match="consumer_id"):
        loop_tools.conversation_thread_sql(CID, "nope", 10)
    with pytest.raises(loop_tools.LoopArgError, match="after_id"):
        loop_tools.engaged_audience_sql(CID, None, None, False, 10, "nope")


def test_text_arg_escapes_the_quote_that_would_close_the_literal():
    assert loop_tools.text_arg("O'Brien", "name") == "O''Brien"
    assert loop_tools.text_arg("a\\b", "name") == "a\\\\b"
    with pytest.raises(loop_tools.LoopArgError):
        loop_tools.text_arg("", "name")
    with pytest.raises(loop_tools.LoopArgError):
        loop_tools.text_arg("x" * 500, "name")


def test_a_quoted_name_cannot_break_out_of_the_literal():
    sql = loop_tools.find_creator_sql(None, None, "O'Brien' OR '1'='1", 10)
    # The apostrophe is doubled, so the injected OR sits inside the string.
    assert "O''Brien'' OR ''1''=''1" in sql
    assert readonly_guard.is_read_only_sql(sql)


def test_enum_arg_rejects_unknown_values():
    with pytest.raises(loop_tools.LoopArgError):
        loop_tools.engaged_audience_sql(CID, "lukewarm", None, False, 10, None)
    with pytest.raises(loop_tools.LoopArgError):
        loop_tools.replies_sql(CID, None, "furious", 10)


def test_find_creator_requires_at_least_one_identifier():
    with pytest.raises(loop_tools.LoopArgError):
        loop_tools.find_creator_sql(None, None, None, 10)


# --------------------------------------------------------------------------
# Bounds
# --------------------------------------------------------------------------
def test_int_arg_clamps_instead_of_trusting_the_caller():
    assert loop_tools.int_arg(None, 50, 500) == 50
    assert loop_tools.int_arg(10, 50, 500) == 10
    assert loop_tools.int_arg(999999, 50, 500) == 500  # ceiling enforced
    assert loop_tools.int_arg(0, 50, 500) == 1  # floor enforced
    assert loop_tools.int_arg(-5, 50, 500) == 1
    assert loop_tools.int_arg("junk", 50, 500) == 50  # type: ignore[arg-type]


def test_every_query_is_bounded():
    for name, sql in _all_sql().items():
        assert "LIMIT" in sql.upper(), f"{name} has no LIMIT"


def test_audience_limit_cannot_be_raised_past_the_ceiling():
    sql = loop_tools.engaged_audience_sql(CID, None, None, False, 100000, None)
    assert "LIMIT 500" in sql


def test_deliverability_window_is_capped():
    assert "interval '365 days'" in loop_tools.deliverability_sql(CID, None, 99999)


# --------------------------------------------------------------------------
# readonly_guard compatibility. The proxy path runs this before forwarding, so a
# builder that emits something the guard rejects is dead on arrival in prod. It
# already bit us once: `substring(x from '...')` is refused because of the inner
# FROM, which is why the builders use split_part instead.
# --------------------------------------------------------------------------
def test_every_query_passes_the_readonly_guard():
    for name, sql in _all_sql().items():
        assert readonly_guard.is_read_only_sql(sql), f"{name} would be refused before it left the router"


def test_no_query_contains_a_statement_separator():
    for name, sql in _all_sql().items():
        assert ";" not in sql, f"{name} contains a semicolon; the guard rejects multi-statement payloads"


def test_no_query_uses_substring_from_which_the_guard_rejects():
    for name, sql in _all_sql().items():
        assert " from '" not in sql.lower().replace("\n", " "), f"{name} uses substring(x from ...)"


# --------------------------------------------------------------------------
# Creator scoping. No caller-level scoping exists upstream, so the query is the
# only thing standing between one authenticated caller and every creator's rows.
# --------------------------------------------------------------------------
def test_every_creator_scoped_query_actually_filters_on_the_creator():
    skip = {"find_creator_tmid", "find_creator_email", "find_creator_name"}
    for name, sql in _all_sql().items():
        if name in skip:
            continue
        assert f"'{CID}'" in sql, f"{name} does not filter on creator_id"


def test_thread_is_scoped_by_creator_as_well_as_consumer():
    # Passing someone else's consumer_id must not return their messages.
    sql = loop_tools.conversation_thread_sql(CID, CONSUMER, 10)
    assert f"cvs.creator_id = '{CID}'" in sql
    assert f"cn.creator_id = '{CID}'" in sql


# --------------------------------------------------------------------------
# Dead columns. Reading these produces a confident wrong answer, which is worse
# than an error, and is exactly how this domain has failed before.
# --------------------------------------------------------------------------
def test_no_query_reads_a_dead_column():
    banned = ["interest_level", "engagement_score", "cn.whatsapp", "consumer_stage"]
    for name, sql in _all_sql().items():
        for col in banned:
            assert col not in sql, f"{name} reads the dead column {col}"


def test_mirror_counters_are_labelled_where_they_are_surfaced():
    # campaigns.leads_converted summed to more than double the real payments, so
    # it may appear only under a name that says it is a mirror.
    sql = loop_tools.campaigns_sql(CID, 10)
    assert "leads_converted_MIRROR" in sql
    assert "paid_ACTUAL" in sql
    overview = loop_tools.creator_overview_sql(CID)
    assert "MIRROR_OVERSTATES" in overview
    assert "DO_NOT_QUOTE" in overview


def test_meetings_booked_is_never_a_tier_input():
    # It was set for 126 people while the meetings table was empty, so it is a
    # flag only. If it ever appears in the tier CASE, the HOT tier is wrong.
    assert "b > 0" not in loop_tools._TIER_EXPR
    assert "booking_flag_UNVERIFIED" in loop_tools.engaged_audience_sql(CID, None, None, False, 10, None)


def test_engaged_has_exactly_one_definition():
    # Three different "engaged" numbers for one creator is what this prevents.
    for sql in (loop_tools.creator_overview_sql(CID), loop_tools.engaged_audience_sql(CID, None, None, False, 10, None)):
        assert loop_tools.ENGAGED_PRED in sql


# --------------------------------------------------------------------------
# Suppression. The obvious columns under-report by an order of magnitude.
# --------------------------------------------------------------------------
def test_audience_excludes_suppressed_people_by_default():
    sql = loop_tools.engaged_audience_sql(CID, None, None, False, 10, None)
    assert "email_suppressions" in sql
    assert "do_not_call" in sql
    assert "unsubscribed_at IS NOT NULL" in sql
    assert "archived_at IS NOT NULL" in sql


def test_audience_drops_negative_only_repliers_by_default():
    sql = loop_tools.engaged_audience_sql(CID, None, None, False, 10, None)
    assert "NOT (coalesce(s.neg, false)" in sql


def test_include_suppressed_is_opt_in_and_lifts_the_filter():
    sql = loop_tools.engaged_audience_sql(CID, None, None, True, 10, None)
    assert "email_suppressions" not in sql


def test_audience_is_keyset_paginated_not_offset():
    sql = loop_tools.engaged_audience_sql(CID, None, None, False, 10, CONSUMER)
    assert f"cn.id > '{CONSUMER}'" in sql
    assert "ORDER BY cn.id" in sql
    assert "OFFSET" not in sql.upper()


def test_interested_tier_means_hot_plus_warm():
    sql = loop_tools.engaged_audience_sql(CID, "interested", None, False, 10, None)
    assert "IN ('HOT', 'WARM')" in sql


# --------------------------------------------------------------------------
# Routing: the tools must reach the loop sidecar, through the one choke point.
# --------------------------------------------------------------------------
@pytest.fixture
def _loop_registry(monkeypatch):
    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "true")
    monkeypatch.setenv("SVC_INTERNAL_MCP_TOKEN", "t")
    monkeypatch.setenv(
        "DOMAIN_REGISTRY_JSON",
        json.dumps({"loop": {"base_url": "http://loop:8000", "token_env": "SVC_INTERNAL_MCP_TOKEN", "database": "ryl_beta"}}),
    )
    domain_registry.reload_registry()
    yield
    domain_registry.reload_registry()


@pytest.mark.asyncio
async def test_loop_tool_forwards_to_the_loop_sidecar_as_execute_sql(monkeypatch, _loop_registry):
    seen = {}

    class _Client:
        async def call_tool(self, name, arguments=None):
            seen["tool"] = name
            seen["sql"] = (arguments or {}).get("sql", "")
            return '[{"campaigns": 12}]'

    async def _get_client(domain):
        seen["domain"] = domain
        return _Client()

    monkeypatch.setattr(downstream_client, "get_downstream_client", _get_client)
    resp = await server.loop_creator_overview(creator_id=CID)

    # The sidecar is asked for execute_sql, not for a tool name it lacks.
    assert seen["tool"] == "execute_sql"
    assert seen["domain"] == "loop"
    assert f"'{CID}'" in seen["sql"]
    # Downstream text passes through verbatim.
    assert '"campaigns": 12' in _text(resp)


@pytest.mark.asyncio
async def test_loop_tool_reports_a_bad_uuid_without_touching_the_downstream(monkeypatch, _loop_registry):
    async def _boom(domain):
        raise AssertionError("must not reach the downstream with an invalid argument")

    monkeypatch.setattr(downstream_client, "get_downstream_client", _boom)
    resp = await server.loop_creator_overview(creator_id="' OR 1=1 --")
    assert "must be a UUID" in _text(resp)


@pytest.mark.asyncio
async def test_loop_tool_says_so_when_multi_domain_is_disabled(monkeypatch):
    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "false")
    monkeypatch.delenv("DOMAIN_REGISTRY_JSON", raising=False)
    domain_registry.reload_registry()
    try:
        resp = await server.loop_creator_overview(creator_id=CID)
        assert "multi-domain routing is disabled" in _text(resp)
    finally:
        domain_registry.reload_registry()


@pytest.mark.asyncio
async def test_loop_tool_says_so_when_the_loop_domain_is_not_registered(monkeypatch):
    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "true")
    monkeypatch.setenv("DOMAIN_REGISTRY_JSON", json.dumps({}))
    domain_registry.reload_registry()
    try:
        resp = await server.loop_creator_overview(creator_id=CID)
        assert "unknown domain 'loop'" in _text(resp)
    finally:
        domain_registry.reload_registry()


@pytest.mark.asyncio
async def test_downstream_failure_text_stays_bounded(monkeypatch, _loop_registry):
    async def _get_client(domain):
        raise ConnectionError("postgresql://mcp_readonly:hunter2@10.20.3.4:5432/ryl_beta unreachable")

    monkeypatch.setattr(downstream_client, "get_downstream_client", _get_client)
    resp = await server.loop_engaged_audience(creator_id=CID)
    out = _text(resp)
    assert "ConnectionError" in out
    # The DSN in the exception must not survive.
    assert "hunter2" not in out
    assert "10.20.3.4" not in out


# --------------------------------------------------------------------------
# The guide is router-local prose, not a query.
# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_guide_is_served_locally_and_names_the_dead_columns(monkeypatch):
    async def _boom(domain):
        raise AssertionError("the guide must not be proxied to the sidecar")

    monkeypatch.setattr(downstream_client, "get_downstream_client", _boom)
    out = _text(await server.get_loop_campaign_guide())
    assert "interest_level" in out
    assert "engagement_score" in out
    assert "loop_engaged_audience" in out


def test_guide_documents_every_loop_tool_it_ships_with():
    from tests.unit.test_domain_coverage import LOOP_ONLY

    mapped = set(loop_tools.LOOP_CAMPAIGN_PLAYBOOK["tool_map"])
    assert mapped == LOOP_ONLY - {"get_loop_campaign_guide"}
