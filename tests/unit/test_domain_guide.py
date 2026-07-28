from postgres_mcp.domain_guide import MULTI_DOMAIN_GUIDE
from postgres_mcp.domain_guide import ROUTING_TABLE
from postgres_mcp.domain_guide import build_schema_guide


def test_guide_has_all_v1_domains():
    for d in ("tm", "igdm", "fin_ledger", "fin_payment", "fin_payout"):
        assert d in MULTI_DOMAIN_GUIDE


def test_every_guide_domain_has_a_routing_line():
    # build_schema_guide filters routing and domains independently, so a domain
    # present in one but not the other silently ships a half-documented entry.
    assert set(MULTI_DOMAIN_GUIDE) == set(ROUTING_TABLE)


def test_loop_domain_is_documented():
    loop = MULTI_DOMAIN_GUIDE["loop"]
    assert loop["database"] == "ryl_beta"
    assert "creator_credit_balances" in loop["key_tables"]


def test_loop_guide_leads_with_the_rls_zero_warning():
    # ryl_beta gates 25 of 131 tables behind tenant-isolation RLS keyed on
    # current_setting('app.creator_id'). The domain only reads them because
    # mcp_readonly holds BYPASSRLS -- if that attribute is ever lost, those tables
    # return an EMPTY SUCCESS rather than an error, which is how a real 4847-row
    # table reported "paying_creators: 0" on 2026-07-28. This must stay the FIRST
    # gotcha, and must name the cross-check that catches it.
    first = MULTI_DOMAIN_GUIDE["loop"]["gotchas"][0].lower()
    assert "app.creator_id" in first
    assert "bypassrls" in first
    assert "n_live_tup" in first


def test_loop_guide_marks_tenant_gated_tables():
    # A model must be able to see at a glance which tables depend on BYPASSRLS,
    # since those are exactly the ones that fail silently rather than loudly.
    kt = MULTI_DOMAIN_GUIDE["loop"]["key_tables"]
    for gated in ("creator_credit_balances", "creator_credit_transactions", "consumers", "campaigns"):
        assert kt[gated].startswith("[T]"), gated
    assert not kt["creators"].startswith("[T]")


def test_loop_guide_pins_the_paying_creator_source():
    blob = str(MULTI_DOMAIN_GUIDE["loop"]["gotchas"]).lower()
    assert "creator_credit_balances.plan_tier not in ('free','trial')" in blob
    # Enumerating paid tiers silently drops the 2 creators still on legacy 'starter'.
    assert "starter" in blob


def test_loop_guide_warns_that_balances_and_gateway_mirror_disagree():
    # Reaching for kelviq_subscription_mirror to answer "who is paying" understates
    # it ~4x (57 vs 234). The guide must say which one is authoritative.
    blob = str(MULTI_DOMAIN_GUIDE["loop"]["gotchas"]).lower()
    assert "kelviq_subscription_mirror" in blob
    assert "disappeared_at" in blob


def test_loop_guide_warns_about_the_dead_loops_table():
    blob = str(MULTI_DOMAIN_GUIDE["loop"]["gotchas"])
    assert "escalations.loop_id" in blob and "campaigns.id" in blob


def test_build_filters_to_enabled_and_includes_routing_table():
    guide = build_schema_guide(["tm", "igdm"])
    assert "routing" in guide
    assert set(guide["domains"].keys()) == {"tm", "igdm"}
    # igdm business-logic gotcha is carried
    assert "user_id" in str(guide["domains"]["igdm"]).lower()
