from postgres_mcp.domain_guide import MULTI_DOMAIN_GUIDE
from postgres_mcp.domain_guide import build_schema_guide


def test_guide_has_all_v1_domains():
    for d in ("tm", "igdm", "fin_ledger", "fin_payment", "fin_payout"):
        assert d in MULTI_DOMAIN_GUIDE


def test_build_filters_to_enabled_and_includes_routing_table():
    guide = build_schema_guide(["tm", "igdm"])
    assert "routing" in guide
    assert set(guide["domains"].keys()) == {"tm", "igdm"}
    # igdm business-logic gotcha is carried
    assert "user_id" in str(guide["domains"]["igdm"]).lower()
