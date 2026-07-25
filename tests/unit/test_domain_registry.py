import json

import pytest

from postgres_mcp import domain_registry as dr


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("MULTI_DOMAIN_ENABLED", raising=False)
    monkeypatch.delenv("DOMAIN_REGISTRY_JSON", raising=False)
    monkeypatch.setenv("SVC_INTERNAL_MCP_TOKEN", "svc-tok")
    dr.reload_registry()
    yield
    dr.reload_registry()


def test_flag_defaults_off_and_tm_is_always_local():
    dr.reload_registry()
    assert dr.multi_domain_enabled() is False
    tm = dr.get_domain("tm")
    assert tm.kind == "local"
    assert dr.list_domains() == ["tm"]  # no registry configured -> only tm


def test_registry_parses_proxy_domains_and_resolves_token(monkeypatch):
    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "true")
    monkeypatch.setenv(
        "DOMAIN_REGISTRY_JSON",
        json.dumps(
            {
                "igdm": {
                    "base_url": "http://instagram-mcp-service:8000",
                    "token_env": "SVC_INTERNAL_MCP_TOKEN",
                    "database": "instagram_auto_dm",
                }
            }
        ),
    )
    dr.reload_registry()
    assert dr.multi_domain_enabled() is True
    assert set(dr.list_domains()) == {"tm", "igdm"}
    igdm = dr.get_domain("igdm")
    assert igdm.kind == "proxy"
    assert igdm.base_url == "http://instagram-mcp-service:8000"
    assert igdm.token == "svc-tok"
    assert igdm.transport == "sse"


def test_unknown_domain_raises():
    dr.reload_registry()
    with pytest.raises(KeyError):
        dr.get_domain("nope")
