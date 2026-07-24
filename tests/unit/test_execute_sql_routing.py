import json

import pytest

from postgres_mcp import domain_registry
from postgres_mcp import downstream_client
from postgres_mcp import server


def _text(resp):
    return "".join(getattr(c, "text", "") for c in resp)


@pytest.fixture(autouse=True)
def _reg(monkeypatch):
    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "true")
    monkeypatch.setenv("SVC_INTERNAL_MCP_TOKEN", "t")
    monkeypatch.setenv(
        "DOMAIN_REGISTRY_JSON",
        json.dumps({"igdm": {"base_url": "http://ig:8000", "token_env": "SVC_INTERNAL_MCP_TOKEN", "database": "instagram_auto_dm"}}),
    )
    domain_registry.reload_registry()
    yield
    domain_registry.reload_registry()


@pytest.mark.asyncio
async def test_default_domain_uses_local_driver(monkeypatch):
    calls = {}

    class _Driver:
        async def execute_query(self, sql):
            calls["sql"] = sql

            class _R:
                cells = {"n": 1}

            return [_R()]

    async def _get_driver():
        return _Driver()

    monkeypatch.setattr(server, "get_sql_driver", _get_driver)
    resp = await server.execute_sql("select 1")  # no domain -> tm local
    assert calls["sql"] == "select 1"
    assert '"n": 1' in _text(resp) or "'n': 1" in _text(resp)


@pytest.mark.asyncio
async def test_proxy_domain_forwards_raw(monkeypatch):
    class _Client:
        async def call_tool(self, name, arguments=None):
            assert name == "execute_sql"
            return '[{"status": "connected", "c": 982}]'

    async def _get_client(domain):
        assert domain == "igdm"
        return _Client()

    monkeypatch.setattr(downstream_client, "get_downstream_client", _get_client)
    resp = await server.execute_sql("select status from instagram_connections", domain="igdm")
    assert _text(resp) == '[{"status": "connected", "c": 982}]'


@pytest.mark.asyncio
async def test_flag_off_rejects_non_tm(monkeypatch):
    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "false")
    domain_registry.reload_registry()
    resp = await server.execute_sql("select 1", domain="igdm")
    assert "multi-domain" in _text(resp).lower()


@pytest.mark.asyncio
async def test_proxy_non_select_rejected():
    resp = await server.execute_sql("update instagram_connections set x=1", domain="igdm")
    assert "read-only" in _text(resp).lower()


@pytest.mark.asyncio
async def test_unknown_domain_lists_valid():
    resp = await server.execute_sql("select 1", domain="bogus")
    assert "bogus" in _text(resp) and "tm" in _text(resp)
