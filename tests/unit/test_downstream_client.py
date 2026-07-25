# tests/unit/test_downstream_client.py
import pytest

from postgres_mcp import downstream_client as dc


class _FakeClient:
    def __init__(self, *a, **k):
        self.calls = []
        self.closed = False

    async def call_tool(self, tool_name, arguments=None):
        self.calls.append((tool_name, arguments))
        return '[{"n": 1}]'

    async def disconnect(self):
        self.closed = True


@pytest.mark.asyncio
async def test_cache_returns_same_client_per_domain(monkeypatch):
    monkeypatch.setattr(dc, "DownstreamMCPClient", _FakeClient)
    import json

    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "true")
    monkeypatch.setenv("SVC_INTERNAL_MCP_TOKEN", "t")
    monkeypatch.setenv(
        "DOMAIN_REGISTRY_JSON",
        json.dumps({"igdm": {"base_url": "http://ig:8000", "token_env": "SVC_INTERNAL_MCP_TOKEN", "database": "instagram_auto_dm"}}),
    )
    dc.domain_registry.reload_registry()
    await dc.close_all_clients()

    c1 = await dc.get_downstream_client("igdm")
    c2 = await dc.get_downstream_client("igdm")
    assert c1 is c2
    out = await c1.call_tool("execute_sql", {"sql": "select 1"})
    assert out == '[{"n": 1}]'
    await dc.close_all_clients()
    assert c1.closed is True
