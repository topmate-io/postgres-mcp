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
async def test_list_objects_proxies(monkeypatch):
    class _Client:
        async def call_tool(self, name, arguments=None):
            assert name == "list_objects"
            assert arguments == {"schema_name": "public", "object_type": "table"}
            return '["instagram_connections"]'

    async def _get_client(domain):
        return _Client()

    monkeypatch.setattr(downstream_client, "get_downstream_client", _get_client)
    resp = await server.list_objects(schema_name="public", object_type="table", domain="igdm")
    assert _text(resp) == '["instagram_connections"]'


@pytest.mark.asyncio
async def test_unknown_domain_lists_valid():
    resp = await server.list_objects(schema_name="public", object_type="table", domain="bogus")
    txt = _text(resp)
    assert "bogus" in txt
    assert "tm" in txt
