"""S1: postgres-mcp FastMCP is stateless_http so /mcp can run multiple replicas."""

from postgres_mcp.server import mcp


def test_stateless_http_enabled():
    assert mcp.settings.stateless_http is True
    assert mcp.settings.json_response is True
