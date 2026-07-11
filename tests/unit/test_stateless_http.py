"""S1: postgres-mcp FastMCP is stateless_http so /mcp can run multiple replicas."""

import asyncio

import httpx
import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from postgres_mcp.server import build_dual_transport_router
from postgres_mcp.server import mcp


def test_stateless_http_enabled():
    assert mcp.settings.stateless_http is True
    assert mcp.settings.json_response is True


@pytest.mark.asyncio
async def test_streamable_http_mcp_endpoint_initializes_after_lifespan():
    """LOOP-511 regression: a POST to /mcp must not 500 with
    'Task group is not initialized'.

    The dual-transport router dispatches to FastMCP's streamable_http_app per
    request, which bypasses that app's own lifespan, so the router itself must
    start the Streamable-HTTP session manager on the ASGI lifespan. Before the
    fix this test fails (the request 500s); after it, /mcp initialize returns 200.
    """
    server = FastMCP("test-dual-transport", stateless_http=True, json_response=True)
    # Mirror prod: disable the DNS-rebinding host check so the ASGI test client's
    # Host header ("test") isn't rejected with 421.
    server.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)

    @server.tool()
    def ping() -> str:
        return "pong"

    app = build_dual_transport_router(server)

    # Drive the ASGI lifespan in the background so session_manager.run() stays
    # entered (its task group must be live for the duration of the request).
    to_app: asyncio.Queue = asyncio.Queue()
    from_app: list = []

    async def receive():
        return await to_app.get()

    async def send(message):
        from_app.append(message)

    lifespan_task = asyncio.create_task(app({"type": "lifespan"}, receive, send))
    await to_app.put({"type": "lifespan.startup"})
    for _ in range(500):
        if any(m["type"] == "lifespan.startup.complete" for m in from_app):
            break
        await asyncio.sleep(0.01)
    assert any(m["type"] == "lifespan.startup.complete" for m in from_app), from_app

    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp",
                headers={"Accept": "application/json, text/event-stream"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "loop511-test", "version": "1.0"},
                    },
                },
            )
        assert resp.status_code == 200, resp.text
        assert "Task group is not initialized" not in resp.text
        assert '"serverInfo"' in resp.text  # a real initialize result came back
    finally:
        await to_app.put({"type": "lifespan.shutdown"})
        try:
            await asyncio.wait_for(lifespan_task, timeout=5)
        except Exception:
            lifespan_task.cancel()
