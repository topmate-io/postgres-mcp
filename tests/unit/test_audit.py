"""Tests for AuditLogMiddleware (LOOP-664 M1).

Contract: one JSON line per non-health request with person, client_ip, path,
rpc_method, tool, arg KEYS (never values), status, duration_ms, request_id.
"""

import json

import pytest

from postgres_mcp.audit import AUDIT_MAX_BODY
from postgres_mcp.audit import AuditLogMiddleware
from postgres_mcp.audit import _parse_jsonrpc
from postgres_mcp.person_auth import current_person


def test_parse_jsonrpc_tools_call():
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "execute_sql", "arguments": {"sql": "SELECT 1", "row_limit": 10}},
        }
    ).encode()
    method, tool, arg_keys = _parse_jsonrpc(body)
    assert method == "tools/call"
    assert tool == "execute_sql"
    assert arg_keys == ["row_limit", "sql"]


def test_parse_jsonrpc_non_json_is_safe():
    assert _parse_jsonrpc(b"\x00\xffnot json") == ("", "", [])
    assert _parse_jsonrpc(b"") == ("", "", [])
    assert _parse_jsonrpc(b"[1,2,3]") == ("", "", [])


class _Inner:
    async def __call__(self, scope, receive, send):
        # Drain the (replayed) body exactly like a real ASGI app would
        while True:
            message = await receive()
            if message["type"] != "http.request" or not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})


def _scope(body_len, path="/postgres-mcp/mcp", method="POST"):
    return {
        "type": "http",
        "path": path,
        "method": method,
        "client": ("10.0.0.9", 4242),
        "headers": [(b"content-length", str(body_len).encode())],
    }


async def _run(mw, scope, body=b""):
    sent = {"body": False}
    delivered = []

    async def send(message):
        delivered.append(message)

    async def receive():
        if not sent["body"]:
            sent["body"] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    await mw(scope, receive, send)
    return delivered


def _audit_lines(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "postgres_mcp.audit"]


@pytest.mark.asyncio
async def test_emits_one_audit_line_with_tool_and_person(caplog):
    caplog.set_level("INFO", logger="postgres_mcp.audit")
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "list_schemas", "arguments": {"secret_arg": "SENSITIVE-VALUE"}},
        }
    ).encode()
    mw = AuditLogMiddleware(_Inner(), get_request_id=lambda: "req-123")
    tok = current_person.set("dharsan")
    try:
        delivered = await _run(mw, _scope(len(body)), body)
    finally:
        current_person.reset(tok)

    lines = _audit_lines(caplog)
    assert len(lines) == 1
    line = lines[0]
    assert line["person"] == "dharsan"
    assert line["tool"] == "list_schemas"
    assert line["rpc_method"] == "tools/call"
    assert line["arg_keys"] == ["secret_arg"]
    assert line["status"] == 200
    assert line["request_id"] == "req-123"
    assert line["client_ip"] == "10.0.0.9"
    assert "duration_ms" in line
    # Redaction: the VALUE must never appear anywhere in the line
    assert "SENSITIVE-VALUE" not in json.dumps(line)
    # The inner app still received and answered the request
    assert delivered[0]["status"] == 200


@pytest.mark.asyncio
async def test_oversized_body_passes_through_without_parse(caplog):
    caplog.set_level("INFO", logger="postgres_mcp.audit")
    mw = AuditLogMiddleware(_Inner(), get_request_id=lambda: "req-big")
    delivered = await _run(mw, _scope(AUDIT_MAX_BODY + 1), b"x")
    lines = _audit_lines(caplog)
    assert len(lines) == 1
    assert lines[0]["tool"] == ""
    assert delivered[0]["status"] == 200


@pytest.mark.asyncio
async def test_health_paths_not_audited(caplog):
    caplog.set_level("INFO", logger="postgres_mcp.audit")
    mw = AuditLogMiddleware(_Inner(), get_request_id=lambda: "req-h")
    await _run(mw, _scope(0, path="/postgres-mcp/health", method="GET"))
    assert _audit_lines(caplog) == []
