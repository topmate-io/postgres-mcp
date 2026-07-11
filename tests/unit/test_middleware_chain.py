"""Integration tests for the composed perimeter middleware chain (LOOP-664 M1).

Each test builds the REAL chain via ``server.build_middleware_stack(...)`` — the
same function ``main()`` calls to wire up the production ASGI app — so a
regression in middleware ORDER (e.g. PersonAuth ending up after AuditLog, or
CallerIdentity ending up before PersonAuth) cannot slip past these tests the
way it could past unit tests that exercise each middleware in isolation.

Middlewares read their config from the environment at construction time, so
every test uses ``monkeypatch.setenv``/``delenv`` before calling
``build_middleware_stack`` (constructing a fresh chain per test).
"""

import hashlib
import json

import pytest

from postgres_mcp.server import build_middleware_stack


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class _Recorder:
    """Terminal ASGI app: records whether/how it was invoked."""

    def __init__(self):
        self.called = False

    async def __call__(self, scope, receive, send):
        self.called = True
        # Drain any buffered/replayed body messages exactly like a real ASGI
        # app would (AuditLogMiddleware replays a pre-read body).
        while True:
            message = await receive()
            if message["type"] != "http.request" or not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})


def _scope(method="GET", path="/postgres-mcp/health", headers=None, client_ip="10.0.0.7"):
    return {
        "type": "http",
        "method": method,
        "path": path,
        "client": (client_ip, 4242),
        "headers": [(k, v) for k, v in (headers or {}).items()],
    }


async def _run(app, scope, body=b""):
    """Drive one request through the chain. Serves the body once, then a
    live disconnect for any further receive() calls (mirrors a real ASGI
    server)."""
    delivered = []
    sent = {"body": False}

    async def send(message):
        delivered.append(message)

    async def receive():
        if not sent["body"]:
            sent["body"] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    await app(scope, receive, send)
    return delivered


def _statuses(delivered):
    return [m["status"] for m in delivered if m["type"] == "http.response.start"]


def _audit_lines(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "postgres_mcp.audit"]


@pytest.mark.asyncio
async def test_valid_person_token_reaches_terminal_and_audits(monkeypatch, caplog):
    """Flag on + valid personal bearer token: request reaches the terminal
    app, gets a 200, and exactly one audit line is emitted naming the person
    and the called tool."""
    caplog.set_level("INFO", logger="postgres_mcp.audit")
    token = "tok-integration-abc"
    monkeypatch.setenv("PERSON_AUTH_ENABLED", "true")
    monkeypatch.setenv("PERSON_TOKENS", json.dumps({"dharsan": _digest(token)}))

    recorder = _Recorder()
    app = build_middleware_stack(recorder)

    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "list_schemas", "arguments": {}},
        }
    ).encode()
    scope = _scope(
        method="POST",
        path="/postgres-mcp/mcp",
        headers={
            b"authorization": f"Bearer {token}".encode(),
            b"content-length": str(len(body)).encode(),
        },
    )

    delivered = await _run(app, scope, body)

    assert recorder.called
    assert _statuses(delivered) == [200]

    lines = _audit_lines(caplog)
    assert len(lines) == 1
    assert lines[0]["person"] == "dharsan"
    assert lines[0]["tool"] == "list_schemas"
    assert lines[0]["status"] == 200


@pytest.mark.asyncio
async def test_missing_token_401_and_denied_audit_line(monkeypatch, caplog):
    """Flag on + no token: the terminal app is never invoked, the response is
    401, and exactly one audit line records the denial (person="", non-empty
    client_ip)."""
    caplog.set_level("INFO", logger="postgres_mcp.audit")
    monkeypatch.setenv("PERSON_AUTH_ENABLED", "true")
    monkeypatch.setenv("PERSON_TOKENS", json.dumps({"dharsan": _digest("tok-integration-abc")}))

    recorder = _Recorder()
    app = build_middleware_stack(recorder)

    scope = _scope(method="POST", path="/postgres-mcp/mcp")
    delivered = await _run(app, scope)

    assert not recorder.called
    assert _statuses(delivered) == [401]

    lines = _audit_lines(caplog)
    assert len(lines) == 1
    assert lines[0]["denied"] == "person_auth"
    assert lines[0]["status"] == 401
    assert lines[0]["person"] == ""
    assert lines[0]["client_ip"]


@pytest.mark.asyncio
async def test_flag_off_passes_through_legacy(monkeypatch, caplog):
    """Flag off (env unset entirely): a request with no Authorization header
    passes straight through to the terminal app — exact pre-M1 behavior."""
    caplog.set_level("INFO", logger="postgres_mcp.audit")
    monkeypatch.delenv("PERSON_AUTH_ENABLED", raising=False)
    monkeypatch.delenv("PERSON_TOKENS", raising=False)

    recorder = _Recorder()
    app = build_middleware_stack(recorder)

    scope = _scope(method="POST", path="/postgres-mcp/mcp")
    delivered = await _run(app, scope)

    assert recorder.called
    assert _statuses(delivered) == [200]


@pytest.mark.asyncio
async def test_health_path_exempt_end_to_end(monkeypatch, caplog):
    """Health path with flag on and no token: never gets PersonAuth's 401 and
    is never audited.

    HealthCheckMiddleware (innermost, ahead of the terminal app) answers
    ``/health`` directly from in-memory pool state (the S6 self-DoS fix), so
    ``recorder`` itself is never invoked for this path either way — what this
    test verifies is that PersonAuth's HEALTH_PATHS exemption holds for the
    *whole* composed chain: no 401, no audit line.
    """
    caplog.set_level("INFO", logger="postgres_mcp.audit")
    monkeypatch.setenv("PERSON_AUTH_ENABLED", "true")
    monkeypatch.setenv("PERSON_TOKENS", json.dumps({"dharsan": _digest("tok-integration-abc")}))

    recorder = _Recorder()
    app = build_middleware_stack(recorder)

    scope = _scope(method="GET", path="/postgres-mcp/health")
    delivered = await _run(app, scope)

    assert not recorder.called
    assert _statuses(delivered) != [401]
    assert _audit_lines(caplog) == []
