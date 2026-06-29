"""ASGI-level tests for CallerIdentityMiddleware (postgres-mcp admin gating).

postgres-mcp is admin-only: legacy/superadmin pass; any other scope is 403'd;
a scoped caller that can't be authenticated is 401'd.
"""

import pytest

import postgres_mcp.caller_identity as ci
from postgres_mcp.server import CallerIdentityMiddleware


def _areturn(value):
    """Build an async validate_token_async stub returning ``value`` (P2)."""
    async def _f(token):
        return value
    return _f


class _Recorder:
    def __init__(self):
        self.called = False

    async def __call__(self, scope, receive, send):
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _scope(headers, path="/postgres-mcp/mcp"):
    return {
        "type": "http",
        "path": path,
        "method": "POST",
        "headers": [(k, v) for k, v in headers.items()],
    }


async def _run(mw, scope):
    statuses = []

    async def send(message):
        if message["type"] == "http.response.start":
            statuses.append(message["status"])

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    await mw(scope, receive, send)
    return statuses


@pytest.mark.asyncio
async def test_legacy_passes_through():
    inner = _Recorder()
    mw = CallerIdentityMiddleware(inner)
    statuses = await _run(mw, _scope({}))
    assert inner.called
    assert statuses == [200]


@pytest.mark.asyncio
async def test_internal_bearer_without_scope_is_legacy(monkeypatch):
    # REGRESSION: internal/ops callers present the shared AUTH_TOKEN and NO
    # X-User-Scope header -> must pass through unchanged (legacy).
    monkeypatch.setenv("AUTH_TOKEN", "shared-secret")
    inner = _Recorder()
    mw = CallerIdentityMiddleware(inner)
    statuses = await _run(mw, _scope({b"authorization": b"Bearer shared-secret"}))
    assert inner.called
    assert statuses == [200]


@pytest.mark.asyncio
async def test_trusted_superadmin_passes(monkeypatch):
    monkeypatch.setenv("AUTH_TOKEN", "shared-secret")
    inner = _Recorder()
    mw = CallerIdentityMiddleware(inner)
    statuses = await _run(
        mw,
        _scope({b"x-user-scope": b"superadmin", b"authorization": b"Bearer shared-secret"}),
    )
    assert inner.called
    assert statuses == [200]


@pytest.mark.asyncio
async def test_trusted_expert_is_403(monkeypatch):
    monkeypatch.setenv("AUTH_TOKEN", "shared-secret")
    inner = _Recorder()
    mw = CallerIdentityMiddleware(inner)
    statuses = await _run(
        mw,
        _scope({b"x-user-scope": b"expert", b"authorization": b"Bearer shared-secret"}),
    )
    assert statuses == [403]
    assert not inner.called


@pytest.mark.asyncio
async def test_untrusted_user_token_expert_is_403(monkeypatch):
    _profile = {"email": "x@topmate.io", "username": "x", "primary_user_type": "expert"}
    monkeypatch.setattr(ci, "validate_token", lambda t: _profile)
    monkeypatch.setattr(ci, "validate_token_async", _areturn(_profile))
    inner = _Recorder()
    mw = CallerIdentityMiddleware(inner)
    statuses = await _run(
        mw, _scope({b"x-user-scope": b"expert", b"authorization": b"Token good"})
    )
    assert statuses == [403]
    assert not inner.called


@pytest.mark.asyncio
async def test_untrusted_superadmin_via_allowlist_passes(monkeypatch):
    monkeypatch.setenv("SUPERADMIN_EMAILS", "admin@topmate.io")
    _profile = {"email": "admin@topmate.io", "username": "admin", "primary_user_type": "follower"}
    monkeypatch.setattr(ci, "validate_token", lambda t: _profile)
    monkeypatch.setattr(ci, "validate_token_async", _areturn(_profile))
    inner = _Recorder()
    mw = CallerIdentityMiddleware(inner)
    statuses = await _run(
        mw, _scope({b"x-user-scope": b"superadmin", b"authorization": b"Token admintok"})
    )
    assert inner.called
    assert statuses == [200]


@pytest.mark.asyncio
async def test_invalid_token_is_401(monkeypatch):
    monkeypatch.setattr(ci, "validate_token", lambda t: None)
    monkeypatch.setattr(ci, "validate_token_async", _areturn(None))
    inner = _Recorder()
    mw = CallerIdentityMiddleware(inner)
    statuses = await _run(
        mw, _scope({b"x-user-scope": b"expert", b"authorization": b"Token bad"})
    )
    assert statuses == [401]
    assert not inner.called


@pytest.mark.asyncio
async def test_health_path_bypasses_gate():
    inner = _Recorder()
    mw = CallerIdentityMiddleware(inner)
    await _run(mw, _scope({b"x-user-scope": b"expert"}, path="/postgres-mcp/health"))
    assert inner.called


@pytest.mark.asyncio
async def test_disabled_passes_through(monkeypatch):
    monkeypatch.setenv("CALLER_SCOPE_ENABLED", "false")
    inner = _Recorder()
    mw = CallerIdentityMiddleware(inner)
    await _run(mw, _scope({b"x-user-scope": b"expert", b"authorization": b"Token bad"}))
    assert inner.called  # kill-switch => pure pass-through
