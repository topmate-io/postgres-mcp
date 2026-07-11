"""ASGI-level tests for PersonAuthMiddleware (LOOP-664 M1)."""

import hashlib

import pytest

from postgres_mcp.person_auth import PersonAuthMiddleware
from postgres_mcp.person_auth import PersonTokenRegistry
from postgres_mcp.person_auth import current_person


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _registry() -> PersonTokenRegistry:
    return PersonTokenRegistry(raw=f'{{"dharsan": "{_digest("tok-abc")}"}}')


class _Recorder:
    def __init__(self):
        self.called = False
        self.person_seen = None

    async def __call__(self, scope, receive, send):
        self.called = True
        self.person_seen = current_person.get()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _scope(headers=None, path="/postgres-mcp/mcp"):
    return {
        "type": "http",
        "path": path,
        "method": "POST",
        "headers": [(k, v) for k, v in (headers or {}).items()],
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
async def test_disabled_passes_through_without_auth():
    inner = _Recorder()
    mw = PersonAuthMiddleware(inner, registry=None, enabled=False)
    statuses = await _run(mw, _scope())
    assert inner.called
    assert statuses == [200]


@pytest.mark.asyncio
async def test_enabled_missing_token_401():
    inner = _Recorder()
    mw = PersonAuthMiddleware(inner, registry=_registry(), enabled=True)
    statuses = await _run(mw, _scope())
    assert not inner.called
    assert statuses == [401]


@pytest.mark.asyncio
async def test_enabled_wrong_token_401():
    inner = _Recorder()
    mw = PersonAuthMiddleware(inner, registry=_registry(), enabled=True)
    statuses = await _run(mw, _scope({b"authorization": b"Bearer tok-WRONG"}))
    assert not inner.called
    assert statuses == [401]


@pytest.mark.asyncio
async def test_enabled_valid_token_passes_and_sets_person():
    inner = _Recorder()
    mw = PersonAuthMiddleware(inner, registry=_registry(), enabled=True)
    statuses = await _run(mw, _scope({b"authorization": b"Bearer tok-abc"}))
    assert inner.called
    assert inner.person_seen == "dharsan"
    assert statuses == [200]


@pytest.mark.asyncio
async def test_contextvar_reset_after_request():
    inner = _Recorder()
    mw = PersonAuthMiddleware(inner, registry=_registry(), enabled=True)
    await _run(mw, _scope({b"authorization": b"Bearer tok-abc"}))
    assert current_person.get() == ""


@pytest.mark.asyncio
async def test_health_paths_exempt_even_when_enabled():
    inner = _Recorder()
    mw = PersonAuthMiddleware(inner, registry=_registry(), enabled=True)
    statuses = await _run(mw, _scope(path="/postgres-mcp/health"))
    assert inner.called
    assert statuses == [200]


@pytest.mark.asyncio
async def test_non_http_scope_passes_through():
    inner = _Recorder()
    mw = PersonAuthMiddleware(inner, registry=_registry(), enabled=True)
    called = {}

    async def app(scope, receive, send):
        called["yes"] = True

    mw.app = app
    await mw({"type": "lifespan"}, None, None)
    assert called.get("yes")


def test_enabled_with_empty_registry_refuses_to_construct():
    with pytest.raises(ValueError, match="refusing to start"):
        PersonAuthMiddleware(_Recorder(), registry=PersonTokenRegistry(raw=""), enabled=True)
