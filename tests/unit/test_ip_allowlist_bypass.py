"""IP-allowlist bypass tests (LOOP-664 follow-up).

A non-whitelisted caller may bypass the IP allowlist with EITHER the shared
static AUTH_TOKEN (legacy) OR a valid per-person token from the registry. The
person-token bypass is active whenever the registry is non-empty, independent
of PERSON_AUTH_ENABLED (which governs whether a person token is *required*, not
whether it grants network access).
"""

import hashlib

import pytest

from postgres_mcp.person_auth import PersonTokenRegistry
from postgres_mcp.person_auth import current_person
from postgres_mcp.server import IPAllowlistMiddleware

WHITELIST = "10.0.0.0/16"
OUTSIDE_IP = "203.0.113.9"  # not in 10.0.0.0/16
INSIDE_IP = "10.0.1.5"
AUTH_TOKEN = "shared-static-token"


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _registry() -> PersonTokenRegistry:
    return PersonTokenRegistry(raw=f'{{"alice": "{_digest("tok-alice")}"}}')


class _Recorder:
    def __init__(self):
        self.called = False

    async def __call__(self, scope, receive, send):
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _scope(client_ip, bearer=None, path="/postgres-mcp/mcp"):
    headers = []
    if bearer is not None:
        headers.append((b"authorization", f"Bearer {bearer}".encode()))
    return {
        "type": "http",
        "path": path,
        "method": "POST",
        "client": (client_ip, 5555),
        "headers": headers,
    }


async def _run(mw, scope):
    statuses = []

    async def send(message):
        if message["type"] == "http.response.start":
            statuses.append(message["status"])

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    await mw(scope, receive, send)
    return statuses[0] if statuses else None


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("ALLOWED_IPS", WHITELIST)
    monkeypatch.setenv("AUTH_TOKEN", AUTH_TOKEN)


@pytest.mark.asyncio
async def test_outside_ip_no_bearer_blocked(env):
    inner = _Recorder()
    mw = IPAllowlistMiddleware(inner, registry=_registry())
    assert await _run(mw, _scope(OUTSIDE_IP)) == 403
    assert not inner.called


@pytest.mark.asyncio
async def test_outside_ip_shared_auth_token_passes(env):
    inner = _Recorder()
    mw = IPAllowlistMiddleware(inner, registry=_registry())
    assert await _run(mw, _scope(OUTSIDE_IP, bearer=AUTH_TOKEN)) == 200
    assert inner.called


@pytest.mark.asyncio
async def test_outside_ip_valid_person_token_passes(env):
    """The new behavior: a valid per-person token grants IP bypass."""
    inner = _Recorder()
    mw = IPAllowlistMiddleware(inner, registry=_registry())
    assert await _run(mw, _scope(OUTSIDE_IP, bearer="tok-alice")) == 200
    assert inner.called


@pytest.mark.asyncio
async def test_outside_ip_unknown_bearer_blocked(env):
    inner = _Recorder()
    mw = IPAllowlistMiddleware(inner, registry=_registry())
    assert await _run(mw, _scope(OUTSIDE_IP, bearer="not-a-real-token")) == 403
    assert not inner.called


@pytest.mark.asyncio
async def test_whitelisted_ip_no_bearer_passes(env):
    inner = _Recorder()
    mw = IPAllowlistMiddleware(inner, registry=_registry())
    assert await _run(mw, _scope(INSIDE_IP)) == 200
    assert inner.called


@pytest.mark.asyncio
async def test_no_registry_means_no_person_bypass(env):
    """Without a registry, a person-shaped token must not grant bypass."""
    inner = _Recorder()
    mw = IPAllowlistMiddleware(inner, registry=None)
    assert await _run(mw, _scope(OUTSIDE_IP, bearer="tok-alice")) == 403
    assert not inner.called
    # ...but the shared AUTH_TOKEN still works with no registry.
    inner2 = _Recorder()
    mw2 = IPAllowlistMiddleware(inner2, registry=None)
    assert await _run(mw2, _scope(OUTSIDE_IP, bearer=AUTH_TOKEN)) == 200


@pytest.mark.asyncio
async def test_person_token_bypass_without_shared_auth_token(monkeypatch):
    """Person-token bypass works even when AUTH_TOKEN is unset (post-retirement)."""
    monkeypatch.setenv("ALLOWED_IPS", WHITELIST)
    monkeypatch.delenv("AUTH_TOKEN", raising=False)
    inner = _Recorder()
    mw = IPAllowlistMiddleware(inner, registry=_registry())
    assert await _run(mw, _scope(OUTSIDE_IP, bearer="tok-alice")) == 200
    assert inner.called
    # An unknown token is still blocked.
    inner2 = _Recorder()
    mw2 = IPAllowlistMiddleware(inner2, registry=_registry())
    assert await _run(mw2, _scope(OUTSIDE_IP, bearer="nope")) == 403


@pytest.mark.asyncio
async def test_health_path_exempt_regardless(env):
    inner = _Recorder()
    mw = IPAllowlistMiddleware(inner, registry=_registry())
    assert await _run(mw, _scope(OUTSIDE_IP, path="/postgres-mcp/health")) == 200
    assert inner.called


class _PersonRecorder:
    def __init__(self):
        self.person_seen = None

    async def __call__(self, scope, receive, send):
        self.person_seen = current_person.get()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


@pytest.mark.asyncio
async def test_person_token_sets_current_person_for_attribution(env):
    """A person-token caller is attributed downstream even with PersonAuth off."""
    inner = _PersonRecorder()
    mw = IPAllowlistMiddleware(inner, registry=_registry())
    await _run(mw, _scope(OUTSIDE_IP, bearer="tok-alice"))
    assert inner.person_seen == "alice"
    assert current_person.get() == ""  # reset after the request


@pytest.mark.asyncio
async def test_auth_token_caller_not_attributed(env):
    """AUTH_TOKEN grants access but carries no identity — person stays unset."""
    inner = _PersonRecorder()
    mw = IPAllowlistMiddleware(inner, registry=_registry())
    await _run(mw, _scope(OUTSIDE_IP, bearer=AUTH_TOKEN))
    assert inner.person_seen == ""
