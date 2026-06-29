"""S6: readiness /health is cheap (pool-state only, never a live SELECT) so a
saturated pool can't flip the pod NotReady and drop all Service endpoints."""

import pytest

import postgres_mcp.server as s


class _BoomPool:
    """A pool whose .connection() raises — proves /health doesn't acquire one."""

    def connection(self):
        raise AssertionError("/health must not acquire a pooled connection (S6)")


class _FakeDb:
    def __init__(self, pool, is_valid):
        self.pool = pool
        self._is_valid = is_valid

    @property
    def is_valid(self):
        return self._is_valid


def _scope(path="/health"):
    return {"type": "http", "path": path, "method": "GET", "headers": []}


async def _status(mw, scope):
    statuses = []

    async def send(m):
        if m["type"] == "http.response.start":
            statuses.append(m["status"])

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    await mw(scope, receive, send)
    return statuses[0] if statuses else None


async def _inner(scope, receive, send):  # should never be reached for /health
    await send({"type": "http.response.start", "status": 599, "headers": []})


@pytest.mark.asyncio
async def test_health_200_when_pool_valid_without_db_call(monkeypatch):
    # BoomPool with is_valid=True: 200 proves the readiness never touched the DB.
    monkeypatch.setattr(s, "db_connection", _FakeDb(_BoomPool(), True))
    assert await _status(s.HealthCheckMiddleware(_inner), _scope("/health")) == 200


@pytest.mark.asyncio
async def test_health_503_when_pool_none(monkeypatch):
    monkeypatch.setattr(s, "db_connection", _FakeDb(None, False))
    assert await _status(s.HealthCheckMiddleware(_inner), _scope("/health")) == 503


@pytest.mark.asyncio
async def test_health_503_when_pool_invalid(monkeypatch):
    monkeypatch.setattr(s, "db_connection", _FakeDb(_BoomPool(), False))
    assert await _status(s.HealthCheckMiddleware(_inner), _scope("/health")) == 503
