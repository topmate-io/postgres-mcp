"""Tests for the person-keyed, LRU-bounded rate limiter (LOOP-664 M1).

Fixes two audited defects: db-mcp's limiter keyed off a spoofable
unauthenticated header, and this repo's old limiter grew its bucket dict
without bound. Identity comes ONLY from the authenticated current_person
contextvar; header spoofing must have no effect on keying.
"""

import pytest

from postgres_mcp.person_auth import current_person
from postgres_mcp.server import RateLimiterMiddleware


class _Recorder:
    def __init__(self):
        self.count = 0

    async def __call__(self, scope, receive, send):
        self.count += 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _scope(headers=None, path="/postgres-mcp/mcp", client_ip="10.0.0.1"):
    return {
        "type": "http",
        "path": path,
        "method": "POST",
        "client": (client_ip, 12345),
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
async def test_limits_by_ip_when_no_person():
    inner = _Recorder()
    mw = RateLimiterMiddleware(inner, max_requests=2, window_seconds=3600)
    assert await _run(mw, _scope()) == [200]
    assert await _run(mw, _scope()) == [200]
    assert await _run(mw, _scope()) == [429]


@pytest.mark.asyncio
async def test_two_persons_behind_same_ip_have_separate_buckets():
    inner = _Recorder()
    mw = RateLimiterMiddleware(inner, max_requests=1, window_seconds=3600)
    tok = current_person.set("alice")
    try:
        assert await _run(mw, _scope()) == [200]
        assert await _run(mw, _scope()) == [429]
    finally:
        current_person.reset(tok)
    tok = current_person.set("bob")
    try:
        # Same client IP, different authenticated person -> fresh bucket
        assert await _run(mw, _scope()) == [200]
    finally:
        current_person.reset(tok)


@pytest.mark.asyncio
async def test_spoofed_username_header_does_not_change_bucket():
    inner = _Recorder()
    mw = RateLimiterMiddleware(inner, max_requests=1, window_seconds=3600)
    assert await _run(mw, _scope({b"x-user-username": b"spoof-1"})) == [200]
    # Varying the header must NOT mint a fresh bucket (same IP, no person)
    assert await _run(mw, _scope({b"x-user-username": b"spoof-2"})) == [429]


@pytest.mark.asyncio
async def test_bucket_store_is_bounded():
    inner = _Recorder()
    mw = RateLimiterMiddleware(inner, max_requests=5, window_seconds=3600)
    for i in range(RateLimiterMiddleware.MAX_BUCKETS + 50):
        await _run(mw, _scope(client_ip=f"10.1.{i // 256}.{i % 256}"))
    assert len(mw._buckets) <= RateLimiterMiddleware.MAX_BUCKETS


@pytest.mark.asyncio
async def test_health_paths_exempt():
    inner = _Recorder()
    mw = RateLimiterMiddleware(inner, max_requests=1, window_seconds=3600)
    for _ in range(5):
        assert await _run(mw, _scope(path="/postgres-mcp/health")) == [200]
