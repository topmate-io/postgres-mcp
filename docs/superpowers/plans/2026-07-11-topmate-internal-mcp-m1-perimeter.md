# topmate-internal-mcp M1 — Perimeter Swap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the shared static `AUTH_TOKEN` perimeter on postgres-mcp with per-person bearer tokens, an identity-keyed bounded rate limiter, and structured audit logging — all env-flag-guarded so rollback is one env var.

**Architecture:** Three additions to the existing hand-rolled ASGI middleware chain in `src/postgres_mcp/server.py` (LOOP-664 spec §3.3/§3.9, milestone M1): a new `person_auth.py` module (token registry + `PersonAuthMiddleware` + `current_person` contextvar), an in-place rewrite of `RateLimiterMiddleware` (person-keyed, bounded LRU), and a new `audit.py` (`AuditLogMiddleware` that parses the JSON-RPC body to log tool name + arg *keys* — never values). New chain: RequestID → CORS → IPAllowlist → **PersonAuth** → **AuditLog** → CallerIdentity → RateLimiter → HealthCheck → SSEKeepAlive.

**Tech Stack:** Python 3.12, stdlib only for new code (`hashlib`, `hmac`, `json`, `contextvars`, `collections`), pytest + pytest-asyncio with the repo's raw-ASGI test harness, uv, EKS manifests + `eks/deploy.sh`.

**Tracking:** Linear LOOP-664. Branch: `dharsan/loop-664-m1-perimeter` off `feat/caller-scoped-access` (or `main` after that branch merges). Every commit message carries `LOOP-664`.

## Global Constraints

- Do NOT change SDK pins in M1 (`pyproject.toml` keeps `mcp[cli]>=1.8.0,<2.0.0`; the `>=1.26` floor arrives in M2 with the db-mcp merge).
- No new runtime dependencies — stdlib only.
- The legacy `AUTH_TOKEN` bypass in `IPAllowlistMiddleware` (server.py:818-928) is NOT removed in M1 — it is retired in M4. Rollback contract: `PERSON_AUTH_ENABLED=false` restores exact pre-M1 behavior.
- `PERSON_AUTH_ENABLED` defaults to `"false"`; the production manifest ships it `"false"` and it is flipped manually after tokens are distributed (see Task 5 runbook).
- New middleware follows the existing pure-ASGI style (no Starlette BaseHTTPMiddleware). The ALB-prefix-strip and client-IP-extraction conventions live in ONE place: `src/postgres_mcp/asgi_utils.py` (`get_path(scope)`, `get_client_ip(scope)`, created in Task 1). New/rewritten middleware imports these — never copy them. (`IPAllowlistMiddleware` keeps its private copies; it is retired wholesale in M4.)
- Health paths `{"/", "/health", "/healthz"}` are always exempt from auth, rate limiting, and audit.
- Argument VALUES are never written to logs — only sorted argument key names (spec §3.9 redaction rule).
- All tests use the repo's raw-ASGI harness conventions from `tests/unit/test_caller_identity_middleware.py` (`_Recorder`, `_scope`, `_run`, `@pytest.mark.asyncio`).
- Run everything through uv: `uv run pytest …`, `uv run ruff check .`, `uv run pyright`.

---

### Task 1: Person-token registry (`person_auth.py` core)

**Files:**
- Create: `src/postgres_mcp/person_auth.py`
- Create: `src/postgres_mcp/asgi_utils.py`
- Test: `tests/unit/test_person_auth.py`
- Test: `tests/unit/test_asgi_utils.py`

**Interfaces:**
- Consumes: nothing (leaf modules; must NOT import `postgres_mcp.server` — the server imports them).
- Produces: `PersonTokenRegistry(raw: str | None = None)` with `.verify(presented: str) -> str | None` and `__len__`; module-level `current_person: contextvars.ContextVar[str]` (default `""`); `asgi_utils.get_path(scope) -> str` (ALB prefix strip) and `asgi_utils.get_client_ip(scope) -> str` (CF-Connecting-IP → XFF[0] → scope client → `"unknown"`). Task 2 wraps the registry in middleware; Tasks 2-4 import the asgi helpers; Task 3 reads `current_person`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_person_auth.py
"""Unit tests for the per-person token registry (LOOP-664 M1).

PERSON_TOKENS is a JSON object mapping person name -> sha256 hex digest of
that person's raw bearer token. The raw token never appears in config.
"""

import hashlib

import pytest

from postgres_mcp.person_auth import PersonTokenRegistry


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def test_verify_known_token_returns_person_name():
    reg = PersonTokenRegistry(raw=f'{{"dharsan": "{_digest("tok-abc")}"}}')
    assert reg.verify("tok-abc") == "dharsan"


def test_verify_unknown_token_returns_none():
    reg = PersonTokenRegistry(raw=f'{{"dharsan": "{_digest("tok-abc")}"}}')
    assert reg.verify("tok-WRONG") is None


def test_verify_empty_presented_returns_none():
    reg = PersonTokenRegistry(raw=f'{{"dharsan": "{_digest("tok-abc")}"}}')
    assert reg.verify("") is None


def test_empty_config_verifies_nothing():
    reg = PersonTokenRegistry(raw="")
    assert len(reg) == 0
    assert reg.verify("anything") is None


def test_digest_matching_is_case_insensitive():
    reg = PersonTokenRegistry(raw=f'{{"ci": "{_digest("tok-ci").upper()}"}}')
    assert reg.verify("tok-ci") == "ci"


def test_malformed_json_raises_value_error():
    with pytest.raises(ValueError, match="not valid JSON"):
        PersonTokenRegistry(raw="{not json")


def test_non_object_json_raises_value_error():
    with pytest.raises(ValueError, match="JSON object"):
        PersonTokenRegistry(raw='["a", "b"]')


def test_non_sha256_digest_raises_value_error():
    with pytest.raises(ValueError, match="sha256 hex digest"):
        PersonTokenRegistry(raw='{"dharsan": "short"}')


def test_two_people_resolve_independently():
    raw = f'{{"dharsan": "{_digest("tok-a")}", "ci-bot": "{_digest("tok-b")}"}}'
    reg = PersonTokenRegistry(raw=raw)
    assert reg.verify("tok-a") == "dharsan"
    assert reg.verify("tok-b") == "ci-bot"
    assert len(reg) == 2
```

```python
# tests/unit/test_asgi_utils.py
"""Tests for the shared ASGI scope helpers (LOOP-664 M1)."""

from postgres_mcp.asgi_utils import get_client_ip
from postgres_mcp.asgi_utils import get_path


def test_get_path_strips_known_alb_prefixes():
    assert get_path({"path": "/postgres-mcp/mcp"}) == "/mcp"
    assert get_path({"path": "/db-mcp/health"}) == "/health"
    assert get_path({"path": "/postgres-mcp"}) == "/"
    assert get_path({"path": "/mcp"}) == "/mcp"
    assert get_path({}) == ""


def test_get_client_ip_prefers_cloudflare_header():
    scope = {
        "headers": [(b"cf-connecting-ip", b"1.2.3.4"), (b"x-forwarded-for", b"5.6.7.8, 9.9.9.9")],
        "client": ("10.0.0.1", 1),
    }
    assert get_client_ip(scope) == "1.2.3.4"


def test_get_client_ip_falls_back_to_first_xff_entry():
    scope = {"headers": [(b"x-forwarded-for", b"5.6.7.8, 9.9.9.9")], "client": ("10.0.0.1", 1)}
    assert get_client_ip(scope) == "5.6.7.8"


def test_get_client_ip_falls_back_to_scope_client_then_unknown():
    assert get_client_ip({"headers": [], "client": ("10.0.0.1", 1)}) == "10.0.0.1"
    assert get_client_ip({"headers": []}) == "unknown"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_person_auth.py tests/unit/test_asgi_utils.py -v`
Expected: FAIL — `ModuleNotFoundError` for both `postgres_mcp.person_auth` and `postgres_mcp.asgi_utils`

- [ ] **Step 3: Write the implementation**

```python
# src/postgres_mcp/asgi_utils.py
"""Shared ASGI scope helpers for the perimeter middleware chain (LOOP-664 M1).

One canonical copy of the ALB ingress-prefix strip and the client-IP
extraction (CF-Connecting-IP -> X-Forwarded-For[0] -> ASGI client) used by
PersonAuth, AuditLog, and RateLimiter. IPAllowlistMiddleware keeps its
private copies until it is retired wholesale in M4.

Leaf module: must not import anything from postgres_mcp.
"""

ALB_PREFIXES = ("/postgres-mcp", "/db-mcp", "/instagram-mcp")


def get_path(scope) -> str:
    """Request path with known ALB ingress prefixes stripped."""
    path = scope.get("path", "")
    for prefix in ALB_PREFIXES:
        if path.startswith(prefix):
            return path[len(prefix):] or "/"
    return path


def get_client_ip(scope) -> str:
    """Real client IP: CF-Connecting-IP > X-Forwarded-For[0] > ASGI client.

    Traffic flows Client -> Cloudflare -> ALB -> Pod. CF-Connecting-IP is set
    by Cloudflare and cannot be spoofed by the client; XFF[0] is the first
    (client-set) entry — less trustworthy but works without Cloudflare.
    """
    headers = {name.lower(): value for name, value in scope.get("headers", [])}
    cf_ip = headers.get(b"cf-connecting-ip")
    if cf_ip:
        return cf_ip.decode("latin-1").strip()
    xff = headers.get(b"x-forwarded-for")
    if xff:
        return xff.decode("latin-1").split(",")[0].strip()
    client = scope.get("client")
    return client[0] if client else "unknown"
```

```python
# src/postgres_mcp/person_auth.py
"""Per-person bearer-token authentication for the internal team MCP (LOOP-664 M1).

Replaces trust in the shared static ``AUTH_TOKEN`` with named, individually
revocable tokens. Config contract:

* ``PERSON_TOKENS`` — JSON object mapping person name -> sha256 hex digest of
  that person's raw bearer token, e.g. ``{"dharsan": "9f86d08…"}``. The raw
  token is handed to the person once and never stored anywhere server-side.
* ``PERSON_AUTH_ENABLED`` — ``"true"`` to enforce; anything else = no-op
  middleware (rollback path; legacy AUTH_TOKEN behavior is untouched).

This module must stay import-leaf: ``postgres_mcp.server`` imports it.
"""

import contextvars
import hashlib
import hmac
import json
import logging
import os

logger = logging.getLogger(__name__)

# Resolved person name for the current request ("" when PersonAuth is off).
current_person: contextvars.ContextVar[str] = contextvars.ContextVar("current_person", default="")


class PersonTokenRegistry:
    """Immutable name<->token-digest registry parsed from PERSON_TOKENS."""

    def __init__(self, raw: str | None = None):
        if raw is None:
            raw = os.getenv("PERSON_TOKENS", "")
        raw = raw.strip()
        self._by_digest: dict[str, str] = {}
        if not raw:
            return
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"PERSON_TOKENS is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("PERSON_TOKENS must be a JSON object of name -> sha256 hex digest")
        for name, digest in parsed.items():
            if not isinstance(digest, str) or len(digest) != 64:
                raise ValueError(f"PERSON_TOKENS[{name!r}] must be a 64-char sha256 hex digest")
            self._by_digest[digest.lower()] = str(name)

    def __len__(self) -> int:
        return len(self._by_digest)

    def verify(self, presented: str) -> str | None:
        """Return the person name for a raw bearer token, or None.

        Scans every entry with hmac.compare_digest so the comparison cost does
        not depend on which (if any) entry matches.
        """
        if not presented or not self._by_digest:
            return None
        digest = hashlib.sha256(presented.encode()).hexdigest()
        matched: str | None = None
        for known_digest, name in self._by_digest.items():
            if hmac.compare_digest(digest, known_digest):
                matched = name
        return matched
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_person_auth.py tests/unit/test_asgi_utils.py -v`
Expected: 13 passed

- [ ] **Step 5: Commit**

```bash
git add src/postgres_mcp/person_auth.py src/postgres_mcp/asgi_utils.py tests/unit/test_person_auth.py tests/unit/test_asgi_utils.py
git commit -m "feat(auth): LOOP-664 M1 — per-person token registry + shared ASGI helpers"
```

---

### Task 2: `PersonAuthMiddleware` + wiring into the server chain

**Files:**
- Modify: `src/postgres_mcp/person_auth.py` (append middleware class)
- Modify: `src/postgres_mcp/server.py:1341-1366` (middleware stack) and the imports block at the top of `server.py`
- Test: `tests/unit/test_person_auth_middleware.py`

**Interfaces:**
- Consumes: `PersonTokenRegistry`, `current_person` (Task 1).
- Produces: `PersonAuthMiddleware(app, registry: PersonTokenRegistry | None = None, enabled: bool | None = None)` — ASGI callable. When enabled and the bearer resolves, sets `current_person` for the downstream app. Raises `ValueError` at construction when enabled with an empty registry (fail-fast: never boot an open server by accident). Tasks 3 and 4 rely on `current_person` being set.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_person_auth_middleware.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_person_auth_middleware.py -v`
Expected: FAIL — `ImportError: cannot import name 'PersonAuthMiddleware'`

- [ ] **Step 3: Append the middleware to `person_auth.py`**

```python
# append to src/postgres_mcp/person_auth.py
# (add `from .asgi_utils import get_path` to the module imports)


class PersonAuthMiddleware:
    """ASGI middleware enforcing per-person bearer tokens (LOOP-664 M1).

    Sits between IPAllowlistMiddleware and AuditLogMiddleware. When enabled,
    every non-health HTTP request must carry ``Authorization: Bearer <token>``
    where sha256(token) is a value in PERSON_TOKENS. On success the resolved
    person name is exposed via ``current_person`` for the rate limiter
    (identity keying) and the audit log.

    Rollback: PERSON_AUTH_ENABLED=false -> exact pre-M1 behavior.
    """

    HEALTH_PATHS = {"/", "/health", "/healthz"}

    def __init__(self, app, registry: PersonTokenRegistry | None = None, enabled: bool | None = None):
        self.app = app
        if enabled is None:
            enabled = os.getenv("PERSON_AUTH_ENABLED", "false").strip().lower() == "true"
        self.enabled = enabled
        self.registry = registry if registry is not None else (PersonTokenRegistry() if enabled else None)
        if self.enabled and (self.registry is None or len(self.registry) == 0):
            raise ValueError(
                "PERSON_AUTH_ENABLED=true but PERSON_TOKENS is empty — "
                "refusing to start an effectively unauthenticated server"
            )
        if self.enabled:
            logger.info("PersonAuth enabled: %d person token(s) loaded", len(self.registry))

    async def __call__(self, scope, receive, send):
        if not self.enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if get_path(scope) in self.HEALTH_PATHS:
            await self.app(scope, receive, send)
            return

        headers = {name.lower(): value for name, value in scope.get("headers", [])}
        auth = headers.get(b"authorization", b"").decode("latin-1")
        presented = auth[len("Bearer "):].strip() if auth.startswith("Bearer ") else ""
        # self.registry is guaranteed non-None when enabled (constructor raises
        # otherwise); the extra check keeps type-checkers satisfied.
        person = self.registry.verify(presented) if (presented and self.registry) else None

        if person is None:
            logger.warning("PersonAuth: rejected request to %s (missing/unknown token)", scope.get("path", ""))
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [[b"content-type", b"application/json"]],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"error":"unauthorized","message":"Valid personal bearer token required"}',
            })
            return

        token = current_person.set(person)
        try:
            await self.app(scope, receive, send)
        finally:
            current_person.reset(token)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_person_auth_middleware.py -v`
Expected: 8 passed

- [ ] **Step 5: Wire into the server chain**

In `src/postgres_mcp/server.py`, add to the imports near the other project imports at the top of the file:

```python
from .person_auth import PersonAuthMiddleware
```

Replace the stack construction (currently server.py:1348-1362) with:

```python
        # Middleware stack (outermost → innermost):
        # 0. RequestIDMiddleware — assigns correlation ID to every request
        # 1. CORSMiddleware — handles OPTIONS preflight + CORS headers
        # 2. IPAllowlistMiddleware — allows whitelisted IPs OR valid AUTH_TOKEN Bearer (legacy, retired in M4)
        # 3. PersonAuthMiddleware — per-person bearer tokens (LOOP-664 M1, PERSON_AUTH_ENABLED)
        # 4. CallerIdentityMiddleware — legacy end-user identity gating (frozen path, retired in M4)
        # 5. RateLimiterMiddleware — person-keyed (fallback per-IP) rate limiting
        # 6. HealthCheckMiddleware — ALB health probes
        # 7. SSEKeepAliveMiddleware — SSE ping to prevent idle timeouts (SSE retired in M4)
        wrapped_app = RequestIDMiddleware(
            CORSMiddleware(
                IPAllowlistMiddleware(
                    PersonAuthMiddleware(
                        CallerIdentityMiddleware(
                            RateLimiterMiddleware(
                                HealthCheckMiddleware(
                                    SSEKeepAliveMiddleware(route_by_transport, interval=15)
                                ),
                                max_requests=int(os.environ.get("RATE_LIMIT_MAX_REQUESTS", "30")),
                                window_seconds=int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60")),
                            )
                        )
                    )
                )
            )
        )
        logger.info(
            "Applied middleware stack: RequestID + CORS + IPAllowlist(+TokenBypass) + "
            "PersonAuth + CallerIdentity + RateLimiter + HealthCheck + SSEKeepAlive"
        )
```

(The AuditLog layer is inserted between PersonAuth and CallerIdentity in Task 4 — this task's comment block is updated again there.)

- [ ] **Step 6: Run the full unit suite to catch wiring regressions**

Run: `uv run pytest tests/unit -v`
Expected: no new failures vs. the pre-existing baseline (the 2 known `tests/unit/explain` failures may still be present; nothing else fails)

- [ ] **Step 7: Commit**

```bash
git add src/postgres_mcp/person_auth.py src/postgres_mcp/server.py tests/unit/test_person_auth_middleware.py
git commit -m "feat(auth): LOOP-664 M1 — PersonAuthMiddleware wired behind PERSON_AUTH_ENABLED"
```

---

### Task 3: Identity-keyed, bounded rate limiter

**Files:**
- Modify: `src/postgres_mcp/server.py:741-815` (`RateLimiterMiddleware`)
- Test: `tests/unit/test_rate_limiter.py`

**Interfaces:**
- Consumes: `current_person` from `postgres_mcp.person_auth` (set by Task 2's middleware, `""` when auth disabled).
- Produces: same class name/constructor (`RateLimiterMiddleware(app, max_requests=30, window_seconds=60)`) so the Task 2 wiring is untouched; new class attribute `MAX_BUCKETS = 1024`; bucket keys are `"person:<name>"` or `"ip:<ip>"`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_rate_limiter.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_rate_limiter.py -v`
Expected: `test_two_persons_behind_same_ip_have_separate_buckets`, `test_bucket_store_is_bounded` FAIL (no person keying, no `MAX_BUCKETS` attribute); the others may pass against the old implementation

- [ ] **Step 3: Rewrite `RateLimiterMiddleware` in place**

Replace the class at `src/postgres_mcp/server.py:741-815` with the code below, and add `from collections import OrderedDict`, `from .person_auth import current_person`, and `from .asgi_utils import get_client_ip, get_path` to the imports at the top of server.py. (`_consume` keeps the original's local `import time as _time` style.)

```python
class RateLimiterMiddleware:
    """Token-bucket rate limiter keyed on authenticated identity (LOOP-664 M1).

    Bucket key: ``person:<name>`` when PersonAuth resolved a caller, else
    ``ip:<client-ip>``. Identity comes ONLY from the current_person contextvar
    (set post-authentication) — never from request headers, which callers
    control. The bucket store is a bounded LRU (MAX_BUCKETS) so many distinct
    keys over a pod's lifetime cannot grow memory without bound.

    Exempt paths: health checks. Exceeding the rate returns 429 + Retry-After.
    """

    HEALTH_PATHS = {"/", "/health", "/healthz"}
    MAX_BUCKETS = 1024

    def __init__(self, app, max_requests: int = 30, window_seconds: int = 60):
        self.app = app
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: OrderedDict[str, list] = OrderedDict()  # key -> [tokens, last_refill]
        self._lock = asyncio.Lock()

    def _bucket_key(self, scope) -> str:
        person = current_person.get()
        if person:
            return f"person:{person}"
        return f"ip:{get_client_ip(scope)}"

    def _consume(self, key: str) -> bool:
        import time as _time
        now = _time.monotonic()
        bucket = self._buckets.get(key)
        if bucket is None:
            while len(self._buckets) >= self.MAX_BUCKETS:
                self._buckets.popitem(last=False)  # evict least-recently-used key
            bucket = [float(self.max_requests), now]
            self._buckets[key] = bucket
        else:
            self._buckets.move_to_end(key)
        tokens, last = bucket
        elapsed = now - last
        refill_rate = self.max_requests / self.window_seconds
        tokens = min(self.max_requests, tokens + elapsed * refill_rate)
        bucket[1] = now
        if tokens >= 1.0:
            bucket[0] = tokens - 1.0
            return True
        bucket[0] = tokens
        return False

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = get_path(scope)
            if path not in self.HEALTH_PATHS:
                key = self._bucket_key(scope)
                async with self._lock:
                    allowed = self._consume(key)
                if not allowed:
                    logger.warning("Rate limit exceeded for %s", key)
                    await send({
                        "type": "http.response.start",
                        "status": 429,
                        "headers": [
                            [b"content-type", b"application/json"],
                            [b"retry-after", str(self.window_seconds).encode()],
                        ],
                    })
                    await send({
                        "type": "http.response.body",
                        "body": b'{"error":"too_many_requests","message":"Rate limit exceeded"}',
                    })
                    return
        await self.app(scope, receive, send)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_rate_limiter.py -v`
Expected: 5 passed

- [ ] **Step 5: Run the full unit suite**

Run: `uv run pytest tests/unit -v`
Expected: no new failures vs. baseline

- [ ] **Step 6: Commit**

```bash
git add src/postgres_mcp/server.py tests/unit/test_rate_limiter.py
git commit -m "fix(perimeter): LOOP-664 M1 — rate limiter keyed on authenticated person, bounded LRU buckets"
```

---

### Task 4: Audit log middleware (`audit.py`)

**Files:**
- Create: `src/postgres_mcp/audit.py`
- Modify: `src/postgres_mcp/server.py` (insert AuditLog between PersonAuth and CallerIdentity; update stack comment + log line)
- Test: `tests/unit/test_audit.py`

**Interfaces:**
- Consumes: `current_person` (Task 1). Receives `get_request_id` as an injected callable to avoid a circular import (`server.py` owns `_request_id_var`).
- Produces: `AuditLogMiddleware(app, get_request_id=None)`; module function `_parse_jsonrpc(body: bytes) -> tuple[str, str, list[str]]` (rpc method, tool name, sorted arg keys). Emits exactly one JSON log line per audited request on logger `postgres_mcp.audit`. M2's metrics dispatch wrapper will reuse this logger's format.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_audit.py
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
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "execute_sql", "arguments": {"sql": "SELECT 1", "row_limit": 10}},
    }).encode()
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
    body = json.dumps({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "list_schemas", "arguments": {"secret_arg": "SENSITIVE-VALUE"}},
    }).encode()
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_audit.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'postgres_mcp.audit'`

- [ ] **Step 3: Write the implementation**

```python
# src/postgres_mcp/audit.py
"""Structured audit logging for the internal team MCP (LOOP-664 M1).

Emits exactly one JSON log line per non-health HTTP request on the
``postgres_mcp.audit`` logger: who (person, client_ip, request_id), what
(path, rpc_method, tool, arg KEYS), and outcome (status, duration_ms).

Redaction rule (spec §3.9): argument VALUES are never logged — only sorted
argument key names. Full redacted-value logging arrives with the M2 dispatch
wrapper.

The request body is pre-read only when Content-Length is present and at most
AUDIT_MAX_BODY, then replayed to the inner app; larger or streaming bodies
pass through untouched and are logged without rpc/tool detail.
"""

import json
import logging
import time

from .asgi_utils import get_client_ip
from .asgi_utils import get_path
from .person_auth import current_person

logger = logging.getLogger("postgres_mcp.audit")

AUDIT_MAX_BODY = 64 * 1024


def _parse_jsonrpc(body: bytes) -> tuple[str, str, list[str]]:
    """Extract (rpc_method, tool_name, sorted arg keys) from a JSON-RPC body."""
    if not body:
        return "", "", []
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return "", "", []
    if not isinstance(payload, dict):
        return "", "", []
    method = str(payload.get("method", ""))
    tool = ""
    arg_keys: list[str] = []
    params = payload.get("params")
    if method == "tools/call" and isinstance(params, dict):
        tool = str(params.get("name", ""))
        args = params.get("arguments")
        if isinstance(args, dict):
            arg_keys = sorted(str(k) for k in args)
    return method, tool, arg_keys


class AuditLogMiddleware:
    """ASGI middleware emitting one audit line per request (LOOP-664 M1)."""

    HEALTH_PATHS = {"/", "/health", "/healthz"}

    def __init__(self, app, get_request_id=None):
        self.app = app
        self._get_request_id = get_request_id or (lambda: "")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or get_path(scope) in self.HEALTH_PATHS:
            await self.app(scope, receive, send)
            return

        headers = {name.lower(): value for name, value in scope.get("headers", [])}
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            content_length = 0

        rpc_method, tool, arg_keys = "", "", []
        inner_receive = receive
        if scope.get("method") == "POST" and 0 < content_length <= AUDIT_MAX_BODY:
            # Pre-read the (small, bounded) body so we can name the tool, then
            # replay the exact messages to the inner app.
            buffered = []
            while True:
                message = await receive()
                buffered.append(message)
                if message["type"] != "http.request" or not message.get("more_body", False):
                    break
            body = b"".join(m.get("body", b"") for m in buffered if m["type"] == "http.request")
            rpc_method, tool, arg_keys = _parse_jsonrpc(body)
            replay = iter(buffered)

            async def replay_receive():
                try:
                    return next(replay)
                except StopIteration:
                    return await receive()

            inner_receive = replay_receive

        status_holder = {"status": 0}

        async def send_with_status(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        start = time.monotonic()
        try:
            await self.app(scope, inner_receive, send_with_status)
        finally:
            line = {
                "request_id": self._get_request_id(),
                "person": current_person.get(),
                "client_ip": get_client_ip(scope),
                "path": scope.get("path", ""),
                "rpc_method": rpc_method,
                "tool": tool,
                "arg_keys": arg_keys,
                "status": status_holder["status"],
                "duration_ms": round((time.monotonic() - start) * 1000, 1),
            }
            logger.info(json.dumps(line, separators=(",", ":")))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_audit.py -v`
Expected: 6 passed

- [ ] **Step 5: Wire AuditLog into the chain**

In `src/postgres_mcp/server.py` imports:

```python
from .audit import AuditLogMiddleware
```

In the stack from Task 2 Step 5, wrap `CallerIdentityMiddleware(...)` with the audit layer (PersonAuth stays outside so `current_person` is set; CallerIdentity/RateLimiter stay inside so their 403/429 responses are audited):

```python
                    PersonAuthMiddleware(
                        AuditLogMiddleware(
                            CallerIdentityMiddleware(
                                RateLimiterMiddleware(
                                    HealthCheckMiddleware(
                                        SSEKeepAliveMiddleware(route_by_transport, interval=15)
                                    ),
                                    max_requests=int(os.environ.get("RATE_LIMIT_MAX_REQUESTS", "30")),
                                    window_seconds=int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60")),
                                )
                            ),
                            get_request_id=lambda: _request_id_var.get(""),
                        )
                    )
```

Update the stack comment block to insert `# 4. AuditLogMiddleware — one JSON audit line per request (LOOP-664 M1)` after the PersonAuth line (renumber the rest), and update the `logger.info("Applied middleware stack: …")` string to `"RequestID + CORS + IPAllowlist(+TokenBypass) + PersonAuth + AuditLog + CallerIdentity + RateLimiter + HealthCheck + SSEKeepAlive"`.

- [ ] **Step 6: Run the full unit suite**

Run: `uv run pytest tests/unit -v`
Expected: no new failures vs. baseline

- [ ] **Step 7: Commit**

```bash
git add src/postgres_mcp/audit.py src/postgres_mcp/server.py tests/unit/test_audit.py
git commit -m "feat(audit): LOOP-664 M1 — per-request JSON audit line (person, tool, arg keys, outcome)"
```

---

### Task 5: Token minting script, manifests, deploy.sh, runbook

**Files:**
- Create: `scripts/mint_person_token.py`
- Create: `docs/PERSON_AUTH.md`
- Modify: `eks/manifests/base/deployment-postgres-mcp.yaml` (env block, after the `AUTH_TOKEN` entry at line 86)
- Modify: `eks/deploy.sh` (person-tokens fetch + `postgres-mcp-secrets` creation around lines 185-192)

**Interfaces:**
- Consumes: env contract from Tasks 1-2 (`PERSON_AUTH_ENABLED`, `PERSON_TOKENS` JSON map of name → sha256 hex).
- Produces: k8s secret key `person-tokens` in `postgres-mcp-secrets`, sourced from AWS Secrets Manager secret `topmate/postgres-mcp/person-tokens`.

- [ ] **Step 1: Write the minting script**

```python
#!/usr/bin/env python3
# scripts/mint_person_token.py
"""Mint a personal bearer token for topmate-internal-mcp PersonAuth (LOOP-664).

Usage: python scripts/mint_person_token.py <person-name>

Prints the raw token ONCE (hand it to the person over a secure channel; it is
never stored) and the PERSON_TOKENS JSON fragment to merge into the AWS
Secrets Manager secret topmate/postgres-mcp/person-tokens.
"""

import hashlib
import secrets
import sys


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        print("usage: mint_person_token.py <person-name>", file=sys.stderr)
        return 1
    name = sys.argv[1].strip()
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    print(f"Raw token for {name} (share once, never store):\n  {token}\n")
    print(f'PERSON_TOKENS fragment:\n  "{name}": "{digest}"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Verify the script round-trips against the registry**

Run:
```bash
uv run python - <<'EOF'
import hashlib, json, subprocess, sys
out = subprocess.run([sys.executable, "scripts/mint_person_token.py", "smoke"], capture_output=True, text=True).stdout
token = out.splitlines()[1].strip()
digest = out.splitlines()[-1].split('"')[3]
from postgres_mcp.person_auth import PersonTokenRegistry
assert PersonTokenRegistry(raw=json.dumps({"smoke": digest})).verify(token) == "smoke"
print("mint -> verify round-trip OK")
EOF
```
Expected: `mint -> verify round-trip OK`

- [ ] **Step 3: Add env vars to the deployment manifest**

In `eks/manifests/base/deployment-postgres-mcp.yaml`, directly after the `AUTH_TOKEN` env entry (line 86 block), add:

```yaml
            # LOOP-664 M1: per-person auth. Flip to "true" only after tokens
            # are minted and distributed (see docs/PERSON_AUTH.md).
            - name: PERSON_AUTH_ENABLED
              value: "false"
            - name: PERSON_TOKENS
              valueFrom:
                secretKeyRef:
                  name: postgres-mcp-secrets
                  key: person-tokens
                  optional: true
```

(`optional: true` lets the pod start before the secret key exists, since the flag ships off.)

- [ ] **Step 4: Add the secret fetch to deploy.sh**

In `eks/deploy.sh`, after the `LOGIC_HUB_API_KEY` fetch block (~line 178-183) and before `kubectl create secret generic postgres-mcp-secrets` (~line 185), insert:

```bash
  PERSON_TOKENS_JSON=$(aws secretsmanager get-secret-value \
    --secret-id topmate/postgres-mcp/person-tokens \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) || {
    echo "  WARN: topmate/postgres-mcp/person-tokens not found — PersonAuth (LOOP-664 M1) cannot be enabled."
    echo "        Create it with: aws secretsmanager create-secret --name topmate/postgres-mcp/person-tokens \\"
    echo "          --secret-string '{\"<name>\": \"<sha256-hex>\"}'   (mint entries via scripts/mint_person_token.py)"
    PERSON_TOKENS_JSON=""
  }
```

and extend the secret creation to include the key (add one `--from-literal` line):

```bash
  kubectl create secret generic postgres-mcp-secrets \
    --from-literal=database-uri="${DATABASE_URI}" \
    --from-literal=logic-hub-url="${LOGIC_HUB_URL}" \
    --from-literal=logic-hub-api-key="${LOGIC_HUB_API_KEY}" \
    --from-literal=person-tokens="${PERSON_TOKENS_JSON}" \
    -n "${NAMESPACE}" \
    --dry-run=client -o yaml | kubectl apply -f -
```

- [ ] **Step 5: Write the rollout runbook**

```markdown
<!-- docs/PERSON_AUTH.md -->
# PersonAuth rollout (LOOP-664 M1)

Per-person bearer tokens replacing the shared AUTH_TOKEN for team callers.

## Config contract
| Env | Meaning |
|---|---|
| `PERSON_AUTH_ENABLED` | `"true"` = every non-health request needs a personal token. Anything else = middleware is a no-op (rollback path). |
| `PERSON_TOKENS` | JSON object `{"<name>": "<sha256 hex of raw token>"}`. Raw tokens are never stored server-side. |

## Rollout
1. Mint a token per teammate + one per service caller (staging EC2, CI):
   `python scripts/mint_person_token.py dharsan`
2. Merge all fragments into one JSON object and store it:
   `aws secretsmanager create-secret --name topmate/postgres-mcp/person-tokens --secret-string '{...}'`
   (or `put-secret-value` to rotate/add).
3. `./eks/deploy.sh` — refreshes the `postgres-mcp-secrets` k8s secret.
4. Flip `PERSON_AUTH_ENABLED` to `"true"` in `eks/manifests/base/deployment-postgres-mcp.yaml`, apply, verify:
   - no token → 401; personal token → 200; old shared AUTH_TOKEN alone → still passes the IP-allowlist bypass but NOT PersonAuth (401) — expected: humans move to personal tokens now, AUTH_TOKEN fully retires in M4.
5. Each caller adds `Authorization: Bearer <personal token>` in their MCP client config,
   AND switches to the streamable-HTTP endpoint — `https://mcp.gabbanext.run/postgres-mcp/mcp`
   (`"type": "http"` in `.mcp.json`) instead of `/sse`. `/mcp` is the promoted path from M1 on;
   `/sse` keeps working for stragglers until it is removed in M4.

## Rollback
Set `PERSON_AUTH_ENABLED` to `"false"` and re-apply the deployment. Exact pre-M1 behavior returns.

## Revoking one person
Remove their entry from the AWS secret, re-run deploy.sh, restart the deployment.

## Audit trail
Every request logs one JSON line on logger `postgres_mcp.audit` (person, tool,
arg keys, status, duration, request_id). Argument values are never logged.
```

- [ ] **Step 6: Validate manifests and script syntax**

Run: `bash -n eks/deploy.sh && kubectl kustomize eks/manifests/base >/dev/null && echo OK`
Expected: `OK` (if `kubectl` is unavailable locally, `python -c "import yaml,sys; yaml.safe_load_all(open('eks/manifests/base/deployment-postgres-mcp.yaml')) and print('OK')"`)

- [ ] **Step 7: Commit**

```bash
git add scripts/mint_person_token.py docs/PERSON_AUTH.md eks/manifests/base/deployment-postgres-mcp.yaml eks/deploy.sh
git commit -m "ops(auth): LOOP-664 M1 — person-token minting, manifest + deploy.sh wiring, rollout runbook"
```

---

### Task 6: Full verification sweep

**Files:**
- No new files; fixes only if the sweep finds regressions.

**Interfaces:**
- Consumes: everything from Tasks 1-5.
- Produces: a green M1 branch ready for PR `dharsan/loop-664-m1-perimeter` → base branch, titled `LOOP-664: M1 perimeter swap (person auth, keyed rate limiter, audit log)`.

- [ ] **Step 1: Full unit suite**

Run: `uv run pytest tests/unit -v`
Expected: all pass except (at most) the 2 pre-existing `tests/unit/explain` failures; record the exact counts in the PR description

- [ ] **Step 2: Lint + types**

Run: `uv run ruff check . && uv run pyright src/postgres_mcp/person_auth.py src/postgres_mcp/audit.py src/postgres_mcp/asgi_utils.py`
Expected: no errors

- [ ] **Step 3: Boot smoke test (flag off = legacy behavior)**

Run:
```bash
PERSON_AUTH_ENABLED=false DATABASE_URI="postgresql://localhost/nonexistent" \
  timeout 10 uv run python -m postgres_mcp --transport sse --sse-port 18099 2>&1 | head -20
```
Expected: startup log shows `Applied middleware stack: … PersonAuth + AuditLog …`; no crash from the new middleware (DB connection warnings are fine — no DB locally)

- [ ] **Step 4: Boot smoke test (flag on, fail-fast without tokens)**

Run:
```bash
PERSON_AUTH_ENABLED=true PERSON_TOKENS="" DATABASE_URI="postgresql://localhost/nonexistent" \
  timeout 10 uv run python -m postgres_mcp --transport sse --sse-port 18099 2>&1 | grep -i "refusing to start"
```
Expected: the ValueError message `refusing to start an effectively unauthenticated server` appears (process exits non-zero)

- [ ] **Step 5: Commit any fixes and push**

```bash
git push -u origin dharsan/loop-664-m1-perimeter
```

Then open the PR referencing LOOP-664 (link: https://linear.app/runyourloop/issue/LOOP-664).
