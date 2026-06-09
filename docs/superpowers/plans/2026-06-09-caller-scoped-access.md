# Caller-Scoped Access (postgres-mcp + topmate-db-mcp-server) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Honor a forwarded end-user identity so an expert only ever sees their own rows, while superadmin keeps full access and existing (header-less) callers behave byte-for-byte as today.

**Architecture:** A pure-ASGI `CallerIdentity` middleware on each server captures the forwarded identity into a `contextvar`. Transport auth gains a new path: `Authorization: Token <x>` is validated against galactus (`GET https://api.galactus.run/profile/`), and the **authoritative** identity (email/username/scope) is derived from that validated profile — headers are trusted only for superadmin act-as. postgres-mcp (all admin tools) 403s any non-superadmin caller. db-mcp-server enforces a mandatory per-creator row filter at one choke point in the AI orchestrator (sqlglot AST rewrite) **and** in every hand-written-SQL tool, resolves the creator's `username → user_user.id` once, and marks creator-safe tools with `_meta.loop/minScope`.

**Tech Stack:** Python 3.12, FastMCP (mcp 1.25 on postgres-mcp / 1.26 on db-mcp), Starlette/ASGI, httpx, sqlglot (new dep on db-mcp), pytest + pytest-asyncio.

**Source of truth for decisions (confirmed with owner):**
1. Full enforcement (NL + aggregate tools too), not just structured-param tools.
2. New `Authorization: Token <x>` validator against galactus `/profile/`.
3. Loop connects over Streamable HTTP (`/db-mcp/mcp`, `/postgres-mcp/mcp`).

**TRUST MODEL (reconciled with `ryl-base-platform/docs/MCP_INTEGRATION_CONTRACT.md`).** The contract says Loop is the trusted gateway: it validates the token (401s before reaching us) and resolves scope — **including superadmin via a Loop session, not galactus** (`/profile/` only yields expert/seeker). The contract also shows Loop registering an MCP with a static `Authorization: Bearer <token>` for transport auth. So identity resolution is **two-tier** (`caller_identity.resolve_identity(headers, transport_trusted, superadmin_emails)`):

1. **No `X-User-Scope` header ⇒ legacy ⇒ byte-for-byte unchanged** (hard rule #1). Internal db→pg calls, ops, Claude.ai OAuth connector — untouched.
2. **Trusted transport** (`is_transport_trusted`: request carries `Authorization: Bearer <AUTH_TOKEN>` — our shared secret, constant-time compared — or a credential in `SUPERADMIN_TOKENS`) ⇒ **trust the forwarded `X-User-*` headers verbatim, including `superadmin`**. This is the contract's gateway-trust model and the likely prod path (only Loop/internal hold the shared secret).
3. **Untrusted transport with `Authorization: Token <x>`** (an end-user token, directly exposed) ⇒ galactus-validate ourselves; derive `expert`/`seeker` from the profile; `superadmin` only if the validated email ∈ `SUPERADMIN_EMAILS`; a non-superadmin can only ever be scoped to **their own** username (anti-impersonation: a mismatched `X-User-Username` is forced back to the token owner).
4. **`X-User-Scope` present but neither trusted nor a valid Token ⇒ `INVALID` (401).**

> ⚠️ A static `Bearer` that is *not* our `AUTH_TOKEN` must **never** be galactus-validated as a user token (it would 401 every such call). `is_transport_trusted` is checked first; only the `Token` scheme hits galactus. (Implemented + regression-tested in postgres-mcp A1/A2.)

**Contract compliance also requires:** every scoped **read** tool carries `annotations={readOnlyHint:true}` (else Loop gates it for needless human approval); tool-level `_meta={"loop/minScope":...}`; `tools/list`/`tools/call` speak MCP `2024-11-05` (SDK negotiates down — verify in B13). FastMCP input schemas are already non-strict (no `additionalProperties:false`), so Loop/ChatGPT injecting a `_meta` arg won't be rejected — explicit `_meta` property is optional ChatGPT hardening.

---

## Definitions & shared contract (both repos)

Caller identity contextvar payload (`dict`):
```python
{
  "scope":    "superadmin" | "expert" | "seeker" | "public" | None,  # None = legacy
  "username": str | None,   # effective creator username for filtering (token-derived for experts; act-as target for superadmin)
  "email":    str | None,
  "raw_scope_header": str | None,  # the literal X-User-Scope value, for logging/audit
}
```

`galactus` validation contract:
```
GET https://api.galactus.run/profile/
  Authorization: Token <x>
  Accept: application/json
200 -> {"id": int, "email": str, "username": str, "primary_user_type": "expert"|"follower", "service_added": bool, "slots_added": bool, ...}
401 -> {"detail": "Invalid token."}     # invalid/expired/revoked/inactive
```
Scope derivation from a 200 profile:
```python
def _scope_from_profile(p: dict) -> str:
    if p.get("primary_user_type") == "expert" or p.get("service_added") or p.get("slots_added"):
        return "expert"
    return "seeker"
```
Validation client behavior (mirror `ryl-base-platform/src/loop_platform/auth/principal.py`): httpx `timeout=8.0`, in-process cache keyed by token with 300s TTL caching **both** hits and misses; any non-200 / network error ⇒ `None` (deny).

New env vars (both repos):
| Env var | Default | Meaning |
|---|---|---|
| `GALACTUS_PROFILE_URL` | `https://api.galactus.run/profile/` | token validation endpoint |
| `SUPERADMIN_EMAILS` | `""` | comma-separated emails that may use superadmin scope / act-as |
| `SUPERADMIN_TOKENS` | `""` | comma-separated Knox tokens that are always superadmin (service callers) |
| `CALLER_SCOPE_ENABLED` | `"true"` | master kill-switch; when `false`, middleware is a pure pass-through |

---

# REPO A — postgres-mcp (`/Users/dharsankumar/Documents/GitHub/postgres-mcp`)

All postgres-mcp tools are DB-admin (raw SQL / DB internals) — none are per-creator-scopable. Policy: capture identity; if an authenticated caller's **effective** scope is anything other than `superadmin` (or legacy/None), 403 the whole request. This is enforced at middleware level (no contextvar→tool propagation needed, works on SSE and Streamable HTTP alike).

### Task A1: Galactus token validator + identity resolver module

**Files:**
- Create: `src/postgres_mcp/caller_identity.py`
- Test: `tests/unit/test_caller_identity.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_caller_identity.py
import pytest
from postgres_mcp import caller_identity as ci


def test_resolve_legacy_when_no_scope_header():
    headers = {b"authorization": b"Bearer abc"}
    ident = ci.resolve_identity(headers, validate_token=lambda t: None)
    assert ident["scope"] is None  # legacy => unchanged behavior


def test_expert_scope_derived_from_profile_not_header():
    # Header claims superadmin, but token profile is an expert and not in allowlist => downgraded to expert
    headers = {
        b"x-user-scope": b"superadmin",
        b"x-user-username": b"attacker",
        b"authorization": b"Token good",
    }
    profile = {"id": 7, "email": "a@topmate.io", "username": "ajay_shenoy", "primary_user_type": "expert"}
    ident = ci.resolve_identity(headers, validate_token=lambda t: profile, superadmin_emails=set())
    assert ident["scope"] == "expert"
    assert ident["username"] == "ajay_shenoy"  # token-derived, header ignored


def test_superadmin_only_via_allowlist_and_can_act_as():
    headers = {
        b"x-user-scope": b"superadmin",
        b"x-user-email": b"target@topmate.io",
        b"x-user-username": b"target_user",
        b"authorization": b"Token admintok",
    }
    profile = {"id": 1, "email": "admin@topmate.io", "username": "admin", "primary_user_type": "follower"}
    ident = ci.resolve_identity(
        headers, validate_token=lambda t: profile, superadmin_emails={"admin@topmate.io"}
    )
    assert ident["scope"] == "superadmin"
    assert ident["username"] == "target_user"  # act-as target honored for superadmin


def test_invalid_token_with_scope_header_is_unauthenticated():
    headers = {b"x-user-scope": b"expert", b"authorization": b"Token bad"}
    ident = ci.resolve_identity(headers, validate_token=lambda t: None)
    assert ident["scope"] == "__invalid__"  # caller meant to be scoped but token failed
```

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/python -m pytest tests/unit/test_caller_identity.py -v`
Expected: FAIL (module/functions missing).

- [ ] **Step 3: Implement the module**

```python
# src/postgres_mcp/caller_identity.py
"""Forwarded end-user identity capture + galactus token validation.

Pure helpers (no I/O in resolve_identity — token validation is injected) so they
are trivially unit-testable. The ASGI middleware in server.py wires the real
galactus validator in.
"""
from __future__ import annotations

import contextvars
import logging
import os
import threading
import time
from typing import Callable

import httpx

logger = logging.getLogger(__name__)

caller_ctx: contextvars.ContextVar[dict] = contextvars.ContextVar("caller", default={})

INVALID = "__invalid__"  # sentinel: caller sent X-User-Scope but token validation failed

_GALACTUS_URL = os.getenv("GALACTUS_PROFILE_URL", "https://api.galactus.run/profile/")
_TTL = 300.0
_cache: dict[str, tuple[dict | None, float]] = {}
_cache_lock = threading.Lock()


def _scope_from_profile(p: dict) -> str:
    if p.get("primary_user_type") == "expert" or p.get("service_added") or p.get("slots_added"):
        return "expert"
    return "seeker"


def validate_token(token: str) -> dict | None:
    """Validate a Topmate Knox token against galactus /profile/. Cached 300s (hits+misses)."""
    if not token:
        return None
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(token)
        if hit and (now - hit[1]) < _TTL:
            return hit[0]
    profile: dict | None = None
    try:
        resp = httpx.get(
            _GALACTUS_URL,
            headers={"Authorization": f"Token {token}", "Accept": "application/json"},
            timeout=8.0,
        )
        if resp.status_code == 200:
            profile = resp.json()
    except Exception as e:  # network/parse error => deny
        logger.warning("galactus validation error: %s", e)
        profile = None
    with _cache_lock:
        _cache[token] = (profile, now)
    return profile


def _bearer_token(headers: dict[bytes, bytes]) -> str | None:
    auth = headers.get(b"authorization", b"").decode("latin-1")
    low = auth.lower()
    if low.startswith("token "):
        return auth[6:].strip()
    if low.startswith("bearer "):
        return auth[7:].strip()
    return None


def resolve_identity(
    headers: dict[bytes, bytes],
    *,
    validate_token: Callable[[str], dict | None] = validate_token,
    superadmin_emails: set[str] | None = None,
    superadmin_tokens: set[str] | None = None,
) -> dict:
    """Return the caller-identity payload. Pure given the injected validator."""
    superadmin_emails = superadmin_emails or set()
    superadmin_tokens = superadmin_tokens or set()
    raw_scope = headers.get(b"x-user-scope")
    raw_scope_s = raw_scope.decode("latin-1").strip() if raw_scope else None

    # Hard rule #1: no X-User-Scope header => legacy => unchanged behavior.
    if not raw_scope_s:
        return {"scope": None, "username": None, "email": None, "raw_scope_header": None}

    token = _bearer_token(headers)
    hdr_username = (headers.get(b"x-user-username") or b"").decode("latin-1").strip() or None
    hdr_email = (headers.get(b"x-user-email") or b"").decode("latin-1").strip() or None

    # Service superadmin token (e.g. Loop's own backend) — trusted, may act-as.
    if token and token in superadmin_tokens:
        return {"scope": "superadmin", "username": hdr_username, "email": hdr_email,
                "raw_scope_header": raw_scope_s}

    profile = validate_token(token) if token else None
    if profile is None:
        return {"scope": INVALID, "username": None, "email": hdr_email, "raw_scope_header": raw_scope_s}

    caller_email = (profile.get("email") or "").strip().lower()
    if caller_email and caller_email in {e.strip().lower() for e in superadmin_emails}:
        # Real superadmin — honor act-as target from headers.
        return {"scope": "superadmin", "username": hdr_username, "email": hdr_email or caller_email,
                "raw_scope_header": raw_scope_s}

    # Non-superadmin: identity is token-derived, headers cannot elevate.
    derived = _scope_from_profile(profile)
    return {"scope": derived, "username": profile.get("username"), "email": profile.get("email"),
            "raw_scope_header": raw_scope_s}


def superadmin_emails_from_env() -> set[str]:
    return {e.strip() for e in os.getenv("SUPERADMIN_EMAILS", "").split(",") if e.strip()}


def superadmin_tokens_from_env() -> set[str]:
    return {t.strip() for t in os.getenv("SUPERADMIN_TOKENS", "").split(",") if t.strip()}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_caller_identity.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit** (see "Git & Jira" — branch + Jira key first)

```bash
git add src/postgres_mcp/caller_identity.py tests/unit/test_caller_identity.py
git commit -m "<JIRA>: add caller identity + galactus token validator (postgres-mcp)"
```

### Task A2: CallerIdentity ASGI middleware + non-superadmin 403

**Files:**
- Modify: `src/postgres_mcp/server.py` (add middleware class near the other middleware ~line 863; wire into stack ~line 1261)
- Test: `tests/unit/test_caller_identity_middleware.py`

- [ ] **Step 1: Write failing test** (ASGI-level, using a stub inner app)

```python
# tests/unit/test_caller_identity_middleware.py
import pytest
from postgres_mcp.server import CallerIdentityMiddleware


class _Recorder:
    def __init__(self): self.called = False
    async def __call__(self, scope, receive, send):
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _scope(headers):
    return {"type": "http", "path": "/postgres-mcp/mcp", "method": "POST",
            "headers": [(k, v) for k, v in headers.items()]}


@pytest.mark.asyncio
async def test_legacy_passes_through(monkeypatch):
    inner = _Recorder()
    mw = CallerIdentityMiddleware(inner)
    sent = []
    await mw(_scope({}), None, lambda m: sent.append(m) or _noop())
    assert inner.called


@pytest.mark.asyncio
async def test_expert_scope_is_403(monkeypatch):
    import postgres_mcp.caller_identity as ci
    monkeypatch.setattr(ci, "validate_token", lambda t: {"username": "x", "email": "x@t.io", "primary_user_type": "expert"})
    inner = _Recorder()
    mw = CallerIdentityMiddleware(inner)
    statuses = []
    async def send(m):
        if m["type"] == "http.response.start": statuses.append(m["status"])
    await mw(_scope({b"x-user-scope": b"expert", b"authorization": b"Token good"}), None, send)
    assert statuses == [403]
    assert not inner.called


async def _noop(): return None
```

- [ ] **Step 2: Run, verify fail.** Run: `.venv/bin/python -m pytest tests/unit/test_caller_identity_middleware.py -v` → FAIL (class missing).

- [ ] **Step 3: Add the middleware class to `server.py`** (after `IPAllowlistMiddleware`, before `SSEKeepAliveMiddleware`):

```python
class CallerIdentityMiddleware:
    """Capture forwarded end-user identity and gate admin-only tools.

    * No ``X-User-Scope`` header  -> legacy caller -> pass through unchanged.
    * Authenticated superadmin     -> pass through (full access).
    * Any other resolved scope     -> 403 (all postgres-mcp tools are admin-only).
    * ``X-User-Scope`` present but token invalid -> 401.

    Disabled entirely when CALLER_SCOPE_ENABLED=false.
    """

    HEALTH_PATHS = {"/", "/health", "/healthz"}

    def __init__(self, app):
        self.app = app
        self.enabled = os.getenv("CALLER_SCOPE_ENABLED", "true").lower() != "false"
        self._sa_emails = caller_identity.superadmin_emails_from_env()
        self._sa_tokens = caller_identity.superadmin_tokens_from_env()

    def _get_path(self, scope):
        path = scope.get("path", "")
        for prefix in ("/postgres-mcp", "/db-mcp", "/instagram-mcp"):
            if path.startswith(prefix):
                return path[len(prefix):] or "/"
        return path

    async def _deny(self, send, status, err, msg):
        await send({"type": "http.response.start", "status": status,
                    "headers": [[b"content-type", b"application/json"]]})
        await send({"type": "http.response.body",
                    "body": f'{{"error":"{err}","message":"{msg}"}}'.encode()})

    async def __call__(self, scope, receive, send):
        if not self.enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if self._get_path(scope) in self.HEALTH_PATHS:
            await self.app(scope, receive, send)
            return
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        ident = caller_identity.resolve_identity(
            headers, superadmin_emails=self._sa_emails, superadmin_tokens=self._sa_tokens,
        )
        token = caller_identity.caller_ctx.set(ident)
        try:
            sc = ident["scope"]
            if sc is None or sc == "superadmin":
                await self.app(scope, receive, send)  # legacy or admin => unchanged
                return
            if sc == caller_identity.INVALID:
                logger.warning("postgres-mcp: scoped caller with invalid token")
                await self._deny(send, 401, "unauthorized", "Invalid end-user token")
                return
            logger.warning("postgres-mcp: rejecting non-superadmin scope=%s on admin server", sc)
            await self._deny(send, 403, "forbidden",
                             "postgres-mcp tools are superadmin-only")
            return
        finally:
            caller_identity.caller_ctx.reset(token)
```

Add import at top of `server.py`: `from . import caller_identity`.

- [ ] **Step 4: Wire into the middleware stack.** Modify the `wrapped_app = ...` block (~line 1261) to insert `CallerIdentityMiddleware` just inside `IPAllowlistMiddleware` (so auth/IP gating runs first, then identity gating):

```python
wrapped_app = RequestIDMiddleware(
    CORSMiddleware(
        IPAllowlistMiddleware(
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
```
Update the log line to mention `+ CallerIdentity`.

- [ ] **Step 5: Run tests, verify pass.** `.venv/bin/python -m pytest tests/unit/ -v` → PASS.

- [ ] **Step 6: Commit.**
```bash
git add src/postgres_mcp/server.py tests/unit/test_caller_identity_middleware.py
git commit -m "<JIRA>: 403 non-superadmin callers on postgres-mcp admin tools"
```

### Task A3: postgres-mcp deployment env

**Files:** Modify `eks/manifests/base/deployment-postgres-mcp.yaml`

- [ ] **Step 1:** Add env vars to the container `env:` list:
```yaml
            - name: GALACTUS_PROFILE_URL
              value: "https://api.galactus.run/profile/"
            - name: SUPERADMIN_EMAILS
              valueFrom:
                secretKeyRef:
                  name: topmate-bi-secrets
                  key: superadmin-emails
                  optional: true
            - name: SUPERADMIN_TOKENS
              valueFrom:
                secretKeyRef:
                  name: topmate-bi-secrets
                  key: superadmin-tokens
                  optional: true
            - name: CALLER_SCOPE_ENABLED
              value: "true"
```
- [ ] **Step 2:** Add `httpx` to postgres-mcp deps if not present. Check `pyproject.toml`; `mcp[cli]` pulls httpx transitively — verify with `.venv/bin/python -c "import httpx"`. If it fails, add `"httpx>=0.28"` to `dependencies` and `uv lock`.
- [ ] **Step 3: Commit.** `git add eks/... pyproject.toml uv.lock && git commit -m "<JIRA>: postgres-mcp galactus + superadmin env"`

---

# REPO B — topmate-db-mcp-server (`/Users/dharsankumar/Documents/GitHub/topmate-db-mcp-server`)

This is where real per-creator scoping lives. Work order: identity module → auth-gate integration → username→id resolver → SQL scope guard → orchestrator threading + cache key → per-category tool enforcement + `_meta` markers → deployment → e2e.

**Contract rule applied throughout B7–B9:** every tool we expose to experts is a read, so it MUST carry `annotations=ToolAnnotations(readOnlyHint=True)` **in addition to** `meta={"loop/minScope":"expert"}` — `from mcp.types import ToolAnnotations`, e.g. `@mcp.tool(..., annotations=ToolAnnotations(readOnlyHint=True), meta={"loop/minScope":"expert"})`. Without `readOnlyHint` Loop treats the tool as a reversible write and forces a human-approval gate (contract §5). Mirror the `caller_identity` two-tier model + `is_transport_trusted` exactly as implemented in postgres-mcp `src/postgres_mcp/caller_identity.py` (the canonical reference).

### Task B1: Caller identity module (contextvar + galactus validator + enforce_scope)

**Files:**
- Create: `src/topmate_mcp/middleware/caller_identity.py`
- Modify: `src/topmate_mcp/config.py` (add `galactus_profile_url`, `superadmin_emails`, `superadmin_tokens`, `caller_scope_enabled`)
- Modify: `src/topmate_mcp/middleware/__init__.py` (export `CallerIdentityMiddleware`)
- Test: `tests/unit/test_caller_identity.py`

- [ ] **Step 1: Add settings to `config.py`** (after the Security block ~line 162):
```python
    # Caller-scoped access (Loop end-user identity forwarding)
    galactus_profile_url: str = Field(default="https://api.galactus.run/profile/", alias="GALACTUS_PROFILE_URL")
    superadmin_emails: str = Field(default="", alias="SUPERADMIN_EMAILS")
    superadmin_tokens: str = Field(default="", alias="SUPERADMIN_TOKENS")
    caller_scope_enabled: bool = Field(default=True, alias="CALLER_SCOPE_ENABLED")
```

- [ ] **Step 2: Write failing tests** mirroring postgres-mcp A1 (`resolve_identity` legacy/expert/superadmin/invalid) PLUS:
```python
def test_enforce_scope_legacy_returns_none():
    from topmate_mcp.middleware import caller_identity as ci
    ci.caller_ctx.set({"scope": None, "username": None})
    assert ci.enforce_scope() is None  # unrestricted (legacy/admin)

def test_enforce_scope_expert_returns_username():
    from topmate_mcp.middleware import caller_identity as ci
    ci.caller_ctx.set({"scope": "expert", "username": "ajay_shenoy"})
    assert ci.enforce_scope() == "ajay_shenoy"

def test_enforce_scope_expert_without_username_raises():
    from topmate_mcp.middleware import caller_identity as ci
    ci.caller_ctx.set({"scope": "expert", "username": None})
    with pytest.raises(PermissionError):
        ci.enforce_scope()

def test_enforce_scope_seeker_rejected_for_creator_tool():
    from topmate_mcp.middleware import caller_identity as ci
    ci.caller_ctx.set({"scope": "seeker", "username": None})
    with pytest.raises(PermissionError):
        ci.enforce_scope()
```

- [ ] **Step 3: Implement `caller_identity.py`.** Copy the postgres-mcp `caller_identity.py` (Task A1 Step 3) — same `resolve_identity` / `validate_token` / `_scope_from_profile` / `caller_ctx` / `INVALID` — but read config from `get_settings()` instead of `os.getenv`, and add the scope helpers + middleware-free helpers:

```python
def caller_scope() -> tuple[str | None, str | None]:
    c = caller_ctx.get() or {}
    return c.get("scope"), c.get("username")


def enforce_scope(*, allow_seeker: bool = False) -> str | None:
    """Return the creator-username to filter by, or None for unrestricted.

    None  -> superadmin or legacy (no header)  -> run query as-is.
    str   -> expert: MANDATORY WHERE creator = <username>.
    raises PermissionError otherwise (seeker/public/invalid/expert-without-username).
    """
    scope, username = caller_scope()
    if scope is None or scope == "superadmin":
        return None
    if scope == "expert":
        if not username:
            raise PermissionError("expert scope requires a resolved username")
        return username
    if scope == "seeker" and allow_seeker:
        return username  # seeker tools (if any) scope to self
    raise PermissionError(f"scope '{scope}' is not permitted for this tool")


def is_unrestricted() -> bool:
    scope, _ = caller_scope()
    return scope is None or scope == "superadmin"
```
Add the `CallerIdentityMiddleware` ASGI class here too (sets `caller_ctx` from headers using `get_settings()` superadmin sets; **does NOT 403** — db-mcp does per-tool enforcement, not blanket reject; but it DOES 401 when `scope == INVALID`). It must be a pure-ASGI middleware so the contextvar propagates into the tool coroutine on the stateless Streamable-HTTP path.

```python
class CallerIdentityMiddleware:
    HEALTH_PATHS = frozenset({"/", "/health", "/healthz"})

    def __init__(self, app):
        self.app = app
        s = get_settings()
        self.enabled = s.caller_scope_enabled
        self._auth_token = (s.auth_token or "").strip()
        self._sa_emails = {e.strip().lower() for e in s.superadmin_emails.split(",") if e.strip()}
        self._sa_tokens = {t.strip() for t in s.superadmin_tokens.split(",") if t.strip()}

    @staticmethod
    def _strip(path):
        for p in ("/bi-mcp", "/db-mcp"):
            if path.startswith(p):
                return path[len(p):] or "/"
        return path

    async def __call__(self, scope, receive, send):
        if not self.enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if self._strip(scope.get("path", "")) in self.HEALTH_PATHS:
            await self.app(scope, receive, send)
            return
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        transport_trusted = is_transport_trusted(
            headers, auth_token=self._auth_token, superadmin_tokens=self._sa_tokens
        )
        ident = resolve_identity(headers, transport_trusted=transport_trusted,
                                 superadmin_emails=self._sa_emails)
        if ident["scope"] == INVALID:
            await send({"type": "http.response.start", "status": 401,
                        "headers": [[b"content-type", b"application/json"]]})
            await send({"type": "http.response.body",
                        "body": b'{"error":"unauthorized","message":"Invalid end-user token"}'})
            return
        tok = caller_ctx.set(ident)
        try:
            await self.app(scope, receive, send)
        finally:
            caller_ctx.reset(tok)
```

- [ ] **Step 4: Export** from `middleware/__init__.py`: add `from topmate_mcp.middleware.caller_identity import CallerIdentityMiddleware` and include in `__all__`.

- [ ] **Step 5: Run** `.venv/bin/python -m pytest tests/unit/test_caller_identity.py -v` → PASS.

- [ ] **Step 6: Commit.** `<JIRA>: caller identity module + enforce_scope (db-mcp)`

### Task B2: Wire CallerIdentity into the middleware stack (contextvar reaches tools)

**Files:** Modify `src/topmate_mcp/server.py` (`build_middleware_stack`, ~line 290)

- [ ] **Step 1:** Add `CallerIdentityMiddleware` to the import block (line 269) and wrap it **innermost** — directly around `app` before `SSEKeepAliveMiddleware` — so the contextvar is set within the same task that the stateless Streamable-HTTP transport uses to run the tool:
```python
        AcceptHeaderMiddleware,
        CallerIdentityMiddleware,
        HealthCheckMiddleware,
        ...
    )
    # 7. Innermost: caller identity (sets contextvar consumed by tools)
    app = CallerIdentityMiddleware(app)
    # 6. SSE keep-alive
    app = SSEKeepAliveMiddleware(app, interval=15)
    ...
```
Rationale: `CallerIdentity` must run **after** IPAllowlist's auth gate but its contextvar must still be live when the tool executes. Because db-mcp runs `stateless_http=True`, the tool coroutine executes within the POST `/mcp` request task, so setting the contextvar in any pure-ASGI middlewrap that wraps the transport app and `await`s it keeps it live. Innermost placement is simplest and avoids other middlewares clearing it.

- [ ] **Step 2: Integration test** — `tests/integration/test_scope_propagation.py`: build the app via `build_transport_app` + `CallerIdentityMiddleware`, register a tiny probe tool that returns `caller_identity.caller_ctx.get()`, POST a `tools/call` to `/mcp` with `X-User-Scope: expert` + a stubbed-valid token (monkeypatch `validate_token`), assert the tool saw `scope=expert`. (This is the critical proof that contextvar propagates on Streamable HTTP.)

- [ ] **Step 3: Run** the integration test → PASS. If it FAILS (contextvar empty in tool), fall back to reading identity from `request` via FastMCP `Context` — see "Risk: contextvar propagation" below. Do not proceed to B5+ until this passes.

- [ ] **Step 4: Commit.** `<JIRA>: wire CallerIdentity into db-mcp stack`

### Task B3: Accept `Authorization: Token <x>` at the auth gate (IPAllowlist)

**Files:** Modify `src/topmate_mcp/middleware/ip_allowlist.py`

- [ ] **Step 1: Write failing test** `tests/unit/test_ip_allowlist_token.py`: a request from a non-allowlisted IP with `Authorization: Token good` (monkeypatch galactus validator to return a profile) passes; with `Token bad` it 401/403s.

- [ ] **Step 2: Implement.** In `_has_valid_token` (line 121), after the static-token and JWT checks, add a galactus check for `Token`-scheme creds:
```python
        # 3) Try galactus end-user token (Authorization: Token <x>)
        from topmate_mcp.middleware.caller_identity import validate_token as _gv
        raw = self._get_token_header_raw(scope)   # new helper: returns ("token"|"bearer", value)
        if raw and raw[0] == "token" and _gv(raw[1]) is not None:
            return True
```
Add `_get_token_header_raw` that returns the scheme + value (since `_get_bearer_token` only handles Bearer). Keep all existing paths intact (IP, static Bearer, JWT, cached OAuth token).

- [ ] **Step 3: Run, pass. Commit.** `<JIRA>: accept galactus Token auth at db-mcp gate`

### Task B4: `username → expert_id` resolver (cached)

**Files:**
- Create: `src/topmate_mcp/clients/creator_resolver.py`
- Test: `tests/unit/test_creator_resolver.py`

The BI schema keys on integer `user_user.id` (aliased `expert_id`/`user_id`), not username. Resolve once, cache.

- [ ] **Step 1: Failing test** — `resolve_expert_id("ajay_shenoy")` calls `postgres.execute_sql("SELECT id FROM user_user WHERE username = '...' ...")` (parameterised-safe: username validated against `^[A-Za-z0-9_.@+-]{1,150}$`, Django username charset) and returns the int; caches; returns `None` for unknown.

- [ ] **Step 2: Implement.**
```python
# src/topmate_mcp/clients/creator_resolver.py
import re, time, logging
logger = logging.getLogger(__name__)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@+-]{1,150}$")  # Django AbstractUser charset
_cache: dict[str, tuple[int | None, float]] = {}
_TTL = 600.0

class CreatorResolver:
    def __init__(self, postgres_client):
        self._pg = postgres_client

    async def resolve_expert_id(self, username: str) -> int | None:
        if not username or not _USERNAME_RE.match(username):
            raise PermissionError("invalid creator username")
        now = time.monotonic()
        hit = _cache.get(username)
        if hit and now - hit[1] < _TTL:
            return hit[0]
        # username is regex-validated to a safe charset -> safe to inline
        out = await self._pg.execute_sql(
            f"SELECT id FROM user_user WHERE username = '{username}' LIMIT 1"
        )
        eid = _parse_first_int(out)
        _cache[username] = (eid, now)
        return eid
```
`_parse_first_int` extracts the integer from the postgres-mcp text response (the response is `format_text_response(list[dict])`). Implement a tolerant parser + test it against a sample `[{'id': 12345}]` string.

- [ ] **Step 3: Wire** a `CreatorResolver` into `initialize_clients` (server.py) as `clients["creator_resolver"]` (depends on `clients["postgres"]`).

- [ ] **Step 4: Run, pass. Commit.** `<JIRA>: username->expert_id resolver`

### Task B5: SQL scope guard (sqlglot AST WHERE-injection)

**Files:**
- Modify: `pyproject.toml` (add `"sqlglot>=25.0"`), then `uv lock`
- Create: `src/topmate_mcp/ai/sql_scope_guard.py`
- Test: `tests/unit/test_sql_scope_guard.py`

- [ ] **Step 1: Failing tests** covering:
  - simple `SELECT ... FROM booking_booking` → gets `WHERE expert_id = <id>` (or `AND` if WHERE exists).
  - `services_service` reference → `user_id = <id>` (NOT `expert_id`).
  - `all_bookings_new` → `expert_id = <id>`.
  - join `booking_booking b JOIN user_user u ON ...` → predicate added on the aliased booking table.
  - CTE: `WITH x AS (SELECT * FROM booking_booking) SELECT * FROM x` → predicate injected **inside** the CTE.
  - `UNION`: predicate injected into **every** leg.
  - non-SELECT (`UPDATE`, `INSERT`, multiple statements) → raises `ScopeViolation`.
  - a query touching **no** scoped table (e.g. `SELECT 1`, `SELECT * FROM services_servicetype`) → for an expert scope, raises `ScopeViolation` ("query cannot be constrained to one creator") per brief rule #3.

- [ ] **Step 2: Implement** using sqlglot. Map of table→creator column:
```python
# src/topmate_mcp/ai/sql_scope_guard.py
import sqlglot
from sqlglot import exp

class ScopeViolation(Exception): ...

# physical creator column per scoped table (lowercased)
_CREATOR_COL = {
    "booking_booking": "expert_id",
    "all_bookings_new": "expert_id",
    "services_service": "user_id",
    "user_user": "id",
    "payments_order": "expert_id",   # confirm against schema_rag before enabling
}

def scope_sql(sql: str, expert_id: int, *, dialect: str = "postgres") -> str:
    try:
        statements = sqlglot.parse(sql, read=dialect)
    except Exception as e:
        raise ScopeViolation(f"unparseable SQL: {e}")
    if len(statements) != 1 or statements[0] is None:
        raise ScopeViolation("only a single statement is allowed for scoped callers")
    tree = statements[0]
    if not isinstance(tree, (exp.Select, exp.Union, exp.With)):
        raise ScopeViolation("only SELECT is allowed for scoped callers")

    touched = 0
    for select in tree.find_all(exp.Select):
        # find scoped tables in THIS select's FROM/JOINs
        for table in select.find_all(exp.Table):
            name = (table.name or "").lower()
            if name in _CREATOR_COL:
                col = _CREATOR_COL[name]
                alias = table.alias_or_name
                pred = exp.condition(f"{alias}.{col} = {int(expert_id)}")
                select.where(pred, copy=False)
                touched += 1
    if touched == 0:
        raise ScopeViolation("query does not reference any creator-scoped table")
    return tree.sql(dialect=dialect)
```
Note: `exp.condition` builds a parsed predicate; `select.where(..., copy=False)` ANDs it into each SELECT's WHERE. Verify with tests that subquery/CTE selects each get the predicate. Adjust table→column map against `schema_rag.py` / `prompts.py` (confirm `all_bookings_new` creator column; the agent noted it differs from `booking_booking` — verify live: `kubectl exec` into postgres-mcp or query via the resolver). **Block until the `all_bookings_new` column is confirmed.**

- [ ] **Step 3: Run, pass. Commit.** `<JIRA>: sqlglot SQL scope guard`

### Task B6: Orchestrator creator_id threading + cache key + prompt rule

**Files:** Modify `src/topmate_mcp/ai/orchestrator.py`, `src/topmate_mcp/ai/prompts.py`

- [ ] **Step 1: Failing test** `tests/unit/test_orchestrator_scope.py`: call `orchestrator._generate_sql(question, context, creator_id=42)` with a stub LLM returning `SELECT * FROM booking_booking` → returned SQL contains `expert_id = 42`; with `creator_id=None` → unchanged. Cache key differs by creator_id.

- [ ] **Step 2: Implement.**
  - Add `creator_id: int | None = None` param to `process_question`, `process_question_fast`, `generate_sql`, `_generate_sql`, `_fetch_data` (orchestrator.py lines ~98, 216, 310, 432, 475).
  - Inside `_generate_sql`, **after** the LLM returns `sql` and **before** the cache write (line ~471): if `creator_id is not None: sql = scope_sql(sql, creator_id)` (import from `sql_scope_guard`). On `ScopeViolation`, raise a clean error the tool converts to a user message.
  - Add `creator_id` to both `_cache_key` callsites (lines ~401, 428, 437, 471) so experts never collide on cached SQL/results: `self._cache_key(question, context, str(creator_id))`.
  - In `prompts.py` `SYSTEM_PROMPT_SQL_GENERATION` add a defense-in-depth rule: "If a creator filter is provided, every query MUST include it; never query across creators." (The guarantee is the AST guard, not this.)

- [ ] **Step 3: Run, pass. Commit.** `<JIRA>: thread creator_id through orchestrator + cache key + guard`

### Task B7: Intelligence tools — mandatory creator scope + remove leak fallbacks + `_meta`

**Files:** Modify `src/topmate_mcp/tools/intelligence/__init__.py`

For `expert_intelligence`, `follower_intelligence`, `service_intelligence`:
- [ ] **Step 1: Failing tests** `tests/unit/test_intelligence_scope.py`: with `caller_ctx={scope:expert, username:ajay}` and a resolver stubbed to map ajay→42, the tool ignores any caller-supplied `expert_id` and uses 42; the all-expert/top-20 fallback branch is NOT taken; with `scope:superadmin` behavior is unchanged (caller `expert_id`/fallbacks allowed).
- [ ] **Step 2: Implement** a shared helper at tool entry:
```python
from topmate_mcp.middleware.caller_identity import enforce_scope, is_unrestricted
async def _effective_expert_id(clients, caller_expert_id):
    username = enforce_scope()          # None (admin) | str (expert) | raises
    if username is None:
        return caller_expert_id         # superadmin/legacy: honor caller arg / fallbacks
    eid = await clients["creator_resolver"].resolve_expert_id(username)
    if eid is None:
        raise PermissionError("creator not found")
    return eid
```
Then in each tool: `eid = await _effective_expert_id(clients, expert_id)`; when `not is_unrestricted()` force the `if expert_id:` scoped branch and **skip** the all-expert leaderboard/top-20 `else` branch (raise or return "scope required" — but since eid is always set for experts, the scoped branch always runs). Sanitize the free-text `question` so it can't widen scope: the SQL is hardcoded around `eid`, and any NL analysis is performed only on the already-scoped rows.
- [ ] **Step 3:** Mark each with `_meta`: `@mcp.tool(..., meta={"loop/minScope": "expert"})`.
- [ ] **Step 4:** Leave `currency_intelligence`, `geography_intelligence`, `detect_anomalies`, `forecast_metric`, `ask_topmate_bi`, `summarize_data` **unmarked**; for the ones that hit the DB, route them through the orchestrator with `creator_id` when scoped (so even if reached they're filtered) OR reject non-superadmin. Decision: reject non-superadmin via `enforce_scope()` guard at entry (they are platform-aggregate / free-text → admin-only). `summarize_data` (no DB) is harmless — leave open.
- [ ] **Step 5: Run, pass. Commit.** `<JIRA>: creator-scope intelligence tools + _meta`

### Task B8: Events tools — creator scope + `_meta`

**Files:** Modify `src/topmate_mcp/tools/events/__init__.py`

- [ ] `query_events`, `conversion_funnel`, `event_intelligence`: force `expert_id` from `_effective_expert_id`; mark `_meta.loop/minScope=expert`. Athena calls already take `expert_id`.
- [ ] `query_athena_sql` (raw): add `enforce_scope()` at entry → for non-superadmin raise PermissionError (admin-only, **no** `_meta`).
- [ ] `event_trends`, `list_event_types`: aggregate/metadata — leave unmarked; reject non-superadmin for `event_trends` (platform aggregate), allow `list_event_types` (metadata only).
- [ ] Tests + commit. `<JIRA>: creator-scope events tools`

### Task B9: Analytics aggregate tools — inject creator filter + `_meta`

**Files:** Modify `src/topmate_mcp/tools/analytics/__init__.py`

`get_business_metrics`, `analyze_trends`, `compare_periods`, `analyze_funnel`, `cohort_analysis` build hardcoded SQL against `all_bookings_new` / base tables and execute on their own client (NOT via orchestrator).
- [ ] **Step 1: Failing tests:** for `scope:expert`, the executed SQL gets the creator predicate; for superadmin, unchanged.
- [ ] **Step 2: Implement:** wrap their final SQL string through `scope_sql(sql, eid)` when scoped, before `.execute_sql(...)`. Resolve `eid` via `_effective_expert_id(clients, None)`. Since these are templated SELECTs, `scope_sql` injects the predicate on the scoped tables they reference. Mark `_meta.loop/minScope=expert`.
- [ ] **Step 3:** Tests + commit. `<JIRA>: creator-scope analytics tools`

### Task B10: Raw / NL / team tools — default-deny for non-superadmin

**Files:** Modify `src/topmate_mcp/tools/data_query/__init__.py`, `tools/team_tools/__init__.py`, `tools/reports/__init__.py`

Tools that take raw SQL or free-text NL where the creator can't be structurally guaranteed stay **admin-only (no `_meta`)**, AND hard-reject non-superadmin as defense-in-depth (in case the platform mis-exposes them):
- [ ] `data_query_raw`, `query_topmate_data` (incl. `sql_override`), `export_data_csv`/`export_data_excel` (incl. `sql_override`), `growth_metrics`, `product_insights`, `support_lookup`, `marketing_analytics`: add `enforce_scope()` at entry; for the NL ones that DO go through the orchestrator, pass `creator_id` so they are filtered if ever allowed — but per default-deny keep them unmarked and reject non-superadmin unless owner later opts them in. **Decision: reject non-superadmin (raise PermissionError → returned as a clean tool error).**
- [ ] `get_db_health_report`, `explain_query_plan`: admin-only, reject non-superadmin.
- [ ] Tests: each raw tool with `scope:expert` returns an error and does NOT execute SQL; with superadmin/legacy unchanged.
- [ ] Commit. `<JIRA>: default-deny raw/NL/team tools for non-superadmin`

### Task B11: tools/list `_meta` verification

- [ ] **Step 1:** Test that `tools/list` over `/mcp` returns `_meta: {"loop/minScope": "expert"}` on exactly the marked tools (expert_intelligence, follower_intelligence, service_intelligence, query_events, conversion_funnel, event_intelligence, get_business_metrics, analyze_trends, compare_periods, analyze_funnel, cohort_analysis) and on no others. Assert raw/NL tools have no `loop/minScope`. Also assert every marked tool carries `annotations.readOnlyHint == true` (contract §5 — else Loop gates the read).
- [ ] **Step 2:** Commit (test only). `<JIRA>: assert _meta markers on scoped tools`

### Task B12: db-mcp deployment env + transport

**Files:** Modify `eks/manifests/base/deployment-db-mcp-server.yaml`

- [ ] Add `GALACTUS_PROFILE_URL`, `SUPERADMIN_EMAILS`, `SUPERADMIN_TOKENS` (secret, optional), `CALLER_SCOPE_ENABLED=true`.
- [ ] Confirm Loop targets `https://mcp.gabbanext.run/db-mcp/mcp` (Streamable HTTP). The `route_by_transport` already serves `/mcp` → `http_app`; no transport flag change needed (SSE stays for internal). Document this for the Loop team in the PR description.
- [ ] Commit. `<JIRA>: db-mcp galactus + superadmin env`

### Task B13: End-to-end acceptance (the brief's tests)

- [ ] **AT1 (regression):** call any tool with **no** scope headers → identical output to current (legacy). Verify via a recorded fixture / live smoke.
- [ ] **AT2 (isolation):** `X-User-Scope: expert`, valid token for creator A → marked tool returns only A's rows; no tool argument lets A read B's data (caller `expert_id` arg is overridden; raw tools rejected; NL SQL is AST-scoped).
- [ ] **AT3 (admin-only):** raw/admin tool with `X-User-Scope: expert` → error; postgres-mcp any tool with `expert` → 403.
- [ ] **AT4 (tools/list):** `_meta.loop/minScope` on exactly the scoped tools; each scoped read carries `annotations.readOnlyHint=true`.
- [ ] **AT5 (protocol):** `initialize` with `protocolVersion:"2024-11-05"` (Loop's version) negotiates successfully on both servers over `/mcp`.
- [ ] **Step:** Write `tests/integration/test_acceptance.py` automating AT2–AT4 against an in-process app with a stubbed galactus + stubbed postgres client. Run full suite `.venv/bin/python -m pytest -q` in both repos → PASS. Commit. `<JIRA>: caller-scope acceptance tests`

---

## Risk: contextvar propagation on Streamable HTTP

The whole db-mcp design depends on a contextvar set in `CallerIdentityMiddleware` being visible inside the tool coroutine. This holds when the tool runs in the same task as the POST `/mcp` request. db-mcp uses `stateless_http=True`, which processes each request inline — `asyncio`/`anyio` copy the current context to child tasks at creation, so the value propagates. **Task B2 Step 3 is the gate that proves this empirically before any tool work.** If it fails, fallback: read the forwarded headers from the FastMCP `Context` request object inside `enforce_scope` (add `ctx: Context` param to scoped tools and pull `ctx.request_context.request.headers`), resolving identity per-call instead of via contextvar. Keep `resolve_identity` pure so either wiring reuses it.

## Git & Jira

- This is Topmate prod code → use a **PDV-XXXX** key (ask the owner once before the first commit; do not invent one).
- Branch per repo off `main`: `git checkout -b <PDV-XXX>-caller-scoped-access`.
- Frequent commits per task (messages above start with `<JIRA>:`). Do not push or open PRs until the owner confirms.

## Self-review notes
- Spec coverage: §1 identity capture → A1/A2/B1/B2; §2 enforce_scope → B1 + per-tool B7–B10; §3 per-tool opt-in + `_meta` → B7–B11; rule "no header ⇒ unchanged" → resolve_identity legacy branch + AT1; rule "default-deny" → B10 + unmarked tools; rule "username only from header/token, never tool args" → B7 `_effective_expert_id` overrides caller arg; "read-only stays read-only" → access-mode untouched, guard rejects non-SELECT.
- The brief's `creator_username` column does not exist; real keys are integer `expert_id`/`user_id` (resolve username→id in B4) and `all_bookings_new` column must be confirmed live (B5).
