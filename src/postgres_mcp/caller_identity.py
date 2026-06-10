"""Forwarded end-user identity capture + galactus token validation.

The Loop platform is the trusted gateway: it authenticates the end-user
(``Authorization: Token <topmate-token>`` validated against galactus
``GET /profile/``, or a superadmin session), resolves a scope, and forwards the
identity on every ``tools/call`` as HTTP headers
(``X-User-Scope`` / ``X-User-Username`` / ``X-User-Email``).

This module turns those headers into a resolved identity using a two-tier trust
model (see ``resolve_identity``):

* **No ``X-User-Scope`` header**  -> legacy caller -> ``scope=None`` (byte-for-byte
  unchanged behavior; internal db->pg calls, ops, Claude.ai connector).
* **Trusted transport** (the request authenticated with our shared ``AUTH_TOKEN``
  Bearer or a configured Loop/superadmin token) -> we trust the forwarded
  ``X-User-*`` headers verbatim, *including* ``superadmin``. This is the contract's
  gateway-trust model: only Loop / internal callers hold the shared secret.
* **Untrusted transport with an end-user ``Authorization: Token <x>``** -> we
  galactus-validate the token ourselves and derive identity from the profile.
  ``superadmin`` is granted only when the validated email is in
  ``SUPERADMIN_EMAILS`` (galactus cannot report superadmin), and a non-superadmin
  can only ever be scoped to *their own* username (anti-impersonation).
* **``X-User-Scope`` present but neither trusted nor a valid token** -> ``INVALID`` (401).

``resolve_identity`` is pure given the injected ``validate_token`` callable and the
``transport_trusted`` flag, so it is trivially unit-testable; the ASGI middleware
in ``server.py`` computes ``transport_trusted`` and wires the real galactus
validator in.
"""

from __future__ import annotations

import asyncio
import contextvars
import hmac
import logging
import os
import threading
import time
from typing import Callable

import httpx
import jwt

logger = logging.getLogger(__name__)

# Contextvar holding the resolved identity for the current request.
caller_ctx: contextvars.ContextVar[dict] = contextvars.ContextVar("caller", default={})

# Sentinel: caller sent X-User-Scope but could not be authenticated.
INVALID = "__invalid__"

_VALID_SCOPES = {"superadmin", "expert", "seeker", "public"}

_GALACTUS_URL = os.getenv("GALACTUS_PROFILE_URL", "https://api.galactus.run/profile/")
_TTL = 300.0
_cache: dict[str, tuple[dict | None, float]] = {}
_cache_lock = threading.Lock()


def _scope_from_profile(p: dict) -> str:
    """Derive expert/seeker from a galactus /profile/ payload."""
    if p.get("primary_user_type") == "expert" or p.get("service_added") or p.get("slots_added"):
        return "expert"
    return "seeker"


def _cached_profile(token: str) -> tuple[bool, dict | None]:
    """Return ``(hit, profile)`` from the 300s cache (hit=False => not cached)."""
    now = time.monotonic()
    with _cache_lock:
        entry = _cache.get(token)
        if entry and (now - entry[1]) < _TTL:
            return True, entry[0]
    return False, None


def _validate_token_blocking(token: str) -> dict | None:
    """Blocking galactus /profile/ call + cache write. Run in a worker thread."""
    profile: dict | None = None
    try:
        resp = httpx.get(
            _GALACTUS_URL,
            headers={"Authorization": f"Token {token}", "Accept": "application/json"},
            timeout=2.5,
        )
        if resp.status_code == 200:
            profile = resp.json()
    except Exception as e:  # network/parse error => deny
        logger.warning("galactus validation error: %s", e)
        profile = None
    with _cache_lock:
        _cache[token] = (profile, time.monotonic())
    return profile


def validate_token(token: str) -> dict | None:
    """Validate a Topmate Knox token against galactus /profile/ (sync, cached 300s).

    Kept synchronous for back-compat and the pure ``resolve_identity`` contract.
    The async ASGI path uses :func:`validate_token_async` so the blocking HTTP
    call doesn't freeze the single postgres-mcp replica's event loop (P2).
    """
    if not token:
        return None
    hit, profile = _cached_profile(token)
    if hit:
        return profile
    return _validate_token_blocking(token)


async def validate_token_async(token: str) -> dict | None:
    """Validate a Knox token, offloaded off the event loop (P2). Cached 300s."""
    if not token:
        return None
    hit, profile = _cached_profile(token)
    if hit:
        return profile
    return await asyncio.to_thread(_validate_token_blocking, token)


def parse_auth(headers: dict[bytes, bytes]) -> tuple[str | None, str | None]:
    """Return ``(scheme_lower, credential)`` from the Authorization header.

    e.g. ``Authorization: Token abc`` -> ``("token", "abc")``;
    ``Authorization: Bearer abc`` -> ``("bearer", "abc")``. ``(None, None)`` if absent.
    """
    auth = headers.get(b"authorization", b"").decode("latin-1").strip()
    if not auth or " " not in auth:
        return None, None
    scheme, _, cred = auth.partition(" ")
    return scheme.lower(), cred.strip()


def is_transport_trusted(
    headers: dict[bytes, bytes],
    *,
    auth_token: str | None,
    superadmin_tokens: set[str] | None = None,
) -> bool:
    """True when the request authenticated as Loop / internal via a shared secret.

    Trusted means: ``Authorization: Bearer <AUTH_TOKEN>`` (our static shared token,
    matched in constant time) or a credential in ``superadmin_tokens``. Such callers
    are Loop or internal and their forwarded ``X-User-*`` headers are trusted verbatim.
    """
    superadmin_tokens = superadmin_tokens or set()
    scheme, cred = parse_auth(headers)
    if not cred:
        return False
    if scheme == "bearer" and auth_token and hmac.compare_digest(cred, auth_token):
        return True
    if cred in superadmin_tokens:
        return True
    return False


def resolve_identity(
    headers: dict[bytes, bytes],
    *,
    validate_token: Callable[[str], dict | None] = validate_token,
    transport_trusted: bool = False,
    superadmin_emails: set[str] | None = None,
    signed_claims: dict | None = None,
    require_signed: bool = False,
) -> dict:
    """Resolve the forwarded identity. Pure given ``validate_token`` + ``transport_trusted``.

    When ``require_signed`` (G1/G3): Tier-1 trust is granted ONLY by a verified
    ``signed_claims``; identity is derived from the claims and a present X-User-*
    header that disagrees forces ``INVALID``. Flag off (default) preserves the
    legacy verbatim-header Tier-1 exactly. See the module docstring for the rules.
    """
    superadmin_emails = superadmin_emails or set()
    raw_scope = headers.get(b"x-user-scope")
    raw_scope_s = raw_scope.decode("latin-1").strip() if raw_scope else None

    # Hard rule #1: no X-User-Scope header => legacy => unchanged behavior.
    if not raw_scope_s:
        return {"scope": None, "username": None, "email": None, "raw_scope_header": None}

    hdr_username = (headers.get(b"x-user-username") or b"").decode("latin-1").strip() or None
    hdr_email = (headers.get(b"x-user-email") or b"").decode("latin-1").strip() or None

    # Tier 1: trusted gateway.
    if require_signed:
        # G1/G3: trust is granted ONLY by a verified signature. Derive identity
        # from the claims; a present X-User-* header that disagrees forces INVALID
        # (no header-alone escalation). No valid signature -> fall through to
        # Tier-2 (a shared Bearer alone can no longer grant scope).
        if signed_claims is not None:
            claim_scope = signed_claims.get("scope")
            claim_username = signed_claims.get("username")
            claim_email = signed_claims.get("email")
            scope = claim_scope if claim_scope in _VALID_SCOPES else INVALID
            if (
                (raw_scope_s is not None and raw_scope_s != claim_scope)
                or (hdr_username is not None and hdr_username != claim_username)
                or (hdr_email is not None and hdr_email != claim_email)
            ):
                scope = INVALID
            return {
                "scope": scope,
                "username": claim_username,
                "email": claim_email,
                "raw_scope_header": raw_scope_s,
            }
    elif transport_trusted:
        scope = raw_scope_s if raw_scope_s in _VALID_SCOPES else INVALID
        return {
            "scope": scope,
            "username": hdr_username,
            "email": hdr_email,
            "raw_scope_header": raw_scope_s,
        }

    # Tier 2: untrusted transport -> require a valid end-user `Authorization: Token <x>`.
    scheme, cred = parse_auth(headers)
    if scheme != "token" or not cred:
        return {"scope": INVALID, "username": None, "email": hdr_email, "raw_scope_header": raw_scope_s}

    profile = validate_token(cred)
    if profile is None:
        return {"scope": INVALID, "username": None, "email": hdr_email, "raw_scope_header": raw_scope_s}

    caller_email = (profile.get("email") or "").strip().lower()
    if caller_email and caller_email in {e.strip().lower() for e in superadmin_emails}:
        # Real superadmin via allowlist — honor act-as target from headers.
        return {
            "scope": "superadmin",
            "username": hdr_username,
            "email": hdr_email or caller_email,
            "raw_scope_header": raw_scope_s,
        }

    # Non-superadmin: derived from the profile; can only ever be scoped to self.
    derived = _scope_from_profile(profile)
    token_username = profile.get("username")
    username = hdr_username or token_username
    if token_username and username != token_username:
        # Anti-impersonation: a non-superadmin cannot act-as another user.
        username = token_username
    return {
        "scope": derived,
        "username": username,
        "email": profile.get("email"),
        "raw_scope_header": raw_scope_s,
    }


def superadmin_emails_from_env() -> set[str]:
    return {e.strip() for e in os.getenv("SUPERADMIN_EMAILS", "").split(",") if e.strip()}


def superadmin_tokens_from_env() -> set[str]:
    return {t.strip() for t in os.getenv("SUPERADMIN_TOKENS", "").split(",") if t.strip()}


# --- G1/G3: signed-identity gate (env-driven, mirrors db-mcp) ----------------

def require_signed_identity_from_env() -> bool:
    return os.getenv("REQUIRE_SIGNED_IDENTITY", "false").lower() == "true"


def identity_jwt_audience_from_env() -> str:
    return os.getenv("IDENTITY_JWT_AUDIENCE", "topmate-mcp")


def identity_jwt_leeway_from_env() -> int:
    try:
        return int(os.getenv("IDENTITY_JWT_LEEWAY_SECONDS", "60"))
    except ValueError:
        return 60


_pubkey_cache: dict = {}


def identity_jwt_public_key_from_env() -> str | None:
    """RSA public-key PEM from IDENTITY_JWT_PUBLIC_KEY or *_PATH (cached)."""
    inline = os.getenv("IDENTITY_JWT_PUBLIC_KEY")
    if inline:
        return inline
    path = os.getenv("IDENTITY_JWT_PUBLIC_KEY_PATH")
    if not path:
        return None
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    cached = _pubkey_cache.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        with open(path) as f:
            pem = f.read()
    except OSError:
        return None
    _pubkey_cache[path] = (mtime, pem)
    return pem


def verify_signed_identity(
    headers: dict[bytes, bytes],
    *,
    public_key: str | None,
    audience: str,
    leeway: int = 60,
) -> dict | None:
    """Verify a Loop-signed RS256 identity JWT from the ``X-Identity-JWT`` header.

    Returns normalized claims ``{scope, username, email}`` on a valid signature,
    or ``None`` on ANY failure. Pure CPU — no network (G1/G3).
    """
    if public_key is None:
        return None
    raw = headers.get(b"x-identity-jwt")
    if not raw:
        return None
    token = raw.decode("latin-1").strip()
    if not token:
        return None
    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],  # pinned — no alg-confusion downgrade
            audience=audience,
            leeway=leeway,
            options={"require": ["exp", "aud"]},
        )
    except Exception as e:
        logger.warning("identity JWT verification failed: %s", e)
        return None
    scope = claims.get("scope")
    if scope not in _VALID_SCOPES:
        return None
    return {"scope": scope, "username": claims.get("username"), "email": claims.get("email")}
