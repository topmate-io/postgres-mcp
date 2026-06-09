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

import contextvars
import hmac
import logging
import os
import threading
import time
from typing import Callable

import httpx

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


def validate_token(token: str) -> dict | None:
    """Validate a Topmate Knox token against galactus /profile/.

    Returns the profile dict on success, or ``None`` on any failure. Cached for
    ``_TTL`` seconds (both hits and misses) so invalid tokens don't repeatedly
    hit galactus either.
    """
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
) -> dict:
    """Resolve the forwarded identity. Pure given ``validate_token`` + ``transport_trusted``.

    See the module docstring for the resolution rules.
    """
    superadmin_emails = superadmin_emails or set()
    raw_scope = headers.get(b"x-user-scope")
    raw_scope_s = raw_scope.decode("latin-1").strip() if raw_scope else None

    # Hard rule #1: no X-User-Scope header => legacy => unchanged behavior.
    if not raw_scope_s:
        return {"scope": None, "username": None, "email": None, "raw_scope_header": None}

    hdr_username = (headers.get(b"x-user-username") or b"").decode("latin-1").strip() or None
    hdr_email = (headers.get(b"x-user-email") or b"").decode("latin-1").strip() or None

    # Tier 1: trusted gateway (Loop/internal via shared secret) -> trust headers verbatim.
    if transport_trusted:
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
