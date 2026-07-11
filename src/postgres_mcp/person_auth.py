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

from .asgi_utils import get_path

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
            raise ValueError("PERSON_AUTH_ENABLED=true but PERSON_TOKENS is empty — refusing to start an effectively unauthenticated server")
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
        presented = auth[len("Bearer ") :].strip() if auth.startswith("Bearer ") else ""
        # self.registry is guaranteed non-None when enabled (constructor raises
        # otherwise); the extra check keeps type-checkers satisfied.
        person = self.registry.verify(presented) if (presented and self.registry) else None

        if person is None:
            logger.warning("PersonAuth: rejected request to %s (missing/unknown token)", scope.get("path", ""))
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [[b"content-type", b"application/json"]],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b'{"error":"unauthorized","message":"Valid personal bearer token required"}',
                }
            )
            return

        token = current_person.set(person)
        try:
            await self.app(scope, receive, send)
        finally:
            current_person.reset(token)
