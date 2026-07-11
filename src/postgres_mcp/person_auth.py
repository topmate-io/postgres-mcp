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
