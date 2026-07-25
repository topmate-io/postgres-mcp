"""Domain connection registry for the unified multi-DB router (LOOP-664 M3).

`tm` is always present and served by the local pool. Other domains are proxied
to sibling per-DB MCPs, configured via DOMAIN_REGISTRY_JSON. All multi-domain
behavior is gated by MULTI_DOMAIN_ENABLED (default off) for backward-compat.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DomainEntry:
    name: str
    kind: Literal["local", "proxy"]
    database: str
    base_url: str | None = None
    token: str | None = None
    transport: str = "sse"


_TM = DomainEntry(name="tm", kind="local", database="topmate_db_prod")

_enabled: bool = False
_domains: dict[str, DomainEntry] = {"tm": _TM}


def reload_registry() -> None:
    """(Re)read env into module state. Safe to call repeatedly (tests + startup)."""
    global _enabled, _domains
    _enabled = os.environ.get("MULTI_DOMAIN_ENABLED", "false").strip().lower() == "true"
    domains: dict[str, DomainEntry] = {"tm": _TM}
    raw = os.environ.get("DOMAIN_REGISTRY_JSON", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.error("Invalid DOMAIN_REGISTRY_JSON, ignoring: %s", e)
            parsed = {}
        for name, cfg in parsed.items():
            if name == "tm":
                continue
            token_env = cfg.get("token_env")
            token = os.environ.get(token_env) if token_env else None
            domains[name] = DomainEntry(
                name=name,
                kind="proxy",
                database=cfg.get("database", name),
                base_url=cfg.get("base_url"),
                token=token,
                transport=cfg.get("transport", "sse"),
            )
    _domains = domains


def multi_domain_enabled() -> bool:
    return _enabled


def list_domains() -> list[str]:
    return list(_domains.keys())


def get_domain(name: str) -> DomainEntry:
    return _domains[name]


reload_registry()
