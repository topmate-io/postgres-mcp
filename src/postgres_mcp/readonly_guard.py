"""Lightweight read-only guard for the proxy path (defense-in-depth).

The downstream crystaldba MCP runs with --access-mode=restricted and is the
authoritative read-only boundary. This is a cheap belt-and-braces check so the
router never forwards an obviously-mutating statement.
"""

from __future__ import annotations

import re

_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_COMMENT_LINE = re.compile(r"--[^\n]*")
_ALLOWED_FIRST = ("select", "with", "show", "table", "values", "explain")


def _strip(sql: str) -> str:
    s = _COMMENT_BLOCK.sub(" ", sql)
    s = _COMMENT_LINE.sub(" ", s)
    return s.strip()


def is_read_only_sql(sql: str) -> bool:
    s = _strip(sql)
    if not s:
        return False
    # Reject multi-statement payloads (ignore a single trailing semicolon).
    if ";" in s.rstrip(";"):
        return False
    lowered = s.lower()
    first = lowered.split(None, 1)[0] if lowered.split(None, 1) else ""
    if first not in _ALLOWED_FIRST:
        return False
    if first == "explain" and "analyze" in lowered:
        return False
    return True
