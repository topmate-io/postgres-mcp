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
from typing import ClassVar

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

    HEALTH_PATHS: ClassVar[set[str]] = {"/", "/health", "/healthz"}

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
