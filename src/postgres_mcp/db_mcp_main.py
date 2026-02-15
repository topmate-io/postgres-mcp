#!/usr/bin/env python3
"""
Topmate Business Logic MCP Server
Provides SQL patterns and troubleshooting guides via MCP SSE transport.
No database connection required - fetches from Topmate Logic Hub API.
"""

import asyncio
import ipaddress
import json
import logging
import os
import signal
import sys

import mcp.types as types
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from topmate_buisness_logic import TopmateBuisnessLogic

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize FastMCP
mcp_server = FastMCP("topmate-db-mcp-server")

# Initialize topmate logic with fallback for missing credentials
topmate_logic = None
try:
    topmate_logic = TopmateBuisnessLogic()
    logger.info("TopmateBuisnessLogic initialized")
except Exception as e:
    logger.warning(f"Could not initialize TopmateBuisnessLogic: {e}")
    topmate_logic = None

ResponseType = list[types.TextContent | types.ImageContent]


def format_text_response(text) -> ResponseType:
    if isinstance(text, str):
        return [types.TextContent(type="text", text=text)]
    return [types.TextContent(type="text", text=json.dumps(text, indent=2, default=str))]


def format_error_response(error: str) -> ResponseType:
    return [types.TextContent(type="text", text=f"Error: {error}")]


@mcp_server.tool(
    name="get_business_logic_patterns",
    description="Provides comprehensive business logic patterns and SQL query guidance for complex scenarios. "
    "Returns business logic patterns, rules, and SQL query guidance.",
)
async def get_business_logic_patterns() -> ResponseType:
    """Get business logic patterns and SQL guidance from Topmate Logic Hub."""
    if topmate_logic is None:
        return format_error_response(
            "TopmateBuisnessLogic service not available. "
            "Please check that TOPMATE_LOGIC_HUB_BASE_URL and TOPMATE_LOGIC_HUB_API_KEY environment variables are set."
        )

    try:
        rules = topmate_logic.get_rules()
        patterns = topmate_logic.get_patterns()
        return format_text_response(
            {
                "description": "Business logic patterns for complex SQL queries",
                "basic_rules": [rule.get("description") for rule in rules] if isinstance(rules, list) else rules,
                "patterns": {p.get("pattern_name"): p.get("pattern_data") for p in patterns} if isinstance(patterns, list) else patterns,
            }
        )
    except Exception as e:
        logger.error(f"Error getting business logic patterns: {e}")
        return format_error_response(str(e))


@mcp_server.tool(
    name="get_sql_troubleshooting_guide",
    description="Provides troubleshooting guidance for common SQL issues when querying the Topmate database.",
)
async def get_sql_troubleshooting_guide() -> ResponseType:
    """Get SQL troubleshooting guide."""
    return format_text_response(
        {
            "description": "Troubleshooting guide for complex SQL queries",
            "common_issues": {
                "slow_queries": {
                    "symptoms": ["Query takes longer than expected", "Timeout errors", "High CPU usage"],
                    "solutions": [
                        "Check if proper indexes exist on filtered columns",
                        "Use EXPLAIN ANALYZE to identify bottlenecks",
                        "Consider breaking complex queries into smaller steps",
                        "Verify statistics are up to date with ANALYZE TABLE",
                    ],
                },
                "incorrect_results": {
                    "symptoms": ["Wrong row counts", "Unexpected null values", "Missing data"],
                    "solutions": [
                        "Check JOIN conditions - ensure proper ON clauses",
                        "Verify date range filters include boundary conditions",
                        "Use INNER vs LEFT JOIN appropriately",
                        "Handle NULL values explicitly with COALESCE",
                    ],
                },
                "complex_aggregations": {
                    "symptoms": ["Aggregation results don't match expectations", "GROUP BY errors"],
                    "solutions": [
                        "Ensure all non-aggregated columns are in GROUP BY",
                        "Use window functions for running totals and rankings",
                        "Consider using HAVING for aggregate filtering instead of WHERE",
                        "Break complex aggregations into CTEs for clarity",
                    ],
                },
            },
        }
    )


class IPAllowlistMiddleware:
    """ASGI middleware that restricts access to allowed IPs/CIDRs.

    Reads comma-separated IPs/CIDRs from the ALLOWED_IPS env var.
    Health check paths are always exempt so ALB probes continue working.
    If ALLOWED_IPS is empty or unset, all traffic is allowed (backwards compatible).
    """

    HEALTH_PATHS = {"/", "/health", "/healthz"}

    def __init__(self, app):
        self.app = app
        self.allowed_networks = self._load_allowed_ips()

    def _load_allowed_ips(self):
        raw = os.getenv("ALLOWED_IPS", "").strip()
        if not raw:
            return None  # None = allow all
        networks = []
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if "/" not in entry:
                entry += "/32"  # Single IP -> /32 CIDR
            networks.append(ipaddress.ip_network(entry, strict=False))
        if networks:
            logger.info(f"IP allowlist loaded: {[str(n) for n in networks]}")
        return networks if networks else None

    def _get_client_ip(self, scope):
        # ASGI headers are list of (name, value) byte tuples
        for name, value in scope.get("headers", []):
            if name.lower() == b"x-forwarded-for":
                return value.decode("latin-1").split(",")[0].strip()
        # Fallback to ASGI client
        client = scope.get("client")
        return client[0] if client else None

    def _is_allowed(self, ip_str):
        if self.allowed_networks is None:
            return True
        if not ip_str:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self.allowed_networks)
        except ValueError:
            return False

    def _get_path(self, scope):
        """Get the request path, stripping known ALB prefixes."""
        path = scope.get("path", "")
        for prefix in ("/db-mcp",):
            if path.startswith(prefix):
                return path[len(prefix):] or "/"
        return path

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and self.allowed_networks is not None:
            path = self._get_path(scope)

            # Always allow health check paths (ALB probes)
            if path not in self.HEALTH_PATHS:
                client_ip = self._get_client_ip(scope)

                if not self._is_allowed(client_ip):
                    logger.warning(f"Blocked request from {client_ip} to {scope.get('path', '')}")
                    await send({
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [[b"content-type", b"application/json"]],
                    })
                    await send({
                        "type": "http.response.body",
                        "body": b'{"error":"forbidden","message":"IP not allowed"}',
                    })
                    return

        await self.app(scope, receive, send)


class HealthCheckMiddleware:
    """ASGI middleware to handle health checks and strip ALB path prefixes."""

    PATH_PREFIXES = ("/db-mcp",)

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            method = scope.get("method", "")

            # Strip ALB ingress path prefix
            # Set root_path so SSE transport includes the prefix in endpoint URLs
            for prefix in self.PATH_PREFIXES:
                if path.startswith(prefix):
                    path = path[len(prefix):] or "/"
                    scope = dict(scope, path=path, root_path=prefix)
                    break

            # Health check endpoints
            if method == "GET" and path in ("/", "/health", "/healthz"):
                status = "ok" if topmate_logic is not None else "degraded"
                body = json.dumps({"status": status, "service": "topmate-db-mcp-server"}).encode()
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [[b"content-type", b"application/json"], [b"cache-control", b"no-store"]],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return

        await self.app(scope, receive, send)


shutdown_in_progress = False


async def shutdown(sig=None):
    global shutdown_in_progress
    if shutdown_in_progress:
        sys.exit(1)
    shutdown_in_progress = True
    if sig:
        logger.info(f"Received exit signal {sig.name}")
    sys.exit(128 + sig.value if sig is not None else 0)


async def main():
    """Main entry point - runs MCP server with Streamable HTTP transport + health check middleware."""
    host = "0.0.0.0"
    port = int(os.getenv("PORT", "9000"))

    logger.info(f"Starting Topmate DB MCP Server on {host}:{port}")

    # Signal handling
    try:
        loop = asyncio.get_running_loop()
        for s in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(s)))
    except NotImplementedError:
        pass

    # Configure SSE transport
    mcp_server.settings.host = host
    mcp_server.settings.port = port
    mcp_server.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    )

    # Expose both SSE and Streamable HTTP transports
    # SSE at /sse + /messages (for Claude Code's type:"sse" config)
    # Streamable HTTP at /mcp (for newer MCP clients)
    import uvicorn

    sse_app = mcp_server.sse_app()
    http_app = mcp_server.streamable_http_app()

    async def route_by_transport(scope, receive, send):
        """Route to SSE or Streamable HTTP based on path."""
        path = scope.get("path", "")
        if path == "/mcp" or path.startswith("/mcp/"):
            await http_app(scope, receive, send)
        else:
            await sse_app(scope, receive, send)

    wrapped_app = IPAllowlistMiddleware(HealthCheckMiddleware(route_by_transport))
    logger.info("Applied IPAllowlistMiddleware + HealthCheckMiddleware")

    config = uvicorn.Config(wrapped_app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
