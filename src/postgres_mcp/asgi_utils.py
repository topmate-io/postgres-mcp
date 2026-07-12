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
            return path[len(prefix) :] or "/"
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
