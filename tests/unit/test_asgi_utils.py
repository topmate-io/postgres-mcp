"""Tests for the shared ASGI scope helpers (LOOP-664 M1)."""

from postgres_mcp.asgi_utils import get_client_ip
from postgres_mcp.asgi_utils import get_path


def test_get_path_strips_known_alb_prefixes():
    assert get_path({"path": "/postgres-mcp/mcp"}) == "/mcp"
    assert get_path({"path": "/db-mcp/health"}) == "/health"
    assert get_path({"path": "/postgres-mcp"}) == "/"
    assert get_path({"path": "/mcp"}) == "/mcp"
    assert get_path({}) == ""


def test_get_client_ip_prefers_cloudflare_header():
    scope = {
        "headers": [(b"cf-connecting-ip", b"1.2.3.4"), (b"x-forwarded-for", b"5.6.7.8, 9.9.9.9")],
        "client": ("10.0.0.1", 1),
    }
    assert get_client_ip(scope) == "1.2.3.4"


def test_get_client_ip_falls_back_to_first_xff_entry():
    scope = {"headers": [(b"x-forwarded-for", b"5.6.7.8, 9.9.9.9")], "client": ("10.0.0.1", 1)}
    assert get_client_ip(scope) == "5.6.7.8"


def test_get_client_ip_falls_back_to_scope_client_then_unknown():
    assert get_client_ip({"headers": [], "client": ("10.0.0.1", 1)}) == "10.0.0.1"
    assert get_client_ip({"headers": []}) == "unknown"
