"""Unit tests for postgres_mcp.caller_identity (pure resolver + trust helper)."""

from postgres_mcp import caller_identity as ci


# --------------------------------------------------------------------------- #
# is_transport_trusted
# --------------------------------------------------------------------------- #

def test_trusted_when_bearer_matches_auth_token():
    headers = {b"authorization": b"Bearer shared-secret"}
    assert ci.is_transport_trusted(headers, auth_token="shared-secret") is True


def test_not_trusted_when_bearer_mismatch():
    headers = {b"authorization": b"Bearer wrong"}
    assert ci.is_transport_trusted(headers, auth_token="shared-secret") is False


def test_not_trusted_for_plain_user_token():
    headers = {b"authorization": b"Token user-knox-token"}
    assert ci.is_transport_trusted(headers, auth_token="shared-secret") is False


def test_trusted_when_token_in_superadmin_set():
    headers = {b"authorization": b"Token loop-svc"}
    assert ci.is_transport_trusted(headers, auth_token=None, superadmin_tokens={"loop-svc"}) is True


# --------------------------------------------------------------------------- #
# resolve_identity — legacy
# --------------------------------------------------------------------------- #

def test_resolve_legacy_when_no_scope_header():
    # No X-User-Scope header => legacy caller => unchanged behavior (scope None).
    headers = {b"authorization": b"Bearer shared-secret"}
    ident = ci.resolve_identity(headers, transport_trusted=True, validate_token=lambda t: None)
    assert ident["scope"] is None
    assert ident["username"] is None


# --------------------------------------------------------------------------- #
# resolve_identity — Tier 1: trusted transport (Loop/internal) trusts headers
# --------------------------------------------------------------------------- #

def test_trusted_transport_honors_forwarded_superadmin():
    headers = {
        b"x-user-scope": b"superadmin",
        b"x-user-username": b"ajay_shenoy",
        b"x-user-email": b"target@topmate.io",
        b"authorization": b"Bearer shared-secret",
    }
    ident = ci.resolve_identity(headers, transport_trusted=True)
    assert ident["scope"] == "superadmin"
    assert ident["username"] == "ajay_shenoy"  # act-as target from header (trusted)
    assert ident["email"] == "target@topmate.io"


def test_trusted_transport_honors_forwarded_expert():
    headers = {
        b"x-user-scope": b"expert",
        b"x-user-username": b"ajay_shenoy",
        b"authorization": b"Bearer shared-secret",
    }
    ident = ci.resolve_identity(headers, transport_trusted=True)
    assert ident["scope"] == "expert"
    assert ident["username"] == "ajay_shenoy"


def test_trusted_transport_rejects_unknown_scope():
    headers = {b"x-user-scope": b"root", b"authorization": b"Bearer shared-secret"}
    ident = ci.resolve_identity(headers, transport_trusted=True)
    assert ident["scope"] == ci.INVALID


# --------------------------------------------------------------------------- #
# resolve_identity — Tier 2: untrusted transport requires a valid galactus Token
# --------------------------------------------------------------------------- #

def test_untrusted_bearer_with_scope_is_invalid_not_validated():
    # BUG-FIX REGRESSION: a static Bearer that is NOT our AUTH_TOKEN must NOT be
    # galactus-validated as a user token; it is simply untrusted => INVALID.
    headers = {b"x-user-scope": b"expert", b"authorization": b"Bearer some-other-bearer"}
    called = []
    ident = ci.resolve_identity(
        headers, transport_trusted=False, validate_token=lambda t: called.append(t) or None
    )
    assert ident["scope"] == ci.INVALID
    assert called == []  # never tried to validate a Bearer as a galactus token


def test_untrusted_token_expert_derived_from_profile():
    headers = {
        b"x-user-scope": b"expert",
        b"x-user-username": b"ajay_shenoy",
        b"authorization": b"Token good",
    }
    profile = {"id": 7, "email": "a@topmate.io", "username": "ajay_shenoy", "primary_user_type": "expert"}
    ident = ci.resolve_identity(headers, transport_trusted=False, validate_token=lambda t: profile)
    assert ident["scope"] == "expert"
    assert ident["username"] == "ajay_shenoy"


def test_untrusted_token_superadmin_only_via_allowlist():
    headers = {
        b"x-user-scope": b"superadmin",
        b"x-user-username": b"target_user",
        b"x-user-email": b"target@topmate.io",
        b"authorization": b"Token admintok",
    }
    profile = {"id": 1, "email": "admin@topmate.io", "username": "admin", "primary_user_type": "follower"}
    ident = ci.resolve_identity(
        headers, transport_trusted=False, validate_token=lambda t: profile,
        superadmin_emails={"admin@topmate.io"},
    )
    assert ident["scope"] == "superadmin"
    assert ident["username"] == "target_user"  # act-as honored for allowlisted superadmin


def test_untrusted_token_anti_impersonation():
    # A non-superadmin cannot act-as another user even via the header.
    headers = {
        b"x-user-scope": b"expert",
        b"x-user-username": b"someone_else",
        b"authorization": b"Token good",
    }
    profile = {"id": 7, "email": "a@topmate.io", "username": "ajay_shenoy", "primary_user_type": "expert"}
    ident = ci.resolve_identity(headers, transport_trusted=False, validate_token=lambda t: profile)
    assert ident["scope"] == "expert"
    assert ident["username"] == "ajay_shenoy"  # forced to the token owner


def test_untrusted_invalid_token_is_invalid():
    headers = {b"x-user-scope": b"expert", b"authorization": b"Token bad"}
    ident = ci.resolve_identity(headers, transport_trusted=False, validate_token=lambda t: None)
    assert ident["scope"] == ci.INVALID


def test_untrusted_no_auth_with_scope_is_invalid():
    headers = {b"x-user-scope": b"expert"}
    ident = ci.resolve_identity(headers, transport_trusted=False, validate_token=lambda t: {"username": "x"})
    assert ident["scope"] == ci.INVALID


# --- P2: galactus token validation is offloaded off the event loop -----------

import pytest  # noqa: E402


@pytest.mark.asyncio
async def test_validate_token_async_offloads_and_does_not_block(monkeypatch):
    import asyncio
    import time as _time
    ci._cache.clear()

    def slow_blocking(token):
        _time.sleep(0.2)
        return {"username": "x"}

    monkeypatch.setattr(ci, "_validate_token_blocking", slow_blocking)
    task = asyncio.create_task(ci.validate_token_async("cold"))
    ticks = 0
    while not task.done():
        ticks += 1
        await asyncio.sleep(0.02)
    assert ticks >= 3
    assert (await task) == {"username": "x"}


def test_validate_token_blocking_timeout_is_2_5(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {}

    def fake_get(url, headers, timeout):
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(ci.httpx, "get", fake_get)
    ci._cache.clear()
    ci._validate_token_blocking("newtok")
    assert captured["timeout"] == 2.5  # dropped from 8.0
