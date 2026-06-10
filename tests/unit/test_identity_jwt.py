"""G1/G3: signed-identity JWT verification (postgres-mcp, flag-gated)."""

import time

import jwt as _pyjwt
import pytest
from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

import postgres_mcp.caller_identity as ci
from postgres_mcp.server import CallerIdentityMiddleware


@pytest.fixture(scope="module")
def keypair():
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption())
    pub = key.public_key().public_bytes(
        _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv, pub


def _mint(priv, scope="superadmin", username="admin", email="a@topmate.io", aud="topmate-mcp", exp_delta=60):
    now = int(time.time())
    return _pyjwt.encode(
        {"scope": scope, "username": username, "email": email, "aud": aud, "exp": now + exp_delta, "iat": now},
        priv, algorithm="RS256",
    )


def _verify(pub, token, aud="topmate-mcp"):
    return ci.verify_signed_identity({b"x-identity-jwt": token.encode()}, public_key=pub, audience=aud)


# --- verify_signed_identity + resolve_identity (pure) ------------------------

def test_valid_signature_derives_claims(keypair):
    priv, pub = keypair
    claims = _verify(pub, _mint(priv, scope="expert", username="ajay"))
    assert claims == {"scope": "expert", "username": "ajay", "email": "a@topmate.io"}


def test_header_mismatch_is_invalid(keypair):
    priv, pub = keypair
    tok = _mint(priv, scope="expert", username="ajay")
    claims = _verify(pub, tok)
    ident = ci.resolve_identity(
        {b"x-user-scope": b"superadmin", b"x-identity-jwt": tok.encode()},
        signed_claims=claims, require_signed=True,
    )
    assert ident["scope"] == ci.INVALID  # header can't escalate over the claim


def test_require_signed_without_jwt_is_invalid():
    ident = ci.resolve_identity(
        {b"x-user-scope": b"superadmin", b"authorization": b"Bearer shared"},
        transport_trusted=True, signed_claims=None, require_signed=True,
    )
    assert ident["scope"] == ci.INVALID


def test_alg_pinning_rejects_hs256(keypair):
    # An HS256 token (header alg=HS256) must be rejected because verify pins
    # algorithms=["RS256"] — defeats the classic RS256->HS256 alg-confusion downgrade.
    _priv, pub = keypair
    now = int(time.time())
    hs = _pyjwt.encode(
        {"scope": "superadmin", "username": "x", "aud": "topmate-mcp", "exp": now + 60},
        "attacker-chosen-secret", algorithm="HS256",
    )
    assert _verify(pub, hs) is None


def test_expired_and_wrong_aud_rejected(keypair):
    priv, pub = keypair
    assert _verify(pub, _mint(priv, exp_delta=-120)) is None
    assert _verify(pub, _mint(priv, aud="nope")) is None


# --- middleware (admin-only server) end-to-end -------------------------------

class _Recorder:
    def __init__(self):
        self.called = False

    async def __call__(self, scope, receive, send):
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _scope(headers, path="/postgres-mcp/mcp"):
    return {"type": "http", "path": path, "method": "POST",
            "headers": [(k, v) for k, v in headers.items()]}


async def _run(mw, scope):
    statuses = []

    async def send(m):
        if m["type"] == "http.response.start":
            statuses.append(m["status"])

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    await mw(scope, receive, send)
    return statuses


@pytest.mark.asyncio
async def test_mw_flag_on(monkeypatch, keypair):
    priv, pub = keypair
    monkeypatch.setenv("REQUIRE_SIGNED_IDENTITY", "true")
    monkeypatch.setenv("IDENTITY_JWT_PUBLIC_KEY", pub)
    monkeypatch.setenv("AUTH_TOKEN", "shared-secret")
    mw = CallerIdentityMiddleware(_Recorder())
    # Bearer + superadmin header, NO signature -> 401 (G1 impersonation blocked)
    s1 = await _run(mw, _scope({b"authorization": b"Bearer shared-secret", b"x-user-scope": b"superadmin"}))
    assert s1 == [401]
    # valid signed superadmin JWT -> 200 (admin-only server admits superadmin)
    tok = _mint(priv, scope="superadmin", username="admin")
    s2 = await _run(mw, _scope({b"x-user-scope": b"superadmin", b"x-user-username": b"admin", b"x-identity-jwt": tok.encode()}))
    assert s2 == [200]


def test_signed_identity_without_scope_header_derives_from_claim(keypair):
    # G1/G3 hardening: a verified JWT governs even without X-User-Scope (review note).
    priv, pub = keypair
    tok = _mint(priv, scope="superadmin", username="admin")
    claims = _verify(pub, tok)
    ident = ci.resolve_identity(
        {b"x-identity-jwt": tok.encode()}, signed_claims=claims, require_signed=True
    )
    assert ident["scope"] == "superadmin" and ident["username"] == "admin"


def test_no_scope_header_no_jwt_still_legacy():
    ident = ci.resolve_identity({}, signed_claims=None, require_signed=True)
    assert ident["scope"] is None  # only a verified signature bypasses Hard rule #1
