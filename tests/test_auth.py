"""Tests for auth: session cookie (Secure flag), allow-lists, and JWKS id_token
signature validation (Fix #3)."""
import time

import pytest
from starlette.responses import Response

from core import auth, config


# --- session cookie ------------------------------------------------------

def test_session_cookie_roundtrip(monkeypatch):
    monkeypatch.setattr(config, "env_locked", lambda: set())
    resp = Response()
    auth._set_session_cookie(resp, "alice", "alice@example.com", ["admins"])
    cookie_header = resp.headers.get("set-cookie")
    assert cookie_header is not None
    assert "HttpOnly" in cookie_header

    # Build a fake request carrying the cookie back
    name = str(config.get_effective("session_cookie_name") or "cfddns_session")
    token = cookie_header.split(f"{name}=", 1)[1].split(";", 1)[0]

    class FakeReq:
        cookies = {name: token}
    parsed = auth._read_session_cookie(FakeReq())
    assert parsed is not None
    username, email, groups = parsed
    assert username == "alice"
    assert email == "alice@example.com"
    assert groups == ["admins"]


def test_session_cookie_secure_flag_default_true(monkeypatch):
    monkeypatch.setattr(config, "env_locked", lambda: set())
    monkeypatch.setattr(config.settings, "session_cookie_secure", True)
    resp = Response()
    auth._set_session_cookie(resp, "bob")
    assert "Secure" in resp.headers.get("set-cookie")


def test_session_cookie_secure_flag_can_disable(monkeypatch):
    monkeypatch.setattr(config, "env_locked", lambda: set())
    # DB value disables Secure for local HTTP dev
    from core.database import get_session
    from core.models import Setting
    sess = get_session()
    try:
        sess.add(Setting(key="session_cookie_secure", value="false"))
        sess.commit()
    finally:
        sess.close()
    resp = Response()
    auth._set_session_cookie(resp, "bob")
    assert "Secure" not in resp.headers.get("set-cookie")


def test_tampered_cookie_rejected(monkeypatch):
    monkeypatch.setattr(config, "env_locked", lambda: set())
    name = str(config.get_effective("session_cookie_name") or "cfddns_session")

    class FakeReq:
        cookies = {name: "totally.bogus.value"}
    assert auth._read_session_cookie(FakeReq()) is None


# --- allow-list ----------------------------------------------------------

def test_user_allowed_no_lists_allows_everyone(monkeypatch):
    monkeypatch.setattr(config, "env_locked", lambda: set())
    monkeypatch.setattr(auth, "get_effective", lambda k, *a: "")
    ok, _ = auth._user_allowed("anyone@example.com", [])
    assert ok is True


def test_user_allowed_by_group(monkeypatch):
    def fake_eff(key, *a):
        return {"oidc_allowed_groups": "admins", "oidc_allowed_emails": ""}.get(key, "")
    monkeypatch.setattr(auth, "get_effective", fake_eff)
    ok, _ = auth._user_allowed("x@example.com", ["admins"])
    assert ok is True
    ok2, reason = auth._user_allowed("x@example.com", ["users"])
    assert ok2 is False
    assert "not in the allowed" in reason


def test_user_allowed_by_email(monkeypatch):
    def fake_eff(key, *a):
        return {"oidc_allowed_groups": "", "oidc_allowed_emails": "boss@example.com"}.get(key, "")
    monkeypatch.setattr(auth, "get_effective", fake_eff)
    ok, _ = auth._user_allowed("boss@example.com", [])
    assert ok is True


# --- JWKS id_token validation (Fix #3) -----------------------------------

@pytest.fixture
def rsa_keypair():
    """Generate an RSA keypair and return (private_jwk, public_jwks)."""
    from authlib.jose import JsonWebKey
    key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
    private_jwk = key.as_dict(is_private=True)
    private_jwk["kid"] = "test-key-1"
    public = key.as_dict(is_private=False)
    public["kid"] = "test-key-1"
    return private_jwk, {"keys": [public]}


def _make_id_token(private_jwk, *, iss, aud, exp_delta=3600, extra=None):
    from authlib.jose import jwt
    header = {"alg": "RS256", "kid": private_jwk.get("kid", "test-key-1")}
    payload = {
        "iss": iss,
        "aud": aud,
        "sub": "user-123",
        "exp": int(time.time()) + exp_delta,
        "iat": int(time.time()),
        "preferred_username": "alice",
        "email": "alice@example.com",
        "groups": ["admins"],
    }
    if extra:
        payload.update(extra)
    return jwt.encode(header, payload, private_jwk).decode()


@pytest.mark.asyncio
async def test_verify_id_token_valid(monkeypatch, rsa_keypair):
    private_jwk, public_jwks = rsa_keypair
    meta = {"issuer": "https://idp.example.com", "jwks_uri": "https://idp.example.com/jwks"}
    token = _make_id_token(private_jwk, iss=meta["issuer"], aud="my-client")

    async def fake_fetch(uri):
        return public_jwks
    monkeypatch.setattr(auth, "_fetch_jwks", fake_fetch)
    auth._jwks_cache.clear()

    claims = await auth._verify_id_token(token, meta, "my-client")
    assert claims["preferred_username"] == "alice"
    assert claims["email"] == "alice@example.com"
    assert claims["groups"] == ["admins"]


@pytest.mark.asyncio
async def test_verify_id_token_wrong_signature_rejected(monkeypatch, rsa_keypair):
    """A token signed by a DIFFERENT key must be rejected."""
    from authlib.jose import JsonWebKey
    _, public_jwks = rsa_keypair
    attacker = JsonWebKey.generate_key("RSA", 2048, is_private=True).as_dict(is_private=True)
    attacker["kid"] = "test-key-1"  # claim the same kid but wrong key
    meta = {"issuer": "https://idp.example.com", "jwks_uri": "https://idp.example.com/jwks"}
    token = _make_id_token(attacker, iss=meta["issuer"], aud="my-client")

    async def fake_fetch(uri):
        return public_jwks
    monkeypatch.setattr(auth, "_fetch_jwks", fake_fetch)
    auth._jwks_cache.clear()

    with pytest.raises(Exception):
        await auth._verify_id_token(token, meta, "my-client")


@pytest.mark.asyncio
async def test_verify_id_token_wrong_audience_rejected(monkeypatch, rsa_keypair):
    private_jwk, public_jwks = rsa_keypair
    meta = {"issuer": "https://idp.example.com", "jwks_uri": "https://idp.example.com/jwks"}
    token = _make_id_token(private_jwk, iss=meta["issuer"], aud="some-other-client")

    async def fake_fetch(uri):
        return public_jwks
    monkeypatch.setattr(auth, "_fetch_jwks", fake_fetch)
    auth._jwks_cache.clear()

    with pytest.raises(Exception):
        await auth._verify_id_token(token, meta, "my-client")


@pytest.mark.asyncio
async def test_verify_id_token_expired_rejected(monkeypatch, rsa_keypair):
    private_jwk, public_jwks = rsa_keypair
    meta = {"issuer": "https://idp.example.com", "jwks_uri": "https://idp.example.com/jwks"}
    token = _make_id_token(private_jwk, iss=meta["issuer"], aud="my-client", exp_delta=-10)

    async def fake_fetch(uri):
        return public_jwks
    monkeypatch.setattr(auth, "_fetch_jwks", fake_fetch)
    auth._jwks_cache.clear()

    with pytest.raises(Exception):
        await auth._verify_id_token(token, meta, "my-client")
