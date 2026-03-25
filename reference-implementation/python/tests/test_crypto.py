"""Tests for a2cn.crypto"""

import pytest
import jcs

from a2cn.crypto import (
    generate_keypair,
    private_key_to_jwk,
    public_key_to_jwk,
    public_key_from_jwk,
    private_key_from_jwk,
    canonicalize,
    hash_object,
    sign_jws,
    verify_jws,
    create_jwt,
    verify_jwt,
)


# ---------------------------------------------------------------------------
# Sanity check: JCS library behaviour
# ---------------------------------------------------------------------------

def test_jcs_key_ordering():
    """JCS must sort keys, not just serialize."""
    result = jcs.canonicalize({"b": 2, "a": 1})
    assert result == b'{"a":1,"b":2}'


def test_jcs_nested():
    result = jcs.canonicalize({"z": {"b": 2, "a": 1}, "a": 0})
    assert result == b'{"a":0,"z":{"a":1,"b":2}}'


# ---------------------------------------------------------------------------
# Keypair generation
# ---------------------------------------------------------------------------

def test_generate_keypair_returns_p256():
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
    priv, pub = generate_keypair()
    assert isinstance(priv.curve, SECP256R1)
    assert isinstance(pub.curve, SECP256R1)


def test_keypair_uniqueness():
    priv1, _ = generate_keypair()
    priv2, _ = generate_keypair()
    assert priv1.private_numbers().private_value != priv2.private_numbers().private_value


# ---------------------------------------------------------------------------
# JWK round-trips
# ---------------------------------------------------------------------------

def test_public_key_jwk_roundtrip():
    priv, pub = generate_keypair()
    jwk = public_key_to_jwk(pub)
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert "d" not in jwk  # no private component

    recovered = public_key_from_jwk(jwk)
    assert recovered.public_numbers() == pub.public_numbers()


def test_private_key_jwk_roundtrip():
    priv, pub = generate_keypair()
    jwk = private_key_to_jwk(priv)
    assert "d" in jwk

    recovered = private_key_from_jwk(jwk)
    assert recovered.private_numbers().private_value == priv.private_numbers().private_value


# ---------------------------------------------------------------------------
# hash_object
# ---------------------------------------------------------------------------

def test_hash_object_deterministic():
    obj = {"session_id": "abc", "round_number": 1, "total_value": 9500000}
    h1 = hash_object(obj)
    h2 = hash_object(obj)
    assert h1 == h2


def test_hash_object_key_order_independent():
    """hash_object must produce the same result regardless of key insertion order."""
    obj1 = {"b": 2, "a": 1}
    obj2 = {"a": 1, "b": 2}
    assert hash_object(obj1) == hash_object(obj2)


def test_hash_object_returns_base64url():
    import base64
    h = hash_object({"x": 1})
    # base64url chars only
    assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in h)
    # no padding
    assert "=" not in h


def test_hash_object_changes_with_content():
    assert hash_object({"a": 1}) != hash_object({"a": 2})


# ---------------------------------------------------------------------------
# JWS sign / verify roundtrip
# ---------------------------------------------------------------------------

def test_jws_roundtrip():
    priv, pub = generate_keypair()
    payload = "sha256-somehashvalue"
    token = sign_jws(payload, priv)
    recovered = verify_jws(token, pub)
    assert recovered == payload


def test_jws_wrong_key_raises():
    import jwt as pyjwt
    priv1, _ = generate_keypair()
    _, pub2 = generate_keypair()
    token = sign_jws("test", priv1)
    with pytest.raises(pyjwt.exceptions.InvalidSignatureError):
        verify_jws(token, pub2)


def test_jws_with_kid():
    priv, pub = generate_keypair()
    token = sign_jws("myhash", priv, kid="did:web:example.com#key-1")
    # Should still verify
    recovered = verify_jws(token, pub)
    assert recovered == "myhash"


# ---------------------------------------------------------------------------
# JWT create / verify roundtrip
# ---------------------------------------------------------------------------

def test_jwt_roundtrip():
    priv, pub = generate_keypair()
    token = create_jwt(
        issuer_did="did:web:initiator.example",
        audience_did="did:web:responder.example",
        private_key=priv,
        purpose="a2cn_session_init",
        exp_seconds=300,
    )
    payload = verify_jwt(
        token,
        pub,
        expected_audience="did:web:responder.example",
        expected_issuer="did:web:initiator.example",
    )
    assert payload["iss"] == "did:web:initiator.example"
    assert payload["aud"] == "did:web:responder.example"
    assert payload["purpose"] == "a2cn_session_init"
    assert "jti" in payload
    assert "iat" in payload
    assert "exp" in payload


def test_jwt_wrong_audience_raises():
    import jwt as pyjwt
    priv, pub = generate_keypair()
    token = create_jwt("did:web:a", "did:web:b", priv)
    with pytest.raises(pyjwt.exceptions.InvalidAudienceError):
        verify_jwt(token, pub, expected_audience="did:web:wrong")


def test_jwt_with_session_id():
    priv, pub = generate_keypair()
    token = create_jwt(
        issuer_did="did:web:a",
        audience_did="did:web:b",
        private_key=priv,
        session_id="my-session-id",
    )
    payload = verify_jwt(token, pub, expected_audience="did:web:b")
    assert payload["session_id"] == "my-session-id"


def test_jwt_expired_raises():
    import time
    import jwt as pyjwt
    priv, pub = generate_keypair()
    token = create_jwt("did:web:a", "did:web:b", priv, exp_seconds=-1)
    with pytest.raises(pyjwt.exceptions.ExpiredSignatureError):
        verify_jwt(token, pub, expected_audience="did:web:b")
