"""
A2CN Cryptographic Primitives

Implements:
- P-256 EC keypair generation
- RFC 8785 JCS canonicalization
- SHA-256 hashing of JCS-canonicalized objects (base64url output)
- JWS signing/verification of protocol act hashes using ES256
- JWT creation and verification for request authentication (Section 11.1.4)
"""

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

import jcs
import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)


def generate_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate a P-256 EC keypair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def private_key_to_jwk(private_key: EllipticCurvePrivateKey) -> dict:
    """Serialize a P-256 private key to JWK format."""
    numbers = private_key.private_numbers()
    pub_numbers = numbers.public_numbers
    coord_len = 32  # P-256 coordinates are 32 bytes

    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(pub_numbers.x.to_bytes(coord_len, "big")),
        "y": _b64url_encode(pub_numbers.y.to_bytes(coord_len, "big")),
        "d": _b64url_encode(numbers.private_value.to_bytes(coord_len, "big")),
    }


def public_key_to_jwk(public_key: EllipticCurvePublicKey) -> dict:
    """Serialize a P-256 public key to JWK format."""
    pub_numbers = public_key.public_numbers()
    coord_len = 32

    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(pub_numbers.x.to_bytes(coord_len, "big")),
        "y": _b64url_encode(pub_numbers.y.to_bytes(coord_len, "big")),
    }


def public_key_from_jwk(jwk: dict) -> EllipticCurvePublicKey:
    """Reconstruct a P-256 public key from a JWK dict."""
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return pub_numbers.public_key()


def private_key_from_jwk(jwk: dict) -> EllipticCurvePrivateKey:
    """Reconstruct a P-256 private key from a JWK dict."""
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
    pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    priv_numbers = ec.EllipticCurvePrivateNumbers(d, pub_numbers)
    return priv_numbers.private_key()


# ---------------------------------------------------------------------------
# JCS + hashing
# ---------------------------------------------------------------------------

def canonicalize(obj: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme."""
    return jcs.canonicalize(obj)


def hash_object(obj: Any) -> str:
    """JCS-canonicalize an object, SHA-256 hash it, return base64url string."""
    canonical_bytes = canonicalize(obj)
    digest = hashlib.sha256(canonical_bytes).digest()
    return _b64url_encode(digest)


def hash_bytes(data: bytes) -> str:
    """SHA-256 hash raw bytes, return base64url string."""
    return _b64url_encode(hashlib.sha256(data).digest())


# ---------------------------------------------------------------------------
# JWS signing / verification (used for protocol_act_signature)
# ---------------------------------------------------------------------------

def sign_jws(payload_str: str, private_key: EllipticCurvePrivateKey, kid: str | None = None) -> str:
    """
    Create a JWS compact serialization signing `payload_str` with ES256.

    The payload is the protocol_act_hash (a base64url string). We encode it
    as the JWS payload bytes so the full compact token is:
      base64url(header).base64url(payload).signature
    """
    headers = {"alg": "ES256"}
    if kid:
        headers["kid"] = kid

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = pyjwt.encode(
        {"payload": payload_str},  # wrap in a claim so PyJWT is happy
        pem,
        algorithm="ES256",
        headers=headers,
    )
    return token


def verify_jws(token: str, public_key: EllipticCurvePublicKey) -> str:
    """
    Verify an ES256 JWS compact token and return the payload string.
    Raises jwt.InvalidSignatureError on failure.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    decoded = pyjwt.decode(token, pem, algorithms=["ES256"])
    return decoded["payload"]


# ---------------------------------------------------------------------------
# JWT creation / verification (used for HTTP Authorization headers)
# ---------------------------------------------------------------------------

def create_jwt(
    issuer_did: str,
    audience_did: str,
    private_key: EllipticCurvePrivateKey,
    kid: str | None = None,
    purpose: str | None = None,
    session_id: str | None = None,
    exp_seconds: int = 60,
) -> str:
    """
    Create a signed JWT per Section 11.1.4.

    Fields: iss, aud, iat, exp, jti, purpose (optional), session_id (optional)
    Algorithm: ES256
    """
    now = int(datetime.now(timezone.utc).timestamp())
    payload: dict[str, Any] = {
        "iss": issuer_did,
        "aud": audience_did,
        "iat": now,
        "exp": now + exp_seconds,
        "jti": str(uuid.uuid4()),
    }
    if purpose:
        payload["purpose"] = purpose
    if session_id:
        payload["session_id"] = session_id

    headers: dict[str, Any] = {"alg": "ES256"}
    if kid:
        headers["kid"] = kid

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pyjwt.encode(payload, pem, algorithm="ES256", headers=headers)


def verify_jwt(
    token: str,
    public_key: EllipticCurvePublicKey,
    expected_audience: str | None = None,
    expected_issuer: str | None = None,
) -> dict:
    """
    Verify an ES256 JWT and return the decoded payload dict.
    Raises pyjwt exceptions on failure.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    options: dict[str, Any] = {"require": ["iss", "aud", "iat", "exp", "jti"]}
    kwargs: dict[str, Any] = {"algorithms": ["ES256"], "options": options}
    if expected_audience:
        kwargs["audience"] = expected_audience
    if expected_issuer:
        kwargs["issuer"] = expected_issuer

    return pyjwt.decode(token, pem, **kwargs)


# ---------------------------------------------------------------------------
# v0.2.0: Invitation signing / verification (Component 8)
# ---------------------------------------------------------------------------

def sign_invitation(invitation_dict: dict, private_key: EllipticCurvePrivateKey) -> str:
    """
    Signs a SessionInvitation or InvitationAcceptance dict using ES256 + RFC 8785 JCS.

    Steps:
    1. Copy dict WITHOUT 'invitation_signature' and 'acceptance_signature' keys
    2. Serialize to canonical JSON (JCS)
    3. Compute SHA-256 hash of canonical bytes
    4. Sign hash bytes with ES256
    5. Return base64url-encoded DER signature

    The caller sets invitation_dict['invitation_signature'] = result.
    """
    canonical_obj = {k: v for k, v in invitation_dict.items()
                     if k not in ("invitation_signature", "acceptance_signature")}
    canonical_bytes = canonicalize(canonical_obj)

    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives import hashes as _hashes
    der_sig = private_key.sign(canonical_bytes, _ec.ECDSA(_hashes.SHA256()))
    return _b64url_encode(der_sig)


def verify_invitation_signature(invitation_dict: dict, public_key: EllipticCurvePublicKey) -> bool:
    """
    Verifies a SessionInvitation or InvitationAcceptance signature.

    Steps:
    1. Extract signature from 'invitation_signature' or 'acceptance_signature'
    2. Copy dict WITHOUT both signature keys
    3. Serialize to canonical JSON and SHA-256 hash
    4. Verify ES256 DER signature against hash
    5. Return True if valid, False otherwise
    """
    sig_b64 = invitation_dict.get("invitation_signature") or invitation_dict.get("acceptance_signature", "")
    if not sig_b64:
        return False

    canonical_obj = {k: v for k, v in invitation_dict.items()
                     if k not in ("invitation_signature", "acceptance_signature")}
    canonical_bytes = canonicalize(canonical_obj)

    try:
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives import hashes as _hashes
        der_sig = _b64url_decode(sig_b64)
        public_key.verify(der_sig, canonical_bytes, _ec.ECDSA(_hashes.SHA256()))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    # Re-add padding
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)
