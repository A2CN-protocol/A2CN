"""
A2CN Cryptographic Primitives

Implements:
- P-256 EC and Ed25519 keypair generation
- RFC 8785 JCS canonicalization
- SHA-256 hashing of JCS-canonicalized objects (base64url output)
- JWS signing/verification of protocol act hashes using ES256 or EdDSA
- JWT creation and verification for request authentication (Section 11.1.4)
"""

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import jcs
import jwt as pyjwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

SigningPrivateKey = EllipticCurvePrivateKey | Ed25519PrivateKey
SigningPublicKey = EllipticCurvePublicKey | Ed25519PublicKey


def generate_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate a P-256 EC keypair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def private_key_to_jwk(private_key: SigningPrivateKey) -> dict:
    """Serialize a supported private key to JWK format."""
    if isinstance(private_key, Ed25519PrivateKey):
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url_encode(public_bytes),
            "d": _b64url_encode(private_bytes),
        }

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


def public_key_to_jwk(public_key: SigningPublicKey) -> dict:
    """Serialize a supported public key to JWK format."""
    if isinstance(public_key, Ed25519PublicKey):
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url_encode(public_bytes),
        }

    pub_numbers = public_key.public_numbers()
    coord_len = 32

    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(pub_numbers.x.to_bytes(coord_len, "big")),
        "y": _b64url_encode(pub_numbers.y.to_bytes(coord_len, "big")),
    }


def public_key_from_jwk(jwk: dict) -> SigningPublicKey:
    """Reconstruct a supported public key from a JWK dict."""
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        return Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))

    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return pub_numbers.public_key()


def private_key_from_jwk(jwk: dict) -> SigningPrivateKey:
    """Reconstruct a supported private key from a JWK dict."""
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        return Ed25519PrivateKey.from_private_bytes(_b64url_decode(jwk["d"]))

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

def sign_jws(payload_str: str, private_key: SigningPrivateKey, kid: str | None = None) -> str:
    """
    Create a JWS compact serialization signing `payload_str` with ES256 or EdDSA.

    The payload is the protocol_act_hash (a base64url string). We encode it
    as the JWS payload bytes so the full compact token is:
      base64url(header).base64url(payload).signature
    """
    algorithm = _jwt_algorithm_for_private_key(private_key)
    headers = {"alg": algorithm}
    if kid:
        headers["kid"] = kid

    protected = _b64url_encode(
        json.dumps(headers, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    payload = _b64url_encode(payload_str.encode("utf-8"))
    signing_input = f"{protected}.{payload}".encode("ascii")

    if isinstance(private_key, Ed25519PrivateKey):
        signature = private_key.sign(signing_input)
    else:
        der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        signature = _ecdsa_der_to_raw(der_signature)

    return f"{protected}.{payload}.{_b64url_encode(signature)}"


def verify_jws(token: str, public_key: SigningPublicKey) -> str:
    """
    Verify a JWS compact token and return the payload string.
    Raises jwt.InvalidSignatureError on failure.
    """
    try:
        protected, payload, signature = token.split(".")
        header = json.loads(_b64url_decode(protected))
        expected_alg = _jwt_algorithm_for_public_key(public_key)
        if header.get("alg") != expected_alg:
            raise pyjwt.exceptions.InvalidSignatureError("JWS alg does not match key type")

        signing_input = f"{protected}.{payload}".encode("ascii")
        signature_bytes = _b64url_decode(signature)
        if isinstance(public_key, Ed25519PublicKey):
            public_key.verify(signature_bytes, signing_input)
        else:
            public_key.verify(
                _ecdsa_raw_to_der(signature_bytes),
                signing_input,
                ec.ECDSA(hashes.SHA256()),
            )
        return _b64url_decode(payload).decode("utf-8")
    except pyjwt.exceptions.InvalidSignatureError:
        raise
    except (InvalidSignature, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise pyjwt.exceptions.InvalidSignatureError("Invalid JWS signature") from exc


# ---------------------------------------------------------------------------
# JWT creation / verification (used for HTTP Authorization headers)
# ---------------------------------------------------------------------------

def create_jwt(
    issuer_did: str,
    audience_did: str,
    private_key: SigningPrivateKey,
    kid: str | None = None,
    purpose: str | None = None,
    session_id: str | None = None,
    exp_seconds: int = 60,
) -> str:
    """
    Create a signed JWT per Section 11.1.4.

    Fields: iss, aud, iat, exp, jti, purpose (optional), session_id (optional)
    Algorithm: ES256 for P-256 keys, EdDSA for Ed25519 keys
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

    algorithm = _jwt_algorithm_for_private_key(private_key)
    headers: dict[str, Any] = {"alg": algorithm}
    if kid:
        headers["kid"] = kid

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pyjwt.encode(payload, pem, algorithm=algorithm, headers=headers)


def verify_jwt(
    token: str,
    public_key: SigningPublicKey,
    expected_audience: str | None = None,
    expected_issuer: str | None = None,
) -> dict:
    """
    Verify a signed JWT and return the decoded payload dict.
    Raises pyjwt exceptions on failure.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    options: dict[str, Any] = {"require": ["iss", "aud", "iat", "exp", "jti"]}
    kwargs: dict[str, Any] = {
        "algorithms": [_jwt_algorithm_for_public_key(public_key)],
        "options": options,
    }
    if expected_audience:
        kwargs["audience"] = expected_audience
    if expected_issuer:
        kwargs["issuer"] = expected_issuer

    return pyjwt.decode(token, pem, **kwargs)


# ---------------------------------------------------------------------------
# v0.2.0: Invitation signing / verification (Component 8)
# ---------------------------------------------------------------------------

def sign_invitation(invitation_dict: dict, private_key: SigningPrivateKey) -> str:
    """
    Signs a SessionInvitation or InvitationAcceptance dict using RFC 8785 JCS.

    Steps:
    1. Copy dict WITHOUT 'invitation_signature' and 'acceptance_signature' keys
    2. Serialize to canonical JSON (JCS)
    3. Sign canonical bytes with the selected signing suite
    4. Return base64url-encoded signature bytes

    The caller sets invitation_dict['invitation_signature'] = result.
    """
    canonical_obj = {k: v for k, v in invitation_dict.items()
                     if k not in ("invitation_signature", "acceptance_signature")}
    canonical_bytes = canonicalize(canonical_obj)

    if isinstance(private_key, Ed25519PrivateKey):
        signature = private_key.sign(canonical_bytes)
    else:
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives import hashes as _hashes
        signature = private_key.sign(canonical_bytes, _ec.ECDSA(_hashes.SHA256()))
    return _b64url_encode(signature)


def verify_invitation_signature(invitation_dict: dict, public_key: SigningPublicKey) -> bool:
    """
    Verifies a SessionInvitation or InvitationAcceptance signature.

    Steps:
    1. Extract signature from 'invitation_signature' or 'acceptance_signature'
    2. Copy dict WITHOUT both signature keys
    3. Serialize to canonical JSON (JCS)
    4. Verify signature against canonical bytes
    5. Return True if valid, False otherwise
    """
    sig_b64 = invitation_dict.get("invitation_signature") or invitation_dict.get("acceptance_signature", "")
    if not sig_b64:
        return False

    canonical_obj = {k: v for k, v in invitation_dict.items()
                     if k not in ("invitation_signature", "acceptance_signature")}
    canonical_bytes = canonicalize(canonical_obj)

    try:
        signature = _b64url_decode(sig_b64)
        if isinstance(public_key, Ed25519PublicKey):
            public_key.verify(signature, canonical_bytes)
        else:
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            from cryptography.hazmat.primitives import hashes as _hashes
            public_key.verify(signature, canonical_bytes, _ec.ECDSA(_hashes.SHA256()))
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


def _ecdsa_der_to_raw(der_signature: bytes) -> bytes:
    r, s = utils.decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _ecdsa_raw_to_der(raw_signature: bytes) -> bytes:
    if len(raw_signature) != 64:
        raise ValueError("ES256 signatures must be 64 raw bytes")
    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:], "big")
    return utils.encode_dss_signature(r, s)


def _jwt_algorithm_for_private_key(private_key: SigningPrivateKey) -> str:
    if isinstance(private_key, Ed25519PrivateKey):
        return "EdDSA"
    return "ES256"


def _jwt_algorithm_for_public_key(public_key: SigningPublicKey) -> str:
    if isinstance(public_key, Ed25519PublicKey):
        return "EdDSA"
    return "ES256"
