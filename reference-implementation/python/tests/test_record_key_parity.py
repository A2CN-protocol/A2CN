"""Values on a TransactionRecord's key path that Python and TypeScript must refuse alike.

A verification method or signature that is not a non-empty string, or a JWS
whose protected header is not a JSON object, was refused for different reasons
in the two implementations: a truthiness test let a list through one and not
the other, and a number reached a string method in one and a catch-all in the
other. Both now read these values by type. The TypeScript suite reads the same
``transaction-record-key-parity.json``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from a2cn.record import verify_transaction_record, verify_transaction_record_reason

VECTOR = json.loads(
    (Path(__file__).parents[3] / "spec" / "test-vectors" / "transaction-record-key-parity.json").read_text()
)


@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda case: case["name"])
def test_the_record_reaches_the_stated_reason(case):
    documents = VECTOR["did_documents"]
    assert verify_transaction_record_reason(case["record"], documents, case["offer_hashes"]) == (
        case["expected_reason"]
    )
    assert verify_transaction_record(case["record"], documents, case["offer_hashes"]) is case["verifies"]


@pytest.mark.parametrize("token", [7, True, None, [], {}], ids=repr)
def test_verify_jws_refuses_a_token_that_is_not_a_string(token):
    from jwt.exceptions import InvalidSignatureError

    from a2cn.crypto import generate_keypair, verify_jws

    _private, public = generate_keypair()
    with pytest.raises(InvalidSignatureError):
        verify_jws(token, public)


def _signed_segments(private_key, header: bytes, payload: bytes) -> str:
    """A genuine ES256 compact JWS over the given raw header and payload bytes."""
    import base64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from a2cn.crypto import _ecdsa_der_to_raw

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    signing_input = f"{b64(header)}.{b64(payload)}"
    der = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    return f"{signing_input}.{b64(_ecdsa_der_to_raw(der))}"


@pytest.mark.parametrize(
    "header, payload",
    [
        (b'{"alg":"ES256"}', b"\xef\xbb\xbfpayload"),
        (b'{"alg":"ES256"}', b"pay\xffload"),
        (b"\xef\xbb\xbf" + b'{"alg":"ES256"}', b"payload"),
        (b'{"alg":"ES256","x":"\xff"}', b"payload"),
        (b'{"alg":"ES256","x":NaN}', b"payload"),
    ],
    ids=["payload-bom", "payload-not-utf8", "header-bom", "header-not-utf8", "header-nan"],
)
def test_a_jws_segment_is_strict_utf8_json_with_no_bom(header, payload):
    from jwt.exceptions import InvalidSignatureError

    from a2cn.crypto import generate_keypair, verify_jws

    private, public = generate_keypair()
    assert verify_jws(_signed_segments(private, b'{"alg":"ES256"}', b"payload"), public) == "payload"
    with pytest.raises(InvalidSignatureError):
        verify_jws(_signed_segments(private, header, payload), public)


_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _flip_unused_bit(text: str) -> str:
    """The same bytes under a non-canonical text: an unused trailing bit set."""
    assert len(text) % 4 in (2, 3)
    return text[:-1] + _ALPHABET[_ALPHABET.index(text[-1]) | 1]


def _signed_texts(private_key, header_text: str, payload_text: str) -> str:
    """A genuine ES256 compact JWS over the segment texts exactly as given."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from a2cn.crypto import _ecdsa_der_to_raw

    signing_input = f"{header_text}.{payload_text}"
    der = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    return f"{signing_input}.{_b64(_ecdsa_der_to_raw(der))}"


# The header {"alg":"ES256","x":"??>~"} encodes with '-' and '_' and unused trailing bits.
_HEADER = _b64(b'{"alg":"ES256","x":"??>~"}')
_PAYLOAD = _b64(b"payload1")


def _shapes():
    """(label, segment, bad text) for every rule a JWS segment's base64url must meet."""
    return [
        ("star", "header", _HEADER[:4] + "*" + _HEADER[4:]),
        ("space", "header", _HEADER[:4] + " " + _HEADER[4:]),
        ("newline", "header", _HEADER[:4] + "\n" + _HEADER[4:]),
        ("plus-slash", "header", _HEADER.replace("-", "+").replace("_", "/")),
        ("padding", "header", _HEADER + "=" * (-len(_HEADER) % 4)),
        ("padding-inside", "header", _HEADER[:4] + "=" + _HEADER[4:]),
        ("length-1-mod-4", "header", _b64(b'{"alg":"ES256"}') + "A"),
        ("noncanonical-tail", "header", _flip_unused_bit(_HEADER)),
        ("length-1-mod-4", "payload", _b64(b"payloa") + "A"),
        ("noncanonical-tail", "payload", _flip_unused_bit(_PAYLOAD)),
        ("padding", "signature", None),
        ("noncanonical-tail", "signature", None),
    ]


@pytest.mark.parametrize("label, segment, bad", _shapes(), ids=lambda v: v if isinstance(v, str) else "")
def test_a_jws_segment_is_canonical_unpadded_base64url(label, segment, bad):
    from jwt.exceptions import InvalidSignatureError

    from a2cn.crypto import generate_keypair, verify_jws

    assert "-" in _HEADER and "_" in _HEADER and len(_HEADER) % 4 in (2, 3)
    private, public = generate_keypair()
    good = _signed_texts(private, _HEADER, _PAYLOAD)
    assert verify_jws(good, public) == "payload1"
    if segment == "header":
        token = _signed_texts(private, bad, _PAYLOAD)
    elif segment == "payload":
        token = _signed_texts(private, _HEADER, bad)
    else:
        head, signature = good.rsplit(".", 1)
        bad = signature + "=" * (-len(signature) % 4) if label == "padding" else _flip_unused_bit(signature)
        token = f"{head}.{bad}"
    with pytest.raises(InvalidSignatureError):
        verify_jws(token, public)


@pytest.mark.parametrize(
    "spoil",
    [
        lambda v: v + "=",
        lambda v: v[:4] + "*" + v[4:],
        lambda v: v[:4] + " " + v[4:],
        lambda v: v.replace("-", "+").replace("_", "/") if ("-" in v or "_" in v) else v + "=",
    ],
    ids=["padding", "star", "space", "plus-slash"],
)
def test_a_public_jwk_coordinate_is_canonical_base64url(spoil):
    from a2cn.crypto import generate_keypair, public_key_from_jwk, public_key_to_jwk

    _private, public = generate_keypair()
    jwk = public_key_to_jwk(public)
    public_key_from_jwk(jwk)
    for name in ("x", "y"):
        with pytest.raises(ValueError):
            public_key_from_jwk({**jwk, name: spoil(jwk[name])})


@pytest.mark.parametrize("label", ["padding", "noncanonical-tail", "star"])
def test_an_invitation_signature_is_canonical_base64url(label):
    from a2cn.crypto import generate_ed25519_keypair, sign_invitation, verify_invitation_signature

    private, public = generate_ed25519_keypair()
    invitation = {"invitation_id": "inv-1", "inviter_did": "did:web:buyer.example"}
    invitation["invitation_signature"] = sign_invitation(invitation, private)
    assert verify_invitation_signature(invitation, public)
    signature = invitation["invitation_signature"]
    spoiled = {
        "padding": signature + "=" * (-len(signature) % 4),
        "noncanonical-tail": _flip_unused_bit(signature),
        "star": signature[:4] + "*" + signature[4:],
    }[label]
    assert spoiled != signature
    assert not verify_invitation_signature({**invitation, "invitation_signature": spoiled}, public)
