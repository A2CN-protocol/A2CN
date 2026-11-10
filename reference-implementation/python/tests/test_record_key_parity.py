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
