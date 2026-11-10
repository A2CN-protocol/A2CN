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
