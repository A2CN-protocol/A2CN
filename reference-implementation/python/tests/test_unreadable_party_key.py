"""A party key its DID document lists but that cannot be read is unavailable, not malformed.

A public JWK coordinate must be unpadded base64url (RFC 7515, RFC 7518). A
signer whose document spells one otherwise (padded, the standard alphabet, a
non-canonical tail, a stray character) has a key no verifier can read, which
says nothing about the record: the record verifier and the evidence and act
verifiers report KEY_NOT_FOUND, and a2cn-verify COULD NOT FINISH and says why.
The record rows live in transaction-record-key-parity.json, which the
TypeScript suite runs too.
"""

from __future__ import annotations

import copy
import io
import json
from pathlib import Path

import pytest

from a2cn.acts import ACT_REASON_KEY_NOT_FOUND, verify_signed_act_reason
from a2cn.evidence import EVIDENCE_REASON_KEY_NOT_FOUND, assess_session_evidence_record
from a2cn.verify import EXIT_UNFINISHED, run

VECTORS = Path(__file__).parents[3] / "spec" / "test-vectors"
KEY_PARITY = json.loads((VECTORS / "transaction-record-key-parity.json").read_text())
HISTORY = json.loads((VECTORS / "transaction-record-offer-history.json").read_text())
BASIS = json.loads((VECTORS / "transaction-record-basis.json").read_text())
UNREADABLE = [case for case in KEY_PARITY["cases"] if case["name"].startswith("unreadable_")]


def _padded_x(documents: dict, did: str) -> dict:
    documents = copy.deepcopy(documents)
    jwk = documents[did]["verificationMethod"][0]["publicKeyJwk"]
    jwk["x"] += "=" * (-len(jwk["x"]) % 4)
    return documents


def test_the_evidence_verifier_reports_an_unreadable_key_as_unavailable():
    record = HISTORY["evidence_record"]
    documents = HISTORY["did_documents"]["current"]
    assert assess_session_evidence_record(record, documents)["reason"] is None
    for did in documents:
        assert assess_session_evidence_record(record, _padded_x(documents, did))["reason"] == (
            EVIDENCE_REASON_KEY_NOT_FOUND
        )


def test_the_act_verifier_reports_an_unreadable_key_as_unavailable():
    offer = BASIS["messages"][0]
    documents = BASIS["did_documents"]
    assert verify_signed_act_reason(offer, documents, wire_version="0.2") is None
    assert verify_signed_act_reason(
        offer, _padded_x(documents, offer["sender_did"]), wire_version="0.2"
    ) == ACT_REASON_KEY_NOT_FOUND


@pytest.mark.parametrize("case", UNREADABLE, ids=lambda case: case["name"])
def test_a2cn_verify_cannot_finish_and_says_why(tmp_path, case):
    record = tmp_path / "record.json"
    record.write_text(json.dumps(case["record"]))
    args = [str(record)]
    for index, document in enumerate(case["did_documents"].values()):
        path = tmp_path / f"did-{index}.json"
        path.write_text(json.dumps(document))
        args.append(str(path))
    args.append("--offline")
    out = io.StringIO()
    status = run(args, out=out, err=out)
    output = out.getvalue()
    assert status == EXIT_UNFINISHED, output
    assert "COULD NOT FINISH: a key in a signer's DID document can't be read" in output
    coordinate = "y" if "_key_y_" in case["name"] else "x"
    if case["name"].endswith("_extra_character"):
        # One more character makes a canonical text for 33 bytes: no P-256 point.
        assert "in its DID document can't be read: " in output
    else:
        assert (
            f"in its DID document can't be read: its {coordinate} coordinate isn't unpadded base64url (RFC 7518)"
        ) in output
