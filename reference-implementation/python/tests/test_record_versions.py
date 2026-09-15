"""record_version: the values each record verifier accepts, and what producers emit.

spec/test-vectors/record-versions.json lists the values. Both suites reseal a
valid TransactionRecord and a valid SessionEvidenceRecord with each one and must
reach the same verdict. A value outside the accepted set is rejected, never
parsed best-effort (Sections 9.5 and 9A.6).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn.crypto import hash_object, private_key_from_jwk, sign_jws
from a2cn.evidence import generate_session_evidence_record, verify_session_evidence_record
from a2cn.record import generate_audit_log, generate_transaction_record, verify_transaction_record
from a2cn.session import Session, SessionManager, SessionState

REPO_ROOT = Path(__file__).parents[3]
VECTORS = REPO_ROOT / "spec" / "test-vectors"
RECORD_VERSIONS = json.loads((VECTORS / "record-versions.json").read_text())
TR_VECTOR = json.loads((VECTORS / "transaction-record-basis.json").read_text())
SER_VECTOR = json.loads((VECTORS / "session-evidence-record-parity.json").read_text())
SER_KEY = private_key_from_jwk(SER_VECTOR["producer_private_jwk"])
SCHEMA = json.loads(
    (REPO_ROOT / "spec" / "schemas" / "session-evidence-record.schema.json").read_text()
)

CASES = [
    pytest.param({"record_version": version}, True, id=f"accepted-{version}")
    for version in RECORD_VERSIONS["accepted"]
] + [
    pytest.param(case, False, id=case["name"]) for case in RECORD_VERSIONS["rejected"]
]


def _with_version(record: dict, case: dict) -> dict:
    """The record with the case's record_version, or without the key if it has none."""
    record = copy.deepcopy(record)
    if "record_version" in case:
        record["record_version"] = copy.deepcopy(case["record_version"])
    else:
        del record["record_version"]
    return record


def _transaction_record_session():
    """Replay transaction-record-basis.json through the state machine to COMPLETED."""
    manager = SessionManager()
    for did, did_document in TR_VECTOR["did_documents"].items():
        manager.register_did_document(did, did_document)
    session_ack = TR_VECTOR["session_ack"]
    session = manager.create_session(
        TR_VECTOR["session_id"],
        TR_VECTOR["session_init"],
        session_ack,
        session_ack["session_created_at"],
    )
    session.session_timeout_seconds = 86400 * 365 * 100  # the timestamps are in the past
    for message in copy.deepcopy(TR_VECTOR["messages"]):
        manager.process_message(session, message)
    assert session.state == SessionState.COMPLETED
    return session


def _transaction_record_offer_hashes() -> list[str]:
    return [
        message["protocol_act_hash"]
        for message in TR_VECTOR["messages"]
        if message["message_type"] in ("offer", "counteroffer")
    ]


def _session_evidence_record() -> dict:
    """The record session-evidence-record-parity.json produces."""
    source = SER_VECTOR["session"]
    session = Session(
        session_id=source["session_id"],
        state=source["state"],
        current_turn="none",
        terminal_reason=source["terminal_reason"],
        terminal_message_id=source["terminal_message_id"],
        session_created_at=source["session_created_at"],
        state_updated_at=source["state_updated_at"],
        session_params=source["session_params"],
        initiator_mandate=source["initiator_mandate"],
        responder_mandate=source["responder_mandate"],
    )
    session._session_init = source["session_init"]
    session._session_ack = source["session_ack"]
    session._message_log = source["message_log"]
    producer = SER_VECTOR["producer"]
    return generate_session_evidence_record(
        session,
        producer_private_key=SER_KEY,
        producer_did=producer["did"],
        producer_agent_id=producer["agent_id"],
        producer_verification_method=producer["verification_method"],
        observed_acts=SER_VECTOR["observed_acts"],
    )


@pytest.mark.parametrize(("case", "accepted"), CASES)
def test_transaction_record_verifier_accepts_only_recognized_versions(case, accepted):
    record = _with_version(generate_transaction_record(_transaction_record_session()), case)
    record["record_hash"] = ""
    record["record_hash"] = hash_object(record)

    assert (
        verify_transaction_record(
            record, TR_VECTOR["did_documents"], _transaction_record_offer_hashes()
        )
        is accepted
    )


@pytest.mark.parametrize(("case", "accepted"), CASES)
def test_session_evidence_record_verifier_accepts_only_recognized_versions(case, accepted):
    record = _with_version(_session_evidence_record(), case)
    record["record_hash"] = ""
    record["producer_signature"] = ""
    record["record_hash"] = hash_object(record)
    record["producer_signature"] = sign_jws(
        record["record_hash"], SER_KEY, kid=SER_VECTOR["producer"]["verification_method"]
    )

    assert verify_session_evidence_record(record, SER_VECTOR["did_documents"]) is accepted


def test_producers_emit_the_current_versions():
    emitted = RECORD_VERSIONS["producers_emit"]
    session = _transaction_record_session()

    assert generate_transaction_record(session)["record_version"] == emitted["transaction_record"]
    assert _session_evidence_record()["record_version"] == emitted["session_evidence_record"]
    # The AuditLog's content did not change, so its version did not move.
    assert generate_audit_log(session)["log_version"] == emitted["audit_log"]
    assert emitted["transaction_record"] in RECORD_VERSIONS["accepted"]
    assert emitted["session_evidence_record"] in RECORD_VERSIONS["accepted"]


def test_the_evidence_schema_names_the_version_producers_emit():
    """The schema, the specification, and both implementations use the same value."""
    version = RECORD_VERSIONS["producers_emit"]["session_evidence_record"]

    assert SCHEMA["$id"] == f"https://a2cn.dev/schemas/session-evidence-record/{version}"
    assert SCHEMA["properties"]["record_version"]["const"] == version
