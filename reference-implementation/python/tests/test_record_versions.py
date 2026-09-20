"""record_version: the values each record verifier accepts, and what producers emit.

spec/test-vectors/record-versions.json lists the values. Both suites reseal a
valid record of each shape of each artifact with each one and must reach the
same verdict. A record's version follows its shape: a "0.2" TransactionRecord
carries a top-level basis and a "0.1" one does not (Section 9.5, step 7), and a
"0.3" SessionEvidenceRecord carries external_commitment_reference and no other
version does (Section 9A.2). A value outside the accepted set is rejected,
never parsed best-effort (Sections 9.5 and 9A.6).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn.crypto import hash_object, private_key_from_jwk, sign_jws
from a2cn.evidence import (
    RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS,
    generate_session_evidence_record,
    verify_session_evidence_record,
)
from a2cn.record import (
    RECOGNIZED_TRANSACTION_RECORD_VERSIONS,
    generate_audit_log,
    generate_transaction_record,
    verify_transaction_record,
)
from a2cn.session import Session, SessionManager, SessionState

REPO_ROOT = Path(__file__).parents[3]
VECTORS = REPO_ROOT / "spec" / "test-vectors"
SCHEMAS = REPO_ROOT / "spec" / "schemas"
RECORD_VERSIONS = json.loads((VECTORS / "record-versions.json").read_text())
TR_VERSIONS = RECORD_VERSIONS["transaction_record"]
SER_VERSIONS = RECORD_VERSIONS["session_evidence_record"]
TR_VECTOR = json.loads((VECTORS / "transaction-record-basis.json").read_text())
SER_VECTOR = json.loads((VECTORS / "session-evidence-record-parity.json").read_text())
EXTERNAL_CHANNEL_VECTOR = json.loads(
    (VECTORS / "session-evidence-record-external-channel.json").read_text()
)

# The recorded session behind each TransactionRecord shape, and the version a
# producer emits for that shape (Section 9.3).
TR_SHAPES = {
    "session_with_basis": TR_VECTOR,
    "session_without_basis": TR_VECTOR["without_basis"],
}
TR_EMITTED = RECORD_VERSIONS["producers_emit"]["transaction_record"]
TR_SHAPE_FOR_VERSION = {version: shape for shape, version in TR_EMITTED.items()}

# The vector behind each SessionEvidenceRecord shape, and the version a producer
# emits for that shape (Section 9A.2).
SER_SHAPES = {
    "without_external_commitment": SER_VECTOR,
    "with_external_commitment": EXTERNAL_CHANNEL_VECTOR,
}
SER_EMITTED = RECORD_VERSIONS["producers_emit"]["session_evidence_record"]

TR_CASES = (
    [
        pytest.param(
            TR_SHAPE_FOR_VERSION[version], {"record_version": version}, True,
            id=f"accepted-{version}",
        )
        for version in TR_VERSIONS["accepted"]
    ]
    + [
        pytest.param(case["shape"], case, False, id=case["name"])
        for case in TR_VERSIONS["cross_shape"]
    ]
    + [
        pytest.param(shape, case, False, id=f"{case['name']}-{shape}")
        for case in TR_VERSIONS["rejected"]
        for shape in TR_SHAPES
    ]
)
SER_CASES = (
    [
        pytest.param(
            case["shape"], case, True, id=f"accepted-{case['record_version']}-{case['shape']}"
        )
        for case in SER_VERSIONS["accepted"]
    ]
    + [
        pytest.param(case["shape"], case, False, id=case["name"])
        for case in SER_VERSIONS["cross_shape"]
    ]
    + [
        pytest.param(shape, case, False, id=f"{case['name']}-{shape}")
        for case in SER_VERSIONS["rejected"]
        for shape in SER_SHAPES
    ]
)


def _with_version(record: dict, case: dict) -> dict:
    """The record with the case's record_version, or without the key if it has none."""
    record = copy.deepcopy(record)
    if "record_version" in case:
        record["record_version"] = copy.deepcopy(case["record_version"])
    else:
        del record["record_version"]
    return record


def _transaction_record_session(vector: dict):
    """Replay a session transaction-record-basis.json records to COMPLETED."""
    manager = SessionManager()
    for did, did_document in vector["did_documents"].items():
        manager.register_did_document(did, did_document)
    session_ack = vector["session_ack"]
    session = manager.create_session(
        vector["session_id"],
        vector["session_init"],
        session_ack,
        session_ack["session_created_at"],
    )
    session.session_timeout_seconds = 86400 * 365 * 100  # the timestamps are in the past
    for message in copy.deepcopy(vector["messages"]):
        manager.process_message(session, message)
    assert session.state == SessionState.COMPLETED
    return session


def _offer_hashes(vector: dict) -> list[str]:
    return [
        message["protocol_act_hash"]
        for message in vector["messages"]
        if message["message_type"] in ("offer", "counteroffer")
    ]


def _session_evidence_record(vector: dict) -> dict:
    """The record a SessionEvidenceRecord vector's session produces."""
    source = vector["session"]
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
    producer = vector["producer"]
    return generate_session_evidence_record(
        session,
        producer_private_key=private_key_from_jwk(vector["producer_private_jwk"]),
        producer_did=producer["did"],
        producer_agent_id=producer["agent_id"],
        producer_verification_method=producer["verification_method"],
        observed_acts=vector["observed_acts"],
        **copy.deepcopy(vector.get("options", {})),
    )


def _schema(artifact: str, version: str) -> dict:
    """An artifact's unversioned schema file is its "0.1" schema; each later
    version is published beside it as <artifact>-<version>.schema.json."""
    name = f"{artifact}.schema.json" if version == "0.1" else f"{artifact}-{version}.schema.json"
    return json.loads((SCHEMAS / name).read_text())


@pytest.mark.parametrize(("shape", "case", "accepted"), TR_CASES)
def test_transaction_record_verifier_accepts_only_recognized_versions(shape, case, accepted):
    vector = TR_SHAPES[shape]
    record = _with_version(generate_transaction_record(_transaction_record_session(vector)), case)
    record["record_hash"] = ""
    record["record_hash"] = hash_object(record)

    assert (
        verify_transaction_record(record, vector["did_documents"], _offer_hashes(vector))
        is accepted
    )


@pytest.mark.parametrize(("shape", "case", "accepted"), SER_CASES)
def test_session_evidence_record_verifier_accepts_only_recognized_versions(shape, case, accepted):
    vector = SER_SHAPES[shape]
    record = _with_version(_session_evidence_record(vector), case)
    record["record_hash"] = ""
    record["producer_signature"] = ""
    record["record_hash"] = hash_object(record)
    record["producer_signature"] = sign_jws(
        record["record_hash"],
        private_key_from_jwk(vector["producer_private_jwk"]),
        kid=vector["producer"]["verification_method"],
    )

    assert verify_session_evidence_record(record, vector["did_documents"]) is accepted


def test_producers_emit_the_current_versions():
    emitted = RECORD_VERSIONS["producers_emit"]

    # Each accepted TransactionRecord version is the one producers emit for one shape.
    assert sorted(emitted["transaction_record"].values()) == sorted(TR_VERSIONS["accepted"])
    for shape, version in emitted["transaction_record"].items():
        session = _transaction_record_session(TR_SHAPES[shape])
        assert generate_transaction_record(session)["record_version"] == version, shape
    # Each SessionEvidenceRecord shape has its own version.
    for shape, version in SER_EMITTED.items():
        assert _session_evidence_record(SER_SHAPES[shape])["record_version"] == version, shape
    # The AuditLog's content did not change, so its version did not move.
    assert generate_audit_log(session)["log_version"] == emitted["audit_log"]
    accepted = [case["record_version"] for case in SER_VERSIONS["accepted"]]
    assert set(SER_EMITTED.values()) <= set(accepted)


def test_each_verifier_recognizes_exactly_the_versions_the_vector_accepts():
    assert list(RECOGNIZED_TRANSACTION_RECORD_VERSIONS) == TR_VERSIONS["accepted"]
    assert list(RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS) == [
        case["record_version"] for case in SER_VERSIONS["accepted"]
    ]


def test_0_3_is_a_session_evidence_record_version_only():
    """The SessionEvidenceRecord recognizes "0.3"; the TransactionRecord still rejects it."""
    assert "0.3" not in TR_VERSIONS["accepted"]
    assert {"name": "next-minor", "record_version": "0.3"} in TR_VERSIONS["rejected"]
    assert "0.3" in [case["record_version"] for case in SER_VERSIONS["accepted"]]
    assert {"name": "next-minor", "record_version": "0.4"} in SER_VERSIONS["rejected"]


SCHEMA_CASES = [
    pytest.param("transaction-record", version, id=f"transaction-record-{version}")
    for version in TR_VERSIONS["accepted"]
] + [
    pytest.param(
        "session-evidence-record",
        case["record_version"],
        id=f"session-evidence-record-{case['record_version']}",
    )
    for case in SER_VERSIONS["accepted"]
]


@pytest.mark.parametrize(("artifact", "version"), SCHEMA_CASES)
def test_every_accepted_version_has_a_schema_that_names_it(artifact, version):
    """A verifier that accepts a version has that version's schema beside the others."""
    schema = _schema(artifact, version)

    assert schema["$id"] == f"https://a2cn.dev/schemas/{artifact}/{version}"
    assert schema["properties"]["record_version"]["const"] == version


def test_the_schemas_name_the_versions_producers_emit():
    """The schema, the specification, and both implementations use the same value."""
    emitted = RECORD_VERSIONS["producers_emit"]

    for version in emitted["transaction_record"].values():
        schema = _schema("transaction-record", version)
        assert schema["properties"]["record_version"]["const"] == version
    for version in SER_EMITTED.values():
        schema = _schema("session-evidence-record", version)
        assert schema["properties"]["record_version"]["const"] == version
