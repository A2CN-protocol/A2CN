"""record_version: the values each record verifier accepts, and what producers emit.

spec/test-vectors/record-versions.json lists them per artifact, because each
versions its own shape. Both suites reseal a valid record of each shape of each
artifact with each value and must reach the same verdict. A TransactionRecord's
version follows its content: a "0.3" record carries the Section 7.3.1 act fields
in final_offer, a "0.2" record carries a top-level basis and no act fields, and a
"0.1" record carries neither (Section 9.5, steps 3 and 8). A "0.3"
SessionEvidenceRecord carries external_commitment_reference and no other version
does (Section 9A.2). A value outside an artifact's accepted set is rejected,
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
    ACCEPTED_TRANSACTION_RECORD_VERSIONS,
    KNOWN_TRANSACTION_RECORD_VERSIONS,
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
WITHOUT_BASIS = TR_VECTOR["without_basis"]
SER_VECTOR = json.loads((VECTORS / "session-evidence-record-parity.json").read_text())
EXTERNAL_CHANNEL_VECTOR = json.loads(
    (VECTORS / "session-evidence-record-external-channel.json").read_text()
)

# The recorded session each TransactionRecord shape came from, for its DID
# documents and its offer chain. A TransactionRecord shape is named by the
# version whose content it carries (Section 9.3).
SHAPE_VECTOR = {"0.1": WITHOUT_BASIS, "0.2": TR_VECTOR, "0.3": TR_VECTOR}
TR_EMITTED = RECORD_VERSIONS["producers_emit"]["transaction_record"]

# The vector behind each SessionEvidenceRecord shape, and the version a producer
# emits for that shape (Section 9A.2).
SER_SHAPES = {
    "without_external_commitment": SER_VECTOR,
    "with_external_commitment": EXTERNAL_CHANNEL_VECTOR,
}
SER_EMITTED = RECORD_VERSIONS["producers_emit"]["session_evidence_record"]


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


def _shape(version: str) -> dict:
    """A valid TransactionRecord whose content fits ``version``.

    "0.3" is what this implementation produces; "0.2" and "0.1" are the records
    earlier implementations produced for the same two sessions.
    """
    if version == "0.3":
        return generate_transaction_record(_transaction_record_session(TR_VECTOR))
    if version == "0.2":
        return copy.deepcopy(TR_VECTOR["expected"]["record_version_0_2"]["full_record"])
    return copy.deepcopy(WITHOUT_BASIS["record_version_0_1"]["full_record"])


def _offer_hashes(vector: dict) -> list[str]:
    return [
        message["protocol_act_hash"]
        for message in vector["messages"]
        if message["message_type"] in ("offer", "counteroffer")
    ]


TR_CASES = (
    [
        pytest.param(version, {"record_version": version}, True, id=f"accepted-{version}")
        for version in TR_VERSIONS["accepted"]
    ]
    + [
        pytest.param(case["shape"], case, False, id=f"unbound-{case['name']}")
        for case in TR_VERSIONS["unbound"]
    ]
    + [
        pytest.param(shape, case, False, id=f"{case['name']}-{shape}")
        for case in TR_VERSIONS["rejected"]
        for shape in TR_VERSIONS["shapes"]
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
    vector = SHAPE_VECTOR[shape]
    record = _with_version(_shape(shape), case)
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


@pytest.mark.parametrize("vector_name", ["with_basis", "without_basis"])
def test_producers_emit_the_transaction_record_version(vector_name):
    """Every record this implementation produces carries the act fields, so every
    one is "0.3", whether or not the session fixed a basis (Section 9.3)."""
    vector = TR_VECTOR if vector_name == "with_basis" else WITHOUT_BASIS

    assert TR_EMITTED in TR_VERSIONS["accepted"]
    assert generate_transaction_record(_transaction_record_session(vector))["record_version"] == (
        TR_EMITTED
    )


def test_producers_emit_the_current_versions():
    emitted = RECORD_VERSIONS["producers_emit"]
    session = _transaction_record_session(TR_VECTOR)

    # Each SessionEvidenceRecord shape has its own version.
    for shape, version in SER_EMITTED.items():
        assert _session_evidence_record(SER_SHAPES[shape])["record_version"] == version, shape
    # The AuditLog's content did not change, so its version did not move.
    assert generate_audit_log(session)["log_version"] == emitted["audit_log"]
    accepted = [case["record_version"] for case in SER_VERSIONS["accepted"]]
    assert set(SER_EMITTED.values()) <= set(accepted)


def test_each_verifier_accepts_exactly_the_versions_the_vector_accepts():
    """The TransactionRecord accepts only the bound version; the evidence record
    is unaffected by that rule and keeps its own set."""
    assert list(ACCEPTED_TRANSACTION_RECORD_VERSIONS) == TR_VERSIONS["accepted"]
    assert list(RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS) == [
        case["record_version"] for case in SER_VERSIONS["accepted"]
    ]
    # The older TransactionRecord shapes stay known, because their schemas are
    # published, and every shape the vector names is one this implementation knows.
    assert set(TR_VERSIONS["shapes"]) == set(KNOWN_TRANSACTION_RECORD_VERSIONS)
    assert set(ACCEPTED_TRANSACTION_RECORD_VERSIONS) < set(KNOWN_TRANSACTION_RECORD_VERSIONS)


def test_each_artifacts_version_set_is_its_own():
    """"0.3" means a different thing to each artifact, and neither set is merged.

    For the TransactionRecord it is the record whose final_offer carries the act
    fields, and the only version a verifier accepts (Section 9.3); for the
    SessionEvidenceRecord it is the record that carries
    external_commitment_reference, one of three it accepts (Section 9A.2). One
    artifact's rules never decide the other's: the TransactionRecord refusing
    "0.1" and "0.2" says nothing about an evidence record carrying them.
    """
    assert TR_VERSIONS["accepted"] == ["0.3"]
    ser_accepted = [case["record_version"] for case in SER_VERSIONS["accepted"]]
    assert ser_accepted == ["0.1", "0.2", "0.3"]
    assert {"name": "next-minor", "record_version": "0.4"} in SER_VERSIONS["rejected"]
    # The versions the TransactionRecord refuses as unbound are still accepted by
    # the evidence record, which is the point of keeping the two sets apart.
    unbound = {case["record_version"] for case in TR_VERSIONS["unbound"]}
    assert {"0.1", "0.2"} <= unbound
    assert {"0.1", "0.2"} <= set(ser_accepted)


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
    schema = _schema("transaction-record", TR_EMITTED)
    assert schema["properties"]["record_version"]["const"] == TR_EMITTED
    for version in SER_EMITTED.values():
        schema = _schema("session-evidence-record", version)
        assert schema["properties"]["record_version"]["const"] == version
