"""The published record schemas: each record validates against its own version's schema.

A record artifact's unversioned schema file describes its "0.1" version; each
later version is published beside it as <name>-<version>.schema.json, and a
published schema file is never rewritten (Section 17). A TransactionRecord's
version follows its shape, so the "0.1" schema permits no top-level basis and
the "0.2" schema requires it (Sections 9.3 and 9.5). The "0.1"
SessionEvidenceRecord schema is the file release 0.3.0 published, which predates
Sections 9A.8 to 9A.11; those arrived in "0.2" (Section 9A.2). The TypeScript
suite checks the same files structurally.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from a2cn.crypto import hash_object, private_key_from_jwk, sign_jws
from a2cn.evidence import generate_session_evidence_record, verify_session_evidence_record
from a2cn.record import generate_transaction_record
from a2cn.session import Session, SessionManager, SessionState

REPO_ROOT = Path(__file__).parents[3]
SCHEMAS = REPO_ROOT / "spec" / "schemas"
VECTORS = REPO_ROOT / "spec" / "test-vectors"
TR_VECTOR = json.loads((VECTORS / "transaction-record-basis.json").read_text())
WITHOUT_BASIS = TR_VECTOR["without_basis"]
PARITY_VECTORS = json.loads((REPO_ROOT / "a2cn_ts" / "parity" / "vectors.json").read_text())
SER_VECTOR = json.loads((VECTORS / "session-evidence-record-parity.json").read_text())

TR_0_1 = "transaction-record.schema.json"
TR_0_2 = "transaction-record-0.2.schema.json"
SER_0_1 = "session-evidence-record.schema.json"
SER_0_2 = "session-evidence-record-0.2.schema.json"
OTHER_VERSION = {TR_0_1: TR_0_2, TR_0_2: TR_0_1, SER_0_1: SER_0_2, SER_0_2: SER_0_1}


def _errors(schema_file: str, record: dict) -> list:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((SCHEMAS / schema_file).read_text())
    return list(jsonschema.Draft202012Validator(schema).iter_errors(record))


# ---------------------------------------------------------------------------
# TransactionRecord
# ---------------------------------------------------------------------------

def _replay(vector: dict, session_init: dict | None = None) -> dict:
    """The TransactionRecord the state machine generates for a recorded session."""
    manager = SessionManager()
    for did, did_document in vector["did_documents"].items():
        manager.register_did_document(did, did_document)
    session_ack = vector["session_ack"]
    session = manager.create_session(
        vector["session_id"],
        session_init or vector["session_init"],
        session_ack,
        session_ack["session_created_at"],
    )
    session.session_timeout_seconds = 86400 * 365 * 100  # the timestamps are in the past
    for message in copy.deepcopy(vector["messages"]):
        manager.process_message(session, message)
    assert session.state == SessionState.COMPLETED
    return generate_transaction_record(session)


def _without_subject_reference() -> dict:
    """A session whose SessionInit carries no subject_reference records it as null."""
    session_init = copy.deepcopy(WITHOUT_BASIS["session_init"])
    del session_init["session_params"]["subject_reference"]
    record = _replay(WITHOUT_BASIS, session_init)
    assert record["subject_reference"] is None
    return record


def _agreed_terms_basis_alone() -> dict:
    """What an implementation that predates basis records for a session that fixed one."""
    record = copy.deepcopy(TR_VECTOR["expected"]["full_record"])
    del record["basis"]
    record["record_version"] = "0.1"
    record["record_hash"] = ""
    record["record_hash"] = hash_object(record)
    assert record["record_hash"] == TR_VECTOR["expected"]["basis_dropped_0_1_record_hash"]
    return record


# Every real TransactionRecord in the vectors, and what the reference
# implementation generates, with the schema of its version.
TRANSACTION_RECORDS = [
    pytest.param(
        TR_0_1, lambda: WITHOUT_BASIS["record_version_0_1"]["full_record"],
        id="0.1-from-an-implementation-that-predates-basis",
    ),
    pytest.param(
        TR_0_1, lambda: _replay(WITHOUT_BASIS), id="0.1-generated-for-a-session-without-basis"
    ),
    pytest.param(
        TR_0_1, lambda: PARITY_VECTORS["session"]["expected"]["full_record"],
        id="0.1-parity-vector",
    ),
    pytest.param(TR_0_1, _without_subject_reference, id="0.1-generated-without-subject-reference"),
    pytest.param(TR_0_1, _agreed_terms_basis_alone, id="0.1-with-agreed-terms-basis-alone"),
    pytest.param(TR_0_2, lambda: TR_VECTOR["expected"]["full_record"], id="0.2-basis-vector"),
    pytest.param(TR_0_2, lambda: _replay(TR_VECTOR), id="0.2-generated-for-a-basis-session"),
]


@pytest.mark.parametrize(("schema_file", "record"), TRANSACTION_RECORDS)
def test_every_transaction_record_validates_against_its_versions_schema(schema_file, record):
    record = record()

    assert _errors(schema_file, record) == []
    # And against no other version's schema.
    assert _errors(OTHER_VERSION[schema_file], record) != []


def _set_basis(value):
    def mutate(record: dict) -> None:
        record["basis"] = value
        record["agreed_terms"]["basis"] = value

    return mutate


INVALID_TRANSACTION_RECORDS = [
    # "0.2": basis is required, is net or gross, and equals agreed_terms.basis.
    pytest.param(TR_0_2, lambda record: record.pop("basis"), id="0.2-without-basis"),
    pytest.param(
        TR_0_2, lambda record: record["agreed_terms"].pop("basis"),
        id="0.2-without-agreed-terms-basis",
    ),
    pytest.param(
        TR_0_2, lambda record: record["agreed_terms"].update(basis="net"),
        id="0.2-agreed-terms-basis-differs",
    ),
    pytest.param(TR_0_2, _set_basis("vat"), id="0.2-unrecognized-basis"),
    pytest.param(TR_0_2, _set_basis(None), id="0.2-null-basis"),
    pytest.param(TR_0_2, lambda record: record.update(record_version="0.1"), id="0.2-labelled-0.1"),
    # "0.1": no top-level basis, not even a null one.
    pytest.param(TR_0_1, lambda record: record.update(basis="gross"), id="0.1-with-basis"),
    pytest.param(TR_0_1, lambda record: record.update(basis=None), id="0.1-with-null-basis"),
    pytest.param(TR_0_1, lambda record: record.update(record_version="0.2"), id="0.1-labelled-0.2"),
    # Both: closed objects, required fields, and field types.
    *[
        pytest.param(schema_file, mutate, id=f"{version}-{name}")
        for schema_file, version in ((TR_0_1, "0.1"), (TR_0_2, "0.2"))
        for name, mutate in (
            ("extra-top-level-field", lambda record: record.update(note="unsealed")),
            (
                "extra-party-field",
                lambda record: record["parties"]["initiator"].update(note="unsealed"),
            ),
            (
                "extra-final-acceptance-field",
                lambda record: record["final_acceptance"].update(note="unsealed"),
            ),
            (
                "extra-final-offer-field",
                lambda record: record["final_offer"].update(note="unsealed"),
            ),
            (
                "extra-negotiation-summary-field",
                lambda record: record["negotiation_summary"].update(note="unsealed"),
            ),
            ("extra-parties-field", lambda record: record["parties"].update(observer={})),
            ("missing-offer-chain-hash", lambda record: record.pop("offer_chain_hash")),
            (
                "string-round-number",
                lambda record: record["final_acceptance"].update(round_number="2"),
            ),
        )
    ],
]
HEALTHY_TRANSACTION_RECORDS = {
    TR_0_1: WITHOUT_BASIS["record_version_0_1"]["full_record"],
    TR_0_2: TR_VECTOR["expected"]["full_record"],
}


@pytest.mark.parametrize(("schema_file", "mutate"), INVALID_TRANSACTION_RECORDS)
def test_the_transaction_record_schemas_refuse_other_shapes(schema_file, mutate):
    """The healthy record goes first: a schema that refused everything would pass every case."""
    record = copy.deepcopy(HEALTHY_TRANSACTION_RECORDS[schema_file])
    assert _errors(schema_file, record) == []

    mutate(record)
    assert _errors(schema_file, record) != []


# Every object the generator fills in full is closed; agreed_terms, the accepted
# offer's terms, stays open (Section 7.2).
CLOSED_OBJECTS = ("parties", "negotiation_summary", "final_offer", "final_acceptance")


@pytest.mark.parametrize("schema_file", [TR_0_1, TR_0_2])
def test_the_transaction_record_schemas_are_closed_except_agreed_terms(schema_file):
    schema = json.loads((SCHEMAS / schema_file).read_text())
    properties = schema["properties"]

    assert schema["additionalProperties"] is False
    for name in CLOSED_OBJECTS:
        assert properties[name]["additionalProperties"] is False, name
    assert schema["$defs"]["party"]["additionalProperties"] is False
    # Both parties use the closed party definition.
    for role in ("initiator", "responder"):
        assert properties["parties"]["properties"][role] == {"$ref": "#/$defs/party"}, role
    assert properties["agreed_terms"].get("additionalProperties") is not False


# ---------------------------------------------------------------------------
# SessionEvidenceRecord
# ---------------------------------------------------------------------------

def _session_evidence_record(version: str) -> dict:
    """The record session-evidence-record-parity.json produces, sealed at ``version``."""
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
    key = private_key_from_jwk(SER_VECTOR["producer_private_jwk"])
    record = generate_session_evidence_record(
        session,
        producer_private_key=key,
        producer_did=producer["did"],
        producer_agent_id=producer["agent_id"],
        producer_verification_method=producer["verification_method"],
        observed_acts=SER_VECTOR["observed_acts"],
    )
    record["record_version"] = version
    record["record_hash"] = ""
    record["producer_signature"] = ""
    record["record_hash"] = hash_object(record)
    record["producer_signature"] = sign_jws(
        record["record_hash"], key, kid=producer["verification_method"]
    )
    assert verify_session_evidence_record(record, SER_VECTOR["did_documents"])
    return record


@pytest.mark.parametrize(("schema_file", "version"), [(SER_0_1, "0.1"), (SER_0_2, "0.2")])
def test_each_session_evidence_record_validates_against_its_versions_schema(schema_file, version):
    record = _session_evidence_record(version)

    assert _errors(schema_file, record) == []
    assert _errors(OTHER_VERSION[schema_file], record) != []


def test_the_0_1_evidence_record_schema_is_the_file_release_0_3_0_published():
    """A published schema file is never rewritten (Section 17)."""
    digest = hashlib.sha256((SCHEMAS / SER_0_1).read_bytes()).hexdigest()

    assert digest == SER_VECTOR["release_0_3_0_schema_sha256"]


def test_a_record_release_0_3_0_produced_still_validates_and_verifies():
    """The "0.1" schema and today's verifier accept the record release 0.3.0 produced."""
    record = SER_VECTOR["release_0_3_0_record"]

    assert record["record_version"] == "0.1"
    assert _errors(SER_0_1, record) == []
    assert verify_session_evidence_record(record, SER_VECTOR["did_documents"])
    # Apart from its version, this implementation produces the same record for the session.
    assert _session_evidence_record("0.1")["record_hash"] == record["record_hash"]


EXTENSIONS_VECTOR = json.loads((VECTORS / "session-evidence-record-extensions.json").read_text())
EXTENSIONS_KEY = private_key_from_jwk(EXTENSIONS_VECTOR["producer_private_jwk"])


def _extension_record(name: str) -> dict:
    """The record a session-evidence-record-extensions.json vector generates."""
    fixture = EXTENSIONS_VECTOR
    vector = fixture["vectors"][name]
    session_ack = fixture["session_acks"][vector["session_ack"]]
    session = Session(
        session_id=fixture["session_id"],
        state=vector["state"],
        current_turn="none",
        terminal_reason=vector["terminal_reason"],
        terminal_message_id=vector["terminal_message_id"],
        session_created_at=fixture["session_created_at"],
        state_updated_at=vector["state_updated_at"],
        session_params=fixture["session_params"],
        initiator_mandate=fixture["session_init"]["initiator_mandate"],
        responder_mandate=session_ack["responder_mandate"],
    )
    session._session_init = fixture["session_init"]
    session._session_ack = session_ack
    session._message_log = vector["message_log"]
    producer = fixture["producer"]
    return generate_session_evidence_record(
        session,
        producer_private_key=EXTENSIONS_KEY,
        producer_did=producer["did"],
        producer_agent_id=producer["agent_id"],
        producer_verification_method=producer["verification_method"],
        observed_acts=vector["observed_acts"],
        **vector["options"],
    )


@pytest.mark.parametrize("name", sorted(EXTENSIONS_VECTOR["vectors"]))
def test_a_record_that_uses_sections_9a_8_to_9a_11_fits_only_the_0_2_schema(name):
    """Sections 9A.8 to 9A.11 arrived in "0.2", so the released "0.1" schema refuses them.

    Verification does not depend on the version (Section 9A.2), so the record
    still verifies when it is relabelled "0.1".
    """
    record = _extension_record(name)
    did_documents = EXTENSIONS_VECTOR["did_documents"]

    assert record["record_version"] == "0.2"
    assert _errors(SER_0_2, record) == []
    assert verify_session_evidence_record(record, did_documents)

    relabelled = copy.deepcopy(record)
    relabelled["record_version"] = "0.1"
    relabelled["record_hash"] = ""
    relabelled["producer_signature"] = ""
    relabelled["record_hash"] = hash_object(relabelled)
    relabelled["producer_signature"] = sign_jws(
        relabelled["record_hash"],
        EXTENSIONS_KEY,
        kid=EXTENSIONS_VECTOR["producer"]["verification_method"],
    )
    assert verify_session_evidence_record(relabelled, did_documents)
    assert _errors(SER_0_1, relabelled) != []
