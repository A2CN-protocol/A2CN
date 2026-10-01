"""The published record schemas: each record validates against its own version's schema.

A record artifact's unversioned schema file describes its "0.1" version; each
later version is published beside it as <name>-<version>.schema.json, and a
published schema file is never rewritten (Section 17). A TransactionRecord's
version follows its shape: the "0.1" schema permits no top-level basis, the
"0.2" schema requires it, and the "0.3" schema requires the Section 7.3.1 act
fields in final_offer and carries basis exactly when agreed_terms does
(Sections 9.3 and 9.5). The "0.1" SessionEvidenceRecord schema is the file
release 0.3.0 published, which predates Sections 9A.8 to 9A.11; those arrived in
"0.2" (Section 9A.2). The TypeScript suite checks the same files structurally.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import a2cn.evidence as evidence
from a2cn.crypto import canonicalize, hash_bytes, hash_object, private_key_from_jwk, sign_jws
from a2cn.evidence import generate_session_evidence_record, verify_session_evidence_record
from a2cn.record import FINAL_OFFER_ACT_FIELDS, generate_transaction_record
from a2cn.session import Session, SessionManager, SessionState

REPO_ROOT = Path(__file__).parents[3]
SCHEMAS = REPO_ROOT / "spec" / "schemas"
VECTORS = REPO_ROOT / "spec" / "test-vectors"
TR_VECTOR = json.loads((VECTORS / "transaction-record-basis.json").read_text())
WITHOUT_BASIS = TR_VECTOR["without_basis"]
EXPECTED_0_2 = TR_VECTOR["expected"]["record_version_0_2"]
EXPECTED_0_3 = TR_VECTOR["expected"]["record_version_0_3"]
# A session whose round-1 offer omits expires_at, so its signed act, and the
# record, carry "". A conformant producer can emit this, so the schema takes it.
EMPTY_EXPIRES_AT = TR_VECTOR["empty_expires_at"]
PARITY_VECTORS = json.loads((REPO_ROOT / "a2cn_ts" / "parity" / "vectors.json").read_text())
SER_VECTOR = json.loads((VECTORS / "session-evidence-record-parity.json").read_text())

TR_0_1 = "transaction-record.schema.json"
TR_0_2 = "transaction-record-0.2.schema.json"
TR_0_3 = "transaction-record-0.3.schema.json"
TR_0_4 = "transaction-record-0.4.schema.json"
SER_0_1 = "session-evidence-record.schema.json"
SER_0_2 = "session-evidence-record-0.2.schema.json"
SER_0_4 = "session-evidence-record-0.4.schema.json"
SER_0_5 = "session-evidence-record-0.5.schema.json"
TR_SCHEMAS = (TR_0_1, TR_0_2, TR_0_3, TR_0_4)
# Every other version's schema, which the record of one version must not fit.
OTHER_VERSIONS = {
    **{name: [other for other in TR_SCHEMAS if other != name] for name in TR_SCHEMAS},
    SER_0_1: [SER_0_2],
    SER_0_2: [SER_0_1],
}


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
        legacy_replay=True,  # a recorded session, possibly negotiated at "0.2"
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
    record = copy.deepcopy(EXPECTED_0_2["full_record"])
    del record["basis"]
    record["record_version"] = "0.1"
    record["record_hash"] = ""
    record["record_hash"] = hash_object(record)
    assert record["record_hash"] == EXPECTED_0_2["basis_dropped_0_1_record_hash"]
    return record


# Every real TransactionRecord in the vectors, and what the reference
# implementation generates, with the schema of its version.
TRANSACTION_RECORDS = [
    pytest.param(
        TR_0_1, lambda: WITHOUT_BASIS["record_version_0_1"]["full_record"],
        id="0.1-from-an-implementation-that-predates-basis",
    ),
    pytest.param(TR_0_1, _agreed_terms_basis_alone, id="0.1-with-agreed-terms-basis-alone"),
    pytest.param(
        TR_0_2, lambda: EXPECTED_0_2["full_record"],
        id="0.2-from-an-implementation-that-predates-the-act-fields",
    ),
    pytest.param(TR_0_3, lambda: EXPECTED_0_3["full_record"], id="0.3-basis-vector"),
    pytest.param(
        TR_0_3, lambda: WITHOUT_BASIS["record_version_0_3"]["full_record"],
        id="0.3-without-basis-vector",
    ),
    pytest.param(TR_0_4, lambda: _replay(TR_VECTOR), id="0.4-generated-for-a-basis-session"),
    pytest.param(
        TR_0_4, lambda: _replay(WITHOUT_BASIS), id="0.4-generated-for-a-session-without-basis"
    ),
    pytest.param(
        TR_0_4, lambda: PARITY_VECTORS["session"]["expected"]["full_record"],
        id="0.4-parity-vector",
    ),
    pytest.param(TR_0_4, _without_subject_reference, id="0.4-generated-without-subject-reference"),
    pytest.param(
        TR_0_3, lambda: EMPTY_EXPIRES_AT["record_version_0_3"]["full_record"],
        id="0.3-empty-expires-at-vector",
    ),
    pytest.param(
        TR_0_4, lambda: _replay(EMPTY_EXPIRES_AT), id="0.4-generated-with-an-empty-expires-at"
    ),
]


@pytest.mark.parametrize(("schema_file", "record"), TRANSACTION_RECORDS)
def test_every_transaction_record_validates_against_its_versions_schema(schema_file, record):
    record = record()

    assert _errors(schema_file, record) == []
    # And against no other version's schema.
    for other in OTHER_VERSIONS[schema_file]:
        assert _errors(other, record) != [], other


def _set_basis(value):
    def mutate(record: dict) -> None:
        record["basis"] = value
        record["agreed_terms"]["basis"] = value

    return mutate


def _drop_act_field(field_name: str):
    def mutate(record: dict) -> None:
        del record["final_offer"][field_name]

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
    # "0.3": every act field is required, and basis is carried exactly when
    # agreed_terms carries one, and equal to it.
    *[
        pytest.param(TR_0_3, _drop_act_field(name), id=f"0.3-without-final-offer-{name}")
        for name in FINAL_OFFER_ACT_FIELDS
    ],
    pytest.param(
        TR_0_3, lambda record: record["agreed_terms"].pop("basis"),
        id="0.3-with-basis-and-no-agreed-terms-basis",
    ),
    pytest.param(
        TR_0_3, lambda record: record.pop("basis"), id="0.3-with-agreed-terms-basis-and-no-basis",
    ),
    pytest.param(
        TR_0_3, lambda record: record["agreed_terms"].update(basis="net"),
        id="0.3-agreed-terms-basis-differs",
    ),
    pytest.param(TR_0_3, _set_basis("vat"), id="0.3-unrecognized-basis"),
    pytest.param(TR_0_3, lambda record: record.update(record_version="0.2"), id="0.3-labelled-0.2"),
    pytest.param(
        TR_0_3, lambda record: record["final_offer"].update(round_number="2"),
        id="0.3-string-final-offer-round-number",
    ),
    pytest.param(
        TR_0_3, lambda record: record["final_offer"].update(message_type="acceptance"),
        id="0.3-final-offer-that-is-not-an-offer",
    ),
    pytest.param(
        TR_0_3, lambda record: record["final_offer"].update(protocol_version=""),
        id="0.3-empty-final-offer-protocol-version",
    ),
    # Every version: closed objects, required fields, and field types.
    *[
        pytest.param(schema_file, mutate, id=f"{version}-{name}")
        for schema_file, version in ((TR_0_1, "0.1"), (TR_0_2, "0.2"), (TR_0_3, "0.3"))
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
    TR_0_2: EXPECTED_0_2["full_record"],
    TR_0_3: EXPECTED_0_3["full_record"],
}


@pytest.mark.parametrize(("schema_file", "mutate"), INVALID_TRANSACTION_RECORDS)
def test_the_transaction_record_schemas_refuse_other_shapes(schema_file, mutate):
    """The healthy record goes first: a schema that refused everything would pass every case."""
    record = copy.deepcopy(HEALTHY_TRANSACTION_RECORDS[schema_file])
    assert _errors(schema_file, record) == []

    mutate(record)
    assert _errors(schema_file, record) != []


def test_the_0_3_schema_requires_every_act_field_and_leaves_basis_optional():
    """The act fields are what "0.3" adds; basis follows agreed_terms (Section 9.3)."""
    schema = json.loads((SCHEMAS / TR_0_3).read_text())
    final_offer = schema["properties"]["final_offer"]

    for name in FINAL_OFFER_ACT_FIELDS:
        assert name in final_offer["properties"], name
        assert name in final_offer["required"], name
    # basis is the one declared top-level field a "0.3" record may leave out.
    assert set(schema["properties"]) - set(schema["required"]) == {"basis"}
    assert schema["properties"]["basis"]["enum"] == ["net", "gross"]


# Every object the generator fills in full is closed; agreed_terms, the accepted
# offer's terms, stays open (Section 7.2).
CLOSED_OBJECTS = ("parties", "negotiation_summary", "final_offer", "final_acceptance")


@pytest.mark.parametrize("schema_file", TR_SCHEMAS)
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

def _without_stated_wire_versions(record: dict) -> dict:
    """The record as generated before each act stated its wire version.

    Every act gained protocol_version, since none of the vector's acts states
    one; each loses it again and its act_hash and the chain are recomputed, so
    the record can be compared with one produced before acts stated their version.
    """
    for entry in record["acts"]:
        entry["act"].pop("protocol_version")
        entry["act_hash"] = hash_object(entry["act"])
    record["act_chain_hash"] = hash_bytes(
        canonicalize([entry["act_hash"] for entry in record["acts"]])
    )
    return record


def _session_evidence_record(version: str, *, as_released: bool = False) -> dict:
    """The record session-evidence-record-parity.json produces, sealed at ``version``.

    as_released strips the wire version each session act now states, giving the
    bytes a generator produced before acts stated it.
    """
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
    if as_released:
        _without_stated_wire_versions(record)
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
    for other in OTHER_VERSIONS[schema_file]:
        assert _errors(other, record) != [], other


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
    # Apart from its version, and from each of its own acts now stating the wire
    # version it was signed under, this implementation produces the same record.
    assert _session_evidence_record("0.1", as_released=True)["record_hash"] == record["record_hash"]
    # The stated versions are the only other difference, and they are not nothing.
    assert _session_evidence_record("0.1")["record_hash"] != record["record_hash"]


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
def test_a_record_that_uses_sections_9a_8_to_9a_11_fits_its_own_versions_schema(name):
    """Sections 9A.8 to 9A.11 arrived in "0.2", so the released "0.1" schema refuses them.

    Every producer now emits "0.5" (Section 9A.2), so the generated record fits
    that version's schema; the features themselves are unchanged since "0.2".
    Verification does not depend on the version, so the record still verifies
    when it is relabelled "0.1".
    """
    record = _extension_record(name)
    did_documents = EXTENSIONS_VECTOR["did_documents"]

    assert record["record_version"] == "0.5"
    assert _errors(SER_0_5, record) == []
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


# ---------------------------------------------------------------------------
# SessionEvidenceRecord "0.3": external-channel completion (Section 9A.12)
# ---------------------------------------------------------------------------

SER_0_3 = "session-evidence-record-0.3.schema.json"
EXTERNAL_CHANNEL_VECTOR = json.loads(
    (VECTORS / "session-evidence-record-external-channel.json").read_text()
)
EXTERNAL_CHANNEL_KEY = private_key_from_jwk(EXTERNAL_CHANNEL_VECTOR["producer_private_jwk"])


def _external_channel_record(reference=None) -> dict:
    """The record the external-channel vector generates, or with ``reference`` instead."""
    fixture = EXTERNAL_CHANNEL_VECTOR
    source = fixture["session"]
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
    options = copy.deepcopy(fixture["options"])
    if reference is not None:
        options["external_commitment_reference"] = copy.deepcopy(reference)
    producer = fixture["producer"]
    return generate_session_evidence_record(
        session,
        producer_private_key=EXTERNAL_CHANNEL_KEY,
        producer_did=producer["did"],
        producer_agent_id=producer["agent_id"],
        producer_verification_method=producer["verification_method"],
        observed_acts=fixture["observed_acts"],
        **options,
    )


def _resealed_external_channel_record(record: dict) -> dict:
    record["record_hash"] = ""
    record["producer_signature"] = ""
    record["record_hash"] = hash_object(record)
    record["producer_signature"] = sign_jws(
        record["record_hash"],
        EXTERNAL_CHANNEL_KEY,
        kid=EXTERNAL_CHANNEL_VECTOR["producer"]["verification_method"],
    )
    return record


def _with_changes(record: dict, case: dict) -> dict:
    """Set each path in case["set"] to its value and delete each path in case["remove"].

    A path element may be a STRING (dict key) or an INTEGER (list index): the
    ``mixed`` external-channel case targets ``["acts", 1, "sender_did"]``, and
    ``holder[key]`` indexes lists and dicts alike. THREE harnesses walk these
    paths -- this one, ``_apply_changes`` in ``tests/test_evidence.py`` and
    ``applyChanges`` in ``a2cn_ts/tests/test_evidence.test.ts`` -- and the vectors
    are the CROSS-LANGUAGE contract, so all three must accept the same paths.
    Replace any of them with a dict-only walk and that case breaks in one
    language only, which is the divergence the shared vectors exist to close.
    """
    for change in case.get("set", []):
        holder = record
        for key in change["path"][:-1]:
            holder = holder[key]
        holder[change["path"][-1]] = copy.deepcopy(change["value"])
    for path in case.get("remove", []):
        holder = record
        for key in path[:-1]:
            holder = holder[key]
        del holder[path[-1]]
    return record


def _names_the_reference(errors: list) -> bool:
    return any("external_commitment_reference" in error.message for error in errors)


EXTERNAL_CHANNEL_RECORDS = [
    pytest.param(lambda: EXTERNAL_CHANNEL_VECTOR["expected"]["record"], id="expected-record"),
    pytest.param(_external_channel_record, id="generated"),
    *[
        pytest.param(
            lambda case=case: _external_channel_record(case["external_commitment_reference"]),
            id=case["name"],
        )
        for case in EXTERNAL_CHANNEL_VECTOR["valid_references"]
    ],
]


@pytest.mark.parametrize("record", EXTERNAL_CHANNEL_RECORDS)
def test_an_external_channel_record_fits_only_the_later_schema(record):
    """Section 9A.12 arrived in "0.3"; the earlier schemas are closed where it goes.

    Every producer now emits "0.5" (Section 9A.2), where the reference is
    OPTIONAL rather than definitional, so these records fit that version's
    schema. "0.1" and "0.2" still have nowhere to put the reference.
    """
    record = record()

    assert record["record_version"] == "0.5"
    assert _errors(SER_0_5, record) == []
    for earlier in (SER_0_1, SER_0_2):
        assert _names_the_reference(_errors(earlier, record)), earlier


@pytest.mark.parametrize(("schema_file", "version"), [(SER_0_1, "0.1"), (SER_0_2, "0.2")])
def test_the_earlier_schemas_refuse_the_reference_under_their_own_version(schema_file, version):
    record = copy.deepcopy(EXTERNAL_CHANNEL_VECTOR["expected"]["record"])
    record["record_version"] = version
    _resealed_external_channel_record(record)

    assert _names_the_reference(_errors(schema_file, record))


@pytest.mark.parametrize(
    "case", EXTERNAL_CHANNEL_VECTOR["invalid_records"], ids=lambda case: case["name"]
)
def test_the_0_5_schema_refuses_every_invalid_external_channel_record(case):
    """The healthy record goes first: a schema that refused everything would pass every case.

    The ``schema_expresses is False`` branch is LIVE and several cases take it,
    all for the same reason: the rule compares two members of the record, which
    a JSON Schema cannot state at all, so the schema accepts the record and only
    the verifier refuses it.

    * ``producer-not-initiator``: Section 9A.12 requires ``producer.did`` to
      equal ``parties.initiator.did``.
    * ``reference-with-a-third-party-signed-act``: Section 9A.12 with
      Section 9A.8 rule 1 requires that no act claim ``verified_signature``
      unless its ``sender_did`` equals ``parties.initiator.did`` or
      ``parties.responder.did``, which compares the parties against each entry
      of ``acts``. It carries the SAME signed act as the valid case
      ``reference-with-a-counterparty-signed-counteroffer`` and differs only in
      ``parties.responder``, so the signer is the responder there and a third
      party here.
    * the four acceptance cases: Section 9A.12 admits a verified acceptance only
      when its signer is ``parties.initiator.did`` and no verified act is
      ``parties.responder.did``'s, which compares the parties against the acts
      and the acts against each other.

    That is the whole point of the flag, and it is not a gap: it marks the
    cases where schema silence is correct rather than missing. Do not read a
    passing schema assertion on such a case as coverage of the rule; the
    verifier test beside it is what covers it.
    """
    record = copy.deepcopy(EXTERNAL_CHANNEL_VECTOR["expected"]["record"])
    assert _errors(SER_0_5, record) == []

    _resealed_external_channel_record(_with_changes(record, case))
    if case.get("schema_expresses") is False:
        assert _errors(SER_0_5, record) == []
    else:
        assert _errors(SER_0_5, record) != []


@pytest.mark.parametrize(
    "case", EXTERNAL_CHANNEL_VECTOR["invalid_references"], ids=lambda case: case["name"]
)
def test_the_0_5_schema_refuses_every_malformed_reference(case):
    record = copy.deepcopy(EXTERNAL_CHANNEL_VECTOR["expected"]["record"])
    assert _errors(SER_0_5, record) == []

    record["external_commitment_reference"] = copy.deepcopy(case["external_commitment_reference"])
    _resealed_external_channel_record(record)
    assert _errors(SER_0_5, record) != []


@pytest.mark.parametrize(
    "case", EXTERNAL_CHANNEL_VECTOR["valid_records"], ids=lambda case: case["name"]
)
def test_the_0_5_schema_accepts_every_valid_external_channel_record(case):
    """The bucket that MUST verify must also fit the schema that admits it.

    Every case carries a DID-bearing full-party responder, which "0.4" refused
    outright, and every one is admitted at "0.5". The observed_party shapes live
    in valid_variants, which the generator builds.
    """
    record = copy.deepcopy(EXTERNAL_CHANNEL_VECTOR["expected"]["record"])
    assert _errors(SER_0_5, record) == []

    _resealed_external_channel_record(_with_changes(record, case))
    assert _errors(SER_0_5, record) == []


@pytest.mark.parametrize(
    "case", EXTERNAL_CHANNEL_VECTOR["valid_records"], ids=lambda case: case["name"]
)
def test_the_0_4_schema_refuses_every_valid_external_channel_record_on_its_version(case):
    """The WEAK half, named for what it is so nobody reads it as shape coverage.

    A "0.5" record fails the "0.4" schema on ``record_version`` alone, which is
    trivially true of every "0.5" record and would hold even if "0.4" had been
    relaxed to admit these shapes. It is a true property worth pinning and it is
    NOT evidence that "0.4" excluded the responder shape. The test below is.
    """
    record = copy.deepcopy(EXTERNAL_CHANNEL_VECTOR["expected"]["record"])
    _resealed_external_channel_record(_with_changes(record, case))

    versions = [
        error for error in _errors(SER_0_4, record) if list(error.absolute_path) == ["record_version"]
    ]
    assert versions, 'the "0.4" refusal must include the record_version objection'


@pytest.mark.parametrize(
    "case", EXTERNAL_CHANNEL_VECTOR["valid_records"], ids=lambda case: case["name"]
)
def test_the_0_4_schema_refuses_the_responder_shape_with_the_version_neutralised(case):
    """The SUBSTANTIVE half: "0.4" refused the SHAPE, not merely the label.

    Asserting the error list is non-empty cannot distinguish refused-for-the-rule
    from refused-for-the-version, so this neutralises ``record_version`` to "0.4"
    and requires the objection to name ``parties.responder``. "0.4" gated the
    external witness on an ``observed_party``, whose ``identity_source`` and
    ``*_declared`` markers a full party does not carry -- so THIS is the
    assertion that would fail if ``allOf[1]`` were relaxed to admit the shape.

    The relabelled record's ``record_hash`` no longer matches its own bytes, which
    is harmless because a JSON Schema never checks the seal -- but it is why this
    record MUST NOT be handed to the verifier.
    """
    record = copy.deepcopy(EXTERNAL_CHANNEL_VECTOR["expected"]["record"])
    _resealed_external_channel_record(_with_changes(record, case))
    record["record_version"] = "0.4"

    errors = _errors(SER_0_4, record)
    assert not [error for error in errors if list(error.absolute_path) == ["record_version"]]
    responder = [
        error for error in errors if list(error.absolute_path)[:2] == ["parties", "responder"]
    ]
    assert responder, '"0.4" must refuse the DID-bearing full-party responder on its shape'


RELABELLED_RESPONDER_CASES = [
    case
    for case in EXTERNAL_CHANNEL_VECTOR["invalid_records"]
    if {tuple(change["path"]) for change in case.get("set", [])}
    == {("parties", "responder"), ("record_version",)}
]


def test_the_relabelled_responder_cases_are_the_two_earlier_versions():
    """The selection below is structural, so pin what it selects."""
    assert sorted(case["name"] for case in RELABELLED_RESPONDER_CASES) == [
        "reference-with-did-bearing-responder-relabelled-0.3",
        "reference-with-did-bearing-responder-relabelled-0.4",
    ]


@pytest.mark.parametrize("case", RELABELLED_RESPONDER_CASES, ids=lambda case: case["name"])
def test_the_own_version_schema_refuses_a_relabelled_responder_on_its_shape_alone(case):
    """The schema half of the version binding the verifier enforces.

    A "0.5" record relabelled to "0.3" or "0.4" is refused by the "0.5" schema
    on ``record_version`` alone, which says nothing about the responder. This
    reads the relabelled record against ITS OWN version's schema instead, and
    requires every objection to be about ``parties.responder``: that version
    admits only an ``observed_party`` there. The verifier side of the same case
    is ``test_external_channel_invalid_records_have_python_typescript_parity``.
    """
    record = copy.deepcopy(EXTERNAL_CHANNEL_VECTOR["expected"]["record"])
    _resealed_external_channel_record(_with_changes(record, case))
    version = record["record_version"]
    assert version in ("0.3", "0.4")

    errors = _errors(f"session-evidence-record-{version}.schema.json", record)
    assert errors, f'the "{version}" schema must refuse the DID-bearing responder'
    assert all(list(error.absolute_path)[:2] == ["parties", "responder"] for error in errors)
    assert case.get("schema_expresses") is not False


def test_no_record_without_the_reference_fits_the_0_3_schema():
    """A record that does not complete through an external channel is never "0.3".

    "0.3" requires the reference by definition, so no record without one fits it
    under any label. The records themselves are "0.5", the version every producer
    now emits, where that reference is OPTIONAL.
    """
    records = [_session_evidence_record("0.5")] + [
        _extension_record(name) for name in sorted(EXTENSIONS_VECTOR["vectors"])
    ]

    for record in records:
        assert _errors(SER_0_5, record) == []
        assert _errors(SER_0_3, record) != []
        relabelled = copy.deepcopy(record)
        relabelled["record_version"] = "0.3"
        assert _names_the_reference(_errors(SER_0_3, relabelled))


def test_the_0_3_schema_is_the_0_2_schema_with_external_channel_completion():
    """Only the version, the new member, and the rules that go with it differ."""
    previous = json.loads((SCHEMAS / SER_0_2).read_text())
    current = json.loads((SCHEMAS / SER_0_3).read_text())

    assert current["$id"] == "https://a2cn.dev/schemas/session-evidence-record/0.3"
    assert current["properties"]["record_version"] == {"type": "string", "const": "0.3"}
    assert current["required"] == previous["required"] + ["external_commitment_reference"]
    assert current["properties"]["external_commitment_reference"] == {
        "$ref": "#/$defs/external_commitment_reference"
    }
    # An external-channel record carries at least one act its producer signed.
    # The schema can require a verified act; that its sender is the initiator is
    # a cross-reference between two members, which a JSON Schema cannot state.
    assert current["properties"]["acts"]["contains"] == {
        "properties": {"attribution": {"const": "verified_signature"}},
        "required": ["attribution"],
    }
    reference = current["$defs"]["external_commitment_reference"]
    assert reference["type"] == "object"
    assert reference["additionalProperties"] is False
    assert reference["required"] == ["external_commitment_id"]
    assert {
        name: {key: rule[key] for key in ("type", "minLength") if key in rule}
        for name, rule in reference["properties"].items()
    } == {
        "external_commitment_id": {"type": "string", "minLength": 1},
        "locator": {"type": "string", "minLength": 1},
        "reference_note": {"type": "string"},
    }

    def everything_else(schema: dict) -> dict:
        schema = copy.deepcopy(schema)
        for name in ("$id", "description", "allOf"):
            del schema[name]
        del schema["properties"]["record_version"]
        del schema["properties"]["acts"]
        schema["properties"].pop("external_commitment_reference", None)
        schema["$defs"].pop("external_commitment_reference", None)
        schema["required"] = [
            name for name in schema["required"] if name != "external_commitment_reference"
        ]
        return schema

    assert everything_else(current) == everything_else(previous)


def test_the_0_2_evidence_record_schema_is_unchanged():
    """The "0.3" schema is published beside it, and "0.2" is not rewritten (Section 17)."""
    digest = hashlib.sha256((SCHEMAS / SER_0_2).read_bytes()).hexdigest()

    assert digest == EXTERNAL_CHANNEL_VECTOR["session_evidence_record_0_2_schema_sha256"]


@pytest.mark.parametrize(
    ("schema_file", "pin"),
    [
        (SER_0_4, "session_evidence_record_0_4_schema_sha256"),
        (SER_0_5, "session_evidence_record_0_5_schema_sha256"),
    ],
    ids=["0.4", "0.5"],
)
def test_the_later_evidence_record_schemas_are_pinned(schema_file, pin):
    """Section 17: a published schema file is never rewritten.

    Before this, only "0.1" and "0.2" were pinned -- 2 of 5 published files, in
    both languages. "0.4" is pinned because this change publishes "0.5" beside
    it and must not touch it; "0.5" is pinned from publication, so the rule
    applies to it from its first day rather than from whenever someone next
    remembers.

    A digest pin needs no JSON Schema validator, so the standing "schema
    validation is Python-only" asymmetry never excused the gap in either
    language.
    """
    digest = hashlib.sha256((SCHEMAS / schema_file).read_bytes()).hexdigest()

    assert digest == EXTERNAL_CHANNEL_VECTOR[pin]


def test_a_stored_0_3_record_still_verifies_and_fits_its_own_schema():
    """The additive recognizer, which nothing else in either suite pins.

    Section 9A.2: the SessionEvidenceRecord's accepted set has only ever GROWN --
    "0.4" then "0.5", losing nothing -- so a record sealed under an earlier
    version stays valid. That is the deliberate opposite of the
    TransactionRecord's clean break, and the recognizer could have been narrowed
    to a single version with every other test still passing.

    This record is loaded, never generated: it is the record this vector's
    session produced before universal "0.4", with the bytes it had. Regenerating
    it would destroy the only thing it proves. Its sibling
    ``test_a_stored_0_4_record_still_verifies`` pins the same promise one
    version along, where a floor written as an equality would have broken it.
    """
    record = EXTERNAL_CHANNEL_VECTOR["historical_0_3_record"]

    assert record["record_version"] == "0.3"
    assert verify_session_evidence_record(record, EXTERNAL_CHANNEL_VECTOR["did_documents"])
    assert _errors(SER_0_3, record) == []
    # And it is not mistaken for any version that superseded it.
    assert _errors(SER_0_4, record) != []
    assert _errors(SER_0_5, record) != []


def test_the_stored_0_3_record_is_todays_record_apart_from_its_version():
    """The two differ in the version, the hash over it, and the seal over that,
    and in the wire version today's record states on each of its acts.

    A guard on the pair: if they drifted in any other member, the test above
    would be verifying an unrelated artifact while appearing to prove the
    recognizer.
    """
    historical = EXTERNAL_CHANNEL_VECTOR["historical_0_3_record"]
    current = EXTERNAL_CHANNEL_VECTOR["expected"]["record"]

    assert current["record_version"] == "0.5"
    _assert_apart_from_version_and_stated_wire_versions(historical, current)


def test_a_stored_0_4_record_still_verifies():
    """PROBE A's pin, and the ONLY artifact that catches the floor regression.

    The version-keyed witness rule returns early for versions at or above the
    floor. Written as an equality against the CURRENT version rather than as a
    floor -- which is how it stood until this change -- it dropped every stored
    "0.4" external-channel record into the historical "0.3" biconditional and
    refused it the moment CURRENT became "0.5".

    NOTHING ELSE CATCHES THAT. ``historical_0_3_record`` covers "0.3", which the
    biconditional governs either way; a regenerated record follows CURRENT and
    so takes the early return whatever the rule says. Only a record stored at
    the PREVIOUS version distinguishes a floor from an equality, which is
    exactly the shape the earlier "0.3" pin had and the reason it existed.

    Loaded, never generated: re-sealing it under today's version would destroy
    the only thing it proves.
    """
    record = EXTERNAL_CHANNEL_VECTOR["historical_0_4_record"]

    assert record["record_version"] == "0.4"
    assert verify_session_evidence_record(record, EXTERNAL_CHANNEL_VECTOR["did_documents"])
    assert _errors(SER_0_4, record) == []
    # And it is not mistaken for the version that superseded it.
    assert _errors(SER_0_5, record) != []


def test_the_stored_0_4_record_is_todays_record_apart_from_its_version():
    """The guard on the pair above, mirroring the "0.3" one.

    Without it, the test above could drift into verifying an unrelated artifact
    while still appearing to prove the recognizer.
    """
    historical = EXTERNAL_CHANNEL_VECTOR["historical_0_4_record"]
    current = EXTERNAL_CHANNEL_VECTOR["expected"]["record"]

    assert historical["record_version"] == "0.4"
    assert current["record_version"] == "0.5"
    _assert_apart_from_version_and_stated_wire_versions(historical, current)


def _assert_apart_from_version_and_stated_wire_versions(historical: dict, current: dict) -> None:
    """The two differ in the version, the hash over it, and the seal over that,
    and in the wire version today's record states on each of its acts.
    """
    differing = {
        name
        for name in set(historical) | set(current)
        if historical.get(name) != current.get(name)
    }
    assert differing == {
        "record_version",
        "record_hash",
        "producer_signature",
        "acts",
        "act_chain_hash",
    }
    # The acts differ only in the stated version and the act_hash over it.
    assert len(current["acts"]) == len(historical["acts"])
    stated = 0
    for now, then in zip(current["acts"], historical["acts"]):
        act = copy.deepcopy(now["act"])
        if "protocol_version" not in then["act"] and "protocol_version" in act:
            del act["protocol_version"]
            stated += 1
        assert act == then["act"]
        assert {k: v for k, v in now.items() if k not in ("act", "act_hash")} == {
            k: v for k, v in then.items() if k not in ("act", "act_hash")
        }
    # Every act, the session's own and the observed one, now states it.
    assert stated == len(current["acts"]) == 2


def test_the_evidence_record_schemas_name_the_versions_the_generator_emits():
    for version, schema_file in (
        (evidence.SESSION_EVIDENCE_RECORD_VERSION_WITHOUT_EXTERNAL_COMMITMENT, SER_0_2),
        (evidence.SESSION_EVIDENCE_RECORD_VERSION_WITH_EXTERNAL_COMMITMENT, SER_0_3),
        # "0.4" has no named constant: it names no shape of its own any more,
        # being neither the emitted version nor one a rule is keyed on. It is
        # still published and still accepted, so its schema is still checked.
        ("0.4", SER_0_4),
        (evidence.SESSION_EVIDENCE_RECORD_VERSION_CURRENT, SER_0_5),
    ):
        schema = json.loads((SCHEMAS / schema_file).read_text())
        assert schema["properties"]["record_version"]["const"] == version
    # A verifier recognizes exactly the versions it has a schema for, and that
    # set is additive: "0.5" was added and none removed, so a record sealed
    # under an earlier version stays valid.
    assert list(evidence.RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS) == [
        "0.1",
        evidence.SESSION_EVIDENCE_RECORD_VERSION_WITHOUT_EXTERNAL_COMMITMENT,
        evidence.SESSION_EVIDENCE_RECORD_VERSION_WITH_EXTERNAL_COMMITMENT,
        "0.4",
        evidence.SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
    ]
