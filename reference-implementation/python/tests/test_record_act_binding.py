"""agreed_terms binds to the signed final offer (Sections 9.3 and 9.5).

The offer's protocol_act_signature already covers the Section 7.3.1 protocol
act, terms included. A record that carries only the act's hash leaves a reader
unable to rebuild the act, so agreed_terms hangs free: a record whose
agreed_terms differs from what was signed, resealed, still verifies. Carrying
the rest of the act in final_offer lets a verifier rebuild it from the record
and recompute the hash, so agreed_terms binds to the signature transitively.
Nothing new is signed, and no signature, hash, or wire message changes.

The acceptance side was already recomputable: acceptance_signature covers the
five fields of Section 7.4 and the record carries all five, so the tests below
also pin that, on a record_version "0.2" record, which predates this change.
"""

from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path

import pytest

from a2cn.crypto import (
    canonicalize,
    generate_keypair,
    hash_bytes,
    hash_object,
    public_key_to_jwk,
    sign_jws,
)
from a2cn.messages import PROTOCOL_ACT_VERSION
from a2cn.record import (
    REASON_UNBOUND_RECORD_VERSION,
    generate_transaction_record,
    verify_transaction_record,
    verify_transaction_record_reason,
)
from a2cn.session import SessionManager, SessionState
from tests.conftest import INITIATOR_DID, RESPONDER_DID, make_did_document

REPO_ROOT = Path(__file__).parents[3]
VECTOR = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "transaction-record-basis.json").read_text()
)
WITHOUT_BASIS = VECTOR["without_basis"]
VECTORS = {"with_basis": VECTOR, "without_basis": WITHOUT_BASIS}
# The record an implementation that predates this binding produced for the basis
# session: no act fields, and record_version "0.2".
EXPECTED_0_2 = VECTOR["expected"]["record_version_0_2"]
# A session whose round-1 offer omits expires_at, so its signed act carries "".
EMPTY_EXPIRES_AT = VECTOR["empty_expires_at"]

# The Section 7.3.1 act fields the record carries in final_offer. session_id is
# at the record's top level, sender_did is already in final_offer, and the act's
# terms are agreed_terms.
ACT_FIELDS = (
    "protocol_version",
    "round_number",
    "sequence_number",
    "message_type",
    "timestamp",
    "expires_at",
)
# The Section 7.4 acceptance payload fields the record carries in final_acceptance;
# its fifth field, session_id, is at the record's top level.
ACCEPTANCE_FIELDS = (
    "round_number",
    "sequence_number",
    "accepted_offer_id",
    "accepted_protocol_act_hash",
)
# An offer message carries no protocol_version of its own (Section 7.1): the act
# states the wire version, so the record states it rather than copying it.
ACT_FIELDS_ON_THE_WIRE = tuple(name for name in ACT_FIELDS if name != "protocol_version")


def _replay(vector: dict):
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


def _record(vector: dict = VECTOR) -> dict:
    return generate_transaction_record(_replay(vector))


def _offer_hashes(vector: dict) -> list[str]:
    return [
        message["protocol_act_hash"]
        for message in vector["messages"]
        if message["message_type"] in ("offer", "counteroffer")
    ]


def _resealed(record: dict) -> dict:
    """The record with record_hash recomputed: the tamper a naive verifier misses."""
    record = copy.deepcopy(record)
    record["record_hash"] = ""
    record["record_hash"] = hash_object(record)
    return record


def _verifies(record: dict, vector: dict = VECTOR) -> bool:
    return verify_transaction_record(record, vector["did_documents"], _offer_hashes(vector))


def _reason(record: dict, vector: dict = VECTOR) -> str | None:
    return verify_transaction_record_reason(
        record, vector["did_documents"], _offer_hashes(vector)
    )


def _record_of_version(record_version: str) -> dict:
    """The record of the given version: "0.3" generated, "0.2" the vector's.

    Only "0.3" is accepted now; the older shape is still built here so a case can
    assert what a verifier does with it.
    """
    if record_version == "0.3":
        return _record()
    return copy.deepcopy(EXPECTED_0_2["full_record"])


def _act_from_record(record: dict) -> dict:
    """Rebuild the Section 7.3.1 protocol act from the record alone.

    Spelled out here rather than imported, so the test is an independent check
    of the field names and sources the record must make available.
    """
    final_offer = record["final_offer"]
    return {
        "protocol_version": final_offer["protocol_version"],
        "session_id": record["session_id"],
        "round_number": final_offer["round_number"],
        "sequence_number": final_offer["sequence_number"],
        "message_type": final_offer["message_type"],
        "sender_did": final_offer["sender_did"],
        "timestamp": final_offer["timestamp"],
        "expires_at": final_offer["expires_at"],
        "terms": record["agreed_terms"],
    }


def _accepted_offer(vector: dict) -> dict:
    acceptance = vector["messages"][-1]
    return next(
        message
        for message in vector["messages"]
        if message["message_id"] == acceptance["accepted_offer_id"]
    )


# ---------------------------------------------------------------------------
# The record carries the signed act
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field_name", ACT_FIELDS_ON_THE_WIRE)
@pytest.mark.parametrize("vector_name", sorted(VECTORS))
def test_final_offer_carries_the_accepted_offers_act_field(vector_name, field_name):
    """Each act field is the accepted offer's value, copied verbatim (Section 9.3)."""
    vector = VECTORS[vector_name]
    record = _record(vector)

    assert record["final_offer"][field_name] == _accepted_offer(vector)[field_name]


@pytest.mark.parametrize("vector_name", sorted(VECTORS))
def test_final_offer_states_the_wire_version_the_act_was_hashed_under(vector_name):
    """The offer message carries no protocol_version, so the record states it."""
    vector = VECTORS[vector_name]

    assert "protocol_version" not in _accepted_offer(vector)
    assert _record(vector)["final_offer"]["protocol_version"] == PROTOCOL_ACT_VERSION


@pytest.mark.parametrize("vector_name", sorted(VECTORS))
def test_the_act_hash_recomputes_from_the_record_alone(vector_name):
    """Section 9.5: the record holds everything the signed act hash covers."""
    vector = VECTORS[vector_name]
    record = _record(vector)

    assert hash_object(_act_from_record(record)) == record["final_offer"]["protocol_act_hash"]
    assert _verifies(record, vector)


@pytest.mark.parametrize("vector_name", sorted(VECTORS))
def test_a_record_that_carries_the_act_fields_is_0_3(vector_name):
    """Section 9.3: the version follows the content, as it does for basis."""
    assert _record(VECTORS[vector_name])["record_version"] == "0.3"


def test_a_0_3_record_carries_basis_exactly_when_agreed_terms_does():
    """Under "0.3" the basis rule reads a signature-backed agreed_terms."""
    with_basis = _record(VECTOR)
    without_basis = _record(WITHOUT_BASIS)

    assert with_basis["basis"] == with_basis["agreed_terms"]["basis"]
    assert "basis" not in without_basis
    assert "basis" not in without_basis["agreed_terms"]


# ---------------------------------------------------------------------------
# The headline: agreed_terms altered after signing must be rejected
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "changes",
    [
        {"total_value": 1},
        {"currency": "EUR"},
        {"basis": "net"},
        {"seat_count": 1},
        {"line_items": [{"sku": "inserted", "total_minor": 1}]},
    ],
    ids=["total_value", "currency", "basis", "a-term", "an-inserted-line-item"],
)
def test_agreed_terms_altered_after_signing_fails_verification(changes):
    """The record this issue exists for: valid signatures over terms nobody agreed.

    Both signatures still verify and record_hash is recomputed, so only the
    rebuilt act hash catches it.
    """
    record = _record()
    signature = record["final_offer"]["protocol_act_signature"]
    record["agreed_terms"].update(changes)
    tampered = _resealed(record)

    assert tampered["final_offer"]["protocol_act_signature"] == signature
    assert hash_object(_act_from_record(tampered)) != tampered["final_offer"]["protocol_act_hash"]
    assert not _verifies(tampered)


def test_agreed_terms_replaced_wholesale_fails_verification():
    record = _record()
    record["agreed_terms"] = {"total_value": 1, "currency": "USD", "basis": "gross"}

    assert not _verifies(_resealed(record))


@pytest.mark.parametrize(
    "agreed_terms", [None, [], "gross", 0], ids=["null", "array", "string", "number"]
)
def test_agreed_terms_that_is_not_an_object_fails_verification(agreed_terms):
    """A non-object cannot be the terms of a Section 7.3.1 act."""
    record = _record()
    record["agreed_terms"] = agreed_terms

    assert not _verifies(_resealed(record))


# ---------------------------------------------------------------------------
# Every act field is bound
# ---------------------------------------------------------------------------

ALTERED_ACT_VALUES = {
    "protocol_version": "0.1",
    "round_number": 1,
    "sequence_number": 1,
    "message_type": "offer",
    "timestamp": "2026-03-24T10:09:00Z",
    "expires_at": "2031-01-01T00:00:00Z",
}


@pytest.mark.parametrize("field_name", ACT_FIELDS)
def test_an_altered_act_field_fails_verification(field_name):
    record = _record()
    record["final_offer"][field_name] = ALTERED_ACT_VALUES[field_name]

    assert not _verifies(_resealed(record))


def test_an_altered_final_offer_sender_did_fails_verification():
    """sender_did is inside the act, and it also picks the verifying key."""
    record = _record()
    record["final_offer"]["sender_did"] = record["parties"]["initiator"]["did"]

    assert not _verifies(_resealed(record))


def test_an_altered_top_level_session_id_fails_verification():
    """session_id is the act's session_id, and the acceptance payload's."""
    record = _record()
    record["session_id"] = "5a1e0b2c-3d4e-4f60-8a7b-000000000000"

    assert not _verifies(_resealed(record))


@pytest.mark.parametrize("field_name", ACT_FIELDS)
def test_a_0_3_record_missing_an_act_field_fails_verification(field_name):
    record = _record()
    del record["final_offer"][field_name]

    assert not _verifies(_resealed(record))


def test_a_0_3_record_with_no_act_fields_at_all_fails_verification():
    record = _record()
    for field_name in ACT_FIELDS:
        del record["final_offer"][field_name]

    assert record["record_version"] == "0.3"
    assert not _verifies(_resealed(record))


@pytest.mark.parametrize(
    ("record_version", "vector_name"), [("0.1", "without_basis"), ("0.2", "with_basis")]
)
def test_an_earlier_version_that_carries_act_fields_fails_verification(
    record_version, vector_name
):
    """The act fields and "0.3" imply each other, so neither is worn alone.

    Each case is a record whose basis shape already fits the version it claims,
    so only the act fields can be what rejects it (Section 9.5).
    """
    vector = VECTORS[vector_name]
    record = _record(vector)
    record["record_version"] = record_version

    assert not _verifies(_resealed(record), vector)


# ---------------------------------------------------------------------------
# Act field types: identical verdicts in both languages
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("protocol_version", ""),
        ("protocol_version", None),
        ("protocol_version", 0.2),
        ("round_number", "2"),
        ("round_number", 0),
        ("round_number", -1),
        ("round_number", True),
        ("round_number", None),
        ("sequence_number", "3"),
        ("sequence_number", 0),
        ("sequence_number", True),
        ("sequence_number", None),
        ("message_type", ""),
        ("message_type", None),
        ("timestamp", ""),
        ("timestamp", None),
        ("expires_at", ""),
        ("expires_at", None),
    ],
    ids=lambda value: repr(value),
)
def test_a_malformed_act_field_fails_verification(field_name, value):
    """Types are checked before the hash, so both languages reach one verdict."""
    record = _record()
    record["final_offer"][field_name] = value

    assert not _verifies(_resealed(record))


def test_a_record_whose_protocol_version_does_not_match_its_act_fails_verification():
    """The act was hashed over one wire version and the record claims another."""
    record = _record()
    signed_hash = record["final_offer"]["protocol_act_hash"]
    record["final_offer"]["protocol_version"] = "0.3"

    assert record["final_offer"]["protocol_act_hash"] == signed_hash
    assert not _verifies(_resealed(record))


# ---------------------------------------------------------------------------
# protocol_version comes from the record, not from a pinned wire version
# ---------------------------------------------------------------------------

_INITIATOR_PRIVATE_KEY, _INITIATOR_PUBLIC_KEY = generate_keypair()
_RESPONDER_PRIVATE_KEY, _RESPONDER_PUBLIC_KEY = generate_keypair()
_INITIATOR_VM = f"{INITIATOR_DID}#key-1"
_RESPONDER_VM = f"{RESPONDER_DID}#key-2026-01"


def _locally_signed_record(
    *,
    timestamp: str = "2026-03-24T10:01:00Z",
    expires_at: str = "2030-01-01T00:00:00Z",
    omit: tuple[str, ...] = (),
) -> tuple[dict, dict]:
    """A completed one-round session whose two signing keys this test holds.

    ``omit`` leaves a field out of the offer message. The state machine defaults
    a missing timestamp or expires_at to "" when it rebuilds the act to check its
    hash (Section 7.3.1), so the signature covers the empty string and the record
    carries it.
    """
    session_id = str(uuid.uuid4())
    session_params = {
        "deal_type": "saas_renewal",
        "currency": "USD",
        "max_rounds": 4,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    }
    session_init = {
        "message_type": "session_init",
        "message_id": "act-init-1",
        "protocol_version": "0.2",
        "session_params": {**session_params, "subject": "Act binding"},
        "initiator": {
            "organization_name": "TechCorp",
            "did": INITIATOR_DID,
            "verification_method": _INITIATOR_VM,
            "agent_id": "buyer-agent",
            "endpoint": "https://techcorp.example/api/a2cn",
        },
        "initiator_mandate": {"mandate_type": "declared"},
    }
    session_ack = {
        "message_type": "session_ack",
        "message_id": "act-ack-1",
        "session_id": session_id,
        "in_reply_to": "act-init-1",
        "protocol_version": "0.2",
        "session_params_accepted": session_params,
        "responder": {
            "organization_name": "Acme",
            "did": RESPONDER_DID,
            "verification_method": _RESPONDER_VM,
            "agent_id": "seller-agent",
            "endpoint": "http://localhost:8000",
        },
        "responder_mandate": {"mandate_type": "declared"},
        "session_created_at": "2026-03-24T10:00:00Z",
        "current_turn": "initiator",
    }
    did_documents = {
        INITIATOR_DID: make_did_document(
            INITIATOR_DID, "key-1", public_key_to_jwk(_INITIATOR_PUBLIC_KEY)
        ),
        RESPONDER_DID: make_did_document(
            RESPONDER_DID, "key-2026-01", public_key_to_jwk(_RESPONDER_PUBLIC_KEY)
        ),
    }

    manager = SessionManager()
    for did, did_document in did_documents.items():
        manager.register_did_document(did, did_document)
    session = manager.create_session(
        session_id, session_init, session_ack, "2026-03-24T10:00:00Z"
    )
    session.session_timeout_seconds = 86400 * 365 * 100

    terms = {"total_value": 9_500_000, "currency": "USD"}
    # What the state machine will rebuild: an omitted field defaults to "".
    protocol_act = {
        "protocol_version": "0.2",
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 1,
        "message_type": "offer",
        "sender_did": INITIATOR_DID,
        "timestamp": "" if "timestamp" in omit else timestamp,
        "expires_at": "" if "expires_at" in omit else expires_at,
        "terms": terms,
    }
    act_hash = hash_object(protocol_act)
    offer = {
        "message_type": "offer",
        "message_id": "act-offer-1",
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "buyer-agent",
        "sender_verification_method": _INITIATOR_VM,
        "terms": terms,
        "protocol_act_hash": act_hash,
        "protocol_act_signature": sign_jws(
            act_hash, _INITIATOR_PRIVATE_KEY, kid=_INITIATOR_VM
        ),
    }
    if "timestamp" not in omit:
        offer["timestamp"] = timestamp
    if "expires_at" not in omit:
        offer["expires_at"] = expires_at
    manager.process_message(session, offer)

    payload = {
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 2,
        "accepted_offer_id": "act-offer-1",
        "accepted_protocol_act_hash": act_hash,
    }
    manager.process_message(
        session,
        {
            "message_type": "acceptance",
            "message_id": "act-acc-1",
            "in_reply_to": "act-offer-1",
            **payload,
            "sender_did": RESPONDER_DID,
            "sender_agent_id": "seller-agent",
            "sender_verification_method": _RESPONDER_VM,
            "timestamp": "2026-03-24T10:03:00Z",
            "acceptance_signature": sign_jws(
                hash_object(payload), _RESPONDER_PRIVATE_KEY, kid=_RESPONDER_VM
            ),
        },
    )
    assert session.state == SessionState.COMPLETED
    return generate_transaction_record(session), did_documents


def _resigned_over_its_act(record: dict) -> tuple[dict, list[str]]:
    """Rebuild the act hash from the record and re-sign both sides over it.

    The record stays wholly self-consistent, so only the rule under test can
    decide the verdict. Nothing about what is signed changes: the object being
    signed is still the Section 7.3.1 act.
    """
    record = copy.deepcopy(record)
    act_hash = hash_object(_act_from_record(record))
    record["final_offer"]["protocol_act_hash"] = act_hash
    record["final_offer"]["protocol_act_signature"] = sign_jws(
        act_hash, _INITIATOR_PRIVATE_KEY, kid=_INITIATOR_VM
    )
    acceptance = record["final_acceptance"]
    acceptance["accepted_protocol_act_hash"] = act_hash
    acceptance["acceptance_signature"] = sign_jws(
        hash_object(
            {
                "session_id": record["session_id"],
                "round_number": acceptance["round_number"],
                "sequence_number": acceptance["sequence_number"],
                "accepted_offer_id": acceptance["accepted_offer_id"],
                "accepted_protocol_act_hash": act_hash,
            }
        ),
        _RESPONDER_PRIVATE_KEY,
        kid=_RESPONDER_VM,
    )
    record["offer_chain_hash"] = hash_bytes(canonicalize([act_hash]))
    return _resealed(record), [act_hash]


def test_a_record_made_under_a_later_wire_version_still_recomputes():
    """The record path reads the protocol_version the record carries (Section 9.5).

    A record produced under a wire version later than this implementation's must
    still rebuild its act, so the binding does not expire with the wire version.
    """
    record, did_documents = _locally_signed_record()
    record["final_offer"]["protocol_version"] = "0.3"
    record, offer_hashes = _resigned_over_its_act(record)

    assert verify_transaction_record(record, did_documents, offer_hashes)


def test_a_locally_signed_record_verifies_and_is_0_3():
    record, did_documents = _locally_signed_record()

    assert record["record_version"] == "0.3"
    assert verify_transaction_record(
        record, did_documents, [record["final_offer"]["protocol_act_hash"]]
    )


# ---------------------------------------------------------------------------
# The acceptance side is recomputable from the record
# ---------------------------------------------------------------------------

ALTERED_ACCEPTANCE_VALUES = {
    "round_number": 1,
    "sequence_number": 4,
    "accepted_offer_id": "basis-offer-1",
    "accepted_protocol_act_hash": VECTOR["messages"][0]["protocol_act_hash"],
}


@pytest.mark.parametrize("field_name", ACCEPTANCE_FIELDS)
def test_an_altered_acceptance_field_fails_verification(field_name):
    """Section 7.4's payload rebuilds from the record (Section 9.5, step 5).

    Only the bound version is checked here. An earlier version never reaches
    this step: step 1 refuses it first, so asserting a rejection on one would
    pass for the wrong reason.
    """
    record = _record()
    record["final_acceptance"][field_name] = ALTERED_ACCEPTANCE_VALUES[field_name]

    assert record["record_version"] == "0.3"
    assert not _verifies(_resealed(record))


def test_an_altered_session_id_fails_the_acceptance_payload():
    """session_id is the fifth acceptance field, and it is the record's own."""
    record = _record()
    record["session_id"] = "5a1e0b2c-3d4e-4f60-8a7b-000000000000"

    assert not _verifies(_resealed(record))


# ---------------------------------------------------------------------------
# The records earlier versions produced are refused as unbound
# ---------------------------------------------------------------------------

def test_the_0_2_record_a_pre_change_implementation_produced_is_refused():
    """It carries no act fields, so nothing rebinds agreed_terms to a signature.

    Accepting it would accept the downgrade: the same bytes are what a presenter
    produces by stripping the act fields from a bound record and relabelling it.
    """
    record = EXPECTED_0_2["full_record"]

    assert record["record_version"] == "0.2"
    assert all(field_name not in record["final_offer"] for field_name in ACT_FIELDS)
    assert record["record_hash"] == EXPECTED_0_2["record_hash"]
    assert not _verifies(record)
    assert _reason(record) == REASON_UNBOUND_RECORD_VERSION


def test_the_0_1_record_a_pre_basis_implementation_produced_is_refused():
    record = WITHOUT_BASIS["record_version_0_1"]["full_record"]

    assert record["record_version"] == "0.1"
    assert all(field_name not in record["final_offer"] for field_name in ACT_FIELDS)
    assert not _verifies(record, WITHOUT_BASIS)
    assert _reason(record, WITHOUT_BASIS) == REASON_UNBOUND_RECORD_VERSION


# ---------------------------------------------------------------------------
# A "0.3" record's act numbers and top-level currency, held to the signed act
# ---------------------------------------------------------------------------

BINDING = VECTOR["record_version_0_3_binding"]
BASIS_0_3 = VECTOR["expected"]["record_version_0_3"]["full_record"]


@pytest.mark.parametrize(
    "spelling", BINDING["act_integer_spellings"], ids=lambda spelling: spelling["name"]
)
def test_an_act_integer_spelling_is_judged_by_the_rebuilt_hash(spelling):
    """RFC 8785 serializes 2.0 and 2 as the same number (Section 9.5, step 3).

    An integral float is therefore the same signed act in a different JSON
    spelling: the record_hash is unchanged and the record must verify. Anything
    that is not an integral JSON number is a different act, or no act at all,
    and is rejected. Both suites read these cases from the same file, so the two
    implementations cannot drift apart.
    """
    record = copy.deepcopy(BASIS_0_3)
    field_name = spelling["field"]
    if "value" in spelling:
        record["final_offer"][field_name] = spelling["value"]
    else:
        del record["final_offer"][field_name]

    unchanged = hash_object({**record, "record_hash": ""}) == BASIS_0_3["record_hash"]
    assert unchanged is spelling["record_hash_unchanged"]
    assert _verifies(_resealed(record)) is spelling["verifies"]


@pytest.mark.parametrize(
    "currency_case", BINDING["currency_cases"], ids=lambda case: case["name"]
)
def test_the_top_level_currency_is_bound_to_agreed_terms_under_0_3(currency_case):
    """Section 9.5 step 8: under "0.3" the record's currency is the signed one.

    A "0.1" or "0.2" record's is not checked, because per-offer currency
    consistency was only required from the version that added terms.basis
    onward, so an older genuine record may legitimately differ and must keep
    verifying. The case that drops agreed_terms.currency also alters the signed
    terms, so it fails at step 3 as well; the tests below isolate step 8 by
    re-signing the act.
    """
    record = _record_of_version(currency_case["record_version"])
    if "currency" in currency_case:
        record["currency"] = currency_case["currency"]
    if currency_case.get("drop_agreed_terms_currency"):
        del record["agreed_terms"]["currency"]

    assert record["record_version"] == currency_case["record_version"]
    assert _verifies(_resealed(record)) is currency_case["verifies"]


def test_a_0_3_record_whose_signed_terms_name_another_currency_is_rejected():
    """The headline case: agreed_terms is signature-bound and says EUR.

    The record's own currency says USD. The act is re-signed over those terms,
    so step 3 passes and only the top-level currency binding can reject it.
    """
    record, did_documents = _locally_signed_record()
    record["agreed_terms"]["currency"] = "EUR"
    record, offer_hashes = _resigned_over_its_act(record)

    assert record["currency"] == "USD"
    assert record["agreed_terms"]["currency"] == "EUR"
    assert not verify_transaction_record(record, did_documents, offer_hashes)


def test_a_0_3_record_whose_signed_terms_carry_no_currency_is_rejected():
    """Also isolated: the act is re-signed over terms without a currency."""
    record, did_documents = _locally_signed_record()
    del record["agreed_terms"]["currency"]
    record, offer_hashes = _resigned_over_its_act(record)

    assert record["currency"] == "USD"
    assert "currency" not in record["agreed_terms"]
    assert not verify_transaction_record(record, did_documents, offer_hashes)


def test_a_0_3_record_whose_currency_matches_its_signed_terms_verifies():
    record, did_documents = _locally_signed_record()
    record, offer_hashes = _resigned_over_its_act(record)

    assert record["currency"] == record["agreed_terms"]["currency"]
    assert verify_transaction_record(record, did_documents, offer_hashes)


# ---------------------------------------------------------------------------
# An act signed over an empty or zero field is still recomputable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("builder_kwargs", "field_name"),
    [
        ({"expires_at": ""}, "expires_at"),
        ({"timestamp": ""}, "timestamp"),
        ({"omit": ("expires_at",)}, "expires_at"),
    ],
    ids=["empty-expires_at", "empty-timestamp", "omitted-expires_at"],
)
def test_an_act_signed_over_an_empty_field_still_verifies(builder_kwargs, field_name):
    """Section 9.5 step 3: the rebuilt hash decides, not a field's length.

    Both reference state machines default a missing timestamp or expires_at to
    "" when they rebuild the act to check its hash, and neither field is
    validated on the wire, so an offer that carries or omits one is signed,
    accepted and recorded with "" inside the signed act. A verifier that refused
    the empty string would reject a record whose signature genuinely covers
    those bytes.
    """
    record, did_documents = _locally_signed_record(**builder_kwargs)

    assert record["final_offer"][field_name] == ""
    assert hash_object(_act_from_record(record)) == record["final_offer"]["protocol_act_hash"]
    assert verify_transaction_record(
        record, did_documents, [record["final_offer"]["protocol_act_hash"]]
    )


@pytest.mark.parametrize("field_name", ["round_number", "sequence_number"])
def test_a_record_whose_act_counts_from_zero_verifies(field_name):
    """A record from elsewhere may number its act from 0, and the hash decides.

    Both reference state machines refuse such an offer on the wire (Section 7.1),
    so a record like this can only come from another implementation. Rebinding
    agreed_terms to its signature is still exactly the hash comparison.
    """
    record, did_documents = _locally_signed_record()
    record["final_offer"][field_name] = 0
    record, offer_hashes = _resigned_over_its_act(record)

    assert verify_transaction_record(record, did_documents, offer_hashes)


def test_an_empty_field_still_fails_when_the_act_hash_does_not_cover_it():
    """Relaxing the type guard does not relax the binding itself."""
    record, did_documents = _locally_signed_record()
    offer_hashes = [record["final_offer"]["protocol_act_hash"]]
    record["final_offer"]["expires_at"] = ""

    assert not verify_transaction_record(_resealed(record), did_documents, offer_hashes)


def test_the_empty_expires_at_vector_replays_and_verifies():
    """The shared session whose offer omits expires_at, replayed on both sides.

    Both suites must reach the same record and the same verdict, so the rule
    cannot drift between the two implementations.
    """
    vector = EMPTY_EXPIRES_AT
    expected = vector["record_version_0_3"]
    offer = vector["messages"][0]

    assert "expires_at" not in offer
    record = generate_transaction_record(_replay(vector))

    assert record["final_offer"]["expires_at"] == vector["act_expires_at"] == ""
    assert json.dumps(record) == json.dumps(expected["full_record"])
    assert record["record_hash"] == expected["record_hash"]
    assert verify_transaction_record(
        record, vector["did_documents"], _offer_hashes(vector)
    )
