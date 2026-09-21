"""The acceptance rebinds from the record alone (Sections 9.3 and 9.5).

The acceptance's signed scope is now the uniform envelope of Section 7.3.1, so
its signature covers `protocol_version`, `message_type`, `sender_did` and
`timestamp` beside the five fields it already covered. Of those four the record
stored only `sender_did`, so a `"0.3"` record cannot rebuild the acceptance's
signed object at all.

A verifier faced with that has only two bad options: invent the missing fields,
or borrow them from `final_offer`. Both are wrong, and both were demonstrated
rather than argued — inventing empty strings produced one wrong hash during the
determination, and borrowing the offer's timestamp produced another. A record
that cannot rebind an act from that act's own stored fields is not bound.

So `final_acceptance` carries `protocol_version`, `message_type` and
`timestamp`, and the record version moves to `"0.4"`. `final_offer` is untouched:
the offer's signed bytes and its `protocol_act_hash` do not move, so the
rebinding of `agreed_terms` is unaffected.
"""

from __future__ import annotations

import copy
import uuid

import pytest

from a2cn.crypto import (
    generate_keypair,
    hash_object,
    public_key_to_jwk,
    sign_jws,
)
from a2cn.messages import (
    PROTOCOL_ACT_VERSION,
    protocol_act_object,
    signed_act_hash,
)
from a2cn.record import (
    ACCEPTED_TRANSACTION_RECORD_VERSIONS,
    FINAL_ACCEPTANCE_ACT_FIELDS,
    KNOWN_TRANSACTION_RECORD_VERSIONS,
    REASON_ACCEPTANCE_SIGNATURE_INVALID,
    REASON_UNBOUND_RECORD_VERSION,
    TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,
    TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE,
    generate_transaction_record,
    verify_transaction_record,
    verify_transaction_record_reason,
)
from a2cn.session import SessionManager, SessionState
from tests.conftest import INITIATOR_DID, RESPONDER_DID, make_did_document

INITIATOR_PRIVATE_KEY, INITIATOR_PUBLIC_KEY = generate_keypair()
RESPONDER_PRIVATE_KEY, RESPONDER_PUBLIC_KEY = generate_keypair()
INITIATOR_VM = f"{INITIATOR_DID}#key-1"
RESPONDER_VM = f"{RESPONDER_DID}#key-2026-01"

OFFER_TIMESTAMP = "2026-03-24T10:01:00Z"
ACCEPTANCE_TIMESTAMP = "2026-03-24T10:03:00Z"
TERMS = {"total_value": 9_500_000, "currency": "USD"}


def _session():
    session_id = str(uuid.uuid4())
    session_init = {
        "message_type": "session_init",
        "message_id": "init-1",
        "protocol_version": "0.2",
        "session_params": {
            "deal_type": "saas_renewal",
            "currency": "USD",
            "subject": "Signed acceptance record",
            "max_rounds": 4,
            "session_timeout_seconds": 3600,
            "round_timeout_seconds": 900,
        },
        "initiator": {
            "organization_name": "TechCorp",
            "did": INITIATOR_DID,
            "verification_method": INITIATOR_VM,
            "agent_id": "buyer-agent",
            "endpoint": "https://techcorp.example/api/a2cn",
        },
        "initiator_mandate": {"mandate_type": "declared"},
    }
    session_ack = {
        "message_type": "session_ack",
        "message_id": "ack-1",
        "session_id": session_id,
        "in_reply_to": "init-1",
        "protocol_version": "0.2",
        "session_params_accepted": {
            "deal_type": "saas_renewal",
            "currency": "USD",
            "max_rounds": 4,
            "session_timeout_seconds": 3600,
            "round_timeout_seconds": 900,
        },
        "responder": {
            "organization_name": "Acme",
            "did": RESPONDER_DID,
            "verification_method": RESPONDER_VM,
            "agent_id": "seller-agent",
            "endpoint": "https://acme.example/api/a2cn",
        },
        "responder_mandate": {"mandate_type": "declared"},
        "session_created_at": "2026-03-24T10:00:00Z",
        "current_turn": "initiator",
    }

    manager = SessionManager()
    did_documents = {
        INITIATOR_DID: make_did_document(
            INITIATOR_DID, "key-1", public_key_to_jwk(INITIATOR_PUBLIC_KEY)
        ),
        RESPONDER_DID: make_did_document(
            RESPONDER_DID, "key-2026-01", public_key_to_jwk(RESPONDER_PUBLIC_KEY)
        ),
    }
    for did, did_document in did_documents.items():
        manager.register_did_document(did, did_document)

    session = manager.create_session(
        session_id, session_init, session_ack, "2026-03-24T10:00:00Z"
    )
    session.session_timeout_seconds = 86400 * 365 * 100
    return manager, session, did_documents


def _offer(session_id: str) -> dict:
    act = protocol_act_object(
        protocol_version=PROTOCOL_ACT_VERSION,
        session_id=session_id,
        round_number=1,
        sequence_number=1,
        message_type="offer",
        sender_did=INITIATOR_DID,
        timestamp=OFFER_TIMESTAMP,
        expires_at="2030-01-01T00:00:00Z",
        terms=TERMS,
    )
    act_hash = hash_object(act)
    return {
        "message_type": "offer",
        "message_id": "offer-1",
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "buyer-agent",
        "sender_verification_method": INITIATOR_VM,
        "timestamp": OFFER_TIMESTAMP,
        "expires_at": "2030-01-01T00:00:00Z",
        "terms": TERMS,
        "protocol_act_hash": act_hash,
        "protocol_act_signature": sign_jws(
            act_hash, INITIATOR_PRIVATE_KEY, kid=INITIATOR_VM
        ),
    }


def _acceptance(session_id: str, offer: dict) -> dict:
    acceptance = {
        "message_type": "acceptance",
        "message_id": "acceptance-1",
        "session_id": session_id,
        "in_reply_to": offer["message_id"],
        "round_number": 1,
        "sequence_number": 2,
        "accepted_offer_id": offer["message_id"],
        "accepted_protocol_act_hash": offer["protocol_act_hash"],
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "seller-agent",
        "sender_verification_method": RESPONDER_VM,
        "timestamp": ACCEPTANCE_TIMESTAMP,
    }
    acceptance["acceptance_signature"] = sign_jws(
        signed_act_hash(acceptance), RESPONDER_PRIVATE_KEY, kid=RESPONDER_VM
    )
    return acceptance


def _completed():
    manager, session, did_documents = _session()
    offer = _offer(session.session_id)
    manager.process_message(session, offer)
    acceptance = _acceptance(session.session_id, offer)
    manager.process_message(session, acceptance)
    assert session.state == SessionState.COMPLETED
    return session, did_documents, offer, acceptance


def _record():
    session, did_documents, offer, acceptance = _completed()
    return (
        generate_transaction_record(session),
        did_documents,
        offer,
        acceptance,
    )


def _resealed(record: dict) -> dict:
    record = copy.deepcopy(record)
    record["record_hash"] = ""
    record["record_hash"] = hash_object(record)
    return record


def _acceptance_act_from_record(record: dict) -> dict:
    """Rebuild the acceptance's signed act from the record, reading ONLY its own.

    Spelled out here rather than imported, so the test is an independent check of
    which fields the record must make available and, just as importantly, of
    where they come from. Nothing here reads final_offer: an acceptance that can
    only be rebuilt by borrowing another act's values is not bound by its own
    signature.
    """
    final_acceptance = record["final_acceptance"]
    return {
        "protocol_version": final_acceptance["protocol_version"],
        "session_id": record["session_id"],
        "round_number": final_acceptance["round_number"],
        "sequence_number": final_acceptance["sequence_number"],
        "message_type": final_acceptance["message_type"],
        "sender_did": final_acceptance["sender_did"],
        "timestamp": final_acceptance["timestamp"],
        "accepted_offer_id": final_acceptance["accepted_offer_id"],
        "accepted_protocol_act_hash": final_acceptance["accepted_protocol_act_hash"],
    }


# ---------------------------------------------------------------------------
# The version, and what the record carries
# ---------------------------------------------------------------------------


def test_the_bound_version_is_the_only_accepted_one():
    assert TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE == "0.4"
    assert ACCEPTED_TRANSACTION_RECORD_VERSIONS == (
        TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE,
    )
    # The older shapes stay known — their schemas are published and a reader can
    # still parse them — but knowing a shape is not accepting it.
    assert TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT in KNOWN_TRANSACTION_RECORD_VERSIONS
    assert TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE in KNOWN_TRANSACTION_RECORD_VERSIONS


def test_a_generated_record_states_the_bound_version():
    record, _, _, _ = _record()

    assert record["record_version"] == TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE


def test_final_acceptance_carries_the_fields_its_signature_covers():
    record, _, _, _ = _record()
    final_acceptance = record["final_acceptance"]

    assert FINAL_ACCEPTANCE_ACT_FIELDS == ("protocol_version", "message_type", "timestamp")
    for name in FINAL_ACCEPTANCE_ACT_FIELDS:
        assert name in final_acceptance
    assert final_acceptance["message_type"] == "acceptance"
    assert final_acceptance["timestamp"] == ACCEPTANCE_TIMESTAMP
    assert final_acceptance["protocol_version"] == PROTOCOL_ACT_VERSION


# ---------------------------------------------------------------------------
# The acceptance rebinds, from its own stored fields
# ---------------------------------------------------------------------------


def test_the_acceptance_rebuilds_from_the_record_to_what_was_signed():
    record, _, _, acceptance = _record()

    assert hash_object(_acceptance_act_from_record(record)) == signed_act_hash(acceptance)


def test_a_record_verifies_end_to_end():
    record, did_documents, offer, _ = _record()

    assert verify_transaction_record(
        record, did_documents, [offer["protocol_act_hash"]]
    )


def test_the_rebuild_reads_the_acceptances_own_timestamp_not_the_offers():
    """The anti-borrowing guard, and the reason this version exists.

    The two wrong hashes produced during the determination both came from a
    value standing in for one the record did not hold — an empty string, then
    the offer's timestamp. The offer's timestamp differs from the acceptance's
    here by design, so a verifier that reached for final_offer would compute a
    different hash and this would fail.
    """
    record, _, _, acceptance = _record()

    assert record["final_offer"]["timestamp"] != record["final_acceptance"]["timestamp"]

    borrowed = _acceptance_act_from_record(record)
    borrowed["timestamp"] = record["final_offer"]["timestamp"]

    assert hash_object(borrowed) != signed_act_hash(acceptance)


def test_altering_the_acceptances_stored_timestamp_breaks_its_signature():
    record, did_documents, offer, _ = _record()
    tampered = copy.deepcopy(record)
    tampered["final_acceptance"]["timestamp"] = "2026-03-24T11:00:00Z"

    assert verify_transaction_record_reason(
        _resealed(tampered), did_documents, [offer["protocol_act_hash"]]
    ) == REASON_ACCEPTANCE_SIGNATURE_INVALID


@pytest.mark.parametrize("field_name", ["protocol_version", "message_type", "timestamp"])
def test_a_record_missing_an_acceptance_act_field_is_unbound(field_name: str):
    record, did_documents, offer, _ = _record()
    stripped = copy.deepcopy(record)
    del stripped["final_acceptance"][field_name]

    assert verify_transaction_record_reason(
        _resealed(stripped), did_documents, [offer["protocol_act_hash"]]
    ) == REASON_UNBOUND_RECORD_VERSION


def test_a_record_relabelled_to_the_previous_version_is_refused():
    """"0.3" cannot rebind the acceptance, so it is not an accepted tier."""
    record, did_documents, offer, _ = _record()
    relabelled = copy.deepcopy(record)
    relabelled["record_version"] = TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT

    assert verify_transaction_record_reason(
        _resealed(relabelled), did_documents, [offer["protocol_act_hash"]]
    ) == REASON_UNBOUND_RECORD_VERSION


# ---------------------------------------------------------------------------
# The offer side does not move
# ---------------------------------------------------------------------------


def test_final_offer_is_untouched_by_this_version():
    record, _, offer, _ = _record()
    final_offer = record["final_offer"]

    assert final_offer["protocol_act_hash"] == offer["protocol_act_hash"]
    assert set(final_offer) == {
        "message_id",
        "protocol_version",
        "round_number",
        "sequence_number",
        "message_type",
        "sender_did",
        "timestamp",
        "expires_at",
        "protocol_act_hash",
        "protocol_act_signature",
    }
