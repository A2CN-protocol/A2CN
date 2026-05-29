"""Tests for transaction record generation and verification."""

import copy
import uuid

from a2cn.crypto import generate_keypair, hash_object, public_key_to_jwk, sign_jws
from a2cn.record import generate_transaction_record, verify_transaction_record
from a2cn.session import SessionManager
from tests.conftest import INITIATOR_DID, RESPONDER_DID, make_did_document


INITIATOR_PRIVATE_KEY, INITIATOR_PUBLIC_KEY = generate_keypair()
RESPONDER_PRIVATE_KEY, RESPONDER_PUBLIC_KEY = generate_keypair()


def _make_session():
    session_id = str(uuid.uuid4())
    session_init = {
        "message_type": "session_init",
        "message_id": "init-1",
        "protocol_version": "0.2",
        "session_params": {
            "deal_type": "saas_renewal",
            "currency": "USD",
            "subject": "Record verification test",
            "max_rounds": 4,
            "session_timeout_seconds": 3600,
            "round_timeout_seconds": 900,
        },
        "initiator": {
            "organization_name": "TechCorp",
            "did": INITIATOR_DID,
            "verification_method": f"{INITIATOR_DID}#key-1",
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
            "verification_method": f"{RESPONDER_DID}#key-2026-01",
            "agent_id": "seller-agent",
            "endpoint": "http://localhost:8000",
        },
        "responder_mandate": {"mandate_type": "declared"},
        "session_created_at": "2026-03-24T10:00:00Z",
        "current_turn": "initiator",
    }

    manager = SessionManager()
    did_documents = {
        INITIATOR_DID: make_did_document(
            INITIATOR_DID,
            "key-1",
            public_key_to_jwk(INITIATOR_PUBLIC_KEY),
        ),
        RESPONDER_DID: make_did_document(
            RESPONDER_DID,
            "key-2026-01",
            public_key_to_jwk(RESPONDER_PUBLIC_KEY),
        ),
    }
    for did, did_document in did_documents.items():
        manager.register_did_document(did, did_document)

    session = manager.create_session(session_id, session_init, session_ack, "2026-03-24T10:00:00Z")
    session.session_timeout_seconds = 86400 * 365 * 100
    return manager, session, did_documents


def _offer(
    session_id: str,
    *,
    sender_did: str = INITIATOR_DID,
    sequence_number: int = 1,
    round_number: int = 1,
    message_type: str = "offer",
    message_id: str = "offer-1",
    in_reply_to: str | None = None,
) -> dict:
    timestamp = "2026-03-24T10:01:00Z"
    expires_at = "2030-01-01T00:00:00Z"
    terms = {"total_value": 9_500_000, "currency": "USD"}
    protocol_act = {
        "protocol_version": "0.2",
        "session_id": session_id,
        "round_number": round_number,
        "sequence_number": sequence_number,
        "message_type": message_type,
        "sender_did": sender_did,
        "timestamp": timestamp,
        "expires_at": expires_at,
        "terms": terms,
    }
    protocol_act_hash = hash_object(protocol_act)
    if sender_did == INITIATOR_DID:
        private_key = INITIATOR_PRIVATE_KEY
        verification_method = f"{INITIATOR_DID}#key-1"
    else:
        private_key = RESPONDER_PRIVATE_KEY
        verification_method = f"{RESPONDER_DID}#key-2026-01"
    offer = {
        "message_type": message_type,
        "message_id": message_id,
        "session_id": session_id,
        "round_number": round_number,
        "sequence_number": sequence_number,
        "sender_did": sender_did,
        "sender_agent_id": "buyer-agent",
        "sender_verification_method": verification_method,
        "timestamp": timestamp,
        "expires_at": expires_at,
        "terms": terms,
        "protocol_act_hash": protocol_act_hash,
        "protocol_act_signature": sign_jws(
            protocol_act_hash,
            private_key,
            kid=verification_method,
        ),
    }
    if in_reply_to:
        offer["in_reply_to"] = in_reply_to
    return offer


def _acceptance(
    session_id: str,
    offer: dict,
    *,
    sender_did: str = RESPONDER_DID,
    message_id: str = "acceptance-1",
    sequence_number: int = 2,
) -> dict:
    if sender_did == INITIATOR_DID:
        private_key = INITIATOR_PRIVATE_KEY
        verification_method = f"{INITIATOR_DID}#key-1"
    else:
        private_key = RESPONDER_PRIVATE_KEY
        verification_method = f"{RESPONDER_DID}#key-2026-01"
    payload = {
        "session_id": session_id,
        "round_number": offer["round_number"],
        "sequence_number": sequence_number,
        "accepted_offer_id": offer["message_id"],
        "accepted_protocol_act_hash": offer["protocol_act_hash"],
    }
    return {
        "message_type": "acceptance",
        "message_id": message_id,
        "session_id": session_id,
        "in_reply_to": offer["message_id"],
        "round_number": offer["round_number"],
        "sequence_number": sequence_number,
        "accepted_offer_id": offer["message_id"],
        "accepted_protocol_act_hash": offer["protocol_act_hash"],
        "sender_did": sender_did,
        "sender_agent_id": "seller-agent",
        "sender_verification_method": verification_method,
        "timestamp": "2026-03-24T10:03:00Z",
        "acceptance_signature": sign_jws(
            hash_object(payload),
            private_key,
            kid=verification_method,
        ),
    }


def _completed_record():
    manager, session, did_documents = _make_session()
    offer = _offer(session.session_id)
    manager.process_message(session, offer)
    manager.process_message(session, _acceptance(session.session_id, offer))
    return generate_transaction_record(session), did_documents, list(session._offer_chain)


def _completed_multiround_record():
    manager, session, did_documents = _make_session()
    offer = _offer(session.session_id)
    manager.process_message(session, offer)
    counteroffer = _offer(
        session.session_id,
        sender_did=RESPONDER_DID,
        sequence_number=2,
        round_number=2,
        message_type="counteroffer",
        message_id="counteroffer-1",
        in_reply_to=offer["message_id"],
    )
    manager.process_message(session, counteroffer)
    acceptance = _acceptance(
        session.session_id,
        counteroffer,
        sender_did=INITIATOR_DID,
        message_id="acceptance-2",
        sequence_number=3,
    )
    manager.process_message(session, acceptance)
    return generate_transaction_record(session), did_documents, list(session._offer_chain)


def _with_recomputed_record_hash(record: dict) -> dict:
    record = copy.deepcopy(record)
    record["record_hash"] = ""
    record["record_hash"] = hash_object(record)
    return record


def test_verify_transaction_record_accepts_valid_record():
    record, did_documents, offer_hashes = _completed_record()

    assert verify_transaction_record(record, did_documents, offer_hashes)


def test_verify_transaction_record_accepts_callable_did_resolver():
    record, did_documents, offer_hashes = _completed_record()

    assert verify_transaction_record(record, did_documents.__getitem__, offer_hashes)


def test_verify_transaction_record_rejects_tampered_record_hash_input():
    record, did_documents, offer_hashes = _completed_record()
    record["agreed_terms"]["total_value"] += 1

    assert not verify_transaction_record(record, did_documents, offer_hashes)


def test_verify_transaction_record_rejects_tampered_final_offer_signature():
    record, did_documents, offer_hashes = _completed_record()
    record["final_offer"]["protocol_act_signature"] = record["final_acceptance"]["acceptance_signature"]
    record = _with_recomputed_record_hash(record)

    assert not verify_transaction_record(record, did_documents, offer_hashes)


def test_verify_transaction_record_rejects_tampered_acceptance_signature():
    record, did_documents, offer_hashes = _completed_record()
    record["final_acceptance"]["acceptance_signature"] = record["final_offer"]["protocol_act_signature"]
    record = _with_recomputed_record_hash(record)

    assert not verify_transaction_record(record, did_documents, offer_hashes)


def test_verify_transaction_record_rejects_acceptance_jws_with_wrong_payload():
    record, did_documents, offer_hashes = _completed_record()
    record["final_acceptance"]["acceptance_signature"] = sign_jws(
        "not-the-acceptance-payload",
        RESPONDER_PRIVATE_KEY,
        kid=f"{RESPONDER_DID}#key-2026-01",
    )
    record = _with_recomputed_record_hash(record)

    assert not verify_transaction_record(record, did_documents, offer_hashes)


def test_verify_transaction_record_rejects_accepted_hash_mismatch():
    record, did_documents, offer_hashes = _completed_record()
    record["final_acceptance"]["accepted_protocol_act_hash"] = "sha256-tampered"
    record = _with_recomputed_record_hash(record)

    assert not verify_transaction_record(record, did_documents, offer_hashes)


def test_verify_transaction_record_rejects_offer_chain_hash_mismatch():
    record, did_documents, offer_hashes = _completed_record()
    record["offer_chain_hash"] = "sha256-tampered"
    record = _with_recomputed_record_hash(record)

    assert not verify_transaction_record(record, did_documents, offer_hashes)


def test_verify_transaction_record_accepts_multiround_offer_chain():
    record, did_documents, offer_hashes = _completed_multiround_record()

    assert verify_transaction_record(record, did_documents, offer_hashes)
    assert not verify_transaction_record(record, did_documents)


def test_verify_transaction_record_rejects_missing_required_fields():
    record, did_documents, offer_hashes = _completed_record()
    del record["final_offer"]["protocol_act_signature"]
    record = _with_recomputed_record_hash(record)

    assert not verify_transaction_record(record, did_documents, offer_hashes)
