"""Tests for producer-sealed Session Evidence Records."""

import copy
import json
import uuid
from pathlib import Path

import pytest

from a2cn.crypto import (
    generate_keypair,
    hash_object,
    private_key_from_jwk,
    public_key_to_jwk,
    sign_jws,
)
from a2cn.evidence import (
    assess_session_evidence_record,
    generate_session_evidence_record,
    verify_session_evidence_record,
)
from a2cn.record import generate_transaction_record, verify_transaction_record
from a2cn.session import Session, SessionManager, SessionState
from tests.conftest import INITIATOR_DID, RESPONDER_DID, make_did_document


INITIATOR_PRIVATE_KEY, INITIATOR_PUBLIC_KEY = generate_keypair()
RESPONDER_PRIVATE_KEY, RESPONDER_PUBLIC_KEY = generate_keypair()

INITIATOR_VM = f"{INITIATOR_DID}#key-1"
RESPONDER_VM = f"{RESPONDER_DID}#key-2026-01"


def _make_session():
    session_id = str(uuid.uuid4())
    session_init = {
        "message_type": "session_init",
        "message_id": "init-1",
        "protocol_version": "0.2",
        "session_params": {
            "deal_type": "saas_renewal",
            "currency": "USD",
            "subject": "Session evidence test",
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

    session = manager.create_session(
        session_id,
        session_init,
        session_ack,
        "2026-03-24T10:00:00Z",
    )
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
    timestamp: str = "2026-03-24T10:01:00Z",
    in_reply_to: str | None = None,
) -> dict:
    terms = {"total_value": 9_500_000, "currency": "USD"}
    verification_method = INITIATOR_VM if sender_did == INITIATOR_DID else RESPONDER_VM
    private_key = (
        INITIATOR_PRIVATE_KEY if sender_did == INITIATOR_DID else RESPONDER_PRIVATE_KEY
    )
    protocol_act = {
        "protocol_version": "0.2",
        "session_id": session_id,
        "round_number": round_number,
        "sequence_number": sequence_number,
        "message_type": message_type,
        "sender_did": sender_did,
        "timestamp": timestamp,
        "expires_at": "2030-01-01T00:00:00Z",
        "terms": terms,
    }
    protocol_act_hash = hash_object(protocol_act)
    message = {
        "message_type": message_type,
        "message_id": message_id,
        "session_id": session_id,
        "round_number": round_number,
        "sequence_number": sequence_number,
        "sender_did": sender_did,
        "sender_agent_id": "buyer-agent" if sender_did == INITIATOR_DID else "seller-agent",
        "sender_verification_method": verification_method,
        "timestamp": timestamp,
        "expires_at": "2030-01-01T00:00:00Z",
        "terms": terms,
        "protocol_act_hash": protocol_act_hash,
        "protocol_act_signature": sign_jws(
            protocol_act_hash,
            private_key,
            kid=verification_method,
        ),
    }
    if in_reply_to:
        message["in_reply_to"] = in_reply_to
    return message


def _acceptance(session_id: str, offer: dict) -> dict:
    payload = {
        "session_id": session_id,
        "round_number": offer["round_number"],
        "sequence_number": 2,
        "accepted_offer_id": offer["message_id"],
        "accepted_protocol_act_hash": offer["protocol_act_hash"],
    }
    return {
        "message_type": "acceptance",
        "message_id": "acceptance-1",
        "session_id": session_id,
        "in_reply_to": offer["message_id"],
        "round_number": offer["round_number"],
        "sequence_number": 2,
        "accepted_offer_id": offer["message_id"],
        "accepted_protocol_act_hash": offer["protocol_act_hash"],
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "seller-agent",
        "sender_verification_method": RESPONDER_VM,
        "timestamp": "2026-03-24T10:03:00Z",
        "acceptance_signature": sign_jws(
            hash_object(payload),
            RESPONDER_PRIVATE_KEY,
            kid=RESPONDER_VM,
        ),
    }


def _mark_timed_out(session) -> None:
    session.state = SessionState.TIMED_OUT
    session.current_turn = "none"
    session.terminal_reason = "session_timeout"
    session.terminal_message_id = None
    session.state_updated_at = "2026-03-24T10:10:00Z"


def _generate(session, observed_acts=None):
    return generate_session_evidence_record(
        session,
        producer_private_key=INITIATOR_PRIVATE_KEY,
        producer_did=INITIATOR_DID,
        producer_agent_id="buyer-agent",
        producer_verification_method=INITIATOR_VM,
        observed_acts=observed_acts,
    )


def _external_counteroffer() -> dict:
    return {
        "sequence_number": 2,
        "round_number": 2,
        "message_type": "counteroffer",
        "message_id": "external-counteroffer-1",
        "sender_did": RESPONDER_DID,
        "timestamp": "2026-03-24T10:02:00Z",
        "source_protocol": "commerce_api",
        "act": {
            "message_type": "counteroffer",
            "message_id": "external-counteroffer-1",
            "session_id": "external-commerce-session-7",
            "sender_did": RESPONDER_DID,
            "timestamp": "2026-03-24T10:02:00Z",
            "terms": {"total_value": 90_300, "currency": "USD"},
        },
    }


def _mixed_record():
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    return _generate(session, [_external_counteroffer()]), did_documents


def test_fully_signed_completed_session_is_bilateral_and_cross_links_transaction_record():
    manager, session, did_documents = _make_session()
    offer = _offer(session.session_id)
    manager.process_message(session, offer)
    manager.process_message(session, _acceptance(session.session_id, offer))

    transaction_record = generate_transaction_record(session)
    evidence = _generate(session)

    assert evidence["evidence_level"] == "bilateral"
    assert evidence["transaction_record_hash"] == transaction_record["record_hash"]
    assert verify_session_evidence_record(evidence, did_documents)
    assert verify_transaction_record(transaction_record, did_documents, session._offer_chain)


def test_external_unsigned_counteroffer_produces_valid_mixed_evidence():
    evidence, did_documents = _mixed_record()

    assessment = assess_session_evidence_record(evidence, did_documents)

    assert assessment == {
        "valid": True,
        "evidence_level": "mixed",
        "verified_acts": 1,
        "unsigned_acts": 1,
        "invalid_acts": 0,
    }
    assert evidence["acts"][1]["attribution"] == "unsigned_observation"
    assert evidence["acts"][1]["signature"] is None
    assert evidence["acts"][1]["act"]["terms"]["total_value"] == 90_300


def test_tampering_with_unsigned_counterparty_act_invalidates_record():
    evidence, did_documents = _mixed_record()
    evidence["acts"][1]["act"]["terms"]["total_value"] = 70_300

    assert not verify_session_evidence_record(evidence, did_documents)


def test_signed_local_offer_and_timeout_are_unilateral():
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)

    evidence = _generate(session)

    assert evidence["evidence_level"] == "unilateral"
    assert evidence["transaction_record_hash"] is None
    assert evidence["terminal"] == {
        "outcome": "TIMED_OUT",
        "reason": "session_timeout",
        "message_id": None,
        "timestamp": "2026-03-24T10:10:00Z",
    }
    assert verify_session_evidence_record(evidence, did_documents)


def test_tampered_producer_seal_or_record_hash_fails_verification():
    evidence, did_documents = _mixed_record()
    tampered_signature = copy.deepcopy(evidence)
    tampered_signature["producer_signature"] = "not-a-jws"
    tampered_hash = copy.deepcopy(evidence)
    tampered_hash["record_hash"] = "tampered"

    assert not verify_session_evidence_record(tampered_signature, did_documents)
    assert not verify_session_evidence_record(tampered_hash, did_documents)


def test_present_but_invalid_counterparty_signature_fails_instead_of_downgrading():
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)

    invalid_counteroffer = _offer(
        session.session_id,
        sender_did=RESPONDER_DID,
        sequence_number=2,
        round_number=2,
        message_type="counteroffer",
        message_id="invalid-counteroffer",
        timestamp="2026-03-24T10:02:00Z",
        in_reply_to="offer-1",
    )
    invalid_counteroffer["protocol_act_signature"] = sign_jws(
        invalid_counteroffer["protocol_act_hash"],
        INITIATOR_PRIVATE_KEY,
        kid=RESPONDER_VM,
    )

    evidence = _generate(session, [invalid_counteroffer])
    assessment = assess_session_evidence_record(evidence, did_documents)

    assert evidence["acts"][1]["attribution"] == "verified_signature"
    assert not assessment["valid"]
    assert assessment["invalid_acts"] == 1


def test_generator_rejects_a_present_signature_without_a_supported_type():
    manager, session, _ = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    observed = _external_counteroffer()
    observed["signature"] = "present-but-untyped"

    with pytest.raises(ValueError, match="signature_type"):
        _generate(session, [observed])


def test_removing_or_reordering_an_act_invalidates_chain_and_record():
    evidence, did_documents = _mixed_record()
    removed = copy.deepcopy(evidence)
    removed["acts"].pop()
    reordered = copy.deepcopy(evidence)
    reordered["acts"].reverse()

    assert not verify_session_evidence_record(removed, did_documents)
    assert not verify_session_evidence_record(reordered, did_documents)


def test_evidence_level_must_match_verified_content_even_with_a_fresh_seal():
    evidence, did_documents = _mixed_record()
    evidence["evidence_level"] = "bilateral"
    evidence["record_hash"] = ""
    evidence["producer_signature"] = ""
    evidence["record_hash"] = hash_object(evidence)
    evidence["producer_signature"] = sign_jws(
        evidence["record_hash"],
        INITIATOR_PRIVATE_KEY,
        kid=INITIATOR_VM,
    )

    assert not verify_session_evidence_record(evidence, did_documents)


def test_generator_rejects_nonterminal_sessions():
    _, session, _ = _make_session()

    try:
        _generate(session)
    except ValueError as exc:
        assert "terminal" in str(exc)
    else:
        raise AssertionError("nonterminal session evidence generation should fail")


@pytest.mark.parametrize(
    "terminal_state",
    [
        SessionState.REJECTED_FINAL,
        SessionState.WITHDRAWN,
        SessionState.TIMED_OUT,
        SessionState.IMPASSE,
        SessionState.ERROR,
    ],
)
def test_all_noncompleted_terminal_states_produce_unilateral_evidence(terminal_state):
    _, session, did_documents = _make_session()
    session.state = terminal_state
    session.current_turn = "none"
    session.terminal_reason = f"test_{terminal_state.lower()}"
    session.state_updated_at = "2026-03-24T10:10:00Z"

    evidence = _generate(session)

    assert evidence["terminal"]["outcome"] == terminal_state
    assert evidence["transaction_record_hash"] is None
    assert evidence["evidence_level"] == "unilateral"
    assert verify_session_evidence_record(evidence, did_documents)


def test_shared_session_evidence_vector_has_python_typescript_hash_parity():
    fixture_path = (
        Path(__file__).parents[3]
        / "spec"
        / "test-vectors"
        / "session-evidence-record-parity.json"
    )
    fixture = json.loads(fixture_path.read_text())
    source = fixture["session"]
    producer = fixture["producer"]
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
    private_key = private_key_from_jwk(fixture["producer_private_jwk"])

    record = generate_session_evidence_record(
        session,
        producer_private_key=private_key,
        producer_did=producer["did"],
        producer_agent_id=producer["agent_id"],
        producer_verification_method=producer["verification_method"],
        observed_acts=fixture["observed_acts"],
    )
    expected = fixture["expected"]

    assert record["evidence_id"] == expected["evidence_id"]
    assert record["generated_at"] == expected["generated_at"]
    assert record["evidence_level"] == expected["evidence_level"]
    assert [entry["act_hash"] for entry in record["acts"]] == expected["act_hashes"]
    assert record["act_chain_hash"] == expected["act_chain_hash"]
    assert record["record_hash"] == expected["record_hash"]
    assert verify_session_evidence_record(record, fixture["did_documents"])
