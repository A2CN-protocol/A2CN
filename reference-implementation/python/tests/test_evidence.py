"""Tests for producer-sealed Session Evidence Records."""

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
THIRD_PARTY_PRIVATE_KEY, THIRD_PARTY_PUBLIC_KEY = generate_keypair()

INITIATOR_VM = f"{INITIATOR_DID}#key-1"
RESPONDER_VM = f"{RESPONDER_DID}#key-2026-01"
THIRD_PARTY_DID = "did:example:payment-processor"
THIRD_PARTY_VM = f"{THIRD_PARTY_DID}#key-1"


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


def _third_party_offer(session_id: str) -> dict:
    protocol_act = {
        "protocol_version": "0.2",
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 3,
        "message_type": "offer",
        "sender_did": THIRD_PARTY_DID,
        "timestamp": "2026-03-24T10:03:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "terms": {"total_value": 1, "currency": "USD"},
    }
    protocol_act_hash = hash_object(protocol_act)
    return {
        **protocol_act,
        "message_id": "third-party-offer-1",
        "sender_verification_method": THIRD_PARTY_VM,
        "source_protocol": "commerce_api",
        "protocol_act_hash": protocol_act_hash,
        "protocol_act_signature": sign_jws(
            protocol_act_hash,
            THIRD_PARTY_PRIVATE_KEY,
            kid=THIRD_PARTY_VM,
        ),
    }


def _malformed_signed_observation(
    session_id: str,
    *,
    omit_round_fields: bool = False,
    null_field: str | None = None,
) -> dict:
    act = _offer(
        session_id,
        sender_did=RESPONDER_DID,
        sequence_number=2,
        round_number=2,
        message_type="counteroffer",
        message_id="malformed-counteroffer",
        timestamp="2026-03-24T10:02:00Z",
        in_reply_to="offer-1",
    )
    if omit_round_fields:
        del act["round_number"]
        del act["sequence_number"]
    if null_field is not None:
        act[null_field] = None

    protocol_act = {
        "protocol_version": "0.2",
        "session_id": act.get("session_id", ""),
        "round_number": act.get("round_number"),
        "sequence_number": act.get("sequence_number"),
        "message_type": act.get("message_type", ""),
        "sender_did": act.get("sender_did", ""),
        "timestamp": act.get("timestamp", ""),
        "expires_at": act.get("expires_at", ""),
        "terms": act.get("terms", {}),
    }
    protocol_act_hash = hash_object(protocol_act)
    act["protocol_act_hash"] = protocol_act_hash
    act["protocol_act_signature"] = sign_jws(
        protocol_act_hash,
        RESPONDER_PRIVATE_KEY,
        kid=RESPONDER_VM,
    )
    return {
        "sequence_number": 2,
        "round_number": 2,
        "message_type": "counteroffer",
        "message_id": "malformed-counteroffer",
        "sender_did": RESPONDER_DID,
        "timestamp": "2026-03-24T10:02:00Z",
        "source_protocol": "commerce_api",
        "act": act,
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


def test_verified_nonparty_act_does_not_make_unsigned_party_acts_mixed():
    _, session, did_documents = _make_session()
    session._message_log = [
        {
            "message_type": "rejection",
            "message_id": "unsigned-initiator-rejection",
            "session_id": session.session_id,
            "round_number": 1,
            "sequence_number": 1,
            "sender_did": INITIATOR_DID,
            "timestamp": "2026-03-24T10:01:00Z",
        },
        {
            "message_type": "withdrawal",
            "message_id": "unsigned-responder-withdrawal",
            "session_id": session.session_id,
            "sequence_number": 2,
            "sender_did": RESPONDER_DID,
            "timestamp": "2026-03-24T10:02:00Z",
        },
    ]
    _mark_timed_out(session)
    did_documents[THIRD_PARTY_DID] = make_did_document(
        THIRD_PARTY_DID,
        "key-1",
        public_key_to_jwk(THIRD_PARTY_PUBLIC_KEY),
    )

    evidence = _generate(session, [_third_party_offer(session.session_id)])

    assert evidence["evidence_level"] == "unilateral"
    assert verify_session_evidence_record(evidence, did_documents)


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


def test_timestamp_and_message_id_are_nullable_for_incomplete_unsigned_terminal_act():
    manager, session, did_documents = _make_session()
    manager.process_message(
        session,
        {
            "message_type": "withdrawal",
            "sender_did": INITIATOR_DID,
        },
    )

    evidence = _generate(session)

    assert evidence["terminal"]["outcome"] == SessionState.WITHDRAWN
    assert evidence["terminal"]["message_id"] is None
    assert evidence["acts"][0]["message_id"] is None
    assert evidence["acts"][0]["timestamp"] is None
    assert "message_id" not in evidence["acts"][0]["act"]
    assert "timestamp" not in evidence["acts"][0]["act"]
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


def test_signed_observed_act_requires_round_and_sequence_in_complete_act():
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    observed = _malformed_signed_observation(
        session.session_id,
        omit_round_fields=True,
    )

    evidence = _generate(session, [observed])

    assert not verify_session_evidence_record(evidence, did_documents)


@pytest.mark.parametrize("null_field", ["session_id", "expires_at", "terms"])
def test_signed_observed_act_rejects_null_protocol_fields(null_field):
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    observed = _malformed_signed_observation(
        session.session_id,
        null_field=null_field,
    )

    evidence = _generate(session, [observed])

    assert not verify_session_evidence_record(evidence, did_documents)


def test_signed_observed_act_from_another_session_fails_even_if_relabelled():
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    foreign_act = _offer(
        str(uuid.uuid4()),
        sender_did=RESPONDER_DID,
        sequence_number=2,
        round_number=2,
        message_type="counteroffer",
        message_id="foreign-counteroffer",
        timestamp="2026-03-24T10:02:00Z",
        in_reply_to="offer-1",
    )
    foreign_act["source_protocol"] = "commerce_api"

    evidence = _generate(session, [foreign_act])

    assert evidence["evidence_level"] == "mixed"
    assert not verify_session_evidence_record(evidence, did_documents)


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


def test_unsequenced_acts_are_ordered_by_rfc3339_instant():
    _, session, did_documents = _make_session()
    _mark_timed_out(session)
    observed = [
        {
            "message_type": "counteroffer",
            "message_id": "middle",
            "sender_did": RESPONDER_DID,
            "timestamp": "2026-03-24T09:30:00Z",
            "source_protocol": "commerce_api",
            "act": {
                "message_type": "counteroffer",
                "message_id": "middle",
                "sender_did": RESPONDER_DID,
                "timestamp": "2026-03-24T09:30:00Z",
            },
        },
        {
            "message_type": "offer",
            "message_id": "earliest",
            "sender_did": INITIATOR_DID,
            "timestamp": "2026-03-24T10:00:00+01:00",
            "source_protocol": "commerce_api",
            "act": {
                "message_type": "offer",
                "message_id": "earliest",
                "sender_did": INITIATOR_DID,
                "timestamp": "2026-03-24T10:00:00+01:00",
            },
        },
        {
            "message_type": "counteroffer",
            "message_id": "latest",
            "sender_did": RESPONDER_DID,
            "timestamp": "2026-03-24T10:00:00-01:00",
            "source_protocol": "commerce_api",
            "act": {
                "message_type": "counteroffer",
                "message_id": "latest",
                "sender_did": RESPONDER_DID,
                "timestamp": "2026-03-24T10:00:00-01:00",
            },
        },
    ]

    evidence = _generate(session, observed)

    assert [entry["message_id"] for entry in evidence["acts"]] == [
        "earliest",
        "middle",
        "latest",
    ]
    assert verify_session_evidence_record(evidence, did_documents)


def test_generator_rejects_null_party_metadata():
    _, session, _ = _make_session()
    _mark_timed_out(session)
    session._session_init["initiator"]["organization_name"] = None

    with pytest.raises(ValueError, match="organization_name"):
        _generate(session)


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


def test_unknown_record_version_is_rejected_even_with_a_fresh_seal():
    evidence, did_documents = _mixed_record()
    evidence["record_version"] = "999"
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

    invalid_record = copy.deepcopy(record)
    invalid_timestamp = fixture["invalid_cases"]["non_rfc3339_timestamp"]
    invalid_record["acts"][1]["timestamp"] = invalid_timestamp
    invalid_record["acts"][1]["act"]["timestamp"] = invalid_timestamp
    invalid_record["acts"][1]["act_hash"] = hash_object(
        invalid_record["acts"][1]["act"]
    )
    invalid_record["act_chain_hash"] = hash_bytes(
        canonicalize([entry["act_hash"] for entry in invalid_record["acts"]])
    )
    invalid_record["record_hash"] = ""
    invalid_record["producer_signature"] = ""
    invalid_record["record_hash"] = hash_object(invalid_record)
    invalid_record["producer_signature"] = sign_jws(
        invalid_record["record_hash"],
        private_key,
        kid=producer["verification_method"],
    )

    assert (
        invalid_record["record_hash"]
        == expected["invalid_non_rfc3339_record_hash"]
    )
    assert not verify_session_evidence_record(
        invalid_record,
        fixture["did_documents"],
    )
