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


def _generate(session, observed_acts=None, **kwargs):
    return generate_session_evidence_record(
        session,
        producer_private_key=INITIATOR_PRIVATE_KEY,
        producer_did=INITIATOR_DID,
        producer_agent_id="buyer-agent",
        producer_verification_method=INITIATOR_VM,
        observed_acts=observed_acts,
        **kwargs,
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


# ---------------------------------------------------------------------------
# Conformance fixtures for the three additive Section 9A extensions:
# identity-light responder, recomputable money basis, controls-halt outcome.
# ---------------------------------------------------------------------------

OBSERVED_RESPONDER = {
    "identity_source": "supplier_ordering_portal",
    "organization_name": "Northwind Supply",
    "observed_credential": {
        "type": "vat_number",
        "digest": hash_bytes(b"GB123456789"),
    },
}

MONEY_BASIS = {
    "raw_amounts": ["70000.00", "25000.00"],
    "currency": "USD",
    "minor_unit_exponent": 2,
    "basis": "net",
    "normalized_total_minor": 9_500_000,
}


def _make_identity_light_session():
    """The same session, except the responder holds no A2CN identity at all."""
    manager, session, did_documents = _make_session()
    session._session_ack["responder"] = {"organization_name": "Northwind Supply"}
    session._session_ack["responder_mandate"] = {}
    session.responder_mandate = {}
    del did_documents[RESPONDER_DID]
    return manager, session, did_documents


def _observed_quote(
    *,
    sender_did: str | None = RESPONDER_DID,
    total_value: int = 9_500_000,
    money_basis: dict | None = None,
    message_id: str = "portal-quote-1",
) -> dict:
    entry = {
        "sequence_number": 2,
        "round_number": 2,
        "message_type": "counteroffer",
        "message_id": message_id,
        "sender_did": sender_did,
        "timestamp": "2026-03-24T10:02:00Z",
        "source_protocol": "supplier_portal",
        "act": {
            "message_type": "counteroffer",
            "message_id": message_id,
            "timestamp": "2026-03-24T10:02:00Z",
            "terms": {"total_value": total_value, "currency": "USD"},
        },
    }
    if money_basis is not None:
        entry["money_basis"] = copy.deepcopy(money_basis)
    return entry


def _reseal(evidence: dict) -> dict:
    """Re-derive the chain hash and producer seal after editing a record."""
    evidence["act_chain_hash"] = hash_bytes(
        canonicalize([entry["act_hash"] for entry in evidence["acts"]])
    )
    evidence["record_hash"] = ""
    evidence["producer_signature"] = ""
    evidence["record_hash"] = hash_object(evidence)
    evidence["producer_signature"] = sign_jws(
        evidence["record_hash"],
        INITIATOR_PRIVATE_KEY,
        kid=INITIATOR_VM,
    )
    return evidence


def _priced_record():
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    evidence = _generate(session, [_observed_quote(money_basis=MONEY_BASIS)])
    return evidence, did_documents


def _halted_record():
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    session.state = SessionState.WITHDRAWN
    session.current_turn = "none"
    session.terminal_message_id = None
    session.state_updated_at = "2026-03-24T10:10:00Z"
    evidence = _generate(
        session,
        terminal_outcome="HALTED_BY_CONTROLS",
        terminal_reason="buyer_spend_control:max_session_commitment",
    )
    return evidence, did_documents


# --- Fixture (i) -----------------------------------------------------------


def test_observed_party_responder_with_unsigned_acts_is_valid_unilateral():
    manager, session, did_documents = _make_identity_light_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)

    evidence = _generate(
        session,
        [_observed_quote(sender_did=None)],
        observed_responder=OBSERVED_RESPONDER,
    )

    assert evidence["parties"]["responder"] == {
        "identity_source": "supplier_ordering_portal",
        "organization_name": "Northwind Supply",
        "observed_credential": {
            "type": "vat_number",
            "digest": hash_bytes(b"GB123456789"),
        },
        "did_declared": False,
        "a2cn_endpoint_declared": False,
        "mandate_declared": False,
    }
    assert "did" not in evidence["parties"]["responder"]
    assert evidence["acts"][1]["sender_did"] is None
    assert evidence["acts"][1]["attribution"] == "unsigned_observation"
    assert assess_session_evidence_record(evidence, did_documents) == {
        "valid": True,
        "evidence_level": "unilateral",
        "verified_acts": 1,
        "unsigned_acts": 1,
        "invalid_acts": 0,
    }


def test_verifier_never_resolves_the_observed_identity():
    manager, session, did_documents = _make_identity_light_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    evidence = _generate(
        session,
        [_observed_quote(sender_did=None)],
        observed_responder=OBSERVED_RESPONDER,
    )
    requested: list[str] = []

    def recording_resolver(did: str) -> dict:
        requested.append(did)
        return did_documents[did]

    assert verify_session_evidence_record(evidence, recording_resolver)
    assert set(requested) == {INITIATOR_DID}


# --- Fixture (ii) ----------------------------------------------------------


def test_observed_responder_claiming_a_verified_signature_is_rejected():
    manager, session, did_documents = _make_identity_light_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    # The counterparty's key IS resolvable here, so the refusal below cannot be
    # blamed on a signature that failed to check out.
    did_documents[RESPONDER_DID] = make_did_document(
        RESPONDER_DID,
        "key-2026-01",
        public_key_to_jwk(RESPONDER_PUBLIC_KEY),
    )

    healthy = _generate(
        session,
        [_observed_quote(sender_did=None)],
        observed_responder=OBSERVED_RESPONDER,
    )
    assert verify_session_evidence_record(healthy, did_documents)

    signed_act = _offer(
        session.session_id,
        sender_did=RESPONDER_DID,
        sequence_number=2,
        round_number=2,
        message_type="counteroffer",
        message_id="portal-quote-1",
        timestamp="2026-03-24T10:02:00Z",
    )
    attack = copy.deepcopy(healthy)
    attack["acts"][1] = {
        "sequence_number": 2,
        "round_number": 2,
        "message_type": "counteroffer",
        "message_id": "portal-quote-1",
        "sender_did": RESPONDER_DID,
        "timestamp": "2026-03-24T10:02:00Z",
        "source_protocol": "supplier_portal",
        "act": signed_act,
        "act_hash": hash_object(signed_act),
        "sender_verification_method": RESPONDER_VM,
        "signature_type": "protocol_act_signature",
        "signature": signed_act["protocol_act_signature"],
        "attribution": "verified_signature",
    }
    _reseal(attack)

    assessment = assess_session_evidence_record(attack, did_documents)

    # Assert the reason before the verdict: the signature really does verify, so
    # the rejection is the identity-light coupling and not a broken act.
    assert assessment["invalid_acts"] == 0
    assert assessment["verified_acts"] == 2
    assert assessment["evidence_level"] == "unilateral"
    assert not assessment["valid"]


def test_generator_refuses_an_observed_party_for_a_responder_that_declared_identity():
    manager, session, _ = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)

    with pytest.raises(ValueError, match="declared a DID"):
        _generate(session, observed_responder=OBSERVED_RESPONDER)


def test_generator_never_fabricates_a_did_for_a_signed_identity_light_act():
    manager, session, _ = _make_identity_light_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    unattributable = _observed_quote(sender_did=None)
    unattributable["act"]["protocol_act_signature"] = "present-but-unattributable"

    with pytest.raises(ValueError, match="sender_did"):
        _generate(session, [unattributable], observed_responder=OBSERVED_RESPONDER)


# --- Fixture (iii) ---------------------------------------------------------


def test_money_basis_recomputing_to_the_signed_total_is_valid():
    evidence, did_documents = _priced_record()

    assert evidence["acts"][1]["money_basis"] == MONEY_BASIS
    # The basis is a producer annotation about the act, never inside the act the
    # act_hash protects.
    assert "money_basis" not in evidence["acts"][1]["act"]
    assert evidence["acts"][1]["act"]["terms"]["total_value"] == 9_500_000
    assert verify_session_evidence_record(evidence, did_documents)


def test_money_basis_on_the_terminal_quote_binds_to_the_named_act():
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    session.state = SessionState.IMPASSE
    session.current_turn = "none"
    session.terminal_reason = "no_movement"
    session.terminal_message_id = "portal-quote-1"
    session.state_updated_at = "2026-03-24T10:10:00Z"

    evidence = _generate(
        session,
        [_observed_quote()],
        terminal_money_basis=MONEY_BASIS,
    )
    assert verify_session_evidence_record(evidence, did_documents)

    # A terminal basis that names no act is refused, not ignored.
    unresolvable = copy.deepcopy(evidence)
    unresolvable["terminal"]["message_id"] = "no-such-act"
    _reseal(unresolvable)
    assert not verify_session_evidence_record(unresolvable, did_documents)

    # And it must bind to the total actually inside the act it names.
    with pytest.raises(ValueError, match="money_basis"):
        _generate(
            session,
            [_observed_quote(total_value=9_400_000)],
            terminal_money_basis=MONEY_BASIS,
        )


# --- Fixture (iv) ----------------------------------------------------------


def test_money_basis_that_does_not_recompute_is_rejected():
    healthy, did_documents = _priced_record()
    assert verify_session_evidence_record(healthy, did_documents)
    # Re-sealing must itself produce verifiable records, or every red below would
    # prove only that the reseal helper is broken.
    assert verify_session_evidence_record(_reseal(copy.deepcopy(healthy)), did_documents)

    tampered_raw = copy.deepcopy(healthy)
    tampered_raw["acts"][1]["money_basis"]["raw_amounts"] = ["70000.00", "25000.01"]
    _reseal(tampered_raw)

    tampered_total = copy.deepcopy(healthy)
    tampered_total["acts"][1]["money_basis"]["normalized_total_minor"] = 9_500_001
    _reseal(tampered_total)

    assert not verify_session_evidence_record(tampered_raw, did_documents)
    assert not verify_session_evidence_record(tampered_total, did_documents)


def test_money_basis_is_never_converted_between_net_and_gross():
    healthy, did_documents = _priced_record()
    assert verify_session_evidence_record(healthy, did_documents)

    # Relabelling net as gross must not make the arithmetic move: the label is
    # checked, never applied. Same raw amounts, same total, still valid.
    relabelled = copy.deepcopy(healthy)
    relabelled["acts"][1]["money_basis"]["basis"] = "gross"
    _reseal(relabelled)
    assert verify_session_evidence_record(relabelled, did_documents)

    # A gross total that only balances if a tax rate were applied stays rejected.
    grossed_up = copy.deepcopy(healthy)
    grossed_up["acts"][1]["money_basis"]["basis"] = "gross"
    grossed_up["acts"][1]["money_basis"]["normalized_total_minor"] = 11_400_000
    _reseal(grossed_up)
    assert not verify_session_evidence_record(grossed_up, did_documents)

    unknown_label = copy.deepcopy(healthy)
    unknown_label["acts"][1]["money_basis"]["basis"] = "vat_exclusive_maybe"
    _reseal(unknown_label)
    assert not verify_session_evidence_record(unknown_label, did_documents)


def test_money_basis_refuses_amounts_finer_than_the_stated_minor_unit():
    healthy, did_documents = _priced_record()
    assert verify_session_evidence_record(healthy, did_documents)

    sub_minor = copy.deepcopy(healthy)
    sub_minor["acts"][1]["money_basis"]["raw_amounts"] = ["70000.001", "25000.00"]
    _reseal(sub_minor)

    # These are chosen so that DISCARDING the sub-minor digit lands exactly on the
    # signed total: rounding to fit is the failure mode, and it would read as a
    # clean recompute. The tenth of a cent must make the record fail instead.
    assert not verify_session_evidence_record(sub_minor, did_documents)


def test_money_basis_currency_must_match_the_act_it_describes():
    healthy, did_documents = _priced_record()
    assert verify_session_evidence_record(healthy, did_documents)

    wrong_currency = copy.deepcopy(healthy)
    wrong_currency["acts"][1]["money_basis"]["currency"] = "EUR"
    _reseal(wrong_currency)

    assert not verify_session_evidence_record(wrong_currency, did_documents)


# --- Fixture (v) -----------------------------------------------------------


def test_money_basis_claiming_a_total_with_no_raw_amounts_fails_closed():
    healthy, did_documents = _priced_record()
    assert verify_session_evidence_record(healthy, did_documents)

    absent = copy.deepcopy(healthy)
    del absent["acts"][1]["money_basis"]["raw_amounts"]
    _reseal(absent)

    empty = copy.deepcopy(healthy)
    empty["acts"][1]["money_basis"]["raw_amounts"] = []
    _reseal(empty)

    assert not verify_session_evidence_record(absent, did_documents)
    assert not verify_session_evidence_record(empty, did_documents)


# --- Fixture (vi) ----------------------------------------------------------


def test_controls_halt_outcome_is_accepted():
    evidence, did_documents = _halted_record()

    assert evidence["terminal"]["outcome"] == "HALTED_BY_CONTROLS"
    assert evidence["terminal"]["reason"] == (
        "buyer_spend_control:max_session_commitment"
    )
    assert evidence["transaction_record_hash"] is None
    assert evidence["evidence_level"] == "unilateral"
    assert verify_session_evidence_record(evidence, did_documents)


def test_a_completed_session_cannot_be_relabelled_as_halted():
    manager, session, _ = _make_session()
    offer = _offer(session.session_id)
    manager.process_message(session, offer)
    manager.process_message(session, _acceptance(session.session_id, offer))

    with pytest.raises(ValueError, match="COMPLETED"):
        _generate(session, terminal_outcome="HALTED_BY_CONTROLS")


# --- Fixture (vii) ---------------------------------------------------------


def test_an_unrecognized_terminal_outcome_is_still_rejected():
    healthy, did_documents = _halted_record()
    # The control proves the outcome gate is not simply refusing everything: the
    # newly recognized member passes through it.
    assert verify_session_evidence_record(healthy, did_documents)

    unknown = copy.deepcopy(healthy)
    unknown["terminal"]["outcome"] = "HALTED_BY_VIBES"
    _reseal(unknown)

    assert not verify_session_evidence_record(unknown, did_documents)


def test_awaiting_counterparty_signature_is_not_a_terminal_outcome():
    healthy, did_documents = _halted_record()
    assert verify_session_evidence_record(healthy, did_documents)

    paused = copy.deepcopy(healthy)
    paused["terminal"]["outcome"] = "AWAITING_COUNTERPARTY_SIGNATURE"
    _reseal(paused)

    assert not verify_session_evidence_record(paused, did_documents)


# --- extensions ------------------------------------------------------------


def test_namespaced_extensions_are_sealed_and_never_interpreted():
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)

    evidence = _generate(
        session,
        extensions={"acme.procurement": {"requisition_id": "REQ-42", "arbitrary": [1, 2]}},
    )

    assert evidence["extensions"] == {
        "acme.procurement": {"requisition_id": "REQ-42", "arbitrary": [1, 2]}
    }
    assert verify_session_evidence_record(evidence, did_documents)

    # The seal covers them: editing an extension without re-sealing invalidates.
    edited = copy.deepcopy(evidence)
    edited["extensions"]["acme.procurement"]["requisition_id"] = "REQ-43"
    assert not verify_session_evidence_record(edited, did_documents)


def test_unnamespaced_extension_keys_are_refused_by_generator_and_verifier():
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)

    with pytest.raises(ValueError, match="namespaced"):
        _generate(session, extensions={"requisition_id": "REQ-42"})

    healthy = _generate(session, extensions={"acme.procurement": {"ok": True}})
    assert verify_session_evidence_record(healthy, did_documents)

    bare = copy.deepcopy(healthy)
    bare["extensions"] = {"requisition_id": "REQ-42"}
    _reseal(bare)
    assert not verify_session_evidence_record(bare, did_documents)


def test_unnamespaced_top_level_fields_remain_closed():
    healthy, did_documents = _priced_record()
    assert verify_session_evidence_record(healthy, did_documents)

    widened = copy.deepcopy(healthy)
    widened["acme_procurement"] = {"requisition_id": "REQ-42"}
    _reseal(widened)

    assert not verify_session_evidence_record(widened, did_documents)


# --- inputs that would silently pass if a guard were absent -----------------


def test_an_observed_responder_cannot_ride_a_completed_record_to_bilateral():
    manager, session, did_documents = _make_session()
    offer = _offer(session.session_id)
    manager.process_message(session, offer)
    manager.process_message(session, _acceptance(session.session_id, offer))

    bilateral = _generate(session)
    assert bilateral["evidence_level"] == "bilateral"
    assert verify_session_evidence_record(bilateral, did_documents)

    # Strip the counterparty's identity and its signed acceptance. What remains
    # is one party whose every act is signed, which the classifier still calls
    # bilateral -- so the explicit unilateral coupling is the only thing that
    # refuses a COMPLETED record with an unidentified counterparty.
    forged = copy.deepcopy(bilateral)
    forged["parties"]["responder"] = {
        "identity_source": "supplier_ordering_portal",
        "did_declared": False,
        "a2cn_endpoint_declared": False,
        "mandate_declared": False,
    }
    forged["acts"] = [forged["acts"][0]]
    _reseal(forged)

    assessment = assess_session_evidence_record(forged, did_documents)

    assert assessment["invalid_acts"] == 0
    assert assessment["evidence_level"] == "bilateral"
    assert not assessment["valid"]


def test_a_zero_total_money_basis_still_requires_its_raw_amounts():
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    zero_basis = {
        "raw_amounts": ["0.00"],
        "currency": "USD",
        "minor_unit_exponent": 2,
        "basis": "line_total",
        "normalized_total_minor": 0,
    }

    healthy = _generate(
        session,
        [_observed_quote(total_value=0, money_basis=zero_basis)],
    )
    assert verify_session_evidence_record(healthy, did_documents)

    # Zero is the one total that absent raw amounts would sum to by themselves,
    # so it separates a fail-closed rule from an arithmetic accident.
    absent = copy.deepcopy(healthy)
    del absent["acts"][1]["money_basis"]["raw_amounts"]
    _reseal(absent)

    assert not verify_session_evidence_record(absent, did_documents)


def test_a_verified_act_can_never_carry_a_null_sender_did():
    """Nullable sender_did must not open a hole in signed attribution.

    Measured, not assumed: both constructions below are already rejected at the
    act level by guards that predate this change -- the entry/act field
    comparison when the act keeps its own sender_did, and the signed-payload
    requirement when it does not. The shape check added alongside observed_party
    makes the invariant local; it is defence in depth, not the sole defence.
    """
    healthy, did_documents = _priced_record()
    assert verify_session_evidence_record(healthy, did_documents)
    assert healthy["acts"][0]["attribution"] == "verified_signature"

    entry_only = copy.deepcopy(healthy)
    entry_only["acts"][0]["sender_did"] = None
    _reseal(entry_only)

    entry_and_act = copy.deepcopy(healthy)
    entry_and_act["acts"][0]["sender_did"] = None
    del entry_and_act["acts"][0]["act"]["sender_did"]
    entry_and_act["acts"][0]["act_hash"] = hash_object(entry_and_act["acts"][0]["act"])
    _reseal(entry_and_act)

    for record in (entry_only, entry_and_act):
        assessment = assess_session_evidence_record(record, did_documents)
        assert assessment["invalid_acts"] == 1
        assert not assessment["valid"]


def test_extension_vectors_have_python_typescript_hash_parity():
    fixture_path = (
        Path(__file__).parents[3]
        / "spec"
        / "test-vectors"
        / "session-evidence-record-extensions.json"
    )
    fixture = json.loads(fixture_path.read_text())
    producer = fixture["producer"]
    private_key = private_key_from_jwk(fixture["producer_private_jwk"])

    assert set(fixture["vectors"]) == {
        "observed_party_responder",
        "money_basis",
        "halted_by_controls",
    }

    for name, vector in fixture["vectors"].items():
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

        record = generate_session_evidence_record(
            session,
            producer_private_key=private_key,
            producer_did=producer["did"],
            producer_agent_id=producer["agent_id"],
            producer_verification_method=producer["verification_method"],
            observed_acts=vector["observed_acts"],
            **vector["options"],
        )
        expected = vector["expected"]

        assert record["evidence_id"] == expected["evidence_id"], name
        assert record["generated_at"] == expected["generated_at"], name
        assert record["evidence_level"] == expected["evidence_level"], name
        assert record["terminal"]["outcome"] == expected["terminal_outcome"], name
        assert [
            entry["act_hash"] for entry in record["acts"]
        ] == expected["act_hashes"], name
        assert record["act_chain_hash"] == expected["act_chain_hash"], name
        assert record["record_hash"] == expected["record_hash"], name
        assert verify_session_evidence_record(record, fixture["did_documents"]), name


def test_every_extension_vector_validates_against_the_published_schema():
    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[3]
    schema = json.loads(
        (root / "spec" / "schemas" / "session-evidence-record.schema.json").read_text()
    )
    fixture = json.loads(
        (
            root / "spec" / "test-vectors" / "session-evidence-record-extensions.json"
        ).read_text()
    )
    validator = jsonschema.Draft202012Validator(schema)
    private_key = private_key_from_jwk(fixture["producer_private_jwk"])
    producer = fixture["producer"]

    for name, vector in fixture["vectors"].items():
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
        record = generate_session_evidence_record(
            session,
            producer_private_key=private_key,
            producer_did=producer["did"],
            producer_agent_id=producer["agent_id"],
            producer_verification_method=producer["verification_method"],
            observed_acts=vector["observed_acts"],
            **vector["options"],
        )

        assert list(validator.iter_errors(record)) == [], name


def test_the_schema_rejects_what_the_verifier_rejects():
    """The schema is not merely permissive: it refuses the same shapes.

    The healthy record goes first. A schema that rejected everything would make
    every refusal below look like a passing guard.
    """
    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[3]
    schema = json.loads(
        (root / "spec" / "schemas" / "session-evidence-record.schema.json").read_text()
    )
    validator = jsonschema.Draft202012Validator(schema)
    healthy, _ = _priced_record()
    assert list(validator.iter_errors(healthy)) == []

    hybrid_party = copy.deepcopy(healthy)
    hybrid_party["parties"]["responder"] = {
        "organization_name": "Northwind Supply",
        "did": RESPONDER_DID,
        "agent_id": "seller-agent",
        "verification_method": RESPONDER_VM,
        "mandate_type": "declared",
        "identity_source": "supplier_ordering_portal",
    }

    positive_marker = copy.deepcopy(healthy)
    positive_marker["parties"]["responder"] = {
        "identity_source": "supplier_ordering_portal",
        "did_declared": True,
        "a2cn_endpoint_declared": False,
        "mandate_declared": False,
    }

    float_amount = copy.deepcopy(healthy)
    float_amount["acts"][1]["money_basis"]["raw_amounts"] = [70000.00, 25000.00]

    bare_extension = copy.deepcopy(healthy)
    bare_extension["extensions"] = {"requisition_id": "REQ-42"}

    for name, record in (
        ("a party may not be both DID-bearing and identity-light", hybrid_party),
        ("did_declared: true contradicts the descriptor", positive_marker),
        ("raw amounts may not be JSON floats", float_amount),
        ("extensions keys must be namespaced", bare_extension),
    ):
        assert list(validator.iter_errors(record)) != [], name


def test_the_pre_extension_parity_record_still_validates_against_the_schema():
    """The additive claim, checked against a record built before these changes."""
    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[3]
    schema = json.loads(
        (root / "spec" / "schemas" / "session-evidence-record.schema.json").read_text()
    )
    fixture = json.loads(
        (
            root / "spec" / "test-vectors" / "session-evidence-record-parity.json"
        ).read_text()
    )
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
    record = generate_session_evidence_record(
        session,
        producer_private_key=private_key_from_jwk(fixture["producer_private_jwk"]),
        producer_did=fixture["producer"]["did"],
        producer_agent_id=fixture["producer"]["agent_id"],
        producer_verification_method=fixture["producer"]["verification_method"],
        observed_acts=fixture["observed_acts"],
    )

    assert record["record_hash"] == fixture["expected"]["record_hash"]
    assert list(jsonschema.Draft202012Validator(schema).iter_errors(record)) == []
