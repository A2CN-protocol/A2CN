"""Tests for a2cn.messages — wire format serialization."""

import pytest
from a2cn.messages import (
    SessionParams,
    AgentInfo,
    DeclaredMandate,
    TermsObject,
    SessionInit,
    SessionAck,
    SessionReject,
    Offer,
    Acceptance,
    Rejection,
    Withdrawal,
)


def make_session_params():
    return SessionParams(
        deal_type="saas_renewal",
        currency="USD",
        subject="Test",
        max_rounds=4,
        session_timeout_seconds=3600,
        round_timeout_seconds=900,
        subject_reference="REF-001",
        estimated_value=12_000_000,
    )


def make_agent_info(did="did:web:example.com"):
    return AgentInfo(
        organization_name="Test Org",
        did=did,
        verification_method=f"{did}#key-1",
        agent_id="agent-001",
        endpoint="https://example.com/api/a2cn",
    )


def make_mandate():
    return DeclaredMandate(
        mandate_type="declared",
        agent_id="agent-001",
        principal_organization="Test Org",
        principal_did="did:web:example.com",
        authorized_deal_types=["saas_renewal"],
        max_commitment_value=15_000_000,
        max_commitment_currency="USD",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T00:00:00Z",
    )


def make_terms():
    return TermsObject(
        total_value=9_500_000,
        currency="USD",
        payment_terms={"net_days": 30},
    )


# ---------------------------------------------------------------------------
# Field names match wire format exactly
# ---------------------------------------------------------------------------

def test_session_params_field_names():
    sp = make_session_params()
    d = sp.to_dict()
    assert "deal_type" in d
    assert "session_timeout_seconds" in d
    assert "round_timeout_seconds" in d
    assert "subject_reference" in d


def test_agent_info_field_names():
    ai = make_agent_info()
    d = ai.to_dict()
    assert "organization_name" in d
    assert "verification_method" in d
    assert "agent_id" in d


def test_declared_mandate_field_names():
    m = make_mandate()
    d = m.to_dict()
    assert d["mandate_type"] == "declared"
    assert "authorized_deal_types" in d
    assert "max_commitment_value" in d
    assert "valid_until" in d


def test_offer_field_names():
    offer = Offer(
        message_type="offer",
        message_id="msg-1",
        session_id="sess-1",
        round_number=1,
        sequence_number=1,
        sender_did="did:web:buyer.example",
        sender_agent_id="agent-001",
        sender_verification_method="did:web:buyer.example#key-1",
        timestamp="2026-03-24T10:00:00Z",
        expires_at="2026-03-24T10:15:00Z",
        terms=make_terms(),
        protocol_act_hash="sha256-abc",
        protocol_act_signature="eyJ...",
    )
    d = offer.to_dict()
    assert d["message_type"] == "offer"
    assert "sender_did" in d
    assert "sender_agent_id" in d
    assert "sender_verification_method" in d
    assert "protocol_act_hash" in d
    assert "protocol_act_signature" in d
    # in_reply_to absent in round 1
    assert "in_reply_to" not in d


def test_offer_round2_has_in_reply_to():
    offer = Offer(
        message_type="counteroffer",
        message_id="msg-2",
        session_id="sess-1",
        round_number=2,
        sequence_number=2,
        sender_did="did:web:seller.example",
        sender_agent_id="agent-002",
        sender_verification_method="did:web:seller.example#key-1",
        timestamp="2026-03-24T10:02:00Z",
        expires_at="2026-03-24T10:17:00Z",
        terms=make_terms(),
        protocol_act_hash="sha256-def",
        protocol_act_signature="eyJ...",
        in_reply_to="msg-1",
    )
    d = offer.to_dict()
    assert d["message_type"] == "counteroffer"
    assert d["in_reply_to"] == "msg-1"


def test_offer_protocol_act_object_fields():
    offer = Offer(
        message_type="offer",
        message_id="msg-1",
        session_id="sess-1",
        round_number=1,
        sequence_number=1,
        sender_did="did:web:buyer.example",
        sender_agent_id="agent-001",
        sender_verification_method="did:web:buyer.example#key-1",
        timestamp="2026-03-24T10:00:00Z",
        expires_at="2026-03-24T10:15:00Z",
        terms=make_terms(),
        protocol_act_hash="sha256-abc",
        protocol_act_signature="eyJ...",
    )
    act = offer.protocol_act_object()
    assert set(act.keys()) == {
        "protocol_version", "session_id", "round_number", "sequence_number",
        "message_type", "sender_did", "timestamp", "expires_at", "terms",
    }


def test_acceptance_field_names():
    acc = Acceptance(
        message_type="acceptance",
        message_id="msg-3",
        session_id="sess-1",
        in_reply_to="msg-2",
        round_number=2,
        sequence_number=3,
        accepted_offer_id="msg-2",
        accepted_protocol_act_hash="sha256-def",
        sender_did="did:web:buyer.example",
        sender_agent_id="agent-001",
        sender_verification_method="did:web:buyer.example#key-1",
        timestamp="2026-03-24T10:05:00Z",
        acceptance_signature="eyJ...",
    )
    d = acc.to_dict()
    assert "accepted_offer_id" in d
    assert "accepted_protocol_act_hash" in d
    assert "acceptance_signature" in d


def test_acceptance_payload():
    acc = Acceptance(
        message_type="acceptance",
        message_id="msg-3",
        session_id="sess-1",
        in_reply_to="msg-2",
        round_number=2,
        sequence_number=3,
        accepted_offer_id="msg-2",
        accepted_protocol_act_hash="sha256-def",
        sender_did="did:web:buyer.example",
        sender_agent_id="agent-001",
        sender_verification_method="did:web:buyer.example#key-1",
        timestamp="2026-03-24T10:05:00Z",
        acceptance_signature="eyJ...",
    )
    payload = acc.acceptance_payload()
    assert set(payload.keys()) == {
        "session_id", "round_number", "sequence_number",
        "accepted_offer_id", "accepted_protocol_act_hash",
    }


def test_none_fields_omitted():
    sp = SessionParams(
        deal_type="saas_renewal",
        currency="USD",
        subject="Test",
        max_rounds=4,
        session_timeout_seconds=3600,
        round_timeout_seconds=900,
        # subject_reference and estimated_value left None
    )
    d = sp.to_dict()
    assert "subject_reference" not in d
    assert "estimated_value" not in d
