"""
Tests for post-commitment lifecycle endpoints:
  POST /sessions/{id}/delivery-notice
  POST /sessions/{id}/delivery-acknowledged
  POST /sessions/{id}/dispute-notice
  POST /sessions/{id}/dispute-resolved

Also covers message dataclass instantiation and JSON schema validation.
"""

from __future__ import annotations

import json
import uuid
import pytest

from a2cn.crypto import hash_object
from a2cn.messages import (
    DeliveryNoticeMessage,
    DeliveryAcknowledgedMessage,
    DisputeNoticeMessage,
    DisputeResolvedMessage,
)
from tests.conftest import make_session_init, INITIATOR_DID, RESPONDER_DID

A2CN_CT = "application/a2cn+json"


def _h(message_id: str) -> dict:
    return {"Content-Type": A2CN_CT, "Idempotency-Key": message_id}


# ---------------------------------------------------------------------------
# Helpers — complete a session end-to-end via HTTP
# ---------------------------------------------------------------------------

async def _create_session(client) -> str:
    body = make_session_init()
    r = await client.post("/sessions", json=body, headers=_h(body["message_id"]))
    assert r.status_code == 201
    return r.json()["session_id"]


def _delivery_notice_body(session_id: str, record_hash: str, msg_id: str | None = None) -> dict:
    mid = msg_id or str(uuid.uuid4())
    return {
        "message_type": "DELIVERY_NOTICE",
        "message_id": mid,
        "session_id": session_id,
        "transaction_record_hash": record_hash,
        "delivery_timestamp": "2026-04-02T08:00:00Z",
        "delivery_reference": "TRK-001",
    }


def _delivery_ack_body(session_id: str, record_hash: str,
                       notice_id: str, accepted: bool,
                       msg_id: str | None = None) -> dict:
    mid = msg_id or str(uuid.uuid4())
    return {
        "message_type": "DELIVERY_ACKNOWLEDGED",
        "message_id": mid,
        "session_id": session_id,
        "transaction_record_hash": record_hash,
        "delivery_notice_message_id": notice_id,
        "acknowledgment_timestamp": "2026-04-03T09:00:00Z",
        "accepted": accepted,
    }


def _dispute_notice_body(session_id: str, record_hash: str, msg_id: str | None = None) -> dict:
    mid = msg_id or str(uuid.uuid4())
    return {
        "message_type": "DISPUTE_NOTICE",
        "message_id": mid,
        "session_id": session_id,
        "transaction_record_hash": record_hash,
        "raised_by": "buyer",
        "dispute_type": "non_delivery",
        "description": "Goods not received after 30 days.",
        "dispute_timestamp": "2026-04-05T10:00:00Z",
    }


# ---------------------------------------------------------------------------
# DeliveryNoticeMessage dataclass
# ---------------------------------------------------------------------------

class TestDeliveryNoticeDataclass:
    def test_instantiation_with_required_fields(self):
        msg = DeliveryNoticeMessage(
            message_id="msg-1",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            delivery_timestamp="2026-04-02T08:00:00Z",
        )
        assert msg.message_type == "DELIVERY_NOTICE"
        assert msg.protocol_version == "0.2"
        assert msg.delivery_reference is None

    def test_to_dict_omits_none_fields(self):
        msg = DeliveryNoticeMessage(
            message_id="msg-1",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            delivery_timestamp="2026-04-02T08:00:00Z",
        )
        d = msg.to_dict()
        assert "delivery_reference" not in d
        assert "notes" not in d
        assert d["message_type"] == "DELIVERY_NOTICE"

    def test_optional_fields_included_when_set(self):
        msg = DeliveryNoticeMessage(
            message_id="msg-1",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            delivery_timestamp="2026-04-02T08:00:00Z",
            delivery_reference="TRK-999",
            notes="Handle with care",
        )
        d = msg.to_dict()
        assert d["delivery_reference"] == "TRK-999"
        assert d["notes"] == "Handle with care"


# ---------------------------------------------------------------------------
# DeliveryAcknowledgedMessage dataclass
# ---------------------------------------------------------------------------

class TestDeliveryAcknowledgedDataclass:
    def test_instantiation_with_required_fields(self):
        msg = DeliveryAcknowledgedMessage(
            message_id="msg-2",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            delivery_notice_message_id="msg-1",
            acknowledgment_timestamp="2026-04-03T09:00:00Z",
            accepted=True,
        )
        assert msg.message_type == "DELIVERY_ACKNOWLEDGED"
        assert msg.accepted is True
        assert msg.notes is None

    def test_accepted_false_included_in_dict(self):
        msg = DeliveryAcknowledgedMessage(
            message_id="msg-2",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            delivery_notice_message_id="msg-1",
            acknowledgment_timestamp="2026-04-03T09:00:00Z",
            accepted=False,
        )
        d = msg.to_dict()
        assert d["accepted"] is False


# ---------------------------------------------------------------------------
# DisputeNoticeMessage dataclass
# ---------------------------------------------------------------------------

class TestDisputeNoticeDataclass:
    def test_instantiation_with_required_fields(self):
        msg = DisputeNoticeMessage(
            message_id="msg-3",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            raised_by="buyer",
            dispute_type="non_delivery",
            description="Goods not received.",
        )
        assert msg.message_type == "DISPUTE_NOTICE"
        assert msg.evidence_references == []
        assert msg.resolution_requested is None
        assert msg.dispute_timestamp is not None

    def test_dispute_timestamp_auto_set(self):
        msg = DisputeNoticeMessage(
            message_id="msg-3",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            raised_by="seller",
            dispute_type="payment_failure",
            description="Payment overdue.",
        )
        assert msg.dispute_timestamp is not None
        assert "T" in msg.dispute_timestamp  # ISO 8601 format

    def test_explicit_dispute_timestamp_preserved(self):
        msg = DisputeNoticeMessage(
            message_id="msg-3",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            raised_by="buyer",
            dispute_type="quality",
            description="Quality issue.",
            dispute_timestamp="2026-04-05T10:00:00Z",
        )
        assert msg.dispute_timestamp == "2026-04-05T10:00:00Z"

    def test_evidence_references_default_empty_list(self):
        msg = DisputeNoticeMessage(
            message_id="msg-3",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            raised_by="buyer",
            dispute_type="other",
            description="Other issue.",
        )
        assert msg.evidence_references == []

    def test_to_dict_includes_evidence_references(self):
        msg = DisputeNoticeMessage(
            message_id="msg-3",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            raised_by="buyer",
            dispute_type="non_delivery",
            description="Dispute.",
            evidence_references=["hash:abc123", "https://evidence.example/doc1"],
        )
        d = msg.to_dict()
        assert d["evidence_references"] == ["hash:abc123", "https://evidence.example/doc1"]


# ---------------------------------------------------------------------------
# JSON schema validation
# ---------------------------------------------------------------------------

class TestJsonSchemaValidation:
    def test_delivery_notice_schema_valid(self):
        import json
        import pathlib
        schema_path = pathlib.Path(__file__).parents[3] / "spec" / "schemas" / "delivery_notice.schema.json"
        schema = json.loads(schema_path.read_text())
        assert schema["properties"]["message_type"]["const"] == "DELIVERY_NOTICE"
        assert "transaction_record_hash" in schema["required"]
        assert schema["additionalProperties"] is False

    def test_delivery_acknowledged_schema_valid(self):
        import json
        import pathlib
        schema_path = pathlib.Path(__file__).parents[3] / "spec" / "schemas" / "delivery_acknowledged.schema.json"
        schema = json.loads(schema_path.read_text())
        assert schema["properties"]["message_type"]["const"] == "DELIVERY_ACKNOWLEDGED"
        assert "accepted" in schema["required"]
        assert schema["additionalProperties"] is False

    def test_dispute_notice_schema_valid(self):
        import json
        import pathlib
        schema_path = pathlib.Path(__file__).parents[3] / "spec" / "schemas" / "dispute_notice.schema.json"
        schema = json.loads(schema_path.read_text())
        assert schema["properties"]["message_type"]["const"] == "DISPUTE_NOTICE"
        assert "raised_by" in schema["required"]
        assert "dispute_type" in schema["required"]
        valid_types = schema["properties"]["dispute_type"]["enum"]
        assert "non_delivery" in valid_types
        assert "payment_failure" in valid_types
        assert schema["additionalProperties"] is False


# ---------------------------------------------------------------------------
# Server endpoint tests: DELIVERY_NOTICE
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDeliveryNoticeEndpoint:
    async def test_valid_delivery_notice_accepted(self, test_client, responder_test_client):
        session_id, record_hash = await _complete_session(test_client, responder_test_client)
        body = _delivery_notice_body(session_id, record_hash)
        r = await test_client.post(
            f"/sessions/{session_id}/delivery-notice", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "DELIVERY_NOTICE_RECORDED"
        assert data["session_id"] == session_id
        assert "delivery_notice_message_id" in data

    async def test_delivery_notice_rejected_if_not_completed(self, test_client):
        session_id = await _create_session(test_client)
        body = _delivery_notice_body(session_id, "a" * 64)
        r = await test_client.post(
            f"/sessions/{session_id}/delivery-notice", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "SESSION_WRONG_STATE"

    async def test_delivery_notice_rejected_if_hash_mismatch(self, test_client, responder_test_client):
        session_id, _ = await _complete_session(test_client, responder_test_client)
        bad_hash = "b" * 64  # wrong hash
        body = _delivery_notice_body(session_id, bad_hash)
        r = await test_client.post(
            f"/sessions/{session_id}/delivery-notice", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "INVALID_RECORD_HASH"


# ---------------------------------------------------------------------------
# Server endpoint tests: DELIVERY_ACKNOWLEDGED
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDeliveryAcknowledgedEndpoint:
    async def _setup(self, test_client, responder_test_client):
        """Complete a session and record a delivery notice. Returns (session_id, record_hash, notice_id)."""
        session_id, record_hash = await _complete_session(test_client, responder_test_client)
        notice_body = _delivery_notice_body(session_id, record_hash)
        r = await test_client.post(
            f"/sessions/{session_id}/delivery-notice",
            json=notice_body,
            headers=_h(notice_body["message_id"]),
        )
        assert r.status_code == 200
        notice_id = r.json()["delivery_notice_message_id"]
        return session_id, record_hash, notice_id

    async def test_valid_delivery_acknowledged_accepted(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await self._setup(test_client, responder_test_client)
        body = _delivery_ack_body(session_id, record_hash, notice_id, accepted=True)
        r = await test_client.post(
            f"/sessions/{session_id}/delivery-acknowledged", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 200
        data = r.json()
        assert data["post_commitment_status"] == "CLOSED"

    async def test_accepted_true_sets_closed(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await self._setup(test_client, responder_test_client)
        body = _delivery_ack_body(session_id, record_hash, notice_id, accepted=True)
        r = await test_client.post(
            f"/sessions/{session_id}/delivery-acknowledged", json=body, headers=_h(body["message_id"])
        )
        assert r.json()["post_commitment_status"] == "CLOSED"

    async def test_accepted_false_sets_disputed(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await self._setup(test_client, responder_test_client)
        body = _delivery_ack_body(session_id, record_hash, notice_id, accepted=False)
        r = await test_client.post(
            f"/sessions/{session_id}/delivery-acknowledged", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 200
        assert r.json()["post_commitment_status"] == "DISPUTED"

    async def test_rejected_if_no_delivery_notice(self, test_client, responder_test_client):
        session_id, record_hash = await _complete_session(test_client, responder_test_client)
        body = _delivery_ack_body(session_id, record_hash, "nonexistent-notice-id", accepted=True)
        r = await test_client.post(
            f"/sessions/{session_id}/delivery-acknowledged", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "NO_DELIVERY_NOTICE"


# ---------------------------------------------------------------------------
# Server endpoint tests: DISPUTE_NOTICE
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDisputeNoticeEndpoint:
    async def test_valid_dispute_notice_accepted(self, test_client, responder_test_client):
        session_id, record_hash = await _complete_session(test_client, responder_test_client)
        body = _dispute_notice_body(session_id, record_hash)
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-notice", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 200
        data = r.json()
        assert data["post_commitment_status"] == "DISPUTED"
        assert data["session_id"] == session_id
        assert "dispute_notice_message_id" in data

    async def test_dispute_sets_post_commitment_status_to_disputed(self, test_client, responder_test_client):
        session_id, record_hash = await _complete_session(test_client, responder_test_client)
        body = _dispute_notice_body(session_id, record_hash)
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-notice", json=body, headers=_h(body["message_id"])
        )
        assert r.json()["post_commitment_status"] == "DISPUTED"

    async def test_dispute_stores_raised_by_and_dispute_type(self, test_client, responder_test_client):
        session_id, record_hash = await _complete_session(test_client, responder_test_client)
        body = _dispute_notice_body(session_id, record_hash)
        body["raised_by"] = "seller"
        body["dispute_type"] = "payment_failure"
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-notice", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 200

    async def test_dispute_rejected_if_not_completed(self, test_client):
        session_id = await _create_session(test_client)
        body = _dispute_notice_body(session_id, "a" * 64)
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-notice", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "SESSION_WRONG_STATE"

    async def test_dispute_note_references_meeting_place(self, test_client, responder_test_client):
        session_id, record_hash = await _complete_session(test_client, responder_test_client)
        body = _dispute_notice_body(session_id, record_hash)
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-notice", json=body, headers=_h(body["message_id"])
        )
        assert "Meeting Place" in r.json()["note"]


# ---------------------------------------------------------------------------
# Helpers — complete a session with two clients (avoids SENDER_DID_MISMATCH)
# ---------------------------------------------------------------------------

async def _complete_session(
    initiator_client, responder_client
) -> tuple[str, str]:
    """Complete a session using the correct JWT for each party. Returns (session_id, record_hash)."""
    session_id = await _create_session(initiator_client)

    timestamp = "2026-04-01T10:00:00Z"
    expires_at = "2030-01-01T00:00:00Z"
    terms = {"total_value": 10_000_000, "currency": "USD", "seat_count": 50}
    offer_id = str(uuid.uuid4())
    protocol_act = {
        "protocol_version": "0.2",
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 1,
        "message_type": "offer",
        "sender_did": INITIATOR_DID,
        "timestamp": timestamp,
        "expires_at": expires_at,
        "terms": terms,
    }
    pah = hash_object(protocol_act)
    offer = {
        "message_type": "offer",
        "message_id": offer_id,
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 1,
        "sender_did": INITIATOR_DID,
        "sender_agent_id": "test-agent",
        "sender_verification_method": f"{INITIATOR_DID}#key-1",
        "timestamp": timestamp,
        "expires_at": expires_at,
        "terms": terms,
        "protocol_act_hash": pah,
        "protocol_act_signature": "eyJ...",
    }
    r = await initiator_client.post(
        f"/sessions/{session_id}/messages", json=offer, headers=_h(offer_id)
    )
    assert r.status_code == 200, r.text

    acc_id = str(uuid.uuid4())
    acceptance = {
        "message_type": "acceptance",
        "message_id": acc_id,
        "session_id": session_id,
        "in_reply_to": offer_id,
        "round_number": 1,
        "sequence_number": 2,
        "accepted_offer_id": offer_id,
        "accepted_protocol_act_hash": pah,
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "test-agent",
        "sender_verification_method": f"{RESPONDER_DID}#key-2026-01",
        "timestamp": "2026-04-01T10:01:00Z",
        "acceptance_signature": "eyJ...",
    }
    r = await responder_client.post(
        f"/sessions/{session_id}/messages", json=acceptance, headers=_h(acc_id)
    )
    assert r.status_code == 200, r.text

    r = await initiator_client.get(f"/sessions/{session_id}/record")
    assert r.status_code == 200, r.text
    record_hash = r.json()["record_hash"]
    return session_id, record_hash


async def _setup_disputed_session(
    initiator_client, responder_client
) -> tuple[str, str, str]:
    """Complete a session and open a DISPUTE_NOTICE. Returns (session_id, record_hash, dispute_notice_id)."""
    session_id, record_hash = await _complete_session(initiator_client, responder_client)
    body = _dispute_notice_body(session_id, record_hash)
    r = await initiator_client.post(
        f"/sessions/{session_id}/dispute-notice", json=body, headers=_h(body["message_id"])
    )
    assert r.status_code == 200, r.text
    dispute_notice_id = r.json()["dispute_notice_message_id"]
    return session_id, record_hash, dispute_notice_id


def _dispute_resolved_body(
    session_id: str,
    record_hash: str,
    dispute_notice_id: str,
    outcome: str = "buyer_prevails",
    msg_id: str | None = None,
) -> dict:
    mid = msg_id or str(uuid.uuid4())
    return {
        "message_type": "DISPUTE_RESOLVED",
        "message_id": mid,
        "session_id": session_id,
        "transaction_record_hash": record_hash,
        "dispute_notice_message_id": dispute_notice_id,
        "resolution_outcome": outcome,
        "resolver_did": "did:web:resolver.neutral.example",
        "resolution_timestamp": "2026-04-10T12:00:00Z",
    }


# ---------------------------------------------------------------------------
# DisputeResolvedMessage dataclass
# ---------------------------------------------------------------------------

class TestDisputeResolvedDataclass:
    def test_instantiation_with_required_fields(self):
        msg = DisputeResolvedMessage(
            message_id="msg-4",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            dispute_notice_message_id="msg-3",
            resolution_outcome="buyer_prevails",
            resolver_did="did:web:resolver.example",
        )
        assert msg.message_type == "DISPUTE_RESOLVED"
        assert msg.protocol_version == "0.2"
        assert msg.evidence_references == []
        assert msg.resolution_notes is None

    def test_resolution_timestamp_auto_set_on_creation(self):
        msg = DisputeResolvedMessage(
            message_id="msg-4",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            dispute_notice_message_id="msg-3",
            resolution_outcome="seller_prevails",
            resolver_did="did:web:resolver.example",
        )
        assert msg.resolution_timestamp is not None
        assert "T" in msg.resolution_timestamp  # ISO 8601 format

    def test_explicit_resolution_timestamp_preserved(self):
        msg = DisputeResolvedMessage(
            message_id="msg-4",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            dispute_notice_message_id="msg-3",
            resolution_outcome="mutual_settlement",
            resolver_did="did:web:resolver.example",
            resolution_timestamp="2026-04-10T12:00:00Z",
        )
        assert msg.resolution_timestamp == "2026-04-10T12:00:00Z"

    def test_evidence_references_default_empty_list(self):
        msg = DisputeResolvedMessage(
            message_id="msg-4",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            dispute_notice_message_id="msg-3",
            resolution_outcome="buyer_prevails",
            resolver_did="did:web:resolver.example",
        )
        assert msg.evidence_references == []

    def test_to_dict_includes_resolution_outcome(self):
        msg = DisputeResolvedMessage(
            message_id="msg-4",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            dispute_notice_message_id="msg-3",
            resolution_outcome="mutual_settlement",
            resolver_did="did:web:resolver.example",
            resolution_timestamp="2026-04-10T12:00:00Z",
        )
        d = msg.to_dict()
        assert d["resolution_outcome"] == "mutual_settlement"
        assert d["resolver_did"] == "did:web:resolver.example"
        assert d["dispute_notice_message_id"] == "msg-3"
        assert d["message_type"] == "DISPUTE_RESOLVED"

    def test_to_dict_omits_none_resolution_notes(self):
        msg = DisputeResolvedMessage(
            message_id="msg-4",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            dispute_notice_message_id="msg-3",
            resolution_outcome="buyer_prevails",
            resolver_did="did:web:resolver.example",
            resolution_timestamp="2026-04-10T12:00:00Z",
        )
        d = msg.to_dict()
        assert "resolution_notes" not in d

    def test_to_dict_includes_evidence_references_when_set(self):
        msg = DisputeResolvedMessage(
            message_id="msg-4",
            session_id="sess-1",
            transaction_record_hash="a" * 64,
            dispute_notice_message_id="msg-3",
            resolution_outcome="seller_prevails",
            resolver_did="did:web:resolver.example",
            resolution_timestamp="2026-04-10T12:00:00Z",
            evidence_references=["hash:abc123", "https://evidence.example/ruling"],
        )
        d = msg.to_dict()
        assert d["evidence_references"] == ["hash:abc123", "https://evidence.example/ruling"]


# ---------------------------------------------------------------------------
# JSON schema validation — DisputeResolvedMessage
# ---------------------------------------------------------------------------

class TestDisputeResolvedSchema:
    def test_dispute_resolved_schema_valid(self):
        import pathlib
        schema_path = pathlib.Path(__file__).parents[3] / "spec" / "schemas" / "dispute_resolved.schema.json"
        schema = json.loads(schema_path.read_text())
        assert schema["properties"]["message_type"]["const"] == "DISPUTE_RESOLVED"
        assert "transaction_record_hash" in schema["required"]
        assert "dispute_notice_message_id" in schema["required"]
        assert "resolver_did" in schema["required"]
        assert "resolution_timestamp" in schema["required"]
        outcomes = schema["properties"]["resolution_outcome"]["enum"]
        assert "buyer_prevails" in outcomes
        assert "seller_prevails" in outcomes
        assert "mutual_settlement" in outcomes
        assert schema["additionalProperties"] is False


# ---------------------------------------------------------------------------
# Server endpoint tests: DISPUTE_RESOLVED
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDisputeResolvedEndpoint:
    async def test_valid_dispute_resolved_accepted(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id)
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 200
        data = r.json()
        assert data["post_commitment_status"] == "RESOLVED"
        assert data["session_id"] == session_id
        assert "dispute_resolved_message_id" in data

    async def test_dispute_resolved_rejected_if_not_in_disputed_status(
        self, test_client, responder_test_client
    ):
        session_id, record_hash = await _complete_session(test_client, responder_test_client)
        body = _dispute_resolved_body(session_id, record_hash, "nonexistent-notice-id")
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "NOT_IN_DISPUTED_STATUS"

    async def test_dispute_resolved_rejected_if_notice_id_mismatch(
        self, test_client, responder_test_client
    ):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, "wrong-notice-id")
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "INVALID_REFERENCE"

    async def test_dispute_resolved_rejected_if_hash_mismatch(
        self, test_client, responder_test_client
    ):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, "b" * 64, notice_id)
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "INVALID_RECORD_HASH"

    async def test_buyer_prevails_outcome_stored(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id, outcome="buyer_prevails")
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 200
        assert r.json()["resolution_outcome"] == "buyer_prevails"

    async def test_seller_prevails_outcome_stored(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id, outcome="seller_prevails")
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 200
        assert r.json()["resolution_outcome"] == "seller_prevails"

    async def test_mutual_settlement_outcome_stored(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id, outcome="mutual_settlement")
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 200
        assert r.json()["resolution_outcome"] == "mutual_settlement"

    async def test_post_commitment_status_set_to_resolved(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id)
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.json()["post_commitment_status"] == "RESOLVED"

    async def test_not_in_disputed_status_error_includes_spec_ref(
        self, test_client, responder_test_client
    ):
        session_id, record_hash = await _complete_session(test_client, responder_test_client)
        body = _dispute_resolved_body(session_id, record_hash, "irrelevant-notice-id")
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 400
        error = r.json()["error"]
        assert error["code"] == "NOT_IN_DISPUTED_STATUS"
        assert error["spec_ref"] == "Section 11"

    async def test_invalid_resolution_outcome_rejected(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id, outcome="everyone_wins")
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "INVALID_RESOLUTION_OUTCOME"

    async def test_missing_resolution_outcome_rejected(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id)
        del body["resolution_outcome"]
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "INVALID_RESOLUTION_OUTCOME"

    async def test_missing_resolver_did_rejected(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id)
        del body["resolver_did"]
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "MISSING_REQUIRED_FIELD"

    async def test_missing_resolution_timestamp_rejected(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id)
        del body["resolution_timestamp"]
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "MISSING_REQUIRED_FIELD"

    async def test_wrong_message_type_rejected(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id)
        body["message_type"] = "DISPUTE_NOTICE"
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "WRONG_MESSAGE_TYPE"

    async def test_missing_message_type_rejected(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id)
        del body["message_type"]
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "WRONG_MESSAGE_TYPE"

    async def test_non_string_resolution_outcome_rejected(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id)
        body["resolution_outcome"] = ["buyer_prevails"]  # array instead of string
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "INVALID_RESOLUTION_OUTCOME"

    async def test_non_string_resolver_did_rejected(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id)
        body["resolver_did"] = 12345  # integer instead of string
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "MISSING_REQUIRED_FIELD"

    async def test_non_string_resolution_timestamp_rejected(self, test_client, responder_test_client):
        session_id, record_hash, notice_id = await _setup_disputed_session(
            test_client, responder_test_client
        )
        body = _dispute_resolved_body(session_id, record_hash, notice_id)
        body["resolution_timestamp"] = {"ts": "2026-04-10"}  # object instead of string
        r = await test_client.post(
            f"/sessions/{session_id}/dispute-resolved", json=body, headers=_h(body["message_id"])
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "MISSING_REQUIRED_FIELD"
