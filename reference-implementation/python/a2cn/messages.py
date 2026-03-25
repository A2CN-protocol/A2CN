"""
A2CN Message Dataclasses

All field names match the wire format exactly (Section 6–7 of the spec).
Every dataclass has a to_dict() method that serializes to wire format,
omitting None fields (optional fields that were not set).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


def _drop_none(d: dict) -> dict:
    """Recursively remove None values from a dict."""
    result = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, dict):
            result[k] = _drop_none(v)
        elif isinstance(v, list):
            result[k] = [_drop_none(i) if isinstance(i, dict) else i for i in v]
        else:
            result[k] = v
    return result


# ---------------------------------------------------------------------------
# Sub-objects
# ---------------------------------------------------------------------------

@dataclass
class SessionParams:
    deal_type: str
    currency: str
    subject: str
    max_rounds: int
    session_timeout_seconds: int
    round_timeout_seconds: int
    subject_reference: str | None = None
    estimated_value: int | None = None

    def to_dict(self) -> dict:
        return _drop_none({
            "deal_type": self.deal_type,
            "currency": self.currency,
            "subject": self.subject,
            "subject_reference": self.subject_reference,
            "estimated_value": self.estimated_value,
            "max_rounds": self.max_rounds,
            "session_timeout_seconds": self.session_timeout_seconds,
            "round_timeout_seconds": self.round_timeout_seconds,
        })


@dataclass
class AgentInfo:
    organization_name: str
    did: str
    verification_method: str
    agent_id: str
    endpoint: str

    def to_dict(self) -> dict:
        return {
            "organization_name": self.organization_name,
            "did": self.did,
            "verification_method": self.verification_method,
            "agent_id": self.agent_id,
            "endpoint": self.endpoint,
        }


@dataclass
class DeclaredMandate:
    mandate_type: str  # "declared"
    agent_id: str
    principal_organization: str
    principal_did: str
    authorized_deal_types: list[str]
    max_commitment_value: int
    max_commitment_currency: str
    valid_from: str
    valid_until: str
    scope_description: str | None = None

    def to_dict(self) -> dict:
        return _drop_none({
            "mandate_type": self.mandate_type,
            "agent_id": self.agent_id,
            "principal_organization": self.principal_organization,
            "principal_did": self.principal_did,
            "authorized_deal_types": self.authorized_deal_types,
            "max_commitment_value": self.max_commitment_value,
            "max_commitment_currency": self.max_commitment_currency,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "scope_description": self.scope_description,
        })


@dataclass
class TermsObject:
    total_value: int
    currency: str
    line_items: list[dict] | None = None
    payment_terms: dict | None = None
    delivery_terms: dict | None = None
    contract_duration: dict | None = None
    sla: dict | None = None
    custom_terms: dict | None = None

    def to_dict(self) -> dict:
        return _drop_none({
            "total_value": self.total_value,
            "currency": self.currency,
            "line_items": self.line_items,
            "payment_terms": self.payment_terms,
            "delivery_terms": self.delivery_terms,
            "contract_duration": self.contract_duration,
            "sla": self.sla,
            "custom_terms": self.custom_terms,
        })


# ---------------------------------------------------------------------------
# Session Initiation
# ---------------------------------------------------------------------------

@dataclass
class SessionInit:
    message_type: str  # "session_init"
    message_id: str
    protocol_version: str  # "0.1"
    session_params: SessionParams
    initiator: AgentInfo
    initiator_mandate: DeclaredMandate | dict
    metadata: dict | None = None

    def to_dict(self) -> dict:
        mandate = (
            self.initiator_mandate.to_dict()
            if hasattr(self.initiator_mandate, "to_dict")
            else self.initiator_mandate
        )
        return _drop_none({
            "message_type": self.message_type,
            "message_id": self.message_id,
            "protocol_version": self.protocol_version,
            "session_params": self.session_params.to_dict(),
            "initiator": self.initiator.to_dict(),
            "initiator_mandate": mandate,
            "metadata": self.metadata,
        })


@dataclass
class SessionAck:
    message_type: str  # "session_ack"
    message_id: str
    session_id: str
    in_reply_to: str
    protocol_version: str  # "0.1"
    session_params_accepted: dict
    responder: AgentInfo
    responder_mandate: DeclaredMandate | dict
    session_created_at: str
    current_turn: str  # "initiator"

    def to_dict(self) -> dict:
        mandate = (
            self.responder_mandate.to_dict()
            if hasattr(self.responder_mandate, "to_dict")
            else self.responder_mandate
        )
        return {
            "message_type": self.message_type,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "in_reply_to": self.in_reply_to,
            "protocol_version": self.protocol_version,
            "session_params_accepted": self.session_params_accepted,
            "responder": self.responder.to_dict(),
            "responder_mandate": mandate,
            "session_created_at": self.session_created_at,
            "current_turn": self.current_turn,
        }


@dataclass
class SessionReject:
    message_type: str  # "session_reject"
    message_id: str
    in_reply_to: str
    error_code: str
    error_message: str
    retry_after_seconds: int | None = None

    def to_dict(self) -> dict:
        return _drop_none({
            "message_type": self.message_type,
            "message_id": self.message_id,
            "in_reply_to": self.in_reply_to,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "retry_after_seconds": self.retry_after_seconds,
        })


# ---------------------------------------------------------------------------
# Offer Exchange
# ---------------------------------------------------------------------------

@dataclass
class Offer:
    """Covers both 'offer' (round 1) and 'counteroffer' (round 2+)."""
    message_type: str  # "offer" | "counteroffer"
    message_id: str
    session_id: str
    round_number: int
    sequence_number: int
    sender_did: str
    sender_agent_id: str
    sender_verification_method: str
    timestamp: str
    expires_at: str
    terms: TermsObject | dict
    protocol_act_hash: str
    protocol_act_signature: str
    in_reply_to: str | None = None  # absent in round 1

    def to_dict(self) -> dict:
        terms_dict = (
            self.terms.to_dict()
            if hasattr(self.terms, "to_dict")
            else self.terms
        )
        return _drop_none({
            "message_type": self.message_type,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "in_reply_to": self.in_reply_to,
            "round_number": self.round_number,
            "sequence_number": self.sequence_number,
            "sender_did": self.sender_did,
            "sender_agent_id": self.sender_agent_id,
            "sender_verification_method": self.sender_verification_method,
            "timestamp": self.timestamp,
            "expires_at": self.expires_at,
            "terms": terms_dict,
            "protocol_act_hash": self.protocol_act_hash,
            "protocol_act_signature": self.protocol_act_signature,
        })

    def protocol_act_object(self) -> dict:
        """Return the protocol act object used for signing (Section 7.3.1)."""
        terms_dict = (
            self.terms.to_dict()
            if hasattr(self.terms, "to_dict")
            else self.terms
        )
        return {
            "protocol_version": "0.1",
            "session_id": self.session_id,
            "round_number": self.round_number,
            "sequence_number": self.sequence_number,
            "message_type": self.message_type,
            "sender_did": self.sender_did,
            "timestamp": self.timestamp,
            "expires_at": self.expires_at,
            "terms": terms_dict,
        }


@dataclass
class Acceptance:
    message_type: str  # "acceptance"
    message_id: str
    session_id: str
    in_reply_to: str
    round_number: int
    sequence_number: int
    accepted_offer_id: str
    accepted_protocol_act_hash: str
    sender_did: str
    sender_agent_id: str
    sender_verification_method: str
    timestamp: str
    acceptance_signature: str

    def to_dict(self) -> dict:
        return {
            "message_type": self.message_type,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "in_reply_to": self.in_reply_to,
            "round_number": self.round_number,
            "sequence_number": self.sequence_number,
            "accepted_offer_id": self.accepted_offer_id,
            "accepted_protocol_act_hash": self.accepted_protocol_act_hash,
            "sender_did": self.sender_did,
            "sender_agent_id": self.sender_agent_id,
            "sender_verification_method": self.sender_verification_method,
            "timestamp": self.timestamp,
            "acceptance_signature": self.acceptance_signature,
        }

    def acceptance_payload(self) -> dict:
        """The object signed to produce acceptance_signature (Section 7.4)."""
        return {
            "session_id": self.session_id,
            "round_number": self.round_number,
            "sequence_number": self.sequence_number,
            "accepted_offer_id": self.accepted_offer_id,
            "accepted_protocol_act_hash": self.accepted_protocol_act_hash,
        }


@dataclass
class Rejection:
    message_type: str  # "rejection"
    message_id: str
    session_id: str
    in_reply_to: str
    round_number: int
    sequence_number: int
    rejected_offer_id: str
    sender_did: str
    sender_agent_id: str
    timestamp: str
    reason_code: str
    reason_description: str | None = None

    def to_dict(self) -> dict:
        return _drop_none({
            "message_type": self.message_type,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "in_reply_to": self.in_reply_to,
            "round_number": self.round_number,
            "sequence_number": self.sequence_number,
            "rejected_offer_id": self.rejected_offer_id,
            "sender_did": self.sender_did,
            "sender_agent_id": self.sender_agent_id,
            "timestamp": self.timestamp,
            "reason_code": self.reason_code,
            "reason_description": self.reason_description,
        })


@dataclass
class Withdrawal:
    message_type: str  # "withdrawal"
    message_id: str
    session_id: str
    sequence_number: int
    sender_did: str
    sender_agent_id: str
    timestamp: str
    reason_code: str
    in_reply_to: str | None = None
    reason_description: str | None = None

    def to_dict(self) -> dict:
        return _drop_none({
            "message_type": self.message_type,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "in_reply_to": self.in_reply_to,
            "sequence_number": self.sequence_number,
            "sender_did": self.sender_did,
            "sender_agent_id": self.sender_agent_id,
            "timestamp": self.timestamp,
            "reason_code": self.reason_code,
            "reason_description": self.reason_description,
        })
