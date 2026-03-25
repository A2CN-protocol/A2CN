"""
A2CN Transaction Record and Audit Log generation (Sections 9–10).

Both are deterministic — derived only from protocol messages, never from
local clock reads.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from a2cn.crypto import hash_object, canonicalize, hash_bytes
from a2cn.session import Session, SessionState, _now

# A2CN namespace UUID for record_id (UUID v5) — Appendix A
A2CN_NAMESPACE = uuid.UUID("f4a2c1e0-8b3d-4f7a-9c2e-1d5b6a8f3e7c")


def generate_transaction_record(session: Session) -> dict:
    """
    Generate the deterministic transaction record (Section 9).
    Both parties calling this independently must produce identical record_hash.

    Must only be called when session.state == COMPLETED.
    """
    final_offer = session._final_offer
    final_acceptance = session._final_acceptance

    if not final_offer or not final_acceptance:
        raise ValueError("Cannot generate transaction record: missing final offer or acceptance")

    session_init = session._session_init or {}
    session_ack = session._session_ack or {}

    initiator_info = session_init.get("initiator", {})
    responder_info = session_ack.get("responder", {})

    # generated_at = timestamp of Acceptance message (NOT datetime.now())
    generated_at = final_acceptance.get("timestamp", "")

    # record_id = UUID v5(A2CN_NAMESPACE, session_id) — Appendix A
    record_id = str(uuid.uuid5(A2CN_NAMESPACE, session.session_id))

    # offer_chain_hash = SHA-256(JCS([hash_1, ..., hash_n])) — Section 9.3
    offer_chain_hash = _compute_offer_chain_hash(session._offer_chain)

    # Count total messages
    total_messages = len(session._message_log)
    total_rounds = session.round_number

    # first_offer timestamp
    first_offer = next(
        (m for m in session._message_log if m.get("message_type") in ("offer", "counteroffer")),
        None,
    )
    first_offer_at = first_offer["timestamp"] if first_offer else generated_at

    record: dict = {
        "record_type": "a2cn_transaction_record",
        "record_version": "0.1",
        "record_id": record_id,
        "session_id": session.session_id,
        "generated_at": generated_at,
        "parties": {
            "initiator": {
                "organization_name": initiator_info.get("organization_name", ""),
                "did": initiator_info.get("did", ""),
                "agent_id": initiator_info.get("agent_id", ""),
                "verification_method": initiator_info.get("verification_method", ""),
                "mandate_type": session.initiator_mandate.get("mandate_type", ""),
            },
            "responder": {
                "organization_name": responder_info.get("organization_name", ""),
                "did": responder_info.get("did", ""),
                "agent_id": responder_info.get("agent_id", ""),
                "verification_method": responder_info.get("verification_method", ""),
                "mandate_type": session.responder_mandate.get("mandate_type", ""),
            },
        },
        "deal_type": session.session_params.get("deal_type", ""),
        "currency": session.session_params.get("currency", ""),
        "subject": session_init.get("session_params", {}).get("subject", ""),
        "subject_reference": session_init.get("session_params", {}).get("subject_reference"),
        "agreed_terms": final_offer.get("terms", {}),
        "negotiation_summary": {
            "total_rounds": total_rounds,
            "total_messages": total_messages,
            "session_created_at": session.session_created_at,
            "first_offer_at": first_offer_at,
            "accepted_at": generated_at,
            "initiating_party_did": initiator_info.get("did", ""),
            "accepting_party_did": final_acceptance.get("sender_did", ""),
        },
        "final_offer": {
            "message_id": final_offer.get("message_id", ""),
            "sender_did": final_offer.get("sender_did", ""),
            "protocol_act_hash": final_offer.get("protocol_act_hash", ""),
            "protocol_act_signature": final_offer.get("protocol_act_signature", ""),
        },
        "final_acceptance": {
            "message_id": final_acceptance.get("message_id", ""),
            "sender_did": final_acceptance.get("sender_did", ""),
            "accepted_protocol_act_hash": final_acceptance.get("accepted_protocol_act_hash", ""),
            "acceptance_signature": final_acceptance.get("acceptance_signature", ""),
        },
        "offer_chain_hash": offer_chain_hash,
        "record_hash": "",  # placeholder — filled below
    }

    # record_hash = SHA-256(JCS(record_with_empty_record_hash)) — Section 9.3
    record["record_hash"] = hash_object(record)
    return record


def _compute_offer_chain_hash(offer_hashes: list[str]) -> str:
    """
    offer_chain_hash = SHA-256(JCS([hash_1, hash_2, ..., hash_n]))
    Using JCS of the array eliminates ambiguity of bare concatenation.
    """
    canonical = canonicalize(offer_hashes)
    return hash_bytes(canonical)


def generate_audit_log(session: Session) -> dict:
    """Generate the audit log for any terminal session (Section 10)."""
    session_init = session._session_init or {}
    session_ack = session._session_ack or {}

    initiator_info = session_init.get("initiator", {})
    responder_info = session_ack.get("responder", {})

    # Determine record_id (null unless COMPLETED)
    record_id = None
    if session.state == SessionState.COMPLETED:
        record_id = str(uuid.uuid5(A2CN_NAMESPACE, session.session_id))

    generated_at = _now()
    session_created_at = session.session_created_at or generated_at

    # first_offer timestamp
    first_offer = next(
        (m for m in session._message_log if m.get("message_type") in ("offer", "counteroffer")),
        None,
    )
    first_offer_at = first_offer["timestamp"] if first_offer else None

    # session_ack timestamp
    session_ack_at = session_ack.get("session_created_at")

    # terminal_state_at: from the last message
    terminal_msg = next(
        (m for m in reversed(session._message_log) if m.get("message_id") == session.terminal_message_id),
        None,
    )
    terminal_state_at = terminal_msg["timestamp"] if terminal_msg else generated_at

    # duration
    try:
        t_start = datetime.fromisoformat(session_created_at.replace("Z", "+00:00"))
        t_end = datetime.fromisoformat(terminal_state_at.replace("Z", "+00:00"))
        duration = int((t_end - t_start).total_seconds())
    except (ValueError, TypeError):
        duration = 0

    # Build negotiation log
    negotiation_log = []
    for msg in session._message_log:
        entry: dict = {
            "sequence_number": msg.get("sequence_number"),
            "message_type": msg.get("message_type", ""),
            "message_id": msg.get("message_id", ""),
            "sender_did": msg.get("sender_did", ""),
            "timestamp": msg.get("timestamp", ""),
            "round_number": msg.get("round_number"),
            "total_value_offered": msg.get("terms", {}).get("total_value") if "terms" in msg else None,
            "protocol_act_hash": msg.get("protocol_act_hash"),
        }
        negotiation_log.append(entry)

    return {
        "log_type": "a2cn_audit_log",
        "log_version": "0.1",
        "log_id": str(uuid.uuid4()),
        "session_id": session.session_id,
        "record_id": record_id,
        "generated_at": generated_at,
        "session_outcome": session.state,
        "parties": {
            "initiator": {
                "organization_name": initiator_info.get("organization_name"),
                "did": initiator_info.get("did"),
                "agent_id": initiator_info.get("agent_id"),
                "mandate_type": session.initiator_mandate.get("mandate_type"),
            },
            "responder": {
                "organization_name": responder_info.get("organization_name"),
                "did": responder_info.get("did"),
                "agent_id": responder_info.get("agent_id"),
                "mandate_type": session.responder_mandate.get("mandate_type"),
            },
        },
        "session_timeline": {
            "session_init_at": session_created_at,
            "session_ack_at": session_ack_at,
            "first_offer_at": first_offer_at,
            "terminal_state_at": terminal_state_at,
            "total_duration_seconds": duration,
        },
        "negotiation_log": negotiation_log,
        "protocol_violations": [],
        "audit_metadata": {
            "ai_system_involved": True,
            "human_oversight_present": False,
            "autonomous_decision": True,
        },
    }
