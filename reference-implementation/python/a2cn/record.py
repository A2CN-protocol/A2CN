"""
A2CN Transaction Record and Audit Log generation (Sections 9–10).

Transaction records are deterministic: both parties derive them only from
protocol messages, never from local clock reads. Audit logs are operational
artifacts and may include local generation metadata such as log_id and
generated_at.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Callable, Mapping

from a2cn.crypto import hash_object, canonicalize, hash_bytes, verify_jws
from a2cn.did import get_public_key, get_verification_method
from a2cn.session import SESSION_BASES, Session, SessionState, _now

# A2CN namespace UUID for record_id (UUID v5) — Appendix A
A2CN_NAMESPACE = uuid.UUID("f4a2c1e0-8b3d-4f7a-9c2e-1d5b6a8f3e7c")

# These identify the transaction-record and audit-log artifact schemas. They
# are intentionally independent of the Python package release version. A
# TransactionRecord's version follows its content (Section 9.3): "0.2" exactly
# when it carries the session's basis, so a session that fixed no basis gets
# the "0.1" record every party derives for it, whichever version its
# implementation is (Section 9.2).
TRANSACTION_RECORD_VERSION_WITHOUT_BASIS = "0.1"
TRANSACTION_RECORD_VERSION_WITH_BASIS = "0.2"
AUDIT_LOG_VERSION = "0.1"
# The TransactionRecord versions a verifier accepts (Section 9.5 step 1). Every
# other value is rejected; step 7 holds each version to its shape.
RECOGNIZED_TRANSACTION_RECORD_VERSIONS = ("0.1", "0.2")


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

    # basis sits beside currency only when the session fixed one (Section 9.3),
    # and the version follows it: the record of a session without a basis has no
    # basis key and is the "0.1" record an implementation that predates basis
    # generates for the same session.
    has_basis = "basis" in session.session_params

    record: dict = {
        "record_type": "a2cn_transaction_record",
        "record_version": (
            TRANSACTION_RECORD_VERSION_WITH_BASIS
            if has_basis
            else TRANSACTION_RECORD_VERSION_WITHOUT_BASIS
        ),
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
        **({"basis": session.session_params["basis"]} if has_basis else {}),
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
            "round_number": final_acceptance.get("round_number"),
            "sequence_number": final_acceptance.get("sequence_number"),
            "accepted_offer_id": final_acceptance.get("accepted_offer_id", ""),
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


def _record_version_recognized(record: dict) -> bool:
    """Section 9.5 step 1: record_version is exactly one of the recognized strings.

    Absent, null, a number, or a string that differs by so much as a space is
    rejected rather than parsed.
    """
    version = record.get("record_version")
    return isinstance(version, str) and version in RECOGNIZED_TRANSACTION_RECORD_VERSIONS


def _record_basis_matches_version(record: dict) -> bool:
    """Section 9.5 step 7: a record carries a top-level basis exactly when it is "0.2".

    A "0.2" record carries basis, as 'net' or 'gross', equal to
    agreed_terms.basis: agreed_terms is the final offer's terms, which restate
    the session basis (Section 7.2). A "0.2" record without basis fails whatever
    agreed_terms holds. A "0.1" record carries no basis key. Presence is by key,
    so a null counts as carried. A "0.1" record's agreed_terms.basis is not
    checked: an implementation that predates the field records it there alone.
    Step 1 has already limited the version to "0.1" or "0.2".
    """
    if record.get("record_version") == TRANSACTION_RECORD_VERSION_WITHOUT_BASIS:
        return "basis" not in record
    agreed_terms = record.get("agreed_terms")
    return (
        "basis" in record
        and record["basis"] in SESSION_BASES
        and isinstance(agreed_terms, dict)
        and agreed_terms.get("basis") == record["basis"]
    )


def verify_transaction_record(
    record: dict,
    did_resolver: Mapping[str, dict] | Callable[[str], dict],
    offer_hashes: list[str] | None = None,
) -> bool:
    """
    Verify a transaction record per Section 9.5.

    `did_resolver` may be a mapping of DID → DID document or a callable returning
    a DID document. For multi-round sessions, pass the chronological offer hash
    list as `offer_hashes` so `offer_chain_hash` can be independently recomputed.
    """
    try:
        if not _record_version_recognized(record):
            return False

        final_offer = record["final_offer"]
        final_acceptance = record["final_acceptance"]
        offer_hash = final_offer["protocol_act_hash"]
        accepted_hash = final_acceptance["accepted_protocol_act_hash"]

        if not _record_hash_matches(record):
            return False

        if not _record_basis_matches_version(record):
            return False

        if accepted_hash != offer_hash:
            return False

        chain_hashes = offer_hashes if offer_hashes is not None else [offer_hash]
        if record.get("offer_chain_hash") != _compute_offer_chain_hash(chain_hashes):
            return False

        if not _verify_record_signature(
            did_resolver,
            record,
            did=final_offer["sender_did"],
            signature=final_offer["protocol_act_signature"],
            expected_payload=offer_hash,
        ):
            return False

        if not _verify_record_signature(
            did_resolver,
            record,
            did=final_acceptance["sender_did"],
            signature=final_acceptance["acceptance_signature"],
            expected_payload=hash_object({
                "session_id": record["session_id"],
                "round_number": final_acceptance["round_number"],
                "sequence_number": final_acceptance["sequence_number"],
                "accepted_offer_id": final_acceptance["accepted_offer_id"],
                "accepted_protocol_act_hash": accepted_hash,
            }),
        ):
            return False

        return True
    except Exception:
        return False


def _record_hash_matches(record: dict) -> bool:
    claimed_hash = record.get("record_hash")
    if not claimed_hash:
        return False
    candidate = dict(record)
    candidate["record_hash"] = ""
    return hash_object(candidate) == claimed_hash


def _verify_record_signature(
    did_resolver: Mapping[str, dict] | Callable[[str], dict],
    record: dict,
    *,
    did: str,
    signature: str,
    expected_payload: str | None = None,
) -> bool:
    verification_method = _verification_method_for_did(record, did)
    if not verification_method or not signature:
        return False

    did_document = _resolve_did_document(did_resolver, did)
    vm = get_verification_method(did_document, verification_method)
    public_key = get_public_key(vm)
    signed_payload = verify_jws(signature, public_key)
    return expected_payload is None or signed_payload == expected_payload


def _resolve_did_document(
    did_resolver: Mapping[str, dict] | Callable[[str], dict],
    did: str,
) -> dict:
    if isinstance(did_resolver, Mapping):
        return did_resolver[did]
    return did_resolver(did)


def _verification_method_for_did(record: dict, did: str) -> str:
    parties = record.get("parties", {})
    for role in ("initiator", "responder"):
        party = parties.get(role, {})
        if party.get("did") == did:
            return party.get("verification_method", "")
    return ""


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

    human_oversight_present = bool(session.approval_receipts)

    return {
        "log_type": "a2cn_audit_log",
        "log_version": AUDIT_LOG_VERSION,
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
            "human_oversight_present": human_oversight_present,
            "autonomous_decision": not human_oversight_present,
        },
    }
