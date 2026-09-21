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

from jwt.exceptions import InvalidSignatureError

from a2cn.crypto import hash_object, canonicalize, hash_bytes, verify_jws
from a2cn.did import get_public_key, get_verification_method
from a2cn.messages import PROTOCOL_ACT_VERSION, protocol_act_object
from a2cn.session import SESSION_BASES, Session, SessionState, _now

# A2CN namespace UUID for record_id (UUID v5) — Appendix A
A2CN_NAMESPACE = uuid.UUID("f4a2c1e0-8b3d-4f7a-9c2e-1d5b6a8f3e7c")

# These identify the transaction-record and audit-log artifact schemas. They
# are intentionally independent of the Python package release version. A
# TransactionRecord's version follows its content (Section 9.3): a producer
# emits "0.3" exactly when final_offer carries the signed act's fields, which
# this implementation always does. "0.2" is the version of a record that carries
# the session's basis and no act fields, and "0.1" of one that carries neither.
TRANSACTION_RECORD_VERSION_WITHOUT_BASIS = "0.1"
TRANSACTION_RECORD_VERSION_WITH_BASIS = "0.2"
TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT = "0.3"
AUDIT_LOG_VERSION = "0.1"
# The record shapes this implementation knows, which is what the published
# schema files describe. Knowing a shape is not accepting it.
KNOWN_TRANSACTION_RECORD_VERSIONS = ("0.1", "0.2", "0.3")
# The versions a verifier accepts (Section 9.5 step 1): only the bound one, the
# version whose final_offer carries the act fields, so the record can be rebound
# to the offering party's signature from the record alone. record_version is
# covered by no signature, so a verifier refuses any version it cannot rebind
# rather than trusting the label; accepting an unbound version would let a
# presenter strip the act fields, relabel the record and alter agreed_terms with
# both signatures still verifying.
ACCEPTED_TRANSACTION_RECORD_VERSIONS = (TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,)

# Why a record failed (Section 9.5). verify_transaction_record returns a bool;
# verify_transaction_record_reason returns one of these, or None when the record
# verifies. A version this implementation knows but cannot rebind is reported as
# unbound, distinct from a value that is no version at all.
REASON_UNRECOGNIZED_RECORD_VERSION = "UNRECOGNIZED_RECORD_VERSION"
REASON_UNBOUND_RECORD_VERSION = "UNBOUND_RECORD_VERSION"
REASON_RECORD_HASH_MISMATCH = "RECORD_HASH_MISMATCH"
REASON_ACT_NOT_RECOMPUTABLE = "ACT_NOT_RECOMPUTABLE"
REASON_BASIS_MISMATCH = "BASIS_MISMATCH"
REASON_CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
REASON_ACCEPTED_HASH_MISMATCH = "ACCEPTED_HASH_MISMATCH"
REASON_OFFER_CHAIN_HASH_MISMATCH = "OFFER_CHAIN_HASH_MISMATCH"
REASON_OFFER_SIGNATURE_INVALID = "OFFER_SIGNATURE_INVALID"
REASON_ACCEPTANCE_SIGNATURE_INVALID = "ACCEPTANCE_SIGNATURE_INVALID"
REASON_MALFORMED_RECORD = "MALFORMED_RECORD"

# The Section 7.3.1 act fields final_offer carries beside the act's hash, so a
# verifier can rebuild the signed act from the record alone (Section 9.3). The
# act's other fields are already in the record: session_id at the top level,
# sender_did in final_offer, and the act's terms as agreed_terms. Nothing new is
# signed — this is the object protocol_act_signature already covers.
FINAL_OFFER_ACT_FIELDS = (
    "protocol_version",
    "round_number",
    "sequence_number",
    "message_type",
    "timestamp",
    "expires_at",
)


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

    # basis sits beside currency only when the session fixed one (Section 9.3).
    # Under "0.3" agreed_terms is bound to the offer's signature, so the version
    # no longer has to encode whether the session fixed a basis; the record still
    # carries basis exactly when it did, equal to agreed_terms.basis.
    has_basis = "basis" in session.session_params

    record: dict = {
        "record_type": "a2cn_transaction_record",
        # Every record this implementation produces carries the act fields, so
        # every one is "0.3" (Section 9.3).
        "record_version": TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,
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
        # The accepted offer's signed act, in Section 7.3.1's order. An offer
        # message carries no protocol_version of its own, so the record states
        # the wire version its signer hashed the act under.
        "final_offer": {
            "message_id": final_offer.get("message_id", ""),
            "protocol_version": PROTOCOL_ACT_VERSION,
            "round_number": final_offer.get("round_number"),
            "sequence_number": final_offer.get("sequence_number"),
            "message_type": final_offer.get("message_type", ""),
            "sender_did": final_offer.get("sender_did", ""),
            "timestamp": final_offer.get("timestamp", ""),
            "expires_at": final_offer.get("expires_at", ""),
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


def _record_version_reason(record: dict) -> str | None:
    """Section 9.5 step 1: the record states the one version a verifier accepts.

    A value that is no version this implementation knows is unrecognized;
    absent, null, a number, or a string that differs by so much as a space is
    rejected rather than parsed. A version it does know but cannot rebind is
    reported as unbound instead, because the two are different facts: one is a
    record from somewhere else, the other a record this implementation once
    produced and no longer accepts.
    """
    version = record.get("record_version")
    if isinstance(version, str) and version in ACCEPTED_TRANSACTION_RECORD_VERSIONS:
        return None
    if isinstance(version, str) and version in KNOWN_TRANSACTION_RECORD_VERSIONS:
        return REASON_UNBOUND_RECORD_VERSION
    return REASON_UNRECOGNIZED_RECORD_VERSION


def _is_act_integer(value: object) -> bool:
    """An integral JSON number, as the act's round and sequence numbers are.

    RFC 8785 serializes 2.0 and 2 as the same number, so the two are one signed
    act in different JSON spellings and must be judged alike: a parser that hands
    back a float where another hands back an int must not change the verdict. A
    bool is an int in Python but is not a number in JSON, so it is excluded here;
    TypeScript's typeof excludes it on its own.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and value.is_integer()


def _final_offer_act_hash(record: dict) -> str | None:
    """Rebuild the final offer's Section 7.3.1 act from the record and hash it.

    Returns None when the record carries no well-formed act: a missing or
    wrongly typed field leaves nothing to rebuild, and the record fails rather
    than being hashed best-effort. The act is rebuilt with the protocol_version
    the record carries, not this implementation's, so a record produced under a
    later wire version still recomputes.

    The types are checked only so far as the act can be rebuilt and canonicalized
    from them. The values are not otherwise constrained: an empty string or a
    zero is rebuilt as it stands, because the hash comparison, not a field's
    length or floor, is what decides. Both state machines default a missing
    timestamp or expires_at to "" when they rebuild an act to check its hash, and
    neither field is validated on the wire, so an offer that omits one is signed
    and recorded with "" inside the signed act; demanding more here would reject
    a record whose signature genuinely covers those bytes.
    """
    final_offer = record.get("final_offer")
    if not isinstance(final_offer, dict):
        return None
    if not all(
        isinstance(final_offer.get(name), str)
        for name in ("protocol_version", "message_type", "sender_did", "timestamp", "expires_at")
    ):
        return None
    if not all(
        _is_act_integer(final_offer.get(name))
        for name in ("round_number", "sequence_number")
    ):
        return None
    session_id = record.get("session_id")
    agreed_terms = record.get("agreed_terms")
    if not isinstance(session_id, str):
        return None
    if not isinstance(agreed_terms, dict):
        return None
    return hash_object(
        protocol_act_object(
            protocol_version=final_offer["protocol_version"],
            session_id=session_id,
            round_number=final_offer["round_number"],
            sequence_number=final_offer["sequence_number"],
            message_type=final_offer["message_type"],
            sender_did=final_offer["sender_did"],
            timestamp=final_offer["timestamp"],
            expires_at=final_offer["expires_at"],
            terms=agreed_terms,
        )
    )


def _record_carries_act_fields(record: dict) -> bool:
    """Whether the record carries every Section 7.3.1 act field to rebuild from.

    A record that does not is unbound: there is nothing to rebind it to, whether
    because it is an older shape or because a presenter stripped the fields and
    relabelled it. Presence is by key.
    """
    final_offer = record.get("final_offer")
    if not isinstance(final_offer, dict):
        return False
    return all(name in final_offer for name in FINAL_OFFER_ACT_FIELDS)


def _record_act_is_bound(record: dict) -> bool:
    """Section 9.5 step 3: the record rebuilds the act its signature covers.

    Step 1 has already limited the version to the bound one, so this always
    runs: final_offer carries every Section 7.3.1 act field, and the act rebuilt
    from the record hashes to the protocol_act_hash the offer's signature
    covers. Step 4 then binds agreed_terms to that signature, because the act it
    was rebuilt from holds agreed_terms as its terms. Presence is by key, and a
    partial set is refused. Nothing here is newly signed.

    The hash comparison is what carries this check. The count of carried fields
    is belt-and-braces: a partial set leaves the rebuild with nothing to read,
    so it would fail the comparison anyway.
    """
    final_offer = record.get("final_offer")
    if not isinstance(final_offer, dict):
        return False
    carried = [name for name in FINAL_OFFER_ACT_FIELDS if name in final_offer]
    if len(carried) != len(FINAL_OFFER_ACT_FIELDS):
        return False
    expected_hash = _final_offer_act_hash(record)
    return expected_hash is not None and expected_hash == final_offer.get("protocol_act_hash")


def _record_basis_matches(record: dict) -> bool:
    """Section 9.5 step 8: the top-level basis is the one that was signed.

    The record carries basis exactly when agreed_terms carries one, and equal to
    it. Step 3 has bound agreed_terms to the offering party's signature, so this
    reads a signed value. Presence is by key, so a null counts as carried.

    Earlier versions meant something else by the same field: a "0.2" record
    always carried basis and a "0.1" record never did, because neither could
    bind agreed_terms and the version had to encode whether the session fixed
    one. A verifier no longer accepts those versions, so those branches are gone
    rather than dead.
    """
    agreed_terms = record.get("agreed_terms")
    if not (isinstance(agreed_terms, dict) and "basis" in agreed_terms):
        return "basis" not in record
    return (
        "basis" in record
        and record["basis"] in SESSION_BASES
        and agreed_terms["basis"] == record["basis"]
    )


def _record_currency_matches(record: dict) -> bool:
    """Section 9.5 step 8: the top-level currency is the one that was signed.

    Step 3 has bound agreed_terms to the offering party's signature, so the
    record's currency is held to agreed_terms.currency: a record that states one
    currency in its headline and another in the terms that were signed is
    rejected. Presence is by key, and both must carry one. The check is
    unconditional, because only the bound version is accepted.
    """
    agreed_terms = record.get("agreed_terms")
    if not isinstance(agreed_terms, dict):
        return False
    return (
        "currency" in record
        and "currency" in agreed_terms
        and record["currency"] == agreed_terms["currency"]
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

    Returns whether the record verifies. `verify_transaction_record_reason` takes
    the same arguments and says why one did not.
    """
    return verify_transaction_record_reason(record, did_resolver, offer_hashes) is None


def verify_transaction_record_reason(
    record: dict,
    did_resolver: Mapping[str, dict] | Callable[[str], dict],
    offer_hashes: list[str] | None = None,
) -> str | None:
    """Why a record does not verify (Section 9.5), or None when it does.

    The same arguments as `verify_transaction_record`, which is this function's
    boolean. The reason is one of the REASON_* constants, so a caller can tell a
    record it cannot rebind from one that was tampered with.
    """
    try:
        version_reason = _record_version_reason(record)
        if version_reason is not None:
            return version_reason

        final_offer = record["final_offer"]
        final_acceptance = record["final_acceptance"]
        offer_hash = final_offer["protocol_act_hash"]
        accepted_hash = final_acceptance["accepted_protocol_act_hash"]

        if not _record_hash_matches(record):
            return REASON_RECORD_HASH_MISMATCH

        # A record with no act to rebuild is unbound, whatever its label says;
        # one that carries the act but hashes to something else was tampered
        # with. The two reasons mean genuinely different things.
        if not _record_carries_act_fields(record):
            return REASON_UNBOUND_RECORD_VERSION

        if not _record_act_is_bound(record):
            return REASON_ACT_NOT_RECOMPUTABLE

        if not _record_basis_matches(record):
            return REASON_BASIS_MISMATCH

        if not _record_currency_matches(record):
            return REASON_CURRENCY_MISMATCH

        if accepted_hash != offer_hash:
            return REASON_ACCEPTED_HASH_MISMATCH

        chain_hashes = offer_hashes if offer_hashes is not None else [offer_hash]
        if record.get("offer_chain_hash") != _compute_offer_chain_hash(chain_hashes):
            return REASON_OFFER_CHAIN_HASH_MISMATCH

        if not _verify_record_signature(
            did_resolver,
            record,
            did=final_offer["sender_did"],
            signature=final_offer["protocol_act_signature"],
            expected_payload=offer_hash,
        ):
            return REASON_OFFER_SIGNATURE_INVALID

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
            return REASON_ACCEPTANCE_SIGNATURE_INVALID

        return None
    except Exception:
        # The last resort: a record whose shape stopped us reaching a verdict at
        # all. A signature that simply does not verify is caught where it is
        # checked, so it reports its own reason instead of arriving here.
        return REASON_MALFORMED_RECORD


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
    # verify_jws raises on bad signature bytes. That is this check failing, not
    # the record being unreadable, so it is caught here and the caller reports
    # the signature reason. An unresolvable DID or a missing verification method
    # is a different thing and still reaches the outer handler as a malformed
    # record.
    try:
        signed_payload = verify_jws(signature, public_key)
    except InvalidSignatureError:
        return False
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
