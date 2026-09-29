"""
A2CN Message Dataclasses

All field names match the wire format exactly (Section 6–7 of the spec).
Every dataclass has a to_dict() method that serializes to wire format,
omitting None fields (optional fields that were not set).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

from a2cn.crypto import hash_object


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
# The signed protocol act (Section 7.3.1)
# ---------------------------------------------------------------------------

# The wire version this implementation emits and negotiates. It is the
# a2cn_version / protocol_version of Section 6.3.1, and it is the first field of
# every signed act object (Section 7.3.1), so a signer and a verifier must use
# the same value for a live act. A responder negotiates only this version for a
# live session (Section 12.1.7).
PROTOCOL_ACT_VERSION = "0.3"

# The wire version a recorded act that states no protocol_version is rebuilt
# under (Section 7.3.1). Acts were recorded without their version until records
# began stating it, and every such act was signed under "0.2". The value is
# pinned for that reason and never follows PROTOCOL_ACT_VERSION: tying it to the
# emit version would leave every earlier record unverifiable after each bump.
LEGACY_VERSIONLESS_WIRE_VERSION = "0.2"

# The wire versions this implementation recognises. A session runs at one of
# them; "0.2" remains so that a session negotiated at it can still be replayed
# and its acts rebuilt.
SUPPORTED_WIRE_VERSIONS = (LEGACY_VERSIONLESS_WIRE_VERSION, PROTOCOL_ACT_VERSION)

# The header every signed act carries, whatever its type, in the order Section
# 7.3.1 lists them. JCS sorts keys before hashing, so the order is for readers.
SIGNED_ACT_HEADER_FIELDS = (
    "protocol_version",
    "session_id",
    "round_number",
    "sequence_number",
    "message_type",
    "sender_did",
    "timestamp",
)

# What each act type signs beside the header. expires_at belongs to the offer
# and counteroffer rather than to the header: an acceptance, rejection or
# withdrawal has no deadline of its own, and putting it in the header would make
# all three sign an empty string as a stand-in for one. Keeping it here also
# leaves the offer's signed object exactly the nine flat keys it has always had,
# so no stored record's protocol_act_hash moves.
SIGNED_ACT_PAYLOAD_FIELDS = {
    "offer": ("expires_at", "terms"),
    "counteroffer": ("expires_at", "terms"),
    "acceptance": ("accepted_offer_id", "accepted_protocol_act_hash"),
    "rejection": ("rejected_offer_id", "reason_code"),
    "withdrawal": ("reason_code",),
}

# The field each act type carries its signature in. Offer and counteroffer share
# one, because they are one act under two names. Rejection and withdrawal get
# their own rather than reusing another type's: a signature field that means one
# act type is what lets a verifier refuse an act relabelled as another, because
# the rebuild then demands the type the signature was made under.
SIGNED_ACT_SIGNATURE_FIELDS = {
    "offer": "protocol_act_signature",
    "counteroffer": "protocol_act_signature",
    "acceptance": "acceptance_signature",
    "rejection": "rejection_signature",
    "withdrawal": "withdrawal_signature",
}

# A SessionEvidenceRecord act entry (Section 9A.3) has two kinds of member. Some
# restate a field the act itself carries on the wire; the rest are the record's
# own, added by the producer when it records the act. The entry's field set is
# the union of the two, and nothing else.
RECORD_ENTRY_WIRE_FIELDS = frozenset(
    {
        "sequence_number",
        "round_number",
        "message_type",
        "message_id",
        "sender_did",
        "timestamp",
        "sender_verification_method",
    }
)
RECORD_ENTRY_WRAPPER_FIELDS = frozenset(
    {"act", "act_hash", "attribution", "signature", "signature_type", "source_protocol"}
)

# The record's own members are reserved: an inbound wire act that carries one is
# refused (Section 7.3.1), because a message carrying them would read, once
# recorded, as a record entry stating its own attribution or wrapping another
# act. Taken from the entry set above, so the two cannot drift apart.
RESERVED_WIRE_KEYS = RECORD_ENTRY_WRAPPER_FIELDS

# The offer's signed object, still named for readers of Section 7.3.1: the
# common header followed by the offer's own payload.
PROTOCOL_ACT_FIELDS = SIGNED_ACT_HEADER_FIELDS + SIGNED_ACT_PAYLOAD_FIELDS["offer"]

# The covered fields that are numbers, and the one that is an object. Every
# other covered field is a string.
_ACT_INTEGER_FIELDS = frozenset({"round_number", "sequence_number"})
_ACT_OBJECT_FIELDS = frozenset({"terms"})

# The offer path's own rule: a missing timestamp or expires_at rebuilds as "".
# Neither is validated on the wire, and both state machines have always rebuilt
# an offer's act that way, so an offer that omits one is signed over "" and is
# recorded that way (Section 9.5). Demanding more would refuse an act whose
# signature genuinely covers those bytes.
#
# This belongs to offer and counteroffer alone. An acceptance carries a REQUIRED
# timestamp of its own, so defaulting one for it would let an acceptance sign the
# empty filler that moving expires_at out of the header exists to prevent.
_OFFER_DEFAULTED_FIELDS = frozenset({"timestamp", "expires_at"})
_NO_DEFAULTED_FIELDS: frozenset[str] = frozenset()


def signed_act_object(
    *,
    protocol_version: str,
    session_id: Any,
    round_number: Any,
    sequence_number: Any,
    message_type: Any,
    sender_did: Any,
    timestamp: Any,
    payload: Mapping[str, Any],
) -> dict:
    """The flat object a signed act's signature covers (Section 7.3.1).

    One envelope for all five act types: the common header, then the type's own
    payload, every field at the top level. Flat rather than nested, because a
    nested payload would add a level and bytes to the offer's signed object and
    so could never reproduce the hash the offer's signature already covers.

    Every value is the caller's, and nothing is defaulted here, so each caller
    keeps its own handling of an absent field.
    """
    return {
        "protocol_version": protocol_version,
        "session_id": session_id,
        "round_number": round_number,
        "sequence_number": sequence_number,
        "message_type": message_type,
        "sender_did": sender_did,
        "timestamp": timestamp,
        **payload,
    }


def protocol_act_object(
    *,
    protocol_version: str,
    session_id: Any,
    round_number: Any,
    sequence_number: Any,
    message_type: Any,
    sender_did: Any,
    timestamp: Any,
    expires_at: Any,
    terms: Any,
) -> dict:
    """The object a protocol_act_signature covers (Section 7.3.1).

    The offer and counteroffer's envelope, named for the sites that build it: a
    client signing an offer, the state machine checking one it received, the
    evidence record rebuilding an act it holds, and the TransactionRecord
    rebuilding the act from the record (Section 9.5). It is the envelope with
    the offer's payload, not a second recipe beside it — which is what keeps the
    offer's signed bytes identical without a legacy branch to maintain.
    """
    return signed_act_object(
        protocol_version=protocol_version,
        session_id=session_id,
        round_number=round_number,
        sequence_number=sequence_number,
        message_type=message_type,
        sender_did=sender_did,
        timestamp=timestamp,
        payload={"expires_at": expires_at, "terms": terms},
    )


def _is_act_integer(value: Any) -> bool:
    """An integral JSON number, as an act's round and sequence numbers are.

    RFC 8785 serializes 2.0 and 2 as the same number, so the two are one signed
    act in different JSON spellings and must be judged alike. A bool is an int
    in Python but is not a number in JSON, so it is excluded here; TypeScript's
    typeof excludes it on its own.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and value.is_integer()


def negotiated_protocol_version(session_init: Any, session_ack: Any) -> str:
    """The wire version a session was negotiated at (Section 12.1.7).

    The SessionInit proposes a version and the SessionAck must state the same
    one; the session runs at it, and every live act of the session is signed and
    verified under it. Raises ValueError, naming the first fault, when either
    message states no version, a version this implementation does not recognise,
    or when the two disagree. Nothing is filled in from the other message or from
    this implementation's own version.

    A session with no SessionAck at all (None), whose responder holds no A2CN
    identity and so never answered (Section 9A.8), runs at the version its
    SessionInit proposed. An ack that is present is never passed over.
    """
    messages = [("SessionInit", session_init)]
    if session_ack is not None:
        messages.append(("SessionAck", session_ack))
    versions = []
    for label, message in messages:
        version = message.get("protocol_version") if isinstance(message, Mapping) else None
        if not isinstance(version, str) or not version:
            raise ValueError(f"{label} protocol_version must be a non-empty string")
        if version not in SUPPORTED_WIRE_VERSIONS:
            raise ValueError(f"{label} protocol_version is not a supported wire version")
        versions.append(version)
    if len(versions) == 2 and versions[0] != versions[1]:
        raise ValueError("SessionAck protocol_version does not match the SessionInit's")
    return versions[0]


def rebuild_signed_act(
    act: Mapping[str, Any],
    *,
    version_when_absent: str = LEGACY_VERSIONLESS_WIRE_VERSION,
) -> dict | None:
    """Rebuild the object an act's signature covers, from the act's own fields.

    The shared verify primitive: a caller hashes what this returns and requires
    the act's signature to be over that hash. Returns None when the act cannot
    be rebuilt — an act type the envelope does not name, or a covered field that
    is missing or of a type that cannot be canonicalized — so an act that cannot
    be rebound is refused rather than hashed best-effort over a filled-in blank.

    The rebuild is gated on nothing. No record_version, schema version or field
    presence decides whether it runs, and an act carrying members the envelope
    does not name still rebuilds from the ones it does: a verifier must never
    read a label and skip the binding check.

    protocol_version is the one covered field an act may omit, and which
    version stands in for it depends on where the act comes from (Section
    7.3.1). An act that states one is always rebuilt under the version it
    states. A live act received in a session states none, and its caller passes
    the session's negotiated version. A recorded act that states none was
    recorded before records stated their acts' versions, and is rebuilt under
    the pinned LEGACY_VERSIONLESS_WIRE_VERSION, the default — never under the
    version this implementation currently emits.

    Values are constrained only so far as the act can be canonicalized from
    them. An empty string is rebuilt as it stands, because the hash comparison,
    not a field's length, is what decides: an offer may genuinely be signed over
    an empty timestamp or expires_at (Section 9.5), and demanding more here
    would refuse an act whose signature covers exactly those bytes.
    """
    if not isinstance(act, Mapping):
        return None
    message_type = act.get("message_type")
    if not isinstance(message_type, str):
        return None
    payload_fields = SIGNED_ACT_PAYLOAD_FIELDS.get(message_type)
    if payload_fields is None:
        return None

    defaulted_fields = (
        _OFFER_DEFAULTED_FIELDS
        if message_type in ("offer", "counteroffer")
        else _NO_DEFAULTED_FIELDS
    )
    rebuilt: dict = {}
    for name in SIGNED_ACT_HEADER_FIELDS + payload_fields:
        if name == "protocol_version" and name not in act:
            rebuilt[name] = version_when_absent
            continue
        if name not in act:
            if name in defaulted_fields:
                rebuilt[name] = ""
                continue
            return None
        value = act[name]
        if name in _ACT_INTEGER_FIELDS:
            if not _is_act_integer(value):
                return None
        elif name in _ACT_OBJECT_FIELDS:
            if not isinstance(value, dict):
                return None
        elif not isinstance(value, str):
            return None
        rebuilt[name] = value
    return rebuilt


def signed_act_hash(
    act: Mapping[str, Any],
    *,
    version_when_absent: str = LEGACY_VERSIONLESS_WIRE_VERSION,
) -> str | None:
    """The hash an act's signature must be over, or None if it cannot be rebuilt.

    version_when_absent is as for rebuild_signed_act: a live act's caller passes
    the session's negotiated version, and a recorded act takes the default.
    """
    rebuilt = rebuild_signed_act(act, version_when_absent=version_when_absent)
    return None if rebuilt is None else hash_object(rebuilt)


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
    impasse_threshold: int | None = None
    basis: str | None = None  # "net" | "gross"; None (absent) means unstated

    def to_dict(self) -> dict:
        return _drop_none({
            "deal_type": self.deal_type,
            "currency": self.currency,
            "basis": self.basis,
            "subject": self.subject,
            "subject_reference": self.subject_reference,
            "estimated_value": self.estimated_value,
            "max_rounds": self.max_rounds,
            "session_timeout_seconds": self.session_timeout_seconds,
            "round_timeout_seconds": self.round_timeout_seconds,
            "impasse_threshold": self.impasse_threshold,
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
    # "net" | "gross": restates the session basis when the session fixed one
    # (Section 7.2). None (absent) when the session fixed no basis.
    basis: str | None = None

    def to_dict(self) -> dict:
        return _drop_none({
            "total_value": self.total_value,
            "currency": self.currency,
            "basis": self.basis,
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
    protocol_version: str  # PROTOCOL_ACT_VERSION
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
    protocol_version: str  # PROTOCOL_ACT_VERSION
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
        # The module-level builder of the same name; this method supplies the
        # offer's own values.
        return protocol_act_object(
            protocol_version=PROTOCOL_ACT_VERSION,
            session_id=self.session_id,
            round_number=self.round_number,
            sequence_number=self.sequence_number,
            message_type=self.message_type,
            sender_did=self.sender_did,
            timestamp=self.timestamp,
            expires_at=self.expires_at,
            terms=terms_dict,
        )


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
        """The object signed to produce acceptance_signature (Section 7.3.1).

        The acceptance's envelope: the common header plus its own payload, the
        offer it accepts and that offer's act hash. It is the envelope with the
        acceptance's payload, not a second recipe beside it — the same
        arrangement protocol_act_object has for the offer.
        """
        return signed_act_object(
            protocol_version=PROTOCOL_ACT_VERSION,
            session_id=self.session_id,
            round_number=self.round_number,
            sequence_number=self.sequence_number,
            message_type=self.message_type,
            sender_did=self.sender_did,
            timestamp=self.timestamp,
            payload={
                "accepted_offer_id": self.accepted_offer_id,
                "accepted_protocol_act_hash": self.accepted_protocol_act_hash,
            },
        )


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
    round_number: int  # the round in progress; 1 before any offer (Section 7.6)
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
            "round_number": self.round_number,
            "sequence_number": self.sequence_number,
            "sender_did": self.sender_did,
            "sender_agent_id": self.sender_agent_id,
            "timestamp": self.timestamp,
            "reason_code": self.reason_code,
            "reason_description": self.reason_description,
        })


# ---------------------------------------------------------------------------
# v0.2.0: Session Invitation (Component 8)
# ---------------------------------------------------------------------------

class InvitationStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    EXPIRED = "expired"


@dataclass
class SessionInvitation:
    message_type: str                  # always "session_invitation"
    invitation_id: str                 # UUID v4
    a2cn_version: str                  # PROTOCOL_ACT_VERSION
    inviter_did: str
    inviter_endpoint: str              # HTTPS URL of inviter's A2CN endpoint
    inviter_discovery_url: str
    proposed_deal_type: str
    proposed_session_params: dict      # currency, max_rounds, timeouts
    proposed_terms_summary: dict       # description, estimated_value, currency
    inviter_mandate_summary: dict      # mandate_type, max_commitment_value, authorized_deal_types
    invitation_expires_at: str         # ISO 8601 UTC
    accept_endpoint: str               # HTTPS URL to POST acceptance to
    decline_endpoint: str              # HTTPS URL to POST decline to
    inviter_verification_method: str
    invitation_signature: str = ""     # set after signing; excluded from canonical form

    def to_dict(self) -> dict:
        return _drop_none({
            "message_type": self.message_type,
            "invitation_id": self.invitation_id,
            "a2cn_version": self.a2cn_version,
            "inviter_did": self.inviter_did,
            "inviter_endpoint": self.inviter_endpoint,
            "inviter_discovery_url": self.inviter_discovery_url,
            "proposed_deal_type": self.proposed_deal_type,
            "proposed_session_params": self.proposed_session_params,
            "proposed_terms_summary": self.proposed_terms_summary,
            "inviter_mandate_summary": self.inviter_mandate_summary,
            "invitation_expires_at": self.invitation_expires_at,
            "accept_endpoint": self.accept_endpoint,
            "decline_endpoint": self.decline_endpoint,
            "inviter_verification_method": self.inviter_verification_method,
            "invitation_signature": self.invitation_signature or None,
        })


@dataclass
class InvitationAcceptance:
    message_type: str               # "invitation_acceptance"
    invitation_id: str
    acceptor_did: str
    acceptor_a2cn_endpoint: str
    acceptor_discovery_url: str
    accepted_at: str                # ISO 8601 UTC
    acceptor_verification_method: str
    acceptance_signature: str = ""

    def to_dict(self) -> dict:
        return _drop_none({
            "message_type": self.message_type,
            "invitation_id": self.invitation_id,
            "acceptor_did": self.acceptor_did,
            "acceptor_a2cn_endpoint": self.acceptor_a2cn_endpoint,
            "acceptor_discovery_url": self.acceptor_discovery_url,
            "accepted_at": self.accepted_at,
            "acceptor_verification_method": self.acceptor_verification_method,
            "acceptance_signature": self.acceptance_signature or None,
        })


@dataclass
class InvitationDecline:
    message_type: str           # "invitation_decline"
    invitation_id: str
    reason_code: str            # DEAL_TYPE_NOT_SUPPORTED | MANDATE_INSUFFICIENT | CAPACITY | OTHER
    declined_at: str
    reason_message: str = ""

    def to_dict(self) -> dict:
        return _drop_none({
            "message_type": self.message_type,
            "invitation_id": self.invitation_id,
            "reason_code": self.reason_code,
            "declined_at": self.declined_at,
            "reason_message": self.reason_message or None,
        })


# ---------------------------------------------------------------------------
# v0.2.0: Webhook Payload (Level 2 conformance — REQUIRED)
# ---------------------------------------------------------------------------

@dataclass
class WebhookPayload:
    event_type: str     # "session.completed" | "session.rejected" | "session.withdrawn"
                        # | "session.impasse" | "session.timed_out" | "session.error"
    session_id: str
    occurred_at: str    # ISO 8601 UTC
    session_state: str
    terminal: bool      # always True for these events
    a2cn_version: str = PROTOCOL_ACT_VERSION
    record_hash: str = ""   # populated only for session.completed

    def to_dict(self) -> dict:
        return _drop_none({
            "event_type": self.event_type,
            "session_id": self.session_id,
            "occurred_at": self.occurred_at,
            "session_state": self.session_state,
            "terminal": self.terminal,
            "a2cn_version": self.a2cn_version,
            "record_hash": self.record_hash or None,
        })


# ---------------------------------------------------------------------------
# v0.2.0: Invitation error codes (Section 11.7 extension)
# ---------------------------------------------------------------------------

INVITATION_EXPIRED = "INVITATION_EXPIRED"
INVITATION_NOT_FOUND = "INVITATION_NOT_FOUND"
INVITATION_SIGNATURE_INVALID = "INVITATION_SIGNATURE_INVALID"
INVITATION_ALREADY_ANSWERED = "INVITATION_ALREADY_ANSWERED"
INVITATION_VERSION_MISMATCH = "INVITATION_VERSION_MISMATCH"


# ---------------------------------------------------------------------------
# v0.2.0: Deal-type terms validation (OQ-004)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# v0.2.0: Post-commitment lifecycle (OQ-017 resolved; Level 3 conformance)
# ---------------------------------------------------------------------------

@dataclass
class DeliveryNoticeMessage:
    """
    Sent by the seller to confirm delivery against a completed session.
    References the transaction record by hash. Required for Level 3
    conformance in A2CN v0.2.0.

    A `delivery_notice` closes the seller's obligation under the agreed terms
    and triggers the buyer's acknowledgment window.
    """
    message_id: str
    session_id: str
    transaction_record_hash: str  # Must match the agreed transaction record
    delivery_timestamp: str       # ISO 8601 — when delivery occurred
    delivery_reference: str | None = None  # Tracking number, PO ref, etc.
    notes: str | None = None
    protocol_version: str = PROTOCOL_ACT_VERSION
    message_type: str = "delivery_notice"

    def to_dict(self) -> dict:
        return _drop_none({
            "message_type": self.message_type,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "transaction_record_hash": self.transaction_record_hash,
            "delivery_timestamp": self.delivery_timestamp,
            "delivery_reference": self.delivery_reference,
            "notes": self.notes,
            "protocol_version": self.protocol_version,
        })


@dataclass
class DeliveryAcknowledgedMessage:
    """
    Sent by the buyer to acknowledge receipt of a `delivery_notice`.
    Closes the post-commitment lifecycle when accepted=True.
    When accepted=False, triggers DISPUTED status on the session.

    References both the `delivery_notice` and the transaction record.
    """
    message_id: str
    session_id: str
    transaction_record_hash: str      # Must match agreed transaction record
    delivery_notice_message_id: str   # References the delivery_notice
    acknowledgment_timestamp: str     # ISO 8601
    accepted: bool                    # True = delivery accepted, False = disputed
    notes: str | None = None
    protocol_version: str = PROTOCOL_ACT_VERSION
    message_type: str = "delivery_acknowledged"

    def to_dict(self) -> dict:
        return _drop_none({
            "message_type": self.message_type,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "transaction_record_hash": self.transaction_record_hash,
            "delivery_notice_message_id": self.delivery_notice_message_id,
            "acknowledgment_timestamp": self.acknowledgment_timestamp,
            "accepted": self.accepted,
            "notes": self.notes,
            "protocol_version": self.protocol_version,
        })


@dataclass
class DisputeNoticeMessage:
    """
    Sent by either party to formally open a dispute referencing a
    committed or delivered session. Freezes further automated processing
    and anchors the dispute to the agreed transaction record.

    Disputes should be routed to a neutral resolver. A neutral third-party
    custodian may provide evidence custody and dispute resolution as an
    optional hosted service.
    """
    message_id: str
    session_id: str
    transaction_record_hash: str  # Must match agreed transaction record
    raised_by: str                # "buyer" or "seller"
    dispute_type: str             # "non_delivery" | "wrong_quantity" | "quality"
                                  # | "payment_failure" | "terms_violation" | "other"
    description: str
    evidence_references: list[str] = None  # Document refs, hashes, URLs
    resolution_requested: str | None = None  # "renegotiate" | "cancel" | "neutral_review"
    dispute_timestamp: str = None  # ISO 8601, auto-set on creation
    protocol_version: str = PROTOCOL_ACT_VERSION
    message_type: str = "dispute_notice"

    def __post_init__(self):
        if self.evidence_references is None:
            self.evidence_references = []
        if self.dispute_timestamp is None:
            from datetime import datetime, timezone
            self.dispute_timestamp = datetime.now(
                timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> dict:
        return _drop_none({
            "message_type": self.message_type,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "transaction_record_hash": self.transaction_record_hash,
            "raised_by": self.raised_by,
            "dispute_type": self.dispute_type,
            "description": self.description,
            "evidence_references": self.evidence_references,
            "resolution_requested": self.resolution_requested,
            "dispute_timestamp": self.dispute_timestamp,
            "protocol_version": self.protocol_version,
        })


@dataclass
class DisputeResolvedMessage:
    """
    Sent by the neutral resolver (or agreed party) to record the outcome
    of a dispute opened by `dispute_notice`. Closes the post-commitment
    dispute lifecycle.

    Anchored to both the original transaction record hash and the
    `dispute_notice` message_id. The resolution_outcome field records
    who prevailed; resolver_did identifies the neutral party that
    issued the resolution.

    Concordia Protocol composition note: this message provides the
    stable input shape for Concordia fulfillment attestations with
    fulfillment.status = "fulfilled_with_mediation" and
    meta.mediator_invoked = True. Both the transaction_record_hash
    and dispute_notice_message_id are required fields for that
    composition seam.
    """
    message_id: str
    session_id: str
    transaction_record_hash: str  # Must match the agreed transaction record
    dispute_notice_message_id: str  # References the dispute_notice being resolved
    resolution_outcome: str  # "buyer_prevails" | "seller_prevails" |
                              # "mutual_settlement"
    resolver_did: str  # DID of the neutral resolver
    resolution_timestamp: str = None  # ISO 8601, auto-set on creation
    resolution_notes: str | None = None
    evidence_references: list[str] = None  # Supporting evidence for the ruling
    protocol_version: str = PROTOCOL_ACT_VERSION
    message_type: str = "dispute_resolved"

    def __post_init__(self):
        if self.evidence_references is None:
            self.evidence_references = []
        if self.resolution_timestamp is None:
            from datetime import datetime, timezone
            self.resolution_timestamp = datetime.now(
                timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> dict:
        return _drop_none({
            "message_type": self.message_type,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "transaction_record_hash": self.transaction_record_hash,
            "dispute_notice_message_id": self.dispute_notice_message_id,
            "resolution_outcome": self.resolution_outcome,
            "resolver_did": self.resolver_did,
            "resolution_timestamp": self.resolution_timestamp,
            "resolution_notes": self.resolution_notes,
            "evidence_references": self.evidence_references,
            "protocol_version": self.protocol_version,
        })


@dataclass
class FulfillmentAttestation:
    """
    Concordia-shaped artifact emitted when A2CN post-commitment fulfillment
    reaches a clean or mediated terminal state.
    """
    attestation_type: str
    id: str
    issued_at: str
    agreement_attestation_id: str
    fulfillment: dict[str, Any]
    references: list[dict[str, Any]]
    signature: dict[str, Any]
    meta: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        return _drop_none({
            "attestation_type": self.attestation_type,
            "id": self.id,
            "issued_at": self.issued_at,
            "agreement_attestation_id": self.agreement_attestation_id,
            "fulfillment": self.fulfillment,
            "references": self.references,
            "signature": self.signature,
            "meta": self.meta,
        })


def validate_deal_type_terms(deal_type: str, terms: dict) -> list[str]:
    """
    Validates terms dict against deal-type-specific schema.
    Returns list of validation error strings. Empty list = valid.

    goods_procurement required fields: delivery_days (int >= 1)
    saas_renewal required fields: seat_count (int >= 1)
    Unknown deal types: always valid (extensible).
    """
    errors: list[str] = []

    if deal_type == "goods_procurement":
        delivery_days = terms.get("delivery_days")
        if delivery_days is None:
            errors.append("goods_procurement terms require 'delivery_days'")
        elif not isinstance(delivery_days, int) or isinstance(delivery_days, bool):
            errors.append(f"delivery_days must be an integer >= 1, got {delivery_days!r}")
        elif delivery_days < 1:
            errors.append(f"delivery_days must be >= 1, got {delivery_days}")

    elif deal_type == "saas_renewal":
        seat_count = terms.get("seat_count")
        if seat_count is None:
            errors.append("saas_renewal terms require 'seat_count'")
        elif not isinstance(seat_count, int) or isinstance(seat_count, bool):
            errors.append(f"seat_count must be an integer >= 1, got {seat_count!r}")
        elif seat_count < 1:
            errors.append(f"seat_count must be >= 1, got {seat_count}")

    # Unknown deal types pass through without validation (extensibility)
    return errors
