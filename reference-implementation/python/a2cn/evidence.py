"""Session Evidence Record generation and verification (Section 9A).

SessionEvidenceRecord is a producer-sealed package for any terminal session. It
preserves complete observed acts and distinguishes verified A2CN signatures from
unsigned observations without changing TransactionRecord or AuditLog semantics.
"""

from __future__ import annotations

import copy
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from fractions import Fraction
from typing import Any

from a2cn.crypto import SigningPrivateKey, canonicalize, hash_bytes, hash_object, sign_jws, verify_jws
from a2cn.did import get_public_key, get_verification_method
from a2cn.messages import (
    RECORD_ENTRY_WIRE_FIELDS,
    RECORD_ENTRY_WRAPPER_FIELDS,
    _is_act_integer,
    negotiated_protocol_version,
    rebuild_signed_act,
)
from a2cn.record import A2CN_NAMESPACE, generate_transaction_record
from a2cn.session import SESSION_BASES, Session, SessionState, _now


SESSION_EVIDENCE_RECORD_VERSION_WITHOUT_EXTERNAL_COMMITMENT = "0.2"
# A record's version follows its content (Section 9A.2): "0.3" exactly when it
# carries external_commitment_reference (Section 9A.12). Every other record
# stays "0.2", so a verifier that predates "0.3" still reads it.
SESSION_EVIDENCE_RECORD_VERSION_WITH_EXTERNAL_COMMITMENT = "0.3"
# The versions a verifier accepts (Section 9A.2). Every other value is rejected.
# Verification is the same for all of them except where a rule is keyed on the
# version, and each such rule is one of the floors below: BELOW "0.4" a record
# carries external_commitment_reference exactly when it is "0.3"; a decline
# signature type requires "0.4" or later; and a DID-bearing responder on a record
# carrying that reference requires "0.5" or later. The biconditional is
# historical and governs only versions under "0.4"; stated as the general rule it
# contradicts the paragraph directly below it.
# Every record a producer emits is "0.5" (Section 9A.2). The constants above
# name versions that only historical records carry; they stay so those records
# can still be read, because the SER recognizer is additive — a version is
# added and none removed, and an older sealed record stays valid.
SESSION_EVIDENCE_RECORD_VERSION_CURRENT = "0.5"

# ORDERED, and the order is load-bearing: _version_at_or_after reads its floors
# off this tuple, so a new version MUST be appended in published order.
RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS = ("0.1", "0.2", "0.3", "0.4", "0.5")
SESSION_EVIDENCE_RECORD_TYPE = "a2cn_session_evidence_record"

EVIDENCE_BILATERAL = "bilateral"
EVIDENCE_MIXED = "mixed"
EVIDENCE_UNILATERAL = "unilateral"

ATTRIBUTION_VERIFIED = "verified_signature"
ATTRIBUTION_UNSIGNED = "unsigned_observation"

SIGNATURE_PROTOCOL_ACT = "protocol_act_signature"
SIGNATURE_ACCEPTANCE = "acceptance_signature"
SIGNATURE_REJECTION = "rejection_signature"
SIGNATURE_WITHDRAWAL = "withdrawal_signature"

# The act vocabulary that "0.4" and later admit. Rejection and Withdrawal became
# signable in band with the uniform signed-act envelope (Sections 7.5, 7.6), so
# no earlier version's schema lists these values and no earlier record can
# legitimately carry one.
_DECLINE_SIGNATURE_TYPES = frozenset({SIGNATURE_REJECTION, SIGNATURE_WITHDRAWAL})
# FLOORS, not literal sets. Every rule keyed on these means "this version or
# later". The first two were once written as sets naming the versions that existed
# when they were written. That is correct until the next version ships and then
# states the opposite of its own docstring: as frozenset({"0.4"}) this refused a
# "0.5" record for carrying a decline that "0.5" admits, and the version-keyed
# witness rule below dropped every stored "0.4" external-channel record into the
# "0.3" biconditional and refused it. Neither docstring ever claimed a single
# version — each already said "or later" — so the literals contradicted the
# prose beside them rather than implementing it.
_VERSION_ADMITTING_DECLINE_VOCABULARY = "0.4"
_VERSION_WITHOUT_VERSION_KEYED_WITNESS_RULE = "0.4"
# The first version whose schema admits a DID-bearing responder on a record
# carrying external_commitment_reference; "0.3" and "0.4" require an
# observed_party there. Also a floor, read through _version_at_or_after.
_VERSION_ADMITTING_VERIFIED_EXTERNAL_RESPONDER = "0.5"

# The act types a responder may sign in a record carrying
# external_commitment_reference (Section 9A.12): negotiation, never a completion
# or a refusal.
_NEGOTIATION_MESSAGE_TYPES = ("offer", "counteroffer")

OUTCOME_HALTED_BY_CONTROLS = "HALTED_BY_CONTROLS"

MONEY_BASIS_LABELS = frozenset(
    {"net", "gross", "per_unit", "line_total", "unspecified"}
)

_TERMINAL_STATES = frozenset(SessionState.TERMINAL)
# HALTED_BY_CONTROLS is an evidence-record outcome only. It is deliberately not a
# SessionState: adding one would be a wire change, and 0.2 is frozen.
_EVIDENCE_TERMINAL_OUTCOMES = _TERMINAL_STATES | {OUTCOME_HALTED_BY_CONTROLS}
_SIGNED_MESSAGE_FIELDS = {
    SIGNATURE_PROTOCOL_ACT: SIGNATURE_PROTOCOL_ACT,
    SIGNATURE_ACCEPTANCE: SIGNATURE_ACCEPTANCE,
    SIGNATURE_REJECTION: SIGNATURE_REJECTION,
    SIGNATURE_WITHDRAWAL: SIGNATURE_WITHDRAWAL,
}
# The act types each signature slot may appear on. A slot that names one act
# type is what lets a verifier refuse an act relabelled as another: the rebuild
# then demands the scope the signature was made under, while the signature is
# still sitting in the slot of the type it was made for. Before the declines had
# slots of their own, a rejection or withdrawal carrying a signature was read as
# an unsigned observation and its signature was never checked at all.
_SIGNATURE_TYPE_MESSAGE_TYPES = {
    SIGNATURE_PROTOCOL_ACT: ("offer", "counteroffer"),
    SIGNATURE_ACCEPTANCE: ("acceptance",),
    SIGNATURE_REJECTION: ("rejection",),
    SIGNATURE_WITHDRAWAL: ("withdrawal",),
}
_RECORD_FIELDS = frozenset(
    {
        "record_type",
        "record_version",
        "evidence_id",
        "session_id",
        "generated_at",
        "producer",
        "parties",
        "terminal",
        "transaction_record_hash",
        "acts",
        "act_chain_hash",
        "evidence_level",
        "record_hash",
        "producer_signature",
    }
)
_RECORD_OPTIONAL_FIELDS = frozenset({"extensions", "external_commitment_reference"})
_EXTERNAL_COMMITMENT_REFERENCE_FIELDS = frozenset({"external_commitment_id"})
_EXTERNAL_COMMITMENT_REFERENCE_OPTIONAL_FIELDS = frozenset({"locator", "reference_note"})
# The fields that restate the wire act, and the record's own (a2cn.messages).
_ACT_FIELDS = RECORD_ENTRY_WIRE_FIELDS | RECORD_ENTRY_WRAPPER_FIELDS
_ACT_OPTIONAL_FIELDS = frozenset({"money_basis"})
_TERMINAL_FIELDS = frozenset({"outcome", "reason", "message_id", "timestamp"})
_TERMINAL_OPTIONAL_FIELDS = frozenset({"money_basis"})
_PARTY_FIELDS = frozenset(
    {
        "organization_name",
        "did",
        "agent_id",
        "verification_method",
        "mandate_type",
    }
)
_OBSERVED_PARTY_FIELDS = frozenset(
    {"identity_source", "did_declared", "a2cn_endpoint_declared", "mandate_declared"}
)
_OBSERVED_PARTY_OPTIONAL_FIELDS = frozenset(
    {"organization_name", "observed_credential"}
)
_OBSERVED_PARTY_MARKERS = ("did_declared", "a2cn_endpoint_declared", "mandate_declared")
# raw_amounts is deliberately absent from the required set so the fail-closed rule
# below owns it by name: a total claimed with no raw data behind it is rejected by
# a branch that says so, not incidentally by a field-set check.
_MONEY_BASIS_FIELDS = frozenset(
    {"currency", "minor_unit_exponent", "basis", "normalized_total_minor"}
)
_MONEY_BASIS_OPTIONAL_FIELDS = frozenset({"raw_amounts"})
_HASH_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_EXTENSION_NAMESPACE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$")
_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")
_DECIMAL_AMOUNT_PATTERN = re.compile(r"^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?$")
# Both reference implementations must agree on every recomputed total. JavaScript
# numbers are exact only to 2**53 - 1, so that bound is the shared contract.
_MAX_EXACT_INTEGER = 2**53 - 1
_RFC3339_PATTERN = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d+))?([Zz]|([+-])(\d{2}):(\d{2}))$"
)
_UNIX_EPOCH = datetime(1970, 1, 1)

DidResolver = Mapping[str, dict] | Callable[[str], dict]


def generate_session_evidence_record(
    session: Session,
    *,
    producer_private_key: SigningPrivateKey,
    producer_verification_method: str,
    producer_did: str | None = None,
    producer_agent_id: str | None = None,
    observed_acts: Sequence[dict] | None = None,
    observed_responder: Mapping[str, Any] | None = None,
    terminal_outcome: str | None = None,
    terminal_reason: str | None = None,
    terminal_money_basis: Mapping[str, Any] | None = None,
    extensions: Mapping[str, Any] | None = None,
    external_commitment_reference: Mapping[str, Any] | None = None,
) -> dict:
    """Generate a producer-sealed evidence package for a terminal session.

    The native session message log is always included. ``observed_acts`` augments
    that log with chronological external observations. An observed item may be a
    raw act/message or an evidence-entry input with an ``act`` object and outer
    metadata such as ``source_protocol``.

    ``observed_responder`` records a counterparty that holds no A2CN identity. It
    is a producer assertion; no DID is ever fabricated for it.
    ``terminal_outcome`` may assert ``HALTED_BY_CONTROLS`` for a session the
    producer's own controls stopped.

    ``external_commitment_reference`` completes a session whose counterparty
    signed no A2CN act: it names the external order or commitment the deal
    produced, in place of a TransactionRecord, which is bilateral (Section
    9A.12). That counterparty may be an observed responder holding no identity,
    or a DID-bearing party whose identity verifies while its acts stay unsigned.
    Such a record is ``"0.5"``, like every record this generator emits; the
    reference is OPTIONAL at that version (Section 9A.2). It is refused for any
    outcome but ``COMPLETED``; ``None`` means it is not supplied.
    """
    if session.state not in _TERMINAL_STATES:
        raise ValueError("Session evidence is only available for terminal sessions")

    outcome = session.state
    reason = session.terminal_reason
    if terminal_outcome is not None:
        if terminal_outcome != OUTCOME_HALTED_BY_CONTROLS:
            raise ValueError(
                f"terminal_outcome may only assert {OUTCOME_HALTED_BY_CONTROLS}"
            )
        if session.state == SessionState.COMPLETED:
            raise ValueError("A COMPLETED session cannot be relabelled as halted")
        outcome = terminal_outcome
    if terminal_reason is not None:
        if terminal_outcome is None:
            raise ValueError("terminal_reason requires terminal_outcome")
        if not isinstance(terminal_reason, str) or not terminal_reason:
            raise ValueError("terminal_reason must be a non-empty string")
        reason = terminal_reason

    parties = _party_metadata(session, observed_responder=observed_responder)
    producer = _producer_metadata(
        parties,
        producer_verification_method=producer_verification_method,
        producer_did=producer_did,
        producer_agent_id=producer_agent_id,
    )

    # A COMPLETED session carries exactly one completion witness (Section 9A.2).
    # A TransactionRecord is bilateral (Section 9.3), so a session whose
    # counterparty signed an acceptance completes with one, and a session whose
    # counterparty signed nothing completes through the external commitment the
    # deal produced (Section 9A.12). That second case is NOT the same as "the
    # responder is observed": a mandate-only counterparty is DID-bearing and
    # still signs no act, so the witness is keyed on the reference the caller
    # supplies rather than on the responder's identity shape.
    reference = None
    if external_commitment_reference is not None:
        if outcome != SessionState.COMPLETED:
            raise ValueError("external_commitment_reference is only for a COMPLETED session")
        reference = _validated_external_commitment_reference(external_commitment_reference)
    elif outcome == SessionState.COMPLETED and observed_responder is not None:
        raise ValueError(
            "A COMPLETED session with an observed responder requires "
            "external_commitment_reference, because a TransactionRecord is bilateral"
        )

    # Every recorded act states the wire version it was signed under, the
    # session's negotiated version (Sections 7.3.1 and 9A.3), whether it is one
    # of the session's own acts or an observed one, so the record can be verified
    # by an implementation that has since moved to another. For a signed act the
    # value checks itself, since a wrong one fails the signature; for an unsigned
    # observation it only frames the act. An act that already states one keeps it.
    wire_version = negotiated_protocol_version(session._session_init, session._session_ack)
    acts = [
        _normalize_evidence_act(
            _stating_wire_version(message, wire_version), default_source_protocol="a2cn"
        )
        for message in session._message_log
    ]
    acts.extend(
        _normalize_evidence_act(
            _stating_wire_version(observed, wire_version), default_source_protocol=None
        )
        for observed in (observed_acts or [])
    )
    acts = _order_evidence_acts(acts)

    terminal_timestamp = _terminal_timestamp(session)
    transaction_record_hash = None
    if outcome == SessionState.COMPLETED and reference is None:
        transaction_record_hash = generate_transaction_record(session)["record_hash"]

    act_chain_hash = hash_bytes(canonicalize([entry["act_hash"] for entry in acts]))
    evidence_level = _classify_evidence_level(
        acts,
        outcome=outcome,
        parties=parties,
        external_commitment=reference is not None,
    )

    record = {
        "record_type": SESSION_EVIDENCE_RECORD_TYPE,
        "record_version": SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
        "evidence_id": str(
            uuid.uuid5(
                A2CN_NAMESPACE,
                f"session-evidence:{session.session_id}:{producer['did']}",
            )
        ),
        "session_id": session.session_id,
        "generated_at": terminal_timestamp,
        "producer": producer,
        "parties": parties,
        "terminal": {
            "outcome": outcome,
            "reason": reason,
            "message_id": session.terminal_message_id or None,
            "timestamp": terminal_timestamp,
        },
        "transaction_record_hash": transaction_record_hash,
        "acts": acts,
        "act_chain_hash": act_chain_hash,
        "evidence_level": evidence_level,
        "record_hash": "",
        "producer_signature": "",
    }
    if terminal_money_basis is not None:
        record["terminal"]["money_basis"] = copy.deepcopy(dict(terminal_money_basis))
    if extensions is not None:
        record["extensions"] = _validated_extensions(extensions)
    if reference is not None:
        record["external_commitment_reference"] = reference

    # Refuse to seal a claim the verifier would reject. The generator and the
    # verifier run the same rules so a producer cannot emit a record that only
    # fails once it is somebody else's problem.
    if not _money_basis_claims_verify(record):
        raise ValueError(
            "money_basis does not recompute to the claimed and signed totals, "
            "or contradicts the currency or basis of the act it describes"
        )
    if not _observed_responder_rules_hold(record):
        raise ValueError(
            "An observed responder requires unsigned counterparty acts and "
            "unilateral evidence"
        )
    if not _completion_witness_holds(record):
        raise ValueError(
            "A COMPLETED record carries exactly one completion witness, and no "
            "other outcome carries one"
        )
    if not _responder_signed_only_negotiation(record):
        raise ValueError(
            "An external commitment reference admits a responder signature only on "
            "an offer or counteroffer: a responder-signed acceptance, rejection or "
            "withdrawal is not negotiation"
        )
    if not _external_commitment_rules_hold(record):
        raise ValueError(
            "An external commitment reference requires that every signed act is a "
            "session party's, and unilateral or mixed evidence"
        )
    if not _no_acceptance_of_responder_signed_act(record):
        raise ValueError(
            "An external commitment reference refuses an acceptance that accepts an "
            "offer or counteroffer the responder signed, or whose accepted act is not "
            "in the record once the responder signed an act: the record must not "
            "attest an in-band acceptance of a responder-signed act"
        )
    # _external_commitment_matches_version_0_3 was checked here, and is not any
    # more. It cannot fire on anything this function builds: record_version is
    # assigned SESSION_EVIDENCE_RECORD_VERSION_CURRENT once, unconditionally,
    # above, and nothing mutates it in between, so the predicate always returns
    # at its `version == CURRENT` branch. Its message ("record_version must be
    # 0.3 exactly when the record carries external_commitment_reference") also
    # states a rule that no longer holds for an emitted record, which is worse
    # than merely unreachable.
    #
    # The predicate itself is NOT dead -- the verifier still calls it, where it
    # governs stored records below the floor. And this call site becomes live
    # again the moment emission stops being UNIVERSAL -- that is, the moment
    # record_version comes to depend on what the record contains. The condition
    # is universality, NOT any particular version number.
    #
    # That distinction is load-bearing and this file has now paid for it twice.
    # An earlier wording said "the moment emission stops being universally
    # 0.4", which the move to "0.5" satisfies LITERALLY while leaving this site
    # exactly as dead as it was: emission stayed universal and the assignment
    # above stayed unconditional. A condition written as a version number goes
    # stale the moment the version moves; a condition written as the property
    # it means does not. The same literal-for-semantic substitution is what
    # made the two version rules below contradict their own docstrings.
    #
    # So if a later change makes the emitted version conditional, this site
    # needs a guard AND A NEW MESSAGE, because the old one asserted a rule that
    # is no longer true of anything we emit -- restoring it verbatim would be
    # worse than the deletion it undoes. An unreachable guard is merely dead; a
    # guard whose failure message states a false rule misleads whoever revives
    # it.
    if not _external_commitment_producer_act_present(record):
        raise ValueError(
            "An external commitment reference requires at least one act signed by "
            "the initiator that seals the record"
        )
    if not _external_commitment_sealed_by_initiator(record):
        raise ValueError(
            "An external-channel record must be sealed by parties.initiator.did"
        )
    if not _bilateral_witness_matches_responder(record):
        raise ValueError(
            "A transaction_record_hash requires a DID-bearing responder, and this "
            "session has none"
        )

    record["record_hash"] = hash_object(record)
    record["producer_signature"] = sign_jws(
        record["record_hash"],
        producer_private_key,
        kid=producer_verification_method,
    )
    return record


def verify_session_evidence_record(record: dict, did_resolver: DidResolver) -> bool:
    """Return true when the record seal, hashes, and every claimed signature verify.

    A true result does not mean every named party signed every act. Callers should
    inspect ``evidence_level`` and each act's ``attribution`` field.
    """
    return assess_session_evidence_record(record, did_resolver)["valid"]


def assess_session_evidence_record(record: dict, did_resolver: DidResolver) -> dict:
    """Return verification status and signed/unsigned act counts."""
    assessment = {
        "valid": False,
        "evidence_level": record.get("evidence_level"),
        "verified_acts": 0,
        "unsigned_acts": 0,
        "invalid_acts": 0,
    }

    try:
        if not _evidence_record_shape_valid(record):
            return assessment
        if record.get("record_type") != SESSION_EVIDENCE_RECORD_TYPE:
            return assessment
        if record.get("record_version") not in RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS:
            return assessment
        if not _decline_vocabulary_requires_0_4(record):
            return assessment
        if not _external_commitment_matches_version_0_3(record):
            return assessment

        terminal = record["terminal"]
        outcome = terminal["outcome"]
        if outcome not in _EVIDENCE_TERMINAL_OUTCOMES:
            return assessment
        if record["generated_at"] != terminal["timestamp"]:
            return assessment
        _timestamp_order_key(record["generated_at"])
        _timestamp_order_key(terminal["timestamp"])
        if not _completion_witness_holds(record):
            return assessment

        producer = record["producer"]
        producer_did = producer["did"]
        producer_verification_method = producer["verification_method"]
        if not _verification_method_controlled_by(producer_verification_method, producer_did):
            return assessment

        expected_evidence_id = str(
            uuid.uuid5(
                A2CN_NAMESPACE,
                f"session-evidence:{record['session_id']}:{producer_did}",
            )
        )
        if record.get("evidence_id") != expected_evidence_id:
            return assessment

        acts = record["acts"]
        if not isinstance(acts, list) or not _evidence_acts_are_ordered(acts):
            return assessment

        computed_act_hashes: list[str] = []
        for entry in acts:
            act_valid, attribution = _verify_evidence_act(
                entry,
                session_id=record["session_id"],
                did_resolver=did_resolver,
            )
            if attribution == ATTRIBUTION_VERIFIED:
                if act_valid:
                    assessment["verified_acts"] += 1
                else:
                    assessment["invalid_acts"] += 1
            elif attribution == ATTRIBUTION_UNSIGNED:
                assessment["unsigned_acts"] += 1
                if not act_valid:
                    assessment["invalid_acts"] += 1
            else:
                assessment["invalid_acts"] += 1

            if not act_valid:
                continue
            computed_act_hashes.append(entry["act_hash"])

        if assessment["invalid_acts"]:
            return assessment
        if not _money_basis_claims_verify(record):
            return assessment
        if not _observed_responder_rules_hold(record):
            return assessment
        if not _external_commitment_rules_hold(record):
            return assessment
        if not _no_acceptance_of_responder_signed_act(record):
            return assessment
        if not _external_commitment_producer_act_present(record):
            return assessment
        if not _external_commitment_sealed_by_initiator(record):
            return assessment
        if not _bilateral_witness_matches_responder(record):
            return assessment
        if record.get("act_chain_hash") != hash_bytes(canonicalize(computed_act_hashes)):
            return assessment

        expected_level = _classify_evidence_level(
            acts,
            outcome=outcome,
            parties=record["parties"],
            external_commitment="external_commitment_reference" in record,
        )
        if record.get("evidence_level") != expected_level:
            return assessment

        if not _evidence_record_hash_matches(record):
            return assessment

        producer_signature = record.get("producer_signature")
        if not isinstance(producer_signature, str) or not producer_signature:
            return assessment
        if not _verify_signature(
            did_resolver,
            did=producer_did,
            verification_method=producer_verification_method,
            signature=producer_signature,
            expected_payload=record["record_hash"],
        ):
            return assessment

        assessment["valid"] = True
        return assessment
    except Exception:
        return assessment


def _party_metadata(
    session: Session,
    *,
    observed_responder: Mapping[str, Any] | None = None,
) -> dict:
    session_init = session._session_init or {}
    session_ack = session._session_ack or {}
    if not isinstance(session_init, Mapping) or not isinstance(session_ack, Mapping):
        raise ValueError("Session initialization metadata must be objects")
    initiator_info = session_init.get("initiator", {})
    responder_info = session_ack.get("responder", {})
    initiator_mandate = session.initiator_mandate
    responder_mandate = session.responder_mandate
    for field_name, value in (
        ("initiator", initiator_info),
        ("responder", responder_info),
        ("initiator_mandate", initiator_mandate),
        ("responder_mandate", responder_mandate),
    ):
        if not isinstance(value, Mapping):
            raise ValueError(f"{field_name} must be an object")

    def party_string(info: Mapping[str, Any], field_name: str) -> str:
        value = info.get(field_name, "")
        if not isinstance(value, str):
            raise ValueError(f"Party {field_name} must be a string")
        return value

    responder = (
        _observed_party_metadata(responder_info, responder_mandate, observed_responder)
        if observed_responder is not None
        else {
            "organization_name": party_string(responder_info, "organization_name"),
            "did": party_string(responder_info, "did"),
            "agent_id": party_string(responder_info, "agent_id"),
            "verification_method": party_string(responder_info, "verification_method"),
            "mandate_type": party_string(responder_mandate, "mandate_type"),
        }
    )
    return {
        "initiator": {
            "organization_name": party_string(initiator_info, "organization_name"),
            "did": party_string(initiator_info, "did"),
            "agent_id": party_string(initiator_info, "agent_id"),
            "verification_method": party_string(initiator_info, "verification_method"),
            "mandate_type": party_string(initiator_mandate, "mandate_type"),
        },
        "responder": responder,
    }


def _observed_party_metadata(
    responder_info: Mapping[str, Any],
    responder_mandate: Mapping[str, Any],
    observed_responder: Mapping[str, Any],
) -> dict:
    """Assemble an identity-light responder from what the caller supplies.

    Every field is a producer assertion. No DID is derived, defaulted, or
    fabricated here, and the session must not already carry the A2CN identity
    this descriptor claims is absent.
    """
    if not isinstance(observed_responder, Mapping):
        raise ValueError("observed_responder must be an object")
    for field_name, marker in (
        ("did", "a DID"),
        ("endpoint", "an A2CN endpoint"),
        ("verification_method", "a verification method"),
    ):
        declared = responder_info.get(field_name)
        if isinstance(declared, str) and declared:
            raise ValueError(
                f"Responder declared {marker}; it is not an observed party"
            )
    if responder_mandate.get("mandate_type"):
        raise ValueError("Responder declared a mandate; it is not an observed party")

    identity_source = observed_responder.get("identity_source")
    if not isinstance(identity_source, str) or not identity_source:
        raise ValueError("observed_responder requires a non-empty identity_source")

    party = {
        "identity_source": identity_source,
        "did_declared": False,
        "a2cn_endpoint_declared": False,
        "mandate_declared": False,
    }
    organization_name = observed_responder.get("organization_name")
    if organization_name is not None:
        if not isinstance(organization_name, str):
            raise ValueError("observed_responder organization_name must be a string")
        party["organization_name"] = organization_name
    credential = observed_responder.get("observed_credential")
    if credential is not None:
        if not isinstance(credential, Mapping) or set(credential) != {"type", "digest"}:
            raise ValueError("observed_credential requires exactly type and digest")
        credential_type = credential["type"]
        digest = credential["digest"]
        if not isinstance(credential_type, str) or not credential_type:
            raise ValueError("observed_credential type must be a non-empty string")
        if not isinstance(digest, str) or not _HASH_PATTERN.fullmatch(digest):
            raise ValueError("observed_credential digest must be a base64url SHA-256")
        party["observed_credential"] = {"type": credential_type, "digest": digest}
    return party


def _validated_extensions(extensions: Mapping[str, Any]) -> dict:
    """Namespaced producer extensions. Never interpreted, only namespaced."""
    if not isinstance(extensions, Mapping):
        raise ValueError("extensions must be an object")
    for name in extensions:
        if not isinstance(name, str) or not _EXTENSION_NAMESPACE_PATTERN.fullmatch(name):
            raise ValueError(f"extensions keys must be namespaced: {name!r}")
    return copy.deepcopy(dict(extensions))


def _validated_external_commitment_reference(reference: Any) -> dict:
    """The caller's external commitment reference, checked and copied before sealing."""
    if not isinstance(reference, Mapping):
        raise ValueError("external_commitment_reference must be an object")
    copied = copy.deepcopy(dict(reference))
    if not _external_commitment_reference_shape_valid(copied):
        raise ValueError(
            "external_commitment_reference must be an object with a non-empty string "
            "external_commitment_id, an optional non-empty string locator, an optional "
            "string reference_note, and no other member"
        )
    return copied


def _exact_fields(
    value: Any,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> bool:
    if not isinstance(value, dict):
        return False
    present = set(value)
    return required <= present <= (required | optional)


def _evidence_record_shape_valid(record: dict) -> bool:
    if not _exact_fields(record, _RECORD_FIELDS, _RECORD_OPTIONAL_FIELDS):
        return False
    if "extensions" in record:
        extensions = record["extensions"]
        if not isinstance(extensions, dict):
            return False
        if not all(
            isinstance(name, str) and _EXTENSION_NAMESPACE_PATTERN.fullmatch(name)
            for name in extensions
        ):
            return False
    if "external_commitment_reference" in record and not (
        _external_commitment_reference_shape_valid(record["external_commitment_reference"])
    ):
        return False
    if not all(
        isinstance(record.get(field), str) and record[field]
        for field in (
            "record_type",
            "record_version",
            "evidence_id",
            "session_id",
            "generated_at",
            "act_chain_hash",
            "evidence_level",
            "record_hash",
            "producer_signature",
        )
    ):
        return False
    if record["evidence_level"] not in {
        EVIDENCE_BILATERAL,
        EVIDENCE_MIXED,
        EVIDENCE_UNILATERAL,
    }:
        return False
    if not _HASH_PATTERN.fullmatch(record["act_chain_hash"]):
        return False
    if not _HASH_PATTERN.fullmatch(record["record_hash"]):
        return False

    producer = record.get("producer")
    if not isinstance(producer, dict) or set(producer) != {
        "did",
        "agent_id",
        "verification_method",
    }:
        return False
    if not isinstance(producer.get("did"), str) or not producer["did"].startswith("did:"):
        return False
    if not isinstance(producer.get("agent_id"), str):
        return False
    if not isinstance(producer.get("verification_method"), str) or not producer[
        "verification_method"
    ]:
        return False

    parties = record.get("parties")
    if not isinstance(parties, dict) or set(parties) != {"initiator", "responder"}:
        return False
    # The producer is a DID-bearing party, so the initiator side stays strict.
    # Only the responder may be identity-light.
    if not _full_party_shape_valid(parties["initiator"]):
        return False
    if not (
        _full_party_shape_valid(parties["responder"])
        or _observed_party_shape_valid(parties["responder"])
    ):
        return False

    terminal = record.get("terminal")
    if not _exact_fields(terminal, _TERMINAL_FIELDS, _TERMINAL_OPTIONAL_FIELDS):
        return False
    if not isinstance(terminal.get("outcome"), str):
        return False
    if terminal.get("reason") is not None and not isinstance(terminal["reason"], str):
        return False
    if terminal.get("message_id") is not None and not isinstance(
        terminal["message_id"], str
    ):
        return False
    if not isinstance(terminal.get("timestamp"), str) or not terminal["timestamp"]:
        return False

    transaction_record_hash = record.get("transaction_record_hash")
    if transaction_record_hash is not None and (
        not isinstance(transaction_record_hash, str)
        or not _HASH_PATTERN.fullmatch(transaction_record_hash)
    ):
        return False
    return isinstance(record.get("acts"), list)


def _full_party_shape_valid(party: Any) -> bool:
    if not _exact_fields(party, _PARTY_FIELDS):
        return False
    if not all(isinstance(party.get(field), str) for field in _PARTY_FIELDS):
        return False
    return party["did"].startswith("did:") and bool(party["verification_method"])


def _observed_party_shape_valid(party: Any) -> bool:
    """Shape of an identity-light counterparty descriptor.

    This checks structure and the explicit negative markers, and nothing else.
    A verifier MUST NOT resolve ``identity_source``, look it up in any registry,
    or apply per-type validation to it: doing so would imply an authentication
    A2CN did not perform. There is no whitelist here by design.
    """
    if not _exact_fields(party, _OBSERVED_PARTY_FIELDS, _OBSERVED_PARTY_OPTIONAL_FIELDS):
        return False
    if not isinstance(party.get("identity_source"), str) or not party["identity_source"]:
        return False
    if any(party.get(marker) is not False for marker in _OBSERVED_PARTY_MARKERS):
        return False
    if "organization_name" in party and not isinstance(
        party["organization_name"], str
    ):
        return False
    if "observed_credential" in party:
        credential = party["observed_credential"]
        if not _exact_fields(credential, frozenset({"type", "digest"})):
            return False
        if not isinstance(credential["type"], str) or not credential["type"]:
            return False
        if not isinstance(credential["digest"], str) or not _HASH_PATTERN.fullmatch(
            credential["digest"]
        ):
            return False
    return True


def _observed_responder_rules_hold(record: dict) -> bool:
    """Couple an identity-light responder to unsigned acts and unilateral evidence.

    A2CN authenticates DID-bearing parties. When the responder holds no DID there
    is no key any counterparty act could be checked against, so the initiator is
    the only party that may carry a verified signature in such a record. A
    responder claiming ``verified_signature`` is rejected outright rather than
    downgraded.
    """
    parties = record.get("parties")
    if not isinstance(parties, dict):
        return False
    if not _observed_party_shape_valid(parties.get("responder")):
        return True

    initiator = parties.get("initiator")
    if not isinstance(initiator, dict):
        return False
    initiator_did = initiator.get("did")
    acts = record.get("acts")
    if not isinstance(acts, list):
        return False
    for entry in acts:
        if not isinstance(entry, dict):
            return False
        if entry.get("attribution") != ATTRIBUTION_VERIFIED:
            continue
        if entry.get("sender_did") != initiator_did:
            return False
    # Asserted explicitly rather than inherited from the classifier, so that a
    # future change to classification cannot quietly promote these records.
    return record.get("evidence_level") == EVIDENCE_UNILATERAL


def _external_commitment_reference_shape_valid(reference: Any) -> bool:
    """Shape of the external order or commitment a COMPLETED session produced.

    This checks structure and types, and nothing else (Section 9A.12). The
    locator is provenance only: a verifier MUST NOT dereference it or contact
    the counterparty, so it is checked as a non-empty string and no further. A
    member present with the value null is malformed, never read as absent.
    """
    if not _exact_fields(
        reference,
        _EXTERNAL_COMMITMENT_REFERENCE_FIELDS,
        _EXTERNAL_COMMITMENT_REFERENCE_OPTIONAL_FIELDS,
    ):
        return False
    commitment_id = reference["external_commitment_id"]
    if not isinstance(commitment_id, str) or not commitment_id:
        return False
    if "locator" in reference and (
        not isinstance(reference["locator"], str) or not reference["locator"]
    ):
        return False
    return "reference_note" not in reference or isinstance(reference["reference_note"], str)


def _completion_witness_holds(record: dict) -> bool:
    """A COMPLETED record carries exactly one completion witness (Section 9A.2).

    The witness is a transaction_record_hash, for the bilateral TransactionRecord,
    or an external_commitment_reference with a null transaction_record_hash
    (Section 9A.12): never both, and never neither. Every other outcome carries
    neither. The reference is present by key, whatever its value.
    """
    has_reference = "external_commitment_reference" in record
    transaction_record_hash = record.get("transaction_record_hash")
    if record["terminal"]["outcome"] == SessionState.COMPLETED:
        if has_reference:
            return transaction_record_hash is None
        return isinstance(transaction_record_hash, str) and bool(transaction_record_hash)
    return transaction_record_hash is None and not has_reference


def _external_commitment_rules_hold(record: dict) -> bool:
    """Who may hold the external witness, at what level, and who may sign in it.

    The reference is the completion witness of a session that produced no
    TransactionRecord (Section 9A.12). The property it carries is that NO
    COUNTERPARTY SIGNATURE WITNESSES THE COMPLETION: the completion is the
    producer's external-order reference, not an act the counterparty signed.

    Until "0.5" this asserted ``observed_party`` and ``unilateral``. That pair is
    an IDENTITY PROXY for the property and is narrower than it: written for the
    no-DID case, it incidentally excluded a verified-identity counterparty, a
    shape an ``observed_party`` cannot even express, since that descriptor
    requires the declared-markers to be literally False. The proxy is relaxed to
    the property here, and BECAUSE it is relaxed, the property has to be CHECKED.
    This function decides who may sign, and what the responder may sign;
    ``_no_acceptance_of_responder_signed_act`` decides what an acceptance may
    name.

    The property is about the completion, not every act. A counterparty that
    signed a counteroffer negotiated; it completed nothing, and no
    TransactionRecord exists for that session. So a verified act is admitted from
    either SESSION PARTY -- ``_every_verified_act_is_a_session_partys`` carries
    the argument for why a third party is not -- and the responder's only as
    negotiation, ``_responder_signed_only_negotiation``.

    ``evidence_level`` was a SECOND identity proxy on the same property, and it
    is relaxed for the same reason. ``unilateral`` and ``mixed`` both describe a
    record whose completion no counterparty signed; which one a record carries
    depends on what the producer recorded, not on the honesty of the record:

    * ``unilateral`` when no act carries a verified counterparty perspective,
      for instance an observed act with no ``sender_did``;
    * ``mixed`` when the counterparty is represented -- its verified DID on an
      act attributed ``unsigned_observation``, or its signed negotiation act.

    BOTH ARE HONEST RECORDS. Admitting only ``unilateral`` would require a
    producer to omit evidence it holds in order to reach a classification.

    ``bilateral`` stays excluded, which is why this checks membership rather
    than merely "not bilateral": that level asserts both parties' material acts
    are attributable, the completion included, which is precisely the claim a
    session completing through an external reference cannot make. The
    classifier never returns it for such a record (``_classify_evidence_level``),
    so this refuses only a record that CLAIMS it.

    The DID-bearing responder is admitted from "0.5" and not before, because
    "0.5" is the first version whose schema admits it; "0.3" and "0.4" require an
    ``observed_party`` there. Without the floor, a "0.5" record relabelled to
    either and resealed would verify while its own version's schema refused it.
    The ``observed_party`` responder needs no floor of its own here: the
    reference itself is refused below "0.3" by the version-keyed witness rule.
    """
    if "external_commitment_reference" not in record:
        return True
    parties = record.get("parties")
    if not isinstance(parties, dict):
        return False
    responder = parties.get("responder")
    if _full_party_shape_valid(responder):
        if not _version_at_or_after(
            record.get("record_version"), _VERSION_ADMITTING_VERIFIED_EXTERNAL_RESPONDER
        ):
            return False
    elif not _observed_party_shape_valid(responder):
        return False
    if record.get("evidence_level") not in (EVIDENCE_MIXED, EVIDENCE_UNILATERAL):
        return False
    if not _every_verified_act_is_a_session_partys(record):
        return False
    return _responder_signed_only_negotiation(record)


def _external_session_dids(parties: dict) -> tuple[str, str | None] | None:
    """The initiator's DID and the responder's, or None if the initiator has none.

    The responder contributes a DID only when it is a full party. An
    ``observed_party`` holds no A2CN identity, so it has none to contribute and
    a verified act can never be its (Section 9A.8 rule 1).
    """
    initiator = parties.get("initiator")
    if not isinstance(initiator, dict):
        return None
    initiator_did = initiator.get("did")
    if not isinstance(initiator_did, str) or not initiator_did:
        # Section 9A.2 requires a DID-bearing initiator, so this record is
        # refused elsewhere too; refusing here keeps the rules from passing
        # vacuously on a record with no initiator to compare against.
        return None
    responder = parties.get("responder")
    responder_did = responder["did"] if _full_party_shape_valid(responder) else None
    return initiator_did, responder_did


def _every_verified_act_is_a_session_partys(record: dict) -> bool:
    """Section 9A.8 rule 1, for every external-channel record rather than some.

    Every act attributed ``verified_signature`` carries a ``sender_did`` equal
    to ``parties.initiator.did`` or ``parties.responder.did`` -- "an act that
    cannot be placed in a known role is refused rather than admitted".
    Section 9A.8 states that for an ``observed_party`` responder, where only the
    initiator holds a DID; it holds for the DID-bearing responder too, so the
    SAME verified third-party act is refused whichever identity tier the
    counterparty is at.

    WHY A THIRD PARTY IS REFUSED rather than merely not counted. Section 9A.5
    declines to COUNT a non-party's act towards ``mixed``, but that is
    classification, not admission. A producer naming one organisational DID as
    ``parties.responder`` while the counterparty signs under an agent or delegate
    DID could otherwise carry a verified counterparty signature -- an acceptance
    included -- past every rule keyed on the responder.

    THE COMPARISON IS EXACT, with no DID normalization. ``sender_did`` has no
    imposed syntax (Section 9A.6), and ``did:web:acme-corp.com#key-2026-01`` is
    a different string from ``did:web:acme-corp.com`` while
    ``_verification_method_controlled_by`` accepts it and a resolver that
    dereferences DID URLs resolves it. Treating the two as equal would make
    admission a property of the CALLER'S resolver. So a DID URL naming either
    party's own key is neither party's DID, and is refused.

    Stated positively, so the rule is a property of the whole act list rather
    than a search for one bad entry: an act list with nothing verified satisfies
    it vacuously, and ``_external_commitment_producer_act_present`` is what
    refuses that record.
    """
    parties = record.get("parties")
    if not isinstance(parties, dict):
        return False
    session_dids = _external_session_dids(parties)
    if session_dids is None:
        return False
    initiator_did, responder_did = session_dids
    acts = record.get("acts")
    if not isinstance(acts, list):
        return False
    return all(
        isinstance(entry, dict)
        and (
            entry.get("attribution") != ATTRIBUTION_VERIFIED
            or entry.get("sender_did") == initiator_did
            or (responder_did is not None and entry.get("sender_did") == responder_did)
        )
        for entry in acts
    )


def _responder_signed_only_negotiation(record: dict) -> bool:
    """In an external-channel record the responder signs negotiation, and nothing else.

    Section 9A.12: an act attributed ``verified_signature`` whose ``sender_did``
    is ``parties.responder.did`` (exact) has ``message_type`` ``offer`` or
    ``counteroffer``. A responder-signed acceptance is a completion the
    counterparty signed, which is a TransactionRecord rather than an external
    witness; a responder-signed rejection or withdrawal is the counterparty's
    signed refusal, which cannot sit in a record stating that the session
    completed. Either way a counterparty signature would bear on the completion
    the reference alone is supposed to witness.

    A third party's verified act never reaches this rule's question: the
    session-party check refuses it first. An ``observed_party`` responder holds
    no DID, so it signs nothing and the rule holds vacuously.
    """
    if "external_commitment_reference" not in record:
        return True
    parties = record.get("parties")
    if not isinstance(parties, dict):
        return False
    session_dids = _external_session_dids(parties)
    if session_dids is None:
        return False
    _initiator_did, responder_did = session_dids
    acts = record.get("acts")
    if not isinstance(acts, list):
        return False
    if responder_did is None:
        return True
    return all(
        not isinstance(entry, dict)
        or entry.get("attribution") != ATTRIBUTION_VERIFIED
        or entry.get("sender_did") != responder_did
        or entry.get("message_type") in _NEGOTIATION_MESSAGE_TYPES
        for entry in acts
    )


def _negotiation_act_hashes(act: dict) -> list[str]:
    """The hashes an acceptance may name an offer or counteroffer by.

    An offer's ``protocol_act_hash`` IS the hash of its signed act (Section
    7.3.1), so an act is named by the hash it states and by the hash of its
    rebuild; for a verified offer the two are equal, because the verifier has
    already refused one whose stated hash differs from its rebuild. An unsigned
    observation may state neither, and is then named by its rebuild alone.
    """
    hashes = []
    stated = act.get("protocol_act_hash")
    if isinstance(stated, str) and stated:
        hashes.append(stated)
    try:
        rebuilt = rebuild_signed_act(act)
        if rebuilt is not None:
            hashes.append(hash_object(rebuilt))
    except Exception:  # an act that cannot be rebuilt is named by nothing else
        pass
    return hashes


def _no_acceptance_of_responder_signed_act(record: dict) -> bool:
    """No act in an external-channel record accepts an act the responder signed.

    Section 9A.12: an external-channel record MUST NOT attest an in-band
    acceptance of an act the responder signed. Out-of-band reconstruction is not
    what this prevents: a keyholder can always sign its own acceptance of a
    responder-signed counteroffer elsewhere, which admitting a counterparty's
    signed negotiation act concedes. The record attests what was recorded
    in-band, and this rule bounds that. An act
    ACCEPTS when its ``message_type`` is ``acceptance`` or its inner act carries
    ``accepted_protocol_act_hash`` or ``accepted_offer_id`` -- whatever its
    type and whether or not it is signed, because nothing constrains an unsigned
    act's ``message_type`` and a target field is what makes an act an
    acceptance of something. For each such act:

    * if its ``accepted_protocol_act_hash`` names, or its ``accepted_offer_id``
      is the ``message_id`` of, an ``offer`` or ``counteroffer`` the responder
      signed, the record is refused -- either field is enough, so a crossed pair
      cannot hide one behind the other;
    * once the responder has any verified act, each target field it carries
      must resolve EXACTLY to an offer or counteroffer in the record, the hash
      written as a canonical 43-character base64url digest; an ``acceptance``
      carrying no hash, a target in another spelling or encoding, or one naming
      nothing in the record is refused (fail-closed): nothing shows it does not
      accept a signed act the producer left out.

    Keyed on the ACCEPTED act, not on the acceptance's own signature. An
    acceptance recorded unsigned still names what it accepted, and is still an
    acceptance the record attests in-band, so a rule that asked whether the
    acceptance was signed would admit exactly the record it exists to refuse.

    The hash is resolved the way the TransactionRecord binds it: the
    acceptance's ``accepted_protocol_act_hash`` against an offer's
    ``protocol_act_hash`` (``record.py``; the session does the same), which is
    the hash of the offer's signed act (``_negotiation_act_hashes``). Membership
    in the responder-signed sets is checked FIRST, so an unsigned duplicate or
    forgery claiming a signed act's ``message_id`` or hash can never launder an
    acceptance of the signed one by giving its target somewhere else to
    resolve.

    What stays admitted: an acceptance -- the initiator's, typically signed --
    of an offer the counterparty did not sign, beside any negotiation either
    party signed. The record then attests no in-band acceptance of a
    responder-signed act.
    """
    if "external_commitment_reference" not in record:
        return True
    parties = record.get("parties")
    if not isinstance(parties, dict):
        return False
    session_dids = _external_session_dids(parties)
    if session_dids is None:
        return False
    _initiator_did, responder_did = session_dids
    acts = record.get("acts")
    if not isinstance(acts, list):
        return False
    if responder_did is None:
        return True
    entries = [entry for entry in acts if isinstance(entry, dict)]
    responder_signed = any(
        entry.get("attribution") == ATTRIBUTION_VERIFIED
        and entry.get("sender_did") == responder_did
        for entry in entries
    )
    if not responder_signed:
        return True
    signed_hashes, signed_ids, recorded_hashes, recorded_ids = [], [], [], []
    for entry in entries:
        act = entry.get("act")
        if entry.get("message_type") not in _NEGOTIATION_MESSAGE_TYPES or not isinstance(act, dict):
            continue
        hashes = _negotiation_act_hashes(act)
        message_id = act.get("message_id")
        ids = [message_id] if isinstance(message_id, str) and message_id else []
        recorded_hashes.extend(hashes)
        recorded_ids.extend(ids)
        if (
            entry.get("attribution") == ATTRIBUTION_VERIFIED
            and entry.get("sender_did") == responder_did
        ):
            signed_hashes.extend(hashes)
            signed_ids.extend(ids)
    for entry in entries:
        act = entry.get("act")
        if not isinstance(act, dict):
            if entry.get("message_type") == "acceptance":
                return False
            continue
        has_hash = "accepted_protocol_act_hash" in act
        has_id = "accepted_offer_id" in act
        if entry.get("message_type") != "acceptance" and not has_hash and not has_id:
            continue
        target_hash = act.get("accepted_protocol_act_hash")
        target_id = act.get("accepted_offer_id")
        if target_hash in signed_hashes or target_id in signed_ids:
            return False
        if not has_hash:
            return False
        if not (
            isinstance(target_hash, str)
            and _HASH_PATTERN.fullmatch(target_hash)
            and target_hash in recorded_hashes
        ):
            return False
        if has_id and not (isinstance(target_id, str) and target_id in recorded_ids):
            return False
    return True


def _version_at_or_after(version: Any, floor: str) -> bool:
    """Whether a recognized ``record_version`` is ``floor`` or later.

    Ordered by position in RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS, which is
    published order. A value this verifier does not recognize is never "later":
    it is refused elsewhere, and treating an unknown label as later would let it
    inherit the newest rules merely by being unfamiliar.
    """
    versions = RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS
    if version not in versions:
        return False
    return versions.index(version) >= versions.index(floor)


def _external_commitment_matches_version_0_3(record: dict) -> bool:
    """A "0.3" record carries external_commitment_reference exactly when it is "0.3".

    A historical rule, kept so "0.3" records still read as they always did.
    From the floor on ("0.4" and later) there is no version-keyed witness rule
    at all: the reference is OPTIONAL there, and Section 9A.6 step 9's
    exactly-one-witness rule — which holds at every record_version and is
    enforced independently of any version — carries the weight instead. Keeping
    the biconditional above the floor would refuse every external-channel
    record, since it would demand the version be "0.3" to carry a reference.

    Read as a FLOOR, not as equality against the current version. Written as
    ``version == CURRENT``, this refused every stored "0.4" external-channel
    record the moment CURRENT became "0.5": such a record fell through to the
    biconditional, which demands "0.3", and was rejected. That break was
    invisible to both suites, because the only stored-record pin was at "0.3".

    The reference is present by key, so one whose value is null counts as
    carried.
    """
    version = record.get("record_version")
    if _version_at_or_after(version, _VERSION_WITHOUT_VERSION_KEYED_WITNESS_RULE):
        return True
    carried = "external_commitment_reference" in record
    return carried == (version == SESSION_EVIDENCE_RECORD_VERSION_WITH_EXTERNAL_COMMITMENT)


def _decline_vocabulary_requires_0_4(record: dict) -> bool:
    """An act carrying a decline signature makes the record "0.4" or later.

    ONE-DIRECTIONAL, and the direction matters: the vocabulary implies the
    version, never the reverse. An ordinary record at or above the floor carries
    no decline at all, so this must not be read as the version implying the
    vocabulary.

    Keyed on ``signature_type`` rather than on the presence of a signature field
    inside ``acts[].act``. That object is open, so a field there violates no
    published schema and a rule keyed on it would refuse a record that is
    perfectly valid at its own version -- an old record may legitimately carry a
    vendor field of that name, since the decline schemas keep the message object
    open. ``signature_type`` is coextensive with the schema violation instead:
    the enum is the only place an earlier version's schema names the vocabulary.

    NOTE the polarity, which is the opposite of the rule above: that one goes
    quiet at the floor and governs only historical records; this one fires only
    below the floor and governs only new vocabulary. Both floors are "0.4" and
    both are read through ``_version_at_or_after``, rather than written as the
    set of versions that happened to exist when this was written -- as the
    literal ``frozenset({"0.4"})`` this refused a "0.5" record for carrying a
    decline that "0.5" admits, while the first line of this docstring already
    said "or later". The prose was right and the code was wrong.
    """
    acts = record.get("acts")
    if not isinstance(acts, list):
        return True  # shape is decided elsewhere; this rule judges vocabulary
    carries_decline = any(
        isinstance(entry, dict) and entry.get("signature_type") in _DECLINE_SIGNATURE_TYPES
        for entry in acts
    )
    if not carries_decline:
        return True
    return _version_at_or_after(
        record.get("record_version"), _VERSION_ADMITTING_DECLINE_VOCABULARY
    )


def _bilateral_witness_matches_responder(record: dict) -> bool:
    """A transaction_record_hash requires a DID-bearing responder (Section 9A.2).

    A TransactionRecord is bilateral by construction (Section 9.3), so a session
    whose responder is an observed_party has none, and a record claiming one for
    such a session is rejected at every version. Such a session completes
    through external_commitment_reference instead (Section 9A.12).
    """
    if record.get("transaction_record_hash") is None:
        return True
    parties = record.get("parties")
    if not isinstance(parties, dict):
        return False
    return _full_party_shape_valid(parties.get("responder"))


def _external_commitment_producer_act_present(record: dict) -> bool:
    """An external-channel record carries at least one act its initiator signed.

    The counterparty attests to nothing in such a record (Section 9A.12). With
    no signed act of the producer's own, nothing in it would be attributable to
    any party, and the seal alone would carry the COMPLETED claim.
    """
    if "external_commitment_reference" not in record:
        return True
    parties = record.get("parties")
    if not isinstance(parties, dict):
        return False
    initiator = parties.get("initiator")
    if not isinstance(initiator, dict):
        return False
    acts = record.get("acts")
    if not isinstance(acts, list):
        return False
    return any(
        isinstance(entry, dict)
        and entry.get("attribution") == ATTRIBUTION_VERIFIED
        and entry.get("sender_did") == initiator.get("did")
        for entry in acts
    )


def _external_commitment_sealed_by_initiator(record: dict) -> bool:
    """An external-channel record is sealed by its initiator (Section 9A.12).

    The producer's seal is the only cryptographic evidence such a record holds,
    so the party it names as initiator is the party that must have sealed it.
    """
    if "external_commitment_reference" not in record:
        return True
    parties = record.get("parties")
    producer = record.get("producer")
    if not isinstance(parties, dict) or not isinstance(producer, dict):
        return False
    initiator = parties.get("initiator")
    if not isinstance(initiator, dict):
        return False
    return bool(producer.get("did")) and producer.get("did") == initiator.get("did")


def _decimal_to_minor(amount: Any, exponent: int) -> int | None:
    """Scale one major-unit decimal string to minor units, exactly.

    Returns ``None`` for anything finer than the stated exponent. Rounding here
    would silently alter money, so a sub-minor amount is refused instead.
    """
    if not isinstance(amount, str):
        return None
    match = _DECIMAL_AMOUNT_PATTERN.fullmatch(amount)
    if match is None:
        return None
    fraction = match.group(3) or ""
    if len(fraction) > exponent:
        return None
    value = int(match.group(2) + fraction.ljust(exponent, "0"))
    return -value if match.group(1) == "-" else value


def _money_basis_recomputes(
    money_basis: Any,
    *,
    expected_total_minor: int,
    expected_currency: str,
) -> bool:
    """Recompute the unit normalization only, and compare it with both totals.

    ``basis`` is a CHECKED LABEL. A verifier MUST NOT convert between net and
    gross: that is a tax calculation, not a normalization, and performing it
    silently corrupts money. The arithmetic below is identical for every label.
    """
    if not _exact_fields(money_basis, _MONEY_BASIS_FIELDS, _MONEY_BASIS_OPTIONAL_FIELDS):
        return False
    if money_basis["basis"] not in MONEY_BASIS_LABELS:
        return False
    currency = money_basis["currency"]
    if not isinstance(currency, str) or not _CURRENCY_PATTERN.fullmatch(currency):
        return False
    if currency != expected_currency:
        return False
    exponent = money_basis["minor_unit_exponent"]
    if isinstance(exponent, bool) or not isinstance(exponent, int):
        return False
    if not 0 <= exponent <= 4:
        return False
    claimed = money_basis["normalized_total_minor"]
    if isinstance(claimed, bool) or not isinstance(claimed, int):
        return False
    if abs(claimed) > _MAX_EXACT_INTEGER:
        return False

    # FAIL-CLOSED: a total claimed with no raw amounts behind it is unverifiable,
    # and an unverifiable claim must never read as a verified one.
    raw_amounts = money_basis.get("raw_amounts")
    if not isinstance(raw_amounts, list) or not raw_amounts:
        return False

    total = 0
    for amount in raw_amounts:
        minor = _decimal_to_minor(amount, exponent)
        if minor is None:
            return False
        total += minor
    return total == claimed == expected_total_minor


def _money_basis_binds_to_act(entry: Any, money_basis: Any) -> bool:
    """Bind a money_basis to the total inside the act it describes."""
    if not isinstance(entry, dict):
        return False
    act = entry.get("act")
    if not isinstance(act, dict):
        return False
    terms = act.get("terms")
    if not isinstance(terms, dict):
        return False
    total = terms.get("total_value")
    if isinstance(total, bool) or not isinstance(total, int):
        return False
    if abs(total) > _MAX_EXACT_INTEGER:
        return False
    currency = terms.get("currency")
    if not isinstance(currency, str):
        return False
    return _money_basis_recomputes(
        money_basis,
        expected_total_minor=total,
        expected_currency=currency,
    ) and _money_basis_label_agrees_with_act(money_basis, terms)


def _money_basis_label_agrees_with_act(money_basis: dict, terms: dict) -> bool:
    """A net or gross label must not contradict the basis the act itself states.

    This mirrors the currency rule: when the act's terms carry basis (Section
    7.2), a money_basis labelled net or gross must carry the same value. The
    other labels, and an act that states no basis, are not compared. Labels are
    compared, never converted. Called only once the money_basis has recomputed,
    so its basis is already a recognized label.
    """
    if "basis" not in terms or money_basis["basis"] not in SESSION_BASES:
        return True
    return terms["basis"] == money_basis["basis"]


def _money_basis_claims_verify(record: dict) -> bool:
    """Every money_basis in the record recomputes, or the record is rejected."""
    acts = record.get("acts")
    if not isinstance(acts, list):
        return False
    for entry in acts:
        if isinstance(entry, dict) and "money_basis" in entry:
            if not _money_basis_binds_to_act(entry, entry["money_basis"]):
                return False

    terminal = record.get("terminal")
    if not isinstance(terminal, dict) or "money_basis" not in terminal:
        return True
    # A terminal money_basis describes the terminal quote, so it must name the act
    # that carries it. An unresolvable reference is refused, not ignored.
    message_id = terminal.get("message_id")
    if not isinstance(message_id, str) or not message_id:
        return False
    quoted = [
        entry
        for entry in acts
        if isinstance(entry, dict) and entry.get("message_id") == message_id
    ]
    if len(quoted) != 1:
        return False
    return _money_basis_binds_to_act(quoted[0], terminal["money_basis"])


def _evidence_act_shape_valid(entry: dict) -> bool:
    if not _exact_fields(entry, _ACT_FIELDS, _ACT_OPTIONAL_FIELDS):
        return False
    for field in ("sequence_number", "round_number"):
        value = entry.get(field)
        # Judged by value, like every other act counter. An entry may omit a
        # counter, so null stays permitted; _is_act_integer refuses None as well
        # as a bool, hence the explicit is-not-None guard rather than folding it
        # in. Before this, the shape check refused the integral float 2.0 that
        # RFC 8785 makes identical to 2 — so an act could clear the payload-hash
        # check and still be counted invalid here, while TypeScript's
        # Number.isInteger accepted it and the two reached opposite verdicts.
        if value is not None and not (_is_act_integer(value) and value >= 1):
            return False
    if not all(
        isinstance(entry.get(field), str) and entry[field]
        for field in ("message_type", "act_hash")
    ):
        return False
    for field in ("message_id", "timestamp"):
        value = entry.get(field)
        if value is not None and (not isinstance(value, str) or not value):
            return False
    sender_did = entry.get("sender_did")
    if sender_did is None:
        # A sender with no DID is only representable as an unsigned observation.
        if entry.get("attribution") != ATTRIBUTION_UNSIGNED:
            return False
    elif not isinstance(sender_did, str) or not sender_did.startswith("did:"):
        return False
    if not _HASH_PATTERN.fullmatch(entry["act_hash"]):
        return False
    if entry.get("source_protocol") is not None and not isinstance(
        entry["source_protocol"], str
    ):
        return False
    return isinstance(entry.get("act"), dict)


def _producer_metadata(
    parties: dict,
    *,
    producer_verification_method: str,
    producer_did: str | None,
    producer_agent_id: str | None,
) -> dict:
    matching_party = next(
        (
            party
            for party in parties.values()
            if party.get("verification_method") == producer_verification_method
            or (producer_did and party.get("did") == producer_did)
        ),
        None,
    )
    resolved_did = producer_did or (matching_party or {}).get("did")
    if not resolved_did and "#" in producer_verification_method:
        resolved_did = producer_verification_method.split("#", 1)[0]
    if not resolved_did:
        raise ValueError("producer_did cannot be derived from the verification method")
    if not _verification_method_controlled_by(producer_verification_method, resolved_did):
        raise ValueError("producer_verification_method is not controlled by producer_did")

    return {
        "did": resolved_did,
        "agent_id": producer_agent_id
        if producer_agent_id is not None
        else (matching_party or {}).get("agent_id", ""),
        "verification_method": producer_verification_method,
    }


def _terminal_timestamp(session: Session) -> str:
    terminal_message = next(
        (
            message
            for message in reversed(session._message_log)
            if message.get("message_id") == session.terminal_message_id
        ),
        None,
    )
    if terminal_message and terminal_message.get("timestamp"):
        return terminal_message["timestamp"]
    if session.state_updated_at:
        return session.state_updated_at
    return _now()


def _stating_wire_version(item: Any, wire_version: str) -> Any:
    """The act as recorded: with protocol_version, which it may omit on the wire.

    An observed item may wrap its act in "act" beside the entry's metadata; the
    version belongs to the act either way. An act that states one keeps it.
    """
    if not isinstance(item, dict):
        return item
    if isinstance(item.get("act"), dict):
        return {**item, "act": _stating_wire_version(item["act"], wire_version)}
    if "protocol_version" not in item:
        return {**item, "protocol_version": wire_version}
    return item


def _normalize_evidence_act(item: dict, *, default_source_protocol: str | None) -> dict:
    if not isinstance(item, dict):
        raise ValueError("Each observed act must be an object")

    is_wrapper = isinstance(item.get("act"), dict)
    metadata = item if is_wrapper else {}
    act = copy.deepcopy(item["act"] if is_wrapper else item)

    def field(name: str, default: Any = None) -> Any:
        if name in metadata:
            return metadata[name]
        return act.get(name, default)

    signature_types = []
    for signature_type, act_field in _SIGNED_MESSAGE_FIELDS.items():
        if act_field in act and act[act_field] is not None:
            signature_types.append(signature_type)

    explicit_signature_type = metadata.get("signature_type") if is_wrapper else None
    if explicit_signature_type is not None:
        if explicit_signature_type not in _SIGNED_MESSAGE_FIELDS:
            raise ValueError(f"Unsupported signature_type: {explicit_signature_type!r}")
        if signature_types and explicit_signature_type not in signature_types:
            raise ValueError("signature_type does not match the signature present in act")
        signature_type = explicit_signature_type
    elif len(signature_types) == 1:
        signature_type = signature_types[0]
    elif len(signature_types) > 1:
        raise ValueError("An act cannot claim more than one supported signature type")
    else:
        signature_type = None

    if (
        signature_type is None
        and is_wrapper
        and "signature" in metadata
        and metadata["signature"] is not None
    ):
        raise ValueError("A present signature requires a supported signature_type")

    signature = None
    if signature_type is not None:
        if "signature" in metadata:
            signature = metadata["signature"]
        else:
            signature = act.get(_SIGNED_MESSAGE_FIELDS[signature_type])
        if signature is None:
            raise ValueError("A claimed signature_type requires a signature")

    attribution = ATTRIBUTION_VERIFIED if signature_type is not None else ATTRIBUTION_UNSIGNED
    explicit_attribution = metadata.get("attribution") if is_wrapper else None
    if explicit_attribution is not None and explicit_attribution != attribution:
        raise ValueError("attribution is inconsistent with the signature claim")

    sender_verification_method = (
        field("sender_verification_method") if signature_type is not None else None
    )
    source_protocol = (
        default_source_protocol
        if default_source_protocol is not None
        else field("source_protocol")
    )

    def optional_string(name: str) -> str | None:
        value = field(name)
        return value if isinstance(value, str) and value else None

    entry = {
        "sequence_number": field("sequence_number"),
        "round_number": field("round_number"),
        "message_type": field("message_type", ""),
        "message_id": optional_string("message_id"),
        "sender_did": field("sender_did", ""),
        "timestamp": optional_string("timestamp"),
        "source_protocol": source_protocol,
        "act": act,
        "act_hash": hash_object(act),
        "sender_verification_method": sender_verification_method,
        "signature_type": signature_type,
        "signature": signature,
        "attribution": attribution,
    }
    if is_wrapper and metadata.get("money_basis") is not None:
        # A producer annotation ABOUT the act, never inside it: `act` stays the
        # verbatim observed bytes that act_hash protects.
        entry["money_basis"] = copy.deepcopy(metadata["money_basis"])
    if not isinstance(entry["message_type"], str) or not entry["message_type"]:
        raise ValueError("Evidence acts require message_type")
    if entry["sender_did"] is None:
        # An identity-light sender is representable, but only unsigned. A DID is
        # never invented to fill this in.
        if signature_type is not None:
            raise ValueError("A signed act requires sender_did")
    elif not isinstance(entry["sender_did"], str) or not entry["sender_did"]:
        raise ValueError("Evidence acts require sender_did")
    return entry


def _order_evidence_acts(acts: list[dict]) -> list[dict]:
    indexed = list(enumerate(acts))
    timestamp_keys = [
        _timestamp_order_key(entry.get("timestamp"))
        if entry.get("timestamp") is not None
        else None
        for entry in acts
    ]
    # Judged by value here too, so ordering and validity cannot disagree about
    # what a counter is. isinstance(True, int) is True in Python, so a boolean
    # sequence_number used to count as sortable; _is_act_integer refuses it and
    # admits the integral float 2.0 that RFC 8785 makes identical to 2.
    if all(_is_act_integer(entry.get("sequence_number")) for entry in acts):
        indexed.sort(
            key=lambda pair: (
                pair[1]["sequence_number"],
                pair[0],
            )
        )
    elif all(timestamp_key is not None for timestamp_key in timestamp_keys):
        indexed.sort(
            key=lambda pair: (
                timestamp_keys[pair[0]],
                pair[1].get("sequence_number")
                if _is_act_integer(pair[1].get("sequence_number"))
                else float("inf"),
                pair[0],
            )
        )
    return [entry for _, entry in indexed]


def _timestamp_order_key(timestamp: Any) -> tuple[int, Fraction]:
    if not isinstance(timestamp, str):
        raise ValueError("Evidence act timestamp must be an RFC 3339 string")
    match = _RFC3339_PATTERN.fullmatch(timestamp)
    if match is None:
        raise ValueError("Evidence act timestamp must be an RFC 3339 string")

    year, month, day, hour, minute, second = (
        int(match.group(index)) for index in range(1, 7)
    )
    if second > 59:
        raise ValueError("Evidence act timestamp leap seconds are not supported")
    local_time = datetime(year, month, day, hour, minute, second)
    delta = local_time - _UNIX_EPOCH
    epoch_seconds = delta.days * 86_400 + delta.seconds

    offset_sign = match.group(9)
    if offset_sign is not None:
        offset_hours = int(match.group(10))
        offset_minutes = int(match.group(11))
        if offset_hours > 23 or offset_minutes > 59:
            raise ValueError("Evidence act timestamp has an invalid UTC offset")
        offset_seconds = offset_hours * 3_600 + offset_minutes * 60
        epoch_seconds += -offset_seconds if offset_sign == "+" else offset_seconds

    fraction_text = match.group(7) or ""
    fraction = (
        Fraction(int(fraction_text), 10 ** len(fraction_text))
        if fraction_text
        else Fraction(0, 1)
    )
    return epoch_seconds, fraction


def _evidence_acts_are_ordered(acts: list[dict]) -> bool:
    return acts == _order_evidence_acts(acts)


def _verify_evidence_act(
    entry: dict,
    *,
    session_id: str,
    did_resolver: DidResolver,
) -> tuple[bool, str | None]:
    attribution = entry.get("attribution") if isinstance(entry, dict) else None
    try:
        if not _evidence_act_shape_valid(entry):
            return False, attribution
        act = entry["act"]
        if not isinstance(act, dict):
            return False, attribution
        if entry.get("act_hash") != hash_object(act):
            return False, attribution

        for field_name in (
            "sequence_number",
            "round_number",
            "message_type",
            "message_id",
            "sender_did",
            "timestamp",
        ):
            act_value = act[field_name] if field_name in act else None
            if field_name in ("message_id", "timestamp") and (
                not isinstance(act_value, str) or not act_value
            ):
                act_value = None
            if field_name in act and act_value != entry.get(field_name):
                return False, attribution

        signature_type = entry.get("signature_type")
        signature = entry.get("signature")
        verification_method = entry.get("sender_verification_method")

        if attribution == ATTRIBUTION_UNSIGNED:
            if signature_type is not None or signature is not None or verification_method is not None:
                return False, attribution
            if any(act.get(field_name) is not None for field_name in _SIGNED_MESSAGE_FIELDS.values()):
                return False, attribution
            return True, attribution

        if attribution != ATTRIBUTION_VERIFIED:
            return False, attribution
        if signature_type not in _SIGNED_MESSAGE_FIELDS:
            return False, attribution
        if act.get("session_id") != session_id:
            return False, attribution
        if not isinstance(signature, str) or not signature:
            return False, attribution
        if not isinstance(verification_method, str) or not verification_method:
            return False, attribution

        sender_did = entry.get("sender_did")
        if not isinstance(sender_did, str) or not sender_did:
            return False, attribution
        if not _verification_method_controlled_by(verification_method, sender_did):
            return False, attribution
        act_signature_field = _SIGNED_MESSAGE_FIELDS[signature_type]
        if act.get(act_signature_field) != signature:
            return False, attribution
        if act.get("sender_verification_method") != verification_method:
            return False, attribution

        expected_payload = _signed_act_payload_hash(act, signature_type)
        if expected_payload is None:
            return False, attribution
        if not _verify_signature(
            did_resolver,
            did=sender_did,
            verification_method=verification_method,
            signature=signature,
            expected_payload=expected_payload,
        ):
            return False, attribution
        return True, attribution
    except Exception:
        return False, attribution


def _signed_act_payload_hash(act: dict, signature_type: str) -> str | None:
    """The hash an act's signature must cover, or None if it cannot be rebound.

    One rebuild for every act type (Section 7.3.1), taken from a2cn.messages
    and shared with the record verifier rather than re-derived here, so the two
    cannot drift apart. What this adds is the evidence record's own, stricter
    reading of an act it is about to vouch for.

    A signature slot names the act type it was made under, so an act relabelled
    as another type is refused before its signature is ever checked.
    """
    allowed_message_types = _SIGNATURE_TYPE_MESSAGE_TYPES.get(signature_type)
    if allowed_message_types is None:
        return None
    if act.get("message_type") not in allowed_message_types:
        return None

    rebuilt = rebuild_signed_act(act)
    if rebuilt is None:
        return None

    # A producer states every covered field outright. The hash would happily
    # cover a blank string or a zero counter — Section 9.5 lets a record rebind
    # one, because there the hash alone decides — but an evidence record does
    # not vouch for an act that leaves one of them empty.
    for field_name, value in rebuilt.items():
        if field_name == "terms":
            continue
        if field_name in ("round_number", "sequence_number"):
            # Judged by value, not by Python's type. RFC 8785 serializes 2.0 and
            # 2 as the same number, so they are one signed act in two JSON
            # spellings and must reach one verdict — the record path and the
            # primitive have always judged them alike, and this path judged 2.0
            # invalid while TypeScript judged it valid. A bool is an int in
            # Python but is not a JSON number, and stays refused.
            if not (_is_act_integer(value) and value >= 1):
                return None
        elif not (isinstance(value, str) and value):
            return None

    if signature_type == SIGNATURE_ACCEPTANCE and not _HASH_PATTERN.fullmatch(
        act["accepted_protocol_act_hash"]
    ):
        return None

    expected_hash = hash_object(rebuilt)
    # An offer states the hash its signature covers, so the two must agree. The
    # other act types carry no such field; their hash is the rebuild alone.
    if (
        signature_type == SIGNATURE_PROTOCOL_ACT
        and act.get("protocol_act_hash") != expected_hash
    ):
        return None
    return expected_hash


def _verify_signature(
    did_resolver: DidResolver,
    *,
    did: str,
    verification_method: str,
    signature: str,
    expected_payload: str,
) -> bool:
    did_document = _resolve_did_document(did_resolver, did)
    vm = get_verification_method(did_document, verification_method)
    public_key = get_public_key(vm)
    return verify_jws(signature, public_key) == expected_payload


def _resolve_did_document(did_resolver: DidResolver, did: str) -> dict:
    if isinstance(did_resolver, Mapping):
        return did_resolver[did]
    return did_resolver(did)


def _verification_method_controlled_by(verification_method: str, did: str) -> bool:
    return bool(
        verification_method
        and did
        and (verification_method == did or verification_method.startswith(f"{did}#"))
    )


def _classify_evidence_level(
    acts: list[dict], *, outcome: str, parties: dict, external_commitment: bool
) -> str:
    # ``external_commitment`` is whether the record carries
    # external_commitment_reference. It is a required keyword so that no caller
    # can reach ``bilateral`` by forgetting it.
    #
    # Section 9A.5: a record whose responder is an observed_party is always
    # unilateral, asserted rather than derived from the acts below. Deriving it
    # would call a record whose acts are all the producer's own bilateral, when
    # the counterparty attested to nothing in it.
    if isinstance(parties, dict) and _observed_party_shape_valid(parties.get("responder")):
        return EVIDENCE_UNILATERAL

    party_dids = {
        party.get("did")
        for party in parties.values()
        if isinstance(party, dict) and party.get("did")
    }
    verified_dids = {
        entry.get("sender_did")
        for entry in acts
        if entry.get("attribution") == ATTRIBUTION_VERIFIED
        and entry.get("sender_did") in party_dids
    }
    represented_dids = {
        entry.get("sender_did")
        for entry in acts
        if entry.get("sender_did") in party_dids
    }
    unsigned_count = sum(
        entry.get("attribution") == ATTRIBUTION_UNSIGNED for entry in acts
    )
    verified_party_count = sum(
        entry.get("attribution") == ATTRIBUTION_VERIFIED
        and entry.get("sender_did") in party_dids
        for entry in acts
    )

    # Section 9A.5: a record carrying external_commitment_reference is never
    # bilateral. Its completion is the producer's external-order reference, not
    # an act either party signed, so even when both parties' acts verify and
    # nothing is unsigned the completion is a fact the counterparty did not
    # attest to -- the same footing as a locally observed terminal fact, and
    # classified the same way.
    if (
        not external_commitment
        and outcome == SessionState.COMPLETED
        and bool(acts)
        and unsigned_count == 0
        and party_dids
        and party_dids.issubset(verified_dids)
    ):
        return EVIDENCE_BILATERAL

    local_terminal_fact = outcome != SessionState.COMPLETED
    if (
        verified_party_count > 0
        and len(represented_dids) >= 2
        and (unsigned_count > 0 or local_terminal_fact or external_commitment)
    ):
        return EVIDENCE_MIXED

    return EVIDENCE_UNILATERAL


def _evidence_record_hash_matches(record: dict) -> bool:
    claimed_hash = record.get("record_hash")
    if not isinstance(claimed_hash, str) or not claimed_hash:
        return False
    candidate = dict(record)
    candidate["record_hash"] = ""
    candidate["producer_signature"] = ""
    return hash_object(candidate) == claimed_hash
