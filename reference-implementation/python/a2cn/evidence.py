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
from a2cn.record import A2CN_NAMESPACE, generate_transaction_record
from a2cn.session import Session, SessionState, _now


SESSION_EVIDENCE_RECORD_VERSION = "0.1"
SESSION_EVIDENCE_RECORD_TYPE = "a2cn_session_evidence_record"

EVIDENCE_BILATERAL = "bilateral"
EVIDENCE_MIXED = "mixed"
EVIDENCE_UNILATERAL = "unilateral"

ATTRIBUTION_VERIFIED = "verified_signature"
ATTRIBUTION_UNSIGNED = "unsigned_observation"

SIGNATURE_PROTOCOL_ACT = "protocol_act_signature"
SIGNATURE_ACCEPTANCE = "acceptance_signature"

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
_RECORD_OPTIONAL_FIELDS = frozenset({"extensions"})
_ACT_FIELDS = frozenset(
    {
        "sequence_number",
        "round_number",
        "message_type",
        "message_id",
        "sender_did",
        "timestamp",
        "source_protocol",
        "act",
        "act_hash",
        "sender_verification_method",
        "signature_type",
        "signature",
        "attribution",
    }
)
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

    acts = [
        _normalize_evidence_act(message, default_source_protocol="a2cn")
        for message in session._message_log
    ]
    acts.extend(
        _normalize_evidence_act(observed, default_source_protocol=None)
        for observed in (observed_acts or [])
    )
    acts = _order_evidence_acts(acts)

    terminal_timestamp = _terminal_timestamp(session)
    transaction_record_hash = None
    if session.state == SessionState.COMPLETED:
        transaction_record_hash = generate_transaction_record(session)["record_hash"]

    act_chain_hash = hash_bytes(canonicalize([entry["act_hash"] for entry in acts]))
    evidence_level = _classify_evidence_level(
        acts,
        outcome=outcome,
        parties=parties,
    )

    record = {
        "record_type": SESSION_EVIDENCE_RECORD_TYPE,
        "record_version": SESSION_EVIDENCE_RECORD_VERSION,
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

    # Refuse to seal a claim the verifier would reject. The generator and the
    # verifier run the same two rules so a producer cannot emit a record that
    # only fails once it is somebody else's problem.
    if not _money_basis_claims_verify(record):
        raise ValueError(
            "money_basis does not recompute to the claimed and signed totals"
        )
    if not _observed_responder_rules_hold(record):
        raise ValueError(
            "An observed responder requires unsigned counterparty acts and "
            "unilateral evidence"
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
        if record.get("record_version") != SESSION_EVIDENCE_RECORD_VERSION:
            return assessment

        terminal = record["terminal"]
        outcome = terminal["outcome"]
        if outcome not in _EVIDENCE_TERMINAL_OUTCOMES:
            return assessment
        if record["generated_at"] != terminal["timestamp"]:
            return assessment
        _timestamp_order_key(record["generated_at"])
        _timestamp_order_key(terminal["timestamp"])
        if outcome == SessionState.COMPLETED:
            if not isinstance(record.get("transaction_record_hash"), str) or not record.get(
                "transaction_record_hash"
            ):
                return assessment
        elif record.get("transaction_record_hash") is not None:
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
        if record.get("act_chain_hash") != hash_bytes(canonicalize(computed_act_hashes)):
            return assessment

        expected_level = _classify_evidence_level(
            acts,
            outcome=outcome,
            parties=record["parties"],
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
    )


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
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 1
        ):
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
    if all(isinstance(entry.get("sequence_number"), int) for entry in acts):
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
                if isinstance(pair[1].get("sequence_number"), int)
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
    if signature_type == SIGNATURE_PROTOCOL_ACT:
        if act.get("message_type") not in ("offer", "counteroffer"):
            return None
        if not all(
            isinstance(act.get(field_name), str) and bool(act[field_name])
            for field_name in (
                "session_id",
                "message_type",
                "sender_did",
                "timestamp",
                "expires_at",
            )
        ):
            return None
        if not all(
            isinstance(act.get(field_name), int)
            and not isinstance(act[field_name], bool)
            and act[field_name] >= 1
            for field_name in ("round_number", "sequence_number")
        ):
            return None
        if not isinstance(act.get("terms"), dict):
            return None
        protocol_act = {
            "protocol_version": "0.2",
            "session_id": act["session_id"],
            "round_number": act["round_number"],
            "sequence_number": act["sequence_number"],
            "message_type": act["message_type"],
            "sender_did": act["sender_did"],
            "timestamp": act["timestamp"],
            "expires_at": act["expires_at"],
            "terms": act["terms"],
        }
        expected_hash = hash_object(protocol_act)
        if act.get("protocol_act_hash") != expected_hash:
            return None
        return expected_hash

    if signature_type == SIGNATURE_ACCEPTANCE:
        if act.get("message_type") != "acceptance":
            return None
        if not all(
            isinstance(act.get(field_name), str) and bool(act[field_name])
            for field_name in (
                "session_id",
                "accepted_offer_id",
                "accepted_protocol_act_hash",
            )
        ):
            return None
        if not _HASH_PATTERN.fullmatch(act["accepted_protocol_act_hash"]):
            return None
        if not all(
            isinstance(act.get(field_name), int)
            and not isinstance(act[field_name], bool)
            and act[field_name] >= 1
            for field_name in ("round_number", "sequence_number")
        ):
            return None
        return hash_object(
            {
                "session_id": act["session_id"],
                "round_number": act["round_number"],
                "sequence_number": act["sequence_number"],
                "accepted_offer_id": act["accepted_offer_id"],
                "accepted_protocol_act_hash": act["accepted_protocol_act_hash"],
            }
        )

    return None


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


def _classify_evidence_level(acts: list[dict], *, outcome: str, parties: dict) -> str:
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

    if (
        outcome == SessionState.COMPLETED
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
        and (unsigned_count > 0 or local_terminal_fact)
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
