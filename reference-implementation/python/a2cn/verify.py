"""Verify A2CN records and acts from the command line.

    a2cn-verify deal/                  # every .json in the folder
    a2cn-verify transaction-record.json evidence-record.json
    python -m a2cn.verify deal/ --offline

The inputs are TransactionRecords, SessionEvidenceRecords, single signed acts
(offer, counteroffer, acceptance, rejection, withdrawal) and DID documents, as
files or folders of files. Every record and act is verified, and the verdict
comes only from this library's own verification:
``verify_transaction_record_reason`` (Section 9.5),
``assess_session_evidence_record`` (Section 9A.6), ``verify_signed_act_reason``
(Sections 7.3 to 7.6) and ``offer_history_from_evidence``.

A TransactionRecord holds only its final offer, and its ``offer_chain_hash`` is
covered by no signature. Its earlier offers are taken from the session's
evidence record among the inputs, the one whose ``transaction_record_hash`` is
the record's ``record_hash``, and only once that evidence record verifies.

DID documents are fetched live: a did:web DID is its own address. Each fetch
goes through the library's bounded resolver (no redirects, 5 s, 64 KiB). A DID
document among the inputs is used only when the live fetch fails or the live
document does not list the signing key, and the verdict then says so and cannot
be a clean pass. ``--offline`` fetches nothing and uses only the DID documents
among the inputs.

Exit status: 0 everything verified, 1 a record or act was refused, 3 nothing
was refused but something could not finish (a missing DID document, a key no
available document lists, a missing offer history), 2 bad usage. A check that
could not run is never reported as a pass.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import a2cn
import a2cn.evidence as _evidence
from a2cn.acts import ACT_REASON_KEY_NOT_FOUND, SIGNED_ACT_TYPES, verify_signed_act_reason
from a2cn.did import (
    VerificationMethodNotFoundError,
    did_web_document_url,
    get_verification_method,
)
from a2cn.evidence import (
    EVIDENCE_REASON_KEY_NOT_FOUND,
    HISTORY_REASON_EVIDENCE_NOT_VERIFIED,
    SESSION_EVIDENCE_RECORD_TYPE,
    assess_session_evidence_record,
    offer_history_from_evidence,
)
from a2cn.messages import SUPPORTED_WIRE_VERSIONS
from a2cn.record import (
    REASON_ACCEPTANCE_SIGNATURE_INVALID,
    REASON_KEY_NOT_FOUND,
    REASON_OFFER_CHAIN_HASH_MISMATCH,
    REASON_OFFER_SIGNATURE_INVALID,
    verify_transaction_record_reason,
)

EXIT_VERIFIED = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
EXIT_UNFINISHED = 3

TYPE_TRANSACTION_RECORD = "transaction-record"
TYPE_EVIDENCE_RECORD = "evidence-record"
TYPE_ACT = "act"
TYPE_DID_DOCUMENT = "did-document"
TYPES = (TYPE_TRANSACTION_RECORD, TYPE_EVIDENCE_RECORD, TYPE_ACT)
KEY_NOT_FOUND_REASONS = frozenset(
    {REASON_KEY_NOT_FOUND, EVIDENCE_REASON_KEY_NOT_FOUND, ACT_REASON_KEY_NOT_FOUND}
)

# The evidence-record checks that run before any act is examined (Section 9A.6
# steps 1 to 4). A record refused by one of them has no act counts to report.
_EVIDENCE_REASONS_BEFORE_ACTS = frozenset(
    getattr(_evidence, f"EVIDENCE_REASON_{name}")
    for name in (
        "MALFORMED_RECORD",
        "UNRECOGNIZED_RECORD_TYPE",
        "UNRECOGNIZED_RECORD_VERSION",
        "DECLINE_VOCABULARY_VERSION",
        "EXTERNAL_COMMITMENT_VERSION",
        "TERMINAL_OUTCOME_INVALID",
        "GENERATED_AT_MISMATCH",
        "COMPLETION_WITNESS_INVALID",
        "PRODUCER_METHOD_NOT_CONTROLLED",
        "EVIDENCE_ID_MISMATCH",
        "ACTS_NOT_ORDERED",
    )
)


class UsageError(Exception):
    """The command line or its inputs cannot be used."""


class _ArgumentParser(argparse.ArgumentParser):
    """Reports a bad command line as a UsageError, on the caller's error stream."""

    def error(self, message: str):  # type: ignore[override]
        raise UsageError(f"{message}\n{self.format_usage().strip()}")


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


@dataclass
class _Input:
    name: str
    kind: str
    document: Any


def classify(document: Any) -> str | None:
    """What a JSON document is, or None when it is none of the known kinds."""
    if not isinstance(document, dict):
        return None
    if document.get("record_type") == SESSION_EVIDENCE_RECORD_TYPE:
        return TYPE_EVIDENCE_RECORD
    if "final_offer" in document and "final_acceptance" in document:
        return TYPE_TRANSACTION_RECORD
    if document.get("message_type") in SIGNED_ACT_TYPES:
        return TYPE_ACT
    did = document.get("id")
    if isinstance(did, str) and did.startswith("did:") and "verificationMethod" in document:
        return TYPE_DID_DOCUMENT
    return None


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise UsageError(f"{path} does not exist") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UsageError(f"{path} is not readable JSON: {exc}") from None


def _unknown(name: str) -> str:
    return (
        f"cannot tell what {name} is: it is not a TransactionRecord, a "
        "SessionEvidenceRecord, a signed act or a DID document. Use --type to say which."
    )


def collect_inputs(paths: list[str], forced_type: str | None) -> tuple[list[_Input], list[str]]:
    """Every input, and a note for each file in a folder that was skipped."""
    inputs: list[_Input] = []
    skipped: list[str] = []
    if forced_type and (len(paths) != 1 or Path(paths[0]).is_dir()):
        raise UsageError("--type applies to a single input file")
    for raw in paths:
        path = Path(raw)
        if raw == "-":
            try:
                document = json.loads(sys.stdin.read())
            except json.JSONDecodeError as exc:
                raise UsageError(f"standard input is not JSON: {exc}") from None
            kind = forced_type or classify(document)
            if kind is None:
                raise UsageError(_unknown("standard input"))
            inputs.append(_Input("standard input", kind, document))
        elif path.is_dir():
            files = sorted(path.glob("*.json"))
            if not files:
                raise UsageError(f"folder {path} holds no .json files")
            for file in files:
                document = _load_json(file)
                kind = classify(document)
                if kind is None:
                    skipped.append(f"{file}: not a record, an act or a DID document")
                else:
                    inputs.append(_Input(str(file), kind, document))
        else:
            document = _load_json(path)
            kind = forced_type or classify(document)
            if kind is None:
                raise UsageError(_unknown(str(path)))
            inputs.append(_Input(str(path), kind, document))
    return inputs, skipped


def _supplied_documents(
    inputs: list[_Input], did_docs: list[str], did_dirs: list[str]
) -> dict[str, tuple[dict, str]]:
    """DID → (document, where it came from), from the inputs and the --did-* options."""
    supplied: dict[str, tuple[dict, str]] = {}
    for item in inputs:
        if item.kind == TYPE_DID_DOCUMENT:
            supplied[item.document["id"]] = (item.document, item.name)
    for directory in did_dirs:
        root = Path(directory)
        if not root.is_dir():
            raise UsageError(f"--did-dir {directory} is not a directory")
        for path in sorted(root.glob("*.json")):
            document = _load_json(path)
            did = document.get("id") if isinstance(document, dict) else None
            if not isinstance(did, str) or not did:
                raise UsageError(f"DID document {path} has no id")
            supplied[did] = (document, str(path))
    for pair in did_docs:
        did, separator, file_name = pair.partition("=")
        if not separator or not did or not file_name:
            raise UsageError(f"--did-doc expects DID=FILE, got {pair!r}")
        document = _load_json(Path(file_name))
        if not isinstance(document, dict):
            raise UsageError(f"DID document {file_name} is not a JSON object")
        supplied[did] = (document, file_name)
    return supplied


# ---------------------------------------------------------------------------
# DID documents
# ---------------------------------------------------------------------------


def _fetch_did_web(did: str) -> dict:
    """One did:web document, through the library's bounded resolver."""
    from a2cn.did import resolve_did_web

    return asyncio.run(resolve_did_web(did))


class _Keys:
    """Where each DID document comes from: the party's site, or a supplied copy."""

    def __init__(self, supplied: dict[str, tuple[dict, str]], offline: bool):
        self.supplied = supplied
        self.offline = offline
        self._live: dict[str, tuple[dict | None, str]] = {}

    def live(self, did: str) -> tuple[dict | None, str]:
        """The live document and its URL, or None and why it could not be fetched."""
        if did not in self._live:
            if not (isinstance(did, str) and did.startswith("did:web:")):
                self._live[did] = (None, "not a did:web DID, so it has no address to fetch")
            else:
                url = did_web_document_url(did)
                try:
                    self._live[did] = (_fetch_did_web(did), url)
                except Exception as exc:  # noqa: BLE001 - reported, never a pass
                    first_line = str(exc).splitlines()[0] if str(exc) else ""
                    self._live[did] = (None, f"fetching {url} failed: {type(exc).__name__}: {first_line}")
        return self._live[did]


class _Attempt:
    """A DID resolver for one verification run, recording what it used."""

    def __init__(self, keys: _Keys, use_supplied: frozenset[str] = frozenset()):
        self.keys = keys
        self.use_supplied = use_supplied
        self.used: dict[str, dict] = {}
        self.sources: dict[str, str] = {}
        self.fallback: dict[str, str] = {}
        self.missing: dict[str, str] = {}

    def __call__(self, did: str) -> dict:
        if did in self.used:
            return self.used[did]
        if did in self.missing:
            raise KeyError(did)
        supplied = self.keys.supplied.get(did)
        if self.keys.offline:
            if supplied is None:
                self.missing[did] = "not among the inputs (--offline fetches nothing)"
                raise KeyError(did)
            return self._use(
                did, supplied[0], f"from {supplied[1]} (offline: not checked against the party's site)"
            )
        if did in self.use_supplied and supplied is not None:
            self.fallback[did] = "the party's site does not list the signing key now"
            return self._use(
                did,
                supplied[0],
                f"from a supplied copy, {supplied[1]}; the party's site does not list the signing key now",
            )
        document, where = self.keys.live(did)
        if document is not None:
            return self._use(did, document, f"from {where}")
        if supplied is not None:
            self.fallback[did] = where
            return self._use(did, supplied[0], f"from a supplied copy, {supplied[1]}; {where}")
        self.missing[did] = where
        raise KeyError(did)

    def _use(self, did: str, document: dict, source: str) -> dict:
        self.used[did] = document
        self.sources[did] = source
        return document


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass
class _Outcome:
    name: str
    artifact: str
    status: int = EXIT_VERIFIED
    headline: str = "VERIFIED"
    lines: list[str] = field(default_factory=list)
    # For an evidence record: the DIDs its verdict took from supplied copies.
    use_supplied: frozenset[str] = frozenset()


def _counts(verified: int, unsigned: int, invalid: int, note: str = "") -> str:
    def plural(count: int, word: str) -> str:
        return f"{count} {word}{'' if count == 1 else 's'}"

    text = (
        f"{plural(verified, 'signed act')} verified, "
        f"{plural(unsigned, 'unsigned observation')}, {invalid} invalid"
    )
    return f"{text} {note}" if note else text


def _signers(kind: str, document: dict) -> list[tuple[str, str]]:
    """The (DID, verification method) pairs a TransactionRecord or act signature names."""
    pairs: list[tuple[Any, Any]] = []
    try:
        if kind == TYPE_TRANSACTION_RECORD:
            methods = {
                party.get("did"): party.get("verification_method")
                for party in document.get("parties", {}).values()
                if isinstance(party, dict)
            }
            for act in ("final_offer", "final_acceptance"):
                did = document[act].get("sender_did")
                pairs.append((did, methods.get(did)))
        elif kind == TYPE_ACT:
            pairs.append((document.get("sender_did"), document.get("sender_verification_method")))
    except Exception:  # noqa: BLE001 - a malformed record names no signers
        pass
    return [(did, vm) for did, vm in pairs if isinstance(did, str) and isinstance(vm, str)]


def _lists(document: dict, verification_method: str) -> bool:
    try:
        get_verification_method(document, verification_method)
    except Exception:  # noqa: BLE001
        return False
    return True


def _keys_not_listed(kind, document, attempt: _Attempt, assessment) -> list[tuple[str, str]]:
    """Keys a signature names that the DID document used does not list.

    A signer whose document could not be obtained at all is in attempt.missing
    and reported as such, not here.
    """
    if assessment is not None:
        pairs = [
            (key["did"], key["verification_method"])
            for key in assessment["unresolved_keys"]
            if key["did"] not in attempt.missing
        ]
    else:
        pairs = []
        for did, vm in _signers(kind, document):
            if did in attempt.used:
                try:
                    get_verification_method(attempt.used[did], vm)
                except VerificationMethodNotFoundError:
                    pairs.append((did, vm))
    return list(dict.fromkeys(pairs))


def _run_library(kind, document, attempt: _Attempt, history, wire_version):
    if kind == TYPE_TRANSACTION_RECORD:
        return verify_transaction_record_reason(document, attempt, history), None
    if kind == TYPE_EVIDENCE_RECORD:
        assessment = assess_session_evidence_record(document, attempt)
        return assessment["reason"], assessment
    return verify_signed_act_reason(document, attempt, wire_version=wire_version), None


def _verify_with_keys(kind, document, keys: _Keys, history=None, wire_version=None):
    """Run the library; retry with a supplied copy for a key the live document lacks."""
    attempt = _Attempt(keys)
    reason, assessment = _run_library(kind, document, attempt, history, wire_version)
    not_listed: list[tuple[str, str]] = []
    # A TransactionRecord checks its offer chain after both signatures, so a
    # chain mismatch can sit beside a key that was not available.
    if reason in KEY_NOT_FOUND_REASONS or (
        kind == TYPE_TRANSACTION_RECORD and reason == REASON_OFFER_CHAIN_HASH_MISMATCH
    ):
        not_listed = _keys_not_listed(kind, document, attempt, assessment)
        retry = frozenset(
            did
            for did, vm in not_listed
            if not keys.offline and did in keys.supplied and _lists(keys.supplied[did][0], vm)
        )
        if retry:
            attempt = _Attempt(keys, use_supplied=retry)
            reason, assessment = _run_library(kind, document, attempt, history, wire_version)
            not_listed = _keys_not_listed(kind, document, attempt, assessment)
    return reason, assessment, attempt, not_listed


def _finish(outcome: _Outcome, reason, counts: str | None, attempt: _Attempt, not_listed) -> _Outcome:
    """Turn a library reason into the record's verdict, and say where its keys came from.

    A definite failure is REFUSED even when some DID documents were missing:
    the library checks everything it can and reports a failure ahead of a key
    it could not find, so the missing documents are listed as notes. COULD NOT
    FINISH is only for a key that was not available, or for a record that
    verified only against a supplied copy.
    """
    if reason is not None and reason not in KEY_NOT_FOUND_REASONS:
        outcome.status = EXIT_REFUSED
        outcome.headline = f"REFUSED: {reason}"
        for did, why in attempt.missing.items():
            outcome.lines.append(f"note: no DID document for {did} ({why}); its signatures were not checked")
        for did, vm in not_listed:
            outcome.lines.append(f"note: {did} doesn't list key {vm}; that signature was not checked")
    elif reason in KEY_NOT_FOUND_REASONS or attempt.missing:
        outcome.status = EXIT_UNFINISHED
        if attempt.missing and not not_listed:
            outcome.headline = "COULD NOT FINISH: a DID document the check needed is not available"
        elif not_listed and not attempt.missing:
            outcome.headline = "COULD NOT FINISH: a signature names a key no available DID document lists"
        else:
            outcome.headline = "COULD NOT FINISH: keys the check needed are not available"
        for did, why in attempt.missing.items():
            outcome.lines.append(f"no DID document for {did}: {why}")
        for did, vm in not_listed:
            outcome.lines.append(
                f"{did} doesn't list key {vm} (rotated?); supply the DID document as it was at signing time"
            )
    elif attempt.fallback:
        outcome.status = EXIT_UNFINISHED
        outcome.headline = "COULD NOT FINISH: verified only against a supplied DID document"
    if counts:
        outcome.lines.append(f"acts: {counts}")
    for did, source in attempt.sources.items():
        outcome.lines.append(f"keys: {did} {source}")
    return outcome


def verify_transaction_record(
    item: _Input, evidence: list[_Input], verdicts: dict[str, _Outcome], keys: _Keys, args
) -> _Outcome:
    document = item.document
    outcome = _Outcome(item.name, f"TransactionRecord, record_version {document.get('record_version')!r}")
    final_offer = document.get("final_offer")
    final_round = final_offer.get("round_number") if isinstance(final_offer, dict) else None

    history: list[str] | None = None
    history_line: str | None = None
    history_attempt: _Attempt | None = None
    history_fallback: list[str] = []
    unlinked: list[str] = []
    linked = [e for e in evidence if e.document.get("transaction_record_hash") == document.get("record_hash")]
    if args.offer_hash:
        history = list(args.offer_hash)
        history_line = (
            f"offer history: {len(history)} hashes typed on the command line; not covered by any signature"
        )
    elif linked:
        source = linked[0]
        verdict = verdicts[source.name]
        if verdict.status != EXIT_VERIFIED and not verdict.use_supplied:
            outcome.status = EXIT_UNFINISHED
            state = "was refused" if verdict.status == EXIT_REFUSED else "could not be checked"
            outcome.headline = f"COULD NOT FINISH: its evidence record {state}"
            outcome.lines.append(
                f"the evidence record {source.name} names this record but {state} (see its own "
                "verdict), so the earlier offers cannot be checked"
            )
            return outcome
        # The same DID documents the evidence record's own verdict used.
        history_attempt = _Attempt(keys, use_supplied=verdict.use_supplied)
        hashes, why = offer_history_from_evidence(document, source.document, history_attempt)
        if history_attempt.missing or why == HISTORY_REASON_EVIDENCE_NOT_VERIFIED:
            outcome.status = EXIT_UNFINISHED
            outcome.headline = "COULD NOT FINISH: its evidence record could not be checked"
            outcome.lines.append(
                f"the evidence record {source.name} names this record but could not be checked, so "
                "the earlier offers cannot be checked"
            )
            return outcome
        if why is not None:
            outcome.status = EXIT_REFUSED
            outcome.headline = f"REFUSED: {why}"
            outcome.lines.append(
                f"the evidence record {source.name} names this record, but its offers are not this "
                "record's complete signed offer history"
            )
            return outcome
        history = hashes
        history_line = (
            f"offer history: {len(hashes)} offers, each signed by its sender, "
            f"from the evidence record {source.name}"
        )
        # Offers in the history whose key came from a supplied copy: the record
        # is never stronger than the weakest input it relied on.
        for entry in source.document.get("acts", []):
            did = entry.get("sender_did")
            if (
                entry.get("message_type") in ("offer", "counteroffer")
                and did in history_attempt.fallback
            ):
                history_fallback.append(
                    f"the round-{entry.get('act', {}).get('round_number')} {entry.get('message_type')} "
                    f"in the offer history was verified against a supplied copy of {did}'s DID "
                    f"document, {keys.supplied[did][1]} ({history_attempt.fallback[did]})"
                )
    else:
        unlinked = [
            f"the evidence record {e.name} names another TransactionRecord "
            f"(transaction_record_hash {e.document.get('transaction_record_hash')!r}), "
            "so it does not belong to this one"
            for e in evidence
        ]

    reason, _assessment, attempt, not_listed = _verify_with_keys(
        TYPE_TRANSACTION_RECORD, document, keys, history
    )

    unchecked = _unchecked_signatures(document, attempt, not_listed)
    if (
        history is None
        and reason == REASON_OFFER_CHAIN_HASH_MISMATCH
        and isinstance(final_round, int)
        and final_round > 1
    ):
        # The chain is checked last, after both signatures.
        rounds_note = (
            f"this deal took {final_round} rounds and the record carries only the final offer; "
            "add this session's evidence record to check the earlier offers"
        )
        if unchecked:
            _finish(outcome, REASON_KEY_NOT_FOUND, _record_counts(None, unchecked), attempt, not_listed)
            outcome.lines.insert(0, rounds_note)
            outcome.lines[1:1] = unlinked
            return outcome
        outcome.status = EXIT_UNFINISHED
        outcome.headline = "COULD NOT FINISH: the earlier offers are not available"
        outcome.lines.append(f"agreed terms and both signatures verified; {rounds_note}")
        outcome.lines.extend(unlinked)
        _finish(outcome, None, _counts(2, 0, 0), attempt, not_listed)
        if outcome.status == EXIT_VERIFIED:  # _finish found nothing weaker
            outcome.status = EXIT_UNFINISHED
            outcome.headline = "COULD NOT FINISH: the earlier offers are not available"
        return outcome

    if history_line is None:
        if isinstance(final_round, int) and final_round > 1:
            history_line = (
                f"offer history: not available; this deal took {final_round} rounds and the record "
                "carries only the final offer"
            )
        else:
            history_line = "offer history: the final offer only (a one-round deal)"
    outcome.lines.append(history_line)
    outcome.lines.extend(history_fallback)
    outcome.lines.extend(unlinked)
    _finish(outcome, reason, _record_counts(reason, unchecked), attempt, not_listed)
    if history_attempt is not None:
        for did, where in history_attempt.sources.items():
            if attempt.sources.get(did) != where:
                outcome.lines.append(f"keys (offer history): {did} {where}")
    if history_fallback and outcome.status == EXIT_VERIFIED:
        outcome.status = EXIT_UNFINISHED
        outcome.headline = "COULD NOT FINISH: verified only against a supplied DID document"
    return outcome


def _unchecked_signatures(document: dict, attempt: _Attempt, not_listed) -> set[str]:
    """Which of a TransactionRecord's two signatures could not be checked."""
    unavailable = set(attempt.missing) | {did for did, _vm in not_listed}
    names = {"final_offer": "the final offer", "final_acceptance": "the acceptance"}
    unchecked = set()
    for act, name in names.items():
        try:
            if document[act].get("sender_did") in unavailable:
                unchecked.add(name)
        except Exception:  # noqa: BLE001
            pass
    return unchecked


def _record_counts(reason, unchecked: set[str]) -> str:
    """A TransactionRecord's two signed acts: verified, invalid, or not checked."""
    if reason not in (
        None,
        REASON_OFFER_SIGNATURE_INVALID,
        REASON_ACCEPTANCE_SIGNATURE_INVALID,
        REASON_OFFER_CHAIN_HASH_MISMATCH,
        REASON_KEY_NOT_FOUND,
    ):
        return "not reached: the record was refused before its signatures were checked"
    invalid = {
        REASON_OFFER_SIGNATURE_INVALID: "the final offer",
        REASON_ACCEPTANCE_SIGNATURE_INVALID: "the acceptance",
    }.get(reason)
    verified = 2 - len(unchecked) - (1 if invalid else 0)
    notes = []
    if invalid:
        notes.append(f"invalid: {invalid}")
    if unchecked:
        notes.append(f"not checked, key not available: {', '.join(sorted(unchecked))}")
    return _counts(verified, 0, 1 if invalid else 0, f"({'; '.join(notes)})" if notes else "")


def verify_evidence_record(item: _Input, keys: _Keys) -> _Outcome:
    document = item.document
    outcome = _Outcome(
        item.name, f"SessionEvidenceRecord, record_version {document.get('record_version')!r}"
    )
    reason, assessment, attempt, not_listed = _verify_with_keys(TYPE_EVIDENCE_RECORD, document, keys)
    if reason is None:
        outcome.use_supplied = frozenset(attempt.fallback)
    if reason in _EVIDENCE_REASONS_BEFORE_ACTS:
        counts = "not reached: the record was refused before its acts were checked"
    else:
        unchecked = len(assessment["unresolved_keys"])
        counts = _counts(
            assessment["verified_acts"],
            assessment["unsigned_acts"],
            assessment["invalid_acts"],
            f"({unchecked} signature{'' if unchecked == 1 else 's'} not checked: key not available)"
            if unchecked
            else "",
        )
    _finish(outcome, reason, counts, attempt, not_listed)
    extensions = document.get("extensions")
    if isinstance(extensions, dict):
        for name in sorted(extensions):
            outcome.lines.append(f"extension {name}: present, sealed, not interpreted")
    return outcome


def verify_act(item: _Input, keys: _Keys, wire_version) -> _Outcome:
    document = item.document
    stated = document.get("protocol_version")
    if stated is not None:
        version = f"protocol_version {stated!r}"
    elif wire_version:
        version = f"protocol_version unstated, rebuilt under {wire_version!r}"
    else:
        version = "protocol_version unstated"
    outcome = _Outcome(item.name, f"signed act ({document.get('message_type')}), {version}")
    reason, _assessment, attempt, not_listed = _verify_with_keys(
        TYPE_ACT, document, keys, wire_version=wire_version
    )
    if reason == "WIRE_VERSION_UNSTATED":
        outcome.status = EXIT_UNFINISHED
        outcome.headline = (
            "COULD NOT FINISH: the act states no protocol_version; pass --wire-version with the "
            "version its session negotiated"
        )
        return outcome
    counts = _counts(1, 0, 0) if reason is None else None if reason in KEY_NOT_FOUND_REASONS else _counts(0, 0, 1)
    return _finish(outcome, reason, counts, attempt, not_listed)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _parser() -> _ArgumentParser:
    parser = _ArgumentParser(
        prog="a2cn-verify",
        description=(
            "Verify A2CN TransactionRecords, SessionEvidenceRecords and signed acts with this "
            "library's own checks. Put a TransactionRecord and its session's evidence record "
            "together, as files or in one folder. DID documents are fetched from the parties' "
            "sites unless --offline is given. Exit status: 0 verified, 1 refused, 2 bad usage, "
            "3 could not finish."
        ),
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        metavar="PATH",
        help="record, act or DID document files, or folders of them ('-' reads standard input)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="fetch nothing; use only DID documents among the inputs (not checked against the parties' sites)",
    )
    parser.add_argument("--type", choices=TYPES, help="what a single input file is, instead of detecting it")
    parser.add_argument(
        "--did-doc",
        action="append",
        default=[],
        metavar="DID=FILE",
        help="a saved DID document for DID (repeatable), treated like one among the inputs",
    )
    parser.add_argument(
        "--did-dir",
        action="append",
        default=[],
        metavar="DIR",
        help="a folder of saved DID documents, each keyed by its id (repeatable)",
    )
    parser.add_argument(
        "--wire-version",
        choices=SUPPORTED_WIRE_VERSIONS,
        help="for an act that states no protocol_version: the version its session negotiated",
    )
    parser.add_argument(
        "--offer-hash",
        action="append",
        default=[],
        metavar="HASH",
        help=(
            "fallback: a TransactionRecord's offer hashes, in order, typed in. Not covered by any "
            "signature, so they prove nothing about the earlier offers; supply the session's "
            "evidence record instead"
        ),
    )
    return parser


def run(argv: list[str] | None = None, *, out=None, err=None) -> int:
    """Run the verifier; return the exit status."""
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        args = _parser().parse_args(argv)
        inputs, skipped = collect_inputs(args.inputs, args.type)
        supplied = _supplied_documents(inputs, args.did_doc, args.did_dir)
        records = [item for item in inputs if item.kind != TYPE_DID_DOCUMENT]
        if not records:
            raise UsageError("no record or act among the inputs")
        if args.offer_hash and sum(item.kind == TYPE_TRANSACTION_RECORD for item in records) != 1:
            raise UsageError("--offer-hash applies to exactly one TransactionRecord")
        if args.wire_version and not any(item.kind == TYPE_ACT for item in records):
            raise UsageError("--wire-version applies to a single act only")
    except UsageError as exc:
        print(f"a2cn-verify: {exc}", file=err)
        return EXIT_USAGE

    keys = _Keys(supplied, args.offline)
    evidence = [item for item in records if item.kind == TYPE_EVIDENCE_RECORD]
    # Evidence records first: a TransactionRecord takes its offer history from
    # one only after that record's own verdict.
    verdicts = {item.name: verify_evidence_record(item, keys) for item in evidence}
    outcomes: list[_Outcome] = []
    for item in records:
        if item.kind == TYPE_TRANSACTION_RECORD:
            outcomes.append(verify_transaction_record(item, evidence, verdicts, keys, args))
        elif item.kind == TYPE_EVIDENCE_RECORD:
            outcomes.append(verdicts[item.name])
        else:
            outcomes.append(verify_act(item, keys, args.wire_version))

    for note in skipped:
        print(f"skipped {note}", file=out)
    for outcome in outcomes:
        print(f"{outcome.name}: {outcome.artifact}", file=out)
        print(f"  {outcome.headline}", file=out)
        for line in outcome.lines:
            print(f"  {line}", file=out)
    refused = sum(o.status == EXIT_REFUSED for o in outcomes)
    unfinished = sum(o.status == EXIT_UNFINISHED for o in outcomes)
    verified = len(outcomes) - refused - unfinished
    if refused:
        status, word = EXIT_REFUSED, "REFUSED"
    elif unfinished:
        status, word = EXIT_UNFINISHED, "COULD NOT FINISH"
    else:
        status, word = EXIT_VERIFIED, "VERIFIED"
    print(
        f"overall: {word} ({verified} verified, {refused} refused, {unfinished} could not finish)",
        file=out,
    )
    if args.offline:
        print("DID documents: offline, from the inputs only; not checked against the parties' sites", file=out)
    print(f"verifier: a2cn {a2cn.__version__}", file=out)
    return status


def main() -> None:
    """Console-script entry point."""
    sys.exit(run())


if __name__ == "__main__":
    main()
