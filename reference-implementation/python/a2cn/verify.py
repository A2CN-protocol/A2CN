"""Verify an A2CN record or act from the command line.

    a2cn-verify RECORD.json --did-dir dids/
    python -m a2cn.verify RECORD.json --did-doc did:web:example.com=example.json

The input is a TransactionRecord, a SessionEvidenceRecord, or one signed act (an
offer, counteroffer, acceptance, rejection or withdrawal). Its type is detected,
or forced with ``--type``. The verdict comes only from this library's own
verification: ``verify_transaction_record_reason`` (Section 9.5),
``assess_session_evidence_record`` (Section 9A.6) and
``verify_signed_act_reason`` (Sections 7.3 to 7.6). Nothing here adds or skips a
check.

DID documents are read from files: ``--did-doc DID=FILE`` and ``--did-dir DIR``
(every ``*.json`` in it, keyed by its ``id``). Nothing is fetched unless
``--resolve`` is given, and then only through the library's bounded did:web
resolver.

Exit status: 0 verified, 1 refused, 2 bad usage, 3 could not finish (for
example, a DID document the check needed was not supplied). A check that could
not run is never reported as a pass.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import a2cn
from a2cn.acts import SIGNED_ACT_TYPES, verify_signed_act_reason
import a2cn.evidence as _evidence
from a2cn.evidence import SESSION_EVIDENCE_RECORD_TYPE, assess_session_evidence_record
from a2cn.messages import SUPPORTED_WIRE_VERSIONS
from a2cn.record import (
    REASON_ACCEPTANCE_SIGNATURE_INVALID,
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
TYPES = (TYPE_TRANSACTION_RECORD, TYPE_EVIDENCE_RECORD, TYPE_ACT)

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
    """The command line or its input cannot be used."""


class _ArgumentParser(argparse.ArgumentParser):
    """Reports a bad command line as a UsageError, on the caller's error stream."""

    def error(self, message: str):  # type: ignore[override]
        raise UsageError(f"{message}\n{self.format_usage().strip()}")


class _Unresolved(Exception):
    """A DID document the check asked for is not available."""


class _Resolver:
    """Looks DID documents up offline, or through the bounded resolver when allowed.

    Every DID the verifier asks for and does not get is recorded, so a check
    that could not finish is reported as such rather than as a refusal.
    """

    def __init__(self, documents: dict[str, dict], resolve: bool):
        self._documents = documents
        self._resolve = resolve
        self.missing: dict[str, str] = {}

    def __call__(self, did: str) -> dict:
        if did in self._documents:
            return self._documents[did]
        if did in self.missing:
            raise _Unresolved(did)
        if self._resolve and isinstance(did, str) and did.startswith("did:web:"):
            from a2cn.did import resolve_did_web

            try:
                document = asyncio.run(resolve_did_web(did))
            except Exception as exc:  # noqa: BLE001 - every failure is reported, none passes
                self.missing[did] = f"did:web resolution failed: {type(exc).__name__}: {exc}"
                raise _Unresolved(did) from exc
            self._documents[did] = document
            return document
        self.missing[did] = (
            "not supplied (pass --did-doc or --did-dir"
            + (")" if self._resolve else ", or --resolve for did:web)")
        )
        raise _Unresolved(did)


def detect_type(document: Any) -> str:
    """The input's type, or UsageError when it is none of the three."""
    if not isinstance(document, dict):
        raise UsageError("the input is not a JSON object")
    if document.get("record_type") == SESSION_EVIDENCE_RECORD_TYPE:
        return TYPE_EVIDENCE_RECORD
    if "final_offer" in document and "final_acceptance" in document:
        return TYPE_TRANSACTION_RECORD
    if document.get("message_type") in SIGNED_ACT_TYPES:
        return TYPE_ACT
    raise UsageError(
        "cannot tell what the input is: it is not a TransactionRecord, a "
        "SessionEvidenceRecord or a signed act. Use --type to say which."
    )


def _load_json(path: Path, what: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise UsageError(f"{what} {path} does not exist") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UsageError(f"{what} {path} is not readable JSON: {exc}") from None


def load_did_documents(did_docs: list[str], did_dirs: list[str]) -> dict[str, dict]:
    """DID documents from ``--did-dir`` directories, then ``--did-doc`` pairs."""
    documents: dict[str, dict] = {}
    for directory in did_dirs:
        root = Path(directory)
        if not root.is_dir():
            raise UsageError(f"--did-dir {directory} is not a directory")
        for path in sorted(root.glob("*.json")):
            document = _load_json(path, "DID document")
            did = document.get("id") if isinstance(document, dict) else None
            if not isinstance(did, str) or not did:
                raise UsageError(f"DID document {path} has no id")
            documents[did] = document
    for pair in did_docs:
        did, separator, file_name = pair.partition("=")
        if not separator or not did or not file_name:
            raise UsageError(f"--did-doc expects DID=FILE, got {pair!r}")
        document = _load_json(Path(file_name), "DID document")
        if not isinstance(document, dict):
            raise UsageError(f"DID document {file_name} is not a JSON object")
        documents[did] = document
    return documents


def _counts(verified: int, unsigned: int, invalid: int, note: str = "") -> str:
    def plural(count: int, word: str) -> str:
        return f"{count} {word}{'' if count == 1 else 's'}"

    text = (
        f"{plural(verified, 'signed act')} verified, "
        f"{plural(unsigned, 'unsigned observation')}, {invalid} invalid"
    )
    return f"{text} {note}" if note else text


def _transaction_record_counts(reason: str | None) -> str:
    # A TransactionRecord carries two signed acts: the final offer and the
    # acceptance. Section 9.5 checks the offer's signature, then the acceptance's.
    if reason is None:
        return _counts(2, 0, 0)
    if reason == REASON_OFFER_SIGNATURE_INVALID:
        return _counts(0, 0, 1, "(the final offer)")
    if reason == REASON_ACCEPTANCE_SIGNATURE_INVALID:
        return _counts(1, 0, 1, "(the acceptance)")
    return "not reached: the record was refused before its signatures were checked"


def verify_document(document: Any, kind: str, resolver: _Resolver, args: argparse.Namespace) -> dict:
    """Run the library's verification for ``kind`` and describe the outcome."""
    if kind == TYPE_TRANSACTION_RECORD:
        offer_hashes = args.offer_hash or None
        reason = verify_transaction_record_reason(document, resolver, offer_hashes)
        hint = None
        if reason == REASON_OFFER_CHAIN_HASH_MISMATCH and offer_hashes is None:
            hint = (
                "for a session of more than one round, pass every offer hash in order "
                "with --offer-hash"
            )
        return {
            "artifact": "TransactionRecord",
            "version": f"record_version {document.get('record_version')!r}",
            "reason": reason,
            "counts": _transaction_record_counts(reason),
            "extensions": [],
            "hint": hint,
        }
    if kind == TYPE_EVIDENCE_RECORD:
        assessment = assess_session_evidence_record(document, resolver)
        extensions = document.get("extensions") if isinstance(document, dict) else None
        return {
            "artifact": "SessionEvidenceRecord",
            "version": f"record_version {document.get('record_version')!r}",
            "reason": assessment["reason"],
            "counts": (
                "not reached: the record was refused before its acts were checked"
                if assessment["reason"] in _EVIDENCE_REASONS_BEFORE_ACTS
                else _counts(
                    assessment["verified_acts"],
                    assessment["unsigned_acts"],
                    assessment["invalid_acts"],
                )
            ),
            "extensions": sorted(extensions) if isinstance(extensions, dict) else [],
            "hint": None,
        }
    reason = verify_signed_act_reason(document, resolver, wire_version=args.wire_version)
    stated = document.get("protocol_version") if isinstance(document, dict) else None
    version = (
        f"protocol_version {stated!r}"
        if stated is not None
        else f"protocol_version unstated, rebuilt under {args.wire_version!r}"
        if args.wire_version
        else "protocol_version unstated"
    )
    return {
        "artifact": f"signed act ({document.get('message_type') if isinstance(document, dict) else '?'})",
        "version": version,
        "reason": reason,
        "counts": _counts(1, 0, 0) if reason is None else _counts(0, 0, 1),
        "extensions": [],
        "hint": None,
    }


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="a2cn-verify",
        description=(
            "Verify an A2CN TransactionRecord, SessionEvidenceRecord or signed act "
            "with this library's own checks. Exit status: 0 verified, 1 refused, "
            "2 bad usage, 3 could not finish."
        ),
    )
    parser.add_argument("file", help="the record or act, as a JSON file ('-' reads standard input)")
    parser.add_argument("--type", choices=TYPES, help="what the input is, instead of detecting it")
    parser.add_argument(
        "--did-doc",
        action="append",
        default=[],
        metavar="DID=FILE",
        help="a DID document for DID, read from FILE (repeatable)",
    )
    parser.add_argument(
        "--did-dir",
        action="append",
        default=[],
        metavar="DIR",
        help="a directory of DID document files, each keyed by its id (repeatable)",
    )
    parser.add_argument(
        "--resolve",
        action="store_true",
        help="fetch did:web documents not supplied as files (bounded: no redirects, "
        "5 s, 64 KiB); without it nothing is fetched",
    )
    parser.add_argument(
        "--offer-hash",
        action="append",
        default=[],
        metavar="HASH",
        help="a TransactionRecord's offer hashes, in order, for its offer chain (repeatable)",
    )
    parser.add_argument(
        "--wire-version",
        choices=SUPPORTED_WIRE_VERSIONS,
        help="for an act that states no protocol_version: the version its session negotiated",
    )
    return parser


def run(argv: list[str] | None = None, *, out=None, err=None) -> int:
    """Run the verifier; return the exit status."""
    out = out or sys.stdout
    err = err or sys.stderr
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except UsageError as exc:
        print(f"a2cn-verify: {exc}", file=err)
        return EXIT_USAGE

    try:
        if args.file == "-":
            try:
                document = json.loads(sys.stdin.read())
            except json.JSONDecodeError as exc:
                raise UsageError(f"standard input is not JSON: {exc}") from None
        else:
            document = _load_json(Path(args.file), "input")
        kind = args.type or detect_type(document)
        if kind != TYPE_ACT and args.wire_version:
            raise UsageError("--wire-version applies to a single act only")
        if kind != TYPE_TRANSACTION_RECORD and args.offer_hash:
            raise UsageError("--offer-hash applies to a TransactionRecord only")
        resolver = _Resolver(load_did_documents(args.did_doc, args.did_dir), args.resolve)
    except UsageError as exc:
        print(f"a2cn-verify: {exc}", file=err)
        return EXIT_USAGE

    outcome = verify_document(document, kind, resolver, args)

    if resolver.missing:
        print("COULD NOT FINISH: a DID document the check needed is not available", file=out)
        for did, why in resolver.missing.items():
            print(f"  {did}: {why}", file=out)
        print(f"artifact: {outcome['artifact']}, {outcome['version']}", file=out)
        print(f"verifier: a2cn {a2cn.__version__}", file=out)
        return EXIT_UNFINISHED

    if outcome["reason"] == "WIRE_VERSION_UNSTATED":
        print(
            "COULD NOT FINISH: the act states no protocol_version; pass --wire-version "
            "with the version its session negotiated",
            file=out,
        )
        print(f"artifact: {outcome['artifact']}", file=out)
        print(f"verifier: a2cn {a2cn.__version__}", file=out)
        return EXIT_UNFINISHED

    verified = outcome["reason"] is None
    print("VERIFIED" if verified else f"REFUSED: {outcome['reason']}", file=out)
    if outcome["hint"]:
        print(f"hint: {outcome['hint']}", file=out)
    print(f"artifact: {outcome['artifact']}, {outcome['version']}", file=out)
    print(f"acts: {outcome['counts']}", file=out)
    for name in outcome["extensions"]:
        print(f"extension {name}: present, sealed, not interpreted", file=out)
    print(f"verifier: a2cn {a2cn.__version__}", file=out)
    return EXIT_VERIFIED if verified else EXIT_REFUSED


def main() -> None:
    """Console-script entry point."""
    sys.exit(run())


if __name__ == "__main__":
    main()
