"""The a2cn-verify command reports the library's own verdict, and never a silent pass.

Every TransactionRecord, SessionEvidenceRecord and standalone signed act in the
committed test vectors is run through the command and compared with what the
library says for the same input: the same verdict, the same reason, and exit
status 0 (verified), 1 (refused) or 3 (a DID document it needed was missing).
"""

from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

import a2cn
from a2cn.acts import verify_signed_act_reason
from a2cn.evidence import SESSION_EVIDENCE_RECORD_TYPE, assess_session_evidence_record
from a2cn.record import verify_transaction_record_reason
from a2cn.verify import (
    EXIT_REFUSED,
    EXIT_UNFINISHED,
    EXIT_USAGE,
    EXIT_VERIFIED,
    run,
)

PYTHON_ROOT = Path(__file__).parents[1]
VECTORS = Path(__file__).parents[3] / "spec" / "test-vectors"
SIGNATURE_FIELDS = (
    "protocol_act_signature",
    "acceptance_signature",
    "rejection_signature",
    "withdrawal_signature",
)
ACT_TYPES = ("offer", "counteroffer", "acceptance", "rejection", "withdrawal")


def _is_did_document_map(value) -> bool:
    return isinstance(value, dict) and all(
        isinstance(document, dict) and "id" in document for document in value.values()
    )


def _offer_hashes_of(messages) -> list[str] | None:
    hashes = [
        message.get("protocol_act_hash")
        for message in messages
        if isinstance(message, dict) and message.get("message_type") in ("offer", "counteroffer")
    ]
    return hashes if hashes and all(isinstance(h, str) for h in hashes) else None


def _collect():
    """(vector file, JSON path, kind, input, DID documents, offer hashes) for every item."""
    items = []

    def walk(node, path, documents, bases, hashes, vector):
        if isinstance(node, dict):
            candidate = node.get("did_documents")
            if _is_did_document_map(candidate):
                documents = candidate
            elif isinstance(candidate, dict) and all(
                _is_did_document_map(value) for value in candidate.values()
            ):
                bases = candidate
            if bases is not None and isinstance(node.get("base"), str) and node["base"] in bases:
                documents = bases[node["base"]]
            if isinstance(node.get("offer_hashes"), list):
                hashes = node["offer_hashes"]
            elif isinstance(node.get("messages"), list):
                hashes = _offer_hashes_of(node["messages"]) or hashes
            if node.get("record_type") == SESSION_EVIDENCE_RECORD_TYPE:
                items.append((vector, path, "evidence-record", node, documents, None))
                return
            if "final_offer" in node and "final_acceptance" in node:
                items.append((vector, path, "transaction-record", node, documents, hashes))
                return
            if node.get("message_type") in ACT_TYPES and any(f in node for f in SIGNATURE_FIELDS):
                items.append((vector, path, "act", node, documents, None))
                return
            for key, value in node.items():
                walk(value, f"{path}/{key}", documents, bases, hashes, vector)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]", documents, bases, hashes, vector)

    for vector_path in sorted(VECTORS.glob("*.json")):
        walk(json.loads(vector_path.read_text()), "", {}, None, None, vector_path.name)
    return items


ITEMS = _collect()


class _TrackingResolver:
    def __init__(self, documents):
        self.documents = documents
        self.missing = False

    def __call__(self, did):
        if did not in self.documents:
            self.missing = True
            raise KeyError(did)
        return self.documents[did]


def _library_reason(kind, document, documents, hashes, wire_version=None):
    resolver = _TrackingResolver(documents)
    if kind == "transaction-record":
        reason = verify_transaction_record_reason(document, resolver, hashes)
    elif kind == "evidence-record":
        reason = assess_session_evidence_record(document, resolver)["reason"]
    else:
        reason = verify_signed_act_reason(document, resolver, wire_version=wire_version)
    return reason, resolver.missing


def _write_dids(directory: Path, documents: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for index, document in enumerate(documents.values()):
        (directory / f"did-{index}.json").write_text(json.dumps(document))
    return directory


def _cli(args: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    status = run(args, out=out, err=err)
    return status, out.getvalue() + err.getvalue()


def _expected_status(reason, missing):
    if missing:
        return EXIT_UNFINISHED
    return EXIT_VERIFIED if reason is None else EXIT_REFUSED


@pytest.mark.parametrize(
    "item",
    [item for item in ITEMS if item[2] != "act"],
    ids=lambda item: f"{item[0]}:{item[1]}",
)
def test_every_vector_record_gets_the_librarys_verdict(item, tmp_path):
    vector, path, kind, document, documents, hashes = item
    reason, missing = _library_reason(kind, document, documents, hashes)
    record_file = tmp_path / "input.json"
    record_file.write_text(json.dumps(document))
    args = [str(record_file), "--did-dir", str(_write_dids(tmp_path / "dids", documents))]
    for offer_hash in (hashes or []) if kind == "transaction-record" else []:
        args += ["--offer-hash", offer_hash]

    status, output = _cli(args)

    assert status == _expected_status(reason, missing), output
    first = output.splitlines()[0]
    if status == EXIT_VERIFIED:
        assert first == "VERIFIED"
    elif status == EXIT_REFUSED:
        assert first == f"REFUSED: {reason}"
    else:
        assert first.startswith("COULD NOT FINISH")
    assert f"verifier: a2cn {a2cn.__version__}" in output


@pytest.mark.parametrize(
    "item",
    [item for item in ITEMS if item[2] == "act"],
    ids=lambda item: f"{item[0]}:{item[1]}",
)
@pytest.mark.parametrize("wire_version", [None, "0.2", "0.3"])
def test_every_vector_act_gets_the_librarys_verdict(item, wire_version, tmp_path):
    vector, path, kind, document, documents, _hashes = item
    reason, missing = _library_reason(kind, document, documents, None, wire_version)
    act_file = tmp_path / "act.json"
    act_file.write_text(json.dumps(document))
    args = [str(act_file), "--did-dir", str(_write_dids(tmp_path / "dids", documents))]
    if wire_version:
        args += ["--wire-version", wire_version]

    status, output = _cli(args)

    if missing or reason == "WIRE_VERSION_UNSTATED":
        assert status == EXIT_UNFINISHED, output
    elif reason is None:
        assert status == EXIT_VERIFIED, output
    else:
        assert status == EXIT_REFUSED, output
        assert output.splitlines()[0] == f"REFUSED: {reason}"


def test_the_vectors_exercise_every_kind_and_both_verdicts():
    """A guard on the walk above, so the tests cannot quietly come to cover nothing."""
    verdicts = {}
    for vector, path, kind, document, documents, hashes in ITEMS:
        wire = "0.2" if kind == "act" and "protocol_version" not in document else None
        reason, missing = _library_reason(kind, document, documents, hashes, wire)
        verdicts.setdefault(kind, set()).add("missing" if missing else reason is None)
    for kind in ("transaction-record", "evidence-record", "act"):
        assert {True, False} <= verdicts[kind], (kind, verdicts[kind])


def _verified(kind):
    for vector, path, item_kind, document, documents, hashes in ITEMS:
        if item_kind == kind and _library_reason(kind, document, documents, hashes) == (None, False):
            return copy.deepcopy(document), documents, hashes
    raise AssertionError(f"no verified {kind} in the vectors")


@pytest.mark.parametrize("kind", ["transaction-record", "evidence-record"])
def test_a_tampered_copy_is_refused(kind, tmp_path):
    document, documents, hashes = _verified(kind)
    if kind == "transaction-record":
        document["agreed_terms"]["total_value"] += 1
    else:
        document["generated_at"] = document["generated_at"].replace("Z", ".5Z")
    record_file = tmp_path / "tampered.json"
    record_file.write_text(json.dumps(document))
    args = [str(record_file), "--did-dir", str(_write_dids(tmp_path / "dids", documents))]
    for offer_hash in hashes or []:
        args += ["--offer-hash", offer_hash]

    status, output = _cli(args)

    assert status == EXIT_REFUSED, output
    assert output.startswith("REFUSED: ")


@pytest.mark.parametrize("kind", ["transaction-record", "evidence-record"])
def test_a_missing_did_document_cannot_finish(kind, tmp_path):
    document, _documents, hashes = _verified(kind)
    record_file = tmp_path / "record.json"
    record_file.write_text(json.dumps(document))
    args = [str(record_file)]
    for offer_hash in hashes or []:
        args += ["--offer-hash", offer_hash]

    status, output = _cli(args)

    assert status == EXIT_UNFINISHED, output
    assert output.startswith("COULD NOT FINISH")
    assert "VERIFIED" not in output


def test_the_verified_output_states_the_counts_and_versions(tmp_path):
    document, documents, _hashes = _verified("evidence-record")
    record_file = tmp_path / "record.json"
    record_file.write_text(json.dumps(document))

    status, output = _cli([str(record_file), "--did-dir", str(_write_dids(tmp_path / "d", documents))])

    assert status == EXIT_VERIFIED
    assert f"record_version {document['record_version']!r}" in output
    assessment = assess_session_evidence_record(document, documents)
    assert f"acts: {assessment['verified_acts']} signed act" in output
    assert f"verifier: a2cn {a2cn.__version__}" in output


def test_an_extension_block_is_listed_and_not_interpreted(tmp_path):
    from tests.test_evidence import _generate, _make_session, _mark_timed_out, _offer

    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    record = _generate(session, extensions={"com.example.review": {"note": "kept as is"}})
    record_file = tmp_path / "record.json"
    record_file.write_text(json.dumps(record))

    status, output = _cli([str(record_file), "--did-dir", str(_write_dids(tmp_path / "d", did_documents))])

    assert status == EXIT_VERIFIED, output
    assert "extension com.example.review: present, sealed, not interpreted" in output


@pytest.mark.parametrize(
    "args, message",
    [
        (["does-not-exist.json"], "does not exist"),
        (["{input}", "--did-doc", "no-equals-sign"], "DID=FILE"),
        (["{unknown}"], "cannot tell what the input is"),
        (["{input}", "--wire-version", "0.3"], "single act only"),
        (["{input}", "--type", "nonsense"], "invalid choice"),
    ],
)
def test_bad_usage_exits_2(args, message, tmp_path):
    document, _documents, _hashes = _verified("evidence-record")
    (tmp_path / "input.json").write_text(json.dumps(document))
    (tmp_path / "unknown.json").write_text(json.dumps({"hello": "world"}))
    args = [
        arg.format(input=tmp_path / "input.json", unknown=tmp_path / "unknown.json") for arg in args
    ]

    status, output = _cli(args)

    assert status == EXIT_USAGE
    assert message in output


def test_python_dash_m_runs_the_verifier(tmp_path):
    document, documents, hashes = _verified("transaction-record")
    record_file = tmp_path / "record.json"
    record_file.write_text(json.dumps(document))
    args = [sys.executable, "-m", "a2cn.verify", str(record_file)]
    args += ["--did-dir", str(_write_dids(tmp_path / "d", documents))]
    for offer_hash in hashes or []:
        args += ["--offer-hash", offer_hash]

    completed = subprocess.run(args, cwd=PYTHON_ROOT, capture_output=True, text=True, timeout=60)

    assert completed.returncode == EXIT_VERIFIED, completed.stdout + completed.stderr
    assert completed.stdout.startswith("VERIFIED")
