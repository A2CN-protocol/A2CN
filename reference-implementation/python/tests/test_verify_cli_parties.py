"""a2cn-verify on a TransactionRecord that one party signed on both sides.

The records are transaction-record-parties.json's. Every one of Section 9.5's
steps 10 to 12 is a definite failure: REFUSED, exit 1, whatever DID documents
were supplied, because the three structural comparisons need no keys and
SAME_SIGNING_KEY is reached only once both signatures verified.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import httpx
import pytest
import respx

from a2cn.did import did_web_document_url
from a2cn.verify import EXIT_REFUSED, EXIT_UNFINISHED, EXIT_USAGE, run

VECTOR = json.loads(
    (
        Path(__file__).parents[3] / "spec" / "test-vectors" / "transaction-record-parties.json"
    ).read_text()
)
DIDS = VECTOR["did_documents"]
CASES = {case["name"]: case for case in VECTOR["cases"]}
NOT_REACHED = "acts: not reached: the record was refused before its signatures were checked"


def _cli(tmp_path: Path, name: str, dids: list[str]) -> tuple[int, str]:
    record = tmp_path / f"{name}.json"
    record.write_text(json.dumps(CASES[name]["record"]))
    args = [str(record), "--offline"]
    for did in dids:
        document = tmp_path / f"did-{len(args)}.json"
        document.write_text(json.dumps(DIDS[did]))
        args += ["--did-doc", f"{did}={document}"]
    out, err = io.StringIO(), io.StringIO()
    status = run(args, out=out, err=err)
    return status, out.getvalue() + err.getvalue()


def test_the_self_dealt_record_is_refused_with_its_did_document(tmp_path):
    status, output = _cli(tmp_path, "offerer_signs_acceptance", ["did:web:techcorp.example"])
    assert status == EXIT_REFUSED, output
    assert "REFUSED: NOT_BILATERAL" in output
    assert NOT_REACHED in output
    assert "VERIFIED" not in output.splitlines()[1]


def test_the_self_dealt_record_is_refused_with_no_did_documents(tmp_path):
    """A structural refusal needs no keys, so a missing document cannot soften it."""
    status, output = _cli(tmp_path, "offerer_signs_acceptance", [])
    assert status == EXIT_REFUSED, output
    assert "REFUSED: NOT_BILATERAL" in output
    assert "COULD NOT FINISH" not in output
    assert NOT_REACHED in output


@pytest.mark.parametrize(
    "name",
    [
        "one_did_for_both_parties",
        "third_party_signs_acceptance",
        "offer_message_id_changed",
        "acceptance_names_another_offer",
        "summary_accepting_party_is_offerer",
        "summary_initiating_party_is_responder",
    ],
)
@pytest.mark.parametrize("with_documents", [True, False], ids=["documents", "no-documents"])
def test_a_structural_refusal_is_refused_before_the_signatures(tmp_path, name, with_documents):
    status, output = _cli(tmp_path, name, list(DIDS) if with_documents else [])
    assert status == EXIT_REFUSED, output
    assert f"REFUSED: {CASES[name]['expected_reason']}" in output
    assert NOT_REACHED in output


@pytest.mark.parametrize("name", ["one_key_two_spellings", "two_dids_one_key"])
def test_one_key_on_both_sides_is_refused_after_both_signatures_verified(tmp_path, name):
    record = CASES[name]["record"]
    signers = [record["final_offer"]["sender_did"], record["final_acceptance"]["sender_did"]]
    status, output = _cli(tmp_path, name, signers)
    assert status == EXIT_REFUSED, output
    assert "REFUSED: SAME_SIGNING_KEY" in output
    assert (
        "acts: 2 signed acts verified, 0 unsigned observations, 0 invalid "
        "(both verified under one public key)"
    ) in output


@pytest.mark.parametrize("name", ["one_key_two_spellings", "two_dids_one_key"])
def test_one_key_with_a_document_missing_cannot_finish(tmp_path, name):
    """The keys cannot be compared until both are available."""
    record = CASES[name]["record"]
    status, output = _cli(tmp_path, name, [record["final_offer"]["sender_did"]])
    assert status != EXIT_REFUSED, output
    assert "COULD NOT FINISH" in output


# --- One party under two spellings of its did:web DID (Section 4.2) ---------

SPELLINGS = VECTOR["spelling_cases"]


def _spelled(tmp_path: Path, case: dict) -> Path:
    record = tmp_path / f"{case['name']}.json"
    record.write_text(json.dumps(case["record"]))
    return record


def _run(args: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    status = run(args, out=out, err=err)
    return status, out.getvalue() + err.getvalue()


@pytest.mark.parametrize("case", SPELLINGS, ids=lambda case: case["name"])
def test_two_spellings_fetched_live_cannot_finish(tmp_path, case):
    """Both document addresses serve the one document; the network is mocked, never touched."""
    document = case["did_documents"][case["canonical_did"]]
    with respx.mock(assert_all_called=False) as router:
        for did in (case["canonical_did"], case["spelled_did"]):
            router.get(did_web_document_url(did)).mock(return_value=httpx.Response(200, json=document))
        status, output = _run([str(_spelled(tmp_path, case))])
    assert status == EXIT_UNFINISHED, output
    assert "COULD NOT FINISH" in output and "VERIFIED" not in output.splitlines()[1]
    assert "DidDocumentIdMismatch" in output


@pytest.mark.parametrize("case", SPELLINGS, ids=lambda case: case["name"])
def test_two_spellings_offline_with_the_document_cannot_finish(tmp_path, case):
    """Supplied among the inputs, the document is keyed by its id: the other spelling has none."""
    document = tmp_path / "did.json"
    document.write_text(json.dumps(case["did_documents"][case["canonical_did"]]))
    status, output = _run([str(_spelled(tmp_path, case)), str(document), "--offline"])
    assert status == EXIT_UNFINISHED, output
    assert f"no DID document for {case['spelled_did']}" in output


@pytest.mark.parametrize("case", SPELLINGS, ids=lambda case: case["name"])
def test_a_did_doc_naming_another_spelling_is_refused_as_usage(tmp_path, case):
    """--did-doc may not map a document to a DID its id does not name."""
    document = tmp_path / "did.json"
    document.write_text(json.dumps(case["did_documents"][case["canonical_did"]]))
    args = [str(_spelled(tmp_path, case)), "--offline"]
    args += ["--did-doc", f"{case['canonical_did']}={document}", "--did-doc", f"{case['spelled_did']}={document}"]
    status, output = _run(args)
    assert status == EXIT_USAGE, output
    assert f"--did-doc names {case['spelled_did']}" in output
    assert "VERIFIED" not in output
