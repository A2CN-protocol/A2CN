"""a2cn-verify on a deal: a TransactionRecord with its evidence record, keys fetched live.

The records come from transaction-record-offer-history.json, a two-round session.
The parties' did:web hosts are mocked: these tests never touch the network.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import httpx
import respx

from a2cn.did import did_web_document_url
from a2cn.verify import EXIT_REFUSED, EXIT_UNFINISHED, EXIT_VERIFIED, run

VECTOR = json.loads(
    (
        Path(__file__).parents[3] / "spec" / "test-vectors" / "transaction-record-offer-history.json"
    ).read_text()
)
CURRENT = VECTOR["did_documents"]["current"]
ROTATED = VECTOR["did_documents"]["rotated"]
TR = VECTOR["transaction_record"]
SER = VECTOR["evidence_record"]
HISTORY_CASES = {case["name"]: case for case in VECTOR["history_cases"]}
ROTATED_KEY = next(
    case for case in VECTOR["record_cases"] if case["name"] == "evidence_key_not_listed"
)["expected_unresolved_keys"][0]


def _deal(tmp_path: Path, **files) -> Path:
    folder = tmp_path / "deal"
    folder.mkdir()
    for name, document in files.items():
        (folder / f"{name}.json").write_text(json.dumps(document))
    return folder


def _host(documents: dict, *, failing: tuple[str, ...] = ()):
    """A respx router serving each DID document at its did:web address."""
    router = respx.mock(assert_all_called=False)
    for did, document in documents.items():
        route = router.get(did_web_document_url(did))
        if did in failing:
            route.mock(return_value=httpx.Response(404))
        else:
            route.mock(return_value=httpx.Response(200, json=document))
    return router


def _cli(args: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    status = run(args, out=out, err=err)
    return status, out.getvalue() + err.getvalue()


def _block(output: str, name: str) -> str:
    """The lines reported for one input file."""
    lines = output.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(str(name)))
    block = [lines[start]]
    for line in lines[start + 1 :]:
        if not line.startswith("  "):
            break
        block.append(line)
    return "\n".join(block)


def test_a_two_round_record_alone_cannot_finish_but_both_signatures_verified(tmp_path):
    folder = _deal(tmp_path, transaction_record=TR)
    with _host(CURRENT):
        status, output = _cli([str(folder)])

    assert status == EXIT_UNFINISHED, output
    assert "COULD NOT FINISH: the earlier offers are not available" in output
    assert (
        "agreed terms and both signatures verified; this deal took 2 rounds and the record carries "
        "only the final offer; add this session's evidence record to check the earlier offers"
    ) in output
    assert "acts: 2 signed acts verified" in output
    assert "REFUSED" not in output


def test_the_record_and_its_evidence_record_verify_with_keys_from_the_parties_sites(tmp_path):
    folder = _deal(tmp_path, transaction_record=TR, evidence_record=SER)
    with _host(CURRENT) as host:
        status, output = _cli([str(folder)])
        calls = [route.call_count for route in host.routes]  # respx clears them on exit

    assert status == EXIT_VERIFIED, output
    tr_block = _block(output, folder / "transaction_record.json")
    assert "  VERIFIED" in tr_block
    assert (
        "offer history: 2 offers, each signed by its sender, from the evidence record "
        f"{folder / 'evidence_record.json'}"
    ) in tr_block
    for did in CURRENT:
        assert f"keys: {did} from {did_web_document_url(did)}" in output
    assert "overall: VERIFIED (2 verified, 0 refused, 0 could not finish)" in output
    assert calls == [1] * len(CURRENT)  # each party's document fetched once


def test_an_evidence_record_for_another_record_does_not_pair(tmp_path):
    other = HISTORY_CASES["not_linked"]["evidence_record"]
    folder = _deal(tmp_path, transaction_record=TR, evidence_record=other)
    with _host(CURRENT):
        status, output = _cli([str(folder)])

    assert status == EXIT_UNFINISHED, output
    tr_block = _block(output, folder / "transaction_record.json")
    assert "COULD NOT FINISH: the earlier offers are not available" in tr_block
    assert "names another TransactionRecord" in tr_block
    assert "  VERIFIED" in _block(output, folder / "evidence_record.json")


def test_an_evidence_record_with_a_missing_round_is_refused(tmp_path):
    gapped = HISTORY_CASES["missing_round"]["evidence_record"]
    folder = _deal(tmp_path, transaction_record=TR, evidence_record=gapped)
    with _host(CURRENT):
        status, output = _cli([str(folder)])

    assert status == EXIT_REFUSED, output
    assert "REFUSED: OFFER_HISTORY_ROUNDS" in _block(output, folder / "transaction_record.json")


def test_offline_uses_only_the_did_documents_in_the_folder(tmp_path):
    documents = {f"did_{index}": doc for index, doc in enumerate(CURRENT.values())}
    folder = _deal(tmp_path, transaction_record=TR, evidence_record=SER, **documents)
    with _host(CURRENT) as host:
        status, output = _cli([str(folder), "--offline"])
        calls = [route.call_count for route in host.routes]  # respx clears them on exit

    assert status == EXIT_VERIFIED, output
    assert calls == [0] * len(CURRENT)
    assert "offline: not checked against the party's site" in output
    assert "DID documents: offline, from the inputs only; not checked against the parties' sites" in output


def test_offline_without_the_documents_cannot_finish(tmp_path):
    folder = _deal(tmp_path, transaction_record=TR, evidence_record=SER)
    status, output = _cli([str(folder), "--offline"])

    assert status == EXIT_UNFINISHED, output
    assert "no DID document for" in output


def test_a_live_document_without_the_signing_key_names_the_key(tmp_path):
    folder = _deal(tmp_path, transaction_record=TR, evidence_record=SER)
    with _host(ROTATED):
        status, output = _cli([str(folder)])

    assert status == EXIT_UNFINISHED, output
    assert "COULD NOT FINISH: a signature names a key no available DID document lists" in output
    assert (
        f"{ROTATED_KEY['did']} doesn't list key {ROTATED_KEY['verification_method']} (rotated?); "
        "supply the DID document as it was at signing time"
    ) in output
    assert "REFUSED" not in output


def test_a_supplied_copy_used_for_a_key_the_site_no_longer_lists_cannot_be_a_clean_pass(tmp_path):
    saved = {f"saved_{index}": doc for index, doc in enumerate(CURRENT.values())}
    folder = _deal(tmp_path, transaction_record=TR, evidence_record=SER, **saved)
    with _host(ROTATED):
        status, output = _cli([str(folder)])

    assert status == EXIT_UNFINISHED, output
    assert "COULD NOT FINISH: verified only against a supplied DID document" in output
    assert (
        f"keys: {ROTATED_KEY['did']} from {did_web_document_url(ROTATED_KEY['did'])}, with "
        f"{ROTATED_KEY['verification_method']} from a supplied copy, "
    ) in output
    assert "the party's site does not list it now" in output


def test_a_failed_live_fetch_falls_back_to_a_supplied_copy_and_says_so(tmp_path):
    saved = {f"saved_{index}": doc for index, doc in enumerate(CURRENT.values())}
    folder = _deal(tmp_path, transaction_record=TR, evidence_record=SER, **saved)
    failing = tuple(CURRENT)
    with _host(CURRENT, failing=failing):
        status, output = _cli([str(folder)])

    assert status == EXIT_UNFINISHED, output
    assert "from a supplied copy" in output
    assert "failed: HTTPStatusError" in output


def test_a_failed_live_fetch_without_a_copy_cannot_finish(tmp_path):
    folder = _deal(tmp_path, transaction_record=TR, evidence_record=SER)
    with _host(CURRENT, failing=tuple(CURRENT)):
        status, output = _cli([str(folder)])

    assert status == EXIT_UNFINISHED, output
    assert "COULD NOT FINISH: a DID document the check needed is not available" in output


def test_files_can_be_named_one_by_one(tmp_path):
    folder = _deal(tmp_path, transaction_record=TR, evidence_record=SER)
    with _host(CURRENT):
        status, output = _cli(
            [str(folder / "transaction_record.json"), str(folder / "evidence_record.json")]
        )
    assert status == EXIT_VERIFIED, output


def test_typed_offer_hashes_are_labelled_as_unsigned(tmp_path):
    folder = _deal(tmp_path, transaction_record=TR)
    hashes = HISTORY_CASES["paired"]["expected_history"]
    args = [str(folder / "transaction_record.json")]
    for offer_hash in hashes:
        args += ["--offer-hash", offer_hash]
    with _host(CURRENT):
        status, output = _cli(args)

    assert status == EXIT_VERIFIED, output
    assert "typed on the command line; not covered by any signature" in output


def test_offer_hash_is_documented_as_unsigned_in_help():
    from a2cn.verify import _parser

    parser_help = " ".join(_parser().format_help().split())
    assert "Not covered by any signature" in parser_help
    assert "--offline" in parser_help
    assert "--resolve" not in parser_help
