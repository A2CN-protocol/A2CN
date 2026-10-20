"""a2cn-verify verdict precedence.

A definite failure is REFUSED even when some DID document is missing, and a
record is never stronger than the weakest input it relied on: a TransactionRecord
whose offer history was verified against a supplied DID document cannot be a
clean pass. The parties' did:web hosts are mocked; nothing touches the network.
"""

from __future__ import annotations

import copy
import io
import json
import uuid
from pathlib import Path

import httpx
import respx

from a2cn.crypto import generate_keypair, hash_object, public_key_to_jwk, sign_jws
from a2cn.did import did_web_document_url
from a2cn.evidence import generate_session_evidence_record
from a2cn.messages import PROTOCOL_ACT_VERSION, signed_act_hash
from a2cn.record import generate_transaction_record
from a2cn.session import SessionManager, SessionState
from a2cn.verify import EXIT_REFUSED, EXIT_UNFINISHED, EXIT_VERIFIED, run

VECTOR = json.loads(
    (
        Path(__file__).parents[3] / "spec" / "test-vectors" / "transaction-record-offer-history.json"
    ).read_text()
)
CURRENT = VECTOR["did_documents"]["current"]
CASES = {case["name"]: case for case in VECTOR["record_cases"]}
PRODUCER_DID = next(iter(set(CURRENT) - set(VECTOR["did_documents"]["partial"])))


def _host(documents: dict, *, withheld: tuple[str, ...] = ()):
    router = respx.mock(assert_all_called=False)
    for did, document in documents.items():
        response = httpx.Response(404) if did in withheld else httpx.Response(200, json=document)
        router.get(did_web_document_url(did)).mock(return_value=response)
    return router


def _cli(args: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    status = run(args, out=out, err=err)
    return status, out.getvalue() + err.getvalue()


def _deal(tmp_path: Path, name: str, **files) -> Path:
    folder = tmp_path / name
    folder.mkdir()
    for file_name, document in files.items():
        (folder / f"{file_name}.json").write_text(json.dumps(document))
    return folder


def _block(output: str, path: Path) -> str:
    lines = output.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(str(path)))
    block = [lines[start]]
    for line in lines[start + 1 :]:
        if not line.startswith("  "):
            break
        block.append(line)
    return "\n".join(block)


# ---------------------------------------------------------------------------
# P1: a definite failure beats a missing DID document
# ---------------------------------------------------------------------------


def test_a_broken_act_signature_is_refused_even_with_another_document_withheld(tmp_path):
    record = CASES["evidence_broken_act_and_signer_document_unavailable"]["record_document"]
    folder = _deal(tmp_path, "p1", evidence_record=record)
    with _host(CURRENT, withheld=(PRODUCER_DID,)):
        status, output = _cli([str(folder)])

    assert status == EXIT_REFUSED, output
    assert "REFUSED: ACT_INVALID" in output
    assert f"note: no DID document for {PRODUCER_DID}" in output


def test_control_all_signatures_fine_and_a_document_withheld_cannot_finish(tmp_path):
    folder = _deal(tmp_path, "p1_control", evidence_record=VECTOR["evidence_record"])
    with _host(CURRENT, withheld=(PRODUCER_DID,)):
        status, output = _cli([str(folder)])

    assert status == EXIT_UNFINISHED, output
    assert "COULD NOT FINISH: a DID document the check needed is not available" in output
    assert "REFUSED" not in output


def test_a_broken_acceptance_is_refused_with_the_offer_signers_document_withheld(tmp_path):
    record = CASES["record_broken_acceptance_and_signer_document_unavailable"]["record_document"]
    assert record["final_offer"]["sender_did"] == PRODUCER_DID
    folder = _deal(tmp_path, "p1_record", transaction_record=record)
    with _host(CURRENT, withheld=(PRODUCER_DID,)):
        status, output = _cli([str(folder)])

    assert status == EXIT_REFUSED, output
    assert "REFUSED: ACCEPTANCE_SIGNATURE_INVALID" in output
    assert f"note: no DID document for {PRODUCER_DID}" in output
    assert "not checked, key not available: the final offer" in output


# ---------------------------------------------------------------------------
# P2: a record is never stronger than the history it relied on
# ---------------------------------------------------------------------------

BUYER = "did:web:buyer.example"
SELLER = "did:web:seller.example"


def _document(did: str, keys: dict) -> dict:
    ids = [f"{did}#{key_id}" for key_id in keys]
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
        "id": did,
        "verificationMethod": [
            {"id": f"{did}#{key_id}", "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": jwk}
            for key_id, jwk in keys.items()
        ],
        "authentication": ids,
        "assertionMethod": ids,
    }


def _three_round_deal():
    """Offer (round 1), counteroffer (2), counteroffer (3), acceptance.

    The buyer declares key-2 for the session but signs its round-1 offer with
    key-1, which it later retires. Returns the records, the DID documents as
    they were during the session, and the buyer's live document after rotation.
    """
    buyer_k1, buyer_k1_public = generate_keypair()
    buyer_k2, buyer_k2_public = generate_keypair()
    seller_key, seller_public = generate_keypair()
    buyer_both = _document(
        BUYER, {"key-1": public_key_to_jwk(buyer_k1_public), "key-2": public_key_to_jwk(buyer_k2_public)}
    )
    buyer_rotated = _document(BUYER, {"key-2": public_key_to_jwk(buyer_k2_public)})
    seller = _document(SELLER, {"key-1": public_key_to_jwk(seller_public)})

    session_id = str(uuid.uuid4())
    params = {
        "deal_type": "saas_renewal",
        "currency": "USD",
        "max_rounds": 6,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    }
    session_init = {
        "message_type": "session_init",
        "message_id": "init-1",
        "protocol_version": PROTOCOL_ACT_VERSION,
        "session_params": {**params, "subject": "Three rounds"},
        "initiator": {
            "organization_name": "Buyer",
            "did": BUYER,
            "verification_method": f"{BUYER}#key-2",
            "agent_id": "buyer-agent",
            "endpoint": "https://buyer.example/a2cn",
        },
        "initiator_mandate": {"mandate_type": "declared"},
    }
    session_ack = {
        "message_type": "session_ack",
        "message_id": "ack-1",
        "session_id": session_id,
        "in_reply_to": "init-1",
        "protocol_version": PROTOCOL_ACT_VERSION,
        "session_params_accepted": params,
        "responder": {
            "organization_name": "Seller",
            "did": SELLER,
            "verification_method": f"{SELLER}#key-1",
            "agent_id": "seller-agent",
            "endpoint": "https://seller.example/a2cn",
        },
        "responder_mandate": {"mandate_type": "declared"},
        "session_created_at": "2026-03-24T10:00:00Z",
        "current_turn": "initiator",
    }
    manager = SessionManager()
    manager.register_did_document(BUYER, buyer_both)
    manager.register_did_document(SELLER, seller)
    session = manager.create_session(session_id, session_init, session_ack, "2026-03-24T10:00:00Z")
    session.session_timeout_seconds = 86400 * 365 * 100

    def offer(message_type, round_number, sender, key, vm, total):
        timestamp = f"2026-03-24T10:0{round_number}:00Z"
        terms = {"total_value": total, "currency": "USD"}
        act = {
            "protocol_version": PROTOCOL_ACT_VERSION,
            "session_id": session_id,
            "round_number": round_number,
            "sequence_number": round_number,
            "message_type": message_type,
            "sender_did": sender,
            "timestamp": timestamp,
            "expires_at": "2030-01-01T00:00:00Z",
            "terms": terms,
        }
        act_hash = hash_object(act)
        return {
            "message_type": message_type,
            "message_id": f"{message_type}-{round_number}",
            "session_id": session_id,
            "round_number": round_number,
            "sequence_number": round_number,
            "sender_did": sender,
            "sender_agent_id": "agent",
            "sender_verification_method": vm,
            "timestamp": timestamp,
            "expires_at": "2030-01-01T00:00:00Z",
            "terms": terms,
            "protocol_act_hash": act_hash,
            "protocol_act_signature": sign_jws(act_hash, key, kid=vm),
        }

    messages = [
        offer("offer", 1, BUYER, buyer_k1, f"{BUYER}#key-1", 9_000_000),
        offer("counteroffer", 2, SELLER, seller_key, f"{SELLER}#key-1", 9_800_000),
        offer("counteroffer", 3, BUYER, buyer_k2, f"{BUYER}#key-2", 9_400_000),
    ]
    for message in messages:
        manager.process_message(session, message)
    final = messages[-1]
    acceptance = {
        "message_type": "acceptance",
        "message_id": "acceptance-4",
        "in_reply_to": final["message_id"],
        "session_id": session_id,
        "round_number": 3,
        "sequence_number": 4,
        "accepted_offer_id": final["message_id"],
        "accepted_protocol_act_hash": final["protocol_act_hash"],
        "sender_did": SELLER,
        "sender_agent_id": "seller-agent",
        "sender_verification_method": f"{SELLER}#key-1",
        "timestamp": "2026-03-24T10:04:00Z",
    }
    acceptance["acceptance_signature"] = sign_jws(
        signed_act_hash(acceptance, version_when_absent=PROTOCOL_ACT_VERSION),
        seller_key,
        kid=f"{SELLER}#key-1",
    )
    manager.process_message(session, acceptance)
    assert session.state == SessionState.COMPLETED
    record = generate_transaction_record(session)
    evidence = generate_session_evidence_record(
        session,
        producer_private_key=buyer_k2,
        producer_did=BUYER,
        producer_agent_id="buyer-agent",
        producer_verification_method=f"{BUYER}#key-2",
    )
    return record, evidence, {BUYER: buyer_both, SELLER: seller}, buyer_rotated


def test_a_record_whose_history_used_a_supplied_copy_cannot_be_a_clean_pass(tmp_path):
    record, evidence, at_signing, buyer_now = _three_round_deal()
    folder = _deal(
        tmp_path,
        "p2",
        transaction_record=record,
        evidence_record=evidence,
        buyer_saved=at_signing[BUYER],
    )
    live = {BUYER: buyer_now, SELLER: at_signing[SELLER]}
    with _host(live):
        status, output = _cli([str(folder)])

    assert status == EXIT_UNFINISHED, output
    evidence_block = _block(output, folder / "evidence_record.json")
    record_block = _block(output, folder / "transaction_record.json")
    assert "COULD NOT FINISH: verified only against a supplied DID document" in evidence_block
    assert "COULD NOT FINISH: verified only against a supplied DID document" in record_block
    assert (
        f"the round-1 offer in the offer history was signed with {BUYER}#key-1, which came from a "
        f"supplied copy, {folder / 'buyer_saved.json'}"
    ) in record_block
    # Round 3 was signed with key-2, which the party's site still lists.
    assert "round-3" not in record_block
    assert "  VERIFIED" not in output


def test_control_all_keys_live_both_verify(tmp_path):
    record, evidence, at_signing, _buyer_now = _three_round_deal()
    folder = _deal(tmp_path, "p2_control", transaction_record=record, evidence_record=evidence)
    with _host(at_signing):
        status, output = _cli([str(folder)])

    assert status == EXIT_VERIFIED, output
    assert "offer history: 3 offers, each signed by its sender" in output
    assert "overall: VERIFIED (2 verified, 0 refused, 0 could not finish)" in output


def test_a_supplied_copy_in_the_history_is_not_hidden_by_the_records_own_live_keys(tmp_path):
    """The record's own two signatures verify against the live documents."""
    record, evidence, at_signing, buyer_now = _three_round_deal()
    assert record["parties"]["initiator"]["verification_method"] == f"{BUYER}#key-2"
    folder = _deal(
        tmp_path,
        "p2_live",
        transaction_record=record,
        evidence_record=evidence,
        buyer_saved=copy.deepcopy(at_signing[BUYER]),
    )
    with _host({BUYER: buyer_now, SELLER: at_signing[SELLER]}):
        _status, output = _cli([str(folder)])
    record_block = _block(output, folder / "transaction_record.json")
    assert f"keys: {BUYER} from {did_web_document_url(BUYER)}" in record_block
    assert (
        f"keys (offer history): {BUYER} from {did_web_document_url(BUYER)}, with {BUYER}#key-1 "
        f"from a supplied copy, {folder / 'buyer_saved.json'}; the party's site does not list it now"
    ) in record_block


def test_a_copy_that_disagrees_with_the_site_cannot_refuse_a_genuine_record(tmp_path):
    """The copy is right about the retired key-1 but carries other material under key-2.

    The site still lists key-2, so the site's key-2 is used: the copy only adds
    keys the site no longer lists. Swapping in the whole copy would check round
    3 against the copy's key-2 and wrongly refuse a genuine record.
    """
    record, evidence, at_signing, buyer_now = _three_round_deal()
    _other, other_public = generate_keypair()
    conflicting = copy.deepcopy(at_signing[BUYER])
    for method in conflicting["verificationMethod"]:
        if method["id"] == f"{BUYER}#key-2":
            method["publicKeyJwk"] = public_key_to_jwk(other_public)
    folder = _deal(
        tmp_path, "conflict", transaction_record=record, evidence_record=evidence, buyer_saved=conflicting
    )
    with _host({BUYER: buyer_now, SELLER: at_signing[SELLER]}):
        status, output = _cli([str(folder)])

    assert status == EXIT_UNFINISHED, output
    assert "REFUSED" not in output
    assert (
        f"note: the supplied copy {folder / 'buyer_saved.json'} disagrees with the party's site about "
        f"key {BUYER}#key-2; the site's key was used"
    ) in output
    for name in ("evidence_record.json", "transaction_record.json"):
        assert "COULD NOT FINISH: verified only against a supplied DID document" in _block(output, folder / name)


def test_an_outright_fetch_failure_still_falls_back_to_the_whole_copy(tmp_path):
    record, evidence, at_signing, _buyer_now = _three_round_deal()
    folder = _deal(
        tmp_path, "fetch_failed", transaction_record=record, evidence_record=evidence, buyer_saved=at_signing[BUYER]
    )
    with _host(at_signing, withheld=(BUYER,)):
        status, output = _cli([str(folder)])

    assert status == EXIT_UNFINISHED, output
    assert f"keys: {BUYER} from a supplied copy, {folder / 'buyer_saved.json'}; fetching" in output
    record_block = _block(output, folder / "transaction_record.json")
    # Every key came from the copy, so both of the buyer's offers are named.
    assert "the round-1 offer in the offer history was signed with" in record_block
    assert "the round-3 counteroffer in the offer history was signed with" in record_block
