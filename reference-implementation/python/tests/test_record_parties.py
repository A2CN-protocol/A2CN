"""Section 9.5 steps 10 to 12: a TransactionRecord is signed one act by each of its two parties.

Before these steps a record whose two acts one party signed verified: nothing
compared either signer with the other, the acceptance's signed accepted_offer_id
was never compared with final_offer.message_id, and negotiation_summary's
parties were never read. The live session refuses one party signing both sides
by turn order; a record presented to a verifier has no session behind it.

Each case in ``transaction-record-parties.json`` is a record whose hashes and
signatures are genuine, so it fails at exactly the step it names, and the
TypeScript suite reads the same bytes.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn.crypto import hash_object, verify_jws
from a2cn.did import get_public_key, get_verification_method
from a2cn.messages import protocol_act_object, rebuild_signed_act
from a2cn.record import (
    REASON_ACCEPTANCE_SIGNATURE_INVALID,
    REASON_ACCEPTED_OFFER_ID_MISMATCH,
    REASON_KEY_NOT_FOUND,
    REASON_NOT_BILATERAL,
    REASON_OFFER_SIGNATURE_INVALID,
    REASON_PARTY_SUMMARY_MISMATCH,
    REASON_SAME_SIGNING_KEY,
    generate_transaction_record,
    verify_transaction_record,
    verify_transaction_record_reason,
)
from a2cn.session import SessionManager, SessionState

VECTORS = Path(__file__).parents[3] / "spec" / "test-vectors"
VECTOR = json.loads((VECTORS / "transaction-record-parties.json").read_text())
BASIS = json.loads((VECTORS / "transaction-record-basis.json").read_text())
DIDS = VECTOR["did_documents"]
CASES = {case["name"]: case for case in VECTOR["cases"]}
SHAPE_CASES = VECTOR["shape_cases"]
ATTACKS = [case for case in VECTOR["cases"] if not case["verifies"]]
NEW_REASONS = {
    REASON_NOT_BILATERAL,
    REASON_ACCEPTED_OFFER_ID_MISMATCH,
    REASON_PARTY_SUMMARY_MISMATCH,
    REASON_SAME_SIGNING_KEY,
}


def _reason(case: dict, resolver=DIDS, hashes=None) -> str | None:
    return verify_transaction_record_reason(
        case["record"], resolver, case["offer_hashes"] if hashes is None else hashes
    )


def _resealed(record: dict) -> dict:
    record = copy.deepcopy(record)
    record["record_hash"] = ""
    record["record_hash"] = hash_object(record)
    return record


def test_the_reason_codes_are_their_names():
    assert REASON_NOT_BILATERAL == "NOT_BILATERAL"
    assert REASON_ACCEPTED_OFFER_ID_MISMATCH == "ACCEPTED_OFFER_ID_MISMATCH"
    assert REASON_PARTY_SUMMARY_MISMATCH == "PARTY_SUMMARY_MISMATCH"
    assert REASON_SAME_SIGNING_KEY == "SAME_SIGNING_KEY"


@pytest.mark.parametrize("case", VECTOR["cases"] + SHAPE_CASES, ids=lambda case: case["name"])
def test_the_record_reaches_the_stated_verdict(case):
    assert _reason(case) == case["expected_reason"]
    assert verify_transaction_record(case["record"], DIDS, case["offer_hashes"]) is case["verifies"]


def test_the_vector_covers_every_new_reason_and_both_controls():
    assert {case["expected_reason"] for case in ATTACKS} == NEW_REASONS
    assert CASES["one_round_control"]["verifies"] and CASES["multi_round_control"]["verifies"]


@pytest.mark.parametrize("case", ATTACKS, ids=lambda case: case["name"])
def test_every_earlier_check_passes(case):
    """The record is sealed, its offer rebinds, and the acceptance names the offer's hash."""
    record = case["record"]
    assert _resealed(record)["record_hash"] == record["record_hash"]
    offer = record["final_offer"]
    rebuilt = protocol_act_object(
        protocol_version=offer["protocol_version"],
        session_id=record["session_id"],
        round_number=offer["round_number"],
        sequence_number=offer["sequence_number"],
        message_type=offer["message_type"],
        sender_did=offer["sender_did"],
        timestamp=offer["timestamp"],
        expires_at=offer["expires_at"],
        terms=record["agreed_terms"],
    )
    assert hash_object(rebuilt) == offer["protocol_act_hash"]
    assert record["final_acceptance"]["accepted_protocol_act_hash"] == offer["protocol_act_hash"]


def _signature_is_genuine(record: dict, act: str) -> bool:
    """Verify one act's signature under its signer's own DID document, independently."""
    signed = record[act]
    document = DIDS[signed["sender_did"]]
    key = get_public_key(get_verification_method(document, document["verificationMethod"][0]["id"]))
    if act == "final_offer":
        return verify_jws(signed["protocol_act_signature"], key) == signed["protocol_act_hash"]
    rebuilt = rebuild_signed_act(
        {
            "protocol_version": signed["protocol_version"],
            "session_id": record["session_id"],
            "round_number": signed["round_number"],
            "sequence_number": signed["sequence_number"],
            "message_type": signed["message_type"],
            "sender_did": signed["sender_did"],
            "timestamp": signed["timestamp"],
            "accepted_offer_id": signed["accepted_offer_id"],
            "accepted_protocol_act_hash": signed["accepted_protocol_act_hash"],
        }
    )
    return verify_jws(signed["acceptance_signature"], key) == hash_object(rebuilt)


@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda case: case["name"])
def test_both_signatures_are_genuine(case):
    """No case is refused for a forged signature: each signer really signed."""
    assert _signature_is_genuine(case["record"], "final_offer")
    assert _signature_is_genuine(case["record"], "final_acceptance")


@pytest.mark.parametrize("name", ["one_key_two_spellings", "two_dids_one_key"])
def test_one_key_under_two_dids_is_one_signer(name):
    case = CASES[name]
    record = case["record"]
    offer_jwk = DIDS[record["final_offer"]["sender_did"]]["verificationMethod"][0]["publicKeyJwk"]
    acceptance_jwk = DIDS[record["final_acceptance"]["sender_did"]]["verificationMethod"][0][
        "publicKeyJwk"
    ]
    assert record["final_offer"]["sender_did"] != record["final_acceptance"]["sender_did"]
    assert offer_jwk == acceptance_jwk
    assert _reason(case) == REASON_SAME_SIGNING_KEY


def test_the_respelled_did_differs_only_in_the_hosts_case():
    record = CASES["one_key_two_spellings"]["record"]
    initiator = record["parties"]["initiator"]["did"]
    responder = record["parties"]["responder"]["did"]
    assert initiator != responder and initiator.lower() == responder.lower()


def test_the_one_round_control_is_what_the_reference_implementation_generates():
    manager = SessionManager()
    for did in (BASIS["session_init"]["initiator"]["did"], BASIS["session_ack"]["responder"]["did"]):
        manager.register_did_document(did, DIDS[did])
    session = manager.create_session(
        BASIS["session_id"],
        BASIS["session_init"],
        BASIS["session_ack"],
        BASIS["session_ack"]["session_created_at"],
        legacy_replay=True,
    )
    session.session_timeout_seconds = 86400 * 365 * 100
    for message in copy.deepcopy(VECTOR["one_round_messages"]):
        manager.process_message(session, message)
    assert session.state == SessionState.COMPLETED
    assert generate_transaction_record(session) == CASES["one_round_control"]["record"]


def test_the_multi_round_control_is_the_basis_vectors_bound_record():
    assert (
        CASES["multi_round_control"]["record"]
        == BASIS["expected"]["record_version_0_4"]["full_record"]
    )


class _Recorder:
    def __init__(self, documents):
        self.documents = documents
        self.asked: list[str] = []

    def __call__(self, did):
        self.asked.append(did)
        return self.documents[did]


@pytest.mark.parametrize(
    "case",
    [case for case in ATTACKS if case["expected_reason"] != REASON_SAME_SIGNING_KEY],
    ids=lambda case: case["name"],
)
def test_a_structural_refusal_needs_no_keys(case):
    """Steps 10's party comparison, 11 and 12 are refused before any DID is resolved."""
    resolver = _Recorder(DIDS)
    assert _reason(case, resolver) == case["expected_reason"]
    assert resolver.asked == []
    assert _reason(case, {}) == case["expected_reason"]


@pytest.mark.parametrize("name", ["one_key_two_spellings", "two_dids_one_key"])
def test_same_key_waits_for_both_keys(name):
    """With either signer's key unavailable the keys cannot be compared: KEY_NOT_FOUND."""
    case = CASES[name]
    record = case["record"]
    for withheld in (record["final_offer"]["sender_did"], record["final_acceptance"]["sender_did"]):
        documents = {did: doc for did, doc in DIDS.items() if did != withheld}
        assert _reason(case, documents) == REASON_KEY_NOT_FOUND


@pytest.mark.parametrize("name", ["one_key_two_spellings", "two_dids_one_key"])
def test_same_key_comes_before_the_offer_chain(name):
    case = CASES[name]
    assert _reason(case, hashes=["not-the-chain"]) == REASON_SAME_SIGNING_KEY


@pytest.mark.parametrize("name", ["one_key_two_spellings", "two_dids_one_key"])
def test_a_signature_failure_comes_before_same_key(name):
    record = copy.deepcopy(CASES[name]["record"])
    record["final_acceptance"]["acceptance_signature"] = CASES["one_round_control"]["record"][
        "final_acceptance"
    ]["acceptance_signature"]
    case = {**CASES[name], "record": _resealed(record)}
    assert _reason(case) == REASON_ACCEPTANCE_SIGNATURE_INVALID


def test_the_structural_steps_come_in_order():
    """A record failing steps 10, 11 and 12 at once reports step 10, then 11, then 12."""
    record = copy.deepcopy(CASES["offerer_signs_acceptance"]["record"])
    record["final_offer"]["message_id"] = "another-offer"
    record["negotiation_summary"]["initiating_party_did"] = "did:web:elsewhere.example"
    case = {**CASES["offerer_signs_acceptance"], "record": _resealed(record)}
    assert _reason(case) == REASON_NOT_BILATERAL

    record = copy.deepcopy(CASES["offer_message_id_changed"]["record"])
    record["negotiation_summary"]["initiating_party_did"] = "did:web:elsewhere.example"
    case = {**CASES["offer_message_id_changed"], "record": _resealed(record)}
    assert _reason(case) == REASON_ACCEPTED_OFFER_ID_MISMATCH


def test_a_structural_step_comes_before_a_signature_failure():
    """The offer's signature is replaced by one over another act: step 12 is reported first."""
    wrong_signature = CASES["multi_round_control"]["record"]["final_offer"]["protocol_act_signature"]
    record = copy.deepcopy(CASES["summary_initiating_party_is_responder"]["record"])
    record["final_offer"]["protocol_act_signature"] = wrong_signature
    assert _reason({**CASES["one_round_control"], "record": _resealed(record)}) == (
        REASON_PARTY_SUMMARY_MISMATCH
    )
    record["negotiation_summary"]["initiating_party_did"] = record["parties"]["initiator"]["did"]
    assert _reason({**CASES["one_round_control"], "record": _resealed(record)}) == (
        REASON_OFFER_SIGNATURE_INVALID
    )


@pytest.mark.parametrize(
    "respelled",
    [
        lambda did: did + " ",
        lambda did: did.replace("acme-corp", "Acme-Corp"),
        lambda did: did + "#key-2026-01",
    ],
    ids=["trailing-space", "host-case", "did-url"],
)
def test_party_dids_are_compared_as_exact_strings(respelled):
    """No normalization: a responder DID spelled otherwise than its signer's is not that signer."""
    record = copy.deepcopy(CASES["one_round_control"]["record"])
    record["parties"]["responder"]["did"] = respelled(record["parties"]["responder"]["did"])
    case = {**CASES["one_round_control"], "record": _resealed(record)}
    assert _reason(case) == REASON_NOT_BILATERAL
