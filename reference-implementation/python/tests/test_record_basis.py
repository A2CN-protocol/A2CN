"""The TransactionRecord basis: recorded beside currency and bound to agreed_terms.basis.

spec/test-vectors/transaction-record-basis.json is a session that fixed basis
"gross"; each of its offers restates the basis in terms.basis (Section 7.2).
The TypeScript suite replays the same signed messages and must reach the same
record_hash. The record_version follows the basis: a record that carries basis
is "0.2", and a session that fixed no basis gets a "0.1" record without the
key, byte-identical to the record an implementation that predates basis produced
for it (Sections 9.3 and 9.5).
"""

from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path

import httpx
import pytest

from a2cn.client import A2CNClient
from a2cn.crypto import generate_keypair, hash_object, private_key_from_jwk, sign_jws
from a2cn.evidence import generate_session_evidence_record, verify_session_evidence_record
from a2cn.record import generate_transaction_record, verify_transaction_record
from a2cn.session import SessionManager, SessionState
from tests.conftest import INITIATOR_DID, RESPONDER_DID, make_session_init

REPO_ROOT = Path(__file__).parents[3]
VECTOR = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "transaction-record-basis.json").read_text()
)
# A session that fixed no basis, with the record_version "0.1" record an
# implementation that predates basis produced for it. This implementation
# produces the same record.
WITHOUT_BASIS = VECTOR["without_basis"]
_ABSENT = object()


def _replay(session_id, session_init, session_ack, did_documents, messages):
    """Run recorded messages through the responder state machine to COMPLETED."""
    manager = SessionManager()
    for did, did_document in did_documents.items():
        manager.register_did_document(did, did_document)
    session = manager.create_session(
        session_id, session_init, session_ack, session_ack["session_created_at"]
    )
    session.session_timeout_seconds = 86400 * 365 * 100  # the timestamps are in the past
    for message in copy.deepcopy(messages):
        manager.process_message(session, message)
    assert session.state == SessionState.COMPLETED
    return session


def _replay_vector():
    return _replay(
        VECTOR["session_id"],
        VECTOR["session_init"],
        VECTOR["session_ack"],
        VECTOR["did_documents"],
        VECTOR["messages"],
    )


def _replay_without_basis():
    return _replay(
        WITHOUT_BASIS["session_id"],
        WITHOUT_BASIS["session_init"],
        WITHOUT_BASIS["session_ack"],
        WITHOUT_BASIS["did_documents"],
        WITHOUT_BASIS["messages"],
    )


def _offer_hashes(messages) -> list[str]:
    return [
        message["protocol_act_hash"]
        for message in messages
        if message["message_type"] in ("offer", "counteroffer")
    ]


def _resealed(record: dict) -> dict:
    record = copy.deepcopy(record)
    record["record_hash"] = ""
    record["record_hash"] = hash_object(record)
    return record


def _verifies(record: dict) -> bool:
    return verify_transaction_record(
        record, VECTOR["did_documents"], _offer_hashes(VECTOR["messages"])
    )


def _verifies_without_basis(record: dict) -> bool:
    return verify_transaction_record(
        record, WITHOUT_BASIS["did_documents"], _offer_hashes(WITHOUT_BASIS["messages"])
    )


def _client_side_record(vector: dict) -> dict:
    """The record the initiator's client builds from the vector's messages."""
    client = A2CNClient(
        agent_info=vector["session_init"]["initiator"],
        private_key=generate_keypair()[0],
        mandate=vector["session_init"]["initiator_mandate"],
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(503))
        ),
    )
    session_id = vector["session_id"]
    # The state initiate_session caches, then every message as the client records it.
    client._sessions[session_id] = {
        "session_init": vector["session_init"],
        "session_ack": vector["session_ack"],
        "sequence_number": 0,
        "round_number": 0,
        "current_turn": "initiator",
        "offer_chain": [],
        "message_log": [],
        "latest_offer": None,
    }
    for message in copy.deepcopy(vector["messages"]):
        client.process_incoming(session_id, message)
    return client.build_client_side_record(session_id)


# ---------------------------------------------------------------------------
# Generation: the shared vector, server side and client side
# ---------------------------------------------------------------------------

def test_basis_record_vector_replays_to_the_expected_record():
    record = generate_transaction_record(_replay_vector())
    expected = VECTOR["expected"]

    assert record["basis"] == expected["basis"]
    assert record["basis"] == VECTOR["session_ack"]["session_params_accepted"]["basis"]
    # agreed_terms is the final offer's terms, which restate the basis.
    assert record["agreed_terms"]["basis"] == record["basis"]
    assert record == expected["full_record"]
    assert record["record_hash"] == expected["record_hash"]
    assert _verifies(record)


def test_client_side_record_matches_the_vector():
    client = A2CNClient(
        agent_info=VECTOR["session_init"]["initiator"],
        private_key=generate_keypair()[0],
        mandate=VECTOR["session_init"]["initiator_mandate"],
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(503))
        ),
    )
    session_id = VECTOR["session_id"]
    # The state initiate_session caches, then every message as the client records it.
    client._sessions[session_id] = {
        "session_init": VECTOR["session_init"],
        "session_ack": VECTOR["session_ack"],
        "sequence_number": 0,
        "round_number": 0,
        "current_turn": "initiator",
        "offer_chain": [],
        "message_log": [],
        "latest_offer": None,
    }
    for message in copy.deepcopy(VECTOR["messages"]):
        client.process_incoming(session_id, message)

    assert client.build_client_side_record(session_id) == VECTOR["expected"]["full_record"]


def test_a_session_without_basis_replays_to_its_0_1_record():
    """A session that fixed no basis gets exactly the record it got before basis existed."""
    record = generate_transaction_record(_replay_without_basis())
    earlier = WITHOUT_BASIS["record_version_0_1"]

    assert "basis" not in record
    assert record["record_version"] == "0.1"
    # The same fields in the same order: the same bytes, so the same hash (Section 9.2).
    assert json.dumps(record) == json.dumps(earlier["full_record"])
    assert record["record_hash"] == earlier["record_hash"]
    assert _verifies_without_basis(record)


def test_client_side_record_for_a_session_without_basis_is_its_0_1_record():
    record = _client_side_record(WITHOUT_BASIS)

    assert json.dumps(record) == json.dumps(WITHOUT_BASIS["record_version_0_1"]["full_record"])


def test_a_record_version_0_1_record_still_verifies():
    vector = WITHOUT_BASIS
    earlier = vector["record_version_0_1"]["full_record"]

    assert verify_transaction_record(
        earlier, vector["did_documents"], _offer_hashes(vector["messages"])
    )


def test_a_session_without_basis_record_relabelled_0_2_fails_verification():
    """Section 9.5 step 7: a "0.2" record carries basis, and this one has none to carry."""
    relabelled = _resealed(
        {**WITHOUT_BASIS["record_version_0_1"]["full_record"], "record_version": "0.2"}
    )

    assert "basis" not in relabelled["agreed_terms"]
    assert relabelled["record_hash"] == WITHOUT_BASIS["relabelled_0_2_record_hash"]
    assert not _verifies_without_basis(relabelled)


def _server_side_record(vector: dict) -> dict:
    """The record the responder's state machine generates from the vector's messages."""
    return generate_transaction_record(
        _replay(
            vector["session_id"],
            vector["session_init"],
            vector["session_ack"],
            vector["did_documents"],
            vector["messages"],
        )
    )


def _without_basis_proposing(basis: str) -> dict:
    """without_basis with a SessionInit that proposed ``basis`` and a SessionAck that omits it.

    The SessionAck is the one a responder that predates basis sends, so the
    session's basis is unstated whatever the SessionInit proposed (Section 6.4.1).
    Neither the SessionInit nor its session_params is inside a signed act, so the
    recorded offers and acceptance still verify.
    """
    vector = copy.deepcopy(WITHOUT_BASIS)
    vector["session_init"]["session_params"]["basis"] = basis
    assert "basis" not in vector["session_ack"]["session_params_accepted"]
    return vector


RECORD_BUILDERS = {"server": _server_side_record, "client": _client_side_record}


@pytest.mark.parametrize("builder", sorted(RECORD_BUILDERS))
@pytest.mark.parametrize("basis", WITHOUT_BASIS["unechoed_proposed_bases"])
def test_a_proposed_basis_the_session_ack_omits_is_not_recorded(basis, builder):
    """Section 9.3: the record's basis, and so its version, follows the SessionAck."""
    record = RECORD_BUILDERS[builder](_without_basis_proposing(basis))
    earlier = WITHOUT_BASIS["record_version_0_1"]

    assert "basis" not in record
    assert json.dumps(record) == json.dumps(earlier["full_record"])
    assert record["record_hash"] == earlier["record_hash"]
    assert _verifies_without_basis(record)


@pytest.mark.parametrize("builder", sorted(RECORD_BUILDERS))
@pytest.mark.parametrize("basis", WITHOUT_BASIS["unechoed_proposed_bases"])
def test_a_proposed_basis_the_session_ack_omits_leaves_a_0_1_schema_record(basis, builder):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (REPO_ROOT / "spec" / "schemas" / "transaction-record.schema.json").read_text()
    )
    record = RECORD_BUILDERS[builder](_without_basis_proposing(basis))

    assert list(jsonschema.Draft202012Validator(schema).iter_errors(record)) == []


@pytest.mark.asyncio
async def test_client_side_record_matches_the_server_record(
    test_client, responder_test_client, initiator_keypair, responder_keypair,
    initiator_did_doc, responder_did_doc,
):
    session_init = make_session_init()
    client = A2CNClient(
        agent_info=session_init["initiator"],
        private_key=initiator_keypair[0],
        mandate=session_init["initiator_mandate"],
        http_client=test_client,
    )
    ack = await client.initiate_session(
        "http://test", RESPONDER_DID, {**session_init["session_params"], "basis": "gross"}
    )
    session_id = ack["session_id"]
    # The client sends terms as given: the caller restates the session basis.
    await client.send_offer(
        "http://test",
        RESPONDER_DID,
        session_id,
        {"total_value": 9_500_000, "currency": "USD", "basis": "gross"},
    )
    offer = client._sessions[session_id]["latest_offer"]

    responder_vm = f"{RESPONDER_DID}#key-2026-01"
    payload = {
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 2,
        "accepted_offer_id": offer["message_id"],
        "accepted_protocol_act_hash": offer["protocol_act_hash"],
    }
    acceptance = {
        "message_type": "acceptance",
        "message_id": str(uuid.uuid4()),
        "in_reply_to": offer["message_id"],
        **payload,
        "sender_did": RESPONDER_DID,
        "sender_agent_id": "sales-agent-acme-007",
        "sender_verification_method": responder_vm,
        "timestamp": offer["timestamp"],
        "acceptance_signature": sign_jws(hash_object(payload), responder_keypair[0], kid=responder_vm),
    }
    r = await responder_test_client.post(
        f"/sessions/{session_id}/messages",
        json=acceptance,
        headers={"Content-Type": "application/a2cn+json", "Idempotency-Key": acceptance["message_id"]},
    )
    assert r.status_code == 200
    client.process_incoming(session_id, acceptance)

    r = await test_client.get(f"/sessions/{session_id}/record")
    assert r.status_code == 200
    server_record = r.json()

    assert server_record["basis"] == "gross"
    assert server_record["agreed_terms"]["basis"] == "gross"
    assert client.build_client_side_record(session_id) == server_record
    assert verify_transaction_record(
        server_record,
        {INITIATOR_DID: initiator_did_doc, RESPONDER_DID: responder_did_doc},
        [offer["protocol_act_hash"]],
    )


# ---------------------------------------------------------------------------
# Verification (Section 9.5): a recorded basis is a basis equal to agreed_terms.basis
# ---------------------------------------------------------------------------

def test_flipping_the_record_basis_fails_verification():
    record = generate_transaction_record(_replay_vector())
    tampered = copy.deepcopy(record)
    tampered["basis"] = VECTOR["expected"]["tampered_basis"]
    tampered = _resealed(tampered)

    assert tampered["record_hash"] == VECTOR["expected"]["tampered_record_hash"]
    assert not _verifies(tampered)


@pytest.mark.parametrize(
    ("record_basis", "agreed_basis"),
    [
        ("gross", _ABSENT),
        ("gross", "net"),
        (None, None),
        ("vat", "vat"),
        ("GROSS", "GROSS"),
    ],
    ids=[
        "agreed-terms-basis-absent",
        "agreed-terms-basis-differs",
        "both-null",
        "both-unrecognized",
        "both-uppercase",
    ],
)
def test_record_basis_must_be_a_basis_equal_to_agreed_terms(record_basis, agreed_basis):
    record = generate_transaction_record(_replay_vector())
    record["basis"] = record_basis
    if agreed_basis is _ABSENT:
        del record["agreed_terms"]["basis"]
    else:
        record["agreed_terms"]["basis"] = agreed_basis

    assert not _verifies(_resealed(record))


def test_record_basis_with_non_object_agreed_terms_fails_verification():
    record = generate_transaction_record(_replay_vector())
    record["agreed_terms"] = []

    assert not _verifies(_resealed(record))


def test_a_0_2_record_without_basis_fails_verification():
    """Section 9.5 step 7: a "0.2" record carries basis, whatever agreed_terms holds."""
    dropped = copy.deepcopy(VECTOR["expected"]["full_record"])
    del dropped["basis"]
    resealed = _resealed(dropped)

    assert resealed["record_version"] == "0.2"
    assert "basis" in resealed["agreed_terms"]
    assert resealed["record_hash"] == VECTOR["expected"]["basis_dropped_record_hash"]
    assert not _verifies(resealed)

    # Key presence: a null agreed_terms.basis counts as carried.
    dropped["agreed_terms"]["basis"] = None
    assert not _verifies(_resealed(dropped))
    # Nor does it verify once agreed_terms carries no basis either.
    del dropped["agreed_terms"]["basis"]
    assert not _verifies(_resealed(dropped))


def test_a_0_1_record_without_basis_gets_no_basis_check():
    """An implementation that predates basis records agreed_terms.basis alone."""
    earlier = copy.deepcopy(VECTOR["expected"]["full_record"])
    del earlier["basis"]
    earlier["record_version"] = "0.1"
    resealed = _resealed(earlier)

    assert resealed["record_hash"] == VECTOR["expected"]["basis_dropped_0_1_record_hash"]
    assert _verifies(resealed)


def test_a_0_1_record_must_not_carry_basis():
    """Section 9.5 step 7: a "0.1" record has no top-level basis, even one equal to agreed_terms.basis."""
    relabelled = _resealed({**VECTOR["expected"]["full_record"], "record_version": "0.1"})

    assert relabelled["basis"] == relabelled["agreed_terms"]["basis"]
    assert relabelled["record_hash"] == VECTOR["expected"]["relabelled_0_1_record_hash"]
    assert not _verifies(relabelled)

    # Key presence: a null basis counts as carried.
    assert not _verifies(_resealed({**relabelled, "basis": None}))


# ---------------------------------------------------------------------------
# The SessionEvidenceRecord seals the basis-carrying record
# ---------------------------------------------------------------------------

def test_basis_fixed_session_evidence_record_seals_the_record_and_verifies():
    producer = VECTOR["producer"]
    evidence = generate_session_evidence_record(
        _replay_vector(),
        producer_private_key=private_key_from_jwk(VECTOR["producer_private_jwk"]),
        producer_did=producer["did"],
        producer_agent_id=producer["agent_id"],
        producer_verification_method=producer["verification_method"],
    )

    assert evidence["transaction_record_hash"] == VECTOR["expected"]["record_hash"]
    assert evidence["record_hash"] == VECTOR["expected"]["evidence_record_hash"]
    assert verify_session_evidence_record(evidence, VECTOR["did_documents"])
