"""The TransactionRecord basis: recorded beside currency and bound to agreed_terms.basis.

spec/test-vectors/transaction-record-basis.json is a session that fixed basis
"gross"; each of its offers restates the basis in terms.basis (Section 7.2).
The TypeScript suite replays the same signed messages and must reach the same
record_hash. Every record this implementation produces is "0.3", because it
carries the Section 7.3.1 act fields (Section 9.3), and "0.3" is the only
version a verifier accepts. The records earlier implementations produced for the
same two sessions are kept in the vector under the version that produced them,
with their bytes and hashes intact, and are now refused as unbound: nothing
rebinds them to the offering party's signature. Under "0.3" the record carries
basis exactly when agreed_terms does, and equal to it (Section 9.5, step 8).
"""

from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path

import httpx
import pytest

from a2cn.client import A2CNClient
from a2cn.crypto import (
    canonicalize,
    generate_keypair,
    hash_bytes,
    hash_object,
    private_key_from_jwk,
    public_key_to_jwk,
    sign_jws,
)
from a2cn.evidence import generate_session_evidence_record, verify_session_evidence_record
from a2cn.record import (
    FINAL_OFFER_ACT_FIELDS,
    REASON_BASIS_MISMATCH,
    REASON_UNBOUND_RECORD_VERSION,
    generate_transaction_record,
    verify_transaction_record,
    verify_transaction_record_reason,
)
from a2cn.session import SessionManager, SessionState
from tests.conftest import (
    INITIATOR_DID,
    RESPONDER_DID,
    make_did_document,
    make_session_init,
)

REPO_ROOT = Path(__file__).parents[3]
VECTOR = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "transaction-record-basis.json").read_text()
)
# A session that fixed no basis, with the record_version "0.1" record an
# implementation that predates basis produced for it, and the "0.3" record this
# implementation produces.
WITHOUT_BASIS = VECTOR["without_basis"]
# The record this implementation produces for the basis session, and the "0.2"
# record an implementation that predates the agreed_terms binding produced.
EXPECTED_0_3 = VECTOR["expected"]["record_version_0_3"]
EXPECTED_0_2 = VECTOR["expected"]["record_version_0_2"]
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


def _reason(record: dict) -> str | None:
    return verify_transaction_record_reason(
        record, VECTOR["did_documents"], _offer_hashes(VECTOR["messages"])
    )


_BASIS_INITIATOR_KEY, _BASIS_INITIATOR_PUBLIC = generate_keypair()
_BASIS_RESPONDER_KEY, _BASIS_RESPONDER_PUBLIC = generate_keypair()
_BASIS_INITIATOR_VM = f"{INITIATOR_DID}#key-1"
_BASIS_RESPONDER_VM = f"{RESPONDER_DID}#key-2026-01"


def _locally_signed_basis_record() -> tuple[dict, dict]:
    """A completed basis session whose two signing keys this test holds.

    Step 8's cases alter agreed_terms, which also breaks the rebuilt act hash,
    so they must be re-signed over their own terms to isolate step 8. That needs
    keys, which the shared vector does not carry for the initiator.
    """
    session_id = str(uuid.uuid4())
    params = {
        "deal_type": "saas_renewal",
        "currency": "USD",
        "basis": "gross",
        "max_rounds": 4,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    }
    session_init = {
        "message_type": "session_init",
        "message_id": "basis-local-init",
        "protocol_version": "0.2",
        "session_params": {**params, "subject": "Local basis record"},
        "initiator": {
            "organization_name": "TechCorp",
            "did": INITIATOR_DID,
            "verification_method": _BASIS_INITIATOR_VM,
            "agent_id": "buyer-agent",
            "endpoint": "https://techcorp.example/api/a2cn",
        },
        "initiator_mandate": {"mandate_type": "declared"},
    }
    session_ack = {
        "message_type": "session_ack",
        "message_id": "basis-local-ack",
        "session_id": session_id,
        "in_reply_to": "basis-local-init",
        "protocol_version": "0.2",
        "session_params_accepted": params,
        "responder": {
            "organization_name": "Acme",
            "did": RESPONDER_DID,
            "verification_method": _BASIS_RESPONDER_VM,
            "agent_id": "seller-agent",
            "endpoint": "http://localhost:8000",
        },
        "responder_mandate": {"mandate_type": "declared"},
        "session_created_at": "2026-03-24T10:00:00Z",
        "current_turn": "initiator",
    }
    did_documents = {
        INITIATOR_DID: make_did_document(
            INITIATOR_DID, "key-1", public_key_to_jwk(_BASIS_INITIATOR_PUBLIC)
        ),
        RESPONDER_DID: make_did_document(
            RESPONDER_DID, "key-2026-01", public_key_to_jwk(_BASIS_RESPONDER_PUBLIC)
        ),
    }
    manager = SessionManager()
    for did, did_document in did_documents.items():
        manager.register_did_document(did, did_document)
    session = manager.create_session(
        session_id, session_init, session_ack, "2026-03-24T10:00:00Z"
    )
    session.session_timeout_seconds = 86400 * 365 * 100

    terms = {"total_value": 9_500_000, "currency": "USD", "basis": "gross"}
    act = {
        "protocol_version": "0.2",
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 1,
        "message_type": "offer",
        "sender_did": INITIATOR_DID,
        "timestamp": "2026-03-24T10:01:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "terms": terms,
    }
    act_hash = hash_object(act)
    manager.process_message(
        session,
        {
            "message_type": "offer",
            "message_id": "basis-local-offer",
            "session_id": session_id,
            "round_number": 1,
            "sequence_number": 1,
            "sender_did": INITIATOR_DID,
            "sender_agent_id": "buyer-agent",
            "sender_verification_method": _BASIS_INITIATOR_VM,
            "timestamp": "2026-03-24T10:01:00Z",
            "expires_at": "2030-01-01T00:00:00Z",
            "terms": terms,
            "protocol_act_hash": act_hash,
            "protocol_act_signature": sign_jws(
                act_hash, _BASIS_INITIATOR_KEY, kid=_BASIS_INITIATOR_VM
            ),
        },
    )
    payload = {
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 2,
        "accepted_offer_id": "basis-local-offer",
        "accepted_protocol_act_hash": act_hash,
    }
    manager.process_message(
        session,
        {
            "message_type": "acceptance",
            "message_id": "basis-local-acc",
            "in_reply_to": "basis-local-offer",
            **payload,
            "sender_did": RESPONDER_DID,
            "sender_agent_id": "seller-agent",
            "sender_verification_method": _BASIS_RESPONDER_VM,
            "timestamp": "2026-03-24T10:03:00Z",
            "acceptance_signature": sign_jws(
                hash_object(payload), _BASIS_RESPONDER_KEY, kid=_BASIS_RESPONDER_VM
            ),
        },
    )
    assert session.state == SessionState.COMPLETED
    return generate_transaction_record(session), did_documents


def _act_from_record(record: dict) -> dict:
    """The Section 7.3.1 act, rebuilt from the record alone."""
    final_offer = record["final_offer"]
    return {
        "protocol_version": final_offer["protocol_version"],
        "session_id": record["session_id"],
        "round_number": final_offer["round_number"],
        "sequence_number": final_offer["sequence_number"],
        "message_type": final_offer["message_type"],
        "sender_did": final_offer["sender_did"],
        "timestamp": final_offer["timestamp"],
        "expires_at": final_offer["expires_at"],
        "terms": record["agreed_terms"],
    }


def _resigned_over_its_act(record: dict) -> tuple[dict, list[str]]:
    """Re-sign both sides over the record's own act, so step 3 passes."""
    record = copy.deepcopy(record)
    act_hash = hash_object(_act_from_record(record))
    record["final_offer"]["protocol_act_hash"] = act_hash
    record["final_offer"]["protocol_act_signature"] = sign_jws(
        act_hash, _BASIS_INITIATOR_KEY, kid=_BASIS_INITIATOR_VM
    )
    acceptance = record["final_acceptance"]
    acceptance["accepted_protocol_act_hash"] = act_hash
    acceptance["acceptance_signature"] = sign_jws(
        hash_object(
            {
                "session_id": record["session_id"],
                "round_number": acceptance["round_number"],
                "sequence_number": acceptance["sequence_number"],
                "accepted_offer_id": acceptance["accepted_offer_id"],
                "accepted_protocol_act_hash": act_hash,
            }
        ),
        _BASIS_RESPONDER_KEY,
        kid=_BASIS_RESPONDER_VM,
    )
    record["offer_chain_hash"] = hash_bytes(canonicalize([act_hash]))
    return _resealed(record), [act_hash]


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
    assert record == EXPECTED_0_3["full_record"]
    assert record["record_hash"] == EXPECTED_0_3["record_hash"]
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

    assert client.build_client_side_record(session_id) == EXPECTED_0_3["full_record"]


def test_a_session_without_basis_replays_to_its_0_3_record():
    """A session that fixed no basis carries no basis, at whatever version."""
    record = generate_transaction_record(_replay_without_basis())
    current = WITHOUT_BASIS["record_version_0_3"]

    assert "basis" not in record
    assert record["record_version"] == "0.3"
    # The same fields in the same order: the same bytes, so the same hash (Section 9.2).
    assert json.dumps(record) == json.dumps(current["full_record"])
    assert record["record_hash"] == current["record_hash"]
    assert _verifies_without_basis(record)


def test_client_side_record_for_a_session_without_basis_matches_the_vector():
    record = _client_side_record(WITHOUT_BASIS)

    assert json.dumps(record) == json.dumps(WITHOUT_BASIS["record_version_0_3"]["full_record"])


def test_a_record_version_0_1_record_is_refused_as_unbound():
    """The record an implementation that predates basis produced, untouched.

    It carries no act fields, so nothing rebinds agreed_terms to the offering
    party's signature, and a verifier refuses it rather than reporting it as
    proof. This is the deliberate break: it must be regenerated.
    """
    vector = WITHOUT_BASIS
    earlier = vector["record_version_0_1"]["full_record"]
    args = (earlier, vector["did_documents"], _offer_hashes(vector["messages"]))

    assert earlier["record_hash"] == vector["record_version_0_1"]["record_hash"]
    assert not verify_transaction_record(*args)
    assert verify_transaction_record_reason(*args) == REASON_UNBOUND_RECORD_VERSION


def test_a_record_version_0_2_record_is_refused_as_unbound():
    """The record an implementation that predates the act binding produced."""
    earlier = EXPECTED_0_2["full_record"]

    assert earlier["record_version"] == "0.2"
    assert earlier["record_hash"] == EXPECTED_0_2["record_hash"]
    assert not _verifies(earlier)
    assert _reason(earlier) == REASON_UNBOUND_RECORD_VERSION


def test_a_session_without_basis_record_relabelled_0_2_fails_verification():
    """Section 9.5 step 8: a "0.2" record carries basis, and this one has none to carry."""
    relabelled = _resealed(
        {**WITHOUT_BASIS["record_version_0_1"]["full_record"], "record_version": "0.2"}
    )

    assert "basis" not in relabelled["agreed_terms"]
    assert relabelled["record_hash"] == WITHOUT_BASIS["relabelled_0_2_record_hash"]
    assert not _verifies_without_basis(relabelled)


def test_a_session_without_basis_0_3_record_relabelled_0_1_fails_verification():
    """Section 9.5 step 3: it still carries the act fields, and "0.1" predates them.

    Its basis shape already fits "0.1", so nothing else can be what rejects it.
    """
    relabelled = _resealed(
        {**WITHOUT_BASIS["record_version_0_3"]["full_record"], "record_version": "0.1"}
    )

    assert "basis" not in relabelled
    assert relabelled["record_hash"] == WITHOUT_BASIS["record_version_0_3"][
        "relabelled_0_1_record_hash"
    ]
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
    """Section 9.3: the record's basis follows the SessionAck."""
    record = RECORD_BUILDERS[builder](_without_basis_proposing(basis))
    current = WITHOUT_BASIS["record_version_0_3"]

    assert "basis" not in record
    assert json.dumps(record) == json.dumps(current["full_record"])
    assert record["record_hash"] == current["record_hash"]
    assert _verifies_without_basis(record)


@pytest.mark.parametrize("builder", sorted(RECORD_BUILDERS))
@pytest.mark.parametrize("basis", WITHOUT_BASIS["unechoed_proposed_bases"])
def test_a_proposed_basis_the_session_ack_omits_leaves_a_0_3_schema_record(basis, builder):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (REPO_ROOT / "spec" / "schemas" / "transaction-record-0.3.schema.json").read_text()
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

def test_flipping_the_basis_of_a_0_3_record_fails_verification():
    record = copy.deepcopy(EXPECTED_0_3["full_record"])
    record["basis"] = VECTOR["expected"]["tampered_basis"]
    tampered = _resealed(record)

    assert tampered["record_hash"] == EXPECTED_0_3["basis_flipped_record_hash"]
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
    """Step 8 on a "0.3" record, the only version a verifier accepts.

    Altering agreed_terms.basis also breaks the rebuilt act hash, so these are
    resigned over their own terms: step 3 then passes and step 8 is what decides.
    """
    record, did_documents = _locally_signed_basis_record()
    record["basis"] = record_basis
    if agreed_basis is _ABSENT:
        del record["agreed_terms"]["basis"]
    else:
        record["agreed_terms"]["basis"] = agreed_basis
    record, offer_hashes = _resigned_over_its_act(record)

    assert verify_transaction_record_reason(record, did_documents, offer_hashes) == (
        REASON_BASIS_MISMATCH
    )


def test_record_basis_with_non_object_agreed_terms_fails_verification():
    record, did_documents = _locally_signed_basis_record()
    record["agreed_terms"] = []

    assert not verify_transaction_record(
        _resealed(record), did_documents, [record["final_offer"]["protocol_act_hash"]]
    )


# ---------------------------------------------------------------------------
# What the earlier versions meant, and that they are no longer accepted
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("name", "build"),
    [
        (
            "0.2-without-basis",
            lambda: _resealed(
                {k: v for k, v in EXPECTED_0_2["full_record"].items() if k != "basis"}
            ),
        ),
        (
            "0.1-carrying-basis",
            lambda: _resealed({**EXPECTED_0_2["full_record"], "record_version": "0.1"}),
        ),
        (
            "0.1-with-agreed-terms-basis-alone",
            lambda: _resealed(
                {
                    **{k: v for k, v in EXPECTED_0_2["full_record"].items() if k != "basis"},
                    "record_version": "0.1",
                }
            ),
        ),
    ],
)
def test_an_earlier_version_is_refused_whatever_its_basis_shape(name, build):
    """Step 1 now decides these, so their basis shape no longer matters.

    The last case verified before this change: a "0.1" record carrying
    agreed_terms.basis alone was exactly what an implementation predating basis
    produced. It is refused now because nothing rebinds it.
    """
    record = build()

    assert not _verifies(record)
    assert _reason(record) == REASON_UNBOUND_RECORD_VERSION


def test_the_pinned_earlier_hashes_are_unchanged():
    """The historical bytes are untouched; only the verdict on them moved."""
    dropped = _resealed(
        {k: v for k, v in EXPECTED_0_2["full_record"].items() if k != "basis"}
    )
    relabelled = _resealed({**EXPECTED_0_2["full_record"], "record_version": "0.1"})

    assert dropped["record_hash"] == EXPECTED_0_2["basis_dropped_record_hash"]
    assert relabelled["record_hash"] == EXPECTED_0_2["relabelled_0_1_record_hash"]
    assert _resealed(
        {**dropped, "record_version": "0.1"}
    )["record_hash"] == EXPECTED_0_2["basis_dropped_0_1_record_hash"]


# ---------------------------------------------------------------------------
# Under "0.3" the basis follows agreed_terms, which the offer's signature covers
# ---------------------------------------------------------------------------

def test_a_0_3_record_without_basis_whose_agreed_terms_has_one_fails_verification():
    dropped = copy.deepcopy(EXPECTED_0_3["full_record"])
    del dropped["basis"]

    assert "basis" in dropped["agreed_terms"]
    assert not _verifies(_resealed(dropped))


def test_a_0_3_record_with_basis_whose_agreed_terms_has_none_fails_verification():
    record = copy.deepcopy(WITHOUT_BASIS["record_version_0_3"]["full_record"])
    record["basis"] = "gross"

    assert "basis" not in record["agreed_terms"]
    assert not _verifies_without_basis(_resealed(record))


def test_a_0_3_record_relabelled_0_2_fails_verification():
    """Section 9.5 step 3: it carries the act fields, and "0.2" predates them.

    It carries a basis equal to agreed_terms.basis, so step 8 is satisfied and
    only the act fields can be what rejects it.
    """
    relabelled = _resealed({**EXPECTED_0_3["full_record"], "record_version": "0.2"})

    assert relabelled["basis"] == relabelled["agreed_terms"]["basis"]
    assert relabelled["record_hash"] == EXPECTED_0_3["relabelled_0_2_record_hash"]
    assert not _verifies(relabelled)


def test_a_0_3_record_without_its_act_fields_fails_verification():
    dropped = copy.deepcopy(EXPECTED_0_3["full_record"])
    for field_name in FINAL_OFFER_ACT_FIELDS:
        del dropped["final_offer"][field_name]
    resealed = _resealed(dropped)

    assert resealed["record_version"] == "0.3"
    assert resealed["record_hash"] == EXPECTED_0_3["act_fields_dropped_record_hash"]
    assert not _verifies(resealed)


def test_altering_agreed_terms_of_a_0_3_record_fails_verification():
    """The signatures still verify; the act rebuilt from the record does not match."""
    record = copy.deepcopy(EXPECTED_0_3["full_record"])
    record["agreed_terms"]["total_value"] = VECTOR["expected"][
        "agreed_terms_tampered_total_value"
    ]
    tampered = _resealed(record)

    assert tampered["record_hash"] == EXPECTED_0_3["agreed_terms_tampered_record_hash"]
    assert not _verifies(tampered)


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

    assert evidence["transaction_record_hash"] == EXPECTED_0_3["record_hash"]
    assert evidence["record_hash"] == EXPECTED_0_3["evidence_record_hash"]
    assert verify_session_evidence_record(evidence, VECTOR["did_documents"])
