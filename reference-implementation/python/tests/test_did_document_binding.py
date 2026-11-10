"""Section 4.2: a DID document is used only for the DID its id names.

Two spellings of one did:web DID can reach one document: the host's case, a
trailing dot, a percent-encoded dot or port, a ``:.well-known`` path, a Unicode
host and its punycode. Without this rule a party whose one document lists two
keys could sign a TransactionRecord's offer under one spelling and its
acceptance under the other, and the record verified: two DIDs, two keys, one
party. No DID is normalized. Wherever a verifier obtains a document (the
did:web resolver, a mapping or resolver the caller supplies, the servers'
registered documents, a2cn-verify's inputs), a document whose id is not exactly
the DID asked for is no document for it, and its key is unavailable.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest
import respx

from a2cn.acts import ACT_REASON_KEY_NOT_FOUND, verify_signed_act_reason
from a2cn.crypto import create_jwt
from a2cn.did import (
    DidDocumentIdMismatch,
    did_document_is_for,
    did_web_document_url,
    require_did_document_for,
    resolve_did_web,
)
from a2cn.errors import A2CNError
from a2cn.evidence import EVIDENCE_REASON_KEY_NOT_FOUND, assess_session_evidence_record
from a2cn.record import (
    REASON_KEY_NOT_FOUND,
    REASON_NOT_BILATERAL,
    is_did,
    verify_transaction_record_reason,
)
from a2cn.session import SessionManager
from tests.conftest import INITIATOR_DID, SERVER_DID, make_session_init

VECTORS = Path(__file__).parents[3] / "spec" / "test-vectors"
PARTIES = json.loads((VECTORS / "transaction-record-parties.json").read_text())
BASIS = json.loads((VECTORS / "transaction-record-basis.json").read_text())
HISTORY = json.loads((VECTORS / "transaction-record-offer-history.json").read_text())
SPELLINGS = PARTIES["spelling_cases"]
CONTROL = next(c for c in PARTIES["cases"] if c["name"] == "multi_round_control")
ACME = "did:web:acme-corp.com"


def _relabelled(document: dict, did: str) -> dict:
    return {**copy.deepcopy(document), "id": did}


def test_a_document_is_for_the_did_its_id_names_and_no_other():
    document = PARTIES["did_documents"][INITIATOR_DID]
    assert did_document_is_for(document, INITIATOR_DID)
    for other in ("did:web:TechCorp.example", INITIATOR_DID + ".", INITIATOR_DID + " ", INITIATOR_DID + "#key-1"):
        assert not did_document_is_for(document, other)
    assert not did_document_is_for({k: v for k, v in document.items() if k != "id"}, INITIATOR_DID)
    for not_a_document in (None, [], "did", 7, {"id": 7}, {"id": None}):
        assert not did_document_is_for(not_a_document, INITIATOR_DID)
    assert require_did_document_for(document, INITIATOR_DID) is document
    with pytest.raises(DidDocumentIdMismatch):
        require_did_document_for(document, "did:web:TechCorp.example")
    assert issubclass(DidDocumentIdMismatch, ValueError)


@pytest.mark.parametrize("case", SPELLINGS, ids=lambda case: case["name"])
def test_one_party_under_two_spellings_is_never_verified(case):
    """Both spellings reach one document; only the one its id names has it.

    A spelling that is not DID syntax at all (a raw Unicode host) is refused
    before any key is resolved, as NOT_BILATERAL (Section 9.5 step 10).
    """
    expected = REASON_KEY_NOT_FOUND if is_did(case["spelled_did"]) else REASON_NOT_BILATERAL
    assert verify_transaction_record_reason(
        case["record"], case["did_documents"], case["offer_hashes"]
    ) == case["expected_reason"] == expected


@pytest.mark.parametrize("case", SPELLINGS, ids=lambda case: case["name"])
def test_the_spelling_cases_are_real(case):
    """One document, two keys; the record is otherwise bilateral and sealed."""
    canonical, spelled = case["canonical_did"], case["spelled_did"]
    documents = case["did_documents"]
    assert documents[canonical] is not None and documents[canonical] == documents[spelled]
    assert documents[canonical]["id"] == canonical != spelled
    record = case["record"]
    assert record["parties"]["initiator"]["did"] == canonical
    assert record["parties"]["responder"]["did"] == spelled
    # Relabelled to name the spelling, the document verifies the acceptance,
    # so the id binding is the only thing that refuses the record; a spelling
    # that is not DID syntax is refused by that check instead.
    relabelled = {canonical: documents[canonical], spelled: _relabelled(documents[canonical], spelled)}
    expected = None if is_did(spelled) else REASON_NOT_BILATERAL
    assert verify_transaction_record_reason(record, relabelled, case["offer_hashes"]) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("case", SPELLINGS, ids=lambda case: case["name"])
async def test_the_resolver_refuses_a_document_naming_another_spelling(case):
    canonical, spelled = case["canonical_did"], case["spelled_did"]
    document = case["did_documents"][canonical]
    with respx.mock(assert_all_called=False) as router:
        router.get(did_web_document_url(canonical)).mock(return_value=httpx.Response(200, json=document))
        router.get(did_web_document_url(spelled)).mock(return_value=httpx.Response(200, json=document))
        async with httpx.AsyncClient() as client:
            assert await resolve_did_web(canonical, client) == document
            with pytest.raises(DidDocumentIdMismatch):
                await resolve_did_web(spelled, client)


@pytest.mark.parametrize("supply", ["mapping", "callable"])
def test_the_record_verifier_refuses_a_document_naming_another_did(supply):
    record, hashes = CONTROL["record"], CONTROL["offer_hashes"]
    documents = {**PARTIES["did_documents"], ACME: _relabelled(PARTIES["did_documents"][ACME], "did:web:elsewhere.example")}
    resolver = documents if supply == "mapping" else documents.__getitem__
    assert verify_transaction_record_reason(record, PARTIES["did_documents"], hashes) is None
    assert verify_transaction_record_reason(record, resolver, hashes) == REASON_KEY_NOT_FOUND


def test_the_evidence_verifier_refuses_a_document_naming_another_did():
    record = HISTORY["evidence_record"]
    documents = HISTORY["did_documents"]["current"]
    assert assess_session_evidence_record(record, documents)["reason"] is None
    for did in documents:
        relabelled = {**documents, did: _relabelled(documents[did], did.upper())}
        assert assess_session_evidence_record(record, relabelled)["reason"] == EVIDENCE_REASON_KEY_NOT_FOUND


def test_the_act_verifier_refuses_a_document_naming_another_did():
    offer = BASIS["messages"][0]
    documents = BASIS["did_documents"]
    did = offer["sender_did"]
    assert verify_signed_act_reason(offer, documents, wire_version="0.2") is None
    relabelled = {**documents, did: _relabelled(documents[did], "did:web:TechCorp.example")}
    assert verify_signed_act_reason(offer, relabelled, wire_version="0.2") == ACT_REASON_KEY_NOT_FOUND


def test_a_session_does_not_use_a_registered_document_naming_another_did():
    manager = SessionManager()
    for did, document in BASIS["did_documents"].items():
        manager.register_did_document(did, document if did != ACME else _relabelled(document, "did:web:elsewhere.example"))
    session = manager.create_session(
        BASIS["session_id"], BASIS["session_init"], BASIS["session_ack"],
        BASIS["session_ack"]["session_created_at"], legacy_replay=True,
    )
    session.session_timeout_seconds = 86400 * 365 * 100
    offer, counteroffer = (copy.deepcopy(m) for m in BASIS["messages"][:2])
    manager.process_message(session, offer)
    with pytest.raises(A2CNError) as refused:
        manager.process_message(session, counteroffer)
    assert refused.value.code == "INVALID_SIGNATURE"


def test_the_server_refuses_to_register_a_document_naming_another_did():
    import a2cn.server as server_module

    document = PARTIES["did_documents"][INITIATOR_DID]
    with pytest.raises(DidDocumentIdMismatch):
        server_module.register_did_document("did:web:TechCorp.example", document)
    assert "did:web:TechCorp.example" not in server_module._did_doc_override


@pytest.mark.asyncio
async def test_the_server_does_not_use_an_override_naming_another_did(raw_test_client, initiator_keypair, initiator_did_doc):
    """A document put in the override table directly is checked when it is read."""
    import a2cn.server as server_module

    private_key, _public = initiator_keypair
    body = make_session_init()

    async def post():
        token = create_jwt(INITIATOR_DID, SERVER_DID, private_key, kid=f"{INITIATOR_DID}#key-1", exp_seconds=3600)
        headers = {"Content-Type": "application/a2cn+json", "Idempotency-Key": body["message_id"],
                   "Authorization": f"Bearer {token}"}
        return await raw_test_client.post("/sessions", json=body, headers=headers)

    server_module._did_doc_override[INITIATOR_DID] = _relabelled(initiator_did_doc, "did:web:TechCorp.example")
    refused = await post()
    assert refused.status_code == 401
    assert refused.json()["error"]["code"] == "INVALID_JWT"

    server_module.register_did_document(INITIATOR_DID, initiator_did_doc)
    assert (await post()).status_code == 201
