"""Ids that name a JavaScript object's inherited members are ordinary ids here.

``__proto__``, ``constructor`` and ``toString`` are names every plain
JavaScript object inherits, so a TypeScript store kept as a plain object has to
read and write own properties to treat them as this implementation does: an id
with no entry is unknown, and ``__proto__`` is an ordinary key. These cases
record what Python does with each, and the TypeScript suite runs the same cases
in tests/test_own_property_lookups.test.ts.
"""

from __future__ import annotations

import json
import uuid

import pytest

from a2cn.crypto import (
    generate_keypair,
    public_key_to_jwk,
    sign_invitation,
    verify_invitation_signature,
)
from a2cn.did import VerificationMethodNotFoundError, get_verification_method
from a2cn.invitation import InvitationStore
from a2cn.messages import _drop_none, rebuild_signed_act, signed_act_hash
from a2cn.session import A2CNError, SessionManager, SessionState
from a2cn.session_store import InMemorySessionStore, RedisSessionStore
from adapters.vendr_adapter import webhook_body_for_signature
from tests.conftest import (
    INITIATOR_DID,
    RESPONDER_DID,
    make_did_document,
    make_session_init,
    sign_decline,
)

INHERITED_IDS = ["__proto__", "constructor", "toString"]
A2CN_CT = "application/a2cn+json"

INITIATOR_PRIV, INITIATOR_PUB = generate_keypair()
INITIATOR_VM = f"{INITIATOR_DID}#key-1"


def _session_pair(session_id: str) -> tuple[dict, dict]:
    params = {
        "deal_type": "saas_renewal",
        "currency": "USD",
        "max_rounds": 4,
        "session_timeout_seconds": 3600,
        "round_timeout_seconds": 900,
    }
    session_init = {
        "message_type": "session_init",
        "message_id": "init-1",
        "protocol_version": "0.3",
        "session_params": params,
        "initiator": {"did": INITIATOR_DID, "verification_method": INITIATOR_VM, "agent_id": "buyer"},
        "initiator_mandate": {"mandate_type": "declared"},
    }
    session_ack = {
        "message_type": "session_ack",
        "message_id": "ack-1",
        "session_id": session_id,
        "in_reply_to": "init-1",
        "protocol_version": "0.3",
        "session_params_accepted": dict(params),
        "responder": {"did": RESPONDER_DID, "verification_method": f"{RESPONDER_DID}#key-1"},
        "responder_mandate": {"mandate_type": "declared"},
        "session_created_at": "2026-03-24T10:00:00Z",
        "current_turn": "initiator",
    }
    return session_init, session_ack


def _manager_with_session(session_id: str | None = None):
    session_id = session_id or str(uuid.uuid4())
    manager = SessionManager()
    manager.register_did_document(
        INITIATOR_DID, make_did_document(INITIATOR_DID, "key-1", public_key_to_jwk(INITIATOR_PUB))
    )
    init, ack = _session_pair(session_id)
    session = manager.create_session(session_id, init, ack, "2026-03-24T10:00:00Z")
    session.session_timeout_seconds = 86400 * 365 * 100
    return manager, session


def _withdrawal(session_id: str, message_id: str, private_key=INITIATOR_PRIV) -> dict:
    return sign_decline(
        {
            "message_type": "withdrawal",
            "message_id": message_id,
            "session_id": session_id,
            "round_number": 1,
            "sequence_number": 1,
            "sender_did": INITIATOR_DID,
            "sender_agent_id": "test-agent",
            "timestamp": "2026-03-24T10:02:00Z",
            "reason_code": "STRATEGY_DECISION",
        },
        private_key,
        INITIATOR_VM,
    )


def _inbound_invitation(invitation_id: str) -> dict:
    return {
        "message_type": "session_invitation",
        "invitation_id": invitation_id,
        "a2cn_version": "0.3",
        "inviter_did": "did:web:buyer.example",
        "inviter_endpoint": "https://buyer.example/a2cn",
        "inviter_discovery_url": "https://buyer.example/.well-known/a2cn-agent",
        "proposed_deal_type": "saas_renewal",
        "proposed_session_params": {"currency": "USD", "max_rounds": 4},
        "proposed_terms_summary": {"total_value": 9_500_000, "currency": "USD"},
        "inviter_mandate_summary": {"mandate_type": "declared"},
        "invitation_expires_at": "2030-01-01T00:00:00Z",
        "accept_endpoint": "https://buyer.example/a2cn/invitations/x/accept",
        "decline_endpoint": "https://buyer.example/a2cn/invitations/x/decline",
        "inviter_verification_method": "did:web:buyer.example#key-1",
        "invitation_signature": "",
    }


# ---------------------------------------------------------------------------
# Library stores
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ident", INHERITED_IDS)
def test_session_manager_treats_inherited_names_as_ordinary_ids(ident):
    manager, session = _manager_with_session()
    assert manager.get_session(ident) is None
    assert manager.has_init_response(ident) is False
    assert manager.has_did_document(ident) is False

    with pytest.raises(A2CNError) as exc:
        manager.process_message(
            session, {"message_type": "bogus", "message_id": ident, "sender_did": INITIATOR_DID}
        )
    assert exc.value.code == "WRONG_MESSAGE_TYPE"

    response = manager.process_message(session, _withdrawal(session.session_id, ident))
    assert session.state == SessionState.WITHDRAWN
    assert list(session._processed_messages) == [ident]
    assert manager.process_message(session, _withdrawal(session.session_id, ident)) is response


@pytest.mark.parametrize("ident", INHERITED_IDS)
def test_session_created_under_an_inherited_name_is_ordinary(ident):
    manager = SessionManager()
    init, ack = _session_pair(ident)
    session = manager.create_session(ident, init, ack, "2026-03-24T10:00:00Z")
    assert manager.get_session(ident) is session
    assert list(manager._sessions) == [ident]
    assert manager.get_session("state") is None


@pytest.mark.parametrize("ident", INHERITED_IDS)
def test_in_memory_session_store_inherited_names(ident):
    store = InMemorySessionStore()
    assert store.get(ident) is None
    data = {"delivery_notice": {"message_type": "delivery_notice"}}
    store.save(ident, data)
    assert store.get(ident) is data
    assert store.list_active() == [ident]
    assert store.get("delivery_notice") is None
    store.delete(ident)
    assert store.get(ident) is None


def test_redis_session_store_keeps_proto_member():
    class _Redis:
        def __init__(self):
            self.written = {}

        def get(self, key):
            return self.written.get(key)

        def set(self, key, value, ex=None):
            self.written[key] = value

    redis = _Redis()
    RedisSessionStore(redis, ttl_seconds=None).save("s-1", json.loads('{"b":1,"__proto__":{"a":2}}'))
    assert redis.written["a2cn:session:s-1"] == '{"__proto__":{"a":2},"b":1}'


@pytest.mark.parametrize("ident", INHERITED_IDS)
def test_invitation_store_inherited_names(ident):
    store = InvitationStore()
    assert store.get_invitation(ident) is None
    priv, _ = generate_keypair()
    with pytest.raises(ValueError, match="^INVITATION_NOT_FOUND$"):
        store.accept_invitation(
            invitation_id=ident,
            acceptor_did=RESPONDER_DID,
            acceptor_a2cn_endpoint="https://acme.example",
            acceptor_discovery_url="https://acme.example/.well-known/a2cn-agent",
            acceptor_verification_method=f"{RESPONDER_DID}#key-1",
            private_key=priv,
        )
    with pytest.raises(ValueError, match="^INVITATION_NOT_FOUND$"):
        store.decline_invitation(ident, "OTHER")

    store.store_inbound(_inbound_invitation(ident))
    assert list(store._invitations) == [ident]
    assert store.get_invitation(ident)["status"].value == "pending"
    for name in ["status", "invitation", "created_at", "answered_at"]:
        assert store.get_invitation(name) is None


@pytest.mark.parametrize("ident", INHERITED_IDS)
def test_verification_method_listed_by_reference_only_is_not_found(ident):
    doc = {"id": "did:web:x", "verificationMethod": [], "authentication": [ident], "assertionMethod": [ident]}
    with pytest.raises(VerificationMethodNotFoundError):
        get_verification_method(doc, ident)


def test_verification_method_named_proto_lends_no_fields():
    method = {
        "id": "__proto__",
        "type": "JsonWebKey2020",
        "controller": "did:web:x",
        "publicKeyJwk": public_key_to_jwk(INITIATOR_PUB),
    }
    doc = {"id": "did:web:x", "verificationMethod": [method], "authentication": ["type", "__proto__"]}
    with pytest.raises(VerificationMethodNotFoundError):
        get_verification_method(doc, "type")
    assert get_verification_method(doc, "__proto__") == method


@pytest.mark.parametrize("ident", INHERITED_IDS)
def test_act_of_inherited_message_type_cannot_be_rebuilt(ident):
    act = {
        "protocol_version": "0.3",
        "session_id": "s-1",
        "round_number": 1,
        "sequence_number": 1,
        "message_type": ident,
        "sender_did": INITIATOR_DID,
        "timestamp": "2026-03-24T10:02:00Z",
    }
    assert rebuild_signed_act(act) is None
    assert signed_act_hash(act) is None


@pytest.mark.parametrize("message_type", [*INHERITED_IDS, "bogus"])
def test_record_with_inherited_acceptance_type_is_refused(message_type):
    from pathlib import Path

    from a2cn.crypto import hash_object
    from a2cn.record import verify_transaction_record_reason

    vector_path = Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "transaction-record-basis.json"
    vector = json.loads(vector_path.read_text())
    record = json.loads(json.dumps(vector["expected"]["record_version_0_4"]["full_record"]))
    record["final_acceptance"]["message_type"] = message_type
    record["record_hash"] = ""
    record["record_hash"] = hash_object(record)
    assert verify_transaction_record_reason(record, vector["did_documents"]) == "UNBOUND_RECORD_VERSION"


def test_objects_rebuilt_from_input_keep_a_proto_member():
    result = _drop_none({"top": json.loads('{"a":1,"__proto__":{"x":1}}'), "keep": 2, "drop": None})
    assert json.dumps(result, separators=(",", ":")) == '{"top":{"a":1,"__proto__":{"x":1}},"keep":2}'
    body = webhook_body_for_signature(json.loads('{"event":"x","__proto__":{"a":1}}'))
    assert body == b'{"__proto__":{"a":1},"event":"x"}'


def test_invitation_signature_covers_a_proto_member():
    priv, pub = generate_keypair()
    invitation = _inbound_invitation(str(uuid.uuid4()))
    invitation["invitation_signature"] = sign_invitation(invitation, priv)
    assert verify_invitation_signature(invitation, pub) is True
    extended = {**invitation, "__proto__": {"inviter_did": "did:web:other.example"}}
    assert verify_invitation_signature(extended, pub) is False


# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------

SESSION_ROUTES = [
    ("GET", ""),
    ("POST", "/messages"),
    ("POST", "/approval-receipt"),
    ("GET", "/messages"),
    ("GET", "/record"),
    ("GET", "/evidence"),
    ("GET", "/audit"),
    ("POST", "/delivery-notice"),
    ("POST", "/delivery-acknowledged"),
    ("POST", "/dispute-notice"),
    ("POST", "/dispute-resolved"),
    ("GET", "/fulfillment-attestation"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("ident", INHERITED_IDS)
@pytest.mark.parametrize("method,suffix", SESSION_ROUTES)
async def test_session_routes_do_not_find_inherited_ids(test_client, method, ident, suffix):
    path = f"/sessions/{ident}{suffix}"
    if method == "GET":
        r = await test_client.get(path)
    else:
        r = await test_client.post(
            path,
            json={"message_type": "x", "message_id": str(uuid.uuid4())},
            headers={"Content-Type": A2CN_CT},
        )
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "SESSION_NOT_FOUND"


@pytest.mark.asyncio
@pytest.mark.parametrize("ident", INHERITED_IDS)
async def test_session_init_with_inherited_message_id(test_client, ident):
    body = make_session_init(ident)
    headers = {"Content-Type": A2CN_CT, "Idempotency-Key": ident}
    first = await test_client.post("/sessions", json=body, headers=headers)
    assert first.status_code == 201
    session_id = first.json()["session_id"]
    assert (await test_client.get(f"/sessions/{session_id}")).status_code == 200
    again = await test_client.post("/sessions", json=body, headers=headers)
    assert again.status_code == 200
    assert again.json()["session_id"] == session_id

    invalid = await test_client.post("/sessions", json={"message_id": ident}, headers=headers)
    # Answered from the stored response: Python keys idempotency on message_id
    # before validating, as TypeScript does.
    assert invalid.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("ident", INHERITED_IDS)
async def test_session_init_with_inherited_message_id_is_validated(test_client, ident):
    r = await test_client.post(
        "/sessions", json={"message_id": ident}, headers={"Content-Type": A2CN_CT, "Idempotency-Key": ident}
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INTERNAL_ERROR"


@pytest.mark.asyncio
@pytest.mark.parametrize("ident", INHERITED_IDS)
async def test_session_message_with_inherited_message_id(test_client, initiator_keypair, ident):
    body = make_session_init()
    created = await test_client.post(
        "/sessions", json=body, headers={"Content-Type": A2CN_CT, "Idempotency-Key": body["message_id"]}
    )
    session_id = created.json()["session_id"]
    headers = {"Content-Type": A2CN_CT, "Idempotency-Key": ident}

    bogus = await test_client.post(
        f"/sessions/{session_id}/messages",
        json={"message_type": "bogus", "message_id": ident, "sender_did": INITIATOR_DID, "session_id": session_id},
        headers=headers,
    )
    assert bogus.status_code == 422
    assert bogus.json()["error"]["code"] == "WRONG_MESSAGE_TYPE"

    r = await test_client.post(
        f"/sessions/{session_id}/messages",
        json=_withdrawal(session_id, ident, initiator_keypair[0]),
        headers=headers,
    )
    assert r.status_code == 200
    assert (await test_client.get(f"/sessions/{session_id}")).json()["state"] == "WITHDRAWN"


@pytest.mark.asyncio
@pytest.mark.parametrize("ident", INHERITED_IDS)
async def test_invitation_routes_do_not_find_inherited_ids(test_client, ident):
    # One client for every route: each fixture reloads the server module.
    r = await test_client.get(f"/invitations/{ident}")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "INVITATION_NOT_FOUND"
    for action in ["accept", "decline"]:
        r = await test_client.post(f"/invitations/{ident}/{action}", json={}, headers={"Content-Type": A2CN_CT})
        assert r.status_code == 404
        assert r.json()["error"]["code"] == "INVITATION_NOT_FOUND"


def _signed_inbound(invitation_id: str) -> dict:
    import a2cn.server as server_module

    priv, pub = generate_keypair()
    inviter_did = "did:web:buyer.example"
    server_module.register_did_document(
        inviter_did, make_did_document(inviter_did, "key-1", public_key_to_jwk(pub))
    )
    invitation = _inbound_invitation(invitation_id)
    invitation["invitation_signature"] = sign_invitation(invitation, priv)
    return invitation


@pytest.mark.asyncio
async def test_inbound_invitation_proto_is_ordinary(test_client):
    import a2cn.server as server_module

    r = await test_client.post("/invitations", json=_signed_inbound("__proto__"))
    assert r.status_code == 201
    assert r.json() == {"invitation_id": "__proto__", "status": "pending"}
    assert list(server_module.invitation_store._invitations) == ["__proto__"]

    fetched = await test_client.get("/invitations/__proto__")
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "pending"
    for name in ["status", "invitation", "created_at", "answered_at", "constructor"]:
        assert (await test_client.get(f"/invitations/{name}")).status_code == 404
        declined = await test_client.post(
            f"/invitations/{name}/decline", json={}, headers={"Content-Type": A2CN_CT}
        )
        assert declined.status_code == 404
    accepted = await test_client.post("/invitations/__proto__/accept", json={}, headers={"Content-Type": A2CN_CT})
    assert accepted.status_code == 200
    assert accepted.json()["invitation_id"] == "__proto__"


@pytest.mark.asyncio
@pytest.mark.parametrize("ident", INHERITED_IDS)
async def test_inbound_invitation_from_inherited_inviter_did(raw_test_client, ident):
    invitation = {
        **_inbound_invitation(str(uuid.uuid4())),
        "inviter_did": ident,
        "inviter_verification_method": f"{ident}#key-1",
        "invitation_signature": "abc",
    }
    r = await raw_test_client.post("/invitations", json=invitation)
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "DID_RESOLUTION_FAILED"


@pytest.mark.asyncio
async def test_inbound_invitation_with_unsigned_proto_member_is_refused(raw_test_client):
    import a2cn.server as server_module

    invitation = {**_signed_inbound(str(uuid.uuid4())), "__proto__": {"status": "accepted"}}
    r = await raw_test_client.post("/invitations", json=invitation)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVITATION_SIGNATURE_INVALID"
    assert list(server_module.invitation_store._invitations) == []


@pytest.mark.asyncio
async def test_created_invitation_signature_covers_proto_member(test_client, responder_keypair):
    r = await test_client.post(
        "/invitations/create",
        json={
            "proposed_deal_type": "saas_renewal",
            "proposed_terms_summary": json.loads('{"total_value":9500000,"__proto__":{"tier":"gold"}}'),
        },
        headers={"Content-Type": A2CN_CT},
    )
    assert r.status_code == 201
    invitation = r.json()
    assert "__proto__" in invitation["proposed_terms_summary"]
    assert verify_invitation_signature(invitation, responder_keypair[1]) is True


@pytest.mark.asyncio
async def test_deal_type_named_constructor_takes_default_round_cap(test_client, responder_config):
    import a2cn.server as server_module

    server_module.configure_responder(
        {**responder_config, "deal_types": ["constructor"], "max_rounds_by_deal_type": {}}
    )
    body = make_session_init()
    body["session_params"]["deal_type"] = "constructor"
    body["initiator_mandate"]["authorized_deal_types"] = ["constructor"]
    r = await test_client.post(
        "/sessions", json=body, headers={"Content-Type": A2CN_CT, "Idempotency-Key": body["message_id"]}
    )
    assert r.status_code == 201
    assert r.json()["session_params_accepted"]["max_rounds"] == 4


@pytest.mark.asyncio
@pytest.mark.parametrize("ident", INHERITED_IDS)
async def test_server_registers_did_document_under_inherited_name(test_client, ident):
    import a2cn.server as server_module

    before = list(server_module._did_doc_override)
    server_module.register_did_document(ident, {"id": ident})
    assert list(server_module._did_doc_override) == [*before, ident]
    assert server_module.manager.has_did_document(ident) is True


@pytest.mark.parametrize("value", ["member", 7, True, [{"x": 1}]])
def test_drop_none_keeps_proto_member_of_any_type(value):
    result = _drop_none({"a": 1, "__proto__": value})
    assert result["__proto__"] == value


def test_docusign_signer_contacts_by_did():
    from adapters.docusign_adapter import a2cn_record_to_docusign_envelope

    envelope = a2cn_record_to_docusign_envelope(
        {
            "session_id": "s-1",
            "record_hash": "h",
            "agreed_terms": {"total_value": 100, "currency": "USD"},
            "parties": {
                "initiator": {"did": "constructor", "organization_name": "TechCorp", "email": "buyer@techcorp.example"},
                "responder": {"did": "toString", "organization_name": "Acme", "email": "seller@acme.example"},
            },
        },
        {},
    )
    signers = envelope["recipients"]["signers"]
    assert [(s["name"], s["email"]) for s in signers] == [
        ("TechCorp", "buyer@techcorp.example"),
        ("Acme", "seller@acme.example"),
    ]
