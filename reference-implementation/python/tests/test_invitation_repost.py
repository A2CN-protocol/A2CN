"""An inbound invitation never replaces the one already stored under its id.

POST /invitations is authenticated by the invitation's own signature, so any
did:web holder can deliver one. The id it names may already be stored: an
invitation received earlier, or one this server created (Section 11.7):

- a different invitation under that id (another inviter, or other content) is
  INVITATION_ID_CONFLICT, whatever the stored status;
- the identical signed invitation re-sent is answered as the first delivery
  was while the stored one is pending, and is INVITATION_ALREADY_ANSWERED or
  INVITATION_EXPIRED once it is answered or expired;
- re-delivery never changes the stored entry's inviter, content, status or
  created_at.

The TypeScript suite runs the same cases in tests/test_invitation_repost.test.ts.
"""

from __future__ import annotations

import uuid

import pytest

from a2cn.crypto import generate_keypair, public_key_to_jwk, sign_invitation
from a2cn.invitation import InvitationStore
from tests.conftest import make_did_document

A2CN_CT = "application/a2cn+json"
ALICE = "did:web:alice.example"
MALLORY = "did:web:mallory.example"
KEYS = {ALICE: generate_keypair(), MALLORY: generate_keypair()}
STATES = ["pending", "accepted", "declined", "expired"]
LIVE = "2030-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"


def _invitation(inviter: str, invitation_id: str, total_value: int = 9_500_000, expires: str = LIVE) -> dict:
    host = inviter.split(":")[-1]
    invitation = {
        "message_type": "session_invitation",
        "invitation_id": invitation_id,
        "a2cn_version": "0.3",
        "inviter_did": inviter,
        "inviter_endpoint": f"https://{host}/a2cn",
        "inviter_discovery_url": f"https://{host}/.well-known/a2cn-agent",
        "proposed_deal_type": "saas_renewal",
        "proposed_session_params": {"currency": "USD", "max_rounds": 4},
        "proposed_terms_summary": {"total_value": total_value, "currency": "USD"},
        "inviter_mandate_summary": {"mandate_type": "declared"},
        "invitation_expires_at": expires,
        "accept_endpoint": f"https://{host}/a2cn/invitations/{invitation_id}/accept",
        "decline_endpoint": f"https://{host}/a2cn/invitations/{invitation_id}/decline",
        "inviter_verification_method": f"{inviter}#key-1",
        "invitation_signature": "",
    }
    invitation["invitation_signature"] = sign_invitation(invitation, KEYS[inviter][0])
    return invitation


def _register_inviters() -> None:
    import a2cn.server as server_module

    for did, (_, pub) in KEYS.items():
        server_module.register_did_document(did, make_did_document(did, "key-1", public_key_to_jwk(pub)))


async def _post(client, invitation: dict):
    return await client.post("/invitations", json=invitation, headers={"Content-Type": A2CN_CT})


async def _answer(client, invitation_id: str, action: str):
    return await client.post(f"/invitations/{invitation_id}/{action}", json={}, headers={"Content-Type": A2CN_CT})


async def _stored(client, invitation_id: str) -> dict:
    r = await client.get(f"/invitations/{invitation_id}")
    assert r.status_code == 200
    return r.json()


async def _first(client, state: str) -> tuple[str, dict]:
    """Alice's invitation, stored and then left pending, accepted, declined or expired."""
    _register_inviters()
    invitation_id = str(uuid.uuid4())
    original = _invitation(ALICE, invitation_id, expires=PAST if state == "expired" else LIVE)
    assert (await _post(client, original)).status_code == 201
    if state in ("accepted", "declined"):
        action = "accept" if state == "accepted" else "decline"
        assert (await _answer(client, invitation_id, action)).status_code == 200
    return invitation_id, original


def _stored_status(state: str) -> str:
    # An expired invitation nobody has tried to answer still reads as pending.
    return "pending" if state == "expired" else state


@pytest.mark.asyncio
@pytest.mark.parametrize("state", STATES)
async def test_another_inviter_is_a_conflict_whatever_the_status(test_client, state):
    invitation_id, original = await _first(test_client, state)
    before = await _stored(test_client, invitation_id)

    r = await _post(test_client, _invitation(MALLORY, invitation_id, expires=original["invitation_expires_at"]))

    assert r.status_code == 409
    assert r.json()["error"]["code"] == "INVITATION_ID_CONFLICT"
    after = await _stored(test_client, invitation_id)
    assert after == before
    assert after["invitation"] == original
    assert after["status"] == _stored_status(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("state", STATES)
async def test_same_inviter_with_different_content_is_a_conflict(test_client, state):
    invitation_id, original = await _first(test_client, state)
    before = await _stored(test_client, invitation_id)

    r = await _post(
        test_client, _invitation(ALICE, invitation_id, total_value=1, expires=original["invitation_expires_at"])
    )

    assert r.status_code == 409
    assert r.json()["error"]["code"] == "INVITATION_ID_CONFLICT"
    after = await _stored(test_client, invitation_id)
    assert after == before
    assert after["invitation"]["proposed_terms_summary"]["total_value"] == 9_500_000


@pytest.mark.asyncio
async def test_identical_retransmission_of_a_pending_invitation_is_answered_as_before(test_client):
    invitation_id, original = await _first(test_client, "pending")
    before = await _stored(test_client, invitation_id)

    r = await _post(test_client, dict(original))

    assert r.status_code == 201
    assert r.json() == {"invitation_id": invitation_id, "status": "pending"}
    assert await _stored(test_client, invitation_id) == before
    # Still answerable, and still Alice's.
    assert (await _answer(test_client, invitation_id, "accept")).status_code == 200
    assert (await _stored(test_client, invitation_id))["status"] == "accepted"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state,code,status",
    [
        ("accepted", "INVITATION_ALREADY_ANSWERED", 409),
        ("declined", "INVITATION_ALREADY_ANSWERED", 409),
        ("expired", "INVITATION_EXPIRED", 410),
    ],
)
async def test_identical_retransmission_never_reopens_an_invitation(test_client, state, code, status):
    invitation_id, original = await _first(test_client, state)
    before = await _stored(test_client, invitation_id)

    r = await _post(test_client, dict(original))

    assert r.status_code == status
    assert r.json()["error"]["code"] == code
    assert await _stored(test_client, invitation_id) == before
    again = await _answer(test_client, invitation_id, "decline" if state == "accepted" else "accept")
    assert again.status_code == status
    assert again.json()["error"]["code"] == code


@pytest.mark.asyncio
async def test_an_inbound_invitation_cannot_take_an_outbound_invitations_id(test_client):
    _register_inviters()
    created = await test_client.post(
        "/invitations/create",
        json={"proposed_deal_type": "saas_renewal", "proposed_terms_summary": {"total_value": 1}},
        headers={"Content-Type": A2CN_CT},
    )
    assert created.status_code == 201
    invitation_id = created.json()["invitation_id"]
    before = await _stored(test_client, invitation_id)

    r = await _post(test_client, _invitation(MALLORY, invitation_id))

    assert r.status_code == 409
    assert r.json()["error"]["code"] == "INVITATION_ID_CONFLICT"
    assert await _stored(test_client, invitation_id) == before


def test_store_inbound_refuses_a_conflicting_id():
    store = InvitationStore()
    invitation_id = str(uuid.uuid4())
    original = _invitation(ALICE, invitation_id)
    store.store_inbound(original)
    entry = store.get_invitation(invitation_id)
    snapshot = dict(entry)
    with pytest.raises(ValueError, match="^INVITATION_ID_CONFLICT$"):
        store.store_inbound(_invitation(MALLORY, invitation_id))
    store.store_inbound(dict(original))
    assert store.get_invitation(invitation_id) is entry
    assert entry == snapshot
