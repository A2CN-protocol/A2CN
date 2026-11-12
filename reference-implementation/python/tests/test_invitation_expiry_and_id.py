"""invitation_expires_at and invitation_id are read the same way in both languages.

An invitation's expiry is an RFC 3339 timestamp with an explicit UTC offset or
`Z` (the schema's `date-time`). Anything else — missing, empty, not a string,
no offset, a basic-format or date-only value, an out-of-range field — counts as
expired, failing closed, at every expiry check: an identical re-send, accept,
decline and the expiry sweep. Nothing about the value can produce a 500.

POST /invitations requires invitation_id to be a non-empty string, before any
DID is resolved or signature checked (INVALID_REQUEST, 400).

The TypeScript suite runs the same cases in
tests/test_invitation_expiry_and_id.test.ts.
"""

from __future__ import annotations

import json
import uuid

import pytest

import a2cn.invitation as invitation_module
from a2cn.crypto import generate_keypair, public_key_to_jwk, sign_invitation
from a2cn.invitation import InvitationStore
from tests.conftest import make_did_document

A2CN_CT = "application/a2cn+json"
ALICE = "did:web:alice.example"
MALLORY = "did:web:mallory.example"
KEYS = {ALICE: generate_keypair(), MALLORY: generate_keypair()}
MISSING = object()

# (invitation_expires_at, counts as expired). The clock is real, so "future"
# values are far ahead and "past" ones far behind.
EXPIRY_CASES = [
    ("2099-01-01T00:00:00Z", False),
    ("2099-01-01T00:00:00.5Z", False),
    ("2099-01-01T00:00:00+05:30", False),
    ("2099-01-01T00:00:00-08:00", False),
    ("2099-01-01t00:00:00z", False),
    ("2020-01-01T00:00:00Z", True),
    ("2020-01-01T00:00:00.1234567Z", True),
    # Not RFC 3339 with an explicit offset: expired, whatever instant it names.
    ("2099-01-01T00:00:00", True),
    ("2020-01-01T00:00:00", True),
    ("2099-01-01", True),
    ("2020-01-01", True),
    ("20200101T000000Z", True),
    ("20990101T000000Z", True),
    ("2099-01-01 00:00:00Z", True),
    ("2099-01-01T24:00:00Z", True),
    ("2099-01-01T00:60:00Z", True),
    ("2099-01-01T00:00:60Z", True),
    ("2099-02-30T00:00:00Z", True),
    ("2099-13-01T00:00:00Z", True),
    ("2099-01-01T00:00:00+24:00", True),
    ("2099-01-01T00:00:00+0530", True),
    ("0000-01-01T00:00:00Z", True),
    ("٢٠٩٩-01-01T00:00:00Z", True),
    ("2099-01-01T00:00:00Z ", True),
    ("", True),
    (MISSING, True),
    (None, True),
    (20990101, True),
    (["2099-01-01T00:00:00Z"], True),
]


def _id(case) -> str:
    value = case[0]
    return "missing" if value is MISSING else json.dumps(value, ensure_ascii=True)


def _invitation(inviter: str, invitation_id, expires="2099-01-01T00:00:00Z") -> dict:
    host = inviter.split(":")[-1]
    body = {
        "message_type": "session_invitation",
        "invitation_id": invitation_id,
        "a2cn_version": "0.3",
        "inviter_did": inviter,
        "inviter_endpoint": f"https://{host}/a2cn",
        "inviter_discovery_url": f"https://{host}/.well-known/a2cn-agent",
        "proposed_deal_type": "saas_renewal",
        "proposed_session_params": {"currency": "USD", "max_rounds": 4},
        "proposed_terms_summary": {"total_value": 9_500_000, "currency": "USD"},
        "inviter_mandate_summary": {"mandate_type": "declared"},
        "invitation_expires_at": expires,
        "accept_endpoint": f"https://{host}/a2cn/invitations/x/accept",
        "decline_endpoint": f"https://{host}/a2cn/invitations/x/decline",
        "inviter_verification_method": f"{inviter}#key-1",
        "invitation_signature": "",
    }
    if expires is MISSING:
        del body["invitation_expires_at"]
    if invitation_id is MISSING:
        del body["invitation_id"]
    body["invitation_signature"] = sign_invitation(body, KEYS[inviter][0])
    return body


def _register_inviters() -> None:
    import a2cn.server as server_module

    for did, (_, pub) in KEYS.items():
        server_module.register_did_document(did, make_did_document(did, "key-1", public_key_to_jwk(pub)))


async def _post(client, body: dict):
    return await client.post("/invitations", content=json.dumps(body), headers={"Content-Type": A2CN_CT})


def _code(r) -> str:
    return (r.json().get("error") or {}).get("code", "ok")


# ---------------------------------------------------------------------------
# invitation_expires_at
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("expires,expired", EXPIRY_CASES, ids=[_id(c) for c in EXPIRY_CASES])
async def test_expiry_is_read_the_same_at_every_check(test_client, expires, expired):
    _register_inviters()
    want = (410, "INVITATION_EXPIRED") if expired else None
    results = {}
    for step in ["resend", "accept", "decline"]:
        invitation_id = str(uuid.uuid4())
        body = _invitation(ALICE, invitation_id, expires)
        first = await _post(test_client, body)
        assert first.status_code == 201, (step, first.text)
        if step == "resend":
            r = await _post(test_client, body)
            ok = (201, "ok")
        else:
            r = await test_client.post(
                f"/invitations/{invitation_id}/{step}", json={}, headers={"Content-Type": A2CN_CT}
            )
            ok = (200, "ok")
        results[step] = (r.status_code, _code(r))
        assert results[step] == (want or ok), (step, r.text)
        status = (await test_client.get(f"/invitations/{invitation_id}")).json()["status"]
        if step == "resend":
            assert status == "pending"
        elif expired:
            assert status == "expired"


@pytest.mark.parametrize("expires,expired", EXPIRY_CASES, ids=[_id(c) for c in EXPIRY_CASES])
def test_expiry_sweep_reads_the_same(expires, expired):
    store = InvitationStore()
    store.store_inbound(_invitation(ALICE, str(uuid.uuid4()), expires))
    assert store.expire_pending() == (1 if expired else 0)


# (invitation_expires_at, clock, counts as expired): the instant an expiry names,
# offset included, read to the millisecond; it has passed once the clock is
# strictly later.
CLOCKED_CASES = [
    ("2030-01-01T00:00:00+05:00", "2030-01-01T02:00:00.000Z", True),
    ("2030-01-01T00:00:00-05:00", "2030-01-01T02:00:00.000Z", False),
    ("2030-01-01T00:00:00Z", "2029-12-31T23:59:59.999Z", False),
    ("2030-01-01T00:00:00Z", "2030-01-01T00:00:00.000Z", False),
    ("2030-01-01T00:00:00Z", "2030-01-01T00:00:00.001Z", True),
    ("2030-01-01T00:00:00.500Z", "2030-01-01T00:00:00.500Z", False),
    ("2030-01-01T00:00:00.500Z", "2030-01-01T00:00:00.501Z", True),
    ("2030-01-01T00:00:00.5009Z", "2030-01-01T00:00:00.501Z", True),
]


def _clock_ms(iso: str) -> int:
    from datetime import datetime, timezone

    moment = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return int(moment.timestamp() * 1000 + 0.5)


@pytest.mark.parametrize("expires,clock,expired", CLOCKED_CASES)
def test_expiry_instant_is_read_with_its_offset_to_the_millisecond(monkeypatch, expires, clock, expired):
    monkeypatch.setattr(invitation_module, "_now_ms", lambda: _clock_ms(clock))
    store = InvitationStore()
    store.store_inbound(_invitation(ALICE, str(uuid.uuid4()), expires))
    assert store.expire_pending() == (1 if expired else 0)


@pytest.mark.asyncio
async def test_answered_and_past_expiry_resend_is_already_answered(test_client, monkeypatch):
    _register_inviters()
    invitation_id = str(uuid.uuid4())
    body = _invitation(ALICE, invitation_id, "2030-01-01T00:00:00Z")
    assert (await _post(test_client, body)).status_code == 201
    accepted = await test_client.post(f"/invitations/{invitation_id}/accept", json={}, headers={"Content-Type": A2CN_CT})
    assert accepted.status_code == 200

    # Later, after the invitation's expiry has passed.
    monkeypatch.setattr(invitation_module, "_now_ms", lambda: 1_924_992_000_000)  # 2031-01-01T00:00:00Z
    r = await _post(test_client, body)

    assert r.status_code == 409
    assert _code(r) == "INVITATION_ALREADY_ANSWERED"
    again = await test_client.post(f"/invitations/{invitation_id}/decline", json={}, headers={"Content-Type": A2CN_CT})
    assert (again.status_code, _code(again)) == (409, "INVITATION_ALREADY_ANSWERED")
    assert (await test_client.get(f"/invitations/{invitation_id}")).json()["status"] == "accepted"


# ---------------------------------------------------------------------------
# invitation_id
# ---------------------------------------------------------------------------

BAD_IDS = [MISSING, None, "", 5, 5.0, 0, True, False, ["x"], {"id": "x"}]


@pytest.mark.asyncio
@pytest.mark.parametrize("invitation_id", BAD_IDS, ids=[_id((v,)) for v in BAD_IDS])
async def test_invitation_id_must_be_a_non_empty_string(test_client, invitation_id):
    import a2cn.server as server_module

    _register_inviters()
    r = await _post(test_client, _invitation(ALICE, invitation_id))

    assert r.status_code == 400
    assert _code(r) == "INVALID_REQUEST"
    assert list(server_module.invitation_store._invitations) == []


@pytest.mark.asyncio
async def test_a_numeric_id_never_reaches_a_string_ids_entry(test_client):
    import a2cn.server as server_module

    _register_inviters()
    assert (await _post(test_client, _invitation(ALICE, "5"))).status_code == 201
    r = await _post(test_client, _invitation(MALLORY, 5))

    assert (r.status_code, _code(r)) == (400, "INVALID_REQUEST")
    stored = (await test_client.get("/invitations/5")).json()
    assert stored["invitation"]["inviter_did"] == ALICE
    assert list(server_module.invitation_store._invitations) == ["5"]
