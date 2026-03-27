# -*- coding: utf-8 -*-
"""
A2CN v0.2.0 Demo — Component 8: Session Invitation Flow

Scenario:
  Buyer:    AcmeBuyer   (inviter)    — proposes a goods_procurement session
  Supplier: TechSupply  (invitee)    — receives, verifies, and accepts
  After acceptance both parties proceed to a short negotiation (2 rounds)
  that reaches COMPLETED.

Demonstrates:
  - InvitationStore.create_invitation() with ES256 signing
  - verify_invitation_signature() on the received invitation
  - POST /invitations  (supplier receives inbound invitation)
  - POST /invitations/{id}/accept  (supplier accepts)
  - GET  /invitations/{id}         (buyer polls status)
  - Session negotiation starting from invitation context
  - Terminal webhook payload structure (logged in-process)

Run with:
  cd reference-implementation/python
  uv run python examples/invitation_flow.py
  (or: ./venv/Scripts/python examples/invitation_flow.py)
"""

from __future__ import annotations
import sys, io
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import asyncio
import json
import threading
import time
import uuid
from dataclasses import asdict

import httpx
import uvicorn


# ---------------------------------------------------------------------------
# Pretty-print helper
# ---------------------------------------------------------------------------

def _log(label: str, obj: dict) -> None:
    width = 72
    print()
    print("─" * width)
    print(f"  {label}")
    print("─" * width)
    print(json.dumps(obj, indent=2))
    print("─" * width)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPLIER_PORT = 8001
SUPPLIER_ENDPOINT = f"http://localhost:{SUPPLIER_PORT}"

BUYER_DID = "did:web:acmebuyer.example"
SUPPLIER_DID = "did:web:techsupply.example"


def _now_fixed(offset_seconds: int = 0) -> str:
    from datetime import datetime, timezone, timedelta
    t = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Server helpers
# ---------------------------------------------------------------------------

def start_server(app, port: int) -> None:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    server.run()


async def wait_for_server(url: str, timeout: float = 10.0) -> None:
    async with httpx.AsyncClient() as client:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                await client.get(url)
                return
            except Exception:
                await asyncio.sleep(0.1)
    raise RuntimeError(f"Server at {url} did not start within {timeout}s")


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

async def main() -> None:
    from a2cn.crypto import (
        generate_keypair,
        public_key_to_jwk,
        verify_invitation_signature,
        hash_object,
        sign_jws,
    )
    from a2cn.server import app, configure_responder, manager
    from a2cn.client import A2CNClient
    from a2cn.invitation import InvitationStore
    from a2cn.messages import InvitationStatus
    from a2cn.session import _now as session_now

    # -----------------------------------------------------------------------
    # 1. Generate keypairs for both parties
    # -----------------------------------------------------------------------
    buyer_priv, buyer_pub = generate_keypair()
    supplier_priv, supplier_pub = generate_keypair()

    supplier_agent_info = {
        "organization_name": "TechSupply Inc",
        "did": SUPPLIER_DID,
        "verification_method": f"{SUPPLIER_DID}#key-1",
        "agent_id": "supply-agent-ts-001",
        "endpoint": SUPPLIER_ENDPOINT,
    }

    supplier_mandate = {
        "mandate_type": "declared",
        "agent_id": "supply-agent-ts-001",
        "principal_organization": "TechSupply Inc",
        "principal_did": SUPPLIER_DID,
        "authorized_deal_types": ["goods_procurement"],
        "max_commitment_value": 5_000_000,
        "max_commitment_currency": "USD",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T00:00:00Z",
    }

    configure_responder({
        "agent_info": supplier_agent_info,
        "mandate": supplier_mandate,
        "deal_types": ["goods_procurement"],
        "max_rounds_by_deal_type": {"goods_procurement": 5},
        "private_key": supplier_priv,
    })

    # -----------------------------------------------------------------------
    # 2. Start the supplier's A2CN server
    # -----------------------------------------------------------------------
    server_thread = threading.Thread(
        target=start_server, args=(app, SUPPLIER_PORT), daemon=True
    )
    server_thread.start()
    await wait_for_server(f"{SUPPLIER_ENDPOINT}/docs")
    print("✓ Supplier server started")

    # -----------------------------------------------------------------------
    # 3. Buyer creates and signs a SessionInvitation
    # -----------------------------------------------------------------------
    buyer_store = InvitationStore()
    invitation = buyer_store.create_invitation(
        inviter_did=BUYER_DID,
        inviter_endpoint="https://acmebuyer.example/a2cn",
        inviter_discovery_url="https://acmebuyer.example/.well-known/a2cn-agent",
        inviter_verification_method=f"{BUYER_DID}#key-1",
        private_key=buyer_priv,
        proposed_deal_type="goods_procurement",
        proposed_session_params={
            "currency": "USD",
            "max_rounds": 4,
            "session_timeout_seconds": 86400,
            "round_timeout_seconds": 3600,
        },
        proposed_terms_summary={
            "description": "Hydraulic fluid drums — 50 x 200L",
            "estimated_value": 1_800_000,
            "currency": "USD",
        },
        inviter_mandate_summary={
            "mandate_type": "declared",
            "max_commitment_value": 2_500_000,
            "authorized_deal_types": ["goods_procurement"],
        },
        expires_hours=24,
        base_url=SUPPLIER_ENDPOINT,
    )

    inv_dict = asdict(invitation)
    _log(
        f"BUYER creates SessionInvitation  invitation_id={invitation.invitation_id[:8]}...",
        inv_dict,
    )
    print(f"✓ Invitation created — id: {invitation.invitation_id}")
    print(f"  signature: {invitation.invitation_signature[:32]}...")

    # -----------------------------------------------------------------------
    # 4. Supplier verifies the invitation signature before storing
    # -----------------------------------------------------------------------
    sig_valid = verify_invitation_signature(inv_dict, buyer_pub)
    assert sig_valid, "Invitation signature verification FAILED"
    print(f"✓ Invitation signature verified (ES256 + JCS)")

    # -----------------------------------------------------------------------
    # 5. Supplier receives invitation via POST /invitations
    # -----------------------------------------------------------------------
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{SUPPLIER_ENDPOINT}/invitations", json=inv_dict)
        assert r.status_code in (200, 201), f"POST /invitations failed: {r.status_code} {r.text}"
        receive_resp = r.json()
        _log("RESPONSE  POST /invitations  (supplier receives inbound invitation)", receive_resp)
        print("✓ Supplier stored inbound invitation")

        # -----------------------------------------------------------------------
        # 6. Supplier polls GET /invitations/{id} — should be PENDING
        # -----------------------------------------------------------------------
        r = await http.get(f"{SUPPLIER_ENDPOINT}/invitations/{invitation.invitation_id}")
        assert r.status_code == 200
        status_resp = r.json()
        assert status_resp["status"] == InvitationStatus.PENDING
        print(f"✓ GET /invitations/{{id}} → status: {status_resp['status']}")

        # -----------------------------------------------------------------------
        # 7. Supplier accepts via POST /invitations/{id}/accept
        # -----------------------------------------------------------------------
        accept_payload = {
            "acceptor_did": SUPPLIER_DID,
            "acceptor_a2cn_endpoint": SUPPLIER_ENDPOINT,
            "acceptor_discovery_url": f"https://techsupply.example/.well-known/a2cn-agent",
            "acceptor_verification_method": f"{SUPPLIER_DID}#key-1",
            "acceptor_public_key_jwk": public_key_to_jwk(supplier_pub),
        }
        r = await http.post(
            f"{SUPPLIER_ENDPOINT}/invitations/{invitation.invitation_id}/accept",
            json=accept_payload,
        )
        assert r.status_code == 200, f"POST /accept failed: {r.status_code} {r.text}"
        acceptance = r.json()
        _log("RESPONSE  POST /invitations/{id}/accept  (InvitationAcceptance)", acceptance)
        print(f"✓ Acceptance issued — signed: {'acceptance_signature' in acceptance}")

        # -----------------------------------------------------------------------
        # 8. Buyer updates stored invitation to ACCEPTED
        # -----------------------------------------------------------------------
        buyer_store.store_inbound(inv_dict)  # store a copy for tracking
        entry = buyer_store.get_invitation(invitation.invitation_id)
        # In production the buyer would receive acceptance via webhook/callback;
        # here we directly mark it accepted to mirror server state.
        from a2cn.messages import InvitationStatus as IS
        entry["status"] = IS.ACCEPTED
        print("✓ Buyer records invitation as ACCEPTED")

        # -----------------------------------------------------------------------
        # 9. Both parties proceed to open a negotiation session
        #    The buyer initiates using the proposed session params from the invitation.
        # -----------------------------------------------------------------------
        buyer_agent_info = {
            "organization_name": "AcmeBuyer Corp",
            "did": BUYER_DID,
            "verification_method": f"{BUYER_DID}#key-1",
            "agent_id": "procurement-agent-ab-001",
            "endpoint": "https://acmebuyer.example/api/a2cn",
        }
        buyer_mandate = {
            "mandate_type": "declared",
            "agent_id": "procurement-agent-ab-001",
            "principal_organization": "AcmeBuyer Corp",
            "principal_did": BUYER_DID,
            "authorized_deal_types": ["goods_procurement"],
            "max_commitment_value": 2_500_000,
            "max_commitment_currency": "USD",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T00:00:00Z",
        }

        client = A2CNClient(
            agent_info=buyer_agent_info,
            private_key=buyer_priv,
            mandate=buyer_mandate,
            http_client=http,
        )

        session_params = {
            "deal_type": "goods_procurement",
            "currency": "USD",
            "subject": "Hydraulic fluid drums — Q3 2026",
            "subject_reference": f"INV-{invitation.invitation_id[:8].upper()}",
            "estimated_value": 1_800_000,
            "max_rounds": 4,
            "session_timeout_seconds": 86400,
            "round_timeout_seconds": 3600,
            # Link back to the invitation that started this session
            "invitation_id": invitation.invitation_id,
        }

        ack = await client.initiate_session(
            endpoint=SUPPLIER_ENDPOINT,
            responder_did=SUPPLIER_DID,
            session_params=session_params,
        )
        session_id = ack["session_id"]
        _log("REQUEST  POST /sessions  →  SessionInit (Buyer → Supplier)", client._sessions[session_id]["session_init"])
        _log("RESPONSE 201  ←  SessionAck (Supplier → Buyer)", ack)
        print(f"✓ Session opened — session_id: {session_id}")

        # Tell client about responder (for offer addressing)
        client._sessions[session_id]["session_ack"]["responder"] = supplier_agent_info

        # -----------------------------------------------------------------------
        # 10. Round 1 — Buyer offers $18,000 (1,800,000 cents)
        # -----------------------------------------------------------------------
        terms_r1 = {
            "total_value": 1_800_000,
            "currency": "USD",
            "line_items": [
                {
                    "id": "li-1",
                    "description": "Hydraulic fluid 200L drums",
                    "quantity": 50,
                    "unit_of_measure": "EA",
                    "unit_price": 36_000,
                    "total": 1_800_000,
                }
            ],
            "delivery_days": 14,
            "payment_terms": {"net_days": 30},
        }
        await client.send_offer(SUPPLIER_ENDPOINT, SUPPLIER_DID, session_id, terms_r1)
        _log(
            "REQUEST  POST /sessions/{id}/messages  →  Offer round 1  (Buyer → Supplier)  $18,000",
            client._sessions[session_id]["latest_offer"],
        )

        # -----------------------------------------------------------------------
        # Supplier counters — Round 2: $20,000 net-60
        # -----------------------------------------------------------------------
        session_obj = manager.get_session(session_id)
        r1_offer = client._sessions[session_id]["latest_offer"]

        def supplier_counter(sess_id, seq, rnd, terms, in_reply_to):
            ts = session_now()
            exp = _now_fixed(900)
            msg_id = str(uuid.uuid4())
            act = {
                "protocol_version": "0.1",
                "session_id": sess_id,
                "round_number": rnd,
                "sequence_number": seq,
                "message_type": "counteroffer",
                "sender_did": SUPPLIER_DID,
                "timestamp": ts,
                "expires_at": exp,
                "terms": terms,
            }
            pah = hash_object(act)
            pas_ = sign_jws(pah, supplier_priv, kid=f"{SUPPLIER_DID}#key-1")
            return {
                "message_type": "counteroffer",
                "message_id": msg_id,
                "session_id": sess_id,
                "in_reply_to": in_reply_to,
                "round_number": rnd,
                "sequence_number": seq,
                "sender_did": SUPPLIER_DID,
                "sender_agent_id": "supply-agent-ts-001",
                "sender_verification_method": f"{SUPPLIER_DID}#key-1",
                "timestamp": ts,
                "expires_at": exp,
                "terms": terms,
                "protocol_act_hash": pah,
                "protocol_act_signature": pas_,
            }

        terms_r2 = {
            "total_value": 2_000_000,
            "currency": "USD",
            "line_items": [
                {
                    "id": "li-1",
                    "description": "Hydraulic fluid 200L drums",
                    "quantity": 50,
                    "unit_of_measure": "EA",
                    "unit_price": 40_000,
                    "total": 2_000_000,
                }
            ],
            "delivery_days": 10,
            "payment_terms": {"net_days": 60},
        }
        co_r2 = supplier_counter(session_id, 2, 2, terms_r2, r1_offer["message_id"])
        manager.process_message(session_obj, co_r2)
        client.process_incoming(session_id, co_r2)
        _log(
            "REQUEST  POST /sessions/{id}/messages  →  Counteroffer round 2  (Supplier → Buyer)  $20,000",
            co_r2,
        )
        print("✓ Round 1: Buyer offers $18,000 — Supplier counters $20,000")

        # -----------------------------------------------------------------------
        # Round 3 — Buyer counters $19,000 (moving round — > 0.5% delta)
        # -----------------------------------------------------------------------
        terms_r3 = {
            "total_value": 1_900_000,
            "currency": "USD",
            "line_items": [
                {
                    "id": "li-1",
                    "description": "Hydraulic fluid 200L drums",
                    "quantity": 50,
                    "unit_of_measure": "EA",
                    "unit_price": 38_000,
                    "total": 1_900_000,
                }
            ],
            "delivery_days": 14,
            "payment_terms": {"net_days": 30},
        }
        await client.send_offer(
            SUPPLIER_ENDPOINT, SUPPLIER_DID, session_id, terms_r3,
            in_reply_to=co_r2["message_id"],
        )
        _log(
            "REQUEST  POST /sessions/{id}/messages  →  Counteroffer round 3  (Buyer → Supplier)  $19,000",
            client._sessions[session_id]["latest_offer"],
        )

        # -----------------------------------------------------------------------
        # Supplier accepts $19,000 — session completes
        # -----------------------------------------------------------------------
        r3_offer = client._sessions[session_id]["latest_offer"]

        # Supplier acceptance message
        ts = session_now()
        msg_id = str(uuid.uuid4())
        # Acceptance uses current round (3), not a new round; sequence advances
        act = {
            "protocol_version": "0.1",
            "session_id": session_id,
            "round_number": 3,
            "sequence_number": 4,
            "accepted_offer_id": r3_offer["message_id"],
            "accepted_protocol_act_hash": r3_offer["protocol_act_hash"],
            "message_type": "acceptance",
            "sender_did": SUPPLIER_DID,
            "timestamp": ts,
            "expires_at": _now_fixed(900),
            "terms": terms_r3,
        }
        pah = hash_object(act)
        pas_ = sign_jws(pah, supplier_priv, kid=f"{SUPPLIER_DID}#key-1")
        supplier_acceptance = {
            "message_type": "acceptance",
            "message_id": msg_id,
            "session_id": session_id,
            "in_reply_to": r3_offer["message_id"],
            "accepted_offer_id": r3_offer["message_id"],
            "accepted_protocol_act_hash": r3_offer["protocol_act_hash"],
            "round_number": 3,
            "sequence_number": 4,
            "sender_did": SUPPLIER_DID,
            "sender_agent_id": "supply-agent-ts-001",
            "sender_verification_method": f"{SUPPLIER_DID}#key-1",
            "timestamp": ts,
            "expires_at": _now_fixed(900),
            "terms": terms_r3,
            "protocol_act_hash": pah,
            "protocol_act_signature": pas_,
        }
        manager.process_message(session_obj, supplier_acceptance)
        client.process_incoming(session_id, supplier_acceptance)
        _log(
            "REQUEST  POST /sessions/{id}/messages  →  Acceptance round 4  (Supplier → Buyer)  $19,000",
            supplier_acceptance,
        )
        print("✓ Round 3: Buyer offers $19,000 — Supplier accepts")

        # -----------------------------------------------------------------------
        # 11. Verify terminal state and transaction record
        # -----------------------------------------------------------------------
        from a2cn.record import generate_transaction_record

        server_record = generate_transaction_record(session_obj)
        client_record = client.build_client_side_record(session_id)

        _log(
            "TRANSACTION RECORD  (generated independently by Supplier / server side)",
            server_record,
        )

        assert server_record["record_hash"] == client_record["record_hash"], (
            f"Hash mismatch!\n  server: {server_record['record_hash']}\n"
            f"  client: {client_record['record_hash']}"
        )

        print(f"✓ Session COMPLETED — record_hash: {server_record['record_hash'][:32]}...")
        print(f"✓ Buyer record_hash == Supplier record_hash")

        # -----------------------------------------------------------------------
        # 12. Show what a terminal WebhookPayload looks like
        # -----------------------------------------------------------------------
        from a2cn.messages import WebhookPayload
        from dataclasses import asdict as _asdict
        webhook = WebhookPayload(
            event_type="session.completed",
            session_id=session_id,
            occurred_at=session_now(),
            session_state="COMPLETED",
            terminal=True,
            a2cn_version="0.2",
            record_hash=server_record["record_hash"],
        )
        _log(
            "WEBHOOK PAYLOAD  (would be POST'd to webhook_url on terminal transition)",
            _asdict(webhook),
        )
        print("✓ WebhookPayload constructed (delivery skipped — no webhook_url configured)")
        print()
        print("✓ A2CN v0.2.0 invitation flow complete")


if __name__ == "__main__":
    asyncio.run(main())
