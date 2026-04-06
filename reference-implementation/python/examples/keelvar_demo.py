# -*- coding: utf-8 -*-
"""
A2CN Keelvar Adapter Demo — Path B Supplier-Side Integration

Scenario:
  Buyer:    AcmeBuyer Corp  (Keelvar platform user, sends sourcing events)
  Supplier: TechSupply Inc  (A2CN agent, responds via Keelvar webhook)

Path B — Zero Keelvar platform changes required:
  1. Keelvar fires SOURCING_EVENTS_FEED_UPDATED webhook to supplier's endpoint
  2. Supplier's A2CN agent parses the webhook → A2CN goods_procurement terms
  3. Agent accepts the implicit invitation and initiates an A2CN session
  4. 3-round negotiation: Buyer at $20,150 → Supplier at $23,000 → Buyer accepts $21,500
  5. Agreed terms translated back to a Keelvar bid response payload
  6. (Production) Supplier POSTs bid response to Keelvar API

Run with:
  cd reference-implementation/python
  python examples/keelvar_demo.py

No external dependencies — Keelvar API calls are simulated in-process.
The supplier's A2CN server runs on localhost:8003.
"""

from __future__ import annotations

import sys
import io

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import asyncio
import json
import threading
import time
import uuid
from pathlib import Path

# Allow running from examples/ subdirectory
_REPO_PY = Path(__file__).parent.parent
if str(_REPO_PY) not in sys.path:
    sys.path.insert(0, str(_REPO_PY))

import httpx
import uvicorn

from adapters.keelvar_adapter import KeelvarEventParser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(label: str, obj: dict) -> None:
    width = 72
    print()
    print("─" * width)
    print(f"  {label}")
    print("─" * width)
    print(json.dumps(obj, indent=2))
    print("─" * width)


SUPPLIER_PORT = 8003
SUPPLIER_ENDPOINT = f"http://localhost:{SUPPLIER_PORT}"

BUYER_DID = "did:web:acmebuyer.example"
SUPPLIER_DID = "did:web:techsupply.example"


def _now_fixed(offset_seconds: int = 0) -> str:
    from datetime import datetime, timezone, timedelta
    t = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def start_server(app, port: int) -> None:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    uvicorn.Server(config).run()


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
# Simulated Keelvar webhook payload (3 line items, mixed units)
# ---------------------------------------------------------------------------

KEELVAR_WEBHOOK = {
    "event_id": "evt-keelvar-q3-2026-001",
    "event_name": "Q3 2026 Industrial Supplies RFQ",
    "buyer_org": "AcmeBuyer Corp",
    "deadline": "2026-05-01T17:00:00Z",
    "currency": "USD",
    "line_items": [
        {
            "description": "Hydraulic fluid 200L drums",
            "quantity": 50,
            "unit_of_measure": "EA",
            "unit_price": 360.0,   # buyer's benchmark price in USD
            "lot_id": "LOT-HF-001",
        },
        {
            "description": "Sealing compound industrial grade",
            "quantity": 20,
            "unit_of_measure": "KG",
            "unit_price": 85.0,
            "lot_id": "LOT-SC-002",
        },
        {
            "description": "Safety gloves cut-resistant (box/100)",
            "quantity": 10,
            "unit_of_measure": "BX",
            "unit_price": 45.0,
            "lot_id": "LOT-SG-003",
        },
    ],
}


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

async def main() -> None:
    from a2cn.crypto import (
        generate_keypair,
        public_key_to_jwk,
        create_jwt,
        hash_object,
        sign_jws,
    )
    import a2cn.server as server_module
    from a2cn.server import app, configure_responder, manager, register_did_document
    from a2cn.client import A2CNClient
    from a2cn.record import generate_transaction_record
    from a2cn.session import _now as session_now

    # -----------------------------------------------------------------------
    # 1. Configure TechSupply (supplier) as the A2CN responder
    # -----------------------------------------------------------------------
    supplier_priv, _ = generate_keypair()
    buyer_priv, buyer_pub = generate_keypair()

    configure_responder({
        "agent_info": {
            "organization_name": "TechSupply Inc",
            "did": SUPPLIER_DID,
            "verification_method": f"{SUPPLIER_DID}#key-1",
            "agent_id": "supply-agent-ts-001",
            "endpoint": SUPPLIER_ENDPOINT,
        },
        "mandate": {
            "mandate_type": "declared",
            "agent_id": "supply-agent-ts-001",
            "principal_organization": "TechSupply Inc",
            "principal_did": SUPPLIER_DID,
            "authorized_deal_types": ["goods_procurement"],
            "max_commitment_value": 5_000_000,
            "max_commitment_currency": "USD",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T00:00:00Z",
        },
        "deal_types": ["goods_procurement"],
        "max_rounds_by_deal_type": {"goods_procurement": 5},
        "private_key": supplier_priv,
    })

    # Register buyer's DID doc so the supplier server can verify JWT signatures
    buyer_pub_jwk = public_key_to_jwk(buyer_pub)
    buyer_did_doc = {
        "@context": ["https://www.w3.org/ns/did/v1",
                     "https://w3id.org/security/suites/jws-2020/v1"],
        "id": BUYER_DID,
        "verificationMethod": [{
            "id": f"{BUYER_DID}#key-1",
            "type": "JsonWebKey2020",
            "controller": BUYER_DID,
            "publicKeyJwk": buyer_pub_jwk,
        }],
        "authentication": [f"{BUYER_DID}#key-1"],
        "assertionMethod": [f"{BUYER_DID}#key-1"],
    }
    # SERVER_DID is the JWT audience; set it to SUPPLIER_DID for this demo
    server_module.SERVER_DID = SUPPLIER_DID
    register_did_document(BUYER_DID, buyer_did_doc)

    server_thread = threading.Thread(
        target=start_server, args=(app, SUPPLIER_PORT), daemon=True
    )
    server_thread.start()
    await wait_for_server(f"{SUPPLIER_ENDPOINT}/.well-known/a2cn-agent")
    print("✓ Supplier A2CN server started")

    # Bearer auth: fresh ES256 JWT per request (anti-replay safe)
    class _BuyerAuth(httpx.Auth):
        def auth_flow(self, request):
            token = create_jwt(
                BUYER_DID, SUPPLIER_DID, buyer_priv,
                kid=f"{BUYER_DID}#key-1", exp_seconds=300,
            )
            request.headers["Authorization"] = f"Bearer {token}"
            yield request

    # -----------------------------------------------------------------------
    # 2. Simulate receiving Keelvar SOURCING_EVENTS_FEED_UPDATED webhook
    # -----------------------------------------------------------------------
    print()
    print("=" * 64)
    print("  Step 1 — Keelvar webhook received")
    print("=" * 64)

    # In production: verify HMAC signature first
    signing_key = "demo-keelvar-signing-key"
    import hashlib
    import hmac as hmac_mod
    body_bytes = json.dumps(KEELVAR_WEBHOOK, separators=(",", ":")).encode("utf-8")
    sig = hmac_mod.new(signing_key.encode(), body_bytes, hashlib.sha256).hexdigest()
    sig_valid = KeelvarEventParser.verify_webhook_signature(body_bytes, sig, signing_key)
    print(f"✓ Webhook signature verified (HMAC_SHA256): {sig_valid}")

    parsed = KeelvarEventParser.parse_sourcing_event_webhook(KEELVAR_WEBHOOK)
    _log("Keelvar SOURCING_EVENTS_FEED_UPDATED  →  parsed summary", {
        k: v for k, v in parsed.items() if k != "raw_payload"
    })
    print(f"✓ Keelvar event_id: {parsed['event_id']}")
    print(f"  Buyer: {parsed['buyer_org']}, deadline: {parsed['deadline']}")
    print(f"  Line items: {len(parsed['line_items'])}")

    # -----------------------------------------------------------------------
    # 3. Translate webhook to A2CN goods_procurement terms
    # -----------------------------------------------------------------------
    print()
    print("=" * 64)
    print("  Step 2 — Translate Keelvar event to A2CN terms")
    print("=" * 64)

    initial_terms = KeelvarEventParser.sourcing_event_to_goods_procurement_terms(
        KEELVAR_WEBHOOK,
        default_delivery_days=14,
    )
    _log("Keelvar line items  →  A2CN goods_procurement terms", initial_terms)
    buyer_benchmark = initial_terms["total_value"]
    print(
        f"✓ Buyer benchmark (from Keelvar prices): "
        f"${buyer_benchmark / 100:,.2f} {initial_terms['currency']}"
    )
    print("  Supplier will open above benchmark and negotiate down")

    # -----------------------------------------------------------------------
    # 4. Supplier initiates A2CN session using buyer benchmark + markup
    #    (in production: buyer sends SessionInvitation first; here we
    #     demonstrate the supplier initiating with benchmark context)
    # -----------------------------------------------------------------------
    print()
    print("=" * 64)
    print("  Step 3 — A2CN negotiation")
    print("=" * 64)

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
        "max_commitment_value": 3_000_000,
        "max_commitment_currency": "USD",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T00:00:00Z",
    }

    async with httpx.AsyncClient(auth=_BuyerAuth()) as http:
        client = A2CNClient(
            agent_info=buyer_agent_info,
            private_key=buyer_priv,
            mandate=buyer_mandate,
            http_client=http,
        )

        session_params = {
            "deal_type": "goods_procurement",
            "currency": "USD",
            "subject": f"Q3 2026 Industrial Supplies — {parsed['event_id']}",
            "subject_reference": parsed["event_id"],
            "estimated_value": buyer_benchmark,
            "max_rounds": 5,
            "session_timeout_seconds": 86400,
            "round_timeout_seconds": 3600,
        }

        ack = await client.initiate_session(
            endpoint=SUPPLIER_ENDPOINT,
            responder_did=SUPPLIER_DID,
            session_params=session_params,
        )
        session_id = ack["session_id"]
        print(f"✓ A2CN session opened — id: {session_id}")

        client._sessions[session_id]["session_ack"]["responder"] = {
            "organization_name": "TechSupply Inc",
            "did": SUPPLIER_DID,
            "verification_method": f"{SUPPLIER_DID}#key-1",
            "agent_id": "supply-agent-ts-001",
            "endpoint": SUPPLIER_ENDPOINT,
        }

        # -------------------------------------------------------------------
        # Round 1 — Buyer opens at benchmark ($20,150 = buyer_benchmark)
        # -------------------------------------------------------------------
        terms_r1 = dict(initial_terms)      # start from Keelvar benchmark
        await client.send_offer(SUPPLIER_ENDPOINT, SUPPLIER_DID, session_id, terms_r1)
        _log(
            f"Round 1 → Buyer offers ${buyer_benchmark / 100:,.0f} (Keelvar benchmark)",
            client._sessions[session_id]["latest_offer"],
        )

        # -------------------------------------------------------------------
        # Supplier counters — Round 2: markup ~14% above benchmark
        # -------------------------------------------------------------------
        session_obj = manager.get_session(session_id)
        r1_offer = client._sessions[session_id]["latest_offer"]

        supplier_counter_value = 2_300_000  # $23,000

        # Scale supplier's line item prices proportionally
        scale = supplier_counter_value / max(buyer_benchmark, 1)
        supplier_line_items = []
        for li in initial_terms["line_items"]:
            new_unit = int(li["unit_price"] * scale)
            supplier_line_items.append({
                **li,
                "unit_price": new_unit,
                "total": li["quantity"] * new_unit,
            })

        terms_r2 = {
            "total_value": supplier_counter_value,
            "currency": "USD",
            "line_items": supplier_line_items,
            "delivery_days": 10,
            "payment_terms": {"net_days": 45},
        }

        ts = session_now()
        exp = _now_fixed(900)
        msg_id_r2 = str(uuid.uuid4())
        act_r2 = {
            "protocol_version": "0.1",
            "session_id": session_id,
            "round_number": 2,
            "sequence_number": 2,
            "message_type": "counteroffer",
            "sender_did": SUPPLIER_DID,
            "timestamp": ts,
            "expires_at": exp,
            "terms": terms_r2,
        }
        pah_r2 = hash_object(act_r2)
        pas_r2 = sign_jws(pah_r2, supplier_priv, kid=f"{SUPPLIER_DID}#key-1")
        co_r2 = {
            "message_type": "counteroffer",
            "message_id": msg_id_r2,
            "session_id": session_id,
            "in_reply_to": r1_offer["message_id"],
            "round_number": 2,
            "sequence_number": 2,
            "sender_did": SUPPLIER_DID,
            "sender_agent_id": "supply-agent-ts-001",
            "sender_verification_method": f"{SUPPLIER_DID}#key-1",
            "timestamp": ts,
            "expires_at": exp,
            "terms": terms_r2,
            "protocol_act_hash": pah_r2,
            "protocol_act_signature": pas_r2,
        }
        manager.process_message(session_obj, co_r2)
        client.process_incoming(session_id, co_r2)
        _log(
            "Round 2 → Supplier counters $23,000 (net-45, delivery 10 days)",
            co_r2,
        )
        print(
            f"✓ Round 1: Buyer ${buyer_benchmark / 100:,.0f} "
            f"→ Supplier ${supplier_counter_value / 100:,.0f}"
        )

        # -------------------------------------------------------------------
        # Round 3 — Buyer counters at $21,500 (midpoint, buyer accepts)
        # -------------------------------------------------------------------
        final_value = 2_150_000  # $21,500

        scale2 = final_value / max(buyer_benchmark, 1)
        buyer_r3_line_items = []
        for li in initial_terms["line_items"]:
            new_unit = int(li["unit_price"] * scale2)
            buyer_r3_line_items.append({
                **li,
                "unit_price": new_unit,
                "total": li["quantity"] * new_unit,
            })

        terms_r3 = {
            "total_value": final_value,
            "currency": "USD",
            "line_items": buyer_r3_line_items,
            "delivery_days": 14,
            "payment_terms": {"net_days": 30},
        }
        await client.send_offer(
            SUPPLIER_ENDPOINT, SUPPLIER_DID, session_id, terms_r3,
            in_reply_to=co_r2["message_id"],
        )
        _log(
            "Round 3 → Buyer counters $21,500 (net-30, delivery 14 days)",
            client._sessions[session_id]["latest_offer"],
        )

        # -------------------------------------------------------------------
        # Supplier accepts $21,500 — session completes
        # -------------------------------------------------------------------
        r3_offer = client._sessions[session_id]["latest_offer"]
        ts = session_now()
        msg_id_acc = str(uuid.uuid4())
        act_acc = {
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
        pah_acc = hash_object(act_acc)
        pas_acc = sign_jws(pah_acc, supplier_priv, kid=f"{SUPPLIER_DID}#key-1")
        supplier_acceptance = {
            "message_type": "acceptance",
            "message_id": msg_id_acc,
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
            "protocol_act_hash": pah_acc,
            "protocol_act_signature": pas_acc,
        }
        manager.process_message(session_obj, supplier_acceptance)
        client.process_incoming(session_id, supplier_acceptance)
        _log(
            "Round 4 → Supplier accepts $21,500 — session COMPLETED",
            supplier_acceptance,
        )
        print(
            f"✓ Round 2: Buyer ${final_value / 100:,.0f} "
            f"→ Supplier accepts — DEAL at ${final_value / 100:,.0f}"
        )

        # -----------------------------------------------------------------------
        # 5. Verify transaction record hashes match
        # -----------------------------------------------------------------------
        server_record = generate_transaction_record(session_obj)
        client_record = client.build_client_side_record(session_id)
        assert server_record["record_hash"] == client_record["record_hash"], (
            f"MISMATCH!\n  server: {server_record['record_hash']}\n"
            f"  client: {client_record['record_hash']}"
        )
        print(f"✓ record_hash: {server_record['record_hash'][:32]}...")
        print(f"✓ Buyer record_hash == Supplier record_hash")

        # -----------------------------------------------------------------------
        # 6. Translate agreed terms back to Keelvar bid response
        # -----------------------------------------------------------------------
        print()
        print("=" * 64)
        print("  Step 4 — Translate agreed terms to Keelvar bid response")
        print("=" * 64)

        agreed_terms = terms_r3
        bid_response = KeelvarEventParser.terms_to_keelvar_bid_response(
            agreed_terms,
            event_id=parsed["event_id"],
            supplier_id="sup-techsupply-001",
        )
        _log(
            "A2CN agreed_terms  →  Keelvar bid response payload",
            bid_response,
        )

        print(f"✓ Bid response prepared for Keelvar event {parsed['event_id']}")
        print(f"  Total price: ${bid_response['total_price']:,.2f} {bid_response['currency']}")
        print(f"  Payment:     {bid_response['payment_terms']}")
        print(f"  Delivery:    {bid_response['delivery_days']} days")
        print(f"  Line items:  {len(bid_response['line_items'])}")
        print()
        print("  [Production] POST bid response to Keelvar API:")
        print("  POST https://my.keelvar.app/api/sourcing-events/bid-responses")
        print("  Authorization: Bearer {KEELVAR_API_KEY}")
        print()
        print(f"✓ Keelvar Path B integration demo complete")


if __name__ == "__main__":
    asyncio.run(main())
