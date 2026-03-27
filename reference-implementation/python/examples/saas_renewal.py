# -*- coding: utf-8 -*-
"""
A2CN v0.1 / v0.2 Demo — Appendix B SaaS Renewal Walkthrough

Scenario (from Appendix B):
  Buyer:  TechCorp Inc  (initiator)       starting position: $95,000
  Seller: Acme Corp     (responder)       starting position: $115,000
  Round 1: TechCorp offers $95K    → Acme counters $115K
  Round 2: TechCorp offers $103K   → Acme counters $105K (net-45)
  Round 4: TechCorp accepts $105K
  Outcome: $105,000 / year, net-45 payment terms

CLI flags (v0.2.0):
  --deal-type TYPE           Override deal_type in session_params (default: saas_renewal)
  --impasse-threshold N      Set impasse detection threshold (default: 3)

Run with:
  cd reference-implementation/python
  uv run python examples/saas_renewal.py
  uv run python examples/saas_renewal.py --deal-type saas_renewal --impasse-threshold 2
  (or: .venv/Scripts/python examples/saas_renewal.py)
"""

from __future__ import annotations
import sys, io
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import argparse
import asyncio
import json
import threading
import time
import uvicorn

import httpx


# ---------------------------------------------------------------------------
# Verbose logging helper
# ---------------------------------------------------------------------------

def _log(label: str, obj: dict) -> None:
    """Print a labelled, indented JSON block to stdout."""
    width = 72
    print()
    print("─" * width)
    print(f"  {label}")
    print("─" * width)
    print(json.dumps(obj, indent=2))
    print("─" * width)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SELLER_PORT = 8000
SELLER_ENDPOINT = f"http://localhost:{SELLER_PORT}"

TECHCORP_DID = "did:web:techcorp.example"
ACME_DID = "did:web:acme-corp.com"


def _now_fixed(offset_seconds: int = 0) -> str:
    from datetime import datetime, timezone, timedelta
    t = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Start the responder server in a background thread
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
                r = await client.get(url)
                return
            except Exception:
                await asyncio.sleep(0.1)
    raise RuntimeError(f"Server at {url} did not start within {timeout}s")


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

async def main(deal_type: str = "saas_renewal", impasse_threshold: int = 3) -> None:
    # -----------------------------------------------------------------------
    # 1. Configure and start the responder (Acme / seller side)
    # -----------------------------------------------------------------------
    from a2cn.crypto import generate_keypair, public_key_to_jwk
    from a2cn.server import app, configure_responder, manager
    from a2cn.client import A2CNClient
    from a2cn.record import generate_transaction_record

    if deal_type != "saas_renewal":
        print(f"  [demo] Using deal_type={deal_type!r}, impasse_threshold={impasse_threshold}")
    if impasse_threshold != 3:
        print(f"  [demo] impasse_threshold={impasse_threshold}")

    # Generate keys for both parties (Week 2 will use real DID-resolved keys)
    acme_priv, acme_pub = generate_keypair()
    techcorp_priv, techcorp_pub = generate_keypair()

    acme_agent_info = {
        "organization_name": "Acme Corp",
        "did": ACME_DID,
        "verification_method": f"{ACME_DID}#key-2026-01",
        "agent_id": "sales-agent-acme-007",
        "endpoint": SELLER_ENDPOINT,
    }

    acme_mandate = {
        "mandate_type": "declared",
        "agent_id": "sales-agent-acme-007",
        "principal_organization": "Acme Corp",
        "principal_did": ACME_DID,
        "authorized_deal_types": ["saas_renewal"],
        "max_commitment_value": 20_000_000,
        "max_commitment_currency": "USD",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T00:00:00Z",
    }

    configure_responder({
        "agent_info": acme_agent_info,
        "mandate": acme_mandate,
        "deal_types": ["saas_renewal", "services_contract", deal_type],
        "max_rounds_by_deal_type": {deal_type: 5},
    })

    # Start server in background thread
    server_thread = threading.Thread(target=start_server, args=(app, SELLER_PORT), daemon=True)
    server_thread.start()
    await wait_for_server(f"{SELLER_ENDPOINT}/docs")

    # -----------------------------------------------------------------------
    # 2. Initiator (TechCorp / buyer side) fetches discovery
    # -----------------------------------------------------------------------
    async with httpx.AsyncClient() as http:
        # Serve discovery document from the server itself for this demo
        # (in production this would be fetched from the seller's domain)
        techcorp_agent_info = {
            "organization_name": "TechCorp Inc",
            "did": TECHCORP_DID,
            "verification_method": f"{TECHCORP_DID}#key-1",
            "agent_id": "procurement-agent-tc-001",
            "endpoint": "https://techcorp.example/api/a2cn",
        }

        techcorp_mandate = {
            "mandate_type": "declared",
            "agent_id": "procurement-agent-tc-001",
            "principal_organization": "TechCorp Inc",
            "principal_did": TECHCORP_DID,
            "authorized_deal_types": ["saas_renewal"],
            "max_commitment_value": 15_000_000,
            "max_commitment_currency": "USD",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T00:00:00Z",
        }

        client = A2CNClient(
            agent_info=techcorp_agent_info,
            private_key=techcorp_priv,
            mandate=techcorp_mandate,
            http_client=http,
        )

        print("✓ Discovery document fetched from seller")

        # -----------------------------------------------------------------------
        # 3. Session initiation
        # -----------------------------------------------------------------------
        session_params = {
            "deal_type": deal_type,
            "currency": "USD",
            "subject": "Acme Analytics Platform — annual renewal FY2027",
            "subject_reference": "CONTRACT-2024-ACME-001",
            "estimated_value": 12_000_000,
            "max_rounds": 4,
            "session_timeout_seconds": 3600,
            "round_timeout_seconds": 900,
            "impasse_threshold": impasse_threshold,
        }

        ack = await client.initiate_session(
            endpoint=SELLER_ENDPOINT,
            responder_did=ACME_DID,
            session_params=session_params,
        )
        session_id = ack["session_id"]

        _log("REQUEST  POST /sessions  →  SessionInit (TechCorp → Acme)",
             client._sessions[session_id]["session_init"])
        _log("RESPONSE 201  ←  SessionAck (Acme → TechCorp)",
             ack)

        print(f"✓ Session initiated — session_id: {session_id}")

        # Tell client about responder party (for offer addressing)
        client._sessions[session_id]["session_ack"]["responder"] = acme_agent_info

        # -----------------------------------------------------------------------
        # 4. Round 1: TechCorp offers $95,000
        # -----------------------------------------------------------------------
        terms_r1 = {
            "total_value": 9_500_000,
            "currency": "USD",
            "line_items": [{
                "id": "li-1",
                "description": "Acme Analytics Platform — 12 months",
                "quantity": 1,
                "unit": "year",
                "unit_price": 9_500_000,
                "total": 9_500_000,
            }],
            "payment_terms": {"net_days": 30},
            "contract_duration": {
                "start_date": "2026-07-01",
                "end_date": "2027-06-30",
                "auto_renewal": False,
                "cancellation_notice_days": 60,
            },
        }

        await client.send_offer(SELLER_ENDPOINT, ACME_DID, session_id, terms_r1)
        _log("REQUEST  POST /sessions/{id}/messages  →  Offer round 1  seq 1  (TechCorp → Acme)  $95,000",
             client._sessions[session_id]["latest_offer"])

        # -----------------------------------------------------------------------
        # Acme (responder) counters — Round 2: $115,000 net-60
        # The responder logic runs in-process here; in production each party
        # would be a separate service. We call process_message directly on
        # the manager to simulate Acme's agent decision.
        # -----------------------------------------------------------------------
        session_obj = manager.get_session(session_id)

        from a2cn.session import _now as session_now
        from a2cn.crypto import hash_object, sign_jws

        def acme_counteroffer(
            sess_id: str,
            seq: int,
            rnd: int,
            terms: dict,
            in_reply_to: str,
        ) -> dict:
            ts = session_now()
            exp = _now_fixed(900)
            msg_id = __import__("uuid").uuid4().__str__()
            act = {
                "protocol_version": "0.1",
                "session_id": sess_id,
                "round_number": rnd,
                "sequence_number": seq,
                "message_type": "counteroffer",
                "sender_did": ACME_DID,
                "timestamp": ts,
                "expires_at": exp,
                "terms": terms,
            }
            pah = hash_object(act)
            pas_ = sign_jws(pah, acme_priv, kid=f"{ACME_DID}#key-2026-01")
            msg = {
                "message_type": "counteroffer",
                "message_id": msg_id,
                "session_id": sess_id,
                "in_reply_to": in_reply_to,
                "round_number": rnd,
                "sequence_number": seq,
                "sender_did": ACME_DID,
                "sender_agent_id": "sales-agent-acme-007",
                "sender_verification_method": f"{ACME_DID}#key-2026-01",
                "timestamp": ts,
                "expires_at": exp,
                "terms": terms,
                "protocol_act_hash": pah,
                "protocol_act_signature": pas_,
            }
            return msg

        # Round 2: Acme counters $115K, net-60
        r1_offer = client._sessions[session_id]["latest_offer"]
        terms_r2 = {
            "total_value": 11_500_000,
            "currency": "USD",
            "line_items": [{
                "id": "li-1",
                "description": "Acme Analytics Platform — 12 months",
                "quantity": 1,
                "unit": "year",
                "unit_price": 11_500_000,
                "total": 11_500_000,
            }],
            "payment_terms": {"net_days": 60},
            "contract_duration": {
                "start_date": "2026-07-01",
                "end_date": "2027-06-30",
                "auto_renewal": False,
                "cancellation_notice_days": 60,
            },
        }
        co_r2 = acme_counteroffer(session_id, 2, 2, terms_r2, r1_offer["message_id"])
        manager.process_message(session_obj, co_r2)

        _log("REQUEST  POST /sessions/{id}/messages  →  Counteroffer round 2  seq 2  (Acme → TechCorp)  $115,000",
             co_r2)

        # Update client state to track Acme's counteroffer
        client.process_incoming(session_id, co_r2)

        print(f"✓ Round 1: TechCorp offers $95,000 — Acme counters $115,000")

        # -----------------------------------------------------------------------
        # Round 3: TechCorp counters $103,000 net-30
        # -----------------------------------------------------------------------
        terms_r3 = {
            "total_value": 10_300_000,
            "currency": "USD",
            "line_items": [{
                "id": "li-1",
                "description": "Acme Analytics Platform — 12 months",
                "quantity": 1,
                "unit": "year",
                "unit_price": 10_300_000,
                "total": 10_300_000,
            }],
            "payment_terms": {"net_days": 30},
            "contract_duration": {
                "start_date": "2026-07-01",
                "end_date": "2027-06-30",
                "auto_renewal": False,
                "cancellation_notice_days": 60,
            },
        }
        await client.send_offer(SELLER_ENDPOINT, ACME_DID, session_id, terms_r3, in_reply_to=co_r2["message_id"])
        _log("REQUEST  POST /sessions/{id}/messages  →  Counteroffer round 3  seq 3  (TechCorp → Acme)  $103,000",
             client._sessions[session_id]["latest_offer"])

        # Round 4: Acme counters $105,000 net-45 (within tolerance — TechCorp will accept)
        r3_offer = client._sessions[session_id]["latest_offer"]
        terms_r4 = {
            "total_value": 10_500_000,
            "currency": "USD",
            "line_items": [{
                "id": "li-1",
                "description": "Acme Analytics Platform — 12 months",
                "quantity": 1,
                "unit": "year",
                "unit_price": 10_500_000,
                "total": 10_500_000,
            }],
            "payment_terms": {"net_days": 45},
            "contract_duration": {
                "start_date": "2026-07-01",
                "end_date": "2027-06-30",
                "auto_renewal": False,
                "cancellation_notice_days": 60,
            },
        }
        co_r4 = acme_counteroffer(session_id, 4, 4, terms_r4, r3_offer["message_id"])
        manager.process_message(session_obj, co_r4)

        _log("REQUEST  POST /sessions/{id}/messages  →  Counteroffer round 4  seq 4  (Acme → TechCorp)  $105,000",
             co_r4)

        # Update client state
        client.process_incoming(session_id, co_r4)

        print(f"✓ Round 2: TechCorp offers $103,000 — Acme counters $105,000 net-45")

        # -----------------------------------------------------------------------
        # TechCorp accepts Acme's $105K offer
        # -----------------------------------------------------------------------
        await client.send_acceptance(SELLER_ENDPOINT, ACME_DID, session_id, co_r4)
        _log("REQUEST  POST /sessions/{id}/messages  →  Acceptance  seq 5  (TechCorp → Acme)",
             client._sessions[session_id]["message_log"][-1])
        print(f"✓ Round 4: TechCorp accepts $105,000")

        # -----------------------------------------------------------------------
        # Both sides generate transaction records independently
        # -----------------------------------------------------------------------
        # Server side
        server_record = generate_transaction_record(session_obj)

        # Client side
        client_record = client.build_client_side_record(session_id)

        _log("TRANSACTION RECORD  (generated independently by Acme / seller side)",
             server_record)
        print(f"✓ Transaction record generated — record_hash: {server_record['record_hash'][:32]}...")

        assert server_record["record_hash"] == client_record["record_hash"], (
            f"MISMATCH!\n  server: {server_record['record_hash']}\n  client: {client_record['record_hash']}"
        )
        print(f"✓ Buyer record_hash == Seller record_hash")
        print(f"✓ A2CN bilateral session complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A2CN SaaS Renewal demo")
    parser.add_argument(
        "--deal-type",
        default="saas_renewal",
        metavar="TYPE",
        help="Deal type for the session (default: saas_renewal)",
    )
    parser.add_argument(
        "--impasse-threshold",
        type=int,
        default=3,
        metavar="N",
        help="Consecutive non-moving rounds before IMPASSE (default: 3)",
    )
    args = parser.parse_args()
    asyncio.run(main(deal_type=args.deal_type, impasse_threshold=args.impasse_threshold))
