# -*- coding: utf-8 -*-
"""
A2CN MCP Agent Demo — SaaS Renewal Negotiation via MCP Tools

Demonstrates how an LLM agent uses the A2CN MCP server tools to negotiate
commercial terms autonomously.  The buyer (TechCorp) interacts exclusively
through the six MCP tools exposed by mcp_server.py.  The seller (Acme) is
simulated in-process using MockLLM, mirroring the pattern in saas_renewal.py.

Architecture (per spec Section 13.9):
    Buyer MockLLM
        → decides: what to offer, whether to accept or reject
    MCP tool layer (mcp_server.py)
        → handles: session state, DID auth, message signing, sequence tracking
    A2CN FastAPI server (seller / responder side)
        → processes all messages, enforces protocol rules, generates records

Expected output:
    ✓ Discovered Acme: A2CN v0.2, conformance 2, deal types: ['saas_renewal']
    ✓ Session initiated — id: xxxxxxxx...
    ✓ Exchange 1: Buyer $95,000 → Seller $109,000
      [Buyer LLM] Counter: $99,000 / net-30
    ✓ Exchange 2: Buyer $99,000 → Seller $106,000
      [Buyer LLM] Accepting $106,000 / net-30
    ✓ Exchange 2: Buyer accepts — deal at $106,000 / net-30
    ✓ Transaction record_hash: ...
    ✓ A2CN MCP agent demo complete

Run with:
    cd reference-implementation/python
    python examples/mcp_agent_demo.py
"""

from __future__ import annotations

import sys
import io

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import os
import asyncio
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup — must happen before any a2cn / mcp_server imports
# ---------------------------------------------------------------------------

_REPO_PY = Path(__file__).parent.parent          # reference-implementation/python
_EXAMPLES = Path(__file__).parent                # reference-implementation/python/examples

if str(_REPO_PY) not in sys.path:
    sys.path.insert(0, str(_REPO_PY))
if str(_EXAMPLES) not in sys.path:
    sys.path.insert(0, str(_EXAMPLES))

# ---------------------------------------------------------------------------
# Agent identity — configure via environment variables before mcp_server loads.
# mcp_server reads these at import time to build the ephemeral DID document.
# ---------------------------------------------------------------------------

os.environ.setdefault("A2CN_AGENT_DID", "did:web:mcp-buyer.demo")
os.environ.setdefault("A2CN_AGENT_ID", "mcp-buyer-001")
os.environ.setdefault("A2CN_AGENT_ORG", "TechCorp Inc")

import httpx
import uvicorn

import mcp_server as mcp_srv
from llm_agent import (
    MockLLM,
    NegotiationSkill,
    get_validated_decision,
    build_terms_from_decision,
    _build_seller_counteroffer,
)

# ---------------------------------------------------------------------------
# Demo constants
# ---------------------------------------------------------------------------

SELLER_DID = "did:web:acme-corp.com"
BUYER_DID = mcp_srv._agent_did          # resolved from env var above
SELLER_PORT = 8002
SELLER_ENDPOINT = f"http://localhost:{SELLER_PORT}"


# ---------------------------------------------------------------------------
# Patch DID-to-URL resolution for local demo
#
# In production:  did:web:acme-corp.com  →  https://acme-corp.com
# In this demo:   did:web:acme-corp.com  →  http://localhost:8002
#
# This lets the MCP tools talk to a local server without modifying mcp_server.py.
# ---------------------------------------------------------------------------

_orig_did_to_base_url = mcp_srv._did_to_base_url


def _demo_did_to_base_url(did: str) -> str:
    if did == SELLER_DID:
        return SELLER_ENDPOINT
    return _orig_did_to_base_url(did)


mcp_srv._did_to_base_url = _demo_did_to_base_url


# ---------------------------------------------------------------------------
# Server helpers (same pattern as saas_renewal.py)
# ---------------------------------------------------------------------------

def _start_server(app, port: int) -> None:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    uvicorn.Server(config).run()


async def _wait_for_server(url: str, timeout: float = 10.0) -> None:
    async with httpx.AsyncClient() as http:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                await http.get(url)
                return
            except Exception:
                await asyncio.sleep(0.1)
    raise RuntimeError(f"Server at {url} did not start within {timeout}s")


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

async def main() -> None:
    from a2cn.crypto import generate_keypair
    import a2cn.server as server_module
    from a2cn.server import app, configure_responder, manager, register_did_document

    # -----------------------------------------------------------------------
    # 1. Configure Acme (seller) as the A2CN responder
    # -----------------------------------------------------------------------
    acme_priv, _ = generate_keypair()

    configure_responder({
        "agent_info": {
            "organization_name": "Acme Corp",
            "did": SELLER_DID,
            "verification_method": f"{SELLER_DID}#key-1",
            "agent_id": "sales-agent-acme-007",
            "endpoint": SELLER_ENDPOINT,
        },
        "mandate": {
            "mandate_type": "declared",
            "agent_id": "sales-agent-acme-007",
            "principal_organization": "Acme Corp",
            "principal_did": SELLER_DID,
            "authorized_deal_types": ["saas_renewal"],
            "max_commitment_value": 20_000_000,
            "max_commitment_currency": "USD",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T00:00:00Z",
        },
        "deal_types": ["saas_renewal"],
        "max_rounds_by_deal_type": {"saas_renewal": 8},
        "private_key": acme_priv,
    })

    # The server's own DID is used as the JWT audience claim.
    # Setting it equal to SELLER_DID means discovery returns the same value,
    # so the MCP tool's JWT audience resolves correctly.
    server_module.SERVER_DID = SELLER_DID

    # Register the MCP buyer's ephemeral DID document with the seller server
    # so it can verify Bearer JWT signatures on incoming requests.
    register_did_document(BUYER_DID, mcp_srv.agent_did_document)

    # Tell the MCP server the JWT audience directly, skipping a second
    # discovery round-trip inside a2cn_initiate_session.
    os.environ["A2CN_COUNTERPARTY_SERVER_DID"] = SELLER_DID

    # -----------------------------------------------------------------------
    # 2. Start the Acme (seller) server in a background thread
    # -----------------------------------------------------------------------
    t = threading.Thread(target=_start_server, args=(app, SELLER_PORT), daemon=True)
    t.start()
    await _wait_for_server(f"{SELLER_ENDPOINT}/.well-known/a2cn-agent")

    print()
    print("=" * 62)
    print("  A2CN MCP Agent Demo — SaaS Renewal Negotiation")
    print("=" * 62)
    print(f"  Buyer  (MCP agent): {BUYER_DID}")
    print(f"  Seller (Acme Corp): {SELLER_DID}")
    print(f"  Transport:          HTTP → {SELLER_ENDPOINT}")
    print()

    # -----------------------------------------------------------------------
    # 3. Discover the seller via MCP tool (Tool 1: a2cn_discover)
    # -----------------------------------------------------------------------
    disc = await mcp_srv.a2cn_discover(SELLER_DID)
    if disc.get("a2cn_capable"):
        print(
            f"✓ Discovered Acme: A2CN v{disc['a2cn_version']}, "
            f"conformance {disc['conformance_level']}, "
            f"deal types: {disc['deal_types']}"
        )
    else:
        # Graceful degradation — demo continues even if discovery HTTP fails
        print(f"  [discovery skipped — demo mode]: {disc.get('message', '')[:70]}")

    # -----------------------------------------------------------------------
    # 4. Initiate session and send opening offer (Tool 2: a2cn_initiate_session)
    # -----------------------------------------------------------------------
    buyer_opening_cents = 9_500_000   # $95,000
    buyer_opening_net   = 30

    print(f"\n[Buyer LLM] Opening offer: ${buyer_opening_cents // 100:,} / net-{buyer_opening_net}")

    init_result = await mcp_srv.a2cn_initiate_session(
        counterparty_did=SELLER_DID,
        deal_type="saas_renewal",
        my_did=BUYER_DID,
        initial_offer_total_value_cents=buyer_opening_cents,
        currency="USD",
        max_rounds=6,
        payment_terms_net_days=buyer_opening_net,
        subject="Acme Analytics Platform — FY2027 renewal",
    )

    if "error" in init_result:
        print(f"✗ Session init failed: {init_result}")
        return

    session_id = init_result["session_id"]
    print(f"✓ Session initiated — id: {session_id[:16]}...")

    # -----------------------------------------------------------------------
    # 5. Negotiation loop
    #
    # Buyer decisions come from MockLLM via MCP tools.
    # Seller decisions come from MockLLM processed directly via the server's
    # session manager (simulating the seller's in-process agent).
    # -----------------------------------------------------------------------
    buyer_skill = NegotiationSkill(
        role="buyer",
        deal_type="saas_renewal",
        floor_value_cents=10_600_000,   # max willing to pay: $106,000
        target_value_cents=buyer_opening_cents,
        max_net_days=45,
        min_net_days=0,
        walk_away_rounds=3,
        rationale_template="aggressive buyer pushing for lowest total cost",
    )
    seller_skill = NegotiationSkill(
        role="seller",
        deal_type="saas_renewal",
        floor_value_cents=10_500_000,   # min willing to accept: $105,000
        target_value_cents=11_500_000,
        max_net_days=60,
        min_net_days=30,
        walk_away_rounds=3,
        rationale_template="seller protecting margin while staying competitive",
    )

    buyer_llm  = MockLLM()
    seller_llm = MockLLM()

    buyer_history:  list[dict] = [{"value": buyer_opening_cents, "net_days": buyer_opening_net}]
    seller_history: list[dict] = []

    session_obj  = manager.get_session(session_id)
    client_state = mcp_srv._sessions[session_id]["client"]._sessions[session_id]

    exchange = 1

    while True:
        # -------------------------------------------------------------------
        # Seller's turn (simulated in-process, not via HTTP)
        # -------------------------------------------------------------------
        buyer_last_offer   = client_state["latest_offer"]
        seller_offer_terms = buyer_last_offer.get("terms", {})

        seller_decision = get_validated_decision(
            seller_llm, seller_skill,
            offer_terms=seller_offer_terms,
            my_history=seller_history,
        )

        if seller_decision is None or seller_decision["action"] == "withdraw":
            print(f"\n✓ Exchange {exchange}: Seller withdrew — no deal.")
            break

        if seller_decision["action"] == "reject":
            print(f"\n✓ Exchange {exchange}: Seller rejected — no deal.")
            break

        if seller_decision["action"] == "accept":
            # Seller accepts buyer's current offer (unusual path — buyer opened aggressively)
            val = seller_offer_terms.get("total_value", 0)
            print(f"\n✓ Exchange {exchange}: Seller accepts buyer's ${val // 100:,} — deal!")
            mcp_srv._sessions[session_id]["status"] = "COMPLETED"
            break

        # Seller sends counteroffer — build and inject into both the server
        # session manager and the MCP client state
        seller_terms = build_terms_from_decision(
            seller_decision, seller_skill, seller_offer_terms
        )

        # next_seq: client_state["sequence_number"] was last incremented by
        # the buyer's most recent send_offer; seller's reply is always +1
        next_seq = client_state["sequence_number"] + 1

        seller_co = _build_seller_counteroffer(
            session_id=session_id,
            round_number=next_seq,      # round == seq (saas_renewal.py convention)
            sequence_number=next_seq,
            terms=seller_terms,
            in_reply_to=buyer_last_offer["message_id"],
            seller_did=SELLER_DID,
            seller_priv=acme_priv,
        )
        # Update server-side session manager (seller "received" the message)
        manager.process_message(session_obj, seller_co)
        # Update MCP client state so a2cn_accept / a2cn_send_offer see the offer
        mcp_srv.inject_counterparty_offer(session_id, seller_co)

        seller_val = seller_terms["total_value"]
        seller_net = seller_terms["payment_terms"]["net_days"]
        buyer_val  = seller_offer_terms.get("total_value", 0)

        print(
            f"\n✓ Exchange {exchange}: "
            f"Buyer ${buyer_val // 100:,} → "
            f"Seller ${seller_val // 100:,} / net-{seller_net}"
        )
        seller_history.append({"value": seller_val, "net_days": seller_net})

        # -------------------------------------------------------------------
        # Buyer's turn (via MCP tools + MockLLM)
        # -------------------------------------------------------------------
        buyer_decision = get_validated_decision(
            buyer_llm, buyer_skill,
            offer_terms=seller_terms,
            my_history=buyer_history,
        )

        if buyer_decision is None or buyer_decision["action"] == "withdraw":
            print("  [Buyer LLM] Withdrawing — no deal.")
            await mcp_srv.a2cn_reject(session_id)
            break

        if buyer_decision["action"] == "reject":
            print("  [Buyer LLM] Rejecting — no deal.")
            await mcp_srv.a2cn_reject(session_id)
            break

        if buyer_decision["action"] == "accept":
            print(f"  [Buyer LLM] Accepting ${seller_val // 100:,} / net-{seller_net}")

            # Tool 4: a2cn_accept
            accept_result = await mcp_srv.a2cn_accept(session_id)
            if "error" in accept_result:
                print(f"✗ Accept failed: {accept_result}")
            else:
                rec_hash = accept_result.get("record_hash", "")
                print(
                    f"\n✓ Exchange {exchange}: Buyer accepts — "
                    f"deal at ${seller_val // 100:,} / net-{seller_net}"
                )
                print(f"✓ Transaction record_hash: {rec_hash[:32]}...")
            break

        # Buyer sends counteroffer via MCP tool (Tool 3: a2cn_send_offer)
        new_val = buyer_decision["total_value_cents"]
        new_net = buyer_decision["net_days"]
        print(f"  [Buyer LLM] Counter: ${new_val // 100:,} / net-{new_net}")

        # Tool 3: a2cn_send_offer
        co_result = await mcp_srv.a2cn_send_offer(
            session_id=session_id,
            total_value_cents=new_val,
            payment_terms_net_days=new_net,
        )
        if "error" in co_result:
            print(f"✗ Send offer failed: {co_result}")
            break

        buyer_history.append({"value": new_val, "net_days": new_net})
        exchange += 1

    # -----------------------------------------------------------------------
    # 6. Final session status (Tool 6: a2cn_get_session_status)
    # -----------------------------------------------------------------------
    final = await mcp_srv.a2cn_get_session_status(session_id)
    print()
    print(f"✓ Final session state: {final['status']}")
    if final.get("transaction_record"):
        tr = final["transaction_record"]
        print(f"✓ Record ID:   {tr.get('record_id', '')}")
        print(f"  Record hash: {tr.get('record_hash', '')[:32]}...")
    print(f"✓ A2CN MCP agent demo complete")


if __name__ == "__main__":
    asyncio.run(main())
