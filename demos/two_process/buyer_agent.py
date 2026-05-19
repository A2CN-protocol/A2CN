"""Buyer-side process for the two-process A2CN HTTP demo."""

from __future__ import annotations

import argparse

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException

from demo_shared import (
    BUYER_DID,
    BUYER_KEY_ID,
    BUYER_PORT,
    SUPPLIER_DID,
    SUPPLIER_URL,
    FreshJwtAuth,
    buyer_agent_info,
    buyer_mandate,
    buyer_private_key,
    renewal_terms,
    session_params,
)
from a2cn.client import A2CNClient

app = FastAPI(title="A2CN Demo Buyer Agent", version="0.2")


@app.get("/demo/health")
async def demo_health() -> dict:
    return {"status": "ok", "role": "buyer", "did": BUYER_DID}


@app.post("/demo/run")
async def run_demo() -> dict:
    try:
        return await run_negotiation()
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text
        raise HTTPException(status_code=exc.response.status_code, detail=detail) from exc


async def run_negotiation() -> dict:
    buyer_key = buyer_private_key()
    transcript: list[dict] = []
    async with httpx.AsyncClient(
        auth=FreshJwtAuth(BUYER_DID, SUPPLIER_DID, buyer_key, BUYER_KEY_ID),
        timeout=10.0,
    ) as http:
        client = A2CNClient(
            agent_info=buyer_agent_info(),
            private_key=buyer_key,
            mandate=buyer_mandate(),
            http_client=http,
        )

        discovery = await client.fetch_discovery(SUPPLIER_URL)
        transcript.append({"step": "discovery", "supplier": discovery})

        ack = await client.initiate_session(
            endpoint=SUPPLIER_URL,
            responder_did=SUPPLIER_DID,
            session_params=session_params(),
        )
        session_id = ack["session_id"]
        transcript.append({"step": "session_ack", "session_id": session_id})

        await client.send_offer(
            SUPPLIER_URL,
            SUPPLIER_DID,
            session_id,
            renewal_terms(9_500_000, 30),
        )
        buyer_offer_1 = client._sessions[session_id]["latest_offer"]
        transcript.append({
            "step": "buyer_offer",
            "amount": "$95,000",
            "message_id": buyer_offer_1["message_id"],
        })

        supplier_r1 = await http.post(
            f"{SUPPLIER_URL}/demo/counteroffer",
            json={
                "session_id": session_id,
                "in_reply_to": buyer_offer_1["message_id"],
                "terms": renewal_terms(11_500_000, 60),
            },
        )
        supplier_r1.raise_for_status()
        supplier_offer_1 = supplier_r1.json()["message"]
        client.process_incoming(session_id, supplier_offer_1)
        transcript.append({
            "step": "supplier_counteroffer",
            "amount": "$115,000",
            "message_id": supplier_offer_1["message_id"],
        })

        await client.send_offer(
            SUPPLIER_URL,
            SUPPLIER_DID,
            session_id,
            renewal_terms(10_300_000, 30),
            in_reply_to=supplier_offer_1["message_id"],
        )
        buyer_offer_2 = client._sessions[session_id]["latest_offer"]
        transcript.append({
            "step": "buyer_counteroffer",
            "amount": "$103,000",
            "message_id": buyer_offer_2["message_id"],
        })

        supplier_r2 = await http.post(
            f"{SUPPLIER_URL}/demo/counteroffer",
            json={
                "session_id": session_id,
                "in_reply_to": buyer_offer_2["message_id"],
                "terms": renewal_terms(10_500_000, 45),
            },
        )
        supplier_r2.raise_for_status()
        supplier_offer_2 = supplier_r2.json()["message"]
        client.process_incoming(session_id, supplier_offer_2)
        transcript.append({
            "step": "supplier_counteroffer",
            "amount": "$105,000 net-45",
            "message_id": supplier_offer_2["message_id"],
        })

        await client.send_acceptance(
            SUPPLIER_URL,
            SUPPLIER_DID,
            session_id,
            supplier_offer_2,
        )
        transcript.append({"step": "buyer_acceptance", "accepted_offer_id": supplier_offer_2["message_id"]})

        supplier_record = await client.get_transaction_record(SUPPLIER_URL, session_id)
        buyer_record = client.build_client_side_record(session_id)

    return {
        "session_id": session_id,
        "transcript": transcript,
        "buyer_record": buyer_record,
        "supplier_record": supplier_record,
        "record_hashes_match": buyer_record["record_hash"] == supplier_record["record_hash"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the A2CN two-process buyer agent")
    parser.add_argument("--port", type=int, default=BUYER_PORT)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
