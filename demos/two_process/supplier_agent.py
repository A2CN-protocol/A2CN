"""Supplier-side process for the two-process A2CN HTTP demo."""

from __future__ import annotations

import argparse

import httpx
import uvicorn
from fastapi import HTTPException, Request

from demo_shared import (
    BUYER_DID,
    BUYER_KEY_ID,
    SUPPLIER_DID,
    SUPPLIER_KEY_ID,
    SUPPLIER_PORT,
    SUPPLIER_URL,
    FreshJwtAuth,
    buyer_private_key,
    did_document,
    renewal_terms,
    supplier_agent_info,
    supplier_counteroffer,
    supplier_mandate,
    supplier_private_key,
)
from a2cn import server as server_module

app = server_module.app


def configure_supplier() -> None:
    supplier_key = supplier_private_key()
    buyer_key = buyer_private_key()
    server_module.SERVER_DID = SUPPLIER_DID
    server_module.configure_responder(
        {
            "agent_info": supplier_agent_info(),
            "mandate": supplier_mandate(),
            "deal_types": ["saas_renewal"],
            "max_rounds_by_deal_type": {"saas_renewal": 4},
            "private_key": supplier_key,
        }
    )
    server_module.register_did_document(
        BUYER_DID,
        did_document(BUYER_DID, BUYER_KEY_ID, buyer_key),
    )
    server_module.register_did_document(
        SUPPLIER_DID,
        did_document(SUPPLIER_DID, SUPPLIER_KEY_ID, supplier_key),
    )


configure_supplier()


@app.get("/demo/health")
async def demo_health() -> dict:
    return {"status": "ok", "role": "supplier", "did": SUPPLIER_DID}


@app.post("/demo/counteroffer")
async def demo_counteroffer(request: Request) -> dict:
    body = await request.json()
    session_id = body.get("session_id")
    in_reply_to = body.get("in_reply_to")
    terms = body.get("terms")
    if not session_id or not in_reply_to or not isinstance(terms, dict):
        raise HTTPException(status_code=400, detail="session_id, in_reply_to, and terms are required")

    session = server_module.manager.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Unknown session_id {session_id!r}")

    message = supplier_counteroffer(session, terms, in_reply_to)
    supplier_key = supplier_private_key()
    async with httpx.AsyncClient(
        auth=FreshJwtAuth(SUPPLIER_DID, SUPPLIER_DID, supplier_key, SUPPLIER_KEY_ID),
        timeout=10.0,
    ) as http:
        response = await http.post(
            f"{SUPPLIER_URL}/sessions/{session_id}/messages",
            json=message,
            headers={
                "Content-Type": "application/a2cn+json",
                "Idempotency-Key": message["message_id"],
            },
        )
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return {"message": message, "state": response.json()}


@app.get("/demo/record/{session_id}")
async def demo_record(session_id: str) -> dict:
    session = server_module.manager.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Unknown session_id {session_id!r}")
    from a2cn.record import generate_transaction_record

    return generate_transaction_record(session)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the A2CN two-process supplier agent")
    parser.add_argument(
        "--port",
        type=int,
        default=SUPPLIER_PORT,
        help="Port to listen on; must match SUPPLIER_PORT in demo_shared.py",
    )
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
