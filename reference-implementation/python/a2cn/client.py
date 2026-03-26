"""
A2CN Initiator Client (Section 3.1, 6, 7)

Implements the buyer-side agent:
  - fetch_discovery
  - initiate_session
  - send_offer
  - send_acceptance
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx

from a2cn.crypto import (
    EllipticCurvePrivateKey,
    hash_object,
    sign_jws,
    create_jwt,
)
from a2cn.record import generate_transaction_record, A2CN_NAMESPACE
from a2cn.session import Session, SessionState

A2CN_CONTENT_TYPE = "application/a2cn+json"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _expires_at(seconds: int) -> str:
    t = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class A2CNClient:
    """
    Buyer-side A2CN client. Holds identity info and a live httpx.AsyncClient.
    """

    def __init__(
        self,
        agent_info: dict,
        private_key: EllipticCurvePrivateKey,
        mandate: dict,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.agent_info = agent_info
        self.private_key = private_key
        self.mandate = mandate
        self._http = http_client or httpx.AsyncClient()

        # Session state maintained by the client
        self._sessions: dict[str, dict] = {}

    async def fetch_discovery(self, base_url: str) -> dict:
        """
        Fetch the discovery document at {base_url}/.well-known/a2cn-agent.
        Section 4.3.
        """
        url = f"{base_url}/.well-known/a2cn-agent"
        response = await self._http.get(url)
        response.raise_for_status()
        return response.json()

    async def initiate_session(
        self,
        endpoint: str,
        responder_did: str,
        session_params: dict,
    ) -> dict:
        """
        Send a SessionInit and return the SessionAck dict.
        Section 6.3.
        """
        message_id = str(uuid.uuid4())

        session_init = {
            "message_type": "session_init",
            "message_id": message_id,
            "protocol_version": "0.1",
            "session_params": session_params,
            "initiator": self.agent_info,
            "initiator_mandate": self.mandate,
        }

        # TODO Week 2: create_jwt with real exp=300
        # jwt_token = create_jwt(self.agent_info["did"], responder_did, self.private_key,
        #                        kid=self.agent_info["verification_method"],
        #                        purpose="a2cn_session_init", exp_seconds=300)
        # headers = {"Authorization": f"Bearer {jwt_token}", ...}

        headers = {
            "Content-Type": A2CN_CONTENT_TYPE,
            "Idempotency-Key": message_id,
        }

        resp = await self._http.post(
            f"{endpoint}/sessions",
            json=session_init,
            headers=headers,
        )
        resp.raise_for_status()
        ack = resp.json()

        # Cache session state
        session_id = ack["session_id"]
        self._sessions[session_id] = {
            "session_init": session_init,
            "session_ack": ack,
            "sequence_number": 0,
            "round_number": 0,
            "current_turn": "initiator",
            "offer_chain": [],
            "message_log": [],
            "latest_offer": None,
        }

        return ack

    async def send_offer(
        self,
        endpoint: str,
        responder_did: str,
        session_id: str,
        terms: dict,
        in_reply_to: str | None = None,
    ) -> dict:
        """
        Construct, sign, and send an Offer or Counteroffer.
        Section 7.1 + 7.3.
        """
        state = self._sessions[session_id]
        state["sequence_number"] += 1
        state["round_number"] += 1

        round_number = state["round_number"]
        sequence_number = state["sequence_number"]
        message_type = "offer" if round_number == 1 else "counteroffer"
        message_id = str(uuid.uuid4())
        timestamp = _now()
        expires_at = _expires_at(state["session_ack"]["session_params_accepted"]["round_timeout_seconds"])

        # Build protocol act object (Section 7.3.1)
        protocol_act = {
            "protocol_version": "0.1",
            "session_id": session_id,
            "round_number": round_number,
            "sequence_number": sequence_number,
            "message_type": message_type,
            "sender_did": self.agent_info["did"],
            "timestamp": timestamp,
            "expires_at": expires_at,
            "terms": terms,
        }

        protocol_act_hash = hash_object(protocol_act)
        protocol_act_signature = sign_jws(
            protocol_act_hash,
            self.private_key,
            kid=self.agent_info["verification_method"],
        )

        offer = {
            "message_type": message_type,
            "message_id": message_id,
            "session_id": session_id,
            "round_number": round_number,
            "sequence_number": sequence_number,
            "sender_did": self.agent_info["did"],
            "sender_agent_id": self.agent_info["agent_id"],
            "sender_verification_method": self.agent_info["verification_method"],
            "timestamp": timestamp,
            "expires_at": expires_at,
            "terms": terms,
            "protocol_act_hash": protocol_act_hash,
            "protocol_act_signature": protocol_act_signature,
        }
        if in_reply_to:
            offer["in_reply_to"] = in_reply_to

        headers = {
            "Content-Type": A2CN_CONTENT_TYPE,
            "Idempotency-Key": message_id,
        }

        resp = await self._http.post(
            f"{endpoint}/sessions/{session_id}/messages",
            json=offer,
            headers=headers,
        )
        resp.raise_for_status()

        state["offer_chain"].append(protocol_act_hash)
        state["message_log"].append(offer)
        state["latest_offer"] = offer

        return resp.json()

    async def send_acceptance(
        self,
        endpoint: str,
        responder_did: str,
        session_id: str,
        offer: dict,
    ) -> dict:
        """
        Sign and send an Acceptance for the given offer dict.
        Section 7.4.
        """
        state = self._sessions[session_id]
        state["sequence_number"] += 1
        sequence_number = state["sequence_number"]
        round_number = state["round_number"]
        message_id = str(uuid.uuid4())
        timestamp = _now()

        accepted_offer_id = offer["message_id"]
        accepted_hash = offer["protocol_act_hash"]

        # Build acceptance payload for signing (Section 7.4)
        acceptance_payload = {
            "session_id": session_id,
            "round_number": round_number,
            "sequence_number": sequence_number,
            "accepted_offer_id": accepted_offer_id,
            "accepted_protocol_act_hash": accepted_hash,
        }

        acceptance_signature = sign_jws(
            hash_object(acceptance_payload),
            self.private_key,
            kid=self.agent_info["verification_method"],
        )

        acceptance = {
            "message_type": "acceptance",
            "message_id": message_id,
            "session_id": session_id,
            "in_reply_to": accepted_offer_id,
            "round_number": round_number,
            "sequence_number": sequence_number,
            "accepted_offer_id": accepted_offer_id,
            "accepted_protocol_act_hash": accepted_hash,
            "sender_did": self.agent_info["did"],
            "sender_agent_id": self.agent_info["agent_id"],
            "sender_verification_method": self.agent_info["verification_method"],
            "timestamp": timestamp,
            "acceptance_signature": acceptance_signature,
        }

        headers = {
            "Content-Type": A2CN_CONTENT_TYPE,
            "Idempotency-Key": message_id,
        }

        resp = await self._http.post(
            f"{endpoint}/sessions/{session_id}/messages",
            json=acceptance,
            headers=headers,
        )
        resp.raise_for_status()
        state["message_log"].append(acceptance)
        return resp.json()

    async def get_session_state(self, endpoint: str, session_id: str) -> dict:
        resp = await self._http.get(f"{endpoint}/sessions/{session_id}")
        resp.raise_for_status()
        return resp.json()

    async def get_transaction_record(self, endpoint: str, session_id: str) -> dict:
        resp = await self._http.get(f"{endpoint}/sessions/{session_id}/record")
        resp.raise_for_status()
        return resp.json()

    def build_client_side_record(self, session_id: str) -> dict:
        """
        Build the transaction record from client-side state.
        Used to assert identical record_hash with the server's record.
        """
        state = self._sessions[session_id]

        # Build a minimal Session-like object for generate_transaction_record
        mock_session = _MockSession(
            session_id=session_id,
            session_init=state["session_init"],
            session_ack=state["session_ack"],
            message_log=state["message_log"],
            offer_chain=state["offer_chain"],
        )
        return generate_transaction_record(mock_session)

    def process_incoming(self, session_id: str, message: dict) -> None:
        """
        Record an incoming message from the counterparty into client-side session state.
        Must be called for every received offer/counteroffer/acceptance so that
        build_client_side_record() produces the correct offer_chain_hash.
        Fix 5.8: replaces manual state patching in examples.
        """
        if message.get("session_id") and message["session_id"] != session_id:
            raise ValueError(
                f"Message session_id mismatch: expected {session_id!r}, "
                f"got {message['session_id']!r}"
            )
        state = self._sessions[session_id]
        msg_type = message.get("message_type", "")

        state["message_log"].append(message)

        if msg_type in ("offer", "counteroffer"):
            pah = message.get("protocol_act_hash")
            if pah:
                state["offer_chain"].append(pah)
            state["sequence_number"] = message.get("sequence_number", state["sequence_number"])
            state["round_number"] = message.get("round_number", state["round_number"])
            state["latest_offer"] = message
            # Flip turn back to initiator after a responder counteroffer
            state["current_turn"] = "initiator"
        elif msg_type == "acceptance":
            state["sequence_number"] = message.get("sequence_number", state["sequence_number"])
            state["current_turn"] = "none"

    async def close(self) -> None:
        await self._http.aclose()


class _MockSession:
    """Minimal Session-like object for client-side record generation."""

    def __init__(
        self,
        session_id: str,
        session_init: dict,
        session_ack: dict,
        message_log: list[dict],
        offer_chain: list[str],
    ) -> None:
        self.session_id = session_id
        self._session_init = session_init
        self._session_ack = session_ack
        self._message_log = message_log
        self._offer_chain = offer_chain
        self.state = SessionState.COMPLETED
        self.session_created_at = session_ack.get("session_created_at", "")

        # Find final offer and acceptance from message log
        acceptance = next(
            (m for m in reversed(message_log) if m.get("message_type") == "acceptance"),
            None,
        )
        accepted_offer_id = acceptance.get("accepted_offer_id") if acceptance else None
        final_offer = next(
            (m for m in message_log if m.get("message_id") == accepted_offer_id),
            None,
        )

        self._final_offer = final_offer
        self._final_acceptance = acceptance
        self.round_number = max(
            (m.get("round_number", 0) for m in message_log if "round_number" in m),
            default=0,
        )

        # Extract party info
        self.initiator_mandate = session_init.get("initiator_mandate", {})
        self.responder_mandate = session_ack.get("responder_mandate", {})
        self.session_params = session_ack.get("session_params_accepted", {})
