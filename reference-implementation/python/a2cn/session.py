"""
A2CN Session State Machine (Section 8)

Maintains the authoritative session state for the responder side.
Enforces:
  - Turn-taking (Section 3.2)
  - Sequence number ordering (Section 7.1)
  - State machine transitions (Section 8.3–8.4)
  - Idempotency (Section 6.1)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from a2cn.crypto import hash_object


# ---------------------------------------------------------------------------
# States (Section 8.2)
# ---------------------------------------------------------------------------

class SessionState:
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    NEGOTIATING = "NEGOTIATING"
    COMPLETED = "COMPLETED"
    REJECTED_FINAL = "REJECTED_FINAL"
    WITHDRAWN = "WITHDRAWN"
    TIMED_OUT = "TIMED_OUT"
    ERROR = "ERROR"

    TERMINAL = {COMPLETED, REJECTED_FINAL, WITHDRAWN, TIMED_OUT, ERROR}


# ---------------------------------------------------------------------------
# Session data container
# ---------------------------------------------------------------------------

@dataclass
class Session:
    # Identity
    session_id: str
    protocol_version: str = "0.1"

    # State machine
    state: str = SessionState.PENDING
    current_turn: str = "initiator"  # "initiator" | "responder" | "none"
    terminal_reason: str | None = None
    terminal_message_id: str | None = None

    # Counters
    round_number: int = 0
    max_rounds: int = 10
    sequence_number: int = 0  # last processed sequence number

    # Offer tracking
    latest_offer_id: str | None = None
    latest_offer_hash: str | None = None

    # Timing
    session_created_at: str = ""
    state_updated_at: str = ""
    session_timeout_seconds: int = 3600

    # Session params (for GET /sessions/{id} response)
    session_params: dict = field(default_factory=dict)

    # Party info (from SessionInit / SessionAck)
    initiator_info: dict = field(default_factory=dict)
    responder_info: dict = field(default_factory=dict)
    initiator_mandate: dict = field(default_factory=dict)
    responder_mandate: dict = field(default_factory=dict)

    # Message store (idempotency): message_id → response dict
    _processed_messages: dict[str, dict] = field(default_factory=dict)

    # Full message history for audit log / transaction record
    _message_log: list[dict] = field(default_factory=list)

    # Offer chain (protocol_act_hash values in order, for offer_chain_hash)
    _offer_chain: list[str] = field(default_factory=list)

    # The accepted offer and acceptance messages (set on COMPLETED)
    _final_offer: dict | None = None
    _final_acceptance: dict | None = None

    # The SessionInit message (for audit log / transaction record)
    _session_init: dict | None = None
    _session_ack: dict | None = None

    def is_terminal(self) -> bool:
        return self.state in SessionState.TERMINAL

    def to_state_dict(self) -> dict:
        """Canonical response for GET /sessions/{session_id} (Section 8.1)."""
        return {
            "session_id": self.session_id,
            "protocol_version": self.protocol_version,
            "state": self.state,
            "current_turn": self.current_turn,
            "round_number": self.round_number,
            "max_rounds": self.max_rounds,
            "sequence_number": self.sequence_number,
            "latest_offer_id": self.latest_offer_id,
            "latest_offer_hash": self.latest_offer_hash,
            "terminal_reason": self.terminal_reason,
            "terminal_message_id": self.terminal_message_id,
            "session_created_at": self.session_created_at,
            "state_updated_at": self.state_updated_at,
            "session_params": self.session_params,
        }


# ---------------------------------------------------------------------------
# Session manager / state machine
# ---------------------------------------------------------------------------

class SessionManager:
    """In-memory store + state machine for all sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        # Pre-session idempotency: message_id → response dict
        self._init_responses: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Session creation (on SessionInit)
    # ------------------------------------------------------------------

    def has_init_response(self, message_id: str) -> bool:
        return message_id in self._init_responses

    def get_init_response(self, message_id: str) -> dict:
        return self._init_responses[message_id]

    def store_init_response(self, message_id: str, response: dict) -> None:
        self._init_responses[message_id] = response

    def create_session(
        self,
        session_id: str,
        session_init: dict,
        session_ack: dict,
        now: str,
    ) -> Session:
        # Read accepted params — the responder may have reduced max_rounds (Section 6.4.1)
        accepted = session_ack.get("session_params_accepted", session_init.get("session_params", {}))
        session = Session(
            session_id=session_id,
            state=SessionState.ACTIVE,
            current_turn="initiator",
            max_rounds=accepted.get("max_rounds", 10),
            session_timeout_seconds=accepted.get("session_timeout_seconds", 3600),
            session_created_at=now,
            state_updated_at=now,
            session_params=accepted,
            initiator_info=session_init.get("initiator", {}),
            responder_info=session_ack.get("responder", {}),
            initiator_mandate=session_init.get("initiator_mandate", {}),
            responder_mandate=session_ack.get("responder_mandate", {}),
        )
        session._session_init = session_init
        session._session_ack = session_ack
        self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    # ------------------------------------------------------------------
    # Message processing — the state machine
    # ------------------------------------------------------------------

    _VALID_MESSAGE_TYPES = frozenset(
        {"offer", "counteroffer", "acceptance", "rejection", "withdrawal"}
    )

    def _validate_message(self, session: Session, message: dict) -> None:
        """Basic type and field validation before any state-machine logic (finding 4.1)."""
        message_id = message.get("message_id")
        message_type = message.get("message_type", "")

        if message_type not in self._VALID_MESSAGE_TYPES:
            raise A2CNError(
                "WRONG_MESSAGE_TYPE",
                f"Invalid message_type: {message_type!r}",
                422,
                session_id=session.session_id,
                message_id=message_id,
            )

        sender_did = message.get("sender_did", "")
        if not isinstance(sender_did, str) or not sender_did.startswith("did:"):
            raise A2CNError(
                "INVALID_REQUEST",
                f"sender_did must be a non-empty DID string, got {sender_did!r}",
                400,
                session_id=session.session_id,
                message_id=message_id,
            )

        # sequence_number and round_number are required on offer-type messages
        if message_type in ("offer", "counteroffer", "acceptance", "rejection"):
            seq = message.get("sequence_number")
            if not isinstance(seq, int) or seq < 1:
                raise A2CNError(
                    "INVALID_REQUEST",
                    f"sequence_number must be a positive integer, got {seq!r}",
                    400,
                    session_id=session.session_id,
                    message_id=message_id,
                )
            rnd = message.get("round_number")
            if not isinstance(rnd, int) or rnd < 1:
                raise A2CNError(
                    "INVALID_REQUEST",
                    f"round_number must be a positive integer, got {rnd!r}",
                    400,
                    session_id=session.session_id,
                    message_id=message_id,
                )

    def process_message(self, session: Session, message: dict) -> dict:
        """
        Apply a message to the session state machine.

        Returns the response dict to send back.
        Raises A2CNError on protocol violations.
        """
        message_id = message.get("message_id", "")
        message_type = message.get("message_type", "")

        # Idempotency check (before validation — a retransmission should always succeed)
        if message_id in session._processed_messages:
            return session._processed_messages[message_id]

        # Input validation (finding 4.1)
        self._validate_message(session, message)

        # Session timeout check (finding 2.9)
        if session.session_created_at:
            try:
                created = datetime.fromisoformat(
                    session.session_created_at.replace("Z", "+00:00")
                )
                elapsed = (datetime.now(timezone.utc) - created).total_seconds()
                if elapsed > session.session_timeout_seconds:
                    session.state = SessionState.TIMED_OUT
                    session.current_turn = "none"
                    session.terminal_reason = "session_timeout"
                    session.state_updated_at = _now()
                    raise A2CNError(
                        "SESSION_WRONG_STATE",
                        "Session has timed out",
                        409,
                        session_id=session.session_id,
                        message_id=message_id,
                    )
            except ValueError:
                pass  # unparseable timestamp — skip timeout check

        # Terminal state check
        if session.is_terminal():
            raise A2CNError(
                "SESSION_WRONG_STATE",
                f"Session is in terminal state {session.state}",
                409,
                session_id=session.session_id,
                message_id=message_id,
            )

        # Withdrawal is always allowed regardless of turn (Section 3.2)
        if message_type == "withdrawal":
            response = self._handle_withdrawal(session, message)
        elif message_type in ("offer", "counteroffer"):
            response = self._handle_offer(session, message)
        elif message_type == "acceptance":
            response = self._handle_acceptance(session, message)
        elif message_type == "rejection":
            response = self._handle_rejection(session, message)
        else:
            raise A2CNError(
                "WRONG_MESSAGE_TYPE",
                f"Unknown message type: {message_type!r}",
                422,
                session_id=session.session_id,
                message_id=message_id,
            )

        session._processed_messages[message_id] = response
        return response

    def _check_sequence(self, session: Session, message: dict) -> None:
        """Enforce strict sequence number ordering (Section 7.1)."""
        seq = message.get("sequence_number")
        if seq is None:
            raise A2CNError(
                "SEQUENCE_ERROR",
                "Missing sequence_number",
                422,
                session_id=session.session_id,
                message_id=message.get("message_id"),
            )
        expected = session.sequence_number + 1
        if seq != expected:
            raise A2CNError(
                "SEQUENCE_ERROR",
                f"Expected sequence_number {expected}, got {seq}",
                422,
                session_id=session.session_id,
                message_id=message.get("message_id"),
            )

    def _check_turn(self, session: Session, sender_role: str, message: dict) -> None:
        """Enforce turn-taking (Section 3.2)."""
        if session.current_turn != sender_role:
            raise A2CNError(
                "NOT_YOUR_TURN",
                f"It is {session.current_turn}'s turn, not {sender_role}'s",
                409,
                session_id=session.session_id,
                message_id=message.get("message_id"),
            )

    def _sender_role(self, session: Session, sender_did: str) -> str:
        """Return 'initiator' or 'responder' based on sender DID."""
        if sender_did == session.initiator_info.get("did"):
            return "initiator"
        if sender_did == session.responder_info.get("did"):
            return "responder"
        raise A2CNError(
            "UNAUTHORIZED_SENDER",
            f"Sender DID {sender_did!r} is not a party to this session",
            403,
            session_id=session.session_id,
        )

    def _handle_offer(self, session: Session, message: dict) -> dict:
        message_id = message.get("message_id", "")
        message_type = message.get("message_type", "")
        sender_did = message.get("sender_did", "")
        round_number = message.get("round_number")
        sequence_number = message.get("sequence_number")

        sender_role = self._sender_role(session, sender_did)

        # Turn check
        self._check_turn(session, sender_role, message)

        # Sequence check
        self._check_sequence(session, message)

        # Protocol act hash verification (finding 4.3)
        claimed_hash = message.get("protocol_act_hash")
        if claimed_hash:
            terms = message.get("terms", {})
            timestamp = message.get("timestamp", "")
            expires_at = message.get("expires_at", "")
            protocol_act = {
                "protocol_version": "0.1",  # Section 7.3.1: always "0.1" for this spec version
                "session_id": message.get("session_id", ""),
                "round_number": message.get("round_number"),
                "sequence_number": message.get("sequence_number"),
                "message_type": message_type,
                "sender_did": sender_did,
                "timestamp": timestamp,
                "expires_at": expires_at,
                "terms": terms,
            }
            expected_hash = hash_object(protocol_act)
            if claimed_hash != expected_hash:
                raise A2CNError(
                    "INVALID_SIGNATURE",
                    "Protocol act hash does not match message fields",
                    400,
                    session_id=session.session_id,
                    message_id=message_id,
                )

        # Message type check: round 1 must be "offer", round 2+ must be "counteroffer"
        if round_number == 1:
            if message_type != "offer":
                raise A2CNError(
                    "WRONG_MESSAGE_TYPE",
                    "Round 1 message must have message_type 'offer'",
                    422,
                    session_id=session.session_id,
                    message_id=message_id,
                )
            # Transition ACTIVE → NEGOTIATING
            if session.state != SessionState.ACTIVE:
                raise A2CNError(
                    "SESSION_WRONG_STATE",
                    f"Cannot send round-1 offer in state {session.state}",
                    409,
                    session_id=session.session_id,
                    message_id=message_id,
                )
        else:
            if message_type != "counteroffer":
                raise A2CNError(
                    "WRONG_MESSAGE_TYPE",
                    f"Round {round_number} message must have message_type 'counteroffer'",
                    422,
                    session_id=session.session_id,
                    message_id=message_id,
                )
            # Round number must advance by 1
            if round_number != session.round_number + 1:
                raise A2CNError(
                    "SESSION_WRONG_STATE",
                    f"Expected round_number {session.round_number + 1}, got {round_number}",
                    422,
                    session_id=session.session_id,
                    message_id=message_id,
                )
            if round_number > session.max_rounds:
                raise A2CNError(
                    "ROUND_LIMIT_EXCEEDED",
                    f"round_number {round_number} exceeds max_rounds {session.max_rounds}",
                    422,
                    session_id=session.session_id,
                    message_id=message_id,
                )

        # Update session state
        now = _now()
        session.sequence_number = sequence_number
        session.round_number = round_number
        session.latest_offer_id = message_id
        session.latest_offer_hash = message.get("protocol_act_hash")
        session.state = SessionState.NEGOTIATING
        session.state_updated_at = now

        # Flip turn to the other party
        session.current_turn = "responder" if sender_role == "initiator" else "initiator"

        # Track offer chain
        if message.get("protocol_act_hash"):
            session._offer_chain.append(message["protocol_act_hash"])

        # Log the message
        session._message_log.append(message)

        return session.to_state_dict()

    def _handle_acceptance(self, session: Session, message: dict) -> dict:
        message_id = message.get("message_id", "")
        sender_did = message.get("sender_did", "")
        sequence_number = message.get("sequence_number")
        accepted_offer_id = message.get("accepted_offer_id")
        accepted_hash = message.get("accepted_protocol_act_hash")

        # State guard: acceptance only valid in NEGOTIATING (finding 2.8)
        if session.state != SessionState.NEGOTIATING:
            raise A2CNError(
                "SESSION_WRONG_STATE",
                f"Acceptance not valid in state {session.state}",
                409,
                session_id=session.session_id,
                message_id=message_id,
            )

        sender_role = self._sender_role(session, sender_did)

        # Turn check
        self._check_turn(session, sender_role, message)

        # Sequence check
        self._check_sequence(session, message)

        # Offer hash match
        if accepted_offer_id != session.latest_offer_id:
            raise A2CNError(
                "OFFER_HASH_MISMATCH",
                f"accepted_offer_id {accepted_offer_id!r} does not match latest offer {session.latest_offer_id!r}",
                400,
                session_id=session.session_id,
                message_id=message_id,
            )
        if accepted_hash != session.latest_offer_hash:
            raise A2CNError(
                "OFFER_HASH_MISMATCH",
                "accepted_protocol_act_hash does not match the latest offer's protocol_act_hash",
                400,
                session_id=session.session_id,
                message_id=message_id,
            )

        # Find the final offer from message log
        final_offer = next(
            (m for m in reversed(session._message_log) if m.get("message_id") == accepted_offer_id),
            None,
        )

        # Offer expiry check (finding 4.2)
        if final_offer:
            expires_at_str = final_offer.get("expires_at")
            if expires_at_str:
                try:
                    expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                    if datetime.now(timezone.utc) > expires_at:
                        raise A2CNError(
                            "OFFER_EXPIRED",
                            f"Offer {accepted_offer_id!r} has expired",
                            422,
                            session_id=session.session_id,
                            message_id=message_id,
                        )
                except ValueError:
                    pass  # unparseable expiry — skip check

        now = _now()
        session.sequence_number = sequence_number
        session.state = SessionState.COMPLETED
        session.current_turn = "none"
        session.terminal_reason = "acceptance"
        session.terminal_message_id = message_id
        session.state_updated_at = now

        session._final_offer = final_offer
        session._final_acceptance = message
        session._message_log.append(message)

        return session.to_state_dict()

    def _handle_rejection(self, session: Session, message: dict) -> dict:
        message_id = message.get("message_id", "")
        sender_did = message.get("sender_did", "")
        round_number = message.get("round_number")
        sequence_number = message.get("sequence_number")

        # State guard: rejection only valid in NEGOTIATING (finding 2.8)
        if session.state != SessionState.NEGOTIATING:
            raise A2CNError(
                "SESSION_WRONG_STATE",
                f"Rejection not valid in state {session.state}",
                409,
                session_id=session.session_id,
                message_id=message_id,
            )

        sender_role = self._sender_role(session, sender_did)

        # Turn check
        self._check_turn(session, sender_role, message)

        # Sequence check
        self._check_sequence(session, message)

        now = _now()
        session.sequence_number = sequence_number

        # After rejection: turn goes to the rejecting party
        session.current_turn = sender_role

        # Check if max rounds reached (Section 7.5)
        if session.round_number >= session.max_rounds:
            session.state = SessionState.REJECTED_FINAL
            session.current_turn = "none"
            session.terminal_reason = "rejection_max_rounds"
            session.terminal_message_id = message_id
        else:
            session.state = SessionState.NEGOTIATING

        session.state_updated_at = now
        session._message_log.append(message)

        return session.to_state_dict()

    def _handle_withdrawal(self, session: Session, message: dict) -> dict:
        message_id = message.get("message_id", "")
        sequence_number = message.get("sequence_number")

        # Sequence check for withdrawal (if applicable)
        if sequence_number is not None:
            self._check_sequence(session, message)
            session.sequence_number = sequence_number

        now = _now()
        session.state = SessionState.WITHDRAWN
        session.current_turn = "none"
        session.terminal_reason = "withdrawal"
        session.terminal_message_id = message_id
        session.state_updated_at = now
        session._message_log.append(message)

        return session.to_state_dict()


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------

# Error codes used in this implementation and their spec references:
#   SESSION_NOT_FOUND       — 404  — spec Section 12.2
#   SESSION_WRONG_STATE     — 409  — spec Section 12.2
#   NOT_YOUR_TURN           — 409  — spec Section 12.2
#   SEQUENCE_ERROR          — 422  — spec Section 12.2
#   OFFER_HASH_MISMATCH     — 400  — spec Section 12.2
#   OFFER_EXPIRED           — 422  — spec Section 12.2
#   ROUND_LIMIT_EXCEEDED    — 422  — spec Section 12.2
#   WRONG_MESSAGE_TYPE      — 422  — spec Section 12.2
#   INVALID_SIGNATURE       — 400  — spec Section 12.2
#   DEAL_TYPE_NOT_SUPPORTED — 403  — spec Section 12.2
#   MANDATE_INVALID         — 403  — spec Section 12.2
#   PROTOCOL_VERSION_MISMATCH — 400 — spec Section 12.2
#   UNAUTHORIZED_SENDER     — 403  — spec Section 12.2
#   INVALID_REQUEST         — 400  — extension (not in spec Section 12.2 table);
#                                     used for malformed input that fails basic
#                                     validation before any protocol logic runs


class A2CNError(Exception):
    """Protocol error with A2CN error code, HTTP status, and context."""

    def __init__(
        self,
        code: str,
        message: str,
        http_status: int = 400,
        detail: str = "",
        session_id: str | None = None,
        message_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.detail = detail
        self.session_id = session_id
        self.message_id = message_id

    def to_dict(self) -> dict:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "detail": self.detail,
                "timestamp": _now(),
                "session_id": self.session_id,
                "message_id": self.message_id,
            }
        }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
