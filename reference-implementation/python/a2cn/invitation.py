"""
A2CN Session Invitation management (Component 8, v0.2.0 spec).

Handles the lifecycle of SessionInvitation objects:
creation, storage, acceptance, and decline.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone, timedelta

from a2cn.messages import (
    INVITATION_ALREADY_ANSWERED,
    INVITATION_EXPIRED,
    INVITATION_ID_CONFLICT,
    PROTOCOL_ACT_VERSION,
    SessionInvitation,
    InvitationAcceptance,
    InvitationDecline,
    InvitationStatus,
)
from a2cn.crypto import hash_object, sign_invitation


class InvitationStore:
    """In-memory invitation store. Replace with persistent store for production."""

    def __init__(self) -> None:
        # invitation_id -> {invitation: dict, status: InvitationStatus, created_at: str, answered_at: str|None}
        self._invitations: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def create_invitation(
        self,
        inviter_did: str,
        inviter_endpoint: str,
        inviter_discovery_url: str,
        inviter_verification_method: str,
        private_key,
        proposed_deal_type: str,
        proposed_session_params: dict,
        proposed_terms_summary: dict,
        inviter_mandate_summary: dict,
        expires_hours: int = 24,
        base_url: str = "http://localhost:8000",
    ) -> SessionInvitation:
        """
        Create and sign a new SessionInvitation.
        Stores internally with status PENDING.
        Returns the signed invitation.
        """
        invitation_id = str(uuid.uuid4())
        expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=expires_hours)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        invitation = SessionInvitation(
            message_type="session_invitation",
            invitation_id=invitation_id,
            a2cn_version=PROTOCOL_ACT_VERSION,
            inviter_did=inviter_did,
            inviter_endpoint=inviter_endpoint,
            inviter_discovery_url=inviter_discovery_url,
            proposed_deal_type=proposed_deal_type,
            proposed_session_params=proposed_session_params,
            proposed_terms_summary=proposed_terms_summary,
            inviter_mandate_summary=inviter_mandate_summary,
            invitation_expires_at=expires_at,
            accept_endpoint=f"{base_url}/invitations/{invitation_id}/accept",
            decline_endpoint=f"{base_url}/invitations/{invitation_id}/decline",
            inviter_verification_method=inviter_verification_method,
        )

        invitation_dict = asdict(invitation)
        sig = sign_invitation(invitation_dict, private_key)
        invitation.invitation_signature = sig

        self._invitations[invitation_id] = {
            "invitation": asdict(invitation),
            "status": InvitationStatus.PENDING,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "answered_at": None,
        }
        return invitation

    def store_inbound(self, invitation_dict: dict) -> None:
        """
        Store an inbound invitation received from a counterparty.
        Status starts as PENDING. Used by POST /invitations endpoint.

        An invitation_id already stored is never replaced (Section 11.7). A
        different invitation under that id raises INVITATION_ID_CONFLICT,
        whatever the stored status. The identical signed invitation re-sent is
        answered as the first delivery was while it is pending, and raises
        INVITATION_ALREADY_ANSWERED or INVITATION_EXPIRED once it is answered
        or expired. Re-delivery never changes the stored entry.
        """
        invitation_id = invitation_dict["invitation_id"]
        stored = self._invitations.get(invitation_id)
        if stored is not None:
            self._check_retransmission(stored, invitation_dict)
            return
        self._invitations[invitation_id] = {
            "invitation": invitation_dict,
            "status": InvitationStatus.PENDING,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "answered_at": None,
        }

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get_invitation(self, invitation_id: str) -> dict | None:
        """Returns stored entry dict or None."""
        return self._invitations.get(invitation_id)

    # ------------------------------------------------------------------
    # Acceptance / Decline
    # ------------------------------------------------------------------

    def accept_invitation(
        self,
        invitation_id: str,
        acceptor_did: str,
        acceptor_a2cn_endpoint: str,
        acceptor_discovery_url: str,
        acceptor_verification_method: str,
        private_key,
    ) -> InvitationAcceptance:
        """
        Accept an invitation. Validates status and expiry.
        Signs the acceptance. Updates stored status to ACCEPTED.
        Returns signed InvitationAcceptance.

        Raises ValueError with error code string on failure.
        """
        stored = self._validate_answerable(invitation_id)

        accepted_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        acceptance = InvitationAcceptance(
            message_type="invitation_acceptance",
            invitation_id=invitation_id,
            acceptor_did=acceptor_did,
            acceptor_a2cn_endpoint=acceptor_a2cn_endpoint,
            acceptor_discovery_url=acceptor_discovery_url,
            accepted_at=accepted_at,
            acceptor_verification_method=acceptor_verification_method,
        )

        acceptance_dict = asdict(acceptance)
        sig = sign_invitation(acceptance_dict, private_key)
        acceptance.acceptance_signature = sig

        stored["status"] = InvitationStatus.ACCEPTED
        stored["answered_at"] = accepted_at
        return acceptance

    def decline_invitation(
        self,
        invitation_id: str,
        reason_code: str,
        reason_message: str = "",
    ) -> InvitationDecline:
        """
        Decline an invitation. Validates status and expiry.
        Updates stored status to DECLINED.
        Returns InvitationDecline.

        Raises ValueError with error code string on failure.
        """
        stored = self._validate_answerable(invitation_id)
        declined_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        decline = InvitationDecline(
            message_type="invitation_decline",
            invitation_id=invitation_id,
            reason_code=reason_code,
            declined_at=declined_at,
            reason_message=reason_message,
        )
        stored["status"] = InvitationStatus.DECLINED
        stored["answered_at"] = declined_at
        return decline

    # ------------------------------------------------------------------
    # Expiry sweep
    # ------------------------------------------------------------------

    def expire_pending(self) -> int:
        """Expire all PENDING invitations past their expiry time. Returns count expired."""
        count = 0
        for entry in self._invitations.values():
            if entry["status"] == InvitationStatus.PENDING and _past_expiry(entry["invitation"]):
                entry["status"] = InvitationStatus.EXPIRED
                count += 1
        return count

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _check_retransmission(stored: dict, invitation_dict: dict) -> None:
        """
        Refuse an inbound invitation whose id is already stored, unless it is
        an identical retransmission of a pending one. Never changes `stored`.
        """
        # Identical means the same RFC 8785 bytes, signature included, so the
        # same inviter re-sending the same signed invitation. Anything else is
        # a conflict whatever the stored status.
        if hash_object(invitation_dict) != hash_object(stored["invitation"]):
            raise ValueError(INVITATION_ID_CONFLICT)
        if stored["status"] in (InvitationStatus.ACCEPTED, InvitationStatus.DECLINED):
            raise ValueError(INVITATION_ALREADY_ANSWERED)
        if stored["status"] == InvitationStatus.EXPIRED or _past_expiry(stored["invitation"]):
            raise ValueError(INVITATION_EXPIRED)

    def _validate_answerable(self, invitation_id: str) -> dict:
        """
        Validates invitation exists, is PENDING, and is not expired.
        Returns stored entry. Raises ValueError with error code on failure.
        """
        stored = self._invitations.get(invitation_id)
        if not stored:
            raise ValueError("INVITATION_NOT_FOUND")
        if stored["status"] in (InvitationStatus.ACCEPTED, InvitationStatus.DECLINED):
            raise ValueError("INVITATION_ALREADY_ANSWERED")
        if stored["status"] == InvitationStatus.EXPIRED:
            raise ValueError("INVITATION_EXPIRED")
        # Check actual expiry even if not yet swept
        if _past_expiry(stored["invitation"]):
            stored["status"] = InvitationStatus.EXPIRED
            raise ValueError("INVITATION_EXPIRED")
        return stored


# RFC 3339 date-time with an explicit offset (Section 5.6): the schema's
# `date-time`. ASCII digits only, a `T` separator, and `Z` or `+hh:mm`/`-hh:mm`.
_RFC3339_DATE_TIME = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]+))?(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))"
)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _expiry_ms(value: object) -> int | None:
    """
    invitation_expires_at as milliseconds since the epoch, or None when it is
    not an RFC 3339 date-time with an explicit offset. Fractions beyond the
    millisecond are dropped, as the TypeScript implementation drops them.
    """
    if not isinstance(value, str):
        return None
    match = _RFC3339_DATE_TIME.fullmatch(value)
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(g) for g in match.group(1, 2, 3, 4, 5, 6))
    if year < 1 or hour > 23 or minute > 59 or second > 59:
        return None
    if match.group(8):
        offset_minutes = 0
    else:
        offset_hours, offset_mins = int(match.group(10)), int(match.group(11))
        if offset_hours > 23 or offset_mins > 59:
            return None
        offset_minutes = (offset_hours * 60 + offset_mins) * (1 if match.group(9) == "+" else -1)
    try:
        moment = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None  # a day the month does not have
    millis = int((match.group(7) or "").ljust(3, "0")[:3])
    return (moment - _EPOCH) // timedelta(milliseconds=1) + millis - offset_minutes * 60_000


def _past_expiry(invitation: dict) -> bool:
    """
    Whether invitation_expires_at has passed. A value that is missing, empty or
    not an RFC 3339 date-time with an explicit offset counts as passed: an
    expiry that cannot be read fails closed, the same in both implementations.
    """
    expires_ms = _expiry_ms(invitation.get("invitation_expires_at"))
    return expires_ms is None or _now_ms() > expires_ms
