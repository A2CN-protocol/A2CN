"""
A2CN Session Invitation management (Component 8, v0.2.0 spec).

Handles the lifecycle of SessionInvitation objects:
creation, storage, acceptance, and decline.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict
from datetime import datetime, timezone, timedelta

from a2cn.messages import (
    SessionInvitation,
    InvitationAcceptance,
    InvitationDecline,
    InvitationStatus,
)
from a2cn.crypto import sign_invitation


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
            a2cn_version="0.2",
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
        """
        invitation_id = invitation_dict["invitation_id"]
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
        now = datetime.now(timezone.utc)
        count = 0
        for entry in self._invitations.values():
            if entry["status"] == InvitationStatus.PENDING:
                expires_str = entry["invitation"].get("invitation_expires_at", "")
                if expires_str:
                    try:
                        expires_at = datetime.fromisoformat(
                            expires_str.replace("Z", "+00:00")
                        )
                        if now > expires_at:
                            entry["status"] = InvitationStatus.EXPIRED
                            count += 1
                    except ValueError:
                        pass
        return count

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

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
        expires_str = stored["invitation"].get("invitation_expires_at", "")
        if expires_str:
            try:
                expires_at = datetime.fromisoformat(
                    expires_str.replace("Z", "+00:00")
                )
                if datetime.now(timezone.utc) > expires_at:
                    stored["status"] = InvitationStatus.EXPIRED
                    raise ValueError("INVITATION_EXPIRED")
            except ValueError as exc:
                if str(exc) == "INVITATION_EXPIRED":
                    raise
                pass  # unparseable expiry — skip check
        return stored
