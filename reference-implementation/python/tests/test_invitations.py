"""Tests for Component 8: Session Invitation (v0.2.0)"""

from __future__ import annotations

import pytest
from dataclasses import asdict
from datetime import datetime, timezone, timedelta

from a2cn.invitation import InvitationStore
from a2cn.crypto import generate_keypair, verify_invitation_signature
from a2cn.messages import InvitationStatus


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_store_with_invitation(expires_hours: int = 24):
    store = InvitationStore()
    priv, pub = generate_keypair()
    invitation = store.create_invitation(
        inviter_did="did:web:buyer.example",
        inviter_endpoint="https://buyer.example/a2cn",
        inviter_discovery_url="https://buyer.example/.well-known/a2cn-agent",
        inviter_verification_method="did:web:buyer.example#key-1",
        private_key=priv,
        proposed_deal_type="goods_procurement",
        proposed_session_params={
            "currency": "USD",
            "max_rounds": 5,
            "session_timeout_seconds": 86400,
            "round_timeout_seconds": 3600,
        },
        proposed_terms_summary={
            "description": "Hydraulic fluid drums",
            "estimated_value": 1800000,
            "currency": "USD",
        },
        inviter_mandate_summary={
            "mandate_type": "declared",
            "max_commitment_value": 2500000,
            "authorized_deal_types": ["goods_procurement"],
        },
        expires_hours=expires_hours,
    )
    return store, invitation, priv, pub


# ---------------------------------------------------------------------------
# TestInvitationCreation
# ---------------------------------------------------------------------------

class TestInvitationCreation:
    def test_create_invitation_has_correct_fields(self):
        store, invitation, _, _ = _make_store_with_invitation()
        assert invitation.message_type == "session_invitation"
        assert invitation.a2cn_version == "0.2"
        assert invitation.proposed_deal_type == "goods_procurement"
        assert invitation.inviter_did == "did:web:buyer.example"
        assert "accept" in invitation.accept_endpoint
        assert "decline" in invitation.decline_endpoint
        assert invitation.invitation_id != ""

    def test_create_invitation_is_signed(self):
        _, invitation, _, _ = _make_store_with_invitation()
        assert invitation.invitation_signature != ""

    def test_invitation_signature_verifies(self):
        _, invitation, priv, pub = _make_store_with_invitation()
        inv_dict = asdict(invitation)
        assert verify_invitation_signature(inv_dict, pub) is True

    def test_tampered_invitation_fails_verification(self):
        _, invitation, priv, pub = _make_store_with_invitation()
        inv_dict = asdict(invitation)
        inv_dict["proposed_deal_type"] = "saas_renewal"  # tamper
        assert verify_invitation_signature(inv_dict, pub) is False

    def test_invitation_stored_as_pending(self):
        store, invitation, _, _ = _make_store_with_invitation()
        entry = store.get_invitation(invitation.invitation_id)
        assert entry is not None
        assert entry["status"] == InvitationStatus.PENDING

    def test_get_nonexistent_invitation_returns_none(self):
        store = InvitationStore()
        assert store.get_invitation("no-such-id") is None


# ---------------------------------------------------------------------------
# TestInvitationAcceptance
# ---------------------------------------------------------------------------

class TestInvitationAcceptance:
    def test_accept_pending_invitation(self):
        store, invitation, priv, _ = _make_store_with_invitation()
        acceptor_priv, _ = generate_keypair()
        acceptance = store.accept_invitation(
            invitation_id=invitation.invitation_id,
            acceptor_did="did:web:supplier.example",
            acceptor_a2cn_endpoint="https://supplier.example/a2cn",
            acceptor_discovery_url="https://supplier.example/.well-known/a2cn-agent",
            acceptor_verification_method="did:web:supplier.example#key-1",
            private_key=acceptor_priv,
        )
        assert acceptance.message_type == "invitation_acceptance"
        assert acceptance.invitation_id == invitation.invitation_id
        entry = store.get_invitation(invitation.invitation_id)
        assert entry["status"] == InvitationStatus.ACCEPTED

    def test_accept_expired_invitation_raises(self):
        store, invitation, _, _ = _make_store_with_invitation(expires_hours=-1)
        acceptor_priv, _ = generate_keypair()
        with pytest.raises(ValueError) as exc_info:
            store.accept_invitation(
                invitation_id=invitation.invitation_id,
                acceptor_did="did:web:supplier.example",
                acceptor_a2cn_endpoint="https://supplier.example/a2cn",
                acceptor_discovery_url="https://supplier.example/.well-known/a2cn-agent",
                acceptor_verification_method="did:web:supplier.example#key-1",
                private_key=acceptor_priv,
            )
        assert str(exc_info.value) == "INVITATION_EXPIRED"

    def test_accept_already_accepted_raises(self):
        store, invitation, _, _ = _make_store_with_invitation()
        acceptor_priv, _ = generate_keypair()
        store.accept_invitation(
            invitation_id=invitation.invitation_id,
            acceptor_did="did:web:supplier.example",
            acceptor_a2cn_endpoint="https://supplier.example/a2cn",
            acceptor_discovery_url="https://supplier.example/.well-known/a2cn-agent",
            acceptor_verification_method="did:web:supplier.example#key-1",
            private_key=acceptor_priv,
        )
        with pytest.raises(ValueError) as exc_info:
            store.accept_invitation(
                invitation_id=invitation.invitation_id,
                acceptor_did="did:web:supplier.example",
                acceptor_a2cn_endpoint="https://supplier.example/a2cn",
                acceptor_discovery_url="https://supplier.example/.well-known/a2cn-agent",
                acceptor_verification_method="did:web:supplier.example#key-1",
                private_key=acceptor_priv,
            )
        assert str(exc_info.value) == "INVITATION_ALREADY_ANSWERED"

    def test_acceptance_is_signed(self):
        store, invitation, _, _ = _make_store_with_invitation()
        acceptor_priv, acceptor_pub = generate_keypair()
        acceptance = store.accept_invitation(
            invitation_id=invitation.invitation_id,
            acceptor_did="did:web:supplier.example",
            acceptor_a2cn_endpoint="https://supplier.example/a2cn",
            acceptor_discovery_url="https://supplier.example/.well-known/a2cn-agent",
            acceptor_verification_method="did:web:supplier.example#key-1",
            private_key=acceptor_priv,
        )
        assert acceptance.acceptance_signature != ""
        assert verify_invitation_signature(asdict(acceptance), acceptor_pub) is True


# ---------------------------------------------------------------------------
# TestInvitationDecline
# ---------------------------------------------------------------------------

class TestInvitationDecline:
    def test_decline_pending_invitation(self):
        store, invitation, _, _ = _make_store_with_invitation()
        decline = store.decline_invitation(
            invitation_id=invitation.invitation_id,
            reason_code="CAPACITY",
            reason_message="At capacity until next quarter",
        )
        assert decline.message_type == "invitation_decline"
        assert decline.reason_code == "CAPACITY"
        entry = store.get_invitation(invitation.invitation_id)
        assert entry["status"] == InvitationStatus.DECLINED

    def test_decline_accepted_invitation_raises(self):
        store, invitation, _, _ = _make_store_with_invitation()
        acceptor_priv, _ = generate_keypair()
        store.accept_invitation(
            invitation_id=invitation.invitation_id,
            acceptor_did="did:web:supplier.example",
            acceptor_a2cn_endpoint="https://supplier.example/a2cn",
            acceptor_discovery_url="https://supplier.example/.well-known/a2cn-agent",
            acceptor_verification_method="did:web:supplier.example#key-1",
            private_key=acceptor_priv,
        )
        with pytest.raises(ValueError) as exc_info:
            store.decline_invitation(invitation.invitation_id, "OTHER")
        assert str(exc_info.value) == "INVITATION_ALREADY_ANSWERED"

    def test_decline_not_found_raises(self):
        store = InvitationStore()
        with pytest.raises(ValueError) as exc_info:
            store.decline_invitation("no-such-id", "OTHER")
        assert str(exc_info.value) == "INVITATION_NOT_FOUND"


# ---------------------------------------------------------------------------
# TestInvitationExpiry
# ---------------------------------------------------------------------------

class TestInvitationExpiry:
    def test_expire_pending_returns_count(self):
        store = InvitationStore()
        priv, _ = generate_keypair()
        for _ in range(3):
            store.create_invitation(
                inviter_did="did:web:buyer.example",
                inviter_endpoint="https://buyer.example/a2cn",
                inviter_discovery_url="https://buyer.example/.well-known/a2cn-agent",
                inviter_verification_method="did:web:buyer.example#key-1",
                private_key=priv,
                proposed_deal_type="goods_procurement",
                proposed_session_params={"currency": "USD", "max_rounds": 3,
                                         "session_timeout_seconds": 3600,
                                         "round_timeout_seconds": 900},
                proposed_terms_summary={"description": "test", "estimated_value": 0, "currency": "USD"},
                inviter_mandate_summary={},
                expires_hours=-1,  # already expired
            )
        count = store.expire_pending()
        assert count == 3

    def test_expire_pending_leaves_accepted_alone(self):
        store, invitation, _, _ = _make_store_with_invitation()
        acceptor_priv, _ = generate_keypair()
        store.accept_invitation(
            invitation_id=invitation.invitation_id,
            acceptor_did="did:web:supplier.example",
            acceptor_a2cn_endpoint="https://supplier.example/a2cn",
            acceptor_discovery_url="https://supplier.example/.well-known/a2cn-agent",
            acceptor_verification_method="did:web:supplier.example#key-1",
            private_key=acceptor_priv,
        )
        # Force expiry time to be in the past for the entry
        entry = store.get_invitation(invitation.invitation_id)
        entry["invitation"]["invitation_expires_at"] = "2020-01-01T00:00:00Z"

        count = store.expire_pending()
        assert count == 0  # ACCEPTED — not touched
        assert entry["status"] == InvitationStatus.ACCEPTED
