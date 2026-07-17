/** Tests for Component 8: Session Invitation (v0.2.0) */

import { describe, expect, test } from "vitest";
import type { KeyObject } from "node:crypto";

import { InvitationStore } from "../src/a2cn/invitation.js";
import {
  generateKeypair,
  generateEd25519Keypair,
  verifyInvitationSignature,
} from "../src/a2cn/crypto.js";
import { InvitationStatus, SessionInvitation, InvitationAcceptance } from "../src/a2cn/messages.js";
import type { Dict } from "../src/a2cn/messages.js";

/** All-fields serialization, mirror of Python's dataclasses.asdict. */
function asDict(obj: SessionInvitation | InvitationAcceptance): Dict {
  return { ...obj } as unknown as Dict;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function makeStoreWithInvitation(
  expiresHours = 24,
): [InvitationStore, SessionInvitation, KeyObject, KeyObject] {
  const store = new InvitationStore();
  const { privateKey, publicKey } = generateKeypair();
  const invitation = store.createInvitation({
    inviterDid: "did:web:buyer.example",
    inviterEndpoint: "https://buyer.example/a2cn",
    inviterDiscoveryUrl: "https://buyer.example/.well-known/a2cn-agent",
    inviterVerificationMethod: "did:web:buyer.example#key-1",
    privateKey,
    proposedDealType: "goods_procurement",
    proposedSessionParams: {
      currency: "USD",
      max_rounds: 5,
      session_timeout_seconds: 86400,
      round_timeout_seconds: 3600,
    },
    proposedTermsSummary: {
      description: "Hydraulic fluid drums",
      estimated_value: 1800000,
      currency: "USD",
    },
    inviterMandateSummary: {
      mandate_type: "declared",
      max_commitment_value: 2500000,
      authorized_deal_types: ["goods_procurement"],
    },
    expiresHours,
  });
  return [store, invitation, privateKey, publicKey];
}

// ---------------------------------------------------------------------------
// TestInvitationCreation
// ---------------------------------------------------------------------------

describe("InvitationCreation", () => {
  test("create invitation has correct fields", () => {
    const [, invitation] = makeStoreWithInvitation();
    expect(invitation.message_type).toBe("session_invitation");
    expect(invitation.a2cn_version).toBe("0.2");
    expect(invitation.proposed_deal_type).toBe("goods_procurement");
    expect(invitation.inviter_did).toBe("did:web:buyer.example");
    expect(invitation.accept_endpoint).toContain("accept");
    expect(invitation.decline_endpoint).toContain("decline");
    expect(invitation.invitation_id).not.toBe("");
  });

  test("create invitation is signed", () => {
    const [, invitation] = makeStoreWithInvitation();
    expect(invitation.invitation_signature).not.toBe("");
  });

  test("invitation signature verifies", () => {
    const [, invitation, , publicKey] = makeStoreWithInvitation();
    const invDict = asDict(invitation);
    expect(verifyInvitationSignature(invDict, publicKey)).toBe(true);
  });

  test("ed25519 invitation signature verifies", () => {
    const store = new InvitationStore();
    const { privateKey, publicKey } = generateEd25519Keypair();
    const invitation = store.createInvitation({
      inviterDid: "did:web:buyer.example",
      inviterEndpoint: "https://buyer.example/a2cn",
      inviterDiscoveryUrl: "https://buyer.example/.well-known/a2cn-agent",
      inviterVerificationMethod: "did:web:buyer.example#ed25519-1",
      privateKey,
      proposedDealType: "goods_procurement",
      proposedSessionParams: {
        currency: "USD",
        max_rounds: 5,
        session_timeout_seconds: 86400,
        round_timeout_seconds: 3600,
      },
      proposedTermsSummary: {
        description: "Hydraulic fluid drums",
        estimated_value: 1800000,
        currency: "USD",
      },
      inviterMandateSummary: {
        mandate_type: "declared",
        max_commitment_value: 2500000,
        authorized_deal_types: ["goods_procurement"],
      },
    });

    expect(verifyInvitationSignature(asDict(invitation), publicKey)).toBe(true);
  });

  test("tampered invitation fails verification", () => {
    const [, invitation, , publicKey] = makeStoreWithInvitation();
    const invDict = asDict(invitation);
    invDict.proposed_deal_type = "saas_renewal"; // tamper
    expect(verifyInvitationSignature(invDict, publicKey)).toBe(false);
  });

  test("invitation stored as pending", () => {
    const [store, invitation] = makeStoreWithInvitation();
    const entry = store.getInvitation(invitation.invitation_id);
    expect(entry).not.toBeNull();
    expect(entry!.status).toBe(InvitationStatus.PENDING);
  });

  test("get nonexistent invitation returns null", () => {
    const store = new InvitationStore();
    expect(store.getInvitation("no-such-id")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// TestInvitationAcceptance
// ---------------------------------------------------------------------------

describe("InvitationAcceptance", () => {
  test("accept pending invitation", () => {
    const [store, invitation] = makeStoreWithInvitation();
    const { privateKey: acceptorPriv } = generateKeypair();
    const acceptance = store.acceptInvitation({
      invitationId: invitation.invitation_id,
      acceptorDid: "did:web:supplier.example",
      acceptorA2cnEndpoint: "https://supplier.example/a2cn",
      acceptorDiscoveryUrl: "https://supplier.example/.well-known/a2cn-agent",
      acceptorVerificationMethod: "did:web:supplier.example#key-1",
      privateKey: acceptorPriv,
    });
    expect(acceptance.message_type).toBe("invitation_acceptance");
    expect(acceptance.invitation_id).toBe(invitation.invitation_id);
    const entry = store.getInvitation(invitation.invitation_id);
    expect(entry!.status).toBe(InvitationStatus.ACCEPTED);
  });

  test("accept expired invitation raises", () => {
    const [store, invitation] = makeStoreWithInvitation(-1);
    const { privateKey: acceptorPriv } = generateKeypair();
    expect(() =>
      store.acceptInvitation({
        invitationId: invitation.invitation_id,
        acceptorDid: "did:web:supplier.example",
        acceptorA2cnEndpoint: "https://supplier.example/a2cn",
        acceptorDiscoveryUrl: "https://supplier.example/.well-known/a2cn-agent",
        acceptorVerificationMethod: "did:web:supplier.example#key-1",
        privateKey: acceptorPriv,
      }),
    ).toThrow("INVITATION_EXPIRED");
  });

  test("accept already accepted raises", () => {
    const [store, invitation] = makeStoreWithInvitation();
    const { privateKey: acceptorPriv } = generateKeypair();
    store.acceptInvitation({
      invitationId: invitation.invitation_id,
      acceptorDid: "did:web:supplier.example",
      acceptorA2cnEndpoint: "https://supplier.example/a2cn",
      acceptorDiscoveryUrl: "https://supplier.example/.well-known/a2cn-agent",
      acceptorVerificationMethod: "did:web:supplier.example#key-1",
      privateKey: acceptorPriv,
    });
    expect(() =>
      store.acceptInvitation({
        invitationId: invitation.invitation_id,
        acceptorDid: "did:web:supplier.example",
        acceptorA2cnEndpoint: "https://supplier.example/a2cn",
        acceptorDiscoveryUrl: "https://supplier.example/.well-known/a2cn-agent",
        acceptorVerificationMethod: "did:web:supplier.example#key-1",
        privateKey: acceptorPriv,
      }),
    ).toThrow("INVITATION_ALREADY_ANSWERED");
  });

  test("acceptance is signed", () => {
    const [store, invitation] = makeStoreWithInvitation();
    const { privateKey: acceptorPriv, publicKey: acceptorPub } = generateKeypair();
    const acceptance = store.acceptInvitation({
      invitationId: invitation.invitation_id,
      acceptorDid: "did:web:supplier.example",
      acceptorA2cnEndpoint: "https://supplier.example/a2cn",
      acceptorDiscoveryUrl: "https://supplier.example/.well-known/a2cn-agent",
      acceptorVerificationMethod: "did:web:supplier.example#key-1",
      privateKey: acceptorPriv,
    });
    expect(acceptance.acceptance_signature).not.toBe("");
    expect(verifyInvitationSignature(asDict(acceptance), acceptorPub)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// TestInvitationDecline
// ---------------------------------------------------------------------------

describe("InvitationDecline", () => {
  test("decline pending invitation", () => {
    const [store, invitation] = makeStoreWithInvitation();
    const decline = store.declineInvitation(
      invitation.invitation_id,
      "CAPACITY",
      "At capacity until next quarter",
    );
    expect(decline.message_type).toBe("invitation_decline");
    expect(decline.reason_code).toBe("CAPACITY");
    const entry = store.getInvitation(invitation.invitation_id);
    expect(entry!.status).toBe(InvitationStatus.DECLINED);
  });

  test("decline accepted invitation raises", () => {
    const [store, invitation] = makeStoreWithInvitation();
    const { privateKey: acceptorPriv } = generateKeypair();
    store.acceptInvitation({
      invitationId: invitation.invitation_id,
      acceptorDid: "did:web:supplier.example",
      acceptorA2cnEndpoint: "https://supplier.example/a2cn",
      acceptorDiscoveryUrl: "https://supplier.example/.well-known/a2cn-agent",
      acceptorVerificationMethod: "did:web:supplier.example#key-1",
      privateKey: acceptorPriv,
    });
    expect(() => store.declineInvitation(invitation.invitation_id, "OTHER")).toThrow(
      "INVITATION_ALREADY_ANSWERED",
    );
  });

  test("decline not found raises", () => {
    const store = new InvitationStore();
    expect(() => store.declineInvitation("no-such-id", "OTHER")).toThrow("INVITATION_NOT_FOUND");
  });
});

// ---------------------------------------------------------------------------
// TestInvitationExpiry
// ---------------------------------------------------------------------------

describe("InvitationExpiry", () => {
  test("expire pending returns count", () => {
    const store = new InvitationStore();
    const { privateKey } = generateKeypair();
    for (let i = 0; i < 3; i++) {
      store.createInvitation({
        inviterDid: "did:web:buyer.example",
        inviterEndpoint: "https://buyer.example/a2cn",
        inviterDiscoveryUrl: "https://buyer.example/.well-known/a2cn-agent",
        inviterVerificationMethod: "did:web:buyer.example#key-1",
        privateKey,
        proposedDealType: "goods_procurement",
        proposedSessionParams: {
          currency: "USD",
          max_rounds: 3,
          session_timeout_seconds: 3600,
          round_timeout_seconds: 900,
        },
        proposedTermsSummary: { description: "test", estimated_value: 0, currency: "USD" },
        inviterMandateSummary: {},
        expiresHours: -1, // already expired
      });
    }
    const count = store.expirePending();
    expect(count).toBe(3);
  });

  test("expire pending leaves accepted alone", () => {
    const [store, invitation] = makeStoreWithInvitation();
    const { privateKey: acceptorPriv } = generateKeypair();
    store.acceptInvitation({
      invitationId: invitation.invitation_id,
      acceptorDid: "did:web:supplier.example",
      acceptorA2cnEndpoint: "https://supplier.example/a2cn",
      acceptorDiscoveryUrl: "https://supplier.example/.well-known/a2cn-agent",
      acceptorVerificationMethod: "did:web:supplier.example#key-1",
      privateKey: acceptorPriv,
    });
    // Force expiry time to be in the past for the entry
    const entry = store.getInvitation(invitation.invitation_id);
    entry!.invitation.invitation_expires_at = "2020-01-01T00:00:00Z";

    const count = store.expirePending();
    expect(count).toBe(0); // ACCEPTED — not touched
    expect(entry!.status).toBe(InvitationStatus.ACCEPTED);
  });
});
