/**
 * A2CN Session Invitation management (Component 8, v0.2.0 spec).
 *
 * Handles the lifecycle of SessionInvitation objects:
 * creation, storage, acceptance, and decline.
 */

import { randomUUID } from "node:crypto";

import {
  SessionInvitation,
  InvitationAcceptance,
  InvitationDecline,
  InvitationStatus,
  type InvitationStatusValue,
  type Dict,
} from "./messages.js";
import { signInvitation, type SigningPrivateKey } from "./crypto.js";
import { parseIsoMs } from "./session.js";

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Serialize invitation objects with ALL fields (mirror of Python asdict). */
function invitationAsDict(invitation: SessionInvitation): Dict {
  return {
    message_type: invitation.message_type,
    invitation_id: invitation.invitation_id,
    a2cn_version: invitation.a2cn_version,
    inviter_did: invitation.inviter_did,
    inviter_endpoint: invitation.inviter_endpoint,
    inviter_discovery_url: invitation.inviter_discovery_url,
    proposed_deal_type: invitation.proposed_deal_type,
    proposed_session_params: invitation.proposed_session_params,
    proposed_terms_summary: invitation.proposed_terms_summary,
    inviter_mandate_summary: invitation.inviter_mandate_summary,
    invitation_expires_at: invitation.invitation_expires_at,
    accept_endpoint: invitation.accept_endpoint,
    decline_endpoint: invitation.decline_endpoint,
    inviter_verification_method: invitation.inviter_verification_method,
    invitation_signature: invitation.invitation_signature,
  };
}

function acceptanceAsDict(acceptance: InvitationAcceptance): Dict {
  return {
    message_type: acceptance.message_type,
    invitation_id: acceptance.invitation_id,
    acceptor_did: acceptance.acceptor_did,
    acceptor_a2cn_endpoint: acceptance.acceptor_a2cn_endpoint,
    acceptor_discovery_url: acceptance.acceptor_discovery_url,
    accepted_at: acceptance.accepted_at,
    acceptor_verification_method: acceptance.acceptor_verification_method,
    acceptance_signature: acceptance.acceptance_signature,
  };
}

export interface StoredInvitation {
  invitation: Dict;
  status: InvitationStatusValue;
  created_at: string;
  answered_at: string | null;
}

/** In-memory invitation store. Replace with persistent store for production. */
export class InvitationStore {
  // invitation_id -> {invitation: dict, status: InvitationStatus, created_at: str, answered_at: str|null}
  _invitations: Record<string, StoredInvitation> = {};

  // ------------------------------------------------------------------
  // Creation
  // ------------------------------------------------------------------

  /**
   * Create and sign a new SessionInvitation.
   * Stores internally with status PENDING.
   * Returns the signed invitation.
   */
  createInvitation(options: {
    inviterDid: string;
    inviterEndpoint: string;
    inviterDiscoveryUrl: string;
    inviterVerificationMethod: string;
    privateKey: SigningPrivateKey;
    proposedDealType: string;
    proposedSessionParams: Dict;
    proposedTermsSummary: Dict;
    inviterMandateSummary: Dict;
    expiresHours?: number;
    baseUrl?: string;
  }): SessionInvitation {
    const { expiresHours = 24, baseUrl = "http://localhost:8000" } = options;
    const invitationId = randomUUID();
    const expiresAt = new Date(Date.now() + expiresHours * 3600 * 1000)
      .toISOString()
      .replace(/\.\d{3}Z$/, "Z");

    const invitation = new SessionInvitation({
      message_type: "session_invitation",
      invitation_id: invitationId,
      a2cn_version: "0.2",
      inviter_did: options.inviterDid,
      inviter_endpoint: options.inviterEndpoint,
      inviter_discovery_url: options.inviterDiscoveryUrl,
      proposed_deal_type: options.proposedDealType,
      proposed_session_params: options.proposedSessionParams,
      proposed_terms_summary: options.proposedTermsSummary,
      inviter_mandate_summary: options.inviterMandateSummary,
      invitation_expires_at: expiresAt,
      accept_endpoint: `${baseUrl}/invitations/${invitationId}/accept`,
      decline_endpoint: `${baseUrl}/invitations/${invitationId}/decline`,
      inviter_verification_method: options.inviterVerificationMethod,
    });

    const invitationDict = invitationAsDict(invitation);
    const sig = signInvitation(invitationDict, options.privateKey);
    invitation.invitation_signature = sig;

    this._invitations[invitationId] = {
      invitation: invitationAsDict(invitation),
      status: InvitationStatus.PENDING,
      created_at: nowIso(),
      answered_at: null,
    };
    return invitation;
  }

  /**
   * Store an inbound invitation received from a counterparty.
   * Status starts as PENDING. Used by POST /invitations endpoint.
   */
  storeInbound(invitationDict: Dict): void {
    const invitationId = invitationDict.invitation_id as string;
    this._invitations[invitationId] = {
      invitation: invitationDict,
      status: InvitationStatus.PENDING,
      created_at: nowIso(),
      answered_at: null,
    };
  }

  // ------------------------------------------------------------------
  // Retrieval
  // ------------------------------------------------------------------

  /** Returns stored entry dict or null. */
  getInvitation(invitationId: string): StoredInvitation | null {
    return this._invitations[invitationId] ?? null;
  }

  // ------------------------------------------------------------------
  // Acceptance / Decline
  // ------------------------------------------------------------------

  /**
   * Accept an invitation. Validates status and expiry.
   * Signs the acceptance. Updates stored status to ACCEPTED.
   * Returns signed InvitationAcceptance.
   *
   * Throws Error with error code string on failure.
   */
  acceptInvitation(options: {
    invitationId: string;
    acceptorDid: string;
    acceptorA2cnEndpoint: string;
    acceptorDiscoveryUrl: string;
    acceptorVerificationMethod: string;
    privateKey: SigningPrivateKey;
  }): InvitationAcceptance {
    const stored = this.validateAnswerable(options.invitationId);

    const acceptedAt = nowIso();
    const acceptance = new InvitationAcceptance({
      message_type: "invitation_acceptance",
      invitation_id: options.invitationId,
      acceptor_did: options.acceptorDid,
      acceptor_a2cn_endpoint: options.acceptorA2cnEndpoint,
      acceptor_discovery_url: options.acceptorDiscoveryUrl,
      accepted_at: acceptedAt,
      acceptor_verification_method: options.acceptorVerificationMethod,
    });

    const acceptanceDict = acceptanceAsDict(acceptance);
    const sig = signInvitation(acceptanceDict, options.privateKey);
    acceptance.acceptance_signature = sig;

    stored.status = InvitationStatus.ACCEPTED;
    stored.answered_at = acceptedAt;
    return acceptance;
  }

  /**
   * Decline an invitation. Validates status and expiry.
   * Updates stored status to DECLINED.
   * Returns InvitationDecline.
   *
   * Throws Error with error code string on failure.
   */
  declineInvitation(invitationId: string, reasonCode: string, reasonMessage = ""): InvitationDecline {
    const stored = this.validateAnswerable(invitationId);
    const declinedAt = nowIso();

    const decline = new InvitationDecline({
      message_type: "invitation_decline",
      invitation_id: invitationId,
      reason_code: reasonCode,
      declined_at: declinedAt,
      reason_message: reasonMessage,
    });
    stored.status = InvitationStatus.DECLINED;
    stored.answered_at = declinedAt;
    return decline;
  }

  // ------------------------------------------------------------------
  // Expiry sweep
  // ------------------------------------------------------------------

  /** Expire all PENDING invitations past their expiry time. Returns count expired. */
  expirePending(): number {
    const nowMs = Date.now();
    let count = 0;
    for (const entry of Object.values(this._invitations)) {
      if (entry.status === InvitationStatus.PENDING) {
        const expiresStr = (entry.invitation.invitation_expires_at as string) ?? "";
        if (expiresStr) {
          const expiresMs = parseIsoMs(expiresStr);
          if (!Number.isNaN(expiresMs) && nowMs > expiresMs) {
            entry.status = InvitationStatus.EXPIRED;
            count += 1;
          }
        }
      }
    }
    return count;
  }

  // ------------------------------------------------------------------
  // Internal
  // ------------------------------------------------------------------

  /**
   * Validates invitation exists, is PENDING, and is not expired.
   * Returns stored entry. Throws Error with error code on failure.
   */
  private validateAnswerable(invitationId: string): StoredInvitation {
    const stored = this._invitations[invitationId];
    if (!stored) {
      throw new Error("INVITATION_NOT_FOUND");
    }
    if (stored.status === InvitationStatus.ACCEPTED || stored.status === InvitationStatus.DECLINED) {
      throw new Error("INVITATION_ALREADY_ANSWERED");
    }
    if (stored.status === InvitationStatus.EXPIRED) {
      throw new Error("INVITATION_EXPIRED");
    }
    // Check actual expiry even if not yet swept
    const expiresStr = (stored.invitation.invitation_expires_at as string) ?? "";
    if (expiresStr) {
      const expiresMs = parseIsoMs(expiresStr);
      if (!Number.isNaN(expiresMs) && Date.now() > expiresMs) {
        stored.status = InvitationStatus.EXPIRED;
        throw new Error("INVITATION_EXPIRED");
      }
    }
    return stored;
  }
}
