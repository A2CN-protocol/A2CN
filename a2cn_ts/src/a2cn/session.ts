/**
 * A2CN Session State Machine (Section 8)
 *
 * Maintains the authoritative session state for the responder side.
 * Enforces:
 *   - Turn-taking (Section 3.2)
 *   - Sequence number ordering (Section 7.1)
 *   - State machine transitions (Section 8.3–8.4)
 *   - Idempotency (Section 6.1)
 */

import { hashObject, verifyJws } from "./crypto.js";
import { getPublicKey, getVerificationMethod } from "./did.js";
import type { Dict } from "./messages.js";

// ---------------------------------------------------------------------------
// States (Section 8.2)
// ---------------------------------------------------------------------------

export const SessionState = {
  PENDING: "PENDING",
  ACTIVE: "ACTIVE",
  NEGOTIATING: "NEGOTIATING",
  AWAITING_HUMAN_APPROVAL: "AWAITING_HUMAN_APPROVAL",
  COMPLETED: "COMPLETED",
  REJECTED_FINAL: "REJECTED_FINAL",
  WITHDRAWN: "WITHDRAWN",
  TIMED_OUT: "TIMED_OUT",
  IMPASSE: "IMPASSE", // v0.2.0: consecutive non-moving rounds exceeded threshold
  ERROR: "ERROR",

  TERMINAL: new Set([
    "COMPLETED",
    "REJECTED_FINAL",
    "WITHDRAWN",
    "TIMED_OUT",
    "IMPASSE",
    "ERROR",
  ]),
} as const;

// ---------------------------------------------------------------------------
// Session data container
// ---------------------------------------------------------------------------

export class Session {
  // Identity
  session_id: string;
  protocol_version = "0.2";

  // State machine
  state: string = SessionState.PENDING;
  current_turn = "initiator"; // "initiator" | "responder" | "none"
  terminal_reason: string | null = null;
  terminal_message_id: string | null = null;

  // Counters
  round_number = 0;
  max_rounds = 10;
  sequence_number = 0; // last processed sequence number

  // Offer tracking
  latest_offer_id: string | null = null;
  latest_offer_hash: string | null = null;
  latest_offer_total_value: number | null = null; // for impasse detection / reporting

  // Human approval pause state
  approval_pending_offer_id: string | null = null;
  approval_pending_offer_hash: string | null = null;
  approval_pending_sender_role: string | null = null;
  approval_pending_mandate: Dict | null = null;
  approval_receipt_id: string | null = null;
  approval_receipts: Dict[] = [];

  // v0.2.0: Impasse detection (OQ-005)
  impasse_threshold = 3; // from session_params
  consecutive_non_moving_rounds = 0;
  _impasse_last_total_by_role: Record<string, unknown> = {};
  _impasse_unchanged_roles_this_round: Set<string> = new Set();

  // Timing
  session_created_at = "";
  state_updated_at = "";
  session_timeout_seconds = 3600;

  // Session params (for GET /sessions/{id} response)
  session_params: Dict = {};

  // Party info (from SessionInit / SessionAck)
  initiator_info: Dict = {};
  responder_info: Dict = {};
  initiator_mandate: Dict = {};
  responder_mandate: Dict = {};

  // Message store (idempotency): message_id → response dict
  _processed_messages: Record<string, Dict> = {};

  // Full message history for audit log / transaction record
  _message_log: Dict[] = [];

  // Offer chain (protocol_act_hash values in order, for offer_chain_hash)
  _offer_chain: string[] = [];

  // The accepted offer and acceptance messages (set on COMPLETED)
  _final_offer: Dict | null = null;
  _final_acceptance: Dict | null = null;
  _pending_acceptance: Dict | null = null;

  // The SessionInit message (for audit log / transaction record)
  _session_init: Dict | null = null;
  _session_ack: Dict | null = null;

  constructor(props: { session_id: string } & Partial<Session>) {
    this.session_id = props.session_id;
    Object.assign(this, props);
  }

  isTerminal(): boolean {
    return SessionState.TERMINAL.has(this.state);
  }

  /** Canonical response for GET /sessions/{session_id} (Section 8.1). */
  toStateDict(): Dict {
    return {
      session_id: this.session_id,
      protocol_version: this.protocol_version,
      state: this.state,
      current_turn: this.current_turn,
      round_number: this.round_number,
      max_rounds: this.max_rounds,
      sequence_number: this.sequence_number,
      latest_offer_id: this.latest_offer_id,
      latest_offer_hash: this.latest_offer_hash,
      approval_pending_offer_id: this.approval_pending_offer_id,
      approval_pending_offer_hash: this.approval_pending_offer_hash,
      approval_receipt_id: this.approval_receipt_id,
      terminal_reason: this.terminal_reason,
      terminal_message_id: this.terminal_message_id,
      session_created_at: this.session_created_at,
      state_updated_at: this.state_updated_at,
      session_params: this.session_params,
    };
  }
}

// ---------------------------------------------------------------------------
// Session manager / state machine
// ---------------------------------------------------------------------------

const VALID_MESSAGE_TYPES = new Set([
  "offer",
  "counteroffer",
  "acceptance",
  "rejection",
  "withdrawal",
]);

/** In-memory store + state machine for all sessions. */
export class SessionManager {
  _sessions: Record<string, Session> = {};
  // Pre-session idempotency: message_id → response dict
  _init_responses: Record<string, Dict> = {};
  _did_documents: Record<string, Dict> = {};

  /** Register a resolved DID document for protocol-act signature checks. */
  registerDidDocument(did: string, didDocument: Dict): void {
    this._did_documents[did] = didDocument;
  }

  // ------------------------------------------------------------------
  // Session creation (on SessionInit)
  // ------------------------------------------------------------------

  hasInitResponse(messageId: string): boolean {
    return messageId in this._init_responses;
  }

  getInitResponse(messageId: string): Dict {
    return this._init_responses[messageId];
  }

  storeInitResponse(messageId: string, response: Dict): void {
    this._init_responses[messageId] = response;
  }

  createSession(sessionId: string, sessionInit: Dict, sessionAck: Dict, now: string): Session {
    // Read accepted params — the responder may have reduced max_rounds (Section 6.4.1)
    const accepted = (sessionAck.session_params_accepted ??
      (sessionInit.session_params as Dict) ??
      {}) as Dict;
    const session = new Session({
      session_id: sessionId,
      state: SessionState.ACTIVE,
      current_turn: "initiator",
      max_rounds: (accepted.max_rounds as number) ?? 10,
      session_timeout_seconds: (accepted.session_timeout_seconds as number) ?? 3600,
      impasse_threshold: (accepted.impasse_threshold as number) ?? 3,
      session_created_at: now,
      state_updated_at: now,
      session_params: accepted,
      initiator_info: (sessionInit.initiator as Dict) ?? {},
      responder_info: (sessionAck.responder as Dict) ?? {},
      initiator_mandate: (sessionInit.initiator_mandate as Dict) ?? {},
      responder_mandate: (sessionAck.responder_mandate as Dict) ?? {},
    });
    session._session_init = sessionInit;
    session._session_ack = sessionAck;
    this._sessions[sessionId] = session;
    return session;
  }

  getSession(sessionId: string): Session | null {
    return this._sessions[sessionId] ?? null;
  }

  // ------------------------------------------------------------------
  // Message processing — the state machine
  // ------------------------------------------------------------------

  /** Basic type and field validation before any state-machine logic (finding 4.1). */
  private validateMessage(session: Session, message: Dict): void {
    const messageId = message.message_id as string | undefined;
    const messageType = (message.message_type as string) ?? "";

    if (!VALID_MESSAGE_TYPES.has(messageType)) {
      throw new A2CNError("WRONG_MESSAGE_TYPE", `Invalid message_type: ${JSON.stringify(messageType)}`, 422, {
        sessionId: session.session_id,
        messageId,
      });
    }

    const senderDid = (message.sender_did as string) ?? "";
    if (typeof senderDid !== "string" || !senderDid.startsWith("did:")) {
      throw new A2CNError(
        "INVALID_REQUEST",
        `sender_did must be a non-empty DID string, got ${JSON.stringify(senderDid)}`,
        400,
        { sessionId: session.session_id, messageId },
      );
    }

    // sequence_number and round_number are required on offer-type messages
    if (["offer", "counteroffer", "acceptance", "rejection"].includes(messageType)) {
      const seq = message.sequence_number;
      if (typeof seq !== "number" || !Number.isInteger(seq) || seq < 1) {
        throw new A2CNError(
          "INVALID_REQUEST",
          `sequence_number must be a positive integer, got ${JSON.stringify(seq)}`,
          400,
          { sessionId: session.session_id, messageId },
        );
      }
      const rnd = message.round_number;
      if (typeof rnd !== "number" || !Number.isInteger(rnd) || rnd < 1) {
        throw new A2CNError(
          "INVALID_REQUEST",
          `round_number must be a positive integer, got ${JSON.stringify(rnd)}`,
          400,
          { sessionId: session.session_id, messageId },
        );
      }
    }
  }

  /**
   * Apply a message to the session state machine.
   *
   * Returns the response dict to send back.
   * Throws A2CNError on protocol violations.
   */
  processMessage(session: Session, message: Dict): Dict {
    const messageId = (message.message_id as string) ?? "";
    const messageType = (message.message_type as string) ?? "";

    // Idempotency check (before validation — a retransmission should always succeed)
    if (messageId in session._processed_messages) {
      return session._processed_messages[messageId];
    }

    // Input validation (finding 4.1)
    this.validateMessage(session, message);

    // Session timeout check (finding 2.9)
    if (session.session_created_at) {
      const createdMs = parseIsoMs(session.session_created_at);
      if (!Number.isNaN(createdMs)) {
        const elapsed = (Date.now() - createdMs) / 1000;
        if (elapsed > session.session_timeout_seconds) {
          session.state = SessionState.TIMED_OUT;
          session.current_turn = "none";
          session.terminal_reason = "session_timeout";
          session.state_updated_at = now();
          throw new A2CNError("SESSION_WRONG_STATE", "Session has timed out", 409, {
            sessionId: session.session_id,
            messageId,
          });
        }
      }
    }

    // Terminal state check
    if (session.isTerminal()) {
      throw new A2CNError(
        "SESSION_WRONG_STATE",
        `Session is in terminal state ${session.state}`,
        409,
        { sessionId: session.session_id, messageId },
      );
    }

    let response: Dict;
    // Withdrawal is always allowed regardless of turn (Section 3.2)
    if (messageType === "withdrawal") {
      response = this.handleWithdrawal(session, message);
    } else if (session.state === SessionState.AWAITING_HUMAN_APPROVAL) {
      throw new A2CNError("SESSION_WRONG_STATE", "Session is awaiting human approval", 409, {
        sessionId: session.session_id,
        messageId,
      });
    } else if (messageType === "offer" || messageType === "counteroffer") {
      response = this.handleOffer(session, message);
    } else if (messageType === "acceptance") {
      response = this.handleAcceptance(session, message);
    } else if (messageType === "rejection") {
      response = this.handleRejection(session, message);
    } else {
      throw new A2CNError("WRONG_MESSAGE_TYPE", `Unknown message type: ${JSON.stringify(messageType)}`, 422, {
        sessionId: session.session_id,
        messageId,
      });
    }

    session._processed_messages[messageId] = response;
    return response;
  }

  /** Enforce strict sequence number ordering (Section 7.1). */
  private checkSequence(session: Session, message: Dict): void {
    const seq = message.sequence_number as number | undefined;
    if (seq === undefined || seq === null) {
      throw new A2CNError("SEQUENCE_ERROR", "Missing sequence_number", 422, {
        sessionId: session.session_id,
        messageId: message.message_id as string | undefined,
      });
    }
    const expected = session.sequence_number + 1;
    if (seq !== expected) {
      throw new A2CNError(
        "SEQUENCE_ERROR",
        `Expected sequence_number ${expected}, got ${seq}`,
        422,
        { sessionId: session.session_id, messageId: message.message_id as string | undefined },
      );
    }
  }

  /** Enforce turn-taking (Section 3.2). */
  private checkTurn(session: Session, senderRole: string, message: Dict): void {
    if (session.current_turn !== senderRole) {
      throw new A2CNError(
        "NOT_YOUR_TURN",
        `It is ${session.current_turn}'s turn, not ${senderRole}'s`,
        409,
        { sessionId: session.session_id, messageId: message.message_id as string | undefined },
      );
    }
  }

  /** Return 'initiator' or 'responder' based on sender DID. */
  private senderRole(session: Session, senderDid: string): string {
    if (senderDid === session.initiator_info.did) {
      return "initiator";
    }
    if (senderDid === session.responder_info.did) {
      return "responder";
    }
    throw new A2CNError(
      "UNAUTHORIZED_SENDER",
      `Sender DID ${JSON.stringify(senderDid)} is not a party to this session`,
      403,
      { sessionId: session.session_id },
    );
  }

  private verifySenderSignature(
    session: Session,
    message: Dict,
    payloadHash: string,
    signatureField: string,
  ): void {
    const senderDid = (message.sender_did as string) ?? "";
    const messageId = message.message_id as string | undefined;
    const verificationMethod = (message.sender_verification_method as string) ?? "";
    const signature = (message[signatureField] as string) ?? "";

    if (!verificationMethod || !signature) {
      throw new A2CNError(
        "INVALID_SIGNATURE",
        `Missing sender_verification_method or ${signatureField}`,
        400,
        { sessionId: session.session_id, messageId },
      );
    }
    if (!(verificationMethod === senderDid || verificationMethod.startsWith(`${senderDid}#`))) {
      throw new A2CNError(
        "INVALID_SIGNATURE",
        "sender_verification_method is not controlled by sender_did",
        400,
        { sessionId: session.session_id, messageId },
      );
    }

    const didDocument = this._did_documents[senderDid];
    if (didDocument === undefined) {
      throw new A2CNError(
        "INVALID_SIGNATURE",
        `No DID document registered for sender ${JSON.stringify(senderDid)}`,
        400,
        { sessionId: session.session_id, messageId },
      );
    }

    let signedPayloadHash: string;
    try {
      const vm = getVerificationMethod(didDocument, verificationMethod);
      const publicKey = getPublicKey(vm);
      signedPayloadHash = verifyJws(signature, publicKey);
    } catch (exc) {
      throw new A2CNError("INVALID_SIGNATURE", `${signatureField} verification failed`, 400, {
        detail: String(exc instanceof Error ? exc.message : exc),
        sessionId: session.session_id,
        messageId,
      });
    }

    if (signedPayloadHash !== payloadHash) {
      throw new A2CNError(
        "INVALID_SIGNATURE",
        `${signatureField} payload does not match message fields`,
        400,
        { sessionId: session.session_id, messageId },
      );
    }
  }

  private handleOffer(session: Session, message: Dict): Dict {
    const messageId = (message.message_id as string) ?? "";
    const messageType = (message.message_type as string) ?? "";
    const senderDid = (message.sender_did as string) ?? "";
    const roundNumber = message.round_number as number;
    const sequenceNumber = message.sequence_number as number;

    const senderRole = this.senderRole(session, senderDid);

    // Turn check
    this.checkTurn(session, senderRole, message);

    // Sequence check
    this.checkSequence(session, message);

    // Protocol act hash verification (finding 4.3)
    const claimedHash = message.protocol_act_hash as string | undefined;
    if (!claimedHash) {
      throw new A2CNError("INVALID_SIGNATURE", "Missing protocol_act_hash", 400, {
        sessionId: session.session_id,
        messageId,
      });
    }
    const terms = (message.terms as Dict) ?? {};
    const timestamp = (message.timestamp as string) ?? "";
    const expiresAt = (message.expires_at as string) ?? "";
    const protocolAct = {
      protocol_version: "0.2", // Section 7.3.1
      session_id: (message.session_id as string) ?? "",
      round_number: message.round_number,
      sequence_number: message.sequence_number,
      message_type: messageType,
      sender_did: senderDid,
      timestamp,
      expires_at: expiresAt,
      terms,
    };
    const expectedHash = hashObject(protocolAct);
    if (claimedHash !== expectedHash) {
      throw new A2CNError("INVALID_SIGNATURE", "Protocol act hash does not match message fields", 400, {
        sessionId: session.session_id,
        messageId,
      });
    }
    this.verifySenderSignature(session, message, expectedHash, "protocol_act_signature");
    this.enforceMaxCommitment(session, senderRole, terms, message);

    // Message type check: round 1 must be "offer", round 2+ must be "counteroffer"
    if (roundNumber === 1) {
      if (messageType !== "offer") {
        throw new A2CNError("WRONG_MESSAGE_TYPE", "Round 1 message must have message_type 'offer'", 422, {
          sessionId: session.session_id,
          messageId,
        });
      }
      // Transition ACTIVE → NEGOTIATING
      if (session.state !== SessionState.ACTIVE) {
        throw new A2CNError(
          "SESSION_WRONG_STATE",
          `Cannot send round-1 offer in state ${session.state}`,
          409,
          { sessionId: session.session_id, messageId },
        );
      }
    } else {
      if (messageType !== "counteroffer") {
        throw new A2CNError(
          "WRONG_MESSAGE_TYPE",
          `Round ${roundNumber} message must have message_type 'counteroffer'`,
          422,
          { sessionId: session.session_id, messageId },
        );
      }
      // Round number must advance by 1
      if (roundNumber !== session.round_number + 1) {
        throw new A2CNError(
          "SESSION_WRONG_STATE",
          `Expected round_number ${session.round_number + 1}, got ${roundNumber}`,
          422,
          { sessionId: session.session_id, messageId },
        );
      }
      if (roundNumber > session.max_rounds) {
        throw new A2CNError(
          "ROUND_LIMIT_EXCEEDED",
          `round_number ${roundNumber} exceeds max_rounds ${session.max_rounds}`,
          422,
          { sessionId: session.session_id, messageId },
        );
      }
    }

    // Update session state
    const nowTs = now();
    const newTotalValue = ((message.terms as Dict) ?? {}).total_value as number | undefined;
    session.sequence_number = sequenceNumber;
    session.round_number = roundNumber;
    session.latest_offer_id = messageId;
    session.latest_offer_hash = (message.protocol_act_hash as string) ?? null;
    session.state = SessionState.NEGOTIATING;
    session.state_updated_at = nowTs;

    if (
      newTotalValue !== undefined &&
      newTotalValue !== null &&
      recordImpasseProgress(session, senderRole, newTotalValue)
    ) {
      session.state = SessionState.IMPASSE;
      session.current_turn = "none";
      session.terminal_reason = "impasse";
      session.terminal_message_id = messageId;
      session.state_updated_at = nowTs;
      if (message.protocol_act_hash) {
        session._offer_chain.push(message.protocol_act_hash as string);
      }
      session._message_log.push(message);
      session.latest_offer_total_value = newTotalValue;
      return session.toStateDict();
    }

    session.latest_offer_total_value = newTotalValue ?? null;

    // Flip turn to the other party
    session.current_turn = senderRole === "initiator" ? "responder" : "initiator";

    // Track offer chain
    if (message.protocol_act_hash) {
      session._offer_chain.push(message.protocol_act_hash as string);
    }

    // Log the message
    session._message_log.push(message);

    if (this.requiresHumanApproval(session, senderRole, newTotalValue ?? null)) {
      // The offer has been received and logged, but the sender's turn remains
      // blocked until the approval receipt is bound to this offer hash.
      this.enterHumanApprovalPause(session, senderRole, messageId, (message.protocol_act_hash as string) ?? null);
    }

    return session.toStateDict();
  }

  /** Validate an ApprovalReceipt and release an approval pause. */
  applyApprovalReceipt(session: Session, receipt: Dict): Dict {
    if (session.state !== SessionState.AWAITING_HUMAN_APPROVAL) {
      throw new A2CNError("NOT_IN_AWAITING_HUMAN_APPROVAL", "Session is not awaiting human approval", 409, {
        sessionId: session.session_id,
      });
    }

    const receiptId = (receipt.id ?? receipt.approval_receipt_id) as string | undefined;
    const scope = (receipt.scope as Dict) ?? {};
    const decision = scope.decision ?? receipt.decision;
    if (decision !== "approve") {
      throw new A2CNError("APPROVAL_RECEIPT_INVALID", "ApprovalReceipt decision must be 'approve'", 400, {
        sessionId: session.session_id,
      });
    }

    const offerHash = scope.offer_hash ?? receipt.offer_hash;
    if (offerHash !== session.approval_pending_offer_hash) {
      throw new A2CNError(
        "OFFER_HASH_MISMATCH",
        "ApprovalReceipt offer_hash does not match the paused offer",
        400,
        { sessionId: session.session_id },
      );
    }

    if (!receiptReferencesSession(receipt, session.session_id)) {
      throw new A2CNError(
        "APPROVAL_RECEIPT_INVALID",
        "ApprovalReceipt must reference this A2CN session",
        400,
        { sessionId: session.session_id },
      );
    }

    const expiresAt = receipt.expires_at as string | undefined;
    if (expiresAt) {
      const expiryMs = parseIsoMs(expiresAt);
      if (Number.isNaN(expiryMs)) {
        throw new A2CNError(
          "APPROVAL_RECEIPT_INVALID",
          "ApprovalReceipt expires_at is not a valid ISO timestamp",
          400,
          { sessionId: session.session_id },
        );
      }
      if (Date.now() > expiryMs) {
        throw new A2CNError("APPROVAL_RECEIPT_EXPIRED", "ApprovalReceipt has expired", 422, {
          sessionId: session.session_id,
        });
      }
    }

    const approverDid = (receipt.approver_did ?? receipt.operator_did ?? receipt.signed_by) as
      | string
      | undefined;
    if (!isAuthorizedApprover(session.approval_pending_mandate ?? {}, approverDid)) {
      throw new A2CNError(
        "UNAUTHORIZED_APPROVER",
        "ApprovalReceipt signer is not authorized by the mandate",
        403,
        { sessionId: session.session_id },
      );
    }

    session.approval_receipt_id = receiptId ?? null;
    session.approval_receipts.push(receipt);
    if (session._pending_acceptance !== null) {
      const pending = session._pending_acceptance;
      const finalOffer =
        [...session._message_log]
          .reverse()
          .find((m) => m.message_id === pending.accepted_offer_id) ?? null;
      session.state = SessionState.COMPLETED;
      session.current_turn = "none";
      session.terminal_reason = "acceptance";
      session.terminal_message_id = (pending.message_id as string) ?? null;
      session._final_offer = finalOffer;
      session._final_acceptance = pending;
      session._message_log.push(pending);
      session._pending_acceptance = null;
      this.clearHumanApprovalPause(session);
      session.state_updated_at = now();
      return session.toStateDict();
    }

    session.state = SessionState.NEGOTIATING;
    session.current_turn =
      session.approval_pending_sender_role === "initiator" ? "responder" : "initiator";
    this.clearHumanApprovalPause(session);
    session.state_updated_at = now();
    return session.toStateDict();
  }

  private enterHumanApprovalPause(
    session: Session,
    senderRole: string,
    offerId: string | null,
    offerHash: string | null,
  ): void {
    session.state = SessionState.AWAITING_HUMAN_APPROVAL;
    session.current_turn = senderRole;
    session.approval_pending_offer_id = offerId;
    session.approval_pending_offer_hash = offerHash;
    session.approval_pending_sender_role = senderRole;
    session.approval_pending_mandate = this.mandateForRole(session, senderRole);
  }

  private clearHumanApprovalPause(session: Session): void {
    session.approval_pending_offer_id = null;
    session.approval_pending_offer_hash = null;
    session.approval_pending_sender_role = null;
    session.approval_pending_mandate = null;
  }

  private mandateForRole(session: Session, role: string): Dict {
    return role === "initiator" ? session.initiator_mandate : session.responder_mandate;
  }

  private requiresHumanApproval(
    session: Session,
    senderRole: string,
    totalValue: number | null,
  ): boolean {
    if (totalValue === null || totalValue === undefined) {
      return false;
    }
    const mandate = this.mandateForRole(session, senderRole);
    const threshold = mandate.requires_human_approval_above;
    if (threshold === null || threshold === undefined) {
      return false;
    }
    const total = toInt(totalValue);
    const limit = toInt(threshold);
    if (total === null || limit === null) {
      return false;
    }
    return total > limit;
  }

  /** Enforce a declared mandate's hard commitment cap before state mutation. */
  private enforceMaxCommitment(session: Session, role: string, terms: Dict, message: Dict): void {
    const mandate = this.mandateForRole(session, role);
    const maxValue = mandate.max_commitment_value;
    if (maxValue === null || maxValue === undefined) {
      return;
    }

    const totalValue =
      terms !== null && typeof terms === "object" ? (terms as Dict).total_value : null;
    if (totalValue === null || totalValue === undefined) {
      return;
    }

    const expectedCurrency = mandate.max_commitment_currency;
    const actualCurrency =
      terms !== null && typeof terms === "object" ? (terms as Dict).currency : null;
    if (expectedCurrency && actualCurrency !== expectedCurrency) {
      throw new A2CNError(
        "MANDATE_INVALID",
        `Commitment currency ${JSON.stringify(actualCurrency)} does not match ${role} ` +
          `mandate currency ${JSON.stringify(expectedCurrency)}`,
        403,
        { sessionId: session.session_id, messageId: message.message_id as string | undefined },
      );
    }

    const total = toInt(totalValue);
    const cap = toInt(maxValue);
    if (total === null || cap === null) {
      throw new A2CNError(
        "MANDATE_INVALID",
        "Commitment total_value or mandate max_commitment_value is not an integer",
        403,
        { sessionId: session.session_id, messageId: message.message_id as string | undefined },
      );
    }

    if (total > cap) {
      throw new A2CNError(
        "MANDATE_INVALID",
        `Commitment total_value ${total} exceeds ${role} mandate max_commitment_value ${cap}`,
        403,
        { sessionId: session.session_id, messageId: message.message_id as string | undefined },
      );
    }
  }

  private handleAcceptance(session: Session, message: Dict): Dict {
    const messageId = (message.message_id as string) ?? "";
    const senderDid = (message.sender_did as string) ?? "";
    const sequenceNumber = message.sequence_number as number;
    const acceptedOfferId = message.accepted_offer_id as string | undefined;
    const acceptedHash = message.accepted_protocol_act_hash as string | undefined;

    // State guard: acceptance only valid in NEGOTIATING (finding 2.8)
    if (session.state !== SessionState.NEGOTIATING) {
      throw new A2CNError("SESSION_WRONG_STATE", `Acceptance not valid in state ${session.state}`, 409, {
        sessionId: session.session_id,
        messageId,
      });
    }

    const senderRole = this.senderRole(session, senderDid);

    // Turn check
    this.checkTurn(session, senderRole, message);

    // Sequence check
    this.checkSequence(session, message);

    const acceptancePayload = {
      session_id: (message.session_id as string) ?? "",
      round_number: message.round_number,
      sequence_number: message.sequence_number,
      accepted_offer_id: acceptedOfferId,
      accepted_protocol_act_hash: acceptedHash,
    };
    this.verifySenderSignature(session, message, hashObject(acceptancePayload), "acceptance_signature");

    // Offer hash match
    if (acceptedOfferId !== session.latest_offer_id) {
      throw new A2CNError(
        "OFFER_HASH_MISMATCH",
        `accepted_offer_id ${JSON.stringify(acceptedOfferId)} does not match latest offer ${JSON.stringify(session.latest_offer_id)}`,
        400,
        { sessionId: session.session_id, messageId },
      );
    }
    if (acceptedHash !== session.latest_offer_hash) {
      throw new A2CNError(
        "OFFER_HASH_MISMATCH",
        "accepted_protocol_act_hash does not match the latest offer's protocol_act_hash",
        400,
        { sessionId: session.session_id, messageId },
      );
    }

    // Find the final offer from message log
    const finalOffer =
      [...session._message_log].reverse().find((m) => m.message_id === acceptedOfferId) ?? null;

    // Offer expiry check (finding 4.2)
    if (finalOffer) {
      const expiresAtStr = finalOffer.expires_at as string | undefined;
      if (expiresAtStr) {
        const expiresMs = parseIsoMs(expiresAtStr);
        if (!Number.isNaN(expiresMs) && Date.now() > expiresMs) {
          throw new A2CNError("OFFER_EXPIRED", `Offer ${JSON.stringify(acceptedOfferId)} has expired`, 422, {
            sessionId: session.session_id,
            messageId,
          });
        }
      }
    }

    const nowTs = now();
    let finalOfferTotalValue: number | null = null;
    let finalOfferTerms: Dict = {};
    if (finalOffer) {
      finalOfferTerms = (finalOffer.terms as Dict) ?? {};
      finalOfferTotalValue = (finalOfferTerms.total_value as number | undefined) ?? null;
    }

    this.enforceMaxCommitment(session, senderRole, finalOfferTerms, message);

    if (this.requiresHumanApproval(session, senderRole, finalOfferTotalValue)) {
      session.sequence_number = sequenceNumber;
      session._pending_acceptance = message;
      session.state_updated_at = nowTs;
      this.enterHumanApprovalPause(session, senderRole, acceptedOfferId ?? null, acceptedHash ?? null);
      return session.toStateDict();
    }

    session.sequence_number = sequenceNumber;
    session.state = SessionState.COMPLETED;
    session.current_turn = "none";
    session.terminal_reason = "acceptance";
    session.terminal_message_id = messageId;
    session.state_updated_at = nowTs;

    session._final_offer = finalOffer;
    session._final_acceptance = message;
    session._message_log.push(message);

    return session.toStateDict();
  }

  private handleRejection(session: Session, message: Dict): Dict {
    const messageId = (message.message_id as string) ?? "";
    const senderDid = (message.sender_did as string) ?? "";
    const sequenceNumber = message.sequence_number as number;

    // State guard: rejection only valid in NEGOTIATING (finding 2.8)
    if (session.state !== SessionState.NEGOTIATING) {
      throw new A2CNError("SESSION_WRONG_STATE", `Rejection not valid in state ${session.state}`, 409, {
        sessionId: session.session_id,
        messageId,
      });
    }

    const senderRole = this.senderRole(session, senderDid);

    // Turn check
    this.checkTurn(session, senderRole, message);

    // Sequence check
    this.checkSequence(session, message);

    const nowTs = now();
    session.sequence_number = sequenceNumber;

    // After rejection: turn goes to the rejecting party
    session.current_turn = senderRole;

    // Check if max rounds reached (Section 7.5)
    if (session.round_number >= session.max_rounds) {
      session.state = SessionState.REJECTED_FINAL;
      session.current_turn = "none";
      session.terminal_reason = "rejection_max_rounds";
      session.terminal_message_id = messageId;
    } else {
      session.state = SessionState.NEGOTIATING;
    }

    session.state_updated_at = nowTs;
    session._message_log.push(message);

    return session.toStateDict();
  }

  private handleWithdrawal(session: Session, message: Dict): Dict {
    const messageId = (message.message_id as string) ?? "";
    const sequenceNumber = message.sequence_number as number | undefined;

    // Sequence check for withdrawal (if applicable)
    if (sequenceNumber !== undefined && sequenceNumber !== null) {
      this.checkSequence(session, message);
      session.sequence_number = sequenceNumber;
    }

    const nowTs = now();
    session.state = SessionState.WITHDRAWN;
    session.current_turn = "none";
    session.terminal_reason = "withdrawal";
    session.terminal_message_id = messageId;
    session.state_updated_at = nowTs;
    session._message_log.push(message);

    return session.toStateDict();
  }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

// Error codes used in this implementation and their spec references:
//   SESSION_NOT_FOUND       — 404  — spec Section 12.3
//   SESSION_WRONG_STATE     — 409  — spec Section 12.3
//   NOT_YOUR_TURN           — 409  — spec Section 12.3
//   SEQUENCE_ERROR          — 422  — spec Section 12.3
//   OFFER_HASH_MISMATCH     — 400  — spec Section 12.3
//   OFFER_EXPIRED           — 422  — spec Section 12.3
//   ROUND_LIMIT_EXCEEDED    — 422  — spec Section 12.3
//   WRONG_MESSAGE_TYPE      — 422  — spec Section 12.3
//   INVALID_SIGNATURE       — 400  — spec Section 12.3
//   DEAL_TYPE_NOT_SUPPORTED — 403  — spec Section 12.3
//   MANDATE_INVALID         — 403  — spec Section 12.3
//   NOT_IN_AWAITING_HUMAN_APPROVAL — 409 — human approval extension
//   APPROVAL_RECEIPT_INVALID — 400 — human approval extension
//   APPROVAL_RECEIPT_EXPIRED — 422 — human approval extension
//   UNAUTHORIZED_APPROVER   — 403  — human approval extension
//   PROTOCOL_VERSION_MISMATCH — 400 — spec Section 12.3
//   UNAUTHORIZED_SENDER     — 403  — spec Section 12.3
//   INVALID_REQUEST         — 400  — extension (not in spec Section 12.3 table);
//                                     used for malformed input that fails basic
//                                     validation before any protocol logic runs

/** Protocol error with A2CN error code, HTTP status, and context. */
export class A2CNError extends Error {
  code: string;
  httpStatus: number;
  detail: string;
  sessionId: string | null;
  messageId: string | null;

  constructor(
    code: string,
    message: string,
    httpStatus = 400,
    options: { detail?: string; sessionId?: string | null; messageId?: string | null } = {},
  ) {
    super(message);
    this.name = "A2CNError";
    this.code = code;
    this.httpStatus = httpStatus;
    this.detail = options.detail ?? "";
    this.sessionId = options.sessionId ?? null;
    this.messageId = options.messageId ?? null;
  }

  toDict(): Dict {
    return {
      error: {
        code: this.code,
        message: this.message,
        detail: this.detail,
        timestamp: now(),
        session_id: this.sessionId,
        message_id: this.messageId,
      },
    };
  }
}

export function now(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Parse an ISO 8601 timestamp (Z suffix allowed) to epoch ms; NaN if invalid. */
export function parseIsoMs(ts: string): number {
  if (typeof ts !== "string" || ts === "") {
    return NaN;
  }
  return Date.parse(ts.replace("Z", "+00:00"));
}

function toInt(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) {
    return parseInt(value.trim(), 10);
  }
  return null;
}

/**
 * Track spec §8.7 soft-impasse progress.
 *
 * A non-moving full round is complete only after both parties repeat their own
 * previous total_value exactly. Any party changing total_value resets the
 * consecutive count.
 */
function recordImpasseProgress(session: Session, senderRole: string, newTotalValue: unknown): boolean {
  const lastTotal = session._impasse_last_total_by_role[senderRole];
  session._impasse_last_total_by_role[senderRole] = newTotalValue;

  if (lastTotal === undefined || lastTotal === null) {
    session._impasse_unchanged_roles_this_round.delete(senderRole);
    return false;
  }

  if (newTotalValue !== lastTotal) {
    session.consecutive_non_moving_rounds = 0;
    session._impasse_unchanged_roles_this_round.clear();
    return false;
  }

  session._impasse_unchanged_roles_this_round.add(senderRole);
  if (
    session._impasse_unchanged_roles_this_round.has("initiator") &&
    session._impasse_unchanged_roles_this_round.has("responder")
  ) {
    session.consecutive_non_moving_rounds += 1;
    session._impasse_unchanged_roles_this_round.clear();
  }

  return session.consecutive_non_moving_rounds >= session.impasse_threshold;
}

function receiptReferencesSession(receipt: Dict, sessionId: string): boolean {
  const references = receipt.references;
  if (!Array.isArray(references)) {
    return false;
  }
  const acceptedIds = new Set([sessionId, `a2cn:session:${sessionId}`]);
  for (const ref of references) {
    if (ref === null || typeof ref !== "object" || Array.isArray(ref)) {
      continue;
    }
    const r = ref as Dict;
    if (r.type === "negotiation_session" && acceptedIds.has(r.id as string)) {
      return true;
    }
  }
  return false;
}

function isAuthorizedApprover(mandate: Dict, approverDid: string | null | undefined): boolean {
  if (!approverDid) {
    return false;
  }
  const configured = (mandate.approval_operator_dids ??
    mandate.trusted_approver_dids ??
    mandate.human_approver_dids ??
    []) as string[];
  if (Array.isArray(configured) && configured.includes(approverDid)) {
    return true;
  }
  return approverDid === mandate.principal_did;
}
