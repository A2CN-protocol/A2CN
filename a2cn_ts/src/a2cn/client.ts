/**
 * A2CN Initiator Client (Section 3.1, 6, 7)
 *
 * Implements the buyer-side agent:
 *   - fetchDiscovery
 *   - initiateSession
 *   - sendOffer
 *   - sendAcceptance
 */

import { randomUUID, type KeyObject } from "node:crypto";

import { hashObject, signJws } from "./crypto.js";
import { generateTransactionRecord, type RecordSession } from "./record.js";
import { SessionState } from "./session.js";
import type { Dict } from "./messages.js";

export const A2CN_CONTENT_TYPE = "application/a2cn+json";

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function expiresAtIso(seconds: number): string {
  return new Date(Date.now() + seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export interface ClientSessionState {
  session_init: Dict;
  session_ack: Dict;
  sequence_number: number;
  round_number: number;
  current_turn: string;
  offer_chain: string[];
  message_log: Dict[];
  latest_offer: Dict | null;
}

export class HttpStatusError extends Error {
  status: number;
  body: string;

  constructor(status: number, body: string, url: string) {
    super(`HTTP ${status} for ${url}: ${body}`);
    this.name = "HttpStatusError";
    this.status = status;
    this.body = body;
  }
}

/**
 * Buyer-side A2CN client. Holds identity info and a fetch implementation.
 */
export class A2CNClient {
  agentInfo: Dict;
  privateKey: KeyObject;
  mandate: Dict;
  authToken: string | null;
  /** Optional per-request token factory (fresh JWT per request, anti-replay safe). */
  authTokenFactory: (() => Promise<string> | string) | null;
  _http: typeof fetch;
  _sessions: Record<string, ClientSessionState> = {};

  constructor(options: {
    agentInfo: Dict;
    privateKey: KeyObject;
    mandate: Dict;
    fetchFn?: typeof fetch;
    authToken?: string | null;
    authTokenFactory?: (() => Promise<string> | string) | null;
  }) {
    this.agentInfo = options.agentInfo;
    this.privateKey = options.privateKey;
    this.mandate = options.mandate;
    this._http = options.fetchFn ?? fetch;
    this.authToken = options.authToken ?? null;
    this.authTokenFactory = options.authTokenFactory ?? null;
  }

  private async authHeaders(): Promise<Record<string, string>> {
    if (this.authTokenFactory) {
      const token = await this.authTokenFactory();
      return { Authorization: `Bearer ${token}` };
    }
    if (this.authToken) {
      return { Authorization: `Bearer ${this.authToken}` };
    }
    return {};
  }

  private async requestJson(
    url: string,
    init: { method?: string; headers?: Record<string, string>; body?: string } = {},
  ): Promise<Dict> {
    const resp = await this._http(url, init);
    const text = await resp.text();
    if (resp.status >= 400) {
      throw new HttpStatusError(resp.status, text, url);
    }
    return JSON.parse(text) as Dict;
  }

  /**
   * Fetch the discovery document at {baseUrl}/.well-known/a2cn-agent.
   * Section 4.3.
   */
  async fetchDiscovery(baseUrl: string): Promise<Dict> {
    return this.requestJson(`${baseUrl}/.well-known/a2cn-agent`);
  }

  /**
   * Send a SessionInit and return the SessionAck dict.
   * Section 6.3.
   */
  async initiateSession(endpoint: string, _responderDid: string, sessionParams: Dict): Promise<Dict> {
    const messageId = randomUUID();

    const sessionInit: Dict = {
      message_type: "session_init",
      message_id: messageId,
      protocol_version: "0.2",
      session_params: sessionParams,
      initiator: this.agentInfo,
      initiator_mandate: this.mandate,
    };

    const headers = {
      "Content-Type": A2CN_CONTENT_TYPE,
      "Idempotency-Key": messageId,
      ...(await this.authHeaders()),
    };

    const ack = await this.requestJson(`${endpoint}/sessions`, {
      method: "POST",
      headers,
      body: JSON.stringify(sessionInit),
    });

    // Cache session state
    const sessionId = ack.session_id as string;
    this._sessions[sessionId] = {
      session_init: sessionInit,
      session_ack: ack,
      sequence_number: 0,
      round_number: 0,
      current_turn: "initiator",
      offer_chain: [],
      message_log: [],
      latest_offer: null,
    };

    return ack;
  }

  /**
   * Construct, sign, and send an Offer or Counteroffer.
   * Section 7.1 + 7.3.
   */
  async sendOffer(
    endpoint: string,
    _responderDid: string,
    sessionId: string,
    terms: Dict,
    inReplyTo: string | null = null,
  ): Promise<Dict> {
    const state = this._sessions[sessionId];
    state.sequence_number += 1;
    state.round_number += 1;

    const roundNumber = state.round_number;
    const sequenceNumber = state.sequence_number;
    const messageType = roundNumber === 1 ? "offer" : "counteroffer";
    const messageId = randomUUID();
    const timestamp = nowIso();
    const expiresAt = expiresAtIso(
      ((state.session_ack.session_params_accepted as Dict).round_timeout_seconds as number) ?? 900,
    );

    // Build protocol act object (Section 7.3.1)
    const protocolAct = {
      protocol_version: "0.2",
      session_id: sessionId,
      round_number: roundNumber,
      sequence_number: sequenceNumber,
      message_type: messageType,
      sender_did: this.agentInfo.did,
      timestamp,
      expires_at: expiresAt,
      terms,
    };

    const protocolActHash = hashObject(protocolAct);
    const protocolActSignature = signJws(
      protocolActHash,
      this.privateKey,
      this.agentInfo.verification_method as string,
    );

    const offer: Dict = {
      message_type: messageType,
      message_id: messageId,
      session_id: sessionId,
      round_number: roundNumber,
      sequence_number: sequenceNumber,
      sender_did: this.agentInfo.did,
      sender_agent_id: this.agentInfo.agent_id,
      sender_verification_method: this.agentInfo.verification_method,
      timestamp,
      expires_at: expiresAt,
      terms,
      protocol_act_hash: protocolActHash,
      protocol_act_signature: protocolActSignature,
    };
    if (inReplyTo) {
      offer.in_reply_to = inReplyTo;
    }

    const headers = {
      "Content-Type": A2CN_CONTENT_TYPE,
      "Idempotency-Key": messageId,
      ...(await this.authHeaders()),
    };

    const result = await this.requestJson(`${endpoint}/sessions/${sessionId}/messages`, {
      method: "POST",
      headers,
      body: JSON.stringify(offer),
    });

    state.offer_chain.push(protocolActHash);
    state.message_log.push(offer);
    state.latest_offer = offer;

    return result;
  }

  /**
   * Sign and send an Acceptance for the given offer dict.
   * Section 7.4.
   */
  async sendAcceptance(
    endpoint: string,
    _responderDid: string,
    sessionId: string,
    offer: Dict,
  ): Promise<Dict> {
    const state = this._sessions[sessionId];
    state.sequence_number += 1;
    const sequenceNumber = state.sequence_number;
    const roundNumber = state.round_number;
    const messageId = randomUUID();
    const timestamp = nowIso();

    const acceptedOfferId = offer.message_id as string;
    const acceptedHash = offer.protocol_act_hash as string;

    // Build acceptance payload for signing (Section 7.4)
    const acceptancePayload = {
      session_id: sessionId,
      round_number: roundNumber,
      sequence_number: sequenceNumber,
      accepted_offer_id: acceptedOfferId,
      accepted_protocol_act_hash: acceptedHash,
    };

    const acceptanceSignature = signJws(
      hashObject(acceptancePayload),
      this.privateKey,
      this.agentInfo.verification_method as string,
    );

    const acceptance: Dict = {
      message_type: "acceptance",
      message_id: messageId,
      session_id: sessionId,
      in_reply_to: acceptedOfferId,
      round_number: roundNumber,
      sequence_number: sequenceNumber,
      accepted_offer_id: acceptedOfferId,
      accepted_protocol_act_hash: acceptedHash,
      sender_did: this.agentInfo.did,
      sender_agent_id: this.agentInfo.agent_id,
      sender_verification_method: this.agentInfo.verification_method,
      timestamp,
      acceptance_signature: acceptanceSignature,
    };

    const headers = {
      "Content-Type": A2CN_CONTENT_TYPE,
      "Idempotency-Key": messageId,
      ...(await this.authHeaders()),
    };

    const result = await this.requestJson(`${endpoint}/sessions/${sessionId}/messages`, {
      method: "POST",
      headers,
      body: JSON.stringify(acceptance),
    });
    state.message_log.push(acceptance);
    return result;
  }

  async getSessionState(endpoint: string, sessionId: string): Promise<Dict> {
    return this.requestJson(`${endpoint}/sessions/${sessionId}`, {
      headers: await this.authHeaders(),
    });
  }

  async getTransactionRecord(endpoint: string, sessionId: string): Promise<Dict> {
    return this.requestJson(`${endpoint}/sessions/${sessionId}/record`, {
      headers: await this.authHeaders(),
    });
  }

  /**
   * Build the transaction record from client-side state.
   * Used to assert identical record_hash with the server's record.
   */
  buildClientSideRecord(sessionId: string): Dict {
    const state = this._sessions[sessionId];

    // Build a minimal Session-like object for generateTransactionRecord
    const mockSession = new MockSession(
      sessionId,
      state.session_init,
      state.session_ack,
      state.message_log,
      state.offer_chain,
    );
    return generateTransactionRecord(mockSession);
  }

  /**
   * Record an incoming message from the counterparty into client-side session state.
   * Must be called for every received offer/counteroffer/acceptance so that
   * buildClientSideRecord() produces the correct offer_chain_hash.
   * Fix 5.8: replaces manual state patching in examples.
   */
  processIncoming(sessionId: string, message: Dict): void {
    if (message.session_id && message.session_id !== sessionId) {
      throw new Error(
        `Message session_id mismatch: expected ${JSON.stringify(sessionId)}, ` +
          `got ${JSON.stringify(message.session_id)}`,
      );
    }
    const state = this._sessions[sessionId];
    const msgType = (message.message_type as string) ?? "";

    state.message_log.push(message);

    if (msgType === "offer" || msgType === "counteroffer") {
      const pah = message.protocol_act_hash as string | undefined;
      if (pah) {
        state.offer_chain.push(pah);
      }
      state.sequence_number = (message.sequence_number as number) ?? state.sequence_number;
      state.round_number = (message.round_number as number) ?? state.round_number;
      state.latest_offer = message;
      // Flip turn back to initiator after a responder counteroffer
      state.current_turn = "initiator";
    } else if (msgType === "acceptance") {
      state.sequence_number = (message.sequence_number as number) ?? state.sequence_number;
      state.current_turn = "none";
    }
  }

  async close(): Promise<void> {
    // fetch has no persistent connection object to close
  }
}

/** Minimal Session-like object for client-side record generation. */
export class MockSession implements RecordSession {
  session_id: string;
  _session_init: Dict;
  _session_ack: Dict;
  _message_log: Dict[];
  _offer_chain: string[];
  state: string;
  session_created_at: string;
  _final_offer: Dict | null;
  _final_acceptance: Dict | null;
  round_number: number;
  initiator_mandate: Dict;
  responder_mandate: Dict;
  session_params: Dict;
  terminal_message_id: string | null = null;
  approval_receipts: Dict[] = [];

  constructor(
    sessionId: string,
    sessionInit: Dict,
    sessionAck: Dict,
    messageLog: Dict[],
    offerChain: string[],
  ) {
    this.session_id = sessionId;
    this._session_init = sessionInit;
    this._session_ack = sessionAck;
    this._message_log = messageLog;
    this._offer_chain = offerChain;
    this.state = SessionState.COMPLETED;
    this.session_created_at = (sessionAck.session_created_at as string) ?? "";

    // Find final offer and acceptance from message log
    const acceptance =
      [...messageLog].reverse().find((m) => m.message_type === "acceptance") ?? null;
    const acceptedOfferId = acceptance ? (acceptance.accepted_offer_id as string) : null;
    const finalOffer = messageLog.find((m) => m.message_id === acceptedOfferId) ?? null;

    this._final_offer = finalOffer;
    this._final_acceptance = acceptance;
    this.round_number = Math.max(
      0,
      ...messageLog.filter((m) => "round_number" in m).map((m) => (m.round_number as number) ?? 0),
    );

    // Extract party info
    this.initiator_mandate = (sessionInit.initiator_mandate as Dict) ?? {};
    this.responder_mandate = (sessionAck.responder_mandate as Dict) ?? {};
    this.session_params = (sessionAck.session_params_accepted as Dict) ?? {};
  }
}
