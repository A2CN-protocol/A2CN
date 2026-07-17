/**
 * A2CN Transaction Record and Audit Log generation (Sections 9–10).
 *
 * Transaction records are deterministic: both parties derive them only from
 * protocol messages, never from local clock reads. Audit logs are operational
 * artifacts and may include local generation metadata such as log_id and
 * generated_at.
 */

import { randomUUID } from "node:crypto";
import { v5 as uuidv5 } from "uuid";

import { hashObject, canonicalize, hashBytes, verifyJws } from "./crypto.js";
import { getPublicKey, getVerificationMethod } from "./did.js";
import { SessionState, now, parseIsoMs } from "./session.js";
import type { Dict } from "./messages.js";

/**
 * Structural view of a Session sufficient for record/audit generation.
 * The client's MockSession satisfies this too.
 */
export interface RecordSession {
  session_id: string;
  state: string;
  round_number: number;
  session_created_at: string;
  session_params: Dict;
  initiator_mandate: Dict;
  responder_mandate: Dict;
  terminal_message_id?: string | null;
  approval_receipts?: Dict[];
  _message_log: Dict[];
  _offer_chain: string[];
  _final_offer: Dict | null;
  _final_acceptance: Dict | null;
  _session_init: Dict | null;
  _session_ack: Dict | null;
}

// A2CN namespace UUID for record_id (UUID v5) — Appendix A
export const A2CN_NAMESPACE = "f4a2c1e0-8b3d-4f7a-9c2e-1d5b6a8f3e7c";

// These identify the transaction-record and audit-log artifact schemas. They
// are intentionally independent of the package release version.
export const TRANSACTION_RECORD_VERSION = "0.1";
export const AUDIT_LOG_VERSION = "0.1";

export type DidResolver = Record<string, Dict> | ((did: string) => Dict);

/**
 * Generate the deterministic transaction record (Section 9).
 * Both parties calling this independently must produce identical record_hash.
 *
 * Must only be called when session.state == COMPLETED.
 */
export function generateTransactionRecord(session: RecordSession): Dict {
  const finalOffer = session._final_offer;
  const finalAcceptance = session._final_acceptance;

  if (!finalOffer || !finalAcceptance) {
    throw new Error("Cannot generate transaction record: missing final offer or acceptance");
  }

  const sessionInit = session._session_init ?? {};
  const sessionAck = session._session_ack ?? {};

  const initiatorInfo = (sessionInit.initiator as Dict) ?? {};
  const responderInfo = (sessionAck.responder as Dict) ?? {};

  // generated_at = timestamp of Acceptance message (NOT local now())
  const generatedAt = (finalAcceptance.timestamp as string) ?? "";

  // record_id = UUID v5(A2CN_NAMESPACE, session_id) — Appendix A
  const recordId = uuidv5(session.session_id, A2CN_NAMESPACE);

  // offer_chain_hash = SHA-256(JCS([hash_1, ..., hash_n])) — Section 9.3
  const offerChainHash = computeOfferChainHash(session._offer_chain);

  // Count total messages
  const totalMessages = session._message_log.length;
  const totalRounds = session.round_number;

  // first_offer timestamp
  const firstOffer = session._message_log.find((m) =>
    ["offer", "counteroffer"].includes(m.message_type as string),
  );
  const firstOfferAt = firstOffer ? (firstOffer.timestamp as string) : generatedAt;

  const sessionInitParams = (sessionInit.session_params as Dict) ?? {};

  const record: Dict = {
    record_type: "a2cn_transaction_record",
    record_version: TRANSACTION_RECORD_VERSION,
    record_id: recordId,
    session_id: session.session_id,
    generated_at: generatedAt,
    parties: {
      initiator: {
        organization_name: (initiatorInfo.organization_name as string) ?? "",
        did: (initiatorInfo.did as string) ?? "",
        agent_id: (initiatorInfo.agent_id as string) ?? "",
        verification_method: (initiatorInfo.verification_method as string) ?? "",
        mandate_type: (session.initiator_mandate.mandate_type as string) ?? "",
      },
      responder: {
        organization_name: (responderInfo.organization_name as string) ?? "",
        did: (responderInfo.did as string) ?? "",
        agent_id: (responderInfo.agent_id as string) ?? "",
        verification_method: (responderInfo.verification_method as string) ?? "",
        mandate_type: (session.responder_mandate.mandate_type as string) ?? "",
      },
    },
    deal_type: (session.session_params.deal_type as string) ?? "",
    currency: (session.session_params.currency as string) ?? "",
    subject: (sessionInitParams.subject as string) ?? "",
    subject_reference: sessionInitParams.subject_reference ?? null,
    agreed_terms: (finalOffer.terms as Dict) ?? {},
    negotiation_summary: {
      total_rounds: totalRounds,
      total_messages: totalMessages,
      session_created_at: session.session_created_at,
      first_offer_at: firstOfferAt,
      accepted_at: generatedAt,
      initiating_party_did: (initiatorInfo.did as string) ?? "",
      accepting_party_did: (finalAcceptance.sender_did as string) ?? "",
    },
    final_offer: {
      message_id: (finalOffer.message_id as string) ?? "",
      sender_did: (finalOffer.sender_did as string) ?? "",
      protocol_act_hash: (finalOffer.protocol_act_hash as string) ?? "",
      protocol_act_signature: (finalOffer.protocol_act_signature as string) ?? "",
    },
    final_acceptance: {
      message_id: (finalAcceptance.message_id as string) ?? "",
      sender_did: (finalAcceptance.sender_did as string) ?? "",
      round_number: finalAcceptance.round_number ?? null,
      sequence_number: finalAcceptance.sequence_number ?? null,
      accepted_offer_id: (finalAcceptance.accepted_offer_id as string) ?? "",
      accepted_protocol_act_hash: (finalAcceptance.accepted_protocol_act_hash as string) ?? "",
      acceptance_signature: (finalAcceptance.acceptance_signature as string) ?? "",
    },
    offer_chain_hash: offerChainHash,
    record_hash: "", // placeholder — filled below
  };

  // record_hash = SHA-256(JCS(record_with_empty_record_hash)) — Section 9.3
  record.record_hash = hashObject(record);
  return record;
}

/**
 * offer_chain_hash = SHA-256(JCS([hash_1, hash_2, ..., hash_n]))
 * Using JCS of the array eliminates ambiguity of bare concatenation.
 */
function computeOfferChainHash(offerHashes: string[]): string {
  const canonical = canonicalize(offerHashes);
  return hashBytes(canonical);
}

/**
 * Verify a transaction record per Section 9.5.
 *
 * `didResolver` may be a mapping of DID → DID document or a callable returning
 * a DID document. For multi-round sessions, pass the chronological offer hash
 * list as `offerHashes` so `offer_chain_hash` can be independently recomputed.
 */
export function verifyTransactionRecord(
  record: Dict,
  didResolver: DidResolver,
  offerHashes: string[] | null = null,
): boolean {
  try {
    const finalOffer = record.final_offer as Dict;
    const finalAcceptance = record.final_acceptance as Dict;
    const offerHash = finalOffer.protocol_act_hash as string;
    const acceptedHash = finalAcceptance.accepted_protocol_act_hash as string;

    if (!recordHashMatches(record)) {
      return false;
    }

    if (acceptedHash !== offerHash) {
      return false;
    }

    const chainHashes = offerHashes !== null ? offerHashes : [offerHash];
    if (record.offer_chain_hash !== computeOfferChainHash(chainHashes)) {
      return false;
    }

    if (
      !verifyRecordSignature(didResolver, record, {
        did: finalOffer.sender_did as string,
        signature: finalOffer.protocol_act_signature as string,
        expectedPayload: offerHash,
      })
    ) {
      return false;
    }

    if (
      !verifyRecordSignature(didResolver, record, {
        did: finalAcceptance.sender_did as string,
        signature: finalAcceptance.acceptance_signature as string,
        expectedPayload: hashObject({
          session_id: record.session_id,
          round_number: finalAcceptance.round_number,
          sequence_number: finalAcceptance.sequence_number,
          accepted_offer_id: finalAcceptance.accepted_offer_id,
          accepted_protocol_act_hash: acceptedHash,
        }),
      })
    ) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

function recordHashMatches(record: Dict): boolean {
  const claimedHash = record.record_hash;
  if (!claimedHash) {
    return false;
  }
  const candidate: Dict = { ...record };
  candidate.record_hash = "";
  return hashObject(candidate) === claimedHash;
}

function verifyRecordSignature(
  didResolver: DidResolver,
  record: Dict,
  options: { did: string; signature: string; expectedPayload?: string | null },
): boolean {
  const { did, signature, expectedPayload = null } = options;
  const verificationMethod = verificationMethodForDid(record, did);
  if (!verificationMethod || !signature) {
    return false;
  }

  const didDocument = resolveDidDocument(didResolver, did);
  const vm = getVerificationMethod(didDocument, verificationMethod);
  const publicKey = getPublicKey(vm);
  const signedPayload = verifyJws(signature, publicKey);
  return expectedPayload === null || signedPayload === expectedPayload;
}

function resolveDidDocument(didResolver: DidResolver, did: string): Dict {
  if (typeof didResolver === "function") {
    return didResolver(did);
  }
  return didResolver[did];
}

function verificationMethodForDid(record: Dict, did: string): string {
  const parties = (record.parties as Dict) ?? {};
  for (const role of ["initiator", "responder"]) {
    const party = (parties[role] as Dict) ?? {};
    if (party.did === did) {
      return (party.verification_method as string) ?? "";
    }
  }
  return "";
}

/** Generate the audit log for any terminal session (Section 10). */
export function generateAuditLog(session: RecordSession): Dict {
  const sessionInit = session._session_init ?? {};
  const sessionAck = session._session_ack ?? {};

  const initiatorInfo = (sessionInit.initiator as Dict) ?? {};
  const responderInfo = (sessionAck.responder as Dict) ?? {};

  // Determine record_id (null unless COMPLETED)
  let recordId: string | null = null;
  if (session.state === SessionState.COMPLETED) {
    recordId = uuidv5(session.session_id, A2CN_NAMESPACE);
  }

  const generatedAt = now();
  const sessionCreatedAt = session.session_created_at || generatedAt;

  // first_offer timestamp
  const firstOffer = session._message_log.find((m) =>
    ["offer", "counteroffer"].includes(m.message_type as string),
  );
  const firstOfferAt = firstOffer ? (firstOffer.timestamp as string) : null;

  // session_ack timestamp
  const sessionAckAt = (sessionAck.session_created_at as string | undefined) ?? null;

  // terminal_state_at: from the last message
  const terminalMsg = [...session._message_log]
    .reverse()
    .find((m) => m.message_id === session.terminal_message_id);
  const terminalStateAt = terminalMsg ? (terminalMsg.timestamp as string) : generatedAt;

  // duration
  let duration = 0;
  const tStart = parseIsoMs(sessionCreatedAt);
  const tEnd = parseIsoMs(terminalStateAt);
  if (!Number.isNaN(tStart) && !Number.isNaN(tEnd)) {
    duration = Math.trunc((tEnd - tStart) / 1000);
  }

  // Build negotiation log
  const negotiationLog: Dict[] = [];
  for (const msg of session._message_log) {
    const entry: Dict = {
      sequence_number: msg.sequence_number ?? null,
      message_type: (msg.message_type as string) ?? "",
      message_id: (msg.message_id as string) ?? "",
      sender_did: (msg.sender_did as string) ?? "",
      timestamp: (msg.timestamp as string) ?? "",
      round_number: msg.round_number ?? null,
      total_value_offered:
        "terms" in msg ? (((msg.terms as Dict) ?? {}).total_value ?? null) : null,
      protocol_act_hash: msg.protocol_act_hash ?? null,
    };
    negotiationLog.push(entry);
  }

  const humanOversightPresent = (session.approval_receipts ?? []).length > 0;

  return {
    log_type: "a2cn_audit_log",
    log_version: AUDIT_LOG_VERSION,
    log_id: randomUUID(),
    session_id: session.session_id,
    record_id: recordId,
    generated_at: generatedAt,
    session_outcome: session.state,
    parties: {
      initiator: {
        organization_name: initiatorInfo.organization_name ?? null,
        did: initiatorInfo.did ?? null,
        agent_id: initiatorInfo.agent_id ?? null,
        mandate_type: session.initiator_mandate.mandate_type ?? null,
      },
      responder: {
        organization_name: responderInfo.organization_name ?? null,
        did: responderInfo.did ?? null,
        agent_id: responderInfo.agent_id ?? null,
        mandate_type: session.responder_mandate.mandate_type ?? null,
      },
    },
    session_timeline: {
      session_init_at: sessionCreatedAt,
      session_ack_at: sessionAckAt,
      first_offer_at: firstOfferAt,
      terminal_state_at: terminalStateAt,
      total_duration_seconds: duration,
    },
    negotiation_log: negotiationLog,
    protocol_violations: [],
    audit_metadata: {
      ai_system_involved: true,
      human_oversight_present: humanOversightPresent,
      autonomous_decision: !humanOversightPresent,
    },
  };
}
