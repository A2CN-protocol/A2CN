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

import {
  hashObject,
  canonicalize,
  hashBytes,
  verifyJws,
  InvalidSignatureError,
} from "./crypto.js";
import { getPublicKey, getVerificationMethod } from "./did.js";
import { SESSION_BASES, SessionState, now, parseIsoMs } from "./session.js";
import { PROTOCOL_ACT_VERSION, protocolActObject, type Dict } from "./messages.js";

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
// are intentionally independent of the package release version. A
// TransactionRecord's version follows its content (Section 9.3): a producer
// emits "0.3" exactly when final_offer carries the signed act's fields, which
// this implementation always does. "0.2" is the version of a record that carries
// the session's basis and no act fields, and "0.1" of one that carries neither.
export const TRANSACTION_RECORD_VERSION_WITHOUT_BASIS = "0.1";
export const TRANSACTION_RECORD_VERSION_WITH_BASIS = "0.2";
export const TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT = "0.3";
export const AUDIT_LOG_VERSION = "0.1";
// The record shapes this implementation knows, which is what the published
// schema files describe. Knowing a shape is not accepting it.
export const KNOWN_TRANSACTION_RECORD_VERSIONS: readonly string[] = ["0.1", "0.2", "0.3"];
// The versions a verifier accepts (Section 9.5 step 1): only the bound one, the
// version whose final_offer carries the act fields, so the record can be rebound
// to the offering party's signature from the record alone. record_version is
// covered by no signature, so a verifier refuses any version it cannot rebind
// rather than trusting the label; accepting an unbound version would let a
// presenter strip the act fields, relabel the record and alter agreed_terms with
// both signatures still verifying.
export const ACCEPTED_TRANSACTION_RECORD_VERSIONS: readonly string[] = [
  TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,
];

// Why a record failed (Section 9.5). verifyTransactionRecord returns a boolean;
// verifyTransactionRecordReason returns one of these, or null when the record
// verifies. A version this implementation knows but cannot rebind is reported as
// unbound, distinct from a value that is no version at all.
export const REASON_UNRECOGNIZED_RECORD_VERSION = "UNRECOGNIZED_RECORD_VERSION";
export const REASON_UNBOUND_RECORD_VERSION = "UNBOUND_RECORD_VERSION";
export const REASON_RECORD_HASH_MISMATCH = "RECORD_HASH_MISMATCH";
export const REASON_ACT_NOT_RECOMPUTABLE = "ACT_NOT_RECOMPUTABLE";
export const REASON_BASIS_MISMATCH = "BASIS_MISMATCH";
export const REASON_CURRENCY_MISMATCH = "CURRENCY_MISMATCH";
export const REASON_ACCEPTED_HASH_MISMATCH = "ACCEPTED_HASH_MISMATCH";
export const REASON_OFFER_CHAIN_HASH_MISMATCH = "OFFER_CHAIN_HASH_MISMATCH";
export const REASON_OFFER_SIGNATURE_INVALID = "OFFER_SIGNATURE_INVALID";
export const REASON_ACCEPTANCE_SIGNATURE_INVALID = "ACCEPTANCE_SIGNATURE_INVALID";
export const REASON_MALFORMED_RECORD = "MALFORMED_RECORD";

// The Section 7.3.1 act fields final_offer carries beside the act's hash, so a
// verifier can rebuild the signed act from the record alone (Section 9.3). The
// act's other fields are already in the record: session_id at the top level,
// sender_did in final_offer, and the act's terms as agreed_terms. Nothing new is
// signed — this is the object protocol_act_signature already covers.
export const FINAL_OFFER_ACT_FIELDS: readonly string[] = [
  "protocol_version",
  "round_number",
  "sequence_number",
  "message_type",
  "timestamp",
  "expires_at",
];

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

  // basis sits beside currency only when the session fixed one (Section 9.3).
  // Under "0.3" agreed_terms is bound to the offer's signature, so the version
  // no longer has to encode whether the session fixed a basis; the record still
  // carries basis exactly when it did, equal to agreed_terms.basis.
  const hasBasis = session.session_params.basis !== undefined;

  const record: Dict = {
    record_type: "a2cn_transaction_record",
    // Every record this implementation produces carries the act fields, so
    // every one is "0.3" (Section 9.3).
    record_version: TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,
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
    ...(hasBasis ? { basis: session.session_params.basis } : {}),
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
    // The accepted offer's signed act, in Section 7.3.1's order. An offer
    // message carries no protocol_version of its own, so the record states the
    // wire version its signer hashed the act under.
    final_offer: {
      message_id: (finalOffer.message_id as string) ?? "",
      protocol_version: PROTOCOL_ACT_VERSION,
      round_number: finalOffer.round_number ?? null,
      sequence_number: finalOffer.sequence_number ?? null,
      message_type: (finalOffer.message_type as string) ?? "",
      sender_did: (finalOffer.sender_did as string) ?? "",
      timestamp: (finalOffer.timestamp as string) ?? "",
      expires_at: (finalOffer.expires_at as string) ?? "",
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
 * Section 9.5 step 1: the record states the one version a verifier accepts.
 *
 * A value that is no version this implementation knows is unrecognized; absent,
 * null, a number, or a string that differs by so much as a space is rejected
 * rather than parsed. A version it does know but cannot rebind is reported as
 * unbound instead, because the two are different facts: one is a record from
 * somewhere else, the other a record this implementation once produced and no
 * longer accepts.
 */
function recordVersionReason(record: Dict): string | null {
  const version = record.record_version;
  if (typeof version === "string" && ACCEPTED_TRANSACTION_RECORD_VERSIONS.includes(version)) {
    return null;
  }
  if (typeof version === "string" && KNOWN_TRANSACTION_RECORD_VERSIONS.includes(version)) {
    return REASON_UNBOUND_RECORD_VERSION;
  }
  return REASON_UNRECOGNIZED_RECORD_VERSION;
}

function isNonemptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

// typeof already excludes a boolean here; Python must exclude it explicitly, so
// the two implementations reach the same verdict.
function isActInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value);
}

function isJsonObject(value: unknown): value is Dict {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Rebuild the final offer's Section 7.3.1 act from the record and hash it.
 *
 * Returns null when the record carries no well-formed act: a missing or wrongly
 * typed field leaves nothing to rebuild, and the record fails rather than being
 * hashed best-effort. The act is rebuilt with the protocol_version the record
 * carries, not this implementation's, so a record produced under a later wire
 * version still recomputes.
 *
 * The types are checked only so far as the act can be rebuilt and canonicalized
 * from them. The values are not otherwise constrained: an empty string or a zero
 * is rebuilt as it stands, because the hash comparison, not a field's length or
 * floor, is what decides. Both state machines default a missing timestamp or
 * expires_at to "" when they rebuild an act to check its hash, and neither field
 * is validated on the wire, so an offer that omits one is signed and recorded
 * with "" inside the signed act; demanding more here would reject a record whose
 * signature genuinely covers those bytes.
 */
function finalOfferActHash(record: Dict): string | null {
  const finalOffer = record.final_offer;
  if (!isJsonObject(finalOffer)) {
    return null;
  }
  if (
    !["protocol_version", "message_type", "sender_did", "timestamp", "expires_at"].every((name) =>
      isString(finalOffer[name]),
    )
  ) {
    return null;
  }
  if (!["round_number", "sequence_number"].every((name) => isActInteger(finalOffer[name]))) {
    return null;
  }
  const sessionId = record.session_id;
  const agreedTerms = record.agreed_terms;
  if (!isString(sessionId) || !isJsonObject(agreedTerms)) {
    return null;
  }
  return hashObject(
    protocolActObject({
      protocol_version: finalOffer.protocol_version as string,
      session_id: sessionId,
      round_number: finalOffer.round_number,
      sequence_number: finalOffer.sequence_number,
      message_type: finalOffer.message_type,
      sender_did: finalOffer.sender_did,
      timestamp: finalOffer.timestamp,
      expires_at: finalOffer.expires_at,
      terms: agreedTerms,
    }),
  );
}

/**
 * Section 9.5 step 3: the record rebuilds the act its signature covers.
 *
 * Step 1 has already limited the version to the bound one, so this always runs:
 * final_offer carries every Section 7.3.1 act field, and the act rebuilt from
 * the record hashes to the protocol_act_hash the offer's signature covers. Step
 * 4 then binds agreed_terms to that signature, because the act it was rebuilt
 * from holds agreed_terms as its terms. Presence is by key, so a null counts as
 * carried; a key whose value is undefined is not serialized, so it is not
 * carried. A partial set is refused. Nothing here is newly signed.
 *
 * The hash comparison is what carries this check. The count of carried fields is
 * belt-and-braces: a partial set leaves the rebuild with nothing to read, so it
 * would fail the comparison anyway.
 */
/**
 * Whether the record carries every Section 7.3.1 act field to rebuild from.
 *
 * A record that does not is unbound: there is nothing to rebind it to, whether
 * because it is an older shape or because a presenter stripped the fields and
 * relabelled it. Presence is by key.
 */
function recordCarriesActFields(record: Dict): boolean {
  const finalOffer = record.final_offer;
  if (!isJsonObject(finalOffer)) {
    return false;
  }
  return FINAL_OFFER_ACT_FIELDS.every((name) => finalOffer[name] !== undefined);
}

function recordActIsBound(record: Dict): boolean {
  const finalOffer = record.final_offer;
  if (!isJsonObject(finalOffer)) {
    return false;
  }
  const carried = FINAL_OFFER_ACT_FIELDS.filter((name) => finalOffer[name] !== undefined);
  if (carried.length !== FINAL_OFFER_ACT_FIELDS.length) {
    return false;
  }
  const expectedHash = finalOfferActHash(record);
  return expectedHash !== null && expectedHash === finalOffer.protocol_act_hash;
}

/**
 * Section 9.5 step 8: the top-level basis is the one that was signed.
 *
 * The record carries basis exactly when agreed_terms carries one, and equal to
 * it. Step 3 has bound agreed_terms to the offering party's signature, so this
 * reads a signed value. Presence is by key, so a null counts as carried; a key
 * whose value is undefined is not serialized, so it is not carried.
 *
 * Earlier versions meant something else by the same field: a "0.2" record always
 * carried basis and a "0.1" record never did, because neither could bind
 * agreed_terms and the version had to encode whether the session fixed one. A
 * verifier no longer accepts those versions, so those branches are gone rather
 * than dead.
 */
function recordBasisMatches(record: Dict): boolean {
  const agreedTerms = record.agreed_terms;
  if (!(isJsonObject(agreedTerms) && (agreedTerms as Dict).basis !== undefined)) {
    return record.basis === undefined;
  }
  return (
    SESSION_BASES.includes(record.basis as string) &&
    (agreedTerms as Dict).basis === record.basis
  );
}

/**
 * Section 9.5 step 8: the top-level currency is the one that was signed.
 *
 * Step 3 has bound agreed_terms to the offering party's signature, so the
 * record's currency is held to agreed_terms.currency: a record that states one
 * currency in its headline and another in the terms that were signed is
 * rejected. Presence is by key, and both must carry one. The check is
 * unconditional, because only the bound version is accepted.
 */
function recordCurrencyMatches(record: Dict): boolean {
  const agreedTerms = record.agreed_terms;
  if (!isJsonObject(agreedTerms)) {
    return false;
  }
  return (
    record.currency !== undefined &&
    (agreedTerms as Dict).currency !== undefined &&
    record.currency === (agreedTerms as Dict).currency
  );
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
  return verifyTransactionRecordReason(record, didResolver, offerHashes) === null;
}

/**
 * Why a record does not verify (Section 9.5), or null when it does.
 *
 * The same arguments as `verifyTransactionRecord`, which is this function's
 * boolean. The reason is one of the REASON_* constants, so a caller can tell a
 * record it cannot rebind from one that was tampered with.
 */
export function verifyTransactionRecordReason(
  record: Dict,
  didResolver: DidResolver,
  offerHashes: string[] | null = null,
): string | null {
  try {
    const versionReason = recordVersionReason(record);
    if (versionReason !== null) {
      return versionReason;
    }

    const finalOffer = record.final_offer as Dict;
    const finalAcceptance = record.final_acceptance as Dict;
    const offerHash = finalOffer.protocol_act_hash as string;
    const acceptedHash = finalAcceptance.accepted_protocol_act_hash as string;

    if (!recordHashMatches(record)) {
      return REASON_RECORD_HASH_MISMATCH;
    }

    // A record with no act to rebuild is unbound, whatever its label says; one
    // that carries the act but hashes to something else was tampered with. The
    // two reasons mean genuinely different things.
    if (!recordCarriesActFields(record)) {
      return REASON_UNBOUND_RECORD_VERSION;
    }

    if (!recordActIsBound(record)) {
      return REASON_ACT_NOT_RECOMPUTABLE;
    }

    if (!recordBasisMatches(record)) {
      return REASON_BASIS_MISMATCH;
    }

    if (!recordCurrencyMatches(record)) {
      return REASON_CURRENCY_MISMATCH;
    }

    if (acceptedHash !== offerHash) {
      return REASON_ACCEPTED_HASH_MISMATCH;
    }

    const chainHashes = offerHashes !== null ? offerHashes : [offerHash];
    if (record.offer_chain_hash !== computeOfferChainHash(chainHashes)) {
      return REASON_OFFER_CHAIN_HASH_MISMATCH;
    }

    if (
      !verifyRecordSignature(didResolver, record, {
        did: finalOffer.sender_did as string,
        signature: finalOffer.protocol_act_signature as string,
        expectedPayload: offerHash,
      })
    ) {
      return REASON_OFFER_SIGNATURE_INVALID;
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
      return REASON_ACCEPTANCE_SIGNATURE_INVALID;
    }

    return null;
  } catch {
    return REASON_MALFORMED_RECORD;
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
  // verifyJws throws on bad signature bytes. That is this check failing, not
  // the record being unreadable, so it is caught here and the caller reports
  // the signature reason. An unresolvable DID or a missing verification method
  // is a different thing and still reaches the outer handler as a malformed
  // record.
  let signedPayload: string;
  try {
    signedPayload = verifyJws(signature, publicKey);
  } catch (exc) {
    if (exc instanceof InvalidSignatureError) {
      return false;
    }
    throw exc;
  }
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
