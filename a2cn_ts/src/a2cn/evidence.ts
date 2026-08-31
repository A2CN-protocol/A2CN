/**
 * Session Evidence Record generation and verification (Section 9A).
 *
 * SessionEvidenceRecord is a producer-sealed package for any terminal session.
 * It preserves complete observed acts and distinguishes verified A2CN
 * signatures from unsigned observations without changing TransactionRecord or
 * AuditLog semantics.
 */

import { v5 as uuidv5 } from "uuid";

import {
  canonicalize,
  hashBytes,
  hashObject,
  signJws,
  verifyJws,
  type SigningPrivateKey,
} from "./crypto.js";
import { getPublicKey, getVerificationMethod } from "./did.js";
import {
  A2CN_NAMESPACE,
  generateTransactionRecord,
  type DidResolver,
  type RecordSession,
} from "./record.js";
import { SessionState, now } from "./session.js";
import type { Dict } from "./messages.js";

export const SESSION_EVIDENCE_RECORD_VERSION = "0.1";
export const SESSION_EVIDENCE_RECORD_TYPE = "a2cn_session_evidence_record";

export const EvidenceLevel = {
  BILATERAL: "bilateral",
  MIXED: "mixed",
  UNILATERAL: "unilateral",
} as const;
const EVIDENCE_LEVEL_VALUES = new Set<string>(Object.values(EvidenceLevel));

export const EvidenceAttribution = {
  VERIFIED: "verified_signature",
  UNSIGNED: "unsigned_observation",
} as const;

export const EvidenceSignatureType = {
  PROTOCOL_ACT: "protocol_act_signature",
  ACCEPTANCE: "acceptance_signature",
} as const;

const SIGNED_MESSAGE_FIELDS: Record<string, string> = {
  [EvidenceSignatureType.PROTOCOL_ACT]: "protocol_act_signature",
  [EvidenceSignatureType.ACCEPTANCE]: "acceptance_signature",
};
const RECORD_FIELDS = new Set([
  "record_type",
  "record_version",
  "evidence_id",
  "session_id",
  "generated_at",
  "producer",
  "parties",
  "terminal",
  "transaction_record_hash",
  "acts",
  "act_chain_hash",
  "evidence_level",
  "record_hash",
  "producer_signature",
]);
const ACT_FIELDS = new Set([
  "sequence_number",
  "round_number",
  "message_type",
  "message_id",
  "sender_did",
  "timestamp",
  "source_protocol",
  "act",
  "act_hash",
  "sender_verification_method",
  "signature_type",
  "signature",
  "attribution",
]);
const HASH_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface EvidenceSession extends RecordSession {
  terminal_reason?: string | null;
  state_updated_at?: string;
}

export interface GenerateSessionEvidenceOptions {
  producerPrivateKey: SigningPrivateKey;
  producerVerificationMethod: string;
  producerDid?: string | null;
  producerAgentId?: string | null;
  observedActs?: Dict[] | null;
}

export interface EvidenceAssessment {
  valid: boolean;
  evidence_level: unknown;
  verified_acts: number;
  unsigned_acts: number;
  invalid_acts: number;
}

/** Generate a producer-sealed evidence package for a terminal session. */
export function generateSessionEvidenceRecord(
  session: EvidenceSession,
  options: GenerateSessionEvidenceOptions,
): Dict {
  if (!SessionState.TERMINAL.has(session.state)) {
    throw new Error("Session evidence is only available for terminal sessions");
  }

  const parties = partyMetadata(session);
  const producer = producerMetadata(parties, {
    producerVerificationMethod: options.producerVerificationMethod,
    producerDid: options.producerDid ?? null,
    producerAgentId: options.producerAgentId ?? null,
  });

  const acts = session._message_log.map((message) =>
    normalizeEvidenceAct(message, "a2cn"),
  );
  acts.push(
    ...(options.observedActs ?? []).map((observed) => normalizeEvidenceAct(observed, null)),
  );
  const orderedActs = orderEvidenceActs(acts);

  const terminalTimestamp = terminalTimestampFor(session);
  let transactionRecordHash: string | null = null;
  if (session.state === SessionState.COMPLETED) {
    transactionRecordHash = generateTransactionRecord(session).record_hash as string;
  }

  const actChainHash = hashBytes(
    canonicalize(orderedActs.map((entry) => entry.act_hash as string)),
  );
  const evidenceLevel = classifyEvidenceLevel(orderedActs, session.state, parties);
  const producerDid = producer.did as string;

  const record: Dict = {
    record_type: SESSION_EVIDENCE_RECORD_TYPE,
    record_version: SESSION_EVIDENCE_RECORD_VERSION,
    evidence_id: uuidv5(
      `session-evidence:${session.session_id}:${producerDid}`,
      A2CN_NAMESPACE,
    ),
    session_id: session.session_id,
    generated_at: terminalTimestamp,
    producer,
    parties,
    terminal: {
      outcome: session.state,
      reason: session.terminal_reason ?? null,
      message_id: session.terminal_message_id ?? null,
      timestamp: terminalTimestamp,
    },
    transaction_record_hash: transactionRecordHash,
    acts: orderedActs,
    act_chain_hash: actChainHash,
    evidence_level: evidenceLevel,
    record_hash: "",
    producer_signature: "",
  };
  record.record_hash = hashObject(record);
  record.producer_signature = signJws(
    record.record_hash as string,
    options.producerPrivateKey,
    options.producerVerificationMethod,
  );
  return record;
}

/**
 * Return true when the record seal, hashes, and every claimed signature verify.
 * A true result does not mean every named party signed every act.
 */
export function verifySessionEvidenceRecord(record: Dict, didResolver: DidResolver): boolean {
  return assessSessionEvidenceRecord(record, didResolver).valid;
}

/** Return verification status and signed/unsigned act counts. */
export function assessSessionEvidenceRecord(
  record: Dict,
  didResolver: DidResolver,
): EvidenceAssessment {
  const assessment: EvidenceAssessment = {
    valid: false,
    evidence_level: record.evidence_level,
    verified_acts: 0,
    unsigned_acts: 0,
    invalid_acts: 0,
  };

  try {
    if (!evidenceRecordShapeValid(record)) {
      return assessment;
    }
    if (record.record_type !== SESSION_EVIDENCE_RECORD_TYPE) {
      return assessment;
    }
    if (record.record_version !== SESSION_EVIDENCE_RECORD_VERSION) {
      return assessment;
    }

    const terminal = record.terminal as Dict;
    const outcome = terminal.outcome as string;
    if (!SessionState.TERMINAL.has(outcome)) {
      return assessment;
    }
    if (record.generated_at !== terminal.timestamp) {
      return assessment;
    }
    if (outcome === SessionState.COMPLETED) {
      if (typeof record.transaction_record_hash !== "string" || !record.transaction_record_hash) {
        return assessment;
      }
    } else if (record.transaction_record_hash !== null) {
      return assessment;
    }

    const producer = record.producer as Dict;
    const producerDid = producer.did as string;
    const producerVerificationMethod = producer.verification_method as string;
    if (!verificationMethodControlledBy(producerVerificationMethod, producerDid)) {
      return assessment;
    }

    const expectedEvidenceId = uuidv5(
      `session-evidence:${record.session_id as string}:${producerDid}`,
      A2CN_NAMESPACE,
    );
    if (record.evidence_id !== expectedEvidenceId) {
      return assessment;
    }

    const acts = record.acts as Dict[];
    if (!Array.isArray(acts) || !evidenceActsAreOrdered(acts)) {
      return assessment;
    }

    const computedActHashes: string[] = [];
    for (const entry of acts) {
      const { valid, attribution } = verifyEvidenceAct(
        entry,
        record.session_id as string,
        didResolver,
      );
      if (attribution === EvidenceAttribution.VERIFIED) {
        if (valid) {
          assessment.verified_acts += 1;
        } else {
          assessment.invalid_acts += 1;
        }
      } else if (attribution === EvidenceAttribution.UNSIGNED) {
        assessment.unsigned_acts += 1;
        if (!valid) {
          assessment.invalid_acts += 1;
        }
      } else {
        assessment.invalid_acts += 1;
      }

      if (valid) {
        computedActHashes.push(entry.act_hash as string);
      }
    }

    if (assessment.invalid_acts > 0) {
      return assessment;
    }
    if (record.act_chain_hash !== hashBytes(canonicalize(computedActHashes))) {
      return assessment;
    }

    const expectedLevel = classifyEvidenceLevel(acts, outcome, record.parties as Dict);
    if (record.evidence_level !== expectedLevel) {
      return assessment;
    }
    if (!evidenceRecordHashMatches(record)) {
      return assessment;
    }

    const producerSignature = record.producer_signature;
    if (typeof producerSignature !== "string" || !producerSignature) {
      return assessment;
    }
    if (
      !verifySignature(didResolver, {
        did: producerDid,
        verificationMethod: producerVerificationMethod,
        signature: producerSignature,
        expectedPayload: record.record_hash as string,
      })
    ) {
      return assessment;
    }

    assessment.valid = true;
    return assessment;
  } catch {
    return assessment;
  }
}

function partyMetadata(session: EvidenceSession): Dict {
  const sessionInit = session._session_init ?? {};
  const sessionAck = session._session_ack ?? {};
  const initiatorInfo = (sessionInit.initiator as Dict) ?? {};
  const responderInfo = (sessionAck.responder as Dict) ?? {};

  return {
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
  };
}

function hasExactFields(object: Dict, expected: Set<string>): boolean {
  const fields = Object.keys(object);
  return fields.length === expected.size && fields.every((field) => expected.has(field));
}

function evidenceRecordShapeValid(record: Dict): boolean {
  if (typeof record !== "object" || record === null || !hasExactFields(record, RECORD_FIELDS)) {
    return false;
  }
  for (const field of [
    "record_type",
    "record_version",
    "evidence_id",
    "session_id",
    "generated_at",
    "act_chain_hash",
    "evidence_level",
    "record_hash",
    "producer_signature",
  ]) {
    if (typeof record[field] !== "string" || !(record[field] as string)) {
      return false;
    }
  }
  if (!EVIDENCE_LEVEL_VALUES.has(record.evidence_level as string)) {
    return false;
  }
  if (!HASH_PATTERN.test(record.act_chain_hash as string)) {
    return false;
  }
  if (!HASH_PATTERN.test(record.record_hash as string)) {
    return false;
  }

  const producer = record.producer as Dict;
  if (
    typeof producer !== "object" ||
    producer === null ||
    !hasExactFields(producer, new Set(["did", "agent_id", "verification_method"]))
  ) {
    return false;
  }
  if (typeof producer.did !== "string" || !producer.did.startsWith("did:")) {
    return false;
  }
  if (typeof producer.agent_id !== "string") {
    return false;
  }
  if (typeof producer.verification_method !== "string" || !producer.verification_method) {
    return false;
  }

  const parties = record.parties as Dict;
  if (
    typeof parties !== "object" ||
    parties === null ||
    !hasExactFields(parties, new Set(["initiator", "responder"]))
  ) {
    return false;
  }
  const partyFields = new Set([
    "organization_name",
    "did",
    "agent_id",
    "verification_method",
    "mandate_type",
  ]);
  for (const value of Object.values(parties)) {
    const party = value as Dict;
    if (typeof party !== "object" || party === null || !hasExactFields(party, partyFields)) {
      return false;
    }
    if ([...partyFields].some((field) => typeof party[field] !== "string")) {
      return false;
    }
    if (!(party.did as string).startsWith("did:") || !party.verification_method) {
      return false;
    }
  }

  const terminal = record.terminal as Dict;
  if (
    typeof terminal !== "object" ||
    terminal === null ||
    !hasExactFields(terminal, new Set(["outcome", "reason", "message_id", "timestamp"]))
  ) {
    return false;
  }
  if (typeof terminal.outcome !== "string") {
    return false;
  }
  if (terminal.reason !== null && typeof terminal.reason !== "string") {
    return false;
  }
  if (terminal.message_id !== null && typeof terminal.message_id !== "string") {
    return false;
  }
  if (typeof terminal.timestamp !== "string" || !terminal.timestamp) {
    return false;
  }

  const transactionRecordHash = record.transaction_record_hash;
  if (
    transactionRecordHash !== null &&
    (typeof transactionRecordHash !== "string" || !HASH_PATTERN.test(transactionRecordHash))
  ) {
    return false;
  }
  return Array.isArray(record.acts);
}

function evidenceActShapeValid(entry: Dict): boolean {
  if (typeof entry !== "object" || entry === null || !hasExactFields(entry, ACT_FIELDS)) {
    return false;
  }
  for (const field of ["sequence_number", "round_number"]) {
    const value = entry[field];
    if (value !== null && (!Number.isInteger(value) || (value as number) < 1)) {
      return false;
    }
  }
  for (const field of [
    "message_type",
    "message_id",
    "sender_did",
    "timestamp",
    "act_hash",
  ]) {
    if (typeof entry[field] !== "string" || !(entry[field] as string)) {
      return false;
    }
  }
  if (!(entry.sender_did as string).startsWith("did:")) {
    return false;
  }
  if (!HASH_PATTERN.test(entry.act_hash as string)) {
    return false;
  }
  if (entry.source_protocol !== null && typeof entry.source_protocol !== "string") {
    return false;
  }
  return typeof entry.act === "object" && entry.act !== null && !Array.isArray(entry.act);
}

function producerMetadata(
  parties: Dict,
  options: {
    producerVerificationMethod: string;
    producerDid: string | null;
    producerAgentId: string | null;
  },
): Dict {
  const matchingParty = Object.values(parties)
    .map((party) => party as Dict)
    .find(
      (party) =>
        party.verification_method === options.producerVerificationMethod ||
        (options.producerDid !== null && party.did === options.producerDid),
    );
  let resolvedDid = options.producerDid ?? ((matchingParty?.did as string | undefined) || null);
  if (!resolvedDid && options.producerVerificationMethod.includes("#")) {
    resolvedDid = options.producerVerificationMethod.split("#", 1)[0];
  }
  if (!resolvedDid) {
    throw new Error("producerDid cannot be derived from the verification method");
  }
  if (!verificationMethodControlledBy(options.producerVerificationMethod, resolvedDid)) {
    throw new Error("producerVerificationMethod is not controlled by producerDid");
  }

  return {
    did: resolvedDid,
    agent_id:
      options.producerAgentId !== null
        ? options.producerAgentId
        : ((matchingParty?.agent_id as string | undefined) ?? ""),
    verification_method: options.producerVerificationMethod,
  };
}

function terminalTimestampFor(session: EvidenceSession): string {
  const terminalMessage = [...session._message_log]
    .reverse()
    .find((message) => message.message_id === session.terminal_message_id);
  if (terminalMessage?.timestamp) {
    return terminalMessage.timestamp as string;
  }
  if (session.state_updated_at) {
    return session.state_updated_at;
  }
  return now();
}

function hasOwn(object: Dict, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function normalizeEvidenceAct(item: Dict, defaultSourceProtocol: string | null): Dict {
  if (typeof item !== "object" || item === null || Array.isArray(item)) {
    throw new Error("Each observed act must be an object");
  }
  const isWrapper = typeof item.act === "object" && item.act !== null && !Array.isArray(item.act);
  const metadata = isWrapper ? item : {};
  const act = structuredClone((isWrapper ? item.act : item) as Dict);

  const field = (name: string, defaultValue: unknown = null): unknown => {
    if (hasOwn(metadata, name)) {
      return metadata[name];
    }
    return hasOwn(act, name) ? act[name] : defaultValue;
  };

  const signatureTypes = Object.entries(SIGNED_MESSAGE_FIELDS)
    .filter(([, actField]) => hasOwn(act, actField) && act[actField] !== null)
    .map(([signatureType]) => signatureType);
  const explicitSignatureType = isWrapper ? metadata.signature_type : null;
  let signatureType: string | null;
  if (explicitSignatureType !== null && explicitSignatureType !== undefined) {
    if (!(explicitSignatureType as string in SIGNED_MESSAGE_FIELDS)) {
      throw new Error(`Unsupported signature_type: ${JSON.stringify(explicitSignatureType)}`);
    }
    if (signatureTypes.length > 0 && !signatureTypes.includes(explicitSignatureType as string)) {
      throw new Error("signature_type does not match the signature present in act");
    }
    signatureType = explicitSignatureType as string;
  } else if (signatureTypes.length === 1) {
    signatureType = signatureTypes[0];
  } else if (signatureTypes.length > 1) {
    throw new Error("An act cannot claim more than one supported signature type");
  } else {
    signatureType = null;
  }

  if (
    signatureType === null &&
    isWrapper &&
    hasOwn(metadata, "signature") &&
    metadata.signature !== null &&
    metadata.signature !== undefined
  ) {
    throw new Error("A present signature requires a supported signature_type");
  }

  let signature: unknown = null;
  if (signatureType !== null) {
    signature = hasOwn(metadata, "signature")
      ? metadata.signature
      : act[SIGNED_MESSAGE_FIELDS[signatureType]];
    if (signature === null || signature === undefined) {
      throw new Error("A claimed signature_type requires a signature");
    }
  }

  const attribution =
    signatureType === null ? EvidenceAttribution.UNSIGNED : EvidenceAttribution.VERIFIED;
  const explicitAttribution = isWrapper ? metadata.attribution : null;
  if (
    explicitAttribution !== null &&
    explicitAttribution !== undefined &&
    explicitAttribution !== attribution
  ) {
    throw new Error("attribution is inconsistent with the signature claim");
  }

  const sourceProtocol =
    defaultSourceProtocol !== null ? defaultSourceProtocol : field("source_protocol", null);
  const entry: Dict = {
    sequence_number: field("sequence_number", null),
    round_number: field("round_number", null),
    message_type: field("message_type", ""),
    message_id: field("message_id", ""),
    sender_did: field("sender_did", ""),
    timestamp: field("timestamp", ""),
    source_protocol: sourceProtocol,
    act,
    act_hash: hashObject(act),
    sender_verification_method:
      signatureType !== null ? field("sender_verification_method", null) : null,
    signature_type: signatureType,
    signature,
    attribution,
  };
  if (!entry.message_type || !entry.message_id || !entry.sender_did) {
    throw new Error("Evidence acts require message_type, message_id, and sender_did");
  }
  if (!entry.timestamp) {
    throw new Error("Evidence acts require a timestamp");
  }
  return entry;
}

function orderEvidenceActs(acts: Dict[]): Dict[] {
  const indexed = acts.map((entry, index) => ({ entry, index }));
  const allSequenced = acts.every((entry) => Number.isInteger(entry.sequence_number));
  if (allSequenced) {
    indexed.sort(
      (left, right) =>
        ((left.entry.sequence_number as number) - (right.entry.sequence_number as number)) ||
        String(left.entry.timestamp).localeCompare(String(right.entry.timestamp)) ||
        left.index - right.index,
    );
  } else {
    indexed.sort(
      (left, right) =>
        String(left.entry.timestamp).localeCompare(String(right.entry.timestamp)) ||
        (Number.isInteger(left.entry.sequence_number)
          ? (left.entry.sequence_number as number)
          : Number.POSITIVE_INFINITY) -
          (Number.isInteger(right.entry.sequence_number)
            ? (right.entry.sequence_number as number)
            : Number.POSITIVE_INFINITY) ||
        left.index - right.index,
    );
  }
  return indexed.map(({ entry }) => entry);
}

function evidenceActsAreOrdered(acts: Dict[]): boolean {
  const ordered = orderEvidenceActs(acts);
  return acts.every((entry, index) => entry === ordered[index]);
}

function verifyEvidenceAct(
  entry: Dict,
  sessionId: string,
  didResolver: DidResolver,
): { valid: boolean; attribution: unknown } {
  const attribution = entry?.attribution;
  try {
    if (!evidenceActShapeValid(entry)) {
      return { valid: false, attribution };
    }
    const act = entry.act as Dict;
    if (typeof act !== "object" || act === null || Array.isArray(act)) {
      return { valid: false, attribution };
    }
    if (entry.act_hash !== hashObject(act)) {
      return { valid: false, attribution };
    }

    for (const fieldName of [
      "sequence_number",
      "round_number",
      "message_type",
      "message_id",
      "sender_did",
      "timestamp",
    ]) {
      if (hasOwn(act, fieldName) && act[fieldName] !== entry[fieldName]) {
        return { valid: false, attribution };
      }
    }
    if (
      entry.source_protocol === "a2cn" &&
      hasOwn(act, "session_id") &&
      act.session_id !== sessionId
    ) {
      return { valid: false, attribution };
    }

    const signatureType = entry.signature_type;
    const signature = entry.signature;
    const verificationMethod = entry.sender_verification_method;

    if (attribution === EvidenceAttribution.UNSIGNED) {
      if (signatureType !== null || signature !== null || verificationMethod !== null) {
        return { valid: false, attribution };
      }
      if (Object.values(SIGNED_MESSAGE_FIELDS).some((fieldName) => act[fieldName] != null)) {
        return { valid: false, attribution };
      }
      return { valid: true, attribution };
    }

    if (attribution !== EvidenceAttribution.VERIFIED) {
      return { valid: false, attribution };
    }
    if (typeof signatureType !== "string" || !(signatureType in SIGNED_MESSAGE_FIELDS)) {
      return { valid: false, attribution };
    }
    if (typeof signature !== "string" || !signature) {
      return { valid: false, attribution };
    }
    if (typeof verificationMethod !== "string" || !verificationMethod) {
      return { valid: false, attribution };
    }

    const senderDid = entry.sender_did as string;
    if (!verificationMethodControlledBy(verificationMethod, senderDid)) {
      return { valid: false, attribution };
    }
    const actSignatureField = SIGNED_MESSAGE_FIELDS[signatureType];
    if (act[actSignatureField] !== signature) {
      return { valid: false, attribution };
    }
    if (act.sender_verification_method !== verificationMethod) {
      return { valid: false, attribution };
    }

    const expectedPayload = signedActPayloadHash(act, signatureType);
    if (expectedPayload === null) {
      return { valid: false, attribution };
    }
    if (
      !verifySignature(didResolver, {
        did: senderDid,
        verificationMethod,
        signature,
        expectedPayload,
      })
    ) {
      return { valid: false, attribution };
    }
    return { valid: true, attribution };
  } catch {
    return { valid: false, attribution };
  }
}

function signedActPayloadHash(act: Dict, signatureType: string): string | null {
  if (signatureType === EvidenceSignatureType.PROTOCOL_ACT) {
    if (act.message_type !== "offer" && act.message_type !== "counteroffer") {
      return null;
    }
    const protocolAct = {
      protocol_version: "0.2",
      session_id: (act.session_id as string) ?? "",
      round_number: act.round_number,
      sequence_number: act.sequence_number,
      message_type: (act.message_type as string) ?? "",
      sender_did: (act.sender_did as string) ?? "",
      timestamp: (act.timestamp as string) ?? "",
      expires_at: (act.expires_at as string) ?? "",
      terms: (act.terms as Dict) ?? {},
    };
    const expectedHash = hashObject(protocolAct);
    if (act.protocol_act_hash !== expectedHash) {
      return null;
    }
    return expectedHash;
  }

  if (signatureType === EvidenceSignatureType.ACCEPTANCE) {
    if (act.message_type !== "acceptance") {
      return null;
    }
    return hashObject({
      session_id: (act.session_id as string) ?? "",
      round_number: act.round_number,
      sequence_number: act.sequence_number,
      accepted_offer_id: (act.accepted_offer_id as string) ?? "",
      accepted_protocol_act_hash: (act.accepted_protocol_act_hash as string) ?? "",
    });
  }

  return null;
}

function verifySignature(
  didResolver: DidResolver,
  options: {
    did: string;
    verificationMethod: string;
    signature: string;
    expectedPayload: string;
  },
): boolean {
  const didDocument = resolveDidDocument(didResolver, options.did);
  const vm = getVerificationMethod(didDocument, options.verificationMethod);
  const publicKey = getPublicKey(vm);
  return verifyJws(options.signature, publicKey) === options.expectedPayload;
}

function resolveDidDocument(didResolver: DidResolver, did: string): Dict {
  if (typeof didResolver === "function") {
    return didResolver(did);
  }
  return didResolver[did];
}

function verificationMethodControlledBy(verificationMethod: string, did: string): boolean {
  return Boolean(
    verificationMethod &&
      did &&
      (verificationMethod === did || verificationMethod.startsWith(`${did}#`)),
  );
}

function classifyEvidenceLevel(acts: Dict[], outcome: string, parties: Dict): string {
  const partyDids = new Set(
    Object.values(parties)
      .map((party) => (party as Dict).did)
      .filter((did): did is string => typeof did === "string" && did.length > 0),
  );
  const verifiedDids = new Set(
    acts
      .filter(
        (entry) =>
          entry.attribution === EvidenceAttribution.VERIFIED &&
          partyDids.has(entry.sender_did as string),
      )
      .map((entry) => entry.sender_did as string),
  );
  const representedDids = new Set(
    acts
      .filter((entry) => partyDids.has(entry.sender_did as string))
      .map((entry) => entry.sender_did as string),
  );
  const unsignedCount = acts.filter(
    (entry) => entry.attribution === EvidenceAttribution.UNSIGNED,
  ).length;
  const verifiedCount = acts.filter(
    (entry) => entry.attribution === EvidenceAttribution.VERIFIED,
  ).length;

  if (
    outcome === SessionState.COMPLETED &&
    acts.length > 0 &&
    unsignedCount === 0 &&
    partyDids.size > 0 &&
    [...partyDids].every((did) => verifiedDids.has(did))
  ) {
    return EvidenceLevel.BILATERAL;
  }

  const localTerminalFact = outcome !== SessionState.COMPLETED;
  if (
    verifiedCount > 0 &&
    representedDids.size >= 2 &&
    (unsignedCount > 0 || localTerminalFact)
  ) {
    return EvidenceLevel.MIXED;
  }

  return EvidenceLevel.UNILATERAL;
}

function evidenceRecordHashMatches(record: Dict): boolean {
  const claimedHash = record.record_hash;
  if (typeof claimedHash !== "string" || !claimedHash) {
    return false;
  }
  const candidate: Dict = { ...record, record_hash: "", producer_signature: "" };
  return hashObject(candidate) === claimedHash;
}
