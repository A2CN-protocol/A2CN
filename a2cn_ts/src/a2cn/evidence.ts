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

export const OUTCOME_HALTED_BY_CONTROLS = "HALTED_BY_CONTROLS";

export const MONEY_BASIS_LABELS = new Set<string>([
  "net",
  "gross",
  "per_unit",
  "line_total",
  "unspecified",
]);

// HALTED_BY_CONTROLS is an evidence-record outcome only. It is deliberately not a
// SessionState: adding one would be a wire change, and 0.2 is frozen.
const EVIDENCE_TERMINAL_OUTCOMES = new Set<string>([
  ...SessionState.TERMINAL,
  OUTCOME_HALTED_BY_CONTROLS,
]);

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
const RECORD_OPTIONAL_FIELDS = new Set(["extensions"]);
const ACT_OPTIONAL_FIELDS = new Set(["money_basis"]);
const TERMINAL_FIELDS = new Set(["outcome", "reason", "message_id", "timestamp"]);
const TERMINAL_OPTIONAL_FIELDS = new Set(["money_basis"]);
const PARTY_FIELDS = new Set([
  "organization_name",
  "did",
  "agent_id",
  "verification_method",
  "mandate_type",
]);
const OBSERVED_PARTY_FIELDS = new Set([
  "identity_source",
  "did_declared",
  "a2cn_endpoint_declared",
  "mandate_declared",
]);
const OBSERVED_PARTY_OPTIONAL_FIELDS = new Set([
  "organization_name",
  "observed_credential",
]);
const OBSERVED_PARTY_MARKERS = [
  "did_declared",
  "a2cn_endpoint_declared",
  "mandate_declared",
];
// raw_amounts is deliberately absent from the required set so the fail-closed rule
// owns it by name: a total claimed with no raw data behind it is rejected by a
// branch that says so, not incidentally by a field-set check.
const MONEY_BASIS_FIELDS = new Set([
  "currency",
  "minor_unit_exponent",
  "basis",
  "normalized_total_minor",
]);
const MONEY_BASIS_OPTIONAL_FIELDS = new Set(["raw_amounts"]);
const HASH_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const EXTENSION_NAMESPACE_PATTERN = /^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$/;
const CURRENCY_PATTERN = /^[A-Z]{3}$/;
const DECIMAL_AMOUNT_PATTERN = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?$/;
const RFC3339_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|([+-])(\d{2}):(\d{2}))$/;

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
  /** A counterparty with no A2CN identity. A producer assertion; no DID is fabricated. */
  observedResponder?: Dict | null;
  /** May only assert HALTED_BY_CONTROLS, for a run the producer's own controls stopped. */
  terminalOutcome?: string | null;
  terminalReason?: string | null;
  terminalMoneyBasis?: Dict | null;
  extensions?: Dict | null;
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

  let outcome = session.state;
  let reason = session.terminal_reason ?? null;
  const terminalOutcome = options.terminalOutcome ?? null;
  if (terminalOutcome !== null) {
    if (terminalOutcome !== OUTCOME_HALTED_BY_CONTROLS) {
      throw new Error(`terminalOutcome may only assert ${OUTCOME_HALTED_BY_CONTROLS}`);
    }
    if (session.state === SessionState.COMPLETED) {
      throw new Error("A COMPLETED session cannot be relabelled as halted");
    }
    outcome = terminalOutcome;
  }
  const terminalReason = options.terminalReason ?? null;
  if (terminalReason !== null) {
    if (terminalOutcome === null) {
      throw new Error("terminalReason requires terminalOutcome");
    }
    if (typeof terminalReason !== "string" || !terminalReason) {
      throw new Error("terminalReason must be a non-empty string");
    }
    reason = terminalReason;
  }

  const parties = partyMetadata(session, options.observedResponder ?? null);
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
  const evidenceLevel = classifyEvidenceLevel(orderedActs, outcome, parties);
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
      outcome,
      reason,
      message_id: session.terminal_message_id || null,
      timestamp: terminalTimestamp,
    },
    transaction_record_hash: transactionRecordHash,
    acts: orderedActs,
    act_chain_hash: actChainHash,
    evidence_level: evidenceLevel,
    record_hash: "",
    producer_signature: "",
  };
  if (options.terminalMoneyBasis != null) {
    (record.terminal as Dict).money_basis = structuredClone(options.terminalMoneyBasis);
  }
  if (options.extensions != null) {
    record.extensions = validatedExtensions(options.extensions);
  }

  // Refuse to seal a claim the verifier would reject. The generator and the
  // verifier run the same two rules so a producer cannot emit a record that only
  // fails once it is somebody else's problem.
  if (!moneyBasisClaimsVerify(record)) {
    throw new Error("money_basis does not recompute to the claimed and signed totals");
  }
  if (!observedResponderRulesHold(record)) {
    throw new Error(
      "An observed responder requires unsigned counterparty acts and unilateral evidence",
    );
  }

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
    if (!EVIDENCE_TERMINAL_OUTCOMES.has(outcome)) {
      return assessment;
    }
    if (record.generated_at !== terminal.timestamp) {
      return assessment;
    }
    timestampOrderKey(record.generated_at);
    timestampOrderKey(terminal.timestamp);
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
    if (!moneyBasisClaimsVerify(record)) {
      return assessment;
    }
    if (!observedResponderRulesHold(record)) {
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

function partyMetadata(session: EvidenceSession, observedResponder: Dict | null): Dict {
  const sessionInit = session._session_init ?? {};
  const sessionAck = session._session_ack ?? {};
  const initiatorInfo = metadataObject(sessionInit.initiator, "initiator");
  const responderInfo = metadataObject(sessionAck.responder, "responder");
  const initiatorMandate = metadataObject(
    session.initiator_mandate,
    "initiator_mandate",
  );
  const responderMandate = metadataObject(
    session.responder_mandate,
    "responder_mandate",
  );

  return {
    initiator: {
      organization_name: metadataString(initiatorInfo, "organization_name"),
      did: metadataString(initiatorInfo, "did"),
      agent_id: metadataString(initiatorInfo, "agent_id"),
      verification_method: metadataString(initiatorInfo, "verification_method"),
      mandate_type: metadataString(initiatorMandate, "mandate_type"),
    },
    responder:
      observedResponder !== null
        ? observedPartyMetadata(responderInfo, responderMandate, observedResponder)
        : {
            organization_name: metadataString(responderInfo, "organization_name"),
            did: metadataString(responderInfo, "did"),
            agent_id: metadataString(responderInfo, "agent_id"),
            verification_method: metadataString(responderInfo, "verification_method"),
            mandate_type: metadataString(responderMandate, "mandate_type"),
          },
  };
}

/**
 * Assemble an identity-light responder from what the caller supplies.
 *
 * Every field is a producer assertion. No DID is derived, defaulted, or
 * fabricated here, and the session must not already carry the A2CN identity this
 * descriptor claims is absent.
 */
function observedPartyMetadata(
  responderInfo: Dict,
  responderMandate: Dict,
  observedResponder: Dict,
): Dict {
  if (
    typeof observedResponder !== "object" ||
    observedResponder === null ||
    Array.isArray(observedResponder)
  ) {
    throw new Error("observedResponder must be an object");
  }
  for (const [fieldName, marker] of [
    ["did", "a DID"],
    ["endpoint", "an A2CN endpoint"],
    ["verification_method", "a verification method"],
  ]) {
    const declared = responderInfo[fieldName];
    if (typeof declared === "string" && declared) {
      throw new Error(`Responder declared ${marker}; it is not an observed party`);
    }
  }
  if (responderMandate.mandate_type) {
    throw new Error("Responder declared a mandate; it is not an observed party");
  }

  const identitySource = observedResponder.identity_source;
  if (typeof identitySource !== "string" || !identitySource) {
    throw new Error("observedResponder requires a non-empty identity_source");
  }

  const party: Dict = {
    identity_source: identitySource,
    did_declared: false,
    a2cn_endpoint_declared: false,
    mandate_declared: false,
  };
  const organizationName = observedResponder.organization_name;
  if (organizationName != null) {
    if (typeof organizationName !== "string") {
      throw new Error("observedResponder organization_name must be a string");
    }
    party.organization_name = organizationName;
  }
  const credential = observedResponder.observed_credential;
  if (credential != null) {
    if (
      typeof credential !== "object" ||
      Array.isArray(credential) ||
      !hasFields(credential as Dict, new Set(["type", "digest"]))
    ) {
      throw new Error("observed_credential requires exactly type and digest");
    }
    const credentialType = (credential as Dict).type;
    const digest = (credential as Dict).digest;
    if (typeof credentialType !== "string" || !credentialType) {
      throw new Error("observed_credential type must be a non-empty string");
    }
    if (typeof digest !== "string" || !HASH_PATTERN.test(digest)) {
      throw new Error("observed_credential digest must be a base64url SHA-256");
    }
    party.observed_credential = { type: credentialType, digest };
  }
  return party;
}

/** Namespaced producer extensions. Never interpreted, only namespaced. */
function validatedExtensions(extensions: Dict): Dict {
  if (typeof extensions !== "object" || extensions === null || Array.isArray(extensions)) {
    throw new Error("extensions must be an object");
  }
  for (const name of Object.keys(extensions)) {
    if (!EXTENSION_NAMESPACE_PATTERN.test(name)) {
      throw new Error(`extensions keys must be namespaced: ${JSON.stringify(name)}`);
    }
  }
  return structuredClone(extensions);
}

function metadataObject(value: unknown, fieldName: string): Dict {
  if (value === undefined) {
    return {};
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  return value as Dict;
}

function metadataString(object: Dict, fieldName: string): string {
  if (!hasOwn(object, fieldName)) {
    return "";
  }
  if (typeof object[fieldName] !== "string") {
    throw new Error(`Party ${fieldName} must be a string`);
  }
  return object[fieldName] as string;
}

function hasFields(object: Dict, required: Set<string>, optional?: Set<string>): boolean {
  if (typeof object !== "object" || object === null || Array.isArray(object)) {
    return false;
  }
  const fields = Object.keys(object);
  if (!fields.every((field) => required.has(field) || optional?.has(field) === true)) {
    return false;
  }
  return [...required].every((field) => fields.includes(field));
}

function evidenceRecordShapeValid(record: Dict): boolean {
  if (!hasFields(record, RECORD_FIELDS, RECORD_OPTIONAL_FIELDS)) {
    return false;
  }
  if (hasOwn(record, "extensions")) {
    const extensions = record.extensions;
    if (typeof extensions !== "object" || extensions === null || Array.isArray(extensions)) {
      return false;
    }
    if (!Object.keys(extensions).every((name) => EXTENSION_NAMESPACE_PATTERN.test(name))) {
      return false;
    }
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
  if (!hasFields(producer, new Set(["did", "agent_id", "verification_method"]))) {
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
  if (!hasFields(parties, new Set(["initiator", "responder"]))) {
    return false;
  }
  // The producer is a DID-bearing party, so the initiator side stays strict.
  // Only the responder may be identity-light.
  if (!fullPartyShapeValid(parties.initiator)) {
    return false;
  }
  if (
    !fullPartyShapeValid(parties.responder) &&
    !observedPartyShapeValid(parties.responder)
  ) {
    return false;
  }

  const terminal = record.terminal as Dict;
  if (!hasFields(terminal, TERMINAL_FIELDS, TERMINAL_OPTIONAL_FIELDS)) {
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

function fullPartyShapeValid(party: unknown): boolean {
  if (!hasFields(party as Dict, PARTY_FIELDS)) {
    return false;
  }
  const value = party as Dict;
  if ([...PARTY_FIELDS].some((field) => typeof value[field] !== "string")) {
    return false;
  }
  return (value.did as string).startsWith("did:") && Boolean(value.verification_method);
}

/**
 * Shape of an identity-light counterparty descriptor.
 *
 * This checks structure and the explicit negative markers, and nothing else. A
 * verifier MUST NOT resolve `identity_source`, look it up in any registry, or
 * apply per-type validation to it: doing so would imply an authentication A2CN
 * did not perform. There is no whitelist here by design.
 */
function observedPartyShapeValid(party: unknown): boolean {
  if (!hasFields(party as Dict, OBSERVED_PARTY_FIELDS, OBSERVED_PARTY_OPTIONAL_FIELDS)) {
    return false;
  }
  const value = party as Dict;
  if (typeof value.identity_source !== "string" || !value.identity_source) {
    return false;
  }
  if (OBSERVED_PARTY_MARKERS.some((marker) => value[marker] !== false)) {
    return false;
  }
  if (hasOwn(value, "organization_name") && typeof value.organization_name !== "string") {
    return false;
  }
  if (hasOwn(value, "observed_credential")) {
    const credential = value.observed_credential as Dict;
    if (!hasFields(credential, new Set(["type", "digest"]))) {
      return false;
    }
    if (typeof credential.type !== "string" || !credential.type) {
      return false;
    }
    if (typeof credential.digest !== "string" || !HASH_PATTERN.test(credential.digest)) {
      return false;
    }
  }
  return true;
}

/**
 * Couple an identity-light responder to unsigned acts and unilateral evidence.
 *
 * A2CN authenticates DID-bearing parties. When the responder holds no DID there
 * is no key any counterparty act could be checked against, so the initiator is
 * the only party that may carry a verified signature in such a record. A
 * responder claiming `verified_signature` is rejected outright, not downgraded.
 */
function observedResponderRulesHold(record: Dict): boolean {
  const parties = record.parties as Dict;
  if (typeof parties !== "object" || parties === null) {
    return false;
  }
  if (!observedPartyShapeValid(parties.responder)) {
    return true;
  }

  const initiator = parties.initiator as Dict;
  if (typeof initiator !== "object" || initiator === null) {
    return false;
  }
  const initiatorDid = initiator.did;
  const acts = record.acts;
  if (!Array.isArray(acts)) {
    return false;
  }
  for (const entry of acts as Dict[]) {
    if (typeof entry !== "object" || entry === null) {
      return false;
    }
    if (entry.attribution !== EvidenceAttribution.VERIFIED) {
      continue;
    }
    if (entry.sender_did !== initiatorDid) {
      return false;
    }
  }
  // Asserted explicitly rather than inherited from the classifier, so that a
  // future change to classification cannot quietly promote these records.
  return record.evidence_level === EvidenceLevel.UNILATERAL;
}

/**
 * Scale one major-unit decimal string to minor units, exactly.
 *
 * Returns null for anything finer than the stated exponent. Rounding here would
 * silently alter money, so a sub-minor amount is refused instead.
 */
function decimalToMinor(amount: unknown, exponent: number): bigint | null {
  if (typeof amount !== "string") {
    return null;
  }
  const match = DECIMAL_AMOUNT_PATTERN.exec(amount);
  if (match === null) {
    return null;
  }
  const fraction = match[3] ?? "";
  if (fraction.length > exponent) {
    return null;
  }
  const value = BigInt(match[2] + fraction.padEnd(exponent, "0"));
  return match[1] === "-" ? -value : value;
}

/**
 * Recompute the unit normalization only, and compare it with both totals.
 *
 * `basis` is a CHECKED LABEL. A verifier MUST NOT convert between net and gross:
 * that is a tax calculation, not a normalization, and performing it silently
 * corrupts money. The arithmetic below is identical for every label.
 */
function moneyBasisRecomputes(
  moneyBasis: unknown,
  expectedTotalMinor: number,
  expectedCurrency: string,
): boolean {
  if (!hasFields(moneyBasis as Dict, MONEY_BASIS_FIELDS, MONEY_BASIS_OPTIONAL_FIELDS)) {
    return false;
  }
  const value = moneyBasis as Dict;
  if (typeof value.basis !== "string" || !MONEY_BASIS_LABELS.has(value.basis)) {
    return false;
  }
  if (typeof value.currency !== "string" || !CURRENCY_PATTERN.test(value.currency)) {
    return false;
  }
  if (value.currency !== expectedCurrency) {
    return false;
  }
  const exponent = value.minor_unit_exponent;
  if (!Number.isInteger(exponent) || (exponent as number) < 0 || (exponent as number) > 4) {
    return false;
  }
  const claimed = value.normalized_total_minor;
  if (!Number.isSafeInteger(claimed)) {
    return false;
  }

  // FAIL-CLOSED: a total claimed with no raw amounts behind it is unverifiable,
  // and an unverifiable claim must never read as a verified one.
  const rawAmounts = value.raw_amounts;
  if (!Array.isArray(rawAmounts) || rawAmounts.length === 0) {
    return false;
  }

  let total = 0n;
  for (const amount of rawAmounts) {
    const minor = decimalToMinor(amount, exponent as number);
    if (minor === null) {
      return false;
    }
    total += minor;
  }
  return total === BigInt(claimed as number) && total === BigInt(expectedTotalMinor);
}

/** Bind a money_basis to the total inside the act it describes. */
function moneyBasisBindsToAct(entry: unknown, moneyBasis: unknown): boolean {
  if (typeof entry !== "object" || entry === null) {
    return false;
  }
  const act = (entry as Dict).act;
  if (typeof act !== "object" || act === null || Array.isArray(act)) {
    return false;
  }
  const terms = (act as Dict).terms;
  if (typeof terms !== "object" || terms === null || Array.isArray(terms)) {
    return false;
  }
  const total = (terms as Dict).total_value;
  if (!Number.isSafeInteger(total)) {
    return false;
  }
  const currency = (terms as Dict).currency;
  if (typeof currency !== "string") {
    return false;
  }
  return moneyBasisRecomputes(moneyBasis, total as number, currency);
}

/** Every money_basis in the record recomputes, or the record is rejected. */
function moneyBasisClaimsVerify(record: Dict): boolean {
  const acts = record.acts;
  if (!Array.isArray(acts)) {
    return false;
  }
  for (const entry of acts as Dict[]) {
    if (typeof entry === "object" && entry !== null && hasOwn(entry, "money_basis")) {
      if (!moneyBasisBindsToAct(entry, entry.money_basis)) {
        return false;
      }
    }
  }

  const terminal = record.terminal as Dict;
  if (typeof terminal !== "object" || terminal === null || !hasOwn(terminal, "money_basis")) {
    return true;
  }
  // A terminal money_basis describes the terminal quote, so it must name the act
  // that carries it. An unresolvable reference is refused, not ignored.
  const messageId = terminal.message_id;
  if (typeof messageId !== "string" || !messageId) {
    return false;
  }
  const quoted = (acts as Dict[]).filter(
    (entry) => typeof entry === "object" && entry !== null && entry.message_id === messageId,
  );
  if (quoted.length !== 1) {
    return false;
  }
  return moneyBasisBindsToAct(quoted[0], terminal.money_basis);
}

function evidenceActShapeValid(entry: Dict): boolean {
  if (!hasFields(entry, ACT_FIELDS, ACT_OPTIONAL_FIELDS)) {
    return false;
  }
  for (const field of ["sequence_number", "round_number"]) {
    const value = entry[field];
    if (value !== null && (!Number.isInteger(value) || (value as number) < 1)) {
      return false;
    }
  }
  for (const field of ["message_type", "act_hash"]) {
    if (typeof entry[field] !== "string" || !(entry[field] as string)) {
      return false;
    }
  }
  const senderDid = entry.sender_did;
  if (senderDid === null) {
    // A sender with no DID is only representable as an unsigned observation.
    if (entry.attribution !== EvidenceAttribution.UNSIGNED) {
      return false;
    }
  } else if (typeof senderDid !== "string" || !senderDid.startsWith("did:")) {
    return false;
  }
  for (const field of ["message_id", "timestamp"]) {
    const value = entry[field];
    if (value !== null && (typeof value !== "string" || !value)) {
      return false;
    }
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
  const optionalString = (name: string): string | null => {
    const value = field(name, null);
    return typeof value === "string" && value.length > 0 ? value : null;
  };
  const entry: Dict = {
    sequence_number: field("sequence_number", null),
    round_number: field("round_number", null),
    message_type: field("message_type", ""),
    message_id: optionalString("message_id"),
    sender_did: field("sender_did", ""),
    timestamp: optionalString("timestamp"),
    source_protocol: sourceProtocol,
    act,
    act_hash: hashObject(act),
    sender_verification_method:
      signatureType !== null ? field("sender_verification_method", null) : null,
    signature_type: signatureType,
    signature,
    attribution,
  };
  if (isWrapper && metadata.money_basis != null) {
    // A producer annotation ABOUT the act, never inside it: `act` stays the
    // verbatim observed bytes that act_hash protects.
    entry.money_basis = structuredClone(metadata.money_basis);
  }
  if (typeof entry.message_type !== "string" || !entry.message_type) {
    throw new Error("Evidence acts require message_type");
  }
  if (entry.sender_did === null) {
    // An identity-light sender is representable, but only unsigned. A DID is
    // never invented to fill this in.
    if (signatureType !== null) {
      throw new Error("A signed act requires sender_did");
    }
  } else if (typeof entry.sender_did !== "string" || !entry.sender_did) {
    throw new Error("Evidence acts require sender_did");
  }
  return entry;
}

function orderEvidenceActs(acts: Dict[]): Dict[] {
  const indexed = acts.map((entry, index) => ({
    entry,
    index,
    timestampKey: entry.timestamp === null ? null : timestampOrderKey(entry.timestamp),
  }));
  const allSequenced = acts.every((entry) => Number.isInteger(entry.sequence_number));
  if (allSequenced) {
    indexed.sort(
      (left, right) =>
        ((left.entry.sequence_number as number) - (right.entry.sequence_number as number)) ||
        left.index - right.index,
    );
  } else if (indexed.every(({ timestampKey }) => timestampKey !== null)) {
    indexed.sort(
      (left, right) =>
        compareTimestampOrderKeys(left.timestampKey!, right.timestampKey!) ||
        compareOptionalSequence(left.entry.sequence_number, right.entry.sequence_number) ||
        left.index - right.index,
    );
  }
  return indexed.map(({ entry }) => entry);
}

interface TimestampOrderKey {
  epochSeconds: number;
  fraction: string;
}

function timestampOrderKey(timestamp: unknown): TimestampOrderKey {
  if (typeof timestamp !== "string") {
    throw new Error("Evidence act timestamp must be an RFC 3339 string");
  }
  const match = RFC3339_PATTERN.exec(timestamp);
  if (match === null) {
    throw new Error("Evidence act timestamp must be an RFC 3339 string");
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (year < 1) {
    throw new Error("Evidence act timestamp must be an RFC 3339 string");
  }
  if (second > 59) {
    throw new Error("Evidence act timestamp leap seconds are not supported");
  }

  const localTime = new Date(0);
  localTime.setUTCHours(0, 0, 0, 0);
  localTime.setUTCFullYear(year, month - 1, day);
  localTime.setUTCHours(hour, minute, second, 0);
  if (
    localTime.getUTCFullYear() !== year ||
    localTime.getUTCMonth() !== month - 1 ||
    localTime.getUTCDate() !== day ||
    localTime.getUTCHours() !== hour ||
    localTime.getUTCMinutes() !== minute ||
    localTime.getUTCSeconds() !== second
  ) {
    throw new Error("Evidence act timestamp must be an RFC 3339 string");
  }

  let epochSeconds = localTime.getTime() / 1_000;
  const offsetSign = match[9];
  if (offsetSign !== undefined) {
    const offsetHours = Number(match[10]);
    const offsetMinutes = Number(match[11]);
    if (offsetHours > 23 || offsetMinutes > 59) {
      throw new Error("Evidence act timestamp has an invalid UTC offset");
    }
    const offsetSeconds = offsetHours * 3_600 + offsetMinutes * 60;
    epochSeconds += offsetSign === "+" ? -offsetSeconds : offsetSeconds;
  }

  return {
    epochSeconds,
    fraction: (match[7] ?? "").replace(/0+$/, ""),
  };
}

function compareTimestampOrderKeys(
  leftKey: TimestampOrderKey,
  rightKey: TimestampOrderKey,
): number {
  if (leftKey.epochSeconds !== rightKey.epochSeconds) {
    return leftKey.epochSeconds < rightKey.epochSeconds ? -1 : 1;
  }
  const fractionLength = Math.max(leftKey.fraction.length, rightKey.fraction.length);
  const leftFraction = leftKey.fraction.padEnd(fractionLength, "0");
  const rightFraction = rightKey.fraction.padEnd(fractionLength, "0");
  if (leftFraction === rightFraction) {
    return 0;
  }
  return leftFraction < rightFraction ? -1 : 1;
}

function compareOptionalSequence(left: unknown, right: unknown): number {
  const leftSequence = Number.isInteger(left) ? (left as number) : null;
  const rightSequence = Number.isInteger(right) ? (right as number) : null;
  if (leftSequence !== null && rightSequence !== null) {
    return leftSequence - rightSequence;
  }
  if (leftSequence !== null) {
    return -1;
  }
  return rightSequence !== null ? 1 : 0;
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
      let actValue = hasOwn(act, fieldName) ? act[fieldName] : null;
      if (
        ["message_id", "timestamp"].includes(fieldName) &&
        (typeof actValue !== "string" || !actValue)
      ) {
        actValue = null;
      }
      if (hasOwn(act, fieldName) && actValue !== entry[fieldName]) {
        return { valid: false, attribution };
      }
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
    if (act.session_id !== sessionId) {
      return { valid: false, attribution };
    }
    if (typeof signature !== "string" || !signature) {
      return { valid: false, attribution };
    }
    if (typeof verificationMethod !== "string" || !verificationMethod) {
      return { valid: false, attribution };
    }

    const senderDid = entry.sender_did as string;
    if (typeof senderDid !== "string" || !senderDid) {
      return { valid: false, attribution };
    }
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
    if (
      ![
        "session_id",
        "message_type",
        "sender_did",
        "timestamp",
        "expires_at",
      ].every((fieldName) => isNonemptyString(act[fieldName]))
    ) {
      return null;
    }
    if (
      !["round_number", "sequence_number"].every((fieldName) =>
        isPositiveInteger(act[fieldName]),
      )
    ) {
      return null;
    }
    if (typeof act.terms !== "object" || act.terms === null || Array.isArray(act.terms)) {
      return null;
    }
    const protocolAct = {
      protocol_version: "0.2",
      session_id: act.session_id,
      round_number: act.round_number,
      sequence_number: act.sequence_number,
      message_type: act.message_type,
      sender_did: act.sender_did,
      timestamp: act.timestamp,
      expires_at: act.expires_at,
      terms: act.terms,
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
    if (
      !["session_id", "accepted_offer_id", "accepted_protocol_act_hash"].every(
        (fieldName) => isNonemptyString(act[fieldName]),
      ) ||
      !HASH_PATTERN.test(act.accepted_protocol_act_hash as string)
    ) {
      return null;
    }
    if (
      !["round_number", "sequence_number"].every((fieldName) =>
        isPositiveInteger(act[fieldName]),
      )
    ) {
      return null;
    }
    return hashObject({
      session_id: act.session_id,
      round_number: act.round_number,
      sequence_number: act.sequence_number,
      accepted_offer_id: act.accepted_offer_id,
      accepted_protocol_act_hash: act.accepted_protocol_act_hash,
    });
  }

  return null;
}

function isNonemptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 1;
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
  const verifiedPartyCount = acts.filter(
    (entry) =>
      entry.attribution === EvidenceAttribution.VERIFIED &&
      partyDids.has(entry.sender_did as string),
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
    verifiedPartyCount > 0 &&
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
