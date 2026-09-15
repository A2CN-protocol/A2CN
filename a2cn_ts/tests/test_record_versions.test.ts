/**
 * record_version: the values each record verifier accepts, and what producers emit.
 *
 * spec/test-vectors/record-versions.json lists the values. Both suites reseal a
 * valid TransactionRecord and a valid SessionEvidenceRecord with each one and
 * must reach the same verdict. A value outside the accepted set is rejected,
 * never parsed best-effort (Sections 9.5 and 9A.6).
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import { hashObject, privateKeyFromJwk, signJws } from "../src/a2cn/crypto.js";
import {
  generateSessionEvidenceRecord,
  verifySessionEvidenceRecord,
} from "../src/a2cn/evidence.js";
import {
  generateAuditLog,
  generateTransactionRecord,
  verifyTransactionRecord,
} from "../src/a2cn/record.js";
import { Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import type { Dict } from "../src/a2cn/messages.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function readJson(...parts: string[]): Dict {
  return JSON.parse(readFileSync(join(REPO_ROOT, ...parts), "utf-8")) as Dict;
}

const RECORD_VERSIONS = readJson("spec", "test-vectors", "record-versions.json");
const TR_VECTOR = readJson("spec", "test-vectors", "transaction-record-basis.json");
const SER_VECTOR = readJson("spec", "test-vectors", "session-evidence-record-parity.json");
const SER_KEY = privateKeyFromJwk(SER_VECTOR.producer_private_jwk as Dict);
const SCHEMA = readJson("spec", "schemas", "session-evidence-record.schema.json");

const CASES: [string, Dict, boolean][] = [
  ...(RECORD_VERSIONS.accepted as string[]).map(
    (version): [string, Dict, boolean] => [`accepted-${version}`, { record_version: version }, true],
  ),
  ...(RECORD_VERSIONS.rejected as Dict[]).map(
    (versionCase): [string, Dict, boolean] => [versionCase.name as string, versionCase, false],
  ),
];

/** The record with the case's record_version, or without the key if it has none. */
function withVersion(record: Dict, versionCase: Dict): Dict {
  const copy = structuredClone(record);
  if (Object.prototype.hasOwnProperty.call(versionCase, "record_version")) {
    copy.record_version = structuredClone(versionCase.record_version);
  } else {
    delete copy.record_version;
  }
  return copy;
}

/** Replay transaction-record-basis.json through the state machine to COMPLETED. */
function transactionRecordSession(): Session {
  const manager = new SessionManager();
  for (const [did, didDocument] of Object.entries(
    TR_VECTOR.did_documents as Record<string, Dict>,
  )) {
    manager.registerDidDocument(did, didDocument);
  }
  const sessionAck = TR_VECTOR.session_ack as Dict;
  const session = manager.createSession(
    TR_VECTOR.session_id as string,
    TR_VECTOR.session_init as Dict,
    sessionAck,
    sessionAck.session_created_at as string,
  );
  session.session_timeout_seconds = 86400 * 365 * 100; // the timestamps are in the past
  for (const message of structuredClone(TR_VECTOR.messages as Dict[])) {
    manager.processMessage(session, message);
  }
  expect(session.state).toBe(SessionState.COMPLETED);
  return session;
}

function transactionRecordOfferHashes(): string[] {
  return (TR_VECTOR.messages as Dict[])
    .filter((message) => message.message_type === "offer" || message.message_type === "counteroffer")
    .map((message) => message.protocol_act_hash as string);
}

/** The record session-evidence-record-parity.json produces. */
function sessionEvidenceRecord(): Dict {
  const source = SER_VECTOR.session as Dict;
  const session = new Session({
    session_id: source.session_id as string,
    state: source.state as string,
    current_turn: "none",
    terminal_reason: source.terminal_reason as string,
    terminal_message_id: source.terminal_message_id as null,
    session_created_at: source.session_created_at as string,
    state_updated_at: source.state_updated_at as string,
    session_params: source.session_params as Dict,
    initiator_mandate: source.initiator_mandate as Dict,
    responder_mandate: source.responder_mandate as Dict,
    _session_init: source.session_init as Dict,
    _session_ack: source.session_ack as Dict,
    _message_log: source.message_log as Dict[],
  });
  const producer = SER_VECTOR.producer as Dict;
  return generateSessionEvidenceRecord(session, {
    producerPrivateKey: SER_KEY,
    producerDid: producer.did as string,
    producerAgentId: producer.agent_id as string,
    producerVerificationMethod: producer.verification_method as string,
    observedActs: SER_VECTOR.observed_acts as Dict[],
  });
}

test.each(CASES)(
  "transaction record verifier accepts only recognized versions: %s",
  (_name, versionCase, accepted) => {
    const record = withVersion(generateTransactionRecord(transactionRecordSession()), versionCase);
    record.record_hash = "";
    record.record_hash = hashObject(record);

    expect(
      verifyTransactionRecord(
        record,
        TR_VECTOR.did_documents as Record<string, Dict>,
        transactionRecordOfferHashes(),
      ),
    ).toBe(accepted);
  },
);

test.each(CASES)(
  "session evidence record verifier accepts only recognized versions: %s",
  (_name, versionCase, accepted) => {
    const record = withVersion(sessionEvidenceRecord(), versionCase);
    record.record_hash = "";
    record.producer_signature = "";
    record.record_hash = hashObject(record);
    record.producer_signature = signJws(
      record.record_hash as string,
      SER_KEY,
      (SER_VECTOR.producer as Dict).verification_method as string,
    );

    expect(
      verifySessionEvidenceRecord(record, SER_VECTOR.did_documents as Record<string, Dict>),
    ).toBe(accepted);
  },
);

test("producers emit the current versions", () => {
  const emitted = RECORD_VERSIONS.producers_emit as Dict;
  const accepted = RECORD_VERSIONS.accepted as string[];
  const session = transactionRecordSession();

  expect(generateTransactionRecord(session).record_version).toBe(emitted.transaction_record);
  expect(sessionEvidenceRecord().record_version).toBe(emitted.session_evidence_record);
  // The AuditLog's content did not change, so its version did not move.
  expect(generateAuditLog(session).log_version).toBe(emitted.audit_log);
  expect(accepted).toContain(emitted.transaction_record);
  expect(accepted).toContain(emitted.session_evidence_record);
});

test("the evidence schema names the version producers emit", () => {
  // The schema, the specification, and both implementations use the same value.
  const version = (RECORD_VERSIONS.producers_emit as Dict).session_evidence_record as string;

  expect(SCHEMA.$id).toBe(`https://a2cn.dev/schemas/session-evidence-record/${version}`);
  expect(((SCHEMA.properties as Dict).record_version as Dict).const).toBe(version);
});
