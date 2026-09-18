/**
 * record_version: the values each record verifier accepts, and what producers emit.
 *
 * spec/test-vectors/record-versions.json lists the values. Both suites reseal a
 * valid TransactionRecord of each shape and a valid SessionEvidenceRecord with
 * each one and must reach the same verdict. A TransactionRecord's version follows
 * its shape: a "0.2" record carries a top-level basis and a "0.1" record does not
 * (Section 9.5, step 7). A value outside the accepted set is rejected, never
 * parsed best-effort (Sections 9.5 and 9A.6).
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

// The recorded session behind each TransactionRecord shape, and the version a
// producer emits for that shape (Section 9.3).
const TR_SHAPES: Record<string, Dict> = {
  session_with_basis: TR_VECTOR,
  session_without_basis: TR_VECTOR.without_basis as Dict,
};
const TR_EMITTED = (RECORD_VERSIONS.producers_emit as Dict).transaction_record as Record<
  string,
  string
>;
const TR_SHAPE_FOR_VERSION: Record<string, string> = Object.fromEntries(
  Object.entries(TR_EMITTED).map(([shape, version]) => [version, shape]),
);

const TR_CASES: [string, string, Dict, boolean][] = [
  ...(RECORD_VERSIONS.accepted as string[]).map((version): [string, string, Dict, boolean] => [
    `accepted-${version}`,
    TR_SHAPE_FOR_VERSION[version],
    { record_version: version },
    true,
  ]),
  ...(RECORD_VERSIONS.transaction_record_cross_shape as Dict[]).map(
    (crossShape): [string, string, Dict, boolean] => [
      crossShape.name as string,
      crossShape.shape as string,
      crossShape,
      false,
    ],
  ),
  ...(RECORD_VERSIONS.rejected as Dict[]).flatMap((versionCase) =>
    Object.keys(TR_SHAPES).map((shape): [string, string, Dict, boolean] => [
      `${versionCase.name as string}-${shape}`,
      shape,
      versionCase,
      false,
    ]),
  ),
];
const SER_CASES: [string, Dict, boolean][] = [
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

/** Replay a session transaction-record-basis.json records to COMPLETED. */
function transactionRecordSession(vector: Dict): Session {
  const manager = new SessionManager();
  for (const [did, didDocument] of Object.entries(vector.did_documents as Record<string, Dict>)) {
    manager.registerDidDocument(did, didDocument);
  }
  const sessionAck = vector.session_ack as Dict;
  const session = manager.createSession(
    vector.session_id as string,
    vector.session_init as Dict,
    sessionAck,
    sessionAck.session_created_at as string,
  );
  session.session_timeout_seconds = 86400 * 365 * 100; // the timestamps are in the past
  for (const message of structuredClone(vector.messages as Dict[])) {
    manager.processMessage(session, message);
  }
  expect(session.state).toBe(SessionState.COMPLETED);
  return session;
}

function offerHashes(vector: Dict): string[] {
  return (vector.messages as Dict[])
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

/**
 * An artifact's unversioned schema file is its "0.1" schema; each later version
 * is published beside it as <artifact>-<version>.schema.json.
 */
function schema(artifact: string, version: string): Dict {
  const name = version === "0.1" ? `${artifact}.schema.json` : `${artifact}-${version}.schema.json`;
  return readJson("spec", "schemas", name);
}

test.each(TR_CASES)(
  "transaction record verifier accepts only recognized versions: %s",
  (_name, shape, versionCase, accepted) => {
    const vector = TR_SHAPES[shape];
    const record = withVersion(
      generateTransactionRecord(transactionRecordSession(vector)),
      versionCase,
    );
    record.record_hash = "";
    record.record_hash = hashObject(record);

    expect(
      verifyTransactionRecord(
        record,
        vector.did_documents as Record<string, Dict>,
        offerHashes(vector),
      ),
    ).toBe(accepted);
  },
);

test.each(SER_CASES)(
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

  // Each accepted TransactionRecord version is the one producers emit for one shape.
  expect(Object.values(TR_EMITTED).sort()).toEqual([...accepted].sort());
  let session: Session | undefined;
  for (const [shape, version] of Object.entries(TR_EMITTED)) {
    session = transactionRecordSession(TR_SHAPES[shape]);
    expect(generateTransactionRecord(session).record_version, shape).toBe(version);
  }
  expect(sessionEvidenceRecord().record_version).toBe(emitted.session_evidence_record);
  // The AuditLog's content did not change, so its version did not move.
  expect(generateAuditLog(session as Session).log_version).toBe(emitted.audit_log);
  expect(accepted).toContain(emitted.session_evidence_record);
});

const SCHEMA_CASES: [string, string][] = ["transaction-record", "session-evidence-record"].flatMap(
  (artifact) => (RECORD_VERSIONS.accepted as string[]).map((version): [string, string] => [artifact, version]),
);

test.each(SCHEMA_CASES)(
  "every accepted version has a schema that names it: %s %s",
  (artifact, version) => {
    // A verifier that accepts a version has that version's schema beside the others.
    const found = schema(artifact, version);

    expect(found.$id).toBe(`https://a2cn.dev/schemas/${artifact}/${version}`);
    expect(((found.properties as Dict).record_version as Dict).const).toBe(version);
  },
);

test("the schemas name the versions producers emit", () => {
  // The schema, the specification, and both implementations use the same value.
  const emitted = RECORD_VERSIONS.producers_emit as Dict;

  for (const version of Object.values(TR_EMITTED)) {
    const found = schema("transaction-record", version);
    expect(((found.properties as Dict).record_version as Dict).const).toBe(version);
  }
  const version = emitted.session_evidence_record as string;
  const found = schema("session-evidence-record", version);
  expect(((found.properties as Dict).record_version as Dict).const).toBe(version);
});
