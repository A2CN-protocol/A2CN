/**
 * record_version: the values each record verifier accepts, and what producers emit.
 *
 * spec/test-vectors/record-versions.json lists them per artifact, because each
 * versions its own shape. Both suites reseal a valid record of each shape of
 * each artifact with each value and must reach the same verdict. A
 * TransactionRecord verifier accepts "0.3" alone: the version whose final_offer
 * carries the Section 7.3.1 act fields, so the record can be rebound to the
 * offering party's signature (Section 9.5, step 1). A version it knows but
 * cannot rebind is unbound; anything else is unrecognized. A "0.3"
 * SessionEvidenceRecord carries external_commitment_reference and no other
 * version does (Section 9A.2); that artifact is unaffected by the
 * TransactionRecord's rule and keeps its own set.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import { hashObject, privateKeyFromJwk, signJws } from "../src/a2cn/crypto.js";
import {
  RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS,
  generateSessionEvidenceRecord,
  verifySessionEvidenceRecord,
  type GenerateSessionEvidenceOptions,
} from "../src/a2cn/evidence.js";
import {
  ACCEPTED_TRANSACTION_RECORD_VERSIONS,
  KNOWN_TRANSACTION_RECORD_VERSIONS,
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
const TR_VERSIONS = RECORD_VERSIONS.transaction_record as Dict;
const SER_VERSIONS = RECORD_VERSIONS.session_evidence_record as Dict;
const TR_VECTOR = readJson("spec", "test-vectors", "transaction-record-basis.json");
const WITHOUT_BASIS = TR_VECTOR.without_basis as Dict;
const SER_VECTOR = readJson("spec", "test-vectors", "session-evidence-record-parity.json");
const EXTERNAL_CHANNEL_VECTOR = readJson(
  "spec",
  "test-vectors",
  "session-evidence-record-external-channel.json",
);

// The recorded session each TransactionRecord shape came from, for its DID
// documents and its offer chain. A TransactionRecord shape is named by the
// version whose content it carries (Section 9.3).
const SHAPE_VECTOR: Record<string, Dict> = {
  "0.1": WITHOUT_BASIS,
  "0.2": TR_VECTOR,
  "0.3": TR_VECTOR,
};
const TR_EMITTED = (RECORD_VERSIONS.producers_emit as Dict).transaction_record as string;

// The vector behind each SessionEvidenceRecord shape, and the version a producer
// emits for that shape (Section 9A.2).
const SER_SHAPES: Record<string, Dict> = {
  without_external_commitment: SER_VECTOR,
  with_external_commitment: EXTERNAL_CHANNEL_VECTOR,
};
const SER_EMITTED = (RECORD_VERSIONS.producers_emit as Dict).session_evidence_record as Record<
  string,
  string
>;

const TR_CASES: [string, string, Dict, boolean][] = [
  ...(TR_VERSIONS.accepted as string[]).map((version): [string, string, Dict, boolean] => [
    `accepted-${version}`,
    version,
    { record_version: version },
    true,
  ]),
  ...(TR_VERSIONS.unbound as Dict[]).map((unboundCase): [string, string, Dict, boolean] => [
    `unbound-${unboundCase.name as string}`,
    unboundCase.shape as string,
    unboundCase,
    false,
  ]),
  ...(TR_VERSIONS.rejected as Dict[]).flatMap((versionCase) =>
    (TR_VERSIONS.shapes as string[]).map((shape): [string, string, Dict, boolean] => [
      `${versionCase.name as string}-${shape}`,
      shape,
      versionCase,
      false,
    ]),
  ),
];
const SER_CASES: [string, string, Dict, boolean][] = [
  ...(SER_VERSIONS.accepted as Dict[]).map((accepted): [string, string, Dict, boolean] => [
    `accepted-${accepted.record_version as string}-${accepted.shape as string}`,
    accepted.shape as string,
    accepted,
    true,
  ]),
  ...(SER_VERSIONS.cross_shape as Dict[]).map((crossShape): [string, string, Dict, boolean] => [
    crossShape.name as string,
    crossShape.shape as string,
    crossShape,
    false,
  ]),
  ...(SER_VERSIONS.rejected as Dict[]).flatMap((versionCase) =>
    Object.keys(SER_SHAPES).map((shape): [string, string, Dict, boolean] => [
      `${versionCase.name as string}-${shape}`,
      shape,
      versionCase,
      false,
    ]),
  ),
];

// The vector files speak snake_case; the TypeScript option names are mapped
// explicitly so a renamed option cannot be silently ignored.
const OPTION_NAMES: Record<string, keyof GenerateSessionEvidenceOptions> = {
  observed_responder: "observedResponder",
  external_commitment_reference: "externalCommitmentReference",
};

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

/**
 * A valid TransactionRecord whose content fits `version`. "0.3" is what this
 * implementation produces; "0.2" and "0.1" are the records earlier
 * implementations produced for the same two sessions.
 */
function shapedRecord(version: string): Dict {
  if (version === "0.3") {
    return generateTransactionRecord(transactionRecordSession(TR_VECTOR));
  }
  if (version === "0.2") {
    return structuredClone(
      ((TR_VECTOR.expected as Dict).record_version_0_2 as Dict).full_record as Dict,
    );
  }
  return structuredClone((WITHOUT_BASIS.record_version_0_1 as Dict).full_record as Dict);
}

function offerHashes(vector: Dict): string[] {
  return (vector.messages as Dict[])
    .filter((message) => message.message_type === "offer" || message.message_type === "counteroffer")
    .map((message) => message.protocol_act_hash as string);
}

/** The record a SessionEvidenceRecord vector's session produces. */
function sessionEvidenceRecord(vector: Dict): Dict {
  const source = vector.session as Dict;
  const session = new Session({
    session_id: source.session_id as string,
    state: source.state as string,
    current_turn: "none",
    terminal_reason: source.terminal_reason as string,
    terminal_message_id: source.terminal_message_id as string | null,
    session_created_at: source.session_created_at as string,
    state_updated_at: source.state_updated_at as string,
    session_params: source.session_params as Dict,
    initiator_mandate: source.initiator_mandate as Dict,
    responder_mandate: source.responder_mandate as Dict,
    _session_init: source.session_init as Dict,
    _session_ack: source.session_ack as Dict | null,
    _message_log: source.message_log as Dict[],
  });
  const producer = vector.producer as Dict;
  const options: GenerateSessionEvidenceOptions = {
    producerPrivateKey: privateKeyFromJwk(vector.producer_private_jwk as Dict),
    producerDid: producer.did as string,
    producerAgentId: producer.agent_id as string,
    producerVerificationMethod: producer.verification_method as string,
    observedActs: vector.observed_acts as Dict[],
  };
  for (const [snakeName, value] of Object.entries((vector.options ?? {}) as Dict)) {
    const optionName = OPTION_NAMES[snakeName];
    expect(optionName, `unmapped vector option ${snakeName}`).toBeDefined();
    (options as unknown as Record<string, unknown>)[optionName] = structuredClone(value);
  }
  return generateSessionEvidenceRecord(session, options);
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
  "transaction record verifier accepts only the bound version: %s",
  (_name, shape, versionCase, accepted) => {
    const vector = SHAPE_VECTOR[shape];
    const record = withVersion(shapedRecord(shape), versionCase);
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
  (_name, shape, versionCase, accepted) => {
    const vector = SER_SHAPES[shape];
    const record = withVersion(sessionEvidenceRecord(vector), versionCase);
    record.record_hash = "";
    record.producer_signature = "";
    record.record_hash = hashObject(record);
    record.producer_signature = signJws(
      record.record_hash as string,
      privateKeyFromJwk(vector.producer_private_jwk as Dict),
      (vector.producer as Dict).verification_method as string,
    );

    expect(
      verifySessionEvidenceRecord(record, vector.did_documents as Record<string, Dict>),
    ).toBe(accepted);
  },
);

test.each([
  ["with basis", TR_VECTOR],
  ["without basis", WITHOUT_BASIS],
] as [string, Dict][])("producers emit the transaction record version: %s", (_name, vector) => {
  // Every record this implementation produces carries the act fields, so every
  // one is "0.3", whether or not the session fixed a basis (Section 9.3).
  expect(TR_VERSIONS.accepted).toContain(TR_EMITTED);
  expect(generateTransactionRecord(transactionRecordSession(vector)).record_version).toBe(
    TR_EMITTED,
  );
});

test("producers emit the current versions", () => {
  const emitted = RECORD_VERSIONS.producers_emit as Dict;
  const session = transactionRecordSession(TR_VECTOR);

  // Each SessionEvidenceRecord shape has its own version.
  for (const [shape, version] of Object.entries(SER_EMITTED)) {
    expect(sessionEvidenceRecord(SER_SHAPES[shape]).record_version, shape).toBe(version);
  }
  // The AuditLog's content did not change, so its version did not move.
  expect(generateAuditLog(session).log_version).toBe(emitted.audit_log);
  const accepted = (SER_VERSIONS.accepted as Dict[]).map((entry) => entry.record_version);
  for (const version of Object.values(SER_EMITTED)) {
    expect(accepted).toContain(version);
  }
});

test("each verifier accepts exactly the versions the vector accepts", () => {
  // The TransactionRecord accepts only the bound version; the evidence record is
  // unaffected by that rule and keeps its own set.
  expect([...ACCEPTED_TRANSACTION_RECORD_VERSIONS]).toEqual(TR_VERSIONS.accepted);
  expect([...RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS]).toEqual(
    (SER_VERSIONS.accepted as Dict[]).map((entry) => entry.record_version),
  );
  // The older TransactionRecord shapes stay known, because their schemas are
  // published, and every shape the vector names is one this implementation knows.
  expect([...(TR_VERSIONS.shapes as string[])].sort()).toEqual(
    [...KNOWN_TRANSACTION_RECORD_VERSIONS].sort(),
  );
  expect(ACCEPTED_TRANSACTION_RECORD_VERSIONS.length).toBeLessThan(
    KNOWN_TRANSACTION_RECORD_VERSIONS.length,
  );
});

test("each artifact's version set is its own", () => {
  // "0.3" means a different thing to each artifact, and neither set is merged.
  // For the TransactionRecord it is the record whose final_offer carries the act
  // fields, and the only version a verifier accepts (Section 9.3); for the
  // SessionEvidenceRecord it is the record that carries
  // external_commitment_reference, one of three it accepts (Section 9A.2). One
  // artifact's rules never decide the other's.
  expect(TR_VERSIONS.accepted).toEqual(["0.3"]);
  const serAccepted = (SER_VERSIONS.accepted as Dict[]).map((entry) => entry.record_version);
  expect(serAccepted).toEqual(["0.1", "0.2", "0.3"]);
  expect(SER_VERSIONS.rejected).toContainEqual({ name: "next-minor", record_version: "0.4" });
  // The versions the TransactionRecord refuses as unbound are still accepted by
  // the evidence record, which is the point of keeping the two sets apart.
  const unbound = (TR_VERSIONS.unbound as Dict[]).map((entry) => entry.record_version);
  expect(unbound).toContain("0.1");
  expect(unbound).toContain("0.2");
  expect(serAccepted).toContain("0.1");
  expect(serAccepted).toContain("0.2");
});

const SCHEMA_CASES: [string, string][] = [
  ...(TR_VERSIONS.accepted as string[]).map((version): [string, string] => [
    "transaction-record",
    version,
  ]),
  ...(SER_VERSIONS.accepted as Dict[]).map((entry): [string, string] => [
    "session-evidence-record",
    entry.record_version as string,
  ]),
];

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
  const found = schema("transaction-record", TR_EMITTED);
  expect(((found.properties as Dict).record_version as Dict).const).toBe(TR_EMITTED);
  for (const version of Object.values(SER_EMITTED)) {
    const serSchema = schema("session-evidence-record", version);
    expect(((serSchema.properties as Dict).record_version as Dict).const).toBe(version);
  }
});
