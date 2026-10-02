/**
 * The published record schemas, held to the implementation and the records it generates.
 *
 * A record artifact's unversioned schema file describes its "0.1" version; each
 * later version is published beside it as <name>-<version>.schema.json, and a
 * published schema file is never rewritten (Section 17). A TransactionRecord's
 * version follows its shape: the "0.1" schema permits no top-level basis, the
 * "0.2" schema requires it, and the "0.3" schema requires the Section 7.3.1 act
 * fields in final_offer and carries basis exactly when agreed_terms does
 * (Sections 9.3 and 9.5). The "0.1" SessionEvidenceRecord schema is the file
 * release 0.3.0 published, which predates Sections 9A.8 to 9A.11; those arrived
 * in "0.2" (Section 9A.2). No JSON Schema validator is a dependency here, so
 * this reads the schemas directly: their versions, fields, closed objects, field
 * types, and basis enums must agree with the implementation's constants and the
 * records it generates. The Python suite runs a full Draft 2020-12 validation
 * over the same records.
 */

import { createHash, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import {
  canonicalize,
  hashBytes,
  hashObject,
  privateKeyFromJwk,
  signJws,
} from "../src/a2cn/crypto.js";
import {
  RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS,
  SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
  SESSION_EVIDENCE_RECORD_VERSION_WITHOUT_EXTERNAL_COMMITMENT,
  SESSION_EVIDENCE_RECORD_VERSION_WITH_EXTERNAL_COMMITMENT,
  generateSessionEvidenceRecord,
  verifySessionEvidenceRecord,
  type GenerateSessionEvidenceOptions,
} from "../src/a2cn/evidence.js";
import {
  ACCEPTED_TRANSACTION_RECORD_VERSIONS,
  FINAL_OFFER_ACT_FIELDS,
  KNOWN_TRANSACTION_RECORD_VERSIONS,
  TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,
  TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE,
  TRANSACTION_RECORD_VERSION_WITHOUT_BASIS,
  TRANSACTION_RECORD_VERSION_WITH_BASIS,
  generateTransactionRecord,
} from "../src/a2cn/record.js";
import { SESSION_BASES, Session, SessionManager, SessionState } from "../src/a2cn/session.js";
import type { Dict } from "../src/a2cn/messages.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function readJson(...parts: string[]): Dict {
  return JSON.parse(readFileSync(join(REPO_ROOT, ...parts), "utf-8")) as Dict;
}

function schema(file: string): Dict {
  return readJson("spec", "schemas", file);
}

const TR_VECTOR = readJson("spec", "test-vectors", "transaction-record-basis.json");
const WITHOUT_BASIS = TR_VECTOR.without_basis as Dict;
const EXPECTED_0_2 = (TR_VECTOR.expected as Dict).record_version_0_2 as Dict;
const EXPECTED_0_3 = (TR_VECTOR.expected as Dict).record_version_0_3 as Dict;
// A session whose round-1 offer omits expires_at, so its signed act, and the
// record, carry "". A conformant producer can emit this, so the schema takes it.
const EMPTY_EXPIRES_AT = TR_VECTOR.empty_expires_at as Dict;
const PARITY_VECTORS = readJson("a2cn_ts", "parity", "vectors.json");

const TR_0_1 = "transaction-record.schema.json";
const TR_0_2 = "transaction-record-0.2.schema.json";
const TR_0_3 = "transaction-record-0.3.schema.json";
const TR_0_4 = "transaction-record-0.4.schema.json";
const TR_SCHEMAS = [TR_0_1, TR_0_2, TR_0_3, TR_0_4];
// Every other version's schema, which the record of one version must not fit.
const OTHER_VERSIONS: Record<string, string[]> = Object.fromEntries(
  TR_SCHEMAS.map((file) => [file, TR_SCHEMAS.filter((other) => other !== file)]),
);

// ---------------------------------------------------------------------------
// Records the implementation generates, and a structural fit against a schema
// ---------------------------------------------------------------------------

/** The TransactionRecord the state machine generates for a recorded session. */
function replay(vector: Dict, sessionInit: Dict = vector.session_init as Dict): Dict {
  const manager = new SessionManager();
  for (const [did, didDocument] of Object.entries(vector.did_documents as Record<string, Dict>)) {
    manager.registerDidDocument(did, didDocument);
  }
  const sessionAck = vector.session_ack as Dict;
  const session = manager.createSession(
    vector.session_id as string,
    sessionInit,
    sessionAck,
    sessionAck.session_created_at as string,
    { legacyReplay: true }, // a recorded session, possibly negotiated at "0.2"
  );
  session.session_timeout_seconds = 86400 * 365 * 100; // the timestamps are in the past
  for (const message of structuredClone(vector.messages as Dict[])) {
    manager.processMessage(session, message);
  }
  expect(session.state).toBe(SessionState.COMPLETED);
  return generateTransactionRecord(session);
}

/** A session whose SessionInit carries no subject_reference records it as null. */
function withoutSubjectReference(): Dict {
  const sessionInit = structuredClone(WITHOUT_BASIS.session_init as Dict);
  delete (sessionInit.session_params as Dict).subject_reference;
  const record = replay(WITHOUT_BASIS, sessionInit);
  expect(record.subject_reference).toBeNull();
  return record;
}

/** What an implementation that predates basis records for a session that fixed one. */
function agreedTermsBasisAlone(): Dict {
  const record = structuredClone(EXPECTED_0_2.full_record as Dict);
  delete record.basis;
  record.record_version = "0.1";
  record.record_hash = "";
  record.record_hash = hashObject(record);
  expect(record.record_hash).toBe(EXPECTED_0_2.basis_dropped_0_1_record_hash);
  return record;
}

/** Resolve a local `$ref` such as "#/$defs/party". */
function resolve(root: Dict, node: Dict): Dict {
  const ref = node.$ref as string | undefined;
  if (ref === undefined) {
    return node;
  }
  return ref
    .replace(/^#\//, "")
    .split("/")
    .reduce((current: Dict, key) => current[key] as Dict, root);
}

function jsonType(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "array";
  }
  if (typeof value === "number") {
    return Number.isInteger(value) ? "integer" : "number";
  }
  return typeof value;
}

/**
 * Hold `value` to the schema `node`, field by field. A closed object carries no
 * field the schema does not declare, and every required field is present; a
 * declared field the schema does not require is optional, as the "0.3" record's
 * basis is. Every typed, constant, enumerated, or patterned field accepts the
 * value the record holds.
 */
function expectFits(root: Dict, node: Dict, value: unknown, path: string): void {
  const resolved = resolve(root, node);
  if (resolved.type !== undefined) {
    const types = ([] as unknown[]).concat(resolved.type);
    const actual = jsonType(value);
    const fits = types.includes(actual) || (actual === "integer" && types.includes("number"));
    expect(fits, `${path}: ${actual} is not ${types.join(" | ")}`).toBe(true);
  }
  if (resolved.const !== undefined) {
    expect(value, path).toStrictEqual(resolved.const);
  }
  if (resolved.enum !== undefined) {
    expect(resolved.enum as unknown[], path).toContainEqual(value);
  }
  if (resolved.pattern !== undefined && typeof value === "string") {
    expect(value, path).toMatch(new RegExp(resolved.pattern as string));
  }
  const properties = (resolved.properties ?? {}) as Dict;
  const required = (resolved.required ?? []) as string[];
  const record = value as Dict;
  if (resolved.additionalProperties === false) {
    const declared = Object.keys(properties);
    expect(
      Object.keys(record).filter((key) => !declared.includes(key)),
      `${path} undeclared fields`,
    ).toEqual([]);
    expect(
      required.filter((key) => !declared.includes(key)),
      `${path} required but undeclared`,
    ).toEqual([]);
  }
  for (const key of required) {
    expect(Object.prototype.hasOwnProperty.call(record, key), `${path}.${key} is required`).toBe(
      true,
    );
  }
  for (const [key, child] of Object.entries(properties)) {
    if (Object.prototype.hasOwnProperty.call(record, key)) {
      expectFits(root, child as Dict, record[key], `${path}.${key}`);
    }
  }
}

// ---------------------------------------------------------------------------
// TransactionRecord
// ---------------------------------------------------------------------------

test("the transaction record schemas name the versions the generator emits", () => {
  expect(TRANSACTION_RECORD_VERSION_WITHOUT_BASIS).toBe("0.1");
  expect(TRANSACTION_RECORD_VERSION_WITH_BASIS).toBe("0.2");
  expect(TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT).toBe("0.3");
  for (const [file, version] of [
    [TR_0_1, TRANSACTION_RECORD_VERSION_WITHOUT_BASIS],
    [TR_0_2, TRANSACTION_RECORD_VERSION_WITH_BASIS],
    [TR_0_3, TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT],
    [TR_0_4, TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE],
  ]) {
    const found = schema(file);
    expect(found.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(found.$id).toBe(`https://a2cn.dev/schemas/transaction-record/${version}`);
    expect(((found.properties as Dict).record_version as Dict).const).toBe(version);
  }
  // This implementation knows exactly the versions it has a schema for, because
  // the published files are never rewritten; it accepts only the bound one.
  expect([...KNOWN_TRANSACTION_RECORD_VERSIONS].sort()).toEqual(
    [
      TRANSACTION_RECORD_VERSION_WITHOUT_BASIS,
      TRANSACTION_RECORD_VERSION_WITH_BASIS,
      TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,
      TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE,
    ].sort(),
  );
  expect([...ACCEPTED_TRANSACTION_RECORD_VERSIONS]).toEqual([
    TRANSACTION_RECORD_VERSION_SIGNED_ACCEPTANCE,
  ]);
});

// Every real TransactionRecord in the vectors, and what the reference
// implementation generates, with the schema of its version.
const TRANSACTION_RECORDS: [string, string, () => Dict][] = [
  [
    "0.1 from an implementation that predates basis",
    TR_0_1,
    () => (WITHOUT_BASIS.record_version_0_1 as Dict).full_record as Dict,
  ],
  ["0.1 with agreed_terms.basis alone", TR_0_1, agreedTermsBasisAlone],
  [
    "0.2 from an implementation that predates the act fields",
    TR_0_2,
    () => EXPECTED_0_2.full_record as Dict,
  ],
  ["0.3 basis vector", TR_0_3, () => EXPECTED_0_3.full_record as Dict],
  [
    "0.3 without-basis vector",
    TR_0_3,
    () => (WITHOUT_BASIS.record_version_0_3 as Dict).full_record as Dict,
  ],
  ["0.4 generated for a basis session", TR_0_4, () => replay(TR_VECTOR)],
  ["0.4 generated for a session without basis", TR_0_4, () => replay(WITHOUT_BASIS)],
  [
    "0.4 parity vector",
    TR_0_4,
    () => ((PARITY_VECTORS.session as Dict).expected as Dict).full_record as Dict,
  ],
  ["0.4 generated without subject_reference", TR_0_4, withoutSubjectReference],
  [
    "0.3 empty expires_at vector",
    TR_0_3,
    () => (EMPTY_EXPIRES_AT.record_version_0_3 as Dict).full_record as Dict,
  ],
  ["0.4 generated with an empty expires_at", TR_0_4, () => replay(EMPTY_EXPIRES_AT)],
];

test.each(TRANSACTION_RECORDS)(
  "every transaction record fits its version's schema: %s",
  (_name, file, makeRecord) => {
    const record = makeRecord();
    const own = schema(file);
    expectFits(own, own, record, "record");
    // And no other version's schema.
    for (const otherFile of OTHER_VERSIONS[file]) {
      const other = schema(otherFile);
      expect(() => expectFits(other, other, record, "record"), otherFile).toThrow();
    }
  },
);

test("the 0.2 schema requires basis in net or gross, equal to agreed_terms.basis", () => {
  const found = schema(TR_0_2);
  const properties = found.properties as Dict;
  expect(found.required).toContain("basis");
  expect((properties.basis as Dict).enum).toEqual([...SESSION_BASES]);
  const agreedTerms = properties.agreed_terms as Dict;
  expect(agreedTerms.type).toBe("object");
  expect(agreedTerms.additionalProperties).not.toBe(false); // terms stay open
  expect(agreedTerms.required).toContain("basis");
  expect(((agreedTerms.properties as Dict).basis as Dict).enum).toEqual([...SESSION_BASES]);
  // One condition per basis carries the equality.
  for (const basis of SESSION_BASES) {
    expect(found.allOf).toContainEqual({
      if: { properties: { basis: { const: basis } }, required: ["basis"] },
      then: { properties: { agreed_terms: { properties: { basis: { const: basis } } } } },
    });
  }
});

test("the 0.1 schema permits no top-level basis and leaves agreed_terms open", () => {
  const found = schema(TR_0_1);
  const properties = found.properties as Dict;
  expect(found.additionalProperties).toBe(false);
  expect("basis" in properties).toBe(false);
  expect(found.required).not.toContain("basis");
  const agreedTerms = properties.agreed_terms as Dict;
  expect(agreedTerms.type).toBe("object");
  expect(agreedTerms.additionalProperties).not.toBe(false);
  expect((agreedTerms.required ?? []) as string[]).not.toContain("basis");
});

test("the 0.3 schema requires every act field and carries basis with agreed_terms", () => {
  const found = schema(TR_0_3);
  const properties = found.properties as Dict;
  const finalOffer = properties.final_offer as Dict;

  for (const name of FINAL_OFFER_ACT_FIELDS) {
    expect(Object.keys(finalOffer.properties as Dict), name).toContain(name);
    expect(finalOffer.required as string[], name).toContain(name);
  }
  // basis is the one declared top-level field a "0.3" record may leave out.
  const optional = Object.keys(properties).filter(
    (name) => !(found.required as string[]).includes(name),
  );
  expect(optional).toEqual(["basis"]);
  expect((properties.basis as Dict).enum).toEqual([...SESSION_BASES]);
  // A basis implies the same agreed_terms.basis, and an agreed_terms.basis implies a basis.
  for (const basis of SESSION_BASES) {
    expect(found.allOf).toContainEqual({
      if: { properties: { basis: { const: basis } }, required: ["basis"] },
      then: {
        properties: {
          agreed_terms: { required: ["basis"], properties: { basis: { const: basis } } },
        },
      },
    });
  }
  expect(found.allOf).toContainEqual({
    if: { required: ["agreed_terms"], properties: { agreed_terms: { required: ["basis"] } } },
    then: { required: ["basis"] },
  });
});

// Every object the generator fills in full is closed; agreed_terms, the accepted
// offer's terms, stays open (Section 7.2).
const CLOSED_OBJECTS = ["parties", "negotiation_summary", "final_offer", "final_acceptance"];

test.each(TR_SCHEMAS)("%s is closed except agreed_terms", (file) => {
  const found = schema(file);
  const properties = found.properties as Dict;

  expect(found.additionalProperties).toBe(false);
  for (const name of CLOSED_OBJECTS) {
    expect((properties[name] as Dict).additionalProperties, name).toBe(false);
  }
  expect(((found.$defs as Dict).party as Dict).additionalProperties).toBe(false);
  // Both parties use the closed party definition.
  for (const role of ["initiator", "responder"]) {
    expect(((properties.parties as Dict).properties as Dict)[role], role).toStrictEqual({
      $ref: "#/$defs/party",
    });
  }
  expect((properties.agreed_terms as Dict).additionalProperties).not.toBe(false);
});

// The healthy record of each version, and each closed object an extra field can go in.
const HEALTHY_TRANSACTION_RECORDS: Record<string, () => Dict> = {
  [TR_0_1]: () => (WITHOUT_BASIS.record_version_0_1 as Dict).full_record as Dict,
  [TR_0_2]: () => EXPECTED_0_2.full_record as Dict,
  [TR_0_3]: () => EXPECTED_0_3.full_record as Dict,
  [TR_0_4]: () => ((TR_VECTOR.expected as Dict).record_version_0_4 as Dict).full_record as Dict,
};
const EXTRA_FIELD_PLACES: [string, (record: Dict) => Dict][] = [
  ["the record", (record) => record],
  ["parties", (record) => record.parties as Dict],
  ["a party", (record) => (record.parties as Dict).initiator as Dict],
  ["negotiation_summary", (record) => record.negotiation_summary as Dict],
  ["final_offer", (record) => record.final_offer as Dict],
  ["final_acceptance", (record) => record.final_acceptance as Dict],
];
const EXTRA_FIELD_CASES: [string, string, (record: Dict) => Dict][] = TR_SCHEMAS.flatMap((file) =>
  EXTRA_FIELD_PLACES.map(([place, locate]): [string, string, (record: Dict) => Dict] => [
    file,
    place,
    locate,
  ]),
);

test.each(EXTRA_FIELD_CASES)(
  "a record with an extra field does not fit %s: in %s",
  (file, _place, locate) => {
    const own = schema(file);
    const record = structuredClone(HEALTHY_TRANSACTION_RECORDS[file]());
    // The healthy record goes first: a check that refused everything would pass every case.
    expectFits(own, own, record, "record");

    locate(record).note = "unsealed";
    expect(() => expectFits(own, own, record, "record")).toThrow();
  },
);

test.each(FINAL_OFFER_ACT_FIELDS)(
  "a 0.3 record missing an act field does not fit its schema: %s",
  (fieldName) => {
    const own = schema(TR_0_3);
    const record = structuredClone(EXPECTED_0_3.full_record as Dict);
    expectFits(own, own, record, "record");

    delete (record.final_offer as Dict)[fieldName];
    expect(() => expectFits(own, own, record, "record")).toThrow();
  },
);

// ---------------------------------------------------------------------------
// SessionEvidenceRecord
// ---------------------------------------------------------------------------

test("every evidence record version a verifier recognizes has a schema that names it", () => {
  for (const version of RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS) {
    const file =
      version === "0.1"
        ? "session-evidence-record.schema.json"
        : `session-evidence-record-${version}.schema.json`;
    const found = schema(file);
    expect(found.$id).toBe(`https://a2cn.dev/schemas/session-evidence-record/${version}`);
    expect(((found.properties as Dict).record_version as Dict).const).toBe(version);
  }
  expect(RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS).toContain(SESSION_EVIDENCE_RECORD_VERSION_WITHOUT_EXTERNAL_COMMITMENT);
});

const SER_0_1 = "session-evidence-record.schema.json";
const SER_0_2 = "session-evidence-record-0.2.schema.json";
const SER_0_4 = "session-evidence-record-0.4.schema.json";
const SER_0_5 = "session-evidence-record-0.5.schema.json";
const SER_VECTOR = readJson("spec", "test-vectors", "session-evidence-record-parity.json");
const EXTENSIONS_VECTOR = readJson("spec", "test-vectors", "session-evidence-record-extensions.json");
const EXTENSIONS_KEY = privateKeyFromJwk(EXTENSIONS_VECTOR.producer_private_jwk as Dict);

/** The record at `version`, with record_hash and the producer seal recomputed. */
function resealedEvidenceRecord(record: Dict, version: string, key: KeyObject, kid: string): Dict {
  const copy = structuredClone(record);
  copy.record_version = version;
  copy.record_hash = "";
  copy.producer_signature = "";
  copy.record_hash = hashObject(copy);
  copy.producer_signature = signJws(copy.record_hash as string, key, kid);
  return copy;
}

/**
 * The record as generated before each act stated its wire version.
 *
 * Every act gained protocol_version, since none of the vector's acts states
 * one; each loses it again and its act_hash and the chain are recomputed, so
 * the record can be compared with one produced before acts stated their version.
 */
function withoutStatedWireVersions(record: Dict): Dict {
  const copy = structuredClone(record);
  for (const entry of copy.acts as Dict[]) {
    const act = entry.act as Dict;
    expect("protocol_version" in act).toBe(true);
    delete act.protocol_version;
    entry.act_hash = hashObject(act);
  }
  copy.act_chain_hash = hashBytes(
    canonicalize((copy.acts as Dict[]).map((entry) => entry.act_hash)),
  );
  return copy;
}

/** The record session-evidence-record-parity.json produces. */
function parityEvidenceRecord(): Dict {
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
    producerPrivateKey: privateKeyFromJwk(SER_VECTOR.producer_private_jwk as Dict),
    producerDid: producer.did as string,
    producerAgentId: producer.agent_id as string,
    producerVerificationMethod: producer.verification_method as string,
    observedActs: SER_VECTOR.observed_acts as Dict[],
  });
}

// The vector file speaks snake_case; the TypeScript option names are mapped
// explicitly so a renamed option cannot be silently ignored.
const OPTION_NAMES: Record<string, keyof GenerateSessionEvidenceOptions> = {
  observed_responder: "observedResponder",
  terminal_outcome: "terminalOutcome",
  terminal_reason: "terminalReason",
  terminal_money_basis: "terminalMoneyBasis",
  extensions: "extensions",
};

/** The record a session-evidence-record-extensions.json vector generates. */
function extensionEvidenceRecord(name: string): Dict {
  const fixture = EXTENSIONS_VECTOR;
  const vector = (fixture.vectors as Record<string, Dict>)[name];
  const sessionAck = (fixture.session_acks as Dict)[vector.session_ack as string] as Dict;
  const session = new Session({
    session_id: fixture.session_id as string,
    state: vector.state as string,
    current_turn: "none",
    terminal_reason: vector.terminal_reason as string,
    terminal_message_id: vector.terminal_message_id as string | null,
    session_created_at: fixture.session_created_at as string,
    state_updated_at: vector.state_updated_at as string,
    session_params: fixture.session_params as Dict,
    initiator_mandate: (fixture.session_init as Dict).initiator_mandate as Dict,
    responder_mandate: sessionAck.responder_mandate as Dict,
    _session_init: fixture.session_init as Dict,
    _session_ack: sessionAck,
    _message_log: vector.message_log as Dict[],
  });
  const producer = fixture.producer as Dict;
  const options: GenerateSessionEvidenceOptions = {
    producerPrivateKey: EXTENSIONS_KEY,
    producerDid: producer.did as string,
    producerAgentId: producer.agent_id as string,
    producerVerificationMethod: producer.verification_method as string,
    observedActs: vector.observed_acts as Dict[],
  };
  for (const [snakeName, value] of Object.entries(vector.options as Dict)) {
    const optionName = OPTION_NAMES[snakeName];
    expect(optionName, `unmapped vector option ${snakeName}`).toBeDefined();
    (options as unknown as Record<string, unknown>)[optionName] = value;
  }
  return generateSessionEvidenceRecord(session, options);
}

/** The Sections 9A.8 to 9A.11 features a SessionEvidenceRecord uses. */
function extensionFeatures(record: Dict): string[] {
  const terminal = record.terminal as Dict;
  const acts = record.acts as Dict[];
  const responder = (record.parties as Dict).responder as Dict;
  const uses: [string, boolean][] = [
    ["observed_party", "identity_source" in responder],
    ["a null act sender_did", acts.some((act) => act.sender_did === null)],
    [
      "money_basis",
      terminal.money_basis !== undefined || acts.some((act) => act.money_basis !== undefined),
    ],
    ["HALTED_BY_CONTROLS", terminal.outcome === "HALTED_BY_CONTROLS"],
    ["extensions", record.extensions !== undefined],
  ];
  return uses.filter(([, used]) => used).map(([feature]) => feature);
}

/** Whether an evidence record schema describes one of those features. */
function describes(found: Dict, feature: string): boolean {
  const properties = found.properties as Dict;
  const defs = found.$defs as Dict;
  const terminal = (properties.terminal as Dict).properties as Dict;
  const act = (defs.evidenceAct as Dict).properties as Dict;
  switch (feature) {
    case "observed_party":
      return defs.observed_party !== undefined;
    case "a null act sender_did":
      return ([] as unknown[]).concat((act.sender_did as Dict).type).includes("null");
    case "money_basis":
      return (
        defs.money_basis !== undefined &&
        terminal.money_basis !== undefined &&
        act.money_basis !== undefined
      );
    case "HALTED_BY_CONTROLS":
      return ((terminal.outcome as Dict).enum as string[]).includes("HALTED_BY_CONTROLS");
    case "extensions":
      return properties.extensions !== undefined;
    default:
      throw new Error(`unknown feature ${feature}`);
  }
}

test("the 0.1 evidence record schema is the file release 0.3.0 published", () => {
  // A published schema file is never rewritten (Section 17).
  const digest = createHash("sha256")
    .update(readFileSync(join(REPO_ROOT, "spec", "schemas", SER_0_1)))
    .digest("hex");

  expect(digest).toBe(SER_VECTOR.release_0_3_0_schema_sha256);
});

test("a record release 0.3.0 produced still verifies", () => {
  // Today's verifier accepts the record release 0.3.0 produced; the Python suite
  // also validates it against the "0.1" schema.
  const record = SER_VECTOR.release_0_3_0_record as Dict;
  const released = schema(SER_0_1);

  expect(record.record_version).toBe("0.1");
  expect(extensionFeatures(record)).toEqual([]);
  expect(Object.keys(record).filter((key) => !(key in (released.properties as Dict)))).toEqual([]);
  expect(
    verifySessionEvidenceRecord(record, SER_VECTOR.did_documents as Record<string, Dict>),
  ).toBe(true);
  // Apart from its version, and from each of its own acts now stating the wire
  // version it was signed under, this implementation produces the same record.
  const key = privateKeyFromJwk(SER_VECTOR.producer_private_jwk as Dict);
  const kid = (SER_VECTOR.producer as Dict).verification_method as string;
  const asReleased = resealedEvidenceRecord(
    withoutStatedWireVersions(parityEvidenceRecord()),
    "0.1",
    key,
    kid,
  );
  expect(asReleased.record_hash).toBe(record.record_hash);
  // The stated versions are the only other difference, and they are not nothing.
  const regenerated = resealedEvidenceRecord(parityEvidenceRecord(), "0.1", key, kid);
  expect(regenerated.record_hash).not.toBe(record.record_hash);
});

test.each(Object.keys(EXTENSIONS_VECTOR.vectors as Dict).sort())(
  "a record that uses Sections 9A.8 to 9A.11 fits its own version's schema: %s",
  (name) => {
    // Sections 9A.8 to 9A.11 arrived in "0.2", so the released "0.1" schema, closed
    // where each of them would go, cannot describe them. Every producer now emits
    // "0.5" (Section 9A.2), which describes them all. Verification does not depend
    // on the version, so the record still verifies when it is relabelled "0.1".
    const record = extensionEvidenceRecord(name);
    const released = schema(SER_0_1);
    const current = schema(SER_0_5);
    const didDocuments = EXTENSIONS_VECTOR.did_documents as Record<string, Dict>;
    const features = extensionFeatures(record);

    expect(released.additionalProperties).toBe(false);
    expect(((released.properties as Dict).terminal as Dict).additionalProperties).toBe(false);
    expect(((released.$defs as Dict).evidenceAct as Dict).additionalProperties).toBe(false);
    expect(((released.$defs as Dict).party as Dict).additionalProperties).toBe(false);
    expect(record.record_version).toBe("0.5");
    expect(features.length).toBeGreaterThan(0);
    for (const feature of features) {
      expect(describes(current, feature), feature).toBe(true);
      expect(describes(released, feature), feature).toBe(false);
    }
    expect(verifySessionEvidenceRecord(record, didDocuments)).toBe(true);
    const relabelled = resealedEvidenceRecord(
      record,
      "0.1",
      EXTENSIONS_KEY,
      (EXTENSIONS_VECTOR.producer as Dict).verification_method as string,
    );
    expect(verifySessionEvidenceRecord(relabelled, didDocuments)).toBe(true);
  },
);

// ---------------------------------------------------------------------------
// SessionEvidenceRecord "0.3": external-channel completion (Section 9A.12)
// ---------------------------------------------------------------------------

const SER_0_3 = "session-evidence-record-0.3.schema.json";
const EXTERNAL_CHANNEL_VECTOR = readJson(
  "spec",
  "test-vectors",
  "session-evidence-record-external-channel.json",
);

/** The record session-evidence-record-external-channel.json generates. */
function externalChannelEvidenceRecord(): Dict {
  const fixture = EXTERNAL_CHANNEL_VECTOR;
  const source = fixture.session as Dict;
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
  const options = fixture.options as Dict;
  expect(Object.keys(options).sort()).toEqual(["external_commitment_reference", "observed_responder"]);
  const producer = fixture.producer as Dict;
  return generateSessionEvidenceRecord(session, {
    producerPrivateKey: privateKeyFromJwk(fixture.producer_private_jwk as Dict),
    producerDid: producer.did as string,
    producerAgentId: producer.agent_id as string,
    producerVerificationMethod: producer.verification_method as string,
    observedActs: fixture.observed_acts as Dict[],
    observedResponder: structuredClone(options.observed_responder as Dict),
    externalCommitmentReference: structuredClone(options.external_commitment_reference as Dict),
  });
}

test("the evidence record schemas name the versions the generator emits", () => {
  expect(SESSION_EVIDENCE_RECORD_VERSION_WITHOUT_EXTERNAL_COMMITMENT).toBe("0.2");
  expect(SESSION_EVIDENCE_RECORD_VERSION_WITH_EXTERNAL_COMMITMENT).toBe("0.3");
  for (const [file, version] of [
    [SER_0_2, SESSION_EVIDENCE_RECORD_VERSION_WITHOUT_EXTERNAL_COMMITMENT],
    [SER_0_3, SESSION_EVIDENCE_RECORD_VERSION_WITH_EXTERNAL_COMMITMENT],
    // "0.4" has no named constant: it names no shape of its own any more, being
    // neither the emitted version nor one a rule is keyed on. It is still
    // published and still accepted, so its schema is still checked.
    [SER_0_4, "0.4"],
    [SER_0_5, SESSION_EVIDENCE_RECORD_VERSION_CURRENT],
  ]) {
    expect(((schema(file).properties as Dict).record_version as Dict).const).toBe(version);
  }
  // A verifier recognizes exactly the versions it has a schema for, and that set
  // is additive: "0.5" was added and none removed, so a record sealed under an
  // earlier version stays valid.
  expect([...RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS]).toEqual([
    "0.1",
    SESSION_EVIDENCE_RECORD_VERSION_WITHOUT_EXTERNAL_COMMITMENT,
    SESSION_EVIDENCE_RECORD_VERSION_WITH_EXTERNAL_COMMITMENT,
    "0.4",
    SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
  ]);
});

test("the 0.3 evidence record schema is the 0.2 schema with external-channel completion", () => {
  // Only the version, the new member, and the rules that go with it differ.
  const previous = schema(SER_0_2);
  const current = schema(SER_0_3);
  const properties = current.properties as Dict;

  expect(current.$id).toBe("https://a2cn.dev/schemas/session-evidence-record/0.3");
  expect(properties.record_version).toStrictEqual({ type: "string", const: "0.3" });
  expect(current.required).toStrictEqual([
    ...(previous.required as string[]),
    "external_commitment_reference",
  ]);
  expect(properties.external_commitment_reference).toStrictEqual({
    $ref: "#/$defs/external_commitment_reference",
  });
  // An external-channel record carries at least one act its producer signed. The
  // schema can require a verified act; that its sender is the initiator is a
  // cross-reference between two members, which a JSON Schema cannot state.
  expect((properties.acts as Dict).contains).toStrictEqual({
    properties: { attribution: { const: "verified_signature" } },
    required: ["attribution"],
  });

  const everythingElse = (found: Dict): Dict => {
    const copy = structuredClone(found);
    delete copy.$id;
    delete copy.description;
    delete copy.allOf;
    delete (copy.properties as Dict).record_version;
    delete (copy.properties as Dict).acts;
    delete (copy.properties as Dict).external_commitment_reference;
    delete (copy.$defs as Dict).external_commitment_reference;
    copy.required = (copy.required as string[]).filter(
      (name) => name !== "external_commitment_reference",
    );
    return copy;
  };
  expect(everythingElse(current)).toStrictEqual(everythingElse(previous));
});

test("the 0.3 schema admits only a COMPLETED, unilateral record against an observed party", () => {
  const allOf = schema(SER_0_3).allOf as Dict[];

  // One completion witness: a COMPLETED record whose transaction_record_hash is
  // null. No other outcome has a completion witness, so no other outcome fits.
  expect(allOf).toContainEqual(
    expect.objectContaining({
      if: {
        properties: {
          terminal: { properties: { outcome: { const: "COMPLETED" } }, required: ["outcome"] },
        },
      },
      then: { properties: { transaction_record_hash: { type: "null" } } },
      else: false,
    }),
  );
  // The coupling: the responder is an observed_party and the evidence is unilateral.
  expect(allOf).toContainEqual(
    expect.objectContaining({
      properties: {
        parties: { properties: { responder: { $ref: "#/$defs/observed_party" } } },
        evidence_level: { const: "unilateral" },
      },
    }),
  );
});

/** Whether `value` fits a closed object definition whose properties are typed strings. */
function fitsStringObject(definition: Dict, value: unknown): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const properties = definition.properties as Dict;
  const object = value as Dict;
  if (Object.keys(object).some((key) => !Object.prototype.hasOwnProperty.call(properties, key))) {
    return false;
  }
  if ((definition.required as string[]).some((key) => !Object.prototype.hasOwnProperty.call(object, key))) {
    return false;
  }
  return Object.entries(object).every(([key, field]) => {
    const rule = properties[key] as Dict;
    return (
      typeof field === rule.type &&
      (rule.minLength === undefined || (field as string).length >= (rule.minLength as number))
    );
  });
}

test("the 0.3 schema's external_commitment_reference agrees with the vector", () => {
  const definition = (schema(SER_0_3).$defs as Dict).external_commitment_reference as Dict;
  expect(definition.type).toBe("object");
  expect(definition.additionalProperties).toBe(false);
  expect(definition.required).toStrictEqual(["external_commitment_id"]);
  const rules = Object.fromEntries(
    Object.entries(definition.properties as Dict).map(([name, rule]) => [
      name,
      { type: (rule as Dict).type, minLength: (rule as Dict).minLength },
    ]),
  );
  expect(rules).toStrictEqual({
    external_commitment_id: { type: "string", minLength: 1 },
    locator: { type: "string", minLength: 1 },
    reference_note: { type: "string", minLength: undefined },
  });

  const valid = [
    (EXTERNAL_CHANNEL_VECTOR.options as Dict).external_commitment_reference,
    ...(EXTERNAL_CHANNEL_VECTOR.valid_references as Dict[]).map(
      (entry) => entry.external_commitment_reference,
    ),
  ];
  for (const reference of valid) {
    expect(fitsStringObject(definition, reference), JSON.stringify(reference)).toBe(true);
  }
  for (const entry of EXTERNAL_CHANNEL_VECTOR.invalid_references as Dict[]) {
    expect(fitsStringObject(definition, entry.external_commitment_reference), entry.name as string).toBe(
      false,
    );
  }
});

test("an external-channel record uses a member only the later schemas describe", () => {
  const record = externalChannelEvidenceRecord();
  const current = schema(SER_0_5);

  expect(record.record_version).toBe("0.5");
  expect(Object.keys(record).filter((key) => !(key in (current.properties as Dict)))).toEqual([]);
  expect((current.required as string[]).filter((key) => !(key in record))).toEqual([]);
  for (const file of [SER_0_1, SER_0_2]) {
    const earlier = schema(file);
    expect(earlier.additionalProperties, file).toBe(false);
    expect(
      Object.keys(record).filter((key) => !(key in (earlier.properties as Dict))),
      file,
    ).toEqual(["external_commitment_reference"]);
  }
  expect(
    verifySessionEvidenceRecord(
      record,
      EXTERNAL_CHANNEL_VECTOR.did_documents as Record<string, Dict>,
    ),
  ).toBe(true);
});

test("no record without the reference has every member the 0.3 schema requires", () => {
  // "0.3" requires the reference by definition, so no record without one fits it
  // under any label. The records themselves are "0.5", the version every producer
  // now emits, where that reference is OPTIONAL.
  const required = schema(SER_0_3).required as string[];
  const records = [
    parityEvidenceRecord(),
    ...Object.keys(EXTENSIONS_VECTOR.vectors as Dict)
      .sort()
      .map((name) => extensionEvidenceRecord(name)),
  ];

  for (const record of records) {
    expect(record.record_version).toBe("0.5");
    expect(required.filter((key) => !(key in record))).toEqual(["external_commitment_reference"]);
  }
});

test("the 0.2 evidence record schema is unchanged", () => {
  // The "0.3" schema is published beside it, and "0.2" is not rewritten (Section 17).
  const digest = createHash("sha256")
    .update(readFileSync(join(REPO_ROOT, "spec", "schemas", SER_0_2)))
    .digest("hex");

  expect(digest).toBe(EXTERNAL_CHANNEL_VECTOR.session_evidence_record_0_2_schema_sha256);
});

// Section 17: a published schema file is never rewritten. Before this, only
// "0.1" and "0.2" were pinned — 2 of 5 published files, in BOTH languages, not
// one. "0.4" is pinned because this change publishes "0.5" beside it and
// must not touch it; "0.5" is pinned from publication rather than from
// whenever someone next remembers. A digest pin needs no JSON Schema
// validator, so the standing "schema validation is Python-only" asymmetry
// never excused this gap.
test.each([
  ["0.4", SER_0_4, "session_evidence_record_0_4_schema_sha256"],
  ["0.5", SER_0_5, "session_evidence_record_0_5_schema_sha256"],
])("the later evidence record schemas are pinned: %s", (_name, file, pin) => {
  const digest = createHash("sha256")
    .update(readFileSync(join(REPO_ROOT, "spec", "schemas", file)))
    .digest("hex");

  expect(digest).toBe(EXTERNAL_CHANNEL_VECTOR[pin]);
});

test("a stored 0.3 record still verifies and fits its own schema", () => {
  // The additive recognizer, which nothing else in either suite pins. Section
  // 9A.2: the SessionEvidenceRecord's accepted set GREW to include "0.4" and
  // lost nothing, so a record sealed under an earlier version stays valid —
  // the deliberate opposite of the TransactionRecord's clean break in the same
  // release. The recognizer could have been narrowed to ["0.4"] and every other
  // test would still have passed.
  //
  // This record is loaded, never generated: it is what this vector's session
  // produced before universal "0.4", with the bytes it had.
  const record = EXTERNAL_CHANNEL_VECTOR.historical_0_3_record as Dict;
  const ownSchema = schema(SER_0_3);

  expect(record.record_version).toBe("0.3");
  expect(
    verifySessionEvidenceRecord(record, EXTERNAL_CHANNEL_VECTOR.did_documents as Record<string, Dict>),
  ).toBe(true);
  expect(
    Object.keys(record).filter((key) => !(key in (ownSchema.properties as Dict))),
  ).toEqual([]);
  expect((ownSchema.required as string[]).filter((key) => !(key in record))).toEqual([]);
});

test("the stored 0.3 record is today's record apart from its version", () => {
  // The two differ in the version, the hash over it, and the seal over that,
  // and in the wire version today's record states on each of its acts.
  // A guard on the pair: if they drifted in any other member, the test above
  // would be verifying an unrelated artifact while appearing to prove the
  // recognizer.
  const historical = EXTERNAL_CHANNEL_VECTOR.historical_0_3_record as Dict;
  const current = (EXTERNAL_CHANNEL_VECTOR.expected as Dict).record as Dict;

  expect(current.record_version).toBe("0.5");
  expectApartFromVersionAndStatedWireVersions(historical, current);
});

test("a stored 0.4 record still verifies", () => {
  // PROBE A's pin, and the ONLY artifact that catches the floor regression.
  //
  // The version-keyed witness rule returns early for versions at or above the
  // floor. Written as an equality against the CURRENT version rather than as a
  // floor — which is how it stood until this change — it dropped every stored
  // "0.4" external-channel record into the historical "0.3" biconditional and
  // refused it the moment CURRENT became "0.5".
  //
  // NOTHING ELSE CATCHES THAT. historical_0_3_record covers "0.3", which the
  // biconditional governs either way; a regenerated record follows CURRENT and
  // so takes the early return whatever the rule says. Only a record stored at
  // the PREVIOUS version distinguishes a floor from an equality.
  //
  // Loaded, never generated: re-sealing it under today's version would destroy
  // the only thing it proves.
  const record = EXTERNAL_CHANNEL_VECTOR.historical_0_4_record as Dict;

  expect(record.record_version).toBe("0.4");
  expect(
    verifySessionEvidenceRecord(record, EXTERNAL_CHANNEL_VECTOR.did_documents as Record<string, Dict>),
  ).toBe(true);
});

test("the stored 0.4 record is today's record apart from its version", () => {
  // The guard on the pair above, mirroring the "0.3" one: without it, the test
  // above could drift into verifying an unrelated artifact while still
  // appearing to prove the recognizer.
  const historical = EXTERNAL_CHANNEL_VECTOR.historical_0_4_record as Dict;
  const current = (EXTERNAL_CHANNEL_VECTOR.expected as Dict).record as Dict;

  expect(historical.record_version).toBe("0.4");
  expect(current.record_version).toBe("0.5");
  expectApartFromVersionAndStatedWireVersions(historical, current);
});

/**
 * The two differ in the version, the hash over it, and the seal over that, and
 * in the wire version today's record states on each of its acts.
 */
function expectApartFromVersionAndStatedWireVersions(historical: Dict, current: Dict): void {
  const differing = [...new Set([...Object.keys(historical), ...Object.keys(current)])]
    .filter((name) => JSON.stringify(historical[name]) !== JSON.stringify(current[name]))
    .sort();
  expect(differing).toEqual([
    "act_chain_hash",
    "acts",
    "producer_signature",
    "record_hash",
    "record_version",
  ]);
  // The acts differ only in the stated version and the act_hash over it.
  const nowActs = current.acts as Dict[];
  const thenActs = historical.acts as Dict[];
  expect(nowActs.length).toBe(thenActs.length);
  const rest = (entry: Dict): Dict =>
    Object.fromEntries(Object.entries(entry).filter(([k]) => k !== "act" && k !== "act_hash"));
  let stated = 0;
  nowActs.forEach((now, i) => {
    const then = thenActs[i];
    const act = structuredClone(now.act as Dict);
    if (!("protocol_version" in (then.act as Dict)) && "protocol_version" in act) {
      delete act.protocol_version;
      stated += 1;
    }
    expect(act).toEqual(then.act);
    expect(rest(now)).toEqual(rest(then));
  });
  // Every act, the session's own and the observed one, now states it.
  expect(stated).toBe(nowActs.length);
  expect(stated).toBe(2);
}
