/**
 * agreed_terms binds to the signed final offer (Sections 9.3 and 9.5).
 *
 * The offer's protocol_act_signature already covers the Section 7.3.1 protocol
 * act, terms included. A record that carries only the act's hash leaves a
 * reader unable to rebuild the act, so agreed_terms hangs free: a record whose
 * agreed_terms differs from what was signed, resealed, still verifies. Carrying
 * the rest of the act in final_offer lets a verifier rebuild it from the record
 * and recompute the hash, so agreed_terms binds to the signature transitively.
 * Nothing new is signed, and no signature, hash, or wire message changes.
 *
 * The acceptance side was already recomputable: acceptance_signature covers the
 * five fields of Section 7.4 and the record carries all five, so the tests
 * below also pin that, on a record_version "0.2" record, which predates this
 * change. The Python suite runs the same cases.
 */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import {
  canonicalize,
  generateKeypair,
  hashBytes,
  hashObject,
  publicKeyToJwk,
  signJws,
} from "../src/a2cn/crypto.js";
import {
  REASON_UNBOUND_RECORD_VERSION,
  generateTransactionRecord,
  verifyTransactionRecord,
  verifyTransactionRecordReason,
} from "../src/a2cn/record.js";
import { SessionManager, SessionState } from "../src/a2cn/session.js";
import { PROTOCOL_ACT_VERSION, type Dict } from "../src/a2cn/messages.js";
import { INITIATOR_DID, RESPONDER_DID, makeDidDocument } from "./conftest.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VECTOR = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "transaction-record-basis.json"), "utf-8"),
) as Dict;
const WITHOUT_BASIS = VECTOR.without_basis as Dict;
const VECTORS: Record<string, Dict> = { with_basis: VECTOR, without_basis: WITHOUT_BASIS };
// The record an implementation that predates this binding produced for the basis
// session: no act fields, and record_version "0.2".
const EXPECTED_0_2 = (VECTOR.expected as Dict).record_version_0_2 as Dict;
// A session whose round-1 offer omits expires_at, so its signed act carries "".
const EMPTY_EXPIRES_AT = VECTOR.empty_expires_at as Dict;

// The Section 7.3.1 act fields the record carries in final_offer. session_id is
// at the record's top level, sender_did is already in final_offer, and the act's
// terms are agreed_terms.
const ACT_FIELDS = [
  "protocol_version",
  "round_number",
  "sequence_number",
  "message_type",
  "timestamp",
  "expires_at",
];
// The Section 7.4 acceptance payload fields the record carries in
// final_acceptance; its fifth field, session_id, is at the record's top level.
const ACCEPTANCE_FIELDS = [
  "round_number",
  "sequence_number",
  "accepted_offer_id",
  "accepted_protocol_act_hash",
];
// An offer message carries no protocol_version of its own (Section 7.1): the act
// states the wire version, so the record states it rather than copying it.
const ACT_FIELDS_ON_THE_WIRE = ACT_FIELDS.filter((name) => name !== "protocol_version");

function replay(vector: Dict) {
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

function record(vector: Dict = VECTOR): Dict {
  return generateTransactionRecord(replay(vector));
}

function offerHashes(vector: Dict): string[] {
  return (vector.messages as Dict[])
    .filter((message) => message.message_type === "offer" || message.message_type === "counteroffer")
    .map((message) => message.protocol_act_hash as string);
}

/** The record with record_hash recomputed: the tamper a naive verifier misses. */
function resealed(value: Dict): Dict {
  const copy = structuredClone(value);
  copy.record_hash = "";
  copy.record_hash = hashObject(copy);
  return copy;
}

function verifies(value: Dict, vector: Dict = VECTOR): boolean {
  return verifyTransactionRecord(
    value,
    vector.did_documents as Record<string, Dict>,
    offerHashes(vector),
  );
}

function reasonFor(value: Dict, vector: Dict = VECTOR): string | null {
  return verifyTransactionRecordReason(
    value,
    vector.did_documents as Record<string, Dict>,
    offerHashes(vector),
  );
}

/**
 * The record of the given version: "0.3" generated, "0.2" the vector's.
 *
 * Only "0.3" is accepted now; the older shape is still built here so a case can
 * assert what a verifier does with it.
 */
function recordOfVersion(recordVersion: string): Dict {
  return recordVersion === "0.3"
    ? record()
    : structuredClone(EXPECTED_0_2.full_record as Dict);
}

/**
 * Rebuild the Section 7.3.1 protocol act from the record alone.
 *
 * Spelled out here rather than imported, so the test is an independent check of
 * the field names and sources the record must make available.
 */
function actFromRecord(value: Dict): Dict {
  const finalOffer = value.final_offer as Dict;
  return {
    protocol_version: finalOffer.protocol_version,
    session_id: value.session_id,
    round_number: finalOffer.round_number,
    sequence_number: finalOffer.sequence_number,
    message_type: finalOffer.message_type,
    sender_did: finalOffer.sender_did,
    timestamp: finalOffer.timestamp,
    expires_at: finalOffer.expires_at,
    terms: value.agreed_terms,
  };
}

function acceptedOffer(vector: Dict): Dict {
  const messages = vector.messages as Dict[];
  const acceptance = messages[messages.length - 1];
  return messages.find((message) => message.message_id === acceptance.accepted_offer_id) as Dict;
}

// ---------------------------------------------------------------------------
// The record carries the signed act
// ---------------------------------------------------------------------------

const CARRIED_FIELD_CASES: [string, string][] = Object.keys(VECTORS)
  .sort()
  .flatMap((name) => ACT_FIELDS_ON_THE_WIRE.map((field): [string, string] => [name, field]));

test.each(CARRIED_FIELD_CASES)(
  "final_offer carries the accepted offer's act field: %s %s",
  (vectorName, fieldName) => {
    // Each act field is the accepted offer's value, copied verbatim (Section 9.3).
    const vector = VECTORS[vectorName];

    expect((record(vector).final_offer as Dict)[fieldName]).toStrictEqual(
      acceptedOffer(vector)[fieldName],
    );
  },
);

test.each(Object.keys(VECTORS).sort())(
  "final_offer states the wire version the act was hashed under: %s",
  (vectorName) => {
    // The offer message carries no protocol_version, so the record states it.
    const vector = VECTORS[vectorName];

    expect("protocol_version" in acceptedOffer(vector)).toBe(false);
    expect((record(vector).final_offer as Dict).protocol_version).toBe(PROTOCOL_ACT_VERSION);
  },
);

test.each(Object.keys(VECTORS).sort())(
  "the act hash recomputes from the record alone: %s",
  (vectorName) => {
    // Section 9.5: the record holds everything the signed act hash covers.
    const vector = VECTORS[vectorName];
    const value = record(vector);

    expect(hashObject(actFromRecord(value))).toBe((value.final_offer as Dict).protocol_act_hash);
    expect(verifies(value, vector)).toBe(true);
  },
);

test.each(Object.keys(VECTORS).sort())(
  "a record that carries the act fields is 0.3: %s",
  (vectorName) => {
    // Section 9.3: the version follows the content, as it does for basis.
    expect(record(VECTORS[vectorName]).record_version).toBe("0.3");
  },
);

test("a 0.3 record carries basis exactly when agreed_terms does", () => {
  // Under "0.3" the basis rule reads a signature-backed agreed_terms.
  const withBasis = record(VECTOR);
  const withoutBasis = record(WITHOUT_BASIS);

  expect(withBasis.basis).toBe((withBasis.agreed_terms as Dict).basis);
  expect("basis" in withoutBasis).toBe(false);
  expect("basis" in (withoutBasis.agreed_terms as Dict)).toBe(false);
});

// ---------------------------------------------------------------------------
// The headline: agreed_terms altered after signing must be rejected
// ---------------------------------------------------------------------------

const AGREED_TERMS_TAMPERS: [string, Dict][] = [
  ["total_value", { total_value: 1 }],
  ["currency", { currency: "EUR" }],
  ["basis", { basis: "net" }],
  ["a term", { seat_count: 1 }],
  ["an inserted line item", { line_items: [{ sku: "inserted", total_minor: 1 }] }],
];

test.each(AGREED_TERMS_TAMPERS)(
  "agreed_terms altered after signing fails verification: %s",
  (_name, changes) => {
    // The record this issue exists for: valid signatures over terms nobody
    // agreed. Both signatures still verify and record_hash is recomputed, so
    // only the rebuilt act hash catches it.
    const value = record();
    const signature = (value.final_offer as Dict).protocol_act_signature;
    Object.assign(value.agreed_terms as Dict, changes);
    const tampered = resealed(value);

    expect((tampered.final_offer as Dict).protocol_act_signature).toBe(signature);
    expect(hashObject(actFromRecord(tampered))).not.toBe(
      (tampered.final_offer as Dict).protocol_act_hash,
    );
    expect(verifies(tampered)).toBe(false);
  },
);

test("agreed_terms replaced wholesale fails verification", () => {
  const value = record();
  value.agreed_terms = { total_value: 1, currency: "USD", basis: "gross" };

  expect(verifies(resealed(value))).toBe(false);
});

test.each([
  ["null", null],
  ["array", []],
  ["string", "gross"],
  ["number", 0],
] as [string, unknown][])(
  "agreed_terms that is not an object fails verification: %s",
  (_name, agreedTerms) => {
    // A non-object cannot be the terms of a Section 7.3.1 act.
    const value = record();
    value.agreed_terms = agreedTerms;

    expect(verifies(resealed(value))).toBe(false);
  },
);

// ---------------------------------------------------------------------------
// Every act field is bound
// ---------------------------------------------------------------------------

const ALTERED_ACT_VALUES: Dict = {
  protocol_version: "0.1",
  round_number: 1,
  sequence_number: 1,
  message_type: "offer",
  timestamp: "2026-03-24T10:09:00Z",
  expires_at: "2031-01-01T00:00:00Z",
};

test.each(ACT_FIELDS)("an altered act field fails verification: %s", (fieldName) => {
  const value = record();
  (value.final_offer as Dict)[fieldName] = ALTERED_ACT_VALUES[fieldName];

  expect(verifies(resealed(value))).toBe(false);
});

test("an altered final_offer sender_did fails verification", () => {
  // sender_did is inside the act, and it also picks the verifying key.
  const value = record();
  (value.final_offer as Dict).sender_did = ((value.parties as Dict).initiator as Dict).did;

  expect(verifies(resealed(value))).toBe(false);
});

test("an altered top-level session_id fails verification", () => {
  // session_id is the act's session_id, and the acceptance payload's.
  const value = record();
  value.session_id = "5a1e0b2c-3d4e-4f60-8a7b-000000000000";

  expect(verifies(resealed(value))).toBe(false);
});

test.each(ACT_FIELDS)("a 0.3 record missing an act field fails verification: %s", (fieldName) => {
  const value = record();
  delete (value.final_offer as Dict)[fieldName];

  expect(verifies(resealed(value))).toBe(false);
});

test("a 0.3 record with no act fields at all fails verification", () => {
  const value = record();
  for (const fieldName of ACT_FIELDS) {
    delete (value.final_offer as Dict)[fieldName];
  }

  expect(value.record_version).toBe("0.3");
  expect(verifies(resealed(value))).toBe(false);
});

test.each([
  ["0.1", "without_basis"],
  ["0.2", "with_basis"],
])(
  "an earlier version that carries act fields fails verification: %s",
  (recordVersion, vectorName) => {
    // The act fields and "0.3" imply each other, so neither is worn alone. Each
    // case is a record whose basis shape already fits the version it claims, so
    // only the act fields can be what rejects it (Section 9.5).
    const vector = VECTORS[vectorName];
    const value = record(vector);
    value.record_version = recordVersion;

    expect(verifies(resealed(value), vector)).toBe(false);
  },
);

// ---------------------------------------------------------------------------
// Act field types: identical verdicts in both languages
// ---------------------------------------------------------------------------

const MALFORMED_ACT_FIELDS: [string, unknown][] = [
  ["protocol_version", ""],
  ["protocol_version", null],
  ["protocol_version", 0.2],
  ["round_number", "2"],
  ["round_number", 0],
  ["round_number", -1],
  ["round_number", true],
  ["round_number", null],
  ["sequence_number", "3"],
  ["sequence_number", 0],
  ["sequence_number", true],
  ["sequence_number", null],
  ["message_type", ""],
  ["message_type", null],
  ["timestamp", ""],
  ["timestamp", null],
  ["expires_at", ""],
  ["expires_at", null],
];

test.each(MALFORMED_ACT_FIELDS)(
  "a malformed act field fails verification: %s = %s",
  (fieldName, value) => {
    // Types are checked before the hash, so both languages reach one verdict.
    const found = record();
    (found.final_offer as Dict)[fieldName as string] = value;

    expect(verifies(resealed(found))).toBe(false);
  },
);

test("a record whose protocol_version does not match its act fails verification", () => {
  // The act was hashed over one wire version and the record claims another.
  const value = record();
  const signedHash = (value.final_offer as Dict).protocol_act_hash;
  (value.final_offer as Dict).protocol_version = "0.3";

  expect((value.final_offer as Dict).protocol_act_hash).toBe(signedHash);
  expect(verifies(resealed(value))).toBe(false);
});

// ---------------------------------------------------------------------------
// protocol_version comes from the record, not from a pinned wire version
// ---------------------------------------------------------------------------

const { privateKey: INITIATOR_PRIVATE_KEY, publicKey: INITIATOR_PUBLIC_KEY } = generateKeypair();
const { privateKey: RESPONDER_PRIVATE_KEY, publicKey: RESPONDER_PUBLIC_KEY } = generateKeypair();
const INITIATOR_VM = `${INITIATOR_DID}#key-1`;
const RESPONDER_VM = `${RESPONDER_DID}#key-2026-01`;

/**
 * A completed one-round session whose two signing keys this test holds.
 *
 * `omit` leaves a field out of the offer message. The state machine defaults a
 * missing timestamp or expires_at to "" when it rebuilds the act to check its
 * hash (Section 7.3.1), so the signature covers the empty string and the record
 * carries it.
 */
function locallySignedRecord(
  options: { timestamp?: string; expiresAt?: string; omit?: string[] } = {},
): [Dict, Record<string, Dict>] {
  const timestamp = options.timestamp ?? "2026-03-24T10:01:00Z";
  const expiresAt = options.expiresAt ?? "2030-01-01T00:00:00Z";
  const omit = options.omit ?? [];
  const sessionId = randomUUID();
  const sessionParams: Dict = {
    deal_type: "saas_renewal",
    currency: "USD",
    max_rounds: 4,
    session_timeout_seconds: 3600,
    round_timeout_seconds: 900,
  };
  const sessionInit: Dict = {
    message_type: "session_init",
    message_id: "act-init-1",
    protocol_version: "0.2",
    session_params: { ...sessionParams, subject: "Act binding" },
    initiator: {
      organization_name: "TechCorp",
      did: INITIATOR_DID,
      verification_method: INITIATOR_VM,
      agent_id: "buyer-agent",
      endpoint: "https://techcorp.example/api/a2cn",
    },
    initiator_mandate: { mandate_type: "declared" },
  };
  const sessionAck: Dict = {
    message_type: "session_ack",
    message_id: "act-ack-1",
    session_id: sessionId,
    in_reply_to: "act-init-1",
    protocol_version: "0.2",
    session_params_accepted: sessionParams,
    responder: {
      organization_name: "Acme",
      did: RESPONDER_DID,
      verification_method: RESPONDER_VM,
      agent_id: "seller-agent",
      endpoint: "http://localhost:8000",
    },
    responder_mandate: { mandate_type: "declared" },
    session_created_at: "2026-03-24T10:00:00Z",
    current_turn: "initiator",
  };
  const didDocuments: Record<string, Dict> = {
    [INITIATOR_DID]: makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(INITIATOR_PUBLIC_KEY)),
    [RESPONDER_DID]: makeDidDocument(
      RESPONDER_DID,
      "key-2026-01",
      publicKeyToJwk(RESPONDER_PUBLIC_KEY),
    ),
  };

  const manager = new SessionManager();
  for (const [did, didDocument] of Object.entries(didDocuments)) {
    manager.registerDidDocument(did, didDocument);
  }
  const session = manager.createSession(
    sessionId,
    sessionInit,
    sessionAck,
    "2026-03-24T10:00:00Z",
  );
  session.session_timeout_seconds = 86400 * 365 * 100;

  const terms = { total_value: 9_500_000, currency: "USD" };
  // What the state machine will rebuild: an omitted field defaults to "".
  const actHash = hashObject({
    protocol_version: "0.2",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    message_type: "offer",
    sender_did: INITIATOR_DID,
    timestamp: omit.includes("timestamp") ? "" : timestamp,
    expires_at: omit.includes("expires_at") ? "" : expiresAt,
    terms,
  });
  const offer: Dict = {
    message_type: "offer",
    message_id: "act-offer-1",
    session_id: sessionId,
    round_number: 1,
    sequence_number: 1,
    sender_did: INITIATOR_DID,
    sender_agent_id: "buyer-agent",
    sender_verification_method: INITIATOR_VM,
    terms,
    protocol_act_hash: actHash,
    protocol_act_signature: signJws(actHash, INITIATOR_PRIVATE_KEY, INITIATOR_VM),
  };
  if (!omit.includes("timestamp")) offer.timestamp = timestamp;
  if (!omit.includes("expires_at")) offer.expires_at = expiresAt;
  manager.processMessage(session, offer);

  const payload = {
    session_id: sessionId,
    round_number: 1,
    sequence_number: 2,
    accepted_offer_id: "act-offer-1",
    accepted_protocol_act_hash: actHash,
  };
  manager.processMessage(session, {
    message_type: "acceptance",
    message_id: "act-acc-1",
    in_reply_to: "act-offer-1",
    ...payload,
    sender_did: RESPONDER_DID,
    sender_agent_id: "seller-agent",
    sender_verification_method: RESPONDER_VM,
    timestamp: "2026-03-24T10:03:00Z",
    acceptance_signature: signJws(hashObject(payload), RESPONDER_PRIVATE_KEY, RESPONDER_VM),
  });
  expect(session.state).toBe(SessionState.COMPLETED);
  return [generateTransactionRecord(session), didDocuments];
}

/**
 * Rebuild the act hash from the record and re-sign both sides over it.
 *
 * The record stays wholly self-consistent, so only the rule under test can
 * decide the verdict. Nothing about what is signed changes: the object being
 * signed is still the Section 7.3.1 act.
 */
function resignedOverItsAct(record: Dict): [Dict, string[]] {
  const value = structuredClone(record);
  const actHash = hashObject(actFromRecord(value));
  (value.final_offer as Dict).protocol_act_hash = actHash;
  (value.final_offer as Dict).protocol_act_signature = signJws(
    actHash,
    INITIATOR_PRIVATE_KEY,
    INITIATOR_VM,
  );
  const acceptance = value.final_acceptance as Dict;
  acceptance.accepted_protocol_act_hash = actHash;
  acceptance.acceptance_signature = signJws(
    hashObject({
      session_id: value.session_id,
      round_number: acceptance.round_number,
      sequence_number: acceptance.sequence_number,
      accepted_offer_id: acceptance.accepted_offer_id,
      accepted_protocol_act_hash: actHash,
    }),
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
  );
  value.offer_chain_hash = hashBytes(canonicalize([actHash]));
  return [resealed(value), [actHash]];
}

test("a record made under a later wire version still recomputes", () => {
  // The record path reads the protocol_version the record carries (Section
  // 9.5). A record produced under a wire version later than this
  // implementation's must still rebuild its act, so the binding does not expire
  // with the wire version.
  const [built, didDocuments] = locallySignedRecord();
  (built.final_offer as Dict).protocol_version = "0.3";
  const [value, offerHashes] = resignedOverItsAct(built);

  expect(verifyTransactionRecord(value, didDocuments, offerHashes)).toBe(true);
});

test("a locally signed record verifies and is 0.3", () => {
  const [value, didDocuments] = locallySignedRecord();

  expect(value.record_version).toBe("0.3");
  expect(
    verifyTransactionRecord(value, didDocuments, [
      (value.final_offer as Dict).protocol_act_hash as string,
    ]),
  ).toBe(true);
});

// ---------------------------------------------------------------------------
// The acceptance side is recomputable from the record
// ---------------------------------------------------------------------------

const ALTERED_ACCEPTANCE_VALUES: Dict = {
  round_number: 1,
  sequence_number: 4,
  accepted_offer_id: "basis-offer-1",
  accepted_protocol_act_hash: (VECTOR.messages as Dict[])[0].protocol_act_hash,
};

test.each(ACCEPTANCE_FIELDS)(
  "an altered acceptance field fails verification: %s",
  (fieldName) => {
    // Section 7.4's payload rebuilds from the record (Section 9.5, step 5).
    // Only the bound version is checked here: an earlier version never reaches
    // this step, since step 1 refuses it first, so asserting a rejection on one
    // would pass for the wrong reason.
    const value = record();
    (value.final_acceptance as Dict)[fieldName] = ALTERED_ACCEPTANCE_VALUES[fieldName];

    expect(value.record_version).toBe("0.3");
    expect(verifies(resealed(value))).toBe(false);
  },
);

test("an altered session_id fails the acceptance payload", () => {
  // session_id is the fifth acceptance field, and it is the record's own.
  const value = record();
  value.session_id = "5a1e0b2c-3d4e-4f60-8a7b-000000000000";

  expect(verifies(resealed(value))).toBe(false);
});

// ---------------------------------------------------------------------------
// The records earlier versions produced are refused as unbound
// ---------------------------------------------------------------------------

test("the 0.2 record a pre-change implementation produced is refused", () => {
  // It carries no act fields, so nothing rebinds agreed_terms to a signature.
  // Accepting it would accept the downgrade: the same bytes are what a
  // presenter produces by stripping the act fields and relabelling.
  const value = EXPECTED_0_2.full_record as Dict;

  expect(value.record_version).toBe("0.2");
  expect(ACT_FIELDS.filter((field) => field in (value.final_offer as Dict))).toEqual([]);
  expect(value.record_hash).toBe(EXPECTED_0_2.record_hash);
  expect(verifies(value)).toBe(false);
  expect(reasonFor(value)).toBe(REASON_UNBOUND_RECORD_VERSION);
});

test("the 0.1 record a pre-basis implementation produced is refused", () => {
  const value = (WITHOUT_BASIS.record_version_0_1 as Dict).full_record as Dict;

  expect(value.record_version).toBe("0.1");
  expect(ACT_FIELDS.filter((field) => field in (value.final_offer as Dict))).toEqual([]);
  expect(verifies(value, WITHOUT_BASIS)).toBe(false);
  expect(reasonFor(value, WITHOUT_BASIS)).toBe(REASON_UNBOUND_RECORD_VERSION);
});

// ---------------------------------------------------------------------------
// A "0.3" record's act numbers and top-level currency, held to the signed act
// ---------------------------------------------------------------------------

const BINDING = VECTOR.record_version_0_3_binding as Dict;
const BASIS_0_3 = ((VECTOR.expected as Dict).record_version_0_3 as Dict).full_record as Dict;

test.each(
  (BINDING.act_integer_spellings as Dict[]).map(
    (spelling) => [spelling.name as string, spelling] as [string, Dict],
  ),
)("an act integer spelling is judged by the rebuilt hash: %s", (_name, spelling) => {
  // RFC 8785 serializes 2.0 and 2 as the same number, so an integral float is
  // the same signed act in a different JSON spelling: the record_hash is
  // unchanged and the record must verify. Anything that is not an integral JSON
  // number is a different act, or no act at all, and is rejected. Both suites
  // read these cases from the same file, so the two cannot drift apart.
  const value = structuredClone(BASIS_0_3);
  const finalOffer = value.final_offer as Dict;
  const field = spelling.field as string;
  if (Object.prototype.hasOwnProperty.call(spelling, "value")) {
    finalOffer[field] = spelling.value;
  } else {
    delete finalOffer[field];
  }

  expect(hashObject({ ...value, record_hash: "" }) === BASIS_0_3.record_hash).toBe(
    spelling.record_hash_unchanged,
  );
  expect(verifies(resealed(value))).toBe(spelling.verifies);
});

test.each(
  (BINDING.currency_cases as Dict[]).map(
    (currencyCase) => [currencyCase.name as string, currencyCase] as [string, Dict],
  ),
)("the top-level currency is bound to agreed_terms under 0.3: %s", (_name, currencyCase) => {
  // Section 9.5 step 8: under "0.3" the top-level currency must equal the
  // signature-bound agreed_terms.currency. A "0.1" or "0.2" record's is not
  // checked, because per-offer currency consistency was only required from the
  // version that added terms.basis onward, so an older genuine record may
  // legitimately differ and must keep verifying. The case that drops
  // agreed_terms.currency also alters the signed terms, so it fails at step 3
  // as well; the two tests below isolate step 8 by re-signing the act.
  const value = recordOfVersion(currencyCase.record_version as string);
  if (Object.prototype.hasOwnProperty.call(currencyCase, "currency")) {
    value.currency = currencyCase.currency;
  }
  if (currencyCase.drop_agreed_terms_currency === true) {
    delete (value.agreed_terms as Dict).currency;
  }

  expect(value.record_version).toBe(currencyCase.record_version);
  expect(verifies(resealed(value))).toBe(currencyCase.verifies);
});

test("a 0.3 record whose signed terms name another currency is rejected", () => {
  // The headline case: agreed_terms is signature-bound and says EUR, while the
  // record's own currency says USD. The act is re-signed over those terms, so
  // step 3 passes and only the top-level currency binding can reject it.
  const [built, didDocuments] = locallySignedRecord();
  (built.agreed_terms as Dict).currency = "EUR";
  const [value, offerHashes] = resignedOverItsAct(built);

  expect(value.currency).toBe("USD");
  expect((value.agreed_terms as Dict).currency).toBe("EUR");
  expect(verifyTransactionRecord(value, didDocuments, offerHashes)).toBe(false);
});

test("a 0.3 record whose signed terms carry no currency is rejected", () => {
  // Also isolated: the act is re-signed over terms without a currency, so step 3
  // passes and the record still states one of its own.
  const [built, didDocuments] = locallySignedRecord();
  delete (built.agreed_terms as Dict).currency;
  const [value, offerHashes] = resignedOverItsAct(built);

  expect(value.currency).toBe("USD");
  expect("currency" in (value.agreed_terms as Dict)).toBe(false);
  expect(verifyTransactionRecord(value, didDocuments, offerHashes)).toBe(false);
});

test("a 0.3 record whose currency matches its signed terms verifies", () => {
  const [built, didDocuments] = locallySignedRecord();
  const [value, offerHashes] = resignedOverItsAct(built);

  expect(value.currency).toBe((value.agreed_terms as Dict).currency);
  expect(verifyTransactionRecord(value, didDocuments, offerHashes)).toBe(true);
});

// ---------------------------------------------------------------------------
// An act signed over an empty or zero field is still recomputable
// ---------------------------------------------------------------------------

test.each([
  ["empty-expires_at", { expiresAt: "" }, "expires_at"],
  ["empty-timestamp", { timestamp: "" }, "timestamp"],
  ["omitted-expires_at", { omit: ["expires_at"] }, "expires_at"],
] as [string, { timestamp?: string; expiresAt?: string; omit?: string[] }, string][])(
  "an act signed over an empty field still verifies: %s",
  (_name, builderOptions, fieldName) => {
    // Section 9.5 step 3: the rebuilt hash decides, not a field's length. Both
    // reference state machines default a missing timestamp or expires_at to ""
    // when they rebuild the act to check its hash, and neither field is
    // validated on the wire, so an offer that carries or omits one is signed,
    // accepted and recorded with "" inside the signed act. A verifier that
    // refused the empty string would reject a record whose signature genuinely
    // covers those bytes.
    const [value, didDocuments] = locallySignedRecord(builderOptions);

    expect((value.final_offer as Dict)[fieldName]).toBe("");
    expect(hashObject(actFromRecord(value))).toBe((value.final_offer as Dict).protocol_act_hash);
    expect(
      verifyTransactionRecord(value, didDocuments, [
        (value.final_offer as Dict).protocol_act_hash as string,
      ]),
    ).toBe(true);
  },
);

test.each(["round_number", "sequence_number"])(
  "a record whose act counts from zero verifies: %s",
  (fieldName) => {
    // A record from elsewhere may number its act from 0, and the hash decides.
    // Both reference state machines refuse such an offer on the wire (Section
    // 7.1), so a record like this can only come from another implementation.
    // Rebinding agreed_terms to its signature is still the hash comparison.
    const [built, didDocuments] = locallySignedRecord();
    (built.final_offer as Dict)[fieldName] = 0;
    const [value, offerHashes] = resignedOverItsAct(built);

    expect(verifyTransactionRecord(value, didDocuments, offerHashes)).toBe(true);
  },
);

test("an empty field still fails when the act hash does not cover it", () => {
  // Relaxing the type guard does not relax the binding itself.
  const [value, didDocuments] = locallySignedRecord();
  const offerHashes = [(value.final_offer as Dict).protocol_act_hash as string];
  (value.final_offer as Dict).expires_at = "";

  expect(verifyTransactionRecord(resealed(value), didDocuments, offerHashes)).toBe(false);
});

test("the empty expires_at vector replays and verifies", () => {
  // The shared session whose offer omits expires_at, replayed on both sides.
  // Both suites must reach the same record and the same verdict, so the rule
  // cannot drift between the two implementations.
  const vector = EMPTY_EXPIRES_AT;
  const expected = vector.record_version_0_3 as Dict;
  const offer = (vector.messages as Dict[])[0];

  expect("expires_at" in offer).toBe(false);
  const value = generateTransactionRecord(replay(vector));

  expect((value.final_offer as Dict).expires_at).toBe("");
  expect(vector.act_expires_at).toBe("");
  expect(JSON.stringify(value)).toBe(JSON.stringify(expected.full_record));
  expect(value.record_hash).toBe(expected.record_hash);
  expect(
    verifyTransactionRecord(
      value,
      vector.did_documents as Record<string, Dict>,
      offerHashes(vector),
    ),
  ).toBe(true);
});
