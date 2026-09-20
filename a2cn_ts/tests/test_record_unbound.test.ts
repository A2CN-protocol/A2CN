/**
 * A verifier accepts only records it can rebind (Section 9.5).
 *
 * record_version is covered by no signature. A verifier that accepted a version
 * whose records cannot be rebound would let a presenter strip the Section 7.3.1
 * act fields, relabel the record to that version, alter agreed_terms and reseal:
 * both signatures still verify and the record keeps its record_id, so the
 * forgery would be reported as genuine. There is therefore no unbound accepted
 * tier. Only the bound version is accepted; a version this implementation knows
 * but cannot rebind is rejected with UNBOUND_RECORD_VERSION, distinct from the
 * generic rejection any other value gets.
 *
 * This is a deliberate break: records produced before the act fields existed no
 * longer verify and must be regenerated. The Python suite runs the same cases.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import { hashObject } from "../src/a2cn/crypto.js";
import * as recordModule from "../src/a2cn/record.js";
import {
  ACCEPTED_TRANSACTION_RECORD_VERSIONS,
  FINAL_OFFER_ACT_FIELDS,
  KNOWN_TRANSACTION_RECORD_VERSIONS,
  REASON_UNBOUND_RECORD_VERSION,
  REASON_UNRECOGNIZED_RECORD_VERSION,
  TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,
  verifyTransactionRecord,
  verifyTransactionRecordReason,
} from "../src/a2cn/record.js";
import type { Dict } from "../src/a2cn/messages.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function readJson(...parts: string[]): Dict {
  return JSON.parse(readFileSync(join(REPO_ROOT, ...parts), "utf-8")) as Dict;
}

const VECTOR = readJson("spec", "test-vectors", "transaction-record-basis.json");
const RECORD_VERSIONS = readJson("spec", "test-vectors", "record-versions.json");
// Each artifact versions its own shape, so the TransactionRecord's set is its own.
const TR_VERSIONS = RECORD_VERSIONS.transaction_record as Dict;
const WITHOUT_BASIS = VECTOR.without_basis as Dict;
const DOWNGRADE = VECTOR.downgrade_attack as Dict;
const BOUND = ((VECTOR.expected as Dict).record_version_0_3 as Dict).full_record as Dict;
// The cases both suites apply to that record, one for each reason a verifier can
// give, so the two implementations must name the same cause for the same bytes.
const REASON_API = VECTOR.reason_api as Dict;
const REASON_CASES = REASON_API.cases as Dict[];
const TAMPERED_SUFFIX = REASON_API.tampered_signature_suffix as string;
// Every reason code the module exports, found by reflection: a code added
// without a case fails this file rather than sitting unreachable.
const ALL_REASON_CODES = new Set(
  Object.entries(recordModule)
    .filter(([name]) => name.startsWith("REASON_"))
    .map(([, value]) => value as string),
);

// The recorded session each record shape came from, for its DID documents and
// its offer chain.
const SHAPE_VECTOR: Record<string, Dict> = {
  "0.1": WITHOUT_BASIS,
  "0.2": VECTOR,
  "0.3": VECTOR,
};

function offerHashes(vector: Dict): string[] {
  return (vector.messages as Dict[])
    .filter((m) => m.message_type === "offer" || m.message_type === "counteroffer")
    .map((m) => m.protocol_act_hash as string);
}

/** A valid record of the given shape, as its producer emitted it. */
function shapedRecord(version: string): Dict {
  if (version === "0.3") {
    return structuredClone(BOUND);
  }
  if (version === "0.2") {
    return structuredClone(
      ((VECTOR.expected as Dict).record_version_0_2 as Dict).full_record as Dict,
    );
  }
  return structuredClone((WITHOUT_BASIS.record_version_0_1 as Dict).full_record as Dict);
}

function resealed(record: Dict): Dict {
  const copy = structuredClone(record);
  copy.record_hash = "";
  copy.record_hash = hashObject(copy);
  return copy;
}

/** The boolean and the reason, which must always agree. */
function verdict(record: Dict, shape = "0.3"): [boolean, string | null] {
  const vector = SHAPE_VECTOR[shape];
  const dids = vector.did_documents as Record<string, Dict>;
  const hashes = offerHashes(vector);
  return [
    verifyTransactionRecord(record, dids, hashes),
    verifyTransactionRecordReason(record, dids, hashes),
  ];
}

// ---------------------------------------------------------------------------
// The downgrade a verifier must refuse
// ---------------------------------------------------------------------------

test.each(
  (DOWNGRADE.cases as Dict[]).map((c) => [c.name as string, c] as [string, Dict]),
)("a downgraded record is rejected: %s", (_name, downgradeCase) => {
  // Both signatures still verify and the record_id is the genuine one.
  const record = downgradeCase.full_record as Dict;

  expect(record.record_hash).toBe(downgradeCase.record_hash);
  expect(record.record_id).toBe(BOUND.record_id);
  expect((record.final_offer as Dict).protocol_act_signature).toBe(
    (BOUND.final_offer as Dict).protocol_act_signature,
  );

  const [verified, reason] = verdict(record);
  expect(verified).toBe(false);
  expect(reason).toBe(downgradeCase.expected_reason);
  expect(reason).toBe(REASON_UNBOUND_RECORD_VERSION);
});

test("the untouched downgrade is the historical record itself", () => {
  // Stripping the act fields and relabelling reproduces the "0.2" record
  // exactly. That is what made the unbound tier a downgrade oracle: the forged
  // shape and the genuine older artifact are the same bytes.
  const untouched = (DOWNGRADE.cases as Dict[]).find(
    (c) => c.name === "stripped-and-relabelled-0.2-terms-untouched",
  ) as Dict;

  expect(untouched.record_hash).toBe(
    ((VECTOR.expected as Dict).record_version_0_2 as Dict).record_hash,
  );
});

// ---------------------------------------------------------------------------
// The collapsed accepted set
// ---------------------------------------------------------------------------

test("only the bound version is accepted", () => {
  expect([...ACCEPTED_TRANSACTION_RECORD_VERSIONS]).toEqual([
    TRANSACTION_RECORD_VERSION_RECOMPUTABLE_ACT,
  ]);
  expect([...ACCEPTED_TRANSACTION_RECORD_VERSIONS]).toEqual(TR_VERSIONS.accepted);
  // The older shapes are still known, because their schema files are published.
  expect([...KNOWN_TRANSACTION_RECORD_VERSIONS].sort()).toEqual(["0.1", "0.2", "0.3"]);
  for (const version of ACCEPTED_TRANSACTION_RECORD_VERSIONS) {
    expect(KNOWN_TRANSACTION_RECORD_VERSIONS).toContain(version);
  }
  expect(ACCEPTED_TRANSACTION_RECORD_VERSIONS.length).toBeLessThan(
    KNOWN_TRANSACTION_RECORD_VERSIONS.length,
  );
});

test("the bound record still verifies", () => {
  const [verified, reason] = verdict(shapedRecord("0.3"));

  expect(verified).toBe(true);
  expect(reason).toBeNull();
});

test.each(
  (TR_VERSIONS.unbound as Dict[]).map((c) => [c.name as string, c] as [string, Dict]),
)("a known but unbindable version is rejected as unbound: %s", (_name, unboundCase) => {
  const record = shapedRecord(unboundCase.shape as string);
  record.record_version = unboundCase.record_version;

  const [verified, reason] = verdict(resealed(record), unboundCase.shape as string);
  expect(verified).toBe(false);
  expect(reason).toBe(REASON_UNBOUND_RECORD_VERSION);
  // The reason both implementations report is the one the shared vector names.
  expect(reason).toBe(TR_VERSIONS.unbound_reason);
});

test.each(
  (TR_VERSIONS.rejected as Dict[]).map((c) => [c.name as string, c] as [string, Dict]),
)("a value that is not a known version is rejected as unrecognized: %s", (_name, rejectedCase) => {
  // The generic rejection stays, and is distinct from the unbound one.
  const record = shapedRecord("0.3");
  if (Object.prototype.hasOwnProperty.call(rejectedCase, "record_version")) {
    record.record_version = structuredClone(rejectedCase.record_version);
  } else {
    delete record.record_version;
  }

  const [verified, reason] = verdict(resealed(record));
  expect(verified).toBe(false);
  expect(reason).toBe(REASON_UNRECOGNIZED_RECORD_VERSION);
  expect(reason).not.toBe(REASON_UNBOUND_RECORD_VERSION);
  expect(reason).toBe(TR_VERSIONS.unrecognized_reason);
});

// ---------------------------------------------------------------------------
// The boolean API is unchanged
// ---------------------------------------------------------------------------

test("the boolean verifier keeps its signature and return type", () => {
  // Callers that only want a verdict are untouched by the reason API.
  const record = shapedRecord("0.3");
  const dids = VECTOR.did_documents as Record<string, Dict>;

  expect(verifyTransactionRecord(record, dids)).toBe(false);
  const result = verifyTransactionRecord(record, dids, offerHashes(VECTOR));
  expect(typeof result).toBe("boolean");
  expect(result).toBe(true);
});

test("the reason is null exactly when the boolean is true", () => {
  // The two entry points never disagree, and a reason is never a bool. The
  // boolean is `reason(...) === null`, so a reason that is a bool keeps the
  // verdict right while the diagnostic lies. Pinning only the agreement cannot
  // see that; pinning the type can.
  const records: Dict[] = [
    shapedRecord("0.3"),
    resealed({ ...shapedRecord("0.3"), record_version: "0.2" }),
    (DOWNGRADE.cases as Dict[])[0].full_record as Dict,
    ...REASON_CASES.map((c) => mutated(c)),
  ];
  for (const record of records) {
    const [verified, reason] = verdict(record);
    expect(verified).toBe(reason === null);
    // A reason is a string or absent, never false, 0 or another falsy value.
    expect(reason === null || typeof reason === "string").toBe(true);
    expect(typeof reason).not.toBe("boolean");
  }
});

// ---------------------------------------------------------------------------
// The reason names the real cause (Section 9.5)
// ---------------------------------------------------------------------------

/** Apply one shared case to the bound record, resealing when it says to. */
function mutated(useCase: Dict): Dict {
  const record = shapedRecord("0.3");
  const mutation = useCase.mutation as string;
  const value = useCase.value;
  const finalOffer = record.final_offer as Dict;
  const finalAcceptance = record.final_acceptance as Dict;

  if (mutation === "tamper_offer_signature") {
    const signature = finalOffer.protocol_act_signature as string;
    finalOffer.protocol_act_signature =
      signature.slice(0, -TAMPERED_SUFFIX.length) + TAMPERED_SUFFIX;
  } else if (mutation === "tamper_acceptance_signature") {
    const signature = finalAcceptance.acceptance_signature as string;
    finalAcceptance.acceptance_signature =
      signature.slice(0, -TAMPERED_SUFFIX.length) + TAMPERED_SUFFIX;
  } else if (mutation === "drop_final_offer") {
    delete record.final_offer;
  } else if (mutation === "drop_final_acceptance") {
    delete record.final_acceptance;
  } else if (mutation === "set_record_version") {
    record.record_version = value;
  } else if (mutation === "strip_act_fields") {
    for (const field of FINAL_OFFER_ACT_FIELDS) {
      delete finalOffer[field];
    }
  } else if (mutation === "set_currency") {
    record.currency = value;
  } else if (mutation === "set_agreed_terms_total_value") {
    (record.agreed_terms as Dict).total_value = value;
  } else if (mutation === "flip_basis") {
    record.basis = record.basis === "net" ? "gross" : "net";
  } else if (mutation === "set_accepted_hash") {
    finalAcceptance.accepted_protocol_act_hash = value;
  } else if (mutation === "set_offer_chain_hash") {
    record.offer_chain_hash = value;
  } else {
    throw new Error(`unknown mutation ${mutation}`);
  }

  return useCase.reseal ? resealed(record) : record;
}

test.each(REASON_CASES.map((c) => [c.name as string, c] as [string, Dict]))(
  "the reason names the real cause: %s",
  (_name, useCase) => {
    // A tampered signature is a signature failure, not a malformed record.
    // verifyJws throws on bad signature bytes. Letting that escape to the outer
    // handler reports the single most likely failure -- someone edited a
    // signature -- as the catch-all.
    const [verified, reason] = verdict(mutated(useCase));

    expect(verified).toBe(false);
    expect(reason).toBe(useCase.expected_reason);
    expect(typeof reason).toBe("string");
  },
);

test("every reason code is reachable", () => {
  // No exported reason code is dead. REASON_MALFORMED_RECORD was defined and
  // never returned in Python, because the handler that should have returned it
  // returned false instead. A code no case can reach is either a missing test
  // or a lie in the taxonomy.
  const observed = new Set(REASON_CASES.map((c) => verdict(mutated(c))[1]));

  expect([...observed].sort()).toEqual([...ALL_REASON_CODES].sort());
});
