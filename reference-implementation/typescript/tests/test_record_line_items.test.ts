/**
 * Section 9.5 step 9: a record's agreed terms are held to Section 7.2's money encoding.
 *
 * The offer path refuses a line item that states its money under the bare
 * `unit_price` / `total` names, or as anything but an integer number of minor
 * units. A verifier must not rely on the producer having run that check: a
 * producer that signed such terms itself gets a record whose hashes and
 * signatures are all genuine, and only this step stands between it and a
 * hundredfold misreading of the agreed price. Each case in
 * `transaction-record-line-items.json` is such a record, and the Python suite
 * reads the same bytes.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { A2CNError } from "../src/a2cn/errors.js";
import { termsLineItemViolation } from "../src/a2cn/line_items.js";
import type { Dict } from "../src/a2cn/messages.js";
import {
  REASON_LINE_ITEMS_INVALID,
  verifyTransactionRecord,
  verifyTransactionRecordReason,
} from "../src/a2cn/record.js";
import { checkOfferLineItems, checkOfferMoneyParams } from "../src/a2cn/session.js";
import { REPO_ROOT } from "./support/paths.js";

const VECTOR_PATH = join(REPO_ROOT, "spec", "test-vectors", "transaction-record-line-items.json");
const VECTOR = JSON.parse(readFileSync(VECTOR_PATH, "utf-8")) as Dict;
const CASES = VECTOR.cases as Dict[];
const DIDS = VECTOR.did_documents as Record<string, Dict>;

function caught(run: () => void): unknown {
  try {
    run();
    return null;
  } catch (error) {
    return error;
  }
}

function reason(c: Dict): string | null {
  return verifyTransactionRecordReason(c.record as Dict, DIDS, c.offer_hashes as string[]);
}

for (const c of CASES) {
  test(`the record reaches the stated verdict: ${c.name}`, () => {
    expect(reason(c)).toBe(c.expected_reason);
    expect(verifyTransactionRecord(c.record as Dict, DIDS, c.offer_hashes as string[])).toBe(
      c.verifies,
    );
  });

  test(`the record and the offer path apply one rule: ${c.name}`, () => {
    // The verifier refuses exactly what the offer path refuses, for the same terms.
    const record = c.record as Dict;
    const params: Dict = { currency: record.currency };
    if (Object.prototype.hasOwnProperty.call(record, "basis")) {
      params.basis = record.basis;
    }
    const refused = caught(() => checkOfferMoneyParams(params, record.agreed_terms));
    if (c.verifies) {
      expect(refused).toBeNull();
    } else {
      expect(refused).toBeInstanceOf(A2CNError);
      expect((refused as A2CNError).code).toBe("INVALID_LINE_ITEM");
    }
  });

  test(`the line item message is the offer path's: ${c.name}`, () => {
    // Where a line item is at fault, both paths name it in the same words.
    const terms = (c.record as Dict).agreed_terms;
    const violation = termsLineItemViolation(terms);
    const refused = caught(() => checkOfferLineItems(terms));
    if (violation === null) {
      expect(refused).toBeNull();
    } else {
      expect((refused as A2CNError).message).toBe(violation);
    }
  });
}

for (const c of CASES.filter((c) => !c.verifies)) {
  test(`a refused record is refused at step 9 alone: ${c.name}`, () => {
    // Every other step passes: the hashes and both signatures are genuine.
    expect(reason(c)).toBe(REASON_LINE_ITEMS_INVALID);
  });
}

test("the whole number float case is spelled as a float", () => {
  // The parity case is only a parity case if the bytes carry the float spelling.
  expect(readFileSync(VECTOR_PATH, "utf-8")).toContain('"unit_price_minor": 100000.0');
  const c = CASES.find((c) => c.name === "whole_number_float_minor") as Dict;
  expect(c.verifies).toBe(true);
});

test("a record without line items is untouched", () => {
  // line_items is OPTIONAL: removing it leaves nothing for step 9 to refuse.
  const c = CASES.find((c) => c.name === "bare_major_units") as Dict;
  const terms = { ...((c.record as Dict).agreed_terms as Dict) };
  delete terms.line_items;
  expect(termsLineItemViolation(terms)).toBeNull();
});
