/**
 * Section 9A.12: the accepted-act rule is keyed on the terms.
 *
 * An external-channel record must not attest an in-band acceptance of terms
 * the responder signed, whichever field names them and whether the acceptance
 * names the signed act or an unsigned copy of its terms. The cases are in
 * `session-evidence-record-external-acceptance.json`, and the Python suite reads
 * the same bytes.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import {
  assessSessionEvidenceRecord,
  verifySessionEvidenceRecord,
} from "../src/a2cn/evidence.js";
import type { Dict } from "../src/a2cn/messages.js";
import { SPEC_DIR } from "./support/paths.js";

const VECTOR = JSON.parse(
  readFileSync(
    join(SPEC_DIR, "test-vectors", "session-evidence-record-external-acceptance.json"),
    "utf-8",
  ),
) as Dict;
const CASES = VECTOR.cases as Dict[];
const DIDS = VECTOR.did_documents as Record<string, Dict>;

for (const c of CASES) {
  test(`the record reaches the stated verdict: ${c.name}`, () => {
    expect(verifySessionEvidenceRecord(c.record as Dict, DIDS)).toBe(c.verifies);
  });
}

for (const c of CASES.filter((c) => !c.verifies)) {
  test(`a refused record has no invalid act: ${c.name}`, () => {
    // Every act verifies on its own: the accepted-act rule alone refuses the record.
    const assessment = assessSessionEvidenceRecord(c.record as Dict, DIDS);
    expect(assessment.invalid_acts).toBe(0);
    expect(Object.prototype.hasOwnProperty.call(c.record, "external_commitment_reference")).toBe(
      true,
    );
  });
}

test("the vector covers every evasion and both controls", () => {
  const names = new Set(CASES.map((c) => c.name));
  for (const name of [
    "reference_through_in_reply_to",
    "reference_inside_terms",
    "unsigned_recorded_copy",
    "accepts_initiator_offer",
    "accepts_unsigned_observed_offer",
  ]) {
    expect(names.has(name)).toBe(true);
  }
});
