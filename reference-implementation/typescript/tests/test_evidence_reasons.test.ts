/**
 * Why a SessionEvidenceRecord does not verify (Section 9A.6).
 *
 * verifySessionEvidenceRecordReason names the first check a record fails, as
 * verifyTransactionRecordReason does for a TransactionRecord. The cases in
 * `session-evidence-record-reasons.json` each fail exactly one check, and the
 * Python suite reads the same bytes, so the two implementations must name the
 * same cause.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import * as evidenceModule from "../src/a2cn/evidence.js";
import {
  assessSessionEvidenceRecord,
  verifySessionEvidenceRecord,
  verifySessionEvidenceRecordReason,
} from "../src/a2cn/evidence.js";
import type { Dict } from "../src/a2cn/messages.js";
import { SPEC_DIR } from "./support/paths.js";

const VECTOR = JSON.parse(
  readFileSync(join(SPEC_DIR, "test-vectors", "session-evidence-record-reasons.json"), "utf-8"),
) as Dict;
const CASES = VECTOR.cases as Dict[];
const DIDS = VECTOR.did_documents as Record<string, Record<string, Dict>>;
// Every reason code the module exports, found by reflection: a code added
// without a case fails this file rather than sitting unreachable.
const ALL_REASON_CODES = new Set(
  Object.entries(evidenceModule)
    .filter(([name]) => name.startsWith("EVIDENCE_REASON_"))
    .map(([, value]) => value as string),
);

for (const c of CASES) {
  test(`the reason names the check that failed: ${c.name}`, () => {
    const didDocuments = DIDS[c.base as string];
    const reason = verifySessionEvidenceRecordReason(c.record as Dict, didDocuments);
    expect(reason).toBe(c.expected_reason);
    expect(typeof reason).toBe("string");
    expect(verifySessionEvidenceRecord(c.record as Dict, didDocuments)).toBe(false);
    expect(assessSessionEvidenceRecord(c.record as Dict, didDocuments).reason).toBe(reason);
  });
}

const HISTORY = JSON.parse(
  readFileSync(join(SPEC_DIR, "test-vectors", "transaction-record-offer-history.json"), "utf-8"),
) as Dict;

test("every reason code is reachable", () => {
  const observed = new Set(CASES.map((c) => c.expected_reason as string));
  // A key the signer's document does not list needs other DID documents.
  for (const c of HISTORY.record_cases as Dict[]) {
    if (c.record === "evidence_record") {
      observed.add(
        verifySessionEvidenceRecordReason(
          HISTORY.evidence_record as Dict,
          (HISTORY.did_documents as Record<string, Record<string, Dict>>)[c.did_documents as string],
        ) as string,
      );
    }
  }
  expect([...observed].sort()).toEqual([...ALL_REASON_CODES].sort());
});
