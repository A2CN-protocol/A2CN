/**
 * A TransactionRecord's offer history, taken from its SessionEvidenceRecord.
 *
 * offer_chain_hash is covered by neither signature, so the earlier offers must
 * come from somewhere a verifier can check: the session's evidence record,
 * which holds every offer as a signed act and names the TransactionRecord by
 * transaction_record_hash. The Python suite reads the same vector.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { assessSessionEvidenceRecord, offerHistoryFromEvidence } from "../src/a2cn/evidence.js";
import type { Dict } from "../src/a2cn/messages.js";
import { verifyTransactionRecordReason } from "../src/a2cn/record.js";
import { SPEC_DIR } from "./support/paths.js";

const VECTOR = JSON.parse(
  readFileSync(join(SPEC_DIR, "test-vectors", "transaction-record-offer-history.json"), "utf-8"),
) as Dict;
const DIDS = VECTOR.did_documents as Record<string, Record<string, Dict>>;
const TR = VECTOR.transaction_record as Dict;

for (const c of VECTOR.history_cases as Dict[]) {
  test(`the history is taken only from a linked, verified, complete record: ${c.name}`, () => {
    const { history, reason } = offerHistoryFromEvidence(TR, c.evidence_record as Dict, DIDS.current);
    expect(history).toEqual(c.expected_history);
    expect(reason).toBe(c.expected_reason);
  });
}

for (const c of VECTOR.record_cases as Dict[]) {
  test(`the records reach the stated verdicts: ${c.name}`, () => {
    const documents = DIDS[c.did_documents as string];
    let reason: string | null;
    if (c.record === "transaction_record") {
      reason = verifyTransactionRecordReason(TR, documents, c.offer_hashes as string[] | null);
    } else {
      const assessment = assessSessionEvidenceRecord(VECTOR.evidence_record as Dict, documents);
      reason = assessment.reason;
      expect(assessment.unresolved_keys).toEqual(c.expected_unresolved_keys ?? []);
    }
    expect(reason).toBe(c.expected_reason);
  });
}

test("the history completes the record", () => {
  const { history, reason } = offerHistoryFromEvidence(TR, VECTOR.evidence_record as Dict, DIDS.current);
  expect(reason).toBeNull();
  expect(history).toHaveLength(2);
  expect((TR.final_offer as Dict).round_number).toBe(2);
  expect(verifyTransactionRecordReason(TR, DIDS.current, history)).toBeNull();
});
