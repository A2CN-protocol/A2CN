/**
 * Values on a TransactionRecord's key path that Python and TypeScript must refuse alike.
 *
 * A verification method or signature that is not a non-empty string, or a JWS
 * whose protected header is not a JSON object, was refused for different
 * reasons in the two implementations: a truthiness test let a list through one
 * and not the other, and a number reached a string method in one and a
 * catch-all in the other. Both now read these values by type. The Python suite
 * reads the same `transaction-record-key-parity.json`.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import type { Dict } from "../src/a2cn/messages.js";
import { verifyTransactionRecord, verifyTransactionRecordReason } from "../src/a2cn/record.js";
import { REPO_ROOT } from "./support/paths.js";

const VECTOR = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "transaction-record-key-parity.json"), "utf-8"),
) as Dict;
const DIDS = VECTOR.did_documents as Record<string, Dict>;

for (const c of VECTOR.cases as Dict[]) {
  test(`the record reaches the stated reason: ${c.name}`, () => {
    const hashes = c.offer_hashes as string[];
    expect(verifyTransactionRecordReason(c.record as Dict, DIDS, hashes)).toBe(c.expected_reason);
    expect(verifyTransactionRecord(c.record as Dict, DIDS, hashes)).toBe(c.verifies);
  });
}
