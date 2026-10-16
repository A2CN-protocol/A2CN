/**
 * ApprovalReceipt signatures verify identically in both reference implementations.
 *
 * The vector holds receipts signed by the Python and the TypeScript
 * implementation with Ed25519 and ES256, and receipts that must be refused.
 * Both suites verify every case and must reach the same verdict.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { publicKeyFromJwk, verifyApprovalReceiptSignature } from "../src/a2cn/crypto.js";
import type { Dict } from "../src/a2cn/messages.js";
import { SPEC_DIR } from "./support/paths.js";

const VECTOR = JSON.parse(
  readFileSync(join(SPEC_DIR, "test-vectors", "approval-receipt-signature.json"), "utf-8"),
) as { cases: Dict[] };

test("the vector covers both languages and both algorithms", () => {
  const signed = new Set(
    VECTOR.cases
      .filter((c) => c.verifies && !(c.name as string).includes("_member"))
      .map((c) => `${c.signed_in}/${((c.receipt as Dict).signature as Dict).alg}`),
  );
  expect([...signed].sort()).toEqual(["python/ES256", "python/Ed25519", "typescript/ES256", "typescript/Ed25519"]);
  expect(VECTOR.cases.some((c) => !c.verifies)).toBe(true);
});

for (const c of VECTOR.cases) {
  test(`receipt signature verdict: ${c.name}`, () => {
    const publicKey = publicKeyFromJwk(c.public_key_jwk as Record<string, unknown>);
    expect(verifyApprovalReceiptSignature(c.receipt as Dict, publicKey)).toBe(c.verifies);
  });
}

test("the section 14.1 example receipt verifies with the example key", () => {
  // The specification's example must be a receipt this implementation accepts.
  const spec = readFileSync(join(SPEC_DIR, "a2cn-spec-v0.2.0.md"), "utf-8");
  const section = spec.slice(
    spec.indexOf("### 14.1 ApprovalReceipt Artifact"),
    spec.indexOf("### 14.2 Transition Semantics"),
  );
  const blocks = [...section.matchAll(/```json\n(\{[\s\S]*?\})\n```/g)].map((m) => m[1]);
  const [example, key] = blocks.slice(-2);
  const receipt = JSON.parse(example) as Dict;
  const publicKey = publicKeyFromJwk(JSON.parse(key) as Record<string, unknown>);
  expect(verifyApprovalReceiptSignature(receipt, publicKey)).toBe(true);
  (receipt.scope as Dict).amount = "1.00 USD";
  expect(verifyApprovalReceiptSignature(receipt, publicKey)).toBe(false);
});
