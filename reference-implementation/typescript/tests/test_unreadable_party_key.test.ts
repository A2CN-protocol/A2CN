/**
 * A party key its DID document lists but that cannot be read is unavailable, not malformed.
 *
 * A public JWK coordinate must be unpadded base64url (RFC 7515, RFC 7518). A
 * signer whose document spells one otherwise has a key no verifier can read,
 * which says nothing about the record: the evidence verifier reports
 * KEY_NOT_FOUND here, and the record rows live in
 * transaction-record-key-parity.json, which both suites run.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { publicKeyFromJwk } from "../src/a2cn/crypto.js";
import { EVIDENCE_REASON_KEY_NOT_FOUND, assessSessionEvidenceRecord } from "../src/a2cn/evidence.js";
import type { Dict } from "../src/a2cn/messages.js";
import { REPO_ROOT } from "./support/paths.js";

const HISTORY = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "transaction-record-offer-history.json"), "utf-8"),
) as Dict;

function paddedX(documents: Record<string, Dict>, did: string): Record<string, Dict> {
  const copy = structuredClone(documents);
  const jwk = ((copy[did].verificationMethod as Dict[])[0].publicKeyJwk as Dict);
  const x = jwk.x as string;
  jwk.x = x + "=".repeat((4 - (x.length % 4)) % 4);
  return copy;
}

test("the evidence verifier reports an unreadable key as unavailable", () => {
  const record = HISTORY.evidence_record as Dict;
  const documents = (HISTORY.did_documents as Dict).current as Record<string, Dict>;
  expect(assessSessionEvidenceRecord(record, documents).reason).toBe(null);
  for (const did of Object.keys(documents)) {
    expect(assessSessionEvidenceRecord(record, paddedX(documents, did)).reason).toBe(
      EVIDENCE_REASON_KEY_NOT_FOUND,
    );
  }
});

test("an unreadable coordinate says which coordinate and why", () => {
  const documents = (HISTORY.did_documents as Dict).current as Record<string, Dict>;
  const did = Object.keys(documents)[0];
  const jwk = (paddedX(documents, did)[did].verificationMethod as Dict[])[0].publicKeyJwk as Dict;
  expect(() => publicKeyFromJwk(jwk)).toThrow("its x coordinate isn't unpadded base64url (RFC 7518)");
});
