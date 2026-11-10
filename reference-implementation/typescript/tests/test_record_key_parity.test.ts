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

import { sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { InvalidSignatureError, b64urlEncode, generateKeypair, verifyJws } from "../src/a2cn/crypto.js";
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

for (const token of [7, true, null, [], {}]) {
  test(`verifyJws refuses a token that is not a string: ${JSON.stringify(token)}`, () => {
    const { publicKey } = generateKeypair();
    expect(() => verifyJws(token as unknown as string, publicKey)).toThrow(InvalidSignatureError);
  });
}

/** A genuine ES256 compact JWS over the given raw header and payload bytes. */
function signedSegments(privateKey: Parameters<typeof sign>[2], header: Buffer, payload: Buffer): string {
  const signingInput = `${b64urlEncode(header)}.${b64urlEncode(payload)}`;
  const signature = sign("sha256", Buffer.from(signingInput, "ascii"), {
    key: privateKey as never,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${b64urlEncode(signature)}`;
}

const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const SEGMENT_CASES: Record<string, [Buffer, Buffer]> = {
  "payload-bom": [Buffer.from('{"alg":"ES256"}'), Buffer.concat([BOM, Buffer.from("payload")])],
  "payload-not-utf8": [Buffer.from('{"alg":"ES256"}'), Buffer.from([0x70, 0x61, 0x79, 0xff, 0x6c])],
  "header-bom": [Buffer.concat([BOM, Buffer.from('{"alg":"ES256"}')]), Buffer.from("payload")],
  "header-not-utf8": [
    Buffer.concat([Buffer.from('{"alg":"ES256","x":"'), Buffer.from([0xff]), Buffer.from('"}')]),
    Buffer.from("payload"),
  ],
  "header-nan": [Buffer.from('{"alg":"ES256","x":NaN}'), Buffer.from("payload")],
};

for (const [label, [header, payload]] of Object.entries(SEGMENT_CASES)) {
  test(`a JWS segment is strict UTF-8 JSON with no BOM: ${label}`, () => {
    const { privateKey, publicKey } = generateKeypair();
    const good = signedSegments(privateKey, Buffer.from('{"alg":"ES256"}'), Buffer.from("payload"));
    expect(verifyJws(good, publicKey)).toBe("payload");
    expect(() => verifyJws(signedSegments(privateKey, header, payload), publicKey)).toThrow(
      InvalidSignatureError,
    );
  });
}
