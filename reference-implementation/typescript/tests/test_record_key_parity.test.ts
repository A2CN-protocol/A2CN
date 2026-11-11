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

import {
  InvalidSignatureError,
  b64urlDecodeCanonical,
  b64urlEncode,
  generateEd25519Keypair,
  generateKeypair,
  publicKeyFromJwk,
  publicKeyToJwk,
  signInvitation,
  verifyInvitationSignature,
  verifyJws,
} from "../src/a2cn/crypto.js";
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

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** The same bytes under a non-canonical text: an unused trailing bit set. */
function flipUnusedBit(text: string): string {
  expect([2, 3]).toContain(text.length % 4);
  return text.slice(0, -1) + ALPHABET[ALPHABET.indexOf(text[text.length - 1]) | 1];
}

/** A genuine ES256 compact JWS over the segment texts exactly as given. */
function signedTexts(privateKey: Parameters<typeof sign>[2], headerText: string, payloadText: string): string {
  const signingInput = `${headerText}.${payloadText}`;
  const signature = sign("sha256", Buffer.from(signingInput, "ascii"), {
    key: privateKey as never,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${b64urlEncode(signature)}`;
}

// The header {"alg":"ES256","x":"??>~"} encodes with "-" and "_" and unused trailing bits.
const HEADER = b64urlEncode(Buffer.from('{"alg":"ES256","x":"??>~"}'));
const PAYLOAD = b64urlEncode(Buffer.from("payload1"));
const SHAPES: [string, "header" | "payload" | "signature", string | null][] = [
  ["star", "header", `${HEADER.slice(0, 4)}*${HEADER.slice(4)}`],
  ["space", "header", `${HEADER.slice(0, 4)} ${HEADER.slice(4)}`],
  ["newline", "header", `${HEADER.slice(0, 4)}\n${HEADER.slice(4)}`],
  ["plus-slash", "header", HEADER.replace(/-/g, "+").replace(/_/g, "/")],
  ["padding", "header", HEADER + "=".repeat((4 - (HEADER.length % 4)) % 4)],
  ["padding-inside", "header", `${HEADER.slice(0, 4)}=${HEADER.slice(4)}`],
  ["length-1-mod-4", "header", `${b64urlEncode(Buffer.from('{"alg":"ES256"}'))}A`],
  ["noncanonical-tail", "header", null],
  ["length-1-mod-4", "payload", `${b64urlEncode(Buffer.from("payloa"))}A`],
  ["noncanonical-tail", "payload", null],
  ["padding", "signature", null],
  ["noncanonical-tail", "signature", null],
];

for (const [label, segment, given] of SHAPES) {
  test(`a JWS segment is canonical unpadded base64url: ${segment} ${label}`, () => {
    expect(HEADER).toMatch(/-/);
    expect(HEADER).toMatch(/_/);
    const { privateKey, publicKey } = generateKeypair();
    const good = signedTexts(privateKey, HEADER, PAYLOAD);
    expect(verifyJws(good, publicKey)).toBe("payload1");
    let token: string;
    if (segment === "header") {
      token = signedTexts(privateKey, given ?? flipUnusedBit(HEADER), PAYLOAD);
    } else if (segment === "payload") {
      token = signedTexts(privateKey, HEADER, given ?? flipUnusedBit(PAYLOAD));
    } else {
      const cut = good.lastIndexOf(".");
      const signature = good.slice(cut + 1);
      const bad =
        label === "padding"
          ? signature + "=".repeat((4 - (signature.length % 4)) % 4)
          : flipUnusedBit(signature);
      token = `${good.slice(0, cut)}.${bad}`;
    }
    expect(() => verifyJws(token, publicKey)).toThrow(InvalidSignatureError);
  });
}

const JWK_SPOILS: Record<string, (v: string) => string> = {
  padding: (v) => `${v}=`,
  star: (v) => `${v.slice(0, 4)}*${v.slice(4)}`,
  space: (v) => `${v.slice(0, 4)} ${v.slice(4)}`,
  "plus-slash": (v) => (/[-_]/.test(v) ? v.replace(/-/g, "+").replace(/_/g, "/") : `${v}=`),
};

for (const [label, spoil] of Object.entries(JWK_SPOILS)) {
  test(`a public JWK coordinate is canonical base64url: ${label}`, () => {
    const { publicKey } = generateKeypair();
    const jwk = publicKeyToJwk(publicKey);
    publicKeyFromJwk(jwk);
    for (const name of ["x", "y"]) {
      expect(() => publicKeyFromJwk({ ...jwk, [name]: spoil(jwk[name]) })).toThrow();
    }
  });
}

for (const label of ["padding", "noncanonical-tail", "star"]) {
  test(`an invitation signature is canonical base64url: ${label}`, () => {
    const { privateKey, publicKey } = generateEd25519Keypair();
    const invitation: Dict = { invitation_id: "inv-1", inviter_did: "did:web:buyer.example" };
    invitation.invitation_signature = signInvitation(invitation, privateKey);
    expect(verifyInvitationSignature(invitation, publicKey)).toBe(true);
    const signature = invitation.invitation_signature as string;
    const spoiled = {
      padding: signature + "=".repeat((4 - (signature.length % 4)) % 4),
      "noncanonical-tail": flipUnusedBit(signature),
      star: `${signature.slice(0, 4)}*${signature.slice(4)}`,
    }[label] as string;
    expect(spoiled).not.toBe(signature);
    expect(verifyInvitationSignature({ ...invitation, invitation_signature: spoiled }, publicKey)).toBe(false);
  });
}

const DECODER_RULES: [string, RegExp][] = [
  ["ab*c", /character outside/],
  ["ab c", /character outside/],
  ["ab+c", /character outside/],
  ["abc=", /character outside/],
  ["abcde", /one character more than a multiple of four/],
  ["abd", /not canonical/],
];

for (const [text, rule] of DECODER_RULES) {
  test(`the base64url decoder names the rule a text breaks: ${JSON.stringify(text)}`, () => {
    expect([...b64urlDecodeCanonical("abc")]).toEqual([0x69, 0xb7]);
    expect(() => b64urlDecodeCanonical(text)).toThrow(rule);
  });
}
