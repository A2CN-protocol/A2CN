/** Tests for a2cn/crypto */

import { describe, expect, test } from "vitest";

import {
  generateKeypair,
  generateEd25519Keypair,
  privateKeyToJwk,
  publicKeyToJwk,
  publicKeyFromJwk,
  privateKeyFromJwk,
  canonicalize,
  hashObject,
  signJws,
  verifyJws,
  createJwt,
  verifyJwt,
  InvalidSignatureError,
  b64urlDecode,
} from "../src/a2cn/crypto.js";

// ---------------------------------------------------------------------------
// Sanity check: JCS library behaviour
// ---------------------------------------------------------------------------

test("jcs key ordering", () => {
  // JCS must sort keys, not just serialize.
  const result = canonicalize({ b: 2, a: 1 });
  expect(result.toString("utf-8")).toBe('{"a":1,"b":2}');
});

test("jcs nested", () => {
  const result = canonicalize({ z: { b: 2, a: 1 }, a: 0 });
  expect(result.toString("utf-8")).toBe('{"a":0,"z":{"a":1,"b":2}}');
});

// ---------------------------------------------------------------------------
// Keypair generation
// ---------------------------------------------------------------------------

test("generate keypair returns p256", () => {
  const { privateKey, publicKey } = generateKeypair();
  expect(privateKey.asymmetricKeyType).toBe("ec");
  expect(publicKey.asymmetricKeyType).toBe("ec");
  expect(privateKey.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
  expect(publicKey.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
});

test("generate ed25519 keypair returns ed25519", () => {
  const { privateKey, publicKey } = generateEd25519Keypair();
  expect(privateKey.asymmetricKeyType).toBe("ed25519");
  expect(publicKey.asymmetricKeyType).toBe("ed25519");
});

test("keypair uniqueness", () => {
  const { privateKey: priv1 } = generateKeypair();
  const { privateKey: priv2 } = generateKeypair();
  expect(privateKeyToJwk(priv1).d).not.toBe(privateKeyToJwk(priv2).d);
});

// ---------------------------------------------------------------------------
// JWK round-trips
// ---------------------------------------------------------------------------

test("public key jwk roundtrip", () => {
  const { publicKey } = generateKeypair();
  const jwk = publicKeyToJwk(publicKey);
  expect(jwk.kty).toBe("EC");
  expect(jwk.crv).toBe("P-256");
  expect("d" in jwk).toBe(false); // no private component

  const recovered = publicKeyFromJwk(jwk);
  expect(publicKeyToJwk(recovered)).toEqual(jwk);
});

test("private key jwk roundtrip", () => {
  const { privateKey } = generateKeypair();
  const jwk = privateKeyToJwk(privateKey);
  expect("d" in jwk).toBe(true);

  const recovered = privateKeyFromJwk(jwk);
  expect(privateKeyToJwk(recovered)).toEqual(jwk);
});

test("ed25519 public key jwk roundtrip", () => {
  const { publicKey } = generateEd25519Keypair();
  const jwk = publicKeyToJwk(publicKey);
  expect(jwk.kty).toBe("OKP");
  expect(jwk.crv).toBe("Ed25519");
  expect("d" in jwk).toBe(false);

  const recovered = publicKeyFromJwk(jwk);
  expect(publicKeyToJwk(recovered)).toEqual(jwk);
});

test("ed25519 private key jwk roundtrip", () => {
  const { privateKey } = generateEd25519Keypair();
  const jwk = privateKeyToJwk(privateKey);
  expect(jwk.kty).toBe("OKP");
  expect(jwk.crv).toBe("Ed25519");
  expect("d" in jwk).toBe(true);

  const recovered = privateKeyFromJwk(jwk);
  expect(privateKeyToJwk(recovered)).toEqual(jwk);
});

// ---------------------------------------------------------------------------
// hashObject
// ---------------------------------------------------------------------------

test("hash object deterministic", () => {
  const obj = { session_id: "abc", round_number: 1, total_value: 9500000 };
  const h1 = hashObject(obj);
  const h2 = hashObject(obj);
  expect(h1).toBe(h2);
});

test("hash object key order independent", () => {
  // hashObject must produce the same result regardless of key insertion order.
  const obj1 = { b: 2, a: 1 };
  const obj2 = { a: 1, b: 2 };
  expect(hashObject(obj1)).toBe(hashObject(obj2));
});

test("hash object returns base64url", () => {
  const h = hashObject({ x: 1 });
  // base64url chars only
  const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  expect([...h].every((c) => allowed.includes(c))).toBe(true);
  // no padding
  expect(h.includes("=")).toBe(false);
});

test("hash object changes with content", () => {
  expect(hashObject({ a: 1 })).not.toBe(hashObject({ a: 2 }));
});

// ---------------------------------------------------------------------------
// JWS sign / verify roundtrip
// ---------------------------------------------------------------------------

test("jws roundtrip", () => {
  const { privateKey, publicKey } = generateKeypair();
  const payload = "sha256-somehashvalue";
  const token = signJws(payload, privateKey);
  const recovered = verifyJws(token, publicKey);
  expect(recovered).toBe(payload);
});

test("jws compact payload is the raw payload string", () => {
  const { privateKey } = generateKeypair();
  const payload = "sha256-somehashvalue";
  const token = signJws(payload, privateKey, "did:web:example.com#key-1");
  const [headerB64, payloadB64, signatureB64] = token.split(".");

  const header = JSON.parse(b64urlDecode(headerB64).toString("utf-8"));
  expect(header.alg).toBe("ES256");
  expect(header.kid).toBe("did:web:example.com#key-1");
  expect(b64urlDecode(payloadB64).toString("utf-8")).toBe(payload);
  expect(() => JSON.parse(b64urlDecode(payloadB64).toString("utf-8"))).toThrow();
  expect(signatureB64).toBeTruthy();
});

test("jws wrong key raises", () => {
  const { privateKey: priv1 } = generateKeypair();
  const { publicKey: pub2 } = generateKeypair();
  const token = signJws("test", priv1);
  expect(() => verifyJws(token, pub2)).toThrow(InvalidSignatureError);
});

test("jws with kid", () => {
  const { privateKey, publicKey } = generateKeypair();
  const token = signJws("myhash", privateKey, "did:web:example.com#key-1");
  // Should still verify
  const recovered = verifyJws(token, publicKey);
  expect(recovered).toBe("myhash");
});

test("jws ed25519 roundtrip", () => {
  const { privateKey, publicKey } = generateEd25519Keypair();
  const token = signJws("ed25519-payload", privateKey, "did:web:example.com#ed25519-1");
  const header = JSON.parse(b64urlDecode(token.split(".")[0]).toString("utf-8"));
  expect(header.alg).toBe("EdDSA");
  expect(header.kid).toBe("did:web:example.com#ed25519-1");

  const recovered = verifyJws(token, publicKey);
  expect(recovered).toBe("ed25519-payload");
});

// ---------------------------------------------------------------------------
// JWT create / verify roundtrip
// ---------------------------------------------------------------------------

test("jwt roundtrip", async () => {
  const { privateKey, publicKey } = generateKeypair();
  const token = await createJwt("did:web:initiator.example", "did:web:responder.example", privateKey, {
    purpose: "a2cn_session_init",
    expSeconds: 300,
  });
  const payload = await verifyJwt(token, publicKey, {
    expectedAudience: "did:web:responder.example",
    expectedIssuer: "did:web:initiator.example",
  });
  expect(payload.iss).toBe("did:web:initiator.example");
  expect(payload.aud).toBe("did:web:responder.example");
  expect(payload.purpose).toBe("a2cn_session_init");
  expect(payload.jti).toBeDefined();
  expect(payload.iat).toBeDefined();
  expect(payload.exp).toBeDefined();
});

test("jwt wrong audience raises", async () => {
  const { privateKey, publicKey } = generateKeypair();
  const token = await createJwt("did:web:a", "did:web:b", privateKey);
  await expect(
    verifyJwt(token, publicKey, { expectedAudience: "did:web:wrong" }),
  ).rejects.toMatchObject({ code: "ERR_JWT_CLAIM_VALIDATION_FAILED" });
});

test("jwt with session id", async () => {
  const { privateKey, publicKey } = generateKeypair();
  const token = await createJwt("did:web:a", "did:web:b", privateKey, {
    sessionId: "my-session-id",
  });
  const payload = await verifyJwt(token, publicKey, { expectedAudience: "did:web:b" });
  expect(payload.session_id).toBe("my-session-id");
});

test("jwt ed25519 roundtrip", async () => {
  const { privateKey, publicKey } = generateEd25519Keypair();
  const token = await createJwt("did:web:initiator.example", "did:web:responder.example", privateKey, {
    kid: "did:web:initiator.example#ed25519-1",
    purpose: "a2cn_session_init",
    expSeconds: 300,
  });
  const header = JSON.parse(b64urlDecode(token.split(".")[0]).toString("utf-8"));
  expect(header.alg).toBe("EdDSA");
  expect(header.kid).toBe("did:web:initiator.example#ed25519-1");

  const payload = await verifyJwt(token, publicKey, {
    expectedAudience: "did:web:responder.example",
    expectedIssuer: "did:web:initiator.example",
  });
  expect(payload.iss).toBe("did:web:initiator.example");
  expect(payload.aud).toBe("did:web:responder.example");
  expect(payload.purpose).toBe("a2cn_session_init");
});

test("jwt expired raises", async () => {
  const { privateKey, publicKey } = generateKeypair();
  const token = await createJwt("did:web:a", "did:web:b", privateKey, { expSeconds: -1 });
  await expect(
    verifyJwt(token, publicKey, { expectedAudience: "did:web:b" }),
  ).rejects.toMatchObject({ code: "ERR_JWT_EXPIRED" });
});
