/** Tests for a2cn/did — using a fake fetch to mock HTTPS fetches. */

import { expect, test } from "vitest";

import {
  resolveDidWeb,
  didWebToUrl,
  getVerificationMethod,
  getPublicKey,
} from "../src/a2cn/did.js";
import {
  generateKeypair,
  generateEd25519Keypair,
  publicKeyToJwk,
} from "../src/a2cn/crypto.js";
import { INITIATOR_DID, makeDidDocument, fakeFetch } from "./conftest.js";

// ---------------------------------------------------------------------------
// didWebToUrl
// ---------------------------------------------------------------------------

test("did web simple", () => {
  expect(didWebToUrl("did:web:example.com")).toBe("https://example.com/.well-known/did.json");
});

test("did web with path", () => {
  expect(didWebToUrl("did:web:example.com:path:to:key")).toBe(
    "https://example.com/path/to/key/did.json",
  );
});

test("did web not did web raises", () => {
  expect(() => didWebToUrl("did:key:z6Mkfoo")).toThrow(/Not a did:web DID/);
});

// ---------------------------------------------------------------------------
// resolveDidWeb (mock HTTP)
// ---------------------------------------------------------------------------

test("resolve did web simple", async () => {
  const { publicKey } = generateKeypair();
  const didDoc = makeDidDocument("did:web:example.com", "key-1", publicKeyToJwk(publicKey));

  const fetchFn = fakeFetch({
    "https://example.com/.well-known/did.json": { status: 200, json: didDoc },
  });

  const result = await resolveDidWeb("did:web:example.com", fetchFn);

  expect(result.id).toBe("did:web:example.com");
  expect((result.verificationMethod as Array<{ type: string }>)[0].type).toBe("JsonWebKey2020");
});

test("resolve did web with path", async () => {
  const { publicKey } = generateKeypair();
  const didDoc = makeDidDocument(
    "did:web:example.com:users:alice",
    "key-1",
    publicKeyToJwk(publicKey),
  );

  const fetchFn = fakeFetch({
    "https://example.com/users/alice/did.json": { status: 200, json: didDoc },
  });

  const result = await resolveDidWeb("did:web:example.com:users:alice", fetchFn);

  expect(result.id).toBe("did:web:example.com:users:alice");
});

test("resolve did web 404 raises", async () => {
  const fetchFn = fakeFetch({
    "https://notfound.example/.well-known/did.json": { status: 404 },
  });
  await expect(resolveDidWeb("did:web:notfound.example", fetchFn)).rejects.toThrow(
    /Failed to fetch DID document/,
  );
});

// ---------------------------------------------------------------------------
// getVerificationMethod
// ---------------------------------------------------------------------------

test("get verification method found", () => {
  const { publicKey } = generateKeypair();
  const didDoc = makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(publicKey));
  const vmId = `${INITIATOR_DID}#key-1`;
  const vm = getVerificationMethod(didDoc, vmId);
  expect(vm.id).toBe(vmId);
});

test("get verification method rejects key agreement only key", () => {
  const { publicKey } = generateKeypair();
  const vmId = `${INITIATOR_DID}#agreement-key`;
  const didDoc = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: INITIATOR_DID,
    verificationMethod: [
      {
        id: vmId,
        type: "JsonWebKey2020",
        controller: INITIATOR_DID,
        publicKeyJwk: publicKeyToJwk(publicKey),
      },
    ],
    keyAgreement: [vmId],
  };

  expect(() => getVerificationMethod(didDoc, vmId)).toThrow(/not found/);
});

test("get verification method not found raises", () => {
  const { publicKey } = generateKeypair();
  const didDoc = makeDidDocument(INITIATOR_DID, "key-1", publicKeyToJwk(publicKey));
  expect(() => getVerificationMethod(didDoc, `${INITIATOR_DID}#nonexistent`)).toThrow(/not found/);
});

// ---------------------------------------------------------------------------
// getPublicKey
// ---------------------------------------------------------------------------

test("get public key roundtrip", () => {
  const { publicKey } = generateKeypair();
  const jwk = publicKeyToJwk(publicKey);
  const vm = {
    id: `${INITIATOR_DID}#key-1`,
    type: "JsonWebKey2020",
    controller: INITIATOR_DID,
    publicKeyJwk: jwk,
  };
  const recovered = getPublicKey(vm);
  expect(publicKeyToJwk(recovered)).toEqual(jwk);
});

test("get public key unsupported type raises", () => {
  const vm = {
    id: "did:web:example.com#key-1",
    type: "RsaVerificationKey2018",
    controller: "did:web:example.com",
  };
  expect(() => getPublicKey(vm)).toThrow(/Unsupported verification method type/);
});

test("get public key ed25519 roundtrip", () => {
  const { publicKey } = generateEd25519Keypair();
  const jwk = publicKeyToJwk(publicKey);
  const vm = {
    id: `${INITIATOR_DID}#ed25519-1`,
    type: "JsonWebKey2020",
    controller: INITIATOR_DID,
    publicKeyJwk: jwk,
  };
  const recovered = getPublicKey(vm);
  expect(publicKeyToJwk(recovered)).toEqual(jwk);
});

test("get public key missing jwk raises", () => {
  const vm = {
    id: "did:web:example.com#key-1",
    type: "JsonWebKey2020",
    controller: "did:web:example.com",
  };
  expect(() => getPublicKey(vm)).toThrow(/missing 'publicKeyJwk'/);
});
