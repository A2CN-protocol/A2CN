/** Tests for a2cn/did — using a fake fetch to mock HTTPS fetches. */

import { expect, test, vi } from "vitest";

import {
  DID_DOCUMENT_MAX_BYTES,
  DID_RESOLUTION_TIMEOUT_MS,
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
// resolveDidWeb limits: content encoding, size, decoding, deadline
// ---------------------------------------------------------------------------

const LIMITS_DID = "did:web:limits.example";

/** A valid DID document padded to exactly `size` bytes. */
function documentOfSize(size: number): Buffer {
  const { publicKey } = generateEd25519Keypair();
  const text = JSON.stringify(makeDidDocument(LIMITS_DID, "key-1", publicKeyToJwk(publicKey)));
  const head = text.slice(0, -1) + ', "pad": "';
  const body = Buffer.from(head + "a".repeat(size - head.length - 2) + '"}', "utf8");
  expect(body.length).toBe(size);
  return body;
}

function answering(body: ConstructorParameters<typeof Response>[0], headers: Record<string, string> = {}): typeof fetch {
  return (async () => new Response(body, { status: 200, headers })) as unknown as typeof fetch;
}

/** A body stream that ignores the fetch signal, as an injected fetch may. */
function streamOf(next: (count: number) => Promise<Uint8Array | null>): ReadableStream<Uint8Array> {
  let count = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      const chunk = await next(count++);
      if (chunk === null) {
        controller.close();
      } else {
        controller.enqueue(chunk);
      }
    },
  });
}

test("resolve did web asks for an unencoded document", async () => {
  const seen: unknown[] = [];
  const fetchFn = (async (_url: string, init?: { headers?: Record<string, string> }) => {
    seen.push(init?.headers?.["Accept-Encoding"]);
    return new Response(documentOfSize(2000), { status: 200 });
  }) as unknown as typeof fetch;
  await resolveDidWeb(LIMITS_DID, fetchFn);
  expect(seen).toEqual(["identity"]);
});

for (const encoding of ["gzip", "x-gzip", "deflate", "br", "zstd", "gzip, gzip"]) {
  test(`resolve did web refuses a compressed document: ${encoding}`, async () => {
    await expect(
      resolveDidWeb(LIMITS_DID, answering(documentOfSize(2000), { "Content-Encoding": encoding })),
    ).rejects.toThrow("content encoding");
  });
}

test("resolve did web accepts an explicit identity encoding", async () => {
  const doc = await resolveDidWeb(LIMITS_DID, answering(documentOfSize(2000), { "Content-Encoding": "identity" }));
  expect(doc.id).toBe(LIMITS_DID);
});

test("resolve did web size limit is inclusive", async () => {
  expect(DID_DOCUMENT_MAX_BYTES).toBe(65536);
  expect((await resolveDidWeb(LIMITS_DID, answering(documentOfSize(65536)))).id).toBe(LIMITS_DID);
  await expect(resolveDidWeb(LIMITS_DID, answering(documentOfSize(65537)))).rejects.toThrow(
    "larger than the resolution limit",
  );
});

test("resolve did web size limit counts every chunk", async () => {
  const body = documentOfSize(70000);
  const stream = streamOf(async (i) => (i * 1000 < body.length ? body.subarray(i * 1000, i * 1000 + 1000) : null));
  await expect(resolveDidWeb(LIMITS_DID, answering(stream))).rejects.toThrow("larger than the resolution limit");
});

test("resolve did web stops reading at the size limit", async () => {
  // 1 MiB of whitespace, offered 4 KiB at a time; reading should stop near 64 KiB.
  let sent = 0;
  const stream = streamOf(async (i) => {
    if (i >= 256) {
      return null;
    }
    sent += 4096;
    return new Uint8Array(4096).fill(0x20);
  });
  await expect(resolveDidWeb(LIMITS_DID, answering(stream))).rejects.toThrow(
    "larger than the resolution limit",
  );
  expect(sent).toBeLessThanOrEqual(65536 + 2 * 4096);
});

test("resolve did web deadline covers the body", async () => {
  // One byte every 20 ms, from a stream that never sees the abort signal.
  const stream = streamOf(async () => {
    await new Promise((resolve) => setTimeout(resolve, 20));
    return new Uint8Array([0x20]);
  });
  const started = Date.now();
  await expect(resolveDidWeb(LIMITS_DID, answering(stream), 200)).rejects.toThrow("timed out");
  expect(Date.now() - started).toBeLessThan(2000);
});

test("resolve did web uses the five second deadline by default", async () => {
  const timeout = vi.spyOn(AbortSignal, "timeout");
  try {
    await resolveDidWeb(LIMITS_DID, answering(documentOfSize(2000)));
    expect(timeout).toHaveBeenCalledWith(DID_RESOLUTION_TIMEOUT_MS);
  } finally {
    timeout.mockRestore();
  }
});

for (const literal of ["NaN", "Infinity", "-Infinity"]) {
  test(`resolve did web refuses non json number literals: ${literal}`, async () => {
    const text = documentOfSize(2000).toString("utf8");
    const body = Buffer.from(text.slice(0, -1) + `, "x": ${literal}}`, "utf8");
    await expect(resolveDidWeb(LIMITS_DID, answering(body))).rejects.toThrow();
  });
}

test("resolve did web refuses invalid utf8", async () => {
  const doc = documentOfSize(2000);
  const body = Buffer.concat([doc.subarray(0, -2), Buffer.from([0xff]), Buffer.from('"}')]);
  await expect(resolveDidWeb(LIMITS_DID, answering(body))).rejects.toThrow(TypeError);
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
