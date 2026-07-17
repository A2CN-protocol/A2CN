/**
 * Cross-language parity vectors: the TypeScript implementation must reproduce
 * (or verify) every vector emitted by the Python reference implementation.
 *
 * Regenerate vectors.json with:
 *   cd reference-implementation/python
 *   uv run --extra dev python ../../a2cn_ts/parity/generate_vectors.py
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, test } from "vitest";
import { v5 as uuidv5 } from "uuid";

import {
  canonicalize,
  hashObject,
  privateKeyFromJwk,
  publicKeyFromJwk,
  signJws,
  signInvitation,
  verifyJws,
  verifyJwt,
  verifyInvitationSignature,
} from "../src/a2cn/crypto.js";
import { SessionManager } from "../src/a2cn/session.js";
import { generateTransactionRecord, A2CN_NAMESPACE } from "../src/a2cn/record.js";
import type { Dict } from "../src/a2cn/messages.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(HERE, "vectors.json"), "utf-8")) as Dict;

// Fixed Ed25519 key (must match generate_vectors.py).
const ED25519_PRIVATE_JWK = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
};

function makeDidDocument(did: string, keyId: string, publicKeyJwk: Dict): Dict {
  const vmId = `${did}#${keyId}`;
  return {
    id: did,
    verificationMethod: [
      { id: vmId, type: "JsonWebKey2020", controller: did, publicKeyJwk },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
}

// ---------------------------------------------------------------------------
// 1. Canonicalization + hash parity
// ---------------------------------------------------------------------------

describe("canonicalization parity", () => {
  const cases = vectors.canonicalization as Array<{
    input: unknown;
    canonical: string;
    hash: string;
  }>;

  for (const [index, vector] of cases.entries()) {
    test(`canonical bytes match python (case ${index})`, () => {
      expect(canonicalize(vector.input).toString("utf-8")).toBe(vector.canonical);
    });

    test(`hash_object matches python (case ${index})`, () => {
      expect(hashObject(vector.input)).toBe(vector.hash);
    });
  }
});

// ---------------------------------------------------------------------------
// 2. Signature parity
// ---------------------------------------------------------------------------

describe("signature parity", () => {
  const sig = vectors.signatures as Dict;

  test("ed25519 jws is byte-identical to python", () => {
    // Ed25519 is deterministic — same key + payload must produce the same token.
    const edPriv = privateKeyFromJwk(ED25519_PRIVATE_JWK);
    const token = signJws(sig.jws_payload as string, edPriv, "did:web:parity.example#ed25519-1");
    expect(token).toBe(sig.ed25519_jws);
  });

  test("python ed25519 jws verifies here", () => {
    const edPub = publicKeyFromJwk(sig.ed25519_public_jwk as Dict);
    expect(verifyJws(sig.ed25519_jws as string, edPub)).toBe(sig.jws_payload);
  });

  test("python es256 jws verifies here", () => {
    const esPub = publicKeyFromJwk(sig.es256_public_jwk as Dict);
    expect(verifyJws(sig.es256_jws as string, esPub)).toBe(sig.jws_payload);
  });

  test("python es256 jwt verifies here", async () => {
    const esPub = publicKeyFromJwk(sig.es256_public_jwk as Dict);
    const payload = await verifyJwt(sig.es256_jwt as string, esPub, {
      expectedAudience: sig.jwt_audience as string,
      expectedIssuer: sig.jwt_issuer as string,
    });
    expect(payload.purpose).toBe("parity_vector");
    expect(payload.session_id).toBe("parity-session");
  });

  test("ed25519 invitation signature is byte-identical to python", () => {
    const edPriv = privateKeyFromJwk(ED25519_PRIVATE_JWK);
    const invitationDict = { ...(sig.invitation_dict as Dict) };
    const produced = signInvitation(invitationDict, edPriv);
    expect(produced).toBe(sig.ed25519_invitation_signature);
  });

  test("python invitation signature verifies here", () => {
    const edPub = publicKeyFromJwk(sig.ed25519_public_jwk as Dict);
    expect(verifyInvitationSignature(sig.invitation_dict as Dict, edPub)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 3. Deterministic session replay → identical transaction record
// ---------------------------------------------------------------------------

describe("session replay parity", () => {
  const sessionVector = vectors.session as Dict;
  const expected = sessionVector.expected as Dict;

  function replaySession() {
    const manager = new SessionManager();
    manager.registerDidDocument(
      sessionVector.buyer_did as string,
      makeDidDocument(
        sessionVector.buyer_did as string,
        "key-1",
        sessionVector.buyer_public_jwk as Dict,
      ),
    );
    manager.registerDidDocument(
      sessionVector.supplier_did as string,
      makeDidDocument(
        sessionVector.supplier_did as string,
        "key-1",
        sessionVector.supplier_public_jwk as Dict,
      ),
    );
    const session = manager.createSession(
      sessionVector.session_id as string,
      sessionVector.session_init as Dict,
      sessionVector.session_ack as Dict,
      "2026-03-24T10:00:00Z",
    );
    session.session_timeout_seconds = 86400 * 365 * 100;
    for (const message of sessionVector.messages as Dict[]) {
      manager.processMessage(session, message);
    }
    return session;
  }

  test("replayed session completes", () => {
    const session = replaySession();
    expect(session.state).toBe("COMPLETED");
  });

  test("record_id matches python (uuid5 namespace)", () => {
    expect(expected.a2cn_namespace).toBe(A2CN_NAMESPACE);
    expect(uuidv5(sessionVector.session_id as string, A2CN_NAMESPACE)).toBe(expected.record_id);
  });

  test("transaction record is byte-identical to python", () => {
    const session = replaySession();
    const record = generateTransactionRecord(session);
    expect(record.record_id).toBe(expected.record_id);
    expect(record.offer_chain_hash).toBe(expected.offer_chain_hash);
    expect(record.generated_at).toBe(expected.generated_at);
    expect(record.record_hash).toBe(expected.record_hash);
    // The complete record must match field-for-field.
    expect(record).toEqual(expected.full_record);
  });
});
