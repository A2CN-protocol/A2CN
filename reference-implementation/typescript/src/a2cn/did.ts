/**
 * A2CN DID Resolution — did:web only.
 *
 * Section 4.2: All signing keys MUST be retrieved from DID documents.
 *
 * did:web:example.com           → https://example.com/.well-known/did.json
 * did:web:example.com:path:to   → https://example.com/path/to/did.json
 */

import { publicKeyFromJwk, type SigningPublicKey } from "./crypto.js";

export type FetchLike = (
  url: string,
  init?: {
    redirect?: "error" | "follow" | "manual";
    signal?: AbortSignal;
    headers?: Record<string, string>;
  },
) => Promise<{
  ok: boolean;
  status: number;
  headers?: { get(name: string): string | null };
  body?: ReadableStream<Uint8Array> | null;
  json(): Promise<unknown>;
}>;

/**
 * Resolution limits, identical in both reference implementations: the whole
 * fetch, body included, must finish within the timeout; no redirect is
 * followed; and a document larger than the cap is refused before it is read in
 * full.
 */
export const DID_RESOLUTION_TIMEOUT_MS = 5000;
export const DID_DOCUMENT_MAX_BYTES = 65536;

/**
 * Resolve a did:web DID to its DID document.
 *
 * The document must be UTF-8 JSON (an optional UTF-8 byte-order mark is
 * allowed), without NaN or Infinity literals, sent without a content encoding,
 * no larger than DID_DOCUMENT_MAX_BYTES, and fetched within `timeoutMs` in
 * total with no redirect followed.
 *
 * Throws:
 * - Error if the DID is not a did:web DID or cannot be parsed
 * - Error if the DID document cannot be fetched, is too large, compressed, or
 *   is not valid UTF-8 JSON, or if the fetch does not finish in time
 */
export async function resolveDidWeb(
  did: string,
  fetchFn: FetchLike = fetch,
  timeoutMs: number = DID_RESOLUTION_TIMEOUT_MS,
): Promise<Record<string, unknown>> {
  const url = didWebToUrl(did);
  const signal = AbortSignal.timeout(timeoutMs);
  const response = await fetchFn(url, {
    redirect: "error",
    signal,
    headers: { "Accept-Encoding": "identity" },
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch DID document: HTTP ${response.status}`);
  }
  // The size limit counts bytes as sent, so a compressed body is refused
  // rather than inflated.
  const encoding = (response.headers?.get("content-encoding") ?? "identity").trim().toLowerCase();
  if (encoding !== "identity") {
    await response.body?.cancel();
    throw new Error("DID document is sent with a content encoding");
  }
  if (!response.body) {
    // A response object without a byte stream: its parsed JSON is all there is.
    return (await response.json()) as Record<string, unknown>;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    if (signal.aborted) {
      await reader.cancel();
      throw new Error("DID document fetch timed out");
    }
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > DID_DOCUMENT_MAX_BYTES) {
      await reader.cancel();
      throw new Error("DID document is larger than the resolution limit");
    }
    chunks.push(value);
  }
  return parseDidDocument(Buffer.concat(chunks));
}

/** Parse a fetched DID document: strict UTF-8 JSON, no NaN or Infinity. */
export function parseDidDocument(body: Uint8Array): Record<string, unknown> {
  // TextDecoder strips a leading UTF-8 byte-order mark; JSON.parse already
  // refuses NaN and Infinity.
  const text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  return JSON.parse(text) as Record<string, unknown>;
}

/** Convert a did:web DID to the corresponding HTTPS URL. */
export function didWebToUrl(did: string): string {
  if (!did.startsWith("did:web:")) {
    throw new Error(`Not a did:web DID: ${JSON.stringify(did)}`);
  }

  const remainder = did.slice("did:web:".length);

  // If there are colons after the domain, they become path segments
  const parts = remainder.split(":");
  const domain = parts[0];
  const pathParts = parts.slice(1);

  if (pathParts.length > 0) {
    const path = pathParts.join("/");
    return `https://${domain}/${path}/did.json`;
  }
  return `https://${domain}/.well-known/did.json`;
}

export interface VerificationMethod {
  id?: string;
  type?: string;
  publicKeyJwk?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface DidDocument {
  id?: string;
  verificationMethod?: VerificationMethod[];
  assertionMethod?: Array<VerificationMethod | string>;
  authentication?: Array<VerificationMethod | string>;
  [key: string]: unknown;
}

/**
 * Extract a signing verification method from a DID document by its DID URL.
 *
 * The method MUST be authorized for one of the allowed verification
 * relationships. By default this permits assertion signatures and JWT
 * authentication signatures, while excluding keyAgreement-only keys.
 *
 * Throws VerificationMethodNotFoundError if the method is not found.
 */
export function getVerificationMethod(
  didDocument: DidDocument,
  methodId: string,
  allowedRelationships: string[] = ["assertionMethod", "authentication"],
): VerificationMethod {
  const verificationMethods: Record<string, VerificationMethod> = {};
  for (const method of didDocument.verificationMethod ?? []) {
    if (method && typeof method === "object" && method.id) {
      verificationMethods[method.id] = method;
    }
  }

  for (const key of allowedRelationships) {
    const relationships = (didDocument[key] as Array<VerificationMethod | string>) ?? [];
    for (const method of relationships) {
      // Methods can be embedded objects or string references.
      if (typeof method === "object" && method !== null && method.id === methodId) {
        return method;
      }
      if (typeof method === "string" && method === methodId) {
        if (methodId in verificationMethods) {
          return verificationMethods[methodId];
        }
        break;
      }
    }
  }

  throw new VerificationMethodNotFoundError(
    `Verification method ${JSON.stringify(methodId)} not found in DID document`,
  );
}

/**
 * The DID document does not list the verification method asked for. Verifiers
 * catch it to tell a key the document does not list (rotated, or never
 * published) from a signature that is wrong.
 */
export class VerificationMethodNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationMethodNotFoundError";
  }
}

/**
 * Return a public key object from a supported verification method.
 *
 * Throws Error if the verification method type is not supported or the key
 * cannot be parsed.
 */
export function getPublicKey(verificationMethod: VerificationMethod): SigningPublicKey {
  const vmType = verificationMethod.type;
  if (vmType !== "JsonWebKey2020" && vmType !== "EcdsaSecp256r1VerificationKey2019") {
    throw new Error(
      `Unsupported verification method type: ${JSON.stringify(vmType)}. ` +
        "Only JsonWebKey2020 and EcdsaSecp256r1VerificationKey2019 are supported.",
    );
  }

  const jwk = verificationMethod.publicKeyJwk;
  if (!jwk) {
    throw new Error("Verification method missing 'publicKeyJwk' field");
  }

  const supportedJwk =
    (jwk.kty === "EC" && jwk.crv === "P-256") || (jwk.kty === "OKP" && jwk.crv === "Ed25519");
  if (!supportedJwk) {
    throw new Error(
      `Unsupported key type/curve: kty=${JSON.stringify(jwk.kty)}, crv=${JSON.stringify(jwk.crv)}. ` +
        "Only EC P-256 and OKP Ed25519 keys are supported.",
    );
  }

  return publicKeyFromJwk(jwk);
}
