/**
 * A2CN DID Resolution — did:web only.
 *
 * Section 4.2: All signing keys MUST be retrieved from DID documents.
 *
 * did:web:example.com           → https://example.com/.well-known/did.json
 * did:web:example.com:path:to   → https://example.com/path/to/did.json
 */

import { publicKeyFromJwk, type SigningPublicKey } from "./crypto.js";

export type FetchLike = (url: string) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

/**
 * Resolve a did:web DID to its DID document.
 *
 * Throws:
 * - Error if the DID is not a did:web DID or cannot be parsed
 * - Error if the DID document cannot be fetched
 */
export async function resolveDidWeb(
  did: string,
  fetchFn: FetchLike = fetch,
): Promise<Record<string, unknown>> {
  const url = didWebToUrl(did);
  const response = await fetchFn(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch DID document: HTTP ${response.status}`);
  }
  return (await response.json()) as Record<string, unknown>;
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
 * Throws Error if the method is not found.
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

  throw new Error(`Verification method ${JSON.stringify(methodId)} not found in DID document`);
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
