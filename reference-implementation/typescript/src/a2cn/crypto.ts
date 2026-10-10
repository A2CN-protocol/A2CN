/**
 * A2CN Cryptographic Primitives
 *
 * Implements:
 * - P-256 EC and Ed25519 keypair generation
 * - RFC 8785 JCS canonicalization
 * - SHA-256 hashing of JCS-canonicalized objects (base64url output)
 * - JWS signing/verification of protocol act hashes using ES256 or EdDSA
 * - JWT creation and verification for request authentication (Section 12.1.4)
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign as cryptoSign,
  verify as cryptoVerify,
  KeyObject,
} from "node:crypto";
import canonicalizeModule from "canonicalize";
import { SignJWT, jwtVerify, type JWTPayload } from "jose";

// The canonicalize package ships CommonJS with types that NodeNext resolves as
// a module namespace rather than the callable itself.
const jcsCanonicalize = canonicalizeModule as unknown as (obj: unknown) => string | undefined;

export type SigningPrivateKey = KeyObject;
export type SigningPublicKey = KeyObject;

export interface Keypair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export class InvalidSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidSignatureError";
  }
}

export function isEd25519(key: KeyObject): boolean {
  return key.asymmetricKeyType === "ed25519";
}

/** Generate a P-256 EC keypair. */
export function generateKeypair(): Keypair {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  return { privateKey, publicKey };
}

/** Generate an Ed25519 keypair. */
export function generateEd25519Keypair(): Keypair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey };
}

/** Serialize a supported private key to JWK format. */
export function privateKeyToJwk(privateKey: SigningPrivateKey): Record<string, string> {
  const jwk = privateKey.export({ format: "jwk" }) as Record<string, string>;
  if (isEd25519(privateKey)) {
    return { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d };
  }
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d };
}

/** Serialize a supported public key to JWK format. */
export function publicKeyToJwk(publicKey: SigningPublicKey): Record<string, string> {
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, string>;
  if (isEd25519(publicKey)) {
    return { kty: "OKP", crv: "Ed25519", x: jwk.x };
  }
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

/** Derive the public key object from a private key (Python private_key.public_key()). */
export function createPublicKeyFromPrivate(privateKey: SigningPrivateKey): SigningPublicKey {
  return createPublicKey(privateKey);
}

/** Reconstruct a supported public key from a JWK dict. */
export function publicKeyFromJwk(jwk: Record<string, unknown>): SigningPublicKey {
  return createPublicKey({ key: jwk as import("node:crypto").JsonWebKey, format: "jwk" });
}

/** Reconstruct a supported private key from a JWK dict. */
export function privateKeyFromJwk(jwk: Record<string, unknown>): SigningPrivateKey {
  return createPrivateKey({ key: jwk as import("node:crypto").JsonWebKey, format: "jwk" });
}

// ---------------------------------------------------------------------------
// JCS + hashing
// ---------------------------------------------------------------------------

/** RFC 8785 JSON Canonicalization Scheme. */
export function canonicalize(obj: unknown): Buffer {
  const canonical = jcsCanonicalize(obj);
  if (canonical === undefined) {
    throw new Error("Cannot canonicalize undefined");
  }
  return Buffer.from(canonical, "utf-8");
}

/** JCS-canonicalize an object, SHA-256 hash it, return base64url string. */
export function hashObject(obj: unknown): string {
  const canonicalBytes = canonicalize(obj);
  const digest = createHash("sha256").update(canonicalBytes).digest();
  return b64urlEncode(digest);
}

/** SHA-256 hash raw bytes, return base64url string. */
export function hashBytes(data: Buffer | Uint8Array): string {
  return b64urlEncode(createHash("sha256").update(data).digest());
}

// ---------------------------------------------------------------------------
// JWS signing / verification (used for protocol_act_signature)
// ---------------------------------------------------------------------------

/**
 * Create a JWS compact serialization signing `payloadStr` with ES256 or EdDSA.
 *
 * The payload is the protocol_act_hash (a base64url string). We encode it
 * as the JWS payload bytes so the full compact token is:
 *   base64url(header).base64url(payload).signature
 */
export function signJws(
  payloadStr: string,
  privateKey: SigningPrivateKey,
  kid?: string | null,
): string {
  const algorithm = jwtAlgorithmForKey(privateKey);
  const headers: Record<string, string> = { alg: algorithm };
  if (kid) {
    headers.kid = kid;
  }

  // Sorted-key compact JSON — same bytes as Python's json.dumps(sort_keys=True,
  // separators=(",", ":")) for these flat ASCII headers.
  const protectedB64 = b64urlEncode(canonicalize(headers));
  const payloadB64 = b64urlEncode(Buffer.from(payloadStr, "utf-8"));
  const signingInput = Buffer.from(`${protectedB64}.${payloadB64}`, "ascii");

  let signature: Buffer;
  if (isEd25519(privateKey)) {
    signature = cryptoSign(null, signingInput, privateKey);
  } else {
    signature = cryptoSign("sha256", signingInput, {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });
  }

  return `${protectedB64}.${payloadB64}.${b64urlEncode(signature)}`;
}

/**
 * Verify a JWS compact token and return the payload string.
 * Throws InvalidSignatureError on failure.
 */
export function verifyJws(token: string, publicKey: SigningPublicKey): string {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("JWS must have three segments");
    }
    const [protectedB64, payloadB64, signatureB64] = parts;
    const header = JSON.parse(b64urlDecode(protectedB64).toString("utf-8"));
    const expectedAlg = jwtAlgorithmForKey(publicKey);
    if (header.alg !== expectedAlg) {
      throw new InvalidSignatureError("JWS alg does not match key type");
    }

    const signingInput = Buffer.from(`${protectedB64}.${payloadB64}`, "ascii");
    const signatureBytes = b64urlDecode(signatureB64);
    let valid: boolean;
    if (isEd25519(publicKey)) {
      valid = cryptoVerify(null, signingInput, publicKey, signatureBytes);
    } else {
      if (signatureBytes.length !== 64) {
        throw new InvalidSignatureError("ES256 signatures must be 64 raw bytes");
      }
      valid = cryptoVerify(
        "sha256",
        signingInput,
        { key: publicKey, dsaEncoding: "ieee-p1363" },
        signatureBytes,
      );
    }
    if (!valid) {
      throw new InvalidSignatureError("Invalid JWS signature");
    }
    return b64urlDecode(payloadB64).toString("utf-8");
  } catch (exc) {
    if (exc instanceof InvalidSignatureError) {
      throw exc;
    }
    throw new InvalidSignatureError("Invalid JWS signature");
  }
}

// ---------------------------------------------------------------------------
// JWT creation / verification (used for HTTP Authorization headers)
// ---------------------------------------------------------------------------

/**
 * Create a signed JWT per Section 12.1.4.
 *
 * Fields: iss, aud, iat, exp, jti, purpose (optional), session_id (optional)
 * Algorithm: ES256 for P-256 keys, EdDSA for Ed25519 keys
 */
export async function createJwt(
  issuerDid: string,
  audienceDid: string,
  privateKey: SigningPrivateKey,
  options: {
    kid?: string | null;
    purpose?: string | null;
    sessionId?: string | null;
    expSeconds?: number;
  } = {},
): Promise<string> {
  const { kid, purpose, sessionId, expSeconds = 60 } = options;
  const now = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = {
    iss: issuerDid,
    aud: audienceDid,
    iat: now,
    exp: now + expSeconds,
    jti: randomUUID(),
  };
  if (purpose) {
    payload.purpose = purpose;
  }
  if (sessionId) {
    payload.session_id = sessionId;
  }

  const algorithm = jwtAlgorithmForKey(privateKey);
  const header: Record<string, string> = { alg: algorithm };
  if (kid) {
    header.kid = kid;
  }

  return new SignJWT(payload)
    .setProtectedHeader(header as { alg: string; kid?: string })
    .sign(privateKey);
}

/**
 * Verify a signed JWT and return the decoded payload dict.
 * Throws on failure.
 */
export async function verifyJwt(
  token: string,
  publicKey: SigningPublicKey,
  options: {
    expectedAudience?: string | null;
    expectedIssuer?: string | null;
  } = {},
): Promise<JWTPayload> {
  const { expectedAudience, expectedIssuer } = options;
  const verifyOptions: Record<string, unknown> = {
    algorithms: [jwtAlgorithmForKey(publicKey)],
    requiredClaims: ["iss", "aud", "iat", "exp", "jti"],
  };
  if (expectedAudience) {
    verifyOptions.audience = expectedAudience;
  }
  if (expectedIssuer) {
    verifyOptions.issuer = expectedIssuer;
  }

  const { payload } = await jwtVerify(token, publicKey, verifyOptions);
  return payload;
}

// ---------------------------------------------------------------------------
// v0.2.0: Invitation signing / verification (Component 8)
// ---------------------------------------------------------------------------

/**
 * Signs a SessionInvitation or InvitationAcceptance dict using RFC 8785 JCS.
 *
 * Steps:
 * 1. Copy dict WITHOUT 'invitation_signature' and 'acceptance_signature' keys
 * 2. Serialize to canonical JSON (JCS)
 * 3. Sign canonical bytes with the selected signing suite
 * 4. Return base64url-encoded signature bytes
 *
 * The caller sets invitationDict['invitation_signature'] = result.
 */
export function signInvitation(
  invitationDict: Record<string, unknown>,
  privateKey: SigningPrivateKey,
): string {
  const canonicalObj = withoutSignatureFields(invitationDict);
  const canonicalBytes = canonicalize(canonicalObj);

  let signature: Buffer;
  if (isEd25519(privateKey)) {
    signature = cryptoSign(null, canonicalBytes, privateKey);
  } else {
    // DER encoding to mirror the Python implementation's ECDSA output.
    signature = cryptoSign("sha256", canonicalBytes, { key: privateKey, dsaEncoding: "der" });
  }
  return b64urlEncode(signature);
}

/**
 * Verifies a SessionInvitation or InvitationAcceptance signature.
 * Returns true if valid, false otherwise.
 */
export function verifyInvitationSignature(
  invitationDict: Record<string, unknown>,
  publicKey: SigningPublicKey,
): boolean {
  const sigB64 =
    (invitationDict.invitation_signature as string | undefined) ||
    (invitationDict.acceptance_signature as string | undefined) ||
    "";
  if (!sigB64) {
    return false;
  }

  const canonicalObj = withoutSignatureFields(invitationDict);

  try {
    const canonicalBytes = canonicalize(canonicalObj);
    const signature = b64urlDecode(sigB64);
    if (isEd25519(publicKey)) {
      return cryptoVerify(null, canonicalBytes, publicKey, signature);
    }
    return cryptoVerify(
      "sha256",
      canonicalBytes,
      { key: publicKey, dsaEncoding: "der" },
      signature,
    );
  } catch {
    return false;
  }
}

function withoutSignatureFields(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k !== "invitation_signature" && k !== "acceptance_signature") {
      result[k] = v;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ApprovalReceipt signatures (Section 14.1)
// ---------------------------------------------------------------------------

/** The P-256 group order, for the low-S rule on ES256 receipt signatures. */
const P256_ORDER = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
const B64URL_ALPHABET = /^[A-Za-z0-9_-]*$/;

/**
 * The bytes an ApprovalReceipt signature covers (Section 14.1): the RFC 8785
 * (JCS) form of the receipt with its top-level `signature` member removed. A
 * `signature` member nested inside the receipt is kept.
 */
export function approvalReceiptSigningBytes(receipt: Record<string, unknown>): Buffer {
  // Object.fromEntries defines each member as an own property, so a member named
  // "__proto__" stays in the signed bytes instead of setting the prototype.
  return canonicalize(Object.fromEntries(Object.entries(receipt).filter(([k]) => k !== "signature")));
}

/**
 * Return the `signature` member for an ApprovalReceipt (Section 14.1):
 * `{alg: "Ed25519" | "ES256", value: <base64url>}`, the algorithm following the
 * key type. An Ed25519 value is the raw 64-byte signature; an ES256 value is the
 * DER-encoded ECDSA signature with a low `s`. The caller sets
 * `receipt.signature` to the result.
 */
export function signApprovalReceipt(
  receipt: Record<string, unknown>,
  privateKey: SigningPrivateKey,
): { alg: string; value: string } {
  const payload = approvalReceiptSigningBytes(receipt);
  if (isEd25519(privateKey)) {
    return { alg: "Ed25519", value: Buffer.from(cryptoSign(null, payload, privateKey)).toString("base64url") + padding(64) };
  }
  if (privateKey.asymmetricKeyDetails?.namedCurve === "prime256v1") {
    const der = cryptoSign("sha256", payload, { key: privateKey, dsaEncoding: "der" });
    const decoded = decodeEcdsaDer(der);
    if (decoded === null) {
      throw new Error("ES256 signing produced an unparseable DER signature");
    }
    const s = decoded.s > P256_ORDER / 2n ? P256_ORDER - decoded.s : decoded.s;
    const lowS = encodeEcdsaDer(decoded.r, s);
    return { alg: "ES256", value: lowS.toString("base64url") + padding(lowS.length) };
  }
  throw new Error("ApprovalReceipt signing supports Ed25519 and P-256 (ES256) keys only");
}

/**
 * Verify an ApprovalReceipt's signature against one public key (Section 14.1).
 *
 * The declared `alg` must match the key type: `Ed25519` for an Ed25519 key,
 * `ES256` for a P-256 key. An ES256 value must be strict DER with a low `s`.
 * Returns false for any missing, malformed or non-verifying signature; it never
 * throws.
 */
export function verifyApprovalReceiptSignature(
  receipt: Record<string, unknown>,
  publicKey: SigningPublicKey,
): boolean {
  const signature = Object.prototype.hasOwnProperty.call(receipt, "signature")
    ? receipt.signature
    : undefined;
  if (signature === null || typeof signature !== "object" || Array.isArray(signature)) {
    return false;
  }
  const sig = signature as Record<string, unknown>;
  const alg = Object.prototype.hasOwnProperty.call(sig, "alg") ? sig.alg : undefined;
  const value = Object.prototype.hasOwnProperty.call(sig, "value") ? sig.value : undefined;
  if (typeof alg !== "string" || typeof value !== "string" || value === "") {
    return false;
  }
  const raw = strictB64urlDecode(value);
  if (raw === null) {
    return false;
  }
  try {
    const payload = approvalReceiptSigningBytes(receipt);
    if (alg === "Ed25519" && isEd25519(publicKey)) {
      return cryptoVerify(null, payload, publicKey, raw);
    }
    if (
      alg === "ES256" &&
      publicKey.asymmetricKeyType === "ec" &&
      publicKey.asymmetricKeyDetails?.namedCurve === "prime256v1"
    ) {
      const decoded = decodeEcdsaDer(raw);
      if (decoded === null || !encodeEcdsaDer(decoded.r, decoded.s).equals(raw)) {
        return false;
      }
      if (decoded.s <= 0n || decoded.s > P256_ORDER / 2n) {
        return false;
      }
      return cryptoVerify("sha256", payload, { key: publicKey, dsaEncoding: "der" }, raw);
    }
    return false;
  } catch {
    return false;
  }
}

/** Base64 padding that a padded encoding of `byteLength` bytes ends with. */
function padding(byteLength: number): string {
  return "=".repeat((3 - (byteLength % 3)) % 3);
}

/**
 * Decode base64url only if `value` is its canonical encoding: padded or
 * unpadded, but the decoded bytes must re-encode to exactly `value` (no stray
 * characters, no `+` or `/`, no extra padding).
 */
function strictB64urlDecode(value: string): Buffer | null {
  const unpadded = value.replace(/=+$/, "");
  if (value === "" || !B64URL_ALPHABET.test(unpadded)) {
    return null;
  }
  const raw = Buffer.from(unpadded, "base64url");
  const canonical = raw.toString("base64url");
  const padded = canonical + padding(raw.length);
  return value === canonical || value === padded ? raw : null;
}

/** Parse a DER ECDSA signature strictly; null unless it is minimal DER. */
function decodeEcdsaDer(der: Buffer | Uint8Array): { r: bigint; s: bigint } | null {
  const buf = Buffer.from(der);
  if (buf.length < 8 || buf[0] !== 0x30 || buf[1] >= 0x80 || buf[1] !== buf.length - 2) {
    return null;
  }
  let offset = 2;
  const readInt = (): bigint | null => {
    if (buf[offset] !== 0x02) {
      return null;
    }
    const len = buf[offset + 1];
    if (len === undefined || len === 0 || len >= 0x80 || offset + 2 + len > buf.length) {
      return null;
    }
    const bytes = buf.subarray(offset + 2, offset + 2 + len);
    if (bytes[0] & 0x80) {
      return null;
    }
    if (len > 1 && bytes[0] === 0x00 && !(bytes[1] & 0x80)) {
      return null;
    }
    offset += 2 + len;
    return BigInt("0x" + (bytes.toString("hex") || "0"));
  };
  const r = readInt();
  const s = readInt();
  if (r === null || s === null || offset !== buf.length) {
    return null;
  }
  return { r, s };
}

/** Encode r and s as a minimal DER ECDSA signature. */
function encodeEcdsaDer(r: bigint, s: bigint): Buffer {
  const encodeInt = (x: bigint): Buffer => {
    let hex = x.toString(16);
    if (hex.length % 2) {
      hex = "0" + hex;
    }
    let bytes = Buffer.from(hex, "hex");
    if (bytes[0] & 0x80) {
      bytes = Buffer.concat([Buffer.from([0x00]), bytes]);
    }
    return Buffer.concat([Buffer.from([0x02, bytes.length]), bytes]);
  };
  const body = Buffer.concat([encodeInt(r), encodeInt(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

export function b64urlEncode(data: Buffer | Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

export function b64urlDecode(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

export function jwtAlgorithmForKey(key: KeyObject): string {
  return isEd25519(key) ? "EdDSA" : "ES256";
}
