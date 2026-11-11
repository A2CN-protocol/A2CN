/**
 * A2CN DID Resolution — did:web only.
 *
 * Section 4.2: All signing keys MUST be retrieved from DID documents.
 *
 * did:web:example.com           → https://example.com/.well-known/did.json
 * did:web:example.com:path:to   → https://example.com/path/to/did.json
 */

import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";

import { Agent, buildConnector, fetch as undiciFetch } from "undici";

import { publicKeyFromJwk, type SigningPublicKey } from "./crypto.js";

export type FetchLike = (
  url: string,
  init?: {
    method?: string;
    body?: string;
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
 * The host must be a name, not an IP address, and every address it resolves to
 * must be public unicast (isPublicUnicast); the default fetch connects only to
 * the addresses it checked, trying them in order until one connects, with no
 * second lookup, and TLS still verifies the host name. Like Node's fetch, it
 * uses no proxy. `allowPrivateHosts` turns both checks off, for local development and
 * tests only. A `fetchFn` you supply makes its own connections: the host-name
 * check still applies, the address check only if it is a publicAddressFetch.
 *
 * The document's `id` must be exactly `did` (didDocumentIsFor): a document that
 * names another DID is refused, however close the spelling, because it is that
 * other DID's document, not this one's. No DID is normalized for the comparison.
 *
 * Throws:
 * - DidWebHostRefused if the address policy refuses the host
 * - DidDocumentIdMismatch if the document's id is not `did`
 * - Error if the DID is not a did:web DID or cannot be parsed
 * - Error if the DID document cannot be fetched, is too large, compressed, or
 *   is not valid UTF-8 JSON, or if the fetch does not finish in time
 */
export async function resolveDidWeb(
  did: string,
  fetchFn?: FetchLike,
  timeoutMs: number = DID_RESOLUTION_TIMEOUT_MS,
  options: { allowPrivateHosts?: boolean } = {},
): Promise<Record<string, unknown>> {
  return requireDidDocumentFor(await fetchDidWebDocument(did, fetchFn, timeoutMs, options), did);
}

/**
 * A DID document whose `id` is not exactly the DID it was obtained for.
 *
 * DID Core requires a resolved document's `id` to be the DID that was resolved.
 * Two spellings of one did:web DID can reach one document (a host's case, a
 * trailing dot, an escaped character, a `:.well-known` path, a Unicode host and
 * its punycode), and only one of them is the document's `id`. A verifier that
 * used the document for the other would let one party sign as two. The key it
 * lists is unavailable for that DID, exactly as when no document can be
 * obtained.
 */
export class DidDocumentIdMismatch extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DidDocumentIdMismatch";
  }
}

/**
 * Whether `didDocument` is the DID document of `did`: its `id` is exactly `did`.
 *
 * The comparison is exact string equality, with no normalization, so a document
 * is the document of one spelling only. A document that is not a JSON object,
 * or has no string `id`, is no DID's document.
 */
export function didDocumentIsFor(didDocument: unknown, did: unknown): boolean {
  return (
    typeof didDocument === "object" &&
    didDocument !== null &&
    !Array.isArray(didDocument) &&
    typeof (didDocument as Record<string, unknown>).id === "string" &&
    (didDocument as Record<string, unknown>).id === did
  );
}

/** Return `didDocument` if it is the document of `did`; throw DidDocumentIdMismatch if not. */
export function requireDidDocumentFor<T>(didDocument: T, did: string): T {
  if (!didDocumentIsFor(didDocument, did)) {
    const named =
      didDocument !== null && typeof didDocument === "object" && !Array.isArray(didDocument)
        ? ((didDocument as Record<string, unknown>).id ?? null)
        : null;
    throw new DidDocumentIdMismatch(
      `the DID document obtained for ${JSON.stringify(did)} is the document of ` +
        `${JSON.stringify(named)}, not of that DID`,
    );
  }
  return didDocument;
}

async function fetchDidWebDocument(
  did: string,
  fetchFn?: FetchLike,
  timeoutMs: number = DID_RESOLUTION_TIMEOUT_MS,
  options: { allowPrivateHosts?: boolean } = {},
): Promise<Record<string, unknown>> {
  const url = didWebToUrl(did);
  const allowPrivateHosts = options.allowPrivateHosts ?? false;
  if (!allowPrivateHosts && isIpLiteral(didWebHost(did))) {
    throw new DidWebHostRefused("did:web host is written as an IP address; it must be a name");
  }
  const doFetch = fetchFn ?? (allowPrivateHosts ? (fetch as FetchLike) : publicAddressFetch());
  const signal = AbortSignal.timeout(timeoutMs);
  let response: Awaited<ReturnType<FetchLike>>;
  try {
    response = await doFetch(url, {
      redirect: "error",
      signal,
      headers: { "Accept-Encoding": "identity" },
    });
  } catch (exc) {
    // fetch reports a refused connection as "fetch failed"; the refusal is the cause.
    if (exc instanceof Error && exc.cause instanceof DidWebHostRefused) {
      throw exc.cause;
    }
    throw exc;
  }
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

/**
 * The address policy refuses this host: an IP address, or a name with an
 * address that is not public unicast. The policy covers every request to a
 * host a caller names: did:web resolution, and the reference server's
 * invitation delivery.
 */
export class DidWebHostRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DidWebHostRefused";
  }
}

// Addresses a did:web document is never fetched from. IPv6 outside 2000::/3 is
// refused as well, and an IPv4-mapped or NAT64 address is judged by the IPv4
// address it carries. The Python implementation holds the same table, and
// spec/test-vectors/did-web-address-policy.json tests both.
const REFUSED_IPV4: Array<[string, number]> = [
  ["0.0.0.0", 8], // this network, unspecified
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // documentation
  ["192.88.99.0", 24], // 6to4 relay anycast
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // documentation
  ["203.0.113.0", 24], // documentation
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved, broadcast
];
const GLOBAL_UNICAST_IPV6: [string, number] = ["2000::", 3];
const REFUSED_IPV6: Array<[string, number]> = [
  ["2001::", 23], // IETF protocol assignments (Teredo, benchmarking, ORCHID)
  ["2001:db8::", 32], // documentation
  ["2002::", 16], // 6to4
  ["3fff::", 20], // documentation
];
const IPV4_CARRYING_IPV6: Array<[string, number]> = [
  ["::ffff:0:0", 96], // IPv4-mapped
  ["64:ff9b::", 96], // NAT64
];

function ipv4ToBigInt(address: string): bigint {
  return address.split(".").reduce((value, part) => (value << 8n) | BigInt(Number(part)), 0n);
}

function ipv6ToBigInt(address: string): bigint {
  let text = address;
  const lastColon = text.lastIndexOf(":");
  const tail = text.slice(lastColon + 1);
  if (tail.includes(".")) {
    // An embedded dotted IPv4 tail is the last two groups.
    const v4 = ipv4ToBigInt(tail);
    text = `${text.slice(0, lastColon + 1)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const groups = (part: string) => (part === "" ? [] : part.split(":").map((group) => parseInt(group, 16)));
  let all: number[];
  if (text.includes("::")) {
    const [head, rest] = text.split("::");
    const before = groups(head);
    const after = groups(rest);
    all = [...before, ...Array<number>(8 - before.length - after.length).fill(0), ...after];
  } else {
    all = groups(text);
  }
  return all.reduce((value, group) => (value << 16n) | BigInt(group), 0n);
}

function inNetwork(value: bigint, bits: number, [network, prefix]: [string, number]): boolean {
  const base = bits === 32 ? ipv4ToBigInt(network) : ipv6ToBigInt(network);
  const shift = BigInt(bits - prefix);
  return value >> shift === base >> shift;
}

/** Whether a did:web document may be fetched from this IP address. */
export function isPublicUnicast(address: string): boolean {
  const bare = address.split("%")[0];
  const version = isIP(bare);
  if (version === 4) {
    const value = ipv4ToBigInt(bare);
    return !REFUSED_IPV4.some((network) => inNetwork(value, 32, network));
  }
  if (version === 6) {
    const value = ipv6ToBigInt(bare);
    if (IPV4_CARRYING_IPV6.some((network) => inNetwork(value, 128, network))) {
      const v4 = value & 0xffffffffn;
      return isPublicUnicast([24n, 16n, 8n, 0n].map((shift) => String((v4 >> shift) & 0xffn)).join("."));
    }
    return (
      inNetwork(value, 128, GLOBAL_UNICAST_IPV6) && !REFUSED_IPV6.some((network) => inNetwork(value, 128, network))
    );
  }
  return false;
}

/** The host a did:web DID names: percent-decoded, without its port. */
export function didWebHost(did: string): string {
  let host = did.slice("did:web:".length).split(":")[0];
  try {
    host = decodeURIComponent(host);
  } catch {
    // Not valid percent-encoding: judged as written.
  }
  if (host.startsWith("[") && host.includes("]")) {
    return host.slice(1, host.indexOf("]"));
  }
  if (host.split(":").length === 2) {
    return host.split(":")[0];
  }
  return host;
}

/**
 * A host written as an IP address, including the shortened and numeric IPv4
 * forms a URL parser reads as addresses (`127.1`, `2130706433`).
 */
function isIpLiteral(host: string): boolean {
  if (isIP(host) !== 0) {
    return true;
  }
  try {
    return isIP(new URL(`https://${host}/`).hostname) !== 0;
  } catch {
    return false;
  }
}

/**
 * The host an http or https URL names, checked before any lookup.
 *
 * Throws:
 * - DidWebHostRefused if the host is written as an IP address (any form
 *   isIpLiteral reads as one), unless `allowPrivateHosts`
 * - Error if the URL is not an http or https URL with a host
 */
export function checkUrlHost(url: string, options: { allowPrivateHosts?: boolean } = {}): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("not an http or https URL");
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.hostname === "") {
    throw new Error("not an http or https URL");
  }
  // An IPv6 host keeps its brackets in URL.hostname.
  const host = parsed.hostname.startsWith("[") ? parsed.hostname.slice(1, -1) : parsed.hostname;
  if (!(options.allowPrivateHosts ?? false) && isIpLiteral(host)) {
    throw new DidWebHostRefused(`host ${host} is written as an IP address; it must be a name`);
  }
  return host;
}

/** Every address a host resolves to. */
export type AddressLookup = (hostname: string) => Promise<string[]>;

const systemLookup: AddressLookup = async (hostname) =>
  (await dnsLookup(hostname, { all: true, verbatim: true })).map((entry) => entry.address);

async function publicAddresses(hostname: string, lookup: AddressLookup): Promise<string[]> {
  const addresses = await lookup(hostname);
  if (addresses.length === 0) {
    throw new DidWebHostRefused(`host ${hostname} has no address`);
  }
  for (const address of addresses) {
    if (!isPublicUnicast(address)) {
      throw new DidWebHostRefused(`host ${hostname} resolves to a non-public address, ${address}`);
    }
  }
  return addresses;
}

/**
 * Connect to the first of `addresses` that accepts, in order, as a direct
 * connection would; the last failure if none does.
 */
function connectInOrder(
  connect: buildConnector.connector,
  opts: buildConnector.Options,
  addresses: string[],
  callback: buildConnector.Callback,
): void {
  const [address, ...rest] = addresses;
  connect({ ...opts, hostname: address, servername: opts.servername ?? opts.hostname }, (exc, socket) => {
    if (exc !== null && rest.length > 0) {
      connectInOrder(connect, opts, rest, callback);
    } else if (exc !== null) {
      callback(exc, null);
    } else {
      callback(null, socket);
    }
  });
}

/**
 * A fetch that connects only through the address policy: each connection looks
 * the host up once, refuses it unless every address is public unicast, and
 * tries the checked addresses in order until one connects, so a host whose
 * first address is unreachable still resolves; the resolver's deadline bounds
 * the whole attempt. TLS is started with the host name, so the certificate is
 * still checked against it. `lookup` and `connect` are for tests.
 */
export function publicAddressFetch(
  options: { lookup?: AddressLookup; connect?: buildConnector.connector } = {},
): FetchLike {
  const lookup = options.lookup ?? systemLookup;
  const connect = options.connect ?? buildConnector({});
  return async (url, init) => {
    const dispatcher = new Agent({
      connect: (opts, callback) => {
        publicAddresses(opts.hostname, lookup).then(
          (addresses) => connectInOrder(connect, opts, addresses, callback),
          (exc: Error) => callback(exc, null),
        );
      },
    });
    let response;
    try {
      response = await undiciFetch(url, { ...init, dispatcher });
    } catch (exc) {
      // A fetch cut off at the deadline stops any connection still being tried.
      void dispatcher.destroy();
      throw exc;
    }
    // Closes once the response body has been read; nothing is kept for a later fetch.
    void dispatcher.close();
    return response as unknown as Awaited<ReturnType<FetchLike>>;
  };
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
