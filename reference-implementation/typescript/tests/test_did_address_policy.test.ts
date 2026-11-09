/**
 * The did:web address policy: no document is fetched from a non-public host.
 *
 * DNS is mocked (the `lookup` of publicAddressFetch) and so is the connection
 * (its `connect`, which hands back a socket to a local server): these tests
 * never touch the network. The address lists are shared with the Python suite,
 * in spec/test-vectors/did-web-address-policy.json.
 */

import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { connect as netConnect, type AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { buildConnector } from "undici";
import { afterAll, beforeAll, expect, test, vi } from "vitest";

import { createJwt, generateEd25519Keypair, publicKeyToJwk } from "../src/a2cn/crypto.js";
import {
  DidWebHostRefused,
  isPublicUnicast,
  publicAddressFetch,
  resolveDidWeb,
  type FetchLike,
} from "../src/a2cn/did.js";
import type { Dict } from "../src/a2cn/messages.js";
import { PROTOCOL_ACT_VERSION } from "../src/a2cn/messages.js";
import { createServerContext, TOKEN_NOT_VERIFIED } from "../src/a2cn/server.js";
import { freshServer, makeDidDocument, SERVER_DID } from "./conftest.js";

const here = dirname(fileURLToPath(import.meta.url));
const POLICY = JSON.parse(
  readFileSync(join(here, "..", "..", "..", "spec", "test-vectors", "did-web-address-policy.json"), "utf8"),
) as {
  refused_addresses: Array<{ address: string; range: string }>;
  public_addresses: Array<{ address: string; range: string }>;
  ip_literal_hosts: Array<{ did: string; form: string }>;
};

const HOST = "did-host.example";
const DID = `did:web:${HOST}`;
const PUBLIC = "8.8.8.8";

// A local server standing in for every public host: the fake connector hands
// undici a socket to it, whatever address the policy checked.
let documentServer: Server;
let documentPort = 0;

beforeAll(async () => {
  documentServer = createServer((_request, response) => {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify(makeDidDocument(DID, "key-1", { kty: "OKP" })));
  });
  await new Promise<void>((resolve) => documentServer.listen(0, "127.0.0.1", resolve));
  documentPort = (documentServer.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise((resolve) => documentServer.close(resolve));
});

/** Mocked DNS and connection; read `lookups` and `connects`. An address in `unreachable` refuses the connection. */
function network(dns: Record<string, string[]>, unreachable: string[] = []) {
  const lookups: string[] = [];
  const connects: Array<{ hostname: string; servername?: string }> = [];
  const lookup = async (hostname: string) => {
    lookups.push(hostname);
    if (!(hostname in dns)) {
      throw new Error(`no such host ${hostname}`);
    }
    return [...dns[hostname]];
  };
  const connect: buildConnector.connector = (opts, callback) => {
    connects.push({ hostname: opts.hostname, servername: opts.servername });
    if (unreachable.includes(opts.hostname)) {
      callback(new Error(`connect ECONNREFUSED ${opts.hostname}`), null);
      return;
    }
    // Calls back once, as undici's own connector does.
    const socket = netConnect(documentPort, "127.0.0.1");
    const failed = (exc: Error) => callback(exc, null);
    socket.once("error", failed);
    socket.once("connect", () => {
      socket.off("error", failed);
      callback(null, socket);
    });
  };
  return { lookups, connects, fetchFn: publicAddressFetch({ lookup, connect }) };
}

// --- The address table ------------------------------------------------------

for (const { address, range } of POLICY.refused_addresses) {
  test(`a non-public address is refused: ${address} (${range})`, () => {
    expect(isPublicUnicast(address)).toBe(false);
  });

  test(`a host resolving to ${address} is never connected`, async () => {
    const net = network({ [HOST]: [address] });
    await expect(resolveDidWeb(DID, net.fetchFn)).rejects.toBeInstanceOf(DidWebHostRefused);
    expect(net.connects).toEqual([]);
  });
}

for (const { address, range } of POLICY.public_addresses) {
  test(`a public address is allowed: ${address} (${range})`, () => {
    expect(isPublicUnicast(address)).toBe(true);
  });
}

// --- The host ---------------------------------------------------------------

for (const { did, form } of POLICY.ip_literal_hosts) {
  test(`a host written as an IP address is refused before any lookup: ${form}`, async () => {
    const net = network({});
    await expect(resolveDidWeb(did, net.fetchFn)).rejects.toThrow(/IP address/);
    expect(net.lookups).toEqual([]);
    expect(net.connects).toEqual([]);
  });
}

test("a host written as an IP address is refused with a supplied fetch too", async () => {
  const fetchFn = vi.fn();
  await expect(resolveDidWeb("did:web:127.0.0.1", fetchFn as unknown as FetchLike)).rejects.toBeInstanceOf(
    DidWebHostRefused,
  );
  expect(fetchFn).not.toHaveBeenCalled();
});

test("an ipv4 mapped address is refused", async () => {
  const net = network({ [HOST]: ["::ffff:127.0.0.1"] });
  await expect(resolveDidWeb(DID, net.fetchFn)).rejects.toThrow(/non-public address/);
  expect(net.connects).toEqual([]);
});

test("one private address among public ones refuses the host", async () => {
  const net = network({ [HOST]: [PUBLIC, "2606:4700:4700::1111", "10.1.2.3"] });
  await expect(resolveDidWeb(DID, net.fetchFn)).rejects.toThrow(/10\.1\.2\.3/);
  expect(net.connects).toEqual([]);
});

test("a host with no address is refused", async () => {
  const net = network({ [HOST]: [] });
  await expect(resolveDidWeb(DID, net.fetchFn)).rejects.toBeInstanceOf(DidWebHostRefused);
});

// --- The connection ---------------------------------------------------------

test("a public host resolves through the address it checked", async () => {
  const net = network({ [HOST]: [PUBLIC, "1.1.1.1"] });
  const document = await resolveDidWeb(DID, net.fetchFn);
  expect(document.id).toBe(DID);
  // One lookup; the connection goes to the first checked address, and TLS is
  // still started for the host name.
  expect(net.lookups).toEqual([HOST]);
  expect(net.connects).toEqual([{ hostname: PUBLIC, servername: HOST }]);
});

test("an unreachable first address falls back to the next checked one", async () => {
  const net = network({ [HOST]: ["2606:4700:4700::1111", PUBLIC] }, ["2606:4700:4700::1111"]);
  const document = await resolveDidWeb(DID, net.fetchFn);
  expect(document.id).toBe(DID);
  expect(net.lookups).toEqual([HOST]); // still one lookup
  expect(net.connects).toEqual([
    { hostname: "2606:4700:4700::1111", servername: HOST },
    { hostname: PUBLIC, servername: HOST },
  ]);
});

test("a host whose addresses are all unreachable fails after trying each", async () => {
  const net = network({ [HOST]: [PUBLIC, "1.1.1.1"] }, [PUBLIC, "1.1.1.1"]);
  await expect(resolveDidWeb(DID, net.fetchFn)).rejects.toThrow();
  expect(net.lookups).toEqual([HOST]);
  expect(net.connects.map((entry) => entry.hostname)).toEqual([PUBLIC, "1.1.1.1"]);
});

for (const position of [0, 1, 2]) {
  test(`a refused address anywhere in the list refuses the host: position ${position}`, async () => {
    const addresses = [PUBLIC, "1.1.1.1"];
    addresses.splice(position, 0, "169.254.169.254");
    const net = network({ [HOST]: addresses }, [PUBLIC]);
    await expect(resolveDidWeb(DID, net.fetchFn)).rejects.toThrow(/169\.254\.169\.254/);
    expect(net.connects).toEqual([]);
  });
}

test("each fetch looks the host up once", async () => {
  const net = network({ [HOST]: [PUBLIC] });
  for (let i = 0; i < 3; i += 1) {
    await resolveDidWeb(DID, net.fetchFn);
  }
  expect(net.lookups).toEqual([HOST, HOST, HOST]);
  expect(net.connects.map((entry) => entry.hostname)).toEqual([PUBLIC, PUBLIC, PUBLIC]);
});

test("the default fetch refuses localhost through the system resolver", async () => {
  // No fetch supplied: the resolver's own, with the real lookup of localhost.
  await expect(resolveDidWeb("did:web:localhost")).rejects.toBeInstanceOf(DidWebHostRefused);
});

// --- The opt-in -------------------------------------------------------------

test("the opt in allows a private host", async () => {
  const served: string[] = [];
  const fetchFn = (async (url: string) => {
    served.push(url);
    return new Response(JSON.stringify({ id: "did:web:127.0.0.1" }), { status: 200 });
  }) as unknown as FetchLike;
  const document = await resolveDidWeb("did:web:127.0.0.1", fetchFn, undefined, { allowPrivateHosts: true });
  expect(document.id).toBe("did:web:127.0.0.1");
  expect(served).toEqual(["https://127.0.0.1/.well-known/did.json"]);
});

test("the opt in is off by default", async () => {
  const net = network({ localhost: ["127.0.0.1", "::1"] });
  await expect(resolveDidWeb("did:web:localhost", net.fetchFn)).rejects.toBeInstanceOf(DidWebHostRefused);
  expect(net.connects).toEqual([]);
});

// --- The server -------------------------------------------------------------

const PRIVATE_HOST = "internal-only.example";
const PRIVATE_DID = `did:web:${PRIVATE_HOST}`;
const PRIVATE_ADDRESS = "10.20.30.40";

async function token(issuer: string): Promise<string> {
  const { privateKey } = generateEd25519Keypair();
  return createJwt(issuer, SERVER_DID, privateKey, { kid: `${issuer}#key-1`, expSeconds: 60 });
}

function expectNothingAboutTheFetch(text: string, ...extra: string[]) {
  for (const leaked of [PRIVATE_HOST, PRIVATE_ADDRESS, "non-public", "resolves", "Refused", ...extra]) {
    expect(text).not.toContain(leaked);
  }
}

test("the 401 names neither the host nor the error", async () => {
  const fixture = freshServer();
  const net = network({ [PRIVATE_HOST]: [PRIVATE_ADDRESS] });
  fixture.ctx.didFetchFn = net.fetchFn;
  const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  try {
    const r = await fixture.rawClient.get("/sessions/any", {
      headers: { Authorization: `Bearer ${await token(PRIVATE_DID)}` },
    });
    expect(r.statusCode).toBe(401);
    expect((r.json().error as Dict).code).toBe("INVALID_JWT");
    expect((r.json().error as Dict).message).toBe(TOKEN_NOT_VERIFIED);
    expectNothingAboutTheFetch(r.body);
    expect(net.connects).toEqual([]);
    // The detail goes to the server log.
    expect(warn.mock.calls.flat().join(" ")).toContain(PRIVATE_ADDRESS);
  } finally {
    warn.mockRestore();
  }
});

test("the 401 does not echo a fetch error", async () => {
  const fixture = freshServer();
  fixture.ctx.didFetchFn = (async () => {
    throw new Error("connection refused by the-secret-detail");
  }) as unknown as FetchLike;
  const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  try {
    const r = await fixture.rawClient.get("/sessions/any", {
      headers: { Authorization: `Bearer ${await token(PRIVATE_DID)}` },
    });
    expect(r.statusCode).toBe(401);
    expectNothingAboutTheFetch(r.body, "the-secret-detail");
  } finally {
    warn.mockRestore();
  }
});

test("the 401 does not echo the fetched document", async () => {
  // The fetched document has no usable key: the reason names its contents, so it stays out.
  const fixture = freshServer();
  fixture.ctx.didFetchFn = network({ [HOST]: [PUBLIC] }).fetchFn;
  const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  try {
    const r = await fixture.rawClient.get("/sessions/any", {
      headers: { Authorization: `Bearer ${await token(DID)}` },
    });
    expect(r.statusCode).toBe(401);
    expect((r.json().error as Dict).message).toBe(TOKEN_NOT_VERIFIED);
    expectNothingAboutTheFetch(r.body, "OKP", "kty", "key-1");
  } finally {
    warn.mockRestore();
  }
});

test("the server's own resolver refuses a private host", async () => {
  // No didFetchFn: the server uses the resolver's own fetch and the real lookup of localhost.
  const fixture = freshServer();
  const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  try {
    const r = await fixture.rawClient.get("/sessions/any", {
      headers: { Authorization: `Bearer ${await token("did:web:localhost")}` },
    });
    expect(r.statusCode).toBe(401);
    expect((r.json().error as Dict).message).toBe(TOKEN_NOT_VERIFIED);
    expect(warn.mock.calls.flat().join(" ")).toContain("DidWebHostRefused");
  } finally {
    warn.mockRestore();
  }
});

test("an invitation from a private host is never fetched", async () => {
  const fixture = freshServer();
  const net = network({ [PRIVATE_HOST]: [PRIVATE_ADDRESS] });
  fixture.ctx.didFetchFn = net.fetchFn;
  const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  try {
    const r = await fixture.rawClient.post("/invitations", {
      json: {
        a2cn_version: PROTOCOL_ACT_VERSION,
        inviter_did: PRIVATE_DID,
        inviter_verification_method: `${PRIVATE_DID}#key-1`,
        invitation_signature: "x",
      },
    });
    expect(r.statusCode).toBe(503);
    expect((r.json().error as Dict).code).toBe("DID_RESOLUTION_FAILED");
    expectNothingAboutTheFetch(r.body);
    expect(net.lookups).toEqual([PRIVATE_HOST]);
    expect(net.connects).toEqual([]);
  } finally {
    warn.mockRestore();
  }
});

test("the server setting allows a private host", async () => {
  const fixture = freshServer();
  const { privateKey, publicKey } = generateEd25519Keypair();
  const issuer = "did:web:127.0.0.1";
  fixture.ctx.allowPrivateDidHosts = true;
  fixture.ctx.didFetchFn = (async () =>
    new Response(JSON.stringify(makeDidDocument(issuer, "key-1", publicKeyToJwk(publicKey))), {
      status: 200,
    })) as unknown as FetchLike;
  const jwt = await createJwt(issuer, SERVER_DID, privateKey, { kid: `${issuer}#key-1`, expSeconds: 60 });
  const r = await fixture.rawClient.get(`/sessions/${crypto.randomUUID()}`, {
    headers: { Authorization: `Bearer ${jwt}` },
  });
  expect(r.statusCode).toBe(404); // authenticated; the session does not exist
});

test("the server setting is off by default", () => {
  const saved = process.env.A2CN_ALLOW_PRIVATE_DID_HOSTS;
  try {
    delete process.env.A2CN_ALLOW_PRIVATE_DID_HOSTS;
    expect(createServerContext().allowPrivateDidHosts).toBe(false);
    process.env.A2CN_ALLOW_PRIVATE_DID_HOSTS = "1";
    expect(createServerContext().allowPrivateDidHosts).toBe(true);
  } finally {
    if (saved === undefined) {
      delete process.env.A2CN_ALLOW_PRIVATE_DID_HOSTS;
    } else {
      process.env.A2CN_ALLOW_PRIVATE_DID_HOSTS = saved;
    }
  }
});
