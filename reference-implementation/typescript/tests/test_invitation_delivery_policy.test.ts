/**
 * Invitation delivery goes only to public hosts.
 *
 * POST /invitations/create with a recipient_endpoint makes the server POST the
 * invitation to <recipient_endpoint>/invitations. That is a request to a host
 * the caller names, so it goes through the same address policy as a did:web
 * fetch.
 *
 * DNS is mocked (the `lookup` of publicAddressFetch) and so is the connection
 * (its `connect`, which hands back a socket to a local recording server): these
 * tests never touch the network. The Python suite has the same cases.
 */

import { createServer, type Server } from "node:http";
import { connect as netConnect, type AddressInfo } from "node:net";

import type { buildConnector } from "undici";
import { afterAll, afterEach, beforeAll, beforeEach, expect, test, vi, type MockInstance } from "vitest";

import { publicAddressFetch } from "../src/a2cn/did.js";
import type { Dict } from "../src/a2cn/messages.js";
import { createServerContext } from "../src/a2cn/server.js";
import { freshServer, type ServerFixture } from "./conftest.js";

const RECIPIENT_HOST = "recipient.example";
const RECIPIENT = `https://${RECIPIENT_HOST}/a2cn`;
const PUBLIC = "8.8.8.8";
const PRIVATE_HOST = "internal-only.example";
const PRIVATE_ADDRESS = "10.20.30.40";
const LOOPBACK_HOST = "loopback-alias.example";
const ELSEWHERE_HOST = "elsewhere.example";
const ELSEWHERE = "1.1.1.1";

const IP_LITERAL_ENDPOINTS = [
  "http://127.0.0.1:8001",
  "https://[::1]",
  "http://2130706433",
  "http://127.1",
  "http://0x7f.0.0.1",
  "http://[::ffff:10.0.0.1]:8080",
  "https://8.8.8.8", // a public address is refused too: the host must be a name
];

const NOT_HTTP_ENDPOINTS: unknown[] = [
  "file:///etc",
  "ftp://recipient.example",
  "recipient.example",
  42,
  ["https://x.example"],
];

// A local server standing in for every recipient: the fake connector hands
// undici a socket to it, whatever address the policy checked.
type Seen = { method: string; url: string; body: string };
let recipientServer: Server;
let recipientPort = 0;
let seen: Seen[] = [];
let reply: { status: number; headers: Record<string, string> } = { status: 202, headers: {} };

beforeAll(async () => {
  recipientServer = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      seen.push({ method: request.method ?? "", url: request.url ?? "", body: Buffer.concat(chunks).toString() });
      response.writeHead(reply.status, reply.headers);
      response.end();
    });
  });
  await new Promise<void>((resolve) => recipientServer.listen(0, "127.0.0.1", resolve));
  recipientPort = (recipientServer.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise((resolve) => recipientServer.close(resolve));
});

let warn: MockInstance;

beforeEach(() => {
  seen = [];
  reply = { status: 202, headers: {} };
  warn = vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  warn.mockRestore();
});

function log(): string {
  return warn.mock.calls.flat().map(String).join("\n");
}

/** A server whose public fetch has mocked DNS and connection; read `lookups` and `connects`. */
function server(unreachable: string[] = []) {
  const dns: Record<string, string[]> = {
    [RECIPIENT_HOST]: [PUBLIC],
    [PRIVATE_HOST]: [PRIVATE_ADDRESS],
    [LOOPBACK_HOST]: ["127.0.0.1"],
    [ELSEWHERE_HOST]: [ELSEWHERE],
    "unreachable.example": [ELSEWHERE],
  };
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
      callback(new Error(`connect ECONNREFUSED ${opts.hostname} the-secret-detail`), null);
      return;
    }
    const socket = netConnect(recipientPort, "127.0.0.1");
    const failed = (exc: Error) => callback(exc, null);
    socket.once("error", failed);
    socket.once("connect", () => {
      socket.off("error", failed);
      callback(null, socket);
    });
  };
  const fixture: ServerFixture = freshServer();
  fixture.ctx.publicFetchFn = publicAddressFetch({ lookup, connect });
  // Webhooks only: invitation delivery never uses it.
  const webhookFetch = vi.fn(async () => new Response(null, { status: 202 }));
  fixture.ctx.fetchFn = webhookFetch as unknown as typeof fetch;
  return { fixture, lookups, connects, webhookFetch };
}

async function create(fixture: ServerFixture, recipientEndpoint?: unknown) {
  const json: Dict = { proposed_deal_type: "saas_renewal" };
  if (recipientEndpoint !== undefined) {
    json.recipient_endpoint = recipientEndpoint;
  }
  return fixture.client.post("/invitations/create", { json });
}

// --- Refused ------------------------------------------------------------------

for (const [name, host, address] of [
  ["private", PRIVATE_HOST, PRIVATE_ADDRESS],
  ["loopback", LOOPBACK_HOST, "127.0.0.1"],
]) {
  test(`a recipient on a non-public host is refused and nothing is sent: ${name}`, async () => {
    const s = server();
    const r = await create(s.fixture, `https://${host}:8443`);
    expect(r.statusCode).toBe(201);
    expect(s.lookups).toEqual([host]);
    expect(s.connects).toEqual([]);
    expect(seen).toEqual([]);
    expect(s.webhookFetch).not.toHaveBeenCalled();
    // The host and the reason go to the server log.
    expect(log()).toContain(host);
    expect(log()).toContain(address);
    expect(log()).toContain("non-public address");
  });
}

for (const endpoint of IP_LITERAL_ENDPOINTS) {
  test(`a recipient written as an IP address is refused before any lookup: ${endpoint}`, async () => {
    const s = server();
    const r = await create(s.fixture, endpoint);
    expect(r.statusCode).toBe(201);
    expect(s.lookups).toEqual([]);
    expect(s.connects).toEqual([]);
    expect(s.webhookFetch).not.toHaveBeenCalled();
    expect(log()).toContain("IP address");
  });
}

for (const endpoint of NOT_HTTP_ENDPOINTS) {
  test(`a recipient that is not an http url is refused: ${JSON.stringify(endpoint)}`, async () => {
    const s = server();
    const r = await create(s.fixture, endpoint);
    expect(r.statusCode).toBe(201);
    expect(s.lookups).toEqual([]);
    expect(s.connects).toEqual([]);
    expect(s.webhookFetch).not.toHaveBeenCalled();
    expect(log()).toContain("Invitation not delivered");
  });
}

test("a redirect from a public recipient is not followed", async () => {
  reply = { status: 307, headers: { Location: `https://${ELSEWHERE_HOST}/invitations` } };
  const s = server();
  const r = await create(s.fixture, RECIPIENT);
  expect(r.statusCode).toBe(201);
  expect(seen.map((request) => `${request.method} ${request.url}`)).toEqual(["POST /a2cn/invitations"]);
  expect(s.lookups).toEqual([RECIPIENT_HOST]);
  expect(s.connects.map((entry) => entry.hostname)).toEqual([PUBLIC]);
  expect(log()).toContain("307");
});

// --- Delivered ----------------------------------------------------------------

test("a public recipient is delivered through the address it checked", async () => {
  const s = server();
  const r = await create(s.fixture, RECIPIENT);
  expect(r.statusCode).toBe(201);
  expect(s.lookups).toEqual([RECIPIENT_HOST]);
  expect(s.connects).toEqual([{ hostname: PUBLIC, servername: RECIPIENT_HOST }]);
  expect(seen.map((request) => `${request.method} ${request.url}`)).toEqual(["POST /a2cn/invitations"]);
  expect(JSON.parse(seen[0].body)).toEqual(r.json());
  expect(s.webhookFetch).not.toHaveBeenCalled();
});

// --- The response does not depend on delivery ---------------------------------

const LEAKS = [
  RECIPIENT_HOST,
  PUBLIC,
  PRIVATE_HOST,
  PRIVATE_ADDRESS,
  "127.0.0.1",
  "non-public",
  "IP address",
  "refused",
  "Refused",
  "deliver",
  "the-secret-detail",
  "ECONNREFUSED",
  "recipient_endpoint",
];

test("the response is the same whether delivery is refused, fails or succeeds", async () => {
  const s = server([ELSEWHERE]);
  const outcomes: Record<string, string | undefined> = {
    none: undefined,
    private: `https://${PRIVATE_HOST}`,
    "ip-literal": "http://127.0.0.1:8001",
    "not-http": "file:///etc",
    unresolvable: "https://no-such-host.example",
    unreachable: "https://unreachable.example",
    delivered: RECIPIENT,
  };
  const shapes = new Set<string>();
  for (const [name, endpoint] of Object.entries(outcomes)) {
    const r = await create(s.fixture, endpoint);
    expect(r.statusCode, name).toBe(201);
    for (const leaked of LEAKS) {
      expect(r.body, `${name}: ${leaked}`).not.toContain(leaked);
    }
    shapes.add(JSON.stringify([r.statusCode, Object.keys(r.json()).sort(), r.headers["content-type"]]));
  }
  expect([...shapes]).toHaveLength(1);
  // Every failure was logged; the delivered one was not.
  for (const name of ["private", "ip-literal", "not-http", "unresolvable", "unreachable"]) {
    expect(log(), name).toContain(outcomes[name]);
  }
  expect(log()).not.toContain(RECIPIENT);
});

// --- The opt-in -----------------------------------------------------------------

test("the server setting lets a private recipient through", async () => {
  // No public fetch: with the setting on, delivery uses a plain fetch to the real loopback server.
  const s = server();
  s.fixture.ctx.allowPrivateHosts = true;
  s.fixture.ctx.publicFetchFn = null;
  const r = await create(s.fixture, `http://127.0.0.1:${recipientPort}`);
  expect(r.statusCode).toBe(201);
  expect(seen.map((request) => `${request.method} ${request.url}`)).toEqual(["POST /invitations"]);
  expect(JSON.parse(seen[0].body)).toEqual(r.json());
  expect(s.webhookFetch).not.toHaveBeenCalled();
});

test("the server setting is off by default", async () => {
  const s = server();
  expect(s.fixture.ctx.allowPrivateHosts).toBe(false);
  s.fixture.ctx.publicFetchFn = null;
  const r = await create(s.fixture, `http://127.0.0.1:${recipientPort}`);
  expect(r.statusCode).toBe(201);
  expect(seen).toEqual([]);
});

test("the server setting is read from the environment", () => {
  const saved = process.env.A2CN_ALLOW_PRIVATE_HOSTS;
  try {
    delete process.env.A2CN_ALLOW_PRIVATE_HOSTS;
    expect(createServerContext().allowPrivateHosts).toBe(false);
    process.env.A2CN_ALLOW_PRIVATE_HOSTS = "1";
    expect(createServerContext().allowPrivateHosts).toBe(true);
  } finally {
    if (saved === undefined) {
      delete process.env.A2CN_ALLOW_PRIVATE_HOSTS;
    } else {
      process.env.A2CN_ALLOW_PRIVATE_HOSTS = saved;
    }
  }
});
