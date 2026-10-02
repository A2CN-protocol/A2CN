/** Buyer-side process for the two-process A2CN HTTP demo. */

import Fastify from "fastify";

import { A2CNClient, HttpStatusError } from "../../src/a2cn/client.js";
import type { Dict } from "../../src/a2cn/messages.js";
import {
  BUYER_DID,
  BUYER_KEY_ID,
  BUYER_PORT,
  SUPPLIER_DID,
  SUPPLIER_URL,
  authedFetch,
  buyerAgentInfo,
  buyerMandate,
  buyerPrivateKey,
  freshJwtFactory,
  renewalTerms,
  sessionParams,
} from "./demo_shared.js";

const app = Fastify({ logger: false });
app.removeAllContentTypeParsers();
app.addContentTypeParser("*", { parseAs: "buffer" }, (_req, body, done) => done(null, body));

app.get("/demo/health", async (_request, reply) => {
  return reply
    .header("content-type", "application/json")
    .send(JSON.stringify({ status: "ok", role: "buyer", did: BUYER_DID }));
});

app.post("/demo/run", async (_request, reply) => {
  try {
    const result = await runNegotiation();
    return reply.header("content-type", "application/json").send(JSON.stringify(result));
  } catch (exc) {
    if (exc instanceof HttpStatusError) {
      return reply.code(exc.status).send(JSON.stringify({ detail: exc.body }));
    }
    throw exc;
  }
});

async function runNegotiation(): Promise<Dict> {
  const buyerKey = buyerPrivateKey();
  const transcript: Dict[] = [];
  const tokenFactory = freshJwtFactory(BUYER_DID, SUPPLIER_DID, buyerKey, BUYER_KEY_ID);
  const http = authedFetch(tokenFactory);
  const client = new A2CNClient({
    agentInfo: buyerAgentInfo(),
    privateKey: buyerKey,
    mandate: buyerMandate(),
    fetchFn: fetch,
    authTokenFactory: tokenFactory,
  });

  const discovery = await client.fetchDiscovery(SUPPLIER_URL);
  transcript.push({ step: "discovery", supplier: discovery });

  const ack = await client.initiateSession(SUPPLIER_URL, SUPPLIER_DID, sessionParams());
  const sessionId = ack.session_id as string;
  transcript.push({ step: "session_ack", session_id: sessionId });

  await client.sendOffer(SUPPLIER_URL, SUPPLIER_DID, sessionId, renewalTerms(9_500_000, 30));
  const buyerOffer1 = client._sessions[sessionId].latest_offer as Dict;
  transcript.push({
    step: "buyer_offer",
    amount: "$95,000",
    message_id: buyerOffer1.message_id,
  });

  const supplierR1 = await http(`${SUPPLIER_URL}/demo/counteroffer`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: sessionId,
      in_reply_to: buyerOffer1.message_id,
      terms: renewalTerms(11_500_000, 60),
    }),
  });
  if (supplierR1.status >= 400) {
    throw new HttpStatusError(supplierR1.status, await supplierR1.text(), "/demo/counteroffer");
  }
  const supplierOffer1 = (((await supplierR1.json()) as Dict).message as Dict);
  client.processIncoming(sessionId, supplierOffer1);
  transcript.push({
    step: "supplier_counteroffer",
    amount: "$115,000",
    message_id: supplierOffer1.message_id,
  });

  await client.sendOffer(
    SUPPLIER_URL,
    SUPPLIER_DID,
    sessionId,
    renewalTerms(10_300_000, 30),
    supplierOffer1.message_id as string,
  );
  const buyerOffer2 = client._sessions[sessionId].latest_offer as Dict;
  transcript.push({
    step: "buyer_counteroffer",
    amount: "$103,000",
    message_id: buyerOffer2.message_id,
  });

  const supplierR2 = await http(`${SUPPLIER_URL}/demo/counteroffer`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: sessionId,
      in_reply_to: buyerOffer2.message_id,
      terms: renewalTerms(10_500_000, 45),
    }),
  });
  if (supplierR2.status >= 400) {
    throw new HttpStatusError(supplierR2.status, await supplierR2.text(), "/demo/counteroffer");
  }
  const supplierOffer2 = (((await supplierR2.json()) as Dict).message as Dict);
  client.processIncoming(sessionId, supplierOffer2);
  transcript.push({
    step: "supplier_counteroffer",
    amount: "$105,000 net-45",
    message_id: supplierOffer2.message_id,
  });

  await client.sendAcceptance(SUPPLIER_URL, SUPPLIER_DID, sessionId, supplierOffer2);
  transcript.push({ step: "buyer_acceptance", accepted_offer_id: supplierOffer2.message_id });

  const supplierRecord = await client.getTransactionRecord(SUPPLIER_URL, sessionId);
  const buyerRecord = client.buildClientSideRecord(sessionId);

  return {
    session_id: sessionId,
    transcript,
    buyer_record: buyerRecord,
    supplier_record: supplierRecord,
    record_hashes_match: buyerRecord.record_hash === supplierRecord.record_hash,
  };
}

const portArgIndex = process.argv.indexOf("--port");
const port =
  portArgIndex >= 0 && portArgIndex + 1 < process.argv.length
    ? parseInt(process.argv[portArgIndex + 1], 10)
    : BUYER_PORT;

app.listen({ host: "127.0.0.1", port }).catch((exc) => {
  console.error(exc);
  process.exit(1);
});
