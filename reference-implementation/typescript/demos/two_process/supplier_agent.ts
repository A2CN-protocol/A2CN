/** Supplier-side process for the two-process A2CN HTTP demo. */

import { createServerContext } from "../../src/a2cn/server.js";
import { generateTransactionRecord } from "../../src/a2cn/record.js";
import type { Dict } from "../../src/a2cn/messages.js";
import {
  BUYER_DID,
  BUYER_KEY_ID,
  SUPPLIER_DID,
  SUPPLIER_KEY_ID,
  SUPPLIER_PORT,
  SUPPLIER_URL,
  authedFetch,
  buyerPrivateKey,
  didDocument,
  freshJwtFactory,
  supplierAgentInfo,
  supplierCounteroffer,
  supplierMandate,
  supplierPrivateKey,
} from "./demo_shared.js";

const ctx = createServerContext();

function configureSupplier(): void {
  const supplierKey = supplierPrivateKey();
  const buyerKey = buyerPrivateKey();
  ctx.SERVER_DID = SUPPLIER_DID;
  ctx.configureResponder({
    agent_info: supplierAgentInfo(),
    mandate: supplierMandate(),
    deal_types: ["saas_renewal"],
    max_rounds_by_deal_type: { saas_renewal: 4 },
    private_key: supplierKey,
  });
  ctx.registerDidDocument(BUYER_DID, didDocument(BUYER_DID, BUYER_KEY_ID, buyerKey));
  ctx.registerDidDocument(SUPPLIER_DID, didDocument(SUPPLIER_DID, SUPPLIER_KEY_ID, supplierKey));
}

configureSupplier();

ctx.app.get("/demo/health", async (_request, reply) => {
  return reply
    .header("content-type", "application/json")
    .send(JSON.stringify({ status: "ok", role: "supplier", did: SUPPLIER_DID }));
});

ctx.app.post("/demo/counteroffer", async (request, reply) => {
  let body: Dict;
  try {
    const raw = request.body;
    body = JSON.parse(Buffer.isBuffer(raw) ? raw.toString("utf-8") : String(raw)) as Dict;
  } catch {
    return reply.code(400).send(
      JSON.stringify({ detail: "session_id, in_reply_to, and terms are required" }),
    );
  }
  const sessionId = body.session_id as string | undefined;
  const inReplyTo = body.in_reply_to as string | undefined;
  const terms = body.terms;
  if (!sessionId || !inReplyTo || terms === null || typeof terms !== "object") {
    return reply.code(400).send(
      JSON.stringify({ detail: "session_id, in_reply_to, and terms are required" }),
    );
  }

  const session = ctx.manager.getSession(sessionId);
  if (session === null) {
    return reply
      .code(404)
      .send(JSON.stringify({ detail: `Unknown session_id ${JSON.stringify(sessionId)}` }));
  }

  const message = supplierCounteroffer(session, terms as Dict, inReplyTo);
  const supplierKey = supplierPrivateKey();
  const http = authedFetch(
    freshJwtFactory(SUPPLIER_DID, SUPPLIER_DID, supplierKey, SUPPLIER_KEY_ID),
  );
  const response = await http(`${SUPPLIER_URL}/sessions/${sessionId}/messages`, {
    method: "POST",
    body: JSON.stringify(message),
    headers: {
      "Content-Type": "application/a2cn+json",
      "Idempotency-Key": message.message_id as string,
    },
  });
  const responseText = await response.text();
  if (response.status >= 400) {
    return reply.code(response.status).send(JSON.stringify({ detail: responseText }));
  }
  return reply.send(JSON.stringify({ message, state: JSON.parse(responseText) }));
});

ctx.app.get("/demo/record/:session_id", async (request, reply) => {
  const { session_id: sessionId } = request.params as { session_id: string };
  const session = ctx.manager.getSession(sessionId);
  if (session === null) {
    return reply
      .code(404)
      .send(JSON.stringify({ detail: `Unknown session_id ${JSON.stringify(sessionId)}` }));
  }
  return reply.send(JSON.stringify(generateTransactionRecord(session)));
});

const portArgIndex = process.argv.indexOf("--port");
const port =
  portArgIndex >= 0 && portArgIndex + 1 < process.argv.length
    ? parseInt(process.argv[portArgIndex + 1], 10)
    : SUPPLIER_PORT;

ctx.app.listen({ host: "127.0.0.1", port }).catch((exc) => {
  console.error(exc);
  process.exit(1);
});
