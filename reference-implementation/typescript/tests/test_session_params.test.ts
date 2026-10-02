/** Tests for impasse_threshold propagation in session_params_accepted (Fix 5). */

import { expect, test } from "vitest";

import type { Dict } from "../src/a2cn/messages.js";
import { freshServer, makeSessionInit } from "./conftest.js";

test("impasse threshold propagated to session ack", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  (body.session_params as Dict).impasse_threshold = 5;
  const r = await client.post("/sessions", {
    json: body,
    headers: {
      "Content-Type": "application/a2cn+json",
      "Idempotency-Key": body.message_id as string,
    },
  });
  expect(r.statusCode).toBe(201);
  const ack = r.json();
  expect((ack.session_params_accepted as Dict).impasse_threshold).toBe(5);
});

test("impasse threshold absent when not in session params", async () => {
  const { client } = freshServer();
  const body = makeSessionInit();
  delete (body.session_params as Dict).impasse_threshold;
  const r = await client.post("/sessions", {
    json: body,
    headers: {
      "Content-Type": "application/a2cn+json",
      "Idempotency-Key": body.message_id as string,
    },
  });
  expect(r.statusCode).toBe(201);
  const ack = r.json();
  expect("impasse_threshold" in (ack.session_params_accepted as Dict)).toBe(false);
});
