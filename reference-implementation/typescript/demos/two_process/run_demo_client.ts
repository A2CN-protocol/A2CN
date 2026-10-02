/** Drives the two-process demo: POST /demo/run on the buyer, print the transcript. */

import type { Dict } from "../../src/a2cn/messages.js";

const buyerUrl = process.argv[2] ?? "http://127.0.0.1:8001";

const response = await fetch(`${buyerUrl}/demo/run`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: "{}",
});
if (response.status >= 400) {
  console.error(`demo run failed: HTTP ${response.status}: ${await response.text()}`);
  process.exit(1);
}
const result = (await response.json()) as Dict;

console.log("A2CN two-process HTTP demo");
console.log("==========================");
console.log(`session_id: ${result.session_id}`);
console.log();
for (const item of result.transcript as Dict[]) {
  const step = item.step as string;
  if ("amount" in item) {
    console.log(`- ${step}: ${item.amount} (${item.message_id})`);
  } else if (step === "buyer_acceptance") {
    console.log(`- ${step}: accepted ${item.accepted_offer_id}`);
  } else if (step === "session_ack") {
    console.log(`- ${step}: ${item.session_id}`);
  } else {
    console.log(`- ${step}`);
  }
}

const buyerHash = (result.buyer_record as Dict).record_hash;
const supplierHash = (result.supplier_record as Dict).record_hash;
console.log();
console.log("Transaction records");
console.log("-------------------");
console.log(`buyer_record.record_hash:    ${buyerHash}`);
console.log(`supplier_record.record_hash: ${supplierHash}`);
console.log(`hashes_match: ${result.record_hashes_match ? "True" : "False"}`);

if (!result.record_hashes_match) {
  process.exit(1);
}
