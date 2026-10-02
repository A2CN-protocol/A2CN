/**
 * One uniform signed-act envelope across all five act types (Section 7.3.1).
 *
 * Today only two act types can be signed: offer/counteroffer carry
 * protocol_act_signature over the nine-field protocol act object, and an
 * acceptance carries acceptance_signature over a different five-field payload.
 * Rejection and withdrawal have no in-band signature slot at all, so a party
 * that signs its own withdrawal has nowhere conformant to put the signature.
 *
 * The envelope is one flat object for every act type: a common seven-field
 * header plus a type-specific payload, all at the top level. Flat, because a
 * nested payload adds a level and bytes and could never reproduce the offer's
 * signed bytes. expires_at is a payload field of offer and counteroffer rather
 * than a header field, so the terminal acts never sign an empty-string filler,
 * and the offer's nine flat keys stay exactly what they are today.
 *
 * The offer's signed bytes MUST NOT move: every stored TransactionRecord is
 * rebound against final_offer.protocol_act_hash, so a change there invalidates
 * records rather than messages. The acceptance's signed scope does change — it
 * gains the four header fields it never covered.
 *
 * Verification is by rebuild: reconstruct the signed object from the act's own
 * fields and hash it. The rebuild is mandatory and gated on nothing — no
 * record_version, no schema version, no field presence decides whether it runs.
 *
 * The Python suite runs the same cases.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

import { canonicalize, hashObject } from "../src/a2cn/crypto.js";
import {
  SIGNED_ACT_HEADER_FIELDS,
  SIGNED_ACT_PAYLOAD_FIELDS,
  SIGNED_ACT_SIGNATURE_FIELDS,
  protocolActObject,
  rebuildSignedAct,
  signedActHash,
  signedActObject,
  type Dict,
} from "../src/a2cn/messages.js";
import { REPO_ROOT } from "./support/paths.js";

const VECTOR = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "transaction-record-basis.json"), "utf-8"),
) as Dict;
const RECORD = ((VECTOR.expected as Dict).record_version_0_3 as Dict).full_record as Dict;
const FINAL_OFFER = RECORD.final_offer as Dict;
const MESSAGES = VECTOR.messages as Dict[];
const OFFER_MESSAGE = MESSAGES.find((m) => m.message_id === FINAL_OFFER.message_id) as Dict;
const ACCEPTANCE_MESSAGE = MESSAGES.find((m) => m.message_type === "acceptance") as Dict;

// Measured against this vector's real signed messages, not hand-built fixtures.
// The offer's numbers are what the stored record already carries, which is the
// point: they must not move.
const OFFER_CANONICAL_BYTES = 336;
const OFFER_ACT_HASH = "UYhzGu9xBpCI4_bXxw_LD4erapnyXFBGi8LDbqiLXKk";
// The acceptance's numbers are new, because its signed scope is what changes.
const ACCEPTANCE_CANONICAL_BYTES = 331;
const ACCEPTANCE_ACT_HASH = "BK-M3Bvf4hSRp1NQVqpTSFluIxdBDukRP9kGOMR4tWE";

// What Section 7.4 signs today, before the envelope.
const ACCEPTANCE_FIELDS_TODAY = [
  "session_id",
  "round_number",
  "sequence_number",
  "accepted_offer_id",
  "accepted_protocol_act_hash",
];

const ACT_TYPES = ["offer", "counteroffer", "acceptance", "rejection", "withdrawal"];

const sorted = (values: Iterable<string>): string[] => [...values].sort();

function offerEnvelope(): Dict {
  return signedActObject({
    protocol_version: FINAL_OFFER.protocol_version as string,
    session_id: RECORD.session_id,
    round_number: FINAL_OFFER.round_number,
    sequence_number: FINAL_OFFER.sequence_number,
    message_type: FINAL_OFFER.message_type,
    sender_did: FINAL_OFFER.sender_did,
    timestamp: FINAL_OFFER.timestamp,
    payload: {
      expires_at: FINAL_OFFER.expires_at,
      terms: RECORD.agreed_terms,
    },
  });
}

function acceptanceEnvelope(): Dict {
  return signedActObject({
    // The version this vector's acts were signed under, as its record states.
    protocol_version: FINAL_OFFER.protocol_version as string,
    session_id: ACCEPTANCE_MESSAGE.session_id,
    round_number: ACCEPTANCE_MESSAGE.round_number,
    sequence_number: ACCEPTANCE_MESSAGE.sequence_number,
    message_type: "acceptance",
    sender_did: ACCEPTANCE_MESSAGE.sender_did,
    timestamp: ACCEPTANCE_MESSAGE.timestamp,
    payload: {
      accepted_offer_id: ACCEPTANCE_MESSAGE.accepted_offer_id,
      accepted_protocol_act_hash: ACCEPTANCE_MESSAGE.accepted_protocol_act_hash,
    },
  });
}

// ---------------------------------------------------------------------------
// The envelope's shape
// ---------------------------------------------------------------------------

test("the common header is seven fields", () => {
  expect([...SIGNED_ACT_HEADER_FIELDS]).toEqual([
    "protocol_version",
    "session_id",
    "round_number",
    "sequence_number",
    "message_type",
    "sender_did",
    "timestamp",
  ]);
});

test("expires_at is an offer payload field, not a header field", () => {
  // A terminal act must never sign an empty-string expires_at. Putting it in
  // the header would make acceptance, rejection and withdrawal each cover a
  // field they have no value for, and the only value available is "" — a filler
  // inside a signature.
  expect(SIGNED_ACT_HEADER_FIELDS).not.toContain("expires_at");
  expect(SIGNED_ACT_PAYLOAD_FIELDS.offer).toContain("expires_at");
  expect(SIGNED_ACT_PAYLOAD_FIELDS.counteroffer).toContain("expires_at");
  for (const messageType of ["acceptance", "rejection", "withdrawal"]) {
    expect(SIGNED_ACT_PAYLOAD_FIELDS[messageType]).not.toContain("expires_at");
  }
});

test("every act type has a payload and a signature slot", () => {
  // Rejection and withdrawal gain a slot for the first time.
  expect(sorted(Object.keys(SIGNED_ACT_PAYLOAD_FIELDS))).toEqual(sorted(ACT_TYPES));
  expect(sorted(Object.keys(SIGNED_ACT_SIGNATURE_FIELDS))).toEqual(sorted(ACT_TYPES));
  expect(SIGNED_ACT_SIGNATURE_FIELDS.offer).toBe("protocol_act_signature");
  expect(SIGNED_ACT_SIGNATURE_FIELDS.counteroffer).toBe("protocol_act_signature");
  expect(SIGNED_ACT_SIGNATURE_FIELDS.acceptance).toBe("acceptance_signature");
  expect(SIGNED_ACT_SIGNATURE_FIELDS.rejection).toBe("rejection_signature");
  expect(SIGNED_ACT_SIGNATURE_FIELDS.withdrawal).toBe("withdrawal_signature");
});

test("each act type's signature slot is its own", () => {
  // One signature field per act type, so a relabel cannot carry a signature.
  // Reusing one slot name across every type would let an act keep its signature
  // while its message_type changed; distinct names make the rebuild demand the
  // type the signature was made under.
  expect(new Set(Object.values(SIGNED_ACT_SIGNATURE_FIELDS)).size).toBe(4);
});

// ---------------------------------------------------------------------------
// The offer's signed bytes do not move
// ---------------------------------------------------------------------------

test("offer envelope is today's nine fields, byte for byte", () => {
  const envelope = offerEnvelope();

  expect(sorted(Object.keys(envelope))).toEqual(
    sorted([
      "protocol_version",
      "session_id",
      "round_number",
      "sequence_number",
      "message_type",
      "sender_did",
      "timestamp",
      "expires_at",
      "terms",
    ]),
  );
  expect(canonicalize(envelope).length).toBe(OFFER_CANONICAL_BYTES);
  expect(hashObject(envelope)).toBe(OFFER_ACT_HASH);
  // The hash the stored record is already rebound against.
  expect(hashObject(envelope)).toBe(FINAL_OFFER.protocol_act_hash);
});

test("protocolActObject is the envelope and not a second path", () => {
  // One recipe, not a legacy branch beside it. protocolActObject is what every
  // existing call site builds; if it did not come out of the envelope,
  // preserving the offer's bytes would mean keeping a special case, which is
  // the cruft this change exists to remove.
  expect(offerEnvelope()).toEqual(
    protocolActObject({
      protocol_version: FINAL_OFFER.protocol_version as string,
      session_id: RECORD.session_id,
      round_number: FINAL_OFFER.round_number,
      sequence_number: FINAL_OFFER.sequence_number,
      message_type: FINAL_OFFER.message_type,
      sender_did: FINAL_OFFER.sender_did,
      timestamp: FINAL_OFFER.timestamp,
      expires_at: FINAL_OFFER.expires_at,
      terms: RECORD.agreed_terms,
    }),
  );
});

test("offer act rebuilds from its own wire fields", () => {
  expect(signedActHash(OFFER_MESSAGE)).toBe(OFFER_ACT_HASH);
  expect(signedActHash(OFFER_MESSAGE)).toBe(OFFER_MESSAGE.protocol_act_hash);
});

// ---------------------------------------------------------------------------
// The acceptance's signed scope changes, by exactly four fields
// ---------------------------------------------------------------------------

test("acceptance gains exactly four fields and drops none", () => {
  const covered = new Set(Object.keys(acceptanceEnvelope()));

  const gained = sorted([...covered].filter((name) => !ACCEPTANCE_FIELDS_TODAY.includes(name)));
  const lost = sorted(ACCEPTANCE_FIELDS_TODAY.filter((name) => !covered.has(name)));

  expect(gained).toEqual(sorted(["protocol_version", "message_type", "sender_did", "timestamp"]));
  expect(lost).toEqual([]);
});

test("acceptance envelope bytes and hash", () => {
  const envelope = acceptanceEnvelope();

  expect(canonicalize(envelope).length).toBe(ACCEPTANCE_CANONICAL_BYTES);
  expect(hashObject(envelope)).toBe(ACCEPTANCE_ACT_HASH);
});

test("acceptance signs who accepted", () => {
  // Bringing sender_did into scope self-attests the accepting party. The offer
  // has always signed sender_did; the acceptance did not, so an acceptance's
  // claimed sender was covered by no signature of its own.
  expect(acceptanceEnvelope().sender_did).toBe(ACCEPTANCE_MESSAGE.sender_did);
});

test("acceptance act rebuilds from its own wire fields", () => {
  expect(signedActHash(ACCEPTANCE_MESSAGE)).toBe(ACCEPTANCE_ACT_HASH);
});

// ---------------------------------------------------------------------------
// The declines, which could not be signed at all before
// ---------------------------------------------------------------------------

function rejection(): Dict {
  return {
    message_type: "rejection",
    message_id: "rej-1",
    session_id: RECORD.session_id,
    in_reply_to: FINAL_OFFER.message_id,
    round_number: 2,
    sequence_number: 4,
    rejected_offer_id: FINAL_OFFER.message_id,
    sender_did: ACCEPTANCE_MESSAGE.sender_did,
    sender_agent_id: "basis-agent",
    timestamp: "2026-03-24T10:04:00Z",
    reason_code: "PRICE_TOO_HIGH",
    reason_description: "free text, and untrusted input",
  };
}

function withdrawal(): Dict {
  return {
    message_type: "withdrawal",
    message_id: "wd-1",
    session_id: RECORD.session_id,
    in_reply_to: FINAL_OFFER.message_id,
    round_number: 2,
    sequence_number: 4,
    sender_did: ACCEPTANCE_MESSAGE.sender_did,
    sender_agent_id: "basis-agent",
    timestamp: "2026-03-24T10:04:00Z",
    reason_code: "STRATEGY_DECISION",
    reason_description: "free text, and untrusted input",
  };
}

test("rejection signs the offer it rejects, and why", () => {
  expect([...SIGNED_ACT_PAYLOAD_FIELDS.rejection]).toEqual(["rejected_offer_id", "reason_code"]);

  const envelope = rebuildSignedAct(rejection()) as Dict;

  expect(sorted(Object.keys(envelope))).toEqual(
    sorted([...SIGNED_ACT_HEADER_FIELDS, "rejected_offer_id", "reason_code"]),
  );
  expect(envelope.rejected_offer_id).toBe(FINAL_OFFER.message_id);
  expect(envelope.reason_code).toBe("PRICE_TOO_HIGH");
});

test("withdrawal signs why", () => {
  expect([...SIGNED_ACT_PAYLOAD_FIELDS.withdrawal]).toEqual(["reason_code"]);

  const envelope = rebuildSignedAct(withdrawal()) as Dict;

  expect(sorted(Object.keys(envelope))).toEqual(sorted([...SIGNED_ACT_HEADER_FIELDS, "reason_code"]));
  expect(envelope.reason_code).toBe("STRATEGY_DECISION");
});

test("reason_description is never inside the signed scope", () => {
  // It is OPTIONAL and it is untrusted free text (Section 13.6). Signing it
  // would make the signed key set depend on whether the sender happened to fill
  // it in, which is the field-presence gating a signed act must never have.
  // reason_code carries the meaning and is a required closed enum.
  for (const act of [rejection(), withdrawal()]) {
    expect(rebuildSignedAct(act) as Dict).not.toHaveProperty("reason_description");
  }

  const withoutDescription = rejection();
  delete withoutDescription.reason_description;

  expect(signedActHash(withoutDescription)).toBe(signedActHash(rejection()));
});

// ---------------------------------------------------------------------------
// The rebuild is mandatory, and it refuses what it cannot rebind
// ---------------------------------------------------------------------------

test("relabelling an act changes what it must rebuild to", () => {
  // message_type is inside the header, so a relabel moves the hash.
  const relabelled = structuredClone(OFFER_MESSAGE);
  relabelled.message_type = OFFER_MESSAGE.message_type === "counteroffer" ? "offer" : "counteroffer";

  expect(signedActHash(relabelled)).not.toBe(OFFER_ACT_HASH);
});

test("a tampered payload does not rebuild to the signed hash", () => {
  const tampered = structuredClone(OFFER_MESSAGE);
  (tampered.terms as Dict).total_value = 1;

  expect(signedActHash(tampered)).not.toBe(OFFER_ACT_HASH);
});

test("a decline relabelled as the other decline does not rebuild", () => {
  const original = rejection();
  const relabelled = structuredClone(original);
  relabelled.message_type = "withdrawal";

  expect(signedActHash(relabelled)).not.toBe(signedActHash(original));
});

test("an act of no known type cannot be rebuilt", () => {
  const unknown = structuredClone(OFFER_MESSAGE);
  unknown.message_type = "not_an_act";

  expect(rebuildSignedAct(unknown)).toBeNull();
  expect(signedActHash(unknown)).toBeNull();
});

test("an act missing a covered field cannot be rebuilt", () => {
  // A missing covered field leaves the act unrebindable, so it is refused
  // rather than hashed best-effort over a filled-in blank. The one exception is
  // the offer path's timestamp and expires_at, which have always rebuilt as ""
  // and are covered by their own tests below.
  for (const fieldName of ["session_id", "sender_did", "reason_code"]) {
    const incomplete = rejection();
    delete incomplete[fieldName];
    expect(rebuildSignedAct(incomplete)).toBeNull();
  }
});

test("an offer defaults a missing timestamp or expires_at to empty", () => {
  // The offer path's own rule, and the reason it exists. Neither field is
  // validated on the wire, and both state machines have always rebuilt an
  // offer's act with "" in place of a missing one, so an offer that omits one
  // is signed over "" and recorded that way (Section 9.5). A primitive that
  // demanded them would refuse an act whose signature genuinely covers those
  // bytes.
  for (const fieldName of ["timestamp", "expires_at"]) {
    const offer = structuredClone(OFFER_MESSAGE);
    delete offer[fieldName];
    const rebuilt = rebuildSignedAct(offer);
    expect(rebuilt).not.toBeNull();
    expect((rebuilt as Dict)[fieldName]).toBe("");
  }
});

test("only the offer path defaults, and the acceptance never does", () => {
  // An acceptance MUST NOT be able to sign an empty timestamp. expires_at was
  // moved out of the common header precisely so terminal acts never sign an
  // empty-string filler; defaulting a missing timestamp for an acceptance would
  // put that filler straight back, by another door.
  const acceptance = structuredClone(ACCEPTANCE_MESSAGE);
  delete acceptance.timestamp;
  expect(rebuildSignedAct(acceptance)).toBeNull();

  for (const build of [rejection, withdrawal]) {
    const decline = build();
    delete decline.timestamp;
    expect(rebuildSignedAct(decline)).toBeNull();
  }
});

test("the rebuild is gated on no version and no extra fields", () => {
  // Nothing decides whether the binding check runs (Section 7.3.1.1). An act
  // carrying an unknown version label, or extra members, still rebuilds from
  // the fields the envelope names — a verifier must not read a label and skip
  // the check.
  const labelled = structuredClone(OFFER_MESSAGE);
  labelled.record_version = "0.1";
  labelled.some_vendor_extension = { ignored: true };

  expect(signedActHash(labelled)).toBe(OFFER_ACT_HASH);
});

// ---------------------------------------------------------------------------
// The shared decline vector, which both suites read
// ---------------------------------------------------------------------------
//
// The cases below are also expressible as local fixtures, and were. A local
// fixture cannot catch the two implementations disagreeing about them, which is
// the failure this whole envelope exists to prevent, so they live in one file
// both languages read instead.

const DECLINE_VECTOR = JSON.parse(
  readFileSync(join(REPO_ROOT, "spec", "test-vectors", "signed-decline-acts.json"), "utf-8"),
) as Dict;
const DECLINE_CASES = Object.fromEntries(
  (DECLINE_VECTOR.cases as Dict[]).map((c) => [c.name as string, c]),
);

test("the decline vector states the envelope this implementation builds", () => {
  // The vector and the code must not drift about the shape itself.
  expect(DECLINE_VECTOR.header_fields).toEqual([...SIGNED_ACT_HEADER_FIELDS]);
  for (const [messageType, payload] of Object.entries(
    DECLINE_VECTOR.payload_fields as Record<string, string[]>,
  )) {
    expect(payload).toEqual([...SIGNED_ACT_PAYLOAD_FIELDS[messageType]]);
  }
  expect(DECLINE_VECTOR.signature_fields).toEqual(SIGNED_ACT_SIGNATURE_FIELDS);
});

test.each((DECLINE_VECTOR.cases as Dict[]).map((c) => [c.name as string, c] as [string, Dict]))(
  "each decline case rebuilds as the vector says: %s",
  (_name, declineCase) => {
    const act = declineCase.act as Dict;
    const rebuilt = rebuildSignedAct(act);

    expect(rebuilt !== null).toBe(declineCase.rebuilds);
    if (!declineCase.rebuilds) {
      expect(signedActHash(act)).toBeNull();
      return;
    }
    // The vector states the signed object outright, so a scope change shows up
    // as a field diff rather than only as an opaque hash mismatch.
    expect(rebuilt).toEqual(declineCase.signed_object);
    expect(canonicalize(rebuilt as Dict).length).toBe(declineCase.canonical_bytes);
    expect(signedActHash(act)).toBe(declineCase.signed_act_hash);
  },
);

test.each(["rejection", "withdrawal"])(
  "the unsigned field leaves the signed act untouched: %s",
  (name) => {
    // reason_description is outside every signed scope, altered or absent.
    const unsigned = DECLINE_VECTOR.unsigned_field_is_not_covered as Dict;
    const act = DECLINE_CASES[name].act as Dict;
    const before = signedActHash(act);

    const altered = structuredClone(act);
    altered[unsigned.field as string] = unsigned.altered_value;
    const removed = structuredClone(act);
    delete removed[unsigned.field as string];

    expect(signedActHash(altered)).toBe(before);
    expect(signedActHash(removed)).toBe(before);
  },
);

test.each(
  (DECLINE_VECTOR.relabel_cases as Dict[]).map((c) => [c.name as string, c] as [string, Dict]),
)("a relabelled decline matches the vector: %s", (_name, relabelCase) => {
  const source = DECLINE_CASES[relabelCase.from as string].act as Dict;
  const relabelled = structuredClone(source);
  relabelled.message_type = relabelCase.to;
  const rebuiltHash = signedActHash(relabelled);

  expect(rebuiltHash !== null).toBe(relabelCase.rebuilds);
  if (relabelCase.rebuilds) {
    // It rebuilds, but to a different act: the hash moved, and the signature it
    // carries is still in the slot of the type it was made for.
    expect(rebuiltHash).toBe(relabelCase.signed_act_hash);
    expect(rebuiltHash).not.toBe(signedActHash(source));
  }
});

// ---------------------------------------------------------------------------
// The regeneration's invariant, as a test rather than an inspection
// ---------------------------------------------------------------------------

const OFFER_CHAIN_HASH = "VHYNTEApaLwB0_fxOv6h89u9FSLe8ZKYBDeGRG2dK5c";

test("no hashed artifact moved when the vector was re-keyed", () => {
  // A private key for the initiator was never stored, so re-signing its acts
  // under the changed acceptance scope required minting one. That changes
  // signature values. It must not change a single hash, because an act's hash
  // is computed over the act and never over the key — and the record path
  // rebinds every stored record against the offer's hash, so a move here is a
  // defect signal rather than an output.
  //
  // Pinned as literals AND re-derived. The re-derivation is the stronger half:
  // it would catch a stored hash edited to match a drifted act, which a literal
  // on its own would not.
  expect(FINAL_OFFER.protocol_act_hash).toBe(OFFER_ACT_HASH);
  expect((VECTOR.expected as Dict).offer_chain_hash).toBe(OFFER_CHAIN_HASH);

  for (const name of ["with_basis", "without_basis", "empty_expires_at"]) {
    const node = (name === "with_basis" ? VECTOR : (VECTOR[name] as Dict)) as Dict;
    for (const message of node.messages as Dict[]) {
      if (message.message_type !== "offer" && message.message_type !== "counteroffer") {
        continue;
      }
      expect(signedActHash(message), `${name}: ${message.message_id as string}`).toBe(
        message.protocol_act_hash,
      );
    }
  }
});
