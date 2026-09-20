/**
 * The pinned line-item money keys (Section 7.2 and spec/schemas/offer.schema.json).
 *
 * A line item states its money as integer minor units, under `unit_price_minor`
 * and `total_minor`. The bare names `unit_price` and `total` are refused
 * outright: the two conventions differ by a factor of one hundred, and a
 * receiver that read a bare name as minor units — or as major units — would
 * agree with the sender about the number and disagree about the amount,
 * silently.
 *
 * spec/test-vectors/offer-line-item-keys.json is the shared contract. No JSON
 * Schema validator is a dependency here, so this reads the schema directly and
 * holds this implementation's own checker to every case in the file; the Python
 * suite runs a full Draft 2020-12 validation over the same cases. Both suites
 * also hash the same offer, so the canonical bytes cannot drift either.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { hashObject } from "../src/a2cn/crypto.js";
import {
  MAX_SAFE_MINOR,
  REJECTED_MONEY_KEYS,
  SUPPORTED_SESSION_CURRENCIES,
  TOTAL_MINOR,
  UNIT_PRICE_MINOR,
  lineItemKeyViolations,
  requireMinor,
  toMinorUnits,
} from "../src/a2cn/line_items.js";
import { A2CNError, checkOfferMoneyParams } from "../src/a2cn/session.js";
import type { Dict } from "../src/a2cn/messages.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function readJson(...parts: string[]): Dict {
  return JSON.parse(readFileSync(join(REPO_ROOT, ...parts), "utf-8")) as Dict;
}

const SCHEMA = readJson("spec", "schemas", "offer.schema.json");
const VECTOR = readJson("spec", "test-vectors", "offer-line-item-keys.json");
const OFFER = VECTOR.offer as Dict;
const SESSION_PARAMS: Dict = { currency: "USD" };

interface LineItemCase {
  name: string;
  reason?: string;
  line_item: unknown;
}

interface ConversionCase {
  name: string;
  value: unknown;
  minor: number;
}

interface RejectedCase {
  name: string;
  value: unknown;
}

const VALID = VECTOR.valid_line_items as unknown as LineItemCase[];
const INVALID = VECTOR.invalid_line_items as unknown as LineItemCase[];
const CONVERSIONS = VECTOR.minor_unit_conversions as unknown as ConversionCase[];
const REJECTED_AMOUNTS = VECTOR.rejected_vendor_amounts as unknown as RejectedCase[];

/** The error a call threw, so a test can read its code rather than only its class. */
function thrownFrom(run: () => unknown): unknown {
  try {
    run();
  } catch (err) {
    return err;
  }
  return undefined;
}

function termsWithLineItems(items: unknown): Dict {
  const terms = structuredClone(OFFER.terms as Dict);
  terms.line_items = items;
  return terms;
}

// ---------------------------------------------------------------------------
// The published schema
// ---------------------------------------------------------------------------

describe("the published offer schema", () => {
  test("is published at the wire version", () => {
    // An offer is a wire message, so its schema's $id carries the wire version.
    expect(SCHEMA.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(SCHEMA.$id).toBe("https://a2cn.dev/schemas/offer/0.2");
  });

  test("requires both pinned keys on a line item and refuses neither bare name by accident", () => {
    const terms = (SCHEMA.properties as Dict).terms as Dict;
    const lineItem = ((terms.properties as Dict).line_items as Dict).items as Dict;

    expect([...(lineItem.required as string[])].sort()).toEqual(
      [UNIT_PRICE_MINOR, TOTAL_MINOR].sort(),
    );
    expect((lineItem.properties as Dict)[UNIT_PRICE_MINOR]).toMatchObject({ type: "integer" });
    expect((lineItem.properties as Dict)[TOTAL_MINOR]).toMatchObject({ type: "integer" });
    // The bare names are refused by name, not merely left undeclared.
    const refused = ((lineItem.propertyNames as Dict).not as Dict).enum as string[];
    expect([...refused].sort()).toEqual([...REJECTED_MONEY_KEYS].sort());
  });

  test("leaves terms and the message open for extensions", () => {
    // Only the two bare money names are pinned shut; deal types still extend.
    expect(SCHEMA.additionalProperties).not.toBe(false);
    const terms = (SCHEMA.properties as Dict).terms as Dict;
    expect(terms.additionalProperties).not.toBe(false);
    const lineItem = ((terms.properties as Dict).line_items as Dict).items as Dict;
    expect(lineItem.additionalProperties).not.toBe(false);
  });
});

test("the vector offer hashes to the same canonical bytes in both languages", () => {
  expect(hashObject(OFFER)).toBe(VECTOR.offer_canonical_hash);
});

// ---------------------------------------------------------------------------
// This implementation's own checker, held to the same cases
// ---------------------------------------------------------------------------

test.each(VALID.map((c) => [c.name, c] as const))(
  "the checker admits a valid line item: %s",
  (_name, testCase) => {
    expect(lineItemKeyViolations(testCase.line_item)).toEqual([]);
  },
);

test.each(INVALID.map((c) => [c.name, c] as const))(
  "the checker refuses an invalid line item: %s",
  (_name, testCase) => {
    expect(lineItemKeyViolations(testCase.line_item), testCase.reason).not.toEqual([]);
  },
);

// ---------------------------------------------------------------------------
// The offer path: a bare-name line item never reaches the state machine
// ---------------------------------------------------------------------------

describe("an offer carrying line items", () => {
  test("is refused when a line item uses a bare name", () => {
    const terms = termsWithLineItems([{ quantity: 50, unit_price: 360, total: 18000 }]);

    let thrown: unknown;
    try {
      checkOfferMoneyParams(SESSION_PARAMS, terms);
    } catch (err) {
      thrown = err;
    }

    expect(thrown).toBeInstanceOf(A2CNError);
    expect((thrown as A2CNError).code).toBe("INVALID_LINE_ITEM");
    expect((thrown as A2CNError).message).toContain("unit_price");
  });

  test("passes when its line items carry the pinned keys", () => {
    expect(() =>
      checkOfferMoneyParams(SESSION_PARAMS, structuredClone(OFFER.terms as Dict)),
    ).not.toThrow();
  });

  test("passes when it carries no line_items at all, which stays optional", () => {
    const terms = structuredClone(OFFER.terms as Dict);
    delete terms.line_items;

    expect(() => checkOfferMoneyParams(SESSION_PARAMS, terms)).not.toThrow();
  });

  test("passes when line_items is empty", () => {
    expect(() => checkOfferMoneyParams(SESSION_PARAMS, termsWithLineItems([]))).not.toThrow();
  });

  test("is refused when line_items is not an array", () => {
    const terms = termsWithLineItems({ "0": { unit_price_minor: 1, total_minor: 1 } });

    let thrown: unknown;
    try {
      checkOfferMoneyParams(SESSION_PARAMS, terms);
    } catch (err) {
      thrown = err;
    }

    expect((thrown as A2CNError).code).toBe("INVALID_LINE_ITEM");
  });

  test("names the line it refused", () => {
    // Two good lines and one bad one: the message points at the third.
    const terms = structuredClone(OFFER.terms as Dict);
    terms.line_items = [
      ...(terms.line_items as Dict[]),
      { quantity: 1, unit_price: 1, total: 1 },
    ];

    let thrown: unknown;
    try {
      checkOfferMoneyParams(SESSION_PARAMS, terms);
    } catch (err) {
      thrown = err;
    }

    expect((thrown as A2CNError).message).toContain("line_items[2]");
  });

  test("still reports a changed currency before a bad line item", () => {
    // Section 7.2's order: the session parameters are settled first.
    const terms = termsWithLineItems([{ quantity: 1, unit_price: 1, total: 1 }]);
    terms.currency = "EUR";

    let thrown: unknown;
    try {
      checkOfferMoneyParams(SESSION_PARAMS, terms);
    } catch (err) {
      thrown = err;
    }

    expect((thrown as A2CNError).code).toBe("SESSION_PARAM_CHANGED");
  });
});

// ---------------------------------------------------------------------------
// An amount is an integer VALUE, not a particular JSON spelling (Section 7.2)
// ---------------------------------------------------------------------------

test("the bound is the safe-integer range the vector records", () => {
  expect(MAX_SAFE_MINOR).toBe(VECTOR.max_safe_minor);
  expect(MAX_SAFE_MINOR).toBe(Number.MAX_SAFE_INTEGER);
});

test.each([
  [36000, 36000],
  [36000.0, 36000],
  [3.6e4, 36000],
  [-0.0, 0],
  [-36000.0, -36000],
])("requireMinor reads any integral spelling as the same amount: %s", (spelling, expected) => {
  // RFC 8785 makes 36000 and 36000.0 one number, and JavaScript cannot tell them apart.
  expect(requireMinor({ [UNIT_PRICE_MINOR]: spelling }, UNIT_PRICE_MINOR)).toBe(expected);
});

test("requireMinor normalises negative zero to a plain zero", () => {
  // A signed zero would leave the two languages disagreeing about the sign of nothing.
  const amount = requireMinor({ [UNIT_PRICE_MINOR]: -0.0 }, UNIT_PRICE_MINOR);

  expect(Object.is(amount, -0)).toBe(false);
  expect(amount).toBe(0);
});

test.each([360.5, 36000.0001, -0.5])("requireMinor refuses a fractional amount: %s", (value) => {
  const thrown = thrownFrom(() => requireMinor({ [UNIT_PRICE_MINOR]: value }, UNIT_PRICE_MINOR));

  expect(thrown).toBeInstanceOf(A2CNError);
  expect((thrown as A2CNError).code).toBe("INVALID_LINE_ITEM");
});

test.each([2 ** 53, -(2 ** 53), 1e21])(
  "requireMinor refuses an amount past the safe-integer range: %s",
  (value) => {
    // Past it a double cannot separate adjacent integers, so the languages could differ.
    expect(
      thrownFrom(() => requireMinor({ [UNIT_PRICE_MINOR]: value }, UNIT_PRICE_MINOR)),
    ).toBeInstanceOf(A2CNError);
  },
);

test("the checker refuses a negative quantity", () => {
  // A refund is a negative price, not a negative count (Section 7.2).
  const violations = lineItemKeyViolations({
    quantity: -5,
    [UNIT_PRICE_MINOR]: 36000,
    [TOTAL_MINOR]: 1800000,
  });

  expect(violations).not.toEqual([]);
  expect(violations.some((phrase) => phrase.includes("quantity"))).toBe(true);
});

// ---------------------------------------------------------------------------
// Reading a line item's money back out
// ---------------------------------------------------------------------------

describe("requireMinor", () => {
  test("returns the pinned amount", () => {
    const lineItem = ((OFFER.terms as Dict).line_items as Dict[])[0];

    expect(requireMinor(lineItem, UNIT_PRICE_MINOR)).toBe(36000);
    expect(requireMinor(lineItem, TOTAL_MINOR)).toBe(1800000);
  });

  test.each([...REJECTED_MONEY_KEYS])(
    "refuses a line item that states only the bare name: %s",
    (bare) => {
      // A bare name is not silently read as the pinned one, at any scale.
      expect(() => requireMinor({ quantity: 1, [bare]: 360 }, `${bare}_minor`)).toThrow(
        new RegExp(`${bare}_minor`),
      );
    },
  );

  test.each([null, "36000", 360.5, true])(
    "refuses an amount that is not an integral number: %s",
    (value) => {
      expect(() => requireMinor({ [UNIT_PRICE_MINOR]: value }, UNIT_PRICE_MINOR)).toThrow(
        new RegExp(UNIT_PRICE_MINOR),
      );
    },
  );
});

test("the rejected names are the two bare spellings", () => {
  expect([...REJECTED_MONEY_KEYS].sort()).toEqual(["total", "unit_price"]);
  expect([UNIT_PRICE_MINOR, TOTAL_MINOR]).toEqual(["unit_price_minor", "total_minor"]);
});

// ---------------------------------------------------------------------------
// Converting a vendor's decimal amount at the boundary
// ---------------------------------------------------------------------------

test.each(CONVERSIONS.map((c) => [c.name, c] as const))(
  "toMinorUnits converts exactly as the vector records: %s",
  (_name, testCase) => {
    expect(toMinorUnits(testCase.value)).toBe(testCase.minor);
  },
);

test.each([-0.001, "-0.004", -0.0049])(
  "toMinorUnits never returns negative zero for a small negative amount: %s",
  (value) => {
    // The vector rows above already catch this, because Vitest's `toBe` is
    // Object.is-based and Object.is(-0, 0) is false. Stated outright so that a
    // reader need not know that to see what those rows guard. The shape is
    // narrow: negative, so the sign branch is taken, yet small enough that the
    // scaled value is zero, so negating it yields -0. An amount that rounds
    // away (-0.005) never reaches it, and -0.0 never takes the branch at all.
    // Python's ints have no negative zero, so a -0 here is a parity defect.
    expect(Object.is(toMinorUnits(value), -0)).toBe(false);
    expect(toMinorUnits(value)).toBe(0);
  },
);

test.each(REJECTED_AMOUNTS.map((c) => [c.name, c] as const))(
  "toMinorUnits refuses a spelling the languages read differently: %s",
  (_name, testCase) => {
    // Each language's own parser takes several of these, and takes them differently.
    const thrown = thrownFrom(() => toMinorUnits(testCase.value));

    expect(thrown).toBeInstanceOf(A2CNError);
    expect((thrown as A2CNError).code).toBe("INVALID_LINE_ITEM");
  },
);

test.each([NaN, Infinity, -Infinity])(
  "toMinorUnits refuses a non-finite amount: %s",
  (value) => {
    // JSON cannot write these, so the shared vector cannot carry them; a caller can.
    expect(thrownFrom(() => toMinorUnits(value))).toBeInstanceOf(A2CNError);
  },
);

test.each([
  [2.675, -2.675],
  [1.15, -1.15],
  [0.005, -0.005],
  [99.995, -99.995],
  [1.005, -1.005],
])("a debit and the credit that offsets it cancel: %s", (debit, credit) => {
  // Rounding half up left a minor unit behind on every such pair; away from zero does not.
  expect(toMinorUnits(debit) + toMinorUnits(credit)).toBe(0);
});

test("toMinorUnits reads an amount inside a money object", () => {
  expect(toMinorUnits({ amount: 360.0, currency: "USD" })).toBe(36000);
  expect(toMinorUnits({ value: 85.25 })).toBe(8525);
});

test("a null amount member falls through to value", () => {
  // `.get("amount", default)` returned None for a present-but-null key; `??` did not.
  expect(toMinorUnits({ amount: null, value: 500 })).toBe(50000);
});

// ---------------------------------------------------------------------------
// The session currency this build is prepared to carry minor amounts in
// ---------------------------------------------------------------------------

interface CurrencyCase {
  name: string;
  currency: string;
  supported: boolean;
}

const CURRENCY_CASES = VECTOR.session_currency_cases as unknown as CurrencyCase[];

function termsInCurrency(currency: string): Dict {
  const terms = structuredClone(OFFER.terms as Dict);
  terms.currency = currency;
  return terms;
}

test("the declared currencies are the ones the vector records", () => {
  expect([...SUPPORTED_SESSION_CURRENCIES].sort()).toEqual(VECTOR.supported_session_currencies);
});

test.each(CURRENCY_CASES.map((c) => [c.name, c] as const))(
  "an offer is refused unless this build carries its session currency: %s",
  (_name, testCase) => {
    // Fails closed: a currency whose exponent really is 2 is refused too, if undeclared.
    const terms = termsInCurrency(testCase.currency);
    const sessionParams: Dict = { currency: testCase.currency };

    if (testCase.supported) {
      expect(() => checkOfferMoneyParams(sessionParams, terms)).not.toThrow();
      return;
    }

    const thrown = thrownFrom(() => checkOfferMoneyParams(sessionParams, terms));

    expect(thrown).toBeInstanceOf(A2CNError);
    expect((thrown as A2CNError).code).toBe("INVALID_LINE_ITEM");
    expect((thrown as A2CNError).message).toContain(testCase.currency);
  },
);

test("the currency guard fires even when the offer carries no line items", () => {
  // Section 7.2's money encoding attaches to the offer, not to the presence of a line.
  const terms = termsInCurrency("JPY");
  delete terms.line_items;

  const thrown = thrownFrom(() => checkOfferMoneyParams({ currency: "JPY" }, terms));

  expect((thrown as A2CNError).code).toBe("INVALID_LINE_ITEM");
});

test("a changed currency is reported before this build's own limit", () => {
  // The counterparty's own mistake outranks a limitation of ours.
  const thrown = thrownFrom(() =>
    checkOfferMoneyParams({ currency: "USD" }, termsInCurrency("JPY")),
  );

  expect((thrown as A2CNError).code).toBe("SESSION_PARAM_CHANGED");
});

test("an added basis is reported before this build's own limit", () => {
  // Same precedence: a session-parameter violation comes before the capability guard.
  const terms = termsInCurrency("JPY");
  terms.basis = "net";

  const thrown = thrownFrom(() => checkOfferMoneyParams({ currency: "JPY" }, terms));

  expect((thrown as A2CNError).code).toBe("SESSION_PARAM_CHANGED");
});
