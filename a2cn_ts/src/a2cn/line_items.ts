/**
 * The pinned line-item money keys (Section 7.2).
 *
 * A line item states its money as integer minor units of the session currency,
 * under two key names and no others:
 *
 *     unit_price_minor    total_minor
 *
 * The bare names `unit_price` and `total` are refused. They are not coerced,
 * scaled, or read as major units. The reason is the size of the mistake: the
 * two conventions differ by a factor of one hundred, so a receiver that guessed
 * wrong would agree with the sender about the *number* and disagree about the
 * *amount*, and nothing in the message would say which of them was right. A
 * refusal is recoverable; a hundredfold silent misreading of a price is not.
 *
 * **An amount is an integer VALUE, not a JSON spelling.** RFC 8785 makes
 * `36000` and `36000.0` the same number, and JavaScript cannot tell them apart
 * once parsed, so judging by Python's `isinstance(v, int)` would have refused in
 * one language exactly what the other accepted — and `36000.0` is how a decimal
 * or money type serialises, so that is the common case, not an exotic one. Both
 * languages therefore accept any integral number and refuse anything with a
 * fractional part.
 *
 * The Python mirror is `reference-implementation/python/a2cn/line_items.py` and
 * the two are held to the same cases by
 * `spec/test-vectors/offer-line-item-keys.json`.
 */

import { A2CNError } from "./errors.js";

/** The pinned spellings. Both are REQUIRED on every line item. */
export const UNIT_PRICE_MINOR = "unit_price_minor";
export const TOTAL_MINOR = "total_minor";

/**
 * The bare spellings, refused by name. `spec/schemas/offer.schema.json` refuses
 * the same two through `propertyNames`, because the line item stays open for
 * deal-type extension fields and cannot simply be closed.
 */
export const REJECTED_MONEY_KEYS = ["unit_price", "total"] as const;

/**
 * Minor units per major unit. Every amount A2CN carries today is in a
 * two-decimal currency, and the adapters have always assumed cents; this names
 * that assumption rather than scattering `* 100` through eleven files. A
 * currency-aware exponent is a separate change (the zero-decimal currencies,
 * JPY and KRW among them, need one).
 */
export const MINOR_UNIT_EXPONENT = 2;

/**
 * The session currencies this build is prepared to carry line-item minor
 * amounts in. NAMES ONLY, deliberately: the moment this maps a currency to a
 * number other than 2 it has stopped being a capability list and become the
 * currency-exponent table, which is separate work.
 *
 * **A capability limit, not knowledge about the world.** A2CN maintains no
 * currency exponent registry (Section 9A.9), and these are emphatically not the
 * only currencies whose minor-unit exponent is 2 — they are the only ones this
 * build has grounds to assert it for. Measured from the corpus on 2026-09-20,
 * not recalled: across the spec, both implementations, every vector and every
 * adapter, the currency-keyed values are USD (446), EUR (39) and GBP (2), and
 * the only currencies ever fixed as a *session* currency are USD and EUR.
 *
 * **The list is short on purpose and will refuse legitimate two-decimal
 * currencies** — CAD among them, which our own Conga adapter can emit. That
 * refusal is the designed behaviour, not an oversight: it fails CLOSED, loudly
 * and recoverably, exactly as Section 7.2 already does for a bare key name. The
 * inverse shape — listing the currencies known *not* to be 2 and assuming 2 for
 * everything else — fails OPEN the moment it falls behind ISO 4217, turning a
 * neglected list into a silent hundredfold misread. Adding a currency here is
 * meant to be a deliberate act with a reason attached, never topping up a list
 * someone assumed was exhaustive.
 */
export const SUPPORTED_SESSION_CURRENCIES = ["EUR", "GBP", "USD"] as const;

/**
 * Whether this build can state a line item's money in `currency`.
 *
 * An exact match on the declared spelling, with no case folding: JavaScript and
 * Python do not upper-case every string identically, and a money guard that
 * differed between the two would be the very defect it exists to prevent. A
 * currency that is not a string is not one this build carries.
 */
export function sessionCurrencyIsSupported(currency: unknown): boolean {
  return (
    typeof currency === "string" &&
    (SUPPORTED_SESSION_CURRENCIES as readonly string[]).includes(currency)
  );
}

/**
 * The largest amount both languages hold exactly: JavaScript's safe-integer
 * range. Past it a double can no longer separate adjacent integers, so one JSON
 * document could be read as two different amounts — Python's
 * arbitrary-precision int would be "more right" and the two implementations
 * would disagree about money. Bounding makes them agree, and no real line states
 * ninety trillion currency units.
 */
export const MAX_SAFE_MINOR = Number.MAX_SAFE_INTEGER;

/**
 * A vendor amount as text: optional sign, ASCII digits, at most one point.
 * `[0-9]` and not `\d` deliberately — Python's `\d` matches Unicode digits
 * (Arabic-Indic among them) while JavaScript's does not, so `\d` would be the
 * divergence rather than the guard against it. No exponent, no underscore
 * separators, no hex/octal/binary: each language's own parser takes a different
 * subset of those, and a vendor amount is a decimal figure, not a numeric
 * literal.
 */
const DECIMAL_TEXT = /^[+-]?([0-9]+(\.[0-9]+)?|\.[0-9]+)$/;

/**
 * Stripped before matching. Spelled out rather than `trim()` because JavaScript
 * strips Unicode whitespace and Python's `strip()` strips a slightly different
 * set; these four are the ones both agree on.
 */
const STRIPPABLE = /^[ \t\n\r]+|[ \t\n\r]+$/g;

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalid(message: string): A2CNError {
  return new A2CNError("INVALID_LINE_ITEM", message, 400);
}

function show(value: unknown): string {
  // JSON.stringify turns NaN and Infinity into "null", which would hide the
  // very thing the message is about.
  return typeof value === "number" && !Number.isFinite(value)
    ? String(value)
    : JSON.stringify(value);
}

/**
 * `value` as an integer amount, or `null` when it is not one.
 *
 * Accepts any integral number however it was spelled, because that is the only
 * rule both languages can enforce (see the module docstring). Refuses a
 * fractional value, a non-finite one, a boolean, anything that is not a number
 * at all, and anything outside `MAX_SAFE_MINOR`. Normalises `-0` to a plain
 * `0`, so the two languages cannot end up disagreeing about the sign of
 * nothing.
 */
export function integralMinor(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    return null;
  }
  if (Math.abs(value) > MAX_SAFE_MINOR) {
    return null;
  }
  return value === 0 ? 0 : value;
}

/**
 * One vendor amount, in integer minor units, at the boundary.
 *
 * **Scaled, then rounded half away from zero, identically in both languages.**
 * `sign * Math.floor(Math.abs(v) * 100 + 0.5)` here and the same operations in
 * the same order in Python agree bit for bit; every case is measured in both and
 * pinned by `spec/test-vectors/offer-line-item-keys.json`.
 *
 * Away from zero rather than simply up, because a debit and the credit that
 * offsets it have to cancel. Under half-up, `2.675` and `-2.675` converted to
 * `268` and `-267`, leaving a minor unit behind on every offsetting pair — and
 * the vector blesses a negative line as exactly what a credit or rebate states,
 * so that was a defect, not a preference.
 *
 * **What is refused, and why here rather than in each language's parser.** A
 * vendor amount is a decimal figure. Hex, octal and binary literals, underscore
 * separators, exponent text, non-ASCII digits, `"NaN"` and `"Infinity"` are
 * refused, because Python and JavaScript each accept a different subset of those
 * and would convert the same payload to different money. A money object
 * contributes its `amount`, or its `value` when `amount` is absent **or null** —
 * a present-but-null member states no amount.
 *
 * Rounding to nearest does not make the conversion exact: exactness needs the
 * source as a decimal *string*, because once a float exists the decimal the
 * vendor wrote is already gone. That is a separate change from this one.
 *
 * Throws `A2CNError` with `INVALID_LINE_ITEM` rather than a bare `Error`: an
 * amount this cannot read is a refusal the protocol has a code for.
 */
export function toMinorUnits(value: unknown, exponent: number = MINOR_UNIT_EXPONENT): number {
  if (value === null || value === undefined) {
    return 0;
  }
  if (typeof value === "boolean") {
    throw invalid(`vendor amount ${show(value)} is a boolean, not a money figure`);
  }
  if (isObject(value)) {
    let amount = value.amount;
    if (amount === null || amount === undefined) {
      amount = value.value;
    }
    if (amount === null || amount === undefined) {
      return 0;
    }
    return toMinorUnits(amount, exponent);
  }

  let number: number;
  if (typeof value === "string") {
    const text = value.replace(STRIPPABLE, "");
    if (text === "") {
      return 0;
    }
    if (!DECIMAL_TEXT.test(text)) {
      throw invalid(
        `vendor amount ${show(value)} is not a decimal figure: an amount is an ` +
          "optional sign, digits, and at most one decimal point",
      );
    }
    number = Number(text);
  } else if (typeof value === "number") {
    number = value;
  } else {
    throw invalid(`vendor amount ${show(value)} is not a money figure`);
  }

  if (!Number.isFinite(number)) {
    throw invalid(`vendor amount ${show(value)} is not a finite number`);
  }
  const scaled = Math.floor(Math.abs(number) * 10 ** exponent + 0.5);
  const minor = number < 0 ? -scaled : scaled;
  if (Math.abs(minor) > MAX_SAFE_MINOR) {
    throw invalid(
      `vendor amount ${show(value)} is ${minor} minor units, beyond the ` +
        `±${MAX_SAFE_MINOR} both implementations represent exactly`,
    );
  }
  return minor === 0 ? 0 : minor;
}

/**
 * One pinned amount off an agreed line item, or a refusal naming the key.
 *
 * Callers used to reach for `item.unit_price ?? 0`, which turned a line item
 * that said nothing about money into one that said the price was zero. Every
 * read goes through here instead, so a missing or malformed amount stops the
 * write-back rather than sending a vendor a free order.
 */
export function requireMinor(lineItem: unknown, key: string): number {
  if (!isObject(lineItem)) {
    throw invalid(`line item is not an object, so it carries no ${JSON.stringify(key)}`);
  }
  if (!Object.prototype.hasOwnProperty.call(lineItem, key)) {
    const bare = key.replace(/_minor$/, "");
    const stated = Object.prototype.hasOwnProperty.call(lineItem, bare)
      ? `, though it carries the bare ${JSON.stringify(bare)}`
      : "";
    throw invalid(
      `line item omits ${JSON.stringify(key)}${stated}; A2CN line-item money is stated in ` +
        "integer minor units under the pinned key (Section 7.2)",
    );
  }
  const amount = integralMinor(lineItem[key]);
  if (amount === null) {
    throw invalid(
      `line item ${JSON.stringify(key)} is ${show(lineItem[key])}, which is not an integer ` +
        `number of minor units within ±${MAX_SAFE_MINOR}`,
    );
  }
  return amount;
}

/**
 * Why this line item is not a well-formed priced line, or an empty list.
 *
 * Each violation is a phrase that reads after `terms.line_items[n]`. The order
 * is fixed so that two implementations refusing the same line item refuse it
 * for the same stated reason: a bare spelling first (it is the money-moving
 * mistake), then an omitted pinned key, then a malformed value.
 */
export function lineItemKeyViolations(lineItem: unknown): string[] {
  if (!isObject(lineItem)) {
    return ["is not an object"];
  }

  const violations: string[] = [];
  for (const bare of [...REJECTED_MONEY_KEYS].sort()) {
    if (Object.prototype.hasOwnProperty.call(lineItem, bare)) {
      violations.push(
        `carries the bare key ${JSON.stringify(bare)}; state the amount in integer minor ` +
          `units under ${JSON.stringify(`${bare}_minor`)} (Section 7.2)`,
      );
    }
  }
  for (const key of [UNIT_PRICE_MINOR, TOTAL_MINOR]) {
    if (!Object.prototype.hasOwnProperty.call(lineItem, key)) {
      violations.push(`omits ${JSON.stringify(key)}, which is REQUIRED on every line item`);
    }
  }
  for (const key of [UNIT_PRICE_MINOR, TOTAL_MINOR]) {
    if (
      Object.prototype.hasOwnProperty.call(lineItem, key) &&
      integralMinor(lineItem[key]) === null
    ) {
      violations.push(
        `has ${JSON.stringify(key)} ${show(lineItem[key])}, which is not an integer number ` +
          `of minor units within ±${MAX_SAFE_MINOR}`,
      );
    }
  }
  if (Object.prototype.hasOwnProperty.call(lineItem, "quantity")) {
    const quantity = integralMinor(lineItem.quantity);
    if (quantity === null) {
      violations.push(`has "quantity" ${show(lineItem.quantity)}, which is not an integer`);
    } else if (quantity < 0) {
      violations.push(
        `has "quantity" ${quantity}, which is negative; a refund is a negative ` +
          "price, not a negative count (Section 7.2)",
      );
    }
  }
  return violations;
}
