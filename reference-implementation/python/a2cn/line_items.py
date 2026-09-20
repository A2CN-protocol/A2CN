"""The pinned line-item money keys (Section 7.2).

A line item states its money as integer minor units of the session currency,
under two key names and no others:

    unit_price_minor    total_minor

The bare names ``unit_price`` and ``total`` are refused. They are not coerced,
scaled, or read as major units. The reason is the size of the mistake: the two
conventions differ by a factor of one hundred, so a receiver that guessed wrong
would agree with the sender about the *number* and disagree about the *amount*,
and nothing in the message would say which of them was right. A refusal is
recoverable; a hundredfold silent misreading of a price is not.

**An amount is an integer VALUE, not a JSON spelling.** RFC 8785 makes ``36000``
and ``36000.0`` the same number, and JavaScript cannot tell them apart once
parsed, so judging by Python's ``isinstance(v, int)`` would have refused in one
language exactly what the other accepted — and ``36000.0`` is how a decimal or
money type serialises, so that is the common case, not an exotic one. Both
languages therefore accept any integral number and refuse anything with a
fractional part.

The TypeScript mirror is ``a2cn_ts/src/a2cn/line_items.ts`` and the two are
held to the same cases by ``spec/test-vectors/offer-line-item-keys.json``.
"""

from __future__ import annotations

import math
import re
from typing import Any

from a2cn.errors import A2CNError

#: The pinned spellings. Both are REQUIRED on every line item.
UNIT_PRICE_MINOR = "unit_price_minor"
TOTAL_MINOR = "total_minor"

#: The bare spellings, refused by name. `spec/schemas/offer.schema.json` refuses
#: the same two through `propertyNames`, because the line item stays open for
#: deal-type extension fields and cannot simply be closed.
REJECTED_MONEY_KEYS = frozenset({"unit_price", "total"})

#: Minor units per major unit. Every amount A2CN carries today is in a
#: two-decimal currency, and the adapters have always assumed cents; this names
#: that assumption rather than scattering `* 100` through eleven files. A
#: currency-aware exponent is a separate change (the zero-decimal currencies,
#: JPY and KRW among them, need one).
MINOR_UNIT_EXPONENT = 2

#: The session currencies this build is prepared to carry line-item minor
#: amounts in. NAMES ONLY, deliberately: the moment this maps a currency to a
#: number other than 2 it has stopped being a capability list and become the
#: currency-exponent table, which is separate work.
#:
#: **A capability limit, not knowledge about the world.** A2CN maintains no
#: currency exponent registry (Section 9A.9), and these are emphatically not the
#: only currencies whose minor-unit exponent is 2 — they are the only ones this
#: build has grounds to assert it for. Measured from the corpus on 2026-09-20,
#: not recalled: across the spec, both implementations, every vector and every
#: adapter, the currency-keyed values are USD (446), EUR (39) and GBP (2), and
#: the only currencies ever fixed as a *session* currency are USD and EUR.
#:
#: **The list is short on purpose and will refuse legitimate two-decimal
#: currencies** — CAD among them, which our own Conga adapter can emit. That
#: refusal is the designed behaviour, not an oversight: it fails CLOSED, loudly
#: and recoverably, exactly as Section 7.2 already does for a bare key name. The
#: inverse shape — listing the currencies known *not* to be 2 and assuming 2 for
#: everything else — fails OPEN the moment it falls behind ISO 4217, turning a
#: neglected list into a silent hundredfold misread. Adding a currency here is
#: meant to be a deliberate act with a reason attached, never topping up a list
#: someone assumed was exhaustive.
SUPPORTED_SESSION_CURRENCIES = frozenset({"EUR", "GBP", "USD"})

#: The largest amount both languages hold exactly: JavaScript's safe-integer
#: range. Past it a double can no longer separate adjacent integers, so one JSON
#: document could be read as two different amounts — Python's arbitrary-precision
#: int would be "more right" and the two implementations would disagree about
#: money. Bounding makes them agree, and no real line states ninety trillion
#: currency units.
MAX_SAFE_MINOR = 2**53 - 1

#: A vendor amount as text: optional sign, ASCII digits, at most one point.
#: ``[0-9]`` and not ``\\d`` deliberately — Python's ``\\d`` matches Unicode
#: digits (Arabic-Indic among them) while JavaScript's does not, so ``\\d`` would
#: be the divergence rather than the guard against it. No exponent, no
#: underscore separators, no hex/octal/binary: each language's own parser takes
#: a different subset of those, and a vendor amount is a decimal figure, not a
#: numeric literal.
_DECIMAL_TEXT = re.compile(r"[+-]?([0-9]+(\.[0-9]+)?|\.[0-9]+)")

#: Stripped before matching. Spelled out rather than ``str.strip()`` because
#: Python strips Unicode whitespace and JavaScript's ``trim`` strips a slightly
#: different set; these four are the ones both agree on.
_STRIPPABLE = " \t\n\r"


def _invalid(message: str) -> A2CNError:
    return A2CNError("INVALID_LINE_ITEM", message, 400)


def session_currency_is_supported(currency: Any) -> bool:
    """Whether this build can state a line item's money in ``currency``.

    An exact match on the declared spelling, with no case folding: Python and
    JavaScript do not upper-case every string identically, and a money guard
    that differed between the two would be the very defect it exists to
    prevent. A currency that is not a string is not one this build carries.
    """
    return isinstance(currency, str) and currency in SUPPORTED_SESSION_CURRENCIES


def integral_minor(value: Any) -> int | None:
    """``value`` as an integer amount, or ``None`` when it is not one.

    Accepts any integral number however it was spelled, because that is the
    only rule both languages can enforce (see the module docstring). Refuses a
    fractional value, a non-finite one, a boolean — which is not a number,
    however much ``isinstance(True, int)`` suggests otherwise — anything that is
    not a number at all, and anything outside :data:`MAX_SAFE_MINOR`.
    Normalises ``-0.0`` to a plain ``0``, so the two languages cannot end up
    disagreeing about the sign of nothing.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        candidate = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        candidate = int(value)
    else:
        return None
    if abs(candidate) > MAX_SAFE_MINOR:
        return None
    return candidate


def to_minor_units(value: Any, *, exponent: int = MINOR_UNIT_EXPONENT) -> int:
    """One vendor amount, in integer minor units, at the boundary.

    **Scaled, then rounded half away from zero, identically in both languages.**
    ``sign * math.floor(abs(v) * 100 + 0.5)`` here and the same operations in
    the same order in TypeScript agree bit for bit; every case is measured in
    both and pinned by ``spec/test-vectors/offer-line-item-keys.json``.

    Away from zero rather than simply up, because a debit and the credit that
    offsets it have to cancel. Under half-up, ``2.675`` and ``-2.675`` converted
    to ``268`` and ``-267``, leaving a minor unit behind on every offsetting
    pair — and the vector blesses a negative line as exactly what a credit or
    rebate states, so that was a defect, not a preference.

    **What is refused, and why here rather than in each language's parser.** A
    vendor amount is a decimal figure. Hex, octal and binary literals,
    underscore separators, exponent text, non-ASCII digits, ``"NaN"`` and
    ``"Infinity"`` are refused, because Python and JavaScript each accept a
    different subset of those and would convert the same payload to different
    money. A money object contributes its ``amount``, or its ``value`` when
    ``amount`` is absent **or null** — a present-but-null member states no
    amount, and ``.get("amount", default)`` used to return that ``None`` and
    stop, where the TypeScript ``??`` fell through to ``value``.

    Rounding to nearest does not make the conversion exact: exactness needs the
    source as a decimal *string*, because once a float exists the decimal the
    vendor wrote is already gone. That is a separate change from this one.

    Raises ``A2CNError`` with ``INVALID_LINE_ITEM`` rather than a bare
    ``ValueError``: an amount this cannot read is a refusal the protocol has a
    code for, not a crash.
    """
    if value is None:
        return 0
    if isinstance(value, bool):
        raise _invalid(f"vendor amount {value!r} is a boolean, not a money figure")
    if isinstance(value, dict):
        amount = value.get("amount")
        if amount is None:
            amount = value.get("value")
        if amount is None:
            return 0
        return to_minor_units(amount, exponent=exponent)
    if isinstance(value, str):
        text = value.strip(_STRIPPABLE)
        if text == "":
            return 0
        if not _DECIMAL_TEXT.fullmatch(text):
            raise _invalid(
                f"vendor amount {value!r} is not a decimal figure: an amount is an "
                "optional sign, digits, and at most one decimal point"
            )
        number = float(text)
    elif isinstance(value, (int, float)):
        number = float(value)
    else:
        raise _invalid(
            f"vendor amount {value!r} is a {type(value).__name__}, not a money figure"
        )
    if not math.isfinite(number):
        raise _invalid(f"vendor amount {value!r} is not a finite number")
    scaled = math.floor(abs(number) * 10**exponent + 0.5)
    minor = -scaled if number < 0 else scaled
    if abs(minor) > MAX_SAFE_MINOR:
        raise _invalid(
            f"vendor amount {value!r} is {minor} minor units, beyond the "
            f"±{MAX_SAFE_MINOR} both implementations represent exactly"
        )
    return minor


def require_minor(line_item: Any, key: str) -> int:
    """One pinned amount off an agreed line item, or a refusal naming the key.

    Callers used to reach for ``line_item.get("unit_price", 0)``, which turned
    a line item that said nothing about money into one that said the price was
    zero. Every read goes through here instead, so a missing or malformed
    amount stops the write-back rather than sending a vendor a free order.
    """
    if not isinstance(line_item, dict):
        raise _invalid(f"line item is not an object, so it carries no {key!r}")
    if key not in line_item:
        bare = key.removesuffix("_minor")
        stated = f", though it carries the bare {bare!r}" if bare in line_item else ""
        raise _invalid(
            f"line item omits {key!r}{stated}; A2CN line-item money is stated in "
            "integer minor units under the pinned key (Section 7.2)"
        )
    amount = integral_minor(line_item[key])
    if amount is None:
        raise _invalid(
            f"line item {key!r} is {line_item[key]!r}, which is not an integer number "
            f"of minor units within ±{MAX_SAFE_MINOR}"
        )
    return amount


def line_item_key_violations(line_item: Any) -> list[str]:
    """Why this line item is not a well-formed priced line, or an empty list.

    Each violation is a phrase that reads after ``terms.line_items[n]``. The
    order is fixed so that two implementations refusing the same line item
    refuse it for the same stated reason: a bare spelling first (it is the
    money-moving mistake), then an omitted pinned key, then a malformed value.
    """
    if not isinstance(line_item, dict):
        return ["is not an object"]

    violations: list[str] = []
    for bare in sorted(REJECTED_MONEY_KEYS):
        if bare in line_item:
            violations.append(
                f"carries the bare key {bare!r}; state the amount in integer minor "
                f"units under {bare + '_minor'!r} (Section 7.2)"
            )
    for key in (UNIT_PRICE_MINOR, TOTAL_MINOR):
        if key not in line_item:
            violations.append(f"omits {key!r}, which is REQUIRED on every line item")
    for key in (UNIT_PRICE_MINOR, TOTAL_MINOR):
        if key in line_item and integral_minor(line_item[key]) is None:
            violations.append(
                f"has {key!r} {line_item[key]!r}, which is not an integer number of "
                f"minor units within ±{MAX_SAFE_MINOR}"
            )
    if "quantity" in line_item:
        quantity = integral_minor(line_item["quantity"])
        if quantity is None:
            violations.append(
                f"has 'quantity' {line_item['quantity']!r}, which is not an integer"
            )
        elif quantity < 0:
            violations.append(
                f"has 'quantity' {quantity}, which is negative; a refund is a negative "
                "price, not a negative count (Section 7.2)"
            )
    return violations
