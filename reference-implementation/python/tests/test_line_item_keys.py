"""The pinned line-item money keys (Section 7.2 and spec/schemas/offer.schema.json).

A line item states its money as integer minor units, under ``unit_price_minor``
and ``total_minor``. The bare names ``unit_price`` and ``total`` are refused
outright: the two conventions differ by a factor of one hundred, and a receiver
that read a bare name as minor units — or as major units — would agree with the
sender about the number and disagree about the amount, silently.

spec/test-vectors/offer-line-item-keys.json is the shared contract. This suite
holds three things to it at once: the published schema, this implementation's
own checker, and the canonical bytes of an offer that carries the pinned keys.
The TypeScript suite reads the same file, so neither language can drift.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn.crypto import hash_object
from a2cn.line_items import (
    MAX_SAFE_MINOR,
    REJECTED_MONEY_KEYS,
    SUPPORTED_SESSION_CURRENCIES,
    TOTAL_MINOR,
    UNIT_PRICE_MINOR,
    line_item_key_violations,
    require_minor,
    session_currency_is_supported,
    to_minor_units,
)
from a2cn.session import A2CNError, check_offer_money_params

REPO_ROOT = Path(__file__).parents[3]
SCHEMA = json.loads((REPO_ROOT / "spec" / "schemas" / "offer.schema.json").read_text())
VECTOR = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "offer-line-item-keys.json").read_text()
)
OFFER = VECTOR["offer"]
SESSION_PARAMS = {"currency": "USD"}


def _errors(instance: object, schema: dict = SCHEMA) -> list:
    jsonschema = pytest.importorskip("jsonschema")
    return list(jsonschema.Draft202012Validator(schema).iter_errors(instance))


def _with_line_items(items: object) -> dict:
    offer = copy.deepcopy(OFFER)
    offer["terms"]["line_items"] = items
    return offer


def _ids(cases: list[dict]) -> list[str]:
    return [case["name"] for case in cases]


# ---------------------------------------------------------------------------
# The published schema
# ---------------------------------------------------------------------------

def test_the_offer_schema_is_published_at_the_wire_version():
    """An offer is a wire message, so its schema's $id carries the wire version."""
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert SCHEMA["$id"] == "https://a2cn.dev/schemas/offer/0.2"


def test_the_vector_offer_validates_against_the_schema():
    """The healthy offer goes first: a schema that refused everything would pass every case."""
    assert _errors(OFFER) == []


def test_the_vector_offer_hashes_to_the_same_canonical_bytes_in_both_languages():
    assert hash_object(OFFER) == VECTOR["offer_canonical_hash"]


@pytest.mark.parametrize(
    "case", VECTOR["valid_line_items"], ids=_ids(VECTOR["valid_line_items"])
)
def test_the_schema_admits_every_valid_line_item(case):
    assert _errors(_with_line_items([case["line_item"]])) == []


@pytest.mark.parametrize(
    "case", VECTOR["invalid_line_items"], ids=_ids(VECTOR["invalid_line_items"])
)
def test_the_schema_refuses_every_invalid_line_item(case):
    assert _errors(_with_line_items([case["line_item"]])) != [], case["reason"]


@pytest.mark.parametrize("rejected", sorted(REJECTED_MONEY_KEYS))
def test_the_schema_names_the_bare_key_it_refused(rejected):
    """A reader of the failure learns which spelling was wrong, not merely that one was."""
    offer = _with_line_items([{"quantity": 1, rejected: 360, UNIT_PRICE_MINOR: 36000,
                               TOTAL_MINOR: 36000}])

    messages = " ".join(error.message for error in _errors(offer))

    assert rejected in messages


def test_the_schema_leaves_terms_and_the_message_open_for_extensions():
    """Only the two bare money names are pinned shut; deal types still extend (Section 7.2)."""
    assert SCHEMA.get("additionalProperties") is not False
    terms = SCHEMA["properties"]["terms"]
    assert terms.get("additionalProperties") is not False
    line_item = terms["properties"]["line_items"]["items"]
    assert line_item.get("additionalProperties") is not False
    assert sorted(line_item["required"]) == sorted([UNIT_PRICE_MINOR, TOTAL_MINOR])


# ---------------------------------------------------------------------------
# This implementation's own checker, held to the same cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "case", VECTOR["valid_line_items"], ids=_ids(VECTOR["valid_line_items"])
)
def test_the_checker_admits_every_valid_line_item(case):
    assert line_item_key_violations(case["line_item"]) == []


@pytest.mark.parametrize(
    "case", VECTOR["invalid_line_items"], ids=_ids(VECTOR["invalid_line_items"])
)
def test_the_checker_refuses_every_invalid_line_item(case):
    assert line_item_key_violations(case["line_item"]) != [], case["reason"]


# ---------------------------------------------------------------------------
# The offer path: a bare-name line item never reaches the state machine
# ---------------------------------------------------------------------------

def test_an_offer_whose_line_item_uses_a_bare_name_is_refused():
    terms = copy.deepcopy(OFFER["terms"])
    terms["line_items"] = [{"quantity": 50, "unit_price": 360, "total": 18000}]

    with pytest.raises(A2CNError) as exc_info:
        check_offer_money_params(SESSION_PARAMS, terms)

    assert exc_info.value.code == "INVALID_LINE_ITEM"
    assert "unit_price" in str(exc_info.value)


def test_an_offer_whose_line_items_carry_the_pinned_keys_passes():
    check_offer_money_params(SESSION_PARAMS, copy.deepcopy(OFFER["terms"]))


def test_terms_without_line_items_pass_because_line_items_is_optional():
    terms = copy.deepcopy(OFFER["terms"])
    del terms["line_items"]

    check_offer_money_params(SESSION_PARAMS, terms)


def test_an_empty_line_items_array_passes():
    terms = copy.deepcopy(OFFER["terms"])
    terms["line_items"] = []

    check_offer_money_params(SESSION_PARAMS, terms)


def test_line_items_that_is_not_an_array_is_refused():
    terms = copy.deepcopy(OFFER["terms"])
    terms["line_items"] = {"0": {"unit_price_minor": 1, "total_minor": 1}}

    with pytest.raises(A2CNError) as exc_info:
        check_offer_money_params(SESSION_PARAMS, terms)

    assert exc_info.value.code == "INVALID_LINE_ITEM"


def test_the_refusal_names_the_line_it_refused():
    """Two good lines and one bad one: the message points at the third."""
    terms = copy.deepcopy(OFFER["terms"])
    terms["line_items"] = list(terms["line_items"]) + [
        {"quantity": 1, "unit_price": 1, "total": 1}
    ]

    with pytest.raises(A2CNError) as exc_info:
        check_offer_money_params(SESSION_PARAMS, terms)

    assert "line_items[2]" in str(exc_info.value)


def test_a_changed_currency_is_still_reported_before_a_bad_line_item():
    """Section 7.2's order: the session parameters are settled first."""
    terms = copy.deepcopy(OFFER["terms"])
    terms["currency"] = "EUR"
    terms["line_items"] = [{"quantity": 1, "unit_price": 1, "total": 1}]

    with pytest.raises(A2CNError) as exc_info:
        check_offer_money_params(SESSION_PARAMS, terms)

    assert exc_info.value.code == "SESSION_PARAM_CHANGED"


# ---------------------------------------------------------------------------
# An amount is an integer VALUE, not a particular JSON spelling (Section 7.2)
# ---------------------------------------------------------------------------

def test_the_bound_is_the_safe_integer_range_the_vector_records():
    assert MAX_SAFE_MINOR == VECTOR["max_safe_minor"] == 2**53 - 1


@pytest.mark.parametrize(
    ("spelling", "expected"),
    [(36000, 36000), (36000.0, 36000), (3.6e4, 36000), (-0.0, 0), (-36000.0, -36000)],
)
def test_require_minor_reads_any_integral_spelling_as_the_same_amount(spelling, expected):
    """RFC 8785 makes 36000 and 36000.0 one number, and JavaScript cannot tell them apart."""
    amount = require_minor({UNIT_PRICE_MINOR: spelling}, UNIT_PRICE_MINOR)

    assert amount == expected
    assert isinstance(amount, int) and not isinstance(amount, bool)


def test_require_minor_normalises_negative_zero_to_a_plain_zero():
    """A signed zero would leave the two languages disagreeing about the sign of nothing."""
    amount = require_minor({UNIT_PRICE_MINOR: -0.0}, UNIT_PRICE_MINOR)

    assert amount == 0
    assert str(amount) == "0"


@pytest.mark.parametrize("fractional", [360.5, 36000.0001, -0.5])
def test_require_minor_refuses_a_fractional_amount(fractional):
    with pytest.raises(A2CNError) as exc_info:
        require_minor({UNIT_PRICE_MINOR: fractional}, UNIT_PRICE_MINOR)

    assert exc_info.value.code == "INVALID_LINE_ITEM"


@pytest.mark.parametrize("beyond", [2**53, -(2**53), 1e21])
def test_require_minor_refuses_an_amount_past_the_safe_integer_range(beyond):
    """Past it a double cannot separate adjacent integers, so the languages could differ."""
    with pytest.raises(A2CNError):
        require_minor({UNIT_PRICE_MINOR: beyond}, UNIT_PRICE_MINOR)


def test_the_checker_refuses_a_negative_quantity():
    """A refund is a negative price, not a negative count (Section 7.2)."""
    violations = line_item_key_violations(
        {"quantity": -5, UNIT_PRICE_MINOR: 36000, TOTAL_MINOR: 1800000}
    )

    assert violations != []
    assert any("quantity" in phrase for phrase in violations)


# ---------------------------------------------------------------------------
# Reading a line item's money back out
# ---------------------------------------------------------------------------

def test_require_minor_returns_the_pinned_amount():
    line_item = OFFER["terms"]["line_items"][0]

    assert require_minor(line_item, UNIT_PRICE_MINOR) == 36000
    assert require_minor(line_item, TOTAL_MINOR) == 1800000


@pytest.mark.parametrize("bare", sorted(REJECTED_MONEY_KEYS))
def test_require_minor_refuses_a_line_item_that_states_only_the_bare_name(bare):
    """A bare name is not silently read as the pinned one, at any scale."""
    with pytest.raises(A2CNError, match=f"{bare}_minor"):
        require_minor({"quantity": 1, bare: 360}, f"{bare}_minor")


@pytest.mark.parametrize("value", [None, "36000", 360.5, True])
def test_require_minor_refuses_an_amount_that_is_not_an_integral_number(value):
    with pytest.raises(A2CNError, match=UNIT_PRICE_MINOR):
        require_minor({UNIT_PRICE_MINOR: value}, UNIT_PRICE_MINOR)


def test_the_rejected_names_are_the_two_bare_spellings():
    assert sorted(REJECTED_MONEY_KEYS) == ["total", "unit_price"]
    assert (UNIT_PRICE_MINOR, TOTAL_MINOR) == ("unit_price_minor", "total_minor")


# ---------------------------------------------------------------------------
# Converting a vendor's decimal amount at the boundary
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "case", VECTOR["minor_unit_conversions"], ids=_ids(VECTOR["minor_unit_conversions"])
)
def test_to_minor_units_converts_exactly_as_the_vector_records(case):
    assert to_minor_units(case["value"]) == case["minor"]


@pytest.mark.parametrize(
    "case", VECTOR["rejected_vendor_amounts"], ids=_ids(VECTOR["rejected_vendor_amounts"])
)
def test_to_minor_units_refuses_every_spelling_the_languages_read_differently(case):
    """Each language's own parser takes several of these, and takes them differently."""
    with pytest.raises(A2CNError) as exc_info:
        to_minor_units(case["value"])

    assert exc_info.value.code == "INVALID_LINE_ITEM"


@pytest.mark.parametrize("not_finite", [float("nan"), float("inf"), float("-inf")])
def test_to_minor_units_refuses_a_non_finite_amount(not_finite):
    """JSON cannot write these, so the shared vector cannot carry them; a caller can."""
    with pytest.raises(A2CNError):
        to_minor_units(not_finite)


@pytest.mark.parametrize(
    "pair",
    [(2.675, -2.675), (1.15, -1.15), (0.005, -0.005), (99.995, -99.995), (1.005, -1.005)],
)
def test_a_debit_and_the_credit_that_offsets_it_cancel(pair):
    """Rounding half up left a minor unit behind on every such pair; away from zero does not."""
    debit, credit = pair

    assert to_minor_units(debit) + to_minor_units(credit) == 0


def test_to_minor_units_reads_an_amount_inside_a_money_object():
    assert to_minor_units({"amount": 360.0, "currency": "USD"}) == 36000
    assert to_minor_units({"value": 85.25}) == 8525


def test_a_null_amount_member_falls_through_to_value():
    """``.get("amount", default)`` returned None for a present-but-null key; ``??`` did not."""
    assert to_minor_units({"amount": None, "value": 500}) == 50000


# ---------------------------------------------------------------------------
# The session currency this build is prepared to carry minor amounts in
# ---------------------------------------------------------------------------

def test_the_declared_currencies_are_the_ones_the_vector_records():
    assert sorted(SUPPORTED_SESSION_CURRENCIES) == VECTOR["supported_session_currencies"]


@pytest.mark.parametrize(
    "case", VECTOR["session_currency_cases"], ids=_ids(VECTOR["session_currency_cases"])
)
def test_an_offer_is_refused_unless_this_build_carries_its_session_currency(case):
    """Fails closed: a currency whose exponent really is 2 is refused too, if undeclared."""
    terms = copy.deepcopy(OFFER["terms"])
    terms["currency"] = case["currency"]
    session_params = {"currency": case["currency"]}

    if case["supported"]:
        check_offer_money_params(session_params, terms)
        return

    with pytest.raises(A2CNError) as exc_info:
        check_offer_money_params(session_params, terms)

    assert exc_info.value.code == "INVALID_LINE_ITEM"
    assert case["currency"] in str(exc_info.value)


def test_the_currency_guard_fires_even_when_the_offer_carries_no_line_items():
    """Section 7.2's money encoding attaches to the offer, not to the presence of a line."""
    terms = copy.deepcopy(OFFER["terms"])
    terms["currency"] = "JPY"
    del terms["line_items"]

    with pytest.raises(A2CNError) as exc_info:
        check_offer_money_params({"currency": "JPY"}, terms)

    assert exc_info.value.code == "INVALID_LINE_ITEM"


def test_a_changed_currency_is_reported_before_this_builds_own_limit():
    """The counterparty's own mistake outranks a limitation of ours."""
    terms = copy.deepcopy(OFFER["terms"])
    terms["currency"] = "JPY"

    with pytest.raises(A2CNError) as exc_info:
        check_offer_money_params({"currency": "USD"}, terms)

    assert exc_info.value.code == "SESSION_PARAM_CHANGED"


def test_an_added_basis_is_reported_before_this_builds_own_limit():
    """Same precedence: a session-parameter violation comes before the capability guard."""
    terms = copy.deepcopy(OFFER["terms"])
    terms["currency"] = "JPY"
    terms["basis"] = "net"

    with pytest.raises(A2CNError) as exc_info:
        check_offer_money_params({"currency": "JPY"}, terms)

    assert exc_info.value.code == "SESSION_PARAM_CHANGED"


@pytest.mark.parametrize(
    "case",
    VECTOR["non_string_session_currencies"],
    ids=_ids(VECTOR["non_string_session_currencies"]),
)
def test_the_guard_answers_false_for_a_currency_that_is_not_a_string(case):
    """The ``isinstance`` is load-bearing here, and only in Python.

    A list or a dict is unhashable, so ``currency in frozenset(...)`` raises
    ``TypeError`` without it, while the TypeScript ``.includes`` simply returns
    false. The two implementations would then disagree about a malformed
    session — one crashing, one refusing — which is the divergence this whole
    section exists to prevent.
    """
    assert session_currency_is_supported(case["currency"]) is False


@pytest.mark.parametrize(
    "case",
    VECTOR["non_string_session_currencies"],
    ids=_ids(VECTOR["non_string_session_currencies"]),
)
def test_a_session_currency_that_is_not_a_string_is_refused_and_does_not_crash(case):
    """It surfaces as a protocol refusal, not an exception the caller cannot read.

    Unreachable through the state machine, which settles a non-string currency
    as INVALID_REQUEST before a session exists (Section 6.4.1); this holds the
    guard to answering for itself anyway.
    """
    terms = copy.deepcopy(OFFER["terms"])
    terms["currency"] = case["currency"]

    with pytest.raises(A2CNError) as exc_info:
        check_offer_money_params({"currency": case["currency"]}, terms)

    assert exc_info.value.code == "INVALID_LINE_ITEM"
