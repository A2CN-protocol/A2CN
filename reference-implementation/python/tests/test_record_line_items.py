"""Section 9.5 step 9: a record's agreed terms are held to Section 7.2's money encoding.

The offer path refuses a line item that states its money under the bare
``unit_price`` / ``total`` names, or as anything but an integer number of minor
units. A verifier must not rely on the producer having run that check: a
producer that signed such terms itself gets a record whose hashes and
signatures are all genuine, and only this step stands between it and a
hundredfold misreading of the agreed price. Each case in
``transaction-record-line-items.json`` is such a record, re-signed with the
basis vector's test-only keys, and the TypeScript suite reads the same bytes.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn.errors import A2CNError
from a2cn.line_items import terms_line_item_violation
from a2cn.record import (
    REASON_LINE_ITEMS_INVALID,
    verify_transaction_record,
    verify_transaction_record_reason,
)
from a2cn.session import check_offer_line_items, check_offer_money_params

VECTOR_PATH = (
    Path(__file__).parents[3] / "spec" / "test-vectors" / "transaction-record-line-items.json"
)
VECTOR = json.loads(VECTOR_PATH.read_text())
CASES = VECTOR["cases"]


def _reason(case: dict) -> str | None:
    return verify_transaction_record_reason(
        case["record"], VECTOR["did_documents"], case["offer_hashes"]
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_the_record_reaches_the_stated_verdict(case):
    assert _reason(case) == case["expected_reason"]
    assert verify_transaction_record(
        case["record"], VECTOR["did_documents"], case["offer_hashes"]
    ) is case["verifies"]


@pytest.mark.parametrize(
    "case", [case for case in CASES if not case["verifies"]], ids=lambda case: case["name"]
)
def test_a_refused_record_is_refused_at_step_9_alone(case):
    """Every other step passes: the hashes and both signatures are genuine."""
    assert _reason(case) == REASON_LINE_ITEMS_INVALID


def _session_params(record: dict) -> dict:
    """The money parameters the record's session fixed, as the offer path reads them."""
    params = {"currency": record["currency"]}
    if "basis" in record:
        params["basis"] = record["basis"]
    return params


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_the_record_and_the_offer_path_apply_one_rule(case):
    """The verifier refuses exactly what the offer path refuses, for the same terms."""
    record = case["record"]
    terms = record["agreed_terms"]
    if case["verifies"]:
        check_offer_money_params(_session_params(record), terms)
    else:
        with pytest.raises(A2CNError) as refused:
            check_offer_money_params(_session_params(record), terms)
        assert refused.value.code == "INVALID_LINE_ITEM"


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_the_line_item_message_is_the_offer_paths(case):
    """Where a line item is at fault, both paths name it in the same words."""
    terms = case["record"]["agreed_terms"]
    violation = terms_line_item_violation(terms)
    if violation is None:
        check_offer_line_items(terms)
    else:
        with pytest.raises(A2CNError) as refused:
            check_offer_line_items(terms)
        assert str(refused.value.message) == violation


def test_the_whole_number_float_case_is_spelled_as_a_float():
    """The parity case is only a parity case if the bytes carry the float spelling."""
    assert '"unit_price_minor": 100000.0' in VECTOR_PATH.read_text()
    case = next(case for case in CASES if case["name"] == "whole_number_float_minor")
    assert case["verifies"] is True


def test_a_record_without_line_items_is_untouched():
    """line_items is OPTIONAL: removing it leaves nothing for step 9 to refuse."""
    case = next(case for case in CASES if case["name"] == "bare_major_units")
    terms = copy.deepcopy(case["record"]["agreed_terms"])
    del terms["line_items"]
    assert terms_line_item_violation(terms) is None
