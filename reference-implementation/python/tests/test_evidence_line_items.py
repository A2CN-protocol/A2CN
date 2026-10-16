"""Section 9A.6, step 13: the line items of the acts an evidence record records.

Every record version is refused a money hazard: a bare ``unit_price`` or
``total``, or a pinned amount that is present but not an integer. An older
``record_version`` label therefore cannot get one past the check. From
``"0.5"`` the whole of Section 7.2's line-item rule applies, through the same
shared check as the offer path and TransactionRecord verification. The cases
are in ``session-evidence-record-line-items.json``, and the TypeScript suite
reads the same bytes.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn.crypto import private_key_from_jwk
from a2cn.evidence import (
    LINE_ITEM_RULE_FULL_FROM,
    generate_session_evidence_record,
    verify_session_evidence_record,
)
from a2cn.line_items import terms_line_item_violation
from a2cn.session import Session

VECTORS = Path(__file__).parents[3] / "spec" / "test-vectors"
VECTOR = json.loads((VECTORS / "session-evidence-record-line-items.json").read_text())
PARITY = json.loads((VECTORS / "session-evidence-record-parity.json").read_text())
CASES = VECTOR["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_the_record_reaches_the_stated_verdict(case):
    assert case["record"]["record_version"] == case["record_version"]
    assert (
        verify_session_evidence_record(case["record"], VECTOR["did_documents"])
        is case["verifies"]
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_the_verdict_is_the_shared_checks(case):
    """Before 0.5 the shared check runs for the money hazards only; from 0.5 in full."""
    terms = case["record"]["acts"][1]["act"]["terms"]
    hazards_only = case["record_version"] != LINE_ITEM_RULE_FULL_FROM
    assert (
        terms_line_item_violation(terms, hazards_only=hazards_only) is None
    ) is case["verifies"]


def test_both_sides_of_the_version_split_are_covered():
    """A pre-0.5 record missing total_minor verifies; a 0.5 one does not."""
    verdicts = {case["name"]: case["verifies"] for case in CASES}
    assert verdicts["pre_0_5_missing_total_minor"] is True
    assert verdicts["missing_total_minor"] is False
    assert verdicts["pre_0_5_bare_names"] is False


def _parity_session() -> Session:
    source = PARITY["session"]
    session = Session(
        session_id=source["session_id"],
        state=source["state"],
        current_turn="none",
        terminal_reason=source["terminal_reason"],
        terminal_message_id=source["terminal_message_id"],
        session_created_at=source["session_created_at"],
        state_updated_at=source["state_updated_at"],
        session_params=source["session_params"],
        initiator_mandate=source["initiator_mandate"],
        responder_mandate=source["responder_mandate"],
    )
    session._session_init = source["session_init"]
    session._session_ack = source["session_ack"]
    session._message_log = source["message_log"]
    return session


def _generate(line_items) -> dict:
    observed = copy.deepcopy(PARITY["observed_acts"])
    with_terms = [item["act"] for item in observed if isinstance(item["act"].get("terms"), dict)]
    assert with_terms
    with_terms[0]["terms"]["line_items"] = line_items
    producer = PARITY["producer"]
    return generate_session_evidence_record(
        _parity_session(),
        producer_private_key=private_key_from_jwk(PARITY["producer_private_jwk"]),
        producer_did=producer["did"],
        producer_agent_id=producer["agent_id"],
        producer_verification_method=producer["verification_method"],
        observed_acts=observed,
    )


def test_the_generator_seals_a_record_whose_line_items_hold():
    record = _generate([{"quantity": 1, "unit_price_minor": 9000, "total_minor": 9000}])
    assert record["record_version"] == LINE_ITEM_RULE_FULL_FROM
    assert verify_session_evidence_record(record, PARITY["did_documents"])


@pytest.mark.parametrize(
    "line_items",
    [
        [{"quantity": 1, "unit_price": 90.0, "total": 90.0}],
        [{"quantity": 1, "unit_price_minor": 9000}],
    ],
    ids=["bare_names", "missing_total_minor"],
)
def test_the_generator_refuses_to_seal_what_the_verifier_would_reject(line_items):
    with pytest.raises(ValueError, match="line_items"):
        _generate(line_items)
