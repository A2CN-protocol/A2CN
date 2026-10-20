"""Why a SessionEvidenceRecord does not verify (Section 9A.6).

verify_session_evidence_record_reason names the first check a record fails, as
verify_transaction_record_reason does for a TransactionRecord. The cases in
``session-evidence-record-reasons.json`` each fail exactly one check, and the
TypeScript suite reads the same bytes, so the two implementations must name the
same cause.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import a2cn.evidence as evidence_module
from a2cn.evidence import (
    assess_session_evidence_record,
    verify_session_evidence_record,
    verify_session_evidence_record_reason,
)

VECTOR = json.loads(
    (
        Path(__file__).parents[3] / "spec" / "test-vectors" / "session-evidence-record-reasons.json"
    ).read_text()
)
CASES = VECTOR["cases"]
# Every reason code the module exports, found by reflection: a code added
# without a case fails this file rather than sitting unreachable.
ALL_REASON_CODES = {
    getattr(evidence_module, name)
    for name in dir(evidence_module)
    if name.startswith("EVIDENCE_REASON_")
}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_the_reason_names_the_check_that_failed(case):
    did_documents = VECTOR["did_documents"][case["base"]]
    reason = verify_session_evidence_record_reason(case["record"], did_documents)
    assert reason == case["expected_reason"]
    assert isinstance(reason, str)
    assert verify_session_evidence_record(case["record"], did_documents) is False
    assert assess_session_evidence_record(case["record"], did_documents)["reason"] == reason


def test_every_reason_code_is_reachable():
    assert {case["expected_reason"] for case in CASES} == ALL_REASON_CODES


def test_a_record_that_verifies_has_no_reason():
    from tests.test_evidence import _priced_record

    record, did_documents = _priced_record()
    assert verify_session_evidence_record_reason(record, did_documents) is None
    assert assess_session_evidence_record(record, did_documents)["reason"] is None
