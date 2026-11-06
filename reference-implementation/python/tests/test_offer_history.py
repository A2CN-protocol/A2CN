"""A TransactionRecord's offer history, taken from its SessionEvidenceRecord.

offer_chain_hash is covered by neither signature, so the earlier offers must
come from somewhere a verifier can check: the session's evidence record, which
holds every offer as a signed act and names the TransactionRecord by
transaction_record_hash. The TypeScript suite reads the same vector.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from a2cn.evidence import assess_session_evidence_record, offer_history_from_evidence
from a2cn.record import verify_transaction_record_reason

VECTOR = json.loads(
    (
        Path(__file__).parents[3] / "spec" / "test-vectors" / "transaction-record-offer-history.json"
    ).read_text()
)
DIDS = VECTOR["did_documents"]


@pytest.mark.parametrize("case", VECTOR["history_cases"], ids=lambda case: case["name"])
def test_the_history_is_taken_only_from_a_linked_verified_complete_record(case):
    history, reason = offer_history_from_evidence(
        VECTOR["transaction_record"], case["evidence_record"], DIDS["current"]
    )
    assert history == case["expected_history"]
    assert reason == case["expected_reason"]


@pytest.mark.parametrize("case", VECTOR["record_cases"], ids=lambda case: case["name"])
def test_the_records_reach_the_stated_verdicts(case):
    documents = DIDS[case["did_documents"]]
    record = case.get("record_document") or VECTOR[case["record"]]
    if case["record"] == "transaction_record":
        reason = verify_transaction_record_reason(record, documents, case["offer_hashes"])
    else:
        assessment = assess_session_evidence_record(record, documents)
        reason = assessment["reason"]
        assert assessment["unresolved_keys"] == case.get("expected_unresolved_keys", [])
    assert reason == case["expected_reason"]


def test_the_history_completes_the_record():
    history, reason = offer_history_from_evidence(
        VECTOR["transaction_record"], VECTOR["evidence_record"], DIDS["current"]
    )
    assert reason is None
    assert len(history) == VECTOR["transaction_record"]["final_offer"]["round_number"] == 2
    assert verify_transaction_record_reason(VECTOR["transaction_record"], DIDS["current"], history) is None
