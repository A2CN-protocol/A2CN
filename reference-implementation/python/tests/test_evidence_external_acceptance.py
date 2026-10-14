"""Section 9A.12: the accepted-act rule is keyed on the terms.

An external-channel record must not attest an in-band acceptance of terms the
responder signed, whichever field names them and whether the acceptance names
the signed act or an unsigned copy of its terms. The cases are in
``session-evidence-record-external-acceptance.json``, and the TypeScript suite
reads the same bytes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from a2cn.evidence import assess_session_evidence_record, verify_session_evidence_record

VECTOR = json.loads(
    (
        Path(__file__).parents[3]
        / "spec"
        / "test-vectors"
        / "session-evidence-record-external-acceptance.json"
    ).read_text()
)
CASES = VECTOR["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_the_record_reaches_the_stated_verdict(case):
    assert (
        verify_session_evidence_record(case["record"], VECTOR["did_documents"])
        is case["verifies"]
    )


@pytest.mark.parametrize(
    "case", [case for case in CASES if not case["verifies"]], ids=lambda case: case["name"]
)
def test_a_refused_record_has_no_invalid_act(case):
    """Every act verifies on its own: the accepted-act rule alone refuses the record."""
    assessment = assess_session_evidence_record(case["record"], VECTOR["did_documents"])
    assert assessment["invalid_acts"] == 0
    assert "external_commitment_reference" in case["record"]


def test_the_vector_covers_every_evasion_and_both_controls():
    names = {case["name"] for case in CASES}
    assert {
        "reference_through_in_reply_to",
        "reference_inside_terms",
        "unsigned_recorded_copy",
        "accepts_initiator_offer",
        "accepts_unsigned_observed_offer",
    } <= names
