"""Static checks for shared conformance fixture catalog."""

import json
from pathlib import Path


FIXTURE_DIR = Path(__file__).parents[4] / "spec" / "conformance-fixtures"

EXPECTED_FIXTURES = {
    "expired_mandate_on_offer_reference",
    "hitl_threshold_crossing",
    "counterparty_outside_allowed_list",
    "payment_terms_drift_mid_negotiation",
    "partial_acceptance_unresolved_constraint",
    "reputation_score_cannot_expand_authority",
}


def test_conformance_fixture_catalog_complete():
    fixture_ids = {
        path.stem
        for path in FIXTURE_DIR.glob("*.json")
    }

    assert fixture_ids == EXPECTED_FIXTURES


def test_conformance_fixtures_have_required_shape():
    for path in FIXTURE_DIR.glob("*.json"):
        fixture = json.loads(path.read_text())

        assert fixture["id"] == path.stem
        assert fixture["status"] in {"active", "known_gap"}
        assert fixture["summary"]
        assert isinstance(fixture["given"], dict)
        assert isinstance(fixture["expect"], dict)
        assert "accepted" in fixture["expect"]
