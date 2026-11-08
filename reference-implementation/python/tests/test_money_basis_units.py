"""Section 9A.9: a money_basis states its money in minor units of 2.

A money_basis is valid only when its currency is one whose minor-unit exponent
this build can establish to be 2 (the TransactionRecord set, Section 9.5 step 9)
and its minor_unit_exponent is 2. Before this, one signed act carrying
total_value 9500000 USD verified at exponents 0, 2, 3 and 4. The refused cases
are in session-evidence-record-reasons.json (base money_basis_units).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from a2cn.evidence import (
    EVIDENCE_REASON_MONEY_BASIS_CURRENCY_UNSUPPORTED,
    EVIDENCE_REASON_MONEY_BASIS_EXPONENT_MISMATCH,
    verify_session_evidence_record,
    verify_session_evidence_record_reason,
)
from a2cn.verify import EXIT_REFUSED, EXIT_VERIFIED, run
from tests.test_evidence import (
    MONEY_BASIS,
    _generate,
    _make_session,
    _mark_timed_out,
    _observed_quote,
    _offer,
    _priced_record,
)

VECTOR = json.loads(
    (Path(__file__).parents[3] / "spec" / "test-vectors" / "session-evidence-record-reasons.json").read_text()
)
UNITS = {case["name"]: case for case in VECTOR["cases"] if case["base"] == "money_basis_units"}
DIDS = VECTOR["did_documents"]["money_basis_units"]


def test_the_cases_cover_each_exponent_and_an_unsupported_currency():
    assert {
        "money_basis_exponent_0",
        "money_basis_exponent_3",
        "money_basis_exponent_4",
        "money_basis_currency_unsupported",
        "terminal_money_basis_exponent_0",
    } <= set(UNITS)


def test_exponent_2_in_a_supported_currency_still_verifies():
    record, did_documents = _priced_record()
    assert MONEY_BASIS["currency"] == "USD" and MONEY_BASIS["minor_unit_exponent"] == 2
    assert verify_session_evidence_record_reason(record, did_documents) is None


def _sealed_with(money_basis: dict) -> dict:
    manager, session, _did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_timed_out(session)
    return _generate(session, [_observed_quote(money_basis=money_basis)])


@pytest.mark.parametrize(
    "changes",
    [
        {"minor_unit_exponent": 0, "raw_amounts": ["9500000"]},
        {"minor_unit_exponent": 3, "raw_amounts": ["9500.000"]},
        {"minor_unit_exponent": 4, "raw_amounts": ["950.0000"]},
        {"currency": "CHF"},
    ],
    ids=["exponent-0", "exponent-3", "exponent-4", "CHF"],
)
def test_the_generator_refuses_to_seal_another_unit(changes):
    with pytest.raises(ValueError, match="minor_unit_exponent 2"):
        _sealed_with({**MONEY_BASIS, **changes})


def _cli(record: dict, tmp_path: Path) -> tuple[int, str]:
    folder = tmp_path / "deal"
    folder.mkdir()
    (folder / "evidence_record.json").write_text(json.dumps(record))
    for index, document in enumerate(DIDS.values()):
        (folder / f"did-{index}.json").write_text(json.dumps(document))
    out = io.StringIO()
    status = run([str(folder), "--offline"], out=out, err=out)
    return status, out.getvalue()


@pytest.mark.parametrize("name", ["money_basis_exponent_0", "money_basis_exponent_3", "money_basis_exponent_4"])
def test_the_cli_refuses_another_exponent(name, tmp_path):
    status, output = _cli(UNITS[name]["record"], tmp_path)
    assert status == EXIT_REFUSED, output
    assert f"REFUSED: {EVIDENCE_REASON_MONEY_BASIS_EXPONENT_MISMATCH}" in output


def test_the_cli_refuses_an_unsupported_currency(tmp_path):
    status, output = _cli(UNITS["money_basis_currency_unsupported"]["record"], tmp_path)
    assert status == EXIT_REFUSED, output
    assert f"REFUSED: {EVIDENCE_REASON_MONEY_BASIS_CURRENCY_UNSUPPORTED}" in output


CONTROL = next(control for control in VECTOR["controls"] if control["name"] == "money_basis_exponent_2")


def test_the_stored_exponent_2_control_verifies():
    assert verify_session_evidence_record(CONTROL["record"], DIDS)


def test_the_cli_verifies_exponent_2(tmp_path):
    status, output = _cli(CONTROL["record"], tmp_path)
    assert status == EXIT_VERIFIED, output
    assert "  VERIFIED" in output
