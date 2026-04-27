"""Tests for UBL 2.1 invoice export from A2CN transaction records."""

from __future__ import annotations

import xml.etree.ElementTree as ET
import pytest

from ubl_export import transaction_record_to_ubl_invoice

_CBC = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
_CAC = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
_INV = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"


def _sample_record(
    session_id: str = "sess-abc-123",
    record_hash: str = "a" * 64,
    total_value: int = 10_000_000,
    completed_at: str = "2026-04-01T10:00:00Z",
) -> dict:
    return {
        "session_id": session_id,
        "record_hash": record_hash,
        "agreed_terms": {"total_value": total_value, "currency": "USD"},
        "completed_at": completed_at,
    }


def _parse(xml_str: str) -> ET.Element:
    return ET.fromstring(xml_str.encode("utf-8"))


# ---------------------------------------------------------------------------
# Basic output tests
# ---------------------------------------------------------------------------

class TestUBLExportBasic:
    def test_valid_record_produces_non_empty_xml_string(self):
        xml_str = transaction_record_to_ubl_invoice(
            _sample_record(), seller_name="Acme Corp", buyer_name="TechCorp Inc"
        )
        assert isinstance(xml_str, str)
        assert len(xml_str) > 0

    def test_output_is_parseable(self):
        xml_str = transaction_record_to_ubl_invoice(
            _sample_record(), seller_name="Acme Corp", buyer_name="TechCorp Inc"
        )
        root = _parse(xml_str)
        assert root is not None

    def test_invoice_number_defaults_to_session_id(self):
        record = _sample_record(session_id="my-session-id")
        xml_str = transaction_record_to_ubl_invoice(
            record, seller_name="Acme Corp", buyer_name="TechCorp Inc"
        )
        root = _parse(xml_str)
        id_el = root.find(f"{{{_CBC}}}ID")
        assert id_el is not None
        assert id_el.text == "my-session-id"

    def test_custom_invoice_number_in_id_element(self):
        xml_str = transaction_record_to_ubl_invoice(
            _sample_record(),
            seller_name="Acme Corp",
            buyer_name="TechCorp Inc",
            invoice_number="INV-2026-0042",
        )
        root = _parse(xml_str)
        assert root.find(f"{{{_CBC}}}ID").text == "INV-2026-0042"

    def test_record_hash_in_note_element(self):
        record = _sample_record(record_hash="deadbeef" * 8)
        xml_str = transaction_record_to_ubl_invoice(
            record, seller_name="Acme Corp", buyer_name="TechCorp Inc"
        )
        assert "deadbeef" * 8 in xml_str

    def test_seller_name_in_supplier_party(self):
        xml_str = transaction_record_to_ubl_invoice(
            _sample_record(),
            seller_name="Acme Supplies Ltd",
            buyer_name="TechCorp Inc",
        )
        root = _parse(xml_str)
        supplier = root.find(f"{{{_CAC}}}AccountingSupplierParty")
        assert supplier is not None
        name_el = supplier.find(f".//{{{_CBC}}}Name")
        assert name_el is not None
        assert name_el.text == "Acme Supplies Ltd"

    def test_buyer_name_in_customer_party(self):
        xml_str = transaction_record_to_ubl_invoice(
            _sample_record(),
            seller_name="Acme Corp",
            buyer_name="Global Procurement Co",
        )
        root = _parse(xml_str)
        customer = root.find(f"{{{_CAC}}}AccountingCustomerParty")
        assert customer is not None
        name_el = customer.find(f".//{{{_CBC}}}Name")
        assert name_el is not None
        assert name_el.text == "Global Procurement Co"

    def test_total_value_in_payable_amount(self):
        # 10_000_000 cents → $100,000.00
        xml_str = transaction_record_to_ubl_invoice(
            _sample_record(total_value=10_000_000),
            seller_name="Acme Corp",
            buyer_name="TechCorp Inc",
        )
        root = _parse(xml_str)
        monetary = root.find(f"{{{_CAC}}}LegalMonetaryTotal")
        assert monetary is not None
        payable = monetary.find(f"{{{_CBC}}}PayableAmount")
        assert payable is not None
        assert payable.text == "100000.00"

    def test_currency_code_in_document_currency_element(self):
        xml_str = transaction_record_to_ubl_invoice(
            _sample_record(),
            seller_name="Acme Corp",
            buyer_name="TechCorp Inc",
            currency_code="EUR",
        )
        root = _parse(xml_str)
        dcc = root.find(f"{{{_CBC}}}DocumentCurrencyCode")
        assert dcc is not None
        assert dcc.text == "EUR"

    def test_currency_code_in_payable_amount_attribute(self):
        xml_str = transaction_record_to_ubl_invoice(
            _sample_record(),
            seller_name="Acme Corp",
            buyer_name="TechCorp Inc",
            currency_code="GBP",
        )
        root = _parse(xml_str)
        monetary = root.find(f"{{{_CAC}}}LegalMonetaryTotal")
        payable = monetary.find(f"{{{_CBC}}}PayableAmount")
        assert payable.get("currencyID") == "GBP"

    def test_issue_date_extracted_from_completed_at(self):
        record = _sample_record(completed_at="2026-04-15T14:30:00Z")
        xml_str = transaction_record_to_ubl_invoice(
            record, seller_name="Acme Corp", buyer_name="TechCorp Inc"
        )
        root = _parse(xml_str)
        issue_date_el = root.find(f"{{{_CBC}}}IssueDate")
        assert issue_date_el is not None
        assert issue_date_el.text == "2026-04-15"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestUBLExportErrors:
    @pytest.mark.parametrize("missing_field", ["session_id", "record_hash", "agreed_terms", "completed_at"])
    def test_value_error_on_missing_required_field(self, missing_field):
        record = _sample_record()
        del record[missing_field]
        with pytest.raises(ValueError, match=missing_field):
            transaction_record_to_ubl_invoice(
                record, seller_name="Acme Corp", buyer_name="TechCorp Inc"
            )

    def test_value_error_on_invalid_currency_code_too_short(self):
        with pytest.raises(ValueError):
            transaction_record_to_ubl_invoice(
                _sample_record(),
                seller_name="Acme Corp",
                buyer_name="TechCorp Inc",
                currency_code="US",
            )

    def test_value_error_on_invalid_currency_code_too_long(self):
        with pytest.raises(ValueError):
            transaction_record_to_ubl_invoice(
                _sample_record(),
                seller_name="Acme Corp",
                buyer_name="TechCorp Inc",
                currency_code="USDX",
            )

    def test_missing_total_value_produces_zero_and_note(self):
        record = _sample_record()
        del record["agreed_terms"]["total_value"]
        xml_str = transaction_record_to_ubl_invoice(
            record, seller_name="Acme Corp", buyer_name="TechCorp Inc"
        )
        root = _parse(xml_str)
        monetary = root.find(f"{{{_CAC}}}LegalMonetaryTotal")
        payable = monetary.find(f"{{{_CBC}}}PayableAmount")
        assert payable.text == "0.00"
        assert "Total value not available" in xml_str

    def test_float_total_value_used_as_is(self):
        record = _sample_record()
        record["agreed_terms"]["total_value"] = 99999.99
        xml_str = transaction_record_to_ubl_invoice(
            record, seller_name="Acme Corp", buyer_name="TechCorp Inc"
        )
        root = _parse(xml_str)
        monetary = root.find(f"{{{_CAC}}}LegalMonetaryTotal")
        payable = monetary.find(f"{{{_CBC}}}PayableAmount")
        assert payable.text == "99999.99"
