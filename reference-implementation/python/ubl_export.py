"""
UBL 2.1 invoice export from A2CN transaction records.

UBL 2.1 (Universal Business Language) is the ISO/OASIS standard for
electronic business documents. It is the native document format for
SAP, Oracle Financials, Microsoft Dynamics 365, and most enterprise
ERP systems. Generating UBL from A2CN transaction records enables
direct ERP integration from completed negotiations.

The A2CN transaction record hash is embedded in the UBL Note element,
creating a permanent audit link between the ERP invoice and the
negotiation record. This supports EU AI Act traceability requirements
and enterprise audit workflows.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import io

_INV = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
_CAC = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
_CBC = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"

ET.register_namespace("", _INV)
ET.register_namespace("cac", _CAC)
ET.register_namespace("cbc", _CBC)

_REQUIRED_FIELDS = ("session_id", "record_hash", "agreed_terms", "completed_at")


def transaction_record_to_ubl_invoice(
    transaction_record: dict,
    seller_name: str,
    buyer_name: str,
    invoice_number: str | None = None,
    currency_code: str = "USD",
) -> str:
    """
    Generate a UBL 2.1 Invoice XML document from an A2CN transaction record.

    The A2CN transaction record hash is embedded in the UBL Note element,
    creating a permanent audit link between the ERP invoice and the
    negotiation record.

    Args:
        transaction_record: Completed A2CN transaction record dict.
                           Must contain: session_id, record_hash,
                           agreed_terms, completed_at.
        seller_name: Legal name of the selling organization.
        buyer_name: Legal name of the buying organization.
        invoice_number: Invoice identifier. Defaults to session_id.
        currency_code: ISO 4217 currency code. Defaults to "USD".

    Returns:
        UBL 2.1 compliant Invoice XML as a UTF-8 string.

    Raises:
        ValueError: If transaction_record is missing required fields.
        ValueError: If currency_code is not a 3-character string.
    """
    for field in _REQUIRED_FIELDS:
        if field not in transaction_record:
            raise ValueError(f"transaction_record missing required field: {field!r}")

    if not isinstance(currency_code, str) or len(currency_code) != 3:
        raise ValueError(
            f"currency_code must be a 3-character ISO 4217 string, got {currency_code!r}"
        )

    inv_number = invoice_number or transaction_record["session_id"]
    record_hash = transaction_record["record_hash"]

    # Take only the date portion (YYYY-MM-DD) from completed_at
    issue_date = transaction_record["completed_at"][:10]

    # Extract and format total_value
    agreed_terms = transaction_record.get("agreed_terms", {})
    total_value = agreed_terms.get("total_value")
    missing_total = total_value is None
    if missing_total:
        payable_amount = "0.00"
    elif isinstance(total_value, int):
        payable_amount = f"{total_value / 100:.2f}"
    else:
        payable_amount = f"{float(total_value):.2f}"

    # Build XML tree
    root = ET.Element(f"{{{_INV}}}Invoice")

    ET.SubElement(root, f"{{{_CBC}}}UBLVersionID").text = "2.1"
    ET.SubElement(root, f"{{{_CBC}}}ID").text = inv_number
    ET.SubElement(root, f"{{{_CBC}}}IssueDate").text = issue_date
    ET.SubElement(root, f"{{{_CBC}}}Note").text = (
        f"A2CN Transaction Record Hash: {record_hash}"
    )
    if missing_total:
        ET.SubElement(root, f"{{{_CBC}}}Note").text = (
            "Total value not available in transaction record."
        )
    ET.SubElement(root, f"{{{_CBC}}}DocumentCurrencyCode").text = currency_code

    # Accounting Supplier Party (seller)
    supplier_party_el = ET.SubElement(root, f"{{{_CAC}}}AccountingSupplierParty")
    supplier_party_inner = ET.SubElement(supplier_party_el, f"{{{_CAC}}}Party")
    supplier_name_el = ET.SubElement(supplier_party_inner, f"{{{_CAC}}}PartyName")
    ET.SubElement(supplier_name_el, f"{{{_CBC}}}Name").text = seller_name

    # Accounting Customer Party (buyer)
    customer_party_el = ET.SubElement(root, f"{{{_CAC}}}AccountingCustomerParty")
    customer_party_inner = ET.SubElement(customer_party_el, f"{{{_CAC}}}Party")
    customer_name_el = ET.SubElement(customer_party_inner, f"{{{_CAC}}}PartyName")
    ET.SubElement(customer_name_el, f"{{{_CBC}}}Name").text = buyer_name

    # Legal Monetary Total
    monetary_total_el = ET.SubElement(root, f"{{{_CAC}}}LegalMonetaryTotal")
    payable_el = ET.SubElement(monetary_total_el, f"{{{_CBC}}}PayableAmount")
    payable_el.set("currencyID", currency_code)
    payable_el.text = payable_amount

    ET.indent(root)
    buf = io.BytesIO()
    ET.ElementTree(root).write(buf, xml_declaration=True, encoding="UTF-8")
    return buf.getvalue().decode("utf-8")
