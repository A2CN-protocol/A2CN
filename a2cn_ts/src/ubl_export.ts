/**
 * UBL 2.1 invoice export from A2CN transaction records.
 *
 * UBL 2.1 (Universal Business Language) is the ISO/OASIS standard for
 * electronic business documents. It is the native document format for
 * SAP, Oracle Financials, Microsoft Dynamics 365, and most enterprise
 * ERP systems. Generating UBL from A2CN transaction records enables
 * direct ERP integration from completed negotiations.
 *
 * The A2CN transaction record hash is embedded in the UBL Note element,
 * creating a permanent audit link between the ERP invoice and the
 * negotiation record. This supports EU AI Act traceability requirements
 * and enterprise audit workflows.
 */

import type { Dict } from "./a2cn/messages.js";

export const UBL_INV_NS = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2";
export const UBL_CAC_NS = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";
export const UBL_CBC_NS = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";

const REQUIRED_FIELDS = ["session_id", "record_hash", "agreed_terms", "completed_at"];

function escapeXml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

/**
 * Generate a UBL 2.1 Invoice XML document from an A2CN transaction record.
 *
 * The A2CN transaction record hash is embedded in the UBL Note element,
 * creating a permanent audit link between the ERP invoice and the
 * negotiation record.
 *
 * Throws Error if the transaction record is missing required fields or if
 * currencyCode is not a 3-character string.
 */
export function transactionRecordToUblInvoice(
  transactionRecord: Dict,
  sellerName: string,
  buyerName: string,
  invoiceNumber: string | null = null,
  currencyCode = "USD",
): string {
  for (const field of REQUIRED_FIELDS) {
    if (!(field in transactionRecord)) {
      throw new Error(`transaction_record missing required field: '${field}'`);
    }
  }

  if (typeof currencyCode !== "string" || currencyCode.length !== 3) {
    throw new Error(
      `currency_code must be a 3-character ISO 4217 string, got ${JSON.stringify(currencyCode)}`,
    );
  }

  const invNumber = invoiceNumber ?? (transactionRecord.session_id as string);
  const recordHash = transactionRecord.record_hash as string;

  // Take only the date portion (YYYY-MM-DD) from completed_at
  const issueDate = (transactionRecord.completed_at as string).slice(0, 10);

  // Extract and format total_value
  const agreedTerms = (transactionRecord.agreed_terms as Dict) ?? {};
  const totalValue = agreedTerms.total_value;
  const missingTotal = totalValue === null || totalValue === undefined;
  let payableAmount: string;
  if (missingTotal) {
    payableAmount = "0.00";
  } else if (typeof totalValue === "number" && Number.isInteger(totalValue)) {
    payableAmount = (totalValue / 100).toFixed(2);
  } else {
    payableAmount = Number(totalValue).toFixed(2);
  }

  const lines: string[] = [];
  lines.push(`<?xml version='1.0' encoding='UTF-8'?>`);
  lines.push(
    `<Invoice xmlns="${UBL_INV_NS}" xmlns:cac="${UBL_CAC_NS}" xmlns:cbc="${UBL_CBC_NS}">`,
  );
  lines.push(`  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>`);
  lines.push(`  <cbc:ID>${escapeXml(invNumber)}</cbc:ID>`);
  lines.push(`  <cbc:IssueDate>${escapeXml(issueDate)}</cbc:IssueDate>`);
  lines.push(`  <cbc:Note>A2CN Transaction Record Hash: ${escapeXml(recordHash)}</cbc:Note>`);
  if (missingTotal) {
    lines.push(`  <cbc:Note>Total value not available in transaction record.</cbc:Note>`);
  }
  lines.push(`  <cbc:DocumentCurrencyCode>${escapeXml(currencyCode)}</cbc:DocumentCurrencyCode>`);
  lines.push(`  <cac:AccountingSupplierParty>`);
  lines.push(`    <cac:Party>`);
  lines.push(`      <cac:PartyName>`);
  lines.push(`        <cbc:Name>${escapeXml(sellerName)}</cbc:Name>`);
  lines.push(`      </cac:PartyName>`);
  lines.push(`    </cac:Party>`);
  lines.push(`  </cac:AccountingSupplierParty>`);
  lines.push(`  <cac:AccountingCustomerParty>`);
  lines.push(`    <cac:Party>`);
  lines.push(`      <cac:PartyName>`);
  lines.push(`        <cbc:Name>${escapeXml(buyerName)}</cbc:Name>`);
  lines.push(`      </cac:PartyName>`);
  lines.push(`    </cac:Party>`);
  lines.push(`  </cac:AccountingCustomerParty>`);
  lines.push(`  <cac:LegalMonetaryTotal>`);
  lines.push(
    `    <cbc:PayableAmount currencyID="${escapeXml(currencyCode)}">${payableAmount}</cbc:PayableAmount>`,
  );
  lines.push(`  </cac:LegalMonetaryTotal>`);
  lines.push(`</Invoice>`);
  return lines.join("\n");
}
