/** Tests for UBL 2.1 invoice export from A2CN transaction records. */

import { describe, expect, test } from "vitest";

import { transactionRecordToUblInvoice } from "../src/ubl_export.js";
import type { Dict } from "../src/a2cn/messages.js";

function sampleRecord(
  options: {
    sessionId?: string;
    recordHash?: string;
    totalValue?: number;
    completedAt?: string;
  } = {},
): Dict {
  const {
    sessionId = "sess-abc-123",
    recordHash = "a".repeat(64),
    totalValue = 10_000_000,
    completedAt = "2026-04-01T10:00:00Z",
  } = options;
  return {
    session_id: sessionId,
    record_hash: recordHash,
    agreed_terms: { total_value: totalValue, currency: "USD" },
    completed_at: completedAt,
  };
}

/** Extract the text of the first XML element with the given tag name. */
function elementText(xml: string, tag: string): string | null {
  const match = xml.match(new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`));
  return match ? match[1] : null;
}

/** Extract the inner XML of the first element with the given tag name. */
function elementInner(xml: string, tag: string): string | null {
  const match = xml.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`));
  return match ? match[1] : null;
}

// ---------------------------------------------------------------------------
// Basic output tests
// ---------------------------------------------------------------------------

describe("UBLExportBasic", () => {
  test("valid record produces non empty xml string", () => {
    const xmlStr = transactionRecordToUblInvoice(sampleRecord(), "Acme Corp", "TechCorp Inc");
    expect(typeof xmlStr).toBe("string");
    expect(xmlStr.length).toBeGreaterThan(0);
  });

  test("output is parseable", () => {
    const xmlStr = transactionRecordToUblInvoice(sampleRecord(), "Acme Corp", "TechCorp Inc");
    expect(xmlStr).toContain("<?xml version='1.0' encoding='UTF-8'?>");
    expect(xmlStr).toContain("<Invoice");
    expect(xmlStr).toContain("</Invoice>");
  });

  test("invoice number defaults to session id", () => {
    const record = sampleRecord({ sessionId: "my-session-id" });
    const xmlStr = transactionRecordToUblInvoice(record, "Acme Corp", "TechCorp Inc");
    expect(elementText(xmlStr, "cbc:ID")).toBe("my-session-id");
  });

  test("custom invoice number in id element", () => {
    const xmlStr = transactionRecordToUblInvoice(
      sampleRecord(),
      "Acme Corp",
      "TechCorp Inc",
      "INV-2026-0042",
    );
    expect(elementText(xmlStr, "cbc:ID")).toBe("INV-2026-0042");
  });

  test("record hash in note element", () => {
    const record = sampleRecord({ recordHash: "deadbeef".repeat(8) });
    const xmlStr = transactionRecordToUblInvoice(record, "Acme Corp", "TechCorp Inc");
    expect(xmlStr).toContain("deadbeef".repeat(8));
  });

  test("seller name in supplier party", () => {
    const xmlStr = transactionRecordToUblInvoice(
      sampleRecord(),
      "Acme Supplies Ltd",
      "TechCorp Inc",
    );
    const supplier = elementInner(xmlStr, "cac:AccountingSupplierParty");
    expect(supplier).not.toBeNull();
    expect(elementText(supplier!, "cbc:Name")).toBe("Acme Supplies Ltd");
  });

  test("buyer name in customer party", () => {
    const xmlStr = transactionRecordToUblInvoice(
      sampleRecord(),
      "Acme Corp",
      "Global Procurement Co",
    );
    const customer = elementInner(xmlStr, "cac:AccountingCustomerParty");
    expect(customer).not.toBeNull();
    expect(elementText(customer!, "cbc:Name")).toBe("Global Procurement Co");
  });

  test("total value in payable amount", () => {
    // 10_000_000 cents → $100,000.00
    const xmlStr = transactionRecordToUblInvoice(
      sampleRecord({ totalValue: 10_000_000 }),
      "Acme Corp",
      "TechCorp Inc",
    );
    const monetary = elementInner(xmlStr, "cac:LegalMonetaryTotal");
    expect(monetary).not.toBeNull();
    expect(elementText(monetary!, "cbc:PayableAmount")).toBe("100000.00");
  });

  test("currency code in document currency element", () => {
    const xmlStr = transactionRecordToUblInvoice(
      sampleRecord(),
      "Acme Corp",
      "TechCorp Inc",
      null,
      "EUR",
    );
    expect(elementText(xmlStr, "cbc:DocumentCurrencyCode")).toBe("EUR");
  });

  test("currency code in payable amount attribute", () => {
    const xmlStr = transactionRecordToUblInvoice(
      sampleRecord(),
      "Acme Corp",
      "TechCorp Inc",
      null,
      "GBP",
    );
    expect(xmlStr).toContain('currencyID="GBP"');
  });

  test("issue date extracted from completed at", () => {
    const record = sampleRecord({ completedAt: "2026-04-15T14:30:00Z" });
    const xmlStr = transactionRecordToUblInvoice(record, "Acme Corp", "TechCorp Inc");
    expect(elementText(xmlStr, "cbc:IssueDate")).toBe("2026-04-15");
  });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

describe("UBLExportErrors", () => {
  for (const missingField of ["session_id", "record_hash", "agreed_terms", "completed_at"]) {
    test(`value error on missing required field ${missingField}`, () => {
      const record = sampleRecord();
      delete record[missingField];
      expect(() =>
        transactionRecordToUblInvoice(record, "Acme Corp", "TechCorp Inc"),
      ).toThrow(new RegExp(missingField));
    });
  }

  test("value error on invalid currency code too short", () => {
    expect(() =>
      transactionRecordToUblInvoice(sampleRecord(), "Acme Corp", "TechCorp Inc", null, "US"),
    ).toThrow();
  });

  test("value error on invalid currency code too long", () => {
    expect(() =>
      transactionRecordToUblInvoice(sampleRecord(), "Acme Corp", "TechCorp Inc", null, "USDX"),
    ).toThrow();
  });

  test("missing total value produces zero and note", () => {
    const record = sampleRecord();
    delete (record.agreed_terms as Dict).total_value;
    const xmlStr = transactionRecordToUblInvoice(record, "Acme Corp", "TechCorp Inc");
    const monetary = elementInner(xmlStr, "cac:LegalMonetaryTotal");
    expect(elementText(monetary!, "cbc:PayableAmount")).toBe("0.00");
    expect(xmlStr).toContain("Total value not available");
  });

  test("float total value used as is", () => {
    const record = sampleRecord();
    (record.agreed_terms as Dict).total_value = 99999.99;
    const xmlStr = transactionRecordToUblInvoice(record, "Acme Corp", "TechCorp Inc");
    const monetary = elementInner(xmlStr, "cac:LegalMonetaryTotal");
    expect(elementText(monetary!, "cbc:PayableAmount")).toBe("99999.99");
  });
});
