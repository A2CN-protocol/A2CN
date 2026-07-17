/**
 * Salesforce Revenue Cloud → A2CN translation layer.
 *
 * Translates Revenue Cloud Pricing API responses into A2CN terms,
 * and translates A2CN agreed terms back into Revenue Cloud order payloads.
 *
 * No I/O in this module — pure data translation, fully testable offline.
 *
 * Revenue Cloud API reference (v65.0+):
 *   Pricing: POST /services/data/v65.0/connect/pricing/...
 *   Quote/Order: POST /services/data/v65.0/connect/qoc/sales-transactions
 */

import type { Dict } from "../a2cn/messages.js";

export class RevenueCloudAdapter {
  /**
   * Translate a Salesforce Revenue Cloud Pricing API response into
   * A2CN terms suitable for an offer message.
   *
   * Revenue Cloud Pricing API response fields:
   *   lineItems: list of {productId, productName, quantity, unitPrice,
   *                        totalPrice, discountPercent, startDate, endDate}
   *   totalAmount (decimal dollars)
   *   currency
   *
   * For saas_renewal, extracts seat_count from quantity of first line item.
   * All prices converted from dollars to cents (A2CN integer format).
   */
  static pricingResponseToA2cnTerms(
    pricingResponse: Dict,
    dealType = "saas_renewal",
    currency = "USD",
  ): Dict {
    const lineItemsRaw = (pricingResponse.lineItems as Dict[]) ?? [];
    const lineItems: Dict[] = [];
    let totalCents = 0;

    for (const item of lineItemsRaw) {
      const unitPriceCents = Math.trunc(Number(item.unitPrice ?? 0) * 100);
      const totalPriceCents = Math.trunc(Number(item.totalPrice ?? 0) * 100);
      totalCents += totalPriceCents;

      lineItems.push({
        description: item.productName ?? "",
        quantity: Math.trunc(Number(item.quantity ?? 1)),
        unit_price: unitPriceCents,
        total: totalPriceCents,
      });
    }

    const terms: Dict = {
      total_value: totalCents || Math.trunc(Number(pricingResponse.totalAmount ?? 0) * 100),
      currency: pricingResponse.currency ?? currency,
      line_items: lineItems,
      payment_terms: { net_days: 30 },
    };

    // Contract duration from first line item dates
    if (lineItemsRaw.length > 0) {
      const firstItem = lineItemsRaw[0];
      if (firstItem.startDate && firstItem.endDate) {
        terms.contract_duration = {
          start_date: firstItem.startDate,
          end_date: firstItem.endDate,
        };
      }
    }

    // saas_renewal extensions
    if (dealType === "saas_renewal" && lineItemsRaw.length > 0) {
      terms.seat_count = Math.trunc(Number(lineItemsRaw[0].quantity ?? 1));
    }

    return terms;
  }

  /**
   * Translate A2CN terms into a Salesforce Revenue Cloud sales transaction
   * payload for quote or order creation.
   *
   * POST /services/data/v65.0/connect/qoc/sales-transactions
   * {transactionType, accountId, pricebookId, lineItems}
   *
   * Use transactionType="Order" when converting an agreed A2CN transaction
   * record into a Revenue Cloud order.
   */
  static a2cnTermsToQuotePayload(
    terms: Dict,
    accountId: string,
    pricebookId: string,
    transactionType = "Quote",
  ): Dict {
    const lineItemsRaw = (terms.line_items as Dict[]) ?? [];
    const rcLineItems: Dict[] = [];

    for (const item of lineItemsRaw) {
      rcLineItems.push({
        quantity: item.quantity ?? 1,
        unitPrice: ((item.unit_price as number) ?? 0) / 100.0,
        // productId would need to be resolved from description
        // in a real integration — omitting here for prototype
      });
    }

    const payload: Dict = {
      transactionType,
      accountId,
      pricebookId,
      lineItems: rcLineItems,
      currencyIsoCode: terms.currency ?? "USD",
    };

    const duration = (terms.contract_duration as Dict) ?? {};
    if (duration.start_date) {
      payload.startDate = duration.start_date;
    }
    if (duration.end_date) {
      payload.endDate = duration.end_date;
    }

    return payload;
  }

  /**
   * Convenience wrapper: translate A2CN agreed_terms from a completed
   * transaction record into a Revenue Cloud order payload.
   *
   *   transaction_record.agreed_terms → Revenue Cloud Order
   */
  static a2cnTermsToOrderPayload(agreedTerms: Dict, accountId: string, pricebookId: string): Dict {
    return RevenueCloudAdapter.a2cnTermsToQuotePayload(agreedTerms, accountId, pricebookId, "Order");
  }
}
