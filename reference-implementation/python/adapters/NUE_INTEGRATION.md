# Nue.io Revenue Lifecycle — A2CN Integration Guide

Nue.io is a seller-side CPQ and billing platform for SaaS companies,
Salesforce-native with a REST API layer. This adapter translates Nue
pricing and subscription data into A2CN session terms, and translates
A2CN agreed terms back into Nue order creation.

## Validation status

**Built from:** Nue.io's published REST API documentation and API conventions.

**Verified:** Payload translation in both directions against those published
schemas — 26 tests in `tests/test_nue_adapter.py`.

**Not verified:** This adapter has not been exercised against a live Nue.io sandbox or production
org. Runtime access requires the credentials listed under Environment Variables
below. Some response shapes are auto-detected rather than confirmed — see
Limitations — and should be verified against a live environment before production
use.

If you have access to a live Nue.io instance and are willing to validate this
adapter against it, please open an issue — that is the help we most need.

---

---

## Prerequisites

- A Nue.io account with API access
- An API key from your Nue administrator
- Access to the Nue production or sandbox environment

---

## Environment Variables

| Variable        | Description                                                        |
|-----------------|--------------------------------------------------------------------|
| `NUE_API_KEY`   | API key from Nue administrator                                     |
| `NUE_BASE_URL`  | `https://api.nue.io` (production) or `https://api.sandbox.nue.io` |

---

## Primary Flow — Pricing → Mandate Bounds → A2CN → Order

```
1. NueEventParser.fetch_pricing(price_book_id, product_id)
       → GET /commerce/pricing from Nue
       ↓
2. NueEventParser.pricing_to_mandate_bounds(pricing_response)
       → returns ceiling_value_cents, floor_value_cents, currency
       → use to configure A2CN agent mandate
       ↓
3. A2CN negotiation session — buyer and seller agents negotiate
       ↓
4. On COMPLETED: NueEventParser.a2cn_terms_to_nue_order(
       agreed_terms, customer_id, price_book_id, product_id,
       a2cn_session_id, record_hash
   )
       → POST /orders to Nue
       → Nue order created with A2CN audit trail in externalReference and notes
```

---

## Renewal Flow — Subscription → Renewal Terms → A2CN

```
1. NueEventParser.fetch_customer_subscriptions(customer_id)
       → GET /subscriptions?customerId={id} from Nue
       → returns list of active subscription dicts
       ↓
2. NueEventParser.subscription_to_renewal_terms(subscription_response)
       → returns A2CN saas_renewal terms with renewal markup applied
       → seat_count, subscription_tier, auto_renew_terms, term_months
       ↓
3. A2CN saas_renewal session — negotiate renewal price and terms
       ↓
4. On COMPLETED: NueEventParser.a2cn_terms_to_nue_order(...)
       → creates renewed Nue order
```

---

## Audit Trail

The `a2cn_terms_to_nue_order` method embeds the A2CN audit trail in every
Nue order:

- `externalReference`: `"a2cn-session-{a2cn_session_id}"` — links the Nue
  order to the A2CN session in both systems.
- `notes`: `"Agreed via A2CN. Record hash: {record_hash}"` — the record
  hash is the content-addressed, dual-signed A2CN transaction record. This
  is the cryptographic proof of agreement.

These two fields create an immutable, auditable link between the Nue order
and the A2CN transaction record. Retain both the record hash and session ID
in your system of record.

---

## Floor Discount Configuration

`floor_discount_pct` in `pricing_to_mandate_bounds` represents the maximum
discount the seller's agent is authorised to offer without human approval.
Configure per product tier in production:

```python
# Standard tier: 10% max discount
std_bounds = NueEventParser.pricing_to_mandate_bounds(pricing, floor_discount_pct=0.10)

# Enterprise tier: 20% max discount (higher authorisation level)
ent_bounds = NueEventParser.pricing_to_mandate_bounds(pricing, floor_discount_pct=0.20)
```

---

## Known Limitations

- **Field names**: Nue API response field names (`listPrice`, `totalValue`,
  `productTier`, `autoRenew`, `termMonths`, etc.) are based on public
  documentation and API conventions. Verify against a live Nue sandbox
  instance before production deployment. Contact Nue support for exact names.
- **Pricing endpoint**: The Commerce Pricing API path (`/commerce/pricing`)
  and its parameters should be confirmed against the latest Nue API docs.
- **Subscription list key**: The top-level key in the subscriptions response
  (`subscriptions` or `items`) is auto-detected; verify against sandbox.
- **Async HTTP**: The HTTP methods use synchronous `httpx`. Wrap in
  `asyncio.to_thread()` or use `httpx.AsyncClient` if your server is
  fully async.
