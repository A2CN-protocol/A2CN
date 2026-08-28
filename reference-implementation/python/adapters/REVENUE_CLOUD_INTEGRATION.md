# Salesforce Revenue Cloud - A2CN Integration Guide

Salesforce Revenue Cloud is a sell-side CPQ and billing platform. This adapter
translates Revenue Cloud Pricing API responses into A2CN terms, and translates
agreed A2CN terms back into Revenue Cloud order payloads.

## Validation status

**Built from:** Salesforce's published Revenue Cloud API documentation (v65.0+),
covering the Pricing API and the QOC sales-transactions endpoint.

**Verified:** Payload translation in both directions against those published
schemas — 7 tests in `tests/test_adapters.py::TestRevenueCloudAdapter`.

**Not verified:** This adapter has not been exercised against a live Salesforce org. Runtime
access requires a Salesforce org with Revenue Cloud provisioned and a connected
app with appropriate scopes, which we do not currently hold. Field names and
response shapes should be confirmed against a live environment before production
use.

If you have access to a live Salesforce Revenue Cloud instance and are willing to validate this
adapter against it, please open an issue — that is the help we most need.

---

## Module

`adapters/revenue_cloud_adapter.py` — pure data translation, no I/O. Every function is
testable offline against fixture payloads.

Entry points: `RevenueCloudAdapter.pricing_response_to_a2cn_terms()` and the
corresponding write-back function.

---

## Scope

This adapter is a translation layer only. It does not perform authentication,
transport, or retry handling; those belong to the calling integration. It
converts platform payloads into A2CN terms and converts agreed A2CN terms back
into platform-shaped payloads.
