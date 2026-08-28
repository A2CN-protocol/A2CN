# Fairmarkit - A2CN Integration Guide

Fairmarkit is a buy-side sourcing and tail-spend platform. This adapter maps
Fairmarkit webhook payloads and API responses into A2CN message structures, and
maps agreed A2CN terms back into Fairmarkit-shaped payloads.

## Validation status

**Built from:** Fairmarkit's published webhooks documentation and the self-service
responses API (`GET /self-service/api/v3/responses/request/{request_id}/`).

**Verified:** Payload translation in both directions against those published
schemas — 10 tests in `tests/test_adapters.py::TestFairmakitAdapter`.

**Not verified:** This adapter has not been exercised against a live Fairmarkit instance. Runtime
access requires Fairmarkit API credentials, which we do not currently hold.
Field names and response shapes should be confirmed against a live environment
before production use.

If you have access to a live Fairmarkit instance and are willing to validate this
adapter against it, please open an issue — that is the help we most need.

---

## Module

`adapters/fairmarkit_adapter.py` — pure data translation, no I/O. Every function is
testable offline against fixture payloads.

Entry points: `FairmakitEventParser.parse_bid_created_webhook()` and related
parsers. Note the class name is spelled `Fairmakit` — a typo retained here for
accuracy; see the open issue on renaming.

---

## Scope

This adapter is a translation layer only. It does not perform authentication,
transport, or retry handling; those belong to the calling integration. It
converts platform payloads into A2CN terms and converts agreed A2CN terms back
into platform-shaped payloads.
