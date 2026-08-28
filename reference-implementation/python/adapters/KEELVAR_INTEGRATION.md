# Keelvar Sourcing - A2CN Integration Guide

Keelvar is a buy-side sourcing optimisation platform. This adapter maps Keelvar
`SOURCING_EVENTS_FEED_UPDATED` webhook payloads and sourcing event data into
A2CN `goods_procurement` terms, and maps agreed A2CN terms back into
Keelvar-shaped bid payloads.

## Validation status

**Built from:** Keelvar's published documentation at `docs.keelvar.app`, covering the
webhooks endpoint, the sourcing-events endpoint and the bids endpoint. The
full field-by-field mapping is documented in the module docstring.

**Verified:** Payload translation in both directions against those published
schemas — 17 tests in `tests/test_adapters.py::TestKeelvarAdapter`.

**Not verified:** This adapter has not been exercised against a live Keelvar instance. Runtime
access requires Keelvar API credentials, which we do not currently hold. Field
names and response shapes should be confirmed against a live environment before
production use.

If you have access to a live Keelvar instance and are willing to validate this
adapter against it, please open an issue — that is the help we most need.

---

## Module

`adapters/keelvar_adapter.py` — pure data translation, no I/O. Every function is
testable offline against fixture payloads.

Entry points: sourcing-event and bid translation functions; see the
module docstring for the complete Keelvar → A2CN field mapping table.

---

## Scope

This adapter is a translation layer only. It does not perform authentication,
transport, or retry handling; those belong to the calling integration. It
converts platform payloads into A2CN terms and converts agreed A2CN terms back
into platform-shaped payloads.
