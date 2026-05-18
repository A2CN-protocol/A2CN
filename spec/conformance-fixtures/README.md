# A2CN Conformance Fixtures

These fixtures capture proposed edge-case scenarios for implementers and future
conformance runners. Each file describes the setup, stimulus, and expected
protocol outcome without requiring every scenario to be executable in the current
Python reference test harness.

Status values:

- `active`: expected behavior is normative for the current protocol surface.
- `known_gap`: fixture documents a gap or future extension path that should not
  silently pass as conformant behavior.

## Fixtures

| Fixture | Status | Expected outcome |
|---------|--------|------------------|
| `expired_mandate_on_offer_reference` | `active` | Reject offer referencing an expired mandate |
| `hitl_threshold_crossing` | `active` | Enter `AWAITING_HUMAN_APPROVAL` |
| `counterparty_outside_allowed_list` | `active` | Reject session initiation |
| `payment_terms_drift_mid_negotiation` | `active` | Reject counteroffer outside mandate bounds |
| `partial_acceptance_unresolved_constraint` | `known_gap` | Partial acceptance is not a v0.2 message type |
| `reputation_score_cannot_expand_authority` | `active` | Mandate remains the authority boundary |
