# A2CN Conformance Fixtures

These fixtures capture proposed edge-case scenarios for implementers and future
conformance runners. Each file describes the setup, stimulus, and expected
protocol outcome without requiring every scenario to be executable in the current
Python reference test harness.

Status values:

- `active`: expected behavior is normative for the current protocol surface.
- `known_gap`: fixture documents a gap or future extension path that should not
  silently pass as conformant behavior, including a scenario that asserts a check the
  current reference servers do not perform.

## Fixtures

| Fixture | Status | Expected outcome |
|---------|--------|------------------|
| `session_mandate_expired_at_act_time` | `known_gap` | Documented gap: the sender's session mandate is validated only at session initiation, not re-checked per act or at commit |
| `hitl_threshold_crossing` | `active` | Enter `AWAITING_HUMAN_APPROVAL` |
| `counterparty_outside_allowed_list` | `known_gap` | Documented gap: declared mandates define no counterparty allow-list; not enforced |
| `payment_terms_drift_mid_negotiation` | `known_gap` | Documented gap: no payment-term bound is a mandate field; not enforced |
| `partial_acceptance_unresolved_constraint` | `known_gap` | Partial acceptance is not a v0.2 message type |
| `reputation_score_cannot_expand_authority` | `active` | Mandate remains the authority boundary |
| `offer_basis_diverges_from_session` | `active` | Reject an offer whose `terms.basis` differs from the session basis with `SESSION_PARAM_CHANGED` |
| `offer_currency_diverges_from_session` | `active` | Reject an offer whose `terms.currency` differs from the session currency with `SESSION_PARAM_CHANGED` |
| `offer_line_item_uses_bare_money_key` | `active` | Reject an offer whose line item states money as the bare `unit_price` / `total` instead of `unit_price_minor` / `total_minor`, with `INVALID_LINE_ITEM` |
