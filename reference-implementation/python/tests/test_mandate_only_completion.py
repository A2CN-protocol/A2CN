"""Mandate-only completion: a verified counterparty whose acts are unsigned (Section 9A.12).

A counterparty can hold a resolvable DID and a mandate that verifies, and still
never sign a negotiation act. Such a responder is a DID-bearing full party, not
an ``observed_party`` -- ``_observed_party_shape_valid`` requires the three
declared-markers to be literally ``False`` -- and with its acts unsigned there is
no bilateral TransactionRecord either. Before this change such a session had no
honest ``COMPLETED`` shape at all: the external-channel witness was gated on an
``observed_party`` responder at ``unilateral``, which is an IDENTITY PROXY
narrower than the property that gate exists to protect.

THE PROPERTY, stated rather than proxied: *no counterparty signature witnesses
the completion*. It is enforced by ``_completion_witness_holds`` together with
the exactly-one-witness rule, both untouched here, and it holds for a verified
full party exactly as it holds for a no-DID one. This file pins the relaxation
to that property and to nothing wider.

WHAT MUST NOT MOVE, asserted here rather than assumed: the counterparty's acts
stay ``unsigned_observation`` (no attribution inflation), a record still carries
exactly one witness, and a ``transaction_record_hash`` still requires a
DID-bearing responder. The Tier-0 no-DID record is covered too, because a
relaxation can widen past its target and nothing else would notice.
"""

from __future__ import annotations

import copy

import pytest

from a2cn.evidence import (
    assess_session_evidence_record,
    generate_transaction_record,
    verify_session_evidence_record,
)
from a2cn.session import SessionState
from tests.test_evidence import (
    EXTERNAL_COMMITMENT_REFERENCE,
    INITIATOR_DID,
    OBSERVED_RESPONDER,
    RESPONDER_DID,
    _external_channel_record,
    _generate,
    _make_identity_light_session,
    _make_session,
    _mark_completed_externally,
    _observed_quote,
    _offer,
    _reseal,
)


def _mandate_only_session():
    """A session whose responder holds a DID and a mandate but signed nothing.

    The responder is the ordinary DID-bearing party of ``_make_session``; what
    makes the session mandate-only is that the only signed act is the
    initiator's own. Nothing about the responder's identity is weakened, which
    is the whole point: this is the tier an ``observed_party`` cannot express.
    """
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_completed_externally(session)
    return session, did_documents


def _mandate_only_record(*, sender_did: str | None = RESPONDER_DID, **kwargs):
    """Both levels are admitted; the default is the a2cn-natural construction.

    A mandate-only counterparty holds a resolvable DID. Whether the record is
    ``mixed`` or ``unilateral`` depends on how the producer projects the act,
    and BOTH are honest:

    * carrying the counterparty's verified DID on an act attributed
      ``unsigned_observation`` -- two represented parties, so ``mixed``. This
      is the default here, and what an act arriving over the A2CN wire looks
      like.
    * recording no ``sender_did`` at all -- one represented party, so
      ``unilateral``. Today's buyer does this by construction.

    Admitting only one of them would make a producer choose its classification
    over its evidence, which is the defect this story exists to remove.
    """
    session, did_documents = _mandate_only_session()
    kwargs.setdefault("external_commitment_reference", EXTERNAL_COMMITMENT_REFERENCE)
    record = _generate(session, [_observed_quote(sender_did=sender_did)], **kwargs)
    return record, did_documents


# ---------------------------------------------------------------------------
# The positive: the shape that had no representation before
# ---------------------------------------------------------------------------


def test_a_mandate_only_completed_record_verifies():
    """Row 1: verified identity, unsigned acts, external witness, COMPLETED."""
    record, did_documents = _mandate_only_record()

    # Preconditions, asserted rather than assumed: acceptance below means
    # nothing unless this really is the mandate-only shape.
    responder = record["parties"]["responder"]
    assert responder["did"] == RESPONDER_DID, "the responder must be DID-bearing"
    assert "identity_source" not in responder, "a full party, not an observed_party"
    assert record["terminal"]["outcome"] == SessionState.COMPLETED
    assert record["transaction_record_hash"] is None
    assert record["external_commitment_reference"] == EXTERNAL_COMMITMENT_REFERENCE

    assert record["record_version"] == "0.5"
    assert record["evidence_level"] == "mixed"
    assert verify_session_evidence_record(record, did_documents)


def test_the_counterparty_act_of_a_mandate_only_record_stays_unsigned():
    """No attribution inflation: a verified DID does not sign an act for its holder.

    The counterparty's identity verifies; its ACTS do not. Recording the act as
    anything but an unsigned observation would attribute to the counterparty a
    commitment it never made, which is the hazard a mandate-only tier exists to
    avoid rather than to introduce.
    """
    record, did_documents = _mandate_only_record()

    attributions = {entry["message_type"]: entry["attribution"] for entry in record["acts"]}
    assert attributions == {
        "offer": "verified_signature",
        "counteroffer": "unsigned_observation",
    }
    assert assess_session_evidence_record(record, did_documents) == {
        "valid": True,
        "evidence_level": "mixed",
        "verified_acts": 1,
        "unsigned_acts": 1,
        "invalid_acts": 0,
    }


def test_a_mandate_only_completion_whose_counterparty_act_carries_no_did_is_unilateral():
    """The cross-product cell a `mixed`-only test would leave unexercised.

    A producer may record the counterparty's act without a ``sender_did`` -- an
    act observed through a channel that carried no identity, which is what
    today's buyer emits by construction. The classifier then counts one
    represented party, not two, and returns ``unilateral`` rather than
    ``mixed``. So the widening is load-bearing for a FULL-PARTY responder at
    ``unilateral`` too, not merely carrying the Tier-0 case along: a relaxation
    admitting only ``mixed`` would refuse this record, and no test that
    exercised ``mixed`` alone would notice.

    Its sibling above is the same shape with the DID present. The two together
    are what pin that BOTH projections are admitted -- neither alone
    distinguishes "this level is what the producer happens to emit" from "this
    level is what the rule requires".

    HISTORY, because a later reader will be tempted to narrow this again. A
    narrower rule was drafted and briefly held: ``evidence_level`` unchanged at
    ``unilateral``, on the measured ground that today's buyer records
    counterparty acts with no ``sender_did`` and so never produces ``mixed``.
    THE MEASUREMENT WAS CORRECT AND THE RULE BUILT ON IT WAS STILL WRONG. It
    would have obliged a producer to omit a DID it had verified -- to record
    less than it knows in order to reach an admitted classification -- which is
    the same defect, one level up, that widening the responder condition
    removes. It would also have pinned the spec to a producer behaviour already
    logged as an open item, so the day that projection changed, every record
    that producer emitted would have stopped being emittable.

    Admitting both levels is also the only option that does not silently settle
    a separate question: whether an act's SENDER and its SIGNER should be the
    same field at all. Attaching a DID to an act nobody signed really is
    attribution inflation, and a missing ``sender_did`` really may be the honest
    projection given no signature. The spec declines to force either, and leaves
    that to the change that should decide it.
    """
    record, did_documents = _mandate_only_record(sender_did=None)

    assert record["parties"]["responder"]["did"] == RESPONDER_DID
    assert record["evidence_level"] == "unilateral"
    assert verify_session_evidence_record(record, did_documents)


def test_the_generator_witnesses_a_mandate_only_completion_with_the_reference_alone():
    """No TransactionRecord is generated, because the counterparty signed nothing.

    The session's responder is DID-bearing, which before this change was the
    generator's test for "completes with a TransactionRecord". That test was
    wrong for this tier: a TransactionRecord needs the counterparty's signed
    acceptance, which a mandate-only session does not have.
    """
    session, _did_documents = _mandate_only_session()
    with pytest.raises(ValueError):
        generate_transaction_record(session)

    record, _ = _mandate_only_record()

    assert record["transaction_record_hash"] is None
    assert "external_commitment_reference" in record


# ---------------------------------------------------------------------------
# The negatives that must still refuse
# ---------------------------------------------------------------------------


def test_a_mandate_only_completed_record_carrying_both_witnesses_is_refused():
    """Row 2a. The exactly-one-witness rule is untouched by the relaxation."""
    healthy, did_documents = _mandate_only_record()
    assert verify_session_evidence_record(healthy, did_documents)
    # The reseal helper must itself produce a verifiable record, or the refusal
    # below would prove only that resealing is broken.
    assert verify_session_evidence_record(_reseal(copy.deepcopy(healthy)), did_documents)

    both = copy.deepcopy(healthy)
    both["transaction_record_hash"] = "A" * 43
    _reseal(both)

    assert both["transaction_record_hash"] is not None
    assert "external_commitment_reference" in both
    assert not verify_session_evidence_record(both, did_documents)


def test_a_mandate_only_completed_record_carrying_neither_witness_is_refused():
    """Row 2b."""
    healthy, did_documents = _mandate_only_record()

    neither = copy.deepcopy(healthy)
    del neither["external_commitment_reference"]
    _reseal(neither)

    assert neither["transaction_record_hash"] is None
    assert "external_commitment_reference" not in neither
    assert not verify_session_evidence_record(neither, did_documents)


def test_a_mandate_only_completion_with_no_producer_signed_act_is_refused():
    """Rows 2c and 5: the external witness needs a producer-signed act.

    With no signed act of the producer's own, nothing in the record is
    attributable to any party and the seal alone would carry the COMPLETED
    claim. The relaxation widens WHO the responder may be; it does not weaken
    what the producer must have signed, and it does not touch
    ``evidence_level``.
    """
    healthy, did_documents = _mandate_only_record()

    act_less = copy.deepcopy(healthy)
    act_less["acts"] = [
        entry for entry in act_less["acts"] if entry["attribution"] != "verified_signature"
    ]
    _reseal(act_less)

    # The semantic precondition: this record really does carry acts, and none of
    # them is signed. An empty acts list would satisfy the rule vacuously and
    # prove nothing about the guard.
    assert act_less["acts"], "a record with no acts would refuse for a different reason"
    assert all(entry["attribution"] != "verified_signature" for entry in act_less["acts"])
    assert not verify_session_evidence_record(act_less, did_documents)


def test_stamping_a_verified_signature_on_an_unsigned_counterparty_act_is_refused():
    """Row 7: the presence-versus-verification hazard, at the tier that invites it.

    A mandate-only counterparty HAS a resolvable key, which is exactly what
    makes this the place someone would be tempted to relabel its unsigned act as
    verified. The record must be refused rather than downgraded.
    """
    healthy, did_documents = _mandate_only_record()

    inflated = copy.deepcopy(healthy)
    counterparty = next(
        entry for entry in inflated["acts"] if entry["attribution"] == "unsigned_observation"
    )
    counterparty["attribution"] = "verified_signature"
    _reseal(inflated)

    assert counterparty["signature"] is None, "nobody signed it; only the label moved"
    assert not verify_session_evidence_record(inflated, did_documents)


def test_a_transaction_record_hash_still_requires_a_did_bearing_responder():
    """Row 2d: the `allOf[2]` direction, which this change does not touch."""
    healthy, did_documents = _external_channel_record()

    claimed = copy.deepcopy(healthy)
    claimed["transaction_record_hash"] = "A" * 43
    del claimed["external_commitment_reference"]
    _reseal(claimed)

    assert "identity_source" in claimed["parties"]["responder"], "responder is observed"
    assert not verify_session_evidence_record(claimed, did_documents)


# ---------------------------------------------------------------------------
# Tier 0 and Tier 2, unchanged
# ---------------------------------------------------------------------------


def test_the_no_did_external_channel_record_is_unchanged():
    """Row 6: the relaxation admits a new shape without altering the old one."""
    record, did_documents = _external_channel_record()

    assert record["parties"]["responder"]["did_declared"] is False
    assert record["evidence_level"] == "unilateral"
    assert record["transaction_record_hash"] is None
    assert verify_session_evidence_record(record, did_documents)


def test_an_observed_responder_still_requires_the_reference_to_complete():
    """The generator's other direction: an observed responder has no TransactionRecord.

    The session must be the identity-light one. Passing ``observed_responder``
    for a session whose responder declared a DID is refused earlier and for a
    different reason -- "Responder declared a DID; it is not an observed party"
    -- which is a guard this change does not touch. Built on the wrong session
    this test passed while exercising nothing it claims to.
    """
    manager, session, _did_documents = _make_identity_light_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_completed_externally(session)

    # Pinned to the message, not merely to ValueError: the generator raises for
    # several distinct reasons here, and a bare raises() would pass through
    # whichever guard happened to fire first -- which is how this test passed
    # before the relaxation, via a guard that no longer exists.
    with pytest.raises(ValueError, match="requires external_commitment_reference"):
        _generate(session, [_observed_quote()], observed_responder=OBSERVED_RESPONDER)


def test_a_reference_is_still_refused_for_a_non_completed_outcome():
    """The witness rule is about COMPLETED alone, at every responder shape."""
    manager, session, _did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    session.state = SessionState.WITHDRAWN
    session.current_turn = "none"
    session.terminal_message_id = None
    session.state_updated_at = "2026-03-24T10:10:00Z"

    with pytest.raises(ValueError, match="only for a COMPLETED session"):
        _generate(
            session,
            [_observed_quote()],
            external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
        )


def test_the_producer_still_seals_a_mandate_only_record_as_initiator():
    """The seal is the only cryptographic evidence, so it must be the initiator's."""
    record, _did_documents = _mandate_only_record()

    assert record["producer"]["did"] == INITIATOR_DID
    assert record["parties"]["initiator"]["did"] == INITIATOR_DID
