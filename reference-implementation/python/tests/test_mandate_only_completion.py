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
the completion*. It holds for a verified full party exactly as it holds for a
no-DID one, and this file pins the relaxation to that property and to nothing
wider.

WHAT ENFORCES IT, measured rather than assumed. An earlier version of this
paragraph named ``_completion_witness_holds`` and the exactly-one-witness rule,
"both untouched here" -- and that was WRONG, in the way that mattered. Neither
excludes a counterparty signature: the first asks for an act of the INITIATOR'S,
which a record where both parties signed supplies, and the second is satisfied by
a producer that suppresses a ``transaction_record_hash`` it could have carried.
While the proxies stood, condition 3's ``unilateral`` and the ``observed_party``
requirement did the excluding between them. Relaxing both at once left the
property unenforced, and a record whose counterparty signed the acceptance
verified. It is now checked on its own: a counterparty may sign NEGOTIATION
acts and nothing else (``_responder_signed_only_negotiation``), and no
acceptance, signed or unsigned, may name an act the counterparty signed
(``_no_acceptance_of_responder_signed_act``), so the record attests no in-band
acceptance of a counterparty-signed act. The completion-rule section of this
file is what would catch either's removal.

WHAT MUST NOT MOVE, asserted here rather than assumed: the counterparty's acts
stay ``unsigned_observation`` (no attribution inflation), a record still carries
exactly one witness, and a ``transaction_record_hash`` still requires a
DID-bearing responder. The Tier-0 no-DID record is covered too, because a
relaxation can widen past its target and nothing else would notice.
"""

from __future__ import annotations

import base64
import copy

import pytest

import a2cn.evidence as evidence_module
from a2cn.crypto import hash_object, public_key_to_jwk, sign_jws, verify_jws
from a2cn.evidence import (
    assess_session_evidence_record,
    generate_transaction_record,
    verify_session_evidence_record,
)
from a2cn.messages import PROTOCOL_ACT_VERSION, rebuild_signed_act, signed_act_hash
from a2cn.session import SessionState
from tests.conftest import make_did_document
from tests.test_evidence import (
    EXTERNAL_COMMITMENT_REFERENCE,
    INITIATOR_DID,
    INITIATOR_PRIVATE_KEY,
    INITIATOR_PUBLIC_KEY,
    INITIATOR_VM,
    OBSERVED_RESPONDER,
    RESPONDER_DID,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
    THIRD_PARTY_DID,
    THIRD_PARTY_PRIVATE_KEY,
    THIRD_PARTY_PUBLIC_KEY,
    THIRD_PARTY_VM,
    _acceptance,
    _external_channel_record,
    _generate,
    _make_identity_light_session,
    _make_session,
    _mark_completed_externally,
    _observed_quote,
    _offer,
    _order_confirmation,
    _reseal,
    _third_party_offer,
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

    THAT NARROWING WAS THEN PROPOSED A SECOND TIME, after this paragraph was
    written, on the same measured ground, and it resolved the same way: both
    levels are admitted. The second pass got as far as the schema clause, both
    verifier rules, both generator messages and six prose passages before this
    docstring surfaced during the sweep and the resolution was revisited; all of
    it was discarded and the tree returned to admitting both. Recorded here
    rather than rewritten away, because a tripwire that fires and is then
    reworded as though it had never been tested is worth less than one carrying
    its own history. Two independent narrowings, the same evidence, the same
    answer -- if a third is drafted, it needs a NEW argument, not this one.

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


# ---------------------------------------------------------------------------
# The property the relaxation had to start enforcing directly
# ---------------------------------------------------------------------------
#
# Widening the responder condition removed the two IDENTITY PROXIES --
# ``observed_party`` and ``unilateral`` -- that had incidentally excluded a
# counterparty signature, and nothing took over the property they stood for:
# NO COUNTERPARTY SIGNATURE WITNESSES THE COMPLETION.
#
# That property is about the COMPLETION, not about every act. A counterparty
# that signed a counteroffer negotiated; it completed nothing, and no
# TransactionRecord exists for such a session (Section 9.3). What completes an
# A2CN session is an acceptance of a signed offer, so Section 9A.12 keys the
# rule on that pair: the responder may sign only an offer or a counteroffer, and
# no acceptance -- signed or unsigned -- may name one the responder signed: the
# record attests no in-band acceptance of a responder-signed act.
#
# ``mixed`` is what made this load-bearing rather than theoretical.
# ``_classify_evidence_level`` returned ``bilateral`` only when NOTHING was
# unsigned, so a single unsigned observed act -- which an external-channel flow
# carries by construction -- demoted a fully signed session to ``mixed``, which
# condition 3 admits, and a counterparty's signed acceptance could ride in under
# an admitted classification. The classifier now never returns ``bilateral`` for
# a record carrying the reference, so the level cannot do the excluding at all:
# the completion rule is what does.


_COUNTERPARTY_ENVELOPE = (
    "sequence_number",
    "round_number",
    "message_type",
    "message_id",
    "timestamp",
)


def _unsigned_counterparty_act(
    message_type: str,
    message_id: str,
    *,
    sequence_number: int,
    round_number: int,
    timestamp: str,
) -> dict:
    """An observed counterparty act carrying no signature of any kind.

    The mandate-only projection: the responder's DID is recorded, because it
    verifies, and the act is an unsigned observation, because nobody signed it.
    """
    return {
        "sequence_number": sequence_number,
        "round_number": round_number,
        "message_type": message_type,
        "message_id": message_id,
        "sender_did": RESPONDER_DID,
        "timestamp": timestamp,
        "source_protocol": "supplier_portal",
        "act": {
            "message_type": message_type,
            "message_id": message_id,
            "timestamp": timestamp,
        },
    }


def _external_completion(observed_acts):
    """A mandate-only external-channel record over the given observed acts."""
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_completed_externally(session)
    record = _generate(
        session,
        observed_acts,
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )
    return record, did_documents, session


def _attach_the_counterparty_signature(record: dict, message: dict, signature_type: str) -> dict:
    """Replace the counterparty's unsigned observation with its real signed act.

    Hand-attached rather than generated, because the generator refuses to build
    this record -- which is the generator-leg assertion below, not a gap. What
    lands here is the counterparty's genuine signature over its own envelope, so
    the act VERIFIES; the tests assert that through ``invalid_acts``, since a
    signature that merely looked present would refuse the record at the act
    level and prove nothing about the rule under test.

    ``evidence_level`` is deliberately left alone. ``_reseal`` does not recompute
    it, so a case whose level SHOULD change would be refused by the
    classifier-consistency check instead of by the rule it names. Here it must
    not change: the record is ``mixed`` with the counterparty's act unsigned and
    ``mixed`` with it signed, since ``bilateral`` needs nothing unsigned and the
    order confirmation is. The tests assert the level on both sides of the
    patch, so a future classifier change cannot turn these into
    overdetermined negatives unnoticed.
    """
    entry = next(item for item in record["acts"] if item["sender_did"] == RESPONDER_DID)
    # Recorded as a record states an act: with the wire version it was signed under.
    act = {"protocol_version": PROTOCOL_ACT_VERSION, **copy.deepcopy(message)}
    entry["act"] = act
    entry["act_hash"] = hash_object(act)
    entry["sender_verification_method"] = message["sender_verification_method"]
    entry["signature_type"] = signature_type
    entry["signature"] = message[signature_type]
    entry["attribution"] = "verified_signature"
    for field in _COUNTERPARTY_ENVELOPE:
        entry[field] = message[field]
    return _reseal(record)


def _signed_counteroffer(session_id: str) -> dict:
    return _offer(
        session_id,
        sender_did=RESPONDER_DID,
        sequence_number=2,
        round_number=2,
        message_type="counteroffer",
        message_id="counteroffer-1",
        timestamp="2026-03-24T10:02:00Z",
    )


_UNSIGNED_COUNTEROFFER = (
    "counteroffer",
    "counteroffer-1",
    {"sequence_number": 2, "round_number": 2, "timestamp": "2026-03-24T10:02:00Z"},
)
_UNSIGNED_ACCEPTANCE = (
    "acceptance",
    "acceptance-1",
    {"sequence_number": 2, "round_number": 1, "timestamp": "2026-03-24T10:03:00Z"},
)


def _mandate_only_pair(shape):
    """The record this change admits, and its observed-act list, for one act type."""
    message_type, message_id, envelope = shape
    observed = [
        _unsigned_counterparty_act(message_type, message_id, **envelope),
        _order_confirmation(),
    ]
    return _external_completion(observed)


def test_a_completion_whose_counterparty_signed_a_counteroffer_verifies_as_mixed():
    """A signed negotiation that completes off-protocol is an honest ``mixed`` record.

    The initiator signed its offer, the responder signed a COUNTEROFFER, and the
    order was confirmed outside A2CN. Both parties have authenticated negotiation
    evidence; nobody signed the completion, whose only witness is the external
    reference. No acceptance means no TransactionRecord exists at all
    (Section 9.3), so the reference is not a weaker witness chosen over a
    stronger one -- it is the only one there is.

    The record is ``mixed``, never ``bilateral``: the completion is the
    producer's account, not an act either party signed.

    Its twin is ``_mandate_only_pair`` unpatched: the same session, the same
    three acts, the same reference, the same ``mixed`` level, and the
    counterparty's signature the only difference. Both verify.
    """
    honest, did_documents, session = _mandate_only_pair(_UNSIGNED_COUNTEROFFER)
    assert honest["evidence_level"] == "mixed"
    assert verify_session_evidence_record(honest, did_documents)
    with pytest.raises(ValueError):
        generate_transaction_record(session)

    signed = _attach_the_counterparty_signature(
        copy.deepcopy(honest),
        _signed_counteroffer(session.session_id),
        "protocol_act_signature",
    )

    counterparty = [
        entry
        for entry in signed["acts"]
        if entry["attribution"] == "verified_signature"
        and entry["sender_did"] == signed["parties"]["responder"]["did"]
    ]
    assert [entry["message_type"] for entry in counterparty] == ["counteroffer"]
    assert signed["parties"]["responder"]["did"] == RESPONDER_DID
    assert "identity_source" not in signed["parties"]["responder"], "a full party"
    assert signed["terminal"]["outcome"] == SessionState.COMPLETED
    assert signed["transaction_record_hash"] is None
    assert signed["external_commitment_reference"] == EXTERNAL_COMMITMENT_REFERENCE
    assert all(entry["message_type"] != "acceptance" for entry in signed["acts"])
    assert signed["evidence_level"] == "mixed"
    assert assess_session_evidence_record(signed, did_documents) == {
        "valid": True,
        "evidence_level": "mixed",
        "verified_acts": 2,
        "unsigned_acts": 1,
        "invalid_acts": 0,
    }


def test_the_generator_emits_a_signed_negotiation_completing_externally_as_mixed():
    """The generator builds the same record from the counterparty's real signed act.

    The signed counteroffer goes in as an observed act, which the generator
    normalizes to ``verified_signature`` from the signature it carries, so this
    is the ordinary act of recording a negotiation the counterparty signed.
    """
    session, did_documents = _mandate_only_session()
    observed = _signed_negotiation(session)
    record = _generate(
        session, observed, external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE
    )

    verified = [
        (entry["message_type"], entry["sender_did"])
        for entry in record["acts"]
        if entry["attribution"] == "verified_signature"
    ]
    assert verified == [("offer", INITIATOR_DID), ("counteroffer", RESPONDER_DID)]
    assert record["evidence_level"] == "mixed"
    assert record["transaction_record_hash"] is None
    assert verify_session_evidence_record(record, did_documents)


def test_a_completion_whose_counterparty_signed_the_acceptance_is_refused():
    """A responder-signed acceptance is a completion the counterparty signed.

    The acceptance is A2CN's completion act, and in an external-channel record the
    responder may sign only an offer or a counteroffer. The session-party check
    admits this act -- its signer is ``parties.responder.did`` exactly -- and the
    acceptance names the initiator's offer, which the responder did not sign, so
    the responder-act-type rule is the one that objects. This session does
    produce a TransactionRecord (Section 9.3): a completion both parties signed
    belongs there, not behind an external reference.
    """
    honest, did_documents, session = _mandate_only_pair(_UNSIGNED_ACCEPTANCE)
    assert verify_session_evidence_record(honest, did_documents)

    offer = next(entry["act"] for entry in honest["acts"] if entry["message_type"] == "offer")
    signed = _attach_the_counterparty_signature(
        copy.deepcopy(honest),
        _acceptance(session.session_id, offer),
        "acceptance_signature",
    )

    counterparty = [
        entry
        for entry in signed["acts"]
        if entry["attribution"] == "verified_signature"
        and entry["sender_did"] == RESPONDER_DID
    ]
    assert [entry["message_type"] for entry in counterparty] == ["acceptance"]
    assert counterparty[0]["sender_did"] == signed["parties"]["responder"]["did"], (
        "a session party, so the session-party check is not what refuses it"
    )
    assert honest["evidence_level"] == signed["evidence_level"] == "mixed"
    assert assess_session_evidence_record(signed, did_documents)["invalid_acts"] == 0

    assert not verify_session_evidence_record(signed, did_documents)


def test_the_generator_refuses_a_completion_whose_counterparty_signed_the_acceptance():
    """The generator runs the same rule, so a producer cannot emit one either.

    The assertion matches the message, which names the rule: the responder may
    sign only an offer or a counteroffer. The message is part of the contract,
    which is why a test asserts on it at all.
    """
    manager, session, _did_documents = _make_session()
    offer = _offer(session.session_id)
    manager.process_message(session, offer)
    _mark_completed_externally(session)

    with pytest.raises(ValueError, match="responder signature only on an offer or counteroffer"):
        _generate(
            session,
            [_acceptance(session.session_id, offer), _order_confirmation()],
            external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
        )
    # The control: the same call with the signature stripped SUCCEEDS, so the
    # refusal above is the signature's doing and not the observed act's.
    message_type, message_id, envelope = _UNSIGNED_ACCEPTANCE
    assert _generate(
        session,
        [
            _unsigned_counterparty_act(message_type, message_id, **envelope),
            _order_confirmation(),
        ],
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )


def test_a_counterparty_signature_cannot_hide_behind_an_unsigned_label():
    """The premise the rule above rests on, guarded rather than assumed.

    That rule is keyed on ``attribution``, so it would be bypassable if an act
    could carry an A2CN signature while calling itself an unsigned observation.
    It cannot: ``_verify_evidence_act`` refuses an ``unsigned_observation``
    whose complete ``act`` still holds any of the four signature fields, and
    counts the act INVALID. Pre-existing behaviour, and pinned here because the
    new rule's completeness now depends on it -- if that refusal ever relaxed,
    keying on attribution would stop covering Section 9A.12 condition 2.

    Arm two is the honest shape the same edit produces once the signature really
    is gone, and arm three is Section 9A.12's deliberate exception: a transport
    signature the producer merely observed belongs inside the observed act, is
    recorded as observed rather than verified, and must NOT be read as a
    counterparty signature.
    """
    honest, did_documents, session = _mandate_only_pair(_UNSIGNED_COUNTEROFFER)
    signed = _attach_the_counterparty_signature(
        copy.deepcopy(honest),
        _signed_counteroffer(session.session_id),
        "protocol_act_signature",
    )

    # Arm one: relabelled as unsigned, entry-level fields nulled exactly as
    # Section 9A.3 demands -- and the inner act keeps its real signature.
    hidden = copy.deepcopy(signed)
    counterparty = next(
        entry for entry in hidden["acts"] if entry["sender_did"] == RESPONDER_DID
    )
    counterparty.update(
        attribution="unsigned_observation",
        signature=None,
        signature_type=None,
        sender_verification_method=None,
    )
    _reseal(hidden)

    assert counterparty["act"]["protocol_act_signature"], "the signature is still in there"
    assert assess_session_evidence_record(hidden, did_documents)["invalid_acts"] == 1
    assert not verify_session_evidence_record(hidden, did_documents)

    # Arm two: strip the A2CN signature fields and the act is genuinely unsigned,
    # so the record is the honest mandate-only shape again.
    stripped = copy.deepcopy(hidden)
    unsigned = next(
        entry for entry in stripped["acts"] if entry["sender_did"] == RESPONDER_DID
    )
    for field in ("protocol_act_signature", "protocol_act_hash", "sender_verification_method"):
        unsigned["act"].pop(field, None)
    unsigned["act_hash"] = hash_object(unsigned["act"])
    _reseal(stripped)

    assert assess_session_evidence_record(stripped, did_documents)["invalid_acts"] == 0
    assert verify_session_evidence_record(stripped, did_documents)

    # Arm three: a non-A2CN signature the producer observed. Section 9A.12 puts
    # it here on purpose, so it changes nothing.
    transport = copy.deepcopy(stripped)
    observed = next(
        entry for entry in transport["acts"] if entry["sender_did"] == RESPONDER_DID
    )
    observed["act"]["x_transport_signature"] = "opaque-bytes-the-producer-observed"
    observed["act_hash"] = hash_object(observed["act"])
    _reseal(transport)

    assert observed["attribution"] == "unsigned_observation"
    assert verify_session_evidence_record(transport, did_documents)


# ---------------------------------------------------------------------------
# Session parties only: every verified act in an external-channel record is
# signed by parties.initiator.did or parties.responder.did, compared exactly
#
# Section 9A.8 rule 1 already refuses a verified act "that cannot be placed in a
# known role" for an ``observed_party`` responder. The same holds for every
# external-channel record: a verified act from a DID that is neither party is
# refused, whatever the responder's identity tier. The comparison is exact
# string equality with no DID normalization, so a DID URL naming a party's own
# key is not that party's DID and is refused too.
# ---------------------------------------------------------------------------


def _signed_entry(message: dict, signature_type: str) -> dict:
    """The evidence entry the generator builds for a flat signed message.

    Hand-built because the generator now REFUSES these records, which is the
    generator-leg assertion below rather than a gap. Validated against the
    generator's own output: for the same message object this reproduces its entry
    exactly, ``act_hash`` included. The message object must be REUSED rather than
    rebuilt -- the third party's key is ES256, whose signatures are randomised,
    so a second call would differ in `signature`, `act` and `act_hash` at once.
    """
    # The generator records every act with the wire version it was signed under.
    act = {"protocol_version": PROTOCOL_ACT_VERSION, **copy.deepcopy(message)}
    return {
        "sequence_number": act.get("sequence_number"),
        "round_number": act.get("round_number"),
        "message_type": act["message_type"],
        "message_id": act.get("message_id"),
        "sender_did": act["sender_did"],
        "timestamp": act.get("timestamp"),
        "source_protocol": act.get("source_protocol"),
        "act": act,
        "act_hash": hash_object(act),
        "sender_verification_method": act["sender_verification_method"],
        "signature_type": signature_type,
        "signature": act[signature_type],
        "attribution": "verified_signature",
    }


def _with_extra_act(record: dict, entry: dict) -> dict:
    """Append one act and reseal, leaving ``evidence_level`` alone.

    The level must not move, or the classifier-consistency check would refuse the
    record instead of the rule under test. It does not: the classifier counts
    only session parties, so an act from a non-party changes neither the
    represented nor the verified set, and a responder act spelled as a DID URL is
    not the responder's DID either. Both are asserted at each call site.
    """
    appended = copy.deepcopy(record)
    appended["acts"] = list(appended["acts"]) + [copy.deepcopy(entry)]
    return _reseal(appended)


def _third_party_resolving_session():
    """A mandate-only session whose resolver also knows a non-party DID.

    The third party's DID must RESOLVE, or its act would be refused as invalid
    and the refusal would say nothing about the rule under test.
    """
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_completed_externally(session)
    did_documents[THIRD_PARTY_DID] = make_did_document(
        THIRD_PARTY_DID, "key-1", public_key_to_jwk(THIRD_PARTY_PUBLIC_KEY)
    )
    return session, did_documents


def _mandate_only_with_reference(session):
    return _generate(
        session,
        [_observed_quote(sender_did=RESPONDER_DID)],
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )


def test_a_completion_carrying_a_third_party_signature_is_refused():
    """A verified act that is nobody's role in the session (Section 9A.8 rule 1).

    THE ACT MUST BE GENUINELY SIGNED, AND THAT IS EASY TO GET WRONG HERE. The
    cheap way to write this test is to take an unsigned observation and relabel
    its ``sender_did`` to an unrelated DID. That does NOT exercise this rule: the
    act stays ``unsigned_observation``, no DID is ever resolved, ``invalid_acts``
    stays 0, and what refuses the record is the ``evidence_level`` recomputation,
    because dropping the responder from the represented set makes a claimed
    ``mixed`` disagree with the computed ``unilateral``. The record is refused, so
    such a test PASSES, while saying nothing about the signer.

    So this builds a REAL signature from a DID that is neither party, which
    RESOLVES and VERIFIES, and asserts ``invalid_acts == 0`` and an unchanged
    level to rule both alternatives out. Do not simplify it back.
    """
    session, did_documents = _third_party_resolving_session()
    honest = _mandate_only_with_reference(session)
    assert verify_session_evidence_record(honest, did_documents), "the positive twin"

    third_party_message = _third_party_offer(session.session_id)
    signed = _with_extra_act(
        honest, _signed_entry(third_party_message, "protocol_act_signature")
    )

    # Preconditions. The signature is real and VERIFIES, so nothing is refused at
    # the act level; and the level is unchanged, so the classifier-consistency
    # check is satisfied. Whatever refuses this record refuses it for the signer.
    entry = signed["acts"][-1]
    assert entry["attribution"] == "verified_signature"
    assert entry["signature"], "a real signature, not a relabelled act"
    assert entry["sender_did"] == THIRD_PARTY_DID
    assert entry["sender_did"] not in (
        signed["parties"]["initiator"]["did"],
        signed["parties"]["responder"]["did"],
    ), "neither party: it has no role in this session"
    assert honest["evidence_level"] == signed["evidence_level"] == "mixed"
    assert assess_session_evidence_record(signed, did_documents) == {
        "valid": False,
        "evidence_level": "mixed",
        "verified_acts": 2,
        "unsigned_acts": 1,
        "invalid_acts": 0,
    }

    assert not verify_session_evidence_record(signed, did_documents)


def test_the_generator_refuses_a_completion_carrying_a_third_party_signature():
    """The generator runs the same rule, so a producer cannot emit one either."""
    session, _did_documents = _third_party_resolving_session()
    observed = [_observed_quote(sender_did=RESPONDER_DID)]

    with pytest.raises(ValueError, match="session party"):
        _generate(
            session,
            observed + [_third_party_offer(session.session_id)],
            external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
        )
    # The control: the same call without the third party's act SUCCEEDS, so the
    # refusal above is that act's doing and not the observed quote's.
    assert _generate(
        session, observed, external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE
    )


def _acceptance_signed_as(session_id: str, offer: dict, sender_did: str) -> dict:
    """The responder's real acceptance, with ``sender_did`` spelled as given."""
    acceptance = {
        "message_type": "acceptance",
        "message_id": "acceptance-1",
        "session_id": session_id,
        "in_reply_to": offer["message_id"],
        "round_number": offer["round_number"],
        "sequence_number": 3,
        "accepted_offer_id": offer["message_id"],
        "accepted_protocol_act_hash": offer["protocol_act_hash"],
        "sender_did": sender_did,
        "sender_agent_id": "seller-agent",
        "sender_verification_method": RESPONDER_VM,
        "timestamp": "2026-03-24T10:03:00Z",
    }
    acceptance["acceptance_signature"] = sign_jws(
        signed_act_hash(acceptance, version_when_absent=PROTOCOL_ACT_VERSION),
        RESPONDER_PRIVATE_KEY,
        kid=RESPONDER_VM,
    )
    return acceptance


def _dereferencing_resolver(did_documents: dict):
    """Resolve the base DID of a DID URL, as W3C DID URL dereferencing does.

    Not a broken resolver: it is what the resolver the JavaScript ecosystem uses
    does when handed a DID URL, and Section 9A.6 imposes no syntax on
    ``sender_did``. The resolver is the CALLER'S, which is why a rule comparing
    ``sender_did`` to one DID by string equality cannot carry the property.
    """

    def resolve(did: str) -> dict:
        return did_documents[did.split("#", 1)[0].split("?", 1)[0]]

    return resolve


def _responder_counteroffer_spelled_as(session_id: str, sender_did: str) -> dict:
    """The responder's real signed counteroffer, with ``sender_did`` spelled as given."""
    return _offer(
        session_id,
        sender_did=sender_did,
        sequence_number=3,
        round_number=2,
        message_type="counteroffer",
        message_id="counteroffer-spelled",
        timestamp="2026-03-24T10:03:00Z",
    )


def test_a_responder_signature_spelled_as_a_did_url_is_refused():
    """The evasion string equality cannot close, measured under the resolver that opens it.

    The responder signs a counteroffer and the producer writes ``sender_did`` as
    ``did:web:acme-corp.com#key-2026-01`` rather than ``did:web:acme-corp.com``.
    Same key, same party, same signature; only the spelling differs.
    ``_verification_method_controlled_by`` accepts it because the method equals
    the sender string, so the signature VERIFIES -- and the string is neither
    ``parties.initiator.did`` nor ``parties.responder.did``, so the session-party
    check refuses it. No DID is normalized.

    A COUNTEROFFER on purpose. A signed counteroffer by a session party is
    admitted, so the bare spelling below VERIFIES and the spelling is the only
    variable between the two arms. A responder acceptance would be refused under
    both spellings, the bare one because the responder may sign only an offer or
    counteroffer, which would leave this refusal with two causes; that case is
    the next test.

    UNDER A DEREFERENCING RESOLVER ON PURPOSE. Under an exact-match resolver the
    DID URL does not resolve, the act is INVALID, and the record is refused for a
    reason that says nothing about the rule -- a test that stopped there would
    pass while proving nothing. Arm one asserts ``invalid_acts`` is 0 to rule
    that out, and arm two holds the resolver fixed while changing only the
    spelling.
    """
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_completed_externally(session)
    resolver = _dereferencing_resolver(did_documents)
    honest = _mandate_only_with_reference(session)
    assert verify_session_evidence_record(honest, resolver), "the positive twin"

    url_signed = _with_extra_act(
        honest,
        _signed_entry(
            _responder_counteroffer_spelled_as(session.session_id, RESPONDER_VM),
            "protocol_act_signature",
        ),
    )

    entry = url_signed["acts"][-1]
    assert entry["sender_did"] == RESPONDER_VM, "spelled as a DID URL"
    assert entry["sender_did"] not in (INITIATOR_DID, RESPONDER_DID), "neither party's DID"
    assert url_signed["evidence_level"] == honest["evidence_level"] == "mixed"
    assessment = assess_session_evidence_record(url_signed, resolver)
    assert assessment["invalid_acts"] == 0, "it really verifies under this resolver"
    assert assessment["verified_acts"] == 2

    assert not verify_session_evidence_record(url_signed, resolver)

    # Arm two, resolver held fixed: the bare spelling is the responder's own DID,
    # so the same counteroffer is a session party's negotiation act and VERIFIES.
    bare_signed = _with_extra_act(
        honest,
        _signed_entry(
            _responder_counteroffer_spelled_as(session.session_id, RESPONDER_DID),
            "protocol_act_signature",
        ),
    )
    assert bare_signed["evidence_level"] == "mixed"
    assert verify_session_evidence_record(bare_signed, resolver)


def test_a_responder_acceptance_is_refused_under_either_spelling():
    """A signed acceptance by the responder never rides in, however it is written.

    The bare spelling is ``parties.responder.did``, which the session-party check
    admits, and the rule that the responder signs only an offer or counteroffer
    refuses it. The DID-URL spelling is neither party's DID, so the session-party
    check refuses it. Either way the verdict does not turn on how the DID is
    written.
    """
    manager, session, did_documents = _make_session()
    offer = _offer(session.session_id)
    manager.process_message(session, offer)
    _mark_completed_externally(session)
    resolver = _dereferencing_resolver(did_documents)
    honest = _mandate_only_with_reference(session)
    assert verify_session_evidence_record(honest, resolver), "the positive twin"

    for sender_did in (RESPONDER_VM, RESPONDER_DID):
        signed = _with_extra_act(
            honest,
            _signed_entry(
                _acceptance_signed_as(session.session_id, offer, sender_did),
                "acceptance_signature",
            ),
        )
        assert signed["acts"][-1]["sender_did"] == sender_did
        assert assess_session_evidence_record(signed, resolver)["invalid_acts"] == 0
        assert not verify_session_evidence_record(signed, resolver)


def _initiator_act_spelled_as(session_id: str, sender_did: str) -> dict:
    """A SECOND act of the INITIATOR's own, ``sender_did`` spelled as given."""
    verification_method = sender_did if "#" in sender_did else INITIATOR_VM
    act = {
        "protocol_version": PROTOCOL_ACT_VERSION,
        "session_id": session_id,
        "round_number": 1,
        "sequence_number": 4,
        "message_type": "offer",
        "sender_did": sender_did,
        "timestamp": "2026-03-24T10:04:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "terms": {"total_value": 9_400_000, "currency": "USD"},
    }
    act_hash = hash_object(act)
    return {
        **act,
        "message_id": "initiator-revision-1",
        "sender_verification_method": verification_method,
        "source_protocol": "a2cn",
        "protocol_act_hash": act_hash,
        "protocol_act_signature": sign_jws(
            act_hash, INITIATOR_PRIVATE_KEY, kid=verification_method
        ),
    }


def test_the_initiator_signing_under_two_spellings_of_its_own_did_is_refused():
    """The comparison is EXACT, and that is the ruled behaviour, not an oversight.

    The initiator signs twice: once with ``sender_did`` equal to
    ``parties.initiator.did``, once under its own DID URL. Both signatures are
    genuine and both verify under a resolver that dereferences DID URLs, and
    condition 6 is satisfied by the bare-DID act -- so this rule is the only thing
    that objects, and the record is REFUSED.

    DELIBERATE AND RULED. The rule compares ``sender_did`` to the session
    parties' DIDs by exact string equality and performs no DID normalization.
    That is the same property that makes it proof against the evasion the
    sibling test above pins: once a verifier starts treating a DID URL
    as equal to its base DID, whether a record is admitted depends on how the
    caller's resolver behaves rather than on the record. Section 9A.12 imposes no
    syntax on ``sender_did``, so the fail-closed direction is the safe one -- a
    producer that wants this act counted writes the DID the record already names.
    This is the cost side of that choice, pinned here so it cannot be "fixed" by
    adding normalization without the ruling being revisited.

    NOT to be confused with the initiator's ONLY act being spelled as a DID URL.
    That record is refused by condition 6 -- no act carries the initiator's
    ``did`` at all -- and was refused before this rule existed, so it pins nothing
    about this one. Here the bare-DID act is asserted present precisely to rule
    that reading out.
    """
    manager, session, did_documents = _make_session()
    manager.process_message(session, _offer(session.session_id))
    _mark_completed_externally(session)
    resolver = _dereferencing_resolver(did_documents)
    honest = _mandate_only_with_reference(session)
    assert verify_session_evidence_record(honest, resolver), "the positive twin"

    two_spellings = _with_extra_act(
        honest,
        _signed_entry(
            _initiator_act_spelled_as(session.session_id, INITIATOR_VM),
            "protocol_act_signature",
        ),
    )

    # Preconditions, all asserted before the verdict.
    entry = two_spellings["acts"][-1]
    assert entry["sender_did"] == INITIATOR_VM, "the initiator's own DID URL"
    assert entry["sender_did"] != INITIATOR_DID, "a different string from its did"
    # Condition 6 holds: an act DOES carry parties.initiator.did exactly.
    assert any(
        item["attribution"] == "verified_signature"
        and item["sender_did"] == two_spellings["parties"]["initiator"]["did"]
        for item in two_spellings["acts"]
    ), "condition 6 is satisfied, so it is not what refuses this record"
    # The level is coherent on both sides of the patch: a DID URL is not a party
    # DID, so the classifier counts neither a new represented nor a new verified
    # party, and the classifier-consistency check is satisfied.
    assert honest["evidence_level"] == two_spellings["evidence_level"] == "mixed"
    # Both signatures verify: nothing is refused at the act level.
    assessment = assess_session_evidence_record(two_spellings, resolver)
    assert assessment["invalid_acts"] == 0
    assert assessment["verified_acts"] == 2

    assert not verify_session_evidence_record(two_spellings, resolver)


# ---------------------------------------------------------------------------
# The completion rule: no in-band acceptance of a responder-signed act
#
# The acceptance is A2CN's completion act, and a TransactionRecord is a
# responder-signed offer plus an acceptance that names it. A record carrying
# external_commitment_reference must not attest such an acceptance in-band, so:
#
#   (a) the responder may sign only NEGOTIATION -- an offer or a counteroffer.
#       A responder-signed acceptance, rejection or withdrawal is refused.
#   (b) no acceptance, SIGNED OR UNSIGNED, may name (by its
#       accepted_protocol_act_hash) an offer or counteroffer the responder
#       signed; and while the responder has signed anything, an acceptance whose
#       target resolves to no offer or counteroffer in the record is refused too.
#
# (b) is keyed on the ACCEPTED act, not on the acceptance's own signature: an
# acceptance recorded unsigned still names the act it accepted, and is still an
# acceptance the record attests in-band. What stays admitted is the shape an
# external channel produces -- the initiator signs its acceptance of an offer
# the counterparty did not sign -- and negotiation signed by either party.
#
# What the rule does NOT prevent: a keyholder can always sign its own acceptance
# of a responder-signed counteroffer out of band and build a TransactionRecord
# elsewhere. That is inherent to admitting a counterparty's signed negotiation
# act. The record attests what was recorded in-band, not what a keyholder could
# build elsewhere.
#
# Each refusal below has a twin that differs from it in ONE signature or ONE
# target and VERIFIES, so the refusal is that difference's doing.
# ---------------------------------------------------------------------------


def _signed_negotiation(session, *between, confirmation=True):
    """The responder's real signed counteroffer, then ``between``, then the confirmation.

    Observed acts for a ``_mandate_only_session``, whose initiator has already
    signed its offer; the caller generates.
    """
    observed = [_signed_counteroffer(session.session_id), *between]
    if confirmation:
        observed.append(_order_confirmation())
    return observed


_SIGNERS = {
    "initiator": (INITIATOR_DID, INITIATOR_VM, INITIATOR_PRIVATE_KEY, "buyer-agent"),
    "responder": (RESPONDER_DID, RESPONDER_VM, RESPONDER_PRIVATE_KEY, "seller-agent"),
    "third_party": (THIRD_PARTY_DID, THIRD_PARTY_VM, THIRD_PARTY_PRIVATE_KEY, "processor-agent"),
}


def _signed_act(message: dict, signer: str) -> dict:
    """``message`` with the signer's envelope fields and its real signature (Section 7.3.1)."""
    sender_did, verification_method, private_key, agent_id = _SIGNERS[signer]
    act = {
        **message,
        "sender_did": sender_did,
        "sender_agent_id": agent_id,
        "sender_verification_method": verification_method,
    }
    signature_field = f"{act['message_type']}_signature"
    act[signature_field] = sign_jws(
        signed_act_hash(act, version_when_absent=PROTOCOL_ACT_VERSION),
        private_key,
        kid=verification_method,
    )
    return act


def _acceptance_by(
    session_id: str,
    *,
    accepted_id: str,
    accepted_hash: str,
    round_number: int,
    sequence_number: int = 3,
    timestamp: str = "2026-03-24T10:03:00Z",
    message_id: str = "acceptance-2",
    signer: str = "initiator",
) -> dict:
    """A real acceptance of the act named, signed per Section 7.3.1 by ``signer``."""
    return _signed_act(
        {
            "message_type": "acceptance",
            "message_id": message_id,
            "session_id": session_id,
            "in_reply_to": accepted_id,
            "round_number": round_number,
            "sequence_number": sequence_number,
            "accepted_offer_id": accepted_id,
            "accepted_protocol_act_hash": accepted_hash,
            "timestamp": timestamp,
        },
        signer,
    )


def _responder_decline(session_id: str, message_type: str) -> dict:
    """The responder's real signed rejection or withdrawal of the initiator's offer."""
    message = {
        "message_type": message_type,
        "message_id": f"{message_type}-1",
        "session_id": session_id,
        "in_reply_to": "offer-1",
        "round_number": 1,
        "sequence_number": 3,
        "reason_code": "PRICE_TOO_HIGH",
        "timestamp": "2026-03-24T10:03:00Z",
    }
    if message_type == "rejection":
        message["rejected_offer_id"] = "offer-1"
    return _signed_act(message, "responder")


_TARGET_FIELDS = ("accepted_offer_id", "accepted_protocol_act_hash", "protocol_act_hash", "terms")


def _unsigned_observation_of(message: dict) -> dict:
    """The same act as an unsigned observation: its content, and no signature.

    An acceptance keeps the act it names and an offer keeps the hash it states,
    so recording an act unsigned changes its attribution and nothing it says.
    """
    return {
        **{field: message[field] for field in _COUNTERPARTY_ENVELOPE},
        "sender_did": message["sender_did"],
        "source_protocol": "supplier_portal",
        "act": {
            "message_type": message["message_type"],
            "message_id": message["message_id"],
            "timestamp": message["timestamp"],
            **{field: message[field] for field in _TARGET_FIELDS if field in message},
        },
    }


def _sign_observed_act(record: dict, message: dict, signature_type: str) -> dict:
    """Replace the unsigned observation of ``message`` with ``message`` itself, signed.

    The twin of a refusal is generated with the act unsigned; this swaps in the
    real signature at the same position, so ordering, envelope and level are
    untouched and the signature is the only difference.
    """
    patched = copy.deepcopy(record)
    entry = next(item for item in patched["acts"] if item["message_id"] == message["message_id"])
    act = {"protocol_version": PROTOCOL_ACT_VERSION, **copy.deepcopy(message)}
    entry["act"] = act
    entry["act_hash"] = hash_object(act)
    entry["sender_verification_method"] = message["sender_verification_method"]
    entry["signature_type"] = signature_type
    entry["signature"] = message[signature_type]
    entry["attribution"] = "verified_signature"
    return _reseal(patched)


def _verified(record: dict) -> list[tuple[str, str]]:
    return [
        (entry["message_type"], entry["sender_did"])
        for entry in record["acts"]
        if entry["attribution"] == "verified_signature"
    ]


def _counteroffer_acceptance(session_id: str, *, signer: str, **kwargs) -> dict:
    counteroffer = _signed_counteroffer(session_id)
    return _acceptance_by(
        session_id,
        accepted_id=counteroffer["message_id"],
        accepted_hash=counteroffer["protocol_act_hash"],
        round_number=counteroffer["round_number"],
        signer=signer,
        **kwargs,
    )


def _later_unsigned_offer() -> dict:
    """A responder offer the producer observed unsigned, stating its protocol_act_hash.

    It states the hash an acceptance of it names, as an observed quote does, so
    the acceptance's target resolves to an act in the record.
    """
    later = _unsigned_counterparty_act(
        "counteroffer",
        "counteroffer-2",
        sequence_number=3,
        round_number=3,
        timestamp="2026-03-24T10:03:00Z",
    )
    later["act"]["terms"] = {"total_value": 9_300_000, "currency": "USD"}
    later["act"]["protocol_act_hash"] = hash_object(later["act"])
    return later


def test_the_responders_signed_acceptance_after_a_signed_negotiation_is_refused(monkeypatch):
    """Clause (a): the responder signs negotiation only.

    The responder signed a counteroffer and then signed an acceptance of the
    INITIATOR's offer. Every act is a session party's, the classifier gives
    ``mixed``, and the acceptance names an act the initiator signed, so (b) does
    not object. (a) does: a responder-signed acceptance is a completion the
    counterparty signed.

    The twin is the same acceptance recorded unsigned, and it verifies: an
    unsigned act is not a responder signature, and the acceptance names the
    initiator's offer rather than a responder-signed act. With (a) switched off
    the signed record verifies too, so (a) is the single cause.
    """
    session, did_documents = _mandate_only_session()
    offer = next(message for message in session._message_log if message["message_type"] == "offer")
    acceptance = _acceptance_by(
        session.session_id,
        accepted_id=offer["message_id"],
        accepted_hash=offer["protocol_act_hash"],
        round_number=offer["round_number"],
        signer="responder",
    )
    twin = _generate(
        session,
        _signed_negotiation(session, _unsigned_observation_of(acceptance)),
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )
    assert twin["evidence_level"] == "mixed"
    assert verify_session_evidence_record(twin, did_documents), "the unsigned twin"

    signed = _sign_observed_act(twin, acceptance, "acceptance_signature")

    assert _verified(signed) == [
        ("offer", INITIATOR_DID),
        ("counteroffer", RESPONDER_DID),
        ("acceptance", RESPONDER_DID),
    ]
    assert signed["evidence_level"] == "mixed"
    assert assess_session_evidence_record(signed, did_documents)["invalid_acts"] == 0
    assert not verify_session_evidence_record(signed, did_documents)

    with pytest.raises(ValueError, match="responder signature only on an offer or counteroffer"):
        _generate(
            session,
            [_signed_counteroffer(session.session_id), acceptance, _order_confirmation()],
            external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
        )

    monkeypatch.setattr(
        evidence_module, "_responder_signed_only_negotiation", lambda record: True
    )
    assert verify_session_evidence_record(signed, did_documents), "single cause"


@pytest.mark.parametrize("message_type", ["rejection", "withdrawal"])
def test_a_responder_signed_decline_in_a_completed_external_record_is_refused(message_type):
    """Clause (a): a responder's signed "no" cannot sit in a COMPLETED external record.

    A rejection or withdrawal the responder signed is a terminal act of its own,
    and it would be the only counterparty signature in a record whose completion
    the counterparty never witnessed. The twin records the same decline unsigned,
    and verifies.
    """
    session, did_documents = _mandate_only_session()
    decline = _responder_decline(session.session_id, message_type)
    twin = _generate(
        session,
        [_unsigned_observation_of(decline), _order_confirmation()],
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )
    assert verify_session_evidence_record(twin, did_documents), "the unsigned twin"

    signed = _sign_observed_act(twin, decline, f"{message_type}_signature")

    assert _verified(signed) == [("offer", INITIATOR_DID), (message_type, RESPONDER_DID)]
    assert signed["terminal"]["outcome"] == SessionState.COMPLETED
    assert signed["evidence_level"] == "mixed"
    assert assess_session_evidence_record(signed, did_documents)["invalid_acts"] == 0
    assert not verify_session_evidence_record(signed, did_documents)

    with pytest.raises(ValueError, match="responder signature only on an offer or counteroffer"):
        _generate(
            session,
            [decline, _order_confirmation()],
            external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
        )


@pytest.mark.parametrize("acceptance_signed", [False, True], ids=["unsigned", "signed"])
def test_an_acceptance_of_a_responder_signed_counteroffer_is_refused(acceptance_signed):
    """Clause (b): the accepted act, not the acceptance's signature, decides.

    The responder signed a counteroffer and the initiator accepted THAT
    counteroffer. Recorded signed, the record attests an in-band acceptance of
    the responder's signed act. Recorded UNSIGNED, it still does: the acceptance
    still names the responder's signed act. Both are refused.

    The twin differs in ONE signature, the counteroffer's: with the counteroffer
    unsigned the acceptance names no responder-signed act, and the same
    acceptance VERIFIES.
    """
    session, did_documents = _mandate_only_session()
    counteroffer = _signed_counteroffer(session.session_id)
    acceptance = _counteroffer_acceptance(session.session_id, signer="initiator")
    recorded = acceptance if acceptance_signed else _unsigned_observation_of(acceptance)

    twin = _generate(
        session,
        [_unsigned_observation_of(counteroffer), recorded, _order_confirmation()],
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )
    assert verify_session_evidence_record(twin, did_documents), "counteroffer unsigned"

    signed = _sign_observed_act(twin, counteroffer, "protocol_act_signature")

    entry = next(item for item in signed["acts"] if item["message_type"] == "acceptance")
    assert entry["act"]["accepted_protocol_act_hash"] == counteroffer["protocol_act_hash"]
    assert entry["attribution"] == (
        "verified_signature" if acceptance_signed else "unsigned_observation"
    )
    assert ("counteroffer", RESPONDER_DID) in _verified(signed)
    assert signed["evidence_level"] == twin["evidence_level"] == "mixed"
    assert assess_session_evidence_record(signed, did_documents)["invalid_acts"] == 0
    assert not verify_session_evidence_record(signed, did_documents)

    with pytest.raises(ValueError, match="accepts an offer or counteroffer the responder signed"):
        _generate(
            session,
            [counteroffer, recorded, _order_confirmation()],
            external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
        )


def test_an_acceptance_whose_target_resolves_nowhere_is_refused_once_the_responder_signed():
    """Clause (b), fail-closed: an acceptance naming nothing in the record.

    While the responder has signed an act, an acceptance whose
    accepted_protocol_act_hash matches no offer or counteroffer in the record is
    refused: the verifier cannot show it does not accept a signed act the
    producer left out. Its twins verify -- the same acceptance with the
    responder's counteroffer unsigned (the fail-closed branch needs a responder
    signature), and an acceptance that names the initiator's own offer.
    """
    session, did_documents = _mandate_only_session()
    counteroffer = _signed_counteroffer(session.session_id)
    dangling = _acceptance_by(
        session.session_id,
        accepted_id="offer-not-recorded",
        accepted_hash=hash_object({"an": "act this record does not carry"}),
        round_number=2,
    )

    twin = _generate(
        session,
        [_unsigned_observation_of(counteroffer), dangling, _order_confirmation()],
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )
    assert verify_session_evidence_record(twin, did_documents), "responder signed nothing"

    signed = _sign_observed_act(twin, counteroffer, "protocol_act_signature")
    targets = {
        item["act"].get("protocol_act_hash")
        for item in signed["acts"]
        if item["message_type"] in ("offer", "counteroffer")
    }
    assert dangling["accepted_protocol_act_hash"] not in targets
    assert assess_session_evidence_record(signed, did_documents)["invalid_acts"] == 0
    assert not verify_session_evidence_record(signed, did_documents)

    offer = next(message for message in session._message_log if message["message_type"] == "offer")
    of_the_offer = _acceptance_by(
        session.session_id,
        accepted_id=offer["message_id"],
        accepted_hash=offer["protocol_act_hash"],
        round_number=offer["round_number"],
    )
    resolved = _generate(
        session,
        [counteroffer, of_the_offer, _order_confirmation()],
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )
    assert verify_session_evidence_record(resolved, did_documents), "names a recorded act"

    with pytest.raises(ValueError, match="accepts an offer or counteroffer the responder signed"):
        _generate(
            session,
            [counteroffer, dangling, _order_confirmation()],
            external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
        )


def test_the_initiators_acceptance_of_an_unsigned_offer_beside_a_signed_counteroffer_verifies():
    """Clause (b) admits an acceptance that names no responder-signed act.

    The responder signed an EARLIER counteroffer; the initiator then signed an
    acceptance of a LATER offer of the responder's that is unsigned. The
    acceptance names an act the responder did not sign, so the record attests no
    in-band acceptance of a responder-signed act: it is admitted, and is
    ``mixed``.

    Its refused twin names the signed counteroffer instead.
    """
    session, did_documents = _mandate_only_session()
    later = _later_unsigned_offer()
    acceptance = _acceptance_by(
        session.session_id,
        accepted_id="counteroffer-2",
        accepted_hash=later["act"]["protocol_act_hash"],
        round_number=3,
        sequence_number=4,
        timestamp="2026-03-24T10:04:00Z",
    )
    record = _generate(
        session,
        _signed_negotiation(session, later, acceptance),
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )

    assert _verified(record) == [
        ("offer", INITIATOR_DID),
        ("counteroffer", RESPONDER_DID),
        ("acceptance", INITIATOR_DID),
    ]
    entry = next(item for item in record["acts"] if item["message_id"] == "counteroffer-2")
    assert entry["attribution"] == "unsigned_observation", "the accepted act is unsigned"
    assert record["evidence_level"] == "mixed"
    assert verify_session_evidence_record(record, did_documents)

    counteroffer = _signed_counteroffer(session.session_id)
    of_the_signed = _acceptance_by(
        session.session_id,
        accepted_id=counteroffer["message_id"],
        accepted_hash=counteroffer["protocol_act_hash"],
        round_number=3,
        sequence_number=4,
        timestamp="2026-03-24T10:04:00Z",
    )
    with pytest.raises(ValueError, match="accepts an offer or counteroffer the responder signed"):
        _generate(
            session,
            _signed_negotiation(session, later, of_the_signed),
            external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
        )


def _retarget(record: dict, message_id: str, **act_changes) -> dict:
    """Edit one unsigned act's inner fields (None deletes one) and reseal.

    Only an ``unsigned_observation`` is edited, so no signature is disturbed;
    ``message_type`` moves on the entry and the act together.
    """
    edited = copy.deepcopy(record)
    entry = next(item for item in edited["acts"] if item["message_id"] == message_id)
    assert entry["attribution"] == "unsigned_observation"
    for field, value in act_changes.items():
        if value is None:
            entry["act"].pop(field, None)
        else:
            entry["act"][field] = value
        if field == "message_type":
            entry["message_type"] = value
    entry["act_hash"] = hash_object(entry["act"])
    return _reseal(edited)


def _accepted_counteroffer_record():
    """The evasion: the initiator's UNSIGNED acceptance of the responder's SIGNED counteroffer.

    Returns the refused record, the twin it was built from (counteroffer
    unsigned, which verifies) and the parts each variant below edits.
    """
    session, did_documents = _mandate_only_session()
    counteroffer = _signed_counteroffer(session.session_id)
    acceptance = _counteroffer_acceptance(session.session_id, signer="initiator")
    twin = _generate(
        session,
        [
            _unsigned_observation_of(counteroffer),
            _unsigned_observation_of(acceptance),
            _order_confirmation(),
        ],
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )
    assert verify_session_evidence_record(twin, did_documents), "counteroffer unsigned"
    refused = _sign_observed_act(twin, counteroffer, "protocol_act_signature")
    return refused, did_documents, session, counteroffer, acceptance


def _hash_spellings(digest: str) -> dict:
    raw = base64.urlsafe_b64decode(digest + "=" * (-len(digest) % 4))
    return {
        "padded": digest + "=",
        "hex": raw.hex(),
        "leading-space": " " + digest,
    }


_DISGUISES = [
    "message_type=order_acceptance",
    "message_type=Acceptance",
    "crossed:hash=initiator-offer,id=counteroffer",
    "crossed:hash=counteroffer,id=initiator-offer",
    "id-only:counteroffer",
    "hash-padded",
    "hash-hex",
    "hash-leading-space",
    "order_confirmation-carries-the-target",
]


@pytest.mark.parametrize("disguise", _DISGUISES)
def test_an_acceptance_of_a_signed_act_is_refused_in_any_disguise(disguise):
    """Clause (b) applies to any act that ACCEPTS, by either target field, in any spelling.

    Nothing constrains an unsigned act's ``message_type``, so an act is an
    acceptance when it carries ``accepted_protocol_act_hash`` or
    ``accepted_offer_id``, whatever it is called. Either field naming the
    responder's signed counteroffer refuses the record, so a crossed pair cannot
    hide one behind the other. A target in another spelling of the same digest
    resolves to nothing EXACTLY, which -- once the responder has signed -- is
    refused too.
    """
    refused, did_documents, session, counteroffer, acceptance = _accepted_counteroffer_record()
    assert not verify_session_evidence_record(refused, did_documents)
    offer = next(message for message in session._message_log if message["message_type"] == "offer")
    accepted_id = acceptance["message_id"]
    spellings = _hash_spellings(counteroffer["protocol_act_hash"])
    if disguise.startswith("message_type="):
        record = _retarget(refused, accepted_id, message_type=disguise.split("=", 1)[1])
    elif disguise == "crossed:hash=initiator-offer,id=counteroffer":
        record = _retarget(refused, accepted_id, accepted_protocol_act_hash=offer["protocol_act_hash"])
        assert record["acts"][2]["act"]["accepted_offer_id"] == counteroffer["message_id"]
    elif disguise == "crossed:hash=counteroffer,id=initiator-offer":
        record = _retarget(refused, accepted_id, accepted_offer_id=offer["message_id"])
    elif disguise == "id-only:counteroffer":
        record = _retarget(
            refused, accepted_id, accepted_protocol_act_hash=None, message_type="order_acceptance"
        )
    elif disguise.startswith("hash-"):
        record = _retarget(
            refused,
            accepted_id,
            accepted_protocol_act_hash=spellings[disguise.split("-", 1)[1]],
            accepted_offer_id="an-id-nothing-has",
        )
    else:
        record = _retarget(
            refused,
            accepted_id,
            message_type="observation_note",
            accepted_protocol_act_hash=None,
            accepted_offer_id=None,
        )
        record = _retarget(
            record,
            "order-confirmation-1",
            accepted_protocol_act_hash=counteroffer["protocol_act_hash"],
            accepted_offer_id=counteroffer["message_id"],
        )

    assert ("counteroffer", RESPONDER_DID) in _verified(record)
    assert assess_session_evidence_record(record, did_documents)["invalid_acts"] == 0
    assert record["evidence_level"] == "mixed"
    assert not verify_session_evidence_record(record, did_documents)


def test_an_unsigned_forgery_of_a_signed_act_does_not_launder_its_acceptance():
    """A duplicate claiming the signed counteroffer's message_id and hash gives no escape.

    The forgery is unsigned, so the acceptance's target now also "resolves" to
    an act the responder did not sign. Membership in the responder-signed set
    is checked first, so the acceptance is still refused.
    """
    session, did_documents = _mandate_only_session()
    counteroffer = _signed_counteroffer(session.session_id)
    acceptance = _counteroffer_acceptance(
        session.session_id, signer="initiator", sequence_number=4, timestamp="2026-03-24T10:04:00Z"
    )
    forgery = _unsigned_observation_of(counteroffer)
    forgery.update(sequence_number=3, timestamp="2026-03-24T10:03:00Z", sender_did=None)
    forgery["act"].update(timestamp="2026-03-24T10:03:00Z", terms={"total_value": 1, "currency": "USD"})
    twin = _generate(
        session,
        [
            _unsigned_observation_of(counteroffer),
            forgery,
            _unsigned_observation_of(acceptance),
            _order_confirmation(),
        ],
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )
    assert verify_session_evidence_record(twin, did_documents), "nothing of the responder's signed"

    signed = _sign_observed_act(twin, counteroffer, "protocol_act_signature")

    claims = [
        item
        for item in signed["acts"]
        if item["act"].get("protocol_act_hash") == counteroffer["protocol_act_hash"]
    ]
    assert [item["attribution"] for item in claims] == ["verified_signature", "unsigned_observation"]
    assert assess_session_evidence_record(signed, did_documents)["invalid_acts"] == 0
    assert not verify_session_evidence_record(signed, did_documents)


@pytest.mark.parametrize("acceptance_signed", [False, True], ids=["unsigned", "signed"])
def test_an_acceptance_of_a_responder_signed_offer_is_refused(acceptance_signed):
    """The responder's signed OFFER is negotiation it may sign, and accepting it is a completion."""
    session, did_documents = _mandate_only_session()
    responder_offer = _offer(
        session.session_id,
        sender_did=RESPONDER_DID,
        sequence_number=2,
        round_number=2,
        message_type="offer",
        message_id="responder-offer-1",
        timestamp="2026-03-24T10:02:00Z",
    )
    acceptance = _acceptance_by(
        session.session_id,
        accepted_id=responder_offer["message_id"],
        accepted_hash=responder_offer["protocol_act_hash"],
        round_number=2,
    )
    recorded = acceptance if acceptance_signed else _unsigned_observation_of(acceptance)
    twin = _generate(
        session,
        [_unsigned_observation_of(responder_offer), recorded, _order_confirmation()],
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )
    assert verify_session_evidence_record(twin, did_documents), "offer unsigned"

    signed = _sign_observed_act(twin, responder_offer, "protocol_act_signature")

    assert ("offer", RESPONDER_DID) in _verified(signed)
    assert assess_session_evidence_record(signed, did_documents)["invalid_acts"] == 0
    assert not verify_session_evidence_record(signed, did_documents)


def test_an_unsigned_offer_stating_no_hash_resolves_by_its_rebuild():
    """An acceptance may name an unsigned offer by the hash of its rebuilt act.

    An offer's protocol_act_hash IS the hash of its signed act, so an unsigned
    observation that states no hash is still named by its rebuild. The
    initiator's signed acceptance of such an offer, beside the responder's
    signed counteroffer, resolves and is admitted.
    """
    session, did_documents = _mandate_only_session()
    later = _offer(
        session.session_id,
        sender_did=RESPONDER_DID,
        sequence_number=3,
        round_number=3,
        message_type="counteroffer",
        message_id="counteroffer-2",
        timestamp="2026-03-24T10:03:00Z",
    )
    observed_act = {
        field: value
        for field, value in later.items()
        if field not in ("protocol_act_hash", "protocol_act_signature", "sender_verification_method")
    }
    observed_act["protocol_version"] = PROTOCOL_ACT_VERSION
    observed = {
        **{field: later[field] for field in _COUNTERPARTY_ENVELOPE},
        "sender_did": RESPONDER_DID,
        "source_protocol": "supplier_portal",
        "act": observed_act,
    }
    rebuilt_hash = hash_object(rebuild_signed_act(observed_act))
    acceptance = _acceptance_by(
        session.session_id,
        accepted_id="counteroffer-2",
        accepted_hash=rebuilt_hash,
        round_number=3,
        sequence_number=4,
        timestamp="2026-03-24T10:04:00Z",
    )
    record = _generate(
        session,
        _signed_negotiation(session, observed, acceptance),
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )

    stated = next(item for item in record["acts"] if item["message_id"] == "counteroffer-2")
    assert "protocol_act_hash" not in stated["act"], "the observed offer states no hash"
    assert ("counteroffer", RESPONDER_DID) in _verified(record)
    assert verify_session_evidence_record(record, did_documents)


def test_a_third_party_signed_acceptance_is_refused():
    """An acceptance signed by a DID that is neither party.

    Refused by the session-party check. The twin is the same acceptance signed by
    the INITIATOR, with nothing of the responder's signed, and it verifies.
    """
    session, did_documents = _third_party_resolving_session()
    quote = _observed_quote(sender_did=RESPONDER_DID)
    accepted = {
        "accepted_id": quote["message_id"],
        "accepted_hash": hash_object(quote["act"]),
        "round_number": quote["round_number"],
    }
    by_initiator = _generate(
        session,
        [quote, _acceptance_by(session.session_id, **accepted, signer="initiator")],
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )
    assert verify_session_evidence_record(by_initiator, did_documents), "the twin"

    third_party_acceptance = _acceptance_by(session.session_id, **accepted, signer="third_party")
    signed = _sign_observed_act(
        _generate(
            session,
            [quote, _unsigned_observation_of(third_party_acceptance)],
            external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
        ),
        third_party_acceptance,
        "acceptance_signature",
    )

    entry = next(item for item in signed["acts"] if item["message_type"] == "acceptance")
    assert entry["attribution"] == "verified_signature"
    assert entry["sender_did"] == THIRD_PARTY_DID
    assert assess_session_evidence_record(signed, did_documents)["invalid_acts"] == 0
    assert not verify_session_evidence_record(signed, did_documents)

    with pytest.raises(ValueError, match="session party"):
        _generate(
            session,
            [quote, third_party_acceptance],
            external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
        )


def test_an_unsigned_acceptance_is_admitted_when_it_names_no_responder_signed_act():
    """An unsigned acceptance is judged by what it names, like a signed one.

    Two admitted shapes: the responder's unsigned acceptance of the INITIATOR's
    offer beside the responder's signed counteroffer, and an unsigned acceptance
    in a record where the responder signed nothing. Both verify, and both are
    ``mixed``.
    """
    session, did_documents = _mandate_only_session()
    offer = next(message for message in session._message_log if message["message_type"] == "offer")
    acceptance = _acceptance_by(
        session.session_id,
        accepted_id=offer["message_id"],
        accepted_hash=offer["protocol_act_hash"],
        round_number=offer["round_number"],
        signer="responder",
    )
    beside_signed = _generate(
        session,
        _signed_negotiation(session, _unsigned_observation_of(acceptance)),
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
    )
    observed_acceptance = next(
        entry for entry in beside_signed["acts"] if entry["message_type"] == "acceptance"
    )
    assert observed_acceptance["attribution"] == "unsigned_observation"
    assert observed_acceptance["act"]["accepted_protocol_act_hash"] == offer["protocol_act_hash"]
    assert beside_signed["evidence_level"] == "mixed"
    assert verify_session_evidence_record(beside_signed, did_documents)

    nothing_signed, did_documents, _session = _mandate_only_pair(_UNSIGNED_ACCEPTANCE)
    assert nothing_signed["evidence_level"] == "mixed"
    assert verify_session_evidence_record(nothing_signed, did_documents)


def _initiator_session(responder: str):
    if responder == "observed_party":
        manager, session, did_documents = _make_identity_light_session()
        return manager, session, did_documents, {"observed_responder": OBSERVED_RESPONDER}
    manager, session, did_documents = _make_session()
    return manager, session, did_documents, {}


@pytest.mark.parametrize("responder", ["observed_party", "did_bearing"])
@pytest.mark.parametrize("path", ["negotiated", "after_the_fact"])
def test_the_initiators_acceptance_of_an_observed_offer_verifies(responder, path):
    """The shape an external channel produces, admitted at both responder tiers.

    The initiator signs its own acceptance of the counterparty's offer, which it
    OBSERVED -- the counterparty signed nothing -- and the order is confirmed
    outside A2CN. ``negotiated`` carries the initiator's signed offer before it;
    ``after_the_fact`` carries the acceptance alone, as a producer does that
    records a commitment after the fact. The acceptance names an act the
    responder did not sign, and the responder holds no verified act, so the
    completion rule admits it; nothing in it is the counterparty's signature, so
    the record is ``unilateral``.
    """
    manager, session, did_documents, extra = _initiator_session(responder)
    if path == "negotiated":
        manager.process_message(session, _offer(session.session_id))
    _mark_completed_externally(session)
    quote = _observed_quote(sender_did=None)
    acceptance = _acceptance_by(
        session.session_id,
        accepted_id=quote["message_id"],
        accepted_hash=hash_object(quote["act"]),
        round_number=quote["round_number"],
    )
    observed = [quote, acceptance] if path == "negotiated" else [acceptance]

    record = _generate(
        session,
        [*observed, _order_confirmation()],
        external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
        **extra,
    )

    expected = [("acceptance", INITIATOR_DID)]
    if path == "negotiated":
        expected.insert(0, ("offer", INITIATOR_DID))
    assert _verified(record) == expected
    assert record["evidence_level"] == "unilateral"
    assert record["record_version"] == "0.5"
    assert verify_session_evidence_record(record, did_documents)


def test_an_external_channel_record_never_classifies_bilateral():
    """Both parties signed and nothing is unsigned, and the record is still ``mixed``.

    Without the reference this act list is what ``bilateral`` describes: both
    session parties have verified acts and no act is unsigned. With the
    reference, the completion is the producer's account rather than an act either
    party signed, so the classifier caps the level at ``mixed``. A record that
    claims ``bilateral`` here is refused, whatever its seal.
    """
    session, did_documents = _mandate_only_session()
    observed = _signed_negotiation(session, confirmation=False)
    record = _generate(
        session, observed, external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE
    )

    assert _verified(record) == [("offer", INITIATOR_DID), ("counteroffer", RESPONDER_DID)]
    assert all(entry["attribution"] == "verified_signature" for entry in record["acts"])
    assert record["evidence_level"] == "mixed"
    assert verify_session_evidence_record(record, did_documents)

    claimed = copy.deepcopy(record)
    claimed["evidence_level"] = "bilateral"
    _reseal(claimed)
    assert not verify_session_evidence_record(claimed, did_documents)


@pytest.mark.parametrize("version", ["0.3", "0.4"])
def test_a_signed_negotiation_record_relabelled_below_0_5_is_refused(version):
    """A counterparty-signed negotiation behind a reference is a "0.5" shape too."""
    session, did_documents = _mandate_only_session()
    observed = _signed_negotiation(session)
    record = _generate(
        session, observed, external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE
    )
    assert verify_session_evidence_record(record, did_documents)

    relabelled = _relabelled(record, version)
    _assert_sealed_and_otherwise_sound(relabelled, did_documents, "mixed")
    assert not verify_session_evidence_record(relabelled, did_documents)


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


# ---------------------------------------------------------------------------
# The shape is bound to the version whose schema admits it
# ---------------------------------------------------------------------------
#
# A DID-bearing responder on a record carrying external_commitment_reference is
# admitted from "0.5", the first version whose schema admits it; "0.3" and "0.4"
# require an observed_party there. A "0.5" record relabelled to an earlier
# version and resealed is a record THAT version's schema refuses, so the verifier
# refuses it too. Each negative below is SINGLE-CAUSE: its preconditions pin
# every other outcome of verification, and with the floor removed the same
# bytes verify.


def _relabelled(record: dict, version: str) -> dict:
    relabelled = copy.deepcopy(record)
    relabelled["record_version"] = version
    return _reseal(relabelled)


def _assert_sealed_and_otherwise_sound(record: dict, did_documents: dict, level: str):
    """Everything but the version binding, asserted rather than assumed."""
    unsealed = {**record, "record_hash": "", "producer_signature": ""}
    assert hash_object(unsealed) == record["record_hash"], "record_hash matches the bytes"
    assert verify_jws(record["producer_signature"], INITIATOR_PUBLIC_KEY) == record["record_hash"]
    assessment = assess_session_evidence_record(record, did_documents)
    assert assessment["invalid_acts"] == 0
    # The acts and parties are those of a record that verified at "0.5", and the
    # classifier reads no version, so the level is still the coherent one.
    assert record["evidence_level"] == level


MANDATE_ONLY_LEVELS = [
    pytest.param(RESPONDER_DID, "mixed", id="mixed"),
    pytest.param(None, "unilateral", id="unilateral"),
]


@pytest.mark.parametrize(("sender_did", "level"), MANDATE_ONLY_LEVELS)
def test_a_mandate_only_record_verifies_at_0_5(sender_did, level):
    record, did_documents = _mandate_only_record(sender_did=sender_did)

    assert record["record_version"] == "0.5"
    _assert_sealed_and_otherwise_sound(record, did_documents, level)
    assert verify_session_evidence_record(record, did_documents)


@pytest.mark.parametrize("version", ["0.3", "0.4"])
@pytest.mark.parametrize(("sender_did", "level"), MANDATE_ONLY_LEVELS)
def test_a_mandate_only_record_relabelled_below_0_5_is_refused(sender_did, level, version):
    """The DID-bearing responder with an external witness is a "0.5" shape."""
    record, did_documents = _mandate_only_record(sender_did=sender_did)
    relabelled = _relabelled(record, version)

    assert "identity_source" not in relabelled["parties"]["responder"]
    assert "external_commitment_reference" in relabelled
    _assert_sealed_and_otherwise_sound(relabelled, did_documents, level)
    assert not verify_session_evidence_record(relabelled, did_documents)


@pytest.mark.parametrize("version", ["0.3", "0.4"])
@pytest.mark.parametrize(("sender_did", "level"), MANDATE_ONLY_LEVELS)
def test_the_relabelled_mandate_only_record_is_refused_by_the_version_floor_alone(
    monkeypatch, sender_did, level, version
):
    """Single cause: with the floor lowered out of the way, the SAME bytes verify.

    A refusal with two causes cannot show that either one bites. Lowering the
    floor to the first recognized version removes it and touches nothing else,
    so a record that then verifies was refused by the floor and by nothing else.
    """
    record, did_documents = _mandate_only_record(sender_did=sender_did)
    relabelled = _relabelled(record, version)
    assert not verify_session_evidence_record(relabelled, did_documents)

    monkeypatch.setattr(
        evidence_module,
        "_VERSION_ADMITTING_VERIFIED_EXTERNAL_RESPONDER",
        evidence_module.RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS[0],
    )
    assert verify_session_evidence_record(relabelled, did_documents)


@pytest.mark.parametrize("version", ["0.3", "0.4", "0.5"])
def test_an_observed_responder_with_the_reference_verifies_from_0_3(version):
    """The floor binds the DID-bearing responder only; observed_party keeps "0.3"."""
    record, did_documents = _external_channel_record()
    relabelled = _relabelled(record, version)

    assert relabelled["parties"]["responder"]["did_declared"] is False
    assert verify_session_evidence_record(relabelled, did_documents)
