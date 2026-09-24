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
verified. It is now a check of its own in ``_external_commitment_rules_hold``,
and the section at the bottom of this file is what would catch its removal.

WHAT MUST NOT MOVE, asserted here rather than assumed: the counterparty's acts
stay ``unsigned_observation`` (no attribution inflation), a record still carries
exactly one witness, and a ``transaction_record_hash`` still requires a
DID-bearing responder. The Tier-0 no-DID record is covered too, because a
relaxation can widen past its target and nothing else would notice.
"""

from __future__ import annotations

import copy

import pytest

from a2cn.crypto import hash_object, public_key_to_jwk, sign_jws
from a2cn.evidence import (
    assess_session_evidence_record,
    generate_transaction_record,
    verify_session_evidence_record,
)
from a2cn.messages import PROTOCOL_ACT_VERSION, signed_act_hash
from a2cn.session import SessionState
from tests.conftest import make_did_document
from tests.test_evidence import (
    EXTERNAL_COMMITMENT_REFERENCE,
    INITIATOR_DID,
    INITIATOR_PRIVATE_KEY,
    INITIATOR_VM,
    OBSERVED_RESPONDER,
    RESPONDER_DID,
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
    THIRD_PARTY_DID,
    THIRD_PARTY_PUBLIC_KEY,
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
# NO COUNTERPARTY SIGNATURE WITNESSES THE COMPLETION. Section 9A.12 states it
# three times over -- condition 2 admits a DID-bearing party only "whose acts
# are unsigned", the producer MUST NOT attach the reference "to a record whose
# counterparty signed an act that verifies", and a record "MUST NOT present" a
# verified identity as a signed act.
#
# ``mixed`` is what made the proxies' removal load-bearing rather than
# theoretical. ``_classify_evidence_level`` returns ``bilateral`` only when
# NOTHING is unsigned, so a single unsigned observed act -- which an
# external-channel flow carries by construction -- demotes a fully signed
# session to ``mixed``, which condition 3 admits. The counterparty's signature
# then rides in under an admitted classification.


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


def test_a_completion_whose_counterparty_signed_a_counteroffer_is_refused():
    """The counterparty signed, so the external reference is not its witness.

    A signed COUNTEROFFER is the variant that closes the one reading a signed
    acceptance leaves open. No acceptance means no TransactionRecord exists at
    all (Section 9.3), so the record is honest that it has no bilateral witness
    -- and a verified counterparty signature still sits inside a record
    Section 9A.12 calls producer-attested. The rule is about the signature, not
    about which witness happened to be available.

    Its positive twin is ``_mandate_only_pair`` unpatched: the same session, the
    same three acts, the same reference, the same ``mixed`` level, and the
    counterparty's signature the only difference. A refusal on its own would not
    separate this rule from any other objection to the record, so the twin is
    asserted here rather than left to a sibling test.
    """
    honest, did_documents, session = _mandate_only_pair(_UNSIGNED_COUNTEROFFER)
    assert honest["evidence_level"] == "mixed"
    assert verify_session_evidence_record(honest, did_documents), (
        "the positive twin must verify, or the refusal below is about the shape "
        "this change exists to admit"
    )
    # No TransactionRecord exists for the signed session either, so the
    # reference is not a weaker witness chosen over a stronger one.
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
    # Single-cause preconditions. The level is unchanged, so the
    # classifier-consistency check is satisfied; no act is invalid, so the
    # counterparty's signature really verifies. Whatever refuses this record
    # refuses it for the signature and for nothing else.
    assert signed["evidence_level"] == "mixed"
    assert assess_session_evidence_record(signed, did_documents) == {
        "valid": False,
        "evidence_level": "mixed",
        "verified_acts": 2,
        "unsigned_acts": 1,
        "invalid_acts": 0,
    }

    assert not verify_session_evidence_record(signed, did_documents)


def test_a_completion_whose_counterparty_signed_the_acceptance_is_refused():
    """The same rule for an acceptance, so no act type is privileged.

    Keyed on the act's ATTRIBUTION rather than on its ``message_type``: an
    acceptance, a counteroffer and a signed decline all trip it identically.
    This session does produce a TransactionRecord, which is the reading the
    counteroffer variant removes -- both are refused, and for the same reason.
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
    assert honest["evidence_level"] == signed["evidence_level"] == "mixed"
    assert assess_session_evidence_record(signed, did_documents)["invalid_acts"] == 0

    assert not verify_session_evidence_record(signed, did_documents)


def test_the_generator_refuses_a_completion_whose_counterparty_signed_an_act():
    """The generator runs the same rule, so a producer cannot emit one either.

    The assertion matches "only the initiator", which is what the message says
    and what the rule is. A message phrased around the RESPONDER would be
    narrower than the rule it reports -- a third party's verified signature is
    refused too, and so is the responder's under any spelling of its DID -- so a
    producer reading it would not learn why its record was refused. The message
    is part of the contract, which is why a test asserts on it at all.

    The signed message goes in as an observed act, which the generator
    normalizes to ``verified_signature`` from the signature it carries -- so
    what is refused is the ordinary act of recording an act the counterparty
    signed, not a hand-built record.
    """
    for message_factory, shape in (
        (_signed_counteroffer, _UNSIGNED_COUNTEROFFER),
        (None, _UNSIGNED_ACCEPTANCE),
    ):
        manager, session, _did_documents = _make_session()
        offer = _offer(session.session_id)
        manager.process_message(session, offer)
        _mark_completed_externally(session)
        message = (
            _acceptance(session.session_id, offer)
            if message_factory is None
            else message_factory(session.session_id)
        )
        with pytest.raises(ValueError, match="only the initiator"):
            _generate(
                session,
                [message, _order_confirmation()],
                external_commitment_reference=EXTERNAL_COMMITMENT_REFERENCE,
            )
        # The control: the same call with the signature stripped SUCCEEDS, so the
        # refusal above is the signature's doing and not the observed act's.
        message_type, message_id, envelope = shape
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
# Initiator-only: every verified act in an external-channel record is the
# initiator's
#
# Section 9A.8 rule 1 already said this for an ``observed_party`` responder --
# "No act may claim attribution: verified_signature unless its sender_did equals
# parties.initiator.did ... an act that cannot be placed in a known role is
# refused rather than admitted". The DID-bearing external-channel shape did not
# exist when that was written, and nothing restated it there, so the SAME
# verified third-party act was refused or admitted according to the
# counterparty's identity tier -- the identity-proxy reasoning this witness
# exists to be rid of.
#
# A rule comparing sender_did to parties.responder.did cannot carry the property
# for a second reason: it is string equality against one spelling, and a DID URL
# for the same key is a different string.
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

    with pytest.raises(ValueError, match="only the initiator"):
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


def test_a_responder_signature_spelled_as_a_did_url_is_refused():
    """The evasion string equality cannot close, measured under the resolver that opens it.

    The responder signs its own acceptance and the producer writes ``sender_did``
    as ``did:web:acme-corp.com#key-2026-01`` rather than
    ``did:web:acme-corp.com``. Same key, same party, same signature; only the
    spelling differs. ``_verification_method_controlled_by`` accepts it because
    the method equals the sender string, so the signature VERIFIES, while a rule
    comparing ``sender_did`` to ``parties.responder.did`` sees two different
    strings and stands aside.

    UNDER A DEREFERENCING RESOLVER ON PURPOSE. Under an exact-match resolver the
    DID URL does not resolve, the act is INVALID, and the record is refused for a
    reason that says nothing about the rule -- a test that stopped there would
    pass while proving nothing. Arm one asserts ``invalid_acts`` is 0 to rule
    that out, and arm two holds the resolver fixed while changing only the
    spelling, which is what makes the spelling the variable under test.

    The initiator-only rule closes this without normalizing any DID: whatever the
    spelling, the string is not ``parties.initiator.did``.
    """
    manager, session, did_documents = _make_session()
    offer = _offer(session.session_id)
    manager.process_message(session, offer)
    _mark_completed_externally(session)
    resolver = _dereferencing_resolver(did_documents)
    honest = _mandate_only_with_reference(session)
    assert verify_session_evidence_record(honest, resolver), "the positive twin"

    url_signed = _with_extra_act(
        honest,
        _signed_entry(
            _acceptance_signed_as(session.session_id, offer, RESPONDER_VM),
            "acceptance_signature",
        ),
    )

    entry = url_signed["acts"][-1]
    assert entry["sender_did"] == RESPONDER_VM, "spelled as a DID URL"
    assert entry["sender_did"] != RESPONDER_DID, "so string equality does not see it"
    assert url_signed["evidence_level"] == honest["evidence_level"] == "mixed"
    assessment = assess_session_evidence_record(url_signed, resolver)
    assert assessment["invalid_acts"] == 0, "it really verifies under this resolver"
    assert assessment["verified_acts"] == 2

    assert not verify_session_evidence_record(url_signed, resolver)

    # Arm two, resolver held fixed: the bare spelling is refused as well, so the
    # verdict does not turn on how the DID is written.
    bare_signed = _with_extra_act(
        honest,
        _signed_entry(
            _acceptance_signed_as(session.session_id, offer, RESPONDER_DID),
            "acceptance_signature",
        ),
    )
    assert not verify_session_evidence_record(bare_signed, resolver)


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

    DELIBERATE AND RULED. The rule compares ``sender_did`` to
    ``parties.initiator.did`` by exact string equality and performs no DID
    normalization. That is the same property that makes it proof against the
    evasion the sibling test above pins: once a verifier starts treating a DID URL
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
