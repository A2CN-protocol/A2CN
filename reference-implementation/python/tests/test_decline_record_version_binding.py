"""Decline vocabulary binds to record_version "0.4", and a signed decline buys no level.

Two properties nothing else in either suite pinned. Measured: before this file,
the content-to-version rule never fired once across the whole suite, so deleting
it left everything green.

THE BINDING (Section 9A.6). "0.4" is the first version whose schema admits
rejection_signature or withdrawal_signature in acts[].signature_type. A producer
seals its own record, so nothing otherwise stops one emitting the new vocabulary
under an old label and sealing again: the seal is no defence here, because the
party that chooses the label is the party that makes the seal. Such a record
would verify while validating against no published schema. The rule is
ONE-DIRECTIONAL -- the vocabulary requires the version, never the reverse, since
an ordinary "0.4" record carries no decline at all.

Each refusal below carries its own control: the same session WITHOUT a signed
decline, relabelled and resealed identically. Without the control a refusal
proves only that something refused, not that this rule did -- and at "0.3"
something else genuinely does.

THE LEVEL (Section 9A.5). bilateral is gated on a COMPLETED outcome, so a fully
signed decline path falls to mixed through its locally observed terminal fact. A
signed decline therefore costs verification and buys no classification credit: a
cryptographically attested rejection classifies exactly as one the producer
merely observed. Section 9A.5's rule that a decline is never bilaterally
attributable survives declines becoming signable, but it now rests on the
terminal outcome rather than on their being unsignable.
"""

from __future__ import annotations

import copy

import pytest

from a2cn.evidence import assess_session_evidence_record, verify_session_evidence_record
from a2cn.session import SessionState
from tests.test_evidence import (
    RESPONDER_PRIVATE_KEY,
    RESPONDER_VM,
    _generate,
    _make_session,
    _mark_timed_out,
    _offer,
    _reseal,
)
from tests.test_signed_decline_acts import _rejection, _sign

# "0.3" is excluded here because a "0.3" record that does not carry
# external_commitment_reference is refused by the historical two-way rule
# (Section 9A.2) whether or not it carries decline vocabulary -- the right
# verdict for the wrong reason. test_a_0_3_relabel_is_refused_for_its_own_reason
# pins that, so this exclusion cannot quietly become a coverage hole.
UNCONFOUNDED_EARLIER_VERSIONS = ["0.1", "0.2"]


def _decline_record(*, signed: bool):
    """A TIMED_OUT record whose only act is a rejection, signed or not."""
    _manager, session, did_documents = _make_session()
    act = _rejection(session.session_id)
    if signed:
        act = _sign(act, RESPONDER_PRIVATE_KEY, RESPONDER_VM)
    session._message_log = [act]
    _mark_timed_out(session)
    return _generate(session), did_documents


def _relabelled(record: dict, version: str) -> dict:
    """Relabel and reseal, as a producer rewriting its own record would."""
    relabelled = copy.deepcopy(record)
    relabelled["record_version"] = version
    return _reseal(relabelled)


def test_a_signed_decline_is_emitted_at_0_5():
    """The control for everything below: the vocabulary and the version agree.

    Named for the EMITTED version, which is "0.5". The binding FLOOR is still
    "0.4" and the refusals below are keyed on it -- the two are different
    numbers now, and conflating them is how this test would come to assert a
    version nobody emits.
    """
    record, did_documents = _decline_record(signed=True)

    assert record["record_version"] == "0.5"
    assert record["acts"][0]["signature_type"] == "rejection_signature"
    assert verify_session_evidence_record(record, did_documents)


@pytest.mark.parametrize("version", UNCONFOUNDED_EARLIER_VERSIONS)
def test_decline_vocabulary_resealed_under_an_earlier_version_is_refused(version):
    """The re-seal hole: a producer relabelling its own record and sealing again."""
    record, did_documents = _decline_record(signed=True)

    assert not verify_session_evidence_record(_relabelled(record, version), did_documents)


@pytest.mark.parametrize("version", UNCONFOUNDED_EARLIER_VERSIONS)
def test_the_same_record_without_the_vocabulary_is_accepted_there(version):
    """The control that makes the refusal above mean something.

    Identical session, identical relabel, identical reseal; only the decline
    signature differs. Without this, the refusal above would be satisfied by a
    verifier that refused every relabelled record for any reason at all.
    """
    record, did_documents = _decline_record(signed=False)

    assert record["acts"][0]["signature_type"] is None
    assert verify_session_evidence_record(_relabelled(record, version), did_documents)


def test_a_0_3_relabel_is_refused_for_its_own_reason():
    """Why "0.3" is excluded above, pinned rather than left as a silent gap.

    A "0.3" record carrying no external_commitment_reference is refused by the
    historical two-way rule with or without decline vocabulary. Both records are
    refused there, so that version cannot isolate the binding.
    """
    signed, did_documents = _decline_record(signed=True)
    unsigned, _ = _decline_record(signed=False)

    assert not verify_session_evidence_record(_relabelled(signed, "0.3"), did_documents)
    assert not verify_session_evidence_record(_relabelled(unsigned, "0.3"), did_documents)


def test_the_binding_is_one_directional():
    """A version at or above the floor does not imply the vocabulary.

    An ordinary record carries no decline at all. The assertion below is on the
    EMITTED version, "0.5"; the floor the binding is keyed on is still "0.4".
    """
    record, did_documents = _decline_record(signed=False)

    assert record["record_version"] == "0.5"
    assert all(entry["signature_type"] is None for entry in record["acts"])
    assert verify_session_evidence_record(record, did_documents)


def test_a_fully_signed_decline_path_is_mixed_not_bilateral():
    """A signed decline costs verification and buys no classification credit.

    Both parties hold a verified act and no act is unsigned, which is the whole
    of the bilateral test apart from the outcome -- and the outcome is what
    decides.
    """
    manager, session, did_documents = _make_session()
    offer = _offer(session.session_id)
    manager.process_message(session, offer)
    rejection = _sign(_rejection(session.session_id), RESPONDER_PRIVATE_KEY, RESPONDER_VM)
    session._message_log.append(rejection)
    session.state = SessionState.REJECTED_FINAL
    session.current_turn = "none"
    session.terminal_reason = "offer_rejected"
    session.terminal_message_id = rejection["message_id"]
    session.state_updated_at = "2026-03-24T10:06:00Z"

    record = _generate(session)
    assessment = assess_session_evidence_record(record, did_documents)

    # Assert the CAUSE before the value. Pinning "mixed" alone would pass just as
    # well when mixed arrives the ordinary way -- because some act was unsigned --
    # which is not the property under test. What is under test is that a record
    # with NO unsigned act still fails to reach bilateral, and that the terminal
    # outcome is the only thing standing in its way.
    assert assessment["valid"] is True
    assert [entry["attribution"] for entry in record["acts"]] == [
        "verified_signature",
        "verified_signature",
    ]
    assert assessment["verified_acts"] == 2
    assert assessment["unsigned_acts"] == 0
    assert assessment["invalid_acts"] == 0
    assert record["terminal"]["outcome"] != SessionState.COMPLETED
    assert record["terminal"]["outcome"] == SessionState.REJECTED_FINAL

    assert assessment["evidence_level"] == "mixed"
