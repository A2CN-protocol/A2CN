"""One uniform signed-act envelope across all five act types (Section 7.3.1).

Today only two act types can be signed: offer/counteroffer carry
`protocol_act_signature` over the nine-field protocol act object, and an
acceptance carries `acceptance_signature` over a different five-field payload.
Rejection and withdrawal have no in-band signature slot at all, so a party that
signs its own withdrawal has nowhere conformant to put the signature.

The envelope is one flat object for every act type: a common seven-field header
plus a type-specific payload, all at the top level. Flat, because a nested
payload adds a level and bytes and could never reproduce the offer's signed
bytes. `expires_at` is a payload field of offer and counteroffer rather than a
header field, so the terminal acts never sign an empty-string filler, and the
offer's nine flat keys stay exactly what they are today.

The offer's signed bytes MUST NOT move: every stored TransactionRecord is
rebound against `final_offer.protocol_act_hash`, so a change there invalidates
records rather than messages. The acceptance's signed scope does change — it
gains the four header fields it never covered.

Verification is by rebuild: reconstruct the signed object from the act's own
fields and hash it. The rebuild is mandatory and gated on nothing — no
record_version, no schema version, no field presence decides whether it runs.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from a2cn.crypto import canonicalize, hash_object
from a2cn.messages import (
    SIGNED_ACT_HEADER_FIELDS,
    SIGNED_ACT_PAYLOAD_FIELDS,
    SIGNED_ACT_SIGNATURE_FIELDS,
    protocol_act_object,
    rebuild_signed_act,
    signed_act_hash,
    signed_act_object,
)

REPO_ROOT = Path(__file__).parents[3]
VECTOR = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "transaction-record-basis.json").read_text()
)
RECORD = VECTOR["expected"]["record_version_0_3"]["full_record"]
FINAL_OFFER = RECORD["final_offer"]
OFFER_MESSAGE = next(
    m for m in VECTOR["messages"] if m["message_id"] == FINAL_OFFER["message_id"]
)
ACCEPTANCE_MESSAGE = next(
    m for m in VECTOR["messages"] if m["message_type"] == "acceptance"
)

# Measured against this vector's real signed messages, not hand-built fixtures.
# The offer's numbers are what the stored record already carries, which is the
# point: they must not move.
OFFER_CANONICAL_BYTES = 336
OFFER_ACT_HASH = "UYhzGu9xBpCI4_bXxw_LD4erapnyXFBGi8LDbqiLXKk"
# The acceptance's numbers are new, because its signed scope is what changes.
ACCEPTANCE_CANONICAL_BYTES = 331
ACCEPTANCE_ACT_HASH = "BK-M3Bvf4hSRp1NQVqpTSFluIxdBDukRP9kGOMR4tWE"

# What Section 7.4 signs today, before the envelope.
ACCEPTANCE_FIELDS_TODAY = frozenset(
    {
        "session_id",
        "round_number",
        "sequence_number",
        "accepted_offer_id",
        "accepted_protocol_act_hash",
    }
)

ACT_TYPES = ("offer", "counteroffer", "acceptance", "rejection", "withdrawal")


def _offer_envelope() -> dict:
    return signed_act_object(
        protocol_version=FINAL_OFFER["protocol_version"],
        session_id=RECORD["session_id"],
        round_number=FINAL_OFFER["round_number"],
        sequence_number=FINAL_OFFER["sequence_number"],
        message_type=FINAL_OFFER["message_type"],
        sender_did=FINAL_OFFER["sender_did"],
        timestamp=FINAL_OFFER["timestamp"],
        payload={
            "expires_at": FINAL_OFFER["expires_at"],
            "terms": RECORD["agreed_terms"],
        },
    )


def _acceptance_envelope() -> dict:
    return signed_act_object(
        # The version this vector's acts were signed under, as its record states.
        protocol_version=FINAL_OFFER["protocol_version"],
        session_id=ACCEPTANCE_MESSAGE["session_id"],
        round_number=ACCEPTANCE_MESSAGE["round_number"],
        sequence_number=ACCEPTANCE_MESSAGE["sequence_number"],
        message_type="acceptance",
        sender_did=ACCEPTANCE_MESSAGE["sender_did"],
        timestamp=ACCEPTANCE_MESSAGE["timestamp"],
        payload={
            "accepted_offer_id": ACCEPTANCE_MESSAGE["accepted_offer_id"],
            "accepted_protocol_act_hash": ACCEPTANCE_MESSAGE[
                "accepted_protocol_act_hash"
            ],
        },
    )


# ---------------------------------------------------------------------------
# The envelope's shape
# ---------------------------------------------------------------------------


def test_the_common_header_is_seven_fields():
    assert SIGNED_ACT_HEADER_FIELDS == (
        "protocol_version",
        "session_id",
        "round_number",
        "sequence_number",
        "message_type",
        "sender_did",
        "timestamp",
    )


def test_expires_at_is_an_offer_payload_field_not_a_header_field():
    """A terminal act must never sign an empty-string expires_at.

    Putting expires_at in the header would make acceptance, rejection and
    withdrawal each cover a field they have no value for, and the only value
    available is "" — a filler inside a signature.
    """
    assert "expires_at" not in SIGNED_ACT_HEADER_FIELDS
    assert "expires_at" in SIGNED_ACT_PAYLOAD_FIELDS["offer"]
    assert "expires_at" in SIGNED_ACT_PAYLOAD_FIELDS["counteroffer"]
    for message_type in ("acceptance", "rejection", "withdrawal"):
        assert "expires_at" not in SIGNED_ACT_PAYLOAD_FIELDS[message_type]


def test_every_act_type_has_a_payload_and_a_signature_slot():
    """Rejection and withdrawal gain a slot for the first time."""
    assert set(SIGNED_ACT_PAYLOAD_FIELDS) == set(ACT_TYPES)
    assert set(SIGNED_ACT_SIGNATURE_FIELDS) == set(ACT_TYPES)
    assert SIGNED_ACT_SIGNATURE_FIELDS["offer"] == "protocol_act_signature"
    assert SIGNED_ACT_SIGNATURE_FIELDS["counteroffer"] == "protocol_act_signature"
    assert SIGNED_ACT_SIGNATURE_FIELDS["acceptance"] == "acceptance_signature"
    assert SIGNED_ACT_SIGNATURE_FIELDS["rejection"] == "rejection_signature"
    assert SIGNED_ACT_SIGNATURE_FIELDS["withdrawal"] == "withdrawal_signature"


def test_each_act_types_signature_slot_is_its_own():
    """One signature field per act type, so a relabel cannot carry a signature.

    Reusing one slot name across every type would let an act keep its signature
    while its message_type changed; distinct names make the rebuild demand the
    type the signature was made under.
    """
    assert len(set(SIGNED_ACT_SIGNATURE_FIELDS.values())) == 4


# ---------------------------------------------------------------------------
# The offer's signed bytes do not move
# ---------------------------------------------------------------------------


def test_offer_envelope_is_todays_nine_fields_byte_for_byte():
    envelope = _offer_envelope()

    assert set(envelope) == {
        "protocol_version",
        "session_id",
        "round_number",
        "sequence_number",
        "message_type",
        "sender_did",
        "timestamp",
        "expires_at",
        "terms",
    }
    assert len(canonicalize(envelope)) == OFFER_CANONICAL_BYTES
    assert hash_object(envelope) == OFFER_ACT_HASH
    # The hash the stored record is already rebound against.
    assert hash_object(envelope) == FINAL_OFFER["protocol_act_hash"]


def test_protocol_act_object_is_the_envelope_and_not_a_second_path():
    """One recipe, not a legacy branch beside it.

    protocol_act_object is what every existing call site builds; if it did not
    come out of the envelope, preserving the offer's bytes would mean keeping a
    special case, which is the cruft this change exists to remove.
    """
    assert _offer_envelope() == protocol_act_object(
        protocol_version=FINAL_OFFER["protocol_version"],
        session_id=RECORD["session_id"],
        round_number=FINAL_OFFER["round_number"],
        sequence_number=FINAL_OFFER["sequence_number"],
        message_type=FINAL_OFFER["message_type"],
        sender_did=FINAL_OFFER["sender_did"],
        timestamp=FINAL_OFFER["timestamp"],
        expires_at=FINAL_OFFER["expires_at"],
        terms=RECORD["agreed_terms"],
    )


def test_offer_act_rebuilds_from_its_own_wire_fields():
    assert signed_act_hash(OFFER_MESSAGE) == OFFER_ACT_HASH
    assert signed_act_hash(OFFER_MESSAGE) == OFFER_MESSAGE["protocol_act_hash"]


# ---------------------------------------------------------------------------
# The acceptance's signed scope changes, by exactly four fields
# ---------------------------------------------------------------------------


def test_acceptance_gains_exactly_four_fields_and_drops_none():
    covered = set(_acceptance_envelope())

    assert covered - ACCEPTANCE_FIELDS_TODAY == {
        "protocol_version",
        "message_type",
        "sender_did",
        "timestamp",
    }
    assert ACCEPTANCE_FIELDS_TODAY - covered == set()


def test_acceptance_envelope_bytes_and_hash():
    envelope = _acceptance_envelope()

    assert len(canonicalize(envelope)) == ACCEPTANCE_CANONICAL_BYTES
    assert hash_object(envelope) == ACCEPTANCE_ACT_HASH


def test_acceptance_signs_who_accepted():
    """Bringing sender_did into scope self-attests the accepting party.

    The offer has always signed sender_did; the acceptance did not, so an
    acceptance's claimed sender was covered by no signature of its own.
    """
    assert _acceptance_envelope()["sender_did"] == ACCEPTANCE_MESSAGE["sender_did"]


def test_acceptance_act_rebuilds_from_its_own_wire_fields():
    assert signed_act_hash(ACCEPTANCE_MESSAGE) == ACCEPTANCE_ACT_HASH


# ---------------------------------------------------------------------------
# The declines, which could not be signed at all before
# ---------------------------------------------------------------------------


def _rejection() -> dict:
    return {
        "message_type": "rejection",
        "message_id": "rej-1",
        "session_id": RECORD["session_id"],
        "in_reply_to": FINAL_OFFER["message_id"],
        "round_number": 2,
        "sequence_number": 4,
        "rejected_offer_id": FINAL_OFFER["message_id"],
        "sender_did": ACCEPTANCE_MESSAGE["sender_did"],
        "sender_agent_id": "basis-agent",
        "timestamp": "2026-03-24T10:04:00Z",
        "reason_code": "PRICE_TOO_HIGH",
        "reason_description": "free text, and untrusted input",
    }


def _withdrawal() -> dict:
    return {
        "message_type": "withdrawal",
        "message_id": "wd-1",
        "session_id": RECORD["session_id"],
        "in_reply_to": FINAL_OFFER["message_id"],
        "round_number": 2,
        "sequence_number": 4,
        "sender_did": ACCEPTANCE_MESSAGE["sender_did"],
        "sender_agent_id": "basis-agent",
        "timestamp": "2026-03-24T10:04:00Z",
        "reason_code": "STRATEGY_DECISION",
        "reason_description": "free text, and untrusted input",
    }


def test_rejection_signs_the_offer_it_rejects_and_why():
    assert SIGNED_ACT_PAYLOAD_FIELDS["rejection"] == ("rejected_offer_id", "reason_code")

    envelope = rebuild_signed_act(_rejection())

    assert set(envelope) == set(SIGNED_ACT_HEADER_FIELDS) | {
        "rejected_offer_id",
        "reason_code",
    }
    assert envelope["rejected_offer_id"] == FINAL_OFFER["message_id"]
    assert envelope["reason_code"] == "PRICE_TOO_HIGH"


def test_withdrawal_signs_why():
    assert SIGNED_ACT_PAYLOAD_FIELDS["withdrawal"] == ("reason_code",)

    envelope = rebuild_signed_act(_withdrawal())

    assert set(envelope) == set(SIGNED_ACT_HEADER_FIELDS) | {"reason_code"}
    assert envelope["reason_code"] == "STRATEGY_DECISION"


def test_an_offer_defaults_a_missing_timestamp_or_expires_at_to_empty():
    """The offer path's own rule, and the reason it exists.

    Neither field is validated on the wire, and both state machines have always
    rebuilt an offer's act with "" in place of a missing one, so an offer that
    omits one is signed over "" and recorded that way (Section 9.5). A primitive
    that demanded them would refuse an act whose signature genuinely covers
    those bytes.
    """
    for field_name in ("timestamp", "expires_at"):
        offer = copy.deepcopy(OFFER_MESSAGE)
        del offer[field_name]
        rebuilt = rebuild_signed_act(offer)
        assert rebuilt is not None
        assert rebuilt[field_name] == ""


def test_only_the_offer_path_defaults_and_the_acceptance_never_does():
    """An acceptance MUST NOT be able to sign an empty timestamp.

    expires_at was moved out of the common header precisely so terminal acts
    never sign an empty-string filler. Defaulting a missing timestamp for an
    acceptance would put that filler straight back, by another door.
    """
    acceptance = copy.deepcopy(ACCEPTANCE_MESSAGE)
    del acceptance["timestamp"]
    assert rebuild_signed_act(acceptance) is None

    for build in (_rejection, _withdrawal):
        decline = build()
        del decline["timestamp"]
        assert rebuild_signed_act(decline) is None


def test_reason_description_is_never_inside_the_signed_scope():
    """It is OPTIONAL and it is untrusted free text (Section 13.6).

    Signing it would make the signed key set depend on whether the sender
    happened to fill it in, which is the field-presence gating a signed act must
    never have. reason_code carries the meaning and is a required closed enum.
    """
    for act in (_rejection(), _withdrawal()):
        assert "reason_description" not in rebuild_signed_act(act)

    without_description = _rejection()
    del without_description["reason_description"]

    assert signed_act_hash(without_description) == signed_act_hash(_rejection())


# ---------------------------------------------------------------------------
# The rebuild is mandatory, and it refuses what it cannot rebind
# ---------------------------------------------------------------------------


def test_relabelling_an_act_changes_what_it_must_rebuild_to():
    """message_type is inside the header, so a relabel moves the hash."""
    relabelled = copy.deepcopy(OFFER_MESSAGE)
    relabelled["message_type"] = "offer" if OFFER_MESSAGE["message_type"] == "counteroffer" else "counteroffer"

    assert signed_act_hash(relabelled) != OFFER_ACT_HASH


def test_a_tampered_payload_does_not_rebuild_to_the_signed_hash():
    tampered = copy.deepcopy(OFFER_MESSAGE)
    tampered["terms"]["total_value"] = 1

    assert signed_act_hash(tampered) != OFFER_ACT_HASH


def test_a_decline_relabelled_as_the_other_decline_does_not_rebuild():
    rejection = _rejection()
    relabelled = copy.deepcopy(rejection)
    relabelled["message_type"] = "withdrawal"

    assert signed_act_hash(relabelled) != signed_act_hash(rejection)


def test_an_act_of_no_known_type_cannot_be_rebuilt():
    unknown = copy.deepcopy(OFFER_MESSAGE)
    unknown["message_type"] = "not_an_act"

    assert rebuild_signed_act(unknown) is None
    assert signed_act_hash(unknown) is None


def test_an_act_missing_a_covered_field_cannot_be_rebuilt():
    """A missing covered field leaves the act unrebindable.

    It is refused rather than hashed best-effort over a filled-in blank. The one
    exception is the offer path's timestamp and expires_at, which have always
    rebuilt as "" and are covered by their own test above.
    """
    for field_name in ("session_id", "sender_did", "reason_code"):
        incomplete = _rejection()
        del incomplete[field_name]
        assert rebuild_signed_act(incomplete) is None


def test_the_rebuild_is_gated_on_no_version_and_no_extra_fields():
    """Nothing decides whether the binding check runs (Section 7.3.1.1).

    An act carrying an unknown version label, or extra members, still rebuilds
    from the fields the envelope names — a verifier must not read a label and
    skip the check.
    """
    labelled = copy.deepcopy(OFFER_MESSAGE)
    labelled["record_version"] = "0.1"
    labelled["some_vendor_extension"] = {"ignored": True}

    assert signed_act_hash(labelled) == OFFER_ACT_HASH


# ---------------------------------------------------------------------------
# The shared decline vector, which both suites read
# ---------------------------------------------------------------------------
#
# The cases below are also expressible as local fixtures, and were. A local
# fixture cannot catch the two implementations disagreeing about them, which is
# the failure this whole envelope exists to prevent, so they live in one file
# both languages read instead.

DECLINE_VECTOR = json.loads(
    (REPO_ROOT / "spec" / "test-vectors" / "signed-decline-acts.json").read_text()
)
DECLINE_CASES = {case["name"]: case for case in DECLINE_VECTOR["cases"]}


def test_the_decline_vector_states_the_envelope_this_implementation_builds():
    """The vector and the code must not drift about the shape itself."""
    assert tuple(DECLINE_VECTOR["header_fields"]) == SIGNED_ACT_HEADER_FIELDS
    for message_type, payload in DECLINE_VECTOR["payload_fields"].items():
        assert tuple(payload) == SIGNED_ACT_PAYLOAD_FIELDS[message_type]
    assert DECLINE_VECTOR["signature_fields"] == SIGNED_ACT_SIGNATURE_FIELDS


@pytest.mark.parametrize("case", DECLINE_VECTOR["cases"], ids=lambda case: case["name"])
def test_each_decline_case_rebuilds_as_the_vector_says(case):
    rebuilt = rebuild_signed_act(case["act"])

    assert (rebuilt is not None) is case["rebuilds"]
    if not case["rebuilds"]:
        assert signed_act_hash(case["act"]) is None
        return
    # The vector states the signed object outright, so a scope change shows up
    # as a field diff rather than only as an opaque hash mismatch.
    assert rebuilt == case["signed_object"]
    assert len(canonicalize(rebuilt)) == case["canonical_bytes"]
    assert signed_act_hash(case["act"]) == case["signed_act_hash"]


@pytest.mark.parametrize("name", ["rejection", "withdrawal"])
def test_the_unsigned_field_leaves_the_signed_act_untouched(name):
    """reason_description is outside every signed scope, altered or absent."""
    unsigned = DECLINE_VECTOR["unsigned_field_is_not_covered"]
    act = DECLINE_CASES[name]["act"]
    before = signed_act_hash(act)

    altered = copy.deepcopy(act)
    altered[unsigned["field"]] = unsigned["altered_value"]
    removed = {k: v for k, v in act.items() if k != unsigned["field"]}

    assert signed_act_hash(altered) == before
    assert signed_act_hash(removed) == before


@pytest.mark.parametrize(
    "case", DECLINE_VECTOR["relabel_cases"], ids=lambda case: case["name"]
)
def test_a_relabelled_decline_matches_the_vector(case):
    relabelled = copy.deepcopy(DECLINE_CASES[case["from"]]["act"])
    relabelled["message_type"] = case["to"]
    rebuilt_hash = signed_act_hash(relabelled)

    assert (rebuilt_hash is not None) is case["rebuilds"]
    if case["rebuilds"]:
        # It rebuilds, but to a different act: the hash moved, and the signature
        # it carries is still in the slot of the type it was made for.
        assert rebuilt_hash == case["signed_act_hash"]
        assert rebuilt_hash != signed_act_hash(DECLINE_CASES[case["from"]]["act"])


# ---------------------------------------------------------------------------
# The regeneration's invariant, as a test rather than an inspection
# ---------------------------------------------------------------------------

OFFER_CHAIN_HASH = "VHYNTEApaLwB0_fxOv6h89u9FSLe8ZKYBDeGRG2dK5c"


def test_no_hashed_artifact_moved_when_the_vector_was_re_keyed():
    """The vector's session was re-keyed; no hashed artifact may have moved.

    A private key for the initiator was never stored, so re-signing its acts
    under the changed acceptance scope required minting one. That changes
    signature values. It must not change a single hash, because an act's hash is
    computed over the act and never over the key -- and the record path rebinds
    every stored record against the offer's hash, so a move here is a defect
    signal rather than an output.

    Pinned as literals AND re-derived, so this is something the suite fails on
    rather than something a reader checked once. The re-derivation is the
    stronger half: it would catch a stored hash edited to match a drifted act,
    which a literal on its own would not.
    """
    assert FINAL_OFFER["protocol_act_hash"] == OFFER_ACT_HASH
    assert VECTOR["expected"]["offer_chain_hash"] == OFFER_CHAIN_HASH

    for name in ("with_basis", "without_basis", "empty_expires_at"):
        node = VECTOR if name == "with_basis" else VECTOR[name]
        for message in node["messages"]:
            if message["message_type"] not in ("offer", "counteroffer"):
                continue
            assert signed_act_hash(message) == message["protocol_act_hash"], (
                f"{name}: {message['message_id']} no longer recomputes"
            )
