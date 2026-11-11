"""An act that cannot be canonicalized is refused, never an internal error.

A string holding a lone surrogate has no UTF-8 encoding, so RFC 8785 cannot
canonicalize the act that holds it, and no signature can be checked against
it. The session manager refuses such an act as INVALID_SIGNATURE (400), the
standalone act verifier reports it ACT_NOT_RECOMPUTABLE, and a2cn-verify says
REFUSED; the TypeScript suite checks the session and server side the same way.
"""

from __future__ import annotations

import copy
import io
import json
from pathlib import Path

import pytest

from a2cn.acts import ACT_REASON_NOT_RECOMPUTABLE, verify_signed_act_reason
from a2cn.errors import A2CNError
from a2cn.session import SessionManager
from a2cn.verify import EXIT_REFUSED, run
from tests.conftest import INITIATOR_DID
from tests.test_server import _create_session, _make_offer_msg, init_headers

BASIS = json.loads(
    (Path(__file__).parents[3] / "spec" / "test-vectors" / "transaction-record-basis.json").read_text()
)
LONE = "\ud800"


def _offer_with_lone_surrogate() -> dict:
    offer = copy.deepcopy(BASIS["messages"][0])
    offer["terms"]["note"] = LONE
    return offer


def test_the_session_manager_refuses_an_offer_that_cannot_be_canonicalized():
    manager = SessionManager()
    for did, document in BASIS["did_documents"].items():
        manager.register_did_document(did, document)
    session = manager.create_session(
        BASIS["session_id"], BASIS["session_init"], BASIS["session_ack"],
        BASIS["session_ack"]["session_created_at"], legacy_replay=True,
    )
    session.session_timeout_seconds = 86400 * 365 * 100
    with pytest.raises(A2CNError) as refused:
        manager.process_message(session, _offer_with_lone_surrogate())
    assert refused.value.code == "INVALID_SIGNATURE"
    assert refused.value.http_status == 400


@pytest.mark.asyncio
async def test_the_server_refuses_an_offer_that_cannot_be_canonicalized(test_client, initiator_keypair):
    session_id = await _create_session(test_client)
    offer = _make_offer_msg(session_id, 1, 1, INITIATOR_DID, initiator_keypair[0])
    offer["terms"]["note"] = LONE
    r = await test_client.post(
        f"/sessions/{session_id}/messages",
        content=json.dumps(offer),
        headers={**init_headers(offer["message_id"])},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_SIGNATURE"


def test_the_act_verifier_reports_an_act_that_cannot_be_canonicalized():
    assert verify_signed_act_reason(BASIS["messages"][0], BASIS["did_documents"], wire_version="0.2") is None
    assert verify_signed_act_reason(
        _offer_with_lone_surrogate(), BASIS["did_documents"], wire_version="0.2"
    ) == ACT_REASON_NOT_RECOMPUTABLE


def test_a2cn_verify_refuses_an_act_that_cannot_be_canonicalized(tmp_path):
    act = tmp_path / "act.json"
    act.write_text(json.dumps(_offer_with_lone_surrogate()))
    document = tmp_path / "did.json"
    document.write_text(json.dumps(BASIS["did_documents"][INITIATOR_DID]))
    out = io.StringIO()
    status = run([str(act), str(document), "--offline", "--wire-version", "0.2"], out=out, err=out)
    assert status == EXIT_REFUSED, out.getvalue()
    assert f"REFUSED: {ACT_REASON_NOT_RECOMPUTABLE}" in out.getvalue()
