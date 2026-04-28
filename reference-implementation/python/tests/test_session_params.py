"""Tests for impasse_threshold propagation in session_params_accepted (Fix 5)."""

from __future__ import annotations

import pytest
from tests.conftest import make_session_init


@pytest.mark.asyncio
async def test_impasse_threshold_propagated_to_session_ack(test_client):
    body = make_session_init()
    body["session_params"]["impasse_threshold"] = 5
    r = await test_client.post("/sessions", json=body,
                                headers={"Content-Type": "application/a2cn+json",
                                         "Idempotency-Key": body["message_id"]})
    assert r.status_code == 201
    ack = r.json()
    assert ack["session_params_accepted"]["impasse_threshold"] == 5


@pytest.mark.asyncio
async def test_impasse_threshold_absent_when_not_in_session_params(test_client):
    body = make_session_init()
    body["session_params"].pop("impasse_threshold", None)
    r = await test_client.post("/sessions", json=body,
                                headers={"Content-Type": "application/a2cn+json",
                                         "Idempotency-Key": body["message_id"]})
    assert r.status_code == 201
    ack = r.json()
    assert "impasse_threshold" not in ack["session_params_accepted"]
