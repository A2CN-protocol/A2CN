"""The wire message schemas: one file per wire version, never rewritten (Section 17).

A message schema's $id carries the wire version it describes. When the wire
version moved to "0.3", each message schema already published for "0.2" stayed
exactly as published, and the "0.3" schema was published beside it as
<name>-0.3.schema.json. The published files are pinned by digest, so a later
edit to one of them fails here rather than silently changing what a "0.2"
message is checked against. Acceptance, rejection and withdrawal were first
published at "0.3", so each has one unversioned file.

The TypeScript suite runs the same checks.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from a2cn.messages import PROTOCOL_ACT_VERSION

SCHEMAS = Path(__file__).parents[3] / "spec" / "schemas"

# sha256 of each message schema file as it was published for wire version "0.2".
PUBLISHED_0_2_SHA256 = {
    "offer": "c1be4ae82e61ea25bc3127fdbc6ef37e44da191840df06661bf459ea3d801f8a",
    "session-invitation": "1564d8c59c48fef91435a576f9ea6fd939ba69370e6314265a50d91421eed87c",
    "delivery_notice": "26259aa0b6d286a52760b9c91a5a85c384f763993e00aec368cdb638dbc9d6d6",
    "delivery_acknowledged": "b4aceb0522b14ef43949dc7e1707babfbee65cae4547d0680f20d199c50a8f02",
    "dispute_notice": "a723cb94d5f55f3d2bcafc03a9a76b8c548b4d678f324c9af3a5db3c9a563c73",
    "dispute_resolved": "1a7d7692a7e8c33be17af257fa648f9f3f588c0a51f2f8b44a293293d5425776",
    "invitation-acceptance": "ba5e4682c27c4d227aa9f54530d7aae3c1cb9b252d1043085a06682b064d062d",
    "invitation-decline": "183f9ffa91bab0740ba2bf129ed548187835f79bb011914e4e81713e0f853ee8",
    "terms/saas_renewal": "c0e1584eae9714a9c183f8dded44b0d5ad6f296870e452d2f2912ca740ff5f27",
    "terms/goods_procurement": "21512ae3bfe5969f54b7f0eb2571bad2e09d7061ba39bfc2bfb1534c661c78b8",
}
FIRST_PUBLISHED_AT_0_3 = ("acceptance", "rejection", "withdrawal")


def _load(name: str) -> dict:
    return json.loads((SCHEMAS / f"{name}.schema.json").read_text())


@pytest.mark.parametrize("name", sorted(PUBLISHED_0_2_SHA256))
def test_a_published_0_2_message_schema_is_unchanged(name):
    digest = hashlib.sha256((SCHEMAS / f"{name}.schema.json").read_bytes()).hexdigest()

    assert digest == PUBLISHED_0_2_SHA256[name]
    assert _load(name)["$id"].endswith("/0.2")


@pytest.mark.parametrize("name", sorted(PUBLISHED_0_2_SHA256))
def test_the_0_3_schema_differs_from_its_0_2_file_only_in_the_version(name):
    current = _load(f"{name}-0.3")
    published = copy.deepcopy(_load(name))

    assert current["$id"] == published["$id"][: -len("0.2")] + PROTOCOL_ACT_VERSION
    published["$id"] = current["$id"]
    if name == "session-invitation":
        assert current["properties"]["a2cn_version"]["const"] == PROTOCOL_ACT_VERSION
        published["properties"]["a2cn_version"]["const"] = PROTOCOL_ACT_VERSION
    assert current == published


@pytest.mark.parametrize("name", FIRST_PUBLISHED_AT_0_3)
def test_a_schema_first_published_at_0_3_states_the_wire_version(name):
    assert _load(name)["$id"] == f"https://a2cn.dev/schemas/{name}/{PROTOCOL_ACT_VERSION}"
    assert not (SCHEMAS / f"{name}-0.3.schema.json").exists()
