"""ApprovalReceipt signatures verify identically in both reference implementations.

The vector holds receipts signed by the Python and the TypeScript implementation
with Ed25519 and ES256, and receipts that must be refused. Both suites verify
every case and must reach the same verdict.
"""

import json
from pathlib import Path

import pytest

from a2cn.crypto import public_key_from_jwk, verify_approval_receipt_signature

VECTOR = json.loads(
    (Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "approval-receipt-signature.json").read_text()
)


def test_the_vector_covers_both_languages_and_both_algorithms():
    signed = {(c["signed_in"], c["receipt"]["signature"]["alg"]) for c in VECTOR["cases"] if c["verifies"]}
    assert signed == {(lang, alg) for lang in ("python", "typescript") for alg in ("Ed25519", "ES256")}
    assert any(not c["verifies"] for c in VECTOR["cases"])


@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda c: c["name"])
def test_receipt_signature_verdict(case):
    public_key = public_key_from_jwk(case["public_key_jwk"])
    assert verify_approval_receipt_signature(case["receipt"], public_key) is case["verifies"]


def test_the_section_14_1_example_receipt_verifies_with_the_example_key():
    # The specification's example must be a receipt this implementation accepts.
    import re

    spec = (Path(__file__).resolve().parents[3] / "spec" / "a2cn-spec-v0.2.0.md").read_text()
    section = spec[spec.index("### 14.1 ApprovalReceipt Artifact"):spec.index("### 14.2 Transition Semantics")]
    example, key = re.findall(r"```json\n(\{.*?\})\n```", section, re.S)[-2:]
    receipt = json.loads(example)
    public_key = public_key_from_jwk(json.loads(key))
    assert verify_approval_receipt_signature(receipt, public_key) is True
    receipt["scope"]["amount"] = "1.00 USD"
    assert verify_approval_receipt_signature(receipt, public_key) is False
