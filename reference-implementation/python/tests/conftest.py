"""Shared pytest fixtures."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from a2cn.crypto import generate_keypair, public_key_to_jwk


# ---------------------------------------------------------------------------
# Crypto fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def keypair():
    priv, pub = generate_keypair()
    return priv, pub


@pytest.fixture
def initiator_keypair():
    return generate_keypair()


@pytest.fixture
def responder_keypair():
    return generate_keypair()


# ---------------------------------------------------------------------------
# Mock DID document fixtures (using respx in test_did.py)
# ---------------------------------------------------------------------------

INITIATOR_DID = "did:web:techcorp.example"
RESPONDER_DID = "did:web:acme-corp.com"


def make_did_document(did: str, key_id: str, public_key_jwk: dict) -> dict:
    """Build a minimal W3C-compliant DID document."""
    vm_id = f"{did}#{key_id}"
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_key_jwk,
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
    }


@pytest.fixture
def initiator_did_doc(initiator_keypair):
    priv, pub = initiator_keypair
    jwk = public_key_to_jwk(pub)
    return make_did_document(INITIATOR_DID, "key-1", jwk)


@pytest.fixture
def responder_did_doc(responder_keypair):
    priv, pub = responder_keypair
    jwk = public_key_to_jwk(pub)
    return make_did_document(RESPONDER_DID, "key-2026-01", jwk)


# ---------------------------------------------------------------------------
# FastAPI test client fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def responder_config(responder_keypair):
    priv, pub = responder_keypair
    return {
        "agent_info": {
            "organization_name": "Acme Corp",
            "did": RESPONDER_DID,
            "verification_method": f"{RESPONDER_DID}#key-2026-01",
            "agent_id": "sales-agent-acme-007",
            "endpoint": "http://localhost:8000",
        },
        "mandate": {
            "mandate_type": "declared",
            "agent_id": "sales-agent-acme-007",
            "principal_organization": "Acme Corp",
            "principal_did": RESPONDER_DID,
            "authorized_deal_types": ["saas_renewal"],
            "max_commitment_value": 20_000_000,
            "max_commitment_currency": "USD",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T00:00:00Z",
        },
        "deal_types": ["saas_renewal"],
        "max_rounds_by_deal_type": {"saas_renewal": 5},
        "private_key": priv,
    }


@pytest_asyncio.fixture
async def test_client(responder_config):
    """Fresh FastAPI test client with a clean server state for each test."""
    # Import fresh copies to avoid state leakage between tests
    import importlib
    import a2cn.server as server_module
    importlib.reload(server_module)

    server_module.configure_responder(responder_config)
    transport = ASGITransport(app=server_module.app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# ---------------------------------------------------------------------------
# Session init helper
# ---------------------------------------------------------------------------

def make_session_init(message_id: str | None = None) -> dict:
    import uuid
    return {
        "message_type": "session_init",
        "message_id": message_id or str(uuid.uuid4()),
        "protocol_version": "0.1",
        "session_params": {
            "deal_type": "saas_renewal",
            "currency": "USD",
            "subject": "Test negotiation",
            "max_rounds": 4,
            "session_timeout_seconds": 3600,
            "round_timeout_seconds": 900,
        },
        "initiator": {
            "organization_name": "TechCorp Inc",
            "did": INITIATOR_DID,
            "verification_method": f"{INITIATOR_DID}#key-1",
            "agent_id": "test-agent",
            "endpoint": "https://techcorp.example/api/a2cn",
        },
        "initiator_mandate": {
            "mandate_type": "declared",
            "agent_id": "test-agent",
            "principal_organization": "TechCorp Inc",
            "principal_did": INITIATOR_DID,
            "authorized_deal_types": ["saas_renewal"],
            "max_commitment_value": 15_000_000,
            "max_commitment_currency": "USD",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T00:00:00Z",
        },
    }
