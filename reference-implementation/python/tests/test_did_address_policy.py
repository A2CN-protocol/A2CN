"""The did:web address policy: no document is fetched from a non-public host.

DNS is mocked (a2cn.did._lookup) and so is the network (a2cn.did._network_backend):
these tests never touch the network. The address lists are shared with the
TypeScript suite, in spec/test-vectors/did-web-address-policy.json.
"""

from __future__ import annotations

import io
import json
import logging
import uuid
from pathlib import Path

import httpcore
import httpx
import pytest
import respx

import a2cn.did as did_module
from a2cn.did import DidWebHostRefused, is_public_unicast, resolve_did_web
from a2cn.verify import EXIT_UNFINISHED, EXIT_USAGE, EXIT_VERIFIED, run
from tests.conftest import INITIATOR_DID, SERVER_DID, make_did_document
from a2cn.crypto import create_jwt, generate_ed25519_keypair, public_key_to_jwk

VECTORS = Path(__file__).parents[3] / "spec" / "test-vectors"
POLICY = json.loads((VECTORS / "did-web-address-policy.json").read_text())
DEAL = json.loads((VECTORS / "transaction-record-offer-history.json").read_text())

HOST = "did-host.example"
DID = f"did:web:{HOST}"
PUBLIC = "8.8.8.8"


def _document_response(document: dict) -> list[bytes]:
    body = json.dumps(document).encode()
    return [
        b"HTTP/1.1 200 OK\r\n",
        b"Content-Type: application/json\r\n",
        f"Content-Length: {len(body)}\r\n".encode(),
        b"\r\n",
        body,
    ]


class _RecordingStream(httpcore.AsyncMockStream):
    def __init__(self, buffer, log):
        super().__init__(buffer)
        self._log = log

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self._log.append(("tls", server_hostname))
        return self


class _RecordingBackend(httpcore.AsyncMockBackend):
    """Serves one canned response and records where it was asked to connect;
    an address in ``unreachable`` refuses the connection."""

    def __init__(self, buffer):
        super().__init__(buffer)
        self.log: list[tuple[str, str | None]] = []
        self.unreachable: set[str] = set()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.log.append(("connect", host))
        if host in self.unreachable:
            raise httpcore.ConnectError(f"connection to {host} refused")
        return _RecordingStream(list(self._buffer), self.log)


@pytest.fixture
def network(monkeypatch):
    """Mocked DNS and network: set ``dns[host]``; read ``lookups`` and ``backend.log``."""

    class Network:
        dns: dict[str, list[str]] = {}
        lookups: list[str] = []
        backend = _RecordingBackend(_document_response(make_did_document(DID, "key-1", {"kty": "OKP"})))

    net = Network()
    net.dns, net.lookups = {}, []

    async def lookup(host, port):
        net.lookups.append(host)
        if host not in net.dns:
            raise OSError(f"no such host {host}")
        return list(net.dns[host])

    monkeypatch.setattr(did_module, "_lookup", lookup)
    monkeypatch.setattr(did_module, "_network_backend", lambda: net.backend)
    return net


# --- The address table ------------------------------------------------------


@pytest.mark.parametrize("case", POLICY["refused_addresses"], ids=lambda c: c["address"])
def test_a_non_public_address_is_refused(case):
    assert not is_public_unicast(case["address"]), case["range"]


@pytest.mark.parametrize("case", POLICY["public_addresses"], ids=lambda c: c["address"])
def test_a_public_address_is_allowed(case):
    assert is_public_unicast(case["address"]), case["range"]


@pytest.mark.parametrize("case", POLICY["refused_addresses"], ids=lambda c: c["address"])
async def test_a_host_resolving_to_a_refused_address_is_never_connected(network, case):
    network.dns[HOST] = [case["address"]]
    with pytest.raises(DidWebHostRefused):
        await resolve_did_web(DID)
    assert network.backend.log == []


# --- The host ---------------------------------------------------------------


@pytest.mark.parametrize("case", POLICY["ip_literal_hosts"], ids=lambda c: c["did"])
async def test_a_host_written_as_an_ip_address_is_refused_before_any_lookup(network, case):
    with pytest.raises(DidWebHostRefused, match="IP address"):
        await resolve_did_web(case["did"])
    assert network.lookups == [] and network.backend.log == []


async def test_a_host_written_as_an_ip_address_is_refused_with_a_supplied_client_too():
    async with httpx.AsyncClient() as client:
        with pytest.raises(DidWebHostRefused):
            await resolve_did_web("did:web:127.0.0.1", client)


async def test_an_ipv4_mapped_address_is_refused(network):
    network.dns[HOST] = ["::ffff:127.0.0.1"]
    with pytest.raises(DidWebHostRefused, match="non-public address"):
        await resolve_did_web(DID)
    assert network.backend.log == []


async def test_one_private_address_among_public_ones_refuses_the_host(network):
    network.dns[HOST] = [PUBLIC, "2606:4700:4700::1111", "10.1.2.3"]
    with pytest.raises(DidWebHostRefused, match="10.1.2.3"):
        await resolve_did_web(DID)
    assert network.backend.log == []


async def test_a_host_with_no_address_is_refused(network):
    network.dns[HOST] = []
    with pytest.raises(DidWebHostRefused):
        await resolve_did_web(DID)


# --- The connection ---------------------------------------------------------


async def test_a_public_host_resolves_through_the_address_it_checked(network):
    network.dns[HOST] = [PUBLIC, "1.1.1.1"]
    document = await resolve_did_web(DID)
    assert document["id"] == DID
    # One lookup; the connection goes to the first checked address, and TLS is
    # still started for the host name.
    assert network.lookups == [HOST]
    assert network.backend.log == [("connect", PUBLIC), ("tls", HOST)]


async def test_an_unreachable_first_address_falls_back_to_the_next_checked_one(network):
    network.dns[HOST] = ["2606:4700:4700::1111", PUBLIC]
    network.backend.unreachable = {"2606:4700:4700::1111"}
    document = await resolve_did_web(DID)
    assert document["id"] == DID
    assert network.lookups == [HOST]  # still one lookup
    assert network.backend.log == [("connect", "2606:4700:4700::1111"), ("connect", PUBLIC), ("tls", HOST)]


async def test_a_host_whose_addresses_are_all_unreachable_fails_after_trying_each(network):
    network.dns[HOST] = [PUBLIC, "1.1.1.1"]
    network.backend.unreachable = {PUBLIC, "1.1.1.1"}
    with pytest.raises(httpx.ConnectError):
        await resolve_did_web(DID)
    assert network.lookups == [HOST]
    assert network.backend.log == [("connect", PUBLIC), ("connect", "1.1.1.1")]


@pytest.mark.parametrize("position", [0, 1, 2])
async def test_a_refused_address_anywhere_in_the_list_refuses_the_host(network, position):
    addresses = [PUBLIC, "1.1.1.1"]
    addresses.insert(position, "169.254.169.254")
    network.dns[HOST] = addresses
    network.backend.unreachable = {PUBLIC}
    with pytest.raises(DidWebHostRefused, match="169.254.169.254"):
        await resolve_did_web(DID)
    assert network.backend.log == []


async def test_each_fetch_looks_the_host_up_once(network):
    network.dns[HOST] = [PUBLIC]
    for _ in range(3):
        await resolve_did_web(DID)
    assert network.lookups == [HOST] * 3
    assert [entry for entry in network.backend.log if entry[0] == "connect"] == [("connect", PUBLIC)] * 3


async def test_a_proxy_from_the_environment_is_not_used(network, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://10.9.9.9:3128")
    network.dns[HOST] = [PUBLIC]
    await resolve_did_web(DID)
    assert network.lookups == [HOST]
    assert network.backend.log[0] == ("connect", PUBLIC)


# --- The opt-in -------------------------------------------------------------


async def test_the_opt_in_allows_a_private_host(network):
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://127.0.0.1/.well-known/did.json").mock(
            return_value=httpx.Response(200, json={"id": "did:web:127.0.0.1"})
        )
        document = await resolve_did_web("did:web:127.0.0.1", allow_private_hosts=True)
    assert document["id"] == "did:web:127.0.0.1"
    assert network.lookups == []  # the policy's lookup is not made


async def test_the_opt_in_is_off_by_default(network):
    network.dns["localhost"] = ["127.0.0.1", "::1"]
    with pytest.raises(DidWebHostRefused):
        await resolve_did_web("did:web:localhost")


# --- The servers ------------------------------------------------------------

PRIVATE_HOST = "internal-only.example"
PRIVATE_DID = f"did:web:{PRIVATE_HOST}"
PRIVATE_ADDRESS = "10.20.30.40"


def _token(issuer: str) -> str:
    key, _ = generate_ed25519_keypair()
    return create_jwt(issuer, SERVER_DID, key, kid=f"{issuer}#key-1", exp_seconds=60)


def _assert_says_nothing_about_the_fetch(text: str, *extra: str):
    for leaked in (PRIVATE_HOST, PRIVATE_ADDRESS, "non-public", "resolves", "Refused", *extra):
        assert leaked not in text


async def test_the_401_names_neither_the_host_nor_the_error(raw_test_client, network, caplog):
    network.dns[PRIVATE_HOST] = [PRIVATE_ADDRESS]
    with caplog.at_level(logging.WARNING, logger="a2cn.server"):
        r = await raw_test_client.get(
            "/sessions/any", headers={"Authorization": f"Bearer {_token(PRIVATE_DID)}"}
        )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "INVALID_JWT"
    assert r.json()["error"]["message"] == "The bearer token could not be verified"
    _assert_says_nothing_about_the_fetch(r.text)
    assert network.backend.log == []
    assert PRIVATE_ADDRESS in caplog.text  # the detail goes to the server log


async def test_the_401_does_not_echo_a_fetch_error(raw_test_client, network, monkeypatch):
    class Failing(_RecordingBackend):
        async def connect_tcp(self, host, port, **kwargs):
            raise httpcore.ConnectError("connection refused by the-secret-detail")

    monkeypatch.setattr(did_module, "_network_backend", lambda: Failing([]))
    network.dns[PRIVATE_HOST] = [PUBLIC]
    r = await raw_test_client.get("/sessions/any", headers={"Authorization": f"Bearer {_token(PRIVATE_DID)}"})
    assert r.status_code == 401
    _assert_says_nothing_about_the_fetch(r.text, "the-secret-detail", "ConnectError")


async def test_the_401_does_not_echo_the_fetched_document(raw_test_client, network):
    # The fetched document has no usable key: the reason names its contents, so it stays out.
    network.dns[PRIVATE_HOST] = [PUBLIC]
    r = await raw_test_client.get("/sessions/any", headers={"Authorization": f"Bearer {_token(DID)}"})
    assert r.status_code == 401
    assert r.json()["error"]["message"] == "The bearer token could not be verified"
    _assert_says_nothing_about_the_fetch(r.text, "OKP", "kty", "key-1")


async def test_an_invitation_from_a_private_host_is_never_fetched(raw_test_client, network):
    from a2cn.messages import PROTOCOL_ACT_VERSION

    network.dns[PRIVATE_HOST] = [PRIVATE_ADDRESS]
    r = await raw_test_client.post(
        "/invitations",
        json={
            "a2cn_version": PROTOCOL_ACT_VERSION,
            "inviter_did": PRIVATE_DID,
            "inviter_verification_method": f"{PRIVATE_DID}#key-1",
            "invitation_signature": "x",
        },
    )
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "DID_RESOLUTION_FAILED"
    _assert_says_nothing_about_the_fetch(r.text)
    assert network.lookups == [PRIVATE_HOST] and network.backend.log == []


async def test_an_approver_on_a_private_host_is_never_fetched(test_client, initiator_keypair, network):
    from tests.test_server import _paused_over_http, _post_receipt, _receipt

    network.dns[PRIVATE_HOST] = [PRIVATE_ADDRESS]
    key, _ = generate_ed25519_keypair()
    session_id, offer, mandate = await _paused_over_http(test_client, initiator_keypair, (PRIVATE_DID,))
    r = await _post_receipt(test_client, session_id, _receipt(session_id, offer, mandate, PRIVATE_DID), key)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "APPROVAL_RECEIPT_KEY_UNRESOLVED"
    # The refusal names the approver the caller's own mandate lists, and nothing the fetch found.
    for leaked in (PRIVATE_ADDRESS, "non-public", "resolves", "Refused"):
        assert leaked not in r.text
    assert network.lookups == [PRIVATE_HOST] and network.backend.log == []


async def test_the_server_setting_allows_a_private_host(raw_test_client, network, monkeypatch):
    import a2cn.server as server_module

    key, public = generate_ed25519_keypair()
    issuer = "did:web:127.0.0.1"
    monkeypatch.setattr(server_module, "ALLOW_PRIVATE_DID_HOSTS", True)
    token = create_jwt(issuer, SERVER_DID, key, kid=f"{issuer}#key-1", exp_seconds=60)
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://127.0.0.1/.well-known/did.json").mock(
            return_value=httpx.Response(200, json=make_did_document(issuer, "key-1", public_key_to_jwk(public)))
        )
        r = await raw_test_client.get(f"/sessions/{uuid.uuid4()}", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404  # authenticated; the session does not exist


def test_the_server_setting_is_off_by_default(monkeypatch):
    import importlib

    import a2cn.server as server_module

    monkeypatch.delenv("A2CN_ALLOW_PRIVATE_DID_HOSTS", raising=False)
    assert importlib.reload(server_module).ALLOW_PRIVATE_DID_HOSTS is False
    monkeypatch.setenv("A2CN_ALLOW_PRIVATE_DID_HOSTS", "1")
    assert importlib.reload(server_module).ALLOW_PRIVATE_DID_HOSTS is True
    monkeypatch.delenv("A2CN_ALLOW_PRIVATE_DID_HOSTS")
    importlib.reload(server_module)


# --- a2cn-verify ------------------------------------------------------------


def _cli(args: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    status = run(args, out=out, err=err)
    return status, out.getvalue() + err.getvalue()


def _deal(tmp_path: Path) -> Path:
    folder = tmp_path / "deal"
    folder.mkdir()
    (folder / "transaction_record.json").write_text(json.dumps(DEAL["transaction_record"]))
    (folder / "evidence_record.json").write_text(json.dumps(DEAL["evidence_record"]))
    return folder


def _party_hosts() -> list[str]:
    return [did_module._did_web_host(did) for did in DEAL["did_documents"]["current"]]


def test_the_cli_refuses_a_party_on_a_private_host(tmp_path, network):
    for host in _party_hosts():
        network.dns[host] = ["192.168.0.10"]
    status, output = _cli([str(_deal(tmp_path))])
    assert status == EXIT_UNFINISHED, output
    assert "DidWebHostRefused" in output
    assert network.backend.log == []


def test_the_cli_flag_allows_a_party_on_a_private_host(tmp_path, network):
    for host in _party_hosts():
        network.dns[host] = ["192.168.0.10"]
    with respx.mock(assert_all_called=False) as mock:
        for did, document in DEAL["did_documents"]["current"].items():
            mock.get(did_module.did_web_document_url(did)).mock(return_value=httpx.Response(200, json=document))
        status, output = _cli([str(_deal(tmp_path)), "--allow-private-did-hosts"])
    assert status == EXIT_VERIFIED, output
    assert "non-public hosts allowed (--allow-private-did-hosts)" in output
    assert network.lookups == []  # the plain client, not the policy's


def test_the_cli_flag_has_no_effect_offline(tmp_path):
    status, output = _cli([str(_deal(tmp_path)), "--offline", "--allow-private-did-hosts"])
    assert status == EXIT_USAGE
    assert "no effect with --offline" in output


def test_the_cli_flag_is_documented():
    from a2cn.verify import _parser

    assert "--allow-private-did-hosts" in _parser().format_help()
