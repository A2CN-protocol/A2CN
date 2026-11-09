"""Invitation delivery goes only to public hosts.

POST /invitations/create with a recipient_endpoint makes the server POST the
invitation to <recipient_endpoint>/invitations. That is a request to a host the
caller names, so it goes through the same address policy as a did:web fetch.

DNS is mocked (a2cn.did._lookup) and so is the network (a2cn.did._network_backend):
these tests never touch the network. The TypeScript suite has the same cases.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import re

import httpcore
import httpx
import pytest
import respx

import a2cn.did as did_module

RECIPIENT_HOST = "recipient.example"
RECIPIENT = f"https://{RECIPIENT_HOST}/a2cn"
PUBLIC = "8.8.8.8"
PRIVATE_HOST = "internal-only.example"
PRIVATE_ADDRESS = "10.20.30.40"
LOOPBACK_HOST = "loopback-alias.example"
ELSEWHERE_HOST = "elsewhere.example"
ELSEWHERE = "1.1.1.1"

IP_LITERAL_ENDPOINTS = [
    "http://127.0.0.1:8001",
    "https://[::1]",
    "http://2130706433",
    "http://127.1",
    "http://0x7f.0.0.1",
    "http://[::ffff:10.0.0.1]:8080",
    "https://8.8.8.8",  # a public address is refused too: the host must be a name
]

NOT_HTTP_ENDPOINTS = ["file:///etc", "ftp://recipient.example", "recipient.example", 42, ["https://x.example"]]


def _response(status: int, reason: str, headers: dict[str, str] | None = None) -> list[bytes]:
    lines = [f"HTTP/1.1 {status} {reason}\r\n".encode(), b"Content-Length: 0\r\n"]
    lines += [f"{name}: {value}\r\n".encode() for name, value in (headers or {}).items()]
    return lines + [b"\r\n"]


class _RecordingStream(httpcore.AsyncMockStream):
    def __init__(self, buffer, net):
        super().__init__(buffer)
        self._net = net

    async def write(self, buffer, timeout=None):
        self._net.sent.extend(buffer)

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self._net.log.append(("tls", server_hostname))
        return self


class _RecordingBackend(httpcore.AsyncMockBackend):
    """Serves ``net.response`` on every connection and records where it was
    asked to connect and every byte sent; an address in ``unreachable`` refuses
    the connection."""

    def __init__(self, net):
        super().__init__([])
        self._net = net

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self._net.log.append(("connect", host))
        if host in self._net.unreachable:
            raise httpcore.ConnectError(f"connection to {host} refused by the-secret-detail")
        return _RecordingStream(list(self._net.response), self._net)


class _Network:
    def __init__(self):
        self.dns: dict[str, list[str]] = {}
        self.lookups: list[str] = []
        self.log: list[tuple[str, str | None]] = []
        self.sent = bytearray()
        self.unreachable: set[str] = set()
        self.response = _response(202, "Accepted")

    @property
    def connects(self) -> list[str]:
        return [host for kind, host in self.log if kind == "connect"]

    def requests(self) -> list[str]:
        return [line.decode() for line in re.findall(rb"(?m)^[A-Z]+ \S+ HTTP/1\.1", bytes(self.sent))]

    def body(self) -> dict:
        return json.loads(bytes(self.sent).split(b"\r\n\r\n", 1)[1])


@pytest.fixture
def network(monkeypatch):
    net = _Network()

    async def lookup(host, port):
        net.lookups.append(host)
        if host not in net.dns:
            raise OSError(f"no such host {host}")
        return list(net.dns[host])

    monkeypatch.setattr(did_module, "_lookup", lookup)
    monkeypatch.setattr(did_module, "_network_backend", lambda: _RecordingBackend(net))
    net.dns = {
        RECIPIENT_HOST: [PUBLIC],
        PRIVATE_HOST: [PRIVATE_ADDRESS],
        LOOPBACK_HOST: ["127.0.0.1"],
        ELSEWHERE_HOST: [ELSEWHERE],
    }
    return net


async def _create(client, recipient_endpoint=None):
    body = {"proposed_deal_type": "saas_renewal"}
    if recipient_endpoint is not None:
        body["recipient_endpoint"] = recipient_endpoint
    return await client.post("/invitations/create", json=body)


def _delivery_log(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records if r.name == "a2cn.server")


# --- Refused ------------------------------------------------------------------


@pytest.mark.parametrize(
    "host, address", [(PRIVATE_HOST, PRIVATE_ADDRESS), (LOOPBACK_HOST, "127.0.0.1")], ids=["private", "loopback"]
)
async def test_a_recipient_on_a_non_public_host_is_refused_and_nothing_is_sent(
    test_client, network, caplog, host, address
):
    with caplog.at_level(logging.WARNING, logger="a2cn.server"):
        r = await _create(test_client, f"https://{host}:8443")
    assert r.status_code == 201
    assert network.lookups == [host]
    assert network.log == [] and network.sent == bytearray()
    # The host and the reason go to the server log.
    log = _delivery_log(caplog)
    assert host in log and address in log and "non-public address" in log


@pytest.mark.parametrize("endpoint", IP_LITERAL_ENDPOINTS)
async def test_a_recipient_written_as_an_ip_address_is_refused_before_any_lookup(
    test_client, network, caplog, endpoint
):
    with caplog.at_level(logging.WARNING, logger="a2cn.server"):
        r = await _create(test_client, endpoint)
    assert r.status_code == 201
    assert network.lookups == [] and network.log == []
    assert "IP address" in _delivery_log(caplog)


@pytest.mark.parametrize("endpoint", NOT_HTTP_ENDPOINTS, ids=repr)
async def test_a_recipient_that_is_not_an_http_url_is_refused(test_client, network, caplog, endpoint):
    with caplog.at_level(logging.WARNING, logger="a2cn.server"):
        r = await _create(test_client, endpoint)
    assert r.status_code == 201
    assert network.lookups == [] and network.log == []
    assert "Invitation not delivered" in _delivery_log(caplog)


async def test_a_redirect_from_a_public_recipient_is_not_followed(test_client, network, caplog):
    network.response = _response(307, "Temporary Redirect", {"Location": f"https://{ELSEWHERE_HOST}/invitations"})
    with caplog.at_level(logging.WARNING, logger="a2cn.server"):
        r = await _create(test_client, RECIPIENT)
    assert r.status_code == 201
    assert network.requests() == ["POST /a2cn/invitations HTTP/1.1"]
    assert network.lookups == [RECIPIENT_HOST]
    assert network.connects == [PUBLIC]
    assert "307" in _delivery_log(caplog)


# --- Delivered ----------------------------------------------------------------


async def test_a_public_recipient_is_delivered_through_the_address_it_checked(test_client, network):
    r = await _create(test_client, RECIPIENT)
    assert r.status_code == 201
    assert network.lookups == [RECIPIENT_HOST]
    assert network.log == [("connect", PUBLIC), ("tls", RECIPIENT_HOST)]
    assert network.requests() == ["POST /a2cn/invitations HTTP/1.1"]
    assert network.body() == r.json()


async def test_a_proxy_from_the_environment_is_not_used(test_client, network, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://10.9.9.9:3128")
    r = await _create(test_client, RECIPIENT)
    assert r.status_code == 201
    assert network.connects == [PUBLIC]


# --- The response does not depend on delivery ---------------------------------

LEAKS = (
    RECIPIENT_HOST, PUBLIC, PRIVATE_HOST, PRIVATE_ADDRESS, "127.0.0.1", "non-public", "IP address",
    "refused", "Refused", "deliver", "the-secret-detail", "ConnectError", "recipient_endpoint",
)


async def test_the_response_is_the_same_whether_delivery_is_refused_fails_or_succeeds(
    test_client, network, caplog
):
    network.dns["unreachable.example"] = [ELSEWHERE]
    network.unreachable = {ELSEWHERE}
    outcomes = {
        "none": None,
        "private": f"https://{PRIVATE_HOST}",
        "ip-literal": "http://127.0.0.1:8001",
        "not-http": "file:///etc",
        "unresolvable": "https://no-such-host.example",
        "unreachable": "https://unreachable.example",
        "delivered": RECIPIENT,
    }
    shapes = {}
    with caplog.at_level(logging.WARNING, logger="a2cn.server"):
        for name, endpoint in outcomes.items():
            r = await _create(test_client, endpoint)
            assert r.status_code == 201, name
            for leaked in LEAKS:
                assert leaked not in r.text, (name, leaked)
            shapes[name] = (r.status_code, sorted(r.json()), r.headers.get("content-type"))
    assert len(set(map(repr, shapes.values()))) == 1, shapes
    # Every failure was logged; the delivered one was not.
    log = _delivery_log(caplog)
    for name in ("private", "ip-literal", "not-http", "unresolvable", "unreachable"):
        assert outcomes[name] in log, name
    assert RECIPIENT not in log


# --- The opt-in -----------------------------------------------------------------


async def test_the_server_setting_lets_a_private_recipient_through(test_client, network, monkeypatch):
    import a2cn.server as server_module

    monkeypatch.setattr(server_module, "ALLOW_PRIVATE_HOSTS", True)
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post("http://127.0.0.1:8001/invitations").mock(return_value=httpx.Response(202))
        r = await _create(test_client, "http://127.0.0.1:8001")
    assert r.status_code == 201
    assert json.loads(route.calls.last.request.content) == r.json()
    assert network.lookups == []  # the plain client, not the policy's


async def test_the_server_setting_is_off_by_default(test_client, network):
    import a2cn.server as server_module

    assert server_module.ALLOW_PRIVATE_HOSTS is False
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post("http://127.0.0.1:8001/invitations").mock(return_value=httpx.Response(202))
        r = await _create(test_client, "http://127.0.0.1:8001")
    assert r.status_code == 201
    assert not route.called


def test_the_server_setting_is_read_from_the_environment(monkeypatch):
    import a2cn.server as server_module

    monkeypatch.delenv("A2CN_ALLOW_PRIVATE_HOSTS", raising=False)
    assert importlib.reload(server_module).ALLOW_PRIVATE_HOSTS is False
    monkeypatch.setenv("A2CN_ALLOW_PRIVATE_HOSTS", "1")
    assert importlib.reload(server_module).ALLOW_PRIVATE_HOSTS is True
    monkeypatch.delenv("A2CN_ALLOW_PRIVATE_HOSTS")
    importlib.reload(server_module)


# --- Delivery starts after the response ---------------------------------------


async def test_the_response_is_sent_before_delivery_finishes(test_client, network, monkeypatch, initiator_keypair):
    """The 201 goes out while the delivery's lookup is still held open, so the
    response and its timing do not depend on the delivery. This drives the ASGI
    app directly: httpx's ASGITransport returns only once the app, background
    tasks included, has finished, which is how the other tests here see a
    delivery complete."""
    import a2cn.server as server_module
    from a2cn.crypto import create_jwt
    from tests.conftest import INITIATOR_DID, SERVER_DID

    gate = asyncio.Event()

    async def held_lookup(host, port):
        network.lookups.append(host)
        await gate.wait()
        return list(network.dns[host])

    monkeypatch.setattr(did_module, "_lookup", held_lookup)

    token = create_jwt(INITIATOR_DID, SERVER_DID, initiator_keypair[0], kid=f"{INITIATOR_DID}#key-1", exp_seconds=60)
    body = json.dumps({"proposed_deal_type": "saas_renewal", "recipient_endpoint": RECIPIENT}).encode()
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "scheme": "http", "path": "/invitations/create", "raw_path": b"/invitations/create",
        "query_string": b"", "root_path": "", "client": ("127.0.0.1", 50000), "server": ("test", 80),
        "headers": [
            (b"host", b"test"),
            (b"content-type", b"application/a2cn+json"),
            (b"content-length", str(len(body)).encode()),
            (b"authorization", f"Bearer {token}".encode()),
        ],
    }
    requested = False
    finished = asyncio.Event()
    response_sent = asyncio.Event()
    messages: list[dict] = []

    async def receive():
        nonlocal requested
        if not requested:
            requested = True
            return {"type": "http.request", "body": body, "more_body": False}
        await finished.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            response_sent.set()

    app = asyncio.create_task(server_module.app(scope, receive, send))
    try:
        # Bounds only the failure: a delivery awaited before responding holds the 201 until the gate opens.
        await asyncio.wait_for(response_sent.wait(), timeout=5)
        assert messages[0]["status"] == 201
        response = json.loads(b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body"))
        assert not app.done()
        assert network.sent == bytearray()  # nothing delivered yet
    finally:
        gate.set()
        finished.set()
        await asyncio.wait_for(app, timeout=5)
    # Released, the delivery completes after the response.
    assert network.lookups == [RECIPIENT_HOST]
    assert network.connects == [PUBLIC]
    assert network.requests() == ["POST /a2cn/invitations HTTP/1.1"]
    assert network.body() == response
