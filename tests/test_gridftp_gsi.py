"""The globus flavour of GSI: the TLS 1.3 turn, one-certificate delegation, data contexts."""

from __future__ import annotations

import os
import socket
import ssl
import threading
from pathlib import Path

import pytest

from conftest import needs_peer_chain
from xgfalclient.crypto.der import sequence
from xgfalclient.crypto.gsi import GSIError, SecurityContext
from xgfalclient.crypto.proxy import make_request
from xgfalclient.plugins.gridftp import gsi
from xgfalclient.plugins.gridftp.data import authenticate
from xgfalclient.plugins.gridftp.gsi import TURN, GlobusContext, data_contexts, same_identity
from xgfalclient.testing.pki import PKI, create_pki, test_key


def client_tls(pki: PKI, *, tls12: bool = False) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(pki.ca_file))
    context.check_hostname = False
    context.load_cert_chain(str(pki.proxy_path))
    if tls12:
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    return context


def drive(client: SecurityContext, server: SecurityContext) -> list[bytes]:
    """Ferry tokens until both are complete; the tokens the server sent."""
    sent = []
    token = client.step()
    for _ in range(20):
        token = server.step(token)
        sent.append(token)
        token = client.step(token)
        if client.complete and server.complete and not token:
            return sent
    raise AssertionError("the GSI exchange did not converge")


@needs_peer_chain
def test_tls13_turn_and_one_certificate_delegation(pki: PKI) -> None:
    client = GlobusContext(client_tls(pki), delegate=pki.credential())
    server = GlobusContext(pki.server_context(), server_side=True, delegation_key=test_key(4))
    sent = drive(client, server)
    assert client.tls.version() == "TLSv1.3"
    # The server's reply to the client's Finished carries the one-byte turn.
    assert any(len(token) >= 23 for token in sent[1:])
    delegated = server.delegated
    assert delegated is not None
    assert delegated.chain[0].public_key == test_key(4).public
    # The server rebuilt the chain from the TLS session, as globus does.
    assert [str(link.subject) for link in delegated.chain[1:]] == [
        str(link.subject) for link in pki.credential().chain
    ]
    assert server.unwrap(client.wrap(b"USER :globus-mapping:\r\n")) == b"USER :globus-mapping:\r\n"


def test_tls13_without_delegation(pki: PKI) -> None:
    client = GlobusContext(client_tls(pki))
    server = GlobusContext(pki.server_context(), server_side=True)
    drive(client, server)
    assert server.delegated is None


def test_tls12_flag_follows_the_handshake(pki: PKI) -> None:
    client = GlobusContext(client_tls(pki, tls12=True), delegate=pki.credential())
    server = GlobusContext(pki.server_context(), server_side=True, delegation_key=test_key(4))
    drive(client, server)
    assert client.tls.version() == "TLSv1.2"
    assert server.delegated is not None


@needs_peer_chain
def test_a_core_client_that_sends_the_whole_chain(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki, tls12=True), delegate=pki.credential())
    server = GlobusContext(pki.server_context(), server_side=True, delegation_key=test_key(4))
    drive(client, server)
    assert server.delegated is not None
    assert len(server.delegated.chain) == 1 + len(pki.credential().chain)


def test_ssl_compatible_is_plain_tls(pki: PKI) -> None:
    client = GlobusContext(client_tls(pki), ssl_compatible=True)
    server = GlobusContext(pki.server_context(), server_side=True, ssl_compatible=True)
    drive(client, server)
    assert client.unwrap(server.wrap(b"data")) == b"data"


def test_handshake_failure(pki: PKI, tmp_path: Path) -> None:
    other = create_pki(tmp_path, key_slots=(5, 6, 7))
    client = GlobusContext(client_tls(other))
    server = GlobusContext(pki.server_context(), server_side=True)
    with pytest.raises(GSIError, match="handshake failed"):
        drive(client, server)


def test_delegation_request_edge_cases(pki: PKI) -> None:
    client = GlobusContext(client_tls(pki), delegate=pki.credential())
    request = make_request(test_key(4))
    client._pending = request[:10]
    client._answer_request()  # incomplete: waits
    assert not client.complete
    client._pending = sequence(b"\x02\x01\x00")
    with pytest.raises(GSIError, match="cannot sign"):
        client._answer_request()


def test_delegated_chain_edge_cases(pki: PKI) -> None:
    server = GlobusContext(pki.server_context(), server_side=True, delegation_key=test_key(4))
    certificate = pki.credential().chain[0].der
    server._pending = certificate[:20]
    server._accept_chain()  # incomplete: waits
    assert not server.complete
    server._pending = certificate
    with pytest.raises(GSIError, match="does not certify"):
        server._accept_chain()


def test_same_identity(pki: PKI) -> None:
    user = pki.credential().chain[1]
    proxy = pki.credential().chain[0]
    assert same_identity(proxy, user.subject.rdns)
    assert same_identity(user, user.subject.rdns)
    assert not same_identity(user, proxy.subject.rdns)
    assert not same_identity(None, user.subject.rdns)


def test_data_contexts_are_cached(pki: PKI) -> None:
    path = str(pki.proxy_path)
    first = data_contexts(path, path, str(pki.ca_dir))
    assert data_contexts(path, path, str(pki.ca_dir)) is first
    initiator, acceptor = data_contexts(path, path, None)
    assert initiator.verify_mode == ssl.CERT_REQUIRED
    assert acceptor.verify_flags & gsi.ALLOW_PROXY


def _pair(pki: PKI, *, ssl_compatible: bool, identity: tuple[tuple[str, str], ...] | None = None):  # type: ignore[no-untyped-def]
    path = str(pki.proxy_path)
    initiator, acceptor = data_contexts(path, path, str(pki.ca_dir))
    person = identity or pki.credential().chain[1].subject.rdns
    left, right = socket.socketpair()
    results: dict[str, object] = {}

    def accept() -> None:
        try:
            results["acceptor"] = authenticate(
                right, acceptor, initiator=False, identity=person, ssl_compatible=ssl_compatible
            )
        except Exception as exc:
            results["acceptor"] = exc

    thread = threading.Thread(target=accept)
    thread.start()
    try:
        results["initiator"] = authenticate(
            left, initiator, initiator=True, identity=person, ssl_compatible=ssl_compatible
        )
    except Exception as exc:
        results["initiator"] = exc
    thread.join(10)
    left.close()
    right.close()
    return results


@pytest.mark.parametrize("ssl_compatible", [False, True])
def test_data_channel_authentication(pki: PKI, ssl_compatible: bool) -> None:
    results = _pair(pki, ssl_compatible=ssl_compatible)
    assert isinstance(results["initiator"], SecurityContext)
    assert isinstance(results["acceptor"], SecurityContext)


def test_data_channel_wrong_identity(pki: PKI) -> None:
    from xgfalclient.errors import GError

    results = _pair(pki, ssl_compatible=False, identity=(("CN", "Somebody Else"),))
    assert isinstance(results["initiator"], GError)
    assert "the peer is not /CN=Somebody Else" in results["initiator"].message


def test_data_channel_peer_hangs_up(pki: PKI) -> None:
    from xgfalclient.errors import GError

    path = str(pki.proxy_path)
    initiator, _ = data_contexts(path, path, str(pki.ca_dir))
    left, right = socket.socketpair()

    def hang_up() -> None:
        right.recv(65536)  # the ClientHello
        right.close()

    thread = threading.Thread(target=hang_up)
    thread.start()
    with pytest.raises(GError, match="hung up"):
        authenticate(left, initiator, initiator=True, identity=())
    thread.join()
    left.close()


def test_turn_byte_is_one_null() -> None:
    assert TURN == b"\x00"
    assert os.path.basename(gsi.__file__) == "gsi.py"
