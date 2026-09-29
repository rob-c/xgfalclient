"""The GSI security context: token-driven TLS, the delegation byte, name checks."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from conftest import needs_peer_chain
from xgfalclient.crypto import der, gsi, rsa, x509
from xgfalclient.crypto.gsi import DelegatedCredential, GSIError, SecurityContext
from xgfalclient.crypto.proxy import make_request, sign_request
from xgfalclient.testing.pki import PKI, create_pki, test_key


def client_tls(pki: PKI, *, ca: Path | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(ca or pki.ca_file))
    context.check_hostname = False
    context.load_cert_chain(str(pki.proxy_path))
    return context


def drive(client: SecurityContext, server: SecurityContext, limit: int = 20) -> None:
    """Ferry tokens until both sides are complete and nothing is left in flight.

    The last token matters even after both report completion: under TLS 1.3
    the server's final token carries session tickets, and a client that
    drops it has lost records from the stream.
    """
    token = client.step()
    for _ in range(limit):
        token = server.step(token)
        token = client.step(token)
        if client.complete and server.complete and not token:
            return
    raise AssertionError("the GSI exchange did not converge")


def test_handshake_without_delegation(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki), server_hostname="localhost")
    server = SecurityContext(pki.server_context(), server_side=True)
    drive(client, server)
    assert server.delegated is None and client.delegated is None
    assert server.unwrap(client.wrap(b"MIC stuff")) == b"MIC stuff"
    assert client.unwrap(server.wrap(b"reply")) == b"reply"
    client.check_host("localhost")
    peer = server.peer_certificate()
    assert peer is not None and peer.is_proxy


@needs_peer_chain
def test_handshake_with_delegation(pki: PKI) -> None:
    credential = pki.credential()
    client = SecurityContext(client_tls(pki), delegate=credential, lifetime=600)
    server = SecurityContext(pki.server_context(), server_side=True, delegation_key=test_key(4))
    drive(client, server)
    delegated = server.delegated
    assert isinstance(delegated, DelegatedCredential)
    assert delegated.chain[0].public_key == test_key(4).public
    assert delegated.chain[0].issuer.rdns == credential.certificate.subject.rdns
    assert (
        delegated.chain[0].not_after
        <= x509.parse_certificate(delegated.chain[0].der).not_before + 600 + 300
    )
    assert delegated.credential().identity == str(pki.user.subject)
    pem = delegated.pem()
    proxy_file = pki.directory / "delegated.pem"
    proxy_file.write_bytes(pem)
    ssl.create_default_context().load_cert_chain(str(proxy_file))  # usable as a client credential


def test_limited_delegation(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki), delegate=pki.credential(), limited=True)
    server = SecurityContext(pki.server_context(), server_side=True, delegation_key=test_key(4))
    drive(client, server)
    assert server.delegated is not None and server.delegated.chain[0].is_limited


def test_server_generates_its_key(pki: PKI, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        rsa.RSAPrivateKey, "generate", classmethod(lambda cls, bits=2048: test_key(7))
    )
    client = SecurityContext(client_tls(pki), delegate=pki.credential())
    server = SecurityContext(pki.server_context(), server_side=True)
    drive(client, server)
    assert server.delegation_key is test_key(7)


def test_handshake_failure(pki: PKI, tmp_path: Path) -> None:
    other = create_pki(tmp_path / "other", key_slots=(5, 6, 7))
    client = SecurityContext(client_tls(pki, ca=other.ca_file))
    server = SecurityContext(pki.server_context(), server_side=True)
    with pytest.raises(GSIError, match="TLS handshake failed"):
        drive(client, server)


class BadFlag(SecurityContext):
    def _handshake(self) -> None:
        try:
            self.tls.do_handshake()
        except ssl.SSLWantReadError:
            return
        self.tls.write(b"X")
        self._state, self.complete = "done", True


def test_unexpected_flag(pki: PKI) -> None:
    client = BadFlag(client_tls(pki))
    server = SecurityContext(pki.server_context(), server_side=True)
    with pytest.raises(GSIError, match="unexpected GSI delegation flag"):
        drive(client, server)


def _handshaken(pki: PKI, *, delegate: bool) -> tuple[SecurityContext, SecurityContext]:
    """A pair whose handshake is done but whose delegation has not started."""
    client = SecurityContext(client_tls(pki), delegate=pki.credential() if delegate else None)
    server = SecurityContext(pki.server_context(), server_side=True, delegation_key=test_key(4))
    token = client.step()
    while client._state in ("handshake", "turn"):
        token = client.step(server.step(token))
    server.step(token)  # the flag
    return client, server


def test_partial_request_and_chain_wait(pki: PKI) -> None:
    client, _ = _handshaken(pki, delegate=True)
    request = make_request(test_key(4))
    client._pending = request[:10]
    client._answer_request()
    assert not client.complete and client._state == "request"
    _, server = _handshaken(pki, delegate=True)
    server._state = "chain"
    server._pending = b"\x30\x82\x05\x00partial"
    server._accept_chain()
    assert not server.complete


def test_chain_for_the_wrong_key(pki: PKI) -> None:
    _, server = _handshaken(pki, delegate=True)
    server._state = "chain"
    server._pending = sign_request(make_request(test_key(5)), pki.credential())
    with pytest.raises(GSIError, match="does not certify the requested key"):
        server._accept_chain()


def test_full_chain_from_an_older_peer(pki: PKI) -> None:
    """A delegator that sends its whole chain is accepted as sent."""
    from xgfalclient.crypto.proxy import delegation_payload

    _, server = _handshaken(pki, delegate=True)
    server._state = "chain"
    server._pending = delegation_payload(
        sign_request(make_request(test_key(4)), pki.credential()), pki.credential()
    )
    server._accept_chain()
    assert server.delegated is not None and len(server.delegated.chain) == 3


def test_ssl_compatible_is_plain_tls(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki), ssl_compatible=True)
    server = SecurityContext(pki.server_context(), server_side=True, ssl_compatible=True)
    drive(client, server)
    assert server.unwrap(client.wrap(b"data")) == b"data"


def test_tls12_has_no_turn(pki: PKI) -> None:
    tls = client_tls(pki)
    tls.maximum_version = ssl.TLSVersion.TLSv1_2
    client = SecurityContext(tls, delegate=pki.credential())
    server = SecurityContext(pki.server_context(), server_side=True, delegation_key=test_key(4))
    drive(client, server)
    assert client.tls.version() == "TLSv1.2" and server.delegated is not None


def test_unsignable_request(pki: PKI) -> None:
    client, _ = _handshaken(pki, delegate=True)
    client._pending = der.sequence(der.integer(1))
    with pytest.raises(GSIError, match="cannot sign the delegation request"):
        client._answer_request()


def test_garbage_and_close_notify(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki))
    server = SecurityContext(pki.server_context(), server_side=True)
    drive(client, server)
    with pytest.raises(GSIError, match="cannot decrypt"):
        server.unwrap(b"\x17\x03\x03\x00\x05hello")
    client = SecurityContext(client_tls(pki))
    server = SecurityContext(pki.server_context(), server_side=True)
    drive(client, server)
    with pytest.raises(ssl.SSLWantReadError):
        server.tls.unwrap()  # sends close_notify, then waits for the peer's
    assert client.unwrap(server._out.read()) == b""


def test_peer_without_certificate(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki))
    server = SecurityContext(pki.server_context(require_client=False), server_side=True)
    drive(client, server)
    assert server.peer_certificate() is None
    with pytest.raises(GSIError, match="no certificate"):
        server.check_host("localhost")


def test_host_names(pki: PKI) -> None:
    gsi.check_host(pki.host, "LOCALHOST.")
    with pytest.raises(GSIError, match="does not match host"):
        gsi.check_host(pki.host, "other.example")
    assert gsi.dns_names(pki.host) == ["localhost"]
    assert gsi.dns_names(pki.ca) == []
    broken = x509.Certificate(
        **{**_fields(pki.host), "extensions": {x509.SUBJECT_ALT_NAME_OID: (False, b"\x05")}}
    )
    assert gsi.dns_names(broken) == []
    by_cn = x509.Certificate(
        **{**_fields(pki.ca), "subject": x509.Name((("CN", "ftp/se.example.org"),))}
    )
    gsi.check_host(by_cn, "se.example.org")
    plain_cn = x509.Certificate(
        **{**_fields(pki.ca), "subject": x509.Name((("CN", "se.example.org"),))}
    )
    gsi.check_host(plain_cn, "se.example.org")
    assert gsi._matches("*.example.org", "a.example.org")
    assert not gsi._matches("*.example.org", "example.org")
    assert not gsi._matches("*.example.org", ".example.org")
    assert not gsi._matches("*.example.org", "a.b.example.org")


def _fields(cert: x509.Certificate) -> dict[str, object]:
    return {name: getattr(cert, name) for name in x509.Certificate.__dataclass_fields__}


def test_dcache_style_peers_take_no_turn(pki: PKI) -> None:
    """dCache's GSI engine neither sends nor waits for the TLS 1.3 turn."""
    client = SecurityContext(client_tls(pki), delegate=pki.credential(), turn=False)
    server = SecurityContext(
        pki.server_context(), server_side=True, delegation_key=test_key(4), turn=False
    )
    drive(client, server)
    assert client.tls.version() == "TLSv1.3" and server.delegated is not None
    assert server.unwrap(client.wrap(b"hello")) == b"hello"
