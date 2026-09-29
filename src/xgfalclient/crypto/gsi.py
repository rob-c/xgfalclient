"""The GSI GSSAPI mechanism: TLS carried in tokens, plus delegation.

Globus GSI is SSL/TLS in disguise. ``gss_init_sec_context`` runs a TLS
handshake whose records are handed to the application as opaque tokens, and
the application ferries them however its protocol likes - GridFTP base64s
them into ``ADAT`` commands, httpg writes them straight to a socket. Once
the handshake is over, ``gss_wrap`` is a TLS application-data record and
``gss_unwrap`` decrypts one.

Three things make it GSI rather than plain TLS, and all are here:

* **the turn.** Under TLS 1.3 the client finishes the handshake first, so a
  Globus acceptor (globus-gridftp-server, CGSI-gSOAP) answers the client's
  Finished with one encrypted zero byte, and the client sends nothing more
  until it has read it. dCache's own GSI engine (its dcap and SRM doors)
  sends no turn and reads the flag at once; ``turn=False`` speaks to it.
* **the delegation byte.** Then the client sends one encrypted byte: ``0``
  for no delegation, ``D`` to delegate. After ``D`` the server sends a
  certificate request, and the client answers with the proxy it has signed -
  that certificate alone; the acceptor completes the chain from the
  certificates the client presented in the handshake.
* **the name check.** A GSI server certificate names its host as
  ``CN=host/fqdn`` (or ``ftp/fqdn``) as often as plain ``CN=fqdn``, which
  ``ssl``'s hostname check does not accept, so :func:`check_host` does it.

``ssl_compatible`` is Globus's ``GSS_C_GLOBUS_SSL_COMPATIBLE``: plain TLS,
complete with the handshake, no turn and no delegation byte - what a GridFTP
``PROT P`` data channel speaks.

:class:`SecurityContext` is ``ssl.SSLObject`` over a pair of memory BIOs,
so it works for any transport. The server half exists for the in-process
test servers and anyone who wants to host a GSI endpoint in Python.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass

from .._compat import SLOTS, peer_chain_der
from .der import DERError, parse, parse_one
from .proxy import make_request, sign_request
from .rsa import RSAPrivateKey
from .x509 import (
    SUBJECT_ALT_NAME_OID,
    Certificate,
    Credential,
    parse_certificate,
    split_der_certificates,
)

__all__ = [
    "GSIError",
    "SecurityContext",
    "DelegatedCredential",
    "check_host",
    "dns_names",
    "NO_DELEGATION",
    "DELEGATE",
    "TURN",
]

NO_DELEGATION = b"0"
DELEGATE = b"D"
#: What a TLS 1.3 acceptor sends to hand the turn back after the handshake.
TURN = b"\x00"


class GSIError(Exception):
    """The GSI exchange failed: bad token, refused delegation, name mismatch."""


@dataclass(frozen=True, **SLOTS)
class DelegatedCredential:
    """What a server ends up holding after the client delegated to it."""

    key: RSAPrivateKey
    chain: tuple[Certificate, ...]

    def credential(self) -> Credential:
        return Credential(self.chain, self.key)

    def pem(self) -> bytes:
        """A proxy file: certificate, key, then the rest of the chain."""
        from .rsa import private_key_pem

        first, *rest = self.chain
        return first.pem() + private_key_pem(self.key) + b"".join(link.pem() for link in rest)


class SecurityContext:
    """One side of a GSI security context, driven by tokens.

    Client::

        ctx = SecurityContext(tls, delegate=credential)
        token = ctx.step()                  # ClientHello
        while not ctx.complete:
            token = ctx.step(send_and_receive(token))

    ``step`` takes the peer's latest token (empty to start) and returns the
    token to send back, which may be empty. ``complete`` turns true once the
    handshake, the delegation byte and any delegation are done.
    """

    def __init__(
        self,
        tls: ssl.SSLContext,
        *,
        server_side: bool = False,
        server_hostname: str | None = None,
        delegate: Credential | None = None,
        limited: bool = False,
        lifetime: float | None = None,
        delegation_key: RSAPrivateKey | None = None,
        ssl_compatible: bool = False,
        turn: bool = True,
    ) -> None:
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self.tls = tls.wrap_bio(
            self._in, self._out, server_side=server_side, server_hostname=server_hostname
        )
        self.server_side = server_side
        self.delegate = delegate
        self.limited = limited
        self.lifetime = lifetime
        self.delegation_key = delegation_key
        self.delegated: DelegatedCredential | None = None
        self.ssl_compatible = ssl_compatible
        self.turn = turn
        self.complete = False
        self._state = "handshake"
        self._pending = b""

    # -- the handshake -------------------------------------------------------------

    def step(self, token: bytes = b"") -> bytes:
        """Consume the peer's ``token``; return what to send it next."""
        if token:
            self._in.write(token)
        if self._state == "handshake":
            self._handshake()
        if self._state != "handshake":
            self._after_handshake()
        return self._out.read()

    def _handshake(self) -> None:
        try:
            self.tls.do_handshake()
        except ssl.SSLWantReadError:
            return
        except ssl.SSLError as exc:
            raise GSIError(f"TLS handshake failed: {exc}") from exc
        tls13 = self.turn and self.tls.version() == "TLSv1.3"
        if self.ssl_compatible:
            self._finish()
        elif self.server_side:
            if tls13:
                self.tls.write(TURN)
            self._state = "flag"
        elif tls13:
            self._state = "turn"
        else:
            self._send_flag()

    def _send_flag(self) -> None:
        self.tls.write(NO_DELEGATION if self.delegate is None else DELEGATE)
        self._state = "request" if self.delegate is not None else "done"
        self.complete = self.delegate is None

    def _after_handshake(self) -> None:
        self._pending += self._drain()
        if self._state == "turn":
            if not self._pending:
                return  # the acceptor has not handed the turn back yet
            self._pending = self._pending[1:]
            self._send_flag()
        if self._state == "flag" and self._pending:
            flag, self._pending = self._pending[:1], self._pending[1:]
            if flag == DELEGATE:
                self._send_request()
            elif flag == NO_DELEGATION:
                self._finish()
            else:
                raise GSIError(f"unexpected GSI delegation flag {flag!r}")
        if self._state == "request" and self._pending:
            self._answer_request()
        elif self._state == "chain" and self._pending:
            self._accept_chain()

    def _drain(self) -> bytes:
        chunks = []
        while True:
            try:
                data = self.tls.read(65536)
            except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
                break
            except ssl.SSLError as exc:
                raise GSIError(f"cannot decrypt GSI token: {exc}") from exc
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)

    def _finish(self) -> None:
        self._state = "done"
        self.complete = True

    # -- delegation, client side ---------------------------------------------------------

    def _answer_request(self) -> None:
        try:
            _, end = parse(self._pending)
        except DERError:
            return  # the request has not fully arrived yet
        request, self._pending = self._pending[:end], self._pending[end:]
        assert self.delegate is not None
        try:
            certificate = sign_request(
                request, self.delegate, lifetime=self.lifetime, limited=self.limited
            )
        except DERError as exc:
            raise GSIError(f"cannot sign the delegation request: {exc}") from exc
        self.tls.write(certificate)  # alone: the acceptor has the rest of the chain
        self._finish()

    # -- delegation, server side -----------------------------------------------------------

    def _send_request(self) -> None:
        if self.delegation_key is None:
            self.delegation_key = RSAPrivateKey.generate(2048)
        self.tls.write(make_request(self.delegation_key))
        self._state = "chain"

    def _accept_chain(self) -> None:
        try:
            chain = split_der_certificates(self._pending)
        except DERError:
            return  # more of the chain is still to come
        assert self.delegation_key is not None
        if chain[0].public_key != self.delegation_key.public:
            raise GSIError("the delegated certificate does not certify the requested key")
        if len(chain) == 1:  # the Globus way: complete it from the handshake
            chain.extend(parse_certificate(der) for der in peer_chain_der(self.tls))
        self.delegated = DelegatedCredential(self.delegation_key, tuple(chain))
        self._pending = b""
        self._finish()

    # -- after the handshake ----------------------------------------------------------------

    def wrap(self, data: bytes) -> bytes:
        """``gss_wrap``: encrypt ``data`` into a token."""
        self.tls.write(data)
        return self._out.read()

    def unwrap(self, token: bytes) -> bytes:
        """``gss_unwrap``: every byte of plaintext ``token`` carries."""
        self._in.write(token)
        return self._drain()

    def peer_certificate(self) -> Certificate | None:
        der = self.tls.getpeercert(binary_form=True)
        return parse_certificate(der) if der else None

    def check_host(self, hostname: str) -> None:
        """Raise ``GSIError`` unless the peer's certificate names ``hostname``."""
        certificate = self.peer_certificate()
        if certificate is None:
            raise GSIError("the peer presented no certificate")
        check_host(certificate, hostname)


def dns_names(certificate: Certificate) -> list[str]:
    """The ``dNSName`` entries of the subjectAltName extension."""
    found = certificate.extensions.get(SUBJECT_ALT_NAME_OID)
    if found is None:
        return []
    try:
        names = parse_one(found[1]).children()
    except DERError:
        return []
    return [name.value.decode("ascii", "replace") for name in names if name.tag == 0x82]


def _matches(pattern: str, hostname: str) -> bool:
    pattern, hostname = pattern.lower().rstrip("."), hostname.lower().rstrip(".")
    if pattern.startswith("*."):
        head, _, rest = hostname.partition(".")
        return bool(head) and rest == pattern[2:]
    return pattern == hostname


def check_host(certificate: Certificate, hostname: str) -> None:
    """GSI's host name check: SAN DNS names, then ``CN=[host/|ftp/]fqdn``."""
    candidates = dns_names(certificate)
    for common in certificate.subject.get("CN"):
        candidates.append(common.split("/", 1)[1] if "/" in common else common)
    if not any(_matches(candidate, hostname) for candidate in candidates):
        raise GSIError(
            f"the server certificate {certificate.subject} does not match host {hostname}"
        )
