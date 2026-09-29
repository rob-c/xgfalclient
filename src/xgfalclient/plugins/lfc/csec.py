"""Csec: how an LFC connection is authenticated before the first request.

Csec (lcgdm's ``security/``) runs once per TCP connection, straight after
``connect``, and then gets out of the way: the Cns requests that follow are
sent in the clear, authorised by the identity Csec established. It has two
parts.

**Negotiation** (``Csec_protocol_policy.c``). The client sends a
``PROTOCOL_REQ`` token listing the mechanisms it can use, in its order of
preference, with delegation flags; the server answers ``PROTOCOL_RESP``
with ``OK`` and the index of the first client mechanism it also allows, or
``NOK`` and its own list. The client's list is ``$CSEC_MECH``, else the
built-in ``GSI ID`` of the EL7 packages.

**The mechanism** (``Csec_plugin_*.c``), in ``HANDSHAKE`` tokens:

``GSI``
    GSS-API over Globus GSI: TLS records carried in tokens (see
    :mod:`~xgfalclient.crypto.gsi`), the last one sent as
    ``HANDSHAKE_FINAL``. liblfc never asks for delegation, so the GSI
    delegation byte is ``0``. A failure is reported to the peer in a
    ``HANDSHAKE_ERROR`` token carrying a reason code.
``KRB5``
    the same exchange with Kerberos 5 GSS tokens for ``host@<server>``,
    through :mod:`~xgfalclient.crypto.krb5` when a Kerberos library is
    present.
``ID``
    one token, ``"<uid> <gid> <username>"``. The server believes it only
    from hosts in its ``TRUST`` list, and then treats the client as root.

Every token is framed as ``LONG 0xCA03, LONG type, LONG length, data``
(``_Csec_send_token``/``_Csec_recv_token`` in ``Csec_common.c``).
"""

from __future__ import annotations

import errno
import os
import socket
import ssl
import struct
from collections.abc import Sequence
from typing import Any

from ..._compat import TIMEOUTS
from ...crypto.gsi import GSIError, SecurityContext
from ...errors import GError
from .wire import Packer, Unpacker, WireError

__all__ = [
    "CsecError",
    "TokenLink",
    "Mechanism",
    "IDMechanism",
    "GSIMechanism",
    "KRB5Mechanism",
    "negotiate",
    "authenticate",
    "encode_request",
    "decode_request",
    "encode_response",
    "decode_response",
    "DEFAULT_MECHS",
    "TOKEN_MAGIC",
]

TOKEN_MAGIC = 0xCA03
PROTOCOL_REQ = 1
PROTOCOL_RESP = 2
HANDSHAKE = 3
HANDSHAKE_FINAL = 5
HANDSHAKE_ERROR = 6

#: ``CSEC_VERSION``.
VERSION = 2
DELEG = 0x1
NODELEG = 0x2
#: ``_Csec_notify_peer_of_handshake_error`` reason codes.
REASON_NONEGIVEN = 0
REASON_ACQUIRE_FAILED = 1
#: ``_Csec_recv_token`` refuses empty tokens and tokens over 128 KiB.
MAX_TOKEN = 128 * 1024
#: ``MAXNETLISTLEN``.
MAX_LIST = 1024

#: ``CSEC_DEFAULT_MECHS`` as the EL7 ``lcgdm-libs`` package was built.
DEFAULT_MECHS = ("GSI", "ID")

_HEAD = struct.Struct(">III")


class CsecError(GError):
    """Authentication failed; ``EACCES`` unless the network was at fault."""

    def __init__(self, message: str, code: int = errno.EACCES) -> None:
        super().__init__(message, code)


def _socket_error(exc: BaseException, peer: str) -> GError:
    if isinstance(exc, TIMEOUTS):
        return GError(f"Timed out authenticating with {peer}", errno.ETIMEDOUT)
    code = getattr(exc, "errno", None) or errno.ECONNRESET
    return GError(f"Lost the connection to {peer} while authenticating: {exc}", code)


class TokenLink:
    """Csec tokens over a connected socket."""

    def __init__(self, sock: socket.socket, peer: str) -> None:
        self.sock = sock
        self.peer = peer

    def send_token(self, kind: int, data: bytes) -> None:
        try:
            self.sock.sendall(_HEAD.pack(TOKEN_MAGIC, kind, len(data)) + data)
        except OSError as exc:  # socket.timeout is an OSError too
            raise _socket_error(exc, self.peer) from exc

    def _exact(self, size: int) -> bytes:
        chunks = bytearray()
        try:
            while len(chunks) < size:
                chunk = self.sock.recv(size - len(chunks))
                if not chunk:
                    raise GError(
                        f"{self.peer} closed the connection during authentication",
                        errno.ECONNRESET,
                    )
                chunks += chunk
        except OSError as exc:
            raise _socket_error(exc, self.peer) from exc
        return bytes(chunks)

    def recv_token(self) -> tuple[int, bytes]:
        magic, kind, length = _HEAD.unpack(self._exact(_HEAD.size))
        if magic != TOKEN_MAGIC:
            raise CsecError(
                f"{self.peer} sent a bad Csec token (magic {magic:#x}, expected "
                f"{TOKEN_MAGIC:#x}); is it an LFC?",
                errno.EPROTO,
            )
        if not 0 < length <= MAX_TOKEN:
            raise CsecError(f"{self.peer} sent a Csec token of {length} bytes", errno.EPROTO)
        return kind, self._exact(length)


# -- negotiation --------------------------------------------------------------------


def _deleg_able(mech: str) -> bool:
    return mech == "GSI"


def _flag_sets(mechs: Sequence[str]) -> Packer:
    """No delegation wanted: mark the mechanisms that cannot delegate ``NODELEG``."""
    packer = Packer()
    unable = [index for index, mech in enumerate(mechs) if not _deleg_able(mech)]
    if unable:
        packer.long(1).long(NODELEG).long(len(unable))
        for index in unable:
            packer.long(index)
    else:
        packer.long(0)
    return packer


def encode_request(mechs: Sequence[str], authorization: tuple[str, str] | None = None) -> bytes:
    """``Csec_client_negociate_protocol``'s ``PROTOCOL_REQ`` body."""
    packer = Packer().long(VERSION)
    if authorization is None:
        packer.long(0)
    else:
        packer.long(1).string(authorization[0]).string(authorization[1])
    packer.long(len(mechs))
    for mech in mechs:
        packer.string(mech)
    if mechs:
        packer.raw(_flag_sets(mechs).bytes())
    packer.long(0)  # no VOMS data
    return packer.bytes()


def _read_flag_sets(reader: Unpacker, count: int) -> list[int]:
    flags = [0] * count
    sets = reader.ulong()
    if sets > MAX_LIST:
        raise WireError("too many sets of Csec flags")
    for _ in range(sets):
        value, nindexes = reader.ulong(), reader.ulong()
        if nindexes > MAX_LIST:
            raise WireError("too many Csec flag indexes")
        for _ in range(nindexes):
            index = reader.ulong()
            if index < count:
                flags[index] |= value
    return flags


def _read_list(reader: Unpacker) -> list[str]:
    count = reader.ulong()
    if count > MAX_LIST:
        raise WireError("too many Csec protocols")
    return [reader.string(15) for _ in range(count)]


def decode_request(
    data: bytes,
) -> tuple[int, tuple[str, str] | None, list[str], list[int]]:
    """``(version, authorization id, mechanisms, flags)`` from a ``PROTOCOL_REQ``."""
    reader = Unpacker(data)
    version = reader.ulong()
    authorization = None
    if reader.ulong():
        authorization = (reader.string(15), reader.string(511))
    mechs = _read_list(reader)
    flags = _read_flag_sets(reader, len(mechs)) if mechs else []
    return version, authorization, mechs, flags


def encode_response(version: int, chosen: int | None, flags: int, offered: Sequence[str]) -> bytes:
    """``Csec_server_negociate_protocol``'s ``PROTOCOL_RESP`` body."""
    packer = Packer().long(min(version, VERSION))
    if chosen is not None:
        return packer.string("OK").long(chosen).long(flags).bytes()
    packer.string("NOK").long(2709).long(len(offered))  # ESEC_PROTNOTSUPP
    for mech in offered:
        packer.string(mech)
    if offered:
        packer.raw(_flag_sets(offered).bytes())
    return packer.bytes()


def decode_response(data: bytes) -> tuple[int, int | None, int, list[str]]:
    """``(version, chosen index or None, flags, server mechanisms)``."""
    reader = Unpacker(data)
    version = reader.ulong()
    verdict = reader.string(1500)
    if verdict == "OK":
        return version, reader.ulong(), reader.ulong(), []
    reader.ulong()  # failure reason
    offered = _read_list(reader)
    if offered:
        _read_flag_sets(reader, len(offered))
    return version, None, 0, offered


def negotiate(
    link: TokenLink, mechs: Sequence[str], authorization: tuple[str, str] | None = None
) -> str:
    """Agree on a mechanism with the server; its name."""
    link.send_token(PROTOCOL_REQ, encode_request(mechs, authorization))
    kind, data = link.recv_token()
    if kind != PROTOCOL_RESP:
        raise CsecError(f"{link.peer} answered the Csec negotiation with token type {kind}")
    _, chosen, flags, offered = decode_response(data)
    if chosen is None:
        theirs = " ".join(offered) or "none"
        raise CsecError(
            f"{link.peer} and this client share no authentication method "
            f"(offered {' '.join(mechs) or 'none'}; the server allows {theirs})"
        )
    if chosen >= len(mechs) or not flags & (DELEG | NODELEG) or flags & DELEG:
        raise CsecError(f"{link.peer} chose an impossible Csec protocol", errno.EPROTO)
    return mechs[chosen]


# -- mechanisms ------------------------------------------------------------------------


class Mechanism:
    """One Csec mechanism's client side."""

    name = ""

    def authenticate(self, link: TokenLink, host: str) -> None:
        raise NotImplementedError


class IDMechanism(Mechanism):
    """``Csec_plugin_ID``: the local uid, gid and user name, on trust."""

    name = "ID"

    def __init__(self, uid: int, gid: int, username: str) -> None:
        self.uid = uid
        self.gid = gid
        self.username = username

    def authenticate(self, link: TokenLink, host: str) -> None:
        text = f"{self.uid} {self.gid} {self.username}"
        link.send_token(HANDSHAKE, text.encode("utf-8", "surrogateescape"))


def _abort(link: TokenLink, reason: int) -> None:
    """Tell the server the handshake is off, as Csec does, ignoring a dead link."""
    try:
        link.send_token(HANDSHAKE_ERROR, struct.pack(">I", reason))
    except GError:
        pass


class _TokenMechanism(Mechanism):
    """The GSS token loop shared by GSI and KRB5 (``Csec_plugin_GSS.c``)."""

    def context(self, host: str) -> Any:
        raise NotImplementedError

    def check(self, context: Any, host: str) -> None:
        """Verify the server's identity once the context is up."""

    def authenticate(self, link: TokenLink, host: str) -> None:
        context = self.context(host)
        try:
            token = context.step(b"")
            while True:
                done = bool(context.complete)
                if token:
                    link.send_token(HANDSHAKE_FINAL if done else HANDSHAKE, token)
                if done:
                    break
                kind, data = link.recv_token()
                if kind == HANDSHAKE_ERROR:
                    raise CsecError(
                        f"{link.peer} had a problem authenticating this connection with {self.name}"
                    )
                token = context.step(data)
            self.check(context, host)
        except CsecError:
            raise  # the server gave up first: nothing to tell it
        except (GSIError, GError) as exc:
            _abort(link, REASON_NONEGIVEN)
            code = exc.code if isinstance(exc, GError) else errno.EACCES
            raise CsecError(
                f"{self.name} authentication with {link.peer} failed: {exc}", code
            ) from exc


class GSIMechanism(_TokenMechanism):
    """GSI: TLS in tokens, the delegation byte ``0``, GSI's host-name check."""

    name = "GSI"

    def __init__(self, tls: ssl.SSLContext | None) -> None:
        self.tls = tls

    def authenticate(self, link: TokenLink, host: str) -> None:
        if self.tls is None:
            # Csec acquires credentials after the negotiation and says so.
            _abort(link, REASON_ACQUIRE_FAILED)
            raise CsecError(
                "No X.509 credential for GSI authentication (set X509_USER_PROXY, "
                "or X509_USER_CERT and X509_USER_KEY)"
            )
        super().authenticate(link, host)

    def context(self, host: str) -> SecurityContext:
        assert self.tls is not None
        return SecurityContext(self.tls, server_hostname=host)

    def check(self, context: Any, host: str) -> None:
        context.check_host(host)


class KRB5Mechanism(_TokenMechanism):
    """Kerberos 5 for ``host@<server>``, when a Kerberos library is present."""

    name = "KRB5"

    def context(self, host: str) -> Any:
        from ...crypto import krb5

        # Csec asks for mutual authentication and replay detection, nothing more.
        return krb5.ClientContext(
            "host", host, sequence=False, integrity=False, confidentiality=False
        )


def available_krb5() -> bool:
    """Whether a Kerberos 5 GSS-API library can be used."""
    from ...crypto import krb5

    return krb5.available() is None


def mechanism_names(value: str | None) -> list[str]:
    """``$CSEC_MECH`` (space- or tab-separated), else the default list."""
    names = (value or "").split()
    return names or list(DEFAULT_MECHS)


def authenticate(
    sock: socket.socket,
    peer: str,
    host: str,
    mechanisms: Sequence[Mechanism],
    authorization: tuple[str, str] | None = None,
) -> str:
    """Run Csec on a fresh connection; the name of the mechanism used."""
    link = TokenLink(sock, peer)
    by_name = {mech.name: mech for mech in mechanisms}
    chosen = negotiate(link, [mech.name for mech in mechanisms], authorization)
    by_name[chosen].authenticate(link, host)
    return chosen


def local_identity() -> tuple[int, int, str]:
    """``geteuid``, ``getegid`` and the user name, for the ID mechanism."""
    uid = getattr(os, "geteuid", lambda: 0)()
    gid = getattr(os, "getegid", lambda: 0)()
    try:
        import pwd

        name = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):  # Windows, or a uid nobody named
        name = str(uid)
    return uid, gid, name
