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
    :mod:`~xrdsec.gsi.gss`), the last one sent as
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

**Where to start reading:** :func:`authenticate`, which
:meth:`.client.Server.connect` calls on each fresh socket; it runs
:func:`negotiate` and then the chosen :class:`Mechanism`. The encode/decode
pairs exist for both ends because the in-process LFC test server
(``xgfalclient.testing.lfc``) answers with :func:`decode_request` and
:func:`encode_response` - change a layout here and both ends move together,
which is why the interop tests against a real LFC matter.

Ordering matters: as in Csec, GSI is offered whether or not a credential
exists, so a missing proxy is reported after a successful negotiation
(``HANDSHAKE_ERROR``, ``REASON_ACQUIRE_FAILED``) rather than by leaving
GSI out of the offer. Nothing here keeps state between
connections; every object is used by one thread for one handshake.
Failures are :class:`CsecError` (``EACCES``, or ``EPROTO`` for a peer that
does not speak Csec) or a ``GError`` with the socket's own ``errno``.
"""

from __future__ import annotations

import contextlib
import errno
import os
import socket
import ssl
import struct
from collections.abc import Sequence
from typing import Any

from xrdsec.gsi.gss import GSIError, SecurityContext

from ...errors import GError
from .wire import Packer, Unpacker, WireError

__all__ = [
    "DEFAULT_MECHS",
    "TOKEN_MAGIC",
    "CsecError",
    "GSIMechanism",
    "IDMechanism",
    "KRB5Mechanism",
    "Mechanism",
    "TokenLink",
    "authenticate",
    "decode_request",
    "decode_response",
    "encode_request",
    "encode_response",
    "negotiate",
]

#: First field of every token; anything else means the peer is not Csec.
TOKEN_MAGIC = 0xCA03
# Token types (``Csec_common.h``).
PROTOCOL_REQ = 1
PROTOCOL_RESP = 2
HANDSHAKE = 3
HANDSHAKE_FINAL = 5
HANDSHAKE_ERROR = 6

#: ``CSEC_VERSION``; the response carries the lower of both ends' versions.
VERSION = 2
#: Per-mechanism negotiation flags: delegation wanted / explicitly not.
#: The server answers with the flags it settled on, which must say
#: ``NODELEG`` - this client never delegates (see :func:`negotiate`).
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

#: Token header: magic, type, length of the data that follows.
_HEAD = struct.Struct(">III")


class CsecError(GError):
    """Authentication failed; ``EACCES`` unless the network was at fault."""

    def __init__(self, message: str, code: int = errno.EACCES) -> None:
        """``code`` defaults to ``EACCES``: the server or the credential said no."""
        super().__init__(message, code)


def _socket_error(exc: BaseException, peer: str) -> GError:
    """A failed socket call during Csec, keeping its ``errno`` (``ETIMEDOUT`` for a timeout).

    An ``OSError`` without an ``errno`` reads as ``ECONNRESET``, the closest
    "the link is gone" code.
    """
    if isinstance(exc, TimeoutError):
        return GError(f"Timed out authenticating with {peer}", errno.ETIMEDOUT)
    code = getattr(exc, "errno", None) or errno.ECONNRESET
    return GError(f"Lost the connection to {peer} while authenticating: {exc}", code)


class TokenLink:
    """Csec tokens over a connected socket.

    A thin framing layer: no buffering beyond the token being read, and no
    ownership - the socket belongs to the caller, which closes it if the
    handshake fails (:meth:`.client.Server.connect`). The socket's timeout
    applies to every read and write. ``peer`` (``host:port``) only labels
    error messages.
    """

    def __init__(self, sock: socket.socket, peer: str) -> None:
        """Frame tokens on ``sock``; ``peer`` names it in errors."""
        self.sock = sock
        self.peer = peer

    def send_token(self, kind: int, data: bytes) -> None:
        """Send one token of type ``kind``; a socket failure is a ``GError`` with its ``errno``.

        Header and data go out in one ``sendall`` so the peer never sees a
        header without its data unless the connection itself broke.
        """
        try:
            self.sock.sendall(_HEAD.pack(TOKEN_MAGIC, kind, len(data)) + data)
        except OSError as exc:  # socket.timeout is an OSError too
            raise _socket_error(exc, self.peer) from exc

    def _exact(self, size: int) -> bytes:
        """Exactly ``size`` bytes; end of stream is ``ECONNRESET``."""
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
        """The next token as ``(type, data)``; the caller checks the type.

        A wrong magic is ``EPROTO`` with a hint, since the usual cause is a
        port that is not an LFC (or a plain-text service answering).
        Empty and over-``MAX_TOKEN`` tokens are refused before any data is
        read, as ``_Csec_recv_token`` does, so a garbage length cannot make
        us allocate gigabytes.
        """
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
    """Only GSI can delegate a credential; KRB5 and ID never can."""
    return mech == "GSI"


def _flag_sets(mechs: Sequence[str]) -> Packer:
    """No delegation wanted: mark the mechanisms that cannot delegate ``NODELEG``.

    The wire form is a list of *flag sets*: ``LONG nsets``, then per set
    ``LONG flags, LONG nindexes, LONG index...`` naming the mechanisms (by
    position in the offered list) the flags apply to. Csec builds one set
    for the mechanisms that cannot delegate and leaves the rest unflagged
    when the caller asked for no delegation; this reproduces that, so a
    list with no such mechanism (``GSI`` alone) is just ``LONG 0``.
    """
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
    """``Csec_client_negociate_protocol``'s ``PROTOCOL_REQ`` body.

    Layout: ``LONG version``; ``LONG 0``, or ``LONG 1`` and the
    authorization id's mechanism and name (a trusted service acting for a
    user - this client never sends one, the test server honours it);
    ``LONG count`` and the mechanism names in order of preference; the flag
    sets of :func:`_flag_sets` (only when there are mechanisms); ``LONG 0``
    for "no VOMS data".
    """
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
    """Undo :func:`_flag_sets`: the OR of the flags each of ``count`` mechanisms got.

    Indexes past ``count`` are ignored; set and index counts
    over ``MAX_LIST`` are refused so a hostile length cannot spin the loop.
    """
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
    """A counted list of mechanism names, each at most 15 bytes."""
    count = reader.ulong()
    if count > MAX_LIST:
        raise WireError("too many Csec protocols")
    return [reader.string(15) for _ in range(count)]


def decode_request(
    data: bytes,
) -> tuple[int, tuple[str, str] | None, list[str], list[int]]:
    """``(version, authorization id, mechanisms, flags)`` from a ``PROTOCOL_REQ``.

    The server half of :func:`encode_request`, used by the test server.
    ``flags[i]`` belongs to ``mechanisms[i]``; the VOMS field after the
    flags is not read. The authorization id's name may be 511 bytes (a DN).
    """
    reader = Unpacker(data)
    version = reader.ulong()
    authorization = None
    if reader.ulong():
        authorization = (reader.string(15), reader.string(511))
    mechs = _read_list(reader)
    flags = _read_flag_sets(reader, len(mechs)) if mechs else []
    return version, authorization, mechs, flags


def encode_response(version: int, chosen: int | None, flags: int, offered: Sequence[str]) -> bytes:
    """``Csec_server_negociate_protocol``'s ``PROTOCOL_RESP`` body.

    On success (``chosen`` an index into the client's list): ``LONG
    version, "OK", LONG chosen, LONG flags``. On failure: ``LONG version,
    "NOK", LONG ESEC_PROTNOTSUPP``, then the server's own mechanisms and
    their flag sets, so the client can say what it would have accepted.
    The version is the lower of the client's and ours.
    """
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
    """``(version, chosen index or None, flags, server mechanisms)``.

    The client half of :func:`encode_response`. ``"OK"`` gives the index
    and flags and an empty list; anything else is a refusal - its reason
    code is skipped and the server's list returned for the error message.
    The verdict string is read with a bound of 1500 bytes.
    """
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
    """Agree on a mechanism with the server; its name.

    One ``PROTOCOL_REQ``/``PROTOCOL_RESP`` round trip. Refusal is
    ``EACCES`` with both lists in the message (typically a client offering
    only ``ID`` to a server that wants ``GSI``). An answer that picks an
    index we did not offer, or that does not confirm ``NODELEG`` (this
    client never delegates), is ``EPROTO``: the two ends would disagree on
    what the handshake that follows looks like.
    """
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
    """One Csec mechanism's client side.

    Subclasses set :attr:`name` (the Csec protocol id offered in
    negotiation) and implement :meth:`authenticate`. Instances are built
    per connection attempt by the plugin (``LFCPlugin._mechanisms``) and so
    may hold credentials without worrying about reuse across threads.
    """

    #: The Csec protocol id: ``GSI``, ``KRB5`` or ``ID``.
    name = ""

    def authenticate(self, link: TokenLink, host: str) -> None:
        """Run the handshake after negotiation chose this mechanism; raise on failure.

        ``host`` is the server's name as the user wrote it, for the
        mechanism's identity check.
        """
        raise NotImplementedError


class IDMechanism(Mechanism):
    """``Csec_plugin_ID``: the local uid, gid and user name, on trust.

    No secret is involved: the server accepts it only from hosts in its
    ``TRUST`` list and otherwise ends the connection with ``EACCES``
    after the token. Useful for service hosts and the test server; never a
    way to authenticate a user to a shared catalogue.
    """

    name = "ID"

    def __init__(self, uid: int, gid: int, username: str) -> None:
        """The identity to claim; see :func:`local_identity`."""
        self.uid = uid
        self.gid = gid
        self.username = username

    def authenticate(self, link: TokenLink, host: str) -> None:
        """Send the one ``HANDSHAKE`` token; the server does not answer it."""
        text = f"{self.uid} {self.gid} {self.username}"
        link.send_token(HANDSHAKE, text.encode("utf-8", "surrogateescape"))


def _abort(link: TokenLink, reason: int) -> None:
    """Tell the server the handshake is off, as Csec does, ignoring a dead link."""
    with contextlib.suppress(GError):
        link.send_token(HANDSHAKE_ERROR, struct.pack(">I", reason))


class _TokenMechanism(Mechanism):
    """The GSS token loop shared by GSI and KRB5 (``Csec_plugin_GSS.c``).

    A subclass supplies the security context (:meth:`context`) - any object
    with ``step(token) -> bytes`` and a ``complete`` flag, i.e. the shape of
    :class:`~xrdsec.gsi.gss.SecurityContext` and of
    :class:`~xgfalclient.crypto.krb5.ClientContext` - and, optionally, a
    post-handshake identity check (:meth:`check`).
    """

    def context(self, host: str) -> Any:
        """A fresh client-side security context for ``host``."""
        raise NotImplementedError

    def check(self, context: Any, host: str) -> None:
        """Verify the server's identity once the context is up."""

    def authenticate(self, link: TokenLink, host: str) -> None:
        """Exchange GSS tokens until the context is complete, then :meth:`check` it.

        The token produced by the step that completes the context, if any,
        is sent as ``HANDSHAKE_FINAL``; after that nothing more is read. A
        ``HANDSHAKE_ERROR`` from the server is ``EACCES`` and is not
        answered. Our own failure (a TLS alert, a bad host name, a dead
        link) is first reported to the server with ``HANDSHAKE_ERROR`` so
        it can log why, then raised as :class:`CsecError` keeping the
        underlying ``errno`` (``EACCES`` for a GSI-level failure).
        """
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
    """GSI: TLS in tokens, the delegation byte ``0``, GSI's host-name check.

    The TLS handshake itself, the delegation byte and the proxy-aware
    certificate checks live in :mod:`xrdsec.gsi.gss`; this class
    only fits them into Csec's token loop.
    """

    name = "GSI"

    def __init__(self, tls: ssl.SSLContext | None) -> None:
        """``tls`` holds the user's proxy and CAs; ``None`` when no credential was found.

        The ``SSLContext`` must not check host names itself (the plugin
        builds it with ``check_hostname=False``): GSI's rule, applied by
        :meth:`check`, also accepts a ``host/`` service certificate.
        """
        self.tls = tls

    def authenticate(self, link: TokenLink, host: str) -> None:
        """Fail like Csec when there is no credential, else run the token loop."""
        if self.tls is None:
            # Csec acquires credentials after the negotiation and says so.
            _abort(link, REASON_ACQUIRE_FAILED)
            raise CsecError(
                "No X.509 credential for GSI authentication (set X509_USER_PROXY, "
                "or X509_USER_CERT and X509_USER_KEY)"
            )
        super().authenticate(link, host)

    def context(self, host: str) -> SecurityContext:
        """A GSI client context presenting the proxy; only built once ``tls`` is known."""
        assert self.tls is not None
        return SecurityContext(self.tls, server_hostname=host)

    def check(self, context: Any, host: str) -> None:
        """GSI's host check: SAN DNS names, then ``CN=[host/]fqdn`` (``GSIError`` if none match)."""
        context.check_host(host)


class KRB5Mechanism(_TokenMechanism):
    """Kerberos 5 for ``host@<server>``, when a Kerberos library is present."""

    name = "KRB5"

    def context(self, host: str) -> Any:
        """A Kerberos context for ``host@<host>``, from the default credential cache.

        Imported lazily: :mod:`xgfalclient.crypto.krb5` loads a native GSS
        library, which most installations never need. Mutual authentication
        is part of the context, so there is no separate :meth:`check`.
        """
        from ...crypto import krb5

        # Csec asks for mutual authentication and replay detection, nothing more.
        return krb5.ClientContext(
            "host", host, sequence=False, integrity=False, confidentiality=False
        )


def available_krb5() -> bool:
    """Whether a Kerberos 5 GSS-API library can be used.

    ``KRB5`` named in ``$CSEC_MECH`` without one is left out of the offer
    (logged at debug level) rather than failing every connection.
    """
    from ...crypto import krb5

    return krb5.available() is None


def mechanism_names(value: str | None) -> list[str]:
    """``$CSEC_MECH`` (space- or tab-separated), else the default list.

    Unknown names are kept here and dropped by the plugin, which knows what
    it can build; an empty or blank value means the default, as in Csec.
    """
    names = (value or "").split()
    return names or list(DEFAULT_MECHS)


def authenticate(
    sock: socket.socket,
    peer: str,
    host: str,
    mechanisms: Sequence[Mechanism],
    authorization: tuple[str, str] | None = None,
) -> str:
    """Run Csec on a fresh connection; the name of the mechanism used.

    ``mechanisms`` is the offer, in order of preference; their names must
    be distinct (a later duplicate would shadow an earlier one). On return
    the socket is ready for the first Cns request; on any exception it is
    in an unknown state and the caller must close it.
    """
    link = TokenLink(sock, peer)
    by_name = {mech.name: mech for mech in mechanisms}
    chosen = negotiate(link, [mech.name for mech in mechanisms], authorization)
    by_name[chosen].authenticate(link, host)
    return chosen


def local_identity() -> tuple[int, int, str]:
    """``geteuid``, ``getegid`` and the user name, for the ID mechanism.

    Effective ids, as ``Csec_plugin_ID`` sends. Where ``pwd`` or the ids do
    not exist (Windows) the identity is root's numbers and the uid as name;
    such a client can only talk to a server that trusts it anyway.
    """
    uid = getattr(os, "geteuid", lambda: 0)()
    gid = getattr(os, "getegid", lambda: 0)()
    try:
        import pwd

        name = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):  # Windows, or a uid nobody named
        name = str(uid)
    return uid, gid, name
