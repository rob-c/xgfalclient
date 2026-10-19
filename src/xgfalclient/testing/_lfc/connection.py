"""One client connection to the LFC test server (``doit`` in ``Cns_main.c``).

:class:`_Connection` owns the socket: it negotiates Csec (``GSI`` as TLS in
tokens, or ``ID`` from a trusted host), maps the DN to a virtual identity,
reads each request, applies any injection queued for its type, and hands
the body to the handler :data:`~.handlers._HANDLERS` names - under the
server's lock, as the real daemon's database transaction would serialise
it. Sessions (``STARTSESS`` ... ``ENDSESS``) and directory listings
(``OPENDIR``, ``READDIR`` batches, ``CLOSEDIR``) are multi-request
exchanges and are run here rather than as handlers.

Lifecycle: :class:`~xgfalclient.testing.lfc.LFCServer` makes one
:class:`_Connection` per accepted socket and runs :meth:`_Connection.run`
on a daemon thread of its own. The connection does Csec, serves one
request - which may be ``STARTSESS`` and so many requests - and closes the
socket; nothing outlives it except what it changed in the catalogue and
the counters and log on the server. ``LFCServer.stop`` shuts the
socket down under a blocked read, which this code sees as end of stream.

Failure handling copies the daemon: a client that breaks the protocol
(bad token, short header, oversized length) is simply dropped, with no
reply, while a well-formed request that fails gets its serrno in
``CNS_RC`` (or ``CNS_IRC`` inside a session). Socket errors on the way out
are swallowed in :meth:`_Connection.send` - the peer may already have gone,
and the test asserting on that sees it from the client side.
"""

from __future__ import annotations

import contextlib
import errno
import select
import socket
from typing import TYPE_CHECKING

from xrdsec.gsi.gss import GSIError
from xrdsec.testing.gsi import accept_tokens, acceptor, proxy_owner

from ...errors import GError
from ...plugins.lfc import wire
from ...plugins.lfc.csec import (
    DELEG,
    HANDSHAKE,
    HANDSHAKE_ERROR,
    NODELEG,
    PROTOCOL_REQ,
    PROTOCOL_RESP,
    TokenLink,
    decode_request,
    encode_response,
)
from ...plugins.lfc.wire import Packer, Unpacker
from .handlers import _HANDLERS
from .model import S_IEXEC, S_IREAD, Entry, Hangup, Identity, Raw, _Fail
from .namespace import _EXISTING, _by_guid, _check, _dirx, _parse

if TYPE_CHECKING:
    from ..lfc import LFCServer


class _Connection:
    """The server's end of one connection (``doit`` in ``Cns_main.c``).

    Used by one thread only, the one running :meth:`run`. ``identity`` is
    set by Csec ``ID`` (root) or, for GSI and authorised ``ID``, lazily by
    :meth:`map_identity` on the first request, so an unmapped DN still
    completes the handshake and is refused per request with
    ``SENOMAPFND`` - as the real server does. ``authorization`` is the
    ``(mechanism, name)`` pair a client may send in ``PROTOCOL_REQ`` to act
    as someone else; only the ``ID`` path honours it.
    """

    def __init__(self, server: LFCServer, sock: socket.socket, address: str) -> None:
        """Serve ``sock`` for ``server``; ``address`` (the peer's IP) is checked for ``ID``."""
        self.server = server
        self.sock = sock
        self.address = address
        self.link = TokenLink(sock, address)
        self.identity: Identity | None = None
        self.dn = ""
        self.authorization: tuple[str, str] | None = None

    # -- the byte stream ----------------------------------------------------------------

    def _exact(self, size: int) -> bytes | None:
        """Exactly ``size`` bytes, or ``None`` at end of stream or on a socket error."""
        data = bytearray()
        while len(data) < size:
            try:
                chunk = self.sock.recv(size - len(data))
            except OSError:
                return None
            if not chunk:
                return None
            data += chunk
        return bytes(data)

    def send(self, data: bytes) -> None:
        """Write ``data``, ignoring a peer that has gone (the client side reports that)."""
        with contextlib.suppress(OSError):
            self.sock.sendall(data)

    def reply(self, kind: int, value: int | bytes) -> None:
        """``sendrep``: a status, or a data message with its length.

        An ``int`` goes in the header's third field on its own (``CNS_RC``,
        ``CNS_IRC``); ``bytes`` are sent after a header carrying their
        length (``MSG_*``). The magic is always ``CNS_MAGIC2``; liblfc
        ignores a reply's magic.
        """
        if isinstance(value, int):
            self.send(wire.HEADER.pack(wire.MAGIC2, kind, value))
        else:
            self.send(wire.HEADER.pack(wire.MAGIC2, kind, len(value)) + value)

    def error(self, text: str) -> None:
        """A ``MSG_ERR`` line, NUL-terminated; the status still follows separately."""
        self.reply(wire.MSG_ERR, text.encode() + b"\0")

    def close(self) -> None:
        """Close the socket; safe to call twice (a hang-up injection closes it early)."""
        with contextlib.suppress(OSError):
            self.sock.close()

    def final(self, status: int) -> None:
        """End the connection as ``sendrep(CNS_RC)`` does: the status, then close."""
        self.reply(wire.CNS_RC, status)
        self.close()

    # -- Csec --------------------------------------------------------------------------------

    def authenticate(self) -> bool:
        """Run Csec on the fresh socket; ``False`` means drop the connection.

        Negotiation first: the client's ``PROTOCOL_REQ`` lists mechanisms in
        its order of preference, and the first one this server allows is
        chosen - unless the client wants delegation for it, which the server
        never grants. The ``PROTOCOL_RESP`` is sent either way, carrying the
        server's list on refusal, so the client can say what it should have
        offered. A GSI handshake that fails on the server's side ends with
        ``HANDSHAKE_ERROR`` and ``CNS_RC ESEC_NO_CONTEXT``, as the daemon
        reports it; a broken negotiation or ``ID`` token is just dropped.
        """
        try:
            kind, data = self.link.recv_token()
            if kind != PROTOCOL_REQ:
                return False
            version, self.authorization, mechs, flags = decode_request(data)
            chosen = None
            for index, mech in enumerate(mechs):
                if mech in self.server.mechanisms and not flags[index] & DELEG:
                    chosen = index
                    break
            self.link.send_token(
                PROTOCOL_RESP,
                encode_response(version, chosen, NODELEG, self.server.mechanisms),
            )
            if chosen is None:
                return False
            if mechs[chosen] == "ID":
                return self._id()
        except GError:
            return False
        try:
            return self._gsi()
        except (GError, GSIError):
            # _Csec_notify_peer_of_handshake_error, then doit's ESEC_NO_CONTEXT
            with contextlib.suppress(GError):
                self.link.send_token(HANDSHAKE_ERROR, Packer().long(0).bytes())
            self.final(wire.ESEC_NO_CONTEXT)
            return False

    def _id(self) -> bool:
        """Csec ``ID``: one ``"<uid> <gid> <name>"`` token, believed only from trusted hosts.

        The claimed uid and gid are not used: a trusted ``ID`` client is root
        (uid 0, which every permission check lets through), the way service
        hosts in the real ``TRUST`` list are treated. With an authorisation
        id it instead acts as that DN, mapped like a GSI user. An untrusted
        host gets ``EACCES`` after its token. Socket and framing errors
        propagate to :meth:`authenticate` as ``GError``.
        """
        kind, data = self.link.recv_token()
        fields = data.decode("utf-8", "replace").split()
        if kind != HANDSHAKE or len(fields) != 3:
            return False
        if self.address not in self.server.trusted:
            # "Host is not trusted, identity provided was (ID,...)"
            self.final(errno.EACCES)
            return False
        if self.authorization is None:
            self.identity = Identity(0, [0], "root", "ID")
        else:
            self.dn = self.authorization[1]
        return True

    def _gsi(self) -> bool:
        """Csec ``GSI``: TLS records in ``HANDSHAKE`` tokens until the context completes.

        ``False`` without a server TLS context (the ``LFCServer`` was built
        without ``gsi``), or when the client gives up with
        ``HANDSHAKE_ERROR`` (answered with ``CNS_RC ESEC_NO_CONTEXT``). On
        success the DN is the proxy's owner (:func:`xrdsec.testing.gsi.proxy_owner`);
        mapping it to an identity waits for the first request. TLS failures
        raise :class:`GSIError` for :meth:`authenticate` to report.
        """
        if self.server.gsi is None:
            return False
        context = acceptor(self.server.gsi)
        # Every token the acceptor sends is a HANDSHAKE one; the client's
        # HANDSHAKE_ERROR (it gave up) ends the loop without a context.
        if not accept_tokens(context, self._handshake_token, self._send_handshake):
            self.final(wire.ESEC_NO_CONTEXT)
            return False
        peer = context.peer_certificate()
        assert peer is not None  # CERT_REQUIRED: no certificate, no handshake
        self.dn = proxy_owner(str(peer.subject))
        return True

    def _handshake_token(self) -> bytes | None:
        """The client's next GSI token; ``None`` when it sent ``HANDSHAKE_ERROR`` instead."""
        kind, data = self.link.recv_token()
        return None if kind == HANDSHAKE_ERROR else data

    def _send_handshake(self, token: bytes) -> None:
        """One acceptor token to the client, as a Csec ``HANDSHAKE``."""
        self.link.send_token(HANDSHAKE, token)

    def map_identity(self) -> Identity:
        """``getidmap``: a virtual uid for the DN, the gid of its VO.

        The mapfile names the DN's VO; the uid and gid are allocated on
        first sight (:meth:`LFCServer.uid_for`), as the real server's
        ``Cns_userinfo``/``Cns_groupinfo`` tables grow. An unmapped DN fails
        with ``SENOMAPFND`` and the daemon's ``MSG_ERR`` text, on every
        request until the mapfile has it. The result is cached for the
        connection.
        """
        if self.identity is None:
            vo = self.server.mapfile.get(self.dn)
            if vo is None:
                raise _Fail(
                    wire.SENOMAPFND,
                    f"Could not get virtual id for {self.dn}: No user mapping !\n",
                )
            self.identity = Identity(
                self.server.uid_for(self.dn), [self.server.gid_for(vo)], self.dn, "GSI"
            )
        return self.identity

    # -- requests -------------------------------------------------------------------------------

    def get_request(self) -> tuple[int, int, bytes] | None:
        """``getreq``: a request, or ``None`` if the peer went away or sent junk.

        Reads the 12-byte header (``LONG magic, LONG type, LONG length``,
        the length including the header) and then the body. A length below
        the header or above ``MAXREQUEST`` is junk; exactly the header size
        comes back with an empty body, which callers answer with
        ``SEINTERNAL`` - the C ``getreq`` reports the zero-length read the
        same way, and liblfc's ``CLOSEDIR`` relies on it.
        """
        header = self._exact(wire.HEADER.size)
        if header is None:
            return None
        magic, kind, length = wire.HEADER.unpack(header)
        if not wire.HEADER.size < length <= wire.MAXREQUEST:
            return (magic, kind, b"") if length == wire.HEADER.size else None
        body = self._exact(length - wire.HEADER.size)
        return None if body is None else (magic, kind, body)

    def run(self) -> None:
        """The connection thread's body: Csec, one request, ``CNS_RC``, close."""
        if not self.authenticate():
            self.close()
            return
        request = self.get_request()
        if request is None:
            self.close()
            return
        self.final(self.process(*request) if request[2] else wire.SEINTERNAL)

    def process(self, magic: int, kind: int, body: bytes) -> int:
        """``procreq``: run one request; its status.

        Every request is logged first, so a test sees even those answered by
        an injection. A queued injection for ``kind`` replaces the whole
        request: a status is returned as is, :class:`Raw` bytes go out with
        status 0 after them, and :class:`Hangup` closes the socket (the
        caller's reply then fails silently). Otherwise sessions and listings
        run here; everything else is the handler's, once the caller has an
        identity, and with the server's lock held so handlers see a stable
        catalogue. A body too short for its fields is ``EINVAL``.
        """
        self.server.log.append((kind, magic))
        injected = self.server._injection(kind)
        if isinstance(injected, int):
            return injected
        if isinstance(injected, Raw):
            self.send(injected.data)
            return 0
        if isinstance(injected, Hangup):
            self.close()
            return 0
        if kind == wire.STARTSESS:
            return self.session()
        if kind == wire.OPENDIR:
            return self.listing(magic, body)
        handler = _HANDLERS.get(kind)
        if handler is None:
            self.error(f"NS003 - illegal function {kind}\n")
            return wire.SEOPNOTSUP
        try:
            ident = self.map_identity()
            reader = Unpacker(body)
            # The client's own uid and gid, ignored: the server trusts Csec.
            reader.long(), reader.long()
            with self.server._lock:
                return handler(self, ident, magic, reader)
        except _Fail as exc:
            if exc.text:
                self.error(exc.text)
            return exc.code
        except GError:  # a body that does not unmarshall
            return errno.EINVAL

    def session(self) -> int:
        """``procsessreq``: answer each request with ``CNS_IRC`` until ``ENDSESS``.

        ``STARTSESS`` is acknowledged with ``CNS_IRC 0`` and its body (a
        comment for the server's log) ignored. Each later request is
        processed as on its own and answered with ``CNS_IRC``; ``ENDSESS``
        returns its status, which :meth:`run` sends as the final ``CNS_RC``.
        Idling longer than :attr:`LFCServer.session_timeout` ends the session
        with ``SETIMEDOUT``, as ``CNS_TRANSTIMEOUT`` does - the client's pool
        must notice and reconnect. A listing inside a session works because
        :meth:`process` hands ``OPENDIR`` to :meth:`listing` either way.
        """
        with self.server._lock:
            self.server.sessions += 1
        self.reply(wire.CNS_IRC, 0)
        while True:
            try:
                readable, _, _ = select.select([self.sock], [], [], self.server.session_timeout)
            except (OSError, ValueError):  # closed under us by an injected hang-up
                return wire.SEINTERNAL
            if not readable:
                return wire.SETIMEDOUT
            request = self.get_request()
            if request is None:
                return wire.SEINTERNAL
            status = self.process(*request) if request[2] else wire.SEINTERNAL
            if request[1] == wire.ENDSESS:
                return status
            self.reply(wire.CNS_IRC, status)

    def listing(self, magic: int, body: bytes) -> int:
        """``procdirreq`` for ``OPENDIR``: batches until anything but ``READDIR``.

        ``OPENDIR`` is answered with ``MSG_DATA`` (the directory's ``HYPER``
        file id) and ``CNS_IRC 0``. The directory's names are snapshotted
        then, sorted, so the batches are stable even if the catalogue changes
        mid-listing. Each ``READDIR`` body is ``WORD getattr, WORD direntsz,
        HYPER fileid, WORD bod``; only ``getattr`` 1 (``readdirx``, stat
        records with the names) is modelled (``SEOPNOTSUP`` otherwise), and
        the file id and ``bod`` are not checked. An injected status for
        ``READDIR`` ends the listing with that status; a queued :class:`Raw`
        or :class:`Hangup` is consumed and ignored here. Any other request,
        ``CLOSEDIR`` included, ends the listing.
        """
        try:
            ident = self.map_identity()
            directory = self._opendir(ident, magic, Unpacker(body))
        except _Fail as exc:
            if exc.text:
                self.error(exc.text)
            return exc.code
        self.reply(wire.MSG_DATA, Packer().hyper(directory.fileid).bytes())
        self.reply(wire.CNS_IRC, 0)
        with self.server._lock:
            names = sorted(self.server.children[directory.fileid].items())
        queue = [self.server.entries[fileid] for _, fileid in names]
        return self._readdirs(queue)

    def _readdirs(self, queue: list[Entry]) -> int:
        """Answer ``READDIR`` with batches of ``queue`` until another request ends the listing.

        The result is the listing's status: 0 after a ``CLOSEDIR``.
        """
        while True:
            request = self.get_request()
            if request is None:
                return wire.SEINTERNAL
            rmagic, kind, rbody = request
            self.server.log.append((kind, rmagic))
            if kind != wire.READDIR:
                # CLOSEDIR: its empty body is a short read to getreq
                return wire.SEINTERNAL if not rbody else 0
            injected = self.server._injection(kind)
            if isinstance(injected, int):
                return injected
            reader = Unpacker(rbody)
            reader.long(), reader.long()
            getattr_, direntsz = reader.word(), reader.word()
            reader.hyper(), reader.word()
            if getattr_ != 1:
                return wire.SEOPNOTSUP
            self.reply(wire.MSG_DATA, self._batch(rmagic, direntsz, queue))
            self.reply(wire.CNS_IRC, 0)

    def _opendir(self, ident: Identity, magic: int, reader: Unpacker) -> Entry:
        """The directory an ``OPENDIR`` names; it needs read and search permission.

        Body after the uid and gid: ``HYPER cwd, STRING path`` and, from
        ``CNS_MAGIC2`` (``Cns_opendirg``), ``STRING guid``, which wins when
        non-empty. Not a directory is ``ENOTDIR``.
        """
        reader.long(), reader.long()
        cwd = reader.hyper()
        path = reader.string()
        guid = reader.string() if magic >= wire.MAGIC2 else ""
        with self.server._lock:
            if guid:
                entry = _by_guid(self.server, guid)
            else:
                _, entry = _parse(self.server, ident, cwd, path, _EXISTING)
            if not entry.is_dir():
                raise _Fail(errno.ENOTDIR)
            _check(entry, S_IREAD | S_IEXEC, ident)
            return entry

    def _batch(self, magic: int, direntsz: int, queue: list[Entry]) -> bytes:
        """One ``Cns_srv_readdir`` reply: what fits in ``DIRBUFSZ``, then ``eod``.

        An entry that does not fit stays at the head of ``queue`` for the next one.

        The reply is ``WORD count``, ``count`` :func:`~.namespace._dirx`
        records and ``WORD eod`` (1 once ``queue`` is empty). Each entry costs
        the client's announced ``direntsz`` - never less than the record's
        fixed size - plus its name and NUL, rounded up to 8 bytes, out of
        ``DIRBUFSZ``, with one entry's worth held back. That makes a long
        directory span several ``READDIR`` round trips, which tests use to
        exercise the client's batching.
        """
        least = 130 if magic >= wire.MAGIC2 else 62  # DIRGSIZE, DIRXSIZE
        size = max(direntsz, least)
        room = wire.DIRBUFSZ - size
        packer = Packer()
        count = 0
        while queue:
            entry = queue[0]
            if len(entry.name) >= room:
                break
            queue.pop(0)
            _dirx(packer, magic, entry)
            count += 1
            room -= ((size + len(entry.name) + 8) // 8) * 8
        eod = 0 if queue else 1
        return Packer().word(count).bytes() + packer.bytes() + Packer().word(eod).bytes()
