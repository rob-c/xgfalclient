"""Data channels: connecting them, securing them, and moving bytes on them.

A GridFTP transfer is a command on the control channel and one or more TCP
connections beside it. Who connects to whom is settled first: ``PASV`` (or
``EPSV``/``SPAS``) makes the server listen and the client connect, ``PORT``
(``EPRT``) the reverse. In ``MODE E`` the *sender* must be the connecting
side, so a parallel download needs ``PORT`` - which is what globus-url-copy
does. With ``OPTS PASV AllowDelayed`` a server may answer ``PASV`` with
"200 Passive delayed" and give the address later, as a ``127`` reply to the
transfer command; gfal2 always asks for that, so dCache can point the data
channel straight at a pool.

Bytes move in one of two framings:

* ``MODE S``: the file, raw, ending when the sender closes the connection.
  One connection, in order.
* ``MODE E`` (GFD.020): blocks of ``(descriptor, count, offset)`` + payload
  over N connections, each ending with an ``EOD`` block. One ``EOF`` block,
  whose offset field counts the ``EOD``s to wait for, ends the transfer.
  Blocks land wherever their offset says, so the receiver ``pwrite``s them.

:class:`DataTransfer` runs one of these beside the control channel: it
starts one thread per connection and polls the control channel meanwhile
for markers, the final reply, cancellation and the deadline.

Security (GFD.20 ``DCAU``, RFC 2228 ``PROT``): with ``DCAU N`` a data
connection is bare TCP. With ``DCAU A`` both ends run a GSI handshake on
it first (:func:`authenticate`), the connecting side as initiator, and each
checks that the other is the same user. ``PROT P`` then wraps every byte in
TLS records (:class:`DataConn`); ``PROT C`` sends clear data after the
handshake. Which of these a session uses is decided once, in
:class:`DataSecurity`.

Where to start reading: :meth:`DataTransfer.run`. The byte movers
(:func:`recv_stream`, :func:`recv_blocks`, :func:`send_stream`,
:func:`send_blocks`) are plain functions of a :class:`DataConn` so that the
client and the in-process test server (:mod:`xgfalclient.testing.gridftp`,
which imports them) share one implementation of each framing; changing one
of their signatures means changing the test server too.

Threading: each connection's worker runs on its own daemon thread; the
caller's thread owns the control channel. Workers report failures by
appending to :attr:`DataTransfer.errors` under its lock, never by touching
the control channel. :class:`Ranges` and :class:`EodCounter` are the only
objects the workers share, and both lock.
"""

from __future__ import annotations

import contextlib
import errno
import os
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from xrdsec.gsi.gss import GSIError, SecurityContext

from ...errors import GError
from .control import Control, connect_error
from .gsi import GlobusContext, same_identity
from .protocol import (
    BLOCK_HEADER,
    DESC_EOD,
    DESC_EOF,
    Reply,
    format_eprt,
    format_port,
    parse_epsv,
    parse_pasv,
    parse_perf_marker,
    parse_spas,
    reply_error,
)

__all__ = [
    "ChannelOptions",
    "ConnSetup",
    "DataConn",
    "DataSecurity",
    "DataTransfer",
    "EodCounter",
    "Feed",
    "Ranges",
    "Reader",
    "Writer",
    "authenticate",
    "open_active",
    "passive",
    "perf_bytes",
    "positional_reader",
    "read_record",
    "recv_blocks",
    "recv_stream",
    "routable",
    "send_blocks",
    "send_stream",
]

#: ``write(view, offset)``: where received bytes go. Must consume all of
#: ``view`` (the buffer is reused at once) and be safe to call from several
#: threads at different offsets, as ``os.pwrite`` is.
Writer = Callable[[memoryview, int], None]
#: ``read(view, offset) -> count``: where sent bytes come from; fewer than
#: ``len(view)`` only at the end of the source, 0 (or less) at its end.
Reader = Callable[[memoryview, int], int]


def positional_reader(fd: int) -> Reader:
    """A :data:`Reader` over ``fd``: positional, so sender threads can share it.

    ``os.preadv`` reads straight into the caller's buffer (``os.pread``
    allocates a new ``bytes`` per block). Not every CPython build has it -
    one built for macOS before 11, as conda's Intel macOS Python is, lacks
    it - and there the reader falls back to ``os.pread`` and a copy.
    """
    preadv = getattr(os, "preadv", None)

    def copied(view: memoryview, offset: int) -> int:
        """Fill ``view`` from ``offset`` through ``os.pread``; fewer bytes only at the end."""
        chunk = os.pread(fd, len(view), offset)
        view[: len(chunk)] = chunk
        return len(chunk)

    if preadv is None:
        return copied

    def direct(view: memoryview, offset: int) -> int:
        """Fill ``view`` from ``offset``; fewer bytes only at the end of the file."""
        return int(preadv(fd, [view], offset))

    return direct


#: 17: the ``MODE E`` header length.
_HEADER = BLOCK_HEADER.size


def recv_exact(sock: socket.socket, view: memoryview) -> bool:
    """Fill ``view``; ``False`` on a clean end of stream before the first byte.

    An end of stream after some bytes is a torn record: ``ECONNRESET``.
    Socket errors propagate as ``OSError`` for :func:`_as_gerror`.
    """
    got = 0
    while got < len(view):
        count = sock.recv_into(view[got:])
        if count == 0:
            if got == 0:
                return False
            raise GError("Data connection closed in the middle of a record", errno.ECONNRESET)
        got += count
    return True


def read_record(sock: socket.socket) -> bytes:
    """One TLS record (header and body) off a raw socket; ``b""`` at the end.

    A TLS record header is five bytes: content type, two version bytes and a
    big-endian 16-bit body length (RFC 8446 §5.1). Reading exactly one record
    at a time is what lets the GSI handshake share a socket with the data
    that follows it: nothing past the last handshake record is consumed.
    """
    header = bytearray(5)
    if not recv_exact(sock, memoryview(header)):
        return b""
    body = bytearray(int.from_bytes(header[3:5], "big"))
    if body and not recv_exact(sock, memoryview(body)):
        raise GError("Data connection closed in the middle of a record", errno.ECONNRESET)
    return bytes(header + body)


class DataConn:
    """One data connection: a socket, optionally with ``PROT P`` wrapping.

    The byte movers read and write through this, never the socket, so they
    work unchanged under ``PROT P``. Owned by the one worker thread that
    moves its bytes; :meth:`finish` (or the transfer's abort) closes it.
    """

    __slots__ = ("_plain", "protect", "sock")

    def __init__(self, sock: socket.socket, protect: SecurityContext | None = None) -> None:
        """Wrap ``sock``; ``protect`` is the authenticated context under ``PROT P``."""
        self.sock = sock
        self.protect = protect
        #: Decrypted bytes of the last record not yet handed out; a TLS
        #: record (up to 16 KiB) rarely fits the caller's view exactly.
        self._plain = bytearray()

    def recv_into(self, view: memoryview) -> int:
        """Like ``socket.recv_into``: up to ``len(view)`` bytes, 0 at the end of stream.

        Under ``PROT P`` a whole record is read and unwrapped, and what does
        not fit waits in :attr:`_plain`. A record that unwraps to nothing (a
        TLS 1.3 key update or session ticket) is skipped, not taken as EOF.
        """
        if self.protect is None:
            return self.sock.recv_into(view)
        while not self._plain:
            record = read_record(self.sock)
            if not record:
                return 0
            self._plain += self.protect.unwrap(record)
        count = min(len(view), len(self._plain))
        view[:count] = self._plain[:count]
        del self._plain[:count]
        return count

    def recv_exact(self, view: memoryview) -> bool:
        """Fill ``view``; ``False`` only at a clean end before the first byte.

        A ``MODE E`` reader uses it for headers and payloads, where stopping
        part-way is an ``ECONNRESET``: the block is torn.
        """
        got = 0
        while got < len(view):
            count = self.recv_into(view[got:])
            if count == 0:
                if got == 0:
                    return False
                raise GError("Data connection closed in the middle of a block", errno.ECONNRESET)
            got += count
        return True

    def sendall(self, data: bytes | bytearray | memoryview) -> None:
        """Send all of ``data``, as one or more TLS records under ``PROT P``."""
        if self.protect is not None:
            data = self.protect.wrap(bytes(data))
        self.sock.sendall(data)

    def finish(self) -> None:
        """Signal the end of what we send (``MODE S`` EOF) and hang up."""
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_WR)
        self.sock.close()


class DataSecurity:
    """What a session's data channels need: ``DCAU A`` contexts and ``PROT``.

    Built once per session profile in :mod:`._base` when ``[GRIDFTP PLUGIN]
    DCAU`` or ``ENCRYPTION`` is on; ``None`` there means ``DCAU N``. Shared,
    read-only, by every data connection of every transfer on that session.
    """

    __slots__ = ("acceptor", "identity", "initiator", "private")

    def __init__(
        self,
        initiator: ssl.SSLContext,
        acceptor: ssl.SSLContext,
        identity: tuple[tuple[str, str], ...],
        private: bool,
    ) -> None:
        """``initiator``/``acceptor`` from :func:`~.gsi.data_contexts`.

        ``identity`` is the RDN sequence of the user's own (non-proxy)
        certificate, which the peer must match. ``private`` is ``PROT P``
        (``ENCRYPTION``): wrap the data, not just authenticate the channel.
        """
        self.initiator = initiator
        self.acceptor = acceptor
        self.identity = identity
        self.private = private

    def secure(self, sock: socket.socket, initiator: bool) -> DataConn:
        """Authenticate a fresh connection; the :class:`DataConn` to move bytes over.

        ``initiator`` is whether this end connected. Under ``PROT P`` the
        context is kept to wrap the data, and the handshake runs in globus's
        ``ssl_compatible`` mode (no turn, no delegation byte), because that is
        what a globus server's data channel then speaks. ``EACCES`` on any
        authentication failure.
        """
        tls = self.initiator if initiator else self.acceptor
        context = authenticate(
            sock, tls, initiator=initiator, identity=self.identity, ssl_compatible=self.private
        )
        return DataConn(sock, context if self.private else None)


def authenticate(
    sock: socket.socket,
    tls: ssl.SSLContext,
    *,
    initiator: bool,
    identity: tuple[tuple[str, str], ...],
    ssl_compatible: bool = False,
) -> SecurityContext:
    """``DCAU A``: GSI on a data connection; the peer must be ``identity``.

    The tokens are raw TLS records on the stream, read one record at a time
    so nothing past the handshake - clear data under ``PROT C`` - is eaten.
    Unlike the control channel there is no base64 and no ``ADAT``: the
    records go on the socket as they are. ``EACCES`` if the handshake fails
    or the peer is someone else; the caller closes the socket.
    """
    context = GlobusContext(tls, server_side=not initiator, ssl_compatible=ssl_compatible)
    try:
        if initiator:
            sock.sendall(context.step())
        while not context.complete:
            record = read_record(sock)
            if not record:
                raise GSIError("the peer hung up during authentication")
            reply = context.step(record)
            if reply:
                sock.sendall(reply)
    except GSIError as exc:
        raise GError(f"Data channel authentication failed: {exc}", errno.EACCES) from exc
    if not same_identity(context.peer_certificate(), identity):
        raise GError(
            "Data channel authentication failed: the peer is not "
            + "".join(f"/{k}={v}" for k, v in identity),
            errno.EACCES,
        )
    return context


# ---------------------------------------------------------------------------
# Passive and active set-up
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChannelOptions:
    """How data channels open: ``[GRIDFTP PLUGIN] IPV6``, ``SPAS`` and ``DELAY_PASSV``."""

    #: Use ``EPSV``/``EPRT`` even on an IPv4 control connection.
    ipv6: bool = False
    #: Use striped ``SPAS``/``SPOR`` (GFD.20) rather than ``PASV``/``PORT``.
    spas: bool = False
    #: Ask for ``OPTS PASV AllowDelayed=1;`` when the server offers it.
    delayed: bool = True


@dataclass(frozen=True, slots=True)
class ConnSetup:
    """What every data connection of one :class:`DataTransfer` gets.

    Both values come from the session's profile: its ``DCAU`` security
    (``None`` for ``DCAU N``) and the operation timeout in seconds, which
    bounds each connect, accept and socket read or write - not the transfer
    as a whole (that is the caller's ``check``).
    """

    security: DataSecurity | None = None
    timeout: float = 300.0


def passive(control: Control, options: ChannelOptions) -> list[tuple[str, int]]:
    """Make the server listen; its address(es), or ``[]`` when delayed to ``127``.

    ``SPAS`` gives one address per stripe; ``EPSV`` (RFC 2428) is used for
    an IPv6 control connection or when ``IPV6`` is set, since ``PASV`` can
    only name IPv4. Plain ``PASV`` first enables delayed passive if the
    server's ``FEAT`` line for ``PASV`` offers ``AllowDelayed``: such a
    server may answer ``200`` rather than ``227``, and the address arrives
    later as ``127`` to the transfer command - the caller must then wait
    for it (:meth:`DataTransfer._await`).
    """
    if options.spas:
        reply = control.command("SPAS")
        found = parse_spas(reply.lines)
    elif options.ipv6 or control.ipv6:
        reply = control.command("EPSV")
        found = [parse_epsv(reply.text)]
    else:
        if options.delayed and "ALLOWDELAYED" in control.features.get("PASV", "").upper():
            control.setting("OPTS PASV", "AllowDelayed=1;")
        reply = control.command("PASV")
        if reply.code != 227:
            return []
        found = [parse_pasv(reply.text)]
    return [(routable(host, control), port) for host, port in found]


def routable(host: str, control: Control) -> str:
    """The advertised host, or the control peer when it advertised nothing usable.

    ``EPSV`` names no host by design, and servers behind NAT or bound to
    the wildcard advertise ``0.0.0.0``/``::``; RFC 2428 says to connect to
    the control connection's peer then.
    """
    return control.peer if host in ("", "0.0.0.0", "::") else host


def open_active(control: Control, *, ipv6: bool) -> socket.socket:
    """Listen beside the control connection and tell the server with PORT/EPRT.

    The listener binds to our end of the control connection (same address
    family, an ephemeral port), the address the server can most likely
    reach. The caller owns the returned socket; it is closed here only if
    the server refuses the command.
    """
    host = control.local
    listener = socket.create_server(
        (host, 0), family=socket.AF_INET6 if control.ipv6 else socket.AF_INET
    )
    port = listener.getsockname()[1]
    try:
        if ipv6 or control.ipv6:
            control.command(f"EPRT {format_eprt(host, port)}")
        else:
            control.command(f"PORT {format_port(host, port)}")
    except GError:
        listener.close()
        raise
    return listener


# ---------------------------------------------------------------------------
# Byte movers (one per connection, run in threads)
# ---------------------------------------------------------------------------


class EodCounter:
    """``MODE E`` completion: the ``EOF`` block's count against ``EOD``s seen.

    GFD.20: a sender may open more connections than it ends up using, so the
    receiver cannot know how many ``EOD``\\ s to wait for until the one ``EOF``
    block says. The ``EOF`` can arrive on any connection, before or after
    other connections' ``EOD``\\ s; :attr:`done` is set when both are in. Shared
    by all receiving threads of one transfer.
    """

    def __init__(self) -> None:
        """Nothing seen yet; ``expected`` stays ``None`` until the ``EOF`` block."""
        self._lock = threading.Lock()
        self.expected: int | None = None
        self.seen = 0
        self.done = threading.Event()

    def eof(self, count: int) -> None:
        """Record the ``EOF`` block's count of ``EOD``\\ s (its offset field)."""
        with self._lock:
            self.expected = count
            self._check()

    def eod(self) -> None:
        """Record one connection's ``EOD``."""
        with self._lock:
            self.seen += 1
            self._check()

    def _check(self) -> None:
        """Set :attr:`done` once the ``EOF`` count is known and met (lock held)."""
        if self.expected is not None and self.seen >= self.expected:
            self.done.set()


class Ranges:
    """Hands out ``(offset, length)`` blocks of a file to sender threads.

    Work-stealing rather than a fixed split: a fast connection simply takes
    more blocks, so one slow stream does not hold the transfer back. Blocks
    go out in ascending offset order, but the receiver must not assume they
    arrive that way (``MODE E`` carries the offset in every header).
    """

    def __init__(self, start: int, end: int, block: int) -> None:
        """Cover ``[start, end)`` in blocks of at most ``block`` bytes."""
        self._lock = threading.Lock()
        self._next = start
        self._end = end
        self._block = block

    def take(self) -> tuple[int, int] | None:
        """The next block to send, or ``None`` when the range is used up."""
        with self._lock:
            if self._next >= self._end:
                return None
            offset = self._next
            length = min(self._block, self._end - offset)
            self._next += length
            return offset, length


def recv_stream(
    conn: DataConn, write: Writer, buffer_size: int, on_bytes: Callable[[int], None], start: int = 0
) -> int:
    """``MODE S``: everything until the sender closes; the byte count.

    RFC 959 stream mode has no framing, so the end of the connection is the
    end of the file - which is why a ``MODE S`` transfer is one connection
    and a dropped connection looks like a short file (the final reply, and
    the size check after a copy, catch that). ``start`` is the file offset of
    the first byte (after ``REST``); ``on_bytes`` sees every chunk, for
    progress.
    """
    buffer = memoryview(bytearray(buffer_size))
    offset = start
    while True:
        count = conn.recv_into(buffer)
        if count == 0:
            return offset - start
        write(buffer[:count], offset)
        offset += count
        on_bytes(count)


def recv_blocks(
    conn: DataConn,
    write: Writer,
    buffer_size: int,
    on_bytes: Callable[[int], None],
    eods: EodCounter,
) -> None:
    """``MODE E``: blocks until this connection's ``EOD``.

    Each block is a :data:`~.protocol.BLOCK_HEADER` and ``count`` payload
    bytes for file offset ``offset``; payloads larger than ``buffer_size``
    are written in pieces. A block may carry descriptor flags with or
    without payload; the ``EOF`` block's offset field is the ``EOD`` count,
    not a position, and goes to ``eods``. The end of stream before an
    ``EOD`` is ``ECONNRESET``: the sender broke off.
    """
    header = memoryview(bytearray(_HEADER))
    buffer = memoryview(bytearray(buffer_size))
    while True:
        if not conn.recv_exact(header):
            raise GError("Data connection closed before its EOD block", errno.ECONNRESET)
        descriptor, count, offset = BLOCK_HEADER.unpack(header)
        while count:
            chunk = buffer[: min(count, buffer_size)]
            if not conn.recv_exact(chunk):
                raise GError("Data connection closed in the middle of a block", errno.ECONNRESET)
            write(chunk, offset)
            offset += len(chunk)
            count -= len(chunk)
            on_bytes(len(chunk))
        if descriptor & DESC_EOF:
            eods.eof(offset)
        if descriptor & DESC_EOD:
            eods.eod()
            return


@dataclass(frozen=True, slots=True)
class Feed:
    """What a sending connection reads from, in what pieces, and whom it tells.

    Shared by :func:`send_stream` and :func:`send_blocks`: one ``Feed`` per
    transfer (or per connection, when progress is counted per connection, as
    the test server does). ``buffer_size`` is the most read at once - in
    ``MODE E`` the block size, so it must match the :class:`Ranges` handed
    out - and ``on_bytes`` is called with each count actually sent, from the
    sending thread.
    """

    read: Reader
    buffer_size: int
    on_bytes: Callable[[int], None]


def send_stream(conn: DataConn, feed: Feed, start: int = 0, end: int | None = None) -> int:
    """``MODE S``: the bytes from ``start`` (to ``end``, else EOF), then hang up.

    Closing our write side *is* the end-of-file marker in stream mode, so
    :meth:`DataConn.finish` runs even when the source ends early; the
    receiver then judges the length. Returns the bytes sent. ``end`` lets
    the test server send just a byte range.
    """
    buffer_size = feed.buffer_size
    buffer = memoryview(bytearray(buffer_size))
    offset = start
    while end is None or offset < end:
        want = buffer_size if end is None else min(buffer_size, end - offset)
        count = feed.read(buffer[:want], offset)
        if count <= 0:
            break
        conn.sendall(buffer[:count])
        offset += count
        feed.on_bytes(count)
    conn.finish()
    return offset - start


def send_blocks(conn: DataConn, feed: Feed, ranges: Ranges, eof_count: int = 0) -> None:
    """``MODE E``: blocks from ``ranges`` until none are left, then ``EOD``.

    The connection given ``eof_count`` also carries the ``EOF`` block, folded
    into its ``EOD`` as globus does (descriptor ``0x48``, count in the offset).
    Exactly one connection of a transfer must get a non-zero ``eof_count``
    (the number of connections), or the receiver never completes. A source
    that reads short (truncated while sending) is ``EIO`` rather than a
    silent hole in the destination. The header and payload go out in one
    ``sendall`` from one buffer to keep each block a single write.
    """
    buffer = memoryview(bytearray(_HEADER + feed.buffer_size))
    while True:
        found = ranges.take()
        if found is None:
            break
        offset, length = found
        count = feed.read(buffer[_HEADER : _HEADER + length], offset)
        if count != length:
            raise GError(f"Short read of the source at offset {offset}", errno.EIO)
        BLOCK_HEADER.pack_into(buffer, 0, 0, count, offset)
        conn.sendall(buffer[: _HEADER + count])
        feed.on_bytes(count)
    if eof_count:
        conn.sendall(BLOCK_HEADER.pack(DESC_EOF | DESC_EOD, 0, eof_count))
    else:
        conn.sendall(BLOCK_HEADER.pack(DESC_EOD, 0, 0))
    conn.finish()


# ---------------------------------------------------------------------------
# The transfer loop
# ---------------------------------------------------------------------------


def _as_gerror(exc: BaseException) -> GError:
    """A worker thread's failure as the ``GError`` the operation will raise.

    Keeps a ``GError`` as is; socket timeouts are ``ETIMEDOUT``, other
    ``OSError``\\ s keep their ``errno`` (``EIO`` if none), and anything else
    - a bug, or ``KeyboardInterrupt`` on a worker - is ``EIO``.
    """
    if isinstance(exc, GError):
        return exc
    if isinstance(exc, TimeoutError):
        return GError("Data connection timed out", errno.ETIMEDOUT)
    if isinstance(exc, OSError):
        code = exc.errno or errno.EIO
        return GError(f"Data connection failed: {exc.strerror or exc}", code)
    return GError(f"Data connection failed: {exc}", errno.EIO)


class DataTransfer:
    """One command with its data connections, run to the final reply.

    ``worker(conn, index)`` moves the bytes of connection ``index``;
    ``streams`` connections are opened. ``check`` is called every poll
    interval and may raise (cancellation, deadline). Preliminary replies -
    ``150``, and the ``111``/``112`` markers a ``MODE E`` receiver sends -
    are passed over: between client and server the byte count is known
    first-hand.

    Single use: build one per command. If anything fails - a worker, the
    reply, ``check`` - every data socket is shut down, the control session
    is marked broken (its reply stream is out of step) and the first error
    is raised. Third-party copies do not use this class; there the data
    flows between the two servers (:class:`~._copy._ThirdParty`).
    """

    #: Seconds between control-channel polls, and so the latency of
    #: cancellation; tests shorten it.
    POLL = 0.2
    #: How long to wait for the server to explain a failed data connection.
    #: A worker's own error (a reset, a short block) says less than the
    #: failure reply the server sends a moment later, so the reply gets this
    #: long to arrive and be reported instead.
    GRACE = 5.0

    def __init__(
        self,
        control: Control,
        *,
        streams: int,
        worker: Callable[[DataConn, int], Any],
        check: Callable[[], None],
        setup: ConnSetup,
    ) -> None:
        """Prepare, without I/O; :meth:`run` does the work.

        ``streams`` below 1 is taken as 1. ``worker`` runs on a thread per
        connection and should raise on failure; its return value is ignored.
        ``setup`` gives each connection its security and timeout.
        """
        self.control = control
        self.streams = max(1, streams)
        self.worker = worker
        self.security = setup.security
        self.check = check
        self.timeout = setup.timeout
        #: Worker failures in the order they happened; the first is raised.
        self.errors: list[GError] = []
        #: Set by :meth:`_abort`: later sockets are closed on arrival and
        #: later worker errors (caused by the abort) are not recorded.
        self.finished = False
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self._lock = threading.Lock()
        self._listener: socket.socket | None = None

    # -- connection threads ------------------------------------------------------------

    def _track(self, sock: socket.socket) -> socket.socket:
        """Register a new data socket so :meth:`_abort` can reach it.

        A socket that arrives after the abort (a connect that was already in
        flight) is closed at once, so its worker fails fast instead of
        moving data nobody waits for.
        """
        with self._lock:
            self._sockets.append(sock)
            aborted = self.finished
        if aborted:
            sock.close()
        return sock

    def _run(self, index: int, obtain: Callable[[], socket.socket], initiator: bool) -> None:
        """One connection thread: get the socket, secure it, run the worker.

        Never raises: a failure is recorded for the control thread, which
        decides what the operation reports.
        """
        try:
            sock = self._track(obtain())
            sock.settimeout(self.timeout)
            conn = (
                DataConn(sock) if self.security is None else self.security.secure(sock, initiator)
            )
            self.worker(conn, index)
        except BaseException as exc:  # handed to the control thread
            with self._lock:
                if not self.finished:
                    self.errors.append(_as_gerror(exc))

    def _start(self, obtain: Callable[[int], Callable[[], socket.socket]], initiator: bool) -> None:
        """Start :attr:`streams` connection threads; ``obtain(index)`` makes each one's socket.

        Threads are daemons so a hung peer cannot keep the interpreter alive;
        :meth:`_join` still waits for them on every normal path.
        """
        for index in range(self.streams):
            thread = threading.Thread(
                target=self._run,
                args=(index, obtain(index), initiator),
                name=f"xgfal-gridftp-data-{index}",
                daemon=True,
            )
            self._threads.append(thread)
            thread.start()

    def _connector(
        self, addresses: list[tuple[str, int]]
    ) -> Callable[[int], Callable[[], socket.socket]]:
        """Passive side: connection ``index`` connects to address ``index`` mod the stripes.

        With one ``PASV`` address every stream connects to it; with ``SPAS``
        the streams are spread round-robin over the stripes.
        """

        def obtain(index: int) -> Callable[[], socket.socket]:
            """The connect function for stream ``index``; called on the control thread."""
            host, port = addresses[index % len(addresses)]

            def connect() -> socket.socket:
                """Connect, reporting failure in globus_xio's words."""
                try:
                    sock = socket.create_connection((host, port), self.timeout)
                except OSError as exc:
                    raise connect_error(exc, host, port) from exc
                return sock

            return connect

        return obtain

    def _acceptor(self, listener: socket.socket) -> Callable[[int], Callable[[], socket.socket]]:
        """Active side: each thread accepts one connection from the shared listener.

        The server may open fewer connections than offered (``MODE E``
        receive); the surplus threads are stopped by :meth:`_settle`'s abort
        once the ``done`` event says the data is complete.
        """
        listener.settimeout(self.timeout)

        def obtain(index: int) -> Callable[[], socket.socket]:
            """Any connection will do: the order of ``accept`` decides the index."""
            return lambda: listener.accept()[0]

        return obtain

    def _abort(self) -> None:
        """Stop everything: shut down every data socket and the listener.

        ``shutdown`` before ``close`` is what wakes a thread blocked in
        ``recv`` on another thread's socket; ``close`` alone does not on
        Linux. Safe to call more than once.
        """
        with self._lock:
            self.finished = True
            sockets = list(self._sockets)
        for sock in sockets:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        if self._listener is not None:
            self._listener.close()

    def _join(self) -> None:
        """Wait for every connection thread, calling ``check`` each poll.

        ``check`` may raise (cancellation); the threads are then left to the
        caller's abort.
        """
        for thread in self._threads:
            while thread.is_alive():
                thread.join(self.POLL)
                self.check()

    # -- the loop ------------------------------------------------------------------------

    def run(
        self,
        command: str,
        options: ChannelOptions,
        *,
        active: bool = False,
        done: threading.Event | None = None,
        getput: bool = False,
    ) -> Reply:
        """Set up the data channel, send ``command``, and see it through.

        ``done`` (MODE E receive) says the data is complete even if some of
        the connections the client offered were never used. ``getput`` is a
        GridFTP v2 ``GET``/``PUT ...;pasv;`` command, which asks for the
        passive address itself: the server answers ``127`` with it.

        ``active`` makes the client listen (``PORT``/``EPRT``) - required
        when the server sends in ``MODE E``, since there the sender must
        connect. The order is: set up the data channel (``PASV``/``PORT``),
        send the command, then connect or accept. Returns the final ``2xx``
        reply; a ``4xx``/``5xx`` raises as gfal2 words it.
        """
        control = self.control
        addresses: list[tuple[str, int]] = []
        if active:
            self._listener = listener = open_active(control, ipv6=options.ipv6)
        elif not getput:
            addresses = passive(control, options)
        try:
            control.send(command)
            if active:
                self._start(self._acceptor(listener), initiator=False)
            elif addresses:
                self._start(self._connector(addresses), initiator=True)
            final = self._await(bool(addresses) or active)
            self._settle(done)
        except BaseException:
            control.broken = True
            self._abort()
            raise
        finally:
            self._release()
        return final

    def _release(self) -> None:
        """Close every data socket and the listener once the transfer is over.

        On success the workers are done with their connections (``_settle``
        joined them); after a failure :meth:`_abort` has shut them down
        already, and closing again is harmless.
        """
        with self._lock:
            sockets = list(self._sockets)
        for sock in sockets:
            sock.close()
        if self._listener is not None:
            self._listener.close()

    def _await(self, started: bool) -> Reply:
        """Poll the control channel until the final reply.

        ``started`` is whether connections are already under way; if not,
        the server owes a ``127`` (delayed passive, or ``GET``/``PUT`` with
        ``pasv``) naming where to connect. While waiting, ``check`` runs
        every :attr:`POLL`, and a worker error is raised once the server has
        had :attr:`GRACE` seconds to send its own explanation.
        """
        control = self.control
        failed_at: float | None = None
        while True:
            reply = control.poll(self.POLL)
            if reply is None:
                failed_at = self._idle(failed_at)
                continue
            if reply.code == 127 and not started:
                host, port = parse_pasv(reply.text)
                self._start(self._connector([(routable(host, control), port)]), initiator=True)
                started = True
            elif reply.kind == 2:
                return reply
            elif reply.kind != 1:
                raise reply_error(reply)

    def _idle(self, failed_at: float | None) -> float | None:
        """A poll without a reply: ``check``, and give a failed worker's server its grace.

        ``failed_at`` is when a worker error was first seen (None before);
        the answer is the same, and the first error is raised once the
        server has had :attr:`GRACE` seconds since then.
        """
        self.check()
        if not self.errors:
            return failed_at
        failed_at = failed_at or time.monotonic()
        if time.monotonic() - failed_at > self.GRACE:
            raise self.errors[0]
        return failed_at

    def _settle(self, done: threading.Event | None) -> None:
        """After the final reply: wait for the workers, then raise the first error.

        With ``done`` (a ``MODE E`` receive), workers still blocked once all
        ``EOD``\\ s are in are waiting on connections the server never opened;
        they are aborted, and the errors that causes are not recorded
        because :attr:`finished` is set first.
        """
        if done is not None:
            for thread in self._threads:
                while thread.is_alive() and not done.is_set():
                    thread.join(self.POLL)
                    self.check()
            if done.is_set():
                self._abort()
        self._join()
        if self.errors:
            raise self.errors[0]


def perf_bytes(markers: dict[int, int], reply: Reply) -> int | None:
    """Fold a ``112`` marker into per-stripe totals; the new sum, or ``None``.

    Markers report each stripe's running total, not a delta, so the latest
    value per stripe replaces the previous one in ``markers`` (which the
    caller owns, one dict per transfer). ``None`` if ``reply`` is not a
    performance marker.
    """
    found = parse_perf_marker(reply)
    if found is None:
        return None
    index, count = found
    markers[index] = count
    return sum(markers.values())
