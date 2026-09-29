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
"""

from __future__ import annotations

import errno
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..._compat import SLOTS
from ...crypto.gsi import GSIError, SecurityContext
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
    "DataConn",
    "DataSecurity",
    "DataTransfer",
    "EodCounter",
    "Ranges",
    "authenticate",
    "passive",
    "read_record",
    "recv_blocks",
    "recv_stream",
    "send_blocks",
    "send_stream",
    "Reader",
    "Writer",
    "open_active",
    "routable",
    "perf_bytes",
]

#: ``write(view, offset)``: where received bytes go.
Writer = Callable[[memoryview, int], None]
#: ``read(view, offset) -> count``: where sent bytes come from.
Reader = Callable[[memoryview, int], int]

_HEADER = BLOCK_HEADER.size


def recv_exact(sock: socket.socket, view: memoryview) -> bool:
    """Fill ``view``; ``False`` on a clean end of stream before the first byte."""
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
    """One TLS record (header and body) off a raw socket; ``b""`` at the end."""
    header = bytearray(5)
    if not recv_exact(sock, memoryview(header)):
        return b""
    body = bytearray(int.from_bytes(header[3:5], "big"))
    if body and not recv_exact(sock, memoryview(body)):
        raise GError("Data connection closed in the middle of a record", errno.ECONNRESET)
    return bytes(header + body)


class DataConn:
    """One data connection: a socket, optionally with ``PROT P`` wrapping."""

    __slots__ = ("_plain", "protect", "sock")

    def __init__(self, sock: socket.socket, protect: SecurityContext | None = None) -> None:
        self.sock = sock
        self.protect = protect
        self._plain = bytearray()

    def recv_into(self, view: memoryview) -> int:
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
        if self.protect is not None:
            data = self.protect.wrap(bytes(data))
        self.sock.sendall(data)

    def finish(self) -> None:
        """Signal the end of what we send (``MODE S`` EOF) and hang up."""
        try:
            self.sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        self.sock.close()


class DataSecurity:
    """What a session's data channels need: ``DCAU A`` contexts and ``PROT``."""

    __slots__ = ("acceptor", "identity", "initiator", "private")

    def __init__(
        self,
        initiator: ssl.SSLContext,
        acceptor: ssl.SSLContext,
        identity: tuple[tuple[str, str], ...],
        private: bool,
    ) -> None:
        self.initiator = initiator
        self.acceptor = acceptor
        self.identity = identity
        self.private = private

    def secure(self, sock: socket.socket, initiator: bool) -> DataConn:
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


@dataclass(frozen=True, **SLOTS)
class ChannelOptions:
    """How data channels open: ``[GRIDFTP PLUGIN] IPV6``, ``SPAS`` and ``DELAY_PASSV``."""

    ipv6: bool = False
    spas: bool = False
    delayed: bool = True


def passive(control: Control, options: ChannelOptions) -> list[tuple[str, int]]:
    """Make the server listen; its address(es), or ``[]`` when delayed to ``127``."""
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
    """The advertised host, or the control peer when it advertised nothing usable."""
    return control.peer if host in ("", "0.0.0.0", "::") else host


def open_active(control: Control, *, ipv6: bool) -> socket.socket:
    """Listen beside the control connection and tell the server with PORT/EPRT."""
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
    """``MODE E`` completion: the ``EOF`` block's count against ``EOD``s seen."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.expected: int | None = None
        self.seen = 0
        self.done = threading.Event()

    def eof(self, count: int) -> None:
        with self._lock:
            self.expected = count
            self._check()

    def eod(self) -> None:
        with self._lock:
            self.seen += 1
            self._check()

    def _check(self) -> None:
        if self.expected is not None and self.seen >= self.expected:
            self.done.set()


class Ranges:
    """Hands out ``(offset, length)`` blocks of a file to sender threads."""

    def __init__(self, start: int, end: int, block: int) -> None:
        self._lock = threading.Lock()
        self._next = start
        self._end = end
        self._block = block

    def take(self) -> tuple[int, int] | None:
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
    """``MODE S``: everything until the sender closes."""
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
    """``MODE E``: blocks until this connection's ``EOD``."""
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


def send_stream(
    conn: DataConn,
    read: Reader,
    buffer_size: int,
    on_bytes: Callable[[int], None],
    start: int = 0,
    end: int | None = None,
) -> int:
    """``MODE S``: the bytes from ``start`` (to ``end``, else EOF), then hang up."""
    buffer = memoryview(bytearray(buffer_size))
    offset = start
    while end is None or offset < end:
        want = buffer_size if end is None else min(buffer_size, end - offset)
        count = read(buffer[:want], offset)
        if count <= 0:
            break
        conn.sendall(buffer[:count])
        offset += count
        on_bytes(count)
    conn.finish()
    return offset - start


def send_blocks(
    conn: DataConn,
    read: Reader,
    ranges: Ranges,
    on_bytes: Callable[[int], None],
    buffer_size: int,
    eof_count: int = 0,
) -> None:
    """``MODE E``: blocks from ``ranges`` until none are left, then ``EOD``.

    The connection given ``eof_count`` also carries the ``EOF`` block, folded
    into its ``EOD`` as globus does (descriptor ``0x48``, count in the offset).
    """
    buffer = memoryview(bytearray(_HEADER + buffer_size))
    while True:
        found = ranges.take()
        if found is None:
            break
        offset, length = found
        count = read(buffer[_HEADER : _HEADER + length], offset)
        if count != length:
            raise GError(f"Short read of the source at offset {offset}", errno.EIO)
        BLOCK_HEADER.pack_into(buffer, 0, 0, count, offset)
        conn.sendall(buffer[: _HEADER + count])
        on_bytes(count)
    if eof_count:
        conn.sendall(BLOCK_HEADER.pack(DESC_EOF | DESC_EOD, 0, eof_count))
    else:
        conn.sendall(BLOCK_HEADER.pack(DESC_EOD, 0, 0))
    conn.finish()


# ---------------------------------------------------------------------------
# The transfer loop
# ---------------------------------------------------------------------------


def _as_gerror(exc: BaseException) -> GError:
    if isinstance(exc, GError):
        return exc
    if isinstance(exc, socket.timeout):
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
    """

    POLL = 0.2
    #: How long to wait for the server to explain a failed data connection.
    GRACE = 5.0

    def __init__(
        self,
        control: Control,
        *,
        streams: int,
        worker: Callable[[DataConn, int], Any],
        security: DataSecurity | None,
        check: Callable[[], None],
        timeout: float = 300.0,
    ) -> None:
        self.control = control
        self.streams = max(1, streams)
        self.worker = worker
        self.security = security
        self.check = check
        self.timeout = timeout
        self.errors: list[GError] = []
        self.finished = False
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self._lock = threading.Lock()
        self._listener: socket.socket | None = None

    # -- connection threads ------------------------------------------------------------

    def _track(self, sock: socket.socket) -> socket.socket:
        with self._lock:
            self._sockets.append(sock)
            aborted = self.finished
        if aborted:
            sock.close()
        return sock

    def _run(self, index: int, obtain: Callable[[], socket.socket], initiator: bool) -> None:
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
        def obtain(index: int) -> Callable[[], socket.socket]:
            host, port = addresses[index % len(addresses)]

            def connect() -> socket.socket:
                try:
                    sock = socket.create_connection((host, port), self.timeout)
                except OSError as exc:
                    raise connect_error(exc, host, port) from exc
                return sock

            return connect

        return obtain

    def _acceptor(self, listener: socket.socket) -> Callable[[int], Callable[[], socket.socket]]:
        listener.settimeout(self.timeout)

        def obtain(index: int) -> Callable[[], socket.socket]:
            return lambda: listener.accept()[0]

        return obtain

    def _abort(self) -> None:
        with self._lock:
            self.finished = True
            sockets = list(self._sockets)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        if self._listener is not None:
            self._listener.close()

    def _join(self) -> None:
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
    ) -> Reply:
        """Set up the data channel, send ``command``, and see it through.

        ``done`` (MODE E receive) says the data is complete even if some of
        the connections the client offered were never used.
        """
        control = self.control
        addresses: list[tuple[str, int]] = []
        if active:
            self._listener = listener = open_active(control, ipv6=options.ipv6)
        else:
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
            if self._listener is not None:
                self._listener.close()
        return final

    def _await(self, started: bool) -> Reply:
        control = self.control
        failed_at: float | None = None
        while True:
            reply = control.poll(self.POLL)
            if reply is None:
                self.check()
                if self.errors:
                    failed_at = failed_at or time.monotonic()
                    if time.monotonic() - failed_at > self.GRACE:
                        raise self.errors[0]
                continue
            if reply.code == 127 and not started:
                host, port = parse_pasv(reply.text)
                self._start(self._connector([(routable(host, control), port)]), initiator=True)
                started = True
            elif reply.kind == 2:
                return reply
            elif reply.kind != 1:
                raise reply_error(reply)

    def _settle(self, done: threading.Event | None) -> None:
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
    """Fold a ``112`` marker into per-stripe totals; the new sum, or ``None``."""
    found = parse_perf_marker(reply)
    if found is None:
        return None
    index, count = found
    markers[index] = count
    return sum(markers.values())
