"""The data channel to a pool mover, and the open file built on it.

Opening a file is a conversation on the control line that ends with a data
connection to the pool that holds (or will hold) the file:

1. The client sends ``open "<url>" r|w|rw [-mode=0644] [-truncate] <host>
   <port> -timeout=-1 -onerror=default -passive -uid=N``, where
   ``<host> <port>`` is a listening socket of its own (libdcap's "callback
   socket").
2. The door picks a pool and either answers ``connect <pool-host>
   <pool-port> <challenge>`` - the client connects and sends
   ``[session][length][challenge]`` - or, with an old pool, the pool
   connects to the client's socket and sends ``[session][length][challenge]``
   itself. dCache's movers have used the first ("passive") form since 1.7;
   gfal2 asks for it (``dc_setClientActive``); both are handled.
3. The data connection then carries requests: a read is ``SEEK_AND_READ``
   (offset, ``SEEK_SET``, length) answered by ``ACK``, ``DATA``, blocks of
   ``[n][n bytes]`` up to 256 KiB each, ``-1`` and ``FIN``; a write is
   ``WRITE`` (or ``SEEK_AND_WRITE``), ``ACK``, then the client's ``DATA``,
   blocks, ``-1``, and the mover's ``FIN``.
4. ``CLOSE`` - carrying the ADLER32 of what was written when the writes were
   sequential, which the pool verifies - is acknowledged on the data
   channel, and the door reports the transfer's outcome on the control line
   (``ok`` or ``failed ...``).

Reads go straight into the caller's buffer with ``recv_into``, and once
they are sequential they are pipelined: each request asks the mover for
:data:`READ_AHEAD` bytes, the next request is on the wire before the current
one has been received, and consecutive ``readinto`` calls take their bytes
from that stream, so the mover never waits for a round trip. (The mover
serves requests in order; one queued behind a running read is simply read
from its socket when that read ends.) Anything else - a read elsewhere, a
write, ``LOCATE``, ``CLOSE`` - first receives and discards what is still
outstanding, at most two windows. A request answered short (the end of the
file) ends the stream there.

Writes are streamed: a write opens a ``WRITE`` and consecutive writes append
blocks to it without waiting for anything; the ``-1``/``FIN`` that ends it is sent
only when something else (a read, a seek, a close) needs the channel. That is
libdcap's "unsafe write" mode - one round trip per stream instead of one per
call - and the mover reports any failure in the ``FIN``, which ``close()``
turns into the error.

``opendir`` works the same way, except that dCache's directory lister always
connects back to the client (``DirectoryLookUpPool``) and the "file" it
serves is the listing, one ``<pnfsid>:<d|f>:<size>:<name>`` line per entry.
"""

from __future__ import annotations

import contextlib
import errno
import os
import socket
import struct
import threading
import time
import zlib
from collections import deque
from collections.abc import Callable

from ...errors import GError
from ...plugin import O_ACCMODE_MASK, O_RDWR, O_WRONLY, PluginFile
from .control import ControlConnection, Door, socket_error
from .protocol import (
    ADLER32,
    DATA_SUM,
    HEADER,
    INT,
    IOCMD_ACK,
    IOCMD_CLOSE,
    IOCMD_DATA,
    IOCMD_FIN,
    IOCMD_LOCATE,
    IOCMD_READ,
    IOCMD_SEEK_READ,
    IOCMD_SEEK_WRITE,
    IOCMD_WRITE,
    SEEK_SET,
    Reply,
)

__all__ = [
    "DataChannel",
    "DcapFile",
    "await_data",
    "callback_listener",
    "read_listing",
    "MAX_BLOCK",
    "LISTING_CHUNK",
    "READ_AHEAD",
]

#: The largest block one write sends (the block length is a signed 32-bit int).
MAX_BLOCK = 1 << 30
#: Writes up to this size go out as one ``send`` together with their length.
SMALL_WRITE = 64 * 1024
#: How much of a directory listing one ``READ`` asks for.
LISTING_CHUNK = 1 << 20
#: What one request asks for once reads are sequential; two are in flight.
READ_AHEAD = 8 << 20
#: The buffer outstanding read-ahead is discarded into.
_DISCARD = 256 * 1024

_SEEK_READ = struct.Struct(">iiqiq")
_SEEK_WRITE = struct.Struct(">iiqi")
_READ = struct.Struct(">iiq")
_CLOSE_SUM = struct.Struct(">iiiiiI")
_REPLY = struct.Struct(">iii")

_NAMES = {IOCMD_ACK: "ACK", IOCMD_FIN: "FIN", IOCMD_DATA: "DATA"}

#: Failure reported by the door on the control line: ``(reply) -> GError``.
DoorError = Callable[[Reply], GError]


class DataChannel:
    """A connection to a mover: exact reads, whole writes, dcap replies."""

    def __init__(self, sock: socket.socket, role: str = "mover") -> None:
        self.sock = sock
        address = sock.getpeername()
        #: What error messages call the other end: ``dcap mover 10.0.0.7:33115``.
        self.peer = f"dcap {role} {address[0]}:{address[1]}"
        self._int = bytearray(4)

    def send(self, data: bytes | bytearray | memoryview) -> None:
        try:
            self.sock.sendall(data)
        except OSError as exc:  # socket.timeout is an OSError too
            raise socket_error(exc, f"The data connection to the {self.peer} failed") from exc

    def recv_into(self, view: memoryview) -> None:
        """Fill ``view`` completely."""
        got, size = 0, len(view)
        try:
            while got < size:
                count = self.sock.recv_into(view[got:])
                if not count:
                    raise GError(f"The {self.peer} closed the connection", errno.EIO)
                got += count
        except OSError as exc:  # socket.timeout is an OSError too
            raise socket_error(exc, f"The data connection to the {self.peer} failed") from exc

    def recv_int(self) -> int:
        self.recv_into(memoryview(self._int))
        return int(INT.unpack(self._int)[0])

    def expect(self, code: int, command: int = 0) -> bytes:
        """Read one reply; it must be ``code`` (for ``command``) and successful.

        Returns the reply's extra fields (a ``SEEK``'s position, a
        ``LOCATE``'s size and position).
        """
        length = self.recv_int()
        if length < 4 or length > 1 << 20:
            raise GError(f"Bad reply length {length} from the {self.peer}", errno.EPROTO)
        body = bytearray(length)
        self.recv_into(memoryview(body))
        kind = INT.unpack_from(body)[0]
        if kind == IOCMD_DATA and code == IOCMD_DATA:
            return b""
        if kind != code or length < 12:
            raise GError(
                f"Expected {_NAMES.get(code, code)} from the {self.peer}, "
                f"got {_NAMES.get(kind, kind)}",
                errno.EPROTO,
            )
        _, answered, result = _REPLY.unpack_from(body)
        extra = bytes(body[12:])
        if result != 0:
            message = ""
            if len(extra) >= 2:
                size = struct.unpack_from(">H", extra)[0]
                message = extra[2 : 2 + size].decode("utf-8", "replace")
            raise GError(
                f"The {self.peer} failed ({result}): {message or 'no reason given'}",
                errno.EIO,
            )
        if command and answered != command:
            raise GError(
                f"The {self.peer} answered command {answered}, not {command}",
                errno.EPROTO,
            )
        return extra

    def receive(self, view: memoryview) -> int:
        """The blocks of one read, into ``view``; ``-1`` ends them."""
        got = 0
        while True:
            size = self.recv_int()
            if size < 0:
                return got
            if got + size > len(view):
                raise GError(f"The {self.peer} sent more than was asked for", errno.EPROTO)
            self.recv_into(view[got : got + size])
            got += size

    def close(self) -> None:
        self.sock.close()


# ---------------------------------------------------------------------------
# Establishing the data connection
# ---------------------------------------------------------------------------


def callback_ports(value: str) -> range:
    """``$DCACHE_CBPORT`` as libdcap reads it: ``first`` or ``first:last``, ``last`` excluded.

    Either number is ``atoi``'s: leading digits, else zero. No port, or port
    zero, is any free port; a ``last`` at or below ``first`` wraps past
    65535 in libdcap, which is every port from ``first`` up.
    """
    first_text, colon, last_text = value.partition(":")
    first = _atoi(first_text)
    if first > 65535:
        return range(0, 1)  # no such port: any will do
    last = _atoi(last_text) if colon else first + 1
    if last <= first:
        last += 65536
    return range(first, min(last, 65536))


def _bind(listener: socket.socket, address: str, ports: range) -> None:
    """Bind to the first of ``ports`` that is free; libdcap's words when none is."""
    for port in ports[:-1]:
        with contextlib.suppress(OSError):
            listener.bind((address, port))
            return
    try:
        listener.bind((address, ports[-1]))
    except OSError as exc:
        if ports[0] == 0:
            raise  # any port at all, and none to be had: the socket's own error
        raise GError(
            "Error reported by the external library dcap : Bind failed, number : 27",
            exc.errno or errno.EADDRINUSE,
        ) from exc


def _atoi(text: str) -> int:
    digits = ""
    for character in text.strip():
        if not character.isdigit():
            break
        digits += character
    return int(digits) if digits else 0


def callback_listener(conn: ControlConnection) -> tuple[socket.socket, str, int]:
    """A listening socket for the pool to call back, and the host and port to announce.

    It is bound to the address the control connection leaves from, which is
    the one the door can route back to; ``$DCACHE_REPLY`` overrides the
    announced name and ``$DCACHE_CBPORT`` the ports it may listen on (for a
    firewalled client), as they do for libdcap.
    """
    local = conn.sock.getsockname()
    ports = callback_ports(os.environ.get("DCACHE_CBPORT", ""))
    listener = socket.socket(conn.sock.family, socket.SOCK_STREAM)
    try:
        _bind(listener, local[0], ports)
        listener.listen(8)
    except GError:
        listener.close()
        raise
    except OSError as exc:
        listener.close()
        raise socket_error(exc, "Cannot create the dcap callback socket") from exc
    host = os.environ.get("DCACHE_REPLY") or local[0]
    return listener, host, listener.getsockname()[1]


def _accept(listener: socket.socket, session: int, timeout: float) -> socket.socket | None:
    """A call from a pool for ``session``; ``None`` if it was for someone else."""
    try:
        sock, _ = listener.accept()
    except OSError as exc:
        raise socket_error(exc, "Cannot accept the dcap data connection") from exc
    sock.settimeout(timeout)
    channel = DataChannel(sock, "pool calling back from")
    try:
        caller = channel.recv_int()
        length = channel.recv_int()
        if not 0 <= length <= 4096:
            raise GError(f"Bad challenge length {length} on a dcap callback", errno.EPROTO)
        channel.recv_into(memoryview(bytearray(length)))
    except GError:
        sock.close()
        raise
    if caller != session:
        sock.close()
        return None
    return sock


def _connect_pool(reply: Reply, session: int, timeout: float) -> socket.socket:
    """Answer the door's ``connect <host> <port> <challenge>``."""
    try:
        host, port, challenge = reply.args[0], int(reply.args[1]), reply.args[2]
    except (IndexError, ValueError) as exc:
        raise GError(f"Malformed connect from the dcap door: {reply.args}", errno.EPROTO) from exc
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:  # socket.timeout is an OSError too
        raise socket_error(exc, f"Cannot connect to the dcap pool {host}:{port}") from exc
    token = challenge.encode("ascii", "replace")
    DataChannel(sock, "pool").send(HEADER.pack(session, len(token)) + token)
    return sock


def await_data(
    conn: ControlConnection,
    session: int,
    listener: socket.socket,
    timeout: float,
    failure: DoorError,
) -> socket.socket:
    """Wait for the data connection of ``session``, whichever side makes it."""
    deadline = time.monotonic() + timeout
    while True:
        if conn.select([listener], deadline):
            sock = _accept(listener, session, timeout)
            if sock is not None:
                break
            continue
        reply = conn.reply_for(conn.read_line(), session)
        if reply is None:
            continue
        if reply.verb == "connect":
            sock = _connect_pool(reply, session, timeout)
            break
        if reply.verb == "failed":
            raise failure(reply)
        if reply.verb == "retry":
            raise GError("The dcap door asked to retry the request", errno.EAGAIN)
    sock.settimeout(timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def read_listing(channel: DataChannel) -> bytes:
    """The whole listing a directory lister serves, then ``CLOSE``."""
    chunks = []
    buffer = bytearray(LISTING_CHUNK)
    view = memoryview(buffer)
    while True:
        channel.send(_READ.pack(12, IOCMD_READ, LISTING_CHUNK))
        channel.expect(IOCMD_ACK, IOCMD_READ)
        channel.expect(IOCMD_DATA)
        count = channel.receive(view)
        channel.expect(IOCMD_FIN, IOCMD_READ)
        if not count:
            break
        chunks.append(bytes(view[:count]))
    channel.send(HEADER.pack(4, IOCMD_CLOSE))
    channel.expect(IOCMD_ACK, IOCMD_CLOSE)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# The open file
# ---------------------------------------------------------------------------


class _Request:
    """One ``SEEK_AND_READ`` on the wire."""

    __slots__ = ("ahead", "got", "length", "offset", "started")

    def __init__(self, offset: int, length: int, ahead: bool) -> None:
        self.offset = offset
        self.length = length
        #: A read-ahead request, followed by the next one while it is received.
        self.ahead = ahead
        #: Bytes of it received so far.
        self.got = 0
        #: Whether its ``ACK`` and ``DATA`` have been received.
        self.started = False


class DcapFile(PluginFile):
    """A file open through a dcap door; see the module docstring for the protocol."""

    def __init__(
        self,
        url: str,
        flags: int,
        door: Door,
        conn: ControlConnection,
        session: int,
        channel: DataChannel,
        failure: DoorError,
    ) -> None:
        super().__init__(url)
        self.writable = (flags & O_ACCMODE_MASK) in (O_WRONLY, O_RDWR)
        self._door = door
        self._conn = conn
        self._session = session
        self._channel = channel
        self._failure = failure
        self._lock = threading.Lock()
        #: Where the mover's own file pointer is.
        self._mover_position = 0
        #: Where the open ``WRITE`` stream will put its next byte, if one is open.
        self._stream: int | None = None
        #: ADLER32 of everything written so far, while writes are sequential.
        self._adler: int | None = 1 if self.writable else None
        #: Set when the channel is in an unknown state; every later call fails with it.
        self._broken: GError | None = None
        #: ``SEEK_AND_READ`` requests on the wire, oldest (the one being received) first.
        self._requests: deque[_Request] = deque()
        #: What is left of the block being received.
        self._block = 0
        #: Where the last read ended: a read starting there is sequential.
        self._read_end = -1

    # -- plumbing ------------------------------------------------------------------

    def _run(self, action: Callable[[], int]) -> int:
        with self._lock:
            if self._broken is not None:
                raise self._broken
            try:
                return action()
            except GError as exc:
                self._broken = exc
                raise

    def _end_write(self) -> None:
        """Finish the open ``WRITE`` stream, if any: ``-1``, then the mover's ``FIN``."""
        if self._stream is None:
            return
        position, self._stream = self._stream, None
        self._channel.send(INT.pack(-1))
        self._channel.expect(IOCMD_FIN)
        self._mover_position = position

    # -- reading -------------------------------------------------------------------

    def _request(self, offset: int, length: int, ahead: bool) -> None:
        self._channel.send(_SEEK_READ.pack(24, IOCMD_SEEK_READ, offset, SEEK_SET, length))
        self._requests.append(_Request(offset, length, ahead))

    def _pull(self, view: memoryview) -> int:
        """Up to ``len(view)`` bytes of the oldest request; 0 once it has ended.

        An ended request is retired, and the mover is then where it stopped.
        """
        channel = self._channel
        request = self._requests[0]
        if not request.started:
            channel.expect(IOCMD_ACK, IOCMD_SEEK_READ)
            channel.expect(IOCMD_DATA)
            request.started = True
        while not self._block:
            size = channel.recv_int()
            if size < 0:
                channel.expect(IOCMD_FIN, IOCMD_SEEK_READ)
                self._requests.popleft()
                self._mover_position = request.offset + request.got
                return 0
            if request.got + size > request.length:
                raise GError(f"The {channel.peer} sent more than was asked for", errno.EPROTO)
            self._block = size
        count = min(self._block, len(view))
        channel.recv_into(view[:count])
        self._block -= count
        request.got += count
        return count

    def _end_read(self) -> None:
        """Receive and discard whatever the outstanding requests still bring."""
        if not self._requests:
            return
        scratch = memoryview(bytearray(_DISCARD))
        while self._requests:
            self._pull(scratch)

    def _read(self, offset: int, view: memoryview) -> int:
        self._end_write()
        size = len(view)
        if not size:
            return 0
        total = 0
        while total < size:
            position = offset + total
            requests = self._requests
            if requests and requests[0].offset + requests[0].got != position:
                self._end_read()  # a read elsewhere, or read-ahead past a short answer
            if not requests:
                if position == self._read_end:
                    self._request(position, max(size, READ_AHEAD), True)
                else:
                    self._request(position, size - total, False)
            head = requests[0]
            # A queued request is never complete: the one that completes is retired below.
            if head.ahead and len(requests) == 1:
                self._request(head.offset + head.length, head.length, True)
            count = self._pull(view[total:])
            total += count
            if not count:
                break  # it ended short: the end of the file, for now
            if head.got == head.length:
                self._pull(view[:0])  # only its end is left; a failure in it is this read's
        self._read_end = offset + total
        return total

    def readinto(self, buffer: memoryview | bytearray) -> int:
        view = memoryview(buffer).cast("B")

        def action() -> int:
            count = self._read(self.position, view)
            self.position += count
            return count

        return self._run(action)

    def read(self, size: int) -> bytes:
        buffer = bytearray(size)
        count = self.readinto(buffer)
        del buffer[count:]
        return bytes(buffer)

    def pread(self, offset: int, size: int) -> bytes:
        buffer = bytearray(size)
        count = self._run(lambda: self._read(offset, memoryview(buffer)))
        del buffer[count:]
        return bytes(buffer)

    # -- writing -------------------------------------------------------------------

    def _write(self, offset: int, data: bytes | bytearray | memoryview) -> int:
        view = memoryview(data).cast("B")
        if not len(view):
            return 0
        channel = self._channel
        self._end_read()
        if self._stream != offset:
            self._end_write()
            if offset == self._mover_position:
                channel.send(HEADER.pack(4, IOCMD_WRITE))
                command = IOCMD_WRITE
            else:
                # libdcap gives up on the running checksum after any seek.
                channel.send(_SEEK_WRITE.pack(16, IOCMD_SEEK_WRITE, offset, SEEK_SET))
                command = IOCMD_SEEK_WRITE
                self._adler = None
            channel.expect(IOCMD_ACK, command)
            channel.send(HEADER.pack(4, IOCMD_DATA))
            self._stream = offset
        for start in range(0, len(view), MAX_BLOCK):
            block = view[start : start + MAX_BLOCK]
            if len(block) <= SMALL_WRITE:
                channel.send(INT.pack(len(block)) + block.tobytes())
            else:
                channel.send(INT.pack(len(block)))
                channel.send(block)
        if self._adler is not None:
            self._adler = zlib.adler32(view, self._adler)
        self._stream = offset + len(view)
        return len(view)

    def write(self, data: bytes | bytearray | memoryview) -> int:
        def action() -> int:
            count = self._write(self.position, data)
            self.position += count
            return count

        return self._run(action)

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        return self._run(lambda: self._write(offset, data))

    # -- size ----------------------------------------------------------------------

    def _locate(self) -> int:
        self._end_read()
        self._end_write()
        self._channel.send(HEADER.pack(4, IOCMD_LOCATE))
        extra = self._channel.expect(IOCMD_ACK, IOCMD_LOCATE)
        if len(extra) < 16:
            raise GError(f"Short LOCATE reply from the {self._channel.peer}", errno.EPROTO)
        size, position = struct.unpack_from(">qq", extra)
        self._mover_position = position
        return int(size)

    def size(self) -> int | None:
        """The file's current size, from the mover (``IOCMD_LOCATE``)."""
        return self._run(self._locate)

    # -- closing -------------------------------------------------------------------

    def _close(self) -> int:
        self._end_read()
        self._end_write()
        if self._adler is not None:
            message = _CLOSE_SUM.pack(20, IOCMD_CLOSE, 12, DATA_SUM, ADLER32, self._adler)
        else:
            message = HEADER.pack(4, IOCMD_CLOSE)
        self._channel.send(message)
        self._channel.expect(IOCMD_ACK, IOCMD_CLOSE)
        reply = self._conn.wait(self._session)
        if reply.verb == "failed":
            raise self._failure(reply)
        return 0

    def close(self) -> None:
        """End the transfer; a failure is reported for files open for writing only.

        As libdcap does: a reader has its data already, and whatever the
        mover says afterwards cannot make it wrong.
        """
        if self.closed:
            return
        self.closed = True
        error: GError | None = None
        try:
            self._run(self._close)
        except GError as exc:
            error = exc
        finally:
            self._channel.close()
            self._door.release(self._conn, reusable=error is None)
        if error is not None and self.writable:
            raise error
