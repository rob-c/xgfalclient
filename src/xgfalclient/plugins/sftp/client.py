"""A pipelined, thread-safe SFTP v3 client over any byte stream.

The client neither knows nor cares what carries it - an ``ssh`` subprocess's
pipes, this package's own SSH-2 channel, or paramiko's - only that the
stream can :meth:`~Stream.send` and :meth:`~Stream.recv_into`.

**Pipelining.** SFTP tags every request with an id and lets the client have
many outstanding, so a transfer need not wait a round trip per chunk.
libssh2 (and so gfal2) keeps a handful in flight; here a read or write keeps
``depth`` requests of ``chunk`` bytes outstanding, sized from the server's
``limits@openssh.com`` when it has one. That is the difference between
round-trip-bound and link-bound throughput.

**Threads.** Any number of threads may use one client at once. Sends are
serialised by a lock. Receiving is "leader/follower": whichever waiting
thread finds nobody reading becomes the reader, files every response it
sees under its request id, and hands over when its own has arrived. There
is no background thread, and a single-threaded caller pays no hand-off.

**Zero copy.** A read may register a *sink* - a slice of the caller's
buffer - for its request id; the ``SSH_FXP_DATA`` payload is then received
straight into it.
"""

from __future__ import annotations

import errno
import struct
import threading
from collections import deque
from collections.abc import Callable, Iterator
from typing import Any, Protocol, Union

from ...crypto.sshkeys import KeyError_, Reader, string, uint32
from ...errors import GError
from . import protocol as fx
from .protocol import Attrs, StatusError

__all__ = ["Stream", "SFTPClient", "WriteBehind", "MAX_PACKET"]

Buffer = Union[bytes, bytearray, memoryview]

#: Refuse any packet longer than this: a text banner read as a length is huge.
MAX_PACKET = 64 * 1024 * 1024
#: What every server must accept (the draft's minimum), used without ``limits``.
DEFAULT_CHUNK = 32768
_HEADER = struct.Struct(">IBI")


class Stream(Protocol):
    """What the client needs from its transport."""

    def send(self, *parts: Buffer) -> None:
        """Write every part, in order, as one uninterrupted run."""

    def recv_into(self, view: memoryview) -> int:
        """Receive at least one byte into ``view``; ``0`` at end of stream."""

    def close(self) -> None: ...


def _closed_error(detail: str) -> GError:
    return GError(f"SFTP session closed by the server: {detail}", errno.ECONNRESET)


class SFTPClient:
    """One SFTP session. ``extensions`` and ``limits`` come from the handshake."""

    def __init__(self, stream: Stream, *, buffer_size: int = 262144) -> None:
        self.stream = stream
        self.extensions: dict[str, bytes] = {}
        self.max_read = DEFAULT_CHUNK
        self.max_write = DEFAULT_CHUNK
        self.max_handles = 0
        self._send_lock = threading.Lock()
        self._cond = threading.Condition()
        self._next_id = 1
        self._responses: dict[int, tuple[int, Any]] = {}
        self._sinks: dict[int, memoryview] = {}
        self._discard: set[int] = set()
        self._filling = 0
        self._reading = False
        self._error: GError | None = None
        self._buffer = bytearray(buffer_size)
        self._start = 0
        self._end = 0

    # -- lifecycle ---------------------------------------------------------------

    def handshake(self) -> None:
        """``SSH_FXP_INIT`` -> ``SSH_FXP_VERSION``, then ``limits@openssh.com`` if offered."""
        self.stream.send(uint32(5) + bytes([fx.INIT]) + uint32(fx.VERSION))
        ptype, version, body = self._read_packet(handshake=True)
        if ptype != fx.VERSION_:
            raise GError(f"SFTP protocol error: expected VERSION, got packet {ptype}", errno.EPROTO)
        if version < fx.VERSION:
            raise GError(f"SFTP server speaks version {version}; 3 is needed", errno.EPROTO)
        reader = Reader(body)
        try:
            while reader.remaining:
                name = reader.text()
                self.extensions[name] = reader.string()
        except KeyError_:
            raise GError("SFTP protocol error: malformed VERSION", errno.EPROTO) from None
        if "limits@openssh.com" in self.extensions:
            self._load_limits()

    def _load_limits(self) -> None:
        ptype, body = self.request(fx.EXTENDED, string("limits@openssh.com"))
        if ptype != fx.EXTENDED_REPLY:
            return
        reader = Reader(body)
        reader.uint64()  # max packet length
        read, write, handles = reader.uint64(), reader.uint64(), reader.uint64()
        # 0 means "no limit"; keep the safe default rather than trust infinity.
        self.max_read = int(read) or self.max_read
        self.max_write = int(write) or self.max_write
        self.max_handles = int(handles)

    @property
    def alive(self) -> bool:
        return self._error is None

    def close(self) -> None:
        with self._cond:
            if self._error is None:
                self._error = _closed_error("the session was closed")
            self._cond.notify_all()
        self.stream.close()

    # -- sending -----------------------------------------------------------------

    def send(self, ptype: int, *parts: Buffer, sink: memoryview | None = None) -> int:
        """Send one request; its id, to :meth:`wait` on."""
        return self.send_many([(ptype, parts, sink)])[0]

    def send_many(
        self, requests: list[tuple[int, tuple[Buffer, ...], memoryview | None]]
    ) -> list[int]:
        """Send ``(type, parts, sink)`` requests in one stream write; their ids.

        Pipelined reads are issued in batches this way, so a bulk download
        costs one transport write per batch rather than one per request.
        """
        rids = []
        with self._cond:
            if self._error is not None:
                raise GError(self._error.message, self._error.code)
            for _, _, sink in requests:
                rid = self._next_id
                self._next_id = (rid + 1) & 0xFFFFFFFF or 1
                if sink is not None:
                    self._sinks[rid] = sink
                rids.append(rid)
        wire: list[Buffer] = []
        for (ptype, parts, _), rid in zip(requests, rids):
            wire.append(_HEADER.pack(5 + sum(len(part) for part in parts), ptype, rid))
            wire.extend(parts)
        try:
            with self._send_lock:
                self.stream.send(*wire)
        except GError as exc:
            self._fail(exc)
            raise
        return rids

    def request(self, ptype: int, *parts: Buffer) -> tuple[int, Any]:
        return self.wait(self.send(ptype, *parts))

    # -- receiving ---------------------------------------------------------------

    def wait(self, rid: int) -> tuple[int, Any]:
        """The response to ``rid``: ``(type, body bytes)``, or ``(DATA, length)`` for a sink."""
        with self._cond:
            while True:
                if rid in self._responses:
                    return self._responses.pop(rid)
                if self._error is not None:
                    self._sinks.pop(rid, None)
                    raise GError(self._error.message, self._error.code)
                if not self._reading:
                    self._reading = True
                    break
                self._cond.wait()
        try:
            while True:
                ptype, got, body = self._read_packet()
                with self._cond:
                    if got in self._discard:
                        self._discard.discard(got)
                    else:
                        self._responses[got] = (ptype, body)
                    if got == rid:
                        return self._responses.pop(rid)
                    self._cond.notify_all()
        except GError as exc:
            self._fail(exc)
            raise
        finally:
            with self._cond:
                self._reading = False
                self._cond.notify_all()

    def forget(self, rids: list[int]) -> None:
        """Abandon outstanding requests: their responses are dropped, their sinks released.

        Waits while the current reader is filling one of their sinks, so the
        caller may reuse the buffer the moment this returns.
        """
        with self._cond:
            while self._filling in rids:
                self._cond.wait()
            for rid in rids:
                self._sinks.pop(rid, None)
                if self._responses.pop(rid, None) is None and self._error is None:
                    self._discard.add(rid)

    def _fail(self, exc: GError) -> None:
        with self._cond:
            if self._error is None:
                self._error = GError(exc.message, exc.code)
            self._reading = False
            self._cond.notify_all()
        try:
            self.stream.close()
        except Exception:  # already failing; the original error is what matters
            pass

    def _fill(self, count: int) -> None:
        """Make at least ``count`` bytes available in the read buffer."""
        if self._end - self._start >= count:
            return
        if len(self._buffer) - self._start < count:
            pending = self._end - self._start
            self._buffer[:pending] = self._buffer[self._start : self._end]
            self._start, self._end = 0, pending
        view = memoryview(self._buffer)
        while self._end - self._start < count:
            got = self.stream.recv_into(view[self._end :])
            if not got:
                raise _closed_error("end of stream")
            self._end += got

    def _take(self, count: int) -> bytes:
        if count <= len(self._buffer):
            self._fill(count)
            chunk = bytes(self._buffer[self._start : self._start + count])
            self._start += count
            return chunk
        out = bytearray(count)
        self._into(memoryview(out))
        return bytes(out)

    def _into(self, view: memoryview) -> None:
        """Fill ``view`` exactly: buffered bytes first, then straight from the stream."""
        have = min(self._end - self._start, len(view))
        view[:have] = self._buffer[self._start : self._start + have]
        self._start += have
        position = have
        while position < len(view):
            got = self.stream.recv_into(view[position:])
            if not got:
                raise _closed_error("end of stream")
            position += got

    def _read_packet(self, handshake: bool = False) -> tuple[int, int, Any]:
        self._fill(9)
        length, ptype, rid = _HEADER.unpack_from(self._buffer, self._start)
        if length < 5 or length > MAX_PACKET:
            hint = " - is the login shell printing text?" if handshake else ""
            raise GError(
                f"SFTP protocol error: received message of length {length}{hint}", errno.EPROTO
            )
        self._start += 9
        remaining = length - 5
        sink = None
        if ptype == fx.DATA and not handshake:
            with self._cond:
                sink = self._sinks.pop(rid, None)
                if sink is not None:
                    self._filling = rid
        if sink is not None:
            self._fill(4)
            (size,) = struct.unpack_from(">I", self._buffer, self._start)
            self._start += 4
            if size != remaining - 4 or size > len(sink):
                with self._cond:
                    self._filling = 0
                raise GError(
                    f"SFTP protocol error: {size} bytes of DATA for a request of {len(sink)}",
                    errno.EPROTO,
                )
            try:
                self._into(sink[:size])
            finally:
                with self._cond:
                    self._filling = 0
                    self._cond.notify_all()
            return ptype, rid, size
        return ptype, rid, self._take(remaining)

    # -- response helpers ----------------------------------------------------------

    @staticmethod
    def status(response: tuple[int, Any]) -> None:
        """Accept ``STATUS OK``; raise :class:`StatusError` for any other status."""
        ptype, body = response
        if ptype != fx.STATUS:
            raise GError(f"SFTP protocol error: expected STATUS, got {ptype}", errno.EPROTO)
        reader = Reader(body)
        code = reader.uint32()
        if code != fx.FX_OK:
            message = reader.text() if reader.remaining >= 4 else ""
            raise StatusError(code, message)

    def _expect(self, response: tuple[int, Any], ptype: int) -> Reader:
        if response[0] == fx.STATUS:
            self.status(response)
        if response[0] != ptype:
            raise GError(
                f"SFTP protocol error: expected packet {ptype}, got {response[0]}", errno.EPROTO
            )
        return Reader(response[1])

    def _attrs(self, response: tuple[int, Any]) -> Attrs:
        return Attrs.decode(self._expect(response, fx.ATTRS))

    def _handle(self, response: tuple[int, Any]) -> bytes:
        return self._expect(response, fx.HANDLE).string()

    def _names(self, response: tuple[int, Any]) -> list[tuple[str, str, Attrs]]:
        reader = self._expect(response, fx.NAME)
        return [
            (
                reader.string().decode("utf-8", "surrogateescape"),
                reader.text(),
                Attrs.decode(reader),
            )
            for _ in range(reader.uint32())
        ]

    # -- operations ----------------------------------------------------------------

    def stat(self, path: bytes) -> Attrs:
        return self._attrs(self.request(fx.STAT, string(path)))

    def lstat(self, path: bytes) -> Attrs:
        return self._attrs(self.request(fx.LSTAT, string(path)))

    def fstat(self, handle: bytes) -> Attrs:
        return self._attrs(self.request(fx.FSTAT, string(handle)))

    def setstat(self, path: bytes, attrs: Attrs) -> None:
        self.status(self.request(fx.SETSTAT, string(path), attrs.encode()))

    def mkdir(self, path: bytes, attrs: Attrs) -> None:
        self.status(self.request(fx.MKDIR, string(path), attrs.encode()))

    def rmdir(self, path: bytes) -> None:
        self.status(self.request(fx.RMDIR, string(path)))

    def remove(self, path: bytes) -> None:
        self.status(self.request(fx.REMOVE, string(path)))

    def rename(self, old: bytes, new: bytes) -> None:
        """POSIX ``rename`` (overwrites) when the server offers it; plain v3 rename otherwise."""
        if "posix-rename@openssh.com" in self.extensions:
            self.extended("posix-rename@openssh.com", string(old) + string(new))
        else:
            self.status(self.request(fx.RENAME, string(old), string(new)))

    def readlink(self, path: bytes) -> str:
        names = self._names(self.request(fx.READLINK, string(path)))
        if not names:
            raise GError("SFTP protocol error: empty READLINK reply", errno.EPROTO)
        return names[0][0]

    def symlink(self, target: bytes, link: bytes) -> None:
        # OpenSSH's sftp-server takes (target, link) - the reverse of the
        # draft - and every other server follows it, so that is the order.
        self.status(self.request(fx.SYMLINK, string(target), string(link)))

    def realpath(self, path: bytes) -> str:
        names = self._names(self.request(fx.REALPATH, string(path)))
        if not names:
            raise GError("SFTP protocol error: empty REALPATH reply", errno.EPROTO)
        return names[0][0]

    def open(self, path: bytes, flags: int, attrs: Attrs | None = None) -> bytes:
        return self._handle(
            self.request(fx.OPEN, string(path), uint32(flags), (attrs or Attrs()).encode())
        )

    def opendir(self, path: bytes) -> bytes:
        return self._handle(self.request(fx.OPENDIR, string(path)))

    def readdir(self, handle: bytes) -> list[tuple[str, str, Attrs]] | None:
        """One batch of entries, or ``None`` at the end of the directory."""
        response = self.request(fx.READDIR, string(handle))
        if response[0] == fx.STATUS:
            try:
                self.status(response)
            except StatusError as exc:
                if exc.code == fx.FX_EOF:
                    return None
                raise
        return self._names(response)

    def listdir(self, path: bytes) -> Iterator[tuple[str, str, Attrs]]:
        """Every entry of a directory, handle closed at the end (or on abandonment)."""
        handle = self.opendir(path)
        try:
            while True:
                batch = self.readdir(handle)
                if batch is None:
                    return
                yield from batch
        finally:
            self.close_handle(handle, quiet=True)

    def close_handle(self, handle: bytes, *, quiet: bool = False) -> None:
        try:
            self.status(self.request(fx.CLOSE, string(handle)))
        except (StatusError, GError):
            if not quiet:
                raise

    def read(self, handle: bytes, offset: int, size: int) -> bytes:
        """One ``SSH_FXP_READ``; ``b""`` at end of file."""
        response = self.request(fx.READ, string(handle), struct.pack(">QI", offset, size))
        if response[0] == fx.STATUS:
            try:
                self.status(response)
            except StatusError as exc:
                if exc.code == fx.FX_EOF:
                    return b""
                raise
        return self._expect(response, fx.DATA).string()

    def extended(self, name: str, payload: bytes = b"") -> tuple[int, Any]:
        """An ``SSH_FXP_EXTENDED`` request; a ``STATUS`` reply is checked."""
        response = self.request(fx.EXTENDED, string(name), payload)
        if response[0] == fx.STATUS:
            self.status(response)
        return response

    def fsync(self, handle: bytes) -> None:
        if "fsync@openssh.com" in self.extensions:
            self.extended("fsync@openssh.com", string(handle))

    def hardlink(self, old: bytes, new: bytes) -> None:
        self.extended("hardlink@openssh.com", string(old) + string(new))

    def statvfs(self, path: bytes) -> dict[str, int]:
        _, body = self.extended("statvfs@openssh.com", string(path))
        reader = Reader(body)
        names = ("bsize", "frsize", "blocks", "bfree", "bavail", "files", "ffree", "favail")
        values = {name: reader.uint64() for name in names}
        values["fsid"] = reader.uint64()
        values["flag"] = reader.uint64()
        values["namemax"] = reader.uint64()
        return values

    def check_file(
        self, path: bytes, algorithms: str, offset: int = 0, length: int = 0
    ) -> tuple[str, bytes]:
        """``check-file-name``: ``(algorithm used, hash)`` over a range (0 = whole file)."""
        payload = string(path) + string(algorithms) + struct.pack(">QQI", offset, length, 0)
        _, body = self.extended("check-file-name", payload)
        reader = Reader(body)
        return reader.text(), reader.rest()

    # -- pipelined data transfer -------------------------------------------------------

    def read_into(
        self,
        handle: bytes,
        offset: int,
        view: memoryview,
        *,
        chunk: int | None = None,
        depth: int = 64,
    ) -> int:
        """Fill ``view`` from ``offset`` with up to ``depth`` reads in flight.

        Returns the bytes read: fewer than ``len(view)`` only at end of file.
        A server may return less than asked for without being at the end;
        the remainder is simply asked for again.
        """
        chunk = chunk or self.max_read
        total = len(view)
        eof = total
        pending: deque[tuple[int, int, int]] = deque()  # rid, start, size
        todo: deque[tuple[int, int]] = deque()
        position = 0
        try:
            while True:
                while len(pending) < depth:
                    if todo:
                        start, size = todo.popleft()
                    elif position < eof:
                        start, size = position, min(chunk, eof - position)
                        position += size
                    else:
                        break
                    rid = self.send(
                        fx.READ,
                        string(handle),
                        struct.pack(">QI", offset + start, size),
                        sink=view[start : start + size],
                    )
                    pending.append((rid, start, size))
                if not pending:
                    return eof
                rid, start, size = pending.popleft()
                response = self.wait(rid)
                if response[0] == fx.DATA:
                    got = int(response[1])
                    if got < size and start + got < eof:
                        todo.append((start + got, size - got))
                    continue
                try:
                    self.status(response)
                except StatusError as exc:
                    if exc.code != fx.FX_EOF:
                        raise
                    # Nothing waits in ``todo`` here: every refill above drains it.
                    eof = min(eof, start)
                    continue
                raise GError("SFTP protocol error: READ answered with OK", errno.EPROTO)
        finally:
            if pending:
                self.forget([rid for rid, _, _ in pending])

    def stream_read(
        self,
        handle: bytes,
        offset: int,
        length: int | None,
        consume: Callable[[int, memoryview], None],
        *,
        chunk: int | None = None,
        depth: int = 64,
        check: Callable[[], None] | None = None,
    ) -> int:
        """Read ``length`` bytes (to EOF if ``None``) and hand each chunk to ``consume`` in order.

        ``depth`` reads stay in flight the whole time, each into its own
        buffer from a small pool, so the link never idles while ``consume``
        writes the previous chunk to disk. Returns the bytes delivered.
        """
        chunk = chunk or self.max_read
        end = None if length is None else offset + length
        free: list[bytearray] = []
        pending: deque[tuple[int, int, int, bytearray]] = deque()
        position = offset
        delivered = 0
        at_eof = False
        handle_string = string(handle)
        # Refill the pipeline a batch at a time: one write for several reads.
        batch = max(1, min(8, depth // 4))
        try:
            while True:
                if len(pending) <= depth - batch:
                    requests: list[tuple[int, tuple[Buffer, ...], memoryview | None]] = []
                    slots: list[tuple[int, int, bytearray]] = []
                    while (
                        not at_eof
                        and len(pending) + len(slots) < depth
                        and (end is None or position < end)
                    ):
                        size = chunk if end is None else min(chunk, end - position)
                        buffer = free.pop() if free else bytearray(chunk)
                        requests.append(
                            (
                                fx.READ,
                                (handle_string, struct.pack(">QI", position, size)),
                                memoryview(buffer)[:size],
                            )
                        )
                        slots.append((position, size, buffer))
                        position += size
                    if requests:
                        for rid, slot in zip(self.send_many(requests), slots):
                            pending.append((rid, *slot))
                if not pending:
                    return delivered
                rid, start, size, buffer = pending.popleft()
                response = self.wait(rid)
                if response[0] == fx.DATA:
                    got = int(response[1])
                    consume(start, memoryview(buffer)[:got])
                    delivered += got
                    if got < size:
                        # Short: re-read the rest in order before anything later.
                        rest = self.read_into(handle, start + got, memoryview(buffer)[: size - got])
                        if rest:
                            consume(start + got, memoryview(buffer)[:rest])
                            delivered += rest
                        if rest < size - got:
                            at_eof = True
                            self._drop(pending)
                    free.append(buffer)
                    if check is not None:
                        check()
                    continue
                try:
                    self.status(response)
                except StatusError as exc:
                    if exc.code != fx.FX_EOF:
                        raise
                    at_eof = True
                    self._drop(pending)
                    continue
                raise GError("SFTP protocol error: READ answered with OK", errno.EPROTO)
        finally:
            if pending:
                self.forget([item[0] for item in pending])

    def _drop(self, pending: deque[tuple[int, int, int, bytearray]]) -> None:
        self.forget([item[0] for item in pending])
        pending.clear()


class WriteBehind:
    """Pipelined writes to one handle: sent at once, acknowledged later.

    :meth:`write` returns as soon as the request is on the wire; up to
    ``depth`` acknowledgements may be outstanding. A failure is raised by
    the next :meth:`write` or by :meth:`flush` - which is why a file opened
    for writing reports errors on ``close()``, as the contract says.
    """

    def __init__(
        self, client: SFTPClient, handle: bytes, *, chunk: int = 0, depth: int = 64
    ) -> None:
        self.client = client
        self.handle = handle
        self.chunk = chunk or client.max_write
        self.depth = max(1, depth)
        self._pending: deque[int] = deque()
        self._error: BaseException | None = None
        self._handle_string = string(handle)

    def write(self, offset: int, data: Buffer) -> None:
        if self._error is not None:
            raise self._error
        view = memoryview(data).cast("B")
        for start in range(0, len(view), self.chunk):
            piece = view[start : start + self.chunk]
            while len(self._pending) >= self.depth:
                self._settle()
            rid = self.client.send(
                fx.WRITE,
                self._handle_string,
                struct.pack(">QI", offset + start, len(piece)),
                piece,
            )
            self._pending.append(rid)

    def _settle(self) -> None:
        rid = self._pending.popleft()
        try:
            self.client.status(self.client.wait(rid))
        except BaseException as exc:
            self._error = exc
            self.client.forget(list(self._pending))
            self._pending.clear()
            raise

    def flush(self) -> None:
        """Wait for every acknowledgement; raise the first failure."""
        while self._pending:
            self._settle()
        if self._error is not None:
            raise self._error
