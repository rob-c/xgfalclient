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

**Wire format** (``draft-ietf-secsh-filexfer-02``, section 3). Every packet
is ``uint32 length`` (counting what follows), ``byte type``, then - for all
but ``SSH_FXP_INIT``/``SSH_FXP_VERSION`` - ``uint32 request-id`` and the
type's fields. Strings are :rfc:`4251` ``string`` (``uint32`` length, then
bytes), integers big-endian. :mod:`.protocol` holds the numbers and the
``ATTRS`` codec; this module does the talking.

**Errors.** Two kinds, kept apart on purpose. A non-``OK`` ``SSH_FXP_STATUS``
is a :class:`~.protocol.StatusError`: the session is fine, the operation
failed, and the plugin turns it into a :class:`GError` with the errno that
status stands for and the URL in the message. Anything that breaks the
session - the stream closing (``ECONNRESET``), a malformed or oversized
packet (``EPROTO``), the transport's own errors (``ETIMEDOUT`` on a stall) -
is a :class:`GError` that also marks the client dead (:attr:`SFTPClient.alive`),
so the plugin's pool never hands it out again.

Where to start reading: :meth:`SFTPClient.handshake`, then
:meth:`SFTPClient.send_many` and :meth:`SFTPClient.wait` (the whole
concurrency story), then :meth:`SFTPClient.stream_read`.
"""

from __future__ import annotations

import contextlib
import errno
import struct
import threading
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Protocol

from ...crypto.sshkeys import KeyError_, Reader, string, uint32
from ...errors import GError
from . import protocol as fx
from .protocol import Attrs, StatusError

__all__ = ["MAX_PACKET", "SFTPClient", "Stream", "StreamOptions", "WriteBehind"]

#: Anything the stream can write without a copy (``send`` takes several).
Buffer = bytes | bytearray | memoryview

#: Refuse any packet longer than this: a text banner read as a length is huge.
MAX_PACKET = 64 * 1024 * 1024
#: What every server must accept (the draft's minimum), used without ``limits``.
#: The draft asks servers to take packets of at least 34000 bytes, which is
#: room for a 32768-byte ``READ``/``WRITE`` payload plus its header.
DEFAULT_CHUNK = 32768
#: ``uint32 length``, ``byte type``, ``uint32 request-id``: the 9 bytes every
#: request and response starts with. In ``SSH_FXP_VERSION`` the third field
#: is the version rather than an id, which :meth:`SFTPClient.handshake` uses.
_HEADER = struct.Struct(">IBI")


class Stream(Protocol):
    """What the client needs from its transport.

    Implemented by :mod:`.openssh` (an ``ssh -s host sftp`` subprocess's pipes),
    :mod:`.ssh` (this package's SSH-2 ``session`` channel running the
    ``sftp`` subsystem, :rfc:`4254` section 6.5) and :mod:`.paramiko_tier`.
    A transport reports its failures as :class:`GError` - a stall as
    ``ETIMEDOUT``, a dropped connection as ``ECONNRESET`` - which the client
    treats as fatal to the session.
    """

    def send(self, *parts: Buffer) -> None:
        """Write every part, in order, as one uninterrupted run."""

    def recv_into(self, view: memoryview) -> int:
        """Receive at least one byte into ``view``; ``0`` at end of stream."""

    def close(self) -> None:
        """Release the transport; must tolerate being called more than once."""

    # A stream may also have ``abort()``: break the connection under a thread
    # blocked in ``send``/``recv_into`` without closing it (see
    # :meth:`SFTPClient.abort`). One without it is closed instead.


def _closed_error(detail: str) -> GError:
    """The ``ECONNRESET`` a session that has gone away fails every later call with."""
    return GError(f"SFTP session closed by the server: {detail}", errno.ECONNRESET)


@dataclass(frozen=True, slots=True)
class StreamOptions:
    """How :meth:`SFTPClient.stream_read` runs its pipeline.

    ``chunk`` is the size of each ``SSH_FXP_READ`` (``None``: the server's
    ``max_read``, 32 KiB without ``limits@openssh.com``). ``depth`` is how
    many stay in flight; ``[SFTP PLUGIN] PIPELINE_DEPTH`` sets it for copies.
    ``check`` is called after each chunk is consumed - a copy passes its
    :meth:`~xgfalclient.transfer.Transfer.check`, which raises ``ECANCELED``
    on cancel or ``ETIMEDOUT`` past the copy's deadline, ending the stream
    between chunks.
    """

    chunk: int | None = None
    depth: int = 64
    check: Callable[[], None] | None = None


_DEFAULT_STREAM = StreamOptions()


class SFTPClient:
    """One SFTP session. ``extensions`` and ``limits`` come from the handshake.

    The client owns its stream: :meth:`close` (or any fatal error) closes
    it. It is shared by the threads of one operation but pooled per
    endpoint by the plugin, which checks it out to one operation (or one
    open file) at a time and only pools it again while :attr:`alive`.

    State shared between threads lives under ``_cond``: the id counter, the
    filed responses, the registered sinks, the ids to discard, which sink
    is being filled, whether a thread is reading, and the fatal error.
    The read buffer (``_buffer``/``_start``/``_end``) is touched only by the
    one thread that holds the reader role, so it needs no lock.
    """

    def __init__(self, stream: Stream, *, buffer_size: int = 262144) -> None:
        """Wrap a connected ``stream``; nothing is sent until :meth:`handshake`.

        ``buffer_size`` is the receive buffer: small replies are parsed out
        of it, and a ``DATA`` reply with a sink bypasses it. 256 KiB holds
        many 32 KiB packets per ``recv_into``.
        """
        self.stream = stream
        #: The server's ``SSH_FXP_VERSION`` extensions: name -> data (often ``b"1"``).
        self.extensions: dict[str, bytes] = {}
        #: Largest ``READ``/``WRITE`` payload to ask for; from ``limits@openssh.com``.
        self.max_read = DEFAULT_CHUNK
        self.max_write = DEFAULT_CHUNK
        #: Open-handle limit the server announced; ``0`` for none (informational).
        self.max_handles = 0
        self._send_lock = threading.Lock()
        self._cond = threading.Condition()
        self._next_id = 1
        # rid -> (packet type, body bytes | DATA length) for responses that
        # arrived while their owner was not the reader.
        self._responses: dict[int, tuple[int, Any]] = {}
        # rid -> caller's buffer slice an SSH_FXP_DATA reply is received into.
        self._sinks: dict[int, memoryview] = {}
        # Ids abandoned by forget() whose replies are still to come: dropped on arrival.
        self._discard: set[int] = set()
        # The rid whose sink the reader is writing into now; 0 for none (ids skip 0).
        self._filling = 0
        self._reading = False
        # Set once, by the first fatal failure or close/abort; every later call re-raises it.
        self._error: GError | None = None
        # Receive buffer: bytes [_start, _end) have arrived but are not yet parsed.
        self._buffer = bytearray(buffer_size)
        self._start = 0
        self._end = 0

    # -- lifecycle ---------------------------------------------------------------

    def handshake(self) -> None:
        """``SSH_FXP_INIT`` -> ``SSH_FXP_VERSION``, then ``limits@openssh.com`` if offered.

        ``INIT`` carries the client's version (3); ``VERSION`` the server's,
        then any number of ``string name, string data`` extension pairs, kept
        in :attr:`extensions` - the operations below consult them to choose
        between a v3 request and an OpenSSH extension. A server below
        version 3 is refused with ``EPROTO``; one above is spoken to in 3,
        as the draft has it negotiate down. A first packet that is not
        ``VERSION`` - or whose length is absurd, which is what a login shell
        printing a banner on the channel looks like - is ``EPROTO`` too.
        """
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
        """Size the pipeline from ``limits@openssh.com`` (OpenSSH 8.6+).

        The reply is four ``uint64``: max packet length, max read length,
        max write length, max open handles. Read and write lengths bound the
        ``chunk`` of a pipelined transfer; the packet length is implied by
        them and not used. A server that answers with anything but
        ``EXTENDED_REPLY`` simply leaves the 32 KiB defaults in place.
        """
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
        """``False`` once closed, aborted or failed fatally; the pool's test for reuse."""
        return self._error is None

    def close(self) -> None:
        """Mark the session closed, wake every waiter, and close the stream.

        Idempotent. A thread still waiting for a reply gets ``ECONNRESET``
        ("the session was closed") rather than hanging; one that failed
        first keeps its original error, since only the first is recorded.
        """
        with self._cond:
            if self._error is None:
                self._error = _closed_error("the session was closed")
            self._cond.notify_all()
        self.stream.close()

    def abort(self) -> None:
        """Break the session under whatever thread is blocked on it; for ``cancel()``.

        Registered with the context (:meth:`~xgfalclient.Gfal2Context.abort_on_cancel`)
        around every operation, so a server gone silent no longer holds a
        ``cancel()`` for the whole timeout. The session is marked dead first
        - so the pool never hands it out again and waiters for other replies
        wake - then the transport is broken beneath the reader: its socket
        shut down, or the ``ssh`` process ended. Closing is left to the
        owner, which sees the failure and closes as it always does.
        """
        with self._cond:
            if self._error is None:
                self._error = _closed_error("the operation was cancelled")
            self._cond.notify_all()
        abort = getattr(self.stream, "abort", None)
        if abort is None:
            self.stream.close()
        else:
            abort()

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

        Ids are taken, and sinks registered, under ``_cond`` *before* the
        write, so a reply can never arrive for an id the reader does not
        know. Two threads may therefore put their ids on the wire out of
        numeric order; that is harmless, since replies are matched by id.
        A dead session raises its recorded error without sending; a failed
        write kills the session (the stream may hold half a packet).
        """
        rids = []
        with self._cond:
            if self._error is not None:
                raise GError(self._error.message, self._error.code)
            for _, _, sink in requests:
                rid = self._next_id
                # Ids are uint32 on the wire; 0 is skipped because ``_filling``
                # uses it to mean "no sink is being filled".
                self._next_id = (rid + 1) & 0xFFFFFFFF or 1
                if sink is not None:
                    self._sinks[rid] = sink
                rids.append(rid)
        wire: list[Buffer] = []
        for (ptype, parts, _), rid in zip(requests, rids, strict=False):
            # The length counts the type byte and the id (5) plus the body.
            wire.append(_HEADER.pack(5 + sum(len(part) for part in parts), ptype, rid))
            wire.extend(parts)
        try:
            # One lock-held send per batch: packets from different threads
            # must not interleave on the stream.
            with self._send_lock:
                self.stream.send(*wire)
        except GError as exc:
            self._fail(exc)
            raise
        return rids

    def request(self, ptype: int, *parts: Buffer) -> tuple[int, Any]:
        """Send one request and wait for its reply: one round trip, ``(type, body)``."""
        return self.wait(self.send(ptype, *parts))

    # -- receiving ---------------------------------------------------------------

    def wait(self, rid: int) -> tuple[int, Any]:
        """The response to ``rid``: ``(type, body bytes)``, or ``(DATA, length)`` for a sink.

        The leader/follower hand-off. A waiter whose reply is already filed
        takes it - even after a fatal error, so replies that arrived before
        the session died are not lost. Otherwise, if no thread is reading,
        it becomes the reader: it reads packets, files each under its id
        (or drops it, if :meth:`forget` abandoned it), wakes the followers
        so they can look for theirs, and returns as soon as its own arrives,
        giving up the reader role in ``finally`` for the next waiter.

        Raises the session's recorded :class:`GError` once it is dead, and
        any read failure - after recording it, so every other waiter fails
        with the same error instead of waiting for a reply that cannot come.
        A ``STATUS`` reply is returned, not raised: callers decide whether
        ``EOF`` is an error.
        """
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
                    # A READ answered with STATUS (EOF, or a refusal) never had
                    # its sink taken by _read_packet; release it now. Left in
                    # place it would pin the caller's buffer and, once request
                    # ids wrap, swallow the DATA of a later request that reuses
                    # the id. For a DATA reply that filled its sink this is a no-op.
                    self._sinks.pop(got, None)
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

        A reply already filed is discarded now; one still on its way is
        remembered in ``_discard`` and dropped by the reader on arrival. On
        a dead session nothing more will arrive, so nothing is remembered.
        """
        with self._cond:
            while self._filling in rids:
                self._cond.wait()
            for rid in rids:
                self._sinks.pop(rid, None)
                if self._responses.pop(rid, None) is None and self._error is None:
                    self._discard.add(rid)

    def _fail(self, exc: GError) -> None:
        """Record a fatal error (the first one wins), wake all waiters, close the stream.

        A copy of ``exc`` is kept, so every later caller raises a fresh
        :class:`GError` with the same message and code rather than sharing
        one exception object (and its traceback) across threads.
        """
        with self._cond:
            if self._error is None:
                self._error = GError(exc.message, exc.code)
            self._reading = False
            self._cond.notify_all()
        # Already failing; the original error is what matters.
        with contextlib.suppress(Exception):
            self.stream.close()

    def _fill(self, count: int) -> None:
        """Make at least ``count`` bytes available in the read buffer."""
        if self._end - self._start >= count:
            return
        if len(self._buffer) - self._start < count:
            # Not enough room after _start: slide the unparsed bytes to the front.
            pending = self._end - self._start
            self._buffer[:pending] = self._buffer[self._start : self._end]
            self._start, self._end = 0, pending
        view = memoryview(self._buffer)
        # recv_into may deliver more than asked for (up to the buffer's end):
        # the surplus is the next packets' bytes, kept for the next call.
        while self._end - self._start < count:
            got = self.stream.recv_into(view[self._end :])
            if not got:
                raise _closed_error("end of stream")
            self._end += got

    def _take(self, count: int) -> bytes:
        """The next ``count`` bytes of the stream, as an owned ``bytes`` copy.

        A body that fits the receive buffer is assembled there; a larger one
        (up to :data:`MAX_PACKET`) gets its own buffer and is received
        straight into it, so the receive buffer never has to grow.
        """
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
        """Read one packet: ``(type, request id, body)``; called only by the reader.

        The body is ``bytes``, except for an ``SSH_FXP_DATA`` whose id has a
        registered sink: then the payload (``uint32 length`` + bytes) is
        received into the sink and the body is its length. The sink is
        taken out of ``_sinks`` and its id put in ``_filling`` under the
        lock, so :meth:`forget` cannot release the buffer mid-copy.

        ``EPROTO`` for a length below 5 (no room for type and id) or above
        :data:`MAX_PACKET`, and for a ``DATA`` that is longer than its sink
        or whose inner length disagrees with the packet length - a server
        must not answer a ``READ`` with more than was asked for. During
        :meth:`handshake` the "id" is the version and no sink is consulted.
        """
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
        """Accept ``STATUS OK``; raise :class:`StatusError` for any other status.

        ``SSH_FXP_STATUS`` is ``uint32 code``, ``string message``, ``string
        language``; some old servers send the code alone, so the message is
        read only if present (:class:`StatusError` then names the code). A
        reply of another type where a status was due is ``EPROTO``.
        """
        ptype, body = response
        if ptype != fx.STATUS:
            raise GError(f"SFTP protocol error: expected STATUS, got {ptype}", errno.EPROTO)
        reader = Reader(body)
        code = reader.uint32()
        if code != fx.FX_OK:
            message = reader.text() if reader.remaining >= 4 else ""
            raise StatusError(code, message)

    def _expect(self, response: tuple[int, Any], ptype: int) -> Reader:
        """A reader over a reply that must be ``ptype``.

        A ``STATUS`` in its place is the server refusing: raised as
        :class:`StatusError`. A ``STATUS OK`` (or any other type) where data
        was due makes no sense and is ``EPROTO``.
        """
        if response[0] == fx.STATUS:
            self.status(response)
        if response[0] != ptype:
            raise GError(
                f"SFTP protocol error: expected packet {ptype}, got {response[0]}", errno.EPROTO
            )
        return Reader(response[1])

    def _attrs(self, response: tuple[int, Any]) -> Attrs:
        """Decode an ``SSH_FXP_ATTRS`` reply."""
        return Attrs.decode(self._expect(response, fx.ATTRS))

    def _handle(self, response: tuple[int, Any]) -> bytes:
        """The opaque handle string of an ``SSH_FXP_HANDLE`` reply."""
        return self._expect(response, fx.HANDLE).string()

    def _names(self, response: tuple[int, Any]) -> list[tuple[str, str, Attrs]]:
        """Decode an ``SSH_FXP_NAME``: ``uint32 count``, then per entry ``(name, longname, ATTRS)``.

        Names are bytes on the wire; undecodable ones survive a round trip
        through ``surrogateescape``, the way :func:`os.fsdecode` treats them.
        ``longname`` is the ``ls -l`` line the draft defines for display.
        """
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
    #
    # One round trip each. A refusal raises StatusError (the plugin maps it to
    # a GError with a real errno); a broken session raises GError. Paths are
    # bytes, as on the wire.

    def stat(self, path: bytes) -> Attrs:
        """``SSH_FXP_STAT``: follows symlinks."""
        return self._attrs(self.request(fx.STAT, string(path)))

    def lstat(self, path: bytes) -> Attrs:
        """``SSH_FXP_LSTAT``: describes a symlink itself."""
        return self._attrs(self.request(fx.LSTAT, string(path)))

    def fstat(self, handle: bytes) -> Attrs:
        """``SSH_FXP_FSTAT`` of an open handle."""
        return self._attrs(self.request(fx.FSTAT, string(handle)))

    def setstat(self, path: bytes, attrs: Attrs) -> None:
        """``SSH_FXP_SETSTAT``: change only the fields set in ``attrs``."""
        self.status(self.request(fx.SETSTAT, string(path), attrs.encode()))

    def mkdir(self, path: bytes, attrs: Attrs) -> None:
        """``SSH_FXP_MKDIR``; an existing path is usually a bare ``FAILURE`` (see the plugin)."""
        self.status(self.request(fx.MKDIR, string(path), attrs.encode()))

    def rmdir(self, path: bytes) -> None:
        """``SSH_FXP_RMDIR``; v3 has no ``DIR_NOT_EMPTY``, so that is ``FAILURE`` too."""
        self.status(self.request(fx.RMDIR, string(path)))

    def remove(self, path: bytes) -> None:
        """``SSH_FXP_REMOVE`` of a file (a directory is refused, as ``FAILURE`` by OpenSSH)."""
        self.status(self.request(fx.REMOVE, string(path)))

    def rename(self, old: bytes, new: bytes) -> None:
        """POSIX ``rename`` (overwrites) when the server offers it; plain v3 rename otherwise.

        v3's ``SSH_FXP_RENAME`` fails if ``new`` exists; OpenSSH's
        ``posix-rename@openssh.com`` (``string old, string new``) is
        :func:`rename(2) <os.rename>`, atomically replacing it.
        """
        if "posix-rename@openssh.com" in self.extensions:
            self.extended("posix-rename@openssh.com", string(old) + string(new))
        else:
            self.status(self.request(fx.RENAME, string(old), string(new)))

    def readlink(self, path: bytes) -> str:
        """``SSH_FXP_READLINK``: the target, from a one-entry ``NAME`` (``EPROTO`` if empty)."""
        names = self._names(self.request(fx.READLINK, string(path)))
        if not names:
            raise GError("SFTP protocol error: empty READLINK reply", errno.EPROTO)
        return names[0][0]

    def symlink(self, target: bytes, link: bytes) -> None:
        """``SSH_FXP_SYMLINK``: make ``link`` point at ``target``."""
        # OpenSSH's sftp-server takes (target, link) - the reverse of the
        # draft - and every other server follows it, so that is the order.
        self.status(self.request(fx.SYMLINK, string(target), string(link)))

    def realpath(self, path: bytes) -> str:
        """``SSH_FXP_REALPATH``: the server's canonical absolute path (``"."`` is the home)."""
        names = self._names(self.request(fx.REALPATH, string(path)))
        if not names:
            raise GError("SFTP protocol error: empty REALPATH reply", errno.EPROTO)
        return names[0][0]

    def open(self, path: bytes, flags: int, attrs: Attrs | None = None) -> bytes:
        """``SSH_FXP_OPEN`` with ``SSH_FXF_*`` ``flags``; the handle, to :meth:`close_handle`.

        ``attrs`` applies only to a file the open creates (its permissions,
        typically); an empty ``ATTRS`` leaves the server's umask to decide.
        """
        return self._handle(
            self.request(fx.OPEN, string(path), uint32(flags), (attrs or Attrs()).encode())
        )

    def opendir(self, path: bytes) -> bytes:
        """``SSH_FXP_OPENDIR``: a directory handle for :meth:`readdir`."""
        return self._handle(self.request(fx.OPENDIR, string(path)))

    def readdir(self, handle: bytes) -> list[tuple[str, str, Attrs]] | None:
        """One batch of entries, or ``None`` at the end of the directory.

        The server chooses the batch size and signals the end with
        ``STATUS EOF``; any other status is raised. OpenSSH includes ``.``
        and ``..``; filtering them is the plugin's business.
        """
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
        """``SSH_FXP_CLOSE``. ``quiet`` swallows any failure, for clean-up paths.

        Clean-up after an error must not replace that error - and on a
        session that has died the close fails with ``ECONNRESET`` anyway.
        Not quiet, a refused close is :class:`StatusError`, which a writer
        must report: the server could not finish the file.
        """
        try:
            self.status(self.request(fx.CLOSE, string(handle)))
        except (StatusError, GError):
            if not quiet:
                raise

    def read(self, handle: bytes, offset: int, size: int) -> bytes:
        """One ``SSH_FXP_READ``; ``b""`` at end of file.

        The request is ``string handle, uint64 offset, uint32 length``. The
        reply may be shorter than ``size`` without being at the end (a server
        caps reads at its own limit), so a short result is not an EOF.
        """
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
        """An ``SSH_FXP_EXTENDED`` request; a ``STATUS`` reply is checked.

        Some extensions answer ``STATUS`` (``posix-rename``, ``fsync``,
        ``hardlink``), others ``EXTENDED_REPLY`` with data; both come back
        as ``(type, body)`` once a non-``OK`` status has been raised. A
        server without the extension answers ``OP_UNSUPPORTED`` (``ENOSYS``).
        """
        response = self.request(fx.EXTENDED, string(name), payload)
        if response[0] == fx.STATUS:
            self.status(response)
        return response

    def fsync(self, handle: bytes) -> None:
        """``fsync@openssh.com`` (``string handle``) if offered; a no-op otherwise.

        An upload asks for it before closing, so "the copy succeeded" means
        the data reached the server's disk, as far as the server can say.
        """
        if "fsync@openssh.com" in self.extensions:
            self.extended("fsync@openssh.com", string(handle))

    def hardlink(self, old: bytes, new: bytes) -> None:
        """``hardlink@openssh.com``: ``link(2)`` ``new`` to ``old``.

        Sent whether or not it was advertised; a server without it answers
        ``OP_UNSUPPORTED``. The plugin does not use it (gfal2 has no hard
        link operation); it is here for completeness of the extension set.
        """
        self.extended("hardlink@openssh.com", string(old) + string(new))

    def statvfs(self, path: bytes) -> dict[str, int]:
        """``statvfs@openssh.com``: the server's :func:`os.statvfs` of ``path``.

        The reply is eleven ``uint64``, in ``struct statvfs`` order:
        ``f_bsize``, ``f_frsize``, ``f_blocks``, ``f_bfree``, ``f_bavail``,
        ``f_files``, ``f_ffree``, ``f_favail``, ``f_fsid``, ``f_flag``
        (``0x1`` read-only, ``0x2`` nosuid) and ``f_namemax``; keyed without
        the ``f_`` prefix. Not wired to a gfal2 operation; tests use it.
        """
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
        """``check-file-name``: ``(algorithm used, hash)`` over a range (0 = whole file).

        From the later filexfer drafts' extensions, offered by ProFTPD and
        some appliances (never by OpenSSH). The request is ``string path``,
        ``string`` comma-separated algorithm preference list, ``uint64
        offset``, ``uint64 length`` and ``uint32 block size``, sent as 0 for
        one hash over the whole range. The reply is read as ``string
        algorithm`` followed by the raw digest. A server that knows none of
        the algorithms answers a ``STATUS`` (raised as :class:`StatusError`).
        """
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

        Each read is a ``chunk``-sized slice of ``view`` registered as its
        sink, so data lands in place, in whatever order it arrives. ``EOF``
        on a read lowers the end to that read's start; reads beyond it are
        still collected and the result is the lowest end seen. On any
        failure the reads still in flight are forgotten before the error
        propagates, so ``view`` is the caller's again when this returns.
        A ``STATUS OK`` in answer to a read is ``EPROTO``.
        """
        return _Scatter(self, handle, offset, view, chunk or self.max_read, depth).run()

    def stream_read(
        self,
        handle: bytes,
        offset: int,
        length: int | None,
        consume: Callable[[int, memoryview], None],
        options: StreamOptions = _DEFAULT_STREAM,
    ) -> int:
        """Read ``length`` bytes (to EOF if ``None``) and hand each chunk to ``consume`` in order.

        ``depth`` reads stay in flight the whole time, each into its own
        buffer from a small pool, so the link never idles while ``consume``
        writes the previous chunk to disk. Returns the bytes delivered.

        ``consume(file offset, view)`` is called in strictly increasing
        offset order, with no gaps: replies are taken in the order the reads
        were sent, and a short reply is completed (synchronously, with
        :meth:`read_into`) before anything later is delivered. The view is
        only valid during the call - its buffer is reused for a later read -
        so ``consume`` must copy or write it out before returning. Whatever
        ``consume`` or ``options.check`` raises ends the stream: the reads
        in flight are forgotten and the exception propagates. A read error
        is :class:`StatusError`; ``EOF`` (as a status, or a short read that
        cannot be completed) ends the stream normally.
        """
        return _Stream(self, handle, offset, length, consume, options).run()


def _expect_eof(client: SFTPClient, response: tuple[int, Any]) -> None:
    """A ``READ`` answered with ``STATUS``: return on ``EOF``, raise anything else.

    A refusal is its :class:`StatusError`; ``OK``, which a read cannot
    mean, is ``EPROTO``.
    """
    try:
        client.status(response)
    except StatusError as exc:
        if exc.code != fx.FX_EOF:
            raise
        return
    raise GError("SFTP protocol error: READ answered with OK", errno.EPROTO)


class _Scatter:
    """One :meth:`SFTPClient.read_into`: reads into slices of one view, in any order."""

    def __init__(
        self,
        client: SFTPClient,
        handle: bytes,
        offset: int,
        view: memoryview,
        chunk: int,
        depth: int,
    ) -> None:
        """Plan reads of ``chunk`` bytes over ``view``, at most ``depth`` in flight."""
        self.client = client
        self.handle = handle
        self.offset = offset
        self.view = view
        self.chunk = chunk
        self.depth = depth
        #: The lowest end seen: ``len(view)`` until a read meets ``EOF``.
        self.eof = len(view)
        self.pending: deque[tuple[int, int, int]] = deque()  # rid, start, size
        #: Remainders of short reads, re-asked for before anything new.
        self.todo: deque[tuple[int, int]] = deque()
        self.position = 0

    def run(self) -> int:
        """Keep the pipeline full until every read is answered; the bytes read.

        On any failure the reads still in flight are forgotten before the
        error propagates, so the view is the caller's again.
        """
        try:
            while True:
                self._refill()
                if not self.pending:
                    return self.eof
                self._take()
        finally:
            if self.pending:
                self.client.forget([rid for rid, _, _ in self.pending])

    def _next(self) -> tuple[int, int] | None:
        """The next ``(start, size)`` to ask for: a remainder first, then new ground."""
        if self.todo:
            return self.todo.popleft()
        if self.position < self.eof:
            start, size = self.position, min(self.chunk, self.eof - self.position)
            self.position += size
            return start, size
        return None

    def _refill(self) -> None:
        """Send reads until ``depth`` are in flight or there is nothing left to ask."""
        while len(self.pending) < self.depth:
            planned = self._next()
            if planned is None:
                return
            start, size = planned
            rid = self.client.send(
                fx.READ,
                string(self.handle),
                struct.pack(">QI", self.offset + start, size),
                sink=self.view[start : start + size],
            )
            self.pending.append((rid, start, size))

    def _take(self) -> None:
        """Collect the oldest read: a short one leaves a remainder, ``EOF`` lowers the end."""
        rid, start, size = self.pending.popleft()
        response = self.client.wait(rid)
        if response[0] == fx.DATA:
            got = int(response[1])
            if got < size and start + got < self.eof:
                self.todo.append((start + got, size - got))
            return
        _expect_eof(self.client, response)
        # Nothing waits in ``todo`` here: every refill drains it.
        self.eof = min(self.eof, start)


class _Stream:
    """One :meth:`SFTPClient.stream_read`: reads in flight, delivered strictly in order."""

    def __init__(
        self,
        client: SFTPClient,
        handle: bytes,
        offset: int,
        length: int | None,
        consume: Callable[[int, memoryview], None],
        options: StreamOptions,
    ) -> None:
        """Plan the reads from ``offset`` (to EOF if ``length`` is None); nothing is sent."""
        self.client = client
        self.handle = handle
        self.handle_string = string(handle)
        self.consume = consume
        self.check = options.check
        self.chunk = options.chunk or client.max_read
        self.depth = options.depth
        self.end = None if length is None else offset + length
        #: Buffers whose chunk has been consumed, ready for the next read.
        self.free: list[bytearray] = []
        self.pending: deque[tuple[int, int, int, bytearray]] = deque()  # rid, offset, size, buffer
        self.position = offset
        self.delivered = 0
        self.at_eof = False
        #: Refill the pipeline a batch at a time: one write for several reads.
        self.batch = max(1, min(8, self.depth // 4))

    def run(self) -> int:
        """Stream until the end or ``EOF``; the bytes delivered.

        Whatever ``consume`` or ``check`` raises ends the stream: the reads in
        flight are forgotten and the exception propagates.
        """
        try:
            while True:
                if len(self.pending) <= self.depth - self.batch:
                    self._refill()
                if not self.pending:
                    return self.delivered
                self._take()
        finally:
            if self.pending:
                self.client.forget([item[0] for item in self.pending])

    def _refill(self) -> None:
        """Send one batch of reads, each into a pooled buffer, in a single write."""
        requests: list[tuple[int, tuple[Buffer, ...], memoryview | None]] = []
        slots: list[tuple[int, int, bytearray]] = []
        while (
            not self.at_eof
            and len(self.pending) + len(slots) < self.depth
            and (self.end is None or self.position < self.end)
        ):
            size = self.chunk if self.end is None else min(self.chunk, self.end - self.position)
            buffer = self.free.pop() if self.free else bytearray(self.chunk)
            requests.append(
                (
                    fx.READ,
                    (self.handle_string, struct.pack(">QI", self.position, size)),
                    memoryview(buffer)[:size],
                )
            )
            slots.append((self.position, size, buffer))
            self.position += size
        if requests:
            for rid, slot in zip(self.client.send_many(requests), slots, strict=False):
                self.pending.append((rid, *slot))

    def _take(self) -> None:
        """Collect the oldest read and deliver it, or end the stream at ``EOF``."""
        rid, start, size, buffer = self.pending.popleft()
        response = self.client.wait(rid)
        if response[0] != fx.DATA:
            _expect_eof(self.client, response)
            self._ended()
            return
        got = int(response[1])
        self.consume(start, memoryview(buffer)[:got])
        self.delivered += got
        if got < size:
            self._complete(start + got, size - got, buffer)
        self.free.append(buffer)
        if self.check is not None:
            self.check()

    def _complete(self, start: int, missing: int, buffer: bytearray) -> None:
        """A short reply: re-read the rest synchronously, before anything later is delivered."""
        rest = self.client.read_into(self.handle, start, memoryview(buffer)[:missing])
        if rest:
            self.consume(start, memoryview(buffer)[:rest])
            self.delivered += rest
        if rest < missing:
            # The file ended inside this chunk: everything in flight is past the end.
            self._ended()

    def _ended(self) -> None:
        """``EOF``: forget every read in flight (they are past it) and stop asking."""
        self.at_eof = True
        self.client.forget([item[0] for item in self.pending])
        self.pending.clear()


class WriteBehind:
    """Pipelined writes to one handle: sent at once, acknowledged later.

    :meth:`write` returns as soon as the request is on the wire; up to
    ``depth`` acknowledgements may be outstanding. A failure is raised by
    the next :meth:`write` or by :meth:`flush` - which is why a file opened
    for writing reports errors on ``close()``, as the contract says.

    Each ``SSH_FXP_WRITE`` is ``string handle, uint64 offset, string data``,
    at most ``chunk`` bytes of data (the server's ``max_write``). The first
    failure is sticky: the outstanding writes are forgotten (their outcome
    no longer matters - the file is already wrong) and every later call
    raises the same exception. Not thread-safe: one writer per handle.
    """

    def __init__(
        self, client: SFTPClient, handle: bytes, *, chunk: int = 0, depth: int = 64
    ) -> None:
        """Pipeline writes to ``handle``; ``chunk`` 0 means the server's ``max_write``."""
        self.client = client
        self.handle = handle
        self.chunk = chunk or client.max_write
        self.depth = max(1, depth)
        self._pending: deque[int] = deque()  # request ids, oldest first
        self._error: BaseException | None = None
        self._handle_string = string(handle)

    def write(self, offset: int, data: Buffer) -> None:
        """Queue ``data`` at ``offset``, split into ``chunk``-sized writes.

        Blocks only when ``depth`` writes are unacknowledged, settling the
        oldest. ``data`` is sent before this returns, so the caller may
        reuse its buffer. Raises an earlier write's failure, or one found
        while settling (:class:`StatusError` for a refusal - to OpenSSH a
        full disk is a bare ``FAILURE`` - :class:`GError` for a broken session).
        """
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
        """Wait for the oldest acknowledgement; on failure, record it and drop the rest."""
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
