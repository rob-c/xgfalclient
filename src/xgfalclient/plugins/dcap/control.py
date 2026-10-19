"""The control line to a dcap door, and a pool of them per door.

libdcap keeps one control connection per door for the whole process and
multiplexes every request over it by session number. Here each request (and
each open file, for its whole life) takes a connection of its own from a
small per-door pool instead: the door does not mind how many connections a
client opens, and a connection that belongs to one caller at a time needs no
reply demultiplexing and no lock around the socket. Session numbers still
increase per connection, and a reply for another session - a late ``ok``
for a file that was abandoned - is skipped, as libdcap skips it.

A pooled connection may have been closed by the door while idle. A request
that fails on a reused connection before a single byte of reply arrived is
retried once on a fresh one (libdcap does the same with its ``ping``).
"""

from __future__ import annotations

import base64
import binascii
import errno
import functools
import logging
import os
import select
import socket
import threading
import time
from collections.abc import Callable
from typing import Any, TypeVar

from ...errors import GError
from ...plugin import shutdown_sockets
from .protocol import VERSION, DcapURL, Reply, parse_reply
from .tunnel import TokenLink, Tunnel

__all__ = ["GID", "MAX_IDLE", "UID", "ControlConnection", "Door", "socket_error"]

_log = logging.getLogger("gfal2")

#: Identity libdcap reports in ``hello`` and on every request (``-uid=``).
UID: int = getattr(os, "getuid", lambda: 0)()
GID: int = getattr(os, "getgid", lambda: 0)()

#: Idle control connections kept per door.
MAX_IDLE = 4

#: How much one ``recv`` asks for; control lines are short, a GSI token a few KiB.
_RECV = 65536

#: How a connection the door closed while it sat in the pool fails.
_STALE = frozenset({errno.ECONNRESET, errno.EPIPE, errno.ECONNABORTED, errno.ENOTCONN})

#: What an exchange run by :meth:`Door.call` returns.
T = TypeVar("T")


def socket_error(exc: BaseException, what: str) -> GError:
    """A ``GError`` for a failed socket call, keeping its ``errno``.

    ``what`` says which connection failed. A timeout is ``ETIMEDOUT``, a
    name that does not resolve ``EHOSTUNREACH``, and an ``OSError`` without
    an ``errno`` ``EIO``. The caller chains the original exception.
    """
    if isinstance(exc, TimeoutError):
        return GError(f"{what}: timed out", errno.ETIMEDOUT)
    if isinstance(exc, socket.gaierror):
        # Its errno is a getaddrinfo EAI_* code (-2, or 8 on macOS), not an errno.
        return GError(f"{what}: {exc}", errno.EHOSTUNREACH)
    code = getattr(exc, "errno", None) or errno.EIO
    return GError(f"{what}: {exc}", code)


class ControlConnection(TokenLink):
    """One authenticated control connection: lines in, lines out.

    Bytes from the socket go through two buffers: ``_wire`` holds what was
    received, and ``_text`` the plaintext lines - the same bytes on a plain
    connection, the unwrapped ``enc`` tokens through a tunnel. Not
    thread-safe; a :class:`Door` hands each connection to one caller at a
    time. It owns its socket and its tunnel's security context, and
    :meth:`close` releases both.
    """

    def __init__(self, sock: socket.socket, peer: str) -> None:
        """Wrap a connected ``sock``; ``peer`` (``host:port``) names it in messages."""
        self.sock = sock
        self.peer = peer
        self.tunnel: Tunnel | None = None
        #: Bytes read from the socket and not yet unframed.
        self._wire = bytearray()
        #: Plaintext not yet split into lines.
        self._text = bytearray()
        #: The last session number this connection used; ``hello`` is session 0.
        self._session = 0
        #: Bytes received so far; a stale pooled connection receives none.
        self.received = 0
        #: True once the connection has served a request and gone back to the pool.
        self.reused = False
        self.closed = False

    @classmethod
    def open(cls, url: DcapURL, tunnel: Tunnel | None, timeout: float) -> ControlConnection:
        """Connect, authenticate through ``tunnel`` if any, and say hello.

        A connection failure keeps the socket's ``errno`` (see
        :func:`socket_error`); a failed handshake raises the tunnel's error
        and a refused ``hello`` is ``EIO``. Whatever fails, the socket is
        closed before the error propagates.
        """
        peer = f"{url.netloc}:{url.port}"
        try:
            sock = socket.create_connection((url.host, url.port), timeout=timeout)
        except OSError as exc:  # socket.timeout is an OSError too
            raise socket_error(exc, f"Cannot connect to the dcap door {peer}") from exc
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn = cls(sock, peer)
        try:
            if tunnel is not None:
                tunnel.handshake(conn, url.host)
                conn.tunnel = tunnel
            conn.hello()
        except BaseException:
            conn.close()
            raise
        return conn

    # -- framing ------------------------------------------------------------------

    def send_token(self, token: bytes) -> None:
        """One GSS token as an ``enc <base64>`` line (the tunnel framing)."""
        self._send(b"enc " + base64.b64encode(token) + b"\n")

    def read_token(self) -> bytes:
        """The next ``enc <base64>`` line's token, blocking until it is whole."""
        while b"\n" not in self._wire:
            self.feed()
        return self._take_token()

    def _take_token(self) -> bytes:
        """Take one buffered token line off ``_wire``; ``EPROTO`` if it is not one.

        A tunnelled door sends nothing but ``enc`` lines, so anything else
        (a plaintext error, say) means the two ends disagree about the tunnel.
        """
        end = self._wire.index(b"\n")
        line = bytes(self._wire[:end]).rstrip(b"\r")
        del self._wire[: end + 1]
        if not line.startswith(b"enc "):
            raise GError(f"The dcap door {self.peer} broke the tunnel framing", errno.EPROTO)
        try:
            return base64.b64decode(line[4:], validate=True)
        except binascii.Error as exc:
            raise GError(f"Bad token from the dcap door {self.peer}: {exc}", errno.EPROTO) from exc

    def _send(self, data: bytes) -> None:
        """Send ``data`` whole, as it is (already wrapped if there is a tunnel)."""
        try:
            self.sock.sendall(data)
        except OSError as exc:  # socket.timeout is an OSError too
            raise socket_error(exc, f"Lost the control connection to {self.peer}") from exc

    def feed(self) -> None:
        """Read what the socket has (blocking until something arrives).

        The door hanging up is ``ECONNRESET``, which (with nothing received)
        is what tells :meth:`Door.call` that a pooled connection went stale.
        """
        try:
            data = self.sock.recv(_RECV)
        except OSError as exc:  # socket.timeout is an OSError too
            raise socket_error(exc, f"Lost the control connection to {self.peer}") from exc
        if not data:
            raise GError(f"The dcap door {self.peer} closed the connection", errno.ECONNRESET)
        self.received += len(data)
        self._wire += data

    # -- lines --------------------------------------------------------------------

    def send_line(self, line: str) -> None:
        """Send one control line; ``\\n`` is added, and a tunnel wraps it."""
        _log.debug("dcap %s <- %s", self.peer, line)
        data = (line + "\n").encode("utf-8", "surrogateescape")
        if self.tunnel is not None:
            self.send_token(self.tunnel.wrap(data))
        else:
            self._send(data)

    def has_line(self) -> bool:
        """Whether a whole line is already buffered (so reading it will not block)."""
        if self.tunnel is None:
            self._text += self._wire
            self._wire.clear()
        else:
            while b"\n" in self._wire:
                self._text += self.tunnel.unwrap(self._take_token())
        return b"\n" in self._text

    def read_line(self) -> str:
        """The next control line, without its line end; blocks until one is whole.

        Bytes that are not UTF-8 are replaced: replies are parsed for
        numbers and verbs, and a door's message text is only reported.
        """
        while not self.has_line():
            self.feed()
        end = self._text.index(b"\n")
        line = bytes(self._text[:end]).rstrip(b"\r").decode("utf-8", "replace")
        del self._text[: end + 1]
        _log.debug("dcap %s -> %s", self.peer, line)
        return line

    def reply_for(self, line: str, session: int) -> Reply | None:
        """``line`` parsed, if it answers ``session``; other lines are dropped."""
        reply = parse_reply(line)
        if reply is None or reply.session != session:
            return None
        return reply

    def wait(self, session: int) -> Reply:
        """The door's next answer for ``session``."""
        while True:
            reply = self.reply_for(self.read_line(), session)
            if reply is not None:
                return reply

    def next_session(self) -> int:
        """A fresh session number for the next request on this connection."""
        self._session += 1
        return self._session

    # -- the conversation -----------------------------------------------------------

    def hello(self) -> None:
        """``hello``, as libdcap sends it; anything but ``welcome`` is ``EIO``.

        The fields are libdcap's: session and command 0, two zeroes, the
        protocol and library version (:data:`VERSION`), an empty quoted
        argument and the client's uid, pid and gid.
        """
        pid = os.getpid()
        major, minor, bug = VERSION
        self.send_line(
            f'0 0 client hello 0 0 {major} {minor} {bug} "" -uid={UID} -pid={pid} -gid={GID}'
        )
        try:
            reply = self.wait(0)
        except GError as exc:
            raise GError(f'The dcap door {self.peer} rejected "hello": {exc}', errno.EIO) from exc
        if reply.verb != "welcome":
            raise GError(
                f'The dcap door {self.peer} rejected "hello": {reply.verb} {" ".join(reply.args)}',
                errno.EIO,
            )

    def select(self, others: list[socket.socket], deadline: float) -> list[socket.socket]:
        """Wait until the control line has a whole line or one of ``others`` is readable.

        Returns the readable ``others`` (never the control socket), or ``[]``
        when a line is ready. Bytes that arrive on the control socket are
        buffered, not lost, while waiting. ``ETIMEDOUT`` once ``deadline``
        (a :func:`time.monotonic` value) has passed.
        """
        while not self.has_line():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GError(f"Timed out waiting for the dcap door {self.peer}", errno.ETIMEDOUT)
            readable, _, _ = select.select([self.sock, *others], [], [], remaining)
            ready = [sock for sock in others if sock in readable]
            if ready:
                return ready
            if self.sock in readable:
                self.feed()
        return []

    def close(self) -> None:
        """Close the socket and release the tunnel; safe to call again."""
        if not self.closed:
            self.closed = True
            self.sock.close()
            if self.tunnel is not None:
                self.tunnel.close()


class Door:
    """The control connections to one door, for one set of credentials.

    With a ``context``, whatever an exchange or an open file is blocked on
    is registered with it (:meth:`register`), so that its ``cancel()`` shuts
    those sockets down and the blocked call fails at once.

    The idle list is guarded by a lock; connecting happens outside it, so a
    slow door does not hold up callers that find an idle connection.
    """

    def __init__(
        self, url: DcapURL, connect: Callable[[], ControlConnection], context: Any = None
    ) -> None:
        """A pool for ``url``'s door; ``connect`` opens (and authenticates) a new connection."""
        self.url = url
        self._connect = connect
        self._context = context
        self._idle: list[ControlConnection] = []
        self._lock = threading.Lock()
        #: Set by :meth:`close`; from then on a released connection is closed, never pooled.
        self._closed = False

    def register(self, *sockets: socket.socket) -> int:
        """Have the context's ``cancel()`` shut ``sockets`` down; the token, or 0 without one."""
        if self._context is None:
            return 0
        return int(self._context.register_abort(functools.partial(shutdown_sockets, *sockets)))

    def unregister(self, token: int) -> None:
        """Undo :meth:`register` (a token of 0 is a no-op without a context)."""
        if self._context is not None:
            self._context.unregister_abort(token)

    def acquire(self) -> ControlConnection:
        """The most recently idle connection, or a new one; the caller owns it now."""
        with self._lock:
            if self._idle:
                return self._idle.pop()
        return self._connect()

    def release(self, conn: ControlConnection, *, reusable: bool = True) -> None:
        """Return ``conn`` to the pool, or close it if it is suspect, the pool full or closed.

        A door that has been closed keeps nothing: its plugin dropped it, so
        a connection parked here would never be closed by anyone.
        """
        if reusable and not conn.closed:
            conn.reused = True
            with self._lock:
                if not self._closed and len(self._idle) < MAX_IDLE:
                    self._idle.append(conn)
                    return
        conn.close()

    def call(self, exchange: Callable[[ControlConnection, int], T], *, keep: bool = False) -> T:
        """Run ``exchange(connection, session)`` on a pooled connection.

        The connection goes back to the pool afterwards unless ``keep`` (an
        open file holds on to its connection until it is closed). A reused
        connection that fails before the door answered at all was closed by
        the door while it sat in the pool; the exchange runs again on another.
        """
        while True:
            conn = self.acquire()
            before = conn.received
            token = 0
            try:
                token = self.register(conn.sock)
                result = exchange(conn, conn.next_session())
            except GError as exc:
                conn.close()
                if conn.reused and conn.received == before and exc.code in _STALE:
                    continue
                raise
            except BaseException:
                conn.close()
                raise
            finally:
                self.unregister(token)
            if not keep:
                self.release(conn)
            return result

    def close(self) -> None:
        """Close the idle connections, and every connection released from now on.

        One still lent out (an open file's) is not touched: the file goes on
        working, and its connection is closed when the file releases it.
        """
        with self._lock:
            self._closed = True
            idle, self._idle = self._idle, []
        for conn in idle:
            conn.close()
