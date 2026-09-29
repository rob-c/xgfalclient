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
import logging
import os
import select
import socket
import threading
import time
from collections.abc import Callable
from typing import TypeVar

from ..._compat import TIMEOUTS
from ...errors import GError
from .protocol import VERSION, DcapURL, Reply, parse_reply
from .tunnel import TokenLink, Tunnel

__all__ = ["ControlConnection", "Door", "socket_error", "UID", "GID", "MAX_IDLE"]

_log = logging.getLogger("gfal2")

#: Identity libdcap reports in ``hello`` and on every request (``-uid=``).
UID: int = getattr(os, "getuid", lambda: 0)()
GID: int = getattr(os, "getgid", lambda: 0)()

#: Idle control connections kept per door.
MAX_IDLE = 4

_RECV = 65536

#: How a connection the door closed while it sat in the pool fails.
_STALE = frozenset({errno.ECONNRESET, errno.EPIPE, errno.ECONNABORTED, errno.ENOTCONN})

T = TypeVar("T")


def socket_error(exc: BaseException, what: str) -> GError:
    """A ``GError`` for a failed socket call, keeping its ``errno``."""
    if isinstance(exc, TIMEOUTS):
        return GError(f"{what}: timed out", errno.ETIMEDOUT)
    if isinstance(exc, socket.gaierror):
        # Its errno is a getaddrinfo EAI_* code (-2, or 8 on macOS), not an errno.
        return GError(f"{what}: {exc}", errno.EHOSTUNREACH)
    code = getattr(exc, "errno", None) or errno.EIO
    return GError(f"{what}: {exc}", code)


class ControlConnection(TokenLink):
    """One authenticated control connection: lines in, lines out."""

    def __init__(self, sock: socket.socket, peer: str) -> None:
        self.sock = sock
        self.peer = peer
        self.tunnel: Tunnel | None = None
        #: Bytes read from the socket and not yet unframed.
        self._wire = bytearray()
        #: Plaintext not yet split into lines.
        self._text = bytearray()
        self._session = 0
        #: Bytes received so far; a stale pooled connection receives none.
        self.received = 0
        #: True once the connection has served a request and gone back to the pool.
        self.reused = False
        self.closed = False

    @classmethod
    def open(cls, url: DcapURL, tunnel: Tunnel | None, timeout: float) -> ControlConnection:
        """Connect, authenticate through ``tunnel`` if any, and say hello."""
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
        self._send(b"enc " + base64.b64encode(token) + b"\n")

    def read_token(self) -> bytes:
        while b"\n" not in self._wire:
            self.feed()
        return self._take_token()

    def _take_token(self) -> bytes:
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
        try:
            self.sock.sendall(data)
        except OSError as exc:  # socket.timeout is an OSError too
            raise socket_error(exc, f"Lost the control connection to {self.peer}") from exc

    def feed(self) -> None:
        """Read what the socket has (blocking until something arrives)."""
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
        self._session += 1
        return self._session

    # -- the conversation -----------------------------------------------------------

    def hello(self) -> None:
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
        """Wait until the control line has a whole line or one of ``others`` is readable."""
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
        if not self.closed:
            self.closed = True
            self.sock.close()
            if self.tunnel is not None:
                self.tunnel.close()


class Door:
    """The control connections to one door, for one set of credentials."""

    def __init__(self, url: DcapURL, connect: Callable[[], ControlConnection]) -> None:
        self.url = url
        self._connect = connect
        self._idle: list[ControlConnection] = []
        self._lock = threading.Lock()

    def acquire(self) -> ControlConnection:
        with self._lock:
            if self._idle:
                return self._idle.pop()
        return self._connect()

    def release(self, conn: ControlConnection, *, reusable: bool = True) -> None:
        """Return ``conn`` to the pool, or close it if it is suspect or the pool is full."""
        if reusable and not conn.closed:
            conn.reused = True
            with self._lock:
                if len(self._idle) < MAX_IDLE:
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
            try:
                result = exchange(conn, conn.next_session())
            except GError as exc:
                conn.close()
                if conn.reused and conn.received == before and exc.code in _STALE:
                    continue
                raise
            except BaseException:
                conn.close()
                raise
            if not keep:
                self.release(conn)
            return result

    def close(self) -> None:
        with self._lock:
            idle, self._idle = self._idle, []
        for conn in idle:
            conn.close()
