"""The control channel: one logged-in FTP session, cleartext or GSI.

A session is a TCP connection that carries commands one way and replies the
other. :class:`Control` reads replies with its own line buffer rather than a
``makefile``, so a read that times out (the transfer loop polls every few
hundred milliseconds to honour cancellation) leaves no reply half-consumed.

GSI sessions (RFC 2228) authenticate with ``AUTH GSSAPI`` and an ``ADAT``
loop carrying TLS records in base64, delegating a proxy on the way so the
server can open ``DCAU A`` data channels and third-party connections as the
user. From then on every command goes out as ``ENC <base64 wrap token>`` and
every reply comes back as ``632`` lines, each wrapping one line of the real
reply - this is what globus-url-copy and gfal2 send, observed against
globus-gridftp-server 13. The login that follows is globus's
``USER :globus-mapping:`` / ``PASS dummy``: the server maps the certificate,
not the name.
"""

from __future__ import annotations

import base64
import collections
import errno
import logging
import os
import select
import socket
import ssl
import time

from ...crypto.gsi import GSIError, SecurityContext
from ...crypto.x509 import Credential
from ...errors import GError
from .gsi import GlobusContext
from .protocol import Reply, check_path, reply_error

__all__ = ["Control", "connect_error", "MAX_LINE"]

_log = logging.getLogger("xgfalclient.plugins.gridftp")

#: A reply line longer than this is not an FTP server talking.
MAX_LINE = 1 << 20
_WRAPPED = ("631", "632", "633")


def connect_error(exc: OSError, host: str, port: int) -> GError:
    """A failed ``connect`` in globus_xio's words, with a faithful ``errno``."""
    if isinstance(exc, socket.timeout):
        code = errno.ETIMEDOUT
    elif isinstance(exc, socket.gaierror):
        code = errno.EHOSTUNREACH
    else:
        code = exc.errno or errno.ECONNREFUSED
    reason = exc.strerror or str(exc) or os.strerror(code)
    return GError(f"globus_xio: Unable to connect to {host}:{port} {reason}", code)


class Control:
    """One control connection and what has been negotiated on it."""

    def __init__(self, host: str, port: int, *, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.security: SecurityContext | None = None
        #: FEAT keywords (upper case) to the rest of their line.
        self.features: dict[str, str] = {}
        #: The last value set with :meth:`setting`, per verb.
        self.state: dict[str, str] = {}
        #: Set once the session can no longer be trusted to be in step.
        self.broken = False
        self._buffer = bytearray()
        self._lines: collections.deque[str] = collections.deque()
        self._partial: list[str] = []

    # -- connection ----------------------------------------------------------------

    def connect(self) -> Reply:
        try:
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
        except OSError as exc:
            raise connect_error(exc, self.host, self.port) from exc
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        greeting = self.reply()
        if greeting.kind != 2:
            self.broken = True
            raise reply_error(greeting)
        return greeting

    @property
    def peer(self) -> str:
        """The server's numeric address, where data connections default to."""
        assert self.sock is not None
        return str(self.sock.getpeername()[0])

    @property
    def local(self) -> str:
        """Our numeric address on this connection, for ``PORT``."""
        assert self.sock is not None
        return str(self.sock.getsockname()[0])

    @property
    def ipv6(self) -> bool:
        assert self.sock is not None
        return self.sock.family == socket.AF_INET6

    def close(self) -> None:
        """``QUIT`` politely when the session is healthy, then hang up."""
        if self.sock is None:
            return
        if not self.broken:
            try:
                self.send("QUIT")
                self._take(min(self.timeout, 2.0))
            except GError:
                pass
        self.sock.close()
        self.sock = None
        self.broken = True

    def healthy(self) -> bool:
        """Whether an idle session can be reused: in step and not hung up on.

        A server that timed the session out has closed it (or said ``421``),
        which shows as the socket turning readable while nothing is owed.
        """
        if self.broken or self.sock is None or self._partial or self._lines or self._buffer:
            return False
        readable, _, _ = select.select([self.sock], [], [], 0)
        return not readable

    # -- replies ---------------------------------------------------------------------

    def _raw_line(self, wait: float) -> str | None:
        assert self.sock is not None
        deadline = time.monotonic() + wait
        while True:
            index = self._buffer.find(b"\n")
            if index >= 0:
                line = bytes(self._buffer[:index]).rstrip(b"\r")
                del self._buffer[: index + 1]
                return line.decode("utf-8", "replace")
            if len(self._buffer) > MAX_LINE:
                self.broken = True
                raise GError("Reply line too long from the server", errno.EPROTO)
            self.sock.settimeout(max(deadline - time.monotonic(), 0.001))
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                return None
            except OSError as exc:
                self.broken = True
                raise GError(f"Connection to the server lost: {exc}", errno.ECONNRESET) from exc
            if not chunk:
                self.broken = True
                raise GError("Connection closed by the server", errno.ECONNRESET)
            self._buffer += chunk

    def _line(self, wait: float) -> str | None:
        while not self._lines:
            raw = self._raw_line(wait)
            if raw is None:
                return None
            if self.security is not None and raw[:3] in _WRAPPED and raw[3:4] in (" ", "-"):
                try:
                    plain = self.security.unwrap(base64.b64decode(raw[4:].strip()))
                except (ValueError, GSIError) as exc:
                    self.broken = True
                    raise GError(f"Cannot unwrap a protected reply: {exc}", errno.EPROTO) from exc
                self._lines.extend(plain.decode("utf-8", "replace").splitlines())
            else:
                self._lines.append(raw)
        return self._lines.popleft()

    def _take(self, wait: float) -> Reply | None:
        """The next complete reply, or ``None`` if none completes within ``wait``."""
        while True:
            line = self._line(wait)
            if line is None:
                return None
            self._partial.append(line)
            code = self._partial[0][:3]
            if not code.isdigit():
                self.broken = True
                raise GError(f"Malformed reply from the server: {line!r}", errno.EPROTO)
            single = len(self._partial) == 1 and line[3:4] != "-"
            if single or (len(self._partial) > 1 and line[:3] == code and line[3:4] == " "):
                reply = Reply(int(code), self._partial)
                self._partial = []
                _log.debug("< %s", reply.lines)
                return reply

    def reply(self) -> Reply:
        """The next reply; ``ETIMEDOUT`` after the session timeout."""
        found = self._take(self.timeout)
        if found is None:
            self.broken = True
            raise GError(f"Operation timeout of {self.timeout:g} seconds expired", errno.ETIMEDOUT)
        return found

    def poll(self, wait: float) -> Reply | None:
        return self._take(wait)

    # -- commands --------------------------------------------------------------------

    def send(self, command: str) -> None:
        assert self.sock is not None
        check_path(command)
        shown = "PASS ****" if command.startswith("PASS ") else command
        _log.debug("> %s", shown)
        data = (command + "\r\n").encode("utf-8", "surrogateescape")
        if self.security is not None:
            token = base64.b64encode(self.security.wrap(data)).decode("ascii")
            data = f"ENC {token}\r\n".encode("ascii")
        try:
            self.sock.sendall(data)
        except OSError as exc:
            self.broken = True
            raise GError(f"Connection to the server lost: {exc}", errno.ECONNRESET) from exc

    def final(self, ok: tuple[int, ...] = (2,)) -> Reply:
        """The next reply that is not preliminary, which must be of a kind in ``ok``."""
        reply = self.reply()
        while reply.kind == 1:
            reply = self.reply()
        if reply.kind not in ok:
            raise reply_error(reply)
        return reply

    def command(self, command: str, ok: tuple[int, ...] = (2,)) -> Reply:
        """Send ``command``; its final reply, which must be of a kind in ``ok``."""
        self.send(command)
        return self.final(ok)

    def setting(self, verb: str, value: str) -> None:
        """``verb value`` unless the session is already set that way."""
        if self.state.get(verb) != value:
            self.command(f"{verb} {value}")
            self.state[verb] = value

    # -- login -----------------------------------------------------------------------

    def authenticate(self, tls: ssl.SSLContext, delegate: Credential | None) -> None:
        """RFC 2228 ``AUTH GSSAPI``/``ADAT``, delegating ``delegate`` if given."""
        self.command("AUTH GSSAPI", ok=(3,))
        context = GlobusContext(tls, delegate=delegate)
        try:
            token = context.step()
            while True:
                reply = self.command("ADAT " + base64.b64encode(token).decode("ascii"), (2, 3))
                _, _, data = reply.text.partition("ADAT=")
                token = context.step(base64.b64decode(data.strip()))
                if reply.kind == 2:
                    break
                if not token:
                    raise GSIError("the server wants a token the mechanism has not produced")
            if not context.complete or token:
                raise GSIError("the server finished authenticating before the client did")
            context.check_host(self.host)
        except (GSIError, ValueError) as exc:
            self.broken = True
            raise GError(
                f"GSSAPI authentication with {self.host} failed: {exc}", errno.EACCES
            ) from exc
        self.security = context

    def login(self, user: str, password: str) -> None:
        reply = self.command(f"USER {user}", ok=(2, 3))
        if reply.kind == 3:
            self.command(f"PASS {password}")
        found = self.command("FEAT", ok=(2, 4, 5))
        if found.kind == 2:
            for line in found.lines[1:-1]:
                keyword, _, rest = line.strip().partition(" ")
                self.features[keyword.upper()] = rest.strip()

    def supports(self, feature: str) -> bool:
        return feature in self.features
