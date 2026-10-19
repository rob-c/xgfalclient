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

Threading: a :class:`Control` belongs to one thread at a time - the pool in
:mod:`._base` lends it out whole. The only cross-thread touch is
:meth:`~._base._Session.abort` shutting the socket down under a blocked
reader for ``cancel()``, which surfaces here as ``ECONNRESET`` and marks the
session broken.

Failure contract: every error leaves as :class:`~xgfalclient.errors.GError`.
Anything that might leave the command/reply stream out of step (a timeout, a
malformed or unwrappable reply, a lost connection) sets :attr:`Control.broken`,
and a broken session is closed rather than pooled. A server's refusal (``4xx``
or ``5xx`` outside the caller's ``ok``) is :func:`~.protocol.reply_error` and
leaves the session usable.
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
from collections.abc import Callable

from xrdsec.gsi.gss import GSIError, SecurityContext

from ...crypto.x509 import Credential
from ...errors import GError
from .gsi import GlobusContext
from .protocol import Reply, check_path, reply_error

__all__ = ["MAX_LINE", "Control", "connect_error"]

_log = logging.getLogger("gfal2")

#: A reply line longer than this is not an FTP server talking.
MAX_LINE = 1 << 20
#: RFC 2228 §4's protected replies: ``631`` integrity-only (``MIC``), ``632``
#: integrity and confidentiality (``ENC``), ``633`` confidentiality-only
#: (``CONF``). globus answers ``ENC`` with ``632``; all three unwrap the same
#: way, since the GSI token itself says how it was protected.
_WRAPPED = ("631", "632", "633")


def connect_error(exc: OSError, host: str, port: int) -> GError:
    """A failed ``connect`` in globus_xio's words, with a faithful ``errno``.

    A timeout is ``ETIMEDOUT`` and a name that does not resolve
    ``EHOSTUNREACH`` (what gfal2 reports for both); any other ``OSError``
    keeps its own ``errno``, defaulting to ``ECONNREFUSED``. Shared by the
    control and data channels so their messages read alike.
    """
    if isinstance(exc, TimeoutError):
        code = errno.ETIMEDOUT
    elif isinstance(exc, socket.gaierror):
        code = errno.EHOSTUNREACH
    else:
        code = exc.errno or errno.ECONNREFUSED
    reason = exc.strerror or str(exc) or os.strerror(code)
    return GError(f"globus_xio: Unable to connect to {host}:{port} {reason}", code)


class Control:
    """One control connection and what has been negotiated on it.

    The life of one is: :meth:`connect` (the ``220`` greeting), optionally
    :meth:`authenticate`, :meth:`login` (which also reads ``FEAT``), then
    any number of :meth:`command`\\ s, and :meth:`close`. Settings that stick
    to a session (``TYPE``, ``MODE``, ``DCAU``, ``OPTS RETR``...) go through
    :meth:`setting`, which remembers them so a pooled session is not sent
    the same ``MODE E`` twice.
    """

    def __init__(self, host: str, port: int, *, timeout: float) -> None:
        """Remember where to connect; no I/O until :meth:`connect`.

        ``timeout`` (seconds) bounds the TCP connect and each wait for a
        reply; callers may change :attr:`timeout` between commands (the
        checksum code raises it for a slow ``CKSM``).
        """
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
        #: Called with every complete reply, when set (gfal2's PASV plugin).
        self.observer: Callable[[Reply], None] | None = None
        #: Received bytes not yet split into lines.
        self._buffer = bytearray()
        #: Lines split off but not yet consumed (several arrive at once when
        #: one ``632`` token unwraps to a whole multi-line reply).
        self._lines: collections.deque[str] = collections.deque()
        #: Lines of a multi-line reply still waiting for its last line. Kept
        #: on the object so a :meth:`poll` that times out mid-reply loses
        #: nothing.
        self._partial: list[str] = []

    # -- connection ----------------------------------------------------------------

    def connect(self) -> Reply:
        """Open the TCP connection and read the server's greeting.

        Nagle is turned off: the control channel is strict request/reply
        with small lines, and a delayed ACK would add up to 200 ms per
        command. A greeting other than ``2xx`` (``421`` busy, ``120`` "ready
        in n minutes" is not waited for) fails as the server put it.
        """
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
        """Whether the control connection runs over IPv6 (so data must use ``EPSV``/``EPRT``)."""
        assert self.sock is not None
        return self.sock.family == socket.AF_INET6

    def close(self) -> None:
        """``QUIT`` politely when the session is healthy, then hang up.

        At most two seconds are spent waiting for ``221``: a pool closing
        many sessions at exit must not stall on a slow server. Idempotent;
        afterwards the object is broken for good.
        """
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
        """One CRLF-terminated line off the socket, or ``None`` if ``wait`` runs out.

        Reads in 64 KiB chunks and keeps the surplus in :attr:`_buffer`, so a
        timeout never splits a line. Bytes are decoded as UTF-8 with
        replacement (RFC 2640 makes paths UTF-8; anything else should not
        break the session). :data:`MAX_LINE` bounds memory against a peer
        that never sends a newline.
        """
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
            # A zero timeout would make the socket non-blocking rather than
            # wait briefly, so the remaining time is floored at 1 ms.
            self.sock.settimeout(max(deadline - time.monotonic(), 0.001))
            try:
                chunk = self.sock.recv(65536)
            except TimeoutError:
                return None
            except OSError as exc:
                self.broken = True
                raise GError(f"Connection to the server lost: {exc}", errno.ECONNRESET) from exc
            if not chunk:
                self.broken = True
                raise GError("Connection closed by the server", errno.ECONNRESET)
            self._buffer += chunk

    def _line(self, wait: float) -> str | None:
        """The next reply line in the clear; ``None`` if ``wait`` runs out.

        On a GSI session a ``631``/``632``/``633`` line carries a base64
        token whose plaintext is one or more complete lines of the real
        reply, CRLFs included (RFC 2228 §4); they are queued in
        :attr:`_lines`. Lines without the envelope pass through: a server
        may answer in the clear even once the session is protected.
        """
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
            # RFC 959 §4.2: ``ddd-`` opens a multi-line reply, which ends at
            # the first line starting with the same code and a space; lines in
            # between may start with anything (FEAT's do with a space).
            single = len(self._partial) == 1 and line[3:4] != "-"
            if single or (len(self._partial) > 1 and line[:3] == code and line[3:4] == " "):
                reply = Reply(int(code), self._partial)
                self._partial = []
                _log.debug("< %s", reply.lines)
                if self.observer is not None:
                    self.observer(reply)
                return reply

    def reply(self) -> Reply:
        """The next reply; ``ETIMEDOUT`` after the session timeout."""
        found = self._take(self.timeout)
        if found is None:
            self.broken = True
            raise GError(f"Operation timeout of {self.timeout:g} seconds expired", errno.ETIMEDOUT)
        return found

    def poll(self, wait: float) -> Reply | None:
        """A reply if one completes within ``wait`` seconds, else ``None``.

        Unlike :meth:`reply`, running out of time is not an error and the
        session stays in step; the transfer loops use this to interleave
        markers with cancellation and watchdog checks.
        """
        return self._take(wait)

    # -- commands --------------------------------------------------------------------

    def send(self, command: str) -> None:
        """Send one command line without waiting for its reply.

        Used directly when the reply must be read in pieces (a transfer's
        ``150``, markers and ``226``); otherwise :meth:`command`. The line is
        checked for CR/LF injection, logged with any password masked, and on
        a GSI session sent as ``ENC <base64 token>`` (RFC 2228 §3). Paths are
        encoded with ``surrogateescape`` so a non-UTF-8 name read off a
        listing goes back out byte for byte.
        """
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
        """``verb value`` unless the session is already set that way.

        The cache is only updated after a ``2xx`` reply, so a refused setting
        is retried next time. Only use it for state that the server keeps
        for the session and that nothing else changes behind its back.
        """
        if self.state.get(verb) != value:
            self.command(f"{verb} {value}")
            self.state[verb] = value

    # -- login -----------------------------------------------------------------------

    def authenticate(self, tls: ssl.SSLContext, delegate: Credential | None) -> None:
        """RFC 2228 ``AUTH GSSAPI``/``ADAT``, delegating ``delegate`` if given.

        ``AUTH GSSAPI`` must be answered ``334`` (go on with ``ADAT``). Each
        ``ADAT`` carries the context's next token; the server answers ``335
        ADAT=<token>`` while it needs more and ``235 [ADAT=<token>]`` when it
        is done (RFC 2228 §3). Both sides must finish on the same round:
        the context complete and nothing left to send, otherwise the
        exchange is out of step. The server's certificate must then name
        :attr:`host` (GSI's ``host/`` or ``ftp/`` CN forms allowed). Any
        failure is ``EACCES`` and breaks the session; from success on, every
        command and reply is wrapped by :attr:`security`.
        """
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
        """``USER``/``PASS`` (RFC 959 §4.1.1), then read ``FEAT`` (RFC 2389).

        ``PASS`` is sent only when ``USER`` asks for it with ``331``; GSI
        servers that map the certificate may log in on ``USER`` alone. The
        ``FEAT`` lines between ``211-`` and ``211 End`` become
        :attr:`features` (``MLST``, ``ERET``, ``GETPUT``, ``PASV
        AllowDelayed``...); a server without ``FEAT`` (``5xx``) simply
        advertises nothing, and every optional feature is then avoided.
        """
        reply = self.command(f"USER {user}", ok=(2, 3))
        if reply.kind == 3:
            self.command(f"PASS {password}")
        found = self.command("FEAT", ok=(2, 4, 5))
        if found.kind == 2:
            for line in found.lines[1:-1]:
                keyword, _, rest = line.strip().partition(" ")
                self.features[keyword.upper()] = rest.strip()

    def supports(self, feature: str) -> bool:
        """Whether ``FEAT`` advertised ``feature`` (an upper-case keyword)."""
        return feature in self.features
