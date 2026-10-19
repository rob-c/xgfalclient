"""The core of one test GridFTP control connection: state, framing and paths.

:class:`_SessionBase` owns everything a command handler reads or changes -
the login and security state, the transfer settings (``MODE``, ``DCAU``,
``PROT``, parallelism, ``REST``), the data-channel endpoints - and the
control channel itself: reading a line, sending a (possibly GSI-wrapped)
reply, and :meth:`~_SessionBase.handle`, which unwraps a protected command,
applies the server's injected faults and dispatches to a ``do_<VERB>``
method. The verbs themselves live in the mixins beside this module
(:mod:`.commands`, :mod:`.data`, :mod:`.namespace`); :mod:`.session` puts
them together as the session class the server runs.

:meth:`~_SessionBase.close_passive` is here rather than with the rest of the
data channel because :meth:`~_SessionBase.run` must release a passive
listener whatever the session was doing when it ended.

Threading: one session runs on one thread (started by
:meth:`GridFTPServer._serve <xgfalclient.testing.gridftp.GridFTPServer>`),
so session state needs no lock. What it shares with other sessions lives on
the server - ``log``, the fault tables, ``track`` - and the fault tables are
only written by the test, before or between operations. Data transfers
start their own threads (see :mod:`.data`) but the control channel stays on
this one.

To add a verb, define ``do_<VERB>(self, arg)`` on the mixin it belongs to;
raise :class:`~.common._Reply` with the final reply. Add it to
:data:`~.common._OPEN` only if a client may send it before logging in.
"""

from __future__ import annotations

import base64
import errno
import os
import socket
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from xrdsec.gsi.gss import SecurityContext

from ...plugins.gridftp.gsi import GlobusContext
from .common import _GLOBUS_CODES, _OPEN, _Hangup, _Reply

if TYPE_CHECKING:
    from ..gridftp import GridFTPServer


class _SessionBase:
    """One control connection's state and its control channel; the verbs are mixins."""

    def __init__(self, server: GridFTPServer, sock: socket.socket) -> None:
        """Fresh per-connection state, as after the ``220`` greeting.

        ``sock`` is the accepted control socket, already registered with
        :meth:`~xgfalclient.testing.gridftp.GridFTPServer.track`; the session
        owns it and closes it in :meth:`run`.
        """
        self.server = server
        self.sock = sock
        # Bytes received but not yet split into lines.
        self.buffer = bytearray()
        # The established GSI context once ADAT completes: from then on every
        # command arrives wrapped (MIC/ENC/CONF) and every reply goes out wrapped.
        self.security: SecurityContext | None = None
        # The context mid-handshake, between AUTH GSSAPI and the last ADAT.
        self.adat: GlobusContext | None = None
        # The reply code for wrapped replies: RFC 2228 answers at the level the
        # client last used (631 MIC, 632 ENC, 633 CONF); globus clients send ENC.
        self.protection = "632"
        self.user: str | None = None
        self.logged_in = False
        # The client's working directory, as a client-side absolute path.
        self.cwd = "/"
        # Transfer settings, at their RFC 959 / GFD.20 defaults: stream mode,
        # no data-channel authentication, clear data.
        self.mode = "S"
        self.dcau = "N"
        self.prot = "C"
        # Streams to open for a MODE E transfer (OPTS RETR Parallelism=n).
        self.parallelism = 1
        # OPTS PASV AllowDelayed=1 seen: PASV answers "200 Passive delayed".
        self.allow_delayed = False
        # A delayed PASV is pending: the transfer command sends the 127 address.
        self.delayed = False
        # At most one of these is set: a passive listener, or active addresses
        # to connect to (several after SPOR).
        self.passive: socket.socket | None = None
        self.active: list[tuple[str, int]] = []
        # The REST offset for the next RETR/STOR; reset after every transfer.
        self.rest = 0
        # The local path an RNFR named, consumed by the next RNTO.
        self.rename_from: str | None = None
        # A temporary file holding the delegated proxy as PEM, used as
        # this side's credential for DCAU A; deleted when the session ends.
        self.delegated: str | None = None
        # The client's DN as RDN pairs, proxy CNs stripped: what DCAU A
        # requires the data-channel peer to be.
        self.identity: tuple[tuple[str, str], ...] = ()

    # -- the control channel -------------------------------------------------------------

    def run(self) -> None:
        """Greet, then serve commands until the client leaves or the server stops.

        A hang-up, ``QUIT``, a ``close`` fault or any socket error ends the
        session quietly - a test server has no one to report to. Whatever
        ends it, the passive listener, the control socket and the delegated
        proxy file are released here.
        """
        try:
            self.reply(f"220 {self.server.host} GridFTP Server xgfal ready.")
            while True:
                line = self.readline()
                if line is None:
                    return
                self.handle(line)
        except (_Hangup, OSError):
            pass
        finally:
            self.close_passive()
            self.sock.close()
            if self.delegated is not None:
                os.unlink(self.delegated)

    def readline(self) -> str | None:
        """The next command line, without its ``CRLF``; ``None`` at EOF.

        Lines end at ``LF`` with an optional ``CR`` (RFC 959 says ``CRLF``,
        but a bare ``LF`` costs nothing to accept). Bytes that are not UTF-8
        survive as surrogates, so a path round-trips to the file system.
        """
        while b"\n" not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                return None
            self.buffer += chunk
        index = self.buffer.index(b"\n")
        line = bytes(self.buffer[:index]).rstrip(b"\r").decode("utf-8", "surrogateescape")
        del self.buffer[: index + 1]
        return line

    def reply(self, text: str) -> None:
        """Send a reply; once protected, each line is wrapped on its own (``632-``).

        globus-gridftp-server wraps each line of a multi-line reply as its
        own token and sends them as ``632-<token>`` lines ending with one
        ``632 <token>``; clients written against globus unwrap line by line,
        so that is reproduced exactly.
        """
        lines = text.split("\r\n")
        if self.security is None:
            data = "".join(f"{line}\r\n" for line in lines)
        else:
            out = []
            for number, line in enumerate(lines):
                token = self.security.wrap(f"{line}\r\n".encode("utf-8", "surrogateescape"))
                sep = " " if number == len(lines) - 1 else "-"
                out.append(f"{self.protection}{sep}{base64.b64encode(token).decode('ascii')}\r\n")
            data = "".join(out)
        self.sock.sendall(data.encode("utf-8", "surrogateescape"))

    def handle(self, line: str) -> None:
        """Answer one command line: unwrap, log, inject faults, dispatch.

        On a protected session (after ``ADAT``) only ``MIC``/``ENC``/``CONF``
        are accepted - anything in clear gets RFC 2228's ``533`` - and the
        real command is the unwrapped token. The command is then appended to
        the server's ``log`` and the fault tables are consulted, in this
        order: ``delays`` (sleep first), then ``faults``: ``close`` hangs up,
        ``hang`` blocks until the server stops, ``raw:<line>`` sends a line
        as is (unwrapped even on a protected session, to test a client's
        handling of garbage), and anything else is sent as the reply.
        Unknown verbs get ``500`` and verbs outside :data:`~.common._OPEN`
        before login get ``530``. Faults apply before the login check, so a
        test can fail ``USER`` or ``PASS`` themselves.
        """
        verb, _, arg = line.partition(" ")
        verb = verb.upper()
        if self.security is not None:
            level = {"MIC": "631", "ENC": "632", "CONF": "633"}.get(verb)
            if level is None:
                self.reply("533 Command protection level denied for security reasons.")
                return
            self.protection = level
            line = self.security.unwrap(base64.b64decode(arg)).decode("utf-8", "surrogateescape")
            verb, _, arg = line.rstrip("\r\n").partition(" ")
            verb = verb.upper()
        self.server.log.append(f"{verb} {arg}".rstrip())
        time.sleep(self.server.delays.get(verb, 0))
        fault = self.server.faults.get(verb)
        if fault == "close":
            raise _Hangup()
        if fault == "hang":
            self.server._stop.wait()
            raise _Hangup()
        if fault is not None and fault.startswith("raw:"):
            self.sock.sendall(f"{fault[4:]}\r\n".encode())
            return
        try:
            if fault is not None:
                raise _Reply(fault)
            handler: Callable[[str], None] | None = getattr(self, f"do_{verb}", None)
            if handler is None:
                raise _Reply("500 Invalid command.")
            if verb not in _OPEN and not self.logged_in:
                raise _Reply("530 Please login with USER and PASS.")
            handler(arg)
        except _Reply as answer:
            self.reply(answer.text)

    # -- paths -----------------------------------------------------------------------------

    def local(self, path: str) -> str:
        """The file a client path names, confined to the root.

        The path is resolved against :attr:`cwd` and normalised *as a client
        path* before it is joined to the root, so ``..`` cannot climb above
        ``/``. Symbolic links inside the root are followed by the OS as
        usual; confinement is against accidents, not a hostile client.
        """
        joined = os.path.normpath(os.path.join(self.cwd, path or "."))
        return os.path.join(self.server.root, joined.lstrip("/"))

    def failure(self, exc: OSError, operation: str, code: str = "550") -> _Reply:
        """An ``OSError`` as globus words it: the ``GlobusError`` block.

        ``operation`` fills "System error in <operation>". ``code`` is the
        reply code for a named failure (``550``, or ``553``/``500`` where
        globus uses those); an unnamed one is always ``451``, as globus
        sends it. The caller raises the result.
        """
        number = exc.errno or errno.EIO
        kind = _GLOBUS_CODES.get(number, "INTERNAL_ERROR")
        code = "451" if kind == "INTERNAL_ERROR" else code
        return _Reply(
            f"{code}-GlobusError: v=1 c={kind}\r\n{code}-GridFTP-Errno: {number}\r\n"
            f"{code}-GridFTP-Reason: System error in {operation}\r\n"
            f"{code}-GridFTP-Error-String: {os.strerror(number)}\r\n{code} End."
        )

    def close_passive(self) -> None:
        """Drop the passive listener, if any, and any pending delayed ``PASV``.

        Called before every new data-channel set-up (a later ``PASV`` or
        ``PORT`` replaces an earlier one, as RFC 959 has it), after every
        transfer, and when the session ends.
        """
        if self.passive is not None:
            self.passive.close()
        self.passive = None
        self.delayed = False
