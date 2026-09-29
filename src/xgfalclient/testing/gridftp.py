"""An in-process GridFTP server for the gridftp plugin's tests.

It serves a directory over ``ftp://`` (cleartext, anonymous or with a user
table) or ``gsiftp://`` (RFC 2228 GSI with delegation), one thread per
control connection, and answers the way globus-gridftp-server 13 does where
a client can tell the difference: reply codes and wording, ``632`` per-line
wrapping, the TLS 1.3 turn, delayed passive (``200 Passive delayed`` then a
``127`` with the address), the globus error block (``550-GlobusError: v=1
c=PATH_NOT_FOUND`` ...), ``MODE E`` with the sender connecting, perf and
range markers. Those behaviours were read off a real server, and the
plugin's interop tests run the same client against one.

Data channels are passive (``PASV``, ``EPSV``, ``SPAS``, or delayed) or
active (``PORT``, ``EPRT``, ``SPOR``), in ``MODE S`` or ``MODE E`` over any
number of connections, clear (``DCAU N``), authenticated with the client's
delegated proxy (``DCAU A``) or encrypted (``PROT P``). Two servers make a
third-party copy: the destination listens and the source connects out.

Faults are injected per verb::

    server.faults["RETR"] = "451 Injected failure"   # reply this instead
    server.faults["STOR"] = "close"                  # hang up on the command
    server.faults["MLST"] = "hang"                   # never answer
    server.faults["PWD"] = "raw:hello"               # send this line as is, unprotected
    server.after["RETR"] = "426 Aborted"             # move the data, then fail
    server.data_faults["RETR"] = "truncate"          # send half the file
    server.data_faults["STOR"] = "drop"              # close data connections at once
    server.delays["CKSM"] = 2.0                      # think before answering

    with GridFTPServer(root) as server:
        url = server.url("/file")
"""

from __future__ import annotations

import base64
import errno
import hashlib
import os
import shutil
import socket
import ssl
import stat as _stat
import tempfile
import threading
import time
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..crypto.gsi import GSIError, SecurityContext
from ..crypto.rsa import RSAPrivateKey
from ..errors import GError
from ..plugins.gridftp.data import (
    DataConn,
    EodCounter,
    Ranges,
    authenticate,
    recv_blocks,
    recv_stream,
    send_blocks,
    send_stream,
)
from ..plugins.gridftp.gsi import GlobusContext, data_contexts
from ..plugins.gridftp.protocol import format_mdtm, parse_epsv, parse_pasv

__all__ = ["GridFTPServer", "FEATURES"]

#: What globus-gridftp-server 13 lists in ``FEAT`` (the part a client uses).
FEATURES = (
    "CKSM MD5:10;ADLER32:10;SHA1:10;SHA256:11;SHA512:12;CRC32:10;",
    "DCAU",
    "PARALLEL",
    "SIZE",
    "MLST Type*;Size*;Modify*;Perm*;Charset;UNIX.mode*;UNIX.owner*;UNIX.uid*;"
    "UNIX.group*;UNIX.gid*;Unique*;UNIX.slink*;X.count;",
    "ERET",
    "ESTO",
    "SPAS",
    "SPOR",
    "REST STREAM",
    "MDTM",
    "PASV AllowDelayed;",
)

#: ``errno`` to the ``c=`` of a globus error block; anything else is 451.
_GLOBUS_CODES = {
    errno.ENOENT: "PATH_NOT_FOUND",
    errno.EEXIST: "PATH_EXISTS",
    errno.EACCES: "PERMISSION_DENIED",
}
#: Verbs a client may send before logging in.
_OPEN = frozenset({"AUTH", "ADAT", "USER", "PASS", "FEAT", "QUIT", "NOOP", "SYST"})
#: How long a data connection may take to turn up.
DATA_TIMEOUT = 30.0


class _Reply(Exception):
    """Raised by a handler to answer with ``text`` (``"550 ..."``)."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.text = text


class _Hangup(Exception):
    """End the session without another word."""


class _Moved:
    """Bytes moved by a transfer's data threads, for perf markers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.count = 0

    def add(self, count: int) -> None:
        with self._lock:
            self.count += count


def _checksum(path: str, algorithm: str, offset: int, length: int) -> str:
    name = algorithm.upper()
    with open(path, "rb") as handle:
        handle.seek(offset)
        data = handle.read() if length < 0 else handle.read(length)
    if name == "ADLER32":
        return f"{zlib.adler32(data):08x}"
    if name == "CRC32":
        return f"{zlib.crc32(data):08x}"
    try:
        return hashlib.new(name.lower(), data).hexdigest()
    except ValueError:
        raise _Reply("500 Unknown checksum algorithm requested.") from None


def _family(host: str) -> socket.AddressFamily:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _slice(data: bytes) -> Callable[[memoryview, int], int]:
    def read(view: memoryview, offset: int) -> int:
        chunk = data[offset : offset + len(view)]
        view[: len(chunk)] = chunk
        return len(chunk)

    return read


class GridFTPServer:
    """A threaded GridFTP server rooted at ``root``.

    ``gsi`` is a server TLS context (``pki.server_context()``) for
    ``gsiftp://``; ``ca_path`` is the CA directory its ``DCAU A`` data
    channels verify against; ``gridmap`` maps DNs to user names (any
    authenticated DN is ``gsiuser`` without one). Without ``gsi`` it is
    cleartext ``ftp://``, anonymous unless ``users`` maps names to
    passwords. ``delegation_key`` spares each session generating an RSA key
    for the delegated proxy. With ``perf_interval``, ``MODE E`` transfers
    send ``112`` markers that often and ``111``/``112`` at the end.
    """

    def __init__(
        self,
        root: Path | str,
        *,
        host: str = "localhost",
        gsi: ssl.SSLContext | None = None,
        ca_path: str | None = None,
        users: dict[str, str] | None = None,
        gridmap: dict[str, str] | None = None,
        delegation_key: RSAPrivateKey | None = None,
        features: tuple[str, ...] = FEATURES,
        perf_interval: float = 0.0,
        block_size: int = 256 * 1024,
        advertise: str | None = None,
    ) -> None:
        self.root = os.path.realpath(root)
        self.host = host
        self.gsi = gsi
        self.ca_path = ca_path
        self.users = users
        self.gridmap = gridmap
        self.delegation_key = delegation_key
        self.features = features
        self.perf_interval = perf_interval
        self.block_size = block_size
        #: The host ``PASV`` advertises; ``None`` means the one it listens on.
        self.advertise = advertise
        #: Whether ``SITE SETNETSTACK udt`` is accepted (globus whitelists it).
        self.udt = False
        #: A fixed reply to ``SITE USAGE``; ``None`` reports the root's disk.
        self.usage: str | None = None
        self.faults: dict[str, str] = {}
        self.after: dict[str, str] = {}
        self.data_faults: dict[str, str] = {}
        self.delays: dict[str, float] = {}
        #: Every command received, unwrapped, in order.
        self.log: list[str] = []
        #: How many control connections have been accepted.
        self.sessions = 0
        self._listener = socket.create_server((host, 0), family=_family(host))
        self.port = int(self._listener.getsockname()[1])
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self._lock = threading.Lock()

    @property
    def scheme(self) -> str:
        return "ftp" if self.gsi is None else "gsiftp"

    def url(self, path: str = "/") -> str:
        return f"{self.scheme}://{self.host}:{self.port}{path}"

    def start(self) -> GridFTPServer:
        thread = threading.Thread(target=self._serve, name="xgfal-gridftp-server", daemon=True)
        self._threads.append(thread)
        thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._listener.close()
        with self._lock:
            sockets, threads = list(self._sockets), list(self._threads)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        for thread in threads:
            thread.join(5)

    def __enter__(self) -> GridFTPServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _serve(self) -> None:
        while True:
            try:
                sock, _ = self._listener.accept()
            except OSError:
                return
            session = _Session(self, self.track(sock))
            thread = threading.Thread(target=session.run, name="xgfal-gridftp-session", daemon=True)
            with self._lock:
                self.sessions += 1
                self._threads.append(thread)
            thread.start()

    def track(self, sock: socket.socket) -> socket.socket:
        """Register a socket so :meth:`stop` can break it."""
        with self._lock:
            self._sockets.append(sock)
        return sock


class _Session:
    """One control connection and its state."""

    def __init__(self, server: GridFTPServer, sock: socket.socket) -> None:
        self.server = server
        self.sock = sock
        self.buffer = bytearray()
        self.security: SecurityContext | None = None
        self.adat: GlobusContext | None = None
        self.protection = "632"
        self.user: str | None = None
        self.logged_in = False
        self.cwd = "/"
        self.mode = "S"
        self.dcau = "N"
        self.prot = "C"
        self.parallelism = 1
        self.allow_delayed = False
        self.delayed = False
        self.passive: socket.socket | None = None
        self.active: list[tuple[str, int]] = []
        self.rest = 0
        self.rename_from: str | None = None
        self.delegated: str | None = None
        self.identity: tuple[tuple[str, str], ...] = ()

    # -- the control channel -------------------------------------------------------------

    def run(self) -> None:
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
        """Send a reply; once protected, each line is wrapped on its own (``632-``)."""
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
        """The file a client path names, confined to the root."""
        joined = os.path.normpath(os.path.join(self.cwd, path or "."))
        return os.path.join(self.server.root, joined.lstrip("/"))

    def failure(self, exc: OSError, operation: str, code: str = "550") -> _Reply:
        """An ``OSError`` as globus words it: the ``GlobusError`` block."""
        number = exc.errno or errno.EIO
        kind = _GLOBUS_CODES.get(number, "INTERNAL_ERROR")
        code = "451" if kind == "INTERNAL_ERROR" else code
        return _Reply(
            f"{code}-GlobusError: v=1 c={kind}\r\n{code}-GridFTP-Errno: {number}\r\n"
            f"{code}-GridFTP-Reason: System error in {operation}\r\n"
            f"{code}-GridFTP-Error-String: {os.strerror(number)}\r\n{code} End."
        )

    # -- login ----------------------------------------------------------------------------

    def do_AUTH(self, arg: str) -> None:
        if self.server.gsi is None or arg.upper() != "GSSAPI":
            raise _Reply("504 Authentication type not supported.")
        self.adat = GlobusContext(
            self.server.gsi, server_side=True, delegation_key=self.server.delegation_key
        )
        raise _Reply("334 Using authentication type; ADAT must follow.")

    def do_ADAT(self, arg: str) -> None:
        context = self.adat
        if context is None:
            raise _Reply("503 You must issue the AUTH command prior to ADAT.")
        try:
            token = context.step(base64.b64decode(arg))
        except (GSIError, ValueError):
            self.adat = None
            raise _Reply("535 GSSAPI authentication failed.") from None
        encoded = base64.b64encode(token).decode("ascii")
        if not context.complete:
            raise _Reply(f"335 ADAT={encoded}")
        # Python < 3.10 cannot verify proxies, so pki.server_context() asks for no
        # client certificate there, and the peer is anonymous.
        peer = context.peer_certificate()
        rdns = peer.subject.rdns if peer is not None else ()
        while (
            rdns
            and rdns[-1][0] == "CN"
            and (rdns[-1][1].isdigit() or rdns[-1][1].endswith("proxy"))
        ):
            rdns = rdns[:-1]
        self.identity = rdns
        if context.delegated is not None:
            handle, self.delegated = tempfile.mkstemp(prefix="xgfal-delegated-")
            with os.fdopen(handle, "wb") as out:
                out.write(context.delegated.pem())
        self.reply(f"235 ADAT={encoded}" if token else "235 GSSAPI Authentication successful.")
        self.security = context

    def do_USER(self, arg: str) -> None:
        if self.server.gsi is not None and self.security is None:
            raise _Reply("530 Must perform GSSAPI authentication.")
        self.user = arg
        raise _Reply(f"331 Password required for {arg}.")

    def do_PASS(self, arg: str) -> None:
        if self.user is None:
            raise _Reply("503 Login with USER first.")
        name: str | None = self.user
        if self.security is not None:
            dn = "".join(f"/{key}={value}" for key, value in self.identity)
            gridmap = self.server.gridmap
            name = "gsiuser" if gridmap is None else gridmap.get(dn)
        elif self.server.users is None:
            name = name if name in ("anonymous", "ftp") else None
        elif self.server.users.get(self.user) != arg:
            name = None
        if name is None:
            raise _Reply("530 Login incorrect.")
        self.logged_in = True
        raise _Reply(f"230 User {name} logged in.")

    def do_FEAT(self, arg: str) -> None:
        body = "".join(f" {feature}\r\n" for feature in self.server.features)
        raise _Reply(f"211-Extensions supported\r\n{body}211 End.")

    def do_QUIT(self, arg: str) -> None:
        self.reply("221 Goodbye.")
        raise _Hangup()

    # -- session settings -----------------------------------------------------------------

    def do_NOOP(self, arg: str) -> None:
        raise _Reply("200 NOOP command successful.")

    def do_SYST(self, arg: str) -> None:
        raise _Reply("215 UNIX Type: L8")

    def do_PWD(self, arg: str) -> None:
        raise _Reply(f'257 "{self.cwd}" is current directory.')

    def do_CWD(self, arg: str) -> None:
        if not os.path.isdir(self.local(arg)):
            raise _Reply(f"550 {arg}: Not a directory.")
        self.cwd = os.path.normpath(os.path.join(self.cwd, arg))
        raise _Reply("250 CWD command successful.")

    def do_TYPE(self, arg: str) -> None:
        if arg.upper() not in ("A", "I"):
            raise _Reply("504 Type not supported.")
        raise _Reply(f"200 Type set to {arg.upper()}.")

    def do_MODE(self, arg: str) -> None:
        if arg.upper() not in ("S", "E"):
            raise _Reply("504 Mode not supported.")
        self.mode = arg.upper()
        raise _Reply(f"200 Mode set to {self.mode}.")

    def do_DCAU(self, arg: str) -> None:
        wanted = arg.upper()
        if wanted not in ("N", "A") or (wanted == "A" and self.delegated is None):
            raise _Reply("504 Bad DCAU mode.")
        self.dcau = wanted
        raise _Reply(f"200 DCAU {wanted}.")

    def do_PBSZ(self, arg: str) -> None:
        raise _Reply(f"200 PBSZ={arg}")

    def do_PROT(self, arg: str) -> None:
        wanted = arg.upper()
        if wanted not in ("C", "P") or (wanted == "P" and self.delegated is None):
            raise _Reply("536 Requested PROT level not supported.")
        self.prot = wanted
        raise _Reply(f"200 Protection level set to {wanted}.")

    def do_OPTS(self, arg: str) -> None:
        what, _, value = arg.partition(" ")
        name, _, setting = value.partition("=")
        if what.upper() == "RETR" and name == "Parallelism":
            self.parallelism = max(1, int(setting.split(",")[0]))
        elif what.upper() == "PASV" and name == "AllowDelayed":
            self.allow_delayed = setting.rstrip(";") == "1"
        else:
            raise _Reply("501 Invalid command arguments.")
        raise _Reply("200 OPTS Command Successful.")

    def do_SITE(self, arg: str) -> None:
        what, _, rest = arg.partition(" ")
        what = what.upper()
        if what == "CLIENTINFO":
            raise _Reply("250 OK.")
        if what == "CHMOD":
            mode, _, path = rest.partition(" ")
            try:
                os.chmod(self.local(path), int(mode, 8))
            except OSError as exc:
                raise self.failure(exc, "chmod") from None
            raise _Reply("200 SITE CHMOD command successful.")
        if what == "USAGE":
            if self.server.usage is not None:
                raise _Reply(self.server.usage)
            usage = shutil.disk_usage(self.server.root)
            raise _Reply(f"250 USAGE {usage.used} FREE {usage.free} TOTAL {usage.total}")
        if what in ("RETRBUFSIZE", "STORBUFSIZE"):
            raise _Reply(f"200 {what} {rest} OK.")
        if what == "SETNETSTACK":
            if rest.lower() == "udt" and not self.server.udt:
                raise _Reply("500 Command failed : udt driver not whitelisted")
            raise _Reply("200 Site Command Successful.")
        raise _Reply("500 Invalid command.")

    def do_ALLO(self, arg: str) -> None:
        raise _Reply("200 ALLO command successful.")

    def do_REST(self, arg: str) -> None:
        self.rest = int(arg)
        raise _Reply("350 Restart Marker OK. Send STORE or RETRIEVE to initiate transfer.")

    def do_ABOR(self, arg: str) -> None:
        raise _Reply("226 Abort successful.")

    # -- data channel set-up -------------------------------------------------------------

    def close_passive(self) -> None:
        if self.passive is not None:
            self.passive.close()
        self.passive = None
        self.delayed = False

    def listen(self) -> int:
        """Open a passive listener beside the control connection; its port."""
        self.close_passive()
        self.active = []
        host = self.sock.getsockname()[0]
        self.passive = self.server.track(socket.create_server((host, 0), family=_family(host)))
        return int(self.passive.getsockname()[1])

    def pasv(self) -> str:
        """Listen, and say where as ``h1,h2,h3,h4,p1,p2``."""
        port = self.listen()
        shown = self.server.advertise or self.sock.getsockname()[0]
        return ",".join([*shown.split("."), str(port // 256), str(port % 256)])

    def do_PASV(self, arg: str) -> None:
        if self.allow_delayed:
            self.close_passive()
            self.active = []
            self.delayed = True
            raise _Reply("200 Passive delayed.")
        raise _Reply(f"227 Entering Passive Mode ({self.pasv()})")

    def do_EPSV(self, arg: str) -> None:
        raise _Reply(f"229 Entering Extended Passive Mode (|||{self.listen()}|)")

    def do_SPAS(self, arg: str) -> None:
        raise _Reply(f"229-Entering Striped Passive Mode\r\n {self.pasv()}\r\n229 End")

    def do_PORT(self, arg: str) -> None:
        self.close_passive()
        self.active = [parse_pasv(arg)]
        raise _Reply("200 PORT Command successful.")

    def do_EPRT(self, arg: str) -> None:
        self.close_passive()
        self.active = [parse_epsv(f"({arg})")]
        raise _Reply("200 EPRT Command successful.")

    def do_SPOR(self, arg: str) -> None:
        self.close_passive()
        self.active = [parse_pasv(part) for part in arg.split()]
        raise _Reply("200 SPOR Command successful.")

    def secure(self, sock: socket.socket, initiator: bool) -> DataConn:
        """``DCAU A`` and/or ``PROT P`` on a fresh data connection."""
        sock.settimeout(DATA_TIMEOUT)
        if self.dcau == "N" and self.prot == "C":
            return DataConn(sock)
        assert self.delegated is not None
        pair = data_contexts(self.delegated, self.delegated, self.server.ca_path)
        context = authenticate(
            sock,
            pair[0] if initiator else pair[1],
            initiator=initiator,
            identity=self.identity,
            ssl_compatible=self.prot == "P",
        )
        return DataConn(sock, context if self.prot == "P" else None)

    def connections(self, open_ended: bool) -> Callable[[], DataConn | None]:
        """Where the transfer's data connections come from; ``None`` is "none yet"."""
        if self.active:
            addresses = list(self.active)
            used: list[int] = []

            def connect_out() -> DataConn:
                host, port = addresses[len(used) % len(addresses)]
                used.append(port)
                try:
                    sock = self.server.track(socket.create_connection((host, port), DATA_TIMEOUT))
                    return self.secure(sock, initiator=True)
                except (OSError, GError) as exc:
                    raise _Reply(f"425 Can't open data connection: {exc}") from None

            return connect_out
        if self.passive is None:
            if not self.delayed:
                raise _Reply("425 Use PORT or PASV first.")
            self.reply(f"127 Entering Passive Mode ({self.pasv()})")
        listener = self.passive
        assert listener is not None
        listener.settimeout(0.05 if open_ended else DATA_TIMEOUT)

        def accept() -> DataConn | None:
            try:
                sock, _ = listener.accept()
            except socket.timeout:
                return None
            try:
                return self.secure(self.server.track(sock), initiator=False)
            except (OSError, GError) as exc:
                raise _Reply(f"425 Can't open data connection: {exc}") from None

        return accept

    # -- transfers ------------------------------------------------------------------------

    def transfer(
        self,
        verb: str,
        count: int,
        work: Callable[[DataConn, int, _Moved], Any],
        eods: EodCounter | None = None,
    ) -> None:
        """Run ``work`` on ``count`` data connections, then reply ``226`` (or ``after``).

        A passive ``MODE E`` receiver (``eods`` given) takes connections until
        the sender's ``EOF`` count is met, however many that turns out to be.
        Perf markers go out on the control channel meanwhile.
        """
        # Set once a passive receiver has everything; it takes connections until then.
        complete = eods.done if eods is not None and not self.active else None
        obtain = self.connections(complete is not None)
        self.reply("150 Beginning transfer.")
        if self.server.data_faults.get(verb) == "drop":
            work = lambda conn, index, moved: None  # noqa: E731
        moved = _Moved()
        errors: list[BaseException] = []
        threads: list[threading.Thread] = []

        def run(conn: DataConn, index: int) -> None:
            try:
                work(conn, index, moved)
            except BaseException as exc:  # reported on the control channel
                errors.append(exc)
            finally:
                conn.sock.close()

        deadline = time.monotonic() + DATA_TIMEOUT
        try:
            while (
                not complete.is_set() and not errors
                if complete is not None
                else len(threads) < count
            ):
                if time.monotonic() > deadline:
                    raise _Reply("425 Can't open data connection: timed out.")
                conn = obtain()
                if conn is not None:
                    thread = threading.Thread(target=run, args=(conn, len(threads)), daemon=True)
                    threads.append(thread)
                    thread.start()
            self.wait(threads, moved)
        finally:
            self.close_passive()
            self.active = []
            self.rest = 0
        if errors:
            raise _Reply(f"426 Data connection failed: {errors[0]}")
        if self.mode == "E" and self.server.perf_interval:
            self.marker(moved.count)
            if eods is not None:
                self.reply(f"111 Range Marker 0-{moved.count}")
        raise _Reply(self.server.after.get(verb, "226 Transfer Complete."))

    def wait(self, threads: list[threading.Thread], moved: _Moved) -> None:
        last = time.monotonic()
        interval = self.server.perf_interval
        for thread in threads:
            while thread.is_alive():
                thread.join(0.02)
                if self.mode == "E" and interval and time.monotonic() - last >= interval:
                    last = time.monotonic()
                    self.marker(moved.count)

    def marker(self, count: int) -> None:
        self.reply(
            "112-Perf Marker\r\n"
            f" Timestamp: {time.time():.1f}\r\n"
            " Stripe Index: 0\r\n"
            f" Stripe Bytes Transferred: {count}\r\n"
            " Total Stripe Count: 1\r\n"
            "112 End."
        )

    def send_file(self, verb: str, path: str, start: int, end: int | None) -> None:
        if os.path.isdir(self.local(path)):
            raise _Reply(
                "500-Command failed. : callback failed.\r\n"
                "500-globus_xio: System error in read: Is a directory\r\n"
                "500-globus_xio: A system call failed: Is a directory\r\n"
                "500 End."
            )
        try:
            fd = os.open(self.local(path), os.O_RDONLY)
        except OSError as exc:
            raise _Reply(
                "500-Command failed. : globus_l_gfs_file_open failed.\r\n"
                f"500-globus_xio: Unable to open file {path}\r\n"
                f"500-globus_xio: System error in open: {os.strerror(exc.errno or errno.EIO)}\r\n"
                "500 End."
            ) from None
        try:
            size = os.fstat(fd).st_size
            stop = size if end is None else min(size, end)
            if self.server.data_faults.get(verb) == "truncate":
                stop = start + (stop - start) // 2

            def read(view: memoryview, offset: int) -> int:
                return int(os.preadv(fd, [view], offset))

            if self.mode == "E":
                ranges = Ranges(start, stop, self.server.block_size)
                streams, block = self.parallelism, self.server.block_size
                self.transfer(
                    verb,
                    streams,
                    lambda conn, index, moved: send_blocks(
                        conn, read, ranges, moved.add, block, streams if index == 0 else 0
                    ),
                )
            else:
                self.transfer(
                    verb,
                    1,
                    lambda conn, index, moved: send_stream(
                        conn, read, 65536, moved.add, start, stop
                    ),
                )
        finally:
            os.close(fd)

    def do_RETR(self, arg: str) -> None:
        self.send_file("RETR", arg, self.rest, None)

    def do_ERET(self, arg: str) -> None:
        module, offset, length, path = arg.split(" ", 3)
        if module != "P":
            raise _Reply("501 Unsupported ERET module.")
        self.send_file("ERET", path, int(offset), int(offset) + int(length))

    def do_ESTO(self, arg: str) -> None:
        module, offset, path = arg.split(" ", 2)
        if module != "A":
            raise _Reply("501 Unsupported ESTO module.")
        self.store(path, int(offset), truncate=False)

    def do_STOR(self, arg: str) -> None:
        self.store(arg, self.rest, truncate=not self.rest)

    def getput(self, arg: str) -> str:
        """Set up a GridFTP v2 ``GET``/``PUT``'s data channel; the file it names."""
        options = dict(item.partition("=")[::2] for item in arg.split(";") if item)
        if "port" in options:
            self.close_passive()
            self.active = [parse_pasv(options["port"])]
        elif "pasv" in options:
            self.reply(f"127 PORT ({self.pasv()})")
        return options.get("file", "")

    def do_GET(self, arg: str) -> None:
        self.send_file("RETR", self.getput(arg), 0, None)

    def do_PUT(self, arg: str) -> None:
        self.store(self.getput(arg), 0, truncate=True)

    def store(self, arg: str, start: int, *, truncate: bool) -> None:
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if truncate else 0)
        try:
            fd = os.open(self.local(arg), flags, 0o644)
        except OSError as exc:
            raise self.failure(exc, "open") from None

        def write(view: memoryview, offset: int) -> None:
            os.pwrite(fd, view, offset)

        try:
            if self.mode == "E":
                eods = EodCounter()
                self.transfer(
                    "STOR",
                    self.parallelism,
                    lambda conn, index, moved: recv_blocks(conn, write, 65536, moved.add, eods),
                    eods,
                )
            else:
                self.transfer(
                    "STOR",
                    1,
                    lambda conn, index, moved: recv_stream(conn, write, 65536, moved.add, start),
                )
        finally:
            os.close(fd)

    def listing(self, verb: str, arg: str, lines: Callable[[str], list[str]]) -> None:
        """Send a listing, always as a plain stream (``MODE S``), as clients read it."""
        try:
            text = "".join(f"{line}\r\n" for line in lines(self.local(arg)))
        except OSError as exc:
            raise self.failure(exc, "stat") from None
        read = _slice(text.encode("utf-8", "surrogateescape"))
        mode, self.mode = self.mode, "S"
        try:
            self.transfer(verb, 1, lambda conn, i, moved: send_stream(conn, read, 65536, moved.add))
        finally:
            self.mode = mode

    def entries(self, path: str) -> list[str]:
        if os.path.isdir(path):
            return [".", "..", *sorted(os.listdir(path))]
        if os.path.lexists(path):
            return [os.path.basename(path)]
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT))

    def do_NLST(self, arg: str) -> None:
        self.listing("NLST", arg, self.entries)

    def do_MLSD(self, arg: str) -> None:
        def lines(path: str) -> list[str]:
            if not os.path.isdir(path):
                raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR))
            return [f"{self.facts(os.path.join(path, n), n)} {n}" for n in self.entries(path)]

        self.listing("MLSD", arg, lines)

    def do_LIST(self, arg: str) -> None:
        def lines(path: str) -> list[str]:
            base = path if os.path.isdir(path) else os.path.dirname(path)
            out = []
            for name in self.entries(path):
                info = os.lstat(os.path.join(base, name))
                when = time.strftime("%b %d %H:%M", time.gmtime(info.st_mtime))
                out.append(
                    f"{_stat.filemode(info.st_mode)} 1 {info.st_uid} {info.st_gid} "
                    f"{info.st_size} {when} {name}"
                )
            return out

        self.listing("LIST", arg, lines)

    def facts(self, path: str, name: str) -> str:
        info = os.stat(path)
        if _stat.S_ISDIR(info.st_mode):
            kind = {".": "cdir", "..": "pdir"}.get(name, "dir")
            perm = "cfmpel"
        else:
            kind, perm = "file", "adfrw"
        return (
            f"Type={kind};Modify={format_mdtm(info.st_mtime)};Size={info.st_size};Perm={perm};"
            f"UNIX.mode={_stat.S_IMODE(info.st_mode):04o};UNIX.owner={info.st_uid};"
            f"UNIX.uid={info.st_uid};UNIX.group={info.st_gid};UNIX.gid={info.st_gid};"
            f"Unique={info.st_dev:x}-{info.st_ino:x};"
        )

    # -- namespace --------------------------------------------------------------------------

    def do_MLST(self, arg: str) -> None:
        path = self.local(arg)
        try:
            facts = self.facts(path, os.path.basename(path))
        except OSError as exc:
            raise self.failure(exc, "stat") from None
        raise _Reply(f"250-status of {arg}\r\n {facts} {arg}\r\n250 End.")

    def do_SIZE(self, arg: str) -> None:
        try:
            info = os.stat(self.local(arg))
        except OSError as exc:
            raise self.failure(exc, "stat") from None
        if _stat.S_ISDIR(info.st_mode):
            raise _Reply(f"550 {arg}: not a plain file.")
        raise _Reply(f"213 {info.st_size}")

    def do_MDTM(self, arg: str) -> None:
        try:
            info = os.stat(self.local(arg))
        except OSError as exc:
            raise self.failure(exc, "stat") from None
        raise _Reply(f"213 {format_mdtm(info.st_mtime)}")

    def do_CKSM(self, arg: str) -> None:
        algorithm, offset, length, path = arg.split(" ", 3)
        try:
            value = _checksum(self.local(path), algorithm, int(offset), int(length))
        except OSError as exc:
            raise self.failure(exc, "open") from None
        raise _Reply(f"213 {value}")

    def simple(self, action: Callable[[str], Any], arg: str, operation: str, done: str) -> None:
        try:
            action(self.local(arg))
        except OSError as exc:
            raise self.failure(
                exc, operation, "553" if exc.errno == errno.EEXIST else "550"
            ) from None
        raise _Reply(done)

    def do_MKD(self, arg: str) -> None:
        self.simple(os.mkdir, arg, "mkdir", f'257 "{arg}" directory created.')

    def do_RMD(self, arg: str) -> None:
        self.simple(os.rmdir, arg, "rmdir", "250 RMD command successful.")

    def do_DELE(self, arg: str) -> None:
        self.simple(os.unlink, arg, "unlink", "250 DELE command successful.")

    def do_RNFR(self, arg: str) -> None:
        self.rename_from = None
        try:
            os.stat(self.local(arg))
        except OSError as exc:
            raise self.failure(exc, "stat", "500") from None
        self.rename_from = self.local(arg)
        raise _Reply("350 Waiting for RNTO.")

    def do_RNTO(self, arg: str) -> None:
        source, self.rename_from = self.rename_from, None
        if source is None:
            raise _Reply("501 Invalid command arguments.")
        self.simple(lambda target: os.rename(source, target), arg, "rename", "250 RNTO successful.")
