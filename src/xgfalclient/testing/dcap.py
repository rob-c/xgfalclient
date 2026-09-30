"""An in-process dCache dcap door, with its pool mover and directory lister.

Enough of dCache's ``DCapDoorInterpreterV3``, ``DCapProtocol_3_nio`` and
``DirectoryLookUpPool`` to drive the ``dcap`` plugin (and libdcap) through
everything gfal2 does, over a local directory::

    with DcapServer(tmp_path) as door:
        ctx.stat(door.url("/data/f"))

    with DcapServer(tmp_path, gsi=pki.server_context()) as door:   # gsidcap
        ...

What it models:

* the control line - ``hello``, ``stat``/``lstat``, ``unlink``, ``rmdir``,
  ``mkdir``, ``chmod``, ``rename``, ``open``, ``opendir``, ``ping``,
  ``byebye`` - with dCache's reply lines and error codes;
* the GSI tunnel (``enc <base64>`` token lines around a server-side
  :class:`~xgfalclient.crypto.gsi.SecurityContext`) when ``gsi`` is given;
* movers that either listen and send ``connect <host> <port> <challenge>``
  (dCache's "passive" pools, the default) or connect back to the client's
  socket (``callback=True``, old pools and the directory lister), serving
  ``READ``, ``SEEK``, ``SEEK_AND_READ``, ``WRITE``, ``SEEK_AND_WRITE``,
  ``LOCATE`` and ``CLOSE`` with its ADLER32 check;
* dCache's write-once files: opening an existing file for writing fails
  unless it is empty or ``-truncate`` is sent and :attr:`truncate` allowed;
* fault injection: :meth:`DcapServer.inject` replaces the door's next
  reply(s) to a verb, and :meth:`DcapServer.fault` makes the next data
  request misbehave in a named way.

Every control line the door receives is kept in :attr:`DcapServer.log`.
"""

from __future__ import annotations

import base64
import os
import posixpath
import socket
import ssl
import stat as _stat
import struct
import threading
import urllib.parse
import uuid
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from ..crypto.gsi import GSIError, SecurityContext
from ..errors import GError
from ..plugins.dcap.control import ControlConnection
from ..plugins.dcap.protocol import (
    HEADER,
    INT,
    IOCMD_ACK,
    IOCMD_CLOSE,
    IOCMD_DATA,
    IOCMD_FIN,
    IOCMD_LOCATE,
    IOCMD_READ,
    IOCMD_SEEK,
    IOCMD_SEEK_READ,
    IOCMD_SEEK_WRITE,
    IOCMD_WRITE,
    SEEK_CURRENT,
    SEEK_END,
    options,
    stat_fields,
    tokenize,
)
from ..plugins.dcap.tunnel import TokenLink, Tunnel
from ..types import Stat

__all__ = ["DcapServer", "DROP", "Raw", "FAULTS", "ServerGSITunnel", "ServerKerberosTunnel"]

#: Inject this to have the door hang up instead of answering.
DROP = "<drop>"


@dataclass(frozen=True)
class Raw:
    """Inject bytes written to the socket as they are, past any tunnel."""

    data: bytes


#: What :meth:`DcapServer.fault` understands, each affecting the next data request:
FAULTS = (
    "ack-error",  # ACK the request with a failure and a message
    "ack-bare-error",  # ... with a failure and no message
    "wrong-reply",  # answer with FIN where an ACK belongs
    "wrong-command",  # ACK a different command
    "bad-length",  # a reply whose length field is 0
    "overflow",  # send more bytes than the read asked for
    "fin-error",  # end a read or a write with a failed FIN
    "hangup",  # close the data connection instead of answering
    "short-locate",  # a LOCATE ACK without its fields
    "close-failed",  # report the transfer as failed on the control line after CLOSE
    "stall",  # say nothing at all
)

Injection = Union[str, Raw, Callable[[int, list[str]], Union[str, Raw, None]]]

_BLOCK = 256 * 1024 - 4  # DCapProtocol_3_nio: a 256 KiB buffer less the length field
_NOT_FOUND = '{s} {c} client failed 10001 "No such file or directory" ENOENT'


class ServerGSITunnel(Tunnel):
    """The door's side of the GSI tunnel (dCache's ``DssSocket.verify``)."""

    def __init__(self, tls: ssl.SSLContext) -> None:
        # dCache's ServerGsiEngine: no TLS 1.3 turn byte after the handshake.
        self.security = SecurityContext(tls, server_side=True, turn=False)

    def handshake(self, link: TokenLink, host: str) -> None:
        while not self.security.complete:
            token = self.security.step(link.read_token())
            if token:
                link.send_token(token)

    def wrap(self, data: bytes) -> bytes:
        return self.security.wrap(data)

    def unwrap(self, token: bytes) -> bytes:
        return self.security.unwrap(token)


class ServerKerberosTunnel(Tunnel):
    """The door's side of the Kerberos tunnel (:class:`xgfalclient.crypto.krb5.AcceptorContext`)."""

    def __init__(self, keytab: str | None = None) -> None:
        from ..crypto import krb5

        self.security = krb5.AcceptorContext(keytab=keytab)

    def handshake(self, link: TokenLink, host: str) -> None:
        # libdcap asks for mutual authentication, so the AP-REQ always earns an AP-REP.
        link.send_token(self.security.step(link.read_token()))

    def wrap(self, data: bytes) -> bytes:
        return bytes(self.security.wrap(data))

    def unwrap(self, token: bytes) -> bytes:
        return bytes(self.security.unwrap(token))

    def close(self) -> None:
        self.security.close()


class _Control:
    """The door's end of one control connection; several threads write to it."""

    def __init__(self, conn: ControlConnection) -> None:
        self.conn = conn
        self.lock = threading.Lock()

    def send(self, line: str) -> None:
        with self.lock:
            self.conn.send_line(line)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return bytes(data)


def _recv_int(sock: socket.socket) -> int:
    return int(INT.unpack(_recv_exact(sock, 4))[0])


def _ack(command: int, result: int = 0, message: str | None = None, extra: bytes = b"") -> bytes:
    body = struct.pack(">iii", IOCMD_ACK, command, result) + extra
    if message is not None:
        text = message.encode()
        body += struct.pack(">H", len(text)) + text
    return INT.pack(len(body)) + body


def _fin(command: int, result: int = 0, message: str | None = None) -> bytes:
    body = struct.pack(">iii", IOCMD_FIN, command, result)
    if message is not None:
        text = message.encode()
        body += struct.pack(">H", len(text)) + text
    return INT.pack(len(body)) + body


_DATA_HEADER = HEADER.pack(4, IOCMD_DATA)


class _Mover:
    """One transfer: the pool's end of the data connection."""

    def __init__(self, server: DcapServer, path: Path, writable: bool) -> None:
        self.server = server
        self.path = path
        self.writable = writable
        self.file = open(path, "r+b", buffering=0)  # noqa: SIM115 - closed in run()
        self.checksum: int | None = None
        self.failed = ""

    def run(self, sock: socket.socket) -> str:
        """Serve requests until CLOSE or hang-up; the door's verdict, ``""`` if all is well."""
        try:
            while self.serve(sock):
                pass
        except (EOFError, OSError):
            pass
        finally:
            self.file.close()
            sock.close()
        return self.failed

    def serve(self, sock: socket.socket) -> bool:
        length = _recv_int(sock)
        body = _recv_exact(sock, length)
        command = INT.unpack_from(body)[0]
        self.server.data_log.append(command)
        fault = self.server._take_fault()
        if fault == "hangup":
            return False
        if fault == "stall":
            return True
        if fault in ("ack-error", "ack-bare-error"):
            message = "Injected failure" if fault == "ack-error" else None
            sock.sendall(_ack(command, 33, message))
            return True
        if fault == "wrong-reply":
            sock.sendall(_fin(command))
            return True
        if fault == "wrong-command":
            sock.sendall(_ack(command + 100))
            return True
        if fault == "bad-length":
            sock.sendall(INT.pack(0))
            return True
        if command == IOCMD_READ:
            (size,) = struct.unpack_from(">q", body, 4)
            self.read(sock, IOCMD_READ, size, fault)
        elif command == IOCMD_SEEK_READ:
            offset, whence, size = struct.unpack_from(">qiq", body, 4)
            self.seek(offset, whence)
            self.read(sock, IOCMD_SEEK_READ, size, fault)
        elif command in (IOCMD_WRITE, IOCMD_SEEK_WRITE):
            if not self.writable:
                sock.sendall(_ack(command, 1, "WRITE denied (not allowed)"))
                return True
            if command == IOCMD_SEEK_WRITE:
                offset, whence = struct.unpack_from(">qi", body, 4)
                self.seek(offset, whence)
            self.write(sock, command, fault)
        elif command == IOCMD_SEEK:
            offset, whence = struct.unpack_from(">qi", body, 4)
            self.seek(offset, whence)
            sock.sendall(_ack(IOCMD_SEEK, extra=struct.pack(">q", self.file.tell())))
        elif command == IOCMD_LOCATE:
            position = self.file.tell()
            size = os.fstat(self.file.fileno()).st_size
            extra = b"" if fault == "short-locate" else struct.pack(">qq", size, position)
            sock.sendall(_ack(IOCMD_LOCATE, extra=extra))
        elif command == IOCMD_CLOSE:
            sock.sendall(_ack(IOCMD_CLOSE))
            if len(body) >= 20:
                self.checksum = struct.unpack_from(">I", body, 16)[0]
                self.file.flush()
                with open(self.path, "rb") as handle:
                    actual = zlib.adler32(handle.read())
                if actual != self.checksum:
                    self.failed = f'10006 "Checksum mismatch ({actual:08x} != {self.checksum:08x})"'
            if fault == "close-failed":
                self.failed = '10006 "Injected transfer failure" EIO'
            return False
        else:
            sock.sendall(_ack(666, 9, f"Invalid mover command : {command}"))
        return True

    def seek(self, offset: int, whence: int) -> None:
        base = {SEEK_CURRENT: os.SEEK_CUR, SEEK_END: os.SEEK_END}.get(whence, os.SEEK_SET)
        self.file.seek(offset, base)

    def read(self, sock: socket.socket, command: int, size: int, fault: str | None) -> None:
        sock.sendall(_ack(command) + _DATA_HEADER)
        if fault == "overflow":
            size += 10
            sock.sendall(INT.pack(size) + b"x" * size + INT.pack(-1) + _fin(command))
            return
        if size == 0:
            sock.sendall(INT.pack(0) + INT.pack(-1) + _fin(command))
            return
        buffer = bytearray(4 + _BLOCK)
        view = memoryview(buffer)
        while size > 0:
            count = self.file.readinto(view[4 : 4 + min(size, _BLOCK)])
            if not count:
                break
            INT.pack_into(buffer, 0, count)
            sock.sendall(view[: 4 + count])
            size -= count
        sock.sendall(INT.pack(-1))
        if fault == "fin-error":
            sock.sendall(_fin(command, 1, "FIN : READ failed (IO not ok)"))
        else:
            sock.sendall(_fin(command))

    def write(self, sock: socket.socket, command: int, fault: str | None) -> None:
        sock.sendall(_ack(command))
        length = _recv_int(sock)
        if INT.unpack(_recv_exact(sock, length)[:4])[0] != IOCMD_DATA:
            raise EOFError  # dCache throws "Expecting : 8" and drops the mover
        buffer = bytearray(1 << 20)
        view = memoryview(buffer)
        while True:
            size = _recv_int(sock)
            if size < 0:
                break
            while size > 0:
                count = sock.recv_into(view[: min(size, len(buffer))])
                if not count:
                    raise EOFError
                self.file.write(view[:count])
                size -= count
        if fault == "fin-error":
            sock.sendall(_fin(command, 30, "WRITE failed : No space left on device"))
        else:
            sock.sendall(_fin(command))


class DcapServer:
    """A threaded dcap door over ``root``; see the module docstring."""

    def __init__(
        self,
        root: Path | str,
        *,
        gsi: ssl.SSLContext | None = None,
        tunnel: Callable[[], Tunnel] | None = None,
        scheme: str | None = None,
        host: str = "127.0.0.1",
        callback: bool = False,
        truncate: bool = False,
        accept_timeout: float = 10.0,
    ) -> None:
        self.root = Path(root)
        if gsi is not None:
            tunnel = lambda: ServerGSITunnel(gsi)  # noqa: E731
        #: Builds the door's side of the tunnel for each connection (``None``: plain dcap).
        self.tunnel = tunnel
        self.scheme = scheme or ("gsidcap" if gsi is not None else "dcap")
        self.host = host
        #: How long a passive mover waits for the client to connect.
        self.accept_timeout = accept_timeout
        #: Movers calling back first dial in with another session's number.
        self.decoy_callback = False
        #: Movers connect to the client instead of sending ``connect``.
        self.callback = callback
        #: dCache's ``dcap.authz.truncate``: may ``-truncate`` replace a file?
        self.truncate = truncate
        #: The ``hello`` answer; anything but ``welcome`` is a rejection.
        self.welcome = "0 0 server welcome 2 47"
        #: Raw bytes sent instead of the first GSI handshake token.
        self.handshake_reply: bytes | None = None
        #: Every control line received, in order.
        self.log: list[str] = []
        #: Every data-channel command received, in order.
        self.data_log: list[int] = []
        #: Control connections accepted so far.
        self.connections = 0
        #: The last ADLER32 a client sent with CLOSE.
        self.checksums: list[int | None] = []
        self._injections: dict[str, list[Injection]] = {}
        self._faults: list[str] = []
        self._lock = threading.Lock()
        self._sockets: set[socket.socket] = set()
        self._threads: list[threading.Thread] = []
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._listener = socket.socket(family, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((host, 0))
        self._listener.listen(16)
        self.port: int = self._listener.getsockname()[1]

    # -- lifecycle -------------------------------------------------------------------

    def start(self) -> DcapServer:
        self._spawn(self._accept_loop)
        return self

    def stop(self) -> None:
        # Linux does not wake a thread blocked in accept() when the listener is
        # merely closed (macOS does); a shutdown does, so stop() takes no 5 s join.
        try:
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._listener.close()
        with self._lock:
            sockets = list(self._sockets)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        for thread in self._threads:
            thread.join(5)

    def __enter__(self) -> DcapServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _spawn(self, target: Callable[..., object], *args: object) -> None:
        thread = threading.Thread(target=target, args=args, daemon=True, name="xgfal-dcapd")
        self._threads.append(thread)
        thread.start()

    def _track(self, sock: socket.socket) -> socket.socket:
        with self._lock:
            self._sockets.add(sock)
        return sock

    # -- addressing ----------------------------------------------------------------------

    def url(self, path: str, *, host: str | None = None) -> str:
        name = host or (f"[{self.host}]" if ":" in self.host else self.host)
        return f"{self.scheme}://{name}:{self.port}{path}"

    def local(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    # -- fault injection -----------------------------------------------------------------

    def inject(self, verb: str, reply: Injection, *, times: int = 1) -> None:
        """Answer the next ``times`` requests for ``verb`` with ``reply`` instead.

        ``reply`` is a line template (``{s}`` is the session, ``{c}`` the
        command id; several lines separated by ``\\n``), :data:`DROP`,
        :class:`Raw` bytes, or ``callable(session, args)`` returning one of
        those (``None`` means answer normally).
        """
        with self._lock:
            self._injections.setdefault(verb, []).extend([reply] * times)

    def fault(self, name: str, *, times: int = 1) -> None:
        """Make the next ``times`` data requests misbehave as ``name`` (see :data:`FAULTS`)."""
        if name not in FAULTS:
            raise ValueError(f"unknown fault {name!r}")
        with self._lock:
            self._faults.extend([name] * times)

    def _take_fault(self) -> str | None:
        with self._lock:
            return self._faults.pop(0) if self._faults else None

    def _injection(self, verb: str) -> Injection | None:
        with self._lock:
            queue = self._injections.get(verb)
            return queue.pop(0) if queue else None

    # -- the door --------------------------------------------------------------------------

    def _accept_loop(self) -> None:
        while True:
            try:
                sock, address = self._listener.accept()
            except OSError:  # stop() closed the listener
                return
            self.connections += 1
            self._spawn(self._serve, self._track(sock), address[0])

    def _serve(self, sock: socket.socket, client: str) -> None:
        conn = ControlConnection(sock, client)
        try:
            if self.tunnel is not None:
                tunnel = self.tunnel()
                if self.handshake_reply is not None:
                    conn.read_token()
                    sock.sendall(self.handshake_reply)
                    return
                tunnel.handshake(conn, client)
                conn.tunnel = tunnel
            control = _Control(conn)
            while True:
                line = conn.read_line()
                self.log.append(line)
                if not self._command(control, client, tokenize(line)):
                    return
        except (GError, GSIError, OSError, EOFError):
            return
        finally:
            conn.close()

    def _command(self, control: _Control, client: str, tokens: list[str]) -> bool:
        if len(tokens) < 4:
            return True
        session, command_id, verb, args = int(tokens[0]), int(tokens[1]), tokens[3], tokens[4:]
        injected = self._injection(verb)
        if callable(injected):
            injected = injected(session, args)
        if injected == DROP:
            return False
        if isinstance(injected, Raw):
            control.conn.sock.sendall(injected.data)
            return True
        if injected is not None:
            for line in injected.format(s=session, c=command_id).split("\n"):
                control.send(line)
            return True
        if verb == "hello":
            control.send(self.welcome)
            return True
        if verb == "byebye":
            return False
        handler = getattr(self, f"_do_{verb}", None)
        if handler is None:
            control.send(
                f'{session} {command_id} client failed 669 "protocolViolation : '
                f"Invalid command '{verb}'\""
            )
            return True
        reply = handler(control, client, session, command_id, args)
        if reply:
            control.send(reply.format(s=session, c=command_id))
        return True

    @staticmethod
    def _name(name: str) -> str:
        """The namespace path a request names (a URL, as ``java.net.URI`` decodes it, or a path)."""
        return urllib.parse.unquote(urllib.parse.urlsplit(name).path) if "://" in name else name

    def _path(self, name: str) -> Path:
        """The local file for the URL (or path) a request names."""
        return self.root / posixpath.normpath(self._name(name)).lstrip("/")

    # -- namespace ---------------------------------------------------------------------------

    def _stat(self, args: list[str], follow: bool) -> str:
        path = self._path(args[0])
        try:
            info = Stat.from_os(path.stat() if follow else path.lstat())
        except OSError:
            return _NOT_FOUND
        info.st_ino &= 0xFFFFFFF
        return "{s} {c} client stat " + stat_fields(info)

    def _do_stat(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        return self._stat(args, True)

    def _do_lstat(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        return self._stat(args, False)

    def _do_ping(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        return "{s} {c} server pong"

    def _do_unlink(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        path = self._path(args[0])
        if not path.exists():
            return _NOT_FOUND
        if path.is_dir():
            return '{s} {c} client failed 17 "Path is a Directory" EISDIR'
        path.unlink()
        return "{s} {c} client ok"

    def _do_rmdir(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        path = self._path(args[0])
        if not path.exists():
            return _NOT_FOUND
        if not path.is_dir():
            reason = "Path exists and has type REGULAR, which is not DIR"
            return f'{{s}} {{c}} client failed 23 "{reason}" EACCES'
        if any(path.iterdir()):
            reason = f"Directory is not empty: {self._name(args[0])}"
            return f'{{s}} {{c}} client failed 23 "{reason}" EACCES'
        path.rmdir()
        return "{s} {c} client ok"

    def _do_mkdir(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        path = self._path(args[0])
        if path.exists():
            return '{s} {c} client failed 20 "Directory exists" EEXIST'
        if not path.parent.is_dir():
            name = self._name(args[0])
            return f'{{s}} {{c}} client failed 10001 "No such file or directory: {name}" '
        path.mkdir()
        path.chmod(int(options(args).get("mode", "448"), 0))
        return "{s} {c} client ok"

    def _do_chmod(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        path = self._path(args[0])
        if not path.exists():
            return _NOT_FOUND
        path.chmod(int(options(args)["mode"], 0))
        return "{s} {c} client ok"

    def _do_rename(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        path = self._path(args[0])
        if not path.exists():
            return _NOT_FOUND
        try:
            path.rename(self._path(args[1]))
        except OSError as exc:
            return f'{{s}} {{c}} client failed 19 "{exc.strerror}" EACCES'
        return "{s} {c} client ok"

    # -- transfers ---------------------------------------------------------------------------

    def _do_open(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        path = self._path(args[0])
        mode, flags = args[1], options(args)
        writing = "w" in mode
        if not path.exists():
            if not writing:
                return '{s} {c} client failed 2 "No such file or directory" '
            if not path.parent.is_dir():
                return '{s} {c} client failed 1 "Parent directory does not exist" '
            path.touch()
            path.chmod(int(flags.get("mode", "0600"), 8))
        elif not path.is_file():
            return '{s} {c} client failed 1 "Not a File" '
        elif writing and path.stat().st_size:
            if "truncate" not in flags or not self.truncate:
                return '{s} {c} client failed 1 "File is readOnly" '
            path.write_bytes(b"")
        positional = [arg for arg in args[2:] if not arg.startswith("-")]
        target = (client, int(positional[1]))
        self._spawn(self._transfer, control, s, c, _Mover(self, path, writing), target)
        return ""

    def _transfer(
        self, control: _Control, s: int, c: int, mover: _Mover, target: tuple[str, int]
    ) -> None:
        sock = self._data_connection(control, s, c, target)
        if sock is None:
            mover.file.close()
            return
        failed = mover.run(sock)
        self.checksums.append(mover.checksum)
        try:
            if failed:
                control.send(f"{s} {c} client failed {failed}")
            else:
                control.send(f"{s} {c} client ok")
        except (GError, OSError):
            pass

    def _data_connection(
        self, control: _Control, s: int, c: int, target: tuple[str, int]
    ) -> socket.socket | None:
        """The pool's end: call the client back, or listen and tell it where."""
        if self.callback:
            return self._call_back(s, target)
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.bind((self.host, 0))
            listener.listen(1)
            listener.settimeout(self.accept_timeout)
            challenge = base64.b64encode(uuid.uuid4().bytes).decode()
            control.send(
                f"{s} {c} client connect {self.host} {listener.getsockname()[1]} {challenge}"
            )
            while True:
                try:
                    sock, _ = listener.accept()
                except OSError:
                    return None
                self._track(sock)
                try:
                    session = _recv_int(sock)
                    token = _recv_exact(sock, _recv_int(sock)).decode()
                except (EOFError, OSError):
                    sock.close()
                    continue
                if session == s and token == challenge:
                    return sock
                sock.close()

    def _call_back(self, s: int, target: tuple[str, int]) -> socket.socket | None:
        if self.decoy_callback:
            with socket.create_connection(target, timeout=10) as decoy:
                decoy.sendall(HEADER.pack(s + 1000, 0))
                decoy.recv(1)  # wait for the client to hang up on it
        try:
            sock = self._track(socket.create_connection(target, timeout=10))
            sock.sendall(HEADER.pack(s, 0))
        except OSError:  # refused, or the client gave up on us
            return None
        return sock

    def _do_opendir(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        path = self._path(args[0])
        if not path.exists():
            return _NOT_FOUND
        if not path.is_dir():
            # dCache 11 checks LIST_DIRECTORY first, which a file fails like a missing path
            return '{s} {c} client failed 10018 "No such file or directory" ENOENT'
        lines = []
        for entry in sorted(path.iterdir()):
            info = entry.lstat()
            kind = "d" if _stat.S_ISDIR(info.st_mode) else "f"
            lines.append(f"{info.st_ino:024X}:{kind}:{info.st_size}:{entry.name}\n")
        listing = "".join(lines).encode()
        self._spawn(self._list, (args[1], int(args[2])), s, listing)
        return ""

    def _list(self, target: tuple[str, int], s: int, listing: bytes) -> None:
        """``DirectoryLookUpPool``: connect to the client, serve READs of the listing."""
        sock = self._call_back(s, target)
        if sock is None:
            return
        index = 0
        try:
            while True:
                body = _recv_exact(sock, _recv_int(sock))
                command = INT.unpack_from(body)[0]
                self.data_log.append(command)
                fault = self._take_fault()
                if fault == "hangup":
                    return
                if command == IOCMD_CLOSE:
                    sock.sendall(_ack(IOCMD_CLOSE))
                    return
                (count,) = struct.unpack_from(">q", body, 4)
                chunk = listing[index : index + count]
                index += len(chunk)
                sock.sendall(
                    _ack(IOCMD_READ)
                    + _DATA_HEADER
                    + INT.pack(len(chunk))
                    + chunk
                    + INT.pack(-1)
                    + _fin(IOCMD_READ)
                )
        except (EOFError, OSError):
            return
        finally:
            sock.close()
