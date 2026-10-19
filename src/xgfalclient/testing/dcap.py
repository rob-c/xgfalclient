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
  :class:`~xrdsec.gsi.gss.SecurityContext`) when ``gsi`` is given;
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

How it is put together: one daemon thread accepts control connections and
one more serves each of them (:meth:`DcapServer._serve`). ``open`` and
``opendir`` answer nothing on the control line straight away; they spawn a
transfer thread that makes the data connection, runs a :class:`_Mover` (or
the directory lister) and only then sends the session's ``ok``/``failed``.
That is why control writes go through :class:`_Control`'s lock: a transfer
thread and the connection's own thread can both be answering at once, just
as a real door relays pool replies while it reads new requests.

The wire format comes from :mod:`xgfalclient.plugins.dcap.protocol`, which
the client shares; a change to a reply shape belongs there, not here. Where
this door deliberately differs from dCache (no PNFS IDs, no pool selection,
inode numbers masked to 28 bits, one fixed welcome line) the comment at that
spot says so. To model a new verb, add a ``_do_<verb>`` method with the
signature of the others; :meth:`DcapServer._command` finds it by name.
"""

from __future__ import annotations

import base64
import contextlib
import functools
import io
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

from xrdcore.sockets import recv_exact
from xrdsec.gsi.gss import GSIError
from xrdsec.testing.gsi import accept_tokens, acceptor

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

__all__ = ["DROP", "FAULTS", "DcapServer", "Raw", "ServerGSITunnel", "ServerKerberosTunnel"]

#: Inject this to have the door hang up instead of answering.
DROP = "<drop>"


@dataclass(frozen=True)
class Raw:
    """Inject bytes written to the socket as they are, past any tunnel.

    Line injections are framed (and, under GSI or Kerberos, wrapped) like any
    reply; ``Raw`` is for the tests that need the client to see something a
    well-behaved door never sends - a truncated line, garbage instead of an
    ``enc`` token, bytes after a hang-up.
    """

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

#: What :meth:`DcapServer.inject` accepts: a reply template, :data:`DROP`,
#: :class:`Raw` bytes, or a function of ``(session, args)`` choosing one.
Injection = str | Raw | Callable[[int, list[str]], str | Raw | None]

# Reads are sent in blocks of this size, as DCapProtocol_3_nio does: a 256 KiB
# buffer less the length field. Clients must cope with a read arriving in many
# blocks, and a block this size is what makes the tests exercise that.
_BLOCK = 256 * 1024 - 4
# dCache's reply when the namespace has no such path (CacheException 10001).
_NOT_FOUND = '{s} {c} client failed 10001 "No such file or directory" ENOENT'


class ServerGSITunnel(Tunnel):
    """The door's side of the GSI tunnel (dCache's ``DssSocket.verify``)."""

    def __init__(self, tls: ssl.SSLContext) -> None:
        """Build an acceptor over ``tls`` (a server context from :mod:`xgfalclient.testing.pki`)."""
        # dCache's ServerGsiEngine: no TLS 1.3 turn byte after the handshake.
        self.security = acceptor(tls, turn=False)

    def handshake(self, link: TokenLink, host: str) -> None:
        """Answer the client's ``enc`` tokens until the TLS handshake (and delegation) is done.

        The client speaks first, so each round reads a token and sends the
        reply, if any (:func:`xrdsec.testing.gsi.accept_tokens`);
        :class:`GSIError` from a bad token ends the connection in
        :meth:`DcapServer._serve`.
        """
        accept_tokens(self.security, link.read_token, link.send_token)

    def wrap(self, data: bytes) -> bytes:
        """Encrypt one control line into a TLS record for an ``enc`` token."""
        return self.security.wrap(data)

    def unwrap(self, token: bytes) -> bytes:
        """Decrypt one ``enc`` token from the client into its control line."""
        return self.security.unwrap(token)


class ServerKerberosTunnel(Tunnel):
    """The door's side of the Kerberos tunnel (:class:`xgfalclient.crypto.krb5.AcceptorContext`)."""

    def __init__(self, keytab: str | None = None) -> None:
        """Accept with the service key in ``keytab`` (``None``: the environment's default).

        :mod:`xgfalclient.crypto.krb5` needs the optional ``krb5``/``gssapi``
        bindings, so it is imported here rather than at module load: the rest
        of the door must work on machines without them.
        """
        from ..crypto import krb5

        self.security = krb5.AcceptorContext(keytab=keytab)

    def handshake(self, link: TokenLink, host: str) -> None:
        """Take the client's AP-REQ and answer with the AP-REP: one round trip."""
        # libdcap asks for mutual authentication, so the AP-REQ always earns an AP-REP.
        link.send_token(self.security.step(link.read_token()))

    def wrap(self, data: bytes) -> bytes:
        """Seal one control line with the established GSS-API context (``gss_wrap``)."""
        return bytes(self.security.wrap(data))

    def unwrap(self, token: bytes) -> bytes:
        """Open one sealed token from the client (``gss_unwrap``)."""
        return bytes(self.security.unwrap(token))

    def close(self) -> None:
        """Release the GSS-API context; the door calls it when the connection ends."""
        self.security.close()


class _Control:
    """The door's end of one control connection; several threads write to it."""

    def __init__(self, conn: ControlConnection) -> None:
        """Wrap ``conn``; the connection stays owned (and closed) by :meth:`DcapServer._serve`."""
        self.conn = conn
        self.lock = threading.Lock()

    def send(self, line: str) -> None:
        """Send one reply line whole.

        Transfer threads report ``ok``/``failed``/``connect`` while the
        connection's thread answers other sessions; under a tunnel each line is
        one wrapped token, so two unlocked writers would interleave records and
        corrupt the stream for the client.
        """
        with self.lock:
            self.conn.send_line(line)


def _recv_int(sock: socket.socket) -> int:
    """Read one big-endian signed 32-bit integer: a length, a command or a session."""
    return int(INT.unpack(recv_exact(sock, 4))[0])


def _ack(command: int, result: int = 0, message: str | None = None, extra: bytes = b"") -> bytes:
    """A framed ``ACK`` for ``command``, as ``DCapOutputByteBuffer.writeACK`` lays it out.

    ``[length][ACK][command][result]`` then ``extra`` (a SEEK's new offset, a
    LOCATE's size and position) and, on failure, a ``[u16 length][text]``
    message. ``result`` 0 is success; anything else is an error code the
    client reports with the message.
    """
    body = struct.pack(">iii", IOCMD_ACK, command, result) + extra
    if message is not None:
        text = message.encode()
        body += struct.pack(">H", len(text)) + text
    return INT.pack(len(body)) + body


def _fin(command: int, result: int = 0, message: str | None = None) -> bytes:
    """A framed ``FIN`` ending a READ or WRITE; laid out like :func:`_ack`, without extras.

    A failed FIN (``result`` != 0) is how a pool reports an error discovered
    after the transfer started, such as a full disk during a write.
    """
    body = struct.pack(">iii", IOCMD_FIN, command, result)
    if message is not None:
        text = message.encode()
        body += struct.pack(">H", len(text)) + text
    return INT.pack(len(body)) + body


# The ``[4][DATA]`` record that opens the block stream of a read (and of a write).
_DATA_HEADER = HEADER.pack(4, IOCMD_DATA)


def _fault_reply(command: int, fault: str | None) -> bytes | None:
    """The reply an injected reply fault sends in place of serving ``command``, if it is one."""
    if fault in ("ack-error", "ack-bare-error"):
        message = "Injected failure" if fault == "ack-error" else None
        return _ack(command, 33, message)
    if fault == "wrong-reply":
        return _fin(command)
    if fault == "wrong-command":
        return _ack(command + 100)
    if fault == "bad-length":
        return INT.pack(0)
    return None


class _Mover:
    """One transfer: the pool's end of the data connection.

    Requests are served strictly one at a time, in arrival order, which is
    what ``DCapProtocol_3_nio`` does and what the client's pipelining
    (several ``SEEK_AND_READ`` in flight) relies on: replies come back in
    request order. Each request first consults :meth:`DcapServer._take_fault`,
    so a test can make exactly the n-th data request misbehave.
    """

    def __init__(self, server: DcapServer, file: io.FileIO, path: Path, writable: bool) -> None:
        """Serve the transfer of ``path`` through ``file``, which the caller opened and closes.

        The file is opened read-write and unbuffered even for reads (see
        :meth:`DcapServer._transfer`) so that a write's bytes are on disk when
        CLOSE recomputes the ADLER32, and so that the door's own ``open``
        checks (which already created or truncated the file) are the only
        policy applied.
        """
        self.server = server
        self.path = path
        self.writable = writable
        self.file = file
        #: The ADLER32 the client sent with CLOSE (``None``: it sent none).
        self.checksum: int | None = None
        #: The ``failed`` reply text for the control line (``""``: report ``ok``).
        self.failed = ""

    def run(self, sock: socket.socket) -> str:
        """Serve requests until CLOSE or hang-up, then close ``sock``; the door's verdict.

        The verdict is ``""`` if all is well.
        """
        with sock, contextlib.suppress(EOFError, OSError):
            while self.serve(sock):
                pass
        return self.failed

    def serve(self, sock: socket.socket) -> bool:
        """Serve one framed request; ``False`` once the connection should end.

        Request bodies are ``[command][arguments]`` with big-endian fields:
        READ ``[i64 size]``; SEEK ``[i64 offset][i32 whence]``; SEEK_AND_READ
        ``[i64 offset][i32 whence][i64 size]``; SEEK_AND_WRITE ``[i64
        offset][i32 whence]``; CLOSE optionally ``[i32 12][i32 DATA_SUM]
        [i32 ADLER32][u32 value]``. Injected faults are applied before the
        request is looked at, so they work for every command.
        """
        length = _recv_int(sock)
        body = recv_exact(sock, length)
        command = INT.unpack_from(body)[0]
        self.server.data_log.append(command)
        fault = self.server._take_fault()
        if fault == "hangup":
            return False
        if fault == "stall":
            return True
        reply = _fault_reply(command, fault)
        if reply is not None:
            sock.sendall(reply)
            return True
        if command == IOCMD_READ:
            (size,) = struct.unpack_from(">q", body, 4)
            self.read(sock, IOCMD_READ, size, fault)
        elif command == IOCMD_SEEK_READ:
            offset, whence, size = struct.unpack_from(">qiq", body, 4)
            self.seek(offset, whence)
            self.read(sock, IOCMD_SEEK_READ, size, fault)
        elif command in (IOCMD_WRITE, IOCMD_SEEK_WRITE):
            self._write_request(sock, command, body, fault)
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
            self._close_request(sock, body, fault)
            return False
        else:
            # dCache's answer to an unknown command, down to the bogus 666.
            sock.sendall(_ack(666, 9, f"Invalid mover command : {command}"))
        return True

    def _write_request(
        self, sock: socket.socket, command: int, body: bytes, fault: str | None
    ) -> None:
        """WRITE or SEEK_AND_WRITE: refused on a mover opened for reading."""
        if not self.writable:
            sock.sendall(_ack(command, 1, "WRITE denied (not allowed)"))
            return
        if command == IOCMD_SEEK_WRITE:
            offset, whence = struct.unpack_from(">qi", body, 4)
            self.seek(offset, whence)
        self.write(sock, command, fault)

    def _close_request(self, sock: socket.socket, body: bytes, fault: str | None) -> None:
        """CLOSE: acknowledge it, then decide the verdict for the control line.

        A 20-byte body carries the client's ADLER32 at offset 16 (see
        :meth:`serve`'s docstring). The pool checks it against the file and
        fails the transfer on the control line, not on the data channel.
        """
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

    def seek(self, offset: int, whence: int) -> None:
        """Move the file position; dcap's whence values are mapped to :mod:`os`'s."""
        base = {SEEK_CURRENT: os.SEEK_CUR, SEEK_END: os.SEEK_END}.get(whence, os.SEEK_SET)
        self.file.seek(offset, base)

    def read(self, sock: socket.socket, command: int, size: int, fault: str | None) -> None:
        """Send up to ``size`` bytes from the current position.

        The reply is ``ACK``, ``[4][DATA]``, then ``[n][n bytes]`` blocks of at
        most :data:`_BLOCK`, a ``-1`` terminator and a ``FIN``. A read at end
        of file sends no blocks at all - just the terminator - which is how the
        client learns it hit EOF. ``overflow`` sends more than was asked so
        the client's length check is exercised.
        """
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
        """Receive one WRITE: ``ACK``, then the client's ``[DATA]`` and blocks, then ``FIN``.

        The blocks are copied straight to the file as they arrive (in pieces of
        up to 1 MiB, however the client chunked them) until the ``-1``
        terminator; a hang-up mid-block raises :class:`EOFError`, which ends the
        mover without a FIN, as a pool would.
        """
        sock.sendall(_ack(command))
        length = _recv_int(sock)
        if INT.unpack(recv_exact(sock, length)[:4])[0] != IOCMD_DATA:
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
    """A threaded dcap door over ``root``; see the module docstring.

    Use it as a context manager (or :meth:`start`/:meth:`stop`). The listener
    is bound in the constructor, so :attr:`port` and :meth:`url` are valid
    before the door starts. The public attributes set in the constructor are
    knobs and records for tests: change the knobs before the client connects,
    read the records after it is done (they are appended to from server
    threads without a lock, which the GIL makes safe for ``list.append``).
    """

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
        """Bind a listener on ``host`` (an ephemeral port) serving files under ``root``.

        ``gsi`` makes it a gsidcap door with that server TLS context;
        ``tunnel`` is the general form (a factory called once per connection,
        e.g. ``ServerKerberosTunnel``) and is overridden by ``gsi``. ``scheme``
        only changes what :meth:`url` prints. ``callback``, ``truncate`` and
        ``accept_timeout`` set the attributes of the same names.
        """
        self.root = Path(root)
        if gsi is not None:
            tunnel = functools.partial(ServerGSITunnel, gsi)
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
        """Start accepting connections on a daemon thread; returns ``self`` for chaining."""
        self._spawn(self._accept_loop)
        return self

    def stop(self) -> None:
        """Close the listener and every tracked socket, then join the threads (5 s each).

        Closing the sockets is what unblocks the serving threads: each is
        parked in a ``recv`` and returns on the resulting ``OSError``/EOF.
        Threads are daemons, so one that will not finish never keeps the test
        process alive.
        """
        # Linux does not wake a thread blocked in accept() when the listener is
        # merely closed (macOS does); a shutdown does, so stop() takes no 5 s join.
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()
        with self._lock:
            sockets = list(self._sockets)
        for sock in sockets:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        for thread in self._threads:
            thread.join(5)

    def __enter__(self) -> DcapServer:
        """Start the door (see :meth:`start`)."""
        return self.start()

    def __exit__(self, *exc: object) -> None:
        """Stop the door (see :meth:`stop`), whether or not the block raised."""
        self.stop()

    def _spawn(self, target: Callable[..., object], *args: object) -> None:
        """Run ``target(*args)`` on a daemon thread that :meth:`stop` will join."""
        thread = threading.Thread(target=target, args=args, daemon=True, name="xgfal-dcapd")
        self._threads.append(thread)
        thread.start()

    def _track(self, sock: socket.socket) -> socket.socket:
        """Remember ``sock`` so :meth:`stop` can shut it down; returns it unchanged."""
        with self._lock:
            self._sockets.add(sock)
        return sock

    # -- addressing ----------------------------------------------------------------------

    def url(self, path: str, *, host: str | None = None) -> str:
        """The client URL for ``path`` on this door (IPv6 literals bracketed per RFC 3986).

        ``host`` replaces the address in the URL only - the tests use it to
        reach the door by name, e.g. ``localhost`` for Kerberos principals.
        """
        name = host or (f"[{self.host}]" if ":" in self.host else self.host)
        return f"{self.scheme}://{name}:{self.port}{path}"

    def local(self, path: str) -> Path:
        """The file under :attr:`root` behind namespace ``path``, for tests to seed or inspect."""
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
        """Consume the next queued data-channel fault, or ``None`` to behave normally."""
        with self._lock:
            return self._faults.pop(0) if self._faults else None

    def _injection(self, verb: str) -> Injection | None:
        """Consume the next injected reply queued for ``verb``, if any."""
        with self._lock:
            queue = self._injections.get(verb)
            return queue.pop(0) if queue else None

    # -- the door --------------------------------------------------------------------------

    def _accept_loop(self) -> None:
        """Accept control connections until :meth:`stop`; one serving thread each."""
        while True:
            try:
                sock, address = self._listener.accept()
            except OSError:  # stop() closed the listener
                return
            self.connections += 1
            self._spawn(self._serve, self._track(sock), address[0])

    def _serve(self, sock: socket.socket, client: str) -> None:
        """Run one control connection: optional tunnel handshake, then request lines.

        The door reuses the client's :class:`ControlConnection` for framing
        (line reading, ``enc`` tokens), which keeps both ends on one codec.
        Any protocol, security or socket error simply ends the connection, as
        a door would drop a misbehaving client; the test sees it as a hang-up.
        """
        conn = ControlConnection(sock, client)
        try:
            if self.tunnel is not None:
                tunnel = self.tunnel()
                # handshake_reply: read the client's first token, answer with
                # garbage and hang up, to test the client's handshake errors.
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
        """Answer one request ``<session> <id> client <verb> [args...]``; ``False`` hangs up.

        Injections take precedence over the built-in behaviour, which is
        dispatched by name to ``_do_<verb>``. Handlers return a reply template
        (``{s}``/``{c}`` filled in here) or ``""`` when a transfer thread will
        answer later. An unknown verb gets dCache's ``protocolViolation``.
        """
        if len(tokens) < 4:  # not a request line: dCache ignores it too
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
        """The ``stat`` reply for ``args[0]``: ``-st_size=... -st_mode=...`` options."""
        path = self._path(args[0])
        try:
            info = Stat.from_os(path.stat() if follow else path.lstat())
        except OSError:
            return _NOT_FOUND
        # dCache derives st_ino from the PNFS ID and it fits in 28 bits; a real
        # 64-bit inode here would test a case no door produces.
        info.st_ino &= 0xFFFFFFF
        return "{s} {c} client stat " + stat_fields(info)

    # Every ``_do_<verb>`` takes ``(control, client, session, command id, args)``
    # and returns a reply template; dCache's CacheException codes (10001
    # not found, 17/20/23 namespace conflicts, ...) and the errno names after
    # the quoted message are what libdcap's str2errno maps, so keep them exact.

    def _do_stat(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        """``stat <url>``: following symbolic links."""
        return self._stat(args, True)

    def _do_lstat(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        """``lstat <url>``: describing a symbolic link itself."""
        return self._stat(args, False)

    def _do_ping(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        """``ping``: the keep-alive libdcap sends on an idle connection."""
        return "{s} {c} server pong"

    def _do_unlink(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        """``unlink <url>``: files only; a directory fails with EISDIR as in dCache."""
        path = self._path(args[0])
        if not path.exists():
            return _NOT_FOUND
        if path.is_dir():
            return '{s} {c} client failed 17 "Path is a Directory" EISDIR'
        path.unlink()
        return "{s} {c} client ok"

    def _do_rmdir(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        """``rmdir <url>``: dCache reports both "not a directory" and "not empty" as EACCES."""
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
        """``mkdir <url> -mode=<decimal>``: a single level; the mode defaults to 0700."""
        path = self._path(args[0])
        if path.exists():
            return '{s} {c} client failed 20 "Directory exists" EEXIST'
        if not path.parent.is_dir():
            name = self._name(args[0])
            return f'{{s}} {{c}} client failed 10001 "No such file or directory: {name}" '
        path.mkdir()
        # chmod after mkdir so the requested mode is not filtered by our umask;
        # "448" is 0o700, libdcap sends the mode in decimal.
        path.chmod(int(options(args).get("mode", "448"), 0))
        return "{s} {c} client ok"

    def _do_chmod(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        """``chmod <url> -mode=<n>``."""
        path = self._path(args[0])
        if not path.exists():
            return _NOT_FOUND
        path.chmod(int(options(args)["mode"], 0))
        return "{s} {c} client ok"

    def _do_rename(self, control: _Control, client: str, s: int, c: int, args: list[str]) -> str:
        """``rename <from> <to>``: any OS refusal comes back as EACCES with its text."""
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
        """``open <url> <r|w> <host> <port> [-mode=...] [-truncate] ...``: start a mover.

        The namespace checks happen here and fail on the control line, as the
        door's do; on success nothing is sent yet - :meth:`_transfer` connects
        the data channel and reports the outcome when the client closes.
        ``<host> <port>`` is the client's callback address, used only when
        :attr:`callback` is set.
        """
        path = self._path(args[0])
        mode, flags = args[1], options(args)
        writing = "w" in mode
        if not path.exists():
            if not writing:
                return '{s} {c} client failed 2 "No such file or directory" '
            if not path.parent.is_dir():
                return '{s} {c} client failed 1 "Parent directory does not exist" '
            path.touch()
            path.chmod(int(flags.get("mode", "0600"), 8))  # octal here, unlike mkdir
        elif not path.is_file():
            return '{s} {c} client failed 1 "Not a File" '
        elif writing and path.stat().st_size:
            # dCache files are write-once: rewriting needs -truncate *and* the
            # door's permission (dcap.authz.truncate).
            if "truncate" not in flags or not self.truncate:
                return '{s} {c} client failed 1 "File is readOnly" '
            path.write_bytes(b"")
        positional = [arg for arg in args[2:] if not arg.startswith("-")]
        target = (client, int(positional[1]))
        self._spawn(self._transfer, control, s, c, path, writing, target)
        return ""

    def _transfer(
        self, control: _Control, s: int, c: int, path: Path, writing: bool, target: tuple[str, int]
    ) -> None:
        """Connect the data channel, run a :class:`_Mover` and report on the control line.

        If the client never connects (or hangs up before the session check)
        nothing is reported at all, matching a mover that timed out; the
        client's own timeout is what the tests then observe.
        """
        with open(path, "r+b", buffering=0) as file:
            mover = _Mover(self, file, path, writing)
            sock = self._data_connection(control, s, c, target)
            if sock is None:
                return
            failed = mover.run(sock)
        self.checksums.append(mover.checksum)
        try:
            if failed:
                control.send(f"{s} {c} client failed {failed}")
            else:
                control.send(f"{s} {c} client ok")
        except (GError, OSError):  # the control connection is already gone
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
            # A passive mover proves the connection is the client's by a random
            # challenge sent on the (authenticated) control line; the client
            # opens the data channel with [session][length][challenge].
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
                    token = recv_exact(sock, _recv_int(sock)).decode()
                except (EOFError, OSError):
                    sock.close()
                    continue
                if session == s and token == challenge:
                    return sock
                sock.close()  # a stray or forged connection: keep waiting for ours

    def _call_back(self, s: int, target: tuple[str, int]) -> socket.socket | None:
        """Connect to the client's listener and announce ``[session][0]``, as old pools do.

        With :attr:`decoy_callback` a connection carrying the wrong session
        comes first; the client must reject it and keep listening, since
        several movers can call back to one listener.
        """
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
        """``opendir <url> <host> <port>``: build the listing and have the lister call back.

        Each entry is ``<id>:<d|f>:<size>:<name>\n``, the id being the inode
        as 24 hex digits in place of a PNFS ID. The listing is snapshotted
        here, so entries created during the read are not seen - as with
        ``DirectoryLookUpPool``.
        """
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
                body = recv_exact(sock, _recv_int(sock))
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
