"""Talking to one LFC: connections, sessions, and the Cns API calls gfal2 uses.

**Connections.** liblfc opens a TCP connection per request, authenticates
it with Csec, sends the request and reads until ``CNS_RC``, after which the
server hangs up (``send2nsd.c``). That costs a full GSI handshake - an RSA
signature at each end - for every ``stat``. A *session*
(``Cns_startsess``) keeps the connection: the server's ``procsessreq`` loop
answers each request with ``CNS_IRC`` instead and waits for the next, until
``Cns_endsess`` or 60 idle seconds (``CNS_TRANSTIMEOUT``). So each
connection here starts a session straight after Csec and goes back to a
small per-server pool after each request. gfal2 2.x switched its own
session reuse off ("unstable" in liblfc's global, thread-unsafe state);
this pool has none of that state - a connection belongs to one caller at a
time - but ``[LFC PLUGIN] SESSION_REUSE=false`` restores one connection per
request.

A pooled connection that went quiet past the server's idle limit has been
answered with a final ``CNS_RC`` (``SETIMEDOUT``) and closed; it is never
reused - connections idle for :data:`MAX_IDLE_SECONDS` are dropped, and one
with anything waiting to be read is stale. A request that fails on a
reused connection before a byte of reply arrived is retried once on a
fresh one.

**Listings** (``Cns_opendir``/``readdirx``/``closedir``) run on a
connection of their own for their whole length, as in liblfc, and are read
to the end at once: the server keeps a thread per open listing
(``procdirreq``), and a listing abandoned half-way would hold it for five
minutes.

**Calls.** Each function builds the request body exactly as the matching
``ns/Cns_*.c`` does (magic, field order, the ``cwd`` of ``0`` - paths here
are always absolute) and decodes the reply the same way.
"""

from __future__ import annotations

import errno
import logging
import os
import select
import socket
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ..._compat import SLOTS, TIMEOUTS
from ...errors import GError
from . import wire
from .csec import Mechanism, authenticate
from .wire import Packer, Unpacker, WireError

__all__ = [
    "CnsError",
    "Connection",
    "Server",
    "Reply",
    "FileStat",
    "Replica",
    "DirEntry",
    "MAX_IDLE_SECONDS",
    "MAX_POOL",
]

_log = logging.getLogger("xgfalclient.plugins.lfc")

#: Connections idle longer than this are closed rather than reused; the
#: server gives up on a session after 60 seconds.
MAX_IDLE_SECONDS = 45.0
#: Idle sessions kept per server: each holds one of the server's threads.
MAX_POOL = 4

#: The size of liblfc's ``struct Cns_direnstat`` up to ``d_name`` on LP64
#: Linux; the server uses it to size listing batches.
DIRENTSZ = 62


class CnsError(GError):
    """The server refused a request: ``serrno`` is its code, ``code`` the errno."""

    def __init__(self, serrno: int, messages: Sequence[str] = ()) -> None:
        super().__init__(wire.serrno_text(serrno), wire.errno_for(serrno))
        self.serrno = serrno
        self.messages = list(messages)


def socket_error(exc: BaseException, what: str) -> GError:
    """A ``GError`` for a failed socket call, keeping its ``errno``."""
    if isinstance(exc, TIMEOUTS):
        return GError(f"{what}: timed out", errno.ETIMEDOUT)
    code = getattr(exc, "errno", None) or errno.ECONNRESET
    return GError(f"{what}: {exc}", code)


@dataclass
class Reply:
    """Everything the server sent for one request, up to its status."""

    status: int = 0
    data: bytearray = field(default_factory=bytearray)
    #: Payloads of list messages (``MSG_LINKS``, ``MSG_REPLIC``...), by type.
    lists: dict[int, list[bytes]] = field(default_factory=dict)
    #: ``MSG_ERR`` texts, which liblfc prints on stderr.
    errors: list[str] = field(default_factory=list)
    #: ``CNS_RC``: the server has closed the connection.
    final: bool = False

    def check(self) -> Reply:
        if self.status:
            raise CnsError(self.status, self.errors)
        return self

    def reader(self) -> Unpacker:
        return Unpacker(self.data)


class Connection:
    """One authenticated connection, in a session or not."""

    def __init__(self, sock: socket.socket, peer: str) -> None:
        self.sock = sock
        self.peer = peer
        self.session = False
        self.closed = False
        self.reused = False
        self.received = 0
        self.idle_since = time.monotonic()

    # -- the byte stream ------------------------------------------------------------

    def send(self, data: bytes) -> None:
        try:
            self.sock.sendall(data)
        except OSError as exc:
            self.close()
            raise socket_error(exc, f"Lost the connection to the LFC {self.peer}") from exc

    def _exact(self, size: int) -> bytes:
        buffer = bytearray(size)
        view = memoryview(buffer)
        got = 0
        try:
            while got < size:
                count = self.sock.recv_into(view[got:])
                if not count:
                    raise GError(f"The LFC {self.peer} closed the connection", errno.ECONNRESET)
                got += count
                self.received += count
        except OSError as exc:
            self.close()
            raise socket_error(exc, f"Lost the connection to the LFC {self.peer}") from exc
        except GError:
            self.close()
            raise
        return bytes(buffer)

    def call(self, magic: int, kind: int, body: bytes = b"") -> Reply:
        """Send one request and read until its status (``send2nsdx``)."""
        self.send(wire.request(magic, kind, body))
        return self.read_reply()

    def read_reply(self) -> Reply:
        reply = Reply()
        while True:
            _, rep_type, value = wire.HEADER.unpack(self._exact(wire.HEADER.size))
            if rep_type in (wire.CNS_RC, wire.CNS_IRC):
                reply.status = value
                if rep_type == wire.CNS_RC:
                    reply.final = True
                    self.close()
                return reply
            if not 0 <= value <= wire.REPBUFSZ:
                self.close()
                raise WireError(f"a reply of {value} bytes (the limit is {wire.REPBUFSZ})")
            payload = self._exact(value)
            if rep_type == wire.MSG_ERR:
                text = payload.split(b"\0", 1)[0].decode("utf-8", "replace").rstrip("\n")
                _log.warning("LFC %s: %s", self.peer, text)
                reply.errors.append(text)
            elif rep_type == wire.MSG_DATA:
                reply.data += payload
            else:
                reply.lists.setdefault(rep_type, []).append(payload)

    def stale(self) -> bool:
        """Whether the server has spoken (or hung up) while we were not asking."""
        if self.closed or time.monotonic() - self.idle_since > MAX_IDLE_SECONDS:
            return True
        readable, _, _ = select.select([self.sock], [], [], 0)
        return bool(readable)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.sock.close()


def _ids() -> Packer:
    """``uid``/``gid`` as every request starts; the server trusts Csec instead."""
    return (
        Packer().long(getattr(os, "geteuid", lambda: 0)()).long(getattr(os, "getegid", lambda: 0)())
    )


_umask_lock = threading.Lock()
_umask: list[int] = []


def process_umask() -> int:
    """liblfc's ``thip->mask``: the process umask, read once."""
    with _umask_lock:
        if not _umask:
            mask = os.umask(0)
            os.umask(mask)
            _umask.append(mask)
        return _umask[0]


# -- records -------------------------------------------------------------------------


@dataclass(**SLOTS)
class FileStat:
    """``struct Cns_filestatg`` (``guid`` and checksum empty for a plain stat)."""

    fileid: int
    mode: int
    nlink: int
    uid: int
    gid: int
    size: int
    atime: int
    mtime: int
    ctime: int
    fileclass: int
    status: str
    guid: str = ""
    csumtype: str = ""
    csumvalue: str = ""


@dataclass(**SLOTS)
class DirEntry:
    """One ``Cns_direnstat`` from a listing: a name and its stat."""

    name: str
    stat: FileStat


@dataclass(**SLOTS)
class Replica:
    """``struct Cns_filereplica``."""

    fileid: int
    nbaccesses: int
    atime: int
    ptime: int
    status: str
    f_type: str
    poolname: str
    host: str
    fs: str
    sfn: str


def _stat(reader: Unpacker, with_guid: bool) -> FileStat:
    fileid = reader.hyper()
    guid = reader.string(wire.MAXGUIDLEN) if with_guid else ""
    record = FileStat(
        fileid,
        reader.word(),
        reader.long(),
        reader.ulong(),
        reader.ulong(),
        reader.hyper(),
        reader.time(),
        reader.time(),
        reader.time(),
        reader.word(),
        chr(reader.byte()),
        guid,
    )
    if with_guid:
        record.csumtype = reader.string(2)
        record.csumvalue = reader.string(32)
    return record


def _replicas(payloads: list[bytes]) -> list[Replica]:
    found = []
    for payload in payloads:
        reader = Unpacker(payload)
        while not reader.at_end():
            found.append(
                Replica(
                    reader.hyper(),
                    reader.hyper(),
                    reader.time(),
                    reader.time(),
                    chr(reader.byte()),
                    chr(reader.byte()),
                    reader.string(),
                    reader.string(),
                    reader.string(),
                    reader.string(),
                )
            )
    return found


def _strings(payloads: list[bytes]) -> list[str]:
    found = []
    for payload in payloads:
        reader = Unpacker(payload)
        while not reader.at_end():
            found.append(reader.string())
    return found


def _longs(payloads: list[bytes]) -> list[int]:
    found = []
    for payload in payloads:
        reader = Unpacker(payload)
        while not reader.at_end():
            found.append(reader.long())
    return found


# -- the server and its pool --------------------------------------------------------------

Connect = Callable[[], socket.socket]


class Server:
    """One LFC endpoint for one identity: a pool of authenticated connections."""

    def __init__(
        self,
        host: str,
        port: int,
        mechanisms: Callable[[], Sequence[Mechanism]],
        *,
        timeout: float = 300.0,
        connect_timeout: float = 120.0,
        retries: int = 0,
        retry_interval: float = 60.0,
        sessions: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.peer = f"{host}:{port}"
        self.mechanisms = mechanisms
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.retries = retries
        self.retry_interval = retry_interval
        self.sessions = sessions
        self._idle: list[Connection] = []
        self._lock = threading.Lock()

    # -- connecting -------------------------------------------------------------------

    def _socket(self) -> socket.socket:
        """``send2nsd``'s connect loop: every address, ``LFC_CONRETRY`` more rounds."""
        failure: GError | None = None
        for attempt in range(self.retries + 1):
            if attempt:
                time.sleep(self.retry_interval)
            try:
                addresses = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise GError(
                    f"Cannot resolve the LFC host {self.host}: {exc}", errno.EHOSTUNREACH
                ) from exc
            for family, kind, proto, _, address in addresses:
                sock = socket.socket(family, kind, proto)
                sock.settimeout(self.connect_timeout)
                try:
                    sock.connect(address)
                except OSError as exc:
                    sock.close()
                    if isinstance(exc, ConnectionRefusedError):
                        failure = GError(
                            f"Name server not active on {self.peer}", errno.ECONNREFUSED
                        )
                    else:
                        failure = socket_error(exc, f"Cannot connect to the LFC {self.peer}")
                    continue
                sock.settimeout(self.timeout)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return sock
        assert failure is not None
        raise failure

    def connect(self) -> Connection:
        """A new authenticated connection, in a session if sessions are on."""
        sock = self._socket()
        conn = Connection(sock, self.peer)
        try:
            mech = authenticate(sock, self.peer, self.host, self.mechanisms())
            _log.debug("LFC %s: authenticated with %s", self.peer, mech)
            if self.sessions:
                body = _ids().string("xgfalclient session").bytes()
                conn.call(wire.MAGIC, wire.STARTSESS, body).check()
                conn.session = True
        except BaseException:
            conn.close()
            raise
        return conn

    # -- the pool ---------------------------------------------------------------------

    def acquire(self) -> Connection:
        while True:
            with self._lock:
                conn = self._idle.pop() if self._idle else None
            if conn is None:
                return self.connect()
            if not conn.stale():
                return conn
            conn.close()

    def release(self, conn: Connection) -> None:
        if conn.session and not conn.closed:
            conn.reused = True
            conn.idle_since = time.monotonic()
            with self._lock:
                if len(self._idle) < MAX_POOL:
                    self._idle.append(conn)
                    return
            self._end(conn)
        conn.close()

    def _end(self, conn: Connection) -> None:
        """``Cns_endsess``, best effort: the server answers ``CNS_RC`` and hangs up."""
        try:
            conn.call(wire.MAGIC, wire.ENDSESS, _ids().bytes())
        except GError:
            pass
        conn.close()

    def close(self) -> None:
        with self._lock:
            idle, self._idle = self._idle, []
        for conn in idle:
            self._end(conn)

    def run(self, exchange: Callable[[Connection], Reply]) -> Reply:
        """``exchange`` on a pooled connection, retried once if that one was dead."""
        while True:
            conn = self.acquire()
            before = conn.received
            try:
                reply = exchange(conn)
            except GError as exc:
                conn.close()
                if conn.reused and conn.received == before and exc.code != errno.ETIMEDOUT:
                    continue
                raise
            except BaseException:
                conn.close()
                raise
            if reply.final:
                conn.session = False
            self.release(conn)
            return reply

    def call(self, magic: int, kind: int, body: bytes = b"") -> Reply:
        return self.run(lambda conn: conn.call(magic, kind, body))

    # -- the API ------------------------------------------------------------------------

    def ping(self) -> str:
        """``Cns_ping``: the server's version string."""
        return self.call(wire.MAGIC, wire.PING, _ids().bytes()).check().reader().string()

    def stat(self, path: str) -> FileStat:
        body = _ids().hyper(0).hyper(0).string(path).bytes()
        return _stat(self.call(wire.MAGIC, wire.STAT, body).check().reader(), False)

    def lstat(self, path: str) -> FileStat:
        body = _ids().hyper(0).hyper(0).string(path).bytes()
        return _stat(self.call(wire.MAGIC2, wire.LSTAT, body).check().reader(), False)

    def statg(self, path: str | None, guid: str | None = None) -> FileStat:
        body = _ids().hyper(0).string(path or "").string(guid or "").bytes()
        return _stat(self.call(wire.MAGIC, wire.STATG, body).check().reader(), True)

    def statr(self, sfn: str) -> FileStat:
        body = _ids().string(sfn).bytes()
        return _stat(self.call(wire.MAGIC, wire.STATR, body).check().reader(), True)

    def access(self, path: str, mode: int) -> None:
        uid = getattr(os, "getuid", lambda: 0)()
        gid = getattr(os, "getgid", lambda: 0)()
        body = Packer().long(uid).long(gid).hyper(0).string(path).long(mode).bytes()
        self.call(wire.MAGIC, wire.ACCESS, body).check()

    def chmod(self, path: str, mode: int) -> None:
        body = _ids().hyper(0).string(path).long(mode & 0o7777).bytes()
        self.call(wire.MAGIC, wire.CHMOD, body).check()

    def mkdir(self, path: str, guid: str, mode: int) -> None:
        """``Cns_mkdirg``: the directory gets ``guid``, and the umask applies."""
        body = (
            _ids()
            .word(process_umask())
            .hyper(0)
            .string(path)
            .long(mode & 0o7777)
            .string(guid)
            .bytes()
        )
        self.call(wire.MAGIC2, wire.MKDIR, body).check()

    def creat(self, path: str, guid: str, mode: int) -> int:
        """``Cns_creatg``: a file entry with ``guid``; its file id."""
        body = _ids().word(process_umask()).hyper(0).string(path).long(mode).string(guid).bytes()
        return self.call(wire.MAGIC2, wire.CREAT, body).check().reader().hyper()

    def rmdir(self, path: str) -> None:
        self.call(wire.MAGIC, wire.RMDIR, _ids().hyper(0).string(path).bytes()).check()

    def unlink(self, path: str) -> None:
        self.call(wire.MAGIC, wire.UNLINK, _ids().hyper(0).string(path).bytes()).check()

    def delfiles(self, paths: Sequence[str], force: bool) -> list[int]:
        """``Cns_delfilesbyname``: one status per path; ``force`` drops replicas too."""
        body = _ids().word(1).word(int(force)).hyper(0).long(len(paths))
        for path in paths:
            body.string(path)
        reply = self.call(wire.MAGIC, wire.DELFILES, body.bytes()).check()
        statuses = _longs(reply.lists.get(wire.MSG_STATUSES, []))
        count = reply.reader().long()
        return statuses[:count]

    def rename(self, old: str, new: str) -> None:
        body = _ids().hyper(0).string(old).string(new).bytes()
        self.call(wire.MAGIC, wire.RENAME, body).check()

    def symlink(self, target: str, link: str) -> None:
        body = _ids().hyper(0).string(target).string(link).bytes()
        self.call(wire.MAGIC, wire.SYMLINK, body).check()

    def readlink(self, path: str) -> str:
        body = _ids().hyper(0).string(path).bytes()
        return self.call(wire.MAGIC, wire.READLINK, body).check().reader().string()

    def getcomment(self, path: str) -> str:
        body = _ids().hyper(0).string(path).bytes()
        return self.call(wire.MAGIC, wire.GETCOMMENT, body).check().reader().string()

    def setcomment(self, path: str, comment: str) -> None:
        body = _ids().hyper(0).string(path).string(comment).bytes()
        self.call(wire.MAGIC, wire.SETCOMMENT, body).check()

    def setfsizeg(self, guid: str, size: int, csumtype: str, csumvalue: str) -> None:
        body = _ids().string(guid).hyper(size).string(csumtype).string(csumvalue).bytes()
        self.call(wire.MAGIC, wire.SETFSIZEG, body).check()

    def getreplica(
        self, path: str | None, guid: str | None = None, se: str | None = None
    ) -> list[Replica]:
        body = _ids().hyper(0).string(path or "").string(guid or "").string(se or "").bytes()
        reply = self.call(wire.MAGIC, wire.GETREPLICA, body).check()
        return _replicas(reply.lists.get(wire.MSG_REPLIC, []))

    def getlinks(self, path: str | None, guid: str | None = None) -> list[str]:
        """``Cns_getlinks``: the file's own path first, then the links to it."""
        body = _ids().hyper(0).string(path or "").string(guid or "").bytes()
        reply = self.call(wire.MAGIC, wire.GETLINKS, body).check()
        return _strings(reply.lists.get(wire.MSG_LINKS, []))

    def addreplica(
        self,
        guid: str,
        fileid: int,
        host: str,
        sfn: str,
        status: str = "-",
        f_type: str = "P",
        poolname: str = "",
        fs: str = "",
    ) -> None:
        """``Cns_addreplica``: by file id when one is known, else by GUID."""
        body = (
            _ids()
            .hyper(fileid)
            .string("" if fileid else guid)
            .string(host)
            .string(sfn)
            .byte(status)
            .byte(f_type)
            .string(poolname)
            .string(fs)
            .byte(0)
            .string("")
        )
        self.call(wire.MAGIC4, wire.ADDREPLICA, body.bytes()).check()

    def delreplica(self, guid: str | None, fileid: int, sfn: str) -> None:
        body = _ids().hyper(fileid).string("" if fileid else guid or "").string(sfn).bytes()
        self.call(wire.MAGIC, wire.DELREPLICA, body).check()

    def listdir(self, path: str) -> list[DirEntry]:
        """``Cns_opendirg`` + ``Cns_readdirx`` to the end + ``Cns_closedir``."""
        entries: list[DirEntry] = []

        def exchange(conn: Connection) -> Reply:
            opened = conn.call(
                wire.MAGIC, wire.OPENDIR, _ids().hyper(0).string(path).string("").bytes()
            )
            if opened.status or opened.final:
                return opened
            fileid = opened.reader().hyper()
            bod, eod = 1, 0
            while not eod:
                body = _ids().word(1).word(DIRENTSZ).hyper(fileid).word(bod).bytes()
                batch = conn.call(wire.MAGIC, wire.READDIR, body)
                if batch.status or batch.final:
                    return batch
                bod = 0
                reader = batch.reader()
                count = reader.word()
                if not count:
                    break
                for _ in range(count):
                    record = _stat(reader, False)
                    entries.append(DirEntry(reader.string(wire.MAXNAMELEN), record))
                eod = reader.word()
            # liblfc ignores the answer to CLOSEDIR: the server's reader takes
            # its empty body for a short read and ends the listing with
            # SEINTERNAL, which is how every listing ends.
            closed = conn.call(wire.MAGIC, wire.CLOSEDIR)
            closed.status = 0
            return closed

        self.run(exchange).check()
        return entries
