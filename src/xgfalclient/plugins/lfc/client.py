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
are always absolute) and decodes the reply the same way. Almost every
body starts with the caller's ``uid`` and ``gid`` (:func:`_ids`); the server
ignores them and uses the identity Csec established, but the fields must be
there for the rest to line up. A refusal is :class:`CnsError`, whose
``code`` is the ``errno`` gfal2 would report (:func:`.wire.errno_for`);
transport failures are plain ``GError`` with the socket's ``errno``;
an unparseable reply is :class:`~.wire.WireError` (``EPROTO``).

**Threads.** A :class:`Server` is shared by every thread using one
catalogue with one identity (:class:`~.plugin.LFCPlugin` keys them so);
only its idle list is locked. A :class:`Connection` is never shared: it is
taken from the pool, used by one call, and given back or closed.

Where to start reading: :meth:`Server.run`, which every call goes through,
then :meth:`Server.connect` and :meth:`Connection.read_reply`. The in-process
test server (``xgfalclient.testing.lfc``) reproduces the server side of
everything here, including session time-outs and the ``CLOSEDIR`` quirk.
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import select
import socket
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ...errors import GError
from . import wire
from .csec import Mechanism, authenticate
from .wire import Packer, Unpacker, WireError

__all__ = [
    "MAX_IDLE_SECONDS",
    "MAX_POOL",
    "CnsError",
    "Connection",
    "DirEntry",
    "FileStat",
    "Replica",
    "ReplicaPlacement",
    "Reply",
    "Server",
    "ServerOptions",
]

# gfal2's logger name, so LFC warnings reach whatever the gfal2 API user set up.
_log = logging.getLogger("gfal2")

#: Connections idle longer than this are closed rather than reused; the
#: server gives up on a session after 60 seconds.
MAX_IDLE_SECONDS = 45.0
#: Idle sessions kept per server: each holds one of the server's threads.
MAX_POOL = 4

#: The size of liblfc's ``struct Cns_direnstat`` up to ``d_name`` on LP64
#: Linux; the server uses it to size listing batches. It is sent, not
#: derived: any value the real client sends works, and a different one
#: would change how many entries fit in each ``DIRBUFSZ`` batch.
DIRENTSZ = 62


class CnsError(GError):
    """The server refused a request: ``serrno`` is its code, ``code`` the errno.

    The message is liblfc's text for the serrno (``sstrerror``); the
    server's own ``MSG_ERR`` lines, already logged as warnings, are kept in
    :attr:`messages` for callers that want the detail. The plugin catches
    this and re-raises gfal2's wording; it should not escape to users.
    """

    def __init__(self, serrno: int, messages: Sequence[str] = ()) -> None:
        """``serrno`` from the reply's status; ``messages`` its ``MSG_ERR`` texts."""
        super().__init__(wire.serrno_text(serrno), wire.errno_for(serrno))
        self.serrno = serrno
        self.messages = list(messages)


def socket_error(exc: BaseException, what: str) -> GError:
    """A ``GError`` for a failed socket call, keeping its ``errno``.

    ``TimeoutError`` (a socket timeout) becomes ``ETIMEDOUT``, which
    :meth:`Server.run` deliberately does not retry; an ``OSError`` without
    an ``errno`` becomes ``ECONNRESET``. ``what`` starts the message.
    """
    if isinstance(exc, TimeoutError):
        return GError(f"{what}: timed out", errno.ETIMEDOUT)
    code = getattr(exc, "errno", None) or errno.ECONNRESET
    return GError(f"{what}: {exc}", code)


@dataclass
class Reply:
    """Everything the server sent for one request, up to its status.

    Built by :meth:`Connection.read_reply`; the call methods then
    :meth:`check` it and decode :attr:`data` or :attr:`lists`.
    """

    #: ``0`` or the serrno from ``CNS_RC``/``CNS_IRC``.
    status: int = 0
    #: The ``MSG_DATA`` payloads, concatenated (normally just one).
    data: bytearray = field(default_factory=bytearray)
    #: Payloads of list messages (``MSG_LINKS``, ``MSG_REPLIC``...), by type.
    lists: dict[int, list[bytes]] = field(default_factory=dict)
    #: ``MSG_ERR`` texts, which liblfc prints on stderr.
    errors: list[str] = field(default_factory=list)
    #: ``CNS_RC``: the server has closed the connection.
    final: bool = False

    def check(self) -> Reply:
        """This reply, or :class:`CnsError` if the status is not ``0``; for chaining."""
        if self.status:
            raise CnsError(self.status, self.errors)
        return self

    def reader(self) -> Unpacker:
        """An :class:`~.wire.Unpacker` over :attr:`data`, from the start."""
        return Unpacker(self.data)


class Connection:
    """One authenticated connection, in a session or not.

    Owns its socket: any transport or framing error closes it, so a
    connection is either usable or :attr:`closed`, never half-read. Not
    thread-safe; the pool hands it to one caller at a time.
    """

    def __init__(self, sock: socket.socket, peer: str) -> None:
        """Wrap a connected socket; Csec and ``STARTSESS`` are the caller's job."""
        self.sock = sock
        #: ``host:port``, for messages.
        self.peer = peer
        #: In a Cns session: requests answer ``CNS_IRC`` and the link stays up.
        self.session = False
        self.closed = False
        #: Taken from the pool at least once - the condition for a retry.
        self.reused = False
        #: Bytes read so far; :meth:`Server.run` compares it to see if a
        #: failed request had started to be answered.
        self.received = 0
        #: When it last went back to the pool (``time.monotonic``).
        self.idle_since = time.monotonic()

    # -- the byte stream ------------------------------------------------------------

    def send(self, data: bytes) -> None:
        """Write all of ``data``; on failure close and raise with the socket's ``errno``."""
        try:
            self.sock.sendall(data)
        except OSError as exc:
            self.close()
            raise socket_error(exc, f"Lost the connection to the LFC {self.peer}") from exc

    def _exact(self, size: int) -> bytes:
        """Exactly ``size`` bytes; end of stream or any error closes the connection.

        Reads into a preallocated buffer (``recv_into``) so a large reply
        is not rebuilt chunk by chunk, and counts :attr:`received` as it
        goes, so even a partial header marks the request as answered.
        """
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
        """Read messages until the status, as ``send2nsdx``'s reply loop.

        ``CNS_RC`` (final: the server hangs up, so the socket is closed
        here) and ``CNS_IRC`` (in a session or listing: more may follow)
        both end the reply. A payload length outside ``0..REPBUFSZ`` means
        the stream is out of step: the connection is closed and
        :class:`~.wire.WireError` raised before anything is allocated.
        ``MSG_ERR`` text is logged as a warning, which is where liblfc
        would print it on stderr.
        """
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
        """Whether the server has spoken (or hung up) while we were not asking.

        An idle session gets nothing from the server except, at its idle
        limit, a final ``CNS_RC`` and end of stream - so anything readable
        means the session is over. Connections older than
        :data:`MAX_IDLE_SECONDS` are treated as stale without looking, to
        stay clear of the server's 60-second limit racing a new request.
        """
        if self.closed or time.monotonic() - self.idle_since > MAX_IDLE_SECONDS:
            return True
        readable, _, _ = select.select([self.sock], [], [], 0)
        return bool(readable)

    def close(self) -> None:
        """Close the socket, once; safe to call again (errors call it eagerly)."""
        if not self.closed:
            self.closed = True
            self.sock.close()


def _ids() -> Packer:
    """``uid``/``gid`` as every request starts; the server trusts Csec instead."""
    return (
        Packer().long(getattr(os, "geteuid", lambda: 0)()).long(getattr(os, "getegid", lambda: 0)())
    )


# The process umask can only be read by setting it, which races with other
# threads creating files; read it once, under a lock, and remember it.
_umask_lock = threading.Lock()
_umask: list[int] = []


def process_umask() -> int:
    """liblfc's ``thip->mask``: the process umask, read once.

    Sent with ``mkdir``/``creat`` so the server applies it, as a local
    ``mkdir(2)`` would. A later ``os.umask`` change is not seen.
    """
    with _umask_lock:
        if not _umask:
            mask = os.umask(0)
            os.umask(mask)
            _umask.append(mask)
        return _umask[0]


# -- records -------------------------------------------------------------------------


@dataclass(slots=True)
class FileStat:
    """``struct Cns_filestatg`` (``guid`` and checksum empty for a plain stat).

    Times are seconds since the epoch; ``status`` is a one-letter file
    status (``'-'`` for an ordinary entry); ``fileclass`` is inherited from
    the Castor name server. ``csumtype`` is the catalogue's two-letter code
    (``AD``, ``MD``, ``CS``), see ``plugin.CHECKSUM_NAMES``.
    """

    #: The server's unique id for the entry, stable across renames.
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


@dataclass(slots=True)
class DirEntry:
    """One ``Cns_direnstat`` from a listing: a name and its stat."""

    name: str
    stat: FileStat


@dataclass(slots=True)
class Replica:
    """``struct Cns_filereplica``: one registered copy of a file.

    ``sfn`` is the replica's URL (an SRM SURL, or any URL gfal2 can open);
    ``host`` is its storage element. ``status`` and ``f_type`` are one-letter
    codes (``'-'`` available; ``'P'`` permanent), ``poolname``/``fs`` DPM
    placement details, empty in a plain LFC. ``ptime`` is the pin time.
    """

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
    """``unmarshall`` a stat record: the plain layout, or the ``statg`` one.

    Plain (``Cns_stat``, ``lstat``, ``readdirx``): ``HYPER fileid, WORD mode,
    LONG nlink, LONG uid, LONG gid, HYPER size, TIME_T atime/mtime/ctime,
    WORD fileclass, BYTE status``. With ``with_guid`` (``Cns_statg``,
    ``statr``) the GUID string follows the file id and the checksum type and
    value strings end the record. Fields are read in that order, so the
    constructor's positional arguments must stay in step with the
    :class:`FileStat` field order.
    """
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
    """Every ``Cns_filereplica`` in the ``MSG_REPLIC`` payloads, records back to back.

    Each: ``HYPER fileid, HYPER nbaccesses, TIME_T atime, TIME_T ptime,
    BYTE status, BYTE f_type, STRING poolname, host, fs, sfn`` - the
    :class:`Replica` field order.
    """
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
    """NUL-terminated strings packed back to back (``MSG_LINKS``)."""
    found = []
    for payload in payloads:
        reader = Unpacker(payload)
        while not reader.at_end():
            found.append(reader.string())
    return found


def _longs(payloads: list[bytes]) -> list[int]:
    """Signed ``LONG`` values packed back to back (``MSG_STATUSES``)."""
    found = []
    for payload in payloads:
        reader = Unpacker(payload)
        while not reader.at_end():
            found.append(reader.long())
    return found


# -- the server and its pool --------------------------------------------------------------

Connect = Callable[[], socket.socket]


@dataclass(frozen=True, slots=True)
class ServerOptions:
    """How a :class:`Server` connects: liblfc's ``LFC_*`` settings and session reuse.

    The defaults are only a fallback for direct use (tests, probes); the
    plugin always passes gfal2's ``[LFC PLUGIN]`` values (see
    ``LFCPlugin.server``).
    """

    #: Seconds any one read or write may block once connected.
    timeout: float = 300.0
    #: Seconds per connect attempt (``LFC_CONNTIMEOUT``).
    connect_timeout: float = 120.0
    #: Further rounds over every address after the first fails (``LFC_CONRETRY``).
    retries: int = 0
    #: Seconds to sleep between rounds (``LFC_CONRETRYINT``).
    retry_interval: float = 60.0
    #: Start a Cns session on each connection and pool it (``SESSION_REUSE``).
    sessions: bool = True


_DEFAULT_OPTIONS = ServerOptions()


@dataclass(frozen=True, slots=True)
class ReplicaPlacement:
    """The ``Cns_addreplica`` columns gfal2 always left at their defaults.

    The plugin registers every replica with these: ``status`` ``'-'``
    (available) and ``f_type`` ``'P'`` (permanent); ``poolname`` and ``fs``
    are DPM's and empty in a catalogue.
    """

    status: str = "-"
    f_type: str = "P"
    poolname: str = ""
    fs: str = ""


_DEFAULT_PLACEMENT = ReplicaPlacement()


class Server:
    """One LFC endpoint for one identity: a pool of authenticated connections.

    Thread-safe: any number of threads may call its methods at once, each
    on a connection of its own (the pool holds at most :data:`MAX_POOL`
    idle ones; busy ones are not counted). :meth:`close` ends the idle
    sessions; connections in use are closed by their callers as usual.
    """

    def __init__(
        self,
        host: str,
        port: int,
        mechanisms: Callable[[], Sequence[Mechanism]],
        options: ServerOptions = _DEFAULT_OPTIONS,
    ) -> None:
        """Remember the endpoint; nothing connects until the first call.

        ``mechanisms`` is called for every new connection, so the Csec
        offer is rebuilt from the current environment each time rather
        than fixed when the server was first used.
        """
        self.host = host
        self.port = port
        self.peer = f"{host}:{port}"
        self.mechanisms = mechanisms
        self.options = options
        self._idle: list[Connection] = []
        self._lock = threading.Lock()

    # -- connecting -------------------------------------------------------------------

    def _socket(self) -> socket.socket:
        """``send2nsd``'s connect loop: every address, ``LFC_CONRETRY`` more rounds.

        A name that does not resolve is ``EHOSTUNREACH`` at once (no
        retry: it will not resolve in a minute either). A refused
        connection is liblfc's "Name server not active", ``ECONNREFUSED``;
        other failures keep their ``errno``. The last failure is raised
        after the last round. The connected socket gets the operation
        timeout and ``TCP_NODELAY`` - requests are small and each waits for
        its answer, so Nagle would only add latency.
        """
        options = self.options
        failure: GError | None = None
        for attempt in range(options.retries + 1):
            if attempt:
                time.sleep(options.retry_interval)
            try:
                addresses = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise GError(
                    f"Cannot resolve the LFC host {self.host}: {exc}", errno.EHOSTUNREACH
                ) from exc
            for family, kind, proto, _, address in addresses:
                sock = socket.socket(family, kind, proto)
                sock.settimeout(options.connect_timeout)
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
                sock.settimeout(options.timeout)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return sock
        assert failure is not None  # getaddrinfo never returns an empty list
        raise failure

    def connect(self) -> Connection:
        """A new authenticated connection, in a session if sessions are on.

        Csec first, then ``Cns_startsess`` (with a comment for the server's
        log). Any failure - including
        ``KeyboardInterrupt`` mid-handshake - closes the socket, so nothing
        leaks.
        """
        sock = self._socket()
        conn = Connection(sock, self.peer)
        try:
            mech = authenticate(sock, self.peer, self.host, self.mechanisms())
            _log.debug("LFC %s: authenticated with %s", self.peer, mech)
            if self.options.sessions:
                body = _ids().string("xgfalclient session").bytes()
                conn.call(wire.MAGIC, wire.STARTSESS, body).check()
                conn.session = True
        except BaseException:
            conn.close()
            raise
        return conn

    # -- the pool ---------------------------------------------------------------------

    def acquire(self) -> Connection:
        """An idle pooled connection that is still alive, else a new one.

        The most recently released connection is tried first (it is the
        least likely to have timed out); stale ones are closed and skipped.
        """
        while True:
            with self._lock:
                conn = self._idle.pop() if self._idle else None
            if conn is None:
                return self.connect()
            if not conn.stale():
                return conn
            conn.close()

    def release(self, conn: Connection) -> None:
        """Give ``conn`` back: pooled if it is a live session and there is room.

        A session that does not fit is ended politely (``ENDSESS``) so the
        server frees its thread at once rather than at its idle limit; a
        connection outside a session, or already closed, is just closed.
        """
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
        with contextlib.suppress(GError):
            conn.call(wire.MAGIC, wire.ENDSESS, _ids().bytes())
        conn.close()

    def close(self) -> None:
        """End every idle session; the server stays usable (new calls reconnect)."""
        with self._lock:
            idle, self._idle = self._idle, []
        for conn in idle:
            self._end(conn)

    def run(self, exchange: Callable[[Connection], Reply]) -> Reply:
        """``exchange`` on a pooled connection, retried once if that one was dead.

        A reused connection that fails before a single reply byte arrived
        was most likely closed by the server while idle, so the request
        runs again on the next pooled connection, or a new one; the loop
        ends because each failed connection is closed, not pooled, and a
        new connection is never ``reused``. A failure after part
        of the reply, a timeout (the request may still be running there),
        or any failure on a fresh connection is raised: the request may
        have taken effect. A ``CNS_RC`` reply ends the session, so the
        connection is not pooled. Any other exception closes the connection
        before propagating.
        """
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
        """One request on a pooled connection; the unchecked :class:`Reply`."""
        return self.run(lambda conn: conn.call(magic, kind, body))

    # -- the API ------------------------------------------------------------------------

    def ping(self) -> str:
        """``Cns_ping``: the server's version string."""
        return self.call(wire.MAGIC, wire.PING, _ids().bytes()).check().reader().string()

    def stat(self, path: str) -> FileStat:
        """``Cns_stat``: the plain record of ``path``, following symlinks.

        Body: ids, ``cwd`` ``0``, file id ``0`` (look up by name), path.
        """
        body = _ids().hyper(0).hyper(0).string(path).bytes()
        return _stat(self.call(wire.MAGIC, wire.STAT, body).check().reader(), False)

    def lstat(self, path: str) -> FileStat:
        """``Cns_lstat``: as :meth:`stat` but about a symlink itself (``CNS_MAGIC2``)."""
        body = _ids().hyper(0).hyper(0).string(path).bytes()
        return _stat(self.call(wire.MAGIC2, wire.LSTAT, body).check().reader(), False)

    def statg(self, path: str | None, guid: str | None = None) -> FileStat:
        """``Cns_statg``: the record with GUID and checksum, by path or by GUID.

        Exactly one of ``path`` and ``guid`` is expected; the other goes
        out as an empty string, which the server reads as "not given".
        """
        body = _ids().hyper(0).string(path or "").string(guid or "").bytes()
        return _stat(self.call(wire.MAGIC, wire.STATG, body).check().reader(), True)

    def statr(self, sfn: str) -> FileStat:
        """``Cns_statr``: the file that has a replica at ``sfn`` (``ENOENT`` if none)."""
        body = _ids().string(sfn).bytes()
        return _stat(self.call(wire.MAGIC, wire.STATR, body).check().reader(), True)

    def access(self, path: str, mode: int) -> None:
        """``Cns_access``: ``EACCES``/``ENOENT`` unless ``mode`` (``os.R_OK``...) is allowed.

        Unlike every other request it sends the *real* uid and gid, as
        ``access(2)`` checks with them; the server still decides with the
        Csec identity. ``os.F_OK`` (``0``) only tests that the entry exists.
        """
        uid = getattr(os, "getuid", lambda: 0)()
        gid = getattr(os, "getgid", lambda: 0)()
        body = Packer().long(uid).long(gid).hyper(0).string(path).long(mode).bytes()
        self.call(wire.MAGIC, wire.ACCESS, body).check()

    def chmod(self, path: str, mode: int) -> None:
        """``Cns_chmod``: permission bits only (``mode & 0o7777``), as ``chmod(2)``."""
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
        """``Cns_rmdir``; a non-empty directory is ``EEXIST`` from the server."""
        self.call(wire.MAGIC, wire.RMDIR, _ids().hyper(0).string(path).bytes()).check()

    def unlink(self, path: str) -> None:
        """``Cns_unlink``: the entry only; a file with replicas is ``EEXIST``."""
        self.call(wire.MAGIC, wire.UNLINK, _ids().hyper(0).string(path).bytes()).check()

    def delfiles(self, paths: Sequence[str], force: bool) -> list[int]:
        """``Cns_delfilesbyname``: one status per path; ``force`` drops replicas too.

        Body: ids, ``WORD 1`` (the argument type: paths, not file ids),
        ``WORD force``, ``cwd``, ``LONG`` count, the paths. The reply is a
        ``MSG_STATUSES`` list of serrno values (``0`` = deleted) and a
        ``MSG_DATA`` count; the overall status is ``0`` even when every path
        failed, so callers must look at the list.
        """
        body = _ids().word(1).word(int(force)).hyper(0).long(len(paths))
        for path in paths:
            body.string(path)
        reply = self.call(wire.MAGIC, wire.DELFILES, body.bytes()).check()
        statuses = _longs(reply.lists.get(wire.MSG_STATUSES, []))
        count = reply.reader().long()
        return statuses[:count]

    def rename(self, old: str, new: str) -> None:
        """``Cns_rename``: both paths on this server; ``rename(2)`` rules apply."""
        body = _ids().hyper(0).string(old).string(new).bytes()
        self.call(wire.MAGIC, wire.RENAME, body).check()

    def symlink(self, target: str, link: str) -> None:
        """``Cns_symlink``: create ``link`` pointing at ``target`` (any string)."""
        body = _ids().hyper(0).string(target).string(link).bytes()
        self.call(wire.MAGIC, wire.SYMLINK, body).check()

    def readlink(self, path: str) -> str:
        """``Cns_readlink``: the target stored in symlink ``path``."""
        body = _ids().hyper(0).string(path).bytes()
        return self.call(wire.MAGIC, wire.READLINK, body).check().reader().string()

    def getcomment(self, path: str) -> str:
        """``Cns_getcomment``: the entry's comment; ``ENOENT`` also means "none set"."""
        body = _ids().hyper(0).string(path).bytes()
        return self.call(wire.MAGIC, wire.GETCOMMENT, body).check().reader().string()

    def setcomment(self, path: str, comment: str) -> None:
        """``Cns_setcomment``: at most ``MAXCOMMENTLEN`` bytes; ``""`` removes it."""
        body = _ids().hyper(0).string(path).string(comment).bytes()
        self.call(wire.MAGIC, wire.SETCOMMENT, body).check()

    def setfsizeg(self, guid: str, size: int, csumtype: str, csumvalue: str) -> None:
        """``Cns_setfsizeg``: record a file's size and checksum, by GUID.

        ``csumtype`` is the two-letter code (``AD``/``MD``/``CS``) or ``""``
        with ``""`` as value for no checksum; other types are ``EINVAL``.
        """
        body = _ids().string(guid).hyper(size).string(csumtype).string(csumvalue).bytes()
        self.call(wire.MAGIC, wire.SETFSIZEG, body).check()

    def getreplica(
        self, path: str | None, guid: str | None = None, se: str | None = None
    ) -> list[Replica]:
        """``Cns_getreplica``: the file's replicas, by path or GUID, optionally on one SE.

        The records arrive as ``MSG_REPLIC`` messages; a file with none
        gives an empty list.
        """
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
        placement: ReplicaPlacement = _DEFAULT_PLACEMENT,
    ) -> None:
        """``Cns_addreplica``: by file id when one is known, else by GUID.

        Sent as ``CNS_MAGIC4``, the newest layout: after the placement
        columns come a replica-type byte and a set name, both left empty
        (``0`` and ``""``). The server refuses a duplicate SFN with ``EEXIST``.
        """
        body = (
            _ids()
            .hyper(fileid)
            .string("" if fileid else guid)
            .string(host)
            .string(sfn)
            .byte(placement.status)
            .byte(placement.f_type)
            .string(placement.poolname)
            .string(placement.fs)
            .byte(0)
            .string("")
        )
        self.call(wire.MAGIC4, wire.ADDREPLICA, body.bytes()).check()

    def delreplica(self, guid: str | None, fileid: int, sfn: str) -> None:
        """``Cns_delreplica``: drop the replica record ``sfn``, by file id or GUID."""
        body = _ids().hyper(fileid).string("" if fileid else guid or "").string(sfn).bytes()
        self.call(wire.MAGIC, wire.DELREPLICA, body).check()

    def listdir(self, path: str) -> list[DirEntry]:
        """``Cns_opendirg`` + ``Cns_readdirx`` to the end + ``Cns_closedir``.

        All three run on one connection inside a single :meth:`run`, so a
        dead pooled connection is retried before anything was listed and a
        failure part-way raises instead of returning a partial listing.
        Each ``READDIR`` asks for attributes (``WORD 1``), announces
        :data:`DIRENTSZ`, and sets ``bod`` (beginning of directory) on the
        first batch only; a batch is ``WORD count``, that many plain stat
        records each followed by its name, and ``WORD eod``.
        """
        entries: list[DirEntry] = []

        def exchange(conn: Connection) -> Reply:
            """The listing on ``conn``; an error reply is returned for :meth:`run`."""
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
