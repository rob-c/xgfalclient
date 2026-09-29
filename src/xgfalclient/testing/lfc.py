"""An in-process LFC name server: Csec, the Cns protocol, a catalogue in memory.

Enough of lcgdm's ``lfcdaemon`` (``ns/Cns_main.c``, ``ns/Cns_procreq.c``,
``ns/Cns_chkperm.c``) to drive the ``lfc`` plugin through everything gfal2
does::

    with LFCServer(gsi=pki.server_context(), mapfile={USER_DN: "xgfal"}) as lfc:
        lfc.mkdir("/grid", mode=0o777)
        ctx.stat(lfc.url("/grid"))

What it models, as the real server behaves:

* **Csec** - protocol negotiation, then ``GSI`` (TLS in tokens, capped at
  TLS 1.2 as EL7's OpenSSL is) or ``ID`` (believed only from ``trusted``
  hosts, and then the client is root);
* **identities** - a GSI DN maps to a virtual uid made on first sight, and
  to the gid of its VO from ``mapfile`` (``/etc/lcgdm-mapfile``); an
  unmapped DN is refused per request with ``SENOMAPFND``;
* **connections** - one request then ``CNS_RC`` and hang up; or a session
  (``STARTSESS``) answering ``CNS_IRC`` until ``ENDSESS`` or
  :attr:`LFCServer.session_timeout`; listings (``OPENDIR``, ``READDIR``,
  ``CLOSEDIR``) with ``DIRBUFSZ`` batches and the entry that did not fit
  carried to the next one;
* **the namespace** - ``Cns_parsepath`` (symlinks, ``..``, search
  permission, write permission on the parent), mode bits and ownership, the
  umask, directory ``nlink`` counting entries, GUIDs, comments, replicas,
  checksums, and the server's error numbers;
* **fault injection** - :meth:`LFCServer.inject` replaces the next reply
  to a request type with a status, a hang-up or raw bytes.

Every request is recorded in :attr:`LFCServer.log` as ``(type, magic)``.
"""

from __future__ import annotations

import errno
import select
import socket
import ssl
import stat as _stat
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Union

from ..crypto.gsi import GSIError, SecurityContext
from ..errors import GError
from ..plugins.lfc import wire
from ..plugins.lfc.csec import (
    DELEG,
    HANDSHAKE,
    HANDSHAKE_ERROR,
    NODELEG,
    PROTOCOL_REQ,
    PROTOCOL_RESP,
    TokenLink,
    decode_request,
    encode_response,
)
from ..plugins.lfc.wire import Packer, Unpacker

__all__ = ["LFCServer", "Entry", "Hangup", "Raw", "USER_DN"]

#: The test PKI's user, as Globus prints it.
USER_DN = "/DC=org/DC=xgfal/OU=People/CN=Test User"
#: ``Cns_srv_ping``'s answer from the EL7 build.
VERSION = "1.13.0-1"
#: Virtual ids start above the system range, as ``Cns_unique_uid`` does.
FIRST_VID = 101
#: ``CNS_TRANSTIMEOUT``.
SESSION_TIMEOUT = 60.0

S_IREAD, S_IWRITE, S_IEXEC = 0o400, 0o200, 0o100
#: OpenSSL's ``X509_V_FLAG_ALLOW_PROXY_CERTS``.
_ALLOW_PROXY_CERTS = 0x40


@dataclass(frozen=True)
class Raw:
    """Inject bytes written to the socket as they are."""

    data: bytes


class Hangup:
    """Inject a closed connection instead of the reply."""


#: What :meth:`LFCServer.inject` takes: a serrno to answer with, a hang-up or raw bytes.
Injection = Union[int, Raw, Hangup]


@dataclass
class Entry:
    """One ``Cns_file_metadata`` row, with its link, comment and replicas."""

    fileid: int
    parent: int
    name: str
    mode: int
    uid: int = 0
    gid: int = 0
    guid: str = ""
    nlink: int = 0
    size: int = 0
    atime: int = 0
    mtime: int = 0
    ctime: int = 0
    fileclass: int = 0
    status: str = "-"
    csumtype: str = ""
    csumvalue: str = ""
    linkname: str = ""
    comment: str | None = None
    replicas: list[ReplicaEntry] = field(default_factory=list)

    def is_dir(self) -> bool:
        return _stat.S_ISDIR(self.mode)

    def is_link(self) -> bool:
        return _stat.S_ISLNK(self.mode)


@dataclass
class ReplicaEntry:
    """One ``Cns_file_replica`` row."""

    fileid: int
    host: str
    sfn: str
    status: str = "-"
    f_type: str = "P"
    poolname: str = ""
    fs: str = ""
    nbaccesses: int = 1
    ctime: int = 0
    atime: int = 0
    ptime: int = 0


class _Fail(Exception):
    """A handler's failure: ``code`` is the serrno, ``text`` an optional ``MSG_ERR``."""

    def __init__(self, code: int, text: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.text = text


@dataclass
class Identity:
    """Who the connection is, once Csec and the id mapping are done."""

    uid: int
    gids: list[int]
    name: str
    mech: str

    @property
    def gid(self) -> int:
        return self.gids[0]


class LFCServer:
    """A threaded LFC on a loopback port, with its catalogue in memory."""

    def __init__(
        self,
        *,
        host: str = "localhost",
        gsi: ssl.SSLContext | None = None,
        mechanisms: tuple[str, ...] = ("GSI", "ID"),
        trusted: tuple[str, ...] = ("127.0.0.1", "::1"),
        mapfile: dict[str, str] | None = None,
        session_timeout: float = SESSION_TIMEOUT,
        readonly: bool = False,
    ) -> None:
        self.host = host
        self.gsi = gsi
        if gsi is not None:
            # EL7's OpenSSL speaks TLS 1.2 at most, and Csec GSI insists on a
            # client certificate - a proxy, which OpenSSL accepts only with
            # X509_V_FLAG_ALLOW_PROXY_CERTS (a constant ssl lacks before 3.10).
            gsi.maximum_version = ssl.TLSVersion.TLSv1_2
            gsi.verify_flags |= _ALLOW_PROXY_CERTS
            gsi.verify_mode = ssl.CERT_REQUIRED
        self.mechanisms = mechanisms
        self.trusted = trusted
        self.mapfile = dict(mapfile or {})
        self.session_timeout = session_timeout
        self.readonly = readonly
        self.log: list[tuple[int, int]] = []
        self.injections: dict[int, list[Injection]] = {}
        #: Accepted connections, and how many of them ran a session.
        self.connections = 0
        self.sessions = 0
        self.users: dict[str, int] = {}
        self.groups: dict[str, int] = {}
        self._lock = threading.RLock()
        self._next_id = 2
        now = int(time.time())
        root = Entry(2, 0, "/", _stat.S_IFDIR | 0o755, atime=now, mtime=now, ctime=now)
        self.entries: dict[int, Entry] = {2: root}
        self.children: dict[int, dict[str, int]] = {0: {"/": 2}, 2: {}}
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._listener = socket.create_server((host, 0), family=family)
        self.port = int(self._listener.getsockname()[1])
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self._stopping = False

    # -- lifecycle ------------------------------------------------------------------

    def url(self, path: str = "/") -> str:
        return f"lfc://{self.host}:{self.port}{path}"

    @property
    def hostport(self) -> str:
        return f"{self.host}:{self.port}"

    def start(self) -> LFCServer:
        thread = threading.Thread(target=self._serve, name="xgfal-lfc-server", daemon=True)
        self._threads.append(thread)
        thread.start()
        return self

    def stop(self) -> None:
        # Closing a listening socket does not wake a blocked accept() on
        # Linux; a connection of our own does, everywhere.
        self._stopping = True
        socket.create_connection((self.host, self.port), timeout=5).close()
        with self._lock:
            acceptor = self._threads[:1]
        for thread in acceptor:  # it takes our connection as the signal and returns
            thread.join(5)
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

    def __enter__(self) -> LFCServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _serve(self) -> None:
        while True:
            sock, address = self._listener.accept()
            if self._stopping:
                sock.close()
                return
            with self._lock:
                self._sockets.append(sock)
                self.connections += 1
            handler = _Connection(self, sock, str(address[0]))
            thread = threading.Thread(target=handler.run, name="xgfal-lfc-conn", daemon=True)
            with self._lock:
                self._threads.append(thread)
            thread.start()

    def inject(self, kind: int, *replies: Injection) -> None:
        """Answer the next request(s) of ``kind`` with ``replies``, one each."""
        with self._lock:
            self.injections.setdefault(kind, []).extend(replies)

    def _injection(self, kind: int) -> Injection | None:
        with self._lock:
            queued = self.injections.get(kind)
            return queued.pop(0) if queued else None

    # -- the catalogue, for tests ---------------------------------------------------------

    def _new_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def lookup(self, path: str) -> Entry:
        """The entry at an absolute path, no symlinks followed (``KeyError`` if none)."""
        entry = self.entries[2]
        for part in (part for part in path.split("/") if part):
            entry = self.entries[self.children[entry.fileid][part]]
        return entry

    def _insert(self, parent: Entry, entry: Entry) -> Entry:
        self.entries[entry.fileid] = entry
        self.children[parent.fileid][entry.name] = entry.fileid
        if entry.is_dir():
            self.children[entry.fileid] = {}
        parent.nlink += 1
        parent.mtime = parent.ctime = int(time.time())
        return entry

    def _add(self, path: str, mode: int, uid: int, gid: int, **fields: object) -> Entry:
        head, _, name = path.rstrip("/").rpartition("/")
        with self._lock:
            parent = self.lookup(head or "/")
            now = int(time.time())
            entry = Entry(
                self._new_id(), parent.fileid, name, mode, uid, gid, atime=now, mtime=now, ctime=now
            )
            for key, value in fields.items():
                setattr(entry, key, value)
            return self._insert(parent, entry)

    def mkdir(self, path: str, mode: int = 0o755, uid: int = 0, gid: int = 0) -> Entry:
        return self._add(path, _stat.S_IFDIR | mode, uid, gid, guid=str(uuid.uuid4()))

    def add_file(
        self,
        path: str,
        *,
        size: int = 0,
        mode: int = 0o644,
        uid: int = 0,
        gid: int = 0,
        guid: str | None = None,
        csumtype: str = "",
        csumvalue: str = "",
        replicas: tuple[str, ...] = (),
        comment: str | None = None,
    ) -> Entry:
        entry = self._add(
            path,
            _stat.S_IFREG | mode,
            uid,
            gid,
            guid=guid or str(uuid.uuid4()),
            size=size,
            nlink=1,
            csumtype=csumtype,
            csumvalue=csumvalue,
            comment=comment,
        )
        for sfn in replicas:
            host = sfn.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            entry.replicas.append(ReplicaEntry(entry.fileid, host, sfn))
        return entry

    def add_link(self, path: str, target: str, uid: int = 0, gid: int = 0) -> Entry:
        return self._add(path, _stat.S_IFLNK | 0o777, uid, gid, nlink=1, linkname=target)

    # -- identities -------------------------------------------------------------------------

    def uid_for(self, name: str) -> int:
        with self._lock:
            if name not in self.users:
                self.users[name] = FIRST_VID + len(self.users)
            return self.users[name]

    def gid_for(self, group: str) -> int:
        with self._lock:
            if group not in self.groups:
                self.groups[group] = FIRST_VID + len(self.groups)
            return self.groups[group]


def _proxy_owner(subject: str) -> str:
    """The end-entity DN of a proxy: drop the ``CN=<serial>``/``CN=proxy`` tail."""
    parts = subject.split("/")
    while len(parts) > 2 and (
        parts[-1] in ("CN=proxy", "CN=limited proxy")
        or (parts[-1].startswith("CN=") and parts[-1][3:].isdigit())
    ):
        parts.pop()
    return "/".join(parts)


class _Connection:
    """The server's end of one connection (``doit`` in ``Cns_main.c``)."""

    def __init__(self, server: LFCServer, sock: socket.socket, address: str) -> None:
        self.server = server
        self.sock = sock
        self.address = address
        self.link = TokenLink(sock, address)
        self.identity: Identity | None = None
        self.dn = ""
        self.authorization: tuple[str, str] | None = None

    # -- the byte stream ----------------------------------------------------------------

    def _exact(self, size: int) -> bytes | None:
        data = bytearray()
        while len(data) < size:
            try:
                chunk = self.sock.recv(size - len(data))
            except OSError:
                return None
            if not chunk:
                return None
            data += chunk
        return bytes(data)

    def send(self, data: bytes) -> None:
        try:
            self.sock.sendall(data)
        except OSError:
            pass

    def reply(self, kind: int, value: int | bytes) -> None:
        """``sendrep``: a status, or a data message with its length."""
        if isinstance(value, int):
            self.send(wire.HEADER.pack(wire.MAGIC2, kind, value))
        else:
            self.send(wire.HEADER.pack(wire.MAGIC2, kind, len(value)) + value)

    def error(self, text: str) -> None:
        self.reply(wire.MSG_ERR, text.encode() + b"\0")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def final(self, status: int) -> None:
        self.reply(wire.CNS_RC, status)
        self.close()

    # -- Csec --------------------------------------------------------------------------------

    def authenticate(self) -> bool:
        try:
            kind, data = self.link.recv_token()
            if kind != PROTOCOL_REQ:
                return False
            version, self.authorization, mechs, flags = decode_request(data)
            chosen = None
            for index, mech in enumerate(mechs):
                if mech in self.server.mechanisms and not flags[index] & DELEG:
                    chosen = index
                    break
            self.link.send_token(
                PROTOCOL_RESP,
                encode_response(version, chosen, NODELEG, self.server.mechanisms),
            )
            if chosen is None:
                return False
            if mechs[chosen] == "ID":
                return self._id()
        except GError:
            return False
        try:
            return self._gsi()
        except (GError, GSIError):
            # _Csec_notify_peer_of_handshake_error, then doit's ESEC_NO_CONTEXT
            try:
                self.link.send_token(HANDSHAKE_ERROR, Packer().long(0).bytes())
            except GError:
                pass
            self.final(wire.ESEC_NO_CONTEXT)
            return False

    def _id(self) -> bool:
        kind, data = self.link.recv_token()
        fields = data.decode("utf-8", "replace").split()
        if kind != HANDSHAKE or len(fields) != 3:
            return False
        if self.address not in self.server.trusted:
            # "Host is not trusted, identity provided was (ID,...)"
            self.final(errno.EACCES)
            return False
        if self.authorization is None:
            self.identity = Identity(0, [0], "root", "ID")
        else:
            self.dn = self.authorization[1]
        return True

    def _gsi(self) -> bool:
        if self.server.gsi is None:
            return False
        context = SecurityContext(self.server.gsi, server_side=True)
        while not context.complete:
            kind, data = self.link.recv_token()
            if kind == HANDSHAKE_ERROR:
                self.final(wire.ESEC_NO_CONTEXT)
                return False
            token = context.step(data)
            # The acceptor completes on the client's delegation flag, which
            # needs no answer: every token it sends is a HANDSHAKE one.
            if token:
                self.link.send_token(HANDSHAKE, token)
        peer = context.peer_certificate()
        assert peer is not None  # CERT_REQUIRED: no certificate, no handshake
        self.dn = _proxy_owner(str(peer.subject))
        return True

    def map_identity(self) -> Identity:
        """``getidmap``: a virtual uid for the DN, the gid of its VO."""
        if self.identity is None:
            vo = self.server.mapfile.get(self.dn)
            if vo is None:
                raise _Fail(
                    wire.SENOMAPFND,
                    f"Could not get virtual id for {self.dn}: No user mapping !\n",
                )
            self.identity = Identity(
                self.server.uid_for(self.dn), [self.server.gid_for(vo)], self.dn, "GSI"
            )
        return self.identity

    # -- requests -------------------------------------------------------------------------------

    def get_request(self) -> tuple[int, int, bytes] | None:
        """``getreq``: a request, or ``None`` if the peer went away or sent junk."""
        header = self._exact(wire.HEADER.size)
        if header is None:
            return None
        magic, kind, length = wire.HEADER.unpack(header)
        if not wire.HEADER.size < length <= wire.MAXREQUEST:
            return (magic, kind, b"") if length == wire.HEADER.size else None
        body = self._exact(length - wire.HEADER.size)
        return None if body is None else (magic, kind, body)

    def run(self) -> None:
        if not self.authenticate():
            self.close()
            return
        request = self.get_request()
        if request is None:
            self.close()
            return
        self.final(self.process(*request) if request[2] else wire.SEINTERNAL)

    def process(self, magic: int, kind: int, body: bytes) -> int:
        """``procreq``: run one request; its status."""
        self.server.log.append((kind, magic))
        injected = self.server._injection(kind)
        if isinstance(injected, int):
            return injected
        if isinstance(injected, Raw):
            self.send(injected.data)
            return 0
        if isinstance(injected, Hangup):
            self.close()
            return 0
        if kind == wire.STARTSESS:
            return self.session()
        if kind == wire.OPENDIR:
            return self.listing(magic, body)
        handler = _HANDLERS.get(kind)
        if handler is None:
            self.error(f"NS003 - illegal function {kind}\n")
            return wire.SEOPNOTSUP
        try:
            ident = self.map_identity()
            reader = Unpacker(body)
            reader.long(), reader.long()  # the client's own uid and gid, ignored
            with self.server._lock:
                return handler(self, ident, magic, reader)
        except _Fail as exc:
            if exc.text:
                self.error(exc.text)
            return exc.code
        except GError:  # a body that does not unmarshall
            return errno.EINVAL

    def session(self) -> int:
        """``procsessreq``: answer each request with ``CNS_IRC`` until ``ENDSESS``."""
        with self.server._lock:
            self.server.sessions += 1
        self.reply(wire.CNS_IRC, 0)
        while True:
            try:
                readable, _, _ = select.select([self.sock], [], [], self.server.session_timeout)
            except (OSError, ValueError):  # closed under us by an injected hang-up
                return wire.SEINTERNAL
            if not readable:
                return wire.SETIMEDOUT
            request = self.get_request()
            if request is None:
                return wire.SEINTERNAL
            status = self.process(*request) if request[2] else wire.SEINTERNAL
            if request[1] == wire.ENDSESS:
                return status
            self.reply(wire.CNS_IRC, status)

    def listing(self, magic: int, body: bytes) -> int:
        """``procdirreq`` for ``OPENDIR``: batches until anything but ``READDIR``."""
        try:
            ident = self.map_identity()
            directory = self._opendir(ident, magic, Unpacker(body))
        except _Fail as exc:
            if exc.text:
                self.error(exc.text)
            return exc.code
        self.reply(wire.MSG_DATA, Packer().hyper(directory.fileid).bytes())
        self.reply(wire.CNS_IRC, 0)
        with self.server._lock:
            names = sorted(self.server.children[directory.fileid].items())
        queue = [self.server.entries[fileid] for _, fileid in names]
        while True:
            request = self.get_request()
            if request is None:
                return wire.SEINTERNAL
            rmagic, kind, rbody = request
            self.server.log.append((kind, rmagic))
            if kind != wire.READDIR:
                # CLOSEDIR: its empty body is a short read to getreq
                return wire.SEINTERNAL if not rbody else 0
            injected = self.server._injection(kind)
            if isinstance(injected, int):
                return injected
            reader = Unpacker(rbody)
            reader.long(), reader.long()
            getattr_, direntsz = reader.word(), reader.word()
            reader.hyper(), reader.word()
            if getattr_ != 1:
                return wire.SEOPNOTSUP
            self.reply(wire.MSG_DATA, self._batch(rmagic, direntsz, queue))
            self.reply(wire.CNS_IRC, 0)

    def _opendir(self, ident: Identity, magic: int, reader: Unpacker) -> Entry:
        reader.long(), reader.long()
        cwd = reader.hyper()
        path = reader.string()
        guid = reader.string() if magic >= wire.MAGIC2 else ""
        with self.server._lock:
            if guid:
                entry = _by_guid(self.server, guid)
            else:
                _, entry = _parse(self.server, ident, cwd, path, must_exist=True)
            if not entry.is_dir():
                raise _Fail(errno.ENOTDIR)
            _check(entry, S_IREAD | S_IEXEC, ident)
            return entry

    def _batch(self, magic: int, direntsz: int, queue: list[Entry]) -> bytes:
        """One ``Cns_srv_readdir`` reply: what fits in ``DIRBUFSZ``, then ``eod``.

        An entry that does not fit stays at the head of ``queue`` for the next one.
        """
        least = 130 if magic >= wire.MAGIC2 else 62  # DIRGSIZE, DIRXSIZE
        size = max(direntsz, least)
        room = wire.DIRBUFSZ - size
        packer = Packer()
        count = 0
        while queue:
            entry = queue[0]
            if len(entry.name) >= room:
                break
            queue.pop(0)
            _dirx(packer, magic, entry)
            count += 1
            room -= ((size + len(entry.name) + 8) // 8) * 8
        eod = 0 if queue else 1
        return Packer().word(count).bytes() + packer.bytes() + Packer().word(eod).bytes()


# -- the namespace logic ------------------------------------------------------------------------


def _check(entry: Entry, mode: int, ident: Identity) -> None:
    """``Cns_chkentryperm`` without ACLs; uid 0 stands for Cupv's administrators."""
    if ident.uid == 0:
        return
    if entry.uid != ident.uid:
        mode >>= 3
        if entry.gid not in ident.gids:
            mode >>= 3
    if entry.mode & mode != mode:
        raise _Fail(errno.EACCES)


def _by_guid(server: LFCServer, guid: str) -> Entry:
    for entry in server.entries.values():
        if entry.guid == guid:
            return entry
    raise _Fail(errno.ENOENT)


def _get(server: LFCServer, parent: int, name: str) -> Entry:
    fileid = server.children.get(parent, {}).get(name)
    if fileid is None:
        raise _Fail(errno.ENOENT)
    return server.entries[fileid]


def _parse(
    server: LFCServer,
    ident: Identity,
    cwd: int,
    path: str,
    *,
    must_exist: bool = False,
    nofollow: bool = False,
    parent: bool = False,
) -> tuple[Entry | None, Entry]:
    """``Cns_parsepath``: ``(parent, entry)``; a new name comes back with ``fileid`` 0."""
    if not path:
        raise _Fail(errno.ENOENT)
    if not cwd and not path.startswith("/"):
        raise _Fail(errno.EINVAL)
    links = 0
    while True:
        path = path.rstrip("/") or "/"
        current = server.entries.get(cwd) if cwd else None
        component = path
        restart = False
        if path != "/":
            pieces = path.split("/")
            if path.startswith("/"):
                pieces[0] = "/"
            *walk, component = pieces
            for index, piece in enumerate(walk):
                if piece in ("", "."):
                    continue
                if piece == "..":
                    assert current is not None
                    if current.parent:
                        current = server.entries[current.parent]
                    continue
                if len(piece) > wire.MAXNAMELEN:
                    raise _Fail(wire.SENAMETOOLONG)
                current = _get(server, current.fileid if current else 0, piece)
                if current.is_link():
                    links += 1
                    if links > wire.MAXSYMLINKS:
                        raise _Fail(wire.SELOOP)
                    path = "/".join([current.linkname, *walk[index + 1 :], component])
                    restart = True
                    break
                if not current.is_dir():
                    raise _Fail(errno.ENOTDIR)
                _check(current, S_IEXEC, ident)
            if restart:
                continue
        base = current.fileid if current else 0
        if component == "..":
            assert current is not None
            entry = server.entries[current.parent] if current.parent else current
        elif component != ".":  # never empty: the path was stripped of trailing "/"
            if len(component) > wire.MAXNAMELEN:
                raise _Fail(wire.SENAMETOOLONG)
            try:
                entry = _get(server, base, component)
            except _Fail:
                if must_exist:
                    raise
                entry = Entry(0, base, component, 0)
            else:
                if entry.is_link() and not nofollow:
                    links += 1
                    if links > wire.MAXSYMLINKS:
                        raise _Fail(wire.SELOOP)
                    path = entry.linkname
                    continue
        else:
            assert current is not None
            entry = current
        above = None
        if parent and entry.parent:
            above = server.entries[entry.parent]
            _check(above, S_IEXEC | S_IWRITE, ident)
        return above, entry


def _path_of(server: LFCServer, entry: Entry) -> str:
    """``getpath``: an entry's absolute path from the root down."""
    parts = []
    while entry.fileid != 2:
        parts.append(entry.name)
        entry = server.entries[entry.parent]
    return "/" + "/".join(reversed(parts))


def _chkback(server: LFCServer, fileid: int, ident: Identity) -> None:
    """``Cns_chkbackperm``: search permission on every ancestor."""
    while fileid > 2:
        entry = server.entries[fileid]
        _check(entry, S_IEXEC, ident)
        fileid = entry.parent


def _stat_record(packer: Packer, entry: Entry) -> None:
    packer.hyper(entry.fileid).word(entry.mode).long(entry.nlink).long(entry.uid).long(entry.gid)
    packer.hyper(entry.size).hyper(entry.atime).hyper(entry.mtime).hyper(entry.ctime)
    packer.word(entry.fileclass).byte(entry.status)


def _statg_record(packer: Packer, entry: Entry) -> None:
    packer.hyper(entry.fileid).string(entry.guid).word(entry.mode).long(entry.nlink)
    packer.long(entry.uid).long(entry.gid).hyper(entry.size)
    packer.hyper(entry.atime).hyper(entry.mtime).hyper(entry.ctime)
    packer.word(entry.fileclass).byte(entry.status).string(entry.csumtype)
    packer.string(entry.csumvalue)


def _dirx(packer: Packer, magic: int, entry: Entry) -> None:
    """``marshall_DIRX``."""
    packer.hyper(entry.fileid)
    if magic >= wire.MAGIC2:
        packer.string(entry.guid)
    packer.word(entry.mode).long(entry.nlink).long(entry.uid).long(entry.gid)
    packer.hyper(entry.size).hyper(entry.atime).hyper(entry.mtime).hyper(entry.ctime)
    packer.word(entry.fileclass).byte(entry.status)
    if magic >= wire.MAGIC2:
        packer.string(entry.csumtype).string(entry.csumvalue)
    packer.string(entry.name)


def _nstring(reader: Unpacker, size: int) -> tuple[str, bool]:
    """``_unmarshall_NSTRINGN``: the string, cut to ``size - 1``, and whether it fit.

    An over-long string is still consumed up to its NUL, so the fields after
    it stay in step; a string with no NUL at all consumes the rest.
    """
    data = reader.data
    end = data.find(b"\0", reader.pos)
    if end < 0:
        reader.pos = len(data)
        return "", False
    raw = data[reader.pos : end]
    reader.pos = end + 1
    fits = len(raw) < size
    return raw[: size - 1].decode("utf-8", "surrogateescape"), fits


def _path(reader: Unpacker) -> str:
    """A path field: ``SENAMETOOLONG`` over 1023 bytes, ``EINVAL`` if unterminated."""
    text, fits = _nstring(reader, wire.MAXPATHLEN + 1)
    if not fits:
        raise _Fail(wire.SENAMETOOLONG if text else errno.EINVAL)
    return text


def _writable(conn: _Connection) -> None:
    if conn.server.readonly:
        raise _Fail(errno.EROFS)


def _remove(server: LFCServer, parent: Entry, entry: Entry) -> None:
    del server.entries[entry.fileid]
    del server.children[parent.fileid][entry.name]
    server.children.pop(entry.fileid, None)
    parent.nlink -= 1
    parent.mtime = parent.ctime = int(time.time())


def _sticky(parent: Entry, entry: Entry, ident: Identity) -> None:
    if parent.mode & _stat.S_ISVTX and ident.uid not in (parent.uid, entry.uid):
        _check(entry, S_IWRITE, ident)


Handler = Callable[[_Connection, Identity, int, Unpacker], int]


def _stat_common(conn: _Connection, ident: Identity, reader: Unpacker, nofollow: bool) -> int:
    cwd, fileid, path = reader.hyper(), reader.hyper(), _path(reader)
    if fileid:
        entry = conn.server.entries.get(fileid)
        if entry is None:
            raise _Fail(errno.ENOENT)
        _chkback(conn.server, entry.parent, ident)
    else:
        _, entry = _parse(conn.server, ident, cwd, path, must_exist=True, nofollow=nofollow)
    packer = Packer()
    _stat_record(packer, entry)
    conn.reply(wire.MSG_DATA, packer.bytes())
    return 0


def _h_stat(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    return _stat_common(conn, ident, reader, False)


def _h_lstat(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    return _stat_common(conn, ident, reader, True)


def _h_statg(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    cwd, path = reader.hyper(), _path(reader)
    guid = reader.string()
    if path:
        _, entry = _parse(conn.server, ident, cwd, path, must_exist=True)
        if guid and guid != entry.guid:
            raise _Fail(errno.EINVAL, "GUID mismatch\n")
    else:
        if not guid:
            raise _Fail(errno.ENOENT)
        entry = _by_guid(conn.server, guid)
    packer = Packer()
    _statg_record(packer, entry)
    conn.reply(wire.MSG_DATA, packer.bytes())
    return 0


def _h_statr(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    sfn = reader.string()
    for entry in conn.server.entries.values():
        if any(replica.sfn == sfn for replica in entry.replicas):
            packer = Packer()
            _statg_record(packer, entry)
            conn.reply(wire.MSG_DATA, packer.bytes())
            return 0
    raise _Fail(errno.ENOENT)


def _h_access(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    cwd, path, amode = reader.hyper(), _path(reader), reader.long()
    if amode & ~7:
        raise _Fail(errno.EINVAL)
    _, entry = _parse(conn.server, ident, cwd, path, must_exist=True)
    if amode:
        _check(entry, (amode & 7) << 6, ident)
    return 0


def _h_chmod(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    _writable(conn)
    cwd, path, mode = reader.hyper(), _path(reader), reader.long()
    _, entry = _parse(conn.server, ident, cwd, path, must_exist=True)
    if ident.uid not in (entry.uid, 0):
        raise _Fail(errno.EPERM)
    if not entry.is_dir() and ident.uid:
        mode &= ~_stat.S_ISVTX
    if ident.uid and entry.gid not in ident.gids:
        mode &= ~_stat.S_ISGID
    entry.mode = _stat.S_IFMT(entry.mode) | (mode & 0o7777)
    entry.ctime = int(time.time())
    return 0


def _new_entry(conn: _Connection, ident: Identity, reader: Unpacker, magic: int, kind: int) -> int:
    """``Cns_srv_mkdir`` and ``Cns_srv_creat``, which differ only in details."""
    _writable(conn)
    mask, cwd, path, mode = reader.word(), reader.hyper(), _path(reader), reader.long()
    guid = reader.string() if magic >= wire.MAGIC2 else ""
    if guid:
        try:
            uuid.UUID(guid)
        except ValueError as exc:
            raise _Fail(errno.EINVAL) from exc
    directory = kind == wire.MKDIR
    above, entry = _parse(
        conn.server, ident, cwd, path, nofollow=directory, parent=True, must_exist=False
    )
    if entry.name == "/":
        raise _Fail(errno.EEXIST if directory else errno.EISDIR)
    assert above is not None
    now = int(time.time())
    if entry.fileid:
        if directory:
            raise _Fail(errno.EEXIST)
        if entry.is_dir():
            raise _Fail(errno.EISDIR)
        if entry.guid != guid:
            raise _Fail(errno.EEXIST)
        _check(entry, S_IWRITE, ident)
        if entry.replicas:
            raise _Fail(errno.EEXIST)
        entry.size, entry.csumtype, entry.csumvalue = 0, "", ""
        entry.mtime = entry.ctime = now
    else:
        if not directory and not guid:
            raise _Fail(errno.EINVAL)  # the LFC insists on a GUID
        kind_bits = _stat.S_IFDIR if directory else _stat.S_IFREG
        entry = Entry(
            conn.server._new_id(),
            above.fileid,
            entry.name,
            kind_bits | ((mode & 0o7777) & ~mask),
            ident.uid,
            ident.gid,
            guid=guid or str(uuid.uuid4()),
            nlink=0 if directory else 1,
            atime=now,
            mtime=now,
            ctime=now,
        )
        if above.mode & _stat.S_ISGID:
            entry.gid = above.gid
            if directory:
                entry.mode |= _stat.S_ISGID
        conn.server._insert(above, entry)
    if not directory:
        conn.reply(wire.MSG_DATA, Packer().hyper(entry.fileid).bytes())
    return 0


def _h_mkdir(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    return _new_entry(conn, ident, reader, magic, wire.MKDIR)


def _h_creat(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    return _new_entry(conn, ident, reader, magic, wire.CREAT)


def _h_rmdir(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    _writable(conn)
    cwd, path = reader.hyper(), _path(reader)
    above, entry = _parse(
        conn.server, ident, cwd, path, must_exist=True, nofollow=True, parent=True
    )
    if entry.name == "/":
        raise _Fail(errno.EINVAL)
    if not entry.is_dir():
        raise _Fail(errno.ENOTDIR)
    if entry.nlink:
        raise _Fail(errno.EEXIST)
    assert above is not None
    _sticky(above, entry, ident)
    _remove(conn.server, above, entry)
    return 0


def _unlink_one(conn: _Connection, ident: Identity, cwd: int, path: str, force: bool) -> int:
    """``unlinkonefile``; returns a status rather than raising, for ``DELFILES``."""
    try:
        above, entry = _parse(
            conn.server, ident, cwd, path, must_exist=True, nofollow=True, parent=True
        )
        if entry.name == "/":
            raise _Fail(errno.EINVAL)
        if entry.is_dir():
            raise _Fail(errno.EPERM)
        assert above is not None
        _sticky(above, entry, ident)
        if entry.replicas and not force:
            raise _Fail(errno.EEXIST)
        _remove(conn.server, above, entry)
    except _Fail as exc:
        return exc.code
    return 0


def _h_unlink(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    _writable(conn)
    cwd, path = reader.hyper(), _path(reader)
    return _unlink_one(conn, ident, cwd, path, False)


def _h_delfiles(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    _writable(conn)
    argtype, force = reader.word(), reader.word()
    cwd = reader.hyper() if argtype == 1 else 0
    count = reader.long()
    if count <= 0 or argtype != 1:
        raise _Fail(errno.EINVAL)
    statuses = Packer()
    for _ in range(count):
        try:
            path = _path(reader)
        except _Fail as exc:
            statuses.long(exc.code)
            continue
        statuses.long(_unlink_one(conn, ident, cwd, path, bool(force)))
    conn.reply(wire.MSG_STATUSES, statuses.bytes())
    conn.reply(wire.MSG_DATA, Packer().long(count).bytes())
    return 0


def _h_rename(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    _writable(conn)
    server = conn.server
    cwd, old, new = reader.hyper(), _path(reader), _path(reader)
    old_parent, source = _parse(
        server, ident, cwd, old, must_exist=True, nofollow=True, parent=True
    )
    new_parent, target = _parse(server, ident, cwd, new, nofollow=True, parent=True)
    if source.fileid == target.fileid:
        return 0
    if source.name == "/" or target.name == "/":
        raise _Fail(errno.EINVAL)
    assert old_parent is not None  # only the root has no parent
    assert new_parent is not None
    if source.is_dir():
        walk = target.parent
        while walk:
            if walk == source.fileid:
                raise _Fail(errno.EINVAL)
            walk = server.entries[walk].parent
    if target.fileid:
        if not source.is_dir() and target.is_dir():
            raise _Fail(errno.EISDIR)
        if source.is_dir() and not target.is_dir():
            raise _Fail(errno.ENOTDIR)
        if target.is_dir() and target.nlink:
            raise _Fail(errno.EEXIST)
        if target.replicas:
            raise _Fail(errno.EEXIST)
        _sticky(new_parent, target, ident)
    if source.is_dir():
        _check(source, S_IWRITE, ident)
    _sticky(old_parent, source, ident)
    if target.fileid:
        _remove(server, new_parent, target)
    del server.children[old_parent.fileid][source.name]
    old_parent.nlink -= 1
    source.parent, source.name = new_parent.fileid, target.name
    server.children[new_parent.fileid][source.name] = source.fileid
    new_parent.nlink += 1
    source.ctime = old_parent.mtime = old_parent.ctime = int(time.time())
    return 0


def _h_symlink(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    _writable(conn)
    cwd, target, link = reader.hyper(), _path(reader), _path(reader)
    above, entry = _parse(conn.server, ident, cwd, link, nofollow=True, parent=True)
    if entry.fileid:
        raise _Fail(errno.EEXIST)
    assert above is not None
    now = int(time.time())
    created = Entry(
        conn.server._new_id(),
        above.fileid,
        entry.name,
        _stat.S_IFLNK | 0o777,
        ident.uid,
        above.gid if above.mode & _stat.S_ISGID else ident.gid,
        nlink=1,
        atime=now,
        mtime=now,
        ctime=now,
        linkname=target,
    )
    conn.server._insert(above, created)
    return 0


def _h_readlink(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    cwd, path = reader.hyper(), _path(reader)
    _, entry = _parse(conn.server, ident, cwd, path, must_exist=True, nofollow=True)
    if ident.uid != entry.uid:
        _check(entry, S_IREAD, ident)
    if not entry.is_link():
        raise _Fail(errno.EINVAL)
    conn.reply(wire.MSG_DATA, Packer().string(entry.linkname).bytes())
    return 0


def _h_getcomment(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    cwd, path = reader.hyper(), _path(reader)
    _, entry = _parse(conn.server, ident, cwd, path, must_exist=True)
    if ident.uid != entry.uid:
        _check(entry, S_IREAD, ident)
    if entry.comment is None:
        raise _Fail(errno.ENOENT)
    conn.reply(wire.MSG_DATA, Packer().string(entry.comment).bytes())
    return 0


def _h_setcomment(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    _writable(conn)
    cwd, path = reader.hyper(), _path(reader)
    try:
        comment = reader.string(wire.MAXCOMMENTLEN)
    except GError as exc:
        raise _Fail(errno.EINVAL) from exc
    _, entry = _parse(conn.server, ident, cwd, path, must_exist=True)
    if ident.uid != entry.uid:
        _check(entry, S_IWRITE, ident)
    entry.comment = comment or None
    return 0


def _h_setfsizeg(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    _writable(conn)
    guid, size = reader.string(), reader.hyper()
    try:
        csumtype, csumvalue = reader.string(2), reader.string(32)
    except GError as exc:
        raise _Fail(errno.EINVAL) from exc
    if size >> 63 or (csumtype and csumtype not in ("CS", "AD", "MD")):
        raise _Fail(errno.EINVAL)
    entry = _by_guid(conn.server, guid)
    _chkback(conn.server, entry.parent, ident)
    if entry.is_dir():
        raise _Fail(errno.EISDIR)
    if ident.uid != entry.uid:
        _check(entry, S_IWRITE, ident)
    entry.size, entry.csumtype, entry.csumvalue = size, csumtype, csumvalue
    entry.mtime = entry.ctime = int(time.time())
    return 0


def _h_addreplica(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    _writable(conn)
    fileid, guid, host, sfn = reader.hyper(), reader.string(), reader.string(), reader.string()
    status, f_type, pool, fs = "-", "", "", ""
    if magic >= wire.MAGIC2:
        status = reader.char()
        f_type = reader.char() if magic >= wire.MAGIC3 else ""
        pool = reader.string()
        fs = reader.string() if magic >= wire.MAGIC3 else ""
    if not host or not sfn:
        raise _Fail(errno.EINVAL)
    if fileid:
        entry = conn.server.entries.get(fileid)
        if entry is None:
            raise _Fail(errno.ENOENT)
    else:
        if not guid:
            raise _Fail(errno.ENOENT)
        entry = _by_guid(conn.server, guid)
    _chkback(conn.server, entry.parent, ident)
    if ident.uid != entry.uid:
        _check(entry, S_IREAD, ident)
    if entry.is_dir():
        raise _Fail(errno.EISDIR)
    for other in conn.server.entries.values():
        if any(replica.sfn == sfn for replica in other.replicas):
            raise _Fail(errno.EEXIST)
    now = int(time.time())
    entry.replicas.append(
        ReplicaEntry(entry.fileid, host, sfn, status, f_type, pool, fs, 1, now, now)
    )
    return 0


def _h_delreplica(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    _writable(conn)
    fileid, guid, sfn = reader.hyper(), reader.string(), reader.string()
    owner = next(
        (e for e in conn.server.entries.values() if any(r.sfn == sfn for r in e.replicas)), None
    )
    if owner is None:
        raise _Fail(errno.ENOENT)
    if fileid:
        entry = conn.server.entries.get(fileid)
        if entry is None:
            raise _Fail(errno.ENOENT)
    elif guid:
        entry = _by_guid(conn.server, guid)
    else:
        entry = owner
    _chkback(conn.server, entry.parent, ident)
    if entry is not owner:
        raise _Fail(errno.ENOENT)
    if ident.uid != entry.uid:
        _check(entry, S_IWRITE, ident)
    entry.replicas = [replica for replica in entry.replicas if replica.sfn != sfn]
    _account(conn.server, entry, -entry.size)
    return 0


def _account(server: LFCServer, entry: Entry, increment: int) -> None:
    """``fixup_parent_dirs_sz``: DPM's space accounting, which the LFC build runs too.

    The ancestors are listed from the parent up to the root, and those from
    the fourth-from-the-root back up to seven levels are adjusted - in an
    unsigned column, so a directory whose files never added to it goes
    "negative" as a huge number, exactly as the real server shows it.
    """
    chain = []
    walk = entry
    while walk.parent:
        walk = server.entries[walk.parent]
        chain.append(walk)
    depth = len(chain)
    for index in range(max(depth - 3, 0), max(depth - 7, 0) - 1, -1):
        chain[index].size = (chain[index].size + increment) % (1 << 64)


def _named(conn: _Connection, ident: Identity, reader: Unpacker, nofollow: bool = False) -> Entry:
    """A path-or-GUID lookup, as ``getreplica`` and ``getlinks`` do it."""
    cwd, path, guid = reader.hyper(), _path(reader), reader.string()
    if path:
        _, entry = _parse(conn.server, ident, cwd, path, must_exist=True, nofollow=nofollow)
        if guid and guid != entry.guid:
            raise _Fail(errno.EINVAL, "GUID mismatch\n")
        return entry
    if not guid:
        raise _Fail(errno.ENOENT)
    return _by_guid(conn.server, guid)


def _h_getreplica(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    entry = _named(conn, ident, reader)
    se = reader.string()
    packer = Packer()
    count = 0
    for replica in entry.replicas:
        if se and replica.host != se:
            continue
        packer.hyper(replica.fileid).hyper(replica.nbaccesses)
        packer.hyper(replica.atime).hyper(replica.ptime)
        packer.byte(replica.status).byte(replica.f_type or "\0")
        packer.string(replica.poolname).string(replica.host).string(replica.fs)
        packer.string(replica.sfn)
        count += 1
    if count:
        conn.reply(wire.MSG_REPLIC, packer.bytes())
    conn.reply(wire.MSG_DATA, Packer().long(count).bytes())
    return 0


def _h_getlinks(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    entry = _named(conn, ident, reader, nofollow=True)  # CNS_NOFOLLOW: a link names its target
    target = entry.linkname if entry.is_link() else _path_of(conn.server, entry)
    names = [target]
    for other in conn.server.entries.values():
        if other.is_link() and other.linkname == target:
            names.append(_path_of(conn.server, other))
    packer = Packer()
    for name in names:
        packer.string(name)
    conn.reply(wire.MSG_LINKS, packer.bytes())
    return 0


def _h_ping(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    conn.reply(wire.MSG_DATA, Packer().string(VERSION).bytes())
    return 0


def _h_endsess(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    return 0


_HANDLERS: dict[int, Handler] = {
    wire.STAT: _h_stat,
    wire.LSTAT: _h_lstat,
    wire.STATG: _h_statg,
    wire.STATR: _h_statr,
    wire.ACCESS: _h_access,
    wire.CHMOD: _h_chmod,
    wire.MKDIR: _h_mkdir,
    wire.CREAT: _h_creat,
    wire.RMDIR: _h_rmdir,
    wire.UNLINK: _h_unlink,
    wire.DELFILES: _h_delfiles,
    wire.RENAME: _h_rename,
    wire.SYMLINK: _h_symlink,
    wire.READLINK: _h_readlink,
    wire.GETCOMMENT: _h_getcomment,
    wire.SETCOMMENT: _h_setcomment,
    wire.SETFSIZEG: _h_setfsizeg,
    wire.ADDREPLICA: _h_addreplica,
    wire.DELREPLICA: _h_delreplica,
    wire.GETREPLICA: _h_getreplica,
    wire.GETLINKS: _h_getlinks,
    wire.PING: _h_ping,
    wire.ENDSESS: _h_endsess,
}
