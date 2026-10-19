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

How this module is organised: it is the public facade. It defines
:class:`LFCServer` - the listener, the in-memory catalogue with the helpers
tests seed it through, identities and fault injection; the protocol lives
in the private :mod:`xgfalclient.testing._lfc` package: the data model,
one client connection (Csec, sessions, listings), the namespace rules, and
the per-request handlers with their dispatch table. Every name the
single-module layout had is re-exported here (the wire and Csec names it
imported included), so ``from xgfalclient.testing.lfc import X`` keeps
working. They are the same objects, not copies, so patching
``lfc._HANDLERS`` or ``lfc.TokenLink`` reaches the connection code; no name
is looked up through this module at call time.

Where it deliberately differs from ``lfcdaemon``: no database (rows live
in dicts and vanish with the server), no ACLs, no Cupv (uid 0 is the only
administrator), no ``KRB5`` mechanism, no transactions, one fixed version
string, and request types it does not model answer ``SEOPNOTSUP``. Each
module of :mod:`xgfalclient.testing._lfc` says where to add a request type
or a rule.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import stat as _stat
import threading
import time
import uuid

# The names the single-module layout imported stay attributes of the
# facade: tests reach ``TokenLink`` (to patch it) and the wire helpers
# through it. The redundant ``as`` marks them, and everything below, as
# this module's API for mypy's no-implicit-reexport and for ruff.
from xrdsec.gsi.gss import GSIError as GSIError
from xrdsec.gsi.gss import SecurityContext as SecurityContext

from ..errors import GError as GError
from ..plugins.lfc import wire as wire
from ..plugins.lfc.csec import DELEG as DELEG
from ..plugins.lfc.csec import HANDSHAKE as HANDSHAKE
from ..plugins.lfc.csec import HANDSHAKE_ERROR as HANDSHAKE_ERROR
from ..plugins.lfc.csec import NODELEG as NODELEG
from ..plugins.lfc.csec import PROTOCOL_REQ as PROTOCOL_REQ
from ..plugins.lfc.csec import PROTOCOL_RESP as PROTOCOL_RESP
from ..plugins.lfc.csec import TokenLink as TokenLink
from ..plugins.lfc.csec import decode_request as decode_request
from ..plugins.lfc.csec import encode_response as encode_response
from ..plugins.lfc.wire import Packer as Packer
from ..plugins.lfc.wire import Unpacker as Unpacker
from ._lfc.connection import _Connection as _Connection
from ._lfc.handlers import _HANDLERS as _HANDLERS
from ._lfc.handlers import Handler as Handler
from ._lfc.handlers import _account as _account
from ._lfc.handlers import _h_access as _h_access
from ._lfc.handlers import _h_addreplica as _h_addreplica
from ._lfc.handlers import _h_chmod as _h_chmod
from ._lfc.handlers import _h_creat as _h_creat
from ._lfc.handlers import _h_delfiles as _h_delfiles
from ._lfc.handlers import _h_delreplica as _h_delreplica
from ._lfc.handlers import _h_endsess as _h_endsess
from ._lfc.handlers import _h_getcomment as _h_getcomment
from ._lfc.handlers import _h_getlinks as _h_getlinks
from ._lfc.handlers import _h_getreplica as _h_getreplica
from ._lfc.handlers import _h_lstat as _h_lstat
from ._lfc.handlers import _h_mkdir as _h_mkdir
from ._lfc.handlers import _h_ping as _h_ping
from ._lfc.handlers import _h_readlink as _h_readlink
from ._lfc.handlers import _h_rename as _h_rename
from ._lfc.handlers import _h_rmdir as _h_rmdir
from ._lfc.handlers import _h_setcomment as _h_setcomment
from ._lfc.handlers import _h_setfsizeg as _h_setfsizeg
from ._lfc.handlers import _h_stat as _h_stat
from ._lfc.handlers import _h_statg as _h_statg
from ._lfc.handlers import _h_statr as _h_statr
from ._lfc.handlers import _h_symlink as _h_symlink
from ._lfc.handlers import _h_unlink as _h_unlink
from ._lfc.handlers import _named as _named
from ._lfc.handlers import _new_entry as _new_entry
from ._lfc.handlers import _stat_common as _stat_common
from ._lfc.handlers import _unlink_one as _unlink_one
from ._lfc.model import FIRST_VID as FIRST_VID
from ._lfc.model import S_IEXEC as S_IEXEC
from ._lfc.model import S_IREAD as S_IREAD
from ._lfc.model import S_IWRITE as S_IWRITE
from ._lfc.model import SESSION_TIMEOUT as SESSION_TIMEOUT
from ._lfc.model import USER_DN as USER_DN
from ._lfc.model import VERSION as VERSION
from ._lfc.model import Entry as Entry
from ._lfc.model import Hangup as Hangup
from ._lfc.model import Identity as Identity
from ._lfc.model import Injection as Injection
from ._lfc.model import Raw as Raw
from ._lfc.model import ReplicaEntry as ReplicaEntry
from ._lfc.model import _Fail as _Fail
from ._lfc.namespace import _by_guid as _by_guid
from ._lfc.namespace import _check as _check
from ._lfc.namespace import _chkback as _chkback
from ._lfc.namespace import _dirx as _dirx
from ._lfc.namespace import _get as _get
from ._lfc.namespace import _nstring as _nstring
from ._lfc.namespace import _parse as _parse
from ._lfc.namespace import _path as _path
from ._lfc.namespace import _path_of as _path_of
from ._lfc.namespace import _remove as _remove
from ._lfc.namespace import _stat_record as _stat_record
from ._lfc.namespace import _statg_record as _statg_record
from ._lfc.namespace import _sticky as _sticky
from ._lfc.namespace import _writable as _writable

__all__ = ["USER_DN", "Entry", "Hangup", "LFCServer", "Raw"]


class LFCServer:
    """A threaded LFC on a loopback port, with its catalogue in memory.

    The listening socket is bound in the constructor (an ephemeral port, in
    :attr:`port`), so :meth:`url` works before :meth:`start`; requests are
    served only once started. One daemon thread accepts, and each
    connection gets a daemon thread of its own running
    :class:`~xgfalclient.testing._lfc.connection._Connection`; use the
    server as a context manager so :meth:`stop` always runs.

    Everything shared - the catalogue (:attr:`entries`, :attr:`children`),
    identities, injections and counters - is guarded by one re-entrant
    lock, held for the whole of each request as the real daemon's database
    transaction would serialise it. Test helpers take it too, so seeding
    the catalogue while a client is connected is safe. :attr:`log` is
    appended without the lock (``list.append`` is atomic in CPython).

    Attributes tests read or set at any time: :attr:`readonly` (``EROFS``
    for every changing request), :attr:`session_timeout`, :attr:`mapfile`
    (DN to VO name), :attr:`log`, :attr:`connections` and
    :attr:`sessions`. :attr:`users` and :attr:`groups` are the virtual id
    tables, DN or VO name to id.
    """

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
        """Bind a listener on ``host`` and seed the catalogue with the root alone.

        ``gsi`` is the server's TLS context for Csec ``GSI`` (``None``: GSI
        clients are dropped); it is changed in place to what Csec needs, see
        below. ``mechanisms`` is what the server accepts, in the order it
        lists them when it refuses a client's offer. ``trusted`` holds the
        peer IPs whose ``ID`` claims make them root. ``mapfile`` maps DNs to
        VO names - the ``/etc/lcgdm-mapfile`` the identity mapping reads;
        it is copied, so later edits go through :attr:`mapfile`. A host
        containing ``:`` is taken as IPv6.
        """
        self.host = host
        self.gsi = gsi
        if gsi is not None:
            # EL7's OpenSSL speaks TLS 1.2 at most, and Csec GSI insists on a
            # client certificate - a proxy, which OpenSSL accepts only with
            # X509_V_FLAG_ALLOW_PROXY_CERTS.
            gsi.maximum_version = ssl.TLSVersion.TLSv1_2
            gsi.verify_flags |= ssl.VERIFY_ALLOW_PROXY_CERTS
            gsi.verify_mode = ssl.CERT_REQUIRED
        self.mechanisms = mechanisms
        self.trusted = trusted
        self.mapfile = dict(mapfile or {})
        self.session_timeout = session_timeout
        self.readonly = readonly
        #: ``(request type, magic)`` of every request received, in order.
        self.log: list[tuple[int, int]] = []
        #: Queued replies per request type; see :meth:`inject`.
        self.injections: dict[int, list[Injection]] = {}
        #: Accepted connections, and how many of them ran a session.
        self.connections = 0
        self.sessions = 0
        self.users: dict[str, int] = {}
        self.groups: dict[str, int] = {}
        # Re-entrant: handlers run under it and call helpers that take it again.
        self._lock = threading.RLock()
        self._next_id = 2
        now = int(time.time())
        # File id 2 is the root, as in a fresh lcgdm database; 0 is the
        # pseudo-directory above it, whose one child is "/", so an absolute
        # path's first piece is looked up like any other name.
        root = Entry(2, 0, "/", _stat.S_IFDIR | 0o755, atime=now, mtime=now, ctime=now)
        #: Every row by file id.
        self.entries: dict[int, Entry] = {2: root}
        #: Each directory's names, to file ids; files have no entry here.
        self.children: dict[int, dict[str, int]] = {0: {"/": 2}, 2: {}}
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._listener = socket.create_server((host, 0), family=family)
        self.port = int(self._listener.getsockname()[1])
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self._stopping = False

    # -- lifecycle ------------------------------------------------------------------

    def url(self, path: str = "/") -> str:
        """The ``lfc://host:port/path`` URL gfal2 would be given for ``path``."""
        return f"lfc://{self.host}:{self.port}{path}"

    @property
    def hostport(self) -> str:
        """``host:port``, the form ``LFC_HOST`` and the plugin's settings take."""
        return f"{self.host}:{self.port}"

    def start(self) -> LFCServer:
        """Start accepting on a daemon thread; returns ``self`` for chaining."""
        thread = threading.Thread(target=self._serve, name="xgfal-lfc-server", daemon=True)
        self._threads.append(thread)
        thread.start()
        return self

    def stop(self) -> None:
        """Stop accepting, hang up every connection and join the threads.

        Each join waits up to 5 seconds, so a connection thread stuck in a
        handler cannot hang the test run; it is a daemon and dies with the
        interpreter. Not restartable: the listener is closed.
        """
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
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        for thread in threads:
            thread.join(5)

    def __enter__(self) -> LFCServer:
        """:meth:`start` the server."""
        return self.start()

    def __exit__(self, *exc: object) -> None:
        """:meth:`stop` the server, whether or not the block raised."""
        self.stop()

    def _serve(self) -> None:
        """The acceptor thread: one :class:`_Connection` thread per client.

        The socket is registered before its thread starts, so :meth:`stop`
        can always shut it down. The connection made by :meth:`stop` itself
        is recognised by :attr:`_stopping` and ends the loop.
        """
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
        """Answer the next request(s) of ``kind`` with ``replies``, one each.

        ``kind`` is a request type from :mod:`xgfalclient.plugins.lfc.wire`
        (``wire.STATG``...). A reply is a serrno to return as the status (0
        succeeds without running the handler), :class:`Raw` bytes, or
        :class:`Hangup`. Injections queue up in order and each one is used
        by exactly one request, on whichever connection asks first; inside
        a listing only a status applies to ``READDIR``.
        """
        with self._lock:
            self.injections.setdefault(kind, []).extend(replies)

    def _injection(self, kind: int) -> Injection | None:
        """Take the next queued injection for ``kind``, if any."""
        with self._lock:
            queued = self.injections.get(kind)
            return queued.pop(0) if queued else None

    # -- the catalogue, for tests ---------------------------------------------------------

    def _new_id(self) -> int:
        """The next file id; ids only grow, so a removed entry's id is never reused."""
        self._next_id += 1
        return self._next_id

    def lookup(self, path: str) -> Entry:
        """The entry at an absolute path, no symlinks followed (``KeyError`` if none)."""
        entry = self.entries[2]
        for part in (part for part in path.split("/") if part):
            entry = self.entries[self.children[entry.fileid][part]]
        return entry

    def _insert(self, parent: Entry, entry: Entry) -> Entry:
        """Link a new row into ``parent``, keeping its ``nlink`` and times up to date.

        Callers hold the lock and have checked the name is free. A directory
        also gets an empty child table.
        """
        self.entries[entry.fileid] = entry
        self.children[parent.fileid][entry.name] = entry.fileid
        if entry.is_dir():
            self.children[entry.fileid] = {}
        parent.nlink += 1
        parent.mtime = parent.ctime = int(time.time())
        return entry

    def _add(self, path: str, mode: int, uid: int, gid: int, **fields: object) -> Entry:
        """Seed an entry at absolute ``path`` with no permission checks.

        The parent must exist (``KeyError`` otherwise, from :meth:`lookup`);
        an existing name is silently replaced in the parent's table, so seed
        each path once. ``fields`` are set on the :class:`Entry` as given.
        """
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
        """Seed a directory (with a fresh GUID), owned by root unless told otherwise."""
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
        """Seed a regular file with its size, checksum, comment and replicas.

        ``guid`` defaults to a fresh UUID. ``csumtype`` is the LFC's
        two-letter type (``"AD"`` for ADLER32) and ``csumvalue`` its hex
        digest. Each of ``replicas`` is an SFN (``srm://se.example/path``);
        its host part becomes the replica's SE, which ``getreplica`` filters
        on.
        """
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
        """Seed a symlink to ``target``, stored as given and not resolved."""
        return self._add(path, _stat.S_IFLNK | 0o777, uid, gid, nlink=1, linkname=target)

    # -- identities -------------------------------------------------------------------------

    def uid_for(self, name: str) -> int:
        """The virtual uid of a DN, allocated from :data:`FIRST_VID` on first sight.

        Tests call it to own seeded entries by the user a connection will
        map to; the connection calls it the same way, so both agree.
        """
        with self._lock:
            if name not in self.users:
                self.users[name] = FIRST_VID + len(self.users)
            return self.users[name]

    def gid_for(self, group: str) -> int:
        """The virtual gid of a VO name, allocated like :meth:`uid_for`."""
        with self._lock:
            if group not in self.groups:
                self.groups[group] = FIRST_VID + len(self.groups)
            return self.groups[group]
