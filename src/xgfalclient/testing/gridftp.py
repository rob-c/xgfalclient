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
    server.data_faults["RETR"] = "stall"             # send half, then go silent
    server.data_faults["STOR"] = "drop"              # close data connections at once
    server.delays["CKSM"] = 2.0                      # think before answering

    with GridFTPServer(root) as server:
        url = server.url("/file")

How this module is organised: it is the public facade. It defines
:class:`GridFTPServer` - the listener, its settings and fault tables -
together with :data:`FEATURES` and :data:`DATA_TIMEOUT`; what one control
connection does lives in the private :mod:`xgfalclient.testing._gridftp`
package (state and the control channel, login and settings, data channels
and transfers, namespace verbs). Every name the single-module layout had is
re-exported here. ``DATA_TIMEOUT`` is looked up on this module at call time
by the data-channel code, so ``monkeypatch.setattr(gridftp, "DATA_TIMEOUT",
...)`` still shortens every data-connection wait.
"""

from __future__ import annotations

# Every name the single-module layout had is re-exported with a redundant
# ``as`` (so mypy's strict no-implicit-reexport and ruff treat it as this
# module's API): what it defined, now defined in ``_gridftp``, and what it
# imported (``stat``, which it imported as ``_stat``, is not re-exported).
import base64 as base64
import contextlib
import errno as errno
import hashlib as hashlib
import os as os
import shutil as shutil
import socket as socket
import ssl as ssl
import tempfile as tempfile
import threading as threading
import time as time
import zlib as zlib
from collections.abc import Callable as Callable
from pathlib import Path as Path
from typing import Any as Any

from xrdsec.gsi.gss import GSIError as GSIError
from xrdsec.gsi.gss import SecurityContext as SecurityContext
from xrdsec.rsa import RSAPrivateKey as RSAPrivateKey

from ..errors import GError as GError
from ..plugins.gridftp.data import DataConn as DataConn
from ..plugins.gridftp.data import EodCounter as EodCounter
from ..plugins.gridftp.data import Feed as Feed
from ..plugins.gridftp.data import Ranges as Ranges
from ..plugins.gridftp.data import authenticate as authenticate
from ..plugins.gridftp.data import recv_blocks as recv_blocks
from ..plugins.gridftp.data import recv_stream as recv_stream
from ..plugins.gridftp.data import send_blocks as send_blocks
from ..plugins.gridftp.data import send_stream as send_stream
from ..plugins.gridftp.gsi import GlobusContext as GlobusContext
from ..plugins.gridftp.gsi import data_contexts as data_contexts
from ..plugins.gridftp.protocol import format_mdtm as format_mdtm
from ..plugins.gridftp.protocol import parse_epsv as parse_epsv
from ..plugins.gridftp.protocol import parse_pasv as parse_pasv
from ._gridftp.base import _SessionBase as _SessionBase
from ._gridftp.commands import _Commands as _Commands
from ._gridftp.common import _GLOBUS_CODES as _GLOBUS_CODES
from ._gridftp.common import _OPEN as _OPEN
from ._gridftp.common import _checksum as _checksum
from ._gridftp.common import _family as _family
from ._gridftp.common import _Hangup as _Hangup
from ._gridftp.common import _Moved as _Moved
from ._gridftp.common import _Reply as _Reply
from ._gridftp.common import _slice as _slice
from ._gridftp.data import _DataChannel as _DataChannel
from ._gridftp.namespace import _Namespace as _Namespace
from ._gridftp.session import _Session as _Session

__all__ = ["FEATURES", "GridFTPServer"]

#: What globus-gridftp-server 13 lists in ``FEAT`` (the part a client uses).
#: Clients decide from this list whether to use ``MLST``, ``ERET``/``ESTO``,
#: ``CKSM`` (and which algorithms), delayed passive and ``DCAU``; pass a
#: shorter tuple as ``features=`` to model an older or a non-globus server.
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
#: How long a data connection may take to turn up, in seconds; also the socket
#: timeout on every data connection and the limit on opening all of a
#: transfer's connections. Tests that exercise a missing connection patch it
#: down (it is read from this module at call time).
DATA_TIMEOUT = 30.0


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

    ``host`` is where it listens (an IPv6 literal listens on IPv6; the port
    is always ephemeral, read it from :attr:`port`); ``advertise`` is the
    host ``PASV`` names instead. ``features`` is the ``FEAT`` list (see
    :data:`FEATURES`); ``block_size`` is the ``MODE E`` block it sends.

    The fault tables are plain dicts keyed by upper-case verb that a test
    fills in at any time (see the module docstring for the values):
    :attr:`faults` replaces or disrupts the control reply, :attr:`after`
    replaces the ``226`` that ends a transfer, :attr:`data_faults` disrupts
    the data connections, :attr:`delays` sleeps before answering. Entries
    stay until removed. :attr:`log` and :attr:`sessions` record what
    clients did.

    Lifecycle: the listening socket is bound in the constructor (so
    :meth:`url` works before :meth:`start`); :meth:`start` runs the accept
    loop on a daemon thread and each control connection gets its own daemon
    thread. :meth:`stop` breaks every socket the server made, which ends
    sessions blocked anywhere, including in a ``hang`` fault. A stopped
    server cannot be restarted.

    The constructor has many keyword options because it is public test API
    used across the suite; it is deliberately not folded into an options
    object.
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
        """Bind the listener now, so :attr:`port` and :meth:`url` work before :meth:`start`."""
        # Resolved once, so paths built under it match what the OS reports
        # (macOS's /var is a symlink to /private/var).
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
        #: Whether the GSI handshake hands the TLS 1.3 turn back, as a globus
        #: acceptor does; ``False`` is dCache's GridFTP door, which sends
        #: session tickets only and waits for the delegation flag.
        self.globus_turn = True
        #: A fixed reply to ``SITE USAGE``; ``None`` reports the root's disk.
        self.usage: str | None = None
        #: Verb to a reply, ``close``, ``hang`` or ``raw:<line>``, sent instead of answering.
        self.faults: dict[str, str] = {}
        #: Verb to the final reply of a transfer that moved its data.
        self.after: dict[str, str] = {}
        #: Verb to ``truncate``, ``stall`` or ``drop``, applied to the data connections.
        self.data_faults: dict[str, str] = {}
        #: Verb to seconds to sleep before handling it.
        self.delays: dict[str, float] = {}
        #: Every command received, unwrapped, in order.
        self.log: list[str] = []
        #: How many control connections have been accepted.
        self.sessions = 0
        self._listener = socket.create_server((host, 0), family=_family(host))
        self.port = int(self._listener.getsockname()[1])
        # Set by stop(); hang and stall faults wait on it.
        self._stop = threading.Event()
        # Every thread and socket the server made, so stop() can end them all;
        # the lock guards these lists and ``sessions`` across session threads.
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self._lock = threading.Lock()

    @property
    def scheme(self) -> str:
        """``gsiftp`` with a GSI context, else ``ftp``."""
        return "ftp" if self.gsi is None else "gsiftp"

    def url(self, path: str = "/") -> str:
        """The URL of ``path`` (absolute, client side) on this server.

        An IPv6 literal host is bracketed (RFC 3986 section 3.2.2), so a
        server on ``"::1"`` gives ``ftp://[::1]:<port>/...``; a name or an
        IPv4 address goes in as it is.
        """
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}{path}"

    def start(self) -> GridFTPServer:
        """Start accepting connections on a daemon thread; returns ``self`` for chaining."""
        thread = threading.Thread(target=self._serve, name="xgfal-gridftp-server", daemon=True)
        self._threads.append(thread)
        thread.start()
        return self

    def stop(self) -> None:
        """Stop serving and break every connection, then join the threads.

        Sets the stop event (releasing ``hang`` and ``stall`` faults), shuts
        down the listener and every tracked control and data socket, and
        joins each thread for up to five seconds; a thread still stuck after
        that is a daemon and will not keep the interpreter alive.
        """
        self._stop.set()
        # Linux does not wake a thread blocked in accept() when the listener is
        # merely closed (macOS does); a shutdown does.
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()
        with self._lock:
            sockets, threads = list(self._sockets), list(self._threads)
        for sock in sockets:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        for thread in threads:
            thread.join(5)

    def __enter__(self) -> GridFTPServer:
        """:meth:`start` the server for a ``with`` block."""
        return self.start()

    def __exit__(self, *exc: object) -> None:
        """:meth:`stop` the server; exceptions propagate."""
        self.stop()

    def _serve(self) -> None:
        """The accept loop: one :class:`_Session` thread per control connection.

        It ends when :meth:`stop` closes the listener and ``accept`` raises.
        """
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
        """Register a socket so :meth:`stop` can break it.

        Sessions call it for every control, passive-listener and data socket
        they create. Sockets are never removed: closing one twice is harmless
        and a test server's lifetime is short.
        """
        with self._lock:
            self._sockets.append(sock)
        return sock
