"""The test SFTP server object: configuration, faults, and how a session is started.

:class:`SFTPServer` holds what every session shares - the root it serves,
the extensions it announces, the request log and the fault and injection
queues - and starts a :class:`~.session._Session` over any stream:
:meth:`SFTPServer.pair` over a socketpair (with :class:`SocketStream` the
client end), :meth:`SFTPServer.serve` over a pair of callables (an SSH
channel, a fake ``ssh``'s stdio).

The server knows nothing of SSH. A session needs only "read exactly ``n``
bytes" and "write these bytes", which is all the SFTP protocol
(draft-ietf-secsh-filexfer-02) assumes of the channel below it; that is why
the same object serves the in-process client over a socketpair, the
:class:`~.ssh.SSHServer` channel, paramiko's transport and the fake ``ssh``
executable's stdin/stdout without any of them knowing about the others.

Lifecycle: every session runs on a daemon thread of its own (see
:meth:`SFTPServer.start`), so a test that forgets to close its client does
not hang the interpreter at exit. There is no ``stop``: a session ends when
its client hangs up, when a fault ends it, or with the process. The
fault and injection queues and the counters are shared by every session and
guarded by one lock; :attr:`SFTPServer.log` is appended to without it,
which is safe because list appends are atomic and tests read it only after
the requests they care about have been answered.
"""

from __future__ import annotations

import contextlib
import os
import posixpath
import socket
import threading
from collections.abc import Callable
from typing import Any

from .session import _Drop, _Session

#: OpenSSH ``sftp-server``'s announced extensions, in its order. The values
#: are the extension versions it sends in ``SSH_FXP_VERSION``; clients compare
#: them as strings, so they are bytes here too. Pass ``extensions=`` to
#: :class:`SFTPServer` to model an older or a non-OpenSSH server.
OPENSSH_EXTENSIONS: dict[str, bytes] = {
    "posix-rename@openssh.com": b"1",
    "statvfs@openssh.com": b"2",
    "fstatvfs@openssh.com": b"2",
    "hardlink@openssh.com": b"1",
    "fsync@openssh.com": b"1",
    "lsetstat@openssh.com": b"1",
    "limits@openssh.com": b"1",
}


class SocketStream:
    """A client :class:`~xgfalclient.plugins.sftp.client.Stream` over a socket.

    What :meth:`SFTPServer.pair` hands a test: the stream protocol the SFTP
    client is written against, with nothing between it and the server but a
    socketpair - no SSH framing, no encryption - so client tests exercise
    SFTP alone. The stream owns ``sock`` and closes it in :meth:`close`.
    """

    def __init__(self, sock: socket.socket) -> None:
        """Wrap the client end of a connected socket; the stream now owns it."""
        self.sock = sock

    def send(self, *parts: Any) -> None:
        """Write each buffer in order; the client passes a packet's header and body apart."""
        for part in parts:
            self.sock.sendall(part)

    def recv_into(self, view: memoryview) -> int:
        """Read what is available into ``view``; 0 means the server hung up."""
        return self.sock.recv_into(view)

    def close(self) -> None:
        """Shut the socket down, then close it.

        ``shutdown`` first wakes a client reader thread blocked in
        ``recv_into`` on the same socket (a bare ``close`` does not on
        Linux) and sends the server its end of stream. ``OSError`` from it
        means the server already hung up, which is fine at close.
        """
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()


class SFTPServer:
    """An SFTP v3 server over ``root``. Sessions run in their own threads.

    Args:
        root: The directory served as ``/``. Every path a client sends is
            resolved under it by :meth:`local`, so ``..`` cannot escape it.
        extensions: The ``SSH_FXP_VERSION`` extension list, name to version;
            defaults to :data:`OPENSSH_EXTENSIONS`. A request for an
            extension that is not listed gets ``OP_UNSUPPORTED``.
        limits: The four ``uint64`` of the ``limits@openssh.com`` reply -
            max packet, max read, max write, max open handles (0: no limit).
            The default is OpenSSH 8.6+'s: a 256 KiB packet and reads and
            writes 1 KiB short of it to leave room for the header. ``None``
            drops the extension, as an older ``sftp-server`` would; reads are
            then capped at 1 MiB instead.
        version: The protocol version announced; 3 is all OpenSSH speaks,
            anything else is for testing how the client refuses it.
        check_file: Hash names (:mod:`hashlib` spelling) for which to offer
            ``check-file-name``; empty, the default, does not offer it (OpenSSH
            never does).
        batch: Names per ``SSH_FXP_NAME`` reply to ``READDIR``, so a test can
            make a listing span many replies.

    Public attributes may be changed between requests; a session reads them
    as it handles each one.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        extensions: dict[str, bytes] | None = None,
        limits: tuple[int, int, int, int] | None = (262144, 261120, 261120, 0),
        version: int = 3,
        check_file: tuple[str, ...] = (),
        batch: int = 100,
    ) -> None:
        """Configure the server (see the class docstring); nothing runs until a session starts."""
        # realpath, so local()/remote() agree with what os.path.realpath returns
        # for REALPATH even when the root itself is reached through a symlink
        # (macOS's /tmp -> /private/tmp).
        self.root = os.path.realpath(os.fspath(root))
        self.extensions = dict(OPENSSH_EXTENSIONS if extensions is None else extensions)
        self.limits = limits
        if limits is None:
            self.extensions.pop("limits@openssh.com", None)
        self.check_file = check_file
        if check_file:
            self.extensions["check-file-name"] = b"1"
        self.version = version
        self.batch = batch
        #: ``(type, first argument)`` for every request, in arrival order.
        self.log: list[tuple[int, bytes]] = []
        #: Named misbehaviours, each consumed when it fires:
        #: ``short_read`` (next READ returns half), ``reorder`` (answer the next
        #: two requests in reverse), ``drop`` (hang up on the next request),
        #: ``garbage`` (answer the next request with an absurd length),
        #: ``wrong_type`` (answer the next request with an unexpected packet),
        #: ``banner`` (text before VERSION), ``oversize`` (next READ sends more DATA
        #: than asked), ``hang`` (never answer the next request).
        self.faults: list[str] = []
        # Request type -> queued ``(status code, message)`` answers; see inject().
        self._injected: dict[int, list[tuple[int, str]]] = {}
        self._lock = threading.Lock()
        #: Every session thread started, so a test can ``join`` them.
        self.threads: list[threading.Thread] = []
        #: Sessions served so far (counted on entry), e.g. to prove a pool reused one.
        self.sessions = 0

    # -- control -------------------------------------------------------------------

    def inject(self, ptype: int, code: int, message: str = "", count: int = 1) -> None:
        """Answer the next ``count`` requests of ``ptype`` with this status instead.

        ``ptype`` is an ``SSH_FXP_*`` request type and ``code`` an
        ``SSH_FX_*`` status code; the request is logged but not carried out.
        An empty ``message`` gets the status code's own name. Injections for
        one type queue up in call order and are shared by every session.
        """
        with self._lock:
            self._injected.setdefault(ptype, []).extend([(code, message)] * count)

    def _take_injection(self, ptype: int) -> tuple[int, str] | None:
        """Pop the next status queued for ``ptype``, or ``None`` to handle it normally."""
        with self._lock:
            queue = self._injected.get(ptype)
            return queue.pop(0) if queue else None

    def _take_fault(self, name: str) -> bool:
        """Consume one ``name`` from :attr:`faults`; ``True`` means misbehave now.

        Listing a fault twice makes it fire twice. The lock makes the
        check-and-remove atomic, so two sessions never both take one fault.
        """
        with self._lock:
            if name in self.faults:
                self.faults.remove(name)
                return True
            return False

    def pair(self) -> SocketStream:
        """A connected client stream; the server side runs in a thread.

        The caller owns the returned stream (close it, or hand it to an
        ``SFTPClient`` that will); the server end closes itself when the
        session ends.
        """
        client, server = socket.socketpair()
        self.start(lambda: _SocketIO(server))
        return SocketStream(client)

    def start(self, io_factory: Callable[[], Any]) -> threading.Thread:
        """Serve one session on a new daemon thread, over what ``io_factory`` returns.

        The factory is called on the new thread and must return an object with
        ``read_exact(n)``, ``write(data)`` and ``close()`` (like
        :class:`_SocketIO`); ``close`` is called however the session ends.
        Deferring construction to the thread lets a factory block, e.g. on
        ``accept``, without blocking the test.
        """
        thread = threading.Thread(target=self._run, args=(io_factory,), daemon=True)
        thread.start()
        self.threads.append(thread)
        return thread

    def _run(self, io_factory: Callable[[], Any]) -> None:
        """The thread body of :meth:`start`: build the I/O, serve, always close it."""
        io = io_factory()
        try:
            self.serve(io.read_exact, io.write)
        finally:
            io.close()

    # -- the session -----------------------------------------------------------------

    def serve(self, read_exact: Callable[[int], bytes], write: Callable[[bytes], None]) -> None:
        """Serve one session until the client goes away (or a fault ends it).

        Runs on the caller's thread. The ways a session ends - a client
        hang-up (``EOFError`` from ``read_exact``), a broken stream
        (``OSError``) or a fault's deliberate :class:`~.session._Drop` - are
        all normal here and swallowed; any other exception is a bug in a
        handler and propagates. Handles still open are closed either way.
        """
        with self._lock:
            self.sessions += 1
        session = _Session(self, read_exact, write)
        try:
            session.run()
        except (_Drop, EOFError, OSError):
            pass
        finally:
            session.close_all()

    # -- paths ---------------------------------------------------------------------

    def local(self, path: bytes | str) -> str:
        """The local file an SFTP path names; never outside ``root``.

        Relative paths are taken from ``/`` (sftp-server would take them from
        the user's home; here home is the root). Normalising after prefixing
        ``/`` drops any ``..`` that would climb above it. Symlinks are not
        resolved, so a link inside the root may still point out of it, as on
        a real server. Non-UTF-8 bytes survive via ``surrogateescape``.
        """
        text = path.decode("utf-8", "surrogateescape") if isinstance(path, bytes) else path
        clean = posixpath.normpath("/" + text)
        return self.root + ("" if clean == "/" else clean)

    def remote(self, local: str) -> str:
        """The SFTP path of a local path under ``root``; the inverse of :meth:`local`."""
        relative = os.path.relpath(local, self.root)
        return "/" if relative == "." else "/" + relative


class _SocketIO:
    """The server end of a socket as the ``read_exact``/``write``/``close`` a session needs.

    Also used by tests that accept their own socket (paramiko's) and hand it
    to :meth:`SFTPServer.start`.
    """

    def __init__(self, sock: socket.socket) -> None:
        """Wrap the server end of a connected socket; :meth:`close` closes it."""
        self.sock = sock

    def read_exact(self, count: int) -> bytes:
        """Exactly ``count`` bytes; ``EOFError`` if the client hangs up first.

        ``EOFError`` is how every stream tells :meth:`SFTPServer.serve` the
        session is over, so it must be raised even mid-packet.
        """
        chunks = bytearray()
        while len(chunks) < count:
            got = self.sock.recv(count - len(chunks))
            if not got:
                raise EOFError
            chunks += got
        return bytes(chunks)

    def write(self, data: bytes) -> None:
        """Send one whole reply; the session never writes partial packets."""
        self.sock.sendall(data)

    def close(self) -> None:
        """Close the socket; the client then reads end of stream."""
        self.sock.close()
