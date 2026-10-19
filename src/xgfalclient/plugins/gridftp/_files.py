"""GridFTP file handles: what ``ctx.open`` returns for ``gsiftp://`` and ``ftp://``.

Part of the :mod:`xgfalclient.plugins.gridftp.plugin` split (that module's
docstring has gfal2's I/O behaviour). :class:`_FilesMixin` is the plugin's
``open`` and its partial ``ERET``/``ESTO`` helpers; it picks one of three
handles: :class:`_ReadFile` (a ``RETR`` stream, ``REST`` after a seek),
:class:`_WriteFile` (a ``STOR`` stream whose verdict comes at ``close``) and
:class:`_PartialFile` (``O_RDWR``: every read an ``ERET``, every write an
``ESTO``). :func:`_stream_open` and :class:`_Opener` open the one ``MODE S``
data connection a stream needs, handshaking ``DCAU A`` on a thread while the
control channel is watched.

No module-level name here is looked up through the facade: nothing patches
one. Patch a helper in this module if a test needs to.

Session ownership. A stream handle holds one borrowed session for as long as
its ``RETR``/``STOR`` is open, because the transfer's final reply is still
owed on that control connection. The handle enters the session's context
manager by hand (``_session_cm``) and must exit it exactly once: on a clean
end the session goes back to the pool; on anything else - an abandoned read,
a failure, a seek away from the stream - it is first marked broken, since the
server is still in the middle of a transfer, and is closed instead. Partial
operations (``ERET``/``ESTO``) borrow a session of their own per call.

Handles are not thread-safe; like gfal2's, one is used by one thread at a
time.
"""

from __future__ import annotations

import errno
import os
import socket
import threading
from typing import Any

from ...errors import GError
from ...plugin import O_ACCMODE_MASK, O_CREAT, O_RDONLY, O_WRONLY, PluginFile
from ...url import URL, parse
from ._base import GROUP, _GridFTPBase, _path, _Session
from .control import connect_error
from .data import DataConn, passive, routable
from .protocol import parse_pasv, reply_error


class _FilesMixin(_GridFTPBase):
    """``open`` and the partial reads and writes behind it: see the module docstring."""

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        """gfal2's modes: read-only is ``RETR``, ``O_WRONLY``/``O_CREAT`` is ``STOR``
        (so ``"rw"`` truncates), and ``O_RDWR`` alone is partial ``ERET``/``ESTO``."""
        parsed = parse(url)
        if flags & O_ACCMODE_MASK == O_RDONLY:
            return _ReadFile(self, url, parsed)
        if flags & (O_WRONLY | O_CREAT):
            return _WriteFile(self, url, parsed, size)
        return _PartialFile(self, url, parsed)

    def _partial_put(
        self, url: str, parsed: URL, data: bytes | bytearray | memoryview, offset: int
    ) -> int:
        """``ESTO A offset path`` on a session of its own: a write at ``offset``.

        GFD.20's adjusted store writes the stream's bytes starting at
        ``offset`` without truncating the file. One ``ESTO`` per call, so each
        partial write costs a data connection.
        """
        handle = _WriteFile(self, url, parsed, None, f"ESTO A {offset} {_path(parsed)}")
        try:
            return handle.write(data)
        finally:
            handle.close()

    def _partial_get(self, parsed: URL, offset: int, size: int) -> bytes:
        """``ERET P offset size path`` (GFD.20 partial retrieve): ``size`` bytes at ``offset``.

        Fewer bytes come back past the end of the file. Runs over a ``MODE
        S`` stream on its own pooled session.
        """
        with self._session(parsed) as session:
            return self._fetch(session, f"ERET P {offset} {size} {_path(parsed)}")


class _ReadFile(PluginFile):
    """A ``RETR`` stream read in order; ``REST`` restarts it after a seek."""

    def __init__(self, plugin: _FilesMixin, url: str, parsed: URL) -> None:
        """Open lazily: no stream until the first read.

        With ``STAT_ON_OPEN`` (gfal2's default) the file is statted first, so
        a missing file fails at ``open`` with gfal2's open error and the
        size is known up front; other stat errors propagate unchanged.
        """
        super().__init__(url)
        self.plugin = plugin
        self.parsed = parsed
        self.path = _path(parsed)
        #: The borrowed session's context manager, entered by hand; ``None``
        #: while no stream is open.
        self._session_cm: Any = None
        self._session: _Session | None = None
        self._conn: DataConn | None = None
        #: The file offset the open stream will deliver next; -1 for none.
        #: A read at any other position restarts the stream there.
        self._stream_at = -1
        #: Where the file ends, once known: from the stat, or the stream's end.
        self._size: int | None = None
        if plugin.options.boolean(GROUP, "STAT_ON_OPEN", True):
            with plugin._session(parsed) as session:
                try:
                    info = plugin._stat(session.control, self.path)
                except GError as exc:
                    if exc.code != errno.ENOENT:
                        raise
                    raise _open_error(exc, url) from exc
            # gfal2 opens a directory, and reading it gives nothing.
            self._size = 0 if info.is_dir() else info.st_size

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Move the cursor only; the stream restarts at the next read if it moved."""
        return _lseek(self, offset, whence)

    def _start(self) -> None:
        """(Re)open the ``RETR`` stream at :attr:`position`.

        Any open stream is dropped first (and its session discarded). A
        non-zero position is ``REST n`` (RFC 3659 §5, answered ``350``)
        before ``RETR``; GridFTP v2 ``GET`` has no offset, so it is only used
        from the start.
        """
        self._stop()
        self._session_cm = self.plugin._session(self.parsed)
        self._session = session = self._session_cm.__enter__()
        control = session.control
        control.setting("MODE", "S")
        if self.position:
            control.command(f"REST {self.position}", ok=(3,))
        getput = not self.position and self.plugin._getput(control)
        command = f"GET file={self.path};pasv;" if getput else f"RETR {self.path}"
        self._conn = _stream_open(self.plugin, session, command, self.url, getput)
        self._stream_at = self.position

    def _stop(self, clean: bool = False) -> None:
        """Close the stream and give the session back; idempotent.

        ``clean`` means the final reply has been read and the session is in
        step; otherwise the server may still be sending, so the session is
        marked broken and closed rather than pooled.
        """
        if self._session_cm is None:
            return
        assert self._session is not None
        if self._conn is not None:
            self._conn.sock.close()
            self._conn = None
        if not clean:
            self._session.control.broken = True
        cm, self._session_cm, self._session = self._session_cm, None, None
        cm.__exit__(None, None, None)

    def readinto(self, buffer: memoryview | bytearray) -> int:
        """Fill ``buffer`` from the stream; short only at the end of the file.

        Past the known size nothing is sent to the server. At the end of
        the stream the final reply is read (a failure there, such as a
        ``426`` for a transfer the server aborted, raises even though bytes
        arrived) and the size becomes known, so later reads return 0 at once.
        """
        view = memoryview(buffer).cast("B")
        if self._size is not None and self.position >= self._size:
            return 0
        if self._conn is None or self._stream_at != self.position:
            self._start()
        assert self._conn is not None
        got = 0
        while got < len(view):
            count = self._conn.recv_into(view[got:])
            if count == 0:
                self._finish()
                self._size = self.position + got
                break
            got += count
        self.position += got
        self._stream_at += got
        return got

    def _finish(self) -> None:
        """The stream ended: read the ``RETR``'s final reply, then release cleanly."""
        assert self._session is not None
        try:
            self._session.control.final()
        except GError:
            self._stop()
            raise
        self._stop(clean=True)

    def read(self, size: int) -> bytes:
        """Up to ``size`` bytes at the cursor, as :meth:`readinto` reads them."""
        buffer = bytearray(max(0, size))
        count = self.readinto(buffer)
        return bytes(buffer[:count])

    def pread(self, offset: int, size: int) -> bytes:
        """``size`` bytes at ``offset`` without moving the cursor.

        ``ERET P`` on a session of its own when the server advertises
        ``ERET``; otherwise a ``REST`` + ``RETR`` that is dropped after
        ``size`` bytes (which costs the stream's session). The request is
        clipped to the known size so no command asks past the end.
        """
        if size <= 0 or (self._size is not None and offset >= self._size):
            return b""
        if self._size is not None:
            size = min(size, self._size - offset)
        with self.plugin._session(self.parsed) as session:
            if session.control.supports("ERET"):
                return self.plugin._fetch(session, f"ERET P {offset} {size} {self.path}")
        saved = self.position
        try:
            self.position = offset
            return self.read(size)
        finally:
            self._stop()
            self.position = saved

    def close(self) -> None:
        """Drop any open stream (its session is discarded, not pooled)."""
        self._stop()
        super().close()


class _WriteFile(PluginFile):
    """A ``STOR`` stream; the server's verdict arrives on :meth:`close`.

    A write anywhere but at the end of what the stream has sent - after a
    seek, which commits the stream, or a ``pwrite`` - is gfal2's partial
    put, an ``ESTO``.
    """

    def __init__(
        self,
        plugin: _FilesMixin,
        url: str,
        parsed: URL,
        size: int | None,
        command: str | None = None,
    ) -> None:
        """Start the upload at once, so ``open`` fails if the server refuses it.

        ``size`` (when the caller knows it) is announced with ``ALLO``
        (RFC 959 §4.1.3), which some servers need to reserve storage; a
        refusal is ignored. ``command`` overrides ``STOR``/``PUT``
        (``ESTO A ...`` for a partial put). If anything fails here the
        session is discarded before the error propagates.
        """
        super().__init__(url)
        self.plugin = plugin
        self.parsed = parsed
        #: Bytes sent on the stream so far: the only offset it can extend.
        self._stream_at = 0
        self._session_cm = plugin._session(parsed)
        self._session: _Session = self._session_cm.__enter__()
        try:
            control = self._session.control
            control.setting("MODE", "S")
            if size is not None:
                control.command(f"ALLO {size}", ok=(2, 4, 5))
            getput = command is None and plugin._getput(control)
            if command is None:
                path = _path(parsed)
                command = f"PUT file={path};pasv;" if getput else f"STOR {path}"
            self._conn: DataConn | None = _stream_open(plugin, self._session, command, url, getput)
        except BaseException:
            self._session.control.broken = True
            self._session_cm.__exit__(None, None, None)
            raise

    def write(self, data: bytes | bytearray | memoryview) -> int:
        """Send ``data`` at the cursor: on the stream, or as an ``ESTO`` once it is committed.

        A send failure is gfal2's ``gridftp write error`` (``EIO``) and
        breaks the session; the server's reason, if any, comes at
        :meth:`close`. Writing to a closed handle is ``EBADF``.
        """
        if self.closed:
            raise GError("I/O operation on a closed file", errno.EBADF)
        if self._conn is None:  # committed by a seek: gfal2's partial put
            count = self.plugin._partial_put(self.url, self.parsed, data, self.position)
        else:
            try:
                self._conn.sendall(data)
            except OSError as exc:
                self._session.control.broken = True
                raise GError(
                    f"gridftp write error : {exc.strerror or exc} on url {self.url}", errno.EIO
                ) from exc
            count = len(memoryview(data).cast("B"))
            self._stream_at += count
        self.position += count
        return count

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        """An ``ESTO`` at ``offset`` on its own session; the stream and cursor are untouched."""
        if self.closed:
            raise GError("I/O operation on a closed file", errno.EBADF)
        return self.plugin._partial_put(self.url, self.parsed, data, offset)

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Move the cursor; moving it off the stream's end commits the ``STOR``.

        The commit waits for the server's verdict, so a failed upload is
        reported here rather than lost; later writes are ``ESTO``\\ s.
        """
        target = _lseek(self, offset, whence)
        if target != self._stream_at:
            self._commit()
        return target

    def _commit(self) -> None:
        """End the ``STOR`` stream; its reply decides whether the upload worked."""
        conn, self._conn = self._conn, None
        if conn is None:
            return
        control = self._session.control
        try:
            conn.finish()
            control.final()
        except GError:
            control.broken = True
            raise

    def close(self) -> None:
        """Commit the stream (raising the server's verdict) and give the session back."""
        if self.closed:
            return
        self.closed = True
        try:
            self._commit()
        finally:
            self._session_cm.__exit__(None, None, None)


class _PartialFile(PluginFile):
    """``O_RDWR`` without ``O_CREAT``: every read an ``ERET``, every write an ``ESTO``."""

    def __init__(self, plugin: _FilesMixin, url: str, parsed: URL) -> None:
        """No I/O and no session: each call opens its own."""
        super().__init__(url)
        self.plugin = plugin
        self.parsed = parsed

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Move the cursor that ``read``/``write`` use (``SEEK_END`` is refused)."""
        return _lseek(self, offset, whence)

    def pread(self, offset: int, size: int) -> bytes:
        """An ``ERET P`` of ``size`` bytes at ``offset``."""
        return self.plugin._partial_get(self.parsed, offset, max(0, size))

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        """An ``ESTO A`` of ``data`` at ``offset``."""
        return self.plugin._partial_put(self.url, self.parsed, data, offset)


def _lseek(handle: PluginFile, offset: int, whence: int) -> int:
    """gfal2's GridFTP seek: from the start or the cursor only.

    ``SEEK_END`` would need the size, which a stream handle may not know;
    gfal2 refuses it, and so does this, with ``EINVAL``.
    """
    if whence not in (os.SEEK_SET, os.SEEK_CUR):
        raise GError("Invalid whence", errno.EINVAL)
    return PluginFile.lseek(handle, offset, whence)


def _open_error(exc: GError, url: str) -> GError:
    """gfal2's open failure text (leading space and all), keeping ``exc``'s ``errno``."""
    return GError(f" gridftp open error : {os.strerror(exc.code)} on url {url}", exc.code)


class _Opener:
    """Connect (and, under ``DCAU A``, authenticate) one stream's data channel.

    globus says ``150`` only once the data channel is authenticated, so the
    handshake runs on a thread while the control channel is watched: waiting
    for ``150`` first would deadlock, and handshaking first would hang on a
    server that refused the command instead.
    """

    def __init__(self, session: _Session) -> None:
        """Nothing connected yet; :meth:`start` once the address is known."""
        self.session = session
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        #: One entry, written by the thread: the connection or its failure.
        self.result: list[DataConn | BaseException] = []

    def start(self, host: str, port: int) -> None:
        """Connect to ``host:port`` now and handshake on a thread.

        The socket is added to the session's ``data`` so a ``cancel()``
        can shut it down. A refused connect raises at once, in globus_xio's
        words.
        """
        timeout = self.session.profile.timeout
        try:
            self.sock = socket.create_connection((host, port), timeout)
        except OSError as exc:
            raise connect_error(exc, host, port) from exc
        self.session.data.append(self.sock)
        self.thread = threading.Thread(target=self._secure, name="xgfal-gridftp-open", daemon=True)
        self.thread.start()

    def _secure(self) -> None:
        """The thread: ``DCAU A`` (as initiator) if the session wants it; never raises."""
        assert self.sock is not None
        security = self.session.profile.security
        try:
            conn = DataConn(self.sock) if security is None else security.secure(self.sock, True)
            self.result.append(conn)
        except BaseException as exc:  # handed to the opening thread
            self.result.append(exc)

    def finish(self) -> DataConn:
        """The ready connection, after the server's ``150``; re-raises the handshake's failure.

        ``EPROTO`` if the server said ``150`` before any data channel was
        opened (no ``227`` and no ``127``).
        """
        if self.thread is None:
            raise GError("The server started the transfer without a data channel", errno.EPROTO)
        self.thread.join()  # the handshake is bounded by the socket's own timeout
        found = self.result[0]
        if isinstance(found, BaseException):
            raise found
        return found

    def abandon(self) -> None:
        """Close the socket after a failed open; the thread then fails and ends."""
        if self.sock is not None:
            self.sock.close()


def _stream_open(
    plugin: _FilesMixin, session: _Session, command: str, url: str, getput: bool = False
) -> DataConn:
    """Start a ``MODE S`` stream for ``command``; the connection once the server is ready.

    A ``getput`` command (GridFTP v2 ``GET``/``PUT ...;pasv;``) asks for the
    passive address itself.

    The connection starts right after ``PASV`` when the address is known,
    or when the ``127`` reply names it (delayed passive, ``GET``/``PUT``);
    it is handed back at the first ``1xx`` (``150``), the point from which
    the server is moving data. Any other reply fails the open. On failure
    the session is marked broken and the error is gfal2's open error, with
    the cause's ``errno``.
    """
    control = session.control
    opener = _Opener(session)
    try:
        control.setting("TYPE", "I")
        addresses = [] if getput else passive(control, plugin._data_options())
        if addresses:
            opener.start(*addresses[0])
        control.send(command)
        while True:
            reply = control.reply()
            if reply.code == 127 and opener.thread is None:
                host, port = parse_pasv(reply.text)
                opener.start(routable(host, control), port)
            elif reply.kind == 1:
                return opener.finish()
            else:
                raise reply_error(reply)
    except GError as exc:
        control.broken = True
        opener.abandon()
        raise _open_error(exc, url) from exc
