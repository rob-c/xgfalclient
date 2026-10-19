"""Open HTTP files: ranged reads, and uploads that stream or spool.

Reading keeps one ``GET`` open for as long as reads are sequential - the
copy engine's ``readinto`` loop, or ``FileType.read`` - so a whole file is
one request however small the reads, and a seek just starts another one
with a ``Range``. ``pread`` is always its own ranged request, which is what
makes it safe to call from several threads at once.

Writing is a ``PUT``, and HTTP needs the length up front (or chunked
encoding, which too many storage elements refuse). When the caller knows
the size - the copy engine passes it as ``open(..., size=N)`` - the ``PUT``
starts at once and each ``write`` goes straight onto the socket; otherwise
the data is spooled to a temporary file and sent with ``sendfile`` on
``close``. Either way the server's verdict arrives on ``close``, which is
where an upload's errors surface, exactly as with gfal2.

Reads fail over as davix's Metalink support does: a read whose server
fails (after ``[HTTP PLUGIN] CONN_RETRY`` resumptions, for a dropped link)
moves to the next replica the Metalink names, never back to one this
handle has tried; a timeout is reported as it is, never failed over.
Writes have one destination and no failover. The plugin opens these through
``HTTPPlugin.open``; :mod:`._ranged` reuses :class:`HTTPReadFile` for its
single-stream fallback.
"""

from __future__ import annotations

import errno
import sys
import tempfile
import threading
from typing import TYPE_CHECKING

from ...errors import GError
from ...plugin import PluginFile
from ._client import PUT, FileBody, Response, TransportError, Upload, status_error

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["HTTPReadFile", "HTTPWriteFile", "check_upload"]

#: Upload statuses that mean the file is there: replaced (200, 204) or created
#: (201), per RFC 9110 section 9.3.4.
UPLOAD_OK = (200, 201, 204)


def check_upload(response: Response) -> None:
    """Raise the gfal2-worded error for a ``PUT`` that did not succeed.

    Read in the ``PUT`` scope, where a ``409 Conflict`` is RFC 4918's
    missing parent collection (``ENOENT``) rather than an existing file.
    The response is closed either way, its connection pooled when clean.
    """
    with response:
        if response.status not in UPLOAD_OK:
            raise status_error(response.status, scope=PUT)


class HTTPReadFile(PluginFile):
    """A remote file opened for reading.

    Sequential reads (:meth:`readinto`, :meth:`read`) share one streaming
    ``GET`` and the handle's position, so they are for one thread at a
    time; :meth:`pread` uses neither and may run on many threads at once.
    The replica in use (``_active``) is shared by both and guarded by
    ``_replica_lock``.
    """

    def __init__(
        self, plugin: HTTPPlugin, url: str, size: int, *, active: str | None = None
    ) -> None:
        """A reader of ``size`` bytes (from the caller's stat) at ``url``.

        ``active`` is the replica to start from when the plugin has already
        chosen one (a Metalink-preferred mirror); ``url`` stays the file's
        name for messages and for asking for replicas.
        """
        super().__init__(url)
        self._plugin = plugin
        self._size = size
        self._active = active or url
        # Every replica this handle has read from, so a failover never cycles
        # back to a server that already failed it.
        self._tried = {self._active}
        self._replica_lock = threading.Lock()
        #: The open sequential ``GET``, and the file offset its next byte is at.
        self._stream: Response | None = None
        self._stream_at = 0

    def size(self) -> int:
        """The size the file was opened with; reads stop there whatever the server sends."""
        return self._size

    def _drop(self) -> None:
        """Close the sequential stream; unread, its connection is not pooled."""
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def _open_stream(self) -> Response:
        """The sequential ``GET`` positioned at :attr:`position`, reused if it already is.

        A seek since the last read makes the old stream useless: it is
        dropped and a new ``Range: bytes=<position>-`` (open-ended, so the
        rest of the file is one request) takes its place. ``416 Range Not
        Satisfiable`` means the position is at or past the end.
        """
        if self._stream is not None and self._stream_at == self.position:
            return self._stream
        self._drop()
        headers = {"Range": f"bytes={self.position}-"} if self.position else {}
        response = self._plugin._get(self._active, headers)
        if response.status == 416:
            response.close()
            raise _EOFError
        # ``_get`` has already raised for anything but 200, 206 and 416. A
        # 200 to a ranged request is the whole file from byte 0.
        if self.position and response.status == 200:
            _skip(response, self.position)  # a server that ignores Range
        self._stream, self._stream_at = response, self.position
        return response

    def readinto(self, buffer: memoryview | bytearray) -> int:
        """Read at :attr:`position` into ``buffer``; ``0`` at the end of the file.

        A short count is normal (one socket read's worth); callers loop.
        """
        # Cast to bytes so a buffer of wider items is filled byte for byte.
        view = memoryview(buffer).cast("B")
        if not view.nbytes or self.position >= self._size:
            return 0
        # A GET whose connection *drops* before the file's end is resumed with
        # a fresh ranged GET from where it got to, so a flaky link costs a
        # reconnect rather than a lost read. A response that ends cleanly at
        # its own declared length is not a drop - it is what the server chose
        # to send - and is passed on as the end, as it was before.
        attempts = 0
        while True:
            try:
                stream = self._open_stream()
                count = stream.readinto(view)
            except _EOFError:
                return 0
            # Order matters: TransportError is a GError. A dropped link is
            # resumed on the same server first; a server's refusal (any other
            # GError) goes straight to the next replica.
            except TransportError as exc:
                attempts = self._retry_stream(exc, attempts)
                continue
            except GError as exc:
                attempts = self._failover_stream(exc)
                continue
            if count > 0:
                self._stream_at += count
                self.position += count
                return count
            # A clean end of this response - honoured, not resumed.
            self._drop()
            return 0

    def _retry_stream(self, error: TransportError, attempts: int) -> int:
        """Resume a dropped body, then try another replica if retries run out.

        Returns the attempt count for the next try (``0`` on a new replica,
        which gets a fresh budget); raises ``EIO`` naming the offset reached.
        """
        self._drop()
        attempts += 1
        if attempts <= self._plugin.conn_retry():
            self._plugin.retry_pause(attempts)
            return attempts
        if error.code != errno.ETIMEDOUT and self._next_replica():
            return 0
        raise GError(
            f"connection closed at {self.position} of {self._size} bytes reading {self.url}",
            errno.EIO,
        ) from None

    def _failover_stream(self, error: GError) -> int:
        """Try another replica for a server failure, or preserve the failure.

        The original error is re-raised unchanged when there is nowhere to
        go, so a 404 is still ``ENOENT`` with davix's words.
        """
        self._drop()
        if error.code != errno.ETIMEDOUT and self._next_replica():
            return 0
        raise error

    def read(self, size: int) -> bytes:
        """Up to ``size`` bytes from :attr:`position`, fewer only at the end of the file."""
        buffer = bytearray(max(size, 0))
        view = memoryview(buffer)
        got = 0
        while got < size:
            count = self.readinto(view[got:])
            if count <= 0:
                break
            got += count
        # The view must be released before the bytearray may be resized.
        view.release()
        del buffer[got:]
        return bytes(buffer)

    def pread(self, offset: int, size: int) -> bytes:
        """``size`` bytes at ``offset``, as one closed ``Range`` request; position untouched.

        Short only at the end of the file. A range cut short is resumed from
        the byte it reached; the retry budget restarts whenever a resumption
        made progress, so a slow-but-alive link is not abandoned. Exhausted,
        it moves to another replica, and with none left fails ``EIO``.
        """
        size = min(size, max(self._size - offset, 0))
        if size <= 0:
            return b""
        buffer = bytearray(size)
        view = memoryview(buffer)
        got = attempts = 0
        try:
            while True:
                before = got
                try:
                    got += self._read_range(offset + got, view[got:])
                    if got >= size:
                        break
                    # The stat said these bytes exist. A cleanly short body is
                    # therefore a lost transfer too, even when http.client did
                    # not turn the premature EOF into an exception.
                    error = TransportError(
                        "Connection terminated before the range arrived", errno.EIO
                    )
                except _PartialRange as cut:
                    got += cut.count
                    error = cut.error
                except GError as caught:
                    # A server's refusal (a status error): no point resuming
                    # from the same server, so straight to another replica.
                    if caught.code == errno.ETIMEDOUT or not self._next_replica():
                        raise
                    attempts = 0
                    continue
                attempts = self._retry_pread(
                    error,
                    attempts,
                    progressed=got > before,
                    position=offset + got,
                    end=offset + size,
                )
            return bytes(view[:got])
        finally:
            view.release()

    def _read_range(self, offset: int, view: memoryview) -> int:
        """Read one HTTP range, retaining its byte count if the link drops.

        A ``200`` (a server that ignores ``Range``) is skipped forward to
        ``offset``; a ``416`` reads nothing. A drop after some bytes is
        :class:`_PartialRange`, so the caller can keep what arrived.
        """
        headers = {"Range": f"bytes={offset}-{offset + len(view) - 1}"}
        got = 0
        try:
            response = self._plugin._get(self._active, headers)
            with response:
                if response.status == 416:
                    return 0
                if response.status == 200:
                    _skip(response, offset)
                while got < len(view):
                    count = response.readinto(view[got:])
                    if count <= 0:
                        break
                    got += count
        except TransportError as error:
            raise _PartialRange(got, error) from error
        return got

    def _retry_pread(
        self,
        error: TransportError,
        attempts: int,
        *,
        progressed: bool,
        position: int,
        end: int,
    ) -> int:
        """Retry one interrupted range, switch replica, or report a short read.

        ``progressed`` resets the budget to one attempt used: the link is
        alive, just unreliable. ``position``/``end`` only word the failure.
        """
        if error.code == errno.ETIMEDOUT:
            raise error
        attempts = 1 if progressed else attempts + 1
        if attempts <= self._plugin.conn_retry():
            self._plugin.retry_pause(attempts)
            return attempts
        if self._next_replica():
            return 0
        raise GError(
            f"connection closed at {position} of {end} bytes reading {self.url}", errno.EIO
        ) from None

    def _next_replica(self) -> bool:
        """Switch to an advertised replica not tried by this handle.

        The Metalink is asked for only once something has failed (the plugin
        caches it), so a healthy read never pays for it; one that cannot be
        had means there is nowhere to go. Thread-safe: parallel ``pread`` calls that
        fail together each move on to a *different* untried replica.
        """
        try:
            replicas = self._plugin._metalink_replicas(self.url)
        except GError:
            return False
        with self._replica_lock:
            candidate = next((item for item in replicas if item not in self._tried), None)
            if candidate is None:
                return False
            self._tried.add(candidate)
            self._active = candidate
        return True

    def close(self) -> None:
        """Drop any open stream; closing twice is harmless."""
        self._drop()
        super().close()


class _EOFError(Exception):
    """A ranged read that started at or past the end of the file."""


class _PartialRange(Exception):
    """A range body that failed after ``count`` bytes had already landed."""

    def __init__(self, count: int, error: TransportError) -> None:
        """Carry ``count`` (bytes already in the caller's buffer) and the drop itself."""
        super().__init__(str(error))
        self.count = count
        self.error = error


def _skip(response: Response, count: int) -> None:
    """Discard ``count`` bytes: the price of a server that does not do ranges.

    Ignoring ``Range`` is allowed (RFC 9110 section 14.2), so this keeps a
    plain web server readable at any offset, at the cost of reading the
    file up to it. A body that ends early just stops; the read that follows
    sees the end.
    """
    buffer = bytearray(min(count, 1 << 20))
    view = memoryview(buffer)
    while count > 0:
        got = response.readinto(view[: min(count, len(buffer))])
        if got <= 0:
            return
        count -= got


class HTTPWriteFile(PluginFile):
    """A remote file opened for writing; the ``PUT`` completes on :meth:`close`.

    Writes are strictly sequential - an HTTP body cannot seek - and one
    thread at a time. The upload has succeeded only when :meth:`close`
    returns without raising.
    """

    def __init__(
        self,
        plugin: HTTPPlugin,
        url: str,
        size: int | None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """A writer of ``size`` bytes streamed, or (``None``) of whatever is written, spooled.

        ``headers`` go on the ``PUT`` (an object store's checksum header, for
        one). Nothing is sent yet: a streamed upload starts on the first
        write, or at :meth:`close` for a file never written to - which then
        sends an empty body, a short one (``EIO``) if ``size`` was not 0.
        """
        super().__init__(url)
        self._plugin = plugin
        self._size = size
        self._headers = headers or {}
        self._upload: Upload | None = None
        # With no size the body is spooled to an anonymous temporary file
        # (deleted on close by the OS), so memory use stays flat however big
        # the upload, and ``sendfile`` can send it in one go at the end.
        self._spool = (
            # SIM115: the spool outlives this call - write() fills it and
            # close() sends and closes it - so no ``with`` can hold it.
            tempfile.TemporaryFile(prefix="xgfal-put-")  # noqa: SIM115
            if size is None
            else None
        )

    def _start(self) -> Upload:
        """The streamed ``PUT``, its head sent (and redirects followed) on first use."""
        if self._upload is None:
            assert self._size is not None
            self._upload = self._plugin.client.upload(
                self.url, self._size, headers=self._headers, timeout=self._plugin.io_timeout()
            )
        return self._upload

    def write(self, data: bytes | bytearray | memoryview) -> int:
        """Append ``data`` to the upload (or the spool); every byte is taken or it raises."""
        size = memoryview(data).nbytes
        if self._spool is not None:
            self._spool.write(data)
        else:
            self._start().write(data)
        self.position += size
        return size

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        """A :meth:`write` that must land exactly at the end (``ESPIPE`` otherwise).

        Callers that write by offset must therefore write in order; an
        out-of-order one is refused rather than silently corrupting the
        object.
        """
        if offset != self.position:
            raise GError("HTTP uploads are sequential: pwrite must continue the file", errno.ESPIPE)
        return self.write(data)

    def close(self) -> None:
        """Finish the upload and report the server's verdict, or abandon it on failure.

        A spooled file is sent now through the plugin's ``_put_file``, which
        may make it an S3 multipart upload. The spool is removed either way.
        """
        if self.closed:
            return
        # Closing while an exception unwinds (the copy failed mid-stream) must
        # abandon the upload, not complete a truncated one - and must not
        # replace the real error with a complaint about the short body.
        failing = sys.exc_info()[1] is not None
        try:
            if self._spool is not None:
                if not failing:
                    self._spool.flush()
                    self._plugin._put_file(
                        self.url,
                        FileBody(self._spool, 0, self.position),
                        self.position,
                        headers=self._headers,
                    )
            elif failing:
                if self._upload is not None:
                    self._upload.abort()
            else:
                check_upload(self._start().finish())
        finally:
            if self._spool is not None:
                self._spool.close()
            super().close()
