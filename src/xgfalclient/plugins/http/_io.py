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
"""

from __future__ import annotations

import errno
import sys
import tempfile
from typing import TYPE_CHECKING

from ...errors import GError
from ...plugin import PluginFile
from ._client import PUT, FileBody, Response, Upload, status_error

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["HTTPReadFile", "HTTPWriteFile", "check_upload"]

#: Upload statuses that mean the file is there.
UPLOAD_OK = (200, 201, 204)


def check_upload(response: Response) -> None:
    """Raise the gfal2-worded error for a ``PUT`` that did not succeed."""
    with response:
        if response.status not in UPLOAD_OK:
            raise status_error(response.status, scope=PUT)


class HTTPReadFile(PluginFile):
    """A remote file opened for reading."""

    def __init__(self, plugin: HTTPPlugin, url: str, size: int) -> None:
        super().__init__(url)
        self._plugin = plugin
        self._size = size
        self._stream: Response | None = None
        self._stream_at = 0

    def size(self) -> int:
        return self._size

    def _drop(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def _open_stream(self) -> Response:
        if self._stream is not None and self._stream_at == self.position:
            return self._stream
        self._drop()
        headers = {"Range": f"bytes={self.position}-"} if self.position else {}
        response = self._plugin._get(self.url, headers)
        if response.status == 416:
            response.close()
            raise _EOFError
        if self.position and response.status == 200:
            _skip(response, self.position)  # a server that ignores Range
        self._stream, self._stream_at = response, self.position
        return response

    def readinto(self, buffer: memoryview | bytearray) -> int:
        view = memoryview(buffer).cast("B")
        if not view.nbytes or self.position >= self._size:
            return 0
        try:
            stream = self._open_stream()
        except _EOFError:
            return 0
        count = stream.readinto(view)
        if count <= 0:
            self._drop()
            return 0
        self._stream_at += count
        self.position += count
        return count

    def read(self, size: int) -> bytes:
        buffer = bytearray(max(size, 0))
        view = memoryview(buffer)
        got = 0
        while got < size:
            count = self.readinto(view[got:])
            if count <= 0:
                break
            got += count
        view.release()
        del buffer[got:]
        return bytes(buffer)

    def pread(self, offset: int, size: int) -> bytes:
        if size <= 0:
            return b""
        headers = {"Range": f"bytes={offset}-{offset + size - 1}"}
        response = self._plugin._get(self.url, headers)
        with response:
            if response.status == 416:
                return b""
            if response.status == 200:
                _skip(response, offset)
            return _read_exactly(response, size)

    def close(self) -> None:
        self._drop()
        super().close()


class _EOFError(Exception):
    """A ranged read that started at or past the end of the file."""


def _skip(response: Response, count: int) -> None:
    """Discard ``count`` bytes: the price of a server that does not do ranges."""
    buffer = bytearray(min(count, 1 << 20))
    view = memoryview(buffer)
    while count > 0:
        got = response.readinto(view[: min(count, len(buffer))])
        if got <= 0:
            return
        count -= got


def _read_exactly(response: Response, size: int) -> bytes:
    buffer = bytearray(size)
    view = memoryview(buffer)
    got = 0
    while got < size:
        count = response.readinto(view[got:])
        if count <= 0:
            break
        got += count
    view.release()
    del buffer[got:]
    return bytes(buffer)


class HTTPWriteFile(PluginFile):
    """A remote file opened for writing; the ``PUT`` completes on :meth:`close`."""

    def __init__(
        self,
        plugin: HTTPPlugin,
        url: str,
        size: int | None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(url)
        self._plugin = plugin
        self._size = size
        self._headers = headers or {}
        self._upload: Upload | None = None
        self._spool = (
            tempfile.TemporaryFile(prefix="xgfal-put-")  # noqa: SIM115 - closed in close()
            if size is None
            else None
        )

    def _start(self) -> Upload:
        if self._upload is None:
            assert self._size is not None
            self._upload = self._plugin.client.upload(
                self.url, self._size, headers=self._headers, timeout=self._plugin.io_timeout()
            )
        return self._upload

    def write(self, data: bytes | bytearray | memoryview) -> int:
        size = memoryview(data).nbytes
        if self._spool is not None:
            self._spool.write(data)
        else:
            self._start().write(data)
        self.position += size
        return size

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        if offset != self.position:
            raise GError("HTTP uploads are sequential: pwrite must continue the file", errno.ESPIPE)
        return self.write(data)

    def close(self) -> None:
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
