"""The ``streamed`` copy mode: the bytes go through this process.

An HTTP source is read with :class:`~._io.HTTPReadFile` (Metalink failover
included) and written with :class:`~._io.HTTPWriteFile` - or, for an object
store that wants one, a multipart upload - through the core's ``pump``. A
``file://`` source is one ``PUT`` whose body goes out with ``sendfile``
(xrdhttp's :func:`~xrdhttp.wire.send_file`), restarted from the top
if the link drops, since a ``PUT`` commits nothing until it completes.
Failures are worded as gfal2 words them: ``<why> (source)`` or
``<why> (destination)``.

This is the last mode :func:`._copy.run_modes` falls back to, and the only
one for a ``file://`` source or with ``ENABLE_REMOTE_COPY`` off. It is
davix's ``DavixCopy`` "streamed" path in spirit only: davix pipes a ``GET``
into a ``PUT`` inside libdavix, where here the core's
:func:`~xgfalclient.transfer.pump` moves blocks between two plugin files, so
progress, cancellation and the timeout are checked by the same code as every
other streamed copy. The bytes cross this process once, single-threaded:
for big HTTP-to-HTTP copies a third-party mode is always preferable, which
is why this one comes last.
"""

from __future__ import annotations

import errno
import os
from typing import TYPE_CHECKING, BinaryIO

from ...errors import GError
from ...plugin import O_CREAT, O_TRUNC, O_WRONLY, PluginFile
from ...transfer import Transfer, pump
from ...url import scheme_of
from ._client import FileBody, TransportError
from ._copy_common import _CHECKSUM_TARGET, _deadline_timeout, local_path, resolved
from ._io import HTTPReadFile, HTTPWriteFile

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["streamed", "upload"]


class _SourceError(GError):
    """A failure reading the source during a streamed copy.

    A distinct type, not a flag, so :func:`_destination` can tell - after
    the error has crossed :func:`~xgfalclient.transfer.pump` and a writer's
    ``close`` - which side it came from without parsing the message.
    """


class _Tagged(PluginFile):
    """The source of a streamed copy, its failures marked as the source's."""

    def __init__(self, inner: PluginFile) -> None:
        """Wrap ``inner``; it stays the caller's to close."""
        super().__init__(inner.url)
        self._inner = inner

    def readinto(self, buffer: memoryview | bytearray) -> int:
        """The inner file's ``readinto``, a failure re-raised as ``<why> (source)``."""
        try:
            return self._inner.readinto(buffer)
        except GError as exc:
            raise _SourceError(f"{exc.message} (source)", exc.code) from exc


def _destination(exc: GError) -> GError:
    """gfal2's ``<why> (destination)``, unless the source failed or the copy stopped.

    A cancel or timeout is the copy's, not either end's: gfal2 reports it
    bare, and FTS classifies it by that errno and message.
    """
    if isinstance(exc, _SourceError) or exc.code in (errno.ECANCELED, errno.ETIMEDOUT):
        return exc
    return GError(f"{exc.message} (destination)", exc.code)


def _upload_headers(transfer: Transfer) -> dict[str, str]:
    """``Content-MD5`` with the user's value as typed, when the target is checked by MD5.

    gfal2 sends it so a server that checks ``Content-MD5`` (RFC 1864; S3
    does) refuses a corrupted body outright. The value is passed through
    unaltered - gfal2 does not convert hex to the base64 the RFC asks for,
    and a server that wants base64 then refuses, as it refuses gfal2.
    """
    if (
        not transfer.params.strict_copy
        and int(transfer.checksum_mode) & _CHECKSUM_TARGET
        and transfer.checksum_algorithm.lower() == "md5"
        and transfer.user_checksum
    ):
        return {"Content-MD5": transfer.user_checksum}
    return {}


def streamed(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """One ``streamed`` attempt: HTTP to HTTP through this process, or a ``file://`` upload.

    The source is stat'ed first, for its size (a ``PUT`` needs a
    ``Content-Length``) and to refuse a directory (``EISDIR``). Every
    failure comes out tagged with the end it belongs to.
    """
    if scheme_of(transfer.source) == "file":
        upload(plugin, transfer)
        return
    info = plugin.stat(transfer.source)
    if info.is_dir():
        raise GError(f"{transfer.source} is a directory", errno.EISDIR)
    size = info.st_size
    transfer.source_size = size
    reader = HTTPReadFile(
        plugin, transfer.source, size, active=plugin._metalink_start(transfer.source)
    )
    try:
        destination = resolved(plugin, transfer.destination)
        # An S3 destination over the multipart threshold needs
        # ``plugin.open``'s multipart writer; anything else streams one PUT.
        writer = (
            plugin.open(destination, O_WRONLY | O_CREAT | O_TRUNC, 0o644, size)
            if plugin._multipart(destination)
            else HTTPWriteFile(plugin, destination, size, _upload_headers(transfer))
        )
        try:
            total = pump(transfer, _Tagged(reader), writer)
            if total != size:
                # Raised before the writer closes, so that it abandons the
                # upload rather than completing a truncated one.
                raise _SourceError(
                    f"Short copy: {total} bytes transferred, the source has {size} (source)",
                    errno.EIO,
                )
        finally:
            writer.close()
    except GError as exc:
        raise _destination(exc) from None
    finally:
        reader.close()


def upload(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """``file://`` to HTTP: one ``PUT``, its body sent with ``sendfile``.

    Used both as a ``streamed`` attempt and by the plugin's own upload path.
    An unreadable local source is ``Could not open source: ...``, gfal2's
    wording for the same failure in its file plugin.
    """
    with _open_source(local_path(transfer.source)) as handle:
        size = os.fstat(handle.fileno()).st_size
        transfer.source_size = size
        _put_with_retry(plugin, transfer, handle, size)
    transfer.progress(size, force=True)


def _open_source(path: str) -> BinaryIO:
    """The local source, opened for reading; gfal2's ``Could not open source`` if it cannot be.

    Only the open is translated: a failure of the upload itself, inside the
    caller's ``with``, keeps its own error.
    """
    try:
        return open(path, "rb")
    except OSError as exc:
        raise GError(f"Could not open source: {exc.strerror}", exc.errno or errno.EIO) from exc


def _put_with_retry(plugin: HTTPPlugin, transfer: Transfer, handle: BinaryIO, size: int) -> None:
    """``PUT`` the whole file, restarting it if a flaky link drops the body.

    A ``PUT`` replaces the whole resource, so a dropped one leaves nothing to
    resume from - but nothing committed either, so it is safe to send again
    from the start, up to ``CONN_RETRY`` times. A refusal (a bad status) is
    the server's answer, not a broken link, and is not retried.
    """
    destination = resolved(plugin, transfer.destination)
    headers = _upload_headers(transfer)
    attempts = 0
    sent = transfer.transferred

    def progress(count: int) -> None:
        """Called by the sender after every slice; raising stops the upload."""
        transfer.add(count)
        transfer.check()

    while True:
        handle.seek(0)
        try:
            plugin._put_file(
                destination,
                FileBody(handle, 0, size, progress),
                size,
                timeout=_deadline_timeout(transfer, plugin.io_timeout()),
                headers=headers,
            )
            return
        except TransportError as exc:
            attempts += 1
            if attempts > plugin.conn_retry():
                raise _destination(exc) from None
            transfer.transferred = sent  # undo the abandoned attempt's progress
            plugin.retry_pause(attempts)
        except GError as exc:
            raise _destination(exc) from None
