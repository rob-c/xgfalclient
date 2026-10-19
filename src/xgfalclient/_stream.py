"""The core's streamed copy, and the local ``copy_file_range`` fast path.

This is the half of :mod:`xgfalclient.transfer` that moves bytes when no
plugin claims the pair (see that module's docstring for the whole copy
sequence and the reasons it is shaped as it is):

* :func:`stream` opens the source and the destination through their plugins
  and copies one into the other;
* :func:`pump` is the reader-thread pipeline that does the copying, shared
  with plugins that stream a leg themselves (the HTTP and XRootD plugins);
* :func:`copy_range` is the kernel fast path between two regular local
  files, which hands over to :func:`pump` at the offset it reached when it
  cannot go on.

Everything here is re-exported by :mod:`xgfalclient.transfer`, which is
where callers import it from and where the tunables live:
``STREAM_MONITOR_INTERVAL`` is read through that module at call time, so a
test (or program) that patches ``xgfalclient.transfer.STREAM_MONITOR_INTERVAL``
still reaches the streamed copy. :data:`PIPELINE_DEPTH` is ``pump``'s
default argument and so is fixed at import, as it always was.

Nothing here imports :mod:`xgfalclient.transfer` at module level - that
module imports this one - so :class:`~xgfalclient.transfer.Transfer` is a
type-only import.
"""

from __future__ import annotations

import errno
import os
import stat as stat_module
from typing import TYPE_CHECKING

from ._log import LOGGER
from .errors import GError, from_oserror
from .plugin import O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY, PluginFile

if TYPE_CHECKING:
    from .plugins.file import LocalFile
    from .transfer import Transfer

__all__ = ["PIPELINE_DEPTH", "copy_range", "pump", "stream"]

#: Buffers in flight between the reader thread and the writer.
PIPELINE_DEPTH = 4


# ---------------------------------------------------------------------------
# The streamed copy
# ---------------------------------------------------------------------------


def pump(
    transfer: Transfer,
    source: PluginFile,
    destination: PluginFile,
    *,
    buffer_size: int | None = None,
    depth: int = PIPELINE_DEPTH,
    final_report: bool = True,
    start: int = 0,
) -> int:
    """Stream through the shared pipeline, retaining GFAL progress/cancel policy.

    ``start`` is how many bytes an earlier stage of the same copy already
    moved (see :func:`copy_range`): progress, and the total returned, count
    from there.

    ``buffer_size`` defaults to ``[CORE] COPY_BUFFERSIZE``; ``depth`` is the
    number of buffers in flight (at least 2, so that reading and writing
    overlap). ``final_report=False`` leaves the last ``monitor_callback`` to
    the caller, for plugins that report the finished total themselves.
    Answers the total bytes moved. Whatever happens, the reader thread is
    stopped before this returns (its source aborted if it does not stop
    within a grace period; see :mod:`xrdcore.pipeline`).

    The keyword list is long because this is plugin-facing API re-exported
    from :mod:`xgfalclient.transfer`; it stays as it is.
    """
    # Imported here, not at module level: ``import gfal2`` loads this module,
    # and most programs that do never stream a copy through the core.
    from xrdcore.pipeline import pump as _pump

    size = buffer_size or transfer.context.options.integer("CORE", "COPY_BUFFERSIZE", 4194304)

    def report(done: int, total: int | None) -> None:
        """The pipeline's per-chunk hook: record progress, then stop if the copy must."""
        transfer.progress(start + done)
        transfer.check()

    total = start + _pump(
        source,
        destination,
        None,
        size,
        report,
        None,
        max(depth, 2),
        recycle=True,
        thread_name="xgfal-reader",
        short_write=lambda: GError("The destination stopped accepting data", errno.EIO),
    )
    transfer.progress(total, force=final_report)
    return total


def stream(transfer: Transfer) -> None:
    """The core's streamed copy: read through one plugin, write through another.

    The source is read to EOF. Its size is only a hint for writers that must
    declare a length (HTTP ``PUT``), given for a non-empty regular file - a
    ``/proc`` file says 0 and has content - and a copy that comes up short of
    it is an error; one that finds more (a growing file) is not.
    """
    context = transfer.context
    try:
        info = context.stat(transfer.source)
    except GError as exc:
        raise GError(f"Could not open source: {exc.message}", exc.code) from exc
    if info.is_dir():
        # gfal2 opens it and fails on the first read, in the file plugin's words.
        raise from_oserror(OSError(errno.EISDIR, ""))
    transfer.source_size = info.st_size
    size = info.st_size if stat_module.S_ISREG(info.st_mode) and info.st_size > 0 else None
    try:
        reader = context._open(transfer.source, O_RDONLY)
    except GError as exc:
        raise GError(f"Could not open source: {exc.message}", exc.code) from exc
    try:
        try:
            plugin = context.plugin(transfer.destination, "open")
            # 0755, as gfal2's streamed copy creates its destination.
            writer: PluginFile = context._guard(
                plugin.open, transfer.destination, O_WRONLY | O_CREAT | O_TRUNC, 0o755, size
            )
        except GError as exc:
            raise GError(f"Could not open destination: {exc.message}", exc.code) from exc
        transfer.owns_destination = True
        # Through the facade, where the tunable lives and callers patch it.
        from . import transfer as _facade

        transfer.monitor_interval = _facade.STREAM_MONITOR_INTERVAL
        try:
            total, finished = copy_range(transfer, reader, writer, size)
            if not finished:
                total = pump(transfer, reader, writer, final_report=False, start=total)
        finally:
            writer.close()
    finally:
        reader.close()
    if size is not None and total < size:
        raise GError(f"Short copy: {total} bytes transferred, the source has {size}", errno.EIO)


# ---------------------------------------------------------------------------
# The local fast path
# ---------------------------------------------------------------------------

#: ``copy_file_range`` failures that mean "not here", not "the copy failed":
#: a cross-filesystem pair on kernels before 5.3 (``EXDEV``), no such call
#: (``ENOSYS``), a filesystem that does not implement it (``EOPNOTSUPP``), a
#: pair it refuses (``EINVAL``: overlapping ranges, special files, some FUSE
#: and network filesystems) and a swap file (``ETXTBSY``).
_RANGE_FALLBACK = frozenset(
    (errno.EXDEV, errno.ENOSYS, errno.EOPNOTSUPP, errno.ENOTSUP, errno.EINVAL, errno.ETXTBSY)
)


def _range_ends(reader: PluginFile, writer: PluginFile) -> tuple[LocalFile, int, int] | None:
    """The source and both descriptors, when both ends are regular files of the file plugin.

    Anything else - a FIFO, ``/dev/null``, a ``/proc`` file (which may claim
    a size of 0 and still have content), another plugin's handle - streams
    through the pipeline, which reads to EOF whatever the file says.
    """
    from .plugins.file import LocalFile  # light, and already loaded for file:// URLs

    if not (isinstance(reader, LocalFile) and isinstance(writer, LocalFile)):
        return None
    try:
        fds = reader.fileno(), writer.fileno()
        regular = all(stat_module.S_ISREG(os.fstat(fd).st_mode) for fd in fds)
    except (OSError, ValueError):  # a closed descriptor: let the pipeline say so
        return None
    return (reader, *fds) if regular else None


def _give_way(source: LocalFile, exc: OSError) -> None:
    """Return if the streamed pipeline may carry on after ``exc``; raise the copy's failure if not.

    One of :data:`_RANGE_FALLBACK` means the kernel cannot do it here; a
    transient read failure the source recovers from (reopened, and still the
    same file) means it may go on. Anything else is the copy's failure.
    """
    if exc.errno in _RANGE_FALLBACK:
        return
    error = from_oserror(exc)
    if not source.recover_read(error):
        raise error from exc


def copy_range(
    transfer: Transfer, reader: PluginFile, writer: PluginFile, size: int | None
) -> tuple[int, bool]:
    """Copy local file to local file in the kernel with ``copy_file_range(2)``.

    Answers ``(copied, finished)``. ``finished`` is True when the source's
    end was reached at or past ``size`` (its ``st_size`` before the copy;
    ``None`` for an empty file); otherwise the caller hands the rest to
    :func:`pump`, which starts from both handles' positions - where this
    stopped - so a fallback part way through neither repeats nor skips a
    byte. That happens when the platform has no ``copy_file_range``
    (macOS), when either end is not a regular local file, when the kernel
    refuses with one of :data:`_RANGE_FALLBACK`'s errors, and when it
    reports the end before ``size``: the pipeline's reads then decide
    whether the file really is short (an error) or the filesystem merely
    cannot do this (a ``/proc``-like file reporting 0).

    A transient failure the file plugin recovers a read from (``ESTALE``,
    ``EAGAIN``...) gets the same recovery - the source is reopened and must
    still be the same file - and the pipeline carries on from there, with the
    plugin's cautious post-recovery reads. Any other failure (``ENOSPC``,
    ``EIO``) is the copy's, worded as the file plugin words it.

    Each call moves at most ``COPY_BUFFERSIZE`` bytes, and between calls the
    copy reports progress and checks for cancellation and its deadline,
    exactly as the pipeline does between chunks. A short count is not an
    error: the next call carries on from where it stopped.
    """
    call = getattr(os, "copy_file_range", None)
    chunk = transfer.context.options.integer("CORE", "COPY_BUFFERSIZE", 4194304)
    if call is None or chunk <= 0:  # a nonsense buffer size fails as the pipeline fails it
        return 0, False
    ends = _range_ends(reader, writer)
    if ends is None:
        return 0, False
    source, src, dst = ends
    done = 0
    while True:
        try:
            count = call(src, dst, chunk, reader.position, writer.position)
        except OSError as exc:
            _give_way(source, exc)
            LOGGER.debug("copy_file_range gave way to streaming after %d bytes: %s", done, exc)
            return done, False
        if not count:
            return done, size is not None and done >= size
        reader.position += count
        writer.position += count
        done += count
        transfer.progress(done)
        transfer.check()
