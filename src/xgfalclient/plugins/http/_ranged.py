"""Parallel ranged downloads: HTTP to ``file://``.

HTTP to ``file://`` is not claimed by gfal2 at all; this plugin takes it
to download large files as ranged ``GET``\\ s over several pooled
connections at once, each writing its bytes straight into place with
``os.pwrite``. ``params.nbstreams`` sets the number of streams when it is
positive; over TLS the default is two, since every TLS record costs a trip
through the GIL. Its steps, words and events (in the core's domain) are the
core's streamed copy's, as gfal2 leaves the pair to its core.

A server that ignores ``Range`` gets the file in one stream instead; one that
fails mid-way is retried from the byte it reached, segment by segment, and -
after the parallel attempt has failed - from a Metalink replica.

Ranges are RFC 9110's (section 14): each segment asks
``Range: bytes=<first>-<last>`` (inclusive) and must be answered
``206 Partial Content``; a ``200`` means the server ignored the header and
is sending the whole file, which is the cue for the single-stream path
(:class:`_NoRanges`), never data to splice in. gfal2 downloads in one
stream; the parallel streams are this plugin's own speed-up, which is why
they sit behind a size threshold and fall back to gfal2's behaviour so
readily.

Threading: :func:`_parallel` runs the segments through
:func:`xrdcore.fanout.run_all` (the fan-out every client on the stack shares:
first failure raised as itself, the rest stopped and noted) on at most
``streams`` workers, each with its own block buffer and its own pooled
connection (:meth:`HTTPPlugin._get`). Workers share only
:class:`_Job`: the destination descriptor (``os.pwrite`` is positional, so
there is no shared offset), the thread-safe :class:`~xgfalclient.transfer.Transfer`
counters, and the ``stop`` event. Nothing here holds a lock while doing I/O.
"""

from __future__ import annotations

import errno
import logging
import os
import queue
import threading
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING

from xrdcore import fanout

from ... import events as ev
from ...errors import GError
from ...transfer import Transfer
from ...url import scheme_of
from ._client import BLOCK, Response, TransportError, wire_scheme
from ._copy_common import STREAMED, local_path
from ._io import HTTPReadFile

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["download"]

_log = logging.getLogger("gfal2")

#: Files at least this big are downloaded over several connections.
PARALLEL_THRESHOLD = 32 << 20
#: Streams for a parallel download when ``params.nbstreams`` does not say.
DEFAULT_STREAMS = 4
#: The same over TLS, where each record is a GIL round trip (see above).
TLS_STREAMS = 2
#: The largest unit of work a download stream takes at a time.
SEGMENT = 64 << 20


class _NoRanges(Exception):
    """The server answered a ranged GET with the whole file.

    Raised out of the pool to :func:`_try_parallel_download`, which starts
    over in one stream; never seen by a caller.
    """


@dataclass(frozen=True, slots=True)
class _Job:
    """What every stream of one parallel download shares.

    ``fd`` is the destination, written with ``os.pwrite`` so streams never
    contend for a file position; ``transfer`` may be shared because ``add``
    takes its lock and ``check`` only reads flags; ``stop`` is set by the
    first failure and polled between blocks. Each stream keeps its own
    block buffer and segment outside this.
    """

    plugin: HTTPPlugin
    transfer: Transfer
    fd: int
    stop: threading.Event


def download(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """HTTP to ``file://``: the bytes, in parallel ranges when that pays, else one stream.

    The destination is truncated and owned by the caller's cleanup
    (:func:`._copy.local_copy`); on any failure the file may hold a
    partial download. Raises :class:`GError` worded as the core's streamed
    copy words it.
    """
    transfer.event(ev.TRANSFER_TYPE, STREAMED)
    size = _download_size(plugin, transfer)
    transfer.source_size = size
    fd = _open_download_destination(transfer.destination)
    try:
        streams = _download_streams(transfer)
        if not _try_parallel_download(plugin, transfer, fd, size, streams):
            _single(plugin, transfer, fd, size)
    finally:
        os.close(fd)
    transfer.progress(size, force=True)


def _download_size(plugin: HTTPPlugin, transfer: Transfer) -> int:
    """Validate the source and return the advertised byte count."""
    try:
        info = plugin.stat(transfer.source)
    except GError as exc:
        # gfal2's streamed copy opens the source first, in these words.
        raise GError(f"Could not open source: {exc.message}", exc.code) from None
    if info.is_dir():
        raise GError(f"{transfer.source} is a directory", errno.EISDIR)
    return info.st_size


def _open_download_destination(url: str) -> int:
    """Open a local download target and translate filesystem failures."""
    try:
        return os.open(local_path(url), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    except OSError as exc:
        raise GError(f"Could not open destination: {exc.strerror}", exc.errno or errno.EIO) from exc


def _download_streams(transfer: Transfer) -> int:
    """``params.nbstreams`` when set (positive), else the default for the source's scheme."""
    configured = transfer.params.nbstreams
    return configured if configured > 0 else _default_streams(transfer.source)


def _try_parallel_download(
    plugin: HTTPPlugin, transfer: Transfer, fd: int, size: int, streams: int
) -> bool:
    """Use ranged streams when worthwhile, returning false for a clean fallback."""
    # Below the threshold the extra connections cost more than they save.
    if size < PARALLEL_THRESHOLD or streams <= 1:
        return False
    try:
        _parallel(plugin, transfer, fd, size, streams)
        return True
    except _NoRanges:
        _log.debug("%s ignores Range; downloading in one stream", transfer.source)
    except GError as exc:
        # Davix applies Metalink below its ranged-read layer. Keep the
        # zero-overhead parallel happy path; only after it fails do we
        # discover replicas and restart through the failover-aware stream.
        if exc.code in (errno.ECANCELED, errno.ETIMEDOUT):
            raise
        try:
            replicas = plugin._metalink_replicas(transfer.source)
        except GError:
            replicas = ()
        if not replicas:
            raise
    # Starting over: the segments that did land must not count twice, nor
    # linger past a shorter replica's end.
    os.ftruncate(fd, 0)
    transfer.progress(0)
    return False


def _default_streams(url: str) -> int:
    """Two streams over TLS, four in the clear (see the constants for why)."""
    return TLS_STREAMS if wire_scheme(scheme_of(url)) == "https" else DEFAULT_STREAMS


def _pwrite_all(fd: int, view: memoryview, offset: int) -> None:
    """Write all of ``view`` at ``offset``, looping over short writes.

    ``os.pwrite`` may write less than asked (a signal, a full pipe-backed
    target); a write of zero would loop forever, so it is ``EIO``. Disk
    errors keep their errno (``ENOSPC``, ``EDQUOT``) for the caller to see.
    """
    done = 0
    while done < len(view):
        try:
            written = os.pwrite(fd, view[done:], offset + done)
        except OSError as exc:
            raise GError(
                f"Could not write destination: {exc.strerror or exc}", exc.errno or errno.EIO
            ) from exc
        if written <= 0:
            raise GError("Could not write destination: write made no progress", errno.EIO)
        done += written


def _single(plugin: HTTPPlugin, transfer: Transfer, fd: int, size: int) -> None:
    """The whole file in one stream, through :class:`~._io.HTTPReadFile`.

    That reader resumes after a drop and fails over between Metalink
    replicas (starting from the one :meth:`HTTPPlugin._metalink_start`
    picks), which the parallel path deliberately does not. A body that ends
    before ``size`` is a short copy (``EIO``), never a silent truncation.
    """
    view = memoryview(bytearray(BLOCK))
    total = 0
    reader = HTTPReadFile(
        plugin, transfer.source, size, active=plugin._metalink_start(transfer.source)
    )
    try:
        while total < size:
            count = reader.readinto(view[: min(len(view), size - total)])
            if count <= 0:
                break
            _pwrite_all(fd, view[:count], total)
            total += count
            transfer.add(count)
            transfer.check()
    finally:
        reader.close()
    if total != size:
        raise GError(f"Short copy: {total} bytes transferred, the source has {size}", errno.EIO)


def _parallel(plugin: HTTPPlugin, transfer: Transfer, fd: int, size: int, streams: int) -> None:
    """Download ``size`` bytes as ranged ``GET`` segments on up to ``streams`` threads.

    The segments are queued in file order and each thread takes the next as
    it finishes one, so the file fills roughly front to back. The first
    failure stops the rest: queued segments are cancelled, and the ones in
    flight stop at their next block (``stop``). That failure is what is
    raised, unchanged (so its ``GError`` code is the download's); failures
    of other streams before they noticed are attached to it as notes, and
    one error every stream raised (a callback's) is reported once - all of
    it :func:`xrdcore.fanout.run_all`'s contract.
    """
    # Big enough to amortise a request, small enough that every stream has work.
    # Never under 1 MiB, however many streams were asked for: tiny ranges
    # would spend more on request round trips than on data.
    step = max(min(SEGMENT, -(-size // streams)), 1 << 20)
    segments = [(offset, min(step, size - offset)) for offset in range(0, size, step)]
    stop = threading.Event()
    job = _Job(plugin, transfer, fd, stop)
    workers = min(streams, len(segments))
    # One block buffer per thread, reused for every segment it fetches.
    buffers: queue.SimpleQueue[memoryview] = queue.SimpleQueue()
    for _ in range(workers):
        buffers.put(memoryview(bytearray(BLOCK)))

    def run(offset: int, count: int) -> None:
        """One segment on a pool thread, with a buffer borrowed for its duration."""
        view = buffers.get()
        try:
            _fetch_segment(job, (offset, count), view)
        finally:
            buffers.put(view)

    fanout.run_all(
        [partial(run, offset, count) for offset, count in segments],
        workers=workers,
        name="xgfal-http-get",
        stop=stop,
    )


def _drain_segment(
    response: Response, job: _Job, remaining: tuple[int, int], view: memoryview
) -> tuple[int, TransportError | None]:
    """Write a ranged answer's body into ``fd``: how many bytes landed, and a drop if one ended it.

    ``remaining`` is ``(offset, count)`` still owed. It stops at the end of
    the body, at ``count``, or once ``stop`` is set. A dropped connection is
    handed back rather than raised, with the bytes that came before it: they
    are in the file already, and the retry asks only for the rest.
    """
    offset, count = remaining
    transfer = job.transfer
    done = 0
    try:
        while done < count and not job.stop.is_set():
            got = response.readinto(view[: min(len(view), count - done)])
            if got <= 0:
                break
            _pwrite_all(job.fd, view[:got], offset + done)
            done += got
            transfer.add(got)
            transfer.check()
    except TransportError as exc:
        return done, exc
    return done, None


def _fetch_segment(job: _Job, segment: tuple[int, int], view: memoryview) -> None:
    """Fetch one ``(offset, count)`` range into ``fd``, resuming it if its connection drops.

    A segment whose connection *drops* is re-requested from where it got
    to, so one flaky stream costs a reconnect rather than the download. A
    clean 206 that is shorter than the range asked for is not a drop - it
    is the short read it has always been. A segment that starts after
    ``stop`` was set - taken off the queue as another stream failed - asks
    for nothing.
    """
    offset, count = segment
    plugin, transfer, stop = job.plugin, job.transfer, job.stop
    # ``done`` survives reconnects: each retry asks only for the bytes still
    # owed, ``bytes=<offset+done>-<last>``, since the earlier ones are in
    # the file already.
    done = 0
    attempts = 0
    timeout = plugin.io_timeout()
    while not stop.is_set():
        headers = {"Range": f"bytes={offset + done}-{offset + count - 1}"}
        try:
            with plugin._get(transfer.source, headers, timeout=timeout) as response:
                if response.status != 206:
                    # 200: Range ignored. Aborts the whole parallel attempt
                    # (via ``stop``) for the single-stream path.
                    raise _NoRanges
                got, dropped = _drain_segment(response, job, (offset + done, count - done), view)
                done += got
                if got:
                    attempts = 0  # progress: the retry budget is for a link that gives nothing
                if dropped is not None:
                    raise dropped
        except TransportError:
            attempts += 1
            if attempts > plugin.conn_retry():
                raise GError(
                    f"connection closed at {offset + done} of {offset + count} "
                    f"reading {transfer.source}",
                    errno.EIO,
                ) from None
            plugin.retry_pause(attempts)
            continue
        if done >= count or stop.is_set():
            return
        raise GError(f"Short read of {transfer.source} at offset {offset + done}", errno.EIO)
