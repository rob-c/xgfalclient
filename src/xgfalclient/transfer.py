"""``filecopy``: the gfal2 copy pipeline, and the streamed copy it falls back to.

A copy is always the same sequence, whatever the protocols, and gfal2's
event stream narrates it::

    LIST:ENTER / LIST:ITEM / LIST:EXIT        what is about to be copied
    CHECKSUM:ENTER / EXIT       (source)      verify against the user's value
    OVERWRITE                   (dest)        remove an existing destination
    TRANSFER:ENTER / TYPE / EXIT              move the bytes
    CHECKSUM:ENTER / EXIT       (dest)        verify the copy
    CLEANUP                     (dest)        remove a failed destination (plugin copies)

A plugin may do the checksum and destination steps itself, in its own order
and words, as gfal2's gridftp, srm, xrootd and http plugins do (the http
plugin's come between ``PREPARE:ENTER`` and ``PREPARE:EXIT``), reusing the
helpers here where gfal2's words are the core's.

Every event is also logged at INFO on the ``gfal2`` logger, as gfal2 logs
it. An exception raised by ``event_callback`` or ``monitor_callback``
aborts the copy and comes out of ``filecopy`` as it was raised - the only
way Python code can stop a gfal2 copy - and a bulk copy stops there too.

The bytes move one of two ways. A plugin that can do better than reading and
writing - an HTTP or GridFTP third-party copy, a single-request upload -
claims the pair in :meth:`~xgfalclient.plugin.Plugin.copy_check` and is
handed a :class:`Transfer`. Otherwise the core streams: it opens the source
through its plugin and the destination through its own (created ``0755``,
as gfal2 creates it), and pipes one into the other until the source says
EOF - so ``/proc`` files and FIFOs copy, whatever their ``st_size``.
``monitor_callback`` fires, as in gfal2's local copy, only once more than
five seconds have passed since the last report, with no final report;
plugin copies report every second. (gfal2 counts whole seconds of
``time()``, so its first report lands somewhere between 5 and 6 seconds in
and says 6; this one comes at 5 and says 5.) ``[CORE] COPY_DIRECT_IO`` and
``COPY_BUFFER_ALIGNMENT`` (``O_DIRECT`` streaming, off by default) are not
honoured.

The stream is pipelined. A reader thread fills a small ring of buffers while
the calling thread drains them into the destination, so the source and the
destination are both busy at once instead of taking turns; ``readinto`` on a
socket and ``write`` on a file both release the GIL, so the overlap is real.

Where this differs from gfal2, deliberately:

* A failed copy removes the destination it wrote (``transfer_cleanup``),
  including after a destination checksum mismatch or a cancel; gfal2's
  local copy never cleans up. A destination this copy never opened - the
  source was missing, say - is left alone, as is a device or FIFO, and so
  is anything a plugin copy leaves in ``strict_copy`` mode, where nobody
  checked what was there before. Only plugin copies narrate ``CLEANUP``, as
  only gfal2's plugins do.
* Copying a file onto itself is refused with ``EINVAL`` when ``overwrite``
  or ``strict_copy`` is set (gfal2 deletes, or rewrites in place, the
  source); without them it is ``EEXIST``, as in gfal2.
* ``timeout = 0`` means no limit; gfal2's local copy expires at once.
* ``strict_copy`` truncates the destination (``O_TRUNC``); gfal2 writes
  over it in place and leaves a longer file's tail behind.
* A bulk copy's per-file ``"ALG:value"`` replaces the algorithm and value
  but keeps the parameters' mode, as in gfal2, without gfal2's bugs: the
  caller's parameters are not modified, the algorithm name is not cut one
  character short, and a bulk copy with no checksum list keeps the
  parameters' algorithm and value instead of dropping them.
"""

from __future__ import annotations

import errno
import queue
import stat as stat_module
import threading
import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from . import events as ev
from ._log import LOGGER
from .checksum import checksums_match, format_adler32, normalise_name
from .enums import checksum_mode
from .errors import GError, from_oserror
from .plugin import O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY, Plugin, PluginFile
from .types import TransferParameters
from .url import parent

if TYPE_CHECKING:
    from .context import Gfal2Context

__all__ = ["TransferParameters", "Transfer", "emit", "run_copy", "run_bulk", "pump", "stream"]


EventCallback = Callable[[ev.GfaltEvent], Any]
MonitorCallback = Callable[[str, str, int, int, int, int], Any]

#: How often ``monitor_callback`` may fire during a plugin copy, in seconds.
MONITOR_INTERVAL = 1.0
#: The same for the core's streamed copy: gfal2 waits more than five seconds.
STREAM_MONITOR_INTERVAL = 5.0
#: Buffers in flight between the reader thread and the writer.
PIPELINE_DEPTH = 4


def emit(
    params: TransferParameters,
    domain: str,
    stage: str,
    description: str = "",
    side: int = ev.BOTH,
) -> None:
    """Deliver one event to ``params.event_callback``, if there is one, and log it.

    An exception from the callback propagates: it aborts the copy.
    """
    event = ev.GfaltEvent(side, domain, stage, description, ev.now_ms())
    callback = params.event_callback
    if callback is not None:
        _call(callback, event)
    ev.log_event(event)


#: Set on an exception a callback raised, so that it passes through every
#: layer of the copy - a bulk copy, an SRM copy's inner one - untouched.
_FROM_CALLBACK = "_xgfal_from_callback"


def _call(callback: Callable[..., Any], *args: Any) -> None:
    try:
        callback(*args)
    except Exception as exc:
        setattr(exc, _FROM_CALLBACK, True)
        raise


def _from_callback(exc: BaseException) -> bool:
    return getattr(exc, _FROM_CALLBACK, False) is True


class Transfer:
    """One copy in progress: what a plugin's :meth:`copy` is handed.

    It carries the two URLs and the parameters, and it is how the plugin
    talks back: :meth:`event` narrates, :meth:`progress` reports bytes (and
    drives ``monitor_callback``), and :meth:`check` raises if the copy has
    been cancelled, has run out of time, or a callback has raised - call it
    between chunks.
    """

    def __init__(
        self,
        context: Gfal2Context,
        params: TransferParameters,
        source: str,
        destination: str,
        *,
        domain: str = ev.DOMAIN_LOCAL,
        user_checksum: tuple[str, str] | None = None,
    ) -> None:
        self.context = context
        self.params = params
        self.source = source
        self.destination = destination
        self.domain = domain
        self.started = time.monotonic()
        mode, algorithm, value = params.get_checksum()
        if user_checksum is not None:  # a bulk entry: its own algorithm and value, same mode
            algorithm, value = user_checksum
        self.checksum_mode = mode
        self.checksum_algorithm = algorithm
        self.user_checksum = value
        self.source_checksum: str | None = None
        self.source_size: int | None = None
        self.transferred = 0
        #: Seconds between ``monitor_callback`` reports.
        self.monitor_interval = MONITOR_INTERVAL
        #: True once this copy may have written the destination, so that a
        #: failure may remove it; never for a destination it did not touch.
        self.owns_destination = False
        #: The first exception a callback raised; :meth:`check` re-raises it.
        self.callback_error: Exception | None = None
        #: Set by a plugin that had one server copy to the other: no byte
        #: passed through here, so only the servers' checksums can say the
        #: destination holds what the source does (see :func:`_verify_third_party`).
        self.third_party = False
        self._generation = context._cancel_generation
        self._lock = threading.Lock()
        self._last_report = self.started
        self._last_bytes = 0

    # -- narration ---------------------------------------------------------------

    def event(
        self, stage: str, description: str = "", side: int = ev.BOTH, domain: str | None = None
    ) -> None:
        try:
            emit(self.params, domain or self.domain, stage, description, side)
        except Exception as exc:
            self._failed(exc)
            raise

    def _failed(self, exc: Exception) -> None:
        with self._lock:
            if self.callback_error is None:
                self.callback_error = exc

    @property
    def pair(self) -> str:
        return f"{self.source} => {self.destination}"

    # -- limits ------------------------------------------------------------------

    @property
    def deadline(self) -> float | None:
        """Monotonic time the copy must finish by, or ``None`` for no limit (``timeout=0``)."""
        timeout = self.params.timeout
        return self.started + timeout if timeout > 0 else None

    def remaining(self) -> float | None:
        deadline = self.deadline
        return None if deadline is None else max(0.0, deadline - time.monotonic())

    def check(self) -> None:
        """Raise a callback's exception, ``ECANCELED`` or ``ETIMEDOUT`` if the copy must stop."""
        error = self.callback_error
        if error is not None:
            raise error
        if self.context._cancel_generation != self._generation:
            raise GError("Transfer canceled", errno.ECANCELED)
        deadline = self.deadline
        if deadline is not None and time.monotonic() > deadline:
            raise GError("Transfer canceled because the timeout expired", errno.ETIMEDOUT)

    # -- progress ----------------------------------------------------------------

    def progress(self, transferred: int, *, force: bool = False, always: bool = False) -> None:
        """Record the absolute byte count; fire ``monitor_callback`` at most once an interval.

        ``always`` fires it now, however short the copy: for plugins whose
        gfal2 counterpart reports every step its library reports - each HTTP
        performance marker (davix), each XrdCl progress call - rather than
        on the core's clock.
        """
        with self._lock:
            self.transferred = transferred
        self._report(force, always)

    def add(self, count: int) -> None:
        """Add ``count`` bytes to the running total; safe from several threads."""
        with self._lock:
            self.transferred += count
        self._report(False, False)

    def _report(self, force: bool, always: bool) -> None:
        callback = self.params.monitor_callback
        if callback is None:
            return
        with self._lock:
            now = time.monotonic()
            interval = self.monitor_interval
            # Like gfal2's core, a copy shorter than one interval is never
            # reported, and ``force`` only flushes the final figure of a longer one.
            if not always:
                if now - self.started < interval:
                    return
                if not force and now - self._last_report < interval:
                    return
            transferred = self.transferred
            elapsed = now - self.started
            window = max(now - self._last_report, 1e-9)
            average = int(transferred / max(elapsed, 1e-9))
            instant = int((transferred - self._last_bytes) / window)
            self._last_report, self._last_bytes = now, transferred
        try:
            _call(
                callback, self.source, self.destination, average, instant, transferred, int(elapsed)
            )
        except Exception as exc:
            self._failed(exc)
            raise


# ---------------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------------


def _checksum_algorithm(transfer: Transfer, plugin: Plugin | None) -> str:
    if transfer.checksum_algorithm:
        return transfer.checksum_algorithm
    return plugin.checksum_type() if plugin is not None else "ADLER32"


def _checksum_value(context: Gfal2Context, url: str, algorithm: str) -> str:
    """``url``'s checksum, an ADLER32 always as eight hex digits, so that it compares."""
    value = context.checksum(url, algorithm)
    if normalise_name(algorithm) == "adler32":
        value = format_adler32(value)
    return value


def _compute_checksum(context: Gfal2Context, url: str, algorithm: str, side: str) -> str:
    try:
        return _checksum_value(context, url, algorithm)
    except GError as exc:
        raise GError(f"Could not get the {side} checksum: {exc.message}", exc.code) from exc


def _verify_source(transfer: Transfer, algorithm: str) -> None:
    if transfer.checksum_mode not in (checksum_mode.source, checksum_mode.both):
        return
    transfer.event(ev.CHECKSUM_ENTER, side=ev.SOURCE)
    value = _compute_checksum(transfer.context, transfer.source, algorithm, "source")
    transfer.event(ev.CHECKSUM_EXIT, side=ev.SOURCE)
    transfer.source_checksum = value
    if transfer.user_checksum and not checksums_match(value, transfer.user_checksum):
        raise GError(
            "SOURCE CHECKSUM MISMATCH Source checksum and user-specified checksum do not "
            f"match: {value} != {transfer.user_checksum}",
            errno.EIO,
        )


def _verify_destination(transfer: Transfer, algorithm: str) -> None:
    if transfer.checksum_mode not in (checksum_mode.target, checksum_mode.both):
        return
    transfer.event(ev.CHECKSUM_ENTER, side=ev.DESTINATION)
    value = _compute_checksum(transfer.context, transfer.destination, algorithm, "destination")
    transfer.event(ev.CHECKSUM_EXIT, side=ev.DESTINATION)
    if transfer.source_checksum is not None:
        if not checksums_match(transfer.source_checksum, value):
            raise GError(
                "DESTINATION CHECKSUM MISMATCH Source checksum and destination checksum do "
                f"not match: {transfer.source_checksum} != {value}",
                errno.EIO,
            )
    elif not checksums_match(transfer.user_checksum, value):  # target mode: always a value
        raise GError(
            "DESTINATION CHECKSUM MISMATCH User defined checksum and destination checksum do "
            f"not match: {transfer.user_checksum} != {value}",
            errno.EIO,
        )


def _verify_third_party(transfer: Transfer, algorithm: str) -> None:
    """After a third-party copy nobody asked to verify: compare the two ends anyway.

    A destination can report a finished pull that never happened: RAL's
    Echo, asked to pull from EOS with a delegated proxy it could not use,
    answered the final ``kXR_sync`` and ``kXR_close`` with success and left a
    file of the full size - pre-sized from ``oss.asize`` - holding no data
    (adler32 ``00000001``). Without a checksum requested, gfal2 calls that a
    successful copy. Here the two servers' checksums are compared, which
    costs two metadata queries; a mismatch fails the copy (and the failed
    destination is removed as any other would be), and an end that cannot
    say its checksum leaves the copy as it was. ``[CORE]
    VERIFY_THIRD_PARTY=false`` turns it off.
    """
    if not transfer.third_party or transfer.checksum_mode != checksum_mode.none:
        return
    if not transfer.context.options.boolean("CORE", "VERIFY_THIRD_PARTY", True):
        return
    try:
        source = _checksum_value(transfer.context, transfer.source, algorithm)
        destination = _checksum_value(transfer.context, transfer.destination, algorithm)
    except GError as exc:
        LOGGER.debug("third-party copy not verified: %s", exc.message)
        return
    if not checksums_match(source, destination):
        # This copy wrote it, and what it wrote is wrong: the plugin's own
        # clean-up ran only for failures it saw, so this one is ours.
        transfer.owns_destination = True
        raise GError(
            "DESTINATION CHECKSUM MISMATCH after a third-party copy the destination "
            f"reported as finished: source {algorithm} {source} != destination {destination}",
            errno.EIO,
        )


def _prepare_destination(transfer: Transfer) -> None:
    """Refuse or remove an existing destination; create its parent if asked."""
    context = transfer.context
    try:
        info = context.stat(transfer.destination)
        # A device, FIFO or socket is a sink to write into, not a file to
        # replace: gfal2 copies into /dev/null without asking for overwrite.
        exists = not _is_special(info.st_mode)
    except GError as exc:
        if exc.code != errno.ENOENT:
            raise
        exists = False
    if exists:
        if not transfer.params.overwrite:
            raise GError("The file exists and overwrite is not set", errno.EEXIST)
        context.unlink(transfer.destination)
        transfer.event(ev.OVERWRITE, f"Deleted {transfer.destination}", side=ev.DESTINATION)
    if transfer.params.create_parent:
        context.mkdir_rec(parent(transfer.destination), 0o755)


def _is_special(mode: int) -> bool:
    return stat_module.S_ISCHR(mode) or stat_module.S_ISFIFO(mode) or stat_module.S_ISSOCK(mode)


def _cleanup(transfer: Transfer, plugin_copy: bool) -> None:
    """Remove a destination this failed copy wrote.

    A plugin copy's clean-up is narrated as ``CLEANUP``, as gfal2's plugins
    narrate theirs: ``0`` when the destination is gone, whether this removed
    it or it was never there, else the errno of the failed removal. The
    streamed copy's is silent, but first makes sure the destination is not a
    device or FIFO it was only writing into.
    """
    if not (transfer.params.transfer_cleanup and transfer.owns_destination):
        return
    context = transfer.context
    if not plugin_copy:
        try:
            if _is_special(context.stat(transfer.destination).st_mode):
                return  # /dev/null or a FIFO: written into, never ours to remove
        except GError:
            return  # nothing there to remove
    code = 0
    try:
        context.unlink(transfer.destination)
    except GError as exc:
        if exc.code != errno.ENOENT:
            LOGGER.warning("When trying to clean the destination: %s", exc.message)
            code = exc.code
    if plugin_copy and transfer.callback_error is None:
        transfer.event(ev.CLEANUP, str(code), side=ev.DESTINATION)


def run_copy(
    context: Gfal2Context,
    params: TransferParameters,
    source: str,
    destination: str,
    user_checksum: tuple[str, str] | None = None,
) -> None:
    """Copy one file, raising ``GError`` (or a callback's exception) on failure."""
    _list_events(params, [(source, destination)])
    if source == destination and (params.overwrite or params.strict_copy):
        # gfal2 deletes the source here (overwrite), or rewrites it in place
        # (strict, which truncates here); refuse instead. Otherwise the
        # existence check below answers EEXIST, as gfal2's does.
        raise GError("Source and destination are the same file", errno.EINVAL)
    plugin = context._copy_plugin(source, destination)
    if plugin is None and not params.local_transfers:
        raise GError(
            f"No plugin supports a transfer from {source} to {destination}, "
            "and local streaming is disabled",
            errno.EPROTONOSUPPORT,
        )
    domain = _domain(plugin) if plugin is not None else ev.DOMAIN_LOCAL
    transfer = Transfer(
        context, params, source, destination, domain=domain, user_checksum=user_checksum
    )
    algorithm = _checksum_algorithm(transfer, plugin)
    # Like gfal2's plugins, one that copies may do the destination and
    # checksum work itself (the mock plugin never even stats the destination).
    manages = plugin is not None and plugin.copy_manages_destination
    verify = not params.strict_copy and (plugin is None or not plugin.copy_manages_checksums)
    if verify:
        _verify_source(transfer, algorithm)
    if not params.strict_copy and not manages:
        _prepare_destination(transfer)
    narrate = plugin is None or not plugin.narrates_transfer
    if narrate:
        transfer.event(ev.TRANSFER_ENTER, transfer.pair)
    try:
        if plugin is not None:
            # In strict mode nobody looked at what was there before.
            transfer.owns_destination = not manages and not params.strict_copy
            plugin.copy(transfer)
            if transfer.callback_error is not None:
                raise transfer.callback_error  # the plugin swallowed it
        else:
            transfer.event(ev.TRANSFER_TYPE, "streamed")
            stream(transfer)
        if narrate:
            transfer.event(ev.TRANSFER_EXIT, transfer.pair)
        if verify:
            _verify_destination(transfer, algorithm)
        _verify_third_party(transfer, algorithm)
    except Exception as exc:
        _cleanup(transfer, plugin_copy=plugin is not None)
        error = transfer.callback_error
        if error is not None and error is not exc:
            raise error from exc  # a plugin wrapped the callback's exception
        if isinstance(exc, GError) or _from_callback(exc):
            raise
        # A plugin bug is still a failed copy, not a crash.
        raise GError(f"Transfer failed: {exc}", errno.EIO) from exc


def _domain(plugin: Plugin) -> str:
    return plugin.event_domain or plugin.name


def _list_events(params: TransferParameters, pairs: Sequence[tuple[str, str]]) -> None:
    emit(params, ev.DOMAIN_COPY, ev.LIST_ENTER)
    for source, destination in pairs:
        text = f"{ev.markup_escape(source)} => {ev.markup_escape(destination)}"
        emit(params, ev.DOMAIN_COPY, ev.LIST_ITEM, text)
    emit(params, ev.DOMAIN_COPY, ev.LIST_EXIT)


def _split_checksum(entry: str) -> tuple[str, str]:
    """``"ADLER32:1a2b3c4d"`` into its parts; with no colon it is all value, as in gfal2."""
    algorithm, sep, value = entry.partition(":")
    return (algorithm, value) if sep else ("", algorithm)


def run_bulk(
    context: Gfal2Context,
    params: TransferParameters,
    sources: Sequence[str],
    destinations: Sequence[str],
    checksums: Sequence[str] = (),
) -> list[GError | None]:
    """Copy each pair in turn; one result per pair, ``None`` for success.

    A callback's exception is not a per-file result: it ends the whole call.
    """
    if len(sources) != len(destinations):
        raise GError("Number of sources and destinations do not match", errno.EINVAL)
    if checksums and len(checksums) != len(sources):
        raise GError("Number of pairs and checksums do not match", errno.EINVAL)
    _list_events(params, list(zip(sources, destinations)))
    # As gfal2 does, the first pair picks the plugin; one with a bulk copy
    # (GridFTP pipelining) takes the whole list and does its own checks.
    plugin = context._copy_plugin(sources[0], destinations[0]) if sources else None
    if plugin is not None and plugin.implements("copy_bulk"):
        domain = _domain(plugin)
        transfers = [
            Transfer(
                context,
                params,
                source,
                destination,
                domain=domain,
                user_checksum=_split_checksum(checksums[index]) if checksums else None,
            )
            for index, (source, destination) in enumerate(zip(sources, destinations))
        ]
        return plugin.copy_bulk(params, transfers)
    mode = params.get_checksum()[0]
    results: list[GError | None] = []
    for index, (source, destination) in enumerate(zip(sources, destinations)):
        try:
            user = None
            if checksums:
                user = _split_checksum(checksums[index])
                if mode in (checksum_mode.source, checksum_mode.target) and not user[1]:
                    raise GError("Checksum value required if mode is not end to end", errno.EINVAL)
            run_copy(context, params, source, destination, user)
            results.append(None)
        except GError as exc:
            if _from_callback(exc):
                raise
            results.append(exc)
    return results


# ---------------------------------------------------------------------------
# The streamed copy
# ---------------------------------------------------------------------------


class _Stop:
    """End-of-stream (or failure) marker on the pipeline queue."""

    __slots__ = ("error",)

    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error


def _reader(
    source: PluginFile,
    buffers: queue.Queue[bytearray],
    filled: queue.Queue[Any],
    stop: threading.Event,
) -> None:
    try:
        while not stop.is_set():
            buffer = buffers.get()
            count = source.readinto(buffer)
            if count <= 0:
                filled.put(_Stop())
                return
            filled.put((buffer, count))
    except BaseException as exc:  # handed to the writer thread to re-raise
        filled.put(_Stop(exc))


def pump(
    transfer: Transfer,
    source: PluginFile,
    destination: PluginFile,
    *,
    buffer_size: int | None = None,
    depth: int = PIPELINE_DEPTH,
    final_report: bool = True,
) -> int:
    """Copy ``source`` to ``destination`` with reads and writes overlapped.

    ``final_report`` flushes the total to ``monitor_callback`` at the end
    (gfal2's plugins do; its local copy does not).
    """
    size = buffer_size or transfer.context.options.integer("CORE", "COPY_BUFFERSIZE", 4194304)
    buffers: queue.Queue[bytearray] = queue.Queue()
    for _ in range(max(depth, 2)):
        buffers.put(bytearray(size))
    filled: queue.Queue[Any] = queue.Queue()
    stop = threading.Event()
    thread = threading.Thread(
        target=_reader, args=(source, buffers, filled, stop), name="xgfal-reader", daemon=True
    )
    thread.start()
    total = 0
    try:
        item = filled.get()
        while not isinstance(item, _Stop):
            buffer, count = item
            destination.write(memoryview(buffer)[:count])
            buffers.put(buffer)
            total += count
            transfer.progress(total)
            transfer.check()
            item = filled.get()
        if item.error is not None:
            raise item.error
    finally:
        stop.set()
        buffers.put(bytearray(0))  # unblock a reader waiting for a buffer
        thread.join()
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
        transfer.monitor_interval = STREAM_MONITOR_INTERVAL
        try:
            total = pump(transfer, reader, writer, final_report=False)
        finally:
            writer.close()
    finally:
        reader.close()
    if size is not None and total < size:
        raise GError(f"Short copy: {total} bytes transferred, the source has {size}", errno.EIO)
