"""``filecopy``: the gfal2 copy pipeline, and the streamed copy it falls back to.

A copy is always the same sequence, whatever the protocols, and gfal2's
event stream narrates it::

    LIST:ENTER / LIST:ITEM / LIST:EXIT        what is about to be copied
    CHECKSUM:ENTER / EXIT       (source)      verify against the user's value
    OVERWRITE                   (dest)        remove an existing destination
    TRANSFER:ENTER / TYPE / EXIT              move the bytes
    CHECKSUM:ENTER / EXIT       (dest)        verify the copy
    CLEANUP                     (dest)        remove a failed destination

The bytes move one of two ways. A plugin that can do better than reading and
writing - an HTTP or GridFTP third-party copy, a single-request upload -
claims the pair in :meth:`~xgfalclient.plugin.Plugin.copy_check` and is
handed a :class:`Transfer`. Otherwise the core streams: it opens the source
through its plugin and the destination through its own, and pipes one into
the other.

The stream is pipelined. A reader thread fills a small ring of buffers while
the calling thread drains them into the destination, so the source and the
destination are both busy at once instead of taking turns; ``readinto`` on a
socket and ``write`` on a file both release the GIL, so the overlap is real.
"""

from __future__ import annotations

import errno
import logging
import queue
import stat as stat_module
import threading
import time
import warnings
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from . import events as ev
from .checksum import checksums_match, format_adler32, normalise_name
from .enums import checksum_mode
from .errors import GError
from .plugin import O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY, Plugin, PluginFile
from .url import parent

if TYPE_CHECKING:
    from .context import Gfal2Context

__all__ = ["TransferParameters", "Transfer", "emit", "run_copy", "run_bulk", "pump", "stream"]

_log = logging.getLogger("gfal2")

EventCallback = Callable[[ev.GfaltEvent], Any]
MonitorCallback = Callable[[str, str, int, int, int, int], Any]

#: How often ``monitor_callback`` may fire, in seconds.
MONITOR_INTERVAL = 1.0
#: Buffers in flight between the reader thread and the writer.
PIPELINE_DEPTH = 4


class TransferParameters:
    """What ``ctx.transfer_parameters()`` returns: the knobs of one copy.

    Attribute names and defaults are gfal2's. ``checksum_check`` and the
    ``*_user_defined_checksum`` pair are gfal2's deprecated spellings of
    :meth:`set_checksum` and still work, with the same warnings.
    """

    def __init__(self) -> None:
        self.timeout = 3600
        self.nbstreams = 0
        self.tcp_buffersize = 0
        self.overwrite = False
        self.strict_copy = False
        self.create_parent = False
        self.src_spacetoken = ""
        self.dst_spacetoken = ""
        self.local_transfers = True
        self.proxy_delegation = True
        self.transfer_cleanup = True
        self.scitag = 0
        self.evict = False
        self.event_callback: EventCallback | None = None
        self.monitor_callback: MonitorCallback | None = None
        self._mode = checksum_mode.none
        self._algorithm = ""
        self._value = ""

    def copy(self) -> TransferParameters:
        clone = TransferParameters()
        for name, value in vars(self).items():
            setattr(clone, name, value)
        return clone

    # -- checksums ---------------------------------------------------------------

    def set_checksum(self, mode: int, algorithm: str, value: str) -> None:
        """Which ends to verify, with which algorithm, against which value.

        ``source`` and ``target`` compare one end with ``value``, so they
        need one; ``both`` compares the ends with each other and ``value``
        is optional.
        """
        member = checksum_mode.values.get(int(mode))
        if member is None:
            raise GError(f"Invalid checksum mode {mode}", errno.EINVAL)
        if member in (checksum_mode.source, checksum_mode.target) and not value:
            raise GError("Checksum value required if mode is not end to end", errno.EINVAL)
        self._mode, self._algorithm, self._value = member, algorithm or "", value or ""

    def get_checksum(self) -> tuple[checksum_mode, str, str]:
        return self._mode, self._algorithm, self._value

    @property
    def checksum_mode(self) -> checksum_mode:
        return self._mode

    @property
    def checksum_algorithm(self) -> str:
        return self._algorithm

    @property
    def checksum_value(self) -> str:
        return self._value

    @property
    def checksum_check(self) -> bool:
        warnings.warn(
            "checksum_check is deprecated. Use get_checksum_mode instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._mode != checksum_mode.none

    @checksum_check.setter
    def checksum_check(self, enabled: bool) -> None:
        self._mode = checksum_mode.both if enabled else checksum_mode.none

    def set_user_defined_checksum(self, algorithm: str, value: str) -> None:
        warnings.warn(
            "set_user_defined_checksum is deprecated. Use set_checksum instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self._algorithm, self._value = algorithm, value

    def get_user_defined_checksum(self) -> tuple[str, str]:
        warnings.warn(
            "get_user_defined_checksum is deprecated. Use get_checksum instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._algorithm, self._value

    def __repr__(self) -> str:
        return (
            f"TransferParameters(timeout={self.timeout}, nbstreams={self.nbstreams}, "
            f"overwrite={self.overwrite}, checksum={self._mode.name})"
        )


def emit(
    params: TransferParameters,
    domain: str,
    stage: str,
    description: str = "",
    side: int = ev.BOTH,
) -> None:
    """Deliver one event to ``params.event_callback``, if there is one."""
    callback = params.event_callback
    if callback is None:
        return
    try:
        callback(ev.GfaltEvent(side, domain, stage, description))
    except Exception:  # a broken callback must not break the copy
        _log.exception("event_callback raised; ignoring")


class Transfer:
    """One copy in progress: what a plugin's :meth:`copy` is handed.

    It carries the two URLs and the parameters, and it is how the plugin
    talks back: :meth:`event` narrates, :meth:`progress` reports bytes (and
    drives ``monitor_callback``), and :meth:`check` raises if the copy has
    been cancelled or has run out of time - call it between chunks.
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
        if user_checksum is not None:
            algorithm, value = user_checksum
            mode = mode if mode != checksum_mode.none else checksum_mode.both
        self.checksum_mode = mode
        self.checksum_algorithm = algorithm
        self.user_checksum = value
        self.source_checksum: str | None = None
        self.source_size: int | None = None
        self.transferred = 0
        self._generation = context._cancel_generation
        self._lock = threading.Lock()
        self._last_report = self.started
        self._last_bytes = 0

    # -- narration ---------------------------------------------------------------

    def event(
        self, stage: str, description: str = "", side: int = ev.BOTH, domain: str | None = None
    ) -> None:
        emit(self.params, domain or self.domain, stage, description, side)

    @property
    def pair(self) -> str:
        return f"{self.source} => {self.destination}"

    # -- limits ------------------------------------------------------------------

    @property
    def deadline(self) -> float | None:
        """Monotonic time the copy must finish by, or ``None`` for no limit."""
        timeout = self.params.timeout
        return self.started + timeout if timeout and timeout > 0 else None

    def remaining(self) -> float | None:
        deadline = self.deadline
        return None if deadline is None else max(0.0, deadline - time.monotonic())

    def check(self) -> None:
        """Raise ``ECANCELED`` or ``ETIMEDOUT`` if the copy must stop."""
        if self.context._cancel_generation != self._generation:
            raise GError("Transfer canceled", errno.ECANCELED)
        deadline = self.deadline
        if deadline is not None and time.monotonic() > deadline:
            raise GError(f"Transfer timed out after {self.params.timeout} seconds", errno.ETIMEDOUT)

    # -- progress ----------------------------------------------------------------

    def progress(self, transferred: int, *, force: bool = False) -> None:
        """Record the absolute byte count; fire ``monitor_callback`` at most once a second."""
        with self._lock:
            self.transferred = transferred
        self._report(force)

    def add(self, count: int) -> None:
        """Add ``count`` bytes to the running total; safe from several threads."""
        with self._lock:
            self.transferred += count
        self._report(False)

    def _report(self, force: bool) -> None:
        callback = self.params.monitor_callback
        if callback is None:
            return
        with self._lock:
            now = time.monotonic()
            # Like gfal2, a copy shorter than one interval is never reported,
            # and ``force`` only flushes the final figure of a longer one.
            if now - self.started < MONITOR_INTERVAL:
                return
            if not force and now - self._last_report < MONITOR_INTERVAL:
                return
            transferred = self.transferred
            elapsed = now - self.started
            window = max(now - self._last_report, 1e-9)
            average = int(transferred / elapsed)
            instant = int((transferred - self._last_bytes) / window)
            self._last_report, self._last_bytes = now, transferred
        try:
            callback(self.source, self.destination, average, instant, transferred, int(elapsed))
        except Exception:
            _log.exception("monitor_callback raised; ignoring")


# ---------------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------------


def _checksum_algorithm(transfer: Transfer, plugin: Plugin | None) -> str:
    if transfer.checksum_algorithm:
        return transfer.checksum_algorithm
    return plugin.checksum_type() if plugin is not None else "ADLER32"


def _compute_checksum(context: Gfal2Context, url: str, algorithm: str, side: str) -> str:
    try:
        value = context.checksum(url, algorithm)
    except GError as exc:
        raise GError(f"Could not get the {side} checksum: {exc.message}", exc.code) from exc
    if normalise_name(algorithm) == "adler32":
        value = format_adler32(value)
    return value


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
    elif transfer.user_checksum and not checksums_match(transfer.user_checksum, value):
        raise GError(
            "DESTINATION CHECKSUM MISMATCH User defined checksum and destination checksum do "
            f"not match: {transfer.user_checksum} != {value}",
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


def _cleanup(transfer: Transfer) -> None:
    if not transfer.params.transfer_cleanup:
        return
    try:
        transfer.context.unlink(transfer.destination)
        transfer.event(ev.CLEANUP, "0", side=ev.DESTINATION)
    except GError as exc:
        transfer.event(ev.CLEANUP, str(exc.code), side=ev.DESTINATION)


def run_copy(
    context: Gfal2Context,
    params: TransferParameters,
    source: str,
    destination: str,
    user_checksum: tuple[str, str] | None = None,
) -> None:
    """Copy one file, raising ``GError`` on failure."""
    _list_events(params, [(source, destination)])
    if source == destination:
        # gfal2 deletes the source here when overwrite is set; refuse instead.
        raise GError("Source and destination are the same file", errno.EINVAL)
    plugin = context._copy_plugin(source, destination)
    if plugin is None and not params.local_transfers:
        raise GError(
            f"No plugin can copy {source} => {destination} and local transfers are disabled",
            errno.EPROTONOSUPPORT,
        )
    domain = plugin.event_domain or plugin.name if plugin is not None else ev.DOMAIN_LOCAL
    transfer = Transfer(
        context, params, source, destination, domain=domain, user_checksum=user_checksum
    )
    algorithm = _checksum_algorithm(transfer, plugin)
    manages = plugin is not None and plugin.copy_manages_destination
    if not params.strict_copy:
        _verify_source(transfer, algorithm)
        if not manages:
            _prepare_destination(transfer)
    narrate = plugin is None or not plugin.narrates_transfer
    if narrate:
        transfer.event(ev.TRANSFER_ENTER, transfer.pair)
    try:
        if plugin is not None:
            plugin.copy(transfer)
        else:
            transfer.event(ev.TRANSFER_TYPE, "streamed")
            stream(transfer)
        if narrate:
            transfer.event(ev.TRANSFER_EXIT, transfer.pair)
        if not params.strict_copy:
            _verify_destination(transfer, algorithm)
    except GError:
        if not manages:
            _cleanup(transfer)
        raise
    except Exception as exc:  # a plugin bug is still a failed copy, not a crash
        if not manages:
            _cleanup(transfer)
        raise GError(f"Transfer failed: {exc}", errno.EIO) from exc


def _list_events(params: TransferParameters, pairs: Sequence[tuple[str, str]]) -> None:
    emit(params, ev.DOMAIN_COPY, ev.LIST_ENTER)
    for source, destination in pairs:
        emit(params, ev.DOMAIN_COPY, ev.LIST_ITEM, f"{source} => {destination}")
    emit(params, ev.DOMAIN_COPY, ev.LIST_EXIT)


def _split_checksum(entry: str) -> tuple[str, str] | None:
    """``"ADLER32:1a2b3c4d"`` into its parts; empty means none."""
    if not entry:
        return None
    algorithm, sep, value = entry.partition(":")
    return (algorithm, value) if sep else ("", algorithm)


def run_bulk(
    context: Gfal2Context,
    params: TransferParameters,
    sources: Sequence[str],
    destinations: Sequence[str],
    checksums: Sequence[str] = (),
) -> list[GError | None]:
    """Copy each pair in turn; one result per pair, ``None`` for success."""
    if len(sources) != len(destinations):
        raise GError("Number of sources and destinations do not match", errno.EINVAL)
    if checksums and len(checksums) != len(sources):
        raise GError("Number of checksums does not match the number of files", errno.EINVAL)
    _list_events(params, list(zip(sources, destinations)))
    results: list[GError | None] = []
    for index, (source, destination) in enumerate(zip(sources, destinations)):
        user = _split_checksum(checksums[index]) if checksums else None
        try:
            run_copy(context, params, source, destination, user)
            results.append(None)
        except GError as exc:
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
) -> int:
    """Copy ``source`` to ``destination`` with reads and writes overlapped."""
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
    transfer.progress(total, force=True)
    return total


def stream(transfer: Transfer) -> None:
    """The core's streamed copy: read through one plugin, write through another."""
    context = transfer.context
    try:
        info = context.stat(transfer.source)
    except GError as exc:
        raise GError(f"Could not open source: {exc.message}", exc.code) from exc
    if info.is_dir():
        raise GError(f"{transfer.source} is a directory", errno.EISDIR)
    transfer.source_size = info.st_size
    try:
        reader = context._open(transfer.source, O_RDONLY)
    except GError as exc:
        raise GError(f"Could not open source: {exc.message}", exc.code) from exc
    try:
        try:
            writer = context._open(
                transfer.destination, O_WRONLY | O_CREAT | O_TRUNC, size=info.st_size
            )
        except GError as exc:
            raise GError(f"Could not open destination: {exc.message}", exc.code) from exc
        try:
            total = pump(transfer, reader, writer)
        finally:
            writer.close()
    finally:
        reader.close()
    if total != info.st_size:
        raise GError(
            f"Short copy: {total} bytes transferred, the source has {info.st_size}", errno.EIO
        )
