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
A copy from one regular ``file://`` file to another, where the platform has
``copy_file_range(2)`` (Linux), skips the pipeline: the kernel moves the
bytes, one ``COPY_BUFFERSIZE`` at a time so that progress and cancellation
behave as they do for the pipeline, and may share or offload them (a reflink
on btrfs or XFS, a server-side copy on NFS 4.2). A kernel or filesystem that
cannot (across filesystems on older kernels, ``ENOSYS``, ``EOPNOTSUPP``...)
hands over to the pipeline at the offset reached; see :func:`copy_range`.

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
* A completed regular ``file://`` destination gets one final ``fsync`` before
  success, so a cache or failing filesystem's delayed ENOSPC/EIO is not a
  false success. This is outside the chunk loop; pipes and devices are skipped.
* A bulk copy's per-file ``"ALG:value"`` replaces the algorithm and value
  but keeps the parameters' mode, as in gfal2, without gfal2's bugs: the
  caller's parameters are not modified, the algorithm name is not cut one
  character short, and a bulk copy with no checksum list keeps the
  parameters' algorithm and value instead of dropping them.

Layout: this module is the copy *sequence* - :class:`Transfer`, the event
and checksum steps, destination preparation and cleanup, :func:`run_copy`
and :func:`run_bulk`. The byte-moving half - :func:`stream`, :func:`pump`
and :func:`copy_range` - is in :mod:`xgfalclient._stream` and re-exported
here, so ``from xgfalclient.transfer import pump`` and patches of this
module's tunables (``MONITOR_INTERVAL``, ``STREAM_MONITOR_INTERVAL``) work
as they always have.
"""

from __future__ import annotations

import errno
import os
import stat as stat_module
import threading
import time
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any, NoReturn

from . import events as ev
from ._log import LOGGER

# The streamed copy and the local ``copy_file_range`` fast path live in
# :mod:`xgfalclient._stream`; they are re-exported here, where plugins and
# programs have always imported them from. ``PIPELINE_DEPTH`` is defined
# there (it is ``pump``'s default) and re-exported as this module's too.
from ._stream import PIPELINE_DEPTH as PIPELINE_DEPTH
from ._stream import copy_range as copy_range
from ._stream import pump as pump
from ._stream import stream as stream
from .checksum import checksums_match, format_adler32, normalise_name
from .enums import checksum_mode
from .errors import GError, from_oserror
from .plugin import Plugin
from .types import TransferParameters
from .url import parent

if TYPE_CHECKING:
    from .context import Gfal2Context

__all__ = [
    "Transfer",
    "TransferParameters",
    "copy_range",
    "emit",
    "pump",
    "run_bulk",
    "run_copy",
    "stream",
]


# The callback shapes, as in :mod:`xgfalclient.types` (kept here for plugins
# that annotate against this module).
EventCallback = Callable[[ev.GfaltEvent], Any]
MonitorCallback = Callable[[str, str, int, int, int, int], Any]

#: How often ``monitor_callback`` may fire during a plugin copy, in seconds.
MONITOR_INTERVAL = 1.0
#: The same for the core's streamed copy: gfal2 waits more than five seconds.
#: (Read by :func:`stream` from here at call time, so patching it works.)
STREAM_MONITOR_INTERVAL = 5.0


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
    """Call a user callback, marking anything it raises with :data:`_FROM_CALLBACK`.

    The mark is what lets every layer above tell "the user's code asked to
    stop" (re-raised untouched, ending even a bulk copy) from an ordinary
    copy failure (reported, cleaned up, possibly per file).
    """
    try:
        callback(*args)
    except Exception as exc:
        setattr(exc, _FROM_CALLBACK, True)
        raise


def _from_callback(exc: BaseException) -> bool:
    """Whether ``exc`` came out of a user callback (see :func:`_call`)."""
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
        """Start the clocks (timeout and monitor) and fix the checksum the copy is held to.

        ``domain`` names the plugin in events (``GFAL2:CORE:COPY:LOCAL`` for
        the streamed copy). ``user_checksum`` is a bulk entry's own
        ``(algorithm, value)``, replacing the parameters' pair but keeping
        their mode. The cancel generation is captured now, so a ``cancel()``
        issued before this copy started does not cancel it.

        Public, plugin-facing API (plugins and tests construct it), hence
        the keyword-only extras rather than a parameter object.
        """
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
        """Emit one event in this copy's domain (or ``domain``); a callback's exception propagates.

        The exception is also recorded, so a plugin that catches it on its
        way out (inside a library callback, say) still has the copy fail with
        it at the next :meth:`check` or when ``copy`` returns.
        """
        try:
            emit(self.params, domain or self.domain, stage, description, side)
        except Exception as exc:
            self._failed(exc)
            raise

    def _failed(self, exc: Exception) -> None:
        """Keep the first callback exception; later ones are consequences of it."""
        with self._lock:
            if self.callback_error is None:
                self.callback_error = exc

    @property
    def pair(self) -> str:
        """``source => destination``: the description gfal2 gives ``TRANSFER:ENTER``/``EXIT``."""
        return f"{self.source} => {self.destination}"

    # -- limits ------------------------------------------------------------------

    @property
    def deadline(self) -> float | None:
        """Monotonic time the copy must finish by, or ``None`` for no limit (``timeout=0``)."""
        timeout = self.params.timeout
        return self.started + timeout if timeout > 0 else None

    def remaining(self) -> float | None:
        """Seconds left before :attr:`deadline` (never negative), or None for no limit.

        For plugins that hand a timeout to a library call; pass it on rather
        than the parameters' ``timeout``, which counts from the copy's start.
        """
        deadline = self.deadline
        return None if deadline is None else max(0.0, deadline - time.monotonic())

    @property
    def cancelled(self) -> bool:
        """Whether the context was cancelled after this copy began."""
        return self.context._cancel_generation != self._generation

    def abort_on_cancel(self, resource: object) -> AbstractContextManager[None]:
        """While the ``with`` block runs, ``cancel()`` aborts ``resource`` (a socket...).

        :meth:`check` notices a cancel only between chunks; a plugin blocked
        in a ``recv`` on a server that has stopped sending registers the
        socket here, and ``cancel()`` shuts it down so the copy fails at
        once - as ``ECANCELED``, however the broken read reports it (see
        :func:`run_copy`). See :meth:`~xgfalclient.Gfal2Context.register_abort`.
        """
        return self.context.abort_on_cancel(resource)

    def check(self) -> None:
        """Raise a callback's exception, ``ECANCELED`` or ``ETIMEDOUT`` if the copy must stop.

        Cheap (no lock, no system call beyond the clock), so call it per
        chunk. The messages are gfal2's for the same conditions.
        """
        error = self.callback_error
        if error is not None:
            raise error
        if self.cancelled:
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
        """Fire ``monitor_callback`` if the interval rules allow; see :meth:`progress`.

        The rates are computed under the lock, the callback called outside
        it: a slow callback must not stall the threads still adding bytes.
        ``average`` is over the whole copy, ``instant`` since the last report.
        """
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
    """The user's algorithm, else the copying plugin's ``COPY_CHECKSUM_TYPE``, else ADLER32."""
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
    """:func:`_checksum_value`, with a failure reworded to say which end (``side``) it was."""
    try:
        return _checksum_value(context, url, algorithm)
    except GError as exc:
        raise GError(f"Could not get the {side} checksum: {exc.message}", exc.code) from exc


def _verify_source(transfer: Transfer, algorithm: str) -> None:
    """``source``/``both`` modes: checksum the source before copying, against the user's value.

    Done first so a corrupt source fails before any byte moves; the value is
    kept for the destination comparison in ``both`` mode. The mismatch text
    is gfal2's, prefix included, because tools match on it.
    """
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
    """``target``/``both`` modes: checksum the finished destination.

    Against the source's value when one was taken (``both``), else against
    the user's (``target``, where :meth:`TransferParameters.set_checksum`
    guaranteed one). A mismatch is ``EIO`` with gfal2's wording, and the
    caller's clean-up then removes the bad copy.
    """
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
    """A character device, FIFO or socket: something written into, never replaced or removed."""
    return stat_module.S_ISCHR(mode) or stat_module.S_ISFIFO(mode) or stat_module.S_ISSOCK(mode)


def _sync_local_destination(transfer: Transfer) -> None:
    """Commit a regular local destination before a copy reports success.

    A final durability barrier catches delayed ENOSPC/EIO from disks, network
    filesystems and FUSE caches without adding work to the hot chunk loop.
    Non-file URLs and special-file streams deliberately have no such contract.
    """
    if not transfer.destination.startswith("file:///"):
        return
    path = transfer.destination[len("file://") :]
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if stat_module.S_ISREG(info.st_mode):
                os.fsync(fd)
                info = os.fstat(fd)
                if info.st_size != transfer.transferred:
                    raise OSError(
                        errno.EIO,
                        "local destination has "
                        f"{info.st_size} bytes after sync; expected {transfer.transferred}",
                    )
        finally:
            os.close(fd)
    except OSError as exc:
        error = from_oserror(exc)
        raise GError(f"Could not sync destination: {error.message}", error.code) from exc


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
        with context.abort_exempt():  # a cancelled copy still removes what it wrote
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
    plugin = _copier(context, params, source, destination)
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
        _move(transfer, plugin, manages)
        _sync_local_destination(transfer)
        if narrate:
            transfer.event(ev.TRANSFER_EXIT, transfer.pair)
        if verify:
            _verify_destination(transfer, algorithm)
        _verify_third_party(transfer, algorithm)
    except Exception as exc:
        _cleanup(transfer, plugin_copy=plugin is not None)
        _raise_failure(transfer, exc)


def _copier(
    context: Gfal2Context, params: TransferParameters, source: str, destination: str
) -> Plugin | None:
    """The plugin that copies the pair, or None for the core's streamed copy.

    A copy onto its own source is refused with ``overwrite`` or a strict
    copy, and a pair no plugin copies needs ``local_transfers``.
    """
    if source == destination and (params.overwrite or params.strict_copy):
        # gfal2 deletes the source here (overwrite), or rewrites it in place
        # (strict, which truncates here); refuse instead. Otherwise the
        # existence check answers EEXIST, as gfal2's does.
        raise GError("Source and destination are the same file", errno.EINVAL)
    plugin = context._copy_plugin(source, destination)
    if plugin is None and not params.local_transfers:
        raise GError(
            f"No plugin supports a transfer from {source} to {destination}, "
            "and local streaming is disabled",
            errno.EPROTONOSUPPORT,
        )
    return plugin


def _move(transfer: Transfer, plugin: Plugin | None, manages: bool) -> None:
    """The copy itself: the plugin's, or the core's stream when there is none."""
    if plugin is None:
        transfer.event(ev.TRANSFER_TYPE, "streamed")
        stream(transfer)
        return
    # In strict mode nobody looked at what was there before.
    transfer.owns_destination = not manages and not transfer.params.strict_copy
    plugin.copy(transfer)
    if transfer.callback_error is not None:
        raise transfer.callback_error  # the plugin swallowed it


def _raise_failure(transfer: Transfer, exc: Exception) -> NoReturn:
    """Raise what a failed copy reports, given what made it fail."""
    error = transfer.callback_error
    if error is not None and error is not exc:
        raise error from exc  # a plugin wrapped the callback's exception
    if _from_callback(exc):
        raise exc
    if transfer.cancelled and not (isinstance(exc, GError) and exc.code == errno.ECANCELED):
        # A cancel that shut the copy's socket down: whatever the broken
        # connection looked like to the plugin, the copy was cancelled.
        raise GError("Transfer canceled", errno.ECANCELED) from exc
    if isinstance(exc, GError):
        raise exc
    # A plugin bug is still a failed copy, not a crash.
    raise GError(f"Transfer failed: {exc}", errno.EIO) from exc


def _domain(plugin: Plugin) -> str:
    """The event domain for ``plugin``'s copies: its declared one, else its name."""
    return plugin.event_domain or plugin.name


def _list_events(params: TransferParameters, pairs: Sequence[tuple[str, str]]) -> None:
    """``LIST:ENTER``, one ``LIST:ITEM`` per pair (URLs markup-escaped), ``LIST:EXIT``.

    gfal2 narrates the list even for a single copy, so FTS's parsers see the
    same frame either way.
    """
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
    _list_events(params, list(zip(sources, destinations, strict=False)))
    # As gfal2 does, the first pair picks the plugin; one with a bulk copy
    # (GridFTP pipelining) takes the whole list and does its own checks.
    plugin = context._copy_plugin(sources[0], destinations[0]) if sources else None
    users: list[tuple[str, str] | None] = [_split_checksum(entry) for entry in checksums]
    users = users or [None] * len(sources)
    if plugin is not None and plugin.implements("copy_bulk"):
        domain = _domain(plugin)
        transfers = [
            Transfer(context, params, source, destination, domain=domain, user_checksum=user)
            for source, destination, user in zip(sources, destinations, users, strict=False)
        ]
        return plugin.copy_bulk(params, transfers)
    mode = params.get_checksum()[0]
    return [
        _bulk_item(context, params, (source, destination), user, mode)
        for source, destination, user in zip(sources, destinations, users, strict=False)
    ]


def _bulk_item(
    context: Gfal2Context,
    params: TransferParameters,
    pair: tuple[str, str],
    user: tuple[str, str] | None,
    mode: checksum_mode,
) -> GError | None:
    """One ``(source, destination)`` of a bulk copy through :func:`run_copy`: None, or its error.

    A user checksum without a value needs end-to-end ``mode``; a callback's
    exception is re-raised, since it ends the whole call.
    """
    try:
        one_sided = mode in (checksum_mode.source, checksum_mode.target)
        if user is not None and one_sided and not user[1]:
            raise GError("Checksum value required if mode is not end to end", errno.EINVAL)
        run_copy(context, params, *pair, user)
    except GError as exc:
        if _from_callback(exc):
            raise
        return exc
    return None
