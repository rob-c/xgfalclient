"""Copies the http plugin claims: uploads, parallel downloads, and third-party copies.

**HTTP destinations** go through gfal2's ``gfal_http_copy``, event for
event and word for word. Between ``PREPARE:ENTER`` and ``PREPARE:EXIT`` come
the source checksum (skipped, with a warning, when the source cannot compute
that algorithm), the existing destination (``DESTINATION EXISTS ...``, or
deleted: ``OVERWRITE``) and the parent directory (``create_parent``); none
of them in ``strict_copy`` mode. Then ``TRANSFER:ENTER``, one
``TRANSFER:TYPE`` per attempt, and ``TRANSFER:EXIT`` - with the pair on
success, the error on failure; then the destination checksum, then
``EVICT``. The modes are ``3rd pull`` (the destination fetches), ``3rd push``
(the source sends) and ``streamed`` (the bytes flow through this process),
tried in that order from the first one chosen:

* a ``file://`` source, or remote copy switched off, means ``streamed`` and
  nothing else - whatever ``ENABLE_STREAM_COPY`` says;
* a ``copy_mode=pull|push`` query argument on the source (else on the
  destination) forces that mode, with no fallback;
* otherwise ``DEFAULT_COPY_MODE`` (``3rd pull``, ``3rd push`` or
  ``streamed``; anything else is ``3rd pull``, with a warning).

``ENABLE_REMOTE_COPY``, ``ENABLE_STREAM_COPY``, ``ENABLE_FALLBACK_TPC_COPY``
and ``DEFAULT_COPY_MODE`` are read from the source's and the destination's
own groups first (``[DAV:HOST]``, ``[HTTP:HOST]`` ...), where a boolean set
on either end must hold on both, and from ``[HTTP PLUGIN]`` otherwise. A
failed attempt's partial destination is removed (a ``CLEANUP`` event,
``0`` when it was gone already) unless it failed because the destination
exists; the next mode is tried unless the copy was cancelled, refused
(``EPERM``, ``EACCES``) or found nothing to copy (``ENOENT``).

Where this differs from gfal2, deliberately: a destination that fails its
checksum check is removed (``CLEANUP``), as the core removes one; with no
checksum algorithm set, the plugin's ``COPY_CHECKSUM_TYPE`` is used (gfal2
asks the endpoints for an algorithm named ``""``, and fails); a copy whose
deadline has passed tries no further mode; and a ``copy_mode`` query
argument does not also switch fallback off for every later copy in the
context, as gfal2's (which writes it into the options) does. A failed
streamed ``PUT`` is numbered from its status as davix numbers it (403
``EPERM``, 500 or 507 ``EIO``), except that a 409 - a missing parent, for
a ``PUT`` - is ``ENOENT`` rather than davix's ``EEXIST``, which tools that
match "File exists" would take for an existing target; gfal2 reports a
stale ``errno`` there - ``EISDIR``, ``EEXIST``, 256 or 39 against the same
answers - with the same message.

This module is gfal2's ``gfal_http_copy``: the preparation, the choice of
modes and their fallback, and the checksums around them. Each attempt is its
own module - :mod:`._tpc` (third-party ``COPY``), :mod:`._streamed` (the bytes
through this process) and, for HTTP to ``file://``, :mod:`._ranged` (parallel
ranged ``GET``\\ s) - with what they share in :mod:`._copy_common`. The
attempts are called through this module (``third_party``, ``streamed``,
``download``), which re-exports them.

Start reading at :func:`copy`, then :func:`http_copy` and :func:`run_modes`.
What a maintainer must not break: the *order* of the events (FTS and the
gfal2 python bindings' callers match them as strings), the message prefixes
(``SOURCE CHECKSUM``, ``DESTINATION EXISTS``, ``TRANSFER ...``) which tests
pin against gfal2's own output, and ``transfer.owns_destination``, which
tells the core whether *it* may remove the destination after a failure -
this module cleans up itself and must hand that ownership back unset.
"""

from __future__ import annotations

import errno
import logging
from typing import TYPE_CHECKING

from ... import events as ev
from ... import transfer as core
from ...checksum import checksums_match
from ...errors import GError
from ...transfer import Transfer
from ...url import parent, parse, scheme_of
from ._client import config_group
from ._copy_common import _CHECKSUM_SOURCE, _CHECKSUM_TARGET, _MODES, _se_boolean
from ._copy_common import HTTP_SCHEMES as HTTP_SCHEMES
from ._copy_common import PULL as PULL
from ._copy_common import PUSH as PUSH
from ._copy_common import STREAMED as STREAMED
from ._copy_common import is_http_scheme as is_http_scheme
from ._copy_common import local_path as local_path
from ._copy_common import resolved as resolved
from ._ranged import download as download
from ._streamed import streamed as streamed
from ._streamed import upload as upload
from ._tpc import third_party as third_party

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["PULL", "PUSH", "STREAMED", "CopyMode", "copy", "copy_mode", "is_http_scheme"]

_log = logging.getLogger("gfal2")

#: ``copy_mode=`` query values. gfal2 has no query spelling of ``streamed``:
#: a URL can force a third-party direction, never the bytes through the client.
_QUERY_MODES = {"pull": PULL, "push": PUSH}


def copy(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """The plugin's ``copy`` entry point: to ``file://`` a download, else gfal2's HTTP copy.

    The plugin only claims a ``file://`` destination when the source is
    HTTP (:meth:`HTTPPlugin.copy_check`); gfal2 itself would leave that pair
    to its core's streamed copy, which :func:`local_copy` mirrors.
    """
    if scheme_of(transfer.destination) == "file":
        local_copy(plugin, transfer)
    else:
        http_copy(plugin, transfer)


def local_copy(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """HTTP to ``file://``: the core's copy, step for step and event for event, moved faster.

    The events are in the core's domain (``DOMAIN_LOCAL``), not the http
    plugin's, because gfal2 never runs its http plugin for this pair - a
    script watching events must see what gfal2 would have shown it. Only
    the byte-moving is the plugin's (:func:`._ranged.download`).
    """
    transfer.domain = ev.DOMAIN_LOCAL
    strict = transfer.params.strict_copy
    algorithm = core._checksum_algorithm(transfer, plugin)
    if not strict:
        core._verify_source(transfer, algorithm)
        core._prepare_destination(transfer)
    transfer.event(ev.TRANSFER_ENTER, transfer.pair)
    # Strict copies never touched the destination beforehand, so they must
    # not remove one afterwards either; otherwise a partial file is ours.
    transfer.owns_destination = not strict
    try:
        download(plugin, transfer)
        transfer.event(ev.TRANSFER_EXIT, transfer.pair)
        if not strict:
            core._verify_destination(transfer, algorithm)
    except Exception:
        core._cleanup(transfer, False)  # quietly, as the core's streamed copy cleans
        raise
    finally:
        transfer.owns_destination = False  # cleaned here: not the core's to remove


def http_copy(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """gfal2's ``gfal_http_copy``: prepare, the modes, the destination checksum, eviction.

    Raises the attempt's :class:`GError`, prefixed as gfal2 prefixes it.
    The destination checksum runs only after a successful transfer; a
    mismatch removes the copy (see the module notes on where that differs
    from gfal2).
    """
    params = transfer.params
    transfer.event(ev.PREPARE_ENTER, transfer.pair)
    # ``strict_copy`` is gfal2's "do nothing but move bytes": no checksum,
    # no existence check, no parent creation - FTS uses it when it has done
    # those itself.
    checks = 0 if params.strict_copy else int(transfer.checksum_mode)
    # Deliberate deviation: gfal2 would ask for an algorithm named "" here.
    algorithm = transfer.checksum_algorithm or plugin.checksum_type()
    if checks & _CHECKSUM_SOURCE:
        _source_checksum(transfer, algorithm)
    if not params.strict_copy:
        _overwrite(transfer)
        _make_parent(transfer)
    transfer.event(ev.PREPARE_EXIT, transfer.pair)
    run_modes(plugin, transfer)
    if checks & _CHECKSUM_TARGET:
        # Owned only for the checksum's duration, so a mismatch's cleanup
        # is attributed to this step and not repeated by the core.
        transfer.owns_destination = True
        try:
            _destination_checksum(transfer, algorithm)
        except Exception:
            core._cleanup(transfer, True)  # deliberately: gfal2 keeps a bad copy
            raise
        finally:
            transfer.owns_destination = False
    if params.evict:
        _evict(plugin, transfer)


# ---------------------------------------------------------------------------
# Preparing, and checking the result
# ---------------------------------------------------------------------------


def _source_checksum(transfer: Transfer, algorithm: str) -> None:
    """The source's checksum, against the user's; skipped if the source cannot compute it.

    ``ENOSYS``/``ENOTSUP`` is how a server without that algorithm answers
    (davix's ``Want-Digest`` miss); gfal2 then copies anyway and lets the
    destination's checksum, if asked for, stand alone. Any other failure
    is the copy's, prefixed ``SOURCE CHECKSUM``.
    """
    transfer.event(ev.CHECKSUM_ENTER, side=ev.SOURCE)
    try:
        value = core._checksum_value(transfer.context, transfer.source, algorithm)
    except GError as exc:
        if exc.code not in (errno.ENOSYS, errno.ENOTSUP):
            raise GError(f"SOURCE CHECKSUM {exc.message}", exc.code) from None
        _log.warning("Checksum type %s not supported by source. Skip source check.", algorithm)
    else:
        transfer.source_checksum = value
        user = transfer.user_checksum
        if user and not checksums_match(value, user):
            raise GError(
                f"SOURCE CHECKSUM MISMATCH Source and user-defined {algorithm} do not match "
                f"({value} != {user})",
                errno.EIO,
            )
    transfer.event(ev.CHECKSUM_EXIT, side=ev.SOURCE)


def _destination_checksum(transfer: Transfer, algorithm: str) -> None:
    """The destination's checksum, against the source's, else against the user's.

    Comparison is :func:`~xgfalclient.checksum.checksums_match`'s: case and
    leading zeros ignored, since some servers drop an ADLER32's leading
    zeros. A source checksum, when one was taken, wins over the user's
    (which the source was already checked against).
    """
    transfer.event(ev.CHECKSUM_ENTER, side=ev.DESTINATION)
    try:
        value = core._checksum_value(transfer.context, transfer.destination, algorithm)
    except GError as exc:
        raise GError(f"DESTINATION CHECKSUM {exc.message}", exc.code) from None
    source, user = transfer.source_checksum, transfer.user_checksum
    if source:
        if not checksums_match(source, value):
            raise GError(
                f"DESTINATION CHECKSUM MISMATCH Source and destination {algorithm} do not match "
                f"({source} != {value})",
                errno.EIO,
            )
    elif user and not checksums_match(user, value):
        raise GError(
            f"DESTINATION CHECKSUM MISMATCH User-defined and destination {algorithm} do not "
            f"match ({user} != {value})",
            errno.EIO,
        )
    transfer.event(ev.CHECKSUM_EXIT, side=ev.DESTINATION)


def _exists(transfer: Transfer, url: str, prefix: str) -> bool:
    """gfal2's ``gfal_http_exists``, a failure worded as its two empty prefixes leave it.

    The three spaces in the message are gfal2's: it formats
    ``"%s %s %s"`` with two empty strings, and tests compare the text.
    """
    try:
        transfer.context.stat(url)
    except GError as exc:
        if exc.code == errno.ENOENT:
            return False
        raise GError(f"{prefix}   {exc.message}", exc.code) from None
    return True


def _overwrite(transfer: Transfer) -> None:
    """Refuse an existing destination (``EEXIST``), or delete it when ``overwrite`` is set.

    The ``EEXIST`` matters beyond the message: :func:`_cleanup` keys on it
    to leave a destination that was there before the copy alone.
    """
    url = transfer.destination
    if not _exists(transfer, url, "DESTINATION OVERWRITE"):
        return
    if not transfer.params.overwrite:
        raise GError(
            "DESTINATION EXISTS The destination file exists and overwrite is not enabled",
            errno.EEXIST,
        )
    try:
        transfer.context.unlink(url)
    except GError as exc:
        raise GError(f"DESTINATION OVERWRITE {exc.message}", exc.code) from None
    transfer.event(ev.OVERWRITE, f"Deleted {url}", side=ev.DESTINATION)


def _make_parent(transfer: Transfer) -> None:
    """Create the destination's parent, when asked and it is not there.

    ``mkdir_rec`` through the context, not the plugin, so a parent on
    another protocol's endpoint (rare, but gfal2 allows it) is made by the
    plugin that owns it; ``MKCOL`` creates one level at a time.
    """
    if not transfer.params.create_parent:
        return
    up = parent(transfer.destination)
    if _exists(transfer, up, "DESTINATION MAKE_PARENT"):
        return
    try:
        transfer.context.mkdir_rec(up, 0o755)
    except GError as exc:
        raise GError(f"DESTINATION MAKE_PARENT {exc.message}", exc.code) from None


def _evict(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """``gfal-copy --evict``: release the source's disk copy, and say how that went.

    A Tape REST ``release`` (:class:`._tape.TapeREST`) with no request id,
    as gfal2 sends it. Its failure never fails the copy - the data is
    already where it was going - it is logged and reported as ``EVICT -1``.
    """
    failed = plugin.tape.release([transfer.source], "")[0]
    if failed is not None:
        _log.info("Eviction request failed: %s", failed.message)
    transfer.event("EVICT", "-1" if failed is not None else "0", side=ev.SOURCE)


# ---------------------------------------------------------------------------
# Choosing the modes
# ---------------------------------------------------------------------------


def _both_ends(plugin: HTTPPlugin, source: str, destination: str, key: str) -> bool:
    """A boolean the endpoints' groups decide together (both must allow), else the plugin's.

    gfal2's ``get_se_custom_opt_boolean`` on each end: a site that says
    ``ENABLE_REMOTE_COPY=false`` for itself vetoes a TPC whichever side it
    is on, and only when neither end says anything does ``[HTTP PLUGIN]``
    decide.
    """
    options = plugin.options
    ends = [_se_boolean(options, url, key) for url in (source, destination)]
    if ends != [None, None]:
        return all(value is not False for value in ends)
    return bool(options.boolean(plugin.option_group, key, True))


def copy_mode(url: str) -> str | None:
    """A ``copy_mode=pull|push`` query argument on ``url``, as a mode name; else ``None``.

    An unknown value is ignored, as gfal2's ``strtol``-free string compare
    ignores it, rather than refused.
    """
    for key, value in parse(url).query_items():
        if key == "copy_mode" and value in _QUERY_MODES:
            return _QUERY_MODES[value]
    return None


class CopyMode:
    """gfal2's ``HttpCopyMode``: where to start, and how far to fall back.

    :attr:`mode` is the mode to try now (``None`` once nothing is left),
    :attr:`fallback` whether a failure moves on to :meth:`next` at all,
    :attr:`streaming` whether ``streamed`` may be reached, and
    :attr:`streaming_only` whether the chosen first mode was ``streamed``
    (kept for gfal2 parity; the loop does not read it). One instance per
    copy; not shared between threads.
    """

    def __init__(self, plugin: HTTPPlugin, source: str, destination: str) -> None:
        """Choose the first mode, following gfal2's precedence (see the module notes)."""
        self.fallback = True
        self.streaming_only = True
        self.streaming = True
        # A non-HTTP source (``file://`` uploads) cannot be pulled by a
        # remote server, and remote copy switched off means the same.
        if not is_http_scheme(source) or not _both_ends(
            plugin, source, destination, "ENABLE_REMOTE_COPY"
        ):
            self.mode: str | None = STREAMED
            return
        self.streaming = _both_ends(plugin, source, destination, "ENABLE_STREAM_COPY")
        forced = copy_mode(source) or copy_mode(destination)
        if forced is not None:
            _log.info("Extracted copy mode from query arguments: %s", forced)
            self.mode, self.fallback, self.streaming_only = forced, False, False
            return
        self.fallback = _both_ends(plugin, source, destination, "ENABLE_FALLBACK_TPC_COPY")
        options = plugin.options
        chosen = None
        # The source's own group is consulted before the destination's, and
        # an invalid value there is skipped silently, as gfal2 skips it.
        for url in (source, destination):
            chosen = chosen or _mode_named(options.string(config_group(url), "DEFAULT_COPY_MODE"))
        if chosen is not None:
            _log.info("Using storage specific copy mode configuration: %s", chosen)
        else:
            configured = options.string(plugin.option_group, "DEFAULT_COPY_MODE", PULL)
            chosen = _mode_named(configured)
            if chosen is None:
                _log.warning(
                    "Invalid Gfal2 configuration for 'DEFAULT_COPY_MODE'. "
                    "Using default copy mode: %s",
                    PULL,
                )
                chosen = PULL
        self.mode, self.streaming_only = chosen, chosen == STREAMED

    def next(self) -> None:
        """Move to the next mode: pull, then push, then streamed (if allowed), then none.

        Starting from ``streamed`` - or from push with streaming disabled -
        there is nowhere left to go, which ends the loop.
        """
        if self.mode == PULL:
            self.mode = PUSH
        elif self.mode == PUSH and self.streaming:
            self.mode = STREAMED
        else:
            self.mode = None


def _mode_named(name: str) -> str | None:
    """``name`` if it is a mode gfal2 knows (``3rd pull``, ``3rd push``, ``streamed``)."""
    return name if name in _MODES else None


def _should_fallback(code: int) -> bool:
    """Whether a failure with ``code`` is worth another mode (gfal2's ``is_fallback_error``).

    Cancelled, forbidden or missing-source failures would fail every mode
    the same way, so trying the next one only adds time and noise.
    """
    return code not in (errno.ECANCELED, errno.EPERM, errno.ENOENT, errno.EACCES)


# ---------------------------------------------------------------------------
# The attempts
# ---------------------------------------------------------------------------


def run_modes(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """gfal2's loop over the copy modes, with its events and its final wording.

    Each attempt gets its own ``TRANSFER:TYPE`` event, and a failed attempt
    is cleaned up before the next starts, so a push never lands on a
    half-written pull. The final error lists every mode tried, as gfal2's
    ``ERROR: Copy failed (3rd pull, 3rd push). Last attempt: ...`` does,
    and keeps the *last* attempt's errno.
    """
    modes = CopyMode(plugin, transfer.source, transfer.destination)
    transfer.event(ev.TRANSFER_ENTER, transfer.pair)
    tried: list[str] = []
    while modes.mode is not None:
        mode = modes.mode
        transfer.event(ev.TRANSFER_TYPE, mode)
        try:
            if mode != STREAMED:
                third_party(plugin, transfer, mode)
            elif modes.streaming:
                streamed(plugin, transfer)
            else:
                # Streamed is next but disabled: gfal2's own error, no cleanup
                # (nothing was attempted) and no further mode.
                last = GError(
                    "STREAMED DISABLED Only streamed copy possible but streaming is disabled",
                    errno.EINVAL,
                )
                _log.warning("%s", last.message)
                break
            transfer.event(ev.TRANSFER_EXIT, transfer.pair)
            return
        except GError as exc:
            _log.warning("Copy failed with mode %s: %s", mode, exc.message)
            last = exc
        _cleanup(plugin, transfer, last)
        tried.append(mode)
        modes.next()
        # The deadline has passed: another mode would only time out too.
        if not (modes.fallback and _should_fallback(last.code)) or transfer.remaining() == 0.0:
            break
    message = last.message
    if tried:
        message = f"ERROR: Copy failed ({', '.join(tried)}). Last attempt: {message}"
    transfer.event(ev.TRANSFER_EXIT, message)
    # Cleaned here, as gfal2 cleans, or deliberately kept: not the core's to remove.
    transfer.owns_destination = False
    raise GError(f"TRANSFER {message}", last.code)


def _cleanup(plugin: HTTPPlugin, transfer: Transfer, error: GError) -> None:
    """Remove what a failed attempt may have left - unless the destination was there before.

    The ``CLEANUP`` event carries the unlink's errno (``0`` also when the
    file was already gone, which is the usual case after a refused
    ``COPY``). ``transfer_cleanup`` off is FTS asking to keep partial files
    for diagnosis.
    """
    if error.code == errno.EEXIST or not transfer.params.transfer_cleanup:
        return
    try:
        with plugin.context.abort_exempt():  # a cancel()'s drain must not stop it
            plugin.unlink(transfer.destination)
        code = 0
    except GError as exc:
        code = 0 if exc.code == errno.ENOENT else exc.code
    transfer.event(ev.CLEANUP, str(code), side=ev.DESTINATION)
