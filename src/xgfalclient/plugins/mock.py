"""``mock://`` - a storage element described entirely by its URL.

gfal2 ships this plugin so that FTS and other callers can be tested without
a server: the query string says what the "file" is and how operations on it
should behave. This is a transcription of gfal2 2.23.5's
``plugins/mock``, quirks included, because test suites written against it
(FTS's among them) depend on the quirks.

Reading the query is gfal2's ``gfal_plugin_mock_get_value``: the value of the
*first* ``&``-separated argument whose name **starts with** the key (so
``size`` also answers to ``size_pre=3``, and ``access`` to
``access_errno=13``), taken raw - no percent-decoding, and ``#`` is just a
character. Numbers are C's ``atoll``/``strtoull``: a leading integer counts,
junk is 0, a negative size wraps around to an unsigned one.

==========================  ===================================================
``wait=N``                  ``stat`` sleeps ``N`` s first (so do ``open``,
                            ``unlink`` and ``opendir``, which stat)
``signal=N``                ``stat`` raises signal ``N`` after a second, only
                            with ``[MOCK PLUGIN] SIGNALS=true``
``errno=N``                 ``stat`` (so ``open``/``unlink``/``opendir``),
                            ``checksum`` and ``getxattr`` fail with ``N``
``size=N``                  the file is ``N`` bytes
``size_pre=N``/``size_post``  only for a ``fts_url_copy`` user agent: the
                            destination's size before (0 is ``ENOENT``) and
                            after the copy - a stat-order state machine
``list=a:0644:10,b``        a directory; entries are ``name[:octal mode[:size]]``
``access=1``/``exists=1``   ``access`` answers 1; otherwise it fails with
                            ``access_errno=N``, else ``ENOENT``
``rd_path=URL`` (repeated)  ``mkdir`` of a URL that prefixes one fails ``EPERM``
``checksum=V``              what ``checksum`` answers, and a copy's source
                            and destination checksums
``user.status=V`` ...       ``getxattr`` of ``user.status``, ``user.replicas``,
                            ``user.guid``, ``user.comment``, ``spacetoken``
``open_errno=N``            ``open`` fails with ``N``
``read_wait=N``             each ``read`` sleeps ``N`` s
``read_errno=N``            ``read`` fails with ``N``
``time=N`` (destination)    a copy takes ``N`` s (else ``MIN_TRANSFER_TIME`` to
                            ``MAX_TRANSFER_TIME``)
``transfer_errno=N`` (dst)  a copy fails with ``N`` after its first second
``staging_time=N``          staging completes ``N`` s after it is asked for
``staging_errno=N``         staging fails with ``N`` once it completes
``release_errno=N``         ``release`` fails with ``N``
``archiving_time=N``        archived ``N`` s after the first poll
``archiving_errno=N``       archiving fails with ``N`` once that time is up
==========================  ===================================================

What the table leaves implicit, and tests rely on:

* Prefix matching cuts both ways. ``?access_errno=13`` on its own makes
  ``access`` *succeed* (its ``access`` value is ``13``); the errno is only
  reached behind an earlier ``access=0``. Put ``size=`` before
  ``size_pre=``, and beware that ``time`` also answers to ``timeout=...``.
* Values are cut to gfal2's buffers: 63 characters for most keys, 1023 for
  ``list``, 2047 for ``checksum``, ``time``, the xattrs and ``getxattr``'s
  ``errno``. ``rd_path`` is the exception twice over: every occurrence
  counts, and ``rd_path=`` is found anywhere after the ``?``.
* Error knobs are numbers stored in a C ``int`` (wrapping at 32 bits) and
  fail with ``os.strerror(N)`` as the message. ``errno``, ``open_errno``,
  ``read_errno`` and ``access_errno`` count only when positive; the
  staging, release, archiving and transfer ones fail on any non-zero
  value. ``wait``, ``staging_time`` and ``archiving_time`` are 64-bit.
* ``size_pre``/``size_post``: with a user agent starting ``fts_url_copy``,
  stats cycle source, destination-before, destination-after (and a copy
  that is not cancelled jumps to "after"), so FTS's stat-copy-stat sequence sees
  the destination appear. Every ``stat`` advances it, including the one in
  ``open``, ``unlink`` and ``opendir``. The cycle is per plugin instance.
* ``open`` accepts exactly ``O_RDONLY`` or ``O_WRONLY``: any other flag
  (``O_CREAT`` included) is ``ENOSYS``, "does not support read and write".
* ``time=0`` makes a copy instant, and then ``transfer_errno`` never fires
  (it is checked once per elapsed second); a negative ``time`` fails the
  copy as cancelled (``ECANCELED``).
* Staging: ``bring_online`` records when each URL will be online; a
  synchronous call, or ``staging_time`` 0, answers at once. A poll for a URL
  never asked for counts as done. Archiving starts its clock at the first
  ``archive_poll`` and forgets the URL once it reports done.

Reads return random bytes, as gfal2's come from ``/dev/urandom``. There is
no ``rmdir``, ``rename``, ``chmod``, ``listxattr``, ``setxattr`` or token
support: those are ``EPROTONOSUPPORT``, as in gfal2. Staging and archiving
state is process-wide, as gfal2's tables are.

The copy is the plugin's own, as in gfal2: it never stats, refuses or
deletes the destination, compares checksums straight from the two URLs (an
empty one matches anything), emits ``TRANSFER:ENTER``/``TYPE``/``EXIT``
itself, reports no progress, and ignores ``params.timeout``.

Where this knowingly differs from gfal2 (each an upstream defect):

* ``read_wait``/``read_errno`` work; gfal2 reads them through a pointer to the
  URL that is freed after ``open``, so in practice they never fire there.
* Reading past the end returns nothing, not more random bytes, and seeking
  before the start is ``EINVAL`` rather than a negative offset.
* A negative ``wait`` does not sleep (gfal2 sleeps for ~136 years).
* ``[MOCK PLUGIN] SIGNALS`` is read when the plugin first loads, which is the
  first ``mock:`` call rather than context creation.
"""

from __future__ import annotations

import contextlib
import errno
import os
import random
import re
import signal
import stat as _stat
import threading
import time
import uuid
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING

from ..errors import GError
from ..plugin import O_RDONLY, O_WRONLY, DirEntry, Plugin, PluginFile, StagingResult
from ..transfer import Transfer
from ..types import Stat

if TYPE_CHECKING:
    from ..context import Gfal2Context

__all__ = ["MockPlugin"]

# gfal2's buffer sizes: a value longer than the buffer is cut short (to one
# less than the size, for the C string's terminating NUL).
_ARG = 64
_LIST = 1024
_URL_MAX = 2048

_ULLONG = 2**64
#: What C's number parsers skip and accept before the digits: isspace(), a sign.
_NUMBER = re.compile(r"[ \t\n\v\f\r]*([+-]?)")

#: Where gfal2 looks for ``MOCK_LOAD_TIME_SIGNAL<N>`` (the process arguments).
_CMDLINE = "/proc/self/cmdline"
_LOAD_TIME_SIGNAL = "MOCK_LOAD_TIME_SIGNAL"

#: How long a second of a mock copy lasts (tests shorten it).
_TICK = 1.0

#: The attributes gfal2's mock answers from the query; the key is the name itself.
_XATTRS = ("user.status", "user.replicas", "user.guid", "user.comment", "spacetoken")

# The fts_url_copy stat stages (gfal_mock_plugin.h ``StatStage``).
_SOURCE, _BEFORE, _AFTER = 0, 1, 2

# Process-wide, like gfal2's static hash tables: URL -> time() it is done.
_tables_lock = threading.Lock()
_staging_end: dict[str, int] = {}
_archiving_end: dict[str, int] = {}


# -- gfal2's query parsing ----------------------------------------------------------------


def _value(url: str, key: str, size: int = _ARG) -> str:
    """``gfal_plugin_mock_get_value``: the first ``key*=value``, raw, at most ``size-1`` chars."""
    mark = url.find("?")
    if mark < 0:
        return ""
    for arg in url[mark + 1 :].split("&"):
        if arg.startswith(key):
            equals = arg.find("=")
            if equals >= 0:
                return arg[equals + 1 :][: size - 1]
    return ""


def _values(url: str, key: str) -> list[str]:
    """``gfal_plugin_mock_get_values``: each non-empty value after ``key=`` in the query."""
    mark = url.find("?")
    if mark < 0:
        return []
    needle = key + "="
    found: list[str] = []
    position = mark
    while True:
        match = url.find(needle, position)
        if match < 0:
            return found
        start = match + len(needle)
        end = url.find("&", match)
        value = url[start:end] if end >= 0 else url[start:]
        if value:
            found.append(value)
        if end < 0:
            return found
        position = end


def _strtol(text: str, base: int = 10) -> tuple[int, int]:
    """C ``strtol``: the value (saturated to 64 bits) and where parsing stopped."""
    lead = _NUMBER.match(text)
    assert lead is not None  # the pattern matches the empty string
    digits = "01234567" if base == 8 else "0123456789"
    end = lead.end()
    while end < len(text) and text[end] in digits:
        end += 1
    if end == lead.end():
        return 0, 0  # no digits: the end pointer is the start of the string
    value = int(text[lead.end() : end], base)
    value = -value if lead.group(1) == "-" else value
    return max(-(2**63), min(2**63 - 1, value)), end


def _atoll(text: str) -> int:
    """C ``atoll``: the leading decimal integer, saturated to 64 bits; junk is 0."""
    return _strtol(text)[0]


def _int(url: str, key: str) -> int:
    """``gfal_plugin_mock_get_int_from_str`` of the value, stored in a C ``int``."""
    return _c_int(_atoll(_value(url, key)))


def _c_int(value: int) -> int:
    """``value`` stored in a 32-bit C ``int``: two's-complement wrap-around."""
    return (value + 2**31) % 2**32 - 2**31


def _unsigned(url: str, key: str) -> int:
    """``strtoull``: a negative value wraps around, an overflow saturates."""
    text = _value(url, key)
    lead = _NUMBER.match(text)
    assert lead is not None
    digits = re.match(r"\d*", text[lead.end() :])
    assert digits is not None
    if not digits.group():
        return 0
    value = int(digits.group())
    if value >= _ULLONG:
        return _ULLONG - 1
    return -value % _ULLONG if lead.group(1) == "-" else value


def _fail(code: int) -> GError:
    """The error an injected errno produces: ``strerror`` text, ``code`` as is."""
    return GError(os.strerror(code), code)


def _not_ready() -> GError:
    """A poll of a file still pending: gfal2's mock words it this way."""
    return GError("Not ready", errno.EAGAIN)


def _now() -> int:
    """``time(NULL)``: gfal2's staging clock has whole seconds."""
    return int(time.time())


def _raise_signal(number: int) -> None:
    """C ``raise``: an invalid signal number is ignored."""
    with contextlib.suppress(ValueError, OSError):
        signal.raise_signal(number)


def _load_time_signal(path: str = _CMDLINE) -> None:
    """gfal2's "seppuku hook": raise the signal ``MOCK_LOAD_TIME_SIGNAL<N>`` in argv names."""
    try:
        with open(path, "rb") as handle:
            arguments = handle.read().decode("utf-8", "replace").split("\0")
    except OSError:
        return  # no /proc: gfal2 does nothing either
    for argument in arguments:
        found = argument.find(_LOAD_TIME_SIGNAL)
        if found >= 0:
            _raise_signal(_atoll(argument[found + len(_LOAD_TIME_SIGNAL) :]))
            return


def _entries(listing: str) -> Iterator[tuple[str, Stat, int]]:
    """gfal2's ``opendir`` parse of ``list=``, including where its ``strtol`` calls stop.

    An entry is ``name[:mode[:size]]`` with an octal mode (``S_IFREG`` added
    when it has no type bits). gfal2 reads the size one character past the
    end of the mode - normally the ``:`` - so a size-less entry takes its
    size from the start of the next entry. ``d_type`` stays 0: gfal2 never
    sets it.
    """
    position = 0
    while True:
        while position < len(listing) and listing[position] == ",":
            position += 1
        if position >= len(listing):
            return
        end = listing.find(",", position)
        end = len(listing) if end < 0 else end
        name, info = _entry(listing, listing[position:end], end)
        yield name, info, 0
        position = end + 1


def _entry(listing: str, token: str, end: int) -> tuple[str, Stat]:
    """One ``name[:mode[:size]]`` entry, ``token``, which ends at ``end`` in ``listing``.

    A size-less entry's size is read from what follows ``end``, as gfal2's
    ``strtol`` does.
    """
    name, colon, rest = token.partition(":")
    mode = size = 0
    if colon:
        mode, used = _strtol(rest, 8)
        mode %= 2**32  # mode_t
        if not mode & 0o170000:  # S_IFMT, which is 16 bits on macOS
            mode |= _stat.S_IFREG
        stop = len(name) + 1 + used
        tail = token[stop + 1 :] if stop < len(token) else listing[end + 1 :]
        size = _strtol(tail)[0] % _ULLONG  # gfal2's bindings print it unsigned
    return name[:255], Stat(st_mode=mode, st_size=size)


def _checksums_match(one: str, other: str) -> bool:
    """An empty checksum on either side counts as a match, as in gfal2."""
    return not one or not other or one == other


# -- files ----------------------------------------------------------------------------------


class _MockReader(PluginFile):
    """Random bytes up to the stat size, as gfal2's reads of ``/dev/urandom``.

    Two reads of the same range differ, so a test cannot compare content,
    only lengths; a copy's checksum comes from ``checksum=`` instead.
    """

    def __init__(self, url: str, size: int) -> None:
        """``size`` is the ``stat`` size taken when the file was opened."""
        super().__init__(url)
        self._size = size

    def size(self) -> int:
        """The size fixed at open, for ``SEEK_END``."""
        return self._size

    def pread(self, offset: int, size: int) -> bytes:
        """``read_wait`` seconds' sleep, then ``read_errno``, then the random bytes.

        Both knobs are read from the URL on every call. Past the end of the
        file the answer is empty.
        """
        wait = _int(self.url, "read_wait")
        if wait > 0:
            time.sleep(wait)
        code = _int(self.url, "read_errno")
        if code > 0:
            raise _fail(code)
        return os.urandom(max(0, min(size, self._size - offset)))


class _MockWriter(PluginFile):
    """gfal2 opens ``/dev/null`` for a plain ``O_WRONLY``: every write is accepted and lost."""

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        """Claim all of ``data`` written; nothing is kept or checked."""
        return len(data)


# -- the plugin -----------------------------------------------------------------------------


class MockPlugin(Plugin):
    """gfal2's ``mock`` plugin; the module docstring lists the URL knobs.

    Per instance (one per context): the ``fts_url_copy`` stat cycle, under
    ``_lock``. Process-wide: the staging and archiving clocks, under
    ``_tables_lock``. Nothing else is remembered between calls, so the same
    URL always behaves the same way otherwise.
    """

    name = "mock"
    schemes = ("mock",)
    option_group = "MOCK PLUGIN"
    priority = 300
    event_domain = "GFAL2::PLUGINS::FILE"
    # gfal2's mock copy does all of it itself: events, destination, checksums.
    narrates_transfer = True
    copy_manages_destination = True
    copy_manages_checksums = True

    def __init__(self, context: Gfal2Context) -> None:
        """Read ``[MOCK PLUGIN] SIGNALS``; when it is true, fire the load-time signal hook."""
        super().__init__(context)
        self._lock = threading.Lock()
        self._stage = _SOURCE
        self._signals = bool(self.options.boolean(self.option_group, "SIGNALS", False))
        if self._signals:
            _load_time_signal()

    def handles(self, url: str, operation: str) -> bool:
        """Every URL that starts ``mock:``, whatever the operation."""
        return url.startswith("mock:")  # gfal2's strncmp: case-sensitive, any form after it

    # -- namespace ---------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        """``wait``, then ``signal``, then ``errno``, then the size; a ``list`` makes a directory.

        The mode is always ``0755`` with ``S_IFDIR`` or ``S_IFREG``; every
        other field is 0. The order of the knobs is gfal2's and matters: a
        URL with both ``wait`` and ``errno`` sleeps before it fails.
        """
        wait = _atoll(_value(url, "wait"))
        if wait > 0:
            time.sleep(wait)
        number = _int(url, "signal")
        if number > 0 and self._signals:
            time.sleep(1)
            _raise_signal(number)
        code = _int(url, "errno")
        if code > 0:
            raise _fail(code)
        size = _unsigned(url, "size")
        agent = self.context.get_user_agent()[0]
        if agent is not None and agent.startswith("fts_url_copy"):
            with self._lock:
                stage = self._stage
                self._stage = {_BEFORE: _AFTER, _AFTER: _SOURCE, _SOURCE: _BEFORE}[stage]
            if stage == _BEFORE:
                size = _unsigned(url, "size_pre")
                if size == 0:
                    raise _fail(errno.ENOENT)
            elif stage == _AFTER:
                size = _unsigned(url, "size_post")
        kind = _stat.S_IFDIR if _value(url, "list") else _stat.S_IFREG
        return Stat(st_mode=kind | 0o755, st_size=size)

    def access(self, url: str, mode: int) -> int:
        """1 if ``access`` or ``exists`` is positive, else ``access_errno`` or ``ENOENT``.

        ``mode`` is ignored, and ``stat``'s knobs (``wait``, ``errno``) do not
        apply. See the module docstring for the prefix trap in ``access``.
        """
        for key in ("access", "exists"):
            value = _value(url, key)
            if value and _c_int(_atoll(value)) > 0:
                return 1
        code = _int(url, "access_errno")
        raise _fail(code if code > 0 else errno.ENOENT)

    def mkdir(self, url: str, mode: int) -> None:
        """Succeed, unless a ``rd_path`` value starts with this URL (minus its query): ``EPERM``.

        Nothing is created: a later ``stat`` of the URL is as its query says.
        """
        read_only = _values(url, "rd_path")
        base = url[: url.find("?")]
        if any(path.startswith(base) for path in read_only):
            raise _fail(errno.EPERM)

    def mkdir_rec(self, url: str, mode: int) -> None:
        """As :meth:`mkdir`: gfal2's mock has no parents to make."""
        self.mkdir(url, mode)

    def unlink(self, url: str) -> None:
        """A :meth:`stat` and nothing more: it fails as that stat fails."""
        self.stat(url)

    def opendir(self, url: str) -> Iterator[DirEntry]:
        """The ``list`` entries, after a :meth:`stat`; ``ENOTDIR`` without a ``list``."""
        if not self.stat(url).is_dir():
            raise _fail(errno.ENOTDIR)
        return iter(list(_entries(_value(url, "list", _LIST))))

    # -- I/O ---------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        """A :meth:`stat`, then ``open_errno``; a random-byte reader or a null writer.

        ``flags`` must be exactly ``O_RDONLY`` or ``O_WRONLY``; anything else
        is ``ENOSYS``. ``mode`` and ``size`` are ignored.
        """
        info = self.stat(url)
        code = _int(url, "open_errno")
        if code > 0:
            raise _fail(code)
        if flags == O_RDONLY:
            return _MockReader(url, info.st_size)
        if flags == O_WRONLY:
            return _MockWriter(url)
        raise GError("Mock plugin does not support read and write", errno.ENOSYS)

    # -- metadata ------------------------------------------------------------------

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        """``errno`` if positive, else the ``checksum`` value, ``""`` when there is none.

        The algorithm and range are ignored: the same text answers for all.
        """
        code = _int(url, "errno")
        if code > 0:
            raise _fail(code)
        return _value(url, "checksum", _URL_MAX)

    def getxattr(self, url: str, name: str) -> str:
        """``errno`` if positive, else the value of the key called ``name``.

        Only :data:`_XATTRS` names are answered, and a known name without a
        value is ``ENODATA``. Any other name is ``ENODATA`` too - unless the
        URL has a non-positive ``errno=``, which gfal2's reuse of its buffer
        turns into ``""``.
        """
        found = _value(url, "errno", _URL_MAX)
        code = _c_int(_atoll(found))
        if code > 0:
            raise _fail(code)
        answer = ""
        if name in _XATTRS:
            found = answer = _value(url, name, _URL_MAX)
        # gfal2 tests its argument buffer, which still holds the errno value
        # for any other name: an ``errno=0`` makes every name answer "".
        if not found:
            raise GError(f"Failed to retrieve xattr {name}", errno.ENODATA)
        return answer

    # -- tape --------------------------------------------------------------------

    def bring_online(
        self,
        urls: Sequence[str],
        metadata: Sequence[str],
        pintime: int,
        timeout: int,
        is_async: bool,
    ) -> tuple[list[StagingResult], str]:
        """Start the staging clock for each URL; a random UUID is the request token.

        Each result is ``True`` (or the ``staging_errno`` failure) when the
        file is "online" already - ``staging_time`` not positive, or a
        synchronous call - and ``False`` (queued) otherwise. ``metadata``,
        ``pintime`` and ``timeout`` are ignored, as in gfal2. Asking again
        restarts that URL's clock.
        """
        results: list[StagingResult] = []
        for url in urls:
            code = _int(url, "staging_errno")
            end = _now() + _atoll(_value(url, "staging_time"))
            with _tables_lock:
                _staging_end[url] = end
            # A synchronous call is done at once; gfal2 does not wait.
            if end <= _now() or not is_async:
                results.append(_fail(code) if code else True)
            else:
                results.append(False)
        return results, str(uuid.uuid4())

    def bring_online_poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        """Per URL: done (``True`` or ``staging_errno``) once its time is up, else ``EAGAIN``.

        The token is ignored; the clocks are keyed by URL alone.
        """
        results: list[StagingResult] = []
        for url in urls:
            code = _int(url, "staging_errno")
            with _tables_lock:
                end = _staging_end.get(url)
            if end is None or end <= _now():
                results.append(_fail(code) if code else True)
            else:
                results.append(_not_ready())
        return results

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``release_errno`` per URL, ``None`` (released) without one; no state changes."""
        results: list[GError | None] = []
        for url in urls:
            code = _int(url, "release_errno")
            results.append(_fail(code) if code else None)
        return results

    def abort_bring_online(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """Success for every URL; the staging clocks are left running."""
        return [None for _ in urls]  # gfal2's only touches its arguments

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        """``EAGAIN`` until ``archiving_time`` after the URL's first poll, then done.

        Done is ``True`` or the ``archiving_errno`` failure, and forgets the
        URL, so polling it again starts a new clock.
        """
        results: list[StagingResult] = []
        for url in urls:
            code = _int(url, "archiving_errno")
            with _tables_lock:
                end = _archiving_end.setdefault(url, _now() + _atoll(_value(url, "archiving_time")))
                done = end <= _now()
                if done:
                    del _archiving_end[url]  # the next poll starts the clock again
            results.append((_fail(code) if code else True) if done else _not_ready())
        return results

    # -- copies ------------------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        """Only ``mock:`` to ``mock:``; a copy to or from anything else is streamed."""
        return source.startswith("mock:") and destination.startswith("mock:")

    def copy(self, transfer: Transfer) -> None:
        """``gfal_plugin_mock_filecopy``: checksums, a timed sleep, injected failure.

        In order: with ``GFALT_CHECKSUM_SOURCE``, the source's ``checksum``
        must match the user's (``EIO``); the copy then "runs" for the
        destination's ``time`` seconds, checking for cancellation, and a
        ``transfer_errno`` on the destination fails it after the first
        second. A cancel is ``ECANCELED`` (or that ``transfer_errno``, when
        there is one). Then the stat cycle moves to
        "after", and with ``GFALT_CHECKSUM_TARGET`` the destination's
        ``checksum`` must match the source's (both modes) or the user's
        (``EIO``). An empty checksum on either side matches anything.
        """
        source, destination = transfer.source, transfer.destination
        mode = int(transfer.checksum_mode)
        user = transfer.user_checksum or ""
        source_checksum = ""
        if mode & 1:  # GFALT_CHECKSUM_SOURCE
            source_checksum = _value(source, "checksum", _URL_MAX)
            if not _checksums_match(user, source_checksum):
                raise GError("User and source checksums do not match", errno.EIO)
        seconds = self._duration(destination)
        transfer.event("TRANSFER:ENTER", f"Mock copy start, sleep {seconds}")
        transfer.event("TRANSFER:TYPE", "mock")
        seconds, error = _sleep_through(transfer, seconds, _int(destination, "transfer_errno"))
        transfer.event("TRANSFER:EXIT", f"Mock copy start, sleep {seconds}")
        if seconds < 0:
            raise error or GError("Transfer canceled", errno.ECANCELED)
        with self._lock:
            self._stage = _AFTER  # "jump over to the destination stat"
        if error is None and mode & 2:  # GFALT_CHECKSUM_TARGET
            target = _value(destination, "checksum", _URL_MAX)
            error = _target_mismatch(target, source_checksum if mode & 1 else None, user)
        if error is not None:
            raise error

    def _duration(self, destination: str) -> int:
        """How many seconds the copy lasts: ``time=``, else a random pick.

        Without ``time`` it is drawn from ``[MIN_TRANSFER_TIME,
        MAX_TRANSFER_TIME)`` (``[MOCK PLUGIN]``, default 10 and 100) when the
        minimum is the smaller, and is exactly the maximum when they are equal.
        """
        given = _value(destination, "time", _URL_MAX)
        if given:
            return _c_int(_atoll(given))
        high = int(self.options.integer(self.option_group, "MAX_TRANSFER_TIME", 100))
        low = int(self.options.integer(self.option_group, "MIN_TRANSFER_TIME", 10))
        if high == low:
            return high
        # rand() % (max - min) + min, with C's sign rule for the remainder
        return random.randrange(abs(high - low)) + low


def _sleep_through(transfer: Transfer, seconds: int, failure: int) -> tuple[int, GError | None]:
    """The copy's "run": ``seconds`` one at a time; the count left and any injected error.

    A cancel drops the count below zero (gfal2's cancel callback sets -10);
    a ``transfer_errno`` (``failure``) ends the run after the first second.
    """
    while seconds > 0:
        if _sleep_second(transfer):
            seconds = -10  # gfal2's cancel callback
        seconds -= 1
        if failure:
            return seconds, _fail(failure)
    return seconds, None


def _target_mismatch(target: str, source: str | None, user: str) -> GError | None:
    """The destination checksum check: against the source's (when checked) or the user's."""
    if source is not None:
        if not _checksums_match(source, target):
            return GError("Source and destination checksums do not match", errno.EIO)
    elif not _checksums_match(user, target):
        return GError("User and destination checksums do not match", errno.EIO)
    return None


def _sleep_second(transfer: Transfer) -> bool:
    """Sleep one second, waking early (and answering True) if the copy is cancelled.

    gfal2's mock copy ignores ``params.timeout``, so a timeout is not a reason
    to stop here.
    """
    deadline = time.monotonic() + _TICK
    while True:
        try:
            transfer.check()
        except GError as exc:
            if exc.code == errno.ECANCELED:
                return True
        left = deadline - time.monotonic()
        if left <= 0:
            return False
        time.sleep(min(0.05, left))
