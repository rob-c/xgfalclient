"""``gfal-copy``: one file, a chain of copies, a list of sources, or a whole tree.

The decisions are gfal2-util 1.9.1's (Apache-2.0, (c) CERN), reimplemented:

* ``src dst1 dst2...`` is a chain, ``src -> dst1 -> dst2``, each hop into
  ``dstN/<basename>`` when ``dstN`` is a directory;
* a directory source is copied recursively when the destination does not
  exist, and only with ``-r`` when it does (else ``Skipping``);
* with ``-r`` a failed file is reported as ``ERROR (errno): message`` and the
  copy goes on, unless ``--abort-on-failure``;
* ``--just-copy`` skips every check and preparation (``strict_copy``);
* ``-`` is standard output.

One thing is done differently: a copy onto a character device, FIFO or
socket (``-``, ``/dev/null``) is streamed here, through ``ctx.open``, rather
than handed to ``filecopy``, whose overwrite check would refuse the existing
"file" - or, with ``-f``, try to delete it.

Reading order: :meth:`_Copier.run` builds the list of ``(source,
destination)`` jobs, :meth:`_Copier.copy` decides what one job means
(file, directory, skip, refuse), and :meth:`_Copier.copy_file` builds the
``TransferParameters`` from the options and runs the copy with its progress
bar. Output lines (``Copying N bytes a => b``, ``Mkdir``, ``Skipping``,
``ERROR (n): ...``) are gfal2-util's and are parsed by scripts.
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import stat
import sys
from typing import IO, TYPE_CHECKING

from ..errors import GError, from_oserror
from ..events import GfaltEvent
from ..transfer import TransferParameters
from ..types import Stat
from . import _base as base
from ._base import Command, Spec, arg, out, output, surl

if TYPE_CHECKING:
    from ._progress import Progress

__all__ = ["SPECS", "STDOUT_URL"]

_log = logging.getLogger(__name__)

#: What ``-`` means as a destination.
STDOUT_URL = "file:///dev/stdout"
#: Bytes per read when streaming to a special file (see :meth:`_Copier.stream`).
CHUNK = 1 << 20

#: ``--copy-mode`` to ``(ENABLE_REMOTE_COPY, ENABLE_FALLBACK_TPC_COPY, DEFAULT_COPY_MODE)``;
#: ``streamed`` leaves the fallback setting alone.
_COPY_MODES = {
    "pull": (True, False, "3rd pull"),
    "push": (True, False, "3rd push"),
    "streamed": (False, None, "streamed"),
}


def _is_special(info: Stat) -> bool:
    """stdout, a pipe, ``/dev/null``: things that exist but are not overwritten."""
    mode = info.st_mode
    return stat.S_ISFIFO(mode) or stat.S_ISCHR(mode) or stat.S_ISSOCK(mode)


class _Copier:
    """One ``gfal-copy`` run over all its jobs.

    ``transferred`` holds the latest byte count the monitor callback (or
    the special-file stream) reported for the file being copied, for the
    machine-readable report; None until something was reported.
    """

    def __init__(self, cmd: Command) -> None:
        """Bind to the invocation (options and context); nothing is copied yet."""
        self.cmd = cmd
        self.params = cmd.params
        self.context = cmd.context
        self.transferred: int | None = None

    # -- the plan ------------------------------------------------------------------

    def run(self) -> int:
        """Build the jobs and run them in order; the command's status (1 for a usage error).

        A chain ``src dst1 dst2`` copies ``src`` to ``dst1`` and then the
        copy just made onwards: when ``dst1`` is a directory the next
        source is ``dst1/<basename>``, which is why each destination is
        stat-ed while planning (skipped with ``--just-copy``, which promises
        no checks). ``--from-file`` sources all go to the first destination.
        """
        jobs = self._plan()
        if jobs is None:
            return 1
        for source, destination in jobs:
            self._run_job(source, destination)
        return 0

    def _plan(self) -> list[tuple[str, str]] | None:
        """The ``(source, destination)`` jobs, or None after reporting a usage error."""
        params = self.params
        if params.from_file and params.src:
            _usage_error(
                "Use either --from-file or a positional source, not both",
                "Cannot combine '--from-file' with a source in the positional arguments\n",
            )
            return None
        if params.from_file:
            with open(params.from_file) as handle:
                sources = [line.strip() for line in handle]
            return [(source, params.dst[0]) for source in sources if source]
        if params.src:
            return self._chain(params.src)
        _usage_error("Provide a source URL or use --from-file", "Missing source\n")
        return None

    def _chain(self, source: str) -> list[tuple[str, str]]:
        """``src dst1 dst2...`` as hops, each from the copy the previous one made."""
        jobs: list[tuple[str, str]] = []
        for destination in self.params.dst:
            jobs.append((source, destination))
            if not self.params.just_copy and self._is_dir(destination):
                source = destination + "/" + os.path.basename(source)
            else:
                source = destination
        return jobs

    def _run_job(self, source: str, destination: str) -> None:
        """One planned job: straight to the copy with ``--just-copy``, else checked first."""
        if destination == "-":
            destination = STDOUT_URL
        if self.params.just_copy:
            self.copy_file(source, destination, 0, special=destination == STDOUT_URL)
        else:
            self.copy(source, destination)

    def _is_dir(self, url: str) -> bool:
        """Whether ``url`` is an existing directory; any failure to stat means no."""
        try:
            return self.context.stat(url).is_dir()
        except GError:
            return False

    def failure(self, message: str, code: int) -> None:
        """Fatal, unless this is a recursive copy that may carry on."""
        error = GError(message, code)
        output.error(error)
        if self.params.abort_on_failure or not self.params.recursive:
            raise error
        out(f"ERROR ({code}): {message}\n")

    # -- one item --------------------------------------------------------------------

    def _destination(self, url: str) -> tuple[bool, bool, bool]:
        """``(exists, is_dir, is_special)``.

        Only a local (``file:``) destination can be special: a remote
        storage never holds a device or FIFO worth writing into.
        """
        if url == STDOUT_URL:
            return True, False, True
        try:
            info = self.context.stat(url)
        except GError:
            return False, False, False
        return True, info.is_dir(), url.startswith("file:") and _is_special(info)

    def copy(self, source: str, destination: str) -> None:
        """One job, with gfal2-util's checks: overwrite, directory over file, recursion.

        Order matters and is gfal2-util's: an existing destination file is
        refused without ``-f`` before anything else (an LFC destination only
        warns, since copying there adds a replica); a directory source into
        a missing destination creates it and recurses even without ``-r``;
        into an existing directory it needs ``-r``. A file copied into a
        directory lands at ``dir/<basename>``.
        """
        output.identify("copy", source=source, target=destination)
        try:
            info = self.context.stat(source)
        except GError as exc:
            self.failure(f"Could not stat the source: {exc.user_message}", exc.code)
            return
        source_dir = info.is_dir()
        exists, dest_dir, special = self._destination(destination)
        if exists and not dest_dir and self._refuses_file(destination, source_dir, special):
            return
        if source_dir:
            self._copy_directory(source, destination, exists)
            return
        if dest_dir:
            destination = (destination if destination.endswith("/") else destination + "/") + (
                os.path.basename(source)
            )
        self.copy_file(source, destination, info.st_size, special=special)

    def _refuses_file(self, destination: str, source_dir: bool, special: bool) -> bool:
        """Whether the existing, non-directory ``destination`` stops the job (reported).

        Without ``-f`` an ordinary file is refused (an LFC destination only
        warns, since copying there adds a replica); a directory source is
        never copied over a file.
        """
        if not special and not self.params.force:
            if destination.startswith(("lfc://", "lfn://", "guid://")):
                _log.warning("Destination exists, but it is an LFC, so try to add a new replica")
            else:
                self.failure(
                    f"Destination {destination} exists and overwrite is not set", errno.EEXIST
                )
                return True
        if source_dir:
            self.failure("Can not copy a directory over a file", errno.EISDIR)
            return True
        return False

    def _copy_directory(self, source: str, destination: str, exists: bool) -> None:
        """A directory source: into a new directory always, an existing one with ``-r``."""
        if not exists:
            try:
                self.mkdir(destination)
            except GError as exc:
                self.failure(f"Could not create the directory: {exc.user_message}", exc.code)
                return
            self.copy_tree(source, destination)
        elif self.params.recursive:
            self.copy_tree(source, destination)
        else:
            output.record(status="skipped")
            out(f"Skipping {source}\n")

    def mkdir(self, url: str) -> None:
        """Print ``Mkdir <url>`` and ``mkdir -p`` it (under ``--dry-run``, only print)."""
        output.identify("mkdir", url=url)
        out(f"Mkdir {url}\n")
        if not self.params.dry_run:
            self.context.mkdir_rec(url, 0o755)
        output.record(status="planned" if self.params.dry_run else "succeeded")

    def copy_tree(self, source: str, destination: str) -> None:
        """Copy each entry of directory ``source`` into ``destination`` (via :meth:`copy`)."""
        names = self.context.listdir(source)
        source_base = source if source.endswith("/") else source + "/"
        dest_base = destination if destination.endswith("/") else destination + "/"
        for name in names:
            if name not in (".", ".."):
                self.copy(source_base + name, dest_base + name)

    # -- the copy itself ---------------------------------------------------------------

    def parameters(self, size: int) -> TransferParameters:
        """Fresh ``TransferParameters`` for one file, from the command-line options.

        Only options given are applied, so gfal2's defaults stand otherwise.
        ``-K ALG[:VALUE]`` with ``--checksum-mode`` becomes ``set_checksum``
        (whose validation can fail the copy, e.g. ``source`` mode without a
        value). ``--copy-mode`` is not a transfer parameter in gfal2: it
        changes the context's ``[HTTP PLUGIN]`` options, as gfal2-util does,
        and so applies to every later copy of this run too.
        """
        params = self.params
        transfer = self.context.transfer_parameters()
        self._set_values(transfer)
        self._set_switches(transfer)
        if params.checksum:
            from ..enums import checksum_mode

            parts = params.checksum.split(":")
            value = parts[1] if len(parts) > 1 else ""
            mode = checksum_mode.names[params.checksum_mode]
            transfer.set_checksum(mode, parts[0], value)
        if params.copy_mode:
            self._set_copy_mode(params.copy_mode)

        self._callbacks(transfer, size)
        return transfer

    def _set_values(self, transfer: TransferParameters) -> None:
        """The valued options: ``-n``, ``-T``, ``-s``, ``-S``, ``--tcp-buffersize``, ``--scitag``"""
        params = self.params
        if params.nbstreams:
            transfer.nbstreams = params.nbstreams
        if params.transfer_timeout:
            transfer.timeout = params.transfer_timeout
        if params.src_spacetoken:
            transfer.src_spacetoken = params.src_spacetoken
        if params.dst_spacetoken:
            transfer.dst_spacetoken = params.dst_spacetoken
        if params.tcp_buffersize:
            transfer.tcp_buffersize = params.tcp_buffersize
        if params.scitag is not None:
            transfer.scitag = params.scitag

    def _set_switches(self, transfer: TransferParameters) -> None:
        """The on/off options (``-p``, ``-f``, ``--just-copy``, ``--disable-cleanup``...)."""
        params = self.params
        if params.parent:
            transfer.create_parent = True
        if params.force:
            transfer.overwrite = True
        if params.just_copy:
            transfer.strict_copy = True
        if params.disable_cleanup:
            transfer.transfer_cleanup = False
        if params.no_delegation:
            transfer.proxy_delegation = False
        if params.evict:
            transfer.evict = True

    def _set_copy_mode(self, copy_mode: str) -> None:
        """``--copy-mode``: the context's ``[HTTP PLUGIN]`` options, as gfal2-util sets them."""
        remote, fallback, default = _COPY_MODES[copy_mode]
        self.context.set_opt_boolean("HTTP PLUGIN", "ENABLE_REMOTE_COPY", remote)
        if fallback is not None:
            self.context.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", fallback)
        self.context.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", default)

    def _callbacks(self, transfer: TransferParameters, size: int) -> None:
        """Attach the event and monitor callbacks: report records, ``-v`` lines, the bar.

        With ``-v`` every event is printed as ``event: <str(event)>`` and
        every progress report as ``monitor: ...``, gfal2-util's debug lines.
        """
        verbose = self.params.verbose
        report = output.current()

        def event_callback(event: GfaltEvent) -> None:
            """Record the event in the report and, with ``-v``, print it."""
            if report is not None:
                report.record(
                    "event",
                    **report.identity,
                    side=event.side,
                    timestamp_ms=event.timestamp,
                    domain=event.domain,
                    stage=event.stage,
                    description=event.description,
                )
            if verbose:
                out(f"event: {event}\n")

        def monitor_callback(
            src: str, dst: str, average: int, instant: int, transferred: int, elapsed: int
        ) -> None:
            """Record progress and redraw the bar.

            Six parameters because this is gfal2's ``monitor_callback``
            signature (source, destination, average and instantaneous
            rate, bytes, seconds); it cannot be grouped.
            """
            self.transferred = transferred
            if report is not None:
                report.record(
                    "progress",
                    source=src,
                    target=dst,
                    bytes_transferred=transferred,
                    seconds=elapsed,
                    average_bytes_per_second=average,
                    instantaneous_bytes_per_second=instant,
                )
            if verbose:
                out(f"monitor: {src} {dst} {average} {instant} {transferred} {elapsed}\n")
            bar = self.cmd.progress_bar
            if bar is not None:
                bar.update(transferred, size, average, elapsed)

        transfer.event_callback = event_callback
        transfer.monitor_callback = monitor_callback

    def copy_file(self, source: str, destination: str, size: int, *, special: bool) -> None:
        """Copy one file, with a progress bar on a terminal or a ``Copying ...`` line otherwise.

        ``-f`` retries once after removing the destination when the copy
        reports ``EEXIST``: some plugins (HTTP third-party copies) find the
        existing destination only at copy time. If the unlink then finds
        nothing (``ENOENT``) the ``EEXIST`` was about something else and is
        reported as it was. Failures go through :meth:`failure`.
        """
        output.identify("copy", source=source, target=destination)
        self.transferred = None
        transfer = self.parameters(size)
        params = self.params
        bar = self._progress(source, destination, size)
        self.cmd.progress_bar = bar
        try:
            if not params.dry_run:
                if special:
                    self.stream(source, destination)
                else:
                    self.context.filecopy(transfer, source, destination)
            _stop(bar, True)
        except GError as exc:
            _stop(bar, False)
            if exc.code == errno.EEXIST and params.force and self._unlinked(destination):
                self.copy_file(source, destination, size, special=special)
                return
            self.failure(exc.user_message, exc.code)
            return
        output.record(
            status="planned" if params.dry_run else "succeeded",
            expected_bytes=None if params.just_copy else size,
            bytes_transferred=0 if params.dry_run else self.transferred,
        )

    def _progress(self, source: str, destination: str, size: int) -> Progress | None:
        """A started progress bar on a terminal; otherwise print ``Copying ...`` and None."""
        params = self.params
        if not params.dry_run and not params.verbose and base.stdout_isatty():
            from ._progress import Progress

            bar = Progress(f"Copying {source}")
            bar.update(total_size=size)
            bar.start()
            return bar
        out(f"Copying {size} bytes {source} => {destination}\n")
        return None

    def _unlinked(self, destination: str) -> bool:
        """``-f``'s retry: remove ``destination``; False if nothing was there (``ENOENT``).

        Nothing there means the ``EEXIST`` was not the destination's (a 409
        for a missing parent): it is reported, not the unlink's ``ENOENT``.
        gfal2 numbers that 409 with a stale errno, so seldom gets here.
        """
        try:
            self.context.unlink(destination)
        except GError as gone:
            if gone.code != errno.ENOENT:
                raise
            return False
        return True

    def stream(self, source: str, destination: str) -> None:
        """Copy onto a special file: read through the context, write to the device."""
        with contextlib.ExitStack() as stack:
            reader = self.context.open(source, "r")
            stack.callback(reader.close)
            sink: IO[bytes]
            if destination == STDOUT_URL:
                sys.stdout.flush()
                sink = sys.stdout.buffer
            else:
                try:
                    sink = stack.enter_context(open(destination[len("file://") :], "wb"))
                except OSError as exc:
                    raise from_oserror(exc) from exc
            while True:
                data = reader.read_bytes(CHUNK)
                if not data:
                    break
                sink.write(data)
                sink.flush()
                self.transferred = (self.transferred or 0) + len(data)


def _usage_error(error: str, message: str) -> None:
    """Report a usage error: ``error`` in the report (code 1), ``message`` on stderr."""
    output.error(ValueError(error), code=1)
    output.message(message, stderr=True)


def _stop(bar: Progress | None, ok: bool) -> None:
    """Stop the progress bar, if there is one, and end its line."""
    if bar is not None:
        bar.stop(ok)
        out("\n")


def copy(cmd: Command) -> int:
    """``gfal-copy``: the command function; see :class:`_Copier`."""
    return _Copier(cmd).run()


SPECS = {
    "copy": Spec(
        "copy",
        "Copy a file or set of files",
        [
            arg(
                "-f",
                "--force",
                action="store_true",
                help="if destination file(s) cannot be overwritten, delete it and try again",
            ),
            arg(
                "-p",
                "--parent",
                action="store_true",
                help="if the destination directory does not exist, create it",
            ),
            arg(
                "-n",
                "--nbstreams",
                type=int,
                default=None,
                help="specify the maximum number of parallel streams to use for the copy",
            ),
            arg("--tcp-buffersize", type=int, default=None, help="specify the TCP buffersize"),
            arg(
                "-s",
                "--src-spacetoken",
                type=str,
                default="",
                help="source spacetoken to use for the transfer",
            ),
            arg(
                "-S",
                "--dst-spacetoken",
                type=str,
                default="",
                help="destination spacetoken to use for the transfer",
            ),
            arg(
                "-T",
                "--transfer-timeout",
                type=int,
                default=None,
                help="global timeout for the transfer operation",
            ),
            arg(
                "-K",
                "--checksum",
                type=str,
                default=None,
                help="checksum algorithm to use, or algorithm:value",
            ),
            arg(
                "--checksum-mode",
                type=str,
                default="both",
                choices=["source", "target", "both"],
                help="checksum validation mode",
            ),
            arg("--from-file", type=str, default=None, help="read sources from a file"),
            arg(
                "--copy-mode",
                type=str,
                default="",
                choices=["pull", "push", "streamed"],
                help="copy mode. N.B. supported only for HTTP/DAV to HTTP/DAV transfers, if not "
                "specified the pull mode will be executed first with fallbacks to other modes in "
                "case of errors",
            ),
            arg(
                "--just-copy",
                action="store_true",
                help="just do the copy and skip any preparation (i.e. checksum, overwrite, etc.)",
            ),
            arg(
                "--disable-cleanup",
                action="store_true",
                help="disable the copy clean-up happening when a transfer fails",
            ),
            arg("--no-delegation", action="store_true", help="disable TPC with proxy delegation"),
            arg(
                "--evict",
                action="store_true",
                help="evict source file from disk buffer when the transfer is finished",
            ),
            arg(
                "--scitag",
                type=int,
                default=None,
                help="SciTag transfer flow identifier (number in [65-65535] range) "
                "(available only for HTTP-TPC)",
            ),
            arg("-r", "--recursive", action="store_true", help="copy directories recursively"),
            arg(
                "--abort-on-failure",
                action="store_true",
                help="abort the whole copy as soon as one failure is encountered",
            ),
            arg(
                "--dry-run",
                action="store_true",
                help="do not perform any action, just print what would be done",
            ),
            arg("src", type=surl, nargs="?", help="source file"),
            arg(
                "dst",
                action="store",
                nargs="+",
                type=surl,
                help="destination file(s). If more than one is given, they will be chained "
                "copy: src -> dst1, dst1->dst2, ...",
            ),
        ],
        copy,
    ),
}
