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
"""

from __future__ import annotations

import errno
import logging
import os
import stat
import sys
from typing import IO

from ..errors import GError, from_oserror
from ..events import GfaltEvent
from ..transfer import TransferParameters
from ..types import Stat
from . import _base as base
from ._base import Command, Spec, arg, out, surl

__all__ = ["SPECS", "STDOUT_URL"]

_log = logging.getLogger(__name__)

#: What ``-`` means as a destination.
STDOUT_URL = "file:///dev/stdout"
#: Bytes per read when streaming to a special file.
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
    def __init__(self, cmd: Command) -> None:
        self.cmd = cmd
        self.params = cmd.params
        self.context = cmd.context

    # -- the plan ------------------------------------------------------------------

    def run(self) -> int:
        params = self.params
        if params.from_file and params.src:
            sys.stderr.write(
                "Cannot combine '--from-file' with a source in the positional arguments\n"
            )
            return 1
        jobs: list[tuple[str, str]] = []
        if params.from_file:
            with open(params.from_file) as handle:
                sources = [line.strip() for line in handle]
            jobs = [(source, params.dst[0]) for source in sources if source]
        elif params.src:
            source = params.src
            for destination in params.dst:
                jobs.append((source, destination))
                if not params.just_copy and self._is_dir(destination):
                    source = destination + "/" + os.path.basename(source)
                else:
                    source = destination
        else:
            sys.stderr.write("Missing source\n")
            return 1
        for source, destination in jobs:
            if destination == "-":
                destination = STDOUT_URL
            if params.just_copy:
                self.copy_file(source, destination, 0, special=destination == STDOUT_URL)
            else:
                self.copy(source, destination)
        return 0

    def _is_dir(self, url: str) -> bool:
        try:
            return self.context.stat(url).is_dir()
        except GError:
            return False

    def failure(self, message: str, code: int) -> None:
        """Fatal, unless this is a recursive copy that may carry on."""
        if self.params.abort_on_failure or not self.params.recursive:
            raise GError(message, code)
        out(f"ERROR ({code}): {message}\n")

    # -- one item --------------------------------------------------------------------

    def _destination(self, url: str) -> tuple[bool, bool, bool]:
        """``(exists, is_dir, is_special)``."""
        if url == STDOUT_URL:
            return True, False, True
        try:
            info = self.context.stat(url)
        except GError:
            return False, False, False
        return True, info.is_dir(), url.startswith("file:") and _is_special(info)

    def copy(self, source: str, destination: str) -> None:
        try:
            info = self.context.stat(source)
        except GError as exc:
            self.failure(f"Could not stat the source: {exc.message}", exc.code)
            return
        source_dir = info.is_dir()
        exists, dest_dir, special = self._destination(destination)
        if exists and not dest_dir and not special and not self.params.force:
            if destination.startswith(("lfc://", "lfn://", "guid://")):
                _log.warning("Destination exists, but it is an LFC, so try to add a new replica")
            else:
                self.failure(
                    f"Destination {destination} exists and overwrite is not set", errno.EEXIST
                )
                return
        if exists and not dest_dir and source_dir:
            self.failure("Can not copy a directory over a file", errno.EISDIR)
            return
        if source_dir and not exists:
            try:
                self.mkdir(destination)
            except GError as exc:
                self.failure(f"Could not create the directory: {exc.message}", exc.code)
                return
            self.copy_tree(source, destination)
            return
        if source_dir:  # onto an existing directory
            if self.params.recursive:
                self.copy_tree(source, destination)
            else:
                out(f"Skipping {source}\n")
            return
        if dest_dir:
            destination = (destination if destination.endswith("/") else destination + "/") + (
                os.path.basename(source)
            )
        self.copy_file(source, destination, info.st_size, special=special)

    def mkdir(self, url: str) -> None:
        out(f"Mkdir {url}\n")
        if not self.params.dry_run:
            self.context.mkdir_rec(url, 0o755)

    def copy_tree(self, source: str, destination: str) -> None:
        names = self.context.listdir(source)
        source_base = source if source.endswith("/") else source + "/"
        dest_base = destination if destination.endswith("/") else destination + "/"
        for name in names:
            if name not in (".", ".."):
                self.copy(source_base + name, dest_base + name)

    # -- the copy itself ---------------------------------------------------------------

    def parameters(self, size: int) -> TransferParameters:
        params = self.params
        transfer = self.context.transfer_parameters()
        if params.nbstreams:
            transfer.nbstreams = params.nbstreams
        if params.transfer_timeout:
            transfer.timeout = params.transfer_timeout
        if params.src_spacetoken:
            transfer.src_spacetoken = params.src_spacetoken
        if params.dst_spacetoken:
            transfer.dst_spacetoken = params.dst_spacetoken
        if params.parent:
            transfer.create_parent = True
        if params.tcp_buffersize:
            transfer.tcp_buffersize = params.tcp_buffersize
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
        if params.scitag is not None:
            transfer.scitag = params.scitag
        if params.checksum:
            from ..enums import checksum_mode

            parts = params.checksum.split(":")
            value = parts[1] if len(parts) > 1 else ""
            mode = checksum_mode.names[params.checksum_mode]
            transfer.set_checksum(mode, parts[0], value)
        if params.copy_mode:
            remote, fallback, default = _COPY_MODES[params.copy_mode]
            self.context.set_opt_boolean("HTTP PLUGIN", "ENABLE_REMOTE_COPY", remote)
            if fallback is not None:
                self.context.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", fallback)
            self.context.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", default)

        verbose = params.verbose

        def event_callback(event: GfaltEvent) -> None:
            if verbose:
                out(f"event: {event}\n")

        def monitor_callback(
            src: str, dst: str, average: int, instant: int, transferred: int, elapsed: int
        ) -> None:
            if verbose:
                out(f"monitor: {src} {dst} {average} {instant} {transferred} {elapsed}\n")
            bar = self.cmd.progress_bar
            if bar is not None:
                bar.update(transferred, size, average, elapsed)

        transfer.event_callback = event_callback
        transfer.monitor_callback = monitor_callback
        return transfer

    def copy_file(self, source: str, destination: str, size: int, *, special: bool) -> None:
        transfer = self.parameters(size)
        params = self.params
        bar = None
        if not params.dry_run and not params.verbose and base.stdout_isatty():
            from ._progress import Progress

            bar = Progress(f"Copying {source}")
            bar.update(total_size=size)
            bar.start()
        else:
            out(f"Copying {size} bytes {source} => {destination}\n")
        self.cmd.progress_bar = bar
        try:
            if not params.dry_run:
                if special:
                    self.stream(source, destination)
                else:
                    self.context.filecopy(transfer, source, destination)
            if bar is not None:
                bar.stop(True)
                out("\n")
        except GError as exc:
            if bar is not None:
                bar.stop(False)
                out("\n")
            if exc.code == errno.EEXIST and params.force:
                try:
                    self.context.unlink(destination)
                except GError as gone:
                    # Nothing there, so the EEXIST was not the destination's (a 409
                    # for a missing parent): report it, not the unlink's ENOENT.
                    # gfal2 numbers that 409 with a stale errno, so seldom gets here.
                    if gone.code != errno.ENOENT:
                        raise
                else:
                    self.copy_file(source, destination, size, special=special)
                    return
            self.failure(exc.message, exc.code)

    def stream(self, source: str, destination: str) -> None:
        """Copy onto a special file: read through the context, write to the device."""
        reader = self.context.open(source, "r")
        try:
            sink: IO[bytes]
            if destination == STDOUT_URL:
                sys.stdout.flush()
                sink = sys.stdout.buffer
            else:
                try:
                    sink = open(destination[len("file://") :], "wb")  # noqa: SIM115
                except OSError as exc:
                    raise from_oserror(exc) from exc
            try:
                while True:
                    data = reader.read_bytes(CHUNK)
                    if not data:
                        break
                    sink.write(data)
                    sink.flush()
            finally:
                if destination != STDOUT_URL:
                    sink.close()
        finally:
            reader.close()


def copy(cmd: Command) -> int:
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
