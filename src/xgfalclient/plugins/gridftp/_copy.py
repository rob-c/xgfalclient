"""GridFTP copies: ``file://`` <-> ``gsiftp://``, third-party, and bulk.

Part of the :mod:`xgfalclient.plugins.gridftp.plugin` split (that module's
docstring describes gfal2's copy sequences and where this differs).
:class:`_CopyMixin` holds the plugin's ``copy_check``/``copy``/``copy_bulk``
and everything between them: the core's checks around a local copy with this
plugin's parallel data movers (``_local_copy``, ``_download``, ``_upload``),
gfal2's ``GridFTPModule::filecopy`` for a third-party copy (checksums,
``OVERWRITE``/``DESTINATION EXISTS``, parent creation, the UDT retry,
clean-up), and the two engines it drives: :class:`_ThirdParty`, which sets
up one server-to-server move and watches its performance markers, and
:class:`_Bulk`, gfal2's ``PREPARE``/transfer/``CLOSE`` bulk copy.

A test that wants a faster poll patches ``_ThirdParty.POLL`` on the class,
which is the same object through the facade. No module-level name here is
looked up through the facade: nothing patches one.

Who moves the bytes. In a local copy this client is one end: it reads or
writes the local file with ``pread``/``pwrite`` from one thread per data
connection, so ``MODE E`` blocks can land in any order. In a third-party
copy neither end is local: the client only steers two control channels
(the destination listens, the source connects and sends, GFD.20's
"third-party transfer") and learns about progress from the destination's
``112`` performance markers.

Errors and clean-up, which the tests pin message by message: a
:class:`_TransferError` is reported as is and never triggers clean-up (the
destination was not, or must not be, touched); any other failure of the move
removes the destination unless it was "exists" (``EEXIST``: not ours), and
its message gains gfal2's ``TRANSFER`` prefix.
"""

from __future__ import annotations

import errno
import os
import stat as _stat
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from ... import events as ev
from ...checksum import checksums_match
from ...errors import GError
from ...types import Stat
from ...url import parse, scheme_of
from ..file import local_path
from ._base import (
    _NO_UDT,
    _SCHEMES,
    _SOURCE,
    _TARGET,
    BULK_DOMAIN,
    GROUP,
    _GridFTPBase,
    _pair_text,
    _path,
    _resolve_dns,
    _Session,
    lookup_host,
)
from .control import Control
from .data import (
    ConnSetup,
    DataConn,
    DataTransfer,
    EodCounter,
    Feed,
    Ranges,
    Reader,
    passive,
    perf_bytes,
    positional_reader,
    recv_blocks,
    recv_stream,
    routable,
    send_blocks,
    send_stream,
)
from .protocol import Reply, format_eprt, format_port, parse_pasv, passive_address, reply_error


class _TransferError(GError):
    """gfal2's ``TransferException``: reported as is, never cleaned up after.

    ``detail`` is the bare text; the message carries gfal2's ``SIDE NOTE``
    prefix.
    """

    def __init__(self, side: str, note: str, detail: str, code: int) -> None:
        """``side`` and ``note`` are gfal2's labels, e.g. ``DESTINATION`` and ``EXISTS``."""
        super().__init__(f"{side} {note} {detail}", code)
        self.detail = detail


def _pwrite(fd: int, view: memoryview, offset: int) -> None:
    """Write all of ``view`` at ``offset``, looping over short writes.

    Positional, so the ``MODE E`` receiver threads can share one descriptor
    without a lock. A write that makes no progress is ``EIO`` rather than a
    spin (it should not happen on a regular file).
    """
    while view:
        written = os.pwrite(fd, view, offset)
        if written <= 0:
            raise OSError(errno.EIO, "local pwrite made no progress")
        view = view[written:]
        offset += written


def _pread(fd: int) -> Reader:
    """A :data:`~.data.Reader` over ``fd``: :func:`~.data.positional_reader`."""
    return positional_reader(fd)


def _compare(expected: int, actual: int) -> None:
    """``EIO`` with gfal2's message unless the two sizes agree."""
    if expected != actual:
        raise GError(
            f"Source and destination file sizes do not match: {expected} != {actual}", errno.EIO
        )


@dataclass(frozen=True, slots=True)
class _Plan:
    """How :class:`_ThirdParty` runs one move; settled before it starts."""

    #: ``RD_NB_STREAM`` or ``nbstreams``; 0 or 1 sends no ``OPTS RETR``.
    streams: int
    #: ``ftp://`` at either end: ``MODE S``, one connection, no markers.
    plain: bool
    #: Ask both ends for ``SITE SETNETSTACK udt`` first.
    udt: bool


class _CopyMixin(_GridFTPBase):
    """``copy``, ``copy_check`` and ``copy_bulk``: see the module docstring."""

    def copy_check(self, source: str, destination: str) -> bool:
        """Claim GridFTP pairs (any mix of ``gsiftp``/``ftp``) and ``file://`` with one.

        The ``file://`` case is deliberately wider than gfal2 (see the plugin
        docstring): it brings this plugin's parallel movers to local copies.
        """
        ends = (scheme_of(source), scheme_of(destination))
        remote = [end in _SCHEMES for end in ends]
        return all(remote) or (any(remote) and "file" in ends)

    def _streams(self, transfer: Any) -> int:
        """``RD_NB_STREAM`` when set, else ``nbstreams`` (gfal2's precedence).

        0 is gfal2's default: a local copy then moves in ``MODE S`` as gfal2
        would, and a third-party copy sends no ``OPTS RETR`` (so the servers'
        own default parallelism applies).
        """
        configured = self.options.integer(GROUP, "RD_NB_STREAM", 0)
        return int(configured or transfer.params.nbstreams or 0)

    def copy(self, transfer: Any) -> None:
        """One copy: a local end goes to :meth:`_local_copy`, else gfal2's ``filecopy``.

        ``transfer`` is the core's :class:`~xgfalclient.transfer.Transfer`
        (parameters, events, progress, ``check()`` for cancellation).
        """
        if "file" in (scheme_of(transfer.source), scheme_of(transfer.destination)):
            self._local_copy(transfer)
        else:
            self._filecopy(transfer)

    # -- file:// <-> gridftp: the core's checks, this plugin's data movers --------------

    def _local_copy(self, transfer: Any) -> None:
        """``file://`` <-> GridFTP: the core's checks around this plugin's data movers.

        Because the plugin declares ``copy_manages_destination`` and
        ``copy_manages_checksums``, the core skips its own checks for every
        copy this plugin runs; for a local end they are wanted, so they are
        called here, in the core's order. A strict copy skips them, as in the
        core. On failure the destination is removed here (when this copy
        owns it) and ownership is dropped so the core does not try again.
        The ``TRANSFER:ENTER``/``EXIT`` events are sent here too, since the
        plugin declares ``narrates_transfer``.
        """
        from ... import transfer as core

        strict = transfer.params.strict_copy
        algorithm = transfer.checksum_algorithm or self.checksum_type()
        if not strict:
            core._verify_source(transfer, algorithm)
            core._prepare_destination(transfer)
        transfer.event(ev.TRANSFER_ENTER, transfer.pair)
        transfer.owns_destination = not strict
        try:
            if scheme_of(transfer.source) == "file":
                self._upload(transfer)
            else:
                self._download(transfer)
            transfer.event(ev.TRANSFER_EXIT, transfer.pair)
            if not strict:
                core._verify_destination(transfer, algorithm)
        except Exception:
            core._cleanup(transfer, True)
            transfer.owns_destination = False  # cleaned: the core must not again
            raise

    def _move(
        self,
        session: _Session,
        transfer: Any,
        command: str,
        streams: int,
        worker: Callable[[DataConn, int], object],
        **run: Any,
    ) -> None:
        """Run ``command`` with ``streams`` data connections, each moved by ``worker``.

        ``transfer.check`` is polled throughout, so ``cancel()`` and the copy
        timeout stop the move; ``run`` passes :meth:`DataTransfer.run`'s
        keywords (``active``, ``done``, ``getput``) through.
        """
        session.control.setting("TYPE", "I")
        DataTransfer(
            session.control,
            streams=streams,
            worker=worker,
            check=transfer.check,
            setup=ConnSetup(session.profile.security, session.profile.timeout),
        ).run(command, self._data_options(), **run)

    def _download(self, transfer: Any) -> None:
        """GridFTP to ``file://``: ``RETR`` into a local file truncated first.

        With streams, ``MODE E`` and ``OPTS RETR Parallelism=n,n,n;``
        (GFD.20: starting, minimum and maximum parallelism). The server is
        the sender, and in ``MODE E`` the sender connects, so the client
        listens (``PORT``); the server may open fewer connections than
        asked, so completion is the :class:`~.data.EodCounter`, not every
        thread finishing. Without streams, ``MODE S`` exactly as gfal2 would
        (``GET`` when GridFTP v2 is on). The local size is compared with
        the source's afterwards: ``MODE S`` cannot tell a short file from a
        dropped connection.
        """
        transfer.event(ev.TRANSFER_TYPE, "streamed")
        source = parse(transfer.source)
        path = _path(source)
        streams = self._streams(transfer)
        size = self._buffer_size()
        with self._session(source) as session:
            control = session.control
            info = self._stat(control, path)
            if info.is_dir():
                raise GError(f"{transfer.source} is a directory", errno.EISDIR)
            transfer.source_size = info.st_size
            # Opened only once the source is known to be a file, so a failed
            # stat leaves no empty destination behind.
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(local_path(transfer.destination), flags, 0o644)
            try:

                def write(view: memoryview, offset: int) -> None:
                    """Land a received block at its offset in the local file."""
                    _pwrite(fd, view, offset)

                if streams > 0:
                    control.setting("MODE", "E")
                    control.setting("OPTS RETR", f"Parallelism={streams},{streams},{streams};")
                    eods = EodCounter()
                    self._move(
                        session,
                        transfer,
                        f"RETR {path}",
                        streams,
                        lambda conn, _: recv_blocks(conn, write, size, transfer.add, eods),
                        active=True,
                        done=eods.done,
                    )
                else:
                    control.setting("MODE", "S")
                    getput = self._getput(control)
                    self._move(
                        session,
                        transfer,
                        f"GET path={path};pasv;" if getput else f"RETR {path}",
                        1,
                        lambda conn, _: recv_stream(conn, write, size, transfer.add),
                        getput=getput,
                    )
                received = os.fstat(fd).st_size
            finally:
                os.close(fd)
        _compare(info.st_size, received)
        transfer.progress(received, force=True)

    def _upload(self, transfer: Any) -> None:
        """``file://`` to GridFTP: ``STOR`` (or ``PUT``) from a local file.

        Here the client is the sender, so in ``MODE E`` it connects
        (passive), and the streams share one :class:`~.data.Ranges` of the
        file; stream 0 carries the ``EOF`` block naming how many ``EOD``\\ s
        the server must see. ``ALLO`` announces the size first (a refusal is
        tolerated). A source that cannot be opened keeps its ``errno``.
        """
        transfer.event(ev.TRANSFER_TYPE, "streamed")
        target = parse(transfer.destination)
        path = _path(target)
        streams = self._streams(transfer)
        size = self._buffer_size()
        try:
            fd = os.open(local_path(transfer.source), os.O_RDONLY)
        except OSError as exc:
            raise GError(f"Could not open source: {exc.strerror}", exc.errno or errno.EIO) from exc
        try:
            info = os.fstat(fd)
            if _stat.S_ISDIR(info.st_mode):
                raise GError(f"{transfer.source} is a directory", errno.EISDIR)
            transfer.source_size = info.st_size
            read = _pread(fd)
            with self._session(target) as session:
                control = session.control
                getput = False
                if streams > 0:
                    control.setting("MODE", "E")
                    ranges = Ranges(0, info.st_size, size)
                    feed = Feed(read, size, transfer.add)

                    def worker(conn: DataConn, index: int) -> None:
                        """Send this stream's share; stream 0 also sends the EOF block."""
                        send_blocks(conn, feed, ranges, streams if index == 0 else 0)

                else:
                    control.setting("MODE", "S")
                    getput = self._getput(control)
                    feed = Feed(read, size, transfer.add)

                    def worker(conn: DataConn, index: int) -> None:
                        """Send the whole file down the one ``MODE S`` connection."""
                        send_stream(conn, feed)

                control.command(f"ALLO {info.st_size}", ok=(2, 4, 5))
                # GridFTP v2 PUT is for MODE S only; MODE E stays on STOR.
                command = f"PUT path={path};pasv;" if getput else f"STOR {path}"
                self._move(session, transfer, command, max(streams, 1), worker, getput=getput)
        finally:
            os.close(fd)
        transfer.progress(info.st_size, force=True)

    # -- gridftp <-> gridftp: gfal2's GridFTPModule::filecopy ----------------------------

    def _copy_checksum(self, url: str, algorithm: str) -> str:
        """The whole file's checksum by ``CKSM`` (offset 0, length "to the end")."""
        return self.checksum(url, algorithm, 0, 0)

    def _filecopy(self, transfer: Any) -> None:
        """gfal2's ``GridFTPModule::filecopy``: a third-party copy and its checks.

        In order: ``RESOLVE_DNS`` (both URLs rewritten to a resolved name),
        the source checksum (unless ``SKIP_SOURCE_CHECKSUM``) compared with
        any user checksum, ``TRANSFER:ENTER``/``TYPE``, the move with its
        destination preparation (:meth:`_copy_internal`), ``TRANSFER:EXIT``,
        then the destination checksum compared with the source's (or the
        user's when the source was not checked). A strict copy checks
        nothing. Checksum mismatches are :class:`_TransferError`\\ s; a
        destination mismatch also removes the destination (more than gfal2
        does, see :meth:`_clean_after_mismatch`).
        """
        source, target = transfer.source, transfer.destination
        ipv6 = self.options.boolean(GROUP, "IPV6", False)
        # The rewritten URLs are used for everything below, events included,
        # but the core's transfer keeps the originals.
        if self.options.boolean("CORE", "RESOLVE_DNS", False):
            source = _resolve_dns(source, "Resolving source", self.log)
            target = _resolve_dns(target, "Resolving destination", self.log)
        mode = self._checksum_mode(transfer)
        algorithm = transfer.checksum_algorithm or self.checksum_type()
        source_sum = ""
        if mode & _SOURCE:
            source_sum = self._check_source(transfer, source, algorithm)
        text = _pair_text(source, target, ipv6)
        transfer.event(ev.TRANSFER_ENTER, text)
        transfer.event(ev.TRANSFER_TYPE, "3rd push")
        self._push(transfer, source, target)
        transfer.event(ev.TRANSFER_EXIT, text)
        if mode & _TARGET:
            self._check_target(transfer, target, algorithm, source_sum if mode & _SOURCE else None)

    def _checksum_mode(self, transfer: Any) -> int:
        """The checksum mode bits this copy honours.

        A strict copy checks nothing, whatever mode was asked for, and
        ``SKIP_SOURCE_CHECKSUM`` drops the source's check.
        """
        mode = 0 if transfer.params.strict_copy else int(transfer.checksum_mode)
        if self.options.boolean(GROUP, "SKIP_SOURCE_CHECKSUM", False):
            mode &= ~_SOURCE
        return mode

    def _check_source(self, transfer: Any, source: str, algorithm: str) -> str:
        """The source's checksum, with its events; it must match a user checksum given."""
        user = transfer.user_checksum
        transfer.event(ev.CHECKSUM_ENTER, algorithm, ev.SOURCE)
        source_sum = self._copy_checksum(source, algorithm)
        transfer.event(ev.CHECKSUM_EXIT, f"{algorithm}={source_sum}", ev.SOURCE)
        if user and not checksums_match(user, source_sum):
            raise _TransferError(
                "TRANSFER",
                "CHECKSUM MISMATCH",
                f"USER_DEFINE and SRC checksums are different. {user} != {source_sum}",
                errno.EIO,
            )
        return source_sum

    def _push(self, transfer: Any, source: str, target: str) -> None:
        """The move itself; a failure other than ``EEXIST`` removes the destination."""
        try:
            self._copy_internal(transfer, source, target)
        except _TransferError:
            raise
        except GError as exc:
            # EEXIST: the server refused to replace what is there, which is
            # not this copy's to remove.
            if exc.code != errno.EEXIST:
                self._clean(target)
            raise GError(f"TRANSFER  {exc.message}", exc.code) from exc

    def _check_target(
        self, transfer: Any, target: str, algorithm: str, source_sum: str | None
    ) -> None:
        """Compare the destination's checksum with the source's, or else the user's.

        ``source_sum`` is None when the source was not checked. A mismatch
        removes the destination (:meth:`_clean_after_mismatch`).
        """
        user = transfer.user_checksum
        transfer.event(ev.CHECKSUM_ENTER, algorithm, ev.DESTINATION)
        target_sum = self._copy_checksum(target, algorithm)
        # Unlike the source's, gfal2's destination event names only the
        # algorithm, not the value.
        transfer.event(ev.CHECKSUM_EXIT, algorithm, ev.DESTINATION)
        if source_sum is not None:
            good = checksums_match(source_sum, target_sum)
            detail = (
                "SRC and DST checksum are different. "
                f"Source: {source_sum} Destination: {target_sum}"
            )
        else:
            good = checksums_match(user, target_sum)
            detail = f"USER_DEFINE and DST checksums are different. {user} != {target_sum}"
        if not good:
            self._clean_after_mismatch(transfer, target)
            raise _TransferError("TRANSFER", "CHECKSUM MISMATCH", detail, errno.EIO)

    def _clean(self, url: str) -> None:
        """gfal2's ``autoCleanFileCopy``: remove a failed destination, quietly.

        Exempt from ``cancel()``'s abort, so a cancelled copy still removes
        what it wrote. A failed removal is only logged: the copy's own error
        is the one reported.
        """
        self.log.info("\t\tError in transfer, clean destination file %s ", url)
        try:
            with self.context.abort_exempt():  # a cancel()'s drain must not stop it
                self.unlink(url)
        except GError:
            self.log.debug("\t\tFailure in cleaning ...")

    def _clean_after_mismatch(self, transfer: Any, url: str) -> None:
        """Deliberately more than gfal2: a copy that fails its checksum is removed.

        Only with ``transfer_cleanup`` (the default). The ``CLEANUP`` event
        carries ``0`` when the file is gone and the removal's ``errno`` when
        it is not, as the core's clean-up narrates its own.
        """
        if not transfer.params.transfer_cleanup:
            return
        try:
            self.unlink(url)
            code = 0
        except GError as exc:
            # Already gone counts as cleaned, as gfal2's plugins report it.
            code = 0 if exc.code == errno.ENOENT else exc.code
        transfer.event(ev.CLEANUP, str(code), ev.DESTINATION)

    def _delete_existing(self, transfer: Any, url: str) -> bool:
        """``OVERWRITE`` an existing destination, or refuse it; True if deleted.

        Without ``overwrite`` an existing destination is gfal2's ``DESTINATION
        EXISTS`` (``EEXIST``). A destination that is not there is fine; any
        other stat error propagates.
        """
        if not self._exists(url):
            return False
        if not transfer.params.overwrite:
            raise _TransferError(
                "DESTINATION", "EXISTS", f" Destination already exist {url}, Cancel", errno.EEXIST
            )
        self.unlink(url)
        transfer.event(ev.OVERWRITE, f"Deleted {url}", ev.DESTINATION)
        return True

    def _create_parent(self, transfer: Any, url: str) -> None:
        """With ``create_parent``, make the destination's directory (recursively) if missing.

        A parent that exists but is a file is gfal2's ``ENOTDIR``; any stat
        error other than ``ENOENT`` propagates. ``mkdir_rec`` goes through
        the context, so it works for whichever plugin owns the URL.
        """
        if not transfer.params.create_parent:
            return
        parent = url.rstrip("/").rpartition("/")[0]
        try:
            info = self.stat(parent)
        except GError as exc:
            if exc.code != errno.ENOENT:
                raise
        else:
            if not info.is_dir():
                raise _TransferError(
                    "DESTINATION",
                    "",
                    "The parent of the destination file exists, but it is not a directory",
                    errno.ENOTDIR,
                )
            return
        self.context.mkdir_rec(parent, 0o755)

    def _copy_internal(self, transfer: Any, source: str, target: str) -> None:
        """Prepare the destination, then move, retrying once without UDT if it is refused.

        A destination just deleted by ``OVERWRITE`` had a parent, so only a
        missing one is created. ``ENABLE_UDT`` asks both servers for the UDT
        network stack; a server whose UDT driver is not whitelisted fails
        with :data:`~._base._NO_UDT` and the move is retried over TCP, with
        gfal2's events. Any other failure is not retried.
        """
        if not transfer.params.strict_copy and not self._delete_existing(transfer, target):
            self._create_parent(transfer, target)
        udt = self.options.boolean(GROUP, "ENABLE_UDT", False)
        if udt:
            self.log.info("Trying UDT transfer")
            transfer.event("UDT:ENABLE", "Trying UDT")
        try:
            self._third_party(transfer, source, target, udt)
        except GError as exc:
            if not udt or _NO_UDT not in exc.message:
                raise
            self.log.warning("UDT transfer failed! Disabling and retrying...")
            transfer.event("UDT:DISABLE", f"UDT failed. Falling back to default mode: {exc}")
            self._third_party(transfer, source, target, False)

    def _third_party(
        self, transfer: Any, source_url: str, target_url: str, udt: bool, compare: bool = True
    ) -> None:
        """Move the bytes; with ``compare``, check the sizes (bulk copies do it at CLOSE).

        One session to each end, held for the whole move. The source's size
        (``None`` when it cannot be had) feeds ``ALLO``, the final progress
        report and the size check; the stream count is
        :meth:`_streams` for ``transfer``. Either session is marked broken if
        the move fails, since both servers may still be mid-transfer.
        """
        source, target = parse(source_url), parse(target_url)
        plan = _Plan(self._streams(transfer), "ftp" in (source.scheme, target.scheme), udt)
        with self._session(source) as src, self._session(target) as dst:
            try:
                info: Stat | None = self._stat(src.control, _path(source))
            except GError:
                # gfal2 asks SIZE and carries on: RETR reports the real problem.
                info = None
            # A directory is RETR's to refuse, as it is for gfal2. Recorded on
            # the transfer for the core's monitor callbacks.
            size = None if info is None or info.is_dir() else info.st_size
            transfer.source_size = size
            copy = _ThirdParty(self, transfer, src.control, dst.control, plan)
            copy.run(_path(source), _path(target), size, target.host)
            if size is not None and compare:
                _compare(size, self._stat(dst.control, _path(target)).st_size)
            # Markers may stop short of the end; the final report is exact.
            if size is not None:
                transfer.progress(size, force=True)

    # -- bulk -------------------------------------------------------------------------------

    def copy_bulk(self, params: Any, transfers: Sequence[Any]) -> list[GError | None]:
        """gfal2's ``gridftp_bulk_copy`` for GridFTP pairs; one copy at a time otherwise.

        Returns one entry per transfer, ``None`` for success. Only an
        all-GridFTP batch gets the bulk engine; a batch with a ``file://``
        end runs each pair through the core's ``run_copy``, which comes back
        to :meth:`copy` with the core's checks. A failure never stops the
        other pairs.
        """
        both = [
            scheme_of(item.source) in _SCHEMES and scheme_of(item.destination) in _SCHEMES
            for item in transfers
        ]
        if all(both):
            return _Bulk(self, params, list(transfers)).run()
        from ...transfer import run_copy

        results: list[GError | None] = []
        for item in transfers:
            try:
                user = (item.checksum_algorithm, item.user_checksum)
                run_copy(self.context, params, item.source, item.destination, user)
                results.append(None)
            except GError as exc:
                results.append(exc)
        return results


class _Bulk:
    """``PREPARE`` every pair, move them, then ``CLOSE`` them: gfal2's bulk copy.

    Each phase runs over the pairs still without an error (:meth:`pending`),
    so a pair that fails drops out of the later phases but the batch goes
    on. Phase-level events (``PREPARE``, ``CLOSE``) go out once, through the
    first transfer, in gfal2's bulk domain; per-pair events go through each
    pair's own transfer. A ``_TransferError`` from destination preparation
    is reported by its bare text, without the ``SIDE NOTE`` labels.
    """

    def __init__(self, plugin: _CopyMixin, params: Any, transfers: list[Any]) -> None:
        """Per-pair state: errors, source sizes and expected checksums (user's, else source's)."""
        self.plugin = plugin
        self.params = params
        self.transfers = transfers
        self.errors: list[GError | None] = [None] * len(transfers)
        self.sizes = [0] * len(transfers)
        self.sums = [item.user_checksum for item in transfers]
        mode, algorithm, _ = params.get_checksum()
        self.mode = 0 if params.strict_copy else int(mode)
        self.algorithm = algorithm or plugin.checksum_type()

    def event(
        self, stage: str, text: str = "", side: int = ev.BOTH, domain: str = BULK_DOMAIN
    ) -> None:
        """A batch-level event, sent once (through the first transfer)."""
        self.transfers[0].event(stage, text, side, domain)

    def pending(self) -> list[tuple[int, Any]]:
        """``(index, transfer)`` of every pair that has not failed yet."""
        return [(i, t) for i, t in enumerate(self.transfers) if self.errors[i] is None]

    def run(self) -> list[GError | None]:
        """All three phases; the per-pair results, ``None`` for success."""
        self.event(ev.PREPARE_ENTER)
        self._sources()
        self._destinations()
        self.event(ev.PREPARE_EXIT)
        started = self._transfer()
        for index in started:
            item = self.transfers[index]
            self.event(ev.TRANSFER_EXIT, f"Done {item.source} => {item.destination}")
        self._close()
        return self.errors

    def _sources(self) -> None:
        """``PREPARE``, sources: each must be a file; record its size and checksum.

        The checksum is checked against the user's when one was given and
        becomes the expected value otherwise (``SOURCE CHECKSUM MISMATCH``,
        ``EIO``). The ``CHECKSUM:EXIT`` event goes out even on failure.
        """
        plugin = self.plugin
        for index, item in self.pending():
            try:
                item.check()
                info = plugin.stat(item.source)
                if info.is_dir():
                    raise GError("File is a directory", errno.EISDIR)
                self.sizes[index] = info.st_size
                if self.mode & _SOURCE:
                    # In bulk, gfal2's checksum events carry the URL, not the
                    # algorithm.
                    item.event(ev.CHECKSUM_ENTER, item.source, ev.SOURCE, BULK_DOMAIN)
                    try:
                        value = plugin._copy_checksum(item.source, self.algorithm)
                        if not self.sums[index]:
                            self.sums[index] = value
                        elif not checksums_match(self.sums[index], value):
                            raise GError(
                                "SOURCE CHECKSUM MISMATCH User checksum and source checksum do "
                                f"not match: {self.sums[index]} != {value}",
                                errno.EIO,
                            )
                    finally:
                        item.event(ev.CHECKSUM_EXIT, item.source, ev.SOURCE, BULK_DOMAIN)
            except GError as exc:
                self.errors[index] = exc

    def _destinations(self) -> None:
        """``PREPARE``, destinations: ``OVERWRITE`` or refuse, then create parents.

        Each parent directory is made at most once per batch, the common case
        being many files into one directory. Skipped for a strict copy.
        """
        plugin = self.plugin
        parents: list[str] = []
        for index, item in self.pending():
            try:
                item.check()
                if self.params.strict_copy:
                    continue
                plugin._delete_existing(item, item.destination)
                parent = item.destination.rpartition("/")[0]
                # The destination check still runs for every pair; only the
                # parent creation is shared.
                if parent not in parents:
                    plugin._create_parent(item, item.destination)
                    parents.append(parent)
            except _TransferError as exc:
                self.errors[index] = GError(exc.detail, exc.code)
            except GError as exc:
                self.errors[index] = exc

    def _transfer(self) -> list[int]:
        """Move each pending pair, one after another, over pooled sessions.

        No size comparison here (``CLOSE`` does it), and UDT is not tried
        in bulk. Returns the indexes that moved.
        """
        plugin = self.plugin
        ipv6 = plugin.options.boolean(GROUP, "IPV6", False)
        started = []
        for index, item in self.pending():
            text = _pair_text(item.source, item.destination, ipv6)
            item.event(ev.TRANSFER_ENTER, text, domain=BULK_DOMAIN)
            item.event(ev.TRANSFER_TYPE, "3rd push")
            try:
                item.check()
                plugin._third_party(item, item.source, item.destination, udt=False, compare=False)
                started.append(index)
            except GError as exc:
                self.errors[index] = exc
        return started

    def _close(self) -> None:
        """``CLOSE``: compare each destination's size, then its checksum, with the source's.

        A mismatch fails that pair (``EIO``) but leaves the destination in
        place, as gfal2's bulk copy does.
        """
        plugin = self.plugin
        self.event("CLOSE:ENTER")
        for index, item in self.pending():
            try:
                size = plugin.stat(item.destination).st_size
                if size != self.sizes[index]:
                    raise GError(
                        "DESTINATION SIZE MISMATCH Source and destination file sizes do not "
                        f"match: {self.sizes[index]} != {size}",
                        errno.EIO,
                    )
                if self.mode & _TARGET:
                    item.event(ev.CHECKSUM_ENTER, item.destination, ev.DESTINATION, BULK_DOMAIN)
                    try:
                        value = plugin._copy_checksum(item.destination, self.algorithm)
                        if self.sums[index] and not checksums_match(self.sums[index], value):
                            raise GError(
                                "DESTINATION CHECKSUM MISMATCH Destination checksum do not "
                                f"match: {self.sums[index]} != {value}",
                                errno.EIO,
                            )
                    finally:
                        # gfal2 names the source in this event.
                        item.event(ev.CHECKSUM_EXIT, item.source, ev.DESTINATION, BULK_DOMAIN)
            except GError as exc:
                self.errors[index] = exc
        self.event("CLOSE:EXIT")


class _ThirdParty:
    """Server-to-server: the destination listens, the source connects and sends.

    The destination is made passive (it will receive) and the source active,
    so in ``MODE E`` the sender is the connecting side, as GFD.20 requires.
    Single use; the caller owns both control connections and has them
    marked broken here if anything fails.
    """

    #: Seconds per round of polling both control channels (split between
    #: those still owed a final reply); tests shorten it on the class.
    POLL = 0.2

    def __init__(
        self,
        plugin: _CopyMixin,
        transfer: Any,
        source: Control,
        destination: Control,
        plan: _Plan,
    ) -> None:
        """Bind the two logged-in sessions; ``plan`` says how to move. No I/O yet."""
        self.plugin = plugin
        self.transfer = transfer
        self.source = source
        self.destination = destination
        #: ``ftp://`` at either end: stream mode, one connection, no markers.
        self.plain = plan.plain
        self.streams = 0 if plan.plain else plan.streams
        self.udt = plan.udt
        self.options = plugin._data_options()
        #: Latest ``112`` byte count per stripe (see :func:`~.data.perf_bytes`).
        self.markers: dict[int, int] = {}
        #: ``PERF_MARKER_TIMEOUT`` seconds without progress fail the copy; 0
        #: disables the watchdog (always for ``ftp://``, which sends no markers).
        self.marker_timeout = (
            0 if plan.plain else plugin.options.integer(GROUP, "PERF_MARKER_TIMEOUT", 360)
        )
        #: When the byte count last grew (the watchdog's reference).
        self.last_progress = time.monotonic()
        #: The highest total seen; markers that do not exceed it are no progress.
        self.best = 0

    def run(self, source_path: str, target_path: str, size: int | None, host: str) -> None:
        """Set both ends up, start the move, and wait for both final replies.

        The order is what makes it work. Both ends get ``TYPE I``, the mode,
        UDT and buffer sizes first. The destination's address is obtained
        (``PASV``/``EPSV``/``SPAS``) and it is sent ``STOR``, so it is
        listening and expecting data, before the source is told where to
        connect (``PORT``/``EPRT``/``SPOR``) and sent ``RETR``. With GridFTP
        v2 on both ends the pair is ``PUT ...;pasv;`` and ``GET ...;port=``,
        which carry the address in the command - but ``port=`` takes only
        the IPv4 ``h1,...,p2`` form, so striping and IPv6 keep the classic
        commands. ``host`` is the destination's host name for the PASV
        events.
        """
        src, dst = self.source, self.destination
        options = self.plugin.options
        # The observer sees every destination reply from here on, including
        # the delayed 127; it is removed in ``finally`` because the session
        # goes back to the pool.
        if options.boolean(GROUP, "ENABLE_PASV_PLUGIN", False):
            dst.observer = lambda reply: self._passive_event(reply, host)
        try:
            self._prepare()
            # GET's port= names one IPv4 address in PORT's form, so striping
            # and IPv6 stay on the classic commands.
            getput = (
                self.plugin._getput(src, dst)
                and not self.options.spas
                and not self.options.ipv6
                and not src.ipv6
            )
            addresses = [] if getput else passive(dst, self.options)
            if size is not None:
                dst.command(f"ALLO {size}", ok=(2, 4, 5))
            dst.send(f"PUT path={target_path};pasv;" if getput else f"STOR {target_path}")
            # Delayed passive or PUT: the address is the 127 reply to STOR/PUT.
            if not addresses:
                addresses = [self._delayed_address()]
            if getput:
                src.send(f"GET path={source_path};port={format_port(*addresses[0])};")
            else:
                self._connect_source(addresses)
                src.send(f"RETR {source_path}")
            self._await()
        except BaseException:
            src.broken = dst.broken = True
            raise
        finally:
            dst.observer = None

    def _prepare(self) -> None:
        """``TYPE I``, the mode, UDT and buffer sizes on both ends; the source's parallelism."""
        src, dst = self.source, self.destination
        buffer = int(self.transfer.params.tcp_buffersize or 0)
        for control, verb in ((dst, "STORBUFSIZE"), (src, "RETRBUFSIZE")):
            control.setting("TYPE", "I")
            control.setting("MODE", "S" if self.plain else "E")
            if self.udt:
                control.command("SITE SETNETSTACK udt")
            # gfal2's tcp_buffersize: the receiving end's socket buffer
            # (STORBUFSIZE) and the sending end's (RETRBUFSIZE); servers
            # that do not know the SITE command are tolerated.
            if buffer > 0:
                control.command(f"SITE {verb} {buffer}", ok=(2, 4, 5))
        # One stream needs no OPTS; the server's default is one.
        if self.streams > 1:
            n = self.streams
            src.setting("OPTS RETR", f"Parallelism={n},{n},{n};")

    def _connect_source(self, addresses: list[tuple[str, int]]) -> None:
        """Tell the source where the destination listens: ``SPOR``, ``EPRT`` or ``PORT``."""
        src = self.source
        if self.options.spas:
            src.command("SPOR " + " ".join(format_port(h, p) for h, p in addresses))
        elif self.options.ipv6 or src.ipv6:
            src.command(f"EPRT {format_eprt(*addresses[0])}")
        else:
            src.command(f"PORT {format_port(*addresses[0])}")

    def _passive_event(self, reply: Reply, host: str) -> None:
        """gfal2's PASV plugin: where the destination listens, as events.

        Installed as the destination's reply observer with
        ``ENABLE_PASV_PLUGIN``. An ``EPSV`` reply names no address, so the
        destination's host is looked up instead, as gfal2 does.
        """
        found = passive_address(reply)
        if found is None:
            return
        ip, port, ipv6 = found
        if not ip:
            ip, ipv6 = lookup_host(host, self.options.ipv6)
        self.transfer.event("PASV", f"{host}:{ip}:{port}", ev.DESTINATION)
        self.transfer.event("IPV6" if ipv6 else "IPV4", f"{ip}:{port}", ev.DESTINATION)

    def _delayed_address(self) -> tuple[str, int]:
        """The destination's ``127`` reply to ``STOR``: where the source must connect."""
        reply = self.destination.reply()
        if reply.code != 127:
            raise reply_error(reply)
        host, port = parse_pasv(reply.text)
        return routable(host, self.destination), port

    def _marker(self, reply: Reply) -> None:
        """A ``1xx`` from either end: progress if it is a ``112`` showing more bytes."""
        total = perf_bytes(self.markers, reply)
        if total is not None and total > self.best:
            self.best = total
            self.last_progress = time.monotonic()
            self.transfer.progress(total)

    def _watchdog(self) -> None:
        """Between polls: honour ``cancel()``/the timeout, then the marker timeout.

        gfal2's ``PERF_MARKER_TIMEOUT`` error (``ETIMEDOUT``) when no marker
        has shown progress for that long, which also catches a server that
        keeps sending markers with zero bytes.
        """
        self.transfer.check()
        timeout = self.marker_timeout
        if timeout > 0 and time.monotonic() - self.last_progress > timeout:
            raise GError(
                f"Transfer canceled because the gsiftp performance marker timeout of {timeout} "
                "seconds has been exceeded, or all performance markers during that period "
                "indicated zero bytes transferred",
                errno.ETIMEDOUT,
            )

    def _await(self) -> None:
        """Poll both ends until each has sent its final ``2xx``.

        The two replies may come in either order. Preliminary replies are
        ``150`` or markers; any ``4xx``/``5xx`` from either end fails the
        copy at once (the caller breaks both sessions, which stops the
        other end too).
        """
        pending = [self.source, self.destination]
        while pending:
            for control in list(pending):
                # Split the poll so a round over both ends still takes POLL.
                reply = control.poll(self.POLL / len(pending))
                if reply is None:
                    continue
                # 150, 111 restart markers and 112 performance markers.
                if reply.kind == 1:
                    self._marker(reply)
                elif reply.kind == 2:
                    pending.remove(control)
                else:
                    raise reply_error(reply)
            self._watchdog()
