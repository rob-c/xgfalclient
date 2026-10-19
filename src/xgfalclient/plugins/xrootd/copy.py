"""A copy, as gfal2 hands it to XrdCl's copy process and narrates it.

gfal2 gives XrdCl the whole job, so the core does none of it here: no
existence check (``force`` decides, and the server answers ``EEXIST``), no
parent creation (a pull and an upload make the path anyway, a download makes
the local one), no ``CHECKSUM`` events (:class:`Verification` is XrdCl's
``checkSumMode``, and a mismatch is ``EILSEQ``), and the clean-up after a
failure is the plugin's own. :class:`CopyJob` is one such job:

* ``root`` to ``root`` is a pull, :mod:`.tpc`;
* ``root`` to ``file://`` is a download over xrdclient's bulk data plane
  (:func:`xrdclient.client.bulk.download`), ``nbstreams`` connections each
  landing its own span straight in the file;
* ``file://`` to ``root`` is an upload on one handle - xrootd admits one
  writer per file - with several writes in flight
  (:meth:`xrdclient.File.write_pieces`) fed by a read-ahead.

Every one of them stops at once when the copy must: the download and the
upload are handed a cancel hook (:class:`Stop`) that xrdclient watches on
a thread of its own, aborting the handles in flight the moment it fires,
and a pull is called off at its destination.

Where to start reading: :meth:`CopyJob.run`, which is the job's whole
narrative; each direction is one method below it. What a maintainer must
not break, because gfal2 users (FTS above all) read it:

* the event sequence - ``TRANSFER:ENTER`` with XrdCl's prepared URLs
  (:func:`job_url`), ``TRANSFER:TYPE``, ``TRANSFER:EXIT`` on success *and*
  failure, ``EVICT`` after a successful one, ``CLEANUP`` after a failed one;
* the error texts, which are ``Error on XrdCl::CopyProcess::Run(): ...``
  with XrdCl's ``(source)``/``(destination)`` side (see :mod:`.errors`);
* that a failure with ``EEXIST`` never removes the destination: the file
  that is there is somebody else's.

Everything on the wire goes through xrdclient's public :class:`~xrdclient.File`,
:class:`~xrdclient.FileSystem` and :mod:`xrdclient.client.bulk`, plus the
read-ahead every client shares (:class:`xrdcore.pipeline.ReadAhead`).
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat as _stat
import urllib.parse
from typing import TYPE_CHECKING, NoReturn

import xrdclient
from xrdclient import errors as xe
from xrdclient.client import bulk as xrd_bulk
from xrdcore.pipeline import ReadAhead

from ... import events as ev
from ...checksum import checksums_match
from ...enums import checksum_mode
from ...errors import GError
from ...url import parent, scheme_of
from .. import xrootd as package
from .errors import CopyError, Failure, describe, local_failure, posix_error, status_error
from .file import Abort, XRootDFile, aborting
from .stat import checksum_name, checksum_value
from .tpc import End, Rendezvous, pull
from .urls import is_root, local_path

if TYPE_CHECKING:
    from xrdclient import Config, XRootDURL

    from ...plugin import PluginFile
    from ...transfer import Transfer
    from .plugin import XRootDPlugin

#: ``TRANSFER:TYPE`` for ``root`` to ``root``: gfal2 asks XrdCl for a
#: third-party copy only (``thirdParty=only``), and announces it so.
TYPE_PULL = "3rd pull"
#: ``TRANSFER:TYPE`` for every other pair, which XrdCl may run either way.
TYPE_STREAMED = "streamed"
#: The event gfal2's xrootd plugin sends after a copy with ``evict`` set:
#: ``0`` when the source's disk copy was released, ``-1`` when not.
EVICT = "EVICT"

#: ``kXR_open`` options, spelled out so an open is one integer:
#: ``kXR_open_read``, ``kXR_open_updt``, ``kXR_new`` (fail if it exists),
#: ``kXR_delete`` (truncate an existing file), ``kXR_mkpath`` (make the
#: directories) and ``kXR_posc`` (persist on successful close: a file whose
#: writer never closed it cleanly is removed by the server, so a broken
#: upload leaves nothing half-written behind).
_READ, _UPDATE, _NEW, _DELETE, _MKPATH = 0x0010, 0x0020, 0x0008, 0x0002, 0x0100
_POSC = 0x1000


class Stop:
    """A copy's cancel hook for xrdclient: should the transfer stop now?

    Asked from xrdclient's watcher thread, it says yes once
    ``transfer.check()`` raises - a ``cancel()``, the copy's timeout, a
    progress callback that raised - and keeps that exception as
    :attr:`reason`, which is what the copy then fails with: xrdclient only
    reports that the transfer was aborted.
    """

    __slots__ = ("reason", "transfer")

    def __init__(self, transfer: Transfer) -> None:
        """A hook for ``transfer``, which has not been asked to stop yet."""
        self.transfer = transfer
        #: The first exception ``transfer.check()`` raised; set once, never cleared.
        self.reason: Exception | None = None

    def __call__(self) -> bool:
        """Whether to stop; asked repeatedly, from xrdclient's threads.

        Once it has said yes it keeps saying yes without asking again: the
        reason is already recorded, and a second ``check()`` could raise a
        different exception (a timeout after a cancel) and blur which one
        the copy reports. The unlocked read-then-write is harmless - two
        threads racing here both store an exception that stops the copy.
        """
        if self.reason is not None:
            return True
        try:
            self.transfer.check()
        except Exception as exc:
            self.reason = exc
            return True
        return False


class CopyJob:
    """One job of XrdCl's copy process, as gfal2 sets it up and narrates it.

    ``TRANSFER:TYPE`` is ``3rd pull`` only for ``root`` to ``root``, where
    gfal2 asks for a third-party copy and nothing else; any other pair of
    XRootD schemes is a job XrdCl may run either way, which gfal2 announces
    as ``streamed``.
    """

    def __init__(self, plugin: XRootDPlugin, transfer: Transfer) -> None:
        """One job for ``transfer``, run with ``plugin``'s settings and filesystems."""
        self.plugin = plugin
        self.transfer = transfer

    def run(self) -> None:
        """The job, narrated: ENTER and TYPE, the copy, EXIT, then EVICT if asked."""
        transfer, plugin = self.transfer, self.plugin
        source, destination = transfer.source, transfer.destination
        params = transfer.params
        only = scheme_of(source) == "root" and scheme_of(destination) == "root"
        transfer.event(
            ev.TRANSFER_ENTER,
            f"{plugin._job_url(source, params.src_spacetoken)} => "
            f"{plugin._job_url(destination, params.dst_spacetoken)}",
        )
        transfer.event(ev.TRANSFER_TYPE, TYPE_PULL if only else TYPE_STREAMED)
        # Which side a failure without its own side is blamed on: XrdCl names
        # the remote end of a streamed job, and none for a pull (the pull's
        # own steps carry their side, see :mod:`.tpc`).
        end = ""
        try:
            verify = Verification(plugin, transfer)
            verify.before()
            if is_root(source) and is_root(destination):
                # Delegation only for root-to-root: gfal2 sets XrdCl's
                # ``delegate`` from ``proxy_delegation`` for that pair alone.
                self._third_party(delegate=only and params.proxy_delegation)
            elif is_root(source):
                end = "source"
                self._download()
            else:
                end = "destination"
                self._upload()
            verify.after()
        except Exception as exc:
            if transfer.callback_error is not None:
                raise  # a callback's own exception: the core hands it back as it was
            self._failed(exc, end)
        transfer.event(ev.TRANSFER_EXIT, "Job finished, [SUCCESS] ")
        if params.evict:
            # gfal2 asks for any source, and a file:// one always fails.
            failed = not is_root(source) or any(
                result is not None for result in plugin.release([source], "")
            )
            transfer.event(EVICT, str(-1 if failed else 0), side=ev.SOURCE)

    def _failed(self, exc: Exception, end: str) -> NoReturn:
        """End the job as XrdCl does, remove what it left, and raise gfal2's error."""
        if isinstance(exc, GError):
            code, text, error = exc.code, exc.message, exc
        else:
            status = status_error(
                "", exc, strerror=False, end=exc.end if isinstance(exc, CopyError) else end
            )
            code, text = status.code, status.message
            error = GError(f"Error on XrdCl::CopyProcess::Run(): {text}", code)
        # gfal2's copy process ends every job with an EXIT; the core only
        # sends one for a copy that worked, so a failed one is said here.
        self.transfer.event(ev.TRANSFER_EXIT, f"Job finished, {text}")
        if self.transfer.params.transfer_cleanup and code != errno.EEXIST:
            self._clean()
        if error is exc:
            raise exc
        raise error from exc

    def _clean(self) -> None:
        """``gfal_xrootd_copy_cleanup``: a destination already gone counts as removed.

        A local device or FIFO is a sink the copy wrote into, not a file it
        made, and is left alone (gfal2 would try to unlink ``/dev/null``).
        A ``root://`` destination is removed by this plugin itself, as gfal2
        calls ``gfal_xrootd_unlinkG`` - not through the context, which
        refuses new operations while a ``cancel()`` drains, and so would leave
        a cancelled copy's destination behind.
        """
        destination = self.transfer.destination
        remote = is_root(destination)
        if not remote and _is_sink(local_path(destination)):
            return
        context = self.plugin.context
        try:
            with context.abort_exempt():  # a cancel()'s drain must not stop it
                (self.plugin.unlink if remote else context.unlink)(destination)
            status = 0
        except GError as exc:
            status = 0 if exc.code == errno.ENOENT else exc.code
        self.transfer.event(ev.CLEANUP, str(status), side=ev.DESTINATION)

    # -- root to root ----------------------------------------------------------------

    def _third_party(self, *, delegate: bool) -> None:
        """Destination pulls from source; see :mod:`.tpc`.

        The destination's path is made as the pull's open makes it, whatever
        ``create_parent`` says: when the open finds no parent, the parent is
        made and the job run once more.
        """
        transfer, plugin = self.transfer, self.plugin
        params = transfer.params
        transfer.third_party = True
        job = Rendezvous(
            End(
                plugin._copy_url(transfer.source, params.src_spacetoken),
                plugin._config(transfer.source),
            ),
            End(
                plugin._copy_url(transfer.destination, params.dst_spacetoken),
                # XrdCl sets XrdSecGSIDELEGPROXY to match before this login.
                plugin._config(transfer.destination).evolve(gsi_delegate=delegate),
            ),
            delegate=delegate,
            overwrite=bool(params.overwrite),
        )
        try:
            size = pull(transfer, job, self._tpc_progress)
        except CopyError as exc:
            if not exc.no_parent:
                raise
            try:
                plugin.mkdir_rec(parent(transfer.destination), 0o755)
            except GError:
                raise exc from None
            size = pull(transfer, job, self._tpc_progress)
        transfer.progress(size, always=True)  # XrdCl's last JobProgress, however short

    def _tpc_progress(self) -> None:
        """How much the destination holds, as the progress of a pull.

        XrdCl's ``RunTPC`` learns nothing from the destination while the
        second ``kXR_sync`` blocks; a stat of the growing file is the only
        progress a pull can have, so that is what a listening caller gets,
        every :data:`~xgfalclient.plugins.xrootd.TPC_PROGRESS` seconds. It
        runs on a pooled filesystem of its own, never on the pull's handle,
        so it cannot delay the cancel that handle may be about to carry, and
        any failure is ignored: a pull's progress is advisory.
        """
        try:
            with self.plugin._fs(self.transfer.destination) as (fs, path):
                self.transfer.progress(int(fs.stat(path).st_size))
        except Exception:
            pass  # not created yet, or busy: the next poll will know

    # -- root to file ----------------------------------------------------------------

    def _download(self) -> None:
        """``root://`` to a local file over the bulk data plane.

        ``nbstreams`` connections each fetch their own span, pipelined and
        written at their own offsets. The local path is made, as XrdCl makes
        it, and an existing file is replaced only with ``overwrite``. XrdCl
        opens the source first, so when the local file cannot be made, the
        source is opened to see whether that is the failure to report.
        """
        transfer, plugin = self.transfer, self.plugin
        params = transfer.params
        source = plugin._copy_url(transfer.source, params.src_spacetoken)
        config = plugin._config(transfer.source)
        workers = params.nbstreams if params.nbstreams > 0 else None
        try:
            fd = _local_create(local_path(transfer.destination), overwrite=bool(params.overwrite))
        except CopyError:
            # A source failure (no such file, no permission) is the one XrdCl
            # would have met first, so it wins; if the source opens, the
            # local failure is re-raised as it was.
            probe = xrdclient.File(source, config)
            probe.open(_READ, 0)
            probe.close()
            raise
        try:
            self._bulk_download(source, config, fd, workers)
        finally:
            os.close(fd)
        transfer.progress(transfer.transferred, always=True)  # XrdCl's last JobProgress

    def _bulk_download(
        self, source: XRootDURL, config: Config, fd: int, workers: int | None
    ) -> None:
        """:func:`xrdclient.client.bulk.download` into ``fd``, stopped at once when the copy must.

        A server without the bulk plane is read one request at a time instead.
        """
        transfer = self.transfer
        stop = Stop(transfer)

        def progress(done: int, total: int | None) -> None:
            """xrdclient's progress report, run on its threads, as the copy's progress.

            It must not raise into xrdclient: a raising monitor callback is
            recorded on the transfer, whose next ``check()`` - asked by the
            :class:`Stop` hook - re-raises it and stops the download.
            """
            # The callback's exception is kept; the hook stops the copy for it.
            with contextlib.suppress(Exception):
                transfer.progress(done)

        try:
            xrd_bulk.download(
                source, fd, config=config, progress=progress, workers=workers, cancel=stop
            )
        except xrd_bulk.BulkUnsupported:
            self._download_serially(source, config, fd)
        except xe.AbortedError as exc:
            # xrdclient only knows it was told to stop; the hook knows why
            # (cancel, timeout, a callback), and that is the copy's failure.
            if stop.reason is None:
                raise
            raise stop.reason from exc

    def _download_serially(self, source: XRootDURL, config: Config, fd: int) -> None:
        """The same download one request at a time, for a server without the bulk plane.

        The core's :func:`~xgfalclient.transfer.pump` between an
        :class:`XRootDFile` and a local file: the same loop any streamed
        copy uses, so progress, ``check()`` and cancellation behave as
        everywhere else. The local file is truncated first because the bulk
        attempt may have landed bytes in it before it gave up. Imported here
        to keep the core and the file plugin out of ``import`` of this
        package.
        """
        from ...transfer import pump
        from ..file import LocalFile

        transfer, plugin = self.transfer, self.plugin
        handle = xrdclient.File(source, config)
        handle.open(_READ, 0)
        reader = XRootDFile(str(source), handle, writable=False, context=plugin.context)
        os.ftruncate(fd, 0)
        writer = LocalFile(
            transfer.destination,
            local_path(transfer.destination),
            os.O_WRONLY,
            0,
            plugin.options,
        )
        try:
            pump(transfer, reader, writer, final_report=False)  # the caller reports
        finally:
            writer.close()
            reader.close()

    # -- file to root ----------------------------------------------------------------

    def _upload(self) -> None:
        """A local file to ``root://`` on one handle, reads and writes overlapped.

        The destination is created exclusively unless ``overwrite`` is set,
        and its path is made. ``nbstreams`` does not apply: xrootd lets one
        writer at a time have a file open (``kXR_FileLocked``), so there is
        no second connection to spread an upload over.
        """
        transfer, plugin = self.transfer, self.plugin
        params = transfer.params
        source = local_path(transfer.source)
        target = plugin._copy_url(transfer.destination, params.dst_spacetoken)
        config = plugin._config(transfer.destination)
        try:
            size = os.stat(source).st_size
        except OSError as exc:
            raise CopyError(local_failure(exc), "source") from exc
        # Persist on successful close, as XrdCl's upload asks.
        create = (_DELETE if params.overwrite else _NEW) | _MKPATH | _UPDATE | _POSC
        moved = self._upload_serially(source, target, config, create)
        if moved != size:
            raise GError(f"Short copy: {moved} bytes transferred, the source has {size}", errno.EIO)

    def _upload_serially(self, source: str, target: XRootDURL, config: Config, create: int) -> int:
        """Open both ends and stream one into the other; the bytes the server acknowledged.

        A local file that cannot be opened is the source's failure, and the
        destination is then never touched. While the upload runs the
        handle is registered with the context, so a ``cancel()`` aborts it
        (:class:`~.file.Abort`) and the write blocked on it returns at once.
        """
        from ..file import LocalFile

        transfer, plugin = self.transfer, self.plugin
        try:
            reader = LocalFile(transfer.source, source, os.O_RDONLY, 0, plugin.options)
        except OSError as exc:
            raise CopyError(local_failure(exc), "source") from exc
        try:
            handle = xrdclient.File(target, config)
            handle.open(create, 0o644)
            writer = XRootDFile(str(target), handle, writable=True, context=plugin.context)
            try:
                with aborting(plugin.context, Abort(handle)):
                    moved = _Upload(transfer, reader, writer, handle).run()
            except BaseException:
                # The failure is the news, not the close that follows it on
                # a connection it may have left unusable.
                with contextlib.suppress(GError):
                    writer.close()
                raise
            writer.close()
            return moved
        finally:
            reader.close()


class _Upload:
    """GFAL's progress and ``kXR_wait`` replay around xrdclient's pipelined writer.

    The pieces come off a read-ahead of the local file; xrdclient keeps
    :data:`UPLOAD_DEPTH` of them in flight on the handle's connection
    (writing one at a time where its bulk plane cannot be used - a signing
    session, say - with the same callbacks). A piece the server answers
    ``kXR_wait`` has not been stored: it is noted and, once the stream has
    settled, read back and written again, as gfal2's XrdCl would.
    """

    def __init__(
        self, transfer: Transfer, reader: PluginFile, writer: XRootDFile, handle: xrdclient.File
    ) -> None:
        """An upload from ``reader`` into ``handle`` (``writer`` wraps it, for replays)."""
        self.transfer = transfer
        self.reader = reader
        self.writer = writer
        self.handle = handle
        #: ``(offset, length)`` of every piece answered ``kXR_wait``, to write again.
        self.again: list[tuple[int, int]] = []
        #: Bytes the server has acknowledged so far: the copy's progress.
        self.done = 0

    def run(self) -> int:
        """Send the whole file, replay what the server deferred; the bytes stored.

        Sizes are read from the package at call time
        (:data:`~xgfalclient.plugins.xrootd.UPLOAD_CHUNK` and friends), so a
        test or a caller that tunes them affects the next upload. The
        read-ahead recycles its buffers - a view is reused once the next
        piece is asked for - so an upload of any size costs a fixed handful
        of buffers, not an allocation per piece. ``check`` is asked between
        pieces, so a cancel stops the stream at the next piece even when no
        write is blocked.
        """
        chunk = package.UPLOAD_CHUNK
        try:
            with ReadAhead(
                self.reader, chunk, package.UPLOAD_BUFFERS, recycle=True, thread_name="xgfal-upload"
            ) as pieces:
                self.handle.write_pieces(
                    pieces,
                    depth=package.UPLOAD_DEPTH,
                    acknowledged=lambda at, count: self._acked(count),
                    waited=lambda at, count: self.again.append((at, count)),
                    check=self.transfer.check,
                )
        except xe.ConnectionError as exc:
            # A connection that closed under the bulk writer (xrdclient's
            # "connection closed with N bytes of a reply outstanding") is
            # reported in gfal2's words; anything else - a timeout is a
            # ConnectionError too - goes on as it is.
            if str(exc).startswith("connection closed with "):
                raise xe.ConnectionError("the server closed the connection") from exc
            raise
        except xe.ServerError as exc:
            raise posix_error("Failed while writing to file", exc) from exc
        # Replayed only after the stream: the deferred pieces are few, and
        # writing them in the middle would interleave with the pipeline.
        for offset, length in self.again:
            self.writer.pwrite(self.reader.pread(offset, length), offset)
            self._acked(length)
        self.transfer.progress(self.done, always=True)
        return self.done

    def _acked(self, count: int) -> None:
        """``count`` more bytes stored, reported as XrdCl's ``JobProgress`` would."""
        self.done += count
        self.transfer.progress(self.done)


class Verification:
    """The checksum part of XrdCl's copy job, as gfal2 configures it.

    ``source`` mode asks the source for its checksum, when no value was
    given, and compares it with nothing; ``target`` compares the
    destination's with the value given; ``both`` (``end2end``) compares it
    with the value given or, failing one, the source's. The value loses its
    leading zeros and its case first, and an algorithm left empty is
    ``[XROOTD PLUGIN] COPY_CHECKSUM_TYPE``. A mismatch is ``EILSEQ``, and no
    ``CHECKSUM`` event is sent.
    """

    def __init__(self, plugin: XRootDPlugin, transfer: Transfer) -> None:
        """The checks ``transfer``'s parameters ask for; nothing is asked of a server yet."""
        self.plugin = plugin
        self.transfer = transfer
        self.mode = transfer.checksum_mode
        self.algorithm = transfer.checksum_algorithm or plugin.checksum_type()
        self.expected = transfer.user_checksum.lstrip("0").lower()

    def before(self) -> None:
        """Before the copy: the source's checksum, when the mode wants one and none was given.

        Asked before anything is opened for the copy, so a source that
        cannot answer fails the job before a byte moves.
        """
        if self.mode in (checksum_mode.source, checksum_mode.both) and not self.expected:
            self.expected = self._ask(self.transfer.source, "source")

    def after(self) -> None:
        """After the copy: the destination's checksum, compared when there is a value to compare.

        A mismatch is XrdCl's ``[ERROR] CheckSum error`` with no side, which
        the job then words as gfal2 does (``EILSEQ``); the destination is
        cleaned up like after any other failure.
        """
        if self.mode not in (checksum_mode.target, checksum_mode.both):
            return
        found = self._ask(self.transfer.destination, "destination")
        if self.expected and not checksums_match(self.expected, found):
            raise CopyError(Failure(errno.EILSEQ, "[ERROR] CheckSum error", ""), "")

    def _ask(self, url: str, end: str) -> str:
        """``url``'s checksum, or a :class:`CopyError` for ``end`` in XrdCl's words.

        A local file is checksummed through the context (the file plugin
        computes it); a remote one is a ``kXR_Qcksum`` on a pooled
        filesystem, its answer parsed as gfal2's ``xroot.cksum`` reads it.
        The query failure keeps XrdCl's status text with its suffix
        inserted before any trailing newline, as XrdCl appends it.
        """
        if not is_root(url):
            try:
                return str(self.plugin.context.checksum(url, self.algorithm))
            except GError as exc:
                raise CopyError(Failure(exc.code, "[ERROR] Local error", exc.message), end) from exc
        wanted = checksum_name(self.algorithm)
        try:
            answer = self.plugin._checksum_answer(url, wanted)
        except Exception as exc:
            failure = describe(exc)
            text = failure.to_str.rstrip("\n")
            newline = "\n" if failure.to_str.endswith("\n") else ""
            failure.to_str = f"{text} Got an error while querying the checksum!{newline}"
            raise CopyError(failure, end) from exc
        try:
            return checksum_value(answer, wanted)
        except GError as exc:
            raise CopyError(
                Failure(exc.code, "[ERROR] Invalid response", exc.message), end
            ) from exc


def job_url(url: str, spacetoken: str, extra_cgi: dict[str, str]) -> str:
    """``url`` as XrdCl's copy job prints it, after gfal2's ``prepare_url``.

    gfal2 gives the path three leading slashes and the ``XRD.*`` options
    (``extra_cgi``), a space token replaces whatever CGI there was
    (``svcClass``), and XrdCl adds its intent, prints the port, and sorts
    the CGI; a local file is on ``localhost``.
    """
    parsed = urllib.parse.urlsplit(url)
    path = urllib.parse.unquote(parsed.path) or "///"
    if not path.startswith("///"):
        path = ("/" if path.startswith("//") else "//") + path
    cgi: dict[str, str] = {}
    if is_root(url):
        host = parsed.hostname or ""
        where = f"[{host}]" if ":" in host else host
        user = f"{parsed.username}@" if parsed.username else ""
        authority = f"{user}{where}:{parsed.port or 1094}"
        cgi.update(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        cgi.update(extra_cgi)
    else:
        authority = "localhost"
    if spacetoken:
        cgi = {"svcClass": spacetoken}
    cgi["xrdcl.intent"] = "tpc"
    query = "&".join(f"{key}={value}" for key, value in sorted(cgi.items()))
    return f"{scheme_of(url)}://{authority}{path}?{query}"


def _is_sink(path: str) -> bool:
    """A device, FIFO or socket: written into, never created or removed."""
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return _stat.S_IFMT(mode) in (_stat.S_IFCHR, _stat.S_IFIFO, _stat.S_IFSOCK)


def _local_create(path: str, *, overwrite: bool) -> int:
    """A download's local file, its directory made; one already there needs ``overwrite``."""
    try:
        # A file where the directory should be: the open says ENOTDIR.
        with contextlib.suppress(FileExistsError):
            os.makedirs(os.path.dirname(path), exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT
        if overwrite:
            return os.open(path, flags | os.O_TRUNC, 0o644)
        try:
            return os.open(path, flags | os.O_EXCL, 0o644)
        except FileExistsError:
            if not _is_sink(path):
                raise
            return os.open(path, os.O_WRONLY)
    except OSError as exc:
        raise CopyError(local_failure(exc), "destination") from exc
