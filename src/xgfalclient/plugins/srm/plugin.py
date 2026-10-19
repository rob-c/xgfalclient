"""``srm://`` - SRM v2.2, as gfal2's srm plugin and srm-ifce speak it.

An SRM stores nothing itself: it answers namespace questions and hands out
transfer URLs (TURLs) on other protocols. So this plugin does the namespace
over SOAP and, for bytes, asks for a TURL and hands the work to whichever
plugin serves that TURL - ``srmPrepareToGet``, a read through, say,
``gsiftp://``, then ``srmReleaseFiles``; ``srmPrepareToPut``, a write, then
``srmPutDone``. It asks for ``TURL_PROTOCOLS`` for local I/O, bring-online
and ``user.replicas``, and for ``TURL_3RD_PARTY_PROTOCOLS`` for copies and
checksums, exactly as gfal2 does.

Copies to or from ``srm://`` are handled here rather than by the core, as in
gfal2 (``gfal_srm_copy.c``), with gfal2's checks and messages. Between
``PREPARE:ENTER`` and ``PREPARE:EXIT``: the source checksum (``SOURCE
CHECKSUM MISMATCH ...``; ``ALLOW_EMPTY_SOURCE_CHECKSUM`` skips it), the
source's size, ``COPY_FAIL_NEARLINE`` (a file exactly ``NEARLINE`` is
refused), the source TURL (``SRM:GET``), an ``srmRm`` of the destination for
``overwrite`` (``OVERWRITE``; without it, ``srmPrepareToPut`` decides), its
parent directory, and the destination TURL (``SRM:PUT``). Each end asks for
``TURL_3RD_PARTY_PROTOCOLS`` with the other end's scheme moved to the front,
so an SRM can hand out a TURL the other end copies with directly. The bytes
then move TURL to TURL through the core - so the TURL plugin's own
third-party copy is used where it has one - and the requests are closed:
``srmPutDone`` (between ``CLOSE:ENTER`` and ``CLOSE:EXIT``), the destination
checksum (``TRANSFER CHECKSUM MISMATCH ...``), and ``srmReleaseFiles``. A
failure aborts the ``PUT`` request and removes what it left, or, once the
bytes have moved, removes the destination (``CLEANUP``). Space token
*descriptions* in ``src_spacetoken``/``dst_spacetoken`` (or
``SPACETOKENDESC``, for everything but copies) are resolved with
``srmGetSpaceTokens``, as srm-ifce resolves them.

SURLs are percent-decoded, and a short SURL's web service is looked up in
the BDII (:mod:`.bdii`) unless ``[BDII] ENABLED`` is false, falling back to
gfal2's guess with gfal2's warning.

Where this differs from gfal2, deliberately: requests are released or
aborted even when ``transfer_cleanup`` is off (gfal2 leaves them pending);
a partial checksum is the partial checksum, where gfal2 returns the whole
file's; there is no ``srmPing`` for Castor before each copy and open; and
``srmLs`` answers are not cached.

Messages, ``errno`` values and the requests on the wire were checked, case by
case, against gfal2 2.23.5 driving :mod:`xgfalclient.testing.srm`.

How the code is laid out (this module is the facade and the plugin class):

* :mod:`._base` - ``_SRMBase``, the plugin's root: options, SURL and BDII
  resolution, the ``srmLs`` of one SURL, the nearline check, and the TURL
  requests (``srmPrepareToGet``/``srmPrepareToPut``, ``srmReleaseFiles``,
  ``srmPutDone``) that I/O and copies share; with the option group, event
  names and the helpers several modules use.
* :mod:`._staging` - ``_StagingMixin``: ``bring_online``,
  ``bring_online_poll``, ``release``, ``abort_bring_online`` and
  ``archive_poll``.
* :mod:`._copy` - ``_CopyMixin``: ``copy_check`` and ``copy``, gfal2's
  ``srm_plugin_filecopy`` with its checks, events and rollback.
* this module - :class:`SRMPlugin` itself (``_StagingMixin`` +
  ``_CopyMixin``, plus the class attributes the registry reads), the
  namespace (``stat``, ``access``, ``mkdir``, ``rmdir``, ``unlink``,
  ``rename``, ``chmod``), listings (``srmLs`` in ``LS_CHUNK`` pages),
  ``open`` and :class:`SRMFile`, and the metadata (``checksum``,
  ``listxattr``, ``getxattr``).

Every name the single-module layout had is re-exported here, so
``from xgfalclient.plugins.srm.plugin import X`` keeps working. ``LS_CHUNK``,
which tests patch on this module, is read here by the listing, so the patch
reaches it; the split modules do not look anything up through this one,
because nothing patches a name they use.
"""

from __future__ import annotations

# The stdlib names the single-module layout imported stay attributes of this
# module, and everything below is re-exported with a redundant ``as`` so
# mypy's strict no-implicit-reexport and ruff both treat it as this module's API.
import errno
import json
import os
import stat as _stat
from collections.abc import Callable as Callable
from collections.abc import Iterator, Sequence
from typing import Any, TypeVar

from ...checksum import checksums_match as checksums_match
from ...checksum import normalise_name
from ...errors import GError
from ...plugin import O_ACCMODE_MASK, PluginFile
from ...plugin import Plugin as Plugin
from ...plugin import StagingResult as StagingResult
from ...transfer import Transfer as Transfer
from ...transfer import TransferParameters as TransferParameters
from ...transfer import run_copy as run_copy
from ...types import Stat
from ...url import scheme_of as scheme_of
from ._base import _ADVICE as _ADVICE
from ._base import _LOCALITIES as _LOCALITIES
from ._base import _SOURCE as _SOURCE
from ._base import _TARGET as _TARGET
from ._base import CLOSE_ENTER as CLOSE_ENTER
from ._base import CLOSE_EXIT as CLOSE_EXIT
from ._base import DEFAULT_3RD_PARTY_PROTOCOLS as DEFAULT_3RD_PARTY_PROTOCOLS
from ._base import DEFAULT_TURL_PROTOCOLS as DEFAULT_TURL_PROTOCOLS
from ._base import EVENT_DOMAIN as EVENT_DOMAIN
from ._base import GET_EVENT as GET_EVENT
from ._base import GROUP, _by_endpoint, _locality, _stat_error
from ._base import PUT_EVENT as PUT_EVENT
from ._base import _SRMBase as _SRMBase
from ._base import _turl as _turl
from ._copy import _CopyMixin as _CopyMixin
from ._copy import _inner as _inner
from ._copy import _prefixed as _prefixed
from ._copy import _reorder as _reorder
from ._staging import _archived as _archived
from ._staging import _file_failure as _file_failure
from ._staging import _staging as _staging
from ._staging import _StagingMixin as _StagingMixin
from .bdii import Resolver as Resolver
from .client import Client as Client
from .client import Detail, Space, Status, file_error
from .client import FileStatus as FileStatus
from .transport import SURL
from .transport import Transport as Transport
from .transport import normalise_path as normalise_path
from .transport import parse_surl as parse_surl

__all__ = ["EVENT_DOMAIN", "LS_CHUNK", "XATTRS", "SRMFile", "SRMPlugin"]

#: The result type of the TURL file method :meth:`SRMFile._io` runs.
_T = TypeVar("_T")

#: Entries per ``srmLs`` once a server has said a directory is too big to
#: list in one go.
LS_CHUNK = 1000

#: What ``listxattr`` answers, as gfal2's srm plugin does.
XATTRS = ["user.replicas", "user.status", "srm.type", "spacetoken"]

#: ``TFileType`` to the ``st_mode`` type bits; srm-ifce leaves them 0 when absent.
_TYPES = {"FILE": _stat.S_IFREG, "DIRECTORY": _stat.S_IFDIR, "LINK": _stat.S_IFLNK}


def _to_stat(detail: Detail) -> Stat:
    """What srm-ifce fills in: no owner, no atime, one link."""
    kind = _TYPES.get(detail.kind, 0)
    mode = kind | detail.owner << 6 | detail.group << 3 | detail.other
    return Stat(
        st_mode=mode,
        st_size=detail.size,
        st_nlink=1,
        st_mtime=detail.modified,
        st_ctime=detail.created,
    )


def _space_json(space: Space) -> str:
    """One space as gfal2 prints it (json-c's spaced style, its key order).

    gfal2 always reports ``usedsize`` as 0 - srm-ifce has no such field -
    and so does this, so that output compares equal.
    """
    return (
        f'{{ "spacetoken": {json.dumps(space.token)}, "owner": {json.dumps(space.owner)}, '
        f'"totalsize": {space.total}, "unusedsize": {space.unused}, "usedsize": 0, '
        f'"guaranteedsize": {space.guaranteed}, "lifetimeassigned": {space.assigned}, '
        f'"lifetimeleft": {space.left}, "retention": {json.dumps(space.retention)}, '
        f'"accesslatency": {json.dumps(space.latency)} }}'
    )


class SRMFile(PluginFile):
    """A file opened through a TURL; closing it closes the SRM request too.

    The bytes go through ``inner``, the file the TURL's plugin opened
    (``gsiftp://``, ``root://``...); this wrapper only keeps the SRM side
    of the bargain. Any I/O failure marks an upload :attr:`failed`, so that
    close aborts it rather than committing a partial file with
    ``srmPutDone``. Seeks and size queries move no bytes, so they cannot
    spoil an upload and are passed straight through.
    """

    def __init__(
        self, plugin: SRMPlugin, surl: SURL, inner: PluginFile, token: str, writing: bool
    ) -> None:
        """Own ``inner`` and the get or put request ``token`` of ``surl``.

        From here on the file is responsible for the request: :meth:`close`
        releases, commits or aborts it.
        """
        super().__init__(surl.url)
        self.plugin = plugin
        self.surl = surl
        self.inner = inner
        self.token = token
        self.writing = writing
        #: Set by the first failed read, write or close of ``inner``.
        self.failed = False

    def _io(self, method: Callable[..., _T], *args: Any) -> _T:
        """Call ``method`` on the TURL's file, noting a failure before re-raising it."""
        try:
            return method(*args)
        except Exception:  # any failure of the TURL's I/O spoils the upload
            self.failed = True
            raise

    def read(self, size: int) -> bytes:
        """Up to ``size`` bytes from the TURL's file, at its position."""
        return self._io(self.inner.read, size)

    def readinto(self, buffer: memoryview | bytearray) -> int:
        """Fill ``buffer`` from the TURL's file; the byte count read."""
        return self._io(self.inner.readinto, buffer)

    def pread(self, offset: int, size: int) -> bytes:
        """Up to ``size`` bytes at ``offset``, as the TURL's plugin supports it."""
        return self._io(self.inner.pread, offset, size)

    def write(self, data: bytes | bytearray | memoryview) -> int:
        """Write to the TURL's file; a failure dooms the upload to an abort."""
        return self._io(self.inner.write, data)

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        """Write at ``offset``; a failure dooms the upload to an abort."""
        return self._io(self.inner.pwrite, data, offset)

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Seek the TURL's file (a failure here does not spoil an upload)."""
        return self.inner.lseek(offset, whence)

    def size(self) -> int | None:
        """The TURL's plugin's idea of the size (``None`` when it has none)."""
        return self.inner.size()

    def close(self) -> None:
        """Close the TURL, then release (read) or finish the upload (write).

        An upload that failed part-way is aborted rather than committed.
        """
        if self.closed:
            return
        self.closed = True
        try:
            self._io(self.inner.close)
        finally:
            if not self.writing:
                self.plugin._release_quietly(self.token, self.surl)
            elif self.failed:
                self.plugin.client.abort_request(self.surl, self.token)
        if self.writing and not self.failed:
            self.plugin._put_done(self.token, self.surl)


class SRMPlugin(_StagingMixin, _CopyMixin):
    """gfal2's ``srm`` plugin.

    The class attributes are what the plugin registry reads; the behaviour
    is spread over the mixins (see the module docstring). Every public
    method fails with :class:`~xgfalclient.errors.GError` worded as gfal2
    words it.
    """

    name = "srm"
    schemes = ("srm",)
    option_group = GROUP
    priority = 200
    #: gfal2 emits no TRANSFER:ENTER/EXIT around an srm copy: only the TURL's.
    narrates_transfer = True
    #: ... and does the destination and checksum work itself.
    copy_manages_destination = True
    copy_manages_checksums = True
    event_domain = "SRM"

    # -- namespace -----------------------------------------------------------------

    def _exists(self, surl: SURL) -> Detail | None:
        """``srmLs`` of ``surl``, or ``None`` when it is missing; other failures raise."""
        try:
            return self._detail(surl)
        except GError as exc:
            if exc.code != errno.ENOENT:
                raise
            return None

    def stat(self, url: str) -> Stat:
        """One ``srmLs``, as srm-ifce turns it into a ``stat``: see ``_to_stat``."""
        return _to_stat(self._detail(self._surl(url)))

    def access(self, url: str, mode: int) -> None:
        """``srmCheckPermission``, then the ``rwx`` bits asked for."""
        surl = self._surl(url)
        status, bits = self.client.check_permission(surl)
        code = status.errno
        if not code and mode & 7 & ~bits:
            code = errno.EACCES
        if code:
            tail = file_error("CheckPermission", status).message
            raise GError(f"Error {code} : {os.strerror(code)} , file {surl.wire}: {tail}", code)

    def mkdir(self, url: str, mode: int) -> None:
        """gfal2's srm ``mkdir`` creates missing parents too, and so does this."""
        surl = self._surl(url)
        if self._exists(surl) is not None:
            raise GError("directory already exist", errno.EEXIST)
        self._makedirs(surl)

    def mkdir_rec(self, url: str, mode: int) -> None:
        """``mkdir -p``: nothing to do for an existing directory, ``ENOTDIR`` for a file.

        ``srmMkdir`` carries no permissions, so ``mode`` is not sent.
        """
        surl = self._surl(url)
        found = self._exists(surl)
        if found is None:
            self._makedirs(surl)
        elif found.kind != "DIRECTORY":
            raise GError(f"{url} it is a file", errno.ENOTDIR)

    def _makedirs(self, surl: SURL) -> None:
        """srm-ifce's ``makedirp``: up until a mkdir works, then back down."""
        try:
            self.client.mkdir(surl)
            return
        except GError as exc:
            up = surl.parent()
            if exc.code != errno.ENOENT or up.path == surl.path:
                raise
        self._makedirs(up)
        self.client.mkdir(surl)

    def rmdir(self, url: str) -> None:
        """``srmLs`` to refuse a file (``ENOTDIR``), then ``srmRmdir``.

        A non-empty directory fails with ``ENOTEMPTY`` from the server's
        ``SRM_NON_EMPTY_DIRECTORY``.
        """
        surl = self._surl(url)
        if self._detail(surl).kind != "DIRECTORY":
            raise GError(
                "This file is not a directory, impossible to use rmdir on it", errno.ENOTDIR
            )
        status = self.client.rmdir(surl)
        if not status.ok:
            code = status.errno  # never 0 for a failure
            raise GError(f"Error report from the srm_ifce {os.strerror(code)} ", code)

    def unlink(self, url: str) -> None:
        """One-file :meth:`unlink_bulk`; ``ENOENT`` for a missing file."""
        result = self.unlink_bulk([url])[0]
        if result is not None:
            raise result

    def unlink_bulk(self, urls: Sequence[str]) -> list[GError | None]:
        """``srmRm`` per endpoint; one answer per URL (``None`` for removed).

        A failed request fails every URL sent with it; a bad URL fails
        alone.
        """
        results: list[GError | None] = [None] * len(urls)
        for indices, surls in _by_endpoint(urls, results, self._surl):
            try:
                statuses = self.client.rm(surls)
            except GError as exc:
                for index in indices:
                    results[index] = exc
                continue
            for index, found in zip(indices, statuses, strict=False):
                results[index] = _rm_error(found.status)
        return results

    def rename(self, old: str, new: str) -> None:
        """``srmMv``, sent to ``old``'s endpoint (an SRM cannot move across services)."""
        self.client.mv(self._surl(old), self._surl(new))

    def chmod(self, url: str, mode: int) -> None:
        """``srmSetPermission`` of the owner and other bits; group bits are not sent."""
        self.client.set_permission(self._surl(url), mode)

    # -- listing -------------------------------------------------------------------

    def _page(self, surl: SURL, offset: int | None, count: int | None) -> list[Detail]:
        """One ``srmLs`` of a directory, ``numOfLevels=1``.

        gfal2 stats the directory with one call and lists it with another;
        the listing's own entry for the directory answers both questions, so
        this makes one round trip where gfal2 makes two.
        """
        top = self.client.ls([surl], levels=1, offset=offset, count=count, timeout=self._timeout())[
            0
        ]
        if not top.status.ok:
            raise _stat_error(top.status)
        if top.kind != "DIRECTORY":
            raise GError(
                f"srm-plugin: {surl.wire} is not a directory, impossible to list content",
                errno.ENOTDIR,
            )
        return top.subpaths

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        """The entries with their ``stat``, as gfal2's ``readdirpp`` gives them.

        One ``srmLs`` of the whole directory first. A server that refuses
        (``EFBIG``, from ``SRM_TOO_MANY_RESULTS``) is asked again in pages
        of :data:`LS_CHUNK`, fetched as the iterator is consumed; failures
        before the first page raise here, later ones from the iterator.
        """
        surl = self._surl(url)
        try:
            return self._entries(surl, self._page(surl, None, None), None)
        except GError as exc:
            if exc.code != errno.EFBIG:
                raise
        self.log.debug("EFBIG while listing SRM directory, chunk listing of size %d", LS_CHUNK)
        try:
            page = self._page(surl, None, LS_CHUNK)
        except GError as exc:
            raise GError(f"Failed when attempting chunk listing{exc.message}", exc.code) from exc
        return self._entries(surl, page, LS_CHUNK)

    def _entries(
        self, surl: SURL, page: list[Detail], count: int | None
    ) -> Iterator[tuple[str, Stat | None]]:
        """Yield ``page``, then (when paging) the next pages until a short one.

        ``count`` ``None`` means ``page`` is the whole listing. A page of
        exactly ``count`` entries may be the last; the empty page that then
        follows ends the listing, at the cost of one extra request.
        """
        offset = 0
        while True:
            for detail in page:
                yield detail.name, _to_stat(detail)
            if count is None or len(page) < count:
                return
            offset += len(page)
            page = self._page(surl, offset, count)

    def listdir(self, url: str) -> list[str]:
        """The names of :meth:`opendir`, paging included."""
        return [name for name, _ in self.opendir(url)]

    # -- I/O -----------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        """A TURL for ``TURL_PROTOCOLS``, opened through the core: see :class:`SRMFile`.

        Any write access mode means ``srmPrepareToPut`` (``size`` is its
        expected size, 0 when unknown), otherwise ``srmPrepareToGet``. If
        the TURL will not open, the request is released or aborted before
        the error propagates, so nothing is left pinned. ``mode`` is not
        sent: the server decides a new file's permissions.
        """
        surl = self._surl(url)
        protocols = self._turl_protocols()
        writing = bool(flags & O_ACCMODE_MASK)
        request = self._local_request(protocols)
        if writing:
            token, turl = self._put_turl(surl, size or 0, request)
        else:
            token, turl = self._get_turl(surl, request)
        try:
            inner = self.context._open(turl, flags, size)
        except GError:
            if writing:
                self.client.abort_request(surl, token)
            else:
                self._release_quietly(token, surl)
            raise
        return SRMFile(self, surl, inner, token, writing)

    # -- metadata ------------------------------------------------------------------

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        """The checksum ``srmLs`` reports, else the TURL's plugin's.

        ``srmLs`` only answers for the whole file and only when its
        algorithm is the one asked for (compared by normalised name). Any
        other case gets a get TURL for ``TURL_3RD_PARTY_PROTOCOLS``, asks
        that plugin, and releases the TURL whatever the result.
        """
        surl = self._surl(url)
        if offset == 0 and length == 0:
            detail = self._detail(surl)
            wanted = normalise_name(algorithm)
            if detail.checksum_value and normalise_name(detail.checksum_type) == wanted:
                return detail.checksum_value
        self.log.debug("No valid SRM checksum, fallback to the TURL checksum")
        protocols = self._third_party_protocols()
        token, turl = self._get_turl(surl, self._local_request(protocols))
        try:
            return self.context.checksum(turl, algorithm, offset, length)
        finally:
            self._release_quietly(token, surl)

    def listxattr(self, url: str) -> list[str]:
        """:data:`XATTRS`, whatever ``url`` is: no request is made."""
        return list(XATTRS)

    def getxattr(self, url: str, name: str) -> str:
        """gfal2's SRM attributes; ``ENODATA`` for any other name.

        ``user.replicas`` is a get TURL (left pinned, as gfal2 leaves it),
        ``user.status`` the locality from ``srmLs``, ``srm.type`` the
        ``backend_type`` from ``srmPing``, and ``spacetoken`` (JSON) the
        user's space tokens, ``spacetoken.description?<desc>`` the metadata
        of a description's spaces and ``spacetoken.token?<token>`` one
        space's.
        """
        surl = self._surl(url)
        if name == "user.replicas":
            if self.options.boolean(GROUP, "XATTR_FAIL_NEARLINE", False):
                self._require_online(surl, "")
            # gfal2 leaves this TURL pinned, so that it stays usable.
            protocols = self._turl_protocols()
            return self._get_turl(surl, self._local_request(protocols))[1]
        if name == "user.status":
            return _locality(self._detail(surl))
        if name == "srm.type":
            backend = self.client.ping(surl)[1].get("backend_type")
            if not backend:
                raise GError("Could not get the storage type", errno.ENODATA)
            return backend
        if name.startswith("spacetoken"):
            rest = name[len("spacetoken") :]
            if rest and not rest.startswith("."):
                raise GError(f"Unknown space token attribute {name}", errno.ENODATA)
            return self._space_xattr(surl, rest[1:])
        raise GError("not an existing extended attribute", errno.ENODATA)

    def _space_xattr(self, surl: SURL, which: str) -> str:
        """The ``spacetoken[.which]`` attribute: ``which`` is "" or ``kind?value``."""
        if not which:
            return json.dumps(self.client.space_tokens(surl), separators=(",", ":"))
        kind, sep, value = which.partition("?")
        if sep and kind == "description":
            tokens = self.client.space_tokens(surl, value)
            spaces = self.client.space_metadata(surl, tokens)
            return "[" + ",".join(_space_json(space) for space in spaces) + "]"
        if sep and kind == "token":
            return _space_json(self.client.space_metadata(surl, [value])[0])
        raise GError(f"Unknown space token attribute {which}", errno.ENODATA)


def _rm_error(status: Status) -> GError | None:
    """One file's ``srmRm`` answer as ``unlink_bulk`` reports it; ``None`` if removed."""
    if status.ok:
        return None
    error = file_error("srmRm", status)
    code = error.code
    if code == errno.EINVAL:
        code = errno.ENOENT  # BeStMan answers EINVAL for a missing file; gfal2 says ENOENT
    return GError(f"error reported from srm_ifce, {error.message}", code)
