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
gfal2: each SRM end is resolved to a TURL (between ``PREPARE:ENTER`` and
``PREPARE:EXIT``, with an ``SRM:GET``/``SRM:PUT`` event naming each TURL),
the bytes move TURL to TURL through the core in strict mode - so the TURL
plugin's own third-party copy is used where it has one - and the requests
are closed: ``srmPutDone`` (between ``CLOSE:ENTER`` and ``CLOSE:EXIT``) and
``srmReleaseFiles`` on success, ``srmAbortRequest`` on failure. Space token
*descriptions* in ``src_spacetoken``/``dst_spacetoken`` are resolved with
``srmGetSpaceTokens``, as srm-ifce resolves them.

Messages, ``errno`` values and the requests on the wire were checked, case by
case, against gfal2 2.23.5 driving :mod:`xgfalclient.testing.srm`.
"""

from __future__ import annotations

import errno
import json
import os
import stat as _stat
from collections.abc import Iterator, Sequence
from typing import Any

from ... import events as ev
from ...checksum import normalise_name
from ...errors import GError
from ...plugin import O_ACCMODE_MASK, Plugin, PluginFile, StagingResult
from ...transfer import Transfer, TransferParameters, run_copy
from ...types import Stat
from ...url import scheme_of
from .client import Client, Detail, FileStatus, Space, Status, file_error
from .transport import SURL, Transport, normalise_path, parse_surl

__all__ = ["SRMPlugin", "SRMFile", "LS_CHUNK", "XATTRS", "EVENT_DOMAIN"]

GROUP = "SRM PLUGIN"
DEFAULT_TURL_PROTOCOLS = ["gsiftp", "rfio", "gsidcap", "dcap", "kdcap"]
DEFAULT_3RD_PARTY_PROTOCOLS = ["gsiftp", "https", "root"]

#: The domain of the ``SRM:GET``/``SRM:PUT`` events; the others are ``SRM``.
EVENT_DOMAIN = "GFAL2::PLUGINS::SRM"
GET_EVENT = "SRM:GET"
PUT_EVENT = "SRM:PUT"
CLOSE_ENTER = "CLOSE:ENTER"
CLOSE_EXIT = "CLOSE:EXIT"

#: Entries per ``srmLs`` once a server has said a directory is too big to
#: list in one go.
LS_CHUNK = 1000

#: What ``listxattr`` answers, as gfal2's srm plugin does.
XATTRS = ["user.replicas", "user.status", "srm.type", "spacetoken"]

#: ``TFileType`` to the ``st_mode`` type bits; srm-ifce leaves them 0 when absent.
_TYPES = {"FILE": _stat.S_IFREG, "DIRECTORY": _stat.S_IFDIR, "LINK": _stat.S_IFLNK}

_LOCALITIES = ("ONLINE", "NEARLINE", "ONLINE_AND_NEARLINE", "LOST", "NONE", "UNAVAILABLE")


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


def _locality(detail: Detail) -> str:
    return detail.locality if detail.locality in _LOCALITIES else "UNKNOWN"


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


def _stat_error(status: Status) -> GError:
    error = file_error("Ls", status)
    return GError(f"Error reported from srm_ifce : {error.code} {error.message}", error.code)


def _prefixed(prefix: str, exc: GError) -> GError:
    return GError(f"{prefix} {exc.message}", exc.code)


class SRMFile(PluginFile):
    """A file opened through a TURL; closing it closes the SRM request too."""

    def __init__(
        self, plugin: SRMPlugin, surl: SURL, inner: PluginFile, token: str, writing: bool
    ) -> None:
        super().__init__(surl.url)
        self.plugin = plugin
        self.surl = surl
        self.inner = inner
        self.token = token
        self.writing = writing
        self.failed = False

    def _io(self, method: Any, *args: Any) -> Any:
        try:
            return method(*args)
        except Exception:  # any failure of the TURL's I/O spoils the upload
            self.failed = True
            raise

    def read(self, size: int) -> bytes:
        return self._io(self.inner.read, size)  # type: ignore[no-any-return]

    def readinto(self, buffer: memoryview | bytearray) -> int:
        return self._io(self.inner.readinto, buffer)  # type: ignore[no-any-return]

    def pread(self, offset: int, size: int) -> bytes:
        return self._io(self.inner.pread, offset, size)  # type: ignore[no-any-return]

    def write(self, data: bytes | bytearray | memoryview) -> int:
        return self._io(self.inner.write, data)  # type: ignore[no-any-return]

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        return self._io(self.inner.pwrite, data, offset)  # type: ignore[no-any-return]

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self.inner.lseek(offset, whence)

    def size(self) -> int | None:
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


class SRMPlugin(Plugin):
    """gfal2's ``srm`` plugin."""

    name = "srm"
    schemes = ("srm",)
    option_group = GROUP
    priority = 200
    #: gfal2 emits no TRANSFER:ENTER/EXIT around an srm copy: only the TURL's.
    narrates_transfer = True
    event_domain = "SRM"

    def __init__(self, context: Any) -> None:
        super().__init__(context)
        self.transport = Transport(self)
        self.client = Client(self.transport)

    def close(self) -> None:
        self.transport.close()

    # -- options -------------------------------------------------------------------

    def _timeout(self) -> float:
        return float(self.option_timeout())

    def _request_time(self) -> int:
        return int(self.options.integer(GROUP, "REQUEST_LIFETIME", 3600))

    def _turl_protocols(self) -> list[str]:
        return list(self.options.string_list(GROUP, "TURL_PROTOCOLS", DEFAULT_TURL_PROTOCOLS))

    def _third_party_protocols(self) -> list[str]:
        return list(
            self.options.string_list(GROUP, "TURL_3RD_PARTY_PROTOCOLS", DEFAULT_3RD_PARTY_PROTOCOLS)
        )

    # -- namespace -----------------------------------------------------------------

    def _detail(self, surl: SURL) -> Detail:
        """``srmLs`` of one SURL, failing as gfal2's stat fails."""
        detail = self.client.ls([surl], timeout=self._timeout())[0]
        if not detail.status.ok:
            raise _stat_error(detail.status)
        return detail

    def _exists(self, surl: SURL) -> Detail | None:
        try:
            return self._detail(surl)
        except GError as exc:
            if exc.code != errno.ENOENT:
                raise
            return None

    def stat(self, url: str) -> Stat:
        return _to_stat(self._detail(parse_surl(url)))

    def access(self, url: str, mode: int) -> None:
        """``srmCheckPermission``, then the ``rwx`` bits asked for."""
        surl = parse_surl(url)
        status, bits = self.client.check_permission(surl)
        code = status.errno
        if not code and mode & 7 & ~bits:
            code = errno.EACCES
        if code:
            tail = file_error("CheckPermission", status).message
            raise GError(f"Error {code} : {os.strerror(code)} , file {surl.wire}: {tail}", code)

    def mkdir(self, url: str, mode: int) -> None:
        """gfal2's srm ``mkdir`` creates missing parents too, and so does this."""
        surl = parse_surl(url)
        if self._exists(surl) is not None:
            raise GError("directory already exist", errno.EEXIST)
        self._makedirs(surl)

    def mkdir_rec(self, url: str, mode: int) -> None:
        surl = parse_surl(url)
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
        surl = parse_surl(url)
        if self._detail(surl).kind != "DIRECTORY":
            raise GError(
                "This file is not a directory, impossible to use rmdir on it", errno.ENOTDIR
            )
        status = self.client.rmdir(surl)
        if not status.ok:
            code = status.errno  # never 0 for a failure
            raise GError(f"Error report from the srm_ifce {os.strerror(code)} ", code)

    def unlink(self, url: str) -> None:
        result = self.unlink_bulk([url])[0]
        if result is not None:
            raise result

    def unlink_bulk(self, urls: Sequence[str]) -> list[GError | None]:
        results: list[GError | None] = [None] * len(urls)
        for indices, surls in _by_endpoint(urls, results):
            try:
                statuses = self.client.rm(surls)
            except GError as exc:
                for index in indices:
                    results[index] = exc
                continue
            for index, found in zip(indices, statuses):
                results[index] = _rm_error(found.status)
        return results

    def rename(self, old: str, new: str) -> None:
        self.client.mv(parse_surl(old), parse_surl(new))

    def chmod(self, url: str, mode: int) -> None:
        self.client.set_permission(parse_surl(url), mode)

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
        surl = parse_surl(url)
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
        offset = 0
        while True:
            for detail in page:
                yield detail.name, _to_stat(detail)
            if count is None or len(page) < count:
                return
            offset += len(page)
            page = self._page(surl, offset, count)

    def listdir(self, url: str) -> list[str]:
        return [name for name, _ in self.opendir(url)]

    # -- TURLs -----------------------------------------------------------------------

    def _get_turl(
        self,
        surl: SURL,
        protocols: list[str],
        timeout: float,
        spacetoken: str = "",
        space: str = "",
    ) -> tuple[str, str]:
        """``(token, TURL)`` of an ``srmPrepareToGet``."""
        token, statuses = self.client.prepare_get(
            [surl],
            protocols,
            request_time=self._request_time(),
            timeout=timeout,
            spacetoken=spacetoken,
        )
        return token, _turl(statuses[0], "PrepareToGet", protocols, space)

    def _put_turl(
        self,
        surl: SURL,
        size: int,
        protocols: list[str],
        timeout: float,
        spacetoken: str = "",
        space: str = "",
    ) -> tuple[str, str]:
        """``(token, TURL)`` of an ``srmPrepareToPut``."""
        token, statuses = self.client.prepare_put(
            [surl],
            [size],
            protocols,
            request_time=self._request_time(),
            timeout=timeout,
            spacetoken=spacetoken,
        )
        return token, _turl(statuses[0], "PrepareToPut", protocols, space)

    def _release_quietly(self, token: str, surl: SURL) -> None:
        try:
            self.client.release(token, [surl])
        except GError as exc:
            self.log.debug("error on the release request : %s", exc)

    def _put_done(self, token: str, surl: SURL) -> None:
        found = self.client.put_done(token, [surl])[0]
        if not found.status.ok:
            error = file_error("PutDone", found.status)
            raise GError(
                f"Error on the surl {surl.wire} while putdone : {error.message}", error.code
            )

    # -- I/O -----------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        surl = parse_surl(url)
        protocols = self._turl_protocols()
        writing = bool(flags & O_ACCMODE_MASK)
        if writing:
            token, turl = self._put_turl(surl, size or 0, protocols, self._timeout())
        else:
            token, turl = self._get_turl(surl, protocols, self._timeout())
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
        """The checksum ``srmLs`` reports, else the TURL's plugin's."""
        surl = parse_surl(url)
        if offset == 0 and length == 0:
            detail = self._detail(surl)
            wanted = normalise_name(algorithm)
            if detail.checksum_value and normalise_name(detail.checksum_type) == wanted:
                return detail.checksum_value
        self.log.debug("No valid SRM checksum, fallback to the TURL checksum")
        token, turl = self._get_turl(surl, self._third_party_protocols(), self._timeout())
        try:
            return self.context.checksum(turl, algorithm, offset, length)
        finally:
            self._release_quietly(token, surl)

    def listxattr(self, url: str) -> list[str]:
        return list(XATTRS)

    def getxattr(self, url: str, name: str) -> str:
        surl = parse_surl(url)
        if name == "user.replicas":
            if self.options.boolean(GROUP, "XATTR_FAIL_NEARLINE", False):
                self._require_online(surl, "")
            # gfal2 leaves this TURL pinned, so that it stays usable.
            return self._get_turl(surl, self._turl_protocols(), self._timeout())[1]
        if name == "user.status":
            return _locality(self._detail(surl))
        if name == "srm.type":
            backend = self.client.ping(surl)[1].get("backend_type")
            if not backend:
                raise GError("Could not get the storage type", errno.ENODATA)
            return backend
        if name == "spacetoken":
            return json.dumps(self.client.space_tokens(surl), separators=(",", ":"))
        if name.startswith("spacetoken."):
            return self._space_xattr(surl, name[len("spacetoken.") :])
        raise GError("not an existing extended attribute", errno.ENODATA)

    def _space_xattr(self, surl: SURL, which: str) -> str:
        kind, sep, value = which.partition("?")
        if sep and kind == "description":
            tokens = self.client.space_tokens(surl, value)
            spaces = self.client.space_metadata(surl, tokens)
            return "[" + ",".join(_space_json(space) for space in spaces) + "]"
        if sep and kind == "token":
            return _space_json(self.client.space_metadata(surl, [value])[0])
        raise GError(f"Unknown space token attribute {which}", errno.ENODATA)

    def _require_online(self, surl: SURL, prefix: str) -> None:
        """``COPY_FAIL_NEARLINE``/``XATTR_FAIL_NEARLINE``: refuse a file on tape only."""
        if _locality(self._detail(surl)) not in ("ONLINE", "ONLINE_AND_NEARLINE"):
            raise GError(f"{prefix}The source file is not ONLINE", errno.EINVAL)

    # -- tape ------------------------------------------------------------------------

    def bring_online(
        self,
        urls: Sequence[str],
        metadata: Sequence[str],
        pintime: int,
        timeout: int,
        is_async: bool,
    ) -> tuple[list[StagingResult], str]:
        surls = [parse_surl(url) for url in urls]
        token, statuses = self.client.bring_online(
            surls,
            self._turl_protocols(),
            pintime=pintime,
            timeout=timeout,
            wait=None if is_async else float(timeout),
            spacetoken=self.options.string(GROUP, "SPACETOKENDESC", ""),
        )
        return [_staging(found.status, "BringOnline") for found in statuses], token

    def bring_online_poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        surls = [parse_surl(url) for url in urls]
        statuses = self.client.bring_online_status(token, surls)
        return [_staging(found.status, "StatusOfBringOnlineRequest") for found in statuses]

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        if not token:
            # gfal2 will not release without the request's token either.
            error = GError("Invalid value handle, surl or token", errno.EINVAL)
            return [error for _ in urls]
        statuses = self.client.release(token, [parse_surl(url) for url in urls])
        return [_file_failure(found.status, "ReleaseFiles", "release") for found in statuses]

    def abort_bring_online(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``srmAbortFiles``; as in gfal2, only a failure of the request itself counts."""
        self.client.abort_files(token, [parse_surl(url) for url in urls])
        return [None for _ in urls]

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        """Archived means on tape: ``NEARLINE`` or ``ONLINE_AND_NEARLINE``."""
        results: list[StagingResult] = [False] * len(urls)
        for indices, surls in _by_endpoint(urls, results):
            try:
                details = self.client.ls(surls, timeout=self._timeout())
            except GError as exc:
                for index in indices:
                    results[index] = exc
                continue
            for index, surl in zip(indices, surls):
                results[index] = _archived(surl, details)
        return results

    # -- copies ----------------------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        """An SRM end, and at the other a SURL, a local file or a third-party protocol."""
        source_srm = scheme_of(source) == "srm"
        destination_srm = scheme_of(destination) == "srm"
        if not (source_srm or destination_srm):
            return False
        other = scheme_of(destination if source_srm else source)
        return other in ("srm", "file", *self._third_party_protocols())

    def copy(self, transfer: Transfer) -> None:
        source, destination = transfer.source, transfer.destination
        params = transfer.params
        get: tuple[str, SURL] | None = None
        put: tuple[str, SURL] | None = None
        source_turl, destination_turl = source, destination
        protocols = _for_other_end(self._third_party_protocols(), source, destination)
        transfer.event(ev.PREPARE_ENTER)
        try:
            if scheme_of(source) == "srm":
                surl = parse_surl(source)
                if self.options.boolean(GROUP, "COPY_FAIL_NEARLINE", False):
                    self._require_online(surl, "SOURCE SRM_GET_TURL ")
                token, source_turl = self._copy_turl(
                    transfer, surl, protocols, params.src_spacetoken, put=False
                )
                get = (token, surl)
                text = f"Got TURL {source} => {source_turl}"
                transfer.event(GET_EVENT, text, ev.SOURCE, EVENT_DOMAIN)
            if scheme_of(destination) == "srm":
                surl = parse_surl(destination)
                token, destination_turl = self._copy_turl(
                    transfer, surl, protocols, params.dst_spacetoken, put=True
                )
                put = (token, surl)
                text = f"Got TURL {destination} => {destination_turl}"
                transfer.event(PUT_EVENT, text, ev.DESTINATION, EVENT_DOMAIN)
            transfer.event(ev.PREPARE_EXIT)
            run_copy(self.context, _inner(transfer), source_turl, destination_turl)
        except BaseException:
            if put is not None:
                self.client.abort_request(put[1], put[0])
            if get is not None:
                self._release_quietly(*get)
            raise
        transfer.event(CLOSE_ENTER, destination, ev.DESTINATION)
        try:
            if put is not None:
                self._put_done(*put)
        except GError as exc:
            raise _prefixed("DESTINATION SRM_PUTDONE", exc) from exc
        finally:
            if get is not None:
                self._release_quietly(*get)
        transfer.event(CLOSE_EXIT, destination, ev.DESTINATION)

    def _copy_turl(
        self, transfer: Transfer, surl: SURL, protocols: list[str], spacetoken: str, put: bool
    ) -> tuple[str, str]:
        """The TURL of one end of a copy, errors prefixed as gfal2 prefixes them."""
        remaining = transfer.remaining()
        timeout = remaining if remaining is not None else self._timeout()
        try:
            if not put:
                return self._get_turl(surl, protocols, timeout, spacetoken, " ")
            size = 0
            try:
                size = self.context.stat(transfer.source).st_size
            except GError as exc:
                self.log.debug("Fail to stat src to determine file size, error %s", exc)
            return self._put_turl(surl, size, protocols, timeout, spacetoken, " ")
        except GError as exc:
            prefix = "DESTINATION SRM_PUT_TURL" if put else "SOURCE SRM_GET_TURL"
            raise _prefixed(prefix, exc) from exc


def _for_other_end(protocols: list[str], source: str, destination: str) -> list[str]:
    """gfal2's TURL reordering: when the far end speaks HTTPS, ask for https first.

    gfal2 swaps ``https`` with the head of the list (``gsiftp;root;https``
    becomes ``https;root;gsiftp``) so that an SRM can hand out a TURL the
    other end can copy with directly.
    """
    others = [scheme_of(url) for url in (source, destination) if scheme_of(url) != "srm"]
    if any(scheme in ("https", "davs") for scheme in others) and "https" in protocols:
        index = protocols.index("https")
        protocols[0], protocols[index] = protocols[index], protocols[0]
    return protocols


def _by_endpoint(urls: Sequence[str], results: list[Any]) -> list[tuple[list[int], list[SURL]]]:
    """SURLs grouped by endpoint, keeping their indices; bad ones fail in place."""
    groups: dict[tuple[str, int, str], tuple[list[int], list[SURL]]] = {}
    for index, url in enumerate(urls):
        try:
            surl = parse_surl(url)
        except GError as exc:
            results[index] = exc
            continue
        indices, surls = groups.setdefault(surl.key, ([], []))
        indices.append(index)
        surls.append(surl)
    return list(groups.values())


def _turl(found: FileStatus, short: str, protocols: list[str], space: str) -> str:
    """The TURL of a get or put, or its failure in gfal2's words.

    gfal2 words a copy's failure ``error on the turl  request`` (an empty
    ``%s`` between the spaces) and an open's ``error on the turl request``;
    ``space`` carries that difference.
    """
    if not found.status.ok or not found.turl:
        status = found.status
        if status.ok:
            status = Status("SRM_FAILURE", "the server returned no transfer URL")
        error = file_error(short, status)
        raise GError(f"error on the turl {space}request : {error.message} ", error.code)
    if scheme_of(found.turl) not in protocols:
        raise GError(
            f"The SRM endpoint returned a protocol that wasn't requested: {found.turl}",
            errno.EPROTONOSUPPORT,
        )
    return found.turl


def _inner(transfer: Transfer) -> TransferParameters:
    """Parameters for the TURL-to-TURL copy: strict, no clean-up, events forwarded.

    The SRM plugin does what the core would otherwise do around a copy -
    overwrite, parent directories, checksums, clean-up - so the inner copy
    only moves bytes, and reports its progress as the outer copy's.
    """
    params = transfer.params.copy()
    params.strict_copy = True
    params.transfer_cleanup = False
    params.set_checksum(0, "", "")
    left = transfer.remaining()
    params.timeout = max(1, int(left)) if left is not None else 0
    params.monitor_callback = lambda _s, _d, _a, _i, done, _e: transfer.progress(done)
    return params


def _rm_error(status: Status) -> GError | None:
    if status.ok:
        return None
    error = file_error("srmRm", status)
    code = error.code
    if code == errno.EINVAL:
        code = errno.ENOENT  # BeStMan answers EINVAL for a missing file; gfal2 says ENOENT
    return GError(f"error reported from srm_ifce, {error.message}", code)


def _file_failure(status: Status, short: str, what: str) -> GError | None:
    if status.ok:
        return None
    error = file_error(short, status)
    return GError(f"error on the {what} request : {error.message} ", error.code)


def _staging(status: Status, short: str) -> StagingResult:
    if status.ok:
        return True
    if status.pending:
        return False
    error = file_error(short, status)
    return GError(f"error on the bring online request: {error.message} ", error.code)


def _archived(surl: SURL, details: list[Detail]) -> StagingResult:
    """One SURL's archive state from a bulk ``srmLs``."""
    wanted = normalise_path(surl.path)
    found = [item for item in details if normalise_path(item.path) == wanted]
    if not found:
        return GError(f"File {surl.url} is not yet archived", errno.EAGAIN)
    if not found[0].status.ok:
        return _stat_error(found[0].status)
    return "NEARLINE" in found[0].locality
