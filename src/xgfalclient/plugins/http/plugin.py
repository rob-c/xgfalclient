"""``HTTPPlugin``: gfal2's http plugin (davix) for HTTP, WebDAV, S3, GCS, Swift and CS3.

The namespace is WebDAV, request for request as davix sends it:

==========  ==================================================================
``stat``    ``PROPFIND`` ``Depth: 0``; for ``http(s)://`` a ``HEAD`` if that fails
``mkdir``   ``MKCOL`` (``405`` is ``EEXIST``, ``409`` a missing parent)
``rmdir``   ``PROPFIND`` to see it is a collection, then ``DELETE`` of ``dir/``
``unlink``  ``PROPFIND`` to see it is not a collection, then ``DELETE``;
            for ``http(s)://`` (davix's plain-HTTP mode) the ``DELETE`` alone
``rename``  ``MOVE`` with a ``Destination``
``listdir`` ``PROPFIND`` ``Depth: 1``, less the collection's own entry
checksum    ``HEAD`` with ``Want-Digest`` (RFC 3230)
==========  ==================================================================

``chmod`` is not implemented, so it fails with ``EPROTONOSUPPORT`` as it does
in gfal2, and so do extended attributes and tape calls on anything but
``http``, ``https``, ``dav`` and ``davs`` (gfal2's ``check_url``). Errors
are worded, and numbered, as davix and gfal2 word and number them
(:func:`~._client.status_error`): ``stat`` adds davix's ``Result ... after
1 attempts`` to anything but a refusal, and ``mkdir``, ``unlink``,
``rename`` and ``rmdir`` add `` with url <url>`` to anything but a 401 or
a 403, which davix raises before it looks at the answer.

``s3://`` and ``gcloud://`` URLs are object stores (:mod:`._s3`,
:mod:`._gcloud`), and so are ``swift://`` ones (:mod:`._swift`). ``cs3://``
(Reva) is plain HTTP with ``[BEARER] TOKEN``: its ``stat`` is a ``HEAD``,
like the fallback for ``http://``, which davix answers with mode ``0755``,
the size, and no times.

Where this differs from gfal2, deliberately:

* a refused connection is ``ECONNREFUSED`` (davix's ``ConnectionProblem``
  becomes ``EHOSTDOWN`` in gfal2), with davix's words for it;
* a checksum the ``HEAD`` did not carry is asked for once more with a
  one-byte ``GET``, which some servers need before they compute one, and
  a hex digest where RFC 3230 wants base64 is read as hex (davix decodes it
  as base64 and reports garbage);
* ``open`` for reading *and* writing is ``ENOTSUP``: an HTTP object cannot
  be both at once (davix lets the open through and fails later);
* a ``token_retrieve`` or TPC token is not fetched before every other HTTPS
  operation the way gfal2 does with ``RETRIEVE_BEARER_TOKEN`` (a macaroon
  ``POST`` ahead of each ``PROPFIND``): the X.509 proxy that would ask for
  it authenticates the operation just as well;
* ``[HTTP PLUGIN] METALINK`` is not read (there is no Metalink support), nor
  are davix's ``LOG_LEVEL``, ``LOG_SENSITIVE`` and ``LOG_CONTENT``: the plugin's
  diagnostics go to the ``gfal2`` logger instead;
* ``User-Agent`` is the context's (``<agent>/<version> gfal2/2.23.5``),
  without the `` neon/0.0.29`` that davix's HTTP library appends.

Tape (the WLCG Tape REST API), tokens, copies and QoS live in their own
modules; this class is the dispatch surface gfal2's API lands on.
"""

from __future__ import annotations

import base64
import binascii
import errno
import logging
import posixpath
import re
import stat as _stat
import string
import time
import urllib.parse
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING

from ...errors import GError
from ...plugin import O_ACCMODE_MASK, O_RDONLY, O_WRONLY, Plugin, PluginFile, StagingResult
from ...types import Stat
from ...url import URL, parent, parse, scheme_of
from . import _copy, _gcloud, _qos, _s3, _swift, _token
from ._client import (
    MKDIR,
    Auth,
    FileBody,
    HTTPClient,
    HTTPStatusError,
    Response,
    Signer,
    status_error,
    valid_authority,
    wire_url,
)
from ._dav import (
    PROPFIND_BODY,
    digest_value,
    parse_multistatus,
    same_path,
)
from ._io import HTTPReadFile, HTTPWriteFile, check_upload
from ._tape import TAPE_XATTRS, TapeREST

if TYPE_CHECKING:
    from ...context import Gfal2Context
    from ...transfer import Transfer

__all__ = ["HTTPPlugin"]

_log = logging.getLogger("gfal2")

#: The schemes gfal2's ``check_url`` allows xattrs and tape calls on.
TAPE_SCHEMES = frozenset({"http", "https", "dav", "davs"})
#: Operations limited to :data:`TAPE_SCHEMES`.
TAPE_OPERATIONS = frozenset(
    {
        "getxattr",
        "setxattr",
        "listxattr",
        "bring_online",
        "bring_online_poll",
        "release",
        "abort_bring_online",
        "archive_poll",
    }
)
#: What davix splits an ``ETag`` on, looking for an MD5 in it.
_ETAG_SPLIT = re.compile(r"[&;\\/\"']")
#: What davix makes of a file it only knows from a ``HEAD``.
HEAD_MODE = _stat.S_IFREG | 0o755


def _result(exc: GError, prefix: str = "") -> GError:
    """davix's wording for a failed ``stat``: ``Result <why> after 1 attempts``.

    davix's retry layer says so about everything but a refusal (403, 405,
    423), which it gives up on at once.
    """
    if exc.code != errno.EPERM:
        return GError(f"{prefix}Result {exc.message} after 1 attempts", exc.code)
    if prefix:
        return GError(f"{prefix}{exc.message}", exc.code)
    return exc


def _decorated(status: int, url: str, *, prefix: str = "", scope: str = "") -> HTTPStatusError:
    """A failed ``DELETE``/``MKCOL``/``MOVE``: `` with url <url>``, but not for 401 or 403."""
    suffix = "" if status in (401, 403) else f" with url {url}"
    return status_error(status, prefix=prefix, suffix=suffix, scope=scope)


def _collection(url: str) -> str:
    """``url`` with a trailing slash on its path, as davix addresses a directory."""
    parsed = parse(url)
    path = parsed.path or "/"
    return str(parsed.with_path(path if path.endswith("/") else path + "/"))


def _kind(url: str) -> str:
    """``s3`` (S3 and GCS), ``swift``, ``cs3``, or ``dav`` for everything WebDAV."""
    scheme = scheme_of(url).partition("+")[0]
    if scheme in ("s3", "s3s", "gcloud", "gclouds"):
        return "s3"
    if scheme in ("swift", "swifts"):
        return "swift"
    if scheme in ("cs3", "cs3s"):
        return "cs3"
    return "dav"


class HTTPPlugin(Plugin):
    """The ``http`` plugin."""

    name = "http"
    schemes = (
        "http",
        "https",
        "dav",
        "davs",
        "s3",
        "s3s",
        "http+3rd",
        "https+3rd",
        "dav+3rd",
        "davs+3rd",
        "gcloud",
        "gclouds",
        "swift",
        "swifts",
        "cs3",
        "cs3s",
    )
    option_group = "HTTP PLUGIN"
    priority = 100
    event_domain = "http_plugin"
    narrates_transfer = True
    # gfal2's http plugin checks checksums, the existing destination and its
    # parent itself, inside PREPARE; a download keeps the core's steps (_copy).
    copy_manages_destination = True
    copy_manages_checksums = True

    def __init__(self, context: Gfal2Context) -> None:
        super().__init__(context)
        self.client = HTTPClient(context, self.option_group)
        self.client.signer_for = self._signer
        self.tape = TapeREST(self)
        self._gcloud = _gcloud.KeyCache()

    def close(self) -> None:
        self.client.close()

    def handles(self, url: str, operation: str) -> bool:
        if operation in TAPE_OPERATIONS:
            return scheme_of(url) in TAPE_SCHEMES
        return super().handles(url, operation)

    # -- plumbing ------------------------------------------------------------------

    def io_timeout(self) -> float:
        return float(self.option_timeout())

    def conn_retry(self) -> int:
        """How many times a dropped transfer is reconnected, as gfal2's ``CONN_RETRY``.

        A read cut short by a flaky link is resumed with a ranged GET up to
        this many times before it gives up; gfal2's default is 3.
        """
        return max(0, int(self.options.integer("CORE", "CONN_RETRY", 3)))

    def retry_pause(self, attempts: int) -> None:
        """Wait before the next reconnect, as gfal2's ``CONN_RETRY_INTERVAL`` does."""
        interval = self.options.integer("CORE", "CONN_RETRY_INTERVAL", 0)
        if interval > 0:
            time.sleep(min(interval, interval * attempts))

    def checksum_timeout(self) -> float:
        return float(self.options.integer("CORE", "CHECKSUM_TIMEOUT", 1800))

    def _signer(self, url: URL) -> Signer | None:
        if _swift.is_swift(url.scheme):
            return _swift.SwiftSigner(_swift.swift_keys(self.options, url))
        return self.presigner_for(str(url))

    def presigner_for(self, url: str) -> Signer | None:
        """What signs requests for (and pre-signs) an S3 or GCS ``url``, if it has keys."""
        parsed = parse(url)
        if _gcloud.is_gcloud(parsed.scheme):
            found = self._gcloud.get(self.options)
            return _gcloud.GCloudSigner(found) if found is not None else None
        keys = _s3.s3_keys(self.options, parsed) if _s3.is_s3(parsed) else None
        return _s3.S3Signer(keys) if keys is not None else None

    def _s3(self, url: str) -> bool:
        """Whether ``url`` is an S3 or GCS object store."""
        return _kind(url) == "s3"

    def _multipart(self, url: str) -> bool:
        """Whether a large upload to ``url`` must go in parts (S3, not GCS)."""
        return _s3.is_s3(parse(url))

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | FileBody | None = None,
        timeout: float | None = None,
        cred_url: str | None = None,
        x509_only: bool = False,
    ) -> Response:
        auth = None
        if x509_only:
            auth = Auth(tls=self.client.tls(cred_url or url))
        return self.client.request(
            method,
            url,
            headers=headers,
            body=body,
            timeout=self.io_timeout() if timeout is None else timeout,
            cred_url=cred_url,
            auth=auth,
        )

    def _get(self, url: str, headers: dict[str, str], timeout: float | None = None) -> Response:
        """A ``GET`` that answered with a body (or ``416`` past the end); else raises."""
        response = self._request("GET", url, headers=headers, timeout=timeout)
        if response.status not in (200, 206, 416):
            response.close()
            raise status_error(response.status)
        return response

    def _put_file(
        self,
        url: str,
        body: FileBody,
        size: int,
        timeout: float | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        if size > _s3.MULTIPART_THRESHOLD and self._multipart(url):
            _s3.upload_file(self, url, body)
            return
        check_upload(self._request("PUT", url, body=body, timeout=timeout, headers=headers))

    # -- stat ----------------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        try:
            return self._stat(url)
        except GError as exc:
            raise _result(exc) from None

    def _stat(self, url: str) -> Stat:
        kind = _kind(url)
        if kind == "s3":
            return _s3.stat(self, url)
        if kind == "swift":
            return _swift.stat(self, url)
        if kind == "cs3":
            return self._head_stat(url)
        if scheme_of(url).startswith("http"):
            try:
                return self._propfind_stat(url)
            except GError as exc:
                _log.debug("Stat over WebDav failed with error: %s. Will fallback to HTTP", exc)
                return self._head_stat(url)
        return self._propfind_stat(url)

    def _propfind_stat(self, url: str) -> Stat:
        response = self._request("PROPFIND", url, headers={"Depth": "0"})
        payload = response.body()
        if response.status not in (200, 207):
            raise status_error(response.status)
        entries = parse_multistatus(payload)
        if not entries:
            raise GError("Parsing Error: properties number < 1", errno.EIO)
        return entries[0][1]

    def _head_stat(self, url: str) -> Stat:
        """davix's plain-HTTP ``stat``: a regular file, ``0755``, its size, and no times."""
        response = self._request("HEAD", url)
        response.close()
        if response.status >= 300:
            raise status_error(response.status)
        return Stat(st_mode=HEAD_MODE, st_size=response.length or 0)

    # -- namespace -----------------------------------------------------------------

    def mkdir(self, url: str, mode: int) -> None:
        if _kind(url) in ("s3", "swift"):
            _swift.mkdir(self, url)
            return
        response = self._request("MKCOL", url)
        response.body()
        if response.status not in (200, 201, 204):
            raise _decorated(response.status, url, scope=MKDIR)

    def mkdir_rec(self, url: str, mode: int) -> None:
        """One ``MKCOL`` when that is enough (XrdHttp makes parents); else walk up."""
        if _kind(url) in ("s3", "swift"):
            self.mkdir(url, mode)  # a marker object needs no parents
            return
        try:
            self.mkdir(url, mode)
            return
        except GError as exc:
            if exc.code == errno.EEXIST:
                # Whatever is there - a file included - is done, as gfal2's core has it.
                return
            up = parent(url)
            if exc.code != errno.ENOENT or up == url:
                raise
        self.mkdir_rec(up, mode)
        try:
            self.mkdir(url, mode)
        except GError as exc:
            if exc.code != errno.EEXIST:
                raise

    def rmdir(self, url: str) -> None:
        info = self.stat(url)
        if not info.is_dir():
            raise GError("Can not rmdir a file", errno.ENOTDIR)
        if self._s3(url):
            return  # a prefix goes when what is under it does
        target = _collection(url)
        response = self._request("DELETE", target)
        response.body()
        if response.status not in (200, 202, 204):
            raise _decorated(response.status, target, prefix="DavPosix::rmdir  ")

    def unlink(self, url: str) -> None:
        prefix = "DavPosix::unlink  "
        if not valid_authority(parse(url).netloc):
            raise _result(GError(f" {url} is not a valid HTTP or Webdav URL", errno.EIO), prefix)
        # davix's plain-HTTP mode (http, https) has no POSIX semantics: the DELETE
        # alone, no PROPFIND first - Rucio rewrites davs:// to https:// to save it.
        if scheme_of(url).partition("+")[0] not in ("http", "https"):
            try:
                info = self._stat(url)
            except GError as exc:
                raise _result(exc, prefix) from None
            if info.is_dir():
                raise GError(
                    f"{prefix} {url} is a directory, impossible to unlink\\n", errno.EISDIR
                )
        try:
            response = self._request("DELETE", url)
        except GError as exc:  # the network's failure, in davix's unlink scope
            raise GError(f"{prefix}{exc.message}", exc.code) from None
        response.body()
        if response.status not in (200, 202, 204):
            raise _decorated(response.status, url, prefix=prefix)

    def rename(self, old: str, new: str) -> None:
        kind = _kind(old)
        if kind == "s3":
            _s3.rename(self, old, new)
            return
        if kind == "swift":
            _swift.rename_swift(self, old, new)
            return
        response = self._request("MOVE", old, headers={"Destination": wire_url(new)})
        response.body()
        if response.status not in (200, 201, 204):
            raise _decorated(response.status, old)

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        return iter(self._list(url))

    def listdir(self, url: str) -> list[str]:
        return [name for name, _ in self._list(url)]

    def _list(self, url: str) -> list[tuple[str, Stat | None]]:
        kind = _kind(url)
        if kind == "s3":
            return self._s3_list(url)
        if kind == "swift":
            return _swift.list_objects(self, url)
        response = self._request(
            "PROPFIND",
            url,
            headers={"Depth": "1", "Content-Type": 'text/xml; charset="utf-8"'},
            body=PROPFIND_BODY,
        )
        payload = response.body()
        if response.status not in (200, 207):
            raise status_error(response.status)
        entries = parse_multistatus(payload)
        own = urllib.parse.unquote(parse(url).path)
        mine = next((i for i, (path, _) in enumerate(entries) if same_path(path, own)), 0)
        if entries and not entries[mine][1].is_dir():
            raise GError(f"{url} is not a collection, listing impossible", errno.ENOTDIR)
        found: list[tuple[str, Stat | None]] = []
        for index, (path, info) in enumerate(entries):
            name = posixpath.basename(path.rstrip("/"))
            if index != mine and name:
                found.append((name, info))
        return found

    def _s3_list(self, url: str) -> list[tuple[str, Stat | None]]:
        entries: list[tuple[str, Stat | None]] = list(_s3.list_objects(self, url))
        _, key = _s3.split(self, url)
        # Nothing under the prefix: ENOENT from the stat for nothing there at all.
        if not entries and key.strip("/") and self._stat(url).is_file():
            raise GError(f"{url} is not a collection, listing impossible", errno.ENOTDIR)
        return entries

    # -- I/O -------------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        if not valid_authority(parse(url).netloc):
            raise GError(" Uri invalid in Davix::Open", errno.EIO)
        access = flags & O_ACCMODE_MASK
        if access == O_RDONLY:
            info = self.stat(url)
            if info.is_dir():
                raise GError(f"{url} is a directory", errno.EISDIR)
            return HTTPReadFile(self, url, info.st_size)
        if access == O_WRONLY:
            if size is not None and size > _s3.MULTIPART_THRESHOLD and self._multipart(url):
                return _s3.S3PartWriter(self, url)
            return HTTPWriteFile(self, url, size)
        raise GError("HTTP files cannot be open for reading and writing at once", errno.ENOTSUP)

    # -- metadata ----------------------------------------------------------------------

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        if offset or length:
            raise GError("HTTP does not support partial checksums", errno.ENOTSUP)
        if self._s3(url):
            return _s3.checksum(self, url, algorithm)
        timeout = self.checksum_timeout()
        want = {"Want-Digest": algorithm}
        response = self._request("HEAD", url, headers=want, timeout=timeout)
        response.close()
        if response.status >= 300:
            raise status_error(response.status)
        md5 = algorithm.strip().lower() == "md5"
        value = _content_md5(response.header("Content-MD5")) if md5 else ""
        value = value or digest_value(response.header("Digest"), algorithm)
        if not value and md5:
            value = _etag_md5(response.header("ETag"))
        if not value:
            # Some servers only compute a digest for a GET; one byte of it will do.
            probe = self._request(
                "GET", url, headers={**want, "Range": "bytes=0-0"}, timeout=timeout
            )
            probe.close()
            if probe.status in (200, 206):
                value = digest_value(probe.header("Digest"), algorithm)
        if not value:
            raise GError(
                f"checksum calculation for {algorithm} not supported for {url}", errno.ENOSYS
            )
        return value

    def getxattr(self, url: str, name: str) -> str:
        if name == "user.status":
            return self.tape.status(url)
        if name in TAPE_XATTRS:
            return self.tape.xattr(url, name)
        raise GError(f'Failed to get the xattr "{name}" (No data available)', errno.ENODATA)

    def listxattr(self, url: str) -> list[str]:
        return list(TAPE_XATTRS)

    def setxattr(self, url: str, name: str, value: str, flags: int) -> None:
        raise GError("Can not set extended attributes", errno.ENOSYS)

    # -- tape --------------------------------------------------------------------------

    def bring_online(
        self,
        urls: Sequence[str],
        metadata: Sequence[str],
        pintime: int,
        timeout: int,
        is_async: bool,
    ) -> tuple[list[StagingResult], str]:
        return self.tape.bring_online(urls, metadata)

    def bring_online_poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        return self.tape.poll(urls, token)

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        return self.tape.release(urls, token)

    def abort_bring_online(self, urls: Sequence[str], token: str) -> list[GError | None]:
        return self.tape.abort(urls, token)

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        return self.tape.archive_poll(urls)

    # -- QoS -----------------------------------------------------------------------------

    def check_file_qos(self, url: str) -> str:
        return _qos.check_file_qos(self, url)

    def check_available_qos_transitions(self, url: str) -> list[str]:
        return _qos.check_available_qos_transitions(self, url)

    def check_target_qos(self, url: str) -> str:
        return _qos.check_target_qos(self, url)

    def change_object_qos(self, url: str, target: str) -> None:
        _qos.change_object_qos(self, url, target)

    def qos_check_classes(self, url: str, kind: str) -> list[str]:
        return _qos.qos_check_classes(self, url, kind)

    # -- tokens --------------------------------------------------------------------------

    def token_retrieve(
        self, url: str, issuer: str, validity: int, write_access: bool, activities: list[str]
    ) -> str:
        return _token.retrieve(self, url, issuer, validity, write_access, activities)

    # -- copies --------------------------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        """gfal2's claim: an HTTP destination (no ``+3rd``) from HTTP or ``file://``.

        Unlike gfal2 it also takes HTTP to ``file://``, for the parallel
        ranged download (:mod:`._copy`); a ``+3rd`` URL is left to the core's
        streamed copy, as gfal2 leaves it.
        """
        src, dst = _copy.is_http_scheme(source), _copy.is_http_scheme(destination)
        if dst:
            return src or source.startswith("file://")
        return src and destination.startswith("file:///")

    def copy(self, transfer: Transfer) -> None:
        _copy.copy(self, transfer)


def _content_md5(value: str) -> str:
    """RFC 1864's ``Content-MD5`` (bare base64) as hex."""
    if not value.strip():
        return ""
    try:
        return base64.b64decode(value.strip(), validate=True).hex()
    except (binascii.Error, ValueError):
        return ""


def _etag_md5(etag: str) -> str:
    """The first 32-hex-digit token of an ``ETag``: davix's last resort for MD5 (S3's ETag)."""
    for token in _ETAG_SPLIT.split(etag):
        if len(token) == 32 and all(char in string.hexdigits for char in token):
            return token
    return ""
