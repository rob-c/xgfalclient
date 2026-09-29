"""``HTTPPlugin``: gfal2's http plugin (davix) for ``http``, ``https``, ``dav``, ``davs``, ``s3``.

The namespace is WebDAV, request for request as davix sends it:

==========  ==================================================================
``stat``    ``PROPFIND`` ``Depth: 0``; for ``http(s)://`` a ``HEAD`` if that fails
``mkdir``   ``MKCOL`` (``405`` is ``EEXIST``, ``409`` a missing parent)
``rmdir``   ``PROPFIND`` to see it is a collection, then ``DELETE`` of ``dir/``
``unlink``  ``PROPFIND`` to see it is not a collection, then ``DELETE``
``rename``  ``MOVE`` with a ``Destination``
``listdir`` ``PROPFIND`` ``Depth: 1``, less the collection's own entry
checksum    ``HEAD`` with ``Want-Digest`` (RFC 3230), then a one-byte ``GET``
==========  ==================================================================

``chmod`` is not implemented, so it fails with ``EPROTONOSUPPORT`` as it does
in gfal2. Error messages are davix's (``Result HTTP 404 : File not found
after 1 attempts``) and so are the errno values, including ``EPERM`` for
403. ``s3://`` URLs, and ``https://`` ones on a host with ``[S3:<HOST>]``
keys, are S3 instead (:mod:`._s3`).

Tape (the WLCG Tape REST API), tokens, copies and QoS live in their own
modules; this class is the dispatch surface gfal2's API lands on.
"""

from __future__ import annotations

import base64
import binascii
import errno
import logging
import posixpath
import urllib.parse
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING

from ...errors import GError, unsupported
from ...plugin import O_ACCMODE_MASK, O_RDONLY, O_WRONLY, Plugin, PluginFile, StagingResult
from ...types import Stat
from ...url import URL, parent, parse, scheme_of
from . import _copy, _gcloud, _qos, _s3, _token
from ._client import (
    Auth,
    FileBody,
    HTTPClient,
    HTTPStatusError,
    Response,
    Signer,
    TransportError,
    status_error,
    wire_url,
)
from ._dav import (
    FILE_MODE,
    PROPFIND_BODY,
    digest_value,
    epoch,
    parse_multistatus,
    same_path,
    want_digest,
)
from ._io import HTTPReadFile, HTTPWriteFile, check_upload
from ._tape import TAPE_XATTRS, TapeREST

if TYPE_CHECKING:
    from ...context import Gfal2Context
    from ...transfer import Transfer

__all__ = ["HTTPPlugin"]

_log = logging.getLogger("xgfalclient.plugins.http")


def _result(exc: GError, prefix: str = "") -> GError:
    """davix's wording for a failed ``stat``: ``Result <why> after 1 attempts``.

    davix retries a 404 and a connection failure, and says so; any other
    status it reports as it came.
    """
    if isinstance(exc, TransportError) or (isinstance(exc, HTTPStatusError) and exc.status == 404):
        return GError(f"{prefix}Result {exc.message} after 1 attempts", exc.code)
    if prefix:
        return GError(f"{prefix}{exc.message}", exc.code)
    return exc


def _collection(url: str) -> str:
    """``url`` with a trailing slash on its path, as davix addresses a directory."""
    parsed = parse(url)
    path = parsed.path or "/"
    return str(parsed.with_path(path if path.endswith("/") else path + "/"))


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
    )
    option_group = "HTTP PLUGIN"
    priority = 100
    event_domain = "http_plugin"

    def __init__(self, context: Gfal2Context) -> None:
        super().__init__(context)
        self.client = HTTPClient(context, self.option_group)
        self.client.signer_for = self._signer
        self.tape = TapeREST(self)
        self._gcloud = _gcloud.KeyCache()

    def close(self) -> None:
        self.client.close()

    # -- plumbing ------------------------------------------------------------------

    def io_timeout(self) -> float:
        return float(self.option_timeout())

    def checksum_timeout(self) -> float:
        return float(self.options.integer("CORE", "CHECKSUM_TIMEOUT", 1800))

    def _signer(self, url: URL) -> Signer | None:
        if _gcloud.is_gcloud(url.scheme):
            found = self._gcloud.get(self.options)
            return _gcloud.GCloudSigner(found) if found is not None else None
        keys = _s3.s3_keys(self.options, url)
        return _s3.S3Signer(keys) if keys is not None else None

    def signer_for(self, url: str) -> Signer | None:
        return self._signer(parse(url))

    def _s3(self, url: str) -> bool:
        """Whether ``url`` is an object store (S3 or GCS) rather than WebDAV."""
        parsed = parse(url)
        return (
            _s3.is_s3(parsed)
            or _gcloud.is_gcloud(parsed.scheme)
            or _s3.s3_keys(self.options, parsed) is not None
        )

    def _multipart(self, url: str) -> bool:
        """Whether a large upload to ``url`` must go in parts (S3, not GCS)."""
        return self._s3(url) and not _gcloud.is_gcloud(scheme_of(url))

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
            auth = Auth(tls=self.context.ssl_context(cred_url or url, group=self.option_group))
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
            raise status_error(response.status, response.reason)
        return response

    def _put_file(self, url: str, body: FileBody, size: int, timeout: float | None = None) -> None:
        if size > _s3.MULTIPART_THRESHOLD and self._multipart(url):
            _s3.upload_file(self, url, body)
            return
        check_upload(self._request("PUT", url, body=body, timeout=timeout))

    # -- stat ----------------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        try:
            return self._stat(url)
        except GError as exc:
            raise _result(exc) from None

    def _stat(self, url: str) -> Stat:
        if self._s3(url):
            return _s3.stat(self, url)
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
            raise status_error(response.status, response.reason)
        entries = parse_multistatus(payload)
        if not entries:
            raise GError(f"The PROPFIND response for {url} has no entries", errno.EPROTO)
        return entries[0][1]

    def _head_stat(self, url: str) -> Stat:
        response = self._request("HEAD", url)
        response.close()
        if response.status != 200:
            raise status_error(response.status, response.reason)
        return Stat(
            st_mode=FILE_MODE,
            st_size=response.length or 0,
            st_mtime=epoch(response.header("Last-Modified")),
        )

    # -- namespace -----------------------------------------------------------------

    def mkdir(self, url: str, mode: int) -> None:
        if self._s3(url):
            return  # S3 has no directories to make
        response = self._request("MKCOL", url)
        response.body()
        if response.status in (200, 201, 204):
            return
        suffix = f" with url {url}"
        if response.status == 405:
            raise status_error(
                405, phrase="Method Not Allowed, File Exist", suffix=suffix, code=errno.EEXIST
            )
        if response.status == 409:
            raise status_error(409, phrase="Conflict", suffix=suffix, code=errno.ENOENT)
        raise status_error(response.status, response.reason)

    def mkdir_rec(self, url: str, mode: int) -> None:
        """One ``MKCOL`` when that is enough (XrdHttp makes parents); else walk up."""
        if self._s3(url):
            return
        try:
            self.mkdir(url, mode)
            return
        except GError as exc:
            if exc.code == errno.EEXIST:
                if self.stat(url).is_dir():
                    return
                raise GError(f"{url} exists and is not a directory", errno.ENOTDIR) from None
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
        if response.status in (200, 202, 204):
            return
        prefix = "DavPosix::rmdir  "
        if response.status == 409:
            raise status_error(
                409,
                phrase="Conflict, File Exist",
                prefix=prefix,
                suffix=f" with url {target}",
                code=errno.EEXIST,
            )
        raise status_error(response.status, response.reason, prefix=prefix)

    def unlink(self, url: str) -> None:
        prefix = "DavPosix::unlink  "
        try:
            info = self._stat(url)
        except GError as exc:
            raise _result(exc, prefix) from None
        if info.is_dir():
            raise GError(f"{prefix} {url} is a directory, impossible to unlink", errno.EISDIR)
        response = self._request("DELETE", url)
        response.body()
        if response.status not in (200, 202, 204):
            raise status_error(response.status, response.reason, prefix=prefix)

    def rename(self, old: str, new: str) -> None:
        if self._s3(old):
            raise unsupported("rename", old)
        response = self._request("MOVE", old, headers={"Destination": wire_url(new)})
        response.body()
        if response.status not in (200, 201, 204):
            raise status_error(response.status, response.reason, suffix=f" with url {old}")

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        return iter(self._list(url))

    def listdir(self, url: str) -> list[str]:
        return [name for name, _ in self._list(url)]

    def _list(self, url: str) -> list[tuple[str, Stat | None]]:
        if self._s3(url):
            return self._s3_list(url)
        response = self._request(
            "PROPFIND",
            url,
            headers={"Depth": "1", "Content-Type": 'text/xml; charset="utf-8"'},
            body=PROPFIND_BODY,
        )
        payload = response.body()
        if response.status not in (200, 207):
            raise status_error(response.status, response.reason)
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
        want = {"Want-Digest": want_digest(algorithm)}
        response = self._request("HEAD", url, headers=want, timeout=timeout)
        response.close()
        if response.status != 200:
            raise status_error(response.status, response.reason)
        value = digest_value(response.header("Digest"), algorithm)
        if not value and algorithm.strip().lower() == "md5":
            value = _content_md5(response.header("Content-MD5"))
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
        return self.tape.bring_online(urls, metadata, timeout, is_async)

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
        """Every pair with an HTTP end: TPC, uploads, and parallel downloads."""
        mine = set(self.schemes)
        src, dst = scheme_of(source), scheme_of(destination)
        if src in mine:
            return dst in mine or destination.startswith("file:///")
        return dst in mine and source.startswith("file:///")

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
