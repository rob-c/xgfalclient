"""S3: AWS Signature Version 4, listings, and multipart uploads.

gfal2 reaches S3 through davix with ``s3://`` and ``s3s://`` URLs. The keys
come from three groups, most specific first, each setting found on its own
(``ACCESS_KEY``/``SECRET_KEY`` as a pair, ``TOKEN``, ``REGION``,
``ALTERNATE``): ``[S3:<HOST>]``, ``[S3:<HOST less its first label>]`` - the
endpoint of a virtual-host bucket - and ``[S3]``. The old names
``ACCESS_TOKEN``/``ACCESS_TOKEN_SECRET`` still work. ``ALTERNATE=true``
selects path-style addressing (``s3://host/bucket/key``) over the default
virtual-host style (``s3://bucket.host/key``); it matters here only for
listings and renames, which must know where the bucket ends and the key
begins. Keys never make an ``https://`` URL an S3 one: gfal2 sends those
unsigned, as WebDAV.

Every request is signed with SigV4 through botocore.
davix falls back to the older SigV2 when no region is configured; this does
not - SigV2 is retired at AWS and every S3 implementation that matters takes
V4 - and signs for ``us-east-1`` instead, which is what they all accept.
The signature travels in an ``Authorization`` header; davix puts it in the
query string (``X-Amz-Signature=...``), which S3 accepts just the same.

S3 has no directories. As in davix, ``mkdir`` puts an empty ``<key>/``
marker object, a "directory" is a key prefix that something lives under,
modes are ``0755``, a listing is ``ListObjectsV2`` with ``/`` as the
delimiter, and a rename is a server-side copy (``x-amz-copy-source``) and a
delete.
"""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from botocore.auth import S3SigV4QueryAuth  # type: ignore[import-untyped]
from botocore.awsrequest import AWSRequest  # type: ignore[import-untyped]
from botocore.credentials import Credentials as AWSCredentials  # type: ignore[import-untyped]
from xrdclient._xml import UnsafeXML
from xrdclient.s3._codec import decode, listing_items, manifest, modified
from xrdclient.s3.sigv4 import _authorize, _signed_request

from ...errors import GError
from ...plugin import PluginFile
from ...types import Stat
from ...url import URL, parse
from . import _swift
from ._client import Body, FileBody, Target, status_error
from ._dav import epoch
from ._gcloud import is_gcloud

if TYPE_CHECKING:
    from ...options import Options
    from .plugin import HTTPPlugin

__all__ = [
    "S3Keys",
    "S3Signer",
    "S3PartWriter",
    "s3_keys",
    "is_s3",
]

ALGORITHM = "AWS4-HMAC-SHA256"
UNSIGNED = "UNSIGNED-PAYLOAD"
DEFAULT_REGION = "us-east-1"
#: Above this, an upload is sent in parts; S3 refuses a single PUT over 5 GiB.
MULTIPART_THRESHOLD = 1 << 30
#: Part size for multipart uploads (S3's minimum is 5 MiB).
PART_SIZE = 64 << 20
#: An object's and a prefix's mode, as davix reports them.
OBJECT_FILE_MODE = _swift.FILE_MODE
OBJECT_DIR_MODE = _swift.DIR_MODE


@dataclass(frozen=True)
class S3Keys:
    access_key: str
    secret_key: str
    token: str
    region: str

    def __repr__(self) -> str:
        return f"S3Keys({self.access_key!r}, secret_key=<redacted>, region={self.region!r})"


def is_s3(url: URL) -> bool:
    return url.scheme.partition("+")[0] in ("s3", "s3s")


def _groups(url: URL) -> list[str]:
    """``S3:HOST``, ``S3:<host minus the bucket label>``, ``S3`` - davix's search order."""
    host = url.host.upper()
    groups = [f"S3:{host}"]
    if "." in host:
        groups.append(f"S3:{host.partition('.')[2]}")
    return [*groups, "S3"]


def s3_keys(options: Options, url: URL) -> S3Keys | None:
    """The keys for ``url``, each setting from the most specific group that has it.

    A group's pair counts only when both halves are there (else its legacy
    ``ACCESS_TOKEN``/``ACCESS_TOKEN_SECRET``); ``TOKEN`` and ``REGION`` are
    looked up on their own, so they may come from a broader group.
    """
    access = secret = token = region = ""
    for group in _groups(url):
        if not (access and secret):
            access = options.string(group, "ACCESS_KEY") or access
            secret = options.string(group, "SECRET_KEY") or secret
            if not (access and secret):
                access = options.string(group, "ACCESS_TOKEN")
                secret = options.string(group, "ACCESS_TOKEN_SECRET")
        token = token or options.string(group, "TOKEN")
        region = region or options.string(group, "REGION")
    if not (access and secret):
        return None
    return S3Keys(access, secret, token, region or DEFAULT_REGION)


def _alternate(options: Options, group: str) -> bool | None:
    try:
        return bool(options.get_boolean(group, "ALTERNATE"))
    except GError:
        return None  # unset, or not a boolean


def path_style(options: Options, url: URL) -> bool:
    """``ALTERNATE`` from the first group that sets it (validly)."""
    found = (_alternate(options, group) for group in _groups(url))
    return next((value for value in found if value is not None), False)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


class S3Signer:
    """Thin botocore adapter retaining GFAL's credential and target policy."""

    def __init__(self, keys: S3Keys) -> None:
        self.keys = keys

    def _credentials(self) -> AWSCredentials:
        return AWSCredentials(self.keys.access_key, self.keys.secret_key, self.keys.token or None)

    def target(self, method: str, target: Target) -> Target:
        return target

    def sign(
        self,
        method: str,
        target: Target,
        headers: Mapping[str, str],
        body: Body | None,
        when: datetime | None = None,
    ) -> dict[str, str]:
        if isinstance(body, FileBody):
            payload = UNSIGNED
        else:
            payload = hashlib.sha256(body or b"").hexdigest()
        signed = _signed_request(
            method,
            f"{target.base}{target.path}",
            target.host_header,
            headers,
            payload,
            credentials=self._credentials(),
            region=self.keys.region,
            when=when,
        )
        return {k: v for k, v in signed.items() if k.lower() != "host"}

    def presign(
        self, method: str, url: str, expires: int = 3600, when: datetime | None = None
    ) -> str:
        target = Target.of(url, s3=True)
        request = AWSRequest(
            method=method.upper(),
            url=f"{target.base}{target.path}",
            headers={"host": target.host_header},
        )
        auth = S3SigV4QueryAuth(self._credentials(), "s3", self.keys.region, expires=expires)
        _authorize(auth, request, when)
        return str(request.url)


# ---------------------------------------------------------------------------
# Namespace
# ---------------------------------------------------------------------------


def _answer(payload: bytes, operation: str, what: str = "S3 response") -> dict[str, Any]:
    try:
        return decode(operation, payload, lenient=True)
    except UnsafeXML as exc:
        raise GError(f"Refusing a {what} with a document type declaration", errno.EIO) from exc
    except ET.ParseError as exc:
        raise GError(f"XML Parsing Error: {what}: {exc}", errno.EIO) from exc


def _entries(page: dict[str, Any], prefix: str) -> Iterator[tuple[str, Stat]]:
    for name, item in listing_items(page, prefix):
        if item is None:
            name = name.strip("/")
            if name:
                yield name, Stat(st_mode=OBJECT_DIR_MODE)
        else:
            yield (
                name,
                Stat(
                    st_mode=OBJECT_FILE_MODE, st_size=item.get("Size", 0), st_mtime=modified(item)
                ),
            )


def split(plugin: HTTPPlugin, url: str) -> tuple[str, str]:
    """``(bucket URL, key)`` for ``url`` under the configured addressing style.

    GCS through davix is always path-style; S3 is when ``ALTERNATE`` says so.
    """
    parsed = parse(url)
    path = urllib.parse.unquote(parsed.path).lstrip("/")
    base = f"{parsed.scheme}://{parsed.netloc}"
    if is_gcloud(parsed.scheme) or path_style(plugin.options, parsed):
        bucket, _, key = path.partition("/")
        return f"{base}/{bucket}", key
    return f"{base}/", path


def list_objects(plugin: HTTPPlugin, url: str) -> list[tuple[str, Stat]]:
    """A listing under ``url`` as a directory: ``(name, stat)`` pairs."""
    return _listing(plugin, url)[0]


def _listing(plugin: HTTPPlugin, url: str, *, limit: int = 0) -> tuple[list[tuple[str, Stat]], int]:
    """The entries under ``url``, and how many keys and prefixes the store listed.

    The count includes ``url``'s own ``<key>/`` marker, which is no entry
    but still means the directory exists. S3 gets ``ListObjectsV2``; GCS's
    XML API gets the original marker-paged listing, which is what davix
    sends it.
    """
    bucket, key = split(plugin, url)
    v1 = is_gcloud(parse(url).scheme)
    prefix = f"{key.rstrip('/')}/" if key.strip("/") else ""
    entries: list[tuple[str, Stat]] = []
    seen = 0
    token = ""
    while True:
        query: dict[str, str] = {"prefix": prefix, "delimiter": "/"}
        if not v1:
            query["list-type"] = "2"
        if limit:
            query["max-keys"] = str(limit)
        if token:
            query["marker" if v1 else "continuation-token"] = token
        listing = f"{bucket}?{urllib.parse.urlencode(query, quote_via=urllib.parse.quote)}"
        response = plugin._request("GET", listing, cred_url=url)
        payload = response.body()
        if response.status != 200:
            raise status_error(response.status)
        root = _answer(payload, "ListObjects" if v1 else "ListObjectsV2", "bucket listing")
        seen += len(root.get("CommonPrefixes", [])) + len(root.get("Contents", []))
        entries.extend(_entries(root, prefix))
        token = root.get("NextMarker" if v1 else "NextContinuationToken", "")
        if limit or not root.get("IsTruncated") or not token:
            return entries, seen


def stat(plugin: HTTPPlugin, url: str) -> Stat:
    """``HEAD`` the object; a key that is only a prefix is a directory."""
    _, key = split(plugin, url)
    if key.strip("/"):
        response = plugin._request("HEAD", url)
        response.close()
        if response.status == 200:
            if key.endswith("/") and not response.length:
                return Stat(st_mode=OBJECT_DIR_MODE)  # a directory marker
            return Stat(
                st_mode=OBJECT_FILE_MODE,
                st_size=response.length or 0,
                st_mtime=epoch(response.header("Last-Modified")),
            )
        if response.status != 404:
            raise status_error(response.status)
        if not _listing(plugin, url, limit=1)[1]:
            raise GError(f"{url} not found", errno.ENOENT)  # davix's s3StatMapper
        return Stat(st_mode=OBJECT_DIR_MODE)
    _listing(plugin, url, limit=1)  # the bucket itself: exists if it lists
    return Stat(st_mode=OBJECT_DIR_MODE)


def rename(plugin: HTTPPlugin, old: str, new: str) -> None:
    """A server-side copy to ``new`` (``x-amz-copy-source``), then the original deleted."""
    parsed = parse(old)
    if is_gcloud(parsed.scheme) or path_style(plugin.options, parsed):
        path = parsed.path
    else:
        path = f"/{parsed.host.partition('.')[0]}{parsed.path}"
    _swift.rename(
        plugin, old, new, copy_header="x-amz-copy-source", source=path, ok=200, verify=_copied
    )


def _copied(payload: bytes) -> None:
    if "Error" in _answer(payload, "CopyObject"):
        raise GError("S3 copy failed; the original file has not been deleted", errno.EIO)


def checksum(plugin: HTTPPlugin, url: str, algorithm: str) -> str:
    """What an object store says about an object's content, without reading it.

    GCS answers ``x-goog-hash`` with base64 ``crc32c`` and ``md5``; S3 only
    has the ``ETag``, which is the MD5 of an object uploaded in one part.
    """
    response = plugin._request("HEAD", url, timeout=plugin.checksum_timeout())
    response.close()
    if response.status != 200:
        raise status_error(response.status)
    wanted = algorithm.strip().lower()
    for item in response.header("x-goog-hash").split(","):
        name, _, value = item.strip().partition("=")
        if name.lower() == wanted and value:
            try:
                return base64.b64decode(value, validate=True).hex()
            except (binascii.Error, ValueError):
                break
    etag = response.header("ETag").strip('"')
    if wanted == "md5" and etag and "-" not in etag:
        return etag.lower()
    raise GError(f"checksum calculation for {algorithm} not supported for {url}", errno.ENOSYS)


# ---------------------------------------------------------------------------
# Multipart uploads
# ---------------------------------------------------------------------------


class Multipart:
    """One multipart upload: create, send parts, complete (or abort)."""

    def __init__(self, plugin: HTTPPlugin, url: str) -> None:
        self.plugin = plugin
        self.url = url
        self.parts: list[str] = []
        response = plugin._request("POST", self._with("uploads="), body=b"", cred_url=url)
        payload = response.body()
        if response.status != 200:
            raise status_error(response.status)
        self.upload_id = _answer(payload, "CreateMultipartUpload").get("UploadId", "")
        if not self.upload_id:
            raise GError(f"S3 did not return an upload id for {url}", errno.EPROTO)

    def _with(self, query: str) -> str:
        head, sep, existing = self.url.partition("?")
        return f"{head}?{existing}&{query}" if sep and existing else f"{head}?{query}"

    def _id(self) -> str:
        return urllib.parse.quote(self.upload_id, safe="")

    def send(self, body: bytes | FileBody, size: int) -> None:
        number = len(self.parts) + 1
        query = f"partNumber={number}&uploadId={self._id()}"
        response = self.plugin._request(
            "PUT", self._with(query), body=body, cred_url=self.url, timeout=self.plugin.io_timeout()
        )
        response.body()
        if response.status != 200:
            raise status_error(response.status)
        self.parts.append(response.header("ETag"))

    def complete(self) -> None:
        body = manifest(self.parts)
        response = self.plugin._request(
            "POST", self._with(f"uploadId={self._id()}"), body=body, cred_url=self.url
        )
        payload = response.body()
        # S3 can answer 200 and still carry an <Error> in the body.
        if response.status != 200 or "Error" in _answer(payload, "CompleteMultipartUpload"):
            raise status_error(response.status if response.status != 200 else 500)

    def abort(self) -> None:
        try:
            self.plugin._request(
                "DELETE", self._with(f"uploadId={self._id()}"), cred_url=self.url
            ).close()
        except GError:
            pass  # best effort: the lifecycle policy reaps what this leaves


def upload_file(plugin: HTTPPlugin, url: str, body: FileBody) -> None:
    """Send a local file in :data:`PART_SIZE` parts."""
    upload = Multipart(plugin, url)
    try:
        offset, end = body.offset, body.offset + body.count
        while offset < end:
            size = min(PART_SIZE, end - offset)
            upload.send(FileBody(body.file, offset, size, body.progress), size)
            offset += size
        upload.complete()
    except BaseException:
        upload.abort()
        raise


class S3PartWriter(PluginFile):
    """A write handle that fills parts in memory and sends each as it fills."""

    def __init__(self, plugin: HTTPPlugin, url: str) -> None:
        super().__init__(url)
        self._upload = Multipart(plugin, url)
        self._part = bytearray()

    def write(self, data: bytes | bytearray | memoryview) -> int:
        view = memoryview(data).cast("B")
        try:
            self._part += view
            while len(self._part) >= PART_SIZE:
                self._upload.send(bytes(self._part[:PART_SIZE]), PART_SIZE)
                del self._part[:PART_SIZE]
        except BaseException:
            self._upload.abort()
            self.closed = True
            raise
        self.position += view.nbytes
        return view.nbytes

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        if offset != self.position:
            raise GError("S3 uploads are sequential: pwrite must continue the file", errno.ESPIPE)
        return self.write(data)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if sys.exc_info()[1] is not None:
            self._upload.abort()
            return
        try:
            if self._part or not self._upload.parts:
                self._upload.send(bytes(self._part), len(self._part))
            self._upload.complete()
        except BaseException:
            self._upload.abort()
            raise
