"""S3: AWS Signature Version 4, listings, and multipart uploads.

gfal2 reaches S3 through davix with ``s3://`` and ``s3s://`` URLs and the
``[S3]`` keys (``ACCESS_KEY``, ``SECRET_KEY``, optional ``TOKEN`` and
``REGION``), or per-endpoint keys in an ``[S3:<HOST>]`` group - which also
make a plain ``https://`` URL on that host an S3 one. ``ALTERNATE=true``
selects path-style addressing (``s3://host/bucket/key``) over the default
virtual-host style (``s3://bucket.host/key``); it matters here only for
listings, which must know where the bucket ends and the key begins.

Every request is signed with SigV4 (``hmac`` and ``hashlib``, nothing else).
davix falls back to the older SigV2 when no region is configured; this does
not - SigV2 is retired at AWS and every S3 implementation that matters takes
V4 - and signs for ``us-east-1`` instead, which is what they all accept.

S3 has no directories. ``mkdir`` succeeds without doing anything, a
"directory" is a key prefix that something lives under, and a listing is
``ListObjectsV2`` with ``/`` as the delimiter.
"""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import hmac
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ...errors import GError
from ...plugin import PluginFile
from ...types import Stat
from ...url import URL, parse
from ._client import Body, FileBody, Target, status_error
from ._dav import DIR_MODE, FILE_MODE, epoch, parse_xml
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


@dataclass(frozen=True)
class S3Keys:
    access_key: str
    secret_key: str
    token: str
    region: str

    def __repr__(self) -> str:
        return f"S3Keys({self.access_key!r}, secret_key=<redacted>, region={self.region!r})"


def _keys(options: Options, group: str) -> S3Keys | None:
    access = options.string(group, "ACCESS_KEY")
    secret = options.string(group, "SECRET_KEY")
    if not access or not secret:
        return None
    region = options.string(group, "REGION") or options.string("S3", "REGION") or DEFAULT_REGION
    return S3Keys(access, secret, options.string(group, "TOKEN"), region)


def is_s3(url: URL) -> bool:
    return url.scheme.partition("+")[0] in ("s3", "s3s")


def s3_keys(options: Options, url: URL) -> S3Keys | None:
    """The keys for ``url``: its host's group first, then ``[S3]`` for ``s3://``."""
    for group in (f"S3:{url.host.upper()}", f"S3:{url.host}"):
        found = _keys(options, group)
        if found is not None:
            return found
    return _keys(options, "S3") if is_s3(url) else None


def path_style(options: Options, url: URL) -> bool:
    fallback = options.boolean("S3", "ALTERNATE", False)
    return bool(options.boolean(f"S3:{url.host.upper()}", "ALTERNATE", fallback))


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _stamp(when: datetime | None) -> str:
    return (when or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")


def _canonical_query(query: str) -> str:
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    return "&".join(
        f"{urllib.parse.quote(name, safe='')}={urllib.parse.quote(value, safe='')}"
        for name, value in sorted(pairs)
    )


class S3Signer:
    """Signs requests (and pre-signs URLs) with one set of keys."""

    def __init__(self, keys: S3Keys) -> None:
        self.keys = keys

    def _signing_key(self, date: str) -> bytes:
        key = f"AWS4{self.keys.secret_key}".encode()
        for step in (date, self.keys.region, "s3", "aws4_request"):
            key = hmac.new(key, step.encode(), hashlib.sha256).digest()
        return key

    def _signature(self, stamp: str, canonical: str) -> str:
        scope = f"{stamp[:8]}/{self.keys.region}/s3/aws4_request"
        to_sign = "\n".join(
            [ALGORITHM, stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()]
        )
        return hmac.new(self._signing_key(stamp[:8]), to_sign.encode(), hashlib.sha256).hexdigest()

    def target(self, method: str, target: Target) -> Target:
        return target  # SigV4 here goes in headers, not in the URL

    def sign(
        self,
        method: str,
        target: Target,
        headers: Mapping[str, str],
        body: Body | None,
        when: datetime | None = None,
    ) -> dict[str, str]:
        """The headers that authorise this request."""
        stamp = _stamp(when)
        if body is None or isinstance(body, FileBody):
            payload = UNSIGNED if isinstance(body, FileBody) else hashlib.sha256(b"").hexdigest()
        else:
            payload = hashlib.sha256(body).hexdigest()
        signed = {k: v for k, v in headers.items() if k.lower().startswith("x-amz-")}
        signed["host"] = target.host_header
        signed["x-amz-date"] = stamp
        signed["x-amz-content-sha256"] = payload
        if self.keys.token:
            signed["x-amz-security-token"] = self.keys.token
        lowered = sorted((k.lower(), " ".join(v.split())) for k, v in signed.items())
        names = ";".join(name for name, _ in lowered)
        path, _, query = target.path.partition("?")
        canonical = "\n".join(
            [
                method.upper(),
                path,
                _canonical_query(query),
                "".join(f"{name}:{value}\n" for name, value in lowered),
                names,
                payload,
            ]
        )
        out = {k: v for k, v in signed.items() if k != "host"}
        scope = f"{stamp[:8]}/{self.keys.region}/s3/aws4_request"
        out["Authorization"] = (
            f"{ALGORITHM} Credential={self.keys.access_key}/{scope}, "
            f"SignedHeaders={names}, Signature={self._signature(stamp, canonical)}"
        )
        return out

    def presign(
        self, method: str, url: str, expires: int = 3600, when: datetime | None = None
    ) -> str:
        """A URL anyone can use for ``method`` until it expires - how S3 joins a TPC."""
        target = Target.of(url, s3=True)
        stamp = _stamp(when)
        scope = f"{stamp[:8]}/{self.keys.region}/s3/aws4_request"
        path, _, query = target.path.partition("?")
        params = urllib.parse.parse_qsl(query, keep_blank_values=True)
        params += [
            ("X-Amz-Algorithm", ALGORITHM),
            ("X-Amz-Credential", f"{self.keys.access_key}/{scope}"),
            ("X-Amz-Date", stamp),
            ("X-Amz-Expires", str(expires)),
            ("X-Amz-SignedHeaders", "host"),
        ]
        if self.keys.token:
            params.append(("X-Amz-Security-Token", self.keys.token))
        canonical_query = _canonical_query(urllib.parse.urlencode(params))
        canonical = "\n".join(
            [
                method.upper(),
                path,
                canonical_query,
                f"host:{target.host_header}\n",
                "host",
                UNSIGNED,
            ]
        )
        signature = self._signature(stamp, canonical)
        return f"{target.base}{path}?{canonical_query}&X-Amz-Signature={signature}"


# ---------------------------------------------------------------------------
# Namespace
# ---------------------------------------------------------------------------


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in element if _local(child.tag) == name]


def _child_text(element: ET.Element, name: str) -> str:
    for child in element:
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return ""


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


def list_objects(plugin: HTTPPlugin, url: str, *, limit: int = 0) -> list[tuple[str, Stat]]:
    """A listing under ``url`` as a directory: ``(name, stat)`` pairs.

    S3 gets ``ListObjectsV2``; GCS's XML API gets the original marker-paged
    listing, which is what davix sends it.
    """
    bucket, key = split(plugin, url)
    v1 = is_gcloud(parse(url).scheme)
    prefix = f"{key.rstrip('/')}/" if key.strip("/") else ""
    entries: list[tuple[str, Stat]] = []
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
            raise status_error(response.status, response.reason)
        root = parse_xml(payload, "bucket listing")
        for item in _children(root, "CommonPrefixes"):
            name = _child_text(item, "Prefix")[len(prefix) :].strip("/")
            if name:
                entries.append((name, Stat(st_mode=DIR_MODE)))
        for item in _children(root, "Contents"):
            name = _child_text(item, "Key")[len(prefix) :]
            if name and "/" not in name:
                size = _child_text(item, "Size")
                entries.append(
                    (
                        name,
                        Stat(
                            st_mode=FILE_MODE,
                            st_size=int(size) if size.isdigit() else 0,
                            st_mtime=epoch(_child_text(item, "LastModified")),
                        ),
                    )
                )
        token = _child_text(root, "NextMarker" if v1 else "NextContinuationToken")
        if limit or _child_text(root, "IsTruncated") != "true" or not token:
            return entries


def stat(plugin: HTTPPlugin, url: str) -> Stat:
    """``HEAD`` the object; a key that is only a prefix is a directory."""
    _, key = split(plugin, url)
    if key.strip("/"):
        response = plugin._request("HEAD", url)
        response.close()
        if response.status == 200:
            return Stat(
                st_mode=FILE_MODE,
                st_size=response.length or 0,
                st_mtime=epoch(response.header("Last-Modified")),
            )
        if response.status != 404:
            raise status_error(response.status, response.reason)
        if not list_objects(plugin, url, limit=1):
            raise status_error(404, response.reason)
        return Stat(st_mode=DIR_MODE)
    list_objects(plugin, url, limit=1)  # the bucket itself: exists if it lists
    return Stat(st_mode=DIR_MODE)


def checksum(plugin: HTTPPlugin, url: str, algorithm: str) -> str:
    """What an object store says about an object's content, without reading it.

    GCS answers ``x-goog-hash`` with base64 ``crc32c`` and ``md5``; S3 only
    has the ``ETag``, which is the MD5 of an object uploaded in one part.
    """
    response = plugin._request("HEAD", url, timeout=plugin.checksum_timeout())
    response.close()
    if response.status != 200:
        raise status_error(response.status, response.reason)
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
            raise status_error(response.status, response.reason)
        self.upload_id = _child_text(parse_xml(payload, "S3 response"), "UploadId")
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
            raise status_error(response.status, response.reason)
        self.parts.append(response.header("ETag"))

    def complete(self) -> None:
        items = "".join(
            f"<Part><PartNumber>{index}</PartNumber><ETag>{etag}</ETag></Part>"
            for index, etag in enumerate(self.parts, start=1)
        )
        body = f"<CompleteMultipartUpload>{items}</CompleteMultipartUpload>".encode()
        response = self.plugin._request(
            "POST", self._with(f"uploadId={self._id()}"), body=body, cred_url=self.url
        )
        payload = response.body()
        # S3 can answer 200 and still carry an <Error> in the body.
        if response.status != 200 or b"<Error>" in payload:
            raise status_error(response.status if response.status != 200 else 500, response.reason)

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
