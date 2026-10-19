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
* davix's ``LOG_LEVEL``, ``LOG_SENSITIVE`` and ``LOG_CONTENT`` are not read: the plugin's
  diagnostics go to the ``gfal2`` logger instead;
* ``User-Agent`` is the context's (``<agent>/<version> gfal2/2.23.5``),
  without the `` neon/0.0.29`` that davix's HTTP library appends.

Tape (the WLCG Tape REST API), tokens, copies and QoS live in their own
modules; this class is the dispatch surface gfal2's API lands on.

Where to start reading: :meth:`HTTPPlugin._request` is the one funnel every
sibling module sends through (credentials, redirects and the retry rule for
dropped connections are decided below it, in :mod:`._client`); the
namespace methods then follow the table above top to bottom. What a
maintainer must not break: the error *wording* and errno of each operation
are pinned by tests against gfal2's own output, and the object-store modules
(:mod:`._s3`, :mod:`._gcloud`) must stay lazily imported (see
:data:`S3_SCHEMES`).
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
import threading
import time
import urllib.parse
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING, TypedDict, Unpack

from ...errors import GError
from ...plugin import O_ACCMODE_MASK, O_RDONLY, O_WRONLY, Plugin, PluginFile, StagingResult
from ...types import Stat
from ...url import URL, parent, parse, scheme_of
from . import _copy, _metalink, _qos, _swift, _token
from ._client import (
    MKDIR,
    Auth,
    FileBody,
    HTTPClient,
    HTTPStatusError,
    Response,
    Signer,
    TransportError,
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
    from ._gcloud import KeyCache

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

# Reissuing these after a connection failed before an answer is safe. Mutating
# methods are retried by their operation-specific code only when it can prove
# what reached the server (for example, a whole-file PUT restart).
_RETRYABLE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PROPFIND"})


class _RequestOptions(TypedDict, total=False):
    """The keyword options of :meth:`HTTPPlugin._request`; every one may be left out.

    Each sibling module (:mod:`._s3`, :mod:`._tape`, :mod:`._token`, ...)
    sends its requests through ``_request`` with some of these, so they are
    spelled out once here rather than as a long keyword list on the method.
    """

    #: Extra request headers, on top of the credentials and standing headers.
    headers: dict[str, str] | None
    #: The body; a :class:`~._client.FileBody` is sent with ``sendfile``.
    body: bytes | FileBody | None
    #: Seconds per socket operation; ``None`` (the default) is :meth:`HTTPPlugin.io_timeout`.
    timeout: float | None
    #: Look credentials up for this URL instead of the request's own.
    cred_url: str | None
    #: Present only the X.509 proxy - no bearer token, no signing - as gfal2's
    #: SE-token retrievers do: asking for a token with a token would be circular.
    x509_only: bool


#: What davix splits an ``ETag`` on, looking for an MD5 in it: S3 quotes the
#: hex MD5 of a single-part object, and some servers wrap it in other fields.
_ETAG_SPLIT = re.compile(r"[&;\\/\"']")
#: What davix makes of a file it only knows from a ``HEAD``: plain HTTP says
#: nothing about type or permissions, so davix calls it a readable file.
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
    """``url`` with a trailing slash on its path, as davix addresses a directory.

    RFC 4918 (section 5.2) names a collection with the trailing slash, and
    some servers refuse or redirect a request for one without it.
    """
    parsed = parse(url)
    path = parsed.path or "/"
    return str(parsed.with_path(path if path.endswith("/") else path + "/"))


#: The object-store schemes, named here rather than asked of :mod:`._s3` and
#: :mod:`._gcloud`: those modules bring botocore and the RSA/X.509 stack with
#: them, and are imported only once a URL of theirs is actually used, so that
#: a ``davs://`` session never pays for them. They agree with ``_s3.is_s3``
#: and ``_gcloud.is_gcloud`` (a test holds them to it).
S3_SCHEMES = frozenset({"s3", "s3s"})
GCLOUD_SCHEMES = frozenset({"gcloud", "gclouds"})


def _kind(url: str) -> str:
    """``s3`` (S3 and GCS), ``swift``, ``cs3``, or ``dav`` for everything WebDAV.

    The namespace calls branch on this rather than on the scheme: GCS speaks
    S3's XML API (its interoperability mode), so the two share one code path,
    and ``http(s)``/``dav(s)`` differ only in details handled where they arise.
    """
    # ``+3rd`` only marks a URL as a third-party-copy end; the store is the same.
    scheme = scheme_of(url).partition("+")[0]
    if scheme in S3_SCHEMES or scheme in GCLOUD_SCHEMES:
        return "s3"
    if scheme in ("swift", "swifts"):
        return "swift"
    if scheme in ("cs3", "cs3s"):
        return "cs3"
    return "dav"


class HTTPPlugin(Plugin):
    """The ``http`` plugin: one instance per context, shared by all its threads.

    A gfal2 context may be used from many threads at once, so everything
    mutable here - the connection pools, the GCS key cache, the Metalink
    replica cache, the tape endpoints - is guarded by its own lock, and
    options are read from the context at each use so that ``set_opt_*``
    between two calls takes effect, as it does in gfal2.
    """

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
        """Make the transport; no connection is opened until the first request.

        The client asks back for a request signer per URL (:meth:`_signer`)
        rather than being told the credentials up front, because S3, GCS and
        Swift keys are options that may change between two calls.
        """
        super().__init__(context)
        #: The pooled transport; owned here and closed by :meth:`close`.
        self.client = HTTPClient(context, self.option_group)
        self.client.signer_for = self._signer
        #: The Tape REST API of each endpoint, discovered once per endpoint.
        self.tape = TapeREST(self)
        #: Made on the first ``gcloud://`` URL; see :data:`GCLOUD_SCHEMES`.
        self._gcloud: KeyCache | None = None
        self._gcloud_lock = threading.Lock()
        #: URL -> its Metalink replicas, the one that last worked first. Never
        #: expired: like davix's, it lives as long as the context.
        self._metalink_cache: dict[str, tuple[str, ...]] = {}
        self._metalink_lock = threading.Lock()

    def close(self) -> None:
        """Close every pooled connection; the context calls this on ``free()``.

        Safe to call twice, and a request made afterwards simply opens a new
        connection - the pool is emptied, not disabled.
        """
        self.client.close()

    def handles(self, url: str, operation: str) -> bool:
        """gfal2's ``check_url``: xattrs and tape calls only on the WebDAV schemes.

        An ``s3://`` or ``swift://`` URL has no Tape REST API and no tape
        xattrs, and gfal2 refuses those calls before sending anything; the
        core then reports ``EPROTONOSUPPORT``, as gfal2 does.
        """
        if operation in TAPE_OPERATIONS:
            return scheme_of(url) in TAPE_SCHEMES
        return super().handles(url, operation)

    # -- plumbing ------------------------------------------------------------------

    def io_timeout(self) -> float:
        """Seconds one socket operation may block: ``[HTTP PLUGIN] OPERATION_TIMEOUT``.

        Like davix's timeouts it bounds each connect, send or read, not the
        whole request: a slow but moving download is never cut off by it.
        """
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
        if self.options.has("CORE", "CONN_RETRY_INTERVAL"):
            if interval > 0:
                time.sleep(float(interval))
            return
        # A missing setting gets a small exponential floor. Immediate retries
        # all land inside the same short outage and spend CONN_RETRY in a few
        # microseconds; 50 ms is invisible on a healthy path and gives a
        # restarting proxy/server a meaningful chance to return.
        time.sleep(min(0.05 * 2 ** max(attempts - 1, 0), 1.0))

    def checksum_timeout(self) -> float:
        """``[CORE] CHECKSUM_TIMEOUT`` (default 1800 s) for a checksum request.

        Longer than :meth:`io_timeout` because a server may read the whole
        file before it answers a ``Want-Digest`` ``HEAD``, and says nothing
        while it does.
        """
        return float(self.options.integer("CORE", "CHECKSUM_TIMEOUT", 1800))

    def _signer(self, url: URL) -> Signer | None:
        """What authorises a request to ``url`` beyond the TLS credential; the client's hook.

        Swift requests carry an ``X-Auth-Token`` (:mod:`._swift`); S3 and GCS
        ones are signed (:meth:`presigner_for`); everything else is ``None``
        and is authorised by headers alone (bearer token, Basic auth).
        """
        if _swift.is_swift(url.scheme):
            return _swift.SwiftSigner(_swift.swift_keys(self.options, url))
        return self.presigner_for(str(url))

    def presigner_for(self, url: str) -> Signer | None:
        """What signs requests for (and pre-signs) an S3 or GCS ``url``, if it has keys."""
        parsed = parse(url)
        scheme = parsed.scheme.partition("+")[0]
        if scheme in GCLOUD_SCHEMES:
            from . import _gcloud

            found = self._gcloud_keys().get(self.options)
            return _gcloud.GCloudSigner(found) if found is not None else None
        if scheme not in S3_SCHEMES:
            return None
        from . import _s3

        keys = _s3.s3_keys(self.options, parsed)
        return _s3.S3Signer(keys) if keys is not None else None

    def _gcloud_keys(self) -> KeyCache:
        """The service-account cache, made (and :mod:`._gcloud` imported) on first use."""
        from . import _gcloud

        with self._gcloud_lock:
            if self._gcloud is None:
                self._gcloud = _gcloud.KeyCache()
            return self._gcloud

    def _s3(self, url: str) -> bool:
        """Whether ``url`` is an S3 or GCS object store."""
        return _kind(url) == "s3"

    def _multipart(self, url: str) -> bool:
        """Whether a large upload to ``url`` must go in parts (S3, not GCS)."""
        return parse(url).scheme.partition("+")[0] in S3_SCHEMES

    def _request(self, method: str, url: str, **options: Unpack[_RequestOptions]) -> Response:
        """One request through the pooled client, retried after a dropped connection if safe.

        Only the idempotent :data:`_RETRYABLE_METHODS` are re-sent, at most
        ``[HTTP PLUGIN] CONN_RETRY`` times with gfal2's back-off between: a
        ``PUT`` or ``DELETE`` that may have reached the server is the
        caller's to retry, because only it knows whether that is safe. A
        timeout is never retried - the server is there, just slow, and a
        second wait would double the time gfal2 promised to give up after.
        Statuses are not checked here; the response comes back unread.
        """
        cred_url = options.get("cred_url")
        timeout = options.get("timeout")
        auth = None
        if options.get("x509_only", False):
            auth = Auth(tls=self.client.tls(cred_url or url))
        attempts = 0
        while True:
            try:
                return self.client.request(
                    method,
                    url,
                    headers=options.get("headers"),
                    body=options.get("body"),
                    timeout=self.io_timeout() if timeout is None else timeout,
                    cred_url=cred_url,
                    auth=auth,
                )
            except TransportError as exc:
                attempts += 1
                if (
                    method not in _RETRYABLE_METHODS
                    or exc.code == errno.ETIMEDOUT
                    or attempts > self.conn_retry()
                ):
                    raise
                self.retry_pause(attempts)

    def _propfind(self, url: str, depth: str, *, body: bytes | None = None) -> tuple[int, bytes]:
        """A PROPFIND whose response body survives a transient disconnect.

        Unlike :meth:`_request` the retry covers reading the body too: a
        multistatus for a large directory is long, and a connection that
        drops halfway through it is as retryable as one that drops before
        the status line (``PROPFIND`` is safe, RFC 4918 section 9.1). With
        no ``body`` the server answers ``allprop``, which is what a
        ``Depth: 0`` stat has always sent.
        """
        headers = {"Depth": depth}
        if body is not None:
            headers["Content-Type"] = 'text/xml; charset="utf-8"'
        attempts = 0
        while True:
            response: Response | None = None
            try:
                response = self.client.request(
                    "PROPFIND",
                    url,
                    headers=headers,
                    body=body,
                    timeout=self.io_timeout(),
                )
                return response.status, response.body()
            except TransportError as exc:
                if response is not None:
                    response.close()
                attempts += 1
                if exc.code == errno.ETIMEDOUT or attempts > self.conn_retry():
                    raise
                self.retry_pause(attempts)

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
        """Upload a whole local file: one ``PUT``, or an S3 multipart upload when large.

        The streamed copy and a spooled :class:`~._io.HTTPWriteFile` end
        here. Above :data:`~._s3.MULTIPART_THRESHOLD` an S3 object goes in
        parts (one S3 ``PUT`` is capped at 5 GiB); a GCS object, for which
        :meth:`_multipart` is false, always gets a single ``PUT``.
        Raises the gfal2-worded upload error (:func:`~._io.check_upload`).
        """
        if self._multipart(url):
            from . import _s3

            if size > _s3.MULTIPART_THRESHOLD:
                _s3.upload_file(self, url, body)
                return
        check_upload(self._request("PUT", url, body=body, timeout=timeout, headers=headers))

    # -- stat ----------------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        """``statG``: davix's stat for the URL's kind, then its Metalink replicas.

        With ``[HTTP PLUGIN] METALINK`` on, a failed stat asks for the file's
        Metalink descriptor and stats the replicas it lists, as davix does
        below its own stat; a timeout is not retried that way, because each
        replica could take as long again. When nothing works the error is
        the original one, in davix's ``Result ... after 1 attempts`` words.
        """
        try:
            return self._stat(url)
        except GError as exc:
            if self._metalink_enabled(url) and exc.code != errno.ETIMEDOUT:
                try:
                    return self._metalink_stat(url, exc)
                except GError as recovered:
                    exc = recovered
            raise _result(exc) from None

    def _stat(self, url: str) -> Stat:
        """One stat with no Metalink and no wording: the dispatch by store kind.

        ``http(s)://`` is davix's plain-HTTP mode, where a server need not
        speak WebDAV at all - a ``PROPFIND`` refused (``405``, ``501``) or
        failed for any reason falls back to a ``HEAD``. ``dav(s)://`` promises
        WebDAV, so its ``PROPFIND`` failure is the answer.
        """
        kind = _kind(url)
        if kind == "s3":
            from . import _s3

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
        """``PROPFIND`` ``Depth: 0``: the resource's own ``<D:response>`` as a stat.

        RFC 4918 answers ``207 Multi-Status``; a few servers say ``200`` with
        the same body, which is accepted too. The first response is taken,
        as davix takes it - with ``Depth: 0`` there is only the resource.
        """
        status, payload = self._propfind(url, "0")
        if status not in (200, 207):
            raise status_error(status)
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

    def _metalink_enabled(self, url: str) -> bool:
        """Whether gfal2's HTTP Metalink option applies to this endpoint."""
        return self.options.boolean(self.option_group, "METALINK", False) and _kind(url) not in (
            "s3",
            "swift",
        )

    def _metalink_start(self, url: str) -> str:
        """A previously discovered preferred replica, else ``url`` itself."""
        with self._metalink_lock:
            replicas = self._metalink_cache.get(url, ())
        return replicas[0] if replicas else url

    def _prefer_metalink(self, url: str, replica: str) -> None:
        """Move a replica that just worked to the front, so later reads start there.

        Only an already-cached replica is promoted: the cache is never seeded
        from here, so a replica the descriptor did not list cannot sneak in.
        """
        with self._metalink_lock:
            replicas = self._metalink_cache.get(url, ())
            if replica in replicas:
                self._metalink_cache[url] = (
                    replica,
                    *(item for item in replicas if item != replica),
                )

    def _metalink_replicas(self, url: str) -> tuple[str, ...]:
        """Discover and cache the HTTP replicas advertised for ``url``.

        davix's discovery: a ``HEAD`` asking for ``application/metalink4+xml``
        that is *not* redirected - a redirect would be to the data, and the
        ``Link`` header (RFC 6249, ``rel=describedby``) is the door's - then a
        ``GET`` of the descriptor (RFC 5854), read to at most
        :data:`~._metalink.MAX_DESCRIPTOR_SIZE` bytes. Nothing advertised is
        ``()``, not an error; an unparsable descriptor is ``GError``. Racing
        threads may both fetch it; ``setdefault`` keeps the first answer.
        """
        if not self._metalink_enabled(url):
            return ()
        with self._metalink_lock:
            cached = self._metalink_cache.get(url)
        if cached is not None:
            return cached
        # Straight to the client: discovery is a single probe, not worth _request's retries.
        response = self.client.request(
            "HEAD",
            url,
            headers={"Accept": _metalink.ACCEPT},
            timeout=self.io_timeout(),
            follow=False,
        )
        with response:
            descriptor = _metalink.descriptor_url(response, url)
        if descriptor is None:
            return ()
        response = self._request("GET", descriptor, headers={"Accept": _metalink.ACCEPT})
        if response.status < 200 or response.status >= 300:
            response.close()
            return ()
        # One byte over the limit, so the parser can tell "too big" from "exactly the limit".
        document = response.body(_metalink.MAX_DESCRIPTOR_SIZE + 1)
        replicas = _metalink.parse_metalink(document, base_url=descriptor).replicas
        with self._metalink_lock:
            return self._metalink_cache.setdefault(url, replicas)

    def _metalink_stat(self, url: str, original: GError) -> Stat:
        """Try advertised replicas, preserving the original error if none works."""
        try:
            replicas = self._metalink_replicas(url)
        except GError:
            raise original from None
        for replica in replicas:
            try:
                info = self._stat(replica)
            except GError:
                continue
            self._prefer_metalink(url, replica)
            return info
        raise original from None

    # -- namespace -----------------------------------------------------------------

    def mkdir(self, url: str, mode: int) -> None:
        """``mkdirG``: ``MKCOL`` (RFC 4918 section 9.3), or a marker object on S3/Swift.

        ``mode`` is ignored, as davix ignores it: WebDAV has no permissions.
        ``MKCOL`` answers ``201 Created``; ``405`` means something is already
        there (``EEXIST``) and ``409 Conflict`` that the parent is missing
        (``ENOENT``) - the ``MKDIR`` scope of :func:`~._client.status_error`.
        """
        if _kind(url) in ("s3", "swift"):
            _swift.mkdir(self, url)
            return
        response = self._request("MKCOL", url)
        response.body()
        # 200 and 204 are not RFC 4918's answers to MKCOL, but some servers send them.
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
        """``rmdirG``: refuse a file (``ENOTDIR``), then ``DELETE`` the collection.

        The stat first is davix's: a ``DELETE`` does not care what it removes,
        so without it ``rmdir`` of a file would delete the file. Emptiness is
        not checked - davix does not either - and RFC 4918 (section 9.6.1)
        makes a collection's ``DELETE`` recursive, so a non-empty directory
        goes or stays as the server's policy decides.
        """
        info = self.stat(url)
        if not info.is_dir():
            raise GError("Can not rmdir a file", errno.ENOTDIR)
        if self._s3(url):
            return  # a prefix goes when what is under it does
        target = _collection(url)
        # DELETE is not retried by _request: a second one after a lost answer
        # would report ENOENT for a directory that was in fact removed.
        response = self._request("DELETE", target)
        response.body()
        if response.status not in (200, 202, 204):
            raise _decorated(response.status, target, prefix="DavPosix::rmdir  ")

    def unlink(self, url: str) -> None:
        """``unlinkG``: ``DELETE`` of a non-collection, in davix's ``DavPosix::unlink`` words.

        ``EISDIR`` for a collection (found by a stat first, except in plain
        HTTP mode - see below); ``200``, ``202 Accepted`` and ``204`` all mean
        done, as RFC 9110 allows a ``DELETE`` to be queued.
        """
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
        """``renameG``: ``MOVE`` (RFC 4918 section 9.9), or copy-and-delete on object stores.

        ``Destination`` must be an absolute ``http(s)`` URI, so a ``davs://``
        name is sent in its wire form. No ``Overwrite`` header is sent, so
        RFC 4918's default (``T``, section 10.6) applies and an existing
        target is replaced (``204``) rather than refused.
        """
        kind = _kind(old)
        if kind == "s3":
            from . import _s3

            _s3.rename(self, old, new)
            return
        if kind == "swift":
            _swift.rename_swift(self, old, new)
            return
        # The Destination must name the same server for most implementations
        # (RFC 4918 lets a server refuse a cross-server MOVE with 502).
        response = self._request("MOVE", old, headers={"Destination": wire_url(new)})
        response.body()
        if response.status not in (200, 201, 204):
            raise _decorated(response.status, old)

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        """``opendirG``: each entry with its stat, from the one listing request.

        The listing is fetched whole before the first entry is returned: a
        multistatus is parsed as one document, and an
        error is better raised by ``opendir`` than by a later ``readdir``.
        """
        return iter(self._list(url))

    def listdir(self, url: str) -> list[str]:
        """``listdir``: the names alone - the same request, since WebDAV has no cheaper one."""
        return [name for name, _ in self._list(url)]

    def _list(self, url: str) -> list[tuple[str, Stat | None]]:
        """The entries directly under ``url``: ``PROPFIND`` ``Depth: 1``, or the store's listing.

        The request names just the properties a stat needs
        (:data:`~._dav.PROPFIND_BODY`) rather than ``allprop``, which asks a
        server for every property of every entry. The collection's own
        ``<D:response>`` is found by path, not position (servers differ on
        the trailing slash and on percent-encoding), falling back to the
        first; if that entry is not a collection the URL is a file, and
        listing it is ``ENOTDIR`` as in gfal2.
        """
        kind = _kind(url)
        if kind == "s3":
            return self._s3_list(url)
        if kind == "swift":
            return _swift.list_objects(self, url)
        status, payload = self._propfind(url, "1", body=PROPFIND_BODY)
        if status not in (200, 207):
            raise status_error(status)
        entries = parse_multistatus(payload)
        # hrefs are compared decoded: a server may percent-encode what the URL did not.
        own = urllib.parse.unquote(parse(url).path)
        mine = next((i for i, (path, _) in enumerate(entries) if same_path(path, own)), 0)
        if entries and not entries[mine][1].is_dir():
            raise GError(f"{url} is not a collection, listing impossible", errno.ENOTDIR)
        found: list[tuple[str, Stat | None]] = []
        for index, (path, info) in enumerate(entries):
            name = posixpath.basename(path.rstrip("/"))
            # An empty name is the root's own entry when the collection's was not found.
            if index != mine and name:
                found.append((name, info))
        return found

    def _s3_list(self, url: str) -> list[tuple[str, Stat | None]]:
        """``ListObjectsV2`` under ``url``'s prefix, with davix's answer for a non-directory.

        S3 lists an absent prefix as an empty one, so an empty listing of a
        key below the bucket is checked with a stat: a file is ``ENOTDIR``,
        nothing at all is the stat's ``ENOENT``, and a bucket is just empty.
        """
        from . import _s3

        entries: list[tuple[str, Stat | None]] = list(_s3.list_objects(self, url))
        _, key = _s3.split(self, url)
        # Nothing under the prefix: ENOENT from the stat for nothing there at all.
        if not entries and key.strip("/") and self._stat(url).is_file():
            raise GError(f"{url} is not a collection, listing impossible", errno.ENOTDIR)
        return entries

    # -- I/O -------------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        """``openG``: a ranged-``GET`` reader or a ``PUT`` writer; never both.

        A read stats the file first, for its size and to refuse a directory
        (``EISDIR``), and starts at the Metalink replica that last worked. A
        write with a known ``size`` above the multipart threshold on S3 goes
        in parts; any other write is an :class:`~._io.HTTPWriteFile`, which
        streams or spools the body until ``close`` commits it - so that is
        where a refused upload is reported. ``mode`` is ignored (WebDAV has
        no permissions).
        """
        # davix validates the URL before anything else, with this message.
        if not valid_authority(parse(url).netloc):
            raise GError(" Uri invalid in Davix::Open", errno.EIO)
        access = flags & O_ACCMODE_MASK
        if access == O_RDONLY:
            info = self.stat(url)
            if info.is_dir():
                raise GError(f"{url} is a directory", errno.EISDIR)
            return HTTPReadFile(self, url, info.st_size, active=self._metalink_start(url))
        if access == O_WRONLY:
            if size is not None and self._multipart(url):
                from . import _s3

                if size > _s3.MULTIPART_THRESHOLD:
                    return _s3.S3PartWriter(self, url)
            return HTTPWriteFile(self, url, size)
        raise GError("HTTP files cannot be open for reading and writing at once", errno.ENOTSUP)

    # -- metadata ----------------------------------------------------------------------

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        """``checksumG``: the server's digest of the whole file, never computed locally.

        Asked for with RFC 3230's ``Want-Digest`` on a ``HEAD`` and taken from,
        in this order: ``Content-MD5`` (RFC 1864, for MD5), ``Digest``, an
        MD5-looking ``ETag`` (S3's), and finally - this plugin's addition, see
        the module docstring - a one-byte ``GET``. Object stores answer from
        their own metadata (:func:`~._s3.checksum`). A partial range is
        ``ENOTSUP``, since HTTP has no way to ask for one; no digest at all is
        gfal2's ``ENOSYS`` "not supported".
        """
        if offset or length:
            raise GError("HTTP does not support partial checksums", errno.ENOTSUP)
        if self._s3(url):
            from . import _s3

            return _s3.checksum(self, url, algorithm)
        timeout = self.checksum_timeout()
        want = {"Want-Digest": algorithm}
        response = self._request("HEAD", url, headers=want, timeout=timeout)
        response.close()
        if response.status >= 300:
            raise status_error(response.status)
        # Content-MD5 can only ever be an MD5; for anything else go straight to Digest.
        md5 = algorithm.strip().lower() == "md5"
        value = _content_md5(response.header("Content-MD5")) if md5 else ""
        value = value or digest_value(response.header("Digest"), algorithm)
        if not value and md5:
            # davix's last resort; an S3 multipart ETag ("<hex>-<parts>") is
            # rejected by the 32-hex-digit test, as it is not the file's MD5.
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
        """``getxattrG``: ``user.status`` from the Tape REST ``archiveinfo``, or the API's own.

        ``user.status`` is ``ONLINE``, ``NEARLINE`` or ``ONLINE_AND_NEARLINE``
        as gfal2 reports it; ``taperestapi.*`` come from the discovery
        document (:mod:`._tape`). Anything else is ``ENODATA`` in gfal2's words.
        """
        if name == "user.status":
            return self.tape.status(url)
        if name in TAPE_XATTRS:
            return self.tape.xattr(url, name)
        raise GError(f'Failed to get the xattr "{name}" (No data available)', errno.ENODATA)

    def listxattr(self, url: str) -> list[str]:
        """The tape xattrs gfal2 lists for any HTTP URL, whether its endpoint has the API or not."""
        return list(TAPE_XATTRS)

    def setxattr(self, url: str, name: str, value: str, flags: int) -> None:
        """Always ``ENOSYS``, gfal2's answer: no HTTP xattr is writable (tape state
        changes through the staging calls, not through attributes)."""
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
        """``bring_online``: one Tape REST ``POST /stage``; the files come back queued.

        ``pintime``, ``timeout`` and ``is_async`` are accepted for the
        plugin interface and not sent, as gfal2's http plugin does not send
        them: its stage request carries only the paths and any targeted
        metadata, and it is always asynchronous - the caller polls with the
        returned request id.
        """
        return self.tape.bring_online(urls, metadata)

    def bring_online_poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        """``GET /stage/{id}``: per file, staged (``True``), ``EAGAIN`` for not yet, or an error."""
        return self.tape.poll(urls, token)

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``POST /release/{id}``: unpin; one failure is every file's, as the API answers once."""
        return self.tape.release(urls, token)

    def abort_bring_online(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``POST /stage/{id}/cancel``: stop a stage request; an id is required (``EINVAL``)."""
        return self.tape.abort(urls, token)

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        """``POST /archiveinfo``: per file, on tape (``True``) or ``EAGAIN`` not yet archived."""
        return self.tape.archive_poll(urls)

    # -- QoS -----------------------------------------------------------------------------
    # dCache's CDMI QoS, request for request as gfal2 sends it; see :mod:`._qos`.

    def check_file_qos(self, url: str) -> str:
        """The object's current QoS class: its CDMI ``capabilitiesURI``."""
        return _qos.check_file_qos(self, url)

    def check_available_qos_transitions(self, url: str) -> list[str]:
        """The classes the current one may move to (``cdmi_capabilities_allowed``)."""
        return _qos.check_available_qos_transitions(self, url)

    def check_target_qos(self, url: str) -> str:
        """The class a transition under way is heading for (``cdmi_capabilities_target``)."""
        return _qos.check_target_qos(self, url)

    def change_object_qos(self, url: str, target: str) -> None:
        """Request a transition by ``PUT``-ting a new ``capabilitiesURI``."""
        _qos.change_object_qos(self, url, target)

    def qos_check_classes(self, url: str, kind: str) -> list[str]:
        """The classes the endpoint offers for ``dataobject`` or ``container``."""
        return _qos.qos_check_classes(self, url, kind)

    # -- tokens --------------------------------------------------------------------------

    def token_retrieve(
        self, url: str, issuer: str, validity: int, write_access: bool, activities: list[str]
    ) -> str:
        """``token_retrieve``: a macaroon or token the storage element (or ``issuer``) mints.

        ``validity`` is in minutes; empty ``activities`` means gfal2's read or
        write set. Authenticated by the X.509 proxy alone; see :mod:`._token`
        for the chain of retrievers tried and ``ENODATA`` when all fail.
        """
        ask = _token.TokenAsk(url, write_access, int(validity), activities)
        return _token.retrieve(self, issuer, ask)

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
        """``filecopy``: gfal2's http copy - TPC ``COPY`` modes with fallback, or streamed.

        :func:`._copy.copy` owns preparation (existing destination, parent,
        checksums), the ``DEFAULT_COPY_MODE``/``ENABLE_FALLBACK_TPC_COPY``
        order of attempts, and the events gfal2 emits for each.
        """
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
