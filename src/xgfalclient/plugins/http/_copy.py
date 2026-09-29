"""Copies the http plugin claims: uploads, parallel downloads, and third-party copies.

**HTTP destinations** go through gfal2's ``gfal_http_copy``, event for
event: ``PREPARE:ENTER``/``EXIT``, ``TRANSFER:ENTER``, one ``TRANSFER:TYPE``
per attempt, and ``TRANSFER:EXIT`` - with the pair on success, the error on
failure. The modes are ``3rd pull`` (the destination fetches), ``3rd push``
(the source sends) and ``streamed`` (the bytes flow through this process),
tried in that order from the first one chosen:

* a ``file://`` source, or remote copy switched off, means ``streamed`` and
  nothing else - whatever ``ENABLE_STREAM_COPY`` says;
* a ``copy_mode=pull|push`` query argument on the source (else on the
  destination) forces that mode, with no fallback;
* otherwise ``DEFAULT_COPY_MODE`` (``3rd pull``, ``3rd push`` or
  ``streamed``; anything else is ``3rd pull``, with a warning).

``ENABLE_REMOTE_COPY``, ``ENABLE_STREAM_COPY``, ``ENABLE_FALLBACK_TPC_COPY``
and ``DEFAULT_COPY_MODE`` are read from the source's and the destination's
own groups first (``[DAV:HOST]``, ``[HTTP:HOST]`` ...), where a boolean set
on either end must hold on both, and from ``[HTTP PLUGIN]`` otherwise. A
failed attempt's partial destination is removed (a ``CLEANUP`` event,
``0`` when it was gone already) unless it failed because the destination
exists; the next mode is tried unless the copy was cancelled, refused
(``EPERM``, ``EACCES``) or found nothing to copy (``ENOENT``).

A third-party ``COPY`` carries what davix sends: ``Source`` or
``Destination``, ``X-Number-Of-Streams``, ``Secure-Redirection``, a
``RequireChecksumVerification: false`` where gfal2 sends one (it never
sends ``true``), ``SciTag``, and the far side's credential: a bearer token
in ``TransferHeaderAuthorization`` with ``Credential: none`` - a
user-set one, or one the far SE mints when ``RETRIEVE_BEARER_TOKEN`` is on -
else ``Credential: gridsite`` when the far side is HTTPS (the active end may
then ask for a delegated proxy, ``X-Delegate-To``), else ``Credential:
none`` and ``X-No-Delegate: true``. An S3 or GCS far side gets a
pre-signed URL and ``Copy-Flags: NoHead``. The response streams
performance markers, which become ``transfer.progress``, and ends
``success``, ``failure``/``failed`` or ``aborted``; errors are worded and
numbered as davix words them.

``[CORE] RESOLVE_DNS`` makes the copy use one address of each endpoint's
DNS alias, by its reverse-resolved name, as gfal2 does (DMC-1348).

**HTTP to ``file://``** is not claimed by gfal2 at all; this plugin takes it
to download large files as ranged ``GET``\\ s over several pooled
connections at once, each writing its bytes straight into place with
``os.pwrite``. ``params.nbstreams`` sets the number of streams when it is
positive; over TLS the default is two, since every TLS record costs a trip
through the GIL. Its events are the core's.

Where this differs from gfal2, deliberately: the source and destination
checksums and the overwrite check are the core's (so they come before
``PREPARE:ENTER`` rather than inside it, and are worded as the core words
them); a copy whose deadline has passed tries no further mode; and a
``copy_mode`` query argument does not also switch fallback off for every
later copy in the context, as gfal2's (which writes it into the options)
does.
"""

from __future__ import annotations

import errno
import logging
import os
import random
import socket
import threading
from dataclasses import replace
from typing import TYPE_CHECKING

from ... import events as ev
from ...errors import GError
from ...plugin import O_CREAT, O_TRUNC, O_WRONLY, PluginFile
from ...transfer import Transfer, pump
from ...url import parse, scheme_of
from ._client import BLOCK, FileBody, Response, config_group, wire_scheme, wire_url
from ._delegation import delegate
from ._io import HTTPReadFile, HTTPWriteFile
from ._token import se_token

if TYPE_CHECKING:
    from ...options import Options
    from .plugin import HTTPPlugin

__all__ = ["PULL", "PUSH", "STREAMED", "CopyMode", "copy", "copy_mode", "is_http_scheme"]

_log = logging.getLogger("gfal2")

PULL = "3rd pull"
PUSH = "3rd push"
STREAMED = "streamed"
_MODES = (PULL, PUSH, STREAMED)
#: ``copy_mode=`` query values.
_QUERY_MODES = {"pull": PULL, "push": PUSH}
#: What ``is_http_scheme`` accepts in gfal2: no ``+3rd``.
HTTP_SCHEMES = frozenset(
    {"http", "https", "dav", "davs", "s3", "s3s", "gcloud", "gclouds"}
    | {"swift", "swifts", "cs3", "cs3s"}
)
_CHECKSUM_SOURCE = 1
_CHECKSUM_TARGET = 2

#: Files at least this big are downloaded over several connections.
PARALLEL_THRESHOLD = 32 << 20
#: Streams for a parallel download when ``params.nbstreams`` does not say.
DEFAULT_STREAMS = 4
#: The same over TLS, where each record is a GIL round trip (see above).
TLS_STREAMS = 2
#: The largest unit of work a download stream takes at a time.
SEGMENT = 64 << 20
#: The longest line believed to be a performance marker.
MAX_MARKER_LINE = 1 << 16


def is_http_scheme(url: str) -> bool:
    """gfal2's ``is_http_scheme``: the plugin's schemes, less the ``+3rd`` ones."""
    return scheme_of(url) in HTTP_SCHEMES


def local_path(url: str) -> str:
    return url[len("file://") :]


def copy(plugin: HTTPPlugin, transfer: Transfer) -> None:
    if scheme_of(transfer.destination) == "file":
        transfer.event(ev.TRANSFER_ENTER, transfer.pair)
        download(plugin, transfer)
        transfer.event(ev.TRANSFER_EXIT, transfer.pair)
    else:
        transfer.event(ev.PREPARE_ENTER, transfer.pair)
        transfer.event(ev.PREPARE_EXIT, transfer.pair)
        run_modes(plugin, transfer)
        if transfer.params.evict:
            _evict(plugin, transfer)


def _deadline_timeout(transfer: Transfer, fallback: float) -> float:
    left = transfer.remaining()
    return fallback if left is None else max(left, 1.0)


def _evict(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """``gfal-copy --evict``: release the source's disk copy, and say how that went."""
    failed = plugin.tape.release([transfer.source], "")[0]
    if failed is not None:
        _log.info("Eviction request failed: %s", failed.message)
    transfer.event("EVICT", "-1" if failed is not None else "0", side=ev.SOURCE)


# ---------------------------------------------------------------------------
# Choosing the modes
# ---------------------------------------------------------------------------


def _se_boolean(options: Options, url: str, key: str) -> bool | None:
    """``key`` from ``url``'s own group, or ``None`` when that group does not set it."""
    group = config_group(url)
    if not options.has(group, key):
        return None
    try:
        return bool(options.get_boolean(group, key))
    except GError:
        return None


def _both_ends(plugin: HTTPPlugin, source: str, destination: str, key: str) -> bool:
    """A boolean the endpoints' groups decide together (both must allow), else the plugin's."""
    options = plugin.options
    ends = [_se_boolean(options, url, key) for url in (source, destination)]
    if ends != [None, None]:
        return all(value is not False for value in ends)
    return bool(options.boolean(plugin.option_group, key, True))


def copy_mode(url: str) -> str | None:
    """A ``copy_mode=pull|push`` query argument on ``url``."""
    for key, value in parse(url).query_items():
        if key == "copy_mode" and value in _QUERY_MODES:
            return _QUERY_MODES[value]
    return None


class CopyMode:
    """gfal2's ``HttpCopyMode``: where to start, and how far to fall back."""

    def __init__(self, plugin: HTTPPlugin, source: str, destination: str) -> None:
        self.fallback = True
        self.streaming_only = True
        self.streaming = True
        if not is_http_scheme(source) or not _both_ends(
            plugin, source, destination, "ENABLE_REMOTE_COPY"
        ):
            self.mode: str | None = STREAMED
            return
        self.streaming = _both_ends(plugin, source, destination, "ENABLE_STREAM_COPY")
        forced = copy_mode(source) or copy_mode(destination)
        if forced is not None:
            _log.info("Extracted copy mode from query arguments: %s", forced)
            self.mode, self.fallback, self.streaming_only = forced, False, False
            return
        self.fallback = _both_ends(plugin, source, destination, "ENABLE_FALLBACK_TPC_COPY")
        options = plugin.options
        chosen = None
        for url in (source, destination):
            chosen = chosen or _mode_named(options.string(config_group(url), "DEFAULT_COPY_MODE"))
        if chosen is not None:
            _log.info("Using storage specific copy mode configuration: %s", chosen)
        else:
            configured = options.string(plugin.option_group, "DEFAULT_COPY_MODE", PULL)
            chosen = _mode_named(configured)
            if chosen is None:
                _log.warning(
                    "Invalid Gfal2 configuration for 'DEFAULT_COPY_MODE'. "
                    "Using default copy mode: %s",
                    PULL,
                )
                chosen = PULL
        self.mode, self.streaming_only = chosen, chosen == STREAMED

    def next(self) -> None:
        if self.mode == PULL:
            self.mode = PUSH
        elif self.mode == PUSH and self.streaming:
            self.mode = STREAMED
        else:
            self.mode = None


def _mode_named(name: str) -> str | None:
    return name if name in _MODES else None


def _should_fallback(code: int) -> bool:
    return code not in (errno.ECANCELED, errno.EPERM, errno.ENOENT, errno.EACCES)


# ---------------------------------------------------------------------------
# The attempts
# ---------------------------------------------------------------------------


def run_modes(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """gfal2's loop over the copy modes, with its events and its final wording."""
    modes = CopyMode(plugin, transfer.source, transfer.destination)
    transfer.event(ev.TRANSFER_ENTER, transfer.pair)
    tried: list[str] = []
    while modes.mode is not None:
        mode = modes.mode
        transfer.event(ev.TRANSFER_TYPE, mode)
        try:
            if mode != STREAMED:
                third_party(plugin, transfer, mode)
            elif modes.streaming:
                streamed(plugin, transfer)
            else:
                last = GError(
                    "STREAMED DISABLED Only streamed copy possible but streaming is disabled",
                    errno.EINVAL,
                )
                _log.warning("%s", last.message)
                break
            transfer.event(ev.TRANSFER_EXIT, transfer.pair)
            return
        except GError as exc:
            _log.warning("Copy failed with mode %s: %s", mode, exc.message)
            last = exc
        _cleanup(plugin, transfer, last)
        tried.append(mode)
        modes.next()
        # The deadline has passed: another mode would only time out too.
        if not (modes.fallback and _should_fallback(last.code)) or transfer.remaining() == 0.0:
            break
    message = last.message
    if tried:
        message = f"ERROR: Copy failed ({', '.join(tried)}). Last attempt: {message}"
    transfer.event(ev.TRANSFER_EXIT, message)
    # Cleaned here, as gfal2 cleans, or deliberately kept: not the core's to remove.
    transfer.owns_destination = False
    raise GError(f"TRANSFER {message}", last.code)


def _cleanup(plugin: HTTPPlugin, transfer: Transfer, error: GError) -> None:
    """Remove what a failed attempt may have left - unless the destination was there before."""
    if error.code == errno.EEXIST or not transfer.params.transfer_cleanup:
        return
    try:
        plugin.unlink(transfer.destination)
        code = 0
    except GError as exc:
        code = 0 if exc.code == errno.ENOENT else exc.code
    transfer.event(ev.CLEANUP, str(code), side=ev.DESTINATION)


def resolved(plugin: HTTPPlugin, url: str) -> str:
    """``url`` on one of its host's addresses, by name, when ``[CORE] RESOLVE_DNS`` is on."""
    if not plugin.options.boolean("CORE", "RESOLVE_DNS", False):
        return url
    parsed = parse(url)
    host = parsed.host
    try:
        found = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        address = random.choice(found)[4]
        name = socket.getnameinfo(address, socket.NI_NAMEREQD)[0]
    except OSError as exc:
        _log.warning("Could not resolve DNS alias %s: %s", host, exc)
        return url
    _log.info("Resolved url: %s => %s", host, name)
    userinfo, at, place = parsed.netloc.rpartition("@")
    return str(replace(parsed, netloc=userinfo + at + place.replace(host, name, 1)))


# ---------------------------------------------------------------------------
# Streamed
# ---------------------------------------------------------------------------


class _SourceError(GError):
    """A failure reading the source during a streamed copy."""


class _Tagged(PluginFile):
    """The source of a streamed copy, its failures marked as the source's."""

    def __init__(self, inner: PluginFile) -> None:
        super().__init__(inner.url)
        self._inner = inner

    def readinto(self, buffer: memoryview | bytearray) -> int:
        try:
            return self._inner.readinto(buffer)
        except GError as exc:
            raise _SourceError(f"{exc.message} (source)", exc.code) from exc


def _destination(exc: GError) -> GError:
    """gfal2's ``<why> (destination)``, unless the source failed or the copy stopped."""
    if isinstance(exc, _SourceError) or exc.code in (errno.ECANCELED, errno.ETIMEDOUT):
        return exc
    return GError(f"{exc.message} (destination)", exc.code)


def _upload_headers(transfer: Transfer) -> dict[str, str]:
    """``Content-MD5`` with the user's value as typed, when the target is checked by MD5."""
    if (
        int(transfer.checksum_mode) & _CHECKSUM_TARGET
        and transfer.checksum_algorithm.lower() == "md5"
        and transfer.user_checksum
    ):
        return {"Content-MD5": transfer.user_checksum}
    return {}


def streamed(plugin: HTTPPlugin, transfer: Transfer) -> None:
    if scheme_of(transfer.source) == "file":
        upload(plugin, transfer)
        return
    info = plugin.stat(transfer.source)
    if info.is_dir():
        raise GError(f"{transfer.source} is a directory", errno.EISDIR)
    size = info.st_size
    transfer.source_size = size
    reader = HTTPReadFile(plugin, transfer.source, size)
    try:
        destination = resolved(plugin, transfer.destination)
        writer = (
            plugin.open(destination, O_WRONLY | O_CREAT | O_TRUNC, 0o644, size)
            if plugin._multipart(destination)
            else HTTPWriteFile(plugin, destination, size, _upload_headers(transfer))
        )
        try:
            total = pump(transfer, _Tagged(reader), writer)
            if total != size:
                # Raised before the writer closes, so that it abandons the
                # upload rather than completing a truncated one.
                raise _SourceError(
                    f"Short copy: {total} bytes transferred, the source has {size} (source)",
                    errno.EIO,
                )
        finally:
            writer.close()
    except GError as exc:
        raise _destination(exc) from None
    finally:
        reader.close()


def upload(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """``file://`` to HTTP: one ``PUT``, its body sent with ``sendfile``."""
    path = local_path(transfer.source)
    try:
        handle = open(path, "rb")  # noqa: SIM115 - closed below, around a long call
    except OSError as exc:
        raise GError(f"Could not open source: {exc.strerror}", exc.errno or errno.EIO) from exc
    with handle:
        size = os.fstat(handle.fileno()).st_size
        transfer.source_size = size

        def progress(count: int) -> None:
            transfer.add(count)
            transfer.check()

        try:
            plugin._put_file(
                resolved(plugin, transfer.destination),
                FileBody(handle, 0, size, progress),
                size,
                timeout=_deadline_timeout(transfer, plugin.io_timeout()),
                headers=_upload_headers(transfer),
            )
        except GError as exc:
            raise _destination(exc) from None
    transfer.progress(size, force=True)


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


class _NoRanges(Exception):
    """The server answered a ranged GET with the whole file."""


def download(plugin: HTTPPlugin, transfer: Transfer) -> None:
    transfer.event(ev.TRANSFER_TYPE, STREAMED)
    info = plugin.stat(transfer.source)
    if info.is_dir():
        raise GError(f"{transfer.source} is a directory", errno.EISDIR)
    size = info.st_size
    transfer.source_size = size
    path = local_path(transfer.destination)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    except OSError as exc:
        raise GError(f"Could not open destination: {exc.strerror}", exc.errno or errno.EIO) from exc
    try:
        params = transfer.params
        streams = params.nbstreams if params.nbstreams > 0 else _default_streams(transfer.source)
        done = False
        if size >= PARALLEL_THRESHOLD and streams > 1:
            try:
                _parallel(plugin, transfer, fd, size, streams)
                done = True
            except _NoRanges:
                _log.debug("%s ignores Range; downloading in one stream", transfer.source)
                os.ftruncate(fd, 0)
                transfer.progress(0)
        if not done:
            _single(plugin, transfer, fd, size)
    finally:
        os.close(fd)
    transfer.progress(size, force=True)


def _default_streams(url: str) -> int:
    return TLS_STREAMS if wire_scheme(scheme_of(url)) == "https" else DEFAULT_STREAMS


def _pwrite_all(fd: int, view: memoryview, offset: int) -> None:
    done = 0
    while done < len(view):
        done += os.pwrite(fd, view[done:], offset + done)


def _single(plugin: HTTPPlugin, transfer: Transfer, fd: int, size: int) -> None:
    timeout = plugin.io_timeout()
    with plugin._get(transfer.source, {}, timeout=timeout) as response:
        buffer = bytearray(BLOCK)
        view = memoryview(buffer)
        total = 0
        while True:
            count = response.readinto(view)
            if count <= 0:
                break
            _pwrite_all(fd, view[:count], total)
            total += count
            transfer.add(count)
            transfer.check()
    if total != size:
        raise GError(f"Short copy: {total} bytes transferred, the source has {size}", errno.EIO)


def _parallel(plugin: HTTPPlugin, transfer: Transfer, fd: int, size: int, streams: int) -> None:
    # Big enough to amortise a request, small enough that every stream has work.
    step = max(min(SEGMENT, -(-size // streams)), 1 << 20)
    segments = iter([(offset, min(step, size - offset)) for offset in range(0, size, step)])
    lock = threading.Lock()
    stop = threading.Event()
    failures: list[BaseException] = []
    timeout = plugin.io_timeout()

    def fetch(offset: int, count: int, view: memoryview) -> None:
        headers = {"Range": f"bytes={offset}-{offset + count - 1}"}
        with plugin._get(transfer.source, headers, timeout=timeout) as response:
            if response.status != 206:
                raise _NoRanges
            done = 0
            while done < count and not stop.is_set():
                got = response.readinto(view[: min(len(view), count - done)])
                if got <= 0:
                    raise GError(
                        f"Short read of {transfer.source} at offset {offset + done}", errno.EIO
                    )
                _pwrite_all(fd, view[:got], offset + done)
                done += got
                transfer.add(got)
                transfer.check()

    def worker() -> None:
        view = memoryview(bytearray(BLOCK))
        try:
            while not stop.is_set():
                with lock:
                    segment = next(segments, None)
                if segment is None:
                    return
                fetch(segment[0], segment[1], view)
        except BaseException as exc:  # handed to the calling thread
            with lock:
                failures.append(exc)
            stop.set()

    threads = [
        threading.Thread(target=worker, name=f"xgfal-http-get-{index}", daemon=True)
        for index in range(min(streams, -(-size // step)))
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if failures:
        raise failures[0]


# ---------------------------------------------------------------------------
# Third-party copy
# ---------------------------------------------------------------------------


def _passive_credential(
    plugin: HTTPPlugin, far: str, write: bool, transfer: Transfer
) -> dict[str, str]:
    """The headers that let the active end reach ``far`` (gfal2's ``get_tpc_params``)."""
    headers: dict[str, str] = {}
    scheme = scheme_of(far)
    if scheme in ("cs3", "cs3s"):
        token = plugin.options.string("BEARER", "TOKEN")
        if token:
            headers["TransferHeaderAuthorization"] = f"Bearer {token}"
    elif scheme in HTTP_SCHEMES - {"s3", "s3s", "gcloud", "gclouds", "swift", "swifts"}:
        token = _far_token(plugin, far, write, transfer)
        if token:
            headers["TransferHeaderAuthorization"] = f"Bearer {token}"
            headers["Credential"] = "none"
    if scheme in ("https", "davs"):
        headers.setdefault("Credential", "gridsite")
    else:
        headers["Credential"] = "none"
        headers["X-No-Delegate"] = "true"
    return headers


def _far_token(plugin: HTTPPlugin, far: str, write: bool, transfer: Transfer) -> str | None:
    """A user-set token for ``far``, or one its SE mints when ``RETRIEVE_BEARER_TOKEN`` says so."""
    parsed = parse(far)
    query = parsed.query_dict()
    if "X-Amz-Signature" in query or "AWSAccessKeyId" in query:
        return None
    found = plugin.client.bearer(far, parsed)
    if found:
        return found
    retrieve = _se_boolean(plugin.options, far, "RETRIEVE_BEARER_TOKEN")
    if retrieve is None:
        retrieve = plugin.options.boolean(plugin.option_group, "RETRIEVE_BEARER_TOKEN", False)
    if not retrieve or parsed.scheme not in ("https", "davs"):
        return None
    minutes = 2 * int(transfer.params.timeout) // 60 + 10
    return se_token(plugin, far, write, minutes)


def _checksum_header(mode: str, checks: int) -> dict[str, str]:
    """``RequireChecksumVerification: false`` exactly where gfal2 sends it (for dCache)."""
    side = _CHECKSUM_SOURCE if mode == PUSH else _CHECKSUM_TARGET
    if checks & side or not checks:
        return {"RequireChecksumVerification": "false"}
    return {}


def third_party(plugin: HTTPPlugin, transfer: Transfer, mode: str) -> None:
    near, far = (
        (transfer.destination, transfer.source)
        if mode == PULL
        else (transfer.source, transfer.destination)
    )
    params = transfer.params
    headers = _passive_credential(plugin, far, mode == PUSH, transfer)
    signer = plugin.presigner_for(far)
    if signer is not None:
        # An S3 or GCS endpoint joins a TPC through a pre-signed URL.
        far_url = signer.presign("GET" if mode == PULL else "PUT", resolved(plugin, far))
        headers["Copy-Flags"] = "NoHead"
    else:
        far_url = wire_url(resolved(plugin, far))
    headers["Source" if mode == PULL else "Destination"] = far_url
    headers["X-Number-Of-Streams"] = str(params.nbstreams)
    headers["Secure-Redirection"] = "1"
    headers.update(_checksum_header(mode, int(transfer.checksum_mode)))
    if params.scitag:
        headers["SciTag"] = str(params.scitag)
    timeout = _deadline_timeout(transfer, 3600.0)
    active = resolved(plugin, near)
    with plugin._request(
        "COPY", active, headers=headers, timeout=timeout, cred_url=near
    ) as response:
        if response.status >= 300:
            raise _copy_refused(response)
        endpoint = response.header("X-Delegate-To").split()
        if endpoint:
            delegate(plugin, endpoint[0], near)
        _follow(response, transfer)


def _copy_refused(response: Response) -> GError:
    """davix's words for a ``COPY`` the active endpoint turned down."""
    status = response.status
    if status == 404:
        return GError("Could not COPY. File not found", errno.ENOENT)
    if status == 403:
        return GError("Could not COPY. Permission denied.", errno.EPERM)
    if status == 501:
        return GError("Could not COPY. The source service does not support it", errno.ENOSYS)
    if status >= 405:
        return GError("Could not COPY. The source service does not allow it", errno.ENOSYS)
    if status == 400:
        text = response.body().decode("utf-8", "replace")
        return GError(f"Could not COPY. The server rejected the request: {text}", errno.EIO)
    return GError(f"Could not COPY. Unknown error code: {status}", errno.EIO)


def _follow(response: Response, transfer: Transfer) -> None:
    """Read performance markers until the outcome line."""
    stripes: dict[int, int] = {}
    block: dict[str, str] = {}
    while True:
        line = response.readline(MAX_MARKER_LINE)
        if not line:
            raise GError("Connection terminated abruptly; Status of TPC request unknown", errno.EIO)
        text = line.decode("utf-8", "replace").strip()
        lowered = text.lower()
        if lowered.startswith("success"):
            transfer.progress(sum(stripes.values()), force=True)
            return
        if lowered.startswith("aborted"):
            raise GError("Transfer aborted in the remote end", errno.ECANCELED)
        if lowered.startswith(("failure", "failed")):
            raise GError(f"Transfer {text}", errno.EIO)
        if lowered.startswith("perf marker"):
            block = {}
        elif lowered.startswith("end"):
            moved = block.get("stripe bytes transferred", "")
            if moved.isdigit():
                index = block.get("stripe index", "0")
                stripes[int(index) if index.isdigit() else 0] = int(moved)
                transfer.progress(sum(stripes.values()))
            transfer.check()
        elif ":" in text:
            name, _, value = text.partition(":")
            block[name.strip().lower()] = value.strip()
