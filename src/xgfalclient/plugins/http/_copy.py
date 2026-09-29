"""Copies the http plugin claims: uploads, parallel downloads, and third-party copies.

**Uploads** (``file://`` to HTTP) are one ``PUT`` whose body leaves with
``sendfile`` in the clear, and in large blocks over TLS.

**Downloads** (HTTP to ``file://``) are where this beats gfal2, which reads
one stream through the core: a large file is fetched as ranged ``GET``\\ s
over several pooled connections at once, each writing its bytes straight
into place with ``os.pwrite``. ``params.nbstreams`` sets the number of
streams when it is positive. Over TLS the default is two: every TLS record
costs a trip through the GIL, and past two streams the threads spend more
time queueing for it than the extra connections gain.

**HTTP to HTTP** is gfal2's mode chain, event for event: ``3rd pull`` (the
destination fetches), then ``3rd push`` (the source sends), then
``streamed`` (the bytes flow through this process), starting from
``DEFAULT_COPY_MODE`` and falling back only while
``ENABLE_FALLBACK_TPC_COPY`` allows. Each attempt announces itself with a
``TRANSFER:TYPE`` event; a failed attempt's partial destination is removed
(a ``CLEANUP`` event) before the next begins. ``ENABLE_REMOTE_COPY=false``
leaves only ``streamed``; ``ENABLE_STREAM_COPY=false`` - or a ``+3rd``
scheme on either side - removes it.

A third-party ``COPY`` carries what davix sends: ``Source`` or
``Destination``, ``X-Number-Of-Streams``, ``Secure-Redirection``,
``RequireChecksumVerification``, and the far side's credential. That is a
token in ``TransferHeaderAuthorization`` when there is one - the far URL's
own ``authz``, the context's bearer token, or, with an X.509 proxy and
``RETRIEVE_BEARER_TOKEN``, a macaroon minted by the far SE - and
``Credential: none``. With only a proxy, and ``proxy_delegation`` set, the
near side is instead allowed to ask for a delegated proxy (``X-Delegate-To``).
The response body streams performance markers, which become
``transfer.progress``, and ends ``success:`` or ``failure:``.
"""

from __future__ import annotations

import errno
import logging
import os
import re
import threading
from typing import TYPE_CHECKING

from ... import events as ev
from ...enums import checksum_mode
from ...errors import ECOMM, GError
from ...plugin import O_CREAT, O_TRUNC, O_WRONLY
from ...transfer import Transfer, pump
from ...url import parse, scheme_of
from ._client import (
    BLOCK,
    FileBody,
    Response,
    http_errno,
    status_error,
    url_token,
    wire_scheme,
    wire_url,
)
from ._delegation import delegate
from ._io import HTTPReadFile
from ._token import retrieve

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["PULL", "PUSH", "STREAMED", "copy", "copy_modes"]

_log = logging.getLogger("xgfalclient.plugins.http")

PULL = "3rd pull"
PUSH = "3rd push"
STREAMED = "streamed"
_ORDER = (PULL, PUSH, STREAMED)
_SPELLINGS = {
    "3rd pull": PULL,
    "pull": PULL,
    "3rd push": PUSH,
    "push": PUSH,
    "streamed": STREAMED,
    "stream": STREAMED,
    "streaming": STREAMED,
}

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

_QUOTED_STATUS = re.compile(r"\b([45]\d\d)\b")


def local_path(url: str) -> str:
    return url[len("file://") :]


def copy(plugin: HTTPPlugin, transfer: Transfer) -> None:
    if scheme_of(transfer.source) == "file":
        upload(plugin, transfer)
    elif scheme_of(transfer.destination) == "file":
        download(plugin, transfer)
    else:
        between(plugin, transfer)


def _deadline_timeout(transfer: Transfer, fallback: float) -> float:
    left = transfer.remaining()
    return fallback if left is None else max(left, 1.0)


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------


def upload(plugin: HTTPPlugin, transfer: Transfer) -> None:
    transfer.event(ev.TRANSFER_TYPE, STREAMED)
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

        plugin._put_file(
            transfer.destination,
            FileBody(handle, 0, size, progress),
            size,
            timeout=_deadline_timeout(transfer, plugin.io_timeout()),
        )
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
# HTTP to HTTP
# ---------------------------------------------------------------------------


def copy_modes(plugin: HTTPPlugin, source: str, destination: str) -> list[str]:
    """The modes gfal2 would try for this pair, in order."""
    options, group = plugin.options, plugin.option_group
    raw = options.string(group, "DEFAULT_COPY_MODE", PULL).strip().lower()
    default = _SPELLINGS.get(raw)
    if default is None:
        _log.warning("Invalid 'DEFAULT_COPY_MODE' %r; using %s", raw, PULL)
        default = PULL
    remote = options.boolean(group, "ENABLE_REMOTE_COPY", True)
    forced = "+3rd" in scheme_of(source) or "+3rd" in scheme_of(destination)
    stream = options.boolean(group, "ENABLE_STREAM_COPY", True) and not forced
    if not remote:
        default = STREAMED
    chain = list(_ORDER[_ORDER.index(default) :])
    if not options.boolean(group, "ENABLE_FALLBACK_TPC_COPY", True):
        chain = [default]
    if not stream:
        chain = [mode for mode in chain if mode != STREAMED]
    return chain


def between(plugin: HTTPPlugin, transfer: Transfer) -> None:
    modes = copy_modes(plugin, transfer.source, transfer.destination)
    if not modes:
        raise GError(
            "STREAMED DISABLED Only streamed copy possible but streaming is disabled", errno.EPERM
        )
    tried: list[str] = []
    last = GError("Copy failed", errno.EIO)
    for mode in modes:
        if tried:
            # A failed attempt may have left part of a file behind.
            _cleanup(plugin, transfer)
        transfer.event(ev.TRANSFER_TYPE, mode)
        try:
            if mode == STREAMED:
                streamed(plugin, transfer)
            else:
                third_party(plugin, transfer, mode)
            return
        except GError as exc:
            _log.info("Copy failed with mode %s: %s", mode, exc.message)
            tried.append(mode)
            last = exc
            # Neither a cancelled copy, one out of time, nor one refused because
            # the file is already there gets anything from trying another way.
            if exc.code in (errno.ECANCELED, errno.EEXIST) or transfer.remaining() == 0.0:
                break
    if last.code == errno.ECANCELED:
        raise last
    raise GError(
        f"TRANSFER ERROR: Copy failed ({', '.join(tried)}). Last attempt: {last.message}",
        last.code,
    )


def _cleanup(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """Remove what a failed attempt may have left, before the next one tries."""
    if not transfer.params.transfer_cleanup:
        return
    try:
        plugin.unlink(transfer.destination)
        code = 0
    except GError as exc:
        code = 0 if exc.code == errno.ENOENT else exc.code
    transfer.event(ev.CLEANUP, str(code), side=ev.DESTINATION)


def streamed(plugin: HTTPPlugin, transfer: Transfer) -> None:
    """GET piped into PUT, through the core's overlapped pump."""
    info = plugin.stat(transfer.source)
    if info.is_dir():
        raise GError(f"{transfer.source} is a directory", errno.EISDIR)
    size = info.st_size
    transfer.source_size = size
    reader = HTTPReadFile(plugin, transfer.source, size)
    try:
        writer = plugin.open(transfer.destination, O_WRONLY | O_CREAT | O_TRUNC, 0o644, size)
        try:
            total = pump(transfer, reader, writer)
            if total != size:
                # Raised before the writer closes, so that it abandons the
                # upload rather than completing a truncated one.
                raise GError(
                    f"Short copy: {total} bytes transferred, the source has {size}", errno.EIO
                )
        finally:
            writer.close()
    finally:
        reader.close()


def _far_token(plugin: HTTPPlugin, far: str, write: bool, transfer: Transfer) -> str | None:
    """The credential for the far endpoint, if it can be a token."""
    found = url_token(parse(far)) or plugin.context.bearer_token(far)
    if found:
        return found
    if not plugin.options.boolean(plugin.option_group, "RETRIEVE_BEARER_TOKEN", True):
        return None
    if plugin.context.x509(far) is None or wire_scheme(scheme_of(far)) != "https":
        return None
    minutes = max(int(transfer.params.timeout) // 60 + 1, 2)
    try:
        return retrieve(plugin, far, "", minutes, write)
    except GError as exc:
        _log.info("(SEToken) Could not retrieve any token for %s: %s", far, exc.message)
        return None


def third_party(plugin: HTTPPlugin, transfer: Transfer, mode: str) -> None:
    source, destination = transfer.source, transfer.destination
    near, far = (destination, source) if mode == PULL else (source, destination)
    params = transfer.params
    headers: dict[str, str] = {}
    signer = plugin.signer_for(far)
    if signer is not None:
        # An S3 endpoint joins a TPC through a pre-signed URL; it needs no token.
        method = "GET" if mode == PULL else "PUT"
        far_url = signer.presign(method, far, expires=max(int(params.timeout), 3600))
        token = None
    else:
        far_url = wire_url(far)
        token = _far_token(plugin, far, mode == PUSH, transfer)
    headers["Source" if mode == PULL else "Destination"] = far_url
    headers["X-Number-Of-Streams"] = str(params.nbstreams)
    headers["Secure-Redirection"] = "1"
    delegating = (
        token is None
        and signer is None
        and params.proxy_delegation
        and plugin.context.x509(near) is not None
        and wire_scheme(scheme_of(near)) == "https"
    )
    if token is not None:
        headers["TransferHeaderAuthorization"] = f"Bearer {token}"
    if not delegating:
        headers["Credential"] = "none"
        headers["X-No-Delegate"] = "true"
    verify = transfer.checksum_mode != checksum_mode.none
    headers["RequireChecksumVerification"] = "true" if verify else "false"
    if params.scitag:
        headers["SciTag"] = str(params.scitag)
    if params.overwrite:
        headers["Overwrite"] = "T"
    timeout = _deadline_timeout(transfer, 3600.0)
    with plugin._request("COPY", near, headers=headers, timeout=timeout) as response:
        if response.status not in (200, 201, 202):
            raise status_error(response.status, response.reason)
        endpoint = response.header("X-Delegate-To").split()
        if delegating and endpoint:
            delegate(plugin, endpoint[0], near)
        _follow(response, transfer)


def _follow(response: Response, transfer: Transfer) -> None:
    """Read performance markers until the outcome line."""
    stripes: dict[int, int] = {}
    block: dict[str, str] = {}
    while True:
        line = response.readline(MAX_MARKER_LINE)
        if not line:
            raise GError("Connection terminated abruptly; Status of TPC request unknown", ECOMM)
        text = line.decode("utf-8", "replace").strip()
        lowered = text.lower()
        if lowered.startswith("success"):
            transfer.progress(sum(stripes.values()), force=True)
            return
        if lowered.startswith(("failure", "failed", "aborted")):
            detail = text.partition(":")[2].strip() or text
            found = _QUOTED_STATUS.search(detail)
            code = http_errno(int(found.group(1))) if found else ECOMM
            raise GError(f"Transfer failure: {detail}", code)
        if lowered == "perf marker":
            block = {}
        elif lowered == "end":
            moved = block.get("stripe bytes transferred", "")
            if moved.isdigit():
                index = block.get("stripe index", "0")
                stripes[int(index) if index.isdigit() else 0] = int(moved)
                transfer.progress(sum(stripes.values()))
            transfer.check()
        elif ":" in text:
            name, _, value = text.partition(":")
            block[name.strip().lower()] = value.strip()
