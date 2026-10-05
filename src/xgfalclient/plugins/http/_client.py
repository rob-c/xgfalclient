"""The HTTP transport under the http plugin: pooled ``http.client`` connections.

davix is what gfal2 speaks HTTP with, and this module does the davix jobs
the plugin needs, on nothing but :mod:`http.client`:

* **connections are pooled** per endpoint and credential, and handed back
  only once a response has been read to the end, so a thousand ``stat``
  calls cost one TCP and TLS handshake (``[HTTP PLUGIN] KEEP_ALIVE``);
* a pooled connection the server has since closed is **retried once** on a
  fresh one - but only when nothing of the response had arrived, so no
  request is ever applied twice;
* **redirects** (301, 302, 303, 307, 308) are followed across hosts, which is
  how dCache doors and XRootD redirectors hand clients to data servers. The
  ``Authorization`` header goes along, as davix sends it along: the data
  server is part of the same storage element and needs the same token. The
  one exception is a hop from ``https`` down to plain ``http`` on another
  host, where a bearer token would travel in clear - it is dropped there;
* uploads send ``Expect: 100-continue`` as davix does and wait (briefly) for
  the go-ahead, so a redirect or a refusal arrives *before* gigabytes have
  been pushed at a door that will not keep them. File bodies go out with
  ``socket.sendfile`` in the clear, and in large ``sendall`` writes over TLS
  (where ``sendfile`` cannot encrypt, and Python quietly falls back to 8 KiB
  sends);
* large bodies of known length are read **straight off the socket** once
  http.client has parsed the headers: one TLS record per call, with none of
  the three Python-level wrappers ``HTTPResponse.readinto`` goes through for
  each record. That time is spent holding the GIL, and parallel download
  streams otherwise queue for it;
* credentials are gfal2's (``get_credentials``): the X.509 proxy is
  presented in every TLS handshake, whatever else is sent, and on top of it
  ``s3``/``gcloud`` requests are signed, ``swift`` ones carry the
  ``X-Auth-Token``, ``cs3`` ones ``[BEARER] TOKEN``, and HTTP/WebDAV ones the
  bearer token found for the URL - a URL-prefix credential, then one keyed
  by the bare host name (FTS sets those), then ``[BEARER] TOKEN`` - or else
  ``USER``/``PASSWD`` Basic auth. A token in the URL's query (``authz=``)
  is left where it is, as davix leaves it.

HTTP statuses are *not* raised here: every caller words its own errors the
way gfal2 does for that operation, with :func:`status_error`, which reads a
status as davix's ``httpcodeToDavixError`` and gfal2's ``davix2errno`` do.
"""

from __future__ import annotations

import base64
import errno
import http.client
import io
import logging
import os
import re
import socket
import ssl
import threading
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, BinaryIO, Protocol, Union, cast

from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from xrdclient.http._engine import REDIRECTS, Request, attempt, redirects
from xrdclient.http.expect import InterimAnswer, await_continue

from ..._compat import TIMEOUTS
from ...creds import BEARER, check_bearer_token
from ...errors import ECOMM, GError
from ...url import URL, parse, scheme_of
from ._connection import HTTPConnection, HTTPSConnection

if TYPE_CHECKING:
    from ...context import Gfal2Context

__all__ = [
    "BLOCK",
    "OBJECT_STORES",
    "Body",
    "FileBody",
    "HTTPClient",
    "HTTPStatusError",
    "Response",
    "Target",
    "TransportError",
    "config_group",
    "davix_status",
    "status_error",
    "status_text",
    "transport_error",
    "wire_scheme",
    "wire_url",
]

_log = logging.getLogger("gfal2")

#: Socket I/O size for bodies: gfal2's ``COPY_BUFFERSIZE``.
BLOCK = 4 << 20
#: Reads at least this big bypass http.client's buffered stream (see :class:`Response`).
DIRECT_READ = 1 << 16
#: How long an upload waits for ``100 Continue`` before sending anyway, as curl does.
CONTINUE_WAIT = 1.0
#: Redirect statuses, and how many hops are followed before giving up.
MAX_REDIRECTS = 10
#: Schemes whose requests are signed (or carry a Swift token) instead of a bearer token.
OBJECT_STORES = frozenset({"s3", "s3s", "gcloud", "gclouds", "swift", "swifts"})
#: Idle connections kept per endpoint.
MAX_IDLE = 16
_WIRE = {
    "http": "http",
    "dav": "http",
    "s3": "http",
    "gcloud": "http",
    "swift": "http",
    "cs3": "http",
    "https": "https",
    "davs": "https",
    "s3s": "https",
    "gclouds": "https",
    "swifts": "https",
    "cs3s": "https",
}


def wire_scheme(scheme: str) -> str:
    """``http`` or ``https`` for a gfal scheme (``davs+3rd`` -> ``https``)."""
    return _WIRE.get(scheme.partition("+")[0], "")


def wire_url(url: str) -> str:
    """``url`` as another server must see it: ``http(s)://``, query and all.

    What goes in a ``Destination`` or ``Source`` header is read by a server,
    not by gfal2, and ``davs://`` means nothing to it.
    """
    parsed = parse(url)
    text = f"{wire_scheme(parsed.scheme)}://{parsed.netloc}{parsed.path or '/'}"
    return f"{text}?{parsed.query}" if parsed.query else text


def config_group(url: str) -> str:
    """gfal2's per-endpoint group for ``url``: ``DAV:HOST`` for ``davs://host/...``.

    The protocol (``+3rd`` dropped) loses one trailing ``s``, and the whole
    name is upper-cased: ``https`` and ``http`` share ``[HTTP:HOST]``.
    """
    parsed = parse(url)
    scheme = parsed.scheme.partition("+")[0]
    scheme = scheme[:-1] if scheme.endswith("s") else scheme
    return f"{scheme}:{parsed.host}".upper()


_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_PATH_SAFE = "/:@!$&'()*+,;=~"


def _quote_path(path: str) -> str:
    """Percent-encode a path, leaving escapes that are already there alone."""
    parts: list[str] = []
    end = 0
    for match in _ESCAPE.finditer(path):
        parts.append(urllib.parse.quote(path[end : match.start()], safe=_PATH_SAFE))
        parts.append(match.group())
        end = match.end()
    parts.append(urllib.parse.quote(path[end:], safe=_PATH_SAFE))
    return "".join(parts)


@dataclass(frozen=True)
class Target:
    """Where one request goes: the endpoint and the origin-form request target."""

    scheme: str
    host: str
    port: int
    path: str
    url: URL

    @classmethod
    def of(cls, url: str, *, s3: bool = False) -> Target:
        parsed = parse(url)
        scheme = wire_scheme(parsed.scheme)
        if not scheme or not valid_authority(parsed.netloc):
            raise GError(f" {url} is not a valid HTTP or Webdav URL", errno.EIO)
        if not parsed.host:
            # davix takes an empty host and fails to resolve it.
            raise TransportError("Domain name resolution failed", errno.EHOSTUNREACH)
        explicit = _explicit_port(parsed.netloc)
        port = explicit or (443 if scheme == "https" else 80)
        raw = parsed.path or "/"
        # S3 signs the path exactly as its canonical form spells it, so the
        # wire must use that spelling too.
        quoted = urllib.parse.quote(urllib.parse.unquote(raw), safe="/") if s3 else _quote_path(raw)
        query = parsed.query
        return cls(scheme, parsed.host, port, f"{quoted}?{query}" if query else quoted, parsed)

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return host if self.port == default else f"{host}:{self.port}"

    @property
    def base(self) -> str:
        """``scheme://host:port`` - where server-rooted APIs live."""
        return f"{self.scheme}://{self.host_header}"


def valid_authority(netloc: str) -> bool:
    """Whether davix (neon's URI parser) takes ``netloc``: a closed ``[...]``, a numeric port."""
    host = netloc.rpartition("@")[2]
    if host.startswith("["):
        if "]" not in host:
            return False
        host = host.rpartition("]")[2]
    port = host.partition(":")[2]
    return not port or port.isdigit()


def _explicit_port(netloc: str) -> int:
    host = netloc.rpartition("@")[2]
    tail = host.rpartition("]")[2] if host.startswith("[") else host
    text = tail.rpartition(":")[2] if ":" in tail else ""
    return int(text) if text.isdigit() else 0


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class HTTPStatusError(GError):
    """A GError that came from an HTTP status; ``status`` says which."""

    def __init__(self, message: str, code: int, status: int) -> None:
        super().__init__(message, code)
        self.status = status


class TransportError(GError):
    """A GError that came from the network, not from the server's answer."""


#: The scope in which davix reads 405 and 409 as a directory question.
MKDIR = "mkdir"
#: An upload: a 409 there means the parent collection is missing (RFC 4918).
PUT = "put"

_EHOSTDOWN = getattr(errno, "EHOSTDOWN", errno.EIO)

#: davix's ``httpcodeToDavixError`` for everything that is not a success,
#: with gfal2's ``davix2errno`` already applied: status -> (errno, phrase).
_DAVIX: dict[int, tuple[int, str]] = {
    **dict.fromkeys((401, 402, 407), (errno.EACCES, "Authentication Error")),
    **dict.fromkeys((303, 404, 410), (errno.ENOENT, "File not found")),
    **dict.fromkeys((408, 504), (errno.ETIMEDOUT, "Operation timeout")),
    **dict.fromkeys((403, 423), (errno.EPERM, "Permission refused")),
    **dict.fromkeys((400, 411, 412, 413, 414, 415, 424, 501), (_EHOSTDOWN, "Server Error")),
    507: (errno.EIO, "Insufficient Storage"),
    **dict.fromkeys(
        (300, 301, 302),
        (errno.ENOSYS, "Redirection requested, transparent redirection disabled"),
    ),
}


def davix_status(status: int, scope: str = "") -> tuple[int, str]:
    """``(errno, phrase)`` for a failed ``status``, as gfal2 reports it through davix.

    Only ``mkdir`` reads 405 and 409 differently: there they mean the
    directory exists and its parent does not, elsewhere a refusal and an
    existing file. Anything davix has no words for is ``EIO``.
    """
    if status == 405:
        if scope == MKDIR:
            return errno.EEXIST, "Method Not Allowed, File Exist"
        return errno.EPERM, "Method Not Allowed, Permission refused"
    if status == 409:
        if scope == MKDIR:
            return errno.ENOENT, "Conflict, File not Found"
        if scope == PUT:
            # davix's words, but not its EEXIST: a PUT's 409 is a missing
            # parent, and "File exists" would read as an existing target to
            # anything matching on it (the ATLAS pilot does). gfal2 itself
            # reports a stale errno here.
            return errno.ENOENT, "Conflict, File Exist"
        return errno.EEXIST, "Conflict, File Exist"
    return _DAVIX.get(status, (errno.EIO, f"Unexpected server error: {status}"))


def status_text(status: int, scope: str = "") -> str:
    """davix's wording: ``HTTP 404 : File not found `` (trailing space and all)."""
    return f"HTTP {status} : {davix_status(status, scope)[1]} "


def status_error(
    status: int, *, prefix: str = "", suffix: str = "", scope: str = ""
) -> HTTPStatusError:
    code, phrase = davix_status(status, scope)
    return HTTPStatusError(f"{prefix}HTTP {status} : {phrase} {suffix}", code, status)


def transport_error(exc: BaseException) -> TransportError:
    """A network failure as the GError gfal2 would raise for it."""
    if isinstance(exc, TransportError):
        return exc
    if isinstance(exc, TIMEOUTS):
        return TransportError("Connection timed out", errno.ETIMEDOUT)
    if isinstance(exc, ConnectionRefusedError):
        return TransportError("Could not connect to server", errno.ECONNREFUSED)
    if isinstance(exc, socket.gaierror):
        return TransportError("Domain name resolution failed", errno.EHOSTUNREACH)
    if isinstance(exc, ssl.SSLCertVerificationError):
        return TransportError(f"SSL handshake failed: {exc.verify_message}", errno.EACCES)
    if isinstance(exc, ssl.SSLError):
        return TransportError(f"SSL error: {getattr(exc, 'reason', None) or exc}", ECOMM)
    if isinstance(exc, (http.client.HTTPException, ConnectionResetError, BrokenPipeError)):
        return TransportError(f"Connection terminated abruptly: {exc}", ECOMM)
    if isinstance(exc, OSError) and exc.errno:
        return TransportError(os.strerror(exc.errno), exc.errno)
    return TransportError(f"Connection error: {exc}", ECOMM)


# ---------------------------------------------------------------------------
# Bodies
# ---------------------------------------------------------------------------


@dataclass
class FileBody:
    """``count`` bytes of an open file from ``offset``, sent with ``sendfile``.

    ``progress`` hears about every slice as it leaves, and may raise to stop
    the upload (a cancelled or timed-out copy).
    """

    file: BinaryIO
    offset: int
    count: int
    progress: Callable[[int], None] | None = None
    slice: int = 16 << 20


Body = Union[bytes, bytearray, memoryview, FileBody]


def _length(body: Body | None) -> int | None:
    if body is None:
        return None
    if isinstance(body, FileBody):
        return body.count
    return memoryview(body).nbytes


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


class Response:
    """A response whose body has not been read yet.

    Read it with :meth:`read`, :meth:`readinto` or :meth:`readline`, then
    :meth:`close` it - which puts the connection back in the pool if the
    body was read to the end, and drops it otherwise.
    """

    def __init__(
        self,
        client: HTTPClient,
        exchange: _Exchange,
        raw: http.client.HTTPResponse,
        url: str,
        reusable: bool = True,
    ) -> None:
        self._client = client
        self._exchange = exchange
        self._raw = raw
        self.url = url
        self.status = raw.status
        self.reason = raw.reason
        self.headers = raw.msg
        self._reusable = reusable
        self.closed = False
        #: Whether http.client's read buffer is known to be empty.
        self._drained = False
        self._receive: Callable[[int, memoryview], int] | None = None

    def header(self, name: str, default: str = "") -> str:
        value = self.headers.get(name)
        return default if value is None else str(value)

    @property
    def length(self) -> int | None:
        """``Content-Length``, when the server sent one."""
        raw = self.header("Content-Length").strip()
        return int(raw) if raw.isdigit() else None

    def read(self, amount: int | None = None) -> bytes:
        self._drained = False
        try:
            return self._raw.read(amount)
        except (OSError, http.client.HTTPException) as exc:
            self._fail()
            raise transport_error(exc) from exc

    def readinto(self, buffer: bytearray | memoryview) -> int:
        raw = self._raw
        length, fp = raw.length, raw.fp
        try:
            # http.client has no length for a chunked body, and no stream once it
            # has closed one (an end of file with bytes still owed, say).
            if len(buffer) >= DIRECT_READ and length and fp is not None:
                count = self._readinto_direct(memoryview(buffer), fp, length)
            else:
                count = raw.readinto(buffer)
        except (OSError, http.client.HTTPException) as exc:
            self._fail()
            raise transport_error(exc) from exc
        if count == 0 and len(buffer) and self._raw.length:
            # http.client reports a body cut short as a quiet end of file;
            # a download must not mistake that for the whole file.
            self._fail()
            raise TransportError(
                f"Connection terminated abruptly: {self._raw.length} bytes of the body "
                "never arrived",
                ECOMM,
            )
        return count

    def _readinto_direct(self, view: memoryview, fp: io.BufferedReader, length: int) -> int:
        """Fill ``view`` from the socket itself, past http.client's buffered stream.

        Whatever http.client has already buffered comes first (one
        ``readinto1`` empties that buffer); after that the socket is read
        with nothing in between. The response's ``length`` is kept up to date, and a body
        read to its end is finished through http.client, which then lets the
        connection go back to the pool.
        """
        raw = self._raw
        want = min(view.nbytes, length)
        view = view.cast("B")[:want]
        got = 0
        if not self._drained:
            got = fp.readinto1(view)
            self._drained = True
        receive = self._receive
        if receive is None:
            receive = self._receive = _receiver(self._exchange.conn.sock)
        while got < want:
            try:
                count = receive(want - got, view[got:])
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
                count = 0  # the peer closed the TLS session: an end of file
            if not count:
                # Once the peer has gone every later read is an end of file
                # too, not whatever OpenSSL says about a dead session.
                self._receive = _at_end
                break
            got += count
        raw.length = length - got
        if not raw.length:
            raw.read()  # nothing left to read: http.client closes its stream
        return got

    def readline(self, limit: int = 1 << 16) -> bytes:
        self._drained = False
        try:
            return self._raw.readline(limit)
        except (OSError, http.client.HTTPException) as exc:
            self._fail()
            raise transport_error(exc) from exc

    def body(self, limit: int = 1 << 26) -> bytes:
        """The whole body (up to ``limit``), and the response closed."""
        try:
            body = self.read(limit)
            if len(body) < limit and self._raw.length:
                # ``HTTPResponse.read(amount)`` quietly returns a short buffer
                # when the peer closes despite an outstanding Content-Length.
                # Whole-body callers need the same contract as ``readinto`` so
                # their operation-level retry can distinguish a cut from EOF.
                owed = self._raw.length
                self._fail()
                raise TransportError(
                    f"Connection terminated abruptly: {owed} bytes of the body never arrived",
                    ECOMM,
                )
            return body
        finally:
            self.close()

    def _fail(self) -> None:
        self._reusable = False
        self.close()

    def close(self) -> None:
        """Return the connection to the pool if it can take another request."""
        if self.closed:
            return
        self.closed = True
        raw = self._raw
        finished = raw.isclosed() and not raw.will_close
        if not finished and self._reusable and not raw.isclosed():
            # A small unread remainder (an error page) is cheaper to drain
            # than a new handshake is to make.
            remaining = raw.length
            if remaining is not None and remaining <= 65536:
                try:
                    raw.read()
                    finished = not raw.will_close
                except (OSError, http.client.HTTPException):
                    finished = False
        raw.close()
        if finished and self._reusable:
            self._client._checkin(self._exchange)
        else:
            self._exchange.close()

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _at_end(count: int, view: memoryview) -> int:
    return 0


def _receiver(sock: socket.socket | None) -> Callable[[int, memoryview], int]:
    """``receive(count, view)``: one read from ``sock`` into ``view``.

    On a TLS socket that is the underlying ``_ssl`` object's ``read`` - one
    record per call, and the wrappers in :mod:`ssl` are per-call Python code
    run while holding the GIL, which is what several download streams contend
    for.
    """
    assert sock is not None
    tls = getattr(sock, "_sslobj", None)
    if tls is not None:
        return tls.read  # type: ignore[no-any-return]

    def receive(count: int, view: memoryview) -> int:
        return sock.recv_into(view, count)

    return receive


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------

_PoolKey = tuple[str, str, int, int]


@dataclass
class _Exchange:
    """One connection, checked out for one request."""

    key: _PoolKey
    conn: http.client.HTTPConnection
    reused: bool

    def send_head(self, method: str, target: str, headers: Mapping[str, str]) -> None:
        self.conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
        for name, value in headers.items():
            self.conn.putheader(name, value)
        self.conn.endheaders()

    def wait_continue(self, method: str) -> http.client.HTTPResponse | None:
        """After headers with ``Expect: 100-continue``: a final answer, or ``None`` to send.

        The server either says ``100 Continue`` (consumed here), answers for
        good without wanting the body (a redirect, a refusal - returned), or
        says nothing within :data:`CONTINUE_WAIT`, which RFC 9110 says means
        go ahead anyway. The interim response is read a byte at a time: a
        buffered read could swallow the start of a final answer the server
        sends straight after it, and then nobody would ever read that.
        """
        try:
            await_continue(self.conn, method, CONTINUE_WAIT)
        except InterimAnswer as early:
            return early.response
        return None

    def send(self, data: bytes | bytearray | memoryview) -> None:
        self.conn.send(data)

    def send_file(self, body: FileBody) -> None:
        sock = self.conn.sock
        assert sock is not None
        if isinstance(sock, ssl.SSLSocket):
            self._send_file_tls(sock, body)
            return
        offset, remaining = body.offset, body.count
        while remaining > 0:
            size = min(body.slice, remaining)
            sent = sock.sendfile(body.file, offset, size)
            if sent <= 0:
                raise GError(f"Short read from the local file at offset {offset}", errno.EIO)
            offset += sent
            remaining -= sent
            if body.progress is not None:
                body.progress(sent)

    @staticmethod
    def _send_file_tls(sock: ssl.SSLSocket, body: FileBody) -> None:
        """``sendfile`` cannot encrypt, and falls back to 8 KiB sends: send big blocks."""
        buffer = bytearray(min(body.slice, BLOCK, body.count))
        view = memoryview(buffer)
        file = cast("io.BufferedIOBase", body.file)
        file.seek(body.offset)
        offset, remaining = body.offset, body.count
        while remaining > 0:
            got = file.readinto(view[: min(len(buffer), remaining)])
            if not got:
                raise GError(f"Short read from the local file at offset {offset}", errno.EIO)
            sock.sendall(view[:got])
            offset += got
            remaining -= got
            if body.progress is not None:
                body.progress(got)

    def send_body(self, body: Body) -> None:
        if isinstance(body, FileBody):
            self.send_file(body)
        else:
            self.send(body)

    def response(self) -> http.client.HTTPResponse:
        return self.conn.getresponse()

    def close(self) -> None:
        self.conn.close()


def _line(raw: io.RawIOBase) -> bytes:
    """One line from an unbuffered stream, never reading past its end."""
    found = bytearray()
    while len(found) < 65536:
        byte = raw.read(1)
        if not byte:
            break
        found += byte
        if byte == b"\n":
            break
    return bytes(found)


def _idle_count(pool: HTTPConnectionPool) -> int:
    queue = pool.pool
    if queue is None:
        return 0
    with queue.mutex:
        return sum(conn is not None for conn in queue.queue)


class Signer(Protocol):
    """What signs object-store requests (S3 SigV4 headers, GCS signed URLs)."""

    def target(self, method: str, target: Target) -> Target: ...

    def sign(
        self, method: str, target: Target, headers: Mapping[str, str], body: Body | None
    ) -> dict[str, str]: ...

    def presign(self, method: str, url: str, expires: int = 3600) -> str: ...


@dataclass
class Auth:
    """How requests for one URL are authorised."""

    headers: dict[str, str] = field(default_factory=dict)
    tls: ssl.SSLContext | None = None
    signer: Signer | None = None


_STALE = (
    http.client.RemoteDisconnected,
    http.client.BadStatusLine,
    ConnectionResetError,
    BrokenPipeError,
    ConnectionAbortedError,
)


class HTTPClient:
    """Thread-safe pooled HTTP for one plugin instance."""

    def __init__(self, context: Gfal2Context, group: str = "HTTP PLUGIN") -> None:
        self.context = context
        self.group = group
        self._lock = threading.Lock()
        self._pools: dict[_PoolKey, HTTPConnectionPool] = {}
        #: S3 credentials for a URL, when there are any; set by the plugin.
        self.signer_for: Callable[[URL], Signer | None] = lambda url: None

    # -- pool --------------------------------------------------------------------

    @property
    def keep_alive(self) -> bool:
        return bool(self.context.options.boolean(self.group, "KEEP_ALIVE", True))

    def _checkout(self, target: Target, tls: ssl.SSLContext | None, timeout: float) -> _Exchange:
        key: _PoolKey = (target.scheme, target.host, target.port, id(tls))
        with self._lock:
            pool = self._pools.get(key)
            if pool is None:
                if target.scheme == "https":
                    pool = HTTPSConnectionPool(
                        target.host, target.port, maxsize=MAX_IDLE, ssl_context=tls, blocksize=BLOCK
                    )
                    pool.ConnectionCls = cast("Any", HTTPSConnection)
                else:
                    pool = HTTPConnectionPool(
                        target.host, target.port, maxsize=MAX_IDLE, blocksize=BLOCK
                    )
                    pool.ConnectionCls = cast("Any", HTTPConnection)
                self._pools[key] = pool
        conn = cast("http.client.HTTPConnection", pool._get_conn())
        reused = conn.sock is not None
        conn.timeout = timeout
        if conn.sock is not None:
            conn.sock.settimeout(timeout)
        return _Exchange(key, conn, reused)

    def _checkin(self, exchange: _Exchange) -> None:
        with self._lock:
            pool = self._pools.get(exchange.key)
        if not self.keep_alive or pool is None:
            exchange.close()
        else:
            pool._put_conn(cast("Any", exchange.conn))

    def close(self) -> None:
        with self._lock:
            pools, self._pools = self._pools, {}
        for pool in pools.values():
            pool.close()

    def idle_count(self) -> int:
        with self._lock:
            return sum(_idle_count(pool) for pool in self._pools.values())

    # -- credentials ---------------------------------------------------------------

    def tls(self, url: str) -> ssl.SSLContext:
        """The TLS context for ``url``, with its X.509 credential when that loads.

        One that does not (a missing or unreadable file) is left out with a
        warning, as gfal2's ``get_certificate`` does: the request goes ahead
        without it, so a token or a server that asks for no certificate
        still works.
        """
        try:
            return self.context.ssl_context(url, group=self.group)
        except GError as exc:
            _log.warning("Could not load the user credentials: %s", exc.message)
            return self.context.ssl_context(url, group=self.group, x509=False)

    def auth(self, url: str) -> Auth:
        """How to authorise requests for ``url``, as gfal2's ``get_credentials`` does.

        The TLS context always carries the X.509 credential, if there is one:
        gfal2 presents it whatever else it sends.
        """
        Target.of(url)  # a URL davix refuses fails as such, before any lookup
        parsed = parse(url)
        tls = self.tls(url)
        scheme = parsed.scheme.partition("+")[0]
        if scheme in ("cs3", "cs3s"):
            configured = self.context.options.string("BEARER", "TOKEN")
            check_bearer_token(configured)
            return Auth({"Authorization": f"Bearer {configured}"} if configured else {}, tls)
        query = parsed.query_dict()
        if "X-Amz-Signature" in query or "AWSAccessKeyId" in query:
            return Auth(tls=tls)  # a pre-signed URL carries its own credential
        if scheme in OBJECT_STORES:
            return Auth(tls=tls, signer=self.signer_for(parsed))
        token = self.bearer(url, parsed)
        if token:
            check_bearer_token(token)
            return Auth({"Authorization": f"Bearer {token}"}, tls)
        user, password = _basic(self.context, url, parsed)
        if user:
            secret = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
            return Auth({"Authorization": f"Basic {secret}"}, tls)
        return Auth(tls=tls)

    def bearer(self, url: str, parsed: URL) -> str | None:
        """The bearer token for ``url``: by URL prefix, then by bare host, then configured."""
        value, _ = self.context.credentials.get(BEARER, url)
        if not value:
            value, _ = self.context.credentials.get(BEARER, parsed.host)
        return value or self.context.bearer_token(url) or None

    # -- headers -------------------------------------------------------------------

    def standing_headers(self, target: Target, origin: URL) -> dict[str, str]:
        """What every request carries: identity, ClientInfo, configured extras.

        The extras are ``HEADERS`` from the endpoint's own group (``[DAV:HOST]``
        for the URL the caller named, not a redirect's), and only when it has
        none, from ``[HTTP PLUGIN]``.
        """
        headers = {"Host": target.host_header, "User-Agent": self.context.user_agent_string()}
        info = self.context.client_info_string()
        if info:
            headers["ClientInfo"] = info
        if not self.keep_alive:
            headers["Connection"] = "close"
        options = self.context.options
        group = config_group(str(origin))
        if not options.has(group, "HEADERS"):
            group = self.group
        for item in options.string_list(group, "HEADERS"):
            name, sep, value = item.partition(":")
            if sep and name.strip():
                headers[name.strip()] = value.strip()
        return headers

    # -- requests ------------------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: Body | None = None,
        timeout: float = 300.0,
        follow: bool = True,
        cred_url: str | None = None,
        auth: Auth | None = None,
    ) -> Response:
        """Send one request (following redirects) and return the unread response."""
        auth = auth if auth is not None else self.auth(cred_url or url)
        first = Target.of(url, s3=auth.signer is not None)

        def send(request: Request[str, Body]) -> Response:
            target = Target.of(request.url, s3=auth.signer is not None)
            sent = self.standing_headers(target, first.url)
            if auth.headers and _may_forward(first, target):
                sent.update(auth.headers)
            sent.update(headers or {})
            length = _length(request.body)
            if length is not None:
                sent["Content-Length"] = str(length)
                if request.method == "PUT" and length > 0:
                    sent["Expect"] = "100-continue"
            if auth.signer is not None:
                target = auth.signer.target(request.method, target)
                sent.update(auth.signer.sign(request.method, target, sent, request.body))
            raw, exchange, reusable = self._perform(
                request.method, target, sent, request.body, timeout, auth.tls
            )
            return Response(self, exchange, raw, request.url, reusable)

        def advance(request: Request[str, Body], response: Response) -> str | None:
            location = response.header("Location")
            if not (follow and response.status in REDIRECTS and location):
                return None
            response.close()
            target = _resolve(request.url, location)
            _log.debug("%s redirected to %s", request.method, target)
            return target

        return redirects(
            Request[str, Body](method, url, body),
            send,
            advance,
            MAX_REDIRECTS,
            lambda: GError(f"Too many redirections for {url}", errno.ELOOP),
        )

    def _perform(
        self,
        method: str,
        target: Target,
        headers: dict[str, str],
        body: Body | None,
        timeout: float,
        tls: ssl.SSLContext | None,
    ) -> tuple[http.client.HTTPResponse, _Exchange, bool]:
        def send(exchange: _Exchange) -> tuple[http.client.HTTPResponse, _Exchange, bool]:
            exchange.send_head(method, target.path, headers)
            if body is not None and "Expect" in headers:
                early = exchange.wait_continue(method)
                if early is not None:
                    return early, exchange, False
            try:
                if body is not None:
                    self._send_body(exchange, body)
            except _Early as early:
                return early.response, exchange, False
            return exchange.response(), exchange, True

        return attempt(
            lambda: self._checkout(target, tls, timeout),
            send,
            lambda item: item.close(),
            lambda item, error: item.reused and isinstance(error, _STALE),
            transport_error,
        )

    def _send_body(self, exchange: _Exchange, body: Body) -> None:
        try:
            exchange.send_body(body)
        except (BrokenPipeError, ConnectionResetError) as exc:
            # The server may have refused the upload and hung up mid-body; its
            # answer, if it sent one, says why far better than EPIPE does.
            try:
                early = exchange.response()
            except (OSError, http.client.HTTPException):
                raise exc from None
            raise _Early(early) from exc

    # -- streamed uploads ------------------------------------------------------------

    def upload(
        self,
        url: str,
        length: int,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float = 300.0,
        cred_url: str | None = None,
    ) -> Upload:
        """Start a ``PUT`` of ``length`` bytes that the caller then writes piecemeal.

        Redirects and refusals are dealt with here, before any of the body is
        sent, courtesy of ``Expect: 100-continue``.
        """
        auth = self.auth(cred_url or url)
        current = url
        first = Target.of(url, s3=auth.signer is not None)
        for _ in range(MAX_REDIRECTS + 1):
            target = Target.of(current, s3=auth.signer is not None)
            sent = self.standing_headers(target, first.url)
            if auth.headers and _may_forward(first, target):
                sent.update(auth.headers)
            sent.update(headers or {})
            sent["Content-Length"] = str(length)
            if length > 0:
                sent["Expect"] = "100-continue"
            if auth.signer is not None:
                target = auth.signer.target("PUT", target)
                sent.update(auth.signer.sign("PUT", target, sent, None))
            exchange, early = self._start(target, sent, timeout, auth.tls, length)
            if early is None:
                return Upload(self, exchange, current, length)
            response = Response(self, exchange, early, current, False)
            location = response.header("Location")
            if response.status in REDIRECTS and location:
                response.close()
                current = _resolve(current, location)
                continue
            return Upload(self, exchange, current, length, response)
        raise GError(f"Too many redirections for {url}", errno.ELOOP)

    def _start(
        self,
        target: Target,
        headers: dict[str, str],
        timeout: float,
        tls: ssl.SSLContext | None,
        length: int,
    ) -> tuple[_Exchange, http.client.HTTPResponse | None]:
        def send(exchange: _Exchange) -> tuple[_Exchange, http.client.HTTPResponse | None]:
            exchange.send_head("PUT", target.path, headers)
            return exchange, exchange.wait_continue("PUT") if length > 0 else exchange.response()

        return attempt(
            lambda: self._checkout(target, tls, timeout),
            send,
            lambda item: item.close(),
            lambda item, error: item.reused and isinstance(error, _STALE),
            transport_error,
        )


class _Early(Exception):
    """The server answered mid-body; carries that answer out of the send loop."""

    def __init__(self, response: http.client.HTTPResponse) -> None:
        super().__init__(response.status)
        self.response = response


class Upload:
    """A ``PUT`` in flight: :meth:`write` the body, then :meth:`finish`."""

    def __init__(
        self,
        client: HTTPClient,
        exchange: _Exchange,
        url: str,
        length: int,
        early: Response | None = None,
    ) -> None:
        self._client = client
        self._exchange = exchange
        self.url = url
        self.length = length
        self.sent = 0
        self.early = early
        self.done = early is not None

    def write(self, data: bytes | bytearray | memoryview) -> None:
        if self.early is not None:
            return  # the server has answered already; finish() reports it
        size = memoryview(data).nbytes
        if self.sent + size > self.length:
            raise GError(
                f"Writing past the declared size of {self.url} ({self.length} bytes)", errno.EFBIG
            )
        try:
            self._exchange.send(data)
        except (BrokenPipeError, ConnectionResetError) as exc:
            try:
                raw = self._exchange.response()
            except (OSError, http.client.HTTPException):
                self._exchange.close()
                self.done = True
                raise transport_error(exc) from exc
            self.early = Response(self._client, self._exchange, raw, self.url, False)
            return
        except OSError as exc:
            self.abort()
            raise transport_error(exc) from exc
        self.sent += size

    def finish(self) -> Response:
        """The server's answer, once the whole body has gone."""
        if self.early is not None:
            return self.early
        self.done = True
        if self.sent != self.length:
            self._exchange.close()
            raise GError(
                f"Upload of {self.url} closed after {self.sent} of {self.length} bytes",
                errno.EIO,
            )
        try:
            raw = self._exchange.response()
        except (OSError, http.client.HTTPException) as exc:
            self._exchange.close()
            raise transport_error(exc) from exc
        return Response(self._client, self._exchange, raw, self.url)

    def abort(self) -> None:
        """Drop the connection, which is how an HTTP upload is abandoned."""
        self.done = True
        if self.early is not None:
            self.early.close()
        else:
            self._exchange.close()


def _may_forward(first: Target, target: Target) -> bool:
    """Whether the original request's ``Authorization`` may go to ``target``."""
    if target.host == first.host:
        return True
    return not (first.scheme == "https" and target.scheme == "http")


def _resolve(current: str, location: str) -> str:
    """A ``Location`` made absolute; a relative one keeps the current scheme."""
    if scheme_of(location):
        return location
    parsed = parse(current)
    base = f"{wire_scheme(parsed.scheme)}://{parsed.netloc}{parsed.path}"
    joined = urllib.parse.urljoin(base, location)
    return parsed.scheme + joined[joined.index("://") :]


def _basic(context: Gfal2Context, url: str, parsed: URL) -> tuple[str, str]:
    """``USER``/``PASSWD`` from the credential store, else the URL's userinfo."""
    user, _ = context.credentials.get("USER", url)
    if user:
        password, _ = context.credentials.get("PASSWD", url)
        return user, password
    info = parsed.userinfo
    if info:
        name, _, secret = info.partition(":")
        return urllib.parse.unquote(name), urllib.parse.unquote(secret)
    return "", ""
