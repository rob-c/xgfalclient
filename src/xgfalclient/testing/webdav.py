"""An in-process WebDAV / HTTP-TPC / S3 / tape-REST server, for tests.

One threaded :class:`http.server` speaking what grid storage speaks over
HTTP, backed by a real directory so that large files are cheap::

    with WebDAVServer(tmp_path) as server:
        ctx.stat(server.url("/data/f"))            # dav://127.0.0.1:<port>/data/f
        server.requests[-1].method                  # "PROPFIND"

What it answers:

* WebDAV: ``PROPFIND`` (depth 0 and 1), ``MKCOL``, ``DELETE``, ``MOVE``;
  ``GET`` with ``Range``, ``HEAD``, ``PUT`` (``Expect: 100-continue``,
  ``Content-Length`` or chunked); RFC 3230 ``Want-Digest``/``Digest``;
* HTTP third-party ``COPY`` in pull and push mode, streaming performance
  markers, with gridsite delegation (``X-Delegate-To``) when the client
  allows it and the server is told to want it;
* the WLCG tape REST API (:class:`Tape`), macaroon and OAuth token
  issuance, CDMI QoS, and an S3 dialect (:class:`S3`) that checks SigV4
  signatures - header-signed and pre-signed - and does multipart uploads;
* authorisation: bearer tokens, Basic, and client certificates over TLS
  (``tls=pki.server_context()``);
* fault injection (:meth:`WebDAVServer.fault`): a status, a dropped
  connection, a delay, a truncated body - for the next matching request.

Every request is recorded in :attr:`WebDAVServer.requests`.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import http.client
import http.server
import json
import os
import posixpath
import socket
import socketserver
import ssl
import threading
import time
import urllib.parse
import uuid
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO
from xml.sax.saxutils import escape

from ..checksum import crc32c
from ..crypto.proxy import make_request, parse_request
from ..crypto.x509 import load_certificates
from .pki import test_key

__all__ = ["WebDAVServer", "Fault", "Request", "S3", "Tape"]

_CHUNK = 4 << 20
_DAV_NS = "DAV:"


@dataclass
class Request:
    """One request as the server saw it."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes = b""

    def header(self, name: str) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None


@dataclass
class Fault:
    """What to do instead of the real thing, for the next ``times`` matching requests."""

    method: str | None = None
    path: str | None = None
    status: int = 0
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    drop: bool = False
    delay: float = 0.0
    truncate: int | None = None
    times: int = 1

    def matches(self, method: str, path: str) -> bool:
        return (self.method is None or self.method == method) and (
            self.path is None or path.startswith(self.path)
        )


@dataclass
class Tape:
    """Tape REST API state: where each path is, and the staging requests."""

    sitename: str = "XGFAL-TEST"
    #: path -> locality (``DISK``, ``TAPE``, ``DISK_AND_TAPE``, ``LOST``...)
    locality: dict[str, str] = field(default_factory=dict)
    #: How many polls a staged file takes to come online.
    stage_polls: int = 0
    requests: dict[str, dict[str, Any]] = field(default_factory=dict)
    released: list[tuple[str, list[str]]] = field(default_factory=list)
    cancelled: list[tuple[str, list[str]]] = field(default_factory=list)
    #: Replace the discovery document (a JSON-able value, or raw bytes).
    discovery: Any = None
    version: str = "v1"


@dataclass
class S3:
    """S3 dialect: path-style buckets under the root, SigV4 with these keys."""

    access_key: str = "AKIDTEST"
    secret_key: str = "SECRETTEST"
    region: str = "us-east-1"
    token: str = ""
    page_size: int = 1000
    uploads: dict[str, dict[int, bytes]] = field(default_factory=dict)
    #: Speak GCS instead: V4 signed URLs checked against this service account.
    gcs_key: Any = None
    gcs_email: str = ""


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    # Non-daemon and joined on close: a handler still writing its reply when
    # a test ends must finish, not be cut off mid-way.
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True
    app: WebDAVServer

    def finish_request(self, request: Any, client_address: Any) -> None:
        tls = self.app.tls
        if tls is not None:
            try:
                request = tls.wrap_socket(request, server_side=True)
            except (OSError, ssl.SSLError):
                return
        self.app._count_connection()
        with self.app._lock:
            self.app._live.add(request)
        try:
            super().finish_request(request, client_address)
        finally:
            with self.app._lock:
                self.app._live.discard(request)

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # a client hanging up mid-request is part of what is being tested


class WebDAVServer:
    """A threaded HTTP(S) storage element rooted at a local directory."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        tls: ssl.SSLContext | None = None,
        host: str = "127.0.0.1",
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.tls = tls
        self.host = host
        self.httpd = _Server((host, 0), _Handler)
        self.httpd.app = self
        self.port = self.httpd.server_address[1]
        self._lock = threading.Lock()
        self._thread: threading.Thread = threading.Thread(
            target=self.httpd.serve_forever, args=(0.02,), name="xgfal-webdav", daemon=True
        )
        self.requests: list[Request] = []
        self.faults: list[Fault] = []
        self.connections = 0
        self._live: set[Any] = set()
        # -- behaviour switches ------------------------------------------------------
        #: Tokens accepted as ``Authorization: Bearer``; empty accepts anything.
        self.tokens: set[str] = set()
        #: ``(user, password)`` for Basic auth, when set.
        self.basic: tuple[str, str] | None = None
        #: Path prefix -> base URL: requests under it are answered with a 307 there.
        self.redirects: dict[str, str] = {}
        #: Checksums offered with ``Digest``; ``digest_on_head=False`` offers them on GET only.
        self.digests: set[str] = {"adler32", "md5", "crc32c", "sha256", "crc32"}
        self.digest_on_head = True
        #: ``False`` makes this a plain HTTP server: ``PROPFIND`` is refused.
        self.webdav = True
        self.ignore_range = False
        #: ``MKCOL`` makes missing parents (as XrdHttp does) rather than answering 409.
        self.mkcol_parents = False
        #: Do not answer ``Expect: 100-continue`` (the client must time out and send).
        self.send_continue = True
        #: Third-party copy: ``"normal"``, ``"xrootd"`` (answers ``OK`` and hangs up),
        #: ``"eof"`` (markers, then no outcome), ``"fail"``.
        self.tpc = "normal"
        self.marker_every = 1 << 20
        #: Ask for a delegated proxy on ``COPY`` when the client allows it.
        self.delegation = False
        #: ``2`` speaks delegation-2 (and 1); ``1`` only delegation-1.
        self.delegation_version = 2
        #: How long a ``COPY`` waits for the delegated proxy to arrive.
        self.delegation_timeout = 10.0
        self.delegated: dict[str, list[Any]] = {}
        self._delegation_keys: dict[str, Any] = {}
        self._delegation_event = threading.Event()
        self.macaroons: list[dict[str, Any]] = []
        #: Advertise an OAuth token endpoint at ``/token``.
        self.oauth = False
        self.oauth_endpoint: str | None = None
        self.tape: Tape | None = None
        self.s3: S3 | None = None
        #: CDMI QoS state: path -> {"capabilitiesURI": ..., "target": ..., "allowed": [...]}
        self.qos: dict[str, dict[str, Any]] = {}
        #: TLS context for outbound TPC connections.
        self.client_tls: ssl.SSLContext | None = None

    # -- lifecycle ------------------------------------------------------------------

    def start(self) -> WebDAVServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop listening and hang up on every open connection, as a dead server would.

        Only a started server can be stopped.
        """
        self.httpd.shutdown()
        with self._lock:
            live, self._live = list(self._live), set()
        for connection in live:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.httpd.server_close()  # joins the handler threads
        self._thread.join()

    def __enter__(self) -> WebDAVServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- addresses --------------------------------------------------------------------

    @property
    def scheme(self) -> str:
        return "https" if self.tls is not None else "http"

    @property
    def base(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def url(self, path: str = "/", scheme: str | None = None) -> str:
        """A URL for ``path`` with ``scheme`` (default ``dav``/``davs``)."""
        chosen = scheme or ("davs" if self.tls is not None else "dav")
        return f"{chosen}://{self.host}:{self.port}{path}"

    def local(self, path: str) -> Path:
        """The file behind a server path."""
        clean = posixpath.normpath("/" + urllib.parse.unquote(path.split("?")[0]).lstrip("/"))
        return self.root / clean.lstrip("/")

    # -- test hooks -------------------------------------------------------------------

    def fault(self, method: str | None = None, path: str | None = None, **kwargs: Any) -> Fault:
        found = Fault(method, path, **kwargs)
        with self._lock:
            self.faults.append(found)
        return found

    def _take_fault(self, method: str, path: str) -> Fault | None:
        with self._lock:
            for index, candidate in enumerate(self.faults):
                if candidate.matches(method, path):
                    candidate.times -= 1
                    if candidate.times <= 0:
                        del self.faults[index]
                    return candidate
        return None

    def _record(self, request: Request) -> None:
        with self._lock:
            self.requests.append(request)

    def _count_connection(self) -> None:
        with self._lock:
            self.connections += 1

    def methods(self) -> list[str]:
        with self._lock:
            return [request.method for request in self.requests]

    def clear(self) -> None:
        with self._lock:
            self.requests.clear()


# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------


def _digest(path: Path, algorithm: str) -> str:
    rolling: dict[str, Callable[[bytes, int], int]] = {
        "adler32": zlib.adler32,
        "crc32": zlib.crc32,
        "crc32c": crc32c,
    }
    with open(path, "rb") as handle:
        if algorithm in rolling:
            step, value = rolling[algorithm], 1 if algorithm == "adler32" else 0
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                value = step(chunk, value)
            return f"{value:08x}"
        digest = hashlib.new(algorithm)
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
        return base64.b64encode(digest.digest()).decode("ascii")


def _crc(path: Path) -> int:
    return int(_digest(path, "crc32c"), 16)


def _http_date(stamp: float) -> str:
    return email.utils.formatdate(stamp, usegmt=True)


# ---------------------------------------------------------------------------
# SigV4 verification (written independently of the client's signer)
# ---------------------------------------------------------------------------


def _sigv4(
    secret: str,
    region: str,
    stamp: str,
    method: str,
    path: str,
    query: list[tuple[str, str]],
    headers: list[tuple[str, str]],
    payload: str,
) -> str:
    canonical_query = "&".join(
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
        for k, v in sorted(query)
    )
    canonical_headers = "".join(f"{k}:{' '.join(v.split())}\n" for k, v in headers)
    names = ";".join(k for k, _ in headers)
    canonical_path = urllib.parse.quote(urllib.parse.unquote(path), safe="/-_.~")
    request = "\n".join(
        [method, canonical_path, canonical_query, canonical_headers, names, payload]
    )
    scope = f"{stamp[:8]}/{region}/s3/aws4_request"
    to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(request.encode()).hexdigest()]
    )
    key = ("AWS4" + secret).encode()
    for part in (stamp[:8], region, "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    return hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# The handler
# ---------------------------------------------------------------------------


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _Server
    _checked: bool
    _consumed: bool
    _prefetched: bytes | None
    _record: Request

    # -- plumbing -----------------------------------------------------------------------

    @property
    def app(self) -> WebDAVServer:
        return self.server.app

    def log_message(self, format: str, *args: Any) -> None:
        pass  # tests read ``server.requests``, not stderr

    def _reply(
        self,
        status: int,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        *,
        length: int | None = None,
    ) -> None:
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body) if length is None else length))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, document: Any) -> None:
        self._reply(status, json.dumps(document).encode(), {"Content-Type": "application/json"})

    def _read_body(self) -> bytes:
        """The whole request body (read once: handlers call this at most once)."""
        self._record.body = b"".join(self._body_chunks())
        return self._record.body

    def _has_body(self) -> bool:
        chunked = self.headers.get("Transfer-Encoding", "").lower() == "chunked"
        return chunked or int(self.headers.get("Content-Length") or 0) > 0

    def _body_chunks(self) -> Iterator[bytes]:
        if self._prefetched is not None:
            yield self._prefetched
            self._consumed = True
            return
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    self._consumed = True
                    return
                yield self.rfile.read(size)
                self.rfile.readline()
        remaining = int(self.headers.get("Content-Length") or 0)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, _CHUNK))
            if not chunk:
                return
            remaining -= len(chunk)
            yield chunk
        self._consumed = True

    # -- dispatch ---------------------------------------------------------------------------

    def parse_request(self) -> bool:
        # One handler serves every request on a keep-alive connection: reset.
        self._checked = False
        self._prefetched = None
        self._consumed = False
        return super().parse_request()

    def handle_expect_100(self) -> bool:
        if self._precheck():
            return False
        if self.app.send_continue:
            # With a header, as XrdHttp sends it: a client must skip those too.
            self.send_response_only(100)
            self.send_header("Server", "xgfal-test")
            self.end_headers()
        return True

    def _dispatch(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if not self._checked and 0 < length <= 1 << 20:
            # A small body is read before any early answer: hanging up on
            # unread data makes the client's kernel discard that answer.
            self._prefetched = self.rfile.read(length)
        if not self._checked and self._precheck():
            return
        self._route(urllib.parse.urlsplit(self.path).path)
        if self._has_body() and not self._consumed:
            self.close_connection = True  # answered without reading the body

    def _precheck(self) -> bool:
        """Record, then faults, redirects and authorisation; ``True`` if answered."""
        self._checked = True
        self._record = Request(self.command, self.path, dict(self.headers.items()))
        self.app._record(self._record)
        answered = self._intercept()
        if answered and self._has_body():
            self.close_connection = True  # the body was never read
        return answered

    def _intercept(self) -> bool:
        path = urllib.parse.urlsplit(self.path).path
        found = self.app._take_fault(self.command, self.path)
        if found is not None:
            if found.delay:
                time.sleep(found.delay)
            if found.drop:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return True
            if found.truncate is not None:
                self.send_response(found.status or 200)
                self.send_header("Content-Length", str(len(found.body)))
                self.end_headers()
                self.wfile.write(found.body[: found.truncate])
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return True
            if found.status:
                self._reply(found.status, found.body, found.headers)
                return True
        for prefix, target in self.app.redirects.items():
            if path.startswith(prefix):
                self._reply(307, b"", {"Location": target + self.path})
                return True
        return self._refused()

    def _refused(self) -> bool:
        app = self.app
        auth = self.headers.get("Authorization", "")
        if app.s3 is not None:
            if self._s3_verified():
                return False
            self._reply(403, b"<Error><Code>SignatureDoesNotMatch</Code></Error>")
            return True
        if app.tokens:
            issued = {m["macaroon"] for m in app.macaroons}
            if auth.startswith("Bearer ") and auth[7:] in (app.tokens | issued):
                return False
            if not auth and self._client_subject():
                return False  # a certificate is as good as a token here
            self._reply(401, b"token required", {"WWW-Authenticate": "Bearer"})
            return True
        if app.basic is not None:
            expected = base64.b64encode(":".join(app.basic).encode()).decode()
            if auth != f"Basic {expected}":
                self._reply(401, b"login required", {"WWW-Authenticate": "Basic"})
                return True
        return False

    def _client_subject(self) -> str:
        getter = getattr(self.connection, "getpeercert", None)
        cert = getter() if getter is not None else None
        return str(cert.get("subject", "")) if cert else ""

    def do_GET(self) -> None:
        self._dispatch()

    do_HEAD = do_PUT = do_DELETE = do_MKCOL = do_MOVE = do_COPY = do_PROPFIND = do_POST = do_GET

    def _route(self, path: str) -> None:
        app = self.app
        method = self.command
        if path == "/.well-known/wlcg-tape-rest-api" or path.startswith("/api/v1/"):
            self._tape(path)
        elif path in (
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
        ):
            self._oauth_discovery()
        elif path == "/token" and method == "POST":
            self._oauth_token()
        elif path == "/gridsite-delegation" and method == "POST":
            self._delegation()
        elif "cdmi" in self.headers.get("Accept", "") or path.startswith("/cdmi_capabilities/"):
            self._cdmi(path)
        elif app.s3 is not None:
            self._s3(path)
        elif method == "POST" and self.headers.get("Content-Type", "").startswith(
            "application/macaroon-request"
        ):
            self._macaroon(path)
        else:
            handler = getattr(self, f"_dav_{method.lower()}", None)
            if handler is None:
                self._reply(405, b"method not allowed")
            else:
                handler(path)

    # -- WebDAV ---------------------------------------------------------------------------

    def _dav_propfind(self, path: str) -> None:
        self._read_body()
        if not self.app.webdav:
            self._reply(405, b"PROPFIND not supported")
            return
        target = self.app.local(path)
        if not target.exists():
            self._reply(404, b"Unable to find file")
            return
        depth = self.headers.get("Depth", "infinity")
        entries = [(path, target)]
        if depth == "1" and target.is_dir():
            base = path if path.endswith("/") else path + "/"
            entries += [(base + child.name, child) for child in sorted(target.iterdir())]
        parts = [f'<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="{_DAV_NS}">']
        for href, local in entries:
            parts.append(_propfind_entry(href, local))
        parts.append("</D:multistatus>")
        self._reply(207, "".join(parts).encode(), {"Content-Type": 'text/xml; charset="utf-8"'})

    def _dav_mkcol(self, path: str) -> None:
        target = self.app.local(path)
        if target.exists():
            self._reply(405, b"exists")
        elif not target.parent.is_dir() and not self.app.mkcol_parents:
            self._reply(409, b"parent missing")
        else:
            target.mkdir(parents=True)
            self._reply(201, b"Created")

    def _dav_delete(self, path: str) -> None:
        target = self.app.local(path)
        if not target.exists():
            self._reply(404, b"not found")
        elif target.is_dir():
            if any(target.iterdir()):
                self._reply(409, b"directory not empty")
            else:
                target.rmdir()
                self._reply(204)
        else:
            target.unlink()
            self._reply(204)

    def _dav_move(self, path: str) -> None:
        target = self.app.local(path)
        destination = urllib.parse.urlsplit(self.headers.get("Destination", "")).path
        if not target.exists():
            self._reply(404, b"not found")
            return
        os.replace(target, self.app.local(destination))
        self._reply(201, b"Created")

    def _range(self, size: int) -> tuple[int, int] | None:
        """``(start, end)`` of the Range asked for (``start >= size``: unsatisfiable)."""
        header = self.headers.get("Range", "")
        if not header.startswith("bytes=") or self.app.ignore_range:
            return None
        first, _, last = header[6:].partition("-")
        start = int(first)
        end = min(int(last), size - 1) if last else size - 1
        return start, end

    def _digest_headers(self, target: Path, is_get: bool) -> dict[str, str]:
        wanted = self.headers.get("Want-Digest", "")
        if not wanted or (not is_get and not self.app.digest_on_head):
            return {}
        values = []
        for item in wanted.split(","):
            name = item.split(";")[0].strip().lower()
            if name in self.app.digests:
                values.append(f"{name}={_digest(target, name)}")
        return {"Digest": ",".join(values)} if values else {}

    def _dav_head(self, path: str) -> None:
        self._dav_get(path)

    def _dav_get(self, path: str) -> None:
        target = self.app.local(path)
        if not target.is_file():
            missing = not target.exists() or self.app.s3 is not None  # S3 has no directories
            self._reply(404 if missing else 403, b"not a file")
            return
        size = target.stat().st_size
        headers = {
            "Last-Modified": _http_date(target.stat().st_mtime),
            "Accept-Ranges": "bytes",
            "ETag": f'"{base64.b64decode(_digest(target, "md5")).hex()}"'
            if self.app.s3 is not None
            else "",
            **self._digest_headers(target, self.command == "GET"),
        }
        if self.app.s3 is not None and self.app.s3.gcs_key is not None:
            crc = base64.b64encode(_crc(target).to_bytes(4, "big")).decode()
            headers["x-goog-hash"] = f"crc32c={crc},md5={_digest(target, 'md5')}"
        headers = {k: v for k, v in headers.items() if v}
        span = self._range(size)
        if span is not None and span[0] >= size:
            self._reply(416, b"", {"Content-Range": f"bytes */{size}"})
            return
        status, start, end = (200, 0, size - 1) if span is None else (206, span[0], span[1])
        if status == 206:
            headers["Content-Range"] = f"bytes {start}-{end}/{size}"
        count = max(end - start + 1, 0)
        self._reply(status, b"", headers, length=count)
        if self.command == "GET" and count:
            with open(target, "rb") as handle:
                self.connection.sendfile(handle, start, count)

    def _dav_put(self, path: str) -> None:
        target = self.app.local(path)
        if target.is_dir():
            self.close_connection = True
            self._reply(405, b"is a directory")
            return
        if not target.parent.is_dir():
            if self.app.s3 is None:
                self.close_connection = True
                self._reply(409, b"parent missing")
                return
            target.parent.mkdir(parents=True)
        existed = target.exists()
        with open(target, "wb") as handle:
            for chunk in self._body_chunks():
                handle.write(chunk)
        self._reply(204 if existed else 201, b"")

    # -- third-party copy -------------------------------------------------------------------

    def _dav_copy(self, path: str) -> None:
        source = self.headers.get("Source")
        destination = self.headers.get("Destination")
        target = self.app.local(path)
        if not source and not destination:
            self._reply(400, b"COPY needs Source or Destination")
            return
        if self.app.tpc == "xrootd":
            self.close_connection = True
            self._reply(200, b"OK", {"Connection": "Close"})
            return
        headers = {"Content-Type": "text/plain", "Transfer-Encoding": "chunked"}
        delegate = self.app.delegation and self.headers.get("Credential") is None
        if delegate:
            self.app._delegation_event.clear()
            headers["X-Delegate-To"] = f"{self.app.base}/gridsite-delegation"
        self.send_response(202)
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        if delegate and not self.app._delegation_event.wait(self.app.delegation_timeout):
            # One write: the client hangs up on reading "failure", and a
            # second write could then hit a closed socket.
            line = b"failure: no delegated credential arrived\n"
            self.wfile.write(f"{len(line):x}\r\n".encode() + line + b"\r\n0\r\n\r\n")
            return
        if self.app.tpc == "fail":
            self._chunk(b"failure: HTTP 500 : the remote side refused\n")
        elif source:
            self._pull(source, target)
        else:
            assert destination is not None
            self._push(target, destination)
        self._chunk(b"")

    def _chunk(self, data: bytes) -> None:
        self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")

    def _marker(self, moved: int) -> None:
        stamp = int(time.time())
        self._chunk(
            (
                "Perf Marker\n"
                f"\tTimestamp: {stamp}\n"
                "\tStripe Index: 0\n"
                f"\tStripe Bytes Transferred: {moved}\n"
                "\tTotal Stripe Count: 1\n"
                "End\n"
            ).encode()
        )

    def _remote(
        self, url: str, method: str, body: BinaryIO | None = None, size: int = 0
    ) -> http.client.HTTPResponse:
        parts = urllib.parse.urlsplit(url)
        connection: http.client.HTTPConnection
        # http.client splits ``host:port`` itself, with the scheme's default port.
        if parts.scheme == "https":
            connection = http.client.HTTPSConnection(
                parts.netloc, context=self.app.client_tls, timeout=30
            )
        else:
            connection = http.client.HTTPConnection(parts.netloc, timeout=30)
        headers = {
            name[len("TransferHeader") :]: value
            for name, value in self.headers.items()
            if name.startswith("TransferHeader")
        }
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        if body is not None:
            headers["Content-Length"] = str(size)
        connection.request(method, target, body=body, headers=headers)
        return connection.getresponse()

    def _pull(self, source: str, target: Path) -> None:
        try:
            response = self._remote(source, "GET")
        except OSError as exc:
            self._chunk(f"failure: could not reach the source: {exc}\n".encode())
            return
        if response.status != 200:
            self._chunk(f"failure: source answered HTTP {response.status}\n".encode())
            return
        moved = 0
        with open(target, "wb") as handle:
            for chunk in iter(lambda: response.read(self.app.marker_every), b""):
                handle.write(chunk)
                moved += len(chunk)
                self._marker(moved)
        if self.app.tpc == "eof":
            return
        self._chunk(b"success: Created\n")

    def _push(self, target: Path, destination: str) -> None:
        if not target.is_file():
            self._chunk(b"failure: HTTP 404 : the source does not exist\n")
            return
        size = target.stat().st_size
        try:
            with open(target, "rb") as handle:
                response = self._remote(destination, "PUT", handle, size)
        except OSError as exc:
            self._chunk(f"failure: could not reach the destination: {exc}\n".encode())
            return
        response.read()
        if response.status not in (200, 201, 204):
            self._chunk(f"failure: destination answered HTTP {response.status}\n".encode())
            return
        self._marker(size)
        self._chunk(b"success: Created\n")

    # -- tokens -----------------------------------------------------------------------------

    def _macaroon(self, path: str) -> None:
        request = json.loads(self._read_body() or b"{}")
        token = f"mac-{uuid.uuid4().hex}"
        self.app.macaroons.append({"path": path, "macaroon": token, **request})
        self._json(200, {"macaroon": token, "uri": {"targetWithMacaroon": path}})

    def _oauth_discovery(self) -> None:
        if not self.app.oauth:
            self._reply(404, b"no oauth here")
            return
        endpoint = self.app.oauth_endpoint or f"{self.app.base}/token"
        self._json(200, {"issuer": self.app.base, "token_endpoint": endpoint})

    def _oauth_token(self) -> None:
        form = urllib.parse.parse_qs(self._read_body().decode())
        token = f"oauth-{uuid.uuid4().hex}"
        self.app.macaroons.append({"macaroon": token, "form": form})
        self._json(200, {"access_token": token, "token_type": "bearer"})

    # -- delegation ---------------------------------------------------------------------------

    def _delegation(self) -> None:
        body = self._read_body().decode()
        app = self.app
        fault = (
            '<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV='
            '"http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><SOAP-ENV:Fault>'
            "<faultstring>{}</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        )
        if "getNewProxyReq" in body and app.delegation_version >= 2:
            delegation_id = uuid.uuid4().hex[:16]
            self._soap(
                "getNewProxyReqResponse",
                f"<getNewProxyReqReturn><proxyRequest>{self._new_request(delegation_id)}"
                f"</proxyRequest><delegationID>{delegation_id}</delegationID>"
                "</getNewProxyReqReturn>",
            )
        elif "getProxyReq" in body:
            delegation_id = body.split("<delegationID>")[1].split("</delegationID>")[0]
            self._soap(
                "getProxyReqResponse",
                f"<getProxyReqReturn>{self._new_request(delegation_id)}</getProxyReqReturn>",
            )
        elif "putProxy" in body:
            delegation_id = body.split("<delegationID>")[1].split("</delegationID>")[0]
            proxy = body.split("<proxy>")[1].split("</proxy>")[0]
            chain = load_certificates(
                proxy.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
            )
            expected = app._delegation_keys.get(delegation_id)
            if not chain or expected is None or chain[0].public_key != expected:
                self._reply(500, fault.format("the proxy does not match the request").encode())
                return
            app.delegated[delegation_id] = chain
            app._delegation_event.set()
            self._soap("putProxyResponse", "")
        else:
            self._reply(500, fault.format("unknown operation").encode())

    def _new_request(self, delegation_id: str) -> str:
        key = test_key(4)
        request = make_request(key)
        self.app._delegation_keys[delegation_id] = parse_request(request).public_key
        der = base64.encodebytes(request).decode("ascii")
        return escape(
            f"-----BEGIN CERTIFICATE REQUEST-----\n{der}-----END CERTIFICATE REQUEST-----\n"
        )

    def _soap(self, element: str, inner: str) -> None:
        document = (
            '<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope '
            'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:ns="http://www.gridsite.org/namespaces/delegation-2"><SOAP-ENV:Body>'
            f"<ns:{element}>{inner}</ns:{element}></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        )
        self._reply(200, document.encode(), {"Content-Type": "text/xml"})

    # -- tape REST ----------------------------------------------------------------------------

    def _tape(self, path: str) -> None:
        tape = self.app.tape
        if tape is None:
            self._reply(403, b"tape REST API not enabled")
            return
        if path == "/.well-known/wlcg-tape-rest-api":
            discovery = tape.discovery
            if isinstance(discovery, bytes):
                self._reply(200, discovery)
                return
            if discovery is None:
                discovery = {
                    "sitename": tape.sitename,
                    "description": "xgfal test tape",
                    "endpoints": [
                        {"uri": f"{self.app.base}/api/v1/", "version": tape.version, "metadata": {}}
                    ],
                }
            self._json(200, discovery)
            return
        body = self._read_body()
        document: Any = json.loads(body) if body else {}
        route = path[len("/api/v1/") :].strip("/").split("/")
        if route == ["stage"] and self.command == "POST":
            request_id = uuid.uuid4().hex
            tape.requests[request_id] = {
                "files": [dict(entry) for entry in document["files"]],
                "polls": 0,
            }
            self._json(201, {"requestId": request_id})
        elif route[0] == "stage" and len(route) == 2 and self.command == "GET":
            request = tape.requests.get(route[1])
            if request is None:
                self._reply(404, b"no such request")
                return
            request["polls"] += 1
            files = []
            for entry in request["files"]:
                online = request["polls"] > tape.stage_polls
                locality = tape.locality.get(entry["path"], "TAPE")
                if locality in ("LOST", "NONE"):
                    files.append(
                        {"path": entry["path"], "error": f"file is {locality}", "state": "FAILED"}
                    )
                elif entry.get("cancelled"):
                    files.append({"path": entry["path"], "state": "CANCELLED", "onDisk": False})
                else:
                    files.append(
                        {
                            "path": entry["path"],
                            "state": "COMPLETED" if online else "STARTED",
                            "onDisk": online,
                        }
                    )
            self._json(200, {"id": route[1], "createdAt": 0, "files": files})
        elif route[0] == "stage" and len(route) == 3 and route[2] == "cancel":
            request = tape.requests.get(route[1])
            if request is None:
                self._reply(404, b"no such request")
                return
            for entry in request["files"]:
                if entry["path"] in document["paths"]:
                    entry["cancelled"] = True
            tape.cancelled.append((route[1], list(document["paths"])))
            self._reply(200)
        elif route[0] == "release" and len(route) == 2:
            tape.released.append((route[1], list(document["paths"])))
            self._reply(200)
        elif route == ["archiveinfo"]:
            answer = []
            for item in document["paths"]:
                where = tape.locality.get(item)
                if where is None:
                    answer.append({"path": item, "error": "USER ERROR: file not found"})
                else:
                    answer.append({"path": item, "locality": where})
            self._json(200, answer)
        else:
            self._reply(404, b"unknown tape API call")

    # -- CDMI ---------------------------------------------------------------------------------

    def _cdmi(self, path: str) -> None:
        qos = self.app.qos
        if path.startswith("/cdmi_capabilities/"):
            kind = path[len("/cdmi_capabilities/") :].strip("/")
            if "/" in kind or kind not in ("dataobject", "container"):
                state = qos.get(path)
                if state is None:
                    self._reply(404, b"no such class")
                    return
                self._json(200, {"objectName": kind, "metadata": state})
                return
            children = sorted(
                {p.split("/")[3] + "/" for p in qos if p.startswith(f"/cdmi_capabilities/{kind}/")}
            )
            self._json(200, {"children": children})
            return
        state = qos.get(path)
        if state is None:
            self._reply(404, b"no such object")
            return
        if self.command == "PUT":
            request = json.loads(self._read_body())
            state["metadata"]["cdmi_capabilities_target"] = request["capabilitiesURI"]
            self._reply(204)
            return
        self._json(200, state)

    # -- S3 -----------------------------------------------------------------------------------

    def _s3_verified(self) -> bool:
        s3 = self.app.s3
        assert s3 is not None
        parts = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        values = dict(query)
        if s3.gcs_key is not None:
            return self._gcs_verified(parts.path, query, values)
        if "X-Amz-Signature" in values:
            stamp = values["X-Amz-Date"]
            signed = [(k, v) for k, v in query if k != "X-Amz-Signature"]
            headers = [("host", self.headers.get("Host", ""))]
            expected = _sigv4(
                s3.secret_key,
                s3.region,
                stamp,
                self.command,
                parts.path,
                signed,
                headers,
                "UNSIGNED-PAYLOAD",
            )
            return hmac.compare_digest(expected, values["X-Amz-Signature"])
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("AWS4-HMAC-SHA256 "):
            return False
        fields = dict(
            item.strip().split("=", 1) for item in auth[len("AWS4-HMAC-SHA256 ") :].split(",")
        )
        if not fields.get("Credential", "").startswith(s3.access_key + "/"):
            return False
        if s3.token and self.headers.get("x-amz-security-token") != s3.token:
            return False
        names = fields["SignedHeaders"].split(";")
        headers = [(name, self.headers.get(name, "")) for name in names]
        payload = self.headers.get("x-amz-content-sha256", "")
        expected = _sigv4(
            s3.secret_key,
            s3.region,
            self.headers.get("x-amz-date", ""),
            self.command,
            parts.path,
            query,
            headers,
            payload,
        )
        return hmac.compare_digest(expected, fields.get("Signature", ""))

    def _gcs_verified(
        self, path: str, query: list[tuple[str, str]], values: dict[str, str]
    ) -> bool:
        s3 = self.app.s3
        assert s3 is not None
        signature = values.get("X-Goog-Signature", "")
        credential = values.get("X-Goog-Credential", "")
        if not signature or not credential.startswith(s3.gcs_email + "/"):
            return False
        signed = sorted((k, v) for k, v in query if k != "X-Goog-Signature")
        canonical_query = "&".join(
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}" for k, v in signed
        )
        canonical = "\n".join(
            [
                self.command,
                urllib.parse.quote(urllib.parse.unquote(path), safe="/-_.~"),
                canonical_query,
                f"host:{self.headers.get('Host', '')}\n",
                "host",
                "UNSIGNED-PAYLOAD",
            ]
        )
        scope = credential.partition("/")[2]
        to_sign = "\n".join(
            [
                "GOOG4-RSA-SHA256",
                values.get("X-Goog-Date", ""),
                scope,
                hashlib.sha256(canonical.encode()).hexdigest(),
            ]
        )
        return bool(s3.gcs_key.verify(to_sign.encode(), bytes.fromhex(signature), digest="sha256"))

    def _s3(self, path: str) -> None:
        s3 = self.app.s3
        assert s3 is not None
        query = dict(
            urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
        )
        method = self.command
        bucket = path.lstrip("/").partition("/")[0]
        if method == "GET" and ("list-type" in query or "delimiter" in query):
            self._s3_list(bucket, query)
        elif method == "POST" and "uploads" in query:
            upload_id = uuid.uuid4().hex
            s3.uploads[upload_id] = {}
            self._reply(
                200,
                f"<InitiateMultipartUploadResult><UploadId>{upload_id}</UploadId>"
                "</InitiateMultipartUploadResult>".encode(),
            )
        elif method == "PUT" and "uploadId" in query:
            data = b"".join(self._body_chunks())
            s3.uploads[query["uploadId"]][int(query["partNumber"])] = data
            self._reply(200, b"", {"ETag": f'"{hashlib.md5(data).hexdigest()}"'})
        elif method == "POST" and "uploadId" in query:
            self._read_body()
            parts = s3.uploads.pop(query["uploadId"])
            target = self.app.local(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as handle:
                for number in sorted(parts):
                    handle.write(parts[number])
            self._reply(200, b"<CompleteMultipartUploadResult/>")
        elif method == "DELETE" and "uploadId" in query:
            s3.uploads.pop(query["uploadId"], None)
            self._reply(204)
        elif method == "DELETE":
            target = self.app.local(path)
            if target.is_file():
                target.unlink()
            self._reply(204)
        elif method in ("GET", "HEAD", "PUT"):
            getattr(self, f"_dav_{method.lower()}")(path)
        else:
            self._reply(405, b"<Error><Code>MethodNotAllowed</Code></Error>")

    def _s3_list(self, bucket: str, query: dict[str, str]) -> None:
        s3 = self.app.s3
        assert s3 is not None
        root = self.app.local("/" + bucket)
        if not root.is_dir():
            self._reply(404, b"<Error><Code>NoSuchBucket</Code></Error>")
            return
        prefix = query.get("prefix", "")
        keys = sorted(
            str(item.relative_to(root)).replace(os.sep, "/")
            for item in root.rglob("*")
            if item.is_file()
        )
        keys = [key for key in keys if key.startswith(prefix)]
        v1 = "list-type" not in query
        start = int(query.get("marker" if v1 else "continuation-token") or 0)
        limit = min(int(query.get("max-keys") or s3.page_size), s3.page_size)
        contents, prefixes = [], []
        for key in keys:
            rest = key[len(prefix) :]
            if "/" in rest:
                common = prefix + rest.split("/")[0] + "/"
                if common not in prefixes:
                    prefixes.append(common)
            else:
                contents.append(key)
        items = [("P", p) for p in prefixes] + [("K", k) for k in contents]
        page = items[start : start + limit]
        truncated = start + limit < len(items)
        body = [
            '<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        ]
        for kind, name in page:
            if kind == "P":
                body.append(f"<CommonPrefixes><Prefix>{escape(name)}</Prefix></CommonPrefixes>")
            else:
                stat = (root / name).stat()
                modified = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(stat.st_mtime))
                body.append(
                    f"<Contents><Key>{escape(name)}</Key><Size>{stat.st_size}</Size>"
                    f"<LastModified>{modified}</LastModified></Contents>"
                )
        body.append(f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>")
        if truncated:
            name = "NextMarker" if v1 else "NextContinuationToken"
            body.append(f"<{name}>{start + limit}</{name}>")
        body.append("</ListBucketResult>")
        self._reply(200, "".join(body).encode(), {"Content-Type": "application/xml"})


def _propfind_entry(href: str, local: Path) -> str:
    info = local.stat()
    is_dir = local.is_dir()
    kind = "<D:collection/>" if is_dir else ""
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(info.st_ctime))
    return (
        f"<D:response><D:href>{escape(urllib.parse.quote(href))}</D:href><D:propstat><D:prop>"
        f"<D:getcontentlength>{4096 if is_dir else info.st_size}</D:getcontentlength>"
        f"<D:getlastmodified>{_http_date(info.st_mtime)}</D:getlastmodified>"
        f"<D:creationdate>{created}</D:creationdate>"
        f"<D:resourcetype>{kind}</D:resourcetype>"
        "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
    )
