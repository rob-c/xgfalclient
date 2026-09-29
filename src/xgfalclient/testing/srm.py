"""An in-process SRM v2.2 server over httpg, for testing the ``srm`` plugin.

It speaks what dCache, StoRM and DPM speak - SOAP 1.1 rpc/encoded in the
``http://srm.lbl.gov/StorageResourceManager`` namespace, over TLS with GSI's
delegation byte - well enough to drive real gfal2 as well as this package's
plugin. The namespace is a local directory, and transfer URLs point into it
with ``file://`` (or at any other server you name per protocol), so copies
through it move real bytes::

    with SRMServer(pki.server_context(), tmp_path) as srm:
        ctx.stat(srm.url("/data/f"))

What it models:

* the namespace calls: ``srmLs`` (levels, ``offset``/``count`` paging,
  ``SRM_TOO_MANY_RESULTS`` past :attr:`~SRMServer.max_ls` entries),
  ``srmMkdir``, ``srmRmdir``, ``srmRm``, ``srmMv``, ``srmSetPermission``,
  ``srmCheckPermission`` and ``srmPing``;
* asynchronous requests with tokens - ``srmPrepareToGet``/``Put``,
  ``srmBringOnline``, and ``srmLs`` when ``ls_queue_polls`` is set - that
  stay queued for ``queue_polls`` status calls;
* tape: :meth:`~SRMServer.set_locality` makes a file ``NEARLINE`` (staged
  after ``stage_polls`` polls), ``ONLINE_AND_NEARLINE``, ``LOST`` or
  ``UNAVAILABLE``;
* space tokens (:attr:`~SRMServer.spaces`), checked on puts and gets;
* fault injection: :meth:`~SRMServer.inject` replaces the next reply(s) to
  an operation with bytes of your choosing, an HTTP error, or a dropped
  connection.

Every request body is kept in :attr:`~SRMServer.log`, for tests that check
what went over the wire.
"""

from __future__ import annotations

import itertools
import os
import posixpath
import shutil
import ssl
import stat as _stat
import threading
import zlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import TCPServer, ThreadingMixIn
from typing import Any, Union

from ..errors import GError
from ..plugins.srm import soap
from ..plugins.srm.transport import parse_surl

__all__ = ["SRMServer", "Reply", "Space", "DROP"]

Fields = soap.Fields


@dataclass
class Reply:
    """An injected answer: ``body`` with HTTP ``status``; ``close`` drops the line."""

    body: bytes = b""
    status: int = 200
    close: bool = False


#: Inject this to have the server hang up instead of answering.
DROP = Reply(close=True)

Injection = Union[bytes, Reply, Callable[[soap.Node], Union[bytes, Reply, None]]]


@dataclass
class Space:
    """A space reservation, as ``srmGetSpaceMetaData`` describes it."""

    description: str
    total: int = 1 << 40
    guaranteed: int = 1 << 40
    unused: int = 1 << 39
    lifetime: int = -1
    retention: str = "REPLICA"
    latency: str = "ONLINE"
    owner: str = "xgfal"


@dataclass
class File:
    """One file of an asynchronous request."""

    surl: str
    path: str
    code: str
    explanation: str = ""
    turl: str = ""
    size: int | None = None
    wait: int = 0
    stage: bool = False


@dataclass
class Request:
    """An asynchronous request, by token; tests inspect these."""

    token: str
    kind: str
    files: list[File] = field(default_factory=list)
    protocol: str = ""
    spacetoken: str = ""
    started: bool = False
    #: For a queued ``srmLs``: the reply it will give once it is done.
    listing: Fields = field(default_factory=list)


def _status(code: str, explanation: str = "") -> Fields:
    return [("statusCode", code), ("explanation", explanation or None)]


def _only(code: str, explanation: str = "") -> Fields:
    return [("returnStatus", _status(code, explanation))]


def _aggregate(codes: Iterable[str]) -> str:
    """A request's status from its files': all good, some good, or none."""
    codes = list(codes)
    if any(code in soap.PENDING for code in codes):
        return "SRM_REQUEST_INPROGRESS"
    good = sum(code in soap.SUCCESS for code in codes)
    if good == len(codes):
        return "SRM_SUCCESS"
    return "SRM_PARTIAL_SUCCESS" if good else "SRM_FAILURE"


def _adler32(path: Path) -> str:
    value = 1
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value = zlib.adler32(chunk, value)
    return f"{value:08x}"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _TCPServer

    def setup(self) -> None:
        srm = self.server.srm
        self.request.settimeout(srm.io_timeout)
        tls = srm.tls.wrap_socket(self.request, server_side=True)
        if srm.globus_turn and tls.version() == "TLSv1.3":
            tls.sendall(b"\x00")  # globus-gssapi's TLS 1.3 "your turn" token
        if tls.recv(1) != b"0":  # the GSI delegation flag: no delegation taken here
            tls.close()
            raise ConnectionError("unexpected GSI delegation flag")
        with srm.lock:
            srm.connections += 1
        self.request = self.connection = tls
        super().setup()

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() != "chunked":
            return self.rfile.read(int(self.headers.get("Content-Length") or 0))
        chunks: list[bytes] = []
        while True:
            size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
            if size == 0:
                self.rfile.readline()
                return b"".join(chunks)
            chunks.append(self.rfile.read(size))
            self.rfile.readline()

    def do_POST(self) -> None:
        srm = self.server.srm
        reply = srm.dispatch(self._body(), dict(self.headers.items()))
        if reply.close:
            self.close_connection = True
            return
        self.send_response(reply.status)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(reply.body)))
        if not srm.keep_alive:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(reply.body)


class _TCPServer(ThreadingMixIn, TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    srm: SRMServer

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # a client that hangs up mid-handshake is not a server failure


_OPERATIONS = (
    "srmPing",
    "srmLs",
    "srmStatusOfLsRequest",
    "srmMkdir",
    "srmRmdir",
    "srmRm",
    "srmMv",
    "srmSetPermission",
    "srmCheckPermission",
    "srmPrepareToGet",
    "srmStatusOfGetRequest",
    "srmPrepareToPut",
    "srmStatusOfPutRequest",
    "srmPutDone",
    "srmReleaseFiles",
    "srmAbortFiles",
    "srmAbortRequest",
    "srmBringOnline",
    "srmStatusOfBringOnlineRequest",
    "srmGetSpaceTokens",
    "srmGetSpaceMetaData",
)


class SRMServer:
    """A threaded SRM v2.2 endpoint serving ``root`` at ``/srm/managerv2``.

    ``tls`` is a server context (``PKI.server_context()``). ``protocols``
    maps a TURL protocol to the URL prefix under which ``root`` is reachable
    that way; the default serves ``file://`` TURLs straight into ``root``.
    Of the protocols a client asks for, the first in the map is used.
    """

    def __init__(
        self,
        tls: ssl.SSLContext,
        root: Path | str,
        *,
        host: str = "localhost",
        port: int = 0,
        protocols: dict[str, str] | None = None,
        queue_polls: int = 0,
        stage_polls: int = 1,
        ls_queue_polls: int = 0,
        max_ls: int = 1000,
        checksum_type: str | None = "ADLER32",
        keep_alive: bool = True,
        multiref: bool = False,
        backend: str = "xgfal",
        io_timeout: float = 30.0,
        globus_turn: bool = False,
    ) -> None:
        # globus-gssapi (CGSI-gSOAP's GSI) runs the handshake as TLS 1.2 token
        # ping-pong: under TLS 1.3 its initiator waits for a server token after
        # its own Finished and then misreads session tickets as data. So this
        # speaks TLS 1.2, unless ``globus_turn`` asks for TLS 1.3 the way a
        # globus acceptor does it - a NUL "turn" byte after the handshake.
        # (dCache speaks TLS 1.3 without the byte.)
        self.globus_turn = globus_turn
        if globus_turn:
            tls.num_tickets = 0
        else:
            tls.maximum_version = ssl.TLSVersion.TLSv1_2
        self.tls = tls
        self.root = Path(root)
        self.protocols = protocols if protocols is not None else {"file": f"file://{self.root}"}
        self.queue_polls = queue_polls
        self.stage_polls = stage_polls
        self.ls_queue_polls = ls_queue_polls
        self.max_ls = max_ls
        self.checksum_type = checksum_type
        self.keep_alive = keep_alive
        self.multiref = multiref
        self.backend = backend
        self.io_timeout = io_timeout
        self.lock = threading.RLock()
        self.connections = 0
        self.log: list[tuple[str, bytes]] = []
        self.headers: list[dict[str, str]] = []
        self.requests: dict[str, Request] = {}
        self.spaces: dict[str, Space] = {}
        self.released: list[str] = []
        self._locality: dict[str, str] = {}
        self._injected: dict[str, list[Injection]] = {}
        self._tokens = itertools.count(1)
        self._server = _TCPServer((host, port), _Handler)
        self._server.srm = self
        self.host = host
        self.port = int(self._server.server_address[1])
        self._operations: dict[str, Callable[[soap.Node], Fields]] = {
            name: getattr(self, "_" + name) for name in _OPERATIONS
        }

    # -- lifecycle -----------------------------------------------------------------

    def start(self) -> SRMServer:
        threading.Thread(target=self._server.serve_forever, name="xgfal-srm", daemon=True).start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> SRMServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- addressing ----------------------------------------------------------------

    @property
    def endpoint(self) -> str:
        return f"httpg://{self.host}:{self.port}/srm/managerv2"

    def url(self, path: str) -> str:
        """The short SURL of ``path``."""
        return f"srm://{self.host}:{self.port}{path}"

    def full_url(self, path: str) -> str:
        """The ``?SFN=`` SURL of ``path``."""
        return f"srm://{self.host}:{self.port}/srm/managerv2?SFN={path}"

    def local(self, path: str) -> Path:
        """Where ``path`` lives on disk (whether or not it exists)."""
        clean = posixpath.normpath("/" + path.lstrip("/"))
        return self.root / clean.lstrip("/")

    # -- knobs ---------------------------------------------------------------------

    def set_locality(self, path: str, locality: str) -> None:
        """Pretend ``path`` is ``NEARLINE``, ``ONLINE_AND_NEARLINE``, ``LOST``..."""
        with self.lock:
            self._locality[posixpath.normpath(path)] = locality

    def locality(self, path: str) -> str:
        with self.lock:
            found = self._locality.get(posixpath.normpath(path))
        if found is not None:
            return found
        return "NONE" if self.local(path).is_dir() else "ONLINE"

    def inject(self, operation: str, reply: Injection, *, times: int = 1) -> None:
        """Answer the next ``times`` calls of ``operation`` with ``reply``.

        ``reply`` is a SOAP body (sent with HTTP 200), a :class:`Reply`, or a
        callable taking the request part and returning either - or ``None``
        to let the server answer as usual.
        """
        with self.lock:
            self._injected.setdefault(operation, []).extend([reply] * times)

    def operations(self) -> list[str]:
        """The operation of every request received, in order."""
        with self.lock:
            return [name for name, _ in self.log]

    @staticmethod
    def status_reply(operation: str, code: str, explanation: str = "") -> bytes:
        """A reply to ``operation`` holding only a ``returnStatus``."""
        return soap.response(operation, _only(code, explanation))

    # -- dispatch ------------------------------------------------------------------

    def dispatch(self, body: bytes, headers: dict[str, str] | None = None) -> Reply:
        """Answer one SOAP request body."""
        try:
            operation, part = soap.parse(body)
        except (soap.SOAPError, soap.SOAPFault) as exc:
            return Reply(soap.fault("SOAP-ENV:Client", str(exc)), 500)
        with self.lock:
            self.log.append((operation, body))
            self.headers.append(dict(headers or {}))
            queue = self._injected.get(operation)
            injected = queue.pop(0) if queue else None
        answer = injected(part) if callable(injected) else injected
        if answer is not None:
            return answer if isinstance(answer, Reply) else Reply(answer)
        method = self._operations.get(operation)
        if method is None:
            text = f"Method '{operation}' not implemented"
            return Reply(soap.fault("SOAP-ENV:Client", text), 500)
        with self.lock:
            fields = method(part)
        return Reply(soap.response(operation, fields, multiref=self.multiref))

    # -- helpers -------------------------------------------------------------------

    @staticmethod
    def _path(surl: str) -> str | None:
        try:
            return posixpath.normpath(parse_surl(surl).path)
        except GError:
            return None

    def _existing(self, surl: str) -> tuple[str | None, Path]:
        """``(path, local)`` of a SURL; ``path`` is ``None`` if it does not exist."""
        path = self._path(surl)
        local = self.local(path or "/")
        return (path if path is not None and local.exists() else None), local

    def _token(self) -> str:
        return f"xgfal-{next(self._tokens)}"

    def _detail(self, path: str, levels: int, offset: int, count: int) -> tuple[Fields, str]:
        local = self.local(path)
        try:
            info = local.stat()
        except OSError:
            missing = _status("SRM_INVALID_PATH", "No such file or directory")
            return [("path", path), ("status", missing)], "SRM_INVALID_PATH"
        is_dir = _stat.S_ISDIR(info.st_mode)
        mode = info.st_mode
        locality = self.locality(path)
        fields: Fields = [
            ("path", path),
            ("status", _status("SRM_SUCCESS")),
            ("size", 0 if is_dir else info.st_size),
            ("createdAtTime", soap.format_time(info.st_ctime)),
            ("lastModificationTime", soap.format_time(info.st_mtime)),
            ("fileStorageType", "PERMANENT"),
            (
                "retentionPolicyInfo",
                [
                    ("retentionPolicy", "CUSTODIAL" if "NEARLINE" in locality else "REPLICA"),
                    ("accessLatency", "NEARLINE" if locality == "NEARLINE" else "ONLINE"),
                ],
            ),
            ("fileLocality", locality),
            ("type", "DIRECTORY" if is_dir else "FILE"),
            ("ownerPermission", [("userID", "xgfal"), ("mode", soap.permission(mode >> 6))]),
            ("groupPermission", [("groupID", "xgfal"), ("mode", soap.permission(mode >> 3))]),
            ("otherPermission", soap.permission(mode)),
        ]
        if not is_dir and self.checksum_type:
            fields.append(("checkSumType", self.checksum_type))
            fields.append(("checkSumValue", _adler32(local)))
        if not (is_dir and levels > 0):
            return fields, "SRM_SUCCESS"
        names = sorted(os.listdir(local))
        if count > self.max_ls or (not count and len(names) > self.max_ls):
            fields[1] = ("status", _status("SRM_TOO_MANY_RESULTS", "Too many results"))
            return fields, "SRM_TOO_MANY_RESULTS"
        window = names[offset : offset + count] if count else names[offset:]
        children = [
            ("pathDetailArray", self._detail(posixpath.join(path, name), 0, 0, 0)[0])
            for name in window
        ]
        fields.append(("arrayOfSubPaths", children))
        return fields, "SRM_SUCCESS"

    def _file_status(self, file: File, key: str) -> Fields:
        return [
            (key, file.surl),
            ("status", _status(file.code, file.explanation)),
            ("fileSize", file.size),
            ("transferURL", file.turl or None),
        ]

    def _request_reply(self, request: Request, key: str) -> Fields:
        code = _aggregate(file.code for file in request.files)
        if code in soap.PENDING and not request.started:
            code = "SRM_REQUEST_QUEUED"
        return [
            ("returnStatus", _status(code)),
            ("requestToken", request.token),
            (
                "arrayOfFileStatuses",
                [("statusArray", self._file_status(file, key)) for file in request.files],
            ),
        ]

    def _advance(self, request: Request) -> None:
        """One status poll's worth of progress."""
        request.started = True
        for file in request.files:
            if file.wait > 0:
                file.wait -= 1
                if file.wait == 0:
                    if file.stage:
                        self.set_locality(file.path, "ONLINE_AND_NEARLINE")
                    self._ready(request, file)

    def _ready(self, request: Request, file: File) -> None:
        if request.kind == "bol":
            file.code = "SRM_SUCCESS"
            return
        file.code = "SRM_FILE_PINNED" if request.kind == "get" else "SRM_SPACE_AVAILABLE"
        file.turl = self.protocols[request.protocol] + file.path

    def _new_request(
        self, kind: str, part: soap.Node, key: str, check: Callable[[str], tuple[str, str]]
    ) -> Request | Fields:
        holder = part.child("transferParameters", "arrayOfTransferProtocols")
        protocols = [node.text for node in holder.children("stringArray")] if holder else []
        spacetoken = part.get("targetSpaceToken")
        if spacetoken and spacetoken not in self.spaces:
            return _only("SRM_INVALID_REQUEST", f"Unknown space token {spacetoken}")
        chosen = next((name for name in protocols if name in self.protocols), "")
        if kind != "bol" and not chosen:
            return _only("SRM_NOT_SUPPORTED", "No requested transfer protocol is supported")
        request = Request(self._token(), kind, protocol=chosen, spacetoken=spacetoken)
        self.requests[request.token] = request
        for node in part.array("arrayOfFileRequests", "requestArray"):
            surl = node.get(key)
            path = self._path(surl)
            file = File(surl, path or "", "SRM_REQUEST_QUEUED")
            if kind == "put":
                file.size = node.integer("expectedFileSize")
            code, explanation = (
                ("SRM_INVALID_PATH", "Invalid SURL") if path is None else check(path)
            )
            if code:
                file.code, file.explanation = code, explanation
            else:
                file.stage = kind != "put" and self.locality(file.path) == "NEARLINE"
                file.wait = max(self.queue_polls, self.stage_polls if file.stage else 0)
                if file.wait == 0:
                    self._ready(request, file)
            request.files.append(file)
        return request

    # -- namespace operations --------------------------------------------------------

    def _srmPing(self, part: soap.Node) -> Fields:
        return [
            ("versionInfo", "v2.2"),
            (
                "otherInfo",
                [
                    ("extraInfoArray", [("key", "backend_type"), ("value", self.backend)]),
                    ("extraInfoArray", [("key", "backend_version"), ("value", "1.0")]),
                ],
            ),
        ]

    def _srmLs(self, part: soap.Node) -> Fields:
        levels = part.integer("numOfLevels")
        levels = 1 if levels is None else levels
        offset = part.integer("offset") or 0
        count = part.integer("count") or 0
        details: Fields = []
        codes = []
        for surl in part.strings("arrayOfSURLs", "urlArray"):
            path = self._path(surl)
            if path is None:
                detail = [("path", surl), ("status", _status("SRM_INVALID_PATH", "Invalid SURL"))]
                code = "SRM_INVALID_PATH"
            else:
                detail, code = self._detail(path, levels, offset, count)
            details.append(("pathDetailArray", detail))
            codes.append(code)
        code = _aggregate(codes)
        if "SRM_TOO_MANY_RESULTS" in codes:
            code = "SRM_TOO_MANY_RESULTS"
        reply = [("returnStatus", _status(code)), ("details", details)]
        if not self.ls_queue_polls:
            return reply
        request = Request(self._token(), "ls", listing=reply)
        request.files.append(File("", "", "SRM_REQUEST_QUEUED", wait=self.ls_queue_polls))
        self.requests[request.token] = request
        return [("returnStatus", _status("SRM_REQUEST_QUEUED")), ("requestToken", request.token)]

    def _srmStatusOfLsRequest(self, part: soap.Node) -> Fields:
        request = self.requests.get(part.get("requestToken"))
        if request is None or request.kind != "ls":
            return _only("SRM_INVALID_REQUEST", "Unknown request token")
        pending = request.files[0]
        pending.wait -= 1
        if pending.wait > 0:
            return _only("SRM_REQUEST_INPROGRESS")
        return request.listing

    def _srmMkdir(self, part: soap.Node) -> Fields:
        path = self._path(part.get("SURL"))
        local = self.local(path or "/")
        if path is None or not local.parent.is_dir():
            return _only("SRM_INVALID_PATH", "Parent directory does not exist")
        if local.exists():
            return _only("SRM_DUPLICATION_ERROR", "Path exists")
        local.mkdir()
        return _only("SRM_SUCCESS")

    def _srmRmdir(self, part: soap.Node) -> Fields:
        path, local = self._existing(part.get("SURL"))
        if path is None:
            return _only("SRM_INVALID_PATH", "No such file or directory")
        if not local.is_dir():
            return _only("SRM_INVALID_PATH", "Not a directory")
        if part.boolean("recursive"):
            shutil.rmtree(local)
        elif any(local.iterdir()):
            return _only("SRM_NON_EMPTY_DIRECTORY", "Directory is not empty")
        else:
            local.rmdir()
        return _only("SRM_SUCCESS")

    def _surl_statuses(self, part: soap.Node, action: Callable[[str], tuple[str, str]]) -> Fields:
        """Apply ``action`` to each SURL of ``arrayOfSURLs``; a TSURLReturnStatus each."""
        statuses: Fields = []
        codes = []
        for surl in part.strings("arrayOfSURLs", "urlArray"):
            code, explanation = action(surl)
            codes.append(code)
            statuses.append(
                ("statusArray", [("surl", surl), ("status", _status(code, explanation))])
            )
        return [("returnStatus", _status(_aggregate(codes))), ("arrayOfFileStatuses", statuses)]

    def _rm(self, surl: str) -> tuple[str, str]:
        path, local = self._existing(surl)
        if path is None:
            return "SRM_INVALID_PATH", "No such file or directory"
        if local.is_dir():
            return "SRM_INVALID_PATH", "Not a file"
        local.unlink()
        return "SRM_SUCCESS", ""

    def _srmRm(self, part: soap.Node) -> Fields:
        return self._surl_statuses(part, self._rm)

    def _srmMv(self, part: soap.Node) -> Fields:
        source, local = self._existing(part.get("fromSURL"))
        target = self._path(part.get("toSURL"))
        if source is None or target is None:
            return _only("SRM_INVALID_PATH", "No such file or directory")
        destination = self.local(target)
        if destination.exists():
            return _only("SRM_DUPLICATION_ERROR", "Destination exists")
        if not destination.parent.is_dir():
            return _only("SRM_INVALID_PATH", "Destination parent does not exist")
        os.rename(local, destination)
        return _only("SRM_SUCCESS")

    def _srmSetPermission(self, part: soap.Node) -> Fields:
        path, local = self._existing(part.get("SURL"))
        if path is None:
            return _only("SRM_INVALID_PATH", "No such file or directory")
        current = local.stat().st_mode
        wanted = (
            part.get("ownerPermission"),
            part.get("arrayOfGroupPermissions", "groupPermissionArray", "mode"),
            part.get("otherPermission"),
        )
        mode = 0
        for shift, text in zip((6, 3, 0), wanted):
            bits = soap.permission_bits(text) if text else (current >> shift) & 7
            mode |= bits << shift
        os.chmod(local, mode)
        return _only("SRM_SUCCESS")

    def _srmCheckPermission(self, part: soap.Node) -> Fields:
        results: Fields = []
        codes = []
        for surl in part.strings("arrayOfSURLs", "urlArray"):
            path, local = self._existing(surl)
            if path is None:
                missing = _status("SRM_INVALID_PATH", "No such file or directory")
                codes.append("SRM_INVALID_PATH")
                results.append(("surlPermissionArray", [("surl", surl), ("status", missing)]))
                continue
            bits = (local.stat().st_mode >> 6) & 7
            codes.append("SRM_SUCCESS")
            entry = [
                ("surl", surl),
                ("status", _status("SRM_SUCCESS")),
                ("permission", soap.permission(bits)),
            ]
            results.append(("surlPermissionArray", entry))
        return [("returnStatus", _status(_aggregate(codes))), ("arrayOfPermissions", results)]

    # -- transfers -------------------------------------------------------------------

    def _check_get(self, path: str) -> tuple[str, str]:
        local = self.local(path)
        if not local.exists():
            return "SRM_INVALID_PATH", "No such file or directory"
        if local.is_dir():
            return "SRM_INVALID_PATH", "Is a directory"
        locality = self.locality(path)
        if locality == "LOST":
            return "SRM_FILE_LOST", "The file is lost"
        if locality == "UNAVAILABLE":
            return "SRM_FILE_UNAVAILABLE", "The file is unavailable"
        return "", ""

    def _check_put(self, path: str) -> tuple[str, str]:
        local = self.local(path)
        if local.exists():
            return "SRM_DUPLICATION_ERROR", "The file exists"
        if not local.parent.is_dir():
            return "SRM_INVALID_PATH", "Parent directory does not exist"
        for request in self.requests.values():
            for file in request.files:
                if request.kind == "put" and file.path == path and file.code in _OPEN_PUT:
                    return "SRM_FILE_BUSY", "The file is being written"
        return "", ""

    def _srmPrepareToGet(self, part: soap.Node) -> Fields:
        request = self._new_request("get", part, "sourceSURL", self._check_get)
        if isinstance(request, Request):
            return self._request_reply(request, "sourceSURL")
        return request

    def _srmPrepareToPut(self, part: soap.Node) -> Fields:
        request = self._new_request("put", part, "targetSURL", self._check_put)
        if isinstance(request, Request):
            return self._request_reply(request, "SURL")
        return request

    def _srmBringOnline(self, part: soap.Node) -> Fields:
        request = self._new_request("bol", part, "sourceSURL", self._check_get)
        if isinstance(request, Request):
            return self._request_reply(request, "sourceSURL")
        return request

    def _poll(self, part: soap.Node, kind: str, key: str) -> Fields:
        request = self.requests.get(part.get("requestToken"))
        if request is None or request.kind != kind:
            return _only("SRM_INVALID_REQUEST", "Unknown request token")
        self._advance(request)
        return self._request_reply(request, key)

    def _srmStatusOfGetRequest(self, part: soap.Node) -> Fields:
        return self._poll(part, "get", "sourceSURL")

    def _srmStatusOfPutRequest(self, part: soap.Node) -> Fields:
        return self._poll(part, "put", "SURL")

    def _srmStatusOfBringOnlineRequest(self, part: soap.Node) -> Fields:
        return self._poll(part, "bol", "sourceSURL")

    def _in_request(
        self, part: soap.Node, action: Callable[[Request | None, str, File | None], tuple[str, str]]
    ) -> Fields:
        """Apply ``action`` to each SURL of a (possibly token-less) request."""
        token = part.get("requestToken")
        request = self.requests.get(token) if token else None
        if token and request is None:
            return _only("SRM_INVALID_REQUEST", "Unknown request token")

        def each(surl: str) -> tuple[str, str]:
            path = self._path(surl)
            if path is None:
                return "SRM_INVALID_PATH", "Invalid SURL"
            files = request.files if request is not None else []
            return action(request, path, next((f for f in files if f.path == path), None))

        return self._surl_statuses(part, each)

    def _put_done(self, request: Request | None, path: str, file: File | None) -> tuple[str, str]:
        if request is None or request.kind != "put" or file is None:
            return "SRM_INVALID_PATH", "The SURL is not part of this request"
        if file.code != "SRM_SPACE_AVAILABLE":
            return "SRM_FAILURE", f"The file is in state {file.code}"
        if not self.local(path).is_file():
            file.code = "SRM_FAILURE"
            return "SRM_INVALID_PATH", "The file was never written"
        file.code = "SRM_SUCCESS"
        return "SRM_SUCCESS", ""

    def _release(self, request: Request | None, path: str, file: File | None) -> tuple[str, str]:
        if not self.local(path).exists():
            return "SRM_INVALID_PATH", "No such file or directory"
        if request is not None:
            if file is None:
                return "SRM_INVALID_PATH", "The SURL is not part of this request"
            file.code = "SRM_RELEASED"
        self.released.append(path)
        return "SRM_SUCCESS", ""

    def _abort(self, request: Request | None, path: str, file: File | None) -> tuple[str, str]:
        if request is None or file is None:
            return "SRM_INVALID_PATH", "The SURL is not part of this request"
        if request.kind == "put" and file.code in _OPEN_PUT:
            local = self.local(path)
            if local.is_file():
                local.unlink()
        file.code, file.wait, file.turl = "SRM_ABORTED", 0, ""
        return "SRM_SUCCESS", ""

    def _srmPutDone(self, part: soap.Node) -> Fields:
        return self._in_request(part, self._put_done)

    def _srmReleaseFiles(self, part: soap.Node) -> Fields:
        return self._in_request(part, self._release)

    def _srmAbortFiles(self, part: soap.Node) -> Fields:
        return self._in_request(part, self._abort)

    def _srmAbortRequest(self, part: soap.Node) -> Fields:
        request = self.requests.get(part.get("requestToken"))
        if request is None:
            return _only("SRM_INVALID_REQUEST", "Unknown request token")
        for file in request.files:
            if file.wait:
                file.code, file.wait = "SRM_ABORTED", 0
        return _only("SRM_SUCCESS")

    # -- space ---------------------------------------------------------------------

    def _srmGetSpaceTokens(self, part: soap.Node) -> Fields:
        description = part.get("userSpaceTokenDescription")
        tokens = [
            token
            for token, space in sorted(self.spaces.items())
            if not description or space.description == description
        ]
        if not tokens:
            return _only("SRM_INVALID_REQUEST", "No such space token descriptor")
        return [
            ("returnStatus", _status("SRM_SUCCESS")),
            ("arrayOfSpaceTokens", [("stringArray", token) for token in tokens]),
        ]

    def _srmGetSpaceMetaData(self, part: soap.Node) -> Fields:
        details: Fields = []
        codes = []
        for token in part.strings("arrayOfSpaceTokens", "stringArray"):
            space = self.spaces.get(token)
            if space is None:
                codes.append("SRM_INVALID_REQUEST")
                unknown = _status("SRM_INVALID_REQUEST", "No such space token")
                details.append(("spaceDataArray", [("spaceToken", token), ("status", unknown)]))
                continue
            codes.append("SRM_SUCCESS")
            policy = [("retentionPolicy", space.retention), ("accessLatency", space.latency)]
            entry = [
                ("spaceToken", token),
                ("status", _status("SRM_SUCCESS")),
                ("retentionPolicyInfo", policy),
                ("owner", space.owner),
                ("totalSize", space.total),
                ("guaranteedSize", space.guaranteed),
                ("unusedSize", space.unused),
                ("lifetimeAssigned", space.lifetime),
                ("lifetimeLeft", space.lifetime),
            ]
            details.append(("spaceDataArray", entry))
        return [("returnStatus", _status(_aggregate(codes))), ("arrayOfSpaceDetails", details)]


#: Put states in which a file is still being written.
_OPEN_PUT = frozenset({"SRM_SPACE_AVAILABLE", "SRM_REQUEST_QUEUED"})
