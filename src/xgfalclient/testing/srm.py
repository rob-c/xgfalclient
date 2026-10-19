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

How this module is organised: it is the public facade. :class:`SRMServer`
is defined here - configuration, lifecycle, addressing, the knobs a test
turns, and SOAP dispatch - and inherits the operations themselves from
mixins in the private :mod:`xgfalclient.testing._srm` package (namespace,
asynchronous requests, space tokens), beside the data model and the httpg
handler. Every name the single-module layout had is re-exported here.
Nothing in the package reads a name through this module at call time, so
patch a helper in its own ``_srm`` module.
"""

from __future__ import annotations

# Every name the single-module layout had is re-exported with a redundant
# ``as`` (so mypy's strict no-implicit-reexport and ruff treat it as this
# module's API): what it defined, now defined in ``_srm``, and what it
# imported (``stat``, which it imported as ``_stat``, is not re-exported).
import itertools as itertools
import os as os
import posixpath as posixpath
import shutil as shutil
import ssl as ssl
import threading as threading
import zlib as zlib
from collections.abc import Callable as Callable
from collections.abc import Iterable as Iterable
from dataclasses import dataclass as dataclass
from dataclasses import field as field
from http.server import BaseHTTPRequestHandler as BaseHTTPRequestHandler
from pathlib import Path as Path
from socketserver import TCPServer as TCPServer
from socketserver import ThreadingMixIn as ThreadingMixIn
from typing import Any as Any

from xrdsec.testing.gsi import httpg_context

from ..errors import GError as GError
from ..plugins.srm import soap as soap
from ..plugins.srm.transport import parse_surl as parse_surl
from ._srm.base import _OperationsBase as _OperationsBase
from ._srm.http import _Handler as _Handler
from ._srm.http import _TCPServer as _TCPServer
from ._srm.model import _OPEN_PUT as _OPEN_PUT
from ._srm.model import DROP as DROP
from ._srm.model import Fields as Fields
from ._srm.model import File as File
from ._srm.model import Injection as Injection
from ._srm.model import Reply as Reply
from ._srm.model import Request as Request
from ._srm.model import Space as Space
from ._srm.model import _adler32 as _adler32
from ._srm.model import _aggregate as _aggregate
from ._srm.model import _only as _only
from ._srm.model import _status as _status
from ._srm.namespace import _NamespaceOps as _NamespaceOps
from ._srm.requests import _RequestOps as _RequestOps
from ._srm.space import _SpaceOps as _SpaceOps

__all__ = ["DROP", "Reply", "SRMServer", "Space"]

#: The SRM v2.2 operations this server implements, each by a ``_<name>``
#: method on one of the mixins. Anything else (``srmCopy``, say) gets a
#: ``SOAP-ENV:Client`` fault, as from an endpoint that lacks the method.
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


class SRMServer(_NamespaceOps, _RequestOps, _SpaceOps):
    """A threaded SRM v2.2 endpoint serving ``root`` at ``/srm/managerv2``.

    ``tls`` is a server context (``PKI.server_context()``). ``protocols``
    maps a TURL protocol to the URL prefix under which ``root`` is reachable
    that way; the default serves ``file://`` TURLs straight into ``root``.
    Of the protocols a client asks for, the first in the map is used.

    The other options model one backend or another:

    * ``host``/``port`` - where to listen; ``port=0`` picks a free one.
    * ``queue_polls`` - status calls a get/put/bring-online request stays
      ``SRM_REQUEST_QUEUED``/``INPROGRESS`` before its files are ready
      (0: ready in the first reply).
    * ``stage_polls`` - status calls a ``NEARLINE`` file takes to stage.
    * ``ls_queue_polls`` - non-zero makes ``srmLs`` asynchronous (a token,
      then ``srmStatusOfLsRequest``), as dCache can answer.
    * ``max_ls`` - entries one ``srmLs`` returns before it answers
      ``SRM_TOO_MANY_RESULTS`` instead, to test a client's paging.
    * ``checksum_type`` - the checksum ``srmLs`` reports (ADLER32 computed on
      the fly); ``None`` reports none, like a backend without checksums.
    * ``keep_alive`` - ``False`` sends ``Connection: close`` on every reply.
    * ``multiref`` - answer Axis-style, with the response part as a
      ``multiRef`` reference, as dCache's Axis server does.
    * ``backend`` - ``srmPing``'s ``backend_type`` (``dCache``, ``StoRM``,
      ``DPM``...), which clients use to pick backend-specific behaviour.
    * ``io_timeout`` - socket timeout on each connection, in seconds.
    * ``globus_turn`` - TLS 1.3 with globus's turn byte instead of TLS 1.2
      (see the comment in the constructor).

    State a test inspects: :attr:`log` (operation and raw body of every
    request), :attr:`headers` (HTTP headers of each), :attr:`connections`
    (TLS connections accepted), :attr:`requests` (asynchronous requests by
    token), :attr:`spaces` (space tokens; fill it to enable them) and
    :attr:`released` (paths ``srmReleaseFiles`` released).

    Threading: :class:`socketserver.ThreadingMixIn` serves each connection
    on its own daemon thread. Every operation runs under :attr:`lock` (an
    ``RLock``, since knobs like :meth:`set_locality` take it again from
    inside an operation), so operations are serialised and a test may
    read the state between calls.

    The constructor takes many keyword options because it is public test
    API used across the suite; it is deliberately not folded into an
    options object.
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
        """Bind the listener (so :attr:`port` is known) and adjust ``tls`` for GSI.

        ``tls`` is modified in place - its TLS version cap or session tickets
        - so do not share one context between servers with different
        ``globus_turn`` settings.
        """
        # TLS 1.2, as globus-gssapi (CGSI-gSOAP's GSI) runs it, unless
        # ``globus_turn`` asks for TLS 1.3 the way a globus acceptor does it -
        # a NUL "turn" byte after the handshake, no session tickets
        # (:func:`xrdsec.testing.gsi.httpg_context` says why). dCache speaks
        # TLS 1.3 without the byte.
        self.globus_turn = globus_turn
        self.tls = httpg_context(tls, turn=globus_turn)
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
        #: Serialises operations and guards every attribute below.
        self.lock = threading.RLock()
        #: TLS connections accepted (after the GSI delegation byte).
        self.connections = 0
        #: ``(operation, raw request body)`` of every parsed request, in order.
        self.log: list[tuple[str, bytes]] = []
        #: The HTTP headers of each request in :attr:`log`.
        self.headers: list[dict[str, str]] = []
        #: Asynchronous requests by token (``xgfal-1``, ``xgfal-2``...).
        self.requests: dict[str, Request] = {}
        #: Space token to reservation; empty means "no space tokens".
        self.spaces: dict[str, Space] = {}
        #: Paths released by ``srmReleaseFiles``, in order.
        self.released: list[str] = []
        # Normalised path to an overriding locality (set_locality).
        self._locality: dict[str, str] = {}
        # Operation to the queue of injected answers still to send.
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
        """Serve on a daemon thread; returns ``self`` for chaining."""
        threading.Thread(target=self._server.serve_forever, name="xgfal-srm", daemon=True).start()
        return self

    def stop(self) -> None:
        """Stop the serve loop and close the listener.

        Connections already open are left to their daemon threads, which
        end at the client's hang-up or ``io_timeout``.
        """
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> SRMServer:
        """:meth:`start` the server for a ``with`` block."""
        return self.start()

    def __exit__(self, *exc: object) -> None:
        """:meth:`stop` the server; exceptions propagate."""
        self.stop()

    # -- addressing ----------------------------------------------------------------

    @property
    def endpoint(self) -> str:
        """The ``httpg://`` service endpoint, as a BDII publishes it."""
        return f"httpg://{self.host}:{self.port}/srm/managerv2"

    def url(self, path: str) -> str:
        """The short SURL of ``path``: the client finds the endpoint itself.

        ``path`` is the SRM path, which is also the path under :attr:`root`.
        """
        return f"srm://{self.host}:{self.port}{path}"

    def full_url(self, path: str) -> str:
        """The ``?SFN=`` SURL of ``path``, which names the endpoint explicitly."""
        return f"srm://{self.host}:{self.port}/srm/managerv2?SFN={path}"

    def local(self, path: str) -> Path:
        """Where ``path`` lives on disk (whether or not it exists).

        The path is normalised as an absolute SRM path first, so ``..``
        cannot leave :attr:`root`.
        """
        clean = posixpath.normpath("/" + path.lstrip("/"))
        return self.root / clean.lstrip("/")

    # -- knobs ---------------------------------------------------------------------

    def set_locality(self, path: str, locality: str) -> None:
        """Pretend ``path`` is ``NEARLINE``, ``ONLINE_AND_NEARLINE``, ``LOST``...

        The value is any ``TFileLocality`` (or ``LOST``/``UNAVAILABLE``,
        which make gets fail with ``SRM_FILE_LOST``/``SRM_FILE_UNAVAILABLE``).
        ``srmLs`` reports it, a get or bring-online of a ``NEARLINE`` file
        waits ``stage_polls`` polls and then makes it ``ONLINE_AND_NEARLINE``.
        """
        with self.lock:
            self._locality[posixpath.normpath(path)] = locality

    def locality(self, path: str) -> str:
        """``path``'s ``TFileLocality``: as set, else ``ONLINE`` (``NONE`` for a directory)."""
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
        """Answer one SOAP request body.

        A body that does not parse is a ``500`` ``SOAP-ENV:Client`` fault and
        is not logged. Otherwise the request is logged, then the next
        injected answer for its operation (if any) is used; an injected
        callable returning ``None`` falls through to the real operation.
        Unknown operations are a ``500`` fault naming the method. Operations
        run under :attr:`lock` and return :data:`Fields`, rendered here as
        ``<operation>Response``. Tests may call this directly, without a
        socket, to exercise an operation.
        """
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
