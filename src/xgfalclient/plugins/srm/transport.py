"""SURLs, endpoints, and SOAP over httpg.

**SURLs.** ``srm://host:port/srm/managerv2?SFN=/path`` (a *full* SURL: an
explicit port, then ``?SFN=``) names its web service: ``httpg://`` plus
everything between ``srm://`` and ``?SFN=``. A short one,
``srm://host[:port]/path``, names a storage element; its service is found
in the BDII (:mod:`.bdii`) by the plugin, and failing that guessed, as gfal2
guesses it, as ``httpg://host[:port]/srm/managerv2`` - with no port when the
SURL has none, which makes the connection go to port 80 (443 for an
``https`` endpoint), as gSOAP's does. The file's path is percent-decoded
(``%20`` is a space), and gfal2 writes every SURL on the wire in the short
form without its port (``srm://host/path``), whichever way the user wrote
it; so does this.

**httpg.** Globus' "HTTP over GSI" is, on the wire, TLS followed by GSI's
delegation flag (always ``0`` here: no SRM operation needs a delegated
credential, as none does from gfal2), with GSI's host-name check
(``host/fqdn`` common names count). The connection class that speaks it -
handshake, name check, flag, and skipping a Globus TLS 1.3 turn byte in front
of the first reply - is :class:`xrdsec.gsi.httpg.HTTPGConnection`, which
lived here until 0.4.0; this module configures it from the plugin's options
(:class:`~xrdsec.gsi.httpg.Handshake`) and pools it.

**Headers.** ``User-Agent`` is gfal2's (the application's, then
``gfal2/<version>``) with srm-ifce's ``srm-ifce/1.24.8 gSOAP/2.8`` after it;
``ClientInfo`` carries the context's client information when there is any.

**Sessions.** With ``KEEP_ALIVE`` (the default) connections are kept per
endpoint and reused, as srm-ifce does with gSOAP's keep-alive; a reused
connection the server has meanwhile closed is retried once on a fresh one.

**Messages.** SOAP 1.1 over HTTP/1.1: one ``POST`` to the service path per
call, ``Content-Type: text/xml``, and a quoted ``SOAPAction`` naming the
operation without its ``srm`` prefix (``"Ls"``). The reply body is read
whole before it is parsed, so a connection goes back to the pool with
nothing left unread on it. Every failure is a
:class:`~xgfalclient.errors.GError` worded by :func:`ifce_error`, as
srm-ifce's are, with an ``errno`` chosen by :func:`_network_error`.

Thread-safety: :class:`Transport` hands each connection to one call at a
time (a connection is either in the idle pool or owned by exactly one
caller), and the pool is guarded by a lock, so one transport serves every
thread of a context.
"""

from __future__ import annotations

import errno
import os
import posixpath
import re
import socket
import ssl
import threading
import urllib.parse
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from xrdhttp.connection import HTTPException, HTTPResponse
from xrdsec.gsi.gss import GSIError
from xrdsec.gsi.httpg import Handshake, HTTPGConnection

from ...errors import ECOMM, GError
from ...url import parse as parse_url
from . import soap

if TYPE_CHECKING:
    from ._base import _SRMBase

__all__ = [
    "SERVICE_PATH",
    "SRM_IFCE_AGENT",
    "SURL",
    "Transport",
    "ifce_error",
    "parse_endpoint",
    "parse_surl",
]

#: The web-service path gfal2 guesses for a short SURL.
SERVICE_PATH = "/srm/managerv2"
#: What srm-ifce appends to the ``User-Agent`` gfal2 gives it.
SRM_IFCE_AGENT = "srm-ifce/1.24.8 gSOAP/2.8"
#: gfal2's ``rex_full``: a port, then (by POSIX ERE's reading) ``SFN=``.
_FULL = re.compile(r"^srm://.+:[0-9]+/.*SFN=", re.IGNORECASE)


def parse_endpoint(endpoint: str) -> tuple[str, int, str]:
    """``(host, port, path)`` of an ``httpg://``/``https://`` service URL.

    A missing port is gSOAP's: 443 for ``https``, 80 for anything else.
    """
    parsed = parse_url(endpoint)
    port = _explicit_port(parsed.netloc) or (443 if parsed.scheme == "https" else 80)
    return parsed.host, port, parsed.path or "/"


def _explicit_port(netloc: str) -> int:
    """The port written in ``netloc``, 0 if none.

    Userinfo and an IPv6 literal's brackets are stripped first, so neither
    ``user:pw@host`` nor ``[::1]`` is mistaken for a port. "Written" matters:
    gfal2 sends the short SURL without a port and guesses the service with
    the SURL's own port only when there is one.
    """
    host = netloc.rpartition("@")[2]
    tail = host.rpartition("]")[2]
    text = tail.rpartition(":")[2] if ":" in tail else ""
    return int(text) if text.isdigit() else 0


def _bracketed(host: str) -> str:
    """An IPv6 literal in brackets, ready to go in a URL; names pass through."""
    return f"[{host}]" if ":" in host else host


@dataclass(frozen=True, slots=True)
class SURL:
    """A parsed SURL: ``url`` as written, ``wire`` as sent, ``path`` the file.

    ``endpoint`` is its web service, and ``server``/``server_port``/``service``
    where that is.

    Immutable: the BDII lookup and path changes make new ones
    (:meth:`with_endpoint`, :meth:`with_path`). Messages show ``url`` to the
    user; requests carry ``wire``; connections go to ``server``.
    """

    #: The SURL exactly as the caller wrote it.
    url: str
    #: The short form gfal2 sends in requests: ``srm://host/path``, no port.
    wire: str
    #: ``host[:port]`` as written, for rebuilding ``url`` on another path.
    netloc: str
    host: str
    #: The port the SURL names, 0 if none.
    port: int
    #: The file's path, percent-decoded, always absolute.
    path: str
    #: Whether the SURL is a full one (it names its own web service).
    full: bool
    #: The web service's URL, ``httpg://...`` (or a BDII-given ``https://``).
    endpoint: str
    #: Where :attr:`endpoint` is: TCP host and port, and the HTTP path to POST to.
    server: str
    server_port: int
    service: str

    @property
    def key(self) -> tuple[str, int, str]:
        """The web service, as the connection pool and the bulk grouping key it."""
        return (self.server, self.server_port, self.service)

    def with_endpoint(self, endpoint: str) -> SURL:
        """The same file, served by ``endpoint``."""
        server, port, service = parse_endpoint(endpoint)
        return replace(self, endpoint=endpoint, server=server, server_port=port, service=service)

    def with_path(self, path: str) -> SURL:
        """The SURL of ``path`` on the same endpoint, written the same way."""
        if self.full:
            url = f"srm://{self.netloc}{self.service}?SFN={path}"
            return replace(self, url=url, wire=_short(self.host, path), path=path)
        return replace(
            self, url=f"srm://{self.netloc}{path}", wire=_short(self.host, path), path=path
        )

    def parent(self) -> SURL:
        """The directory holding this path (``/`` is its own parent)."""
        trimmed = self.path.rstrip("/")
        return self.with_path(posixpath.dirname(trimmed) or "/")

    def join(self, name: str) -> SURL:
        """The SURL of entry ``name`` in this directory."""
        return self.with_path(self.path.rstrip("/") + "/" + name)


def guessed_endpoint(host: str, port: int) -> str:
    """gfal2's default service: ``httpg://host[:port]/srm/managerv2``."""
    where = _bracketed(host) + (f":{port}" if port else "")
    return f"httpg://{where}{SERVICE_PATH}"


def parse_surl(url: str) -> SURL:
    """Split an ``srm://`` URL; ``EINVAL`` for one that names no host or path.

    A short SURL gets the guessed endpoint; the plugin may replace it with
    the BDII's.

    A SURL is full only if gfal2's ``rex_full`` matches (an explicit port
    before the path) and it contains ``?SFN=``; its endpoint is then
    everything between ``srm://`` and ``?SFN=`` behind ``httpg://``.
    Anything else is short, even ``srm://host/srm/managerv2?SFN=/p``
    without a port: its path is still the ``SFN`` value.
    """
    parsed = parse_url(url)
    host = parsed.host
    if parsed.scheme != "srm" or not host:
        raise GError(f"Invalid SRM URL: {url}", errno.EINVAL)
    port = _explicit_port(parsed.netloc)
    _, sep, sfn = parsed.query.partition("SFN=")
    path = urllib.parse.unquote(sfn if sep else parsed.path)
    if not path.startswith("/"):
        raise GError(f"Invalid SRM URL, no path: {url}", errno.EINVAL)
    full = "?SFN=" in url and _FULL.match(url) is not None
    endpoint = f"httpg://{url[6 : url.index('?SFN=')]}" if full else guessed_endpoint(host, port)
    server, server_port, service = parse_endpoint(endpoint)
    return SURL(
        url,
        _short(host, path),
        parsed.netloc,
        host,
        port,
        path,
        full,
        endpoint,
        server,
        server_port,
        service,
    )


def _short(host: str, path: str) -> str:
    """A short-form SURL as gfal2 sends it: no port."""
    return f"srm://{_bracketed(host)}{path}"


def ifce_error(code: int, text: str) -> GError:
    """A failed srm-ifce call, as gfal2 reports it: ``srm-ifce err: <strerror>, err: <text>``."""
    return GError(f"srm-ifce err: {os.strerror(code)}, err: {text}\n", code)


def normalise_path(path: str) -> str:
    """``/a//b/`` and ``/a/b`` are the same file to an SRM."""
    return posixpath.normpath(path) if path else "/"


# ---------------------------------------------------------------------------
# The connection pool
# ---------------------------------------------------------------------------


class Transport:
    """SOAP calls to SRM endpoints over pooled httpg connections.

    Options are read from the plugin on every call, not cached, so a
    ``set_opt_*`` on the context takes effect at the next request (the
    connections already pooled keep their timeouts). Pooled connections
    are only closed by :meth:`close`, by a failure, or by the server.
    """

    def __init__(self, plugin: _SRMBase) -> None:
        """Serve ``plugin``, whose context supplies options, TLS and headers."""
        self.plugin = plugin
        self._lock = threading.Lock()
        self._idle: dict[tuple[str, int, str], list[HTTPGConnection]] = {}

    # -- pooling -------------------------------------------------------------------

    def _headers(self, short: str, length: int, keep_alive: bool) -> dict[str, str]:
        """The request headers srm-ifce's gSOAP sends, ``ClientInfo`` when one is set."""
        headers = {
            "User-Agent": f"{self.plugin.context.user_agent_string()} {SRM_IFCE_AGENT}",
            "Content-Type": "text/xml; charset=utf-8",
            "Content-Length": str(length),
            "Connection": "keep-alive" if keep_alive else "close",
            "SOAPAction": f'"{short}"',
        }
        info = self.plugin.context.client_info_string()
        if info:
            headers["ClientInfo"] = info
        return headers

    def _post(
        self, surl: SURL, short: str, headers: dict[str, str], body: bytes
    ) -> tuple[HTTPGConnection, HTTPResponse, bytes]:
        """``POST`` the request: the connection, its reply and the reply's body.

        A session the server closed while idle fails in many ways (EOF,
        reset, an OpenSSL "[SYS]" error); anything but a timeout on a reused
        one earns one retry on a fresh one.
        """
        while True:
            connection, reused = self._connection(surl)
            try:
                connection.putrequest("POST", surl.service, skip_accept_encoding=True)
                for name, value in headers.items():
                    connection.putheader(name, value)
                connection.endheaders(body)
                reply = connection.getresponse()
                return connection, reply, reply.read()
            except (OSError, HTTPException, GSIError) as exc:
                connection.close()
                if reused and not isinstance(exc, TimeoutError):
                    continue
                raise _network_error(surl, short, exc) from exc

    def _connection(self, surl: SURL) -> tuple[HTTPGConnection, bool]:
        """An idle connection to ``surl``'s service, or a new one; and whether reused.

        The newest idle one is taken (LIFO), being the least likely to have
        been dropped by the server. A new one is not connected yet: that
        happens, outside the lock, on its first request.
        """
        with self._lock:
            idle = self._idle.get(surl.key)
            if idle:
                return idle.pop(), True
        options = self.plugin.options
        group = self.plugin.option_group
        insecure = options.boolean(group, "INSECURE", False)
        tls = self.plugin.context.ssl_context(surl.url, group=group, check_hostname=False)
        # A timeout of 0 means "none" to gfal2, as None does to sockets.
        handshake = Handshake(tls, options.integer(group, "CONN_TIMEOUT", 60) or None, not insecure)
        connection = HTTPGConnection(
            surl.server,
            surl.server_port,
            handshake,
            timeout=self.plugin.option_timeout() or None,
        )
        return connection, False

    def _release(self, surl: SURL, connection: HTTPGConnection, reusable: bool) -> None:
        """Pool ``connection`` again, or close it when it cannot be reused.

        Not reusable: ``KEEP_ALIVE`` is off, or the server said it will
        close (``Connection: close``, HTTP/1.0).
        """
        if not reusable:
            connection.close()
            return
        with self._lock:
            self._idle.setdefault(surl.key, []).append(connection)

    def close(self) -> None:
        """Close every idle connection; ones in use close when their call ends.

        The pool is swapped out under the lock and closed outside it, so a
        slow close never blocks another thread's call.
        """
        with self._lock:
            pools, self._idle = list(self._idle.values()), {}
        for pool in pools:
            for connection in pool:
                connection.close()

    # -- calls ---------------------------------------------------------------------

    def call(self, surl: SURL, operation: str, fields: soap.Fields) -> soap.Node:
        """POST one SOAP request and return the response part.

        The part is returned whatever its ``returnStatus`` says: judging it
        is the :class:`~.client.Client`'s job. Raises ``GError``: the
        network's ``errno`` (``ETIMEDOUT``, ``ECONNREFUSED``...) for a
        failed exchange; ``ECOMM`` for a SOAP fault, or for a body that is
        not SOAP (then an HTTP status other than 200 is what is reported).
        """
        body = soap.request(operation, fields)
        short = operation[3:]
        keep_alive = self.plugin.options.boolean(self.plugin.option_group, "KEEP_ALIVE", True)
        headers = self._headers(short, len(body), keep_alive)
        connection, reply, data = self._post(surl, short, headers, body)
        self._release(surl, connection, keep_alive and not reply.will_close)
        try:
            _, part = soap.parse(data)
        except soap.SOAPFault as exc:
            text = exc.text or f"Unknown SOAP error ({exc.code})"
            raise ifce_error(ECOMM, f"[SE][{short}][] {surl.endpoint}: {text}") from exc
        except soap.SOAPError as exc:
            if reply.status != 200:
                detail = f"Error {reply.status}: HTTP {reply.status} {reply.reason}"
            else:
                detail = f"Unknown SOAP error ({exc})"
            raise ifce_error(ECOMM, f"[SE][{short}][] {surl.endpoint}: {detail}") from exc
        return part


def _network_error(surl: SURL, short: str, exc: BaseException) -> GError:
    """A transport failure in srm-ifce's words, with a faithful ``errno``."""
    where = f"[SE][{short}][] {surl.endpoint}"
    if isinstance(exc, TimeoutError):
        return ifce_error(errno.ETIMEDOUT, f"{where}: Connection fails or timeout")
    if isinstance(exc, ConnectionRefusedError):
        return ifce_error(errno.ECONNREFUSED, f"{where}: Connection refused")
    if isinstance(exc, (ssl.SSLError, GSIError)):
        return ifce_error(ECOMM, f"{where}: CGSI-gSOAP: Error during the GSI handshake: {exc}")
    if isinstance(exc, socket.gaierror):
        # getaddrinfo's codes are negative and no errno; gSOAP fails the send.
        return ifce_error(ECOMM, f"{where}: Host not found: {exc.strerror}")
    if isinstance(exc, OSError) and exc.errno:
        return ifce_error(exc.errno, f"{where}: {os.strerror(exc.errno)}")
    return ifce_error(ECOMM, f"{where}: {str(exc) or type(exc).__name__}")
