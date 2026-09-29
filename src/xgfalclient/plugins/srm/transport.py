"""SURLs, endpoints, and SOAP over httpg.

**SURLs.** ``srm://host:port/path`` names a file on the SRM at
``httpg://host:port/srm/managerv2``; ``srm://host:port/srm/managerv2?SFN=/path``
says the same with the web-service path spelt out. With the BDII disabled
(it is not consulted here at all) the endpoint of the short form is guessed,
as gfal2 guesses it, to be ``/srm/managerv2`` on the same host and port; a
missing port is 8443, where every SRM of note listens. On the wire gfal2
writes every SURL in the short form without its port (``srm://host/path``),
whichever way the user wrote it, and so does this.

**httpg.** Globus' "HTTP over GSI" is, on the wire, TLS: GSI's tokens are TLS
records, and globus-gssapi writes them to the socket without the length
header it adds to anything else. The one GSI addition is the delegation
flag, a single application-data byte the client sends as soon as the
handshake completes - ``0`` for no delegation, ``D`` to delegate - and which
CGSI-gSOAP (StoRM, DPM) and jGlobus (dCache) servers both read before the
HTTP request. None of the operations here needs a delegated credential, so
the flag is always ``0``, as it is from gfal2. Host names are checked GSI's
way (``host/fqdn`` common names count) rather than with ``ssl``'s check.

**Sessions.** With ``KEEP_ALIVE`` (the default) connections are kept per
endpoint and reused, as srm-ifce does with gSOAP's keep-alive; a reused
connection the server has meanwhile closed is retried once on a fresh one.
"""

from __future__ import annotations

import errno
import http.client
import os
import posixpath
import socket
import ssl
import threading
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from ..._compat import SLOTS, TIMEOUTS
from ...crypto.gsi import NO_DELEGATION, GSIError, check_host
from ...crypto.x509 import parse_certificate
from ...errors import ECOMM, GError
from ...url import parse as parse_url
from . import soap

if TYPE_CHECKING:
    from .plugin import SRMPlugin

__all__ = ["SURL", "parse_surl", "Transport", "ifce_error", "DEFAULT_PORT", "SERVICE_PATH"]

DEFAULT_PORT = 8443
SERVICE_PATH = "/srm/managerv2"


@dataclass(frozen=True, **SLOTS)
class SURL:
    """A parsed SURL: ``url`` as written, ``wire`` as sent, ``path`` the file."""

    url: str
    wire: str
    netloc: str
    host: str
    port: int
    service: str
    path: str
    full: bool

    @property
    def endpoint(self) -> str:
        return f"httpg://{self.host}:{self.port}{self.service}"

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.host, self.port, self.service)

    def with_path(self, path: str) -> SURL:
        """The SURL of ``path`` on the same endpoint, written the same way."""
        if self.full:
            url = f"srm://{self.netloc}{self.service}?SFN={path}"
            return replace(self, url=url, wire=_short(self.host, path), path=path)
        return replace(
            self, url=f"srm://{self.netloc}{path}", wire=_short(self.host, path), path=path
        )

    def parent(self) -> SURL:
        trimmed = self.path.rstrip("/")
        return self.with_path(posixpath.dirname(trimmed) or "/")

    def join(self, name: str) -> SURL:
        return self.with_path(self.path.rstrip("/") + "/" + name)


def parse_surl(url: str) -> SURL:
    """Split an ``srm://`` URL; ``EINVAL`` for one that names no host or path."""
    parsed = parse_url(url)
    host = parsed.host
    if parsed.scheme != "srm" or not host:
        raise GError(f"Invalid SRM URL: {url}", errno.EINVAL)
    port = parsed.port
    _, sep, sfn = parsed.query.partition("SFN=")
    if sep:
        path, full = sfn.partition("&")[0], True
        service = parsed.path or SERVICE_PATH  # srm://host?SFN=/f names no service
    else:
        path, full, service = parsed.path, False, SERVICE_PATH
    if not path.startswith("/"):
        raise GError(f"Invalid SRM URL, no path: {url}", errno.EINVAL)
    return SURL(url, _short(host, path), parsed.netloc, host, port, service, path, full)


def _short(host: str, path: str) -> str:
    """A short-form SURL as gfal2 sends it: no port."""
    return f"srm://[{host}]{path}" if ":" in host else f"srm://{host}{path}"


def ifce_error(code: int, text: str) -> GError:
    """A failed srm-ifce call, as gfal2 reports it: ``srm-ifce err: <strerror>, err: <text>``."""
    return GError(f"srm-ifce err: {os.strerror(code)}, err: {text}\n", code)


def normalise_path(path: str) -> str:
    """``/a//b/`` and ``/a/b`` are the same file to an SRM."""
    return posixpath.normpath(path) if path else "/"


# ---------------------------------------------------------------------------
# The connection
# ---------------------------------------------------------------------------


class _Response(http.client.HTTPResponse):
    """A reply that may be preceded by a Globus TLS 1.3 turn byte.

    A globus-gssapi acceptor (CGSI-gSOAP: StoRM, DPM) that negotiated TLS 1.3
    writes one NUL after the handshake, a "your turn" token its initiators
    wait for before sending the delegation flag. jGlobus (dCache) sends none.
    Rather than guess whether to wait for it, the flag is sent at once and a
    NUL in front of the status line is skipped.
    """

    def _read_status(self) -> tuple[str, int, str]:
        if self.fp.peek(1)[:1] == b"\x00":
            self.fp.read(1)
        return super()._read_status()  # type: ignore[no-any-return,misc]


class HTTPGConnection(http.client.HTTPConnection):
    """``http.client`` over GSI-flavoured TLS: handshake, name check, flag byte."""

    response_class = _Response

    def __init__(
        self,
        host: str,
        port: int,
        tls: ssl.SSLContext,
        *,
        connect_timeout: float | None,
        timeout: float | None,
        check_name: bool,
    ) -> None:
        super().__init__(host, port, timeout=timeout)
        self.tls = tls
        self.connect_timeout = connect_timeout
        self.check_name = check_name

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), self.connect_timeout)
        try:
            raw.settimeout(self.connect_timeout)
            sock = self.tls.wrap_socket(raw, server_hostname=self.host)
            if self.check_name:
                der = sock.getpeercert(binary_form=True)
                if der is None:
                    raise GSIError("the peer presented no certificate")
                check_host(parse_certificate(der), self.host)
            sock.sendall(NO_DELEGATION)
            sock.settimeout(self.timeout)
        except BaseException:
            raw.close()
            raise
        self.sock = sock


class Transport:
    """SOAP calls to SRM endpoints over pooled httpg connections."""

    def __init__(self, plugin: SRMPlugin) -> None:
        self.plugin = plugin
        self._lock = threading.Lock()
        self._idle: dict[tuple[str, int, str], list[HTTPGConnection]] = {}

    # -- pooling -------------------------------------------------------------------

    def _connection(self, surl: SURL) -> tuple[HTTPGConnection, bool]:
        with self._lock:
            idle = self._idle.get(surl.key)
            if idle:
                return idle.pop(), True
        options = self.plugin.options
        group = self.plugin.option_group
        insecure = options.boolean(group, "INSECURE", False)
        tls = self.plugin.context.ssl_context(surl.url, group=group, check_hostname=False)
        connection = HTTPGConnection(
            surl.host,
            surl.port,
            tls,
            connect_timeout=options.integer(group, "CONN_TIMEOUT", 60) or None,
            timeout=self.plugin.option_timeout() or None,
            check_name=not insecure,
        )
        return connection, False

    def _release(self, surl: SURL, connection: HTTPGConnection, reusable: bool) -> None:
        if not reusable:
            connection.close()
            return
        with self._lock:
            self._idle.setdefault(surl.key, []).append(connection)

    def close(self) -> None:
        with self._lock:
            pools, self._idle = list(self._idle.values()), {}
        for pool in pools:
            for connection in pool:
                connection.close()

    # -- calls ---------------------------------------------------------------------

    def call(self, surl: SURL, operation: str, fields: soap.Fields) -> soap.Node:
        """POST one SOAP request and return the response part."""
        body = soap.request(operation, fields)
        short = operation[3:]
        keep_alive = self.plugin.options.boolean(self.plugin.option_group, "KEEP_ALIVE", True)
        headers = {
            "User-Agent": self.plugin.context.user_agent_string(),
            "Content-Type": "text/xml; charset=utf-8",
            "Content-Length": str(len(body)),
            "Connection": "keep-alive" if keep_alive else "close",
            "SOAPAction": f'"{short}"',
        }
        while True:
            connection, reused = self._connection(surl)
            try:
                connection.putrequest("POST", surl.service, skip_accept_encoding=True)
                for name, value in headers.items():
                    connection.putheader(name, value)
                connection.endheaders(body)
                reply = connection.getresponse()
                data = reply.read()
            except (OSError, http.client.HTTPException, GSIError) as exc:
                connection.close()
                # A session the server closed while idle fails in many ways
                # (EOF, reset, an OpenSSL "[SYS]" error); anything but a
                # timeout on a reused one earns one retry on a fresh one.
                if reused and not isinstance(exc, TIMEOUTS):
                    continue
                raise _network_error(surl, short, exc) from exc
            break
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
    if isinstance(exc, TIMEOUTS):
        return ifce_error(errno.ETIMEDOUT, f"{where}: Connection fails or timeout")
    if isinstance(exc, ConnectionRefusedError):
        return ifce_error(errno.ECONNREFUSED, f"{where}: Connection refused")
    if isinstance(exc, (ssl.SSLError, GSIError)):
        return ifce_error(ECOMM, f"{where}: CGSI-gSOAP: Error during the GSI handshake: {exc}")
    if isinstance(exc, OSError) and exc.errno:
        return ifce_error(exc.errno, f"{where}: {os.strerror(exc.errno)}")
    return ifce_error(ECOMM, f"{where}: {str(exc) or type(exc).__name__}")
