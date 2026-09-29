"""Authentication "tunnels" for the dcap control line: GSI, and room for Kerberos.

libdcap does not authenticate itself. A URL prefix (``gsidcap``, ``kdcap``)
makes it load ``lib<prefix>Tunnel.so``, which establishes a GSS-API security
context on the fresh control socket and from then on wraps every line the
client writes and unwraps every line the door sends. On the wire each GSS
token - handshake or wrapped data - is one line::

    enc <base64 of the token>\\n

(libdcap's ``gssIoTunnel.c``; dCache's ``Base64TokenReader``/``Writer`` and
``DssSocket`` on the door side). The mechanism behind the tokens is the only
difference between the tunnels:

* **GSI** (``gsidcap``): TLS carried in the tokens, with GSI's delegation
  flag, as :class:`~xgfalclient.crypto.gsi.SecurityContext` implements it.
  libdcap asks for mutual authentication and no delegation (it never sets
  ``GSS_C_DELEG_FLAG``), so the flag sent is ``0``; the door's certificate
  must name the door's host.
* **Kerberos 5** (``kdcap``): the same framing around ``krb5`` GSS tokens
  for ``host@<door>``. The standard library has no Kerberos, so the
  mechanism comes from :mod:`xgfalclient.crypto.krb5` (``ctypes`` into the
  system's ``libgssapi_krb5``, or the optional ``gssapi`` package) when that
  can find one; :func:`unavailable` says what is missing otherwise.
  :func:`register_tunnel` installs any other implementation.

Only the control line is protected. As in dCache, the data channel to the
pool is plain TCP, authorised by the one-time challenge the door hands out.
"""

from __future__ import annotations

import errno
import importlib
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ...errors import GError
from .protocol import DcapURL

if TYPE_CHECKING:
    import ssl

    from ...crypto.gsi import SecurityContext
    from .plugin import DcapPlugin

__all__ = [
    "TokenLink",
    "Tunnel",
    "GSITunnel",
    "DoorContext",
    "KerberosTunnel",
    "TunnelFactory",
    "kerberos_module",
    "register_tunnel",
    "tunnel_factory",
    "unavailable",
    "KERBEROS_HINT",
]


class TokenLink:
    """What a tunnel needs from the connection while it authenticates."""

    def send_token(self, token: bytes) -> None:
        raise NotImplementedError

    def read_token(self) -> bytes:
        raise NotImplementedError


class Tunnel:
    """An established security context: ``wrap`` outgoing, ``unwrap`` incoming tokens."""

    def handshake(self, link: TokenLink, host: str) -> None:
        raise NotImplementedError

    def wrap(self, data: bytes) -> bytes:
        raise NotImplementedError

    def unwrap(self, token: bytes) -> bytes:
        raise NotImplementedError

    def close(self) -> None:
        """Release the security context: its connection is closing."""


def DoorContext(tls: ssl.SSLContext, *, server_hostname: str) -> SecurityContext:
    """GSI as dCache's doors speak it: no TLS 1.3 "turn".

    dCache's acceptor (``org.dcache.gsi.ServerGsiEngine`` behind
    ``DssSocket``) sends only its session tickets after the handshake and
    reads the delegation flag straight away - seen against dCache 11.2's
    gsidcap door, which negotiates TLS 1.3 - so the flag must follow the
    handshake at once, as libdcap's globus library sends it.

    :mod:`xgfalclient.crypto.gsi` (and the X.509 code behind it) is imported
    on the first GSI connection, so that plain ``dcap://`` never pays for it.
    """
    from ...crypto.gsi import SecurityContext

    return SecurityContext(tls, server_hostname=server_hostname, turn=False)


class GSITunnel(Tunnel):
    """libdcap's ``libgsiTunnel.so``: GSI (TLS in tokens), no delegation."""

    def __init__(self, tls: ssl.SSLContext) -> None:
        self.tls = tls
        self.security: SecurityContext | None = None

    def handshake(self, link: TokenLink, host: str) -> None:
        from ...crypto.gsi import GSIError

        security = DoorContext(self.tls, server_hostname=host)
        try:
            token = security.step()
            while True:
                # The last token carries the delegation flag after the handshake records.
                if token:
                    link.send_token(token)
                if security.complete:
                    break
                token = security.step(link.read_token())
            security.check_host(host)
        except GSIError as exc:
            raise GError(f"GSI authentication with {host} failed: {exc}", errno.EACCES) from exc
        self.security = security

    def wrap(self, data: bytes) -> bytes:
        assert self.security is not None
        return self.security.wrap(data)

    def unwrap(self, token: bytes) -> bytes:
        # Under TLS 1.3 the door's first tokens after the handshake may be
        # session tickets alone; they unwrap to nothing and the reader moves on.
        from ...crypto.gsi import GSIError

        assert self.security is not None
        try:
            return self.security.unwrap(token)
        except GSIError as exc:
            raise GError(f"Cannot decrypt a GSI token from the door: {exc}", errno.EPROTO) from exc


#: Builds the tunnel for one new control connection.
TunnelFactory = Callable[["DcapPlugin", DcapURL], Tunnel]


def _gsi(plugin: DcapPlugin, url: DcapURL) -> Tunnel:
    # GSI checks the host itself (host/fqdn names), so ssl's check is off.
    tls = plugin.context.ssl_context(
        url.url(url.path), group=plugin.option_group, check_hostname=False
    )
    return GSITunnel(tls)


class KerberosTunnel(Tunnel):
    """libdcap's Kerberos tunnel: ``krb5`` GSS tokens for ``host@<door>``.

    ``mechanism`` is :mod:`xgfalclient.crypto.krb5` (or anything with its
    ``ClientContext(service, host)`` offering ``step(token)``, ``complete``,
    ``wrap(data, confidential)``, ``unwrap(token)`` and ``close()``). As in
    libdcap's ``gssIoTunnel.c``: the target is ``host@<door>``
    (``gssAuth(fd, ctx, host, "host")``), mutual authentication, no
    delegation, and every line is sealed (``gss_wrap`` with
    ``conf_req_flag=1``; dCache's ``GssDssContext`` wraps with
    ``MessageProp(true)`` as well). libdcap names the door by the reverse
    lookup of its address; the URL's host is used here, as for GSI.

    A mechanism error that is a ``GError`` (``krb5.KerberosError`` is) keeps
    its code; anything else is ``EACCES`` in the handshake and ``EPROTO``
    after it.
    """

    def __init__(self, mechanism: Any) -> None:
        self.mechanism = mechanism
        self.context: Any = None

    def handshake(self, link: TokenLink, host: str) -> None:
        context = None
        try:
            context = self.mechanism.ClientContext("host", host)
            token = context.step(b"")
            while True:
                if token:
                    link.send_token(token)
                if context.complete:
                    break
                token = context.step(link.read_token())
        except Exception as exc:  # the mechanism's own error type, whatever it is
            if context is not None:
                context.close()
            code = exc.code if isinstance(exc, GError) else errno.EACCES
            raise GError(f"Kerberos authentication with {host} failed: {exc}", code) from exc
        self.context = context

    def wrap(self, data: bytes) -> bytes:
        return bytes(self.context.wrap(data, confidential=True))

    def unwrap(self, token: bytes) -> bytes:
        try:
            return bytes(self.context.unwrap(token))
        except Exception as exc:
            code = exc.code if isinstance(exc, GError) else errno.EPROTO
            raise GError(f"Cannot unwrap a Kerberos token from the door: {exc}", code) from exc

    def close(self) -> None:
        context, self.context = self.context, None
        if context is not None:
            context.close()


#: Where the Kerberos 5 mechanism lives when this installation has one.
KERBEROS_MODULE = "xgfalclient.crypto.krb5"

KERBEROS_HINT = (
    "kdcap:// needs Kerberos 5 (GSS-API) support, which is not available in this "
    "installation; use dcap:// or gsidcap://"
)


def kerberos_module() -> Any:
    """:mod:`xgfalclient.crypto.krb5`, or ``None`` if this installation has none."""
    try:
        return importlib.import_module(KERBEROS_MODULE)
    except ImportError:
        return None


def _kerberos(plugin: DcapPlugin, url: DcapURL) -> Tunnel:
    return KerberosTunnel(kerberos_module())


_FACTORIES: dict[str, TunnelFactory] = {"gsidcap": _gsi}


def register_tunnel(scheme: str, factory: TunnelFactory | None) -> None:
    """Install (or, with ``None``, remove) the tunnel used for ``scheme`` URLs.

    A registered tunnel takes precedence over the built-in Kerberos one.
    """
    if factory is None:
        _FACTORIES.pop(scheme, None)
    else:
        _FACTORIES[scheme] = factory


def unavailable(scheme: str) -> str | None:
    """Why ``scheme`` cannot be used, or ``None`` if it can."""
    if scheme == "dcap" or scheme in _FACTORIES:
        return None
    if scheme != "kdcap":
        return f"{scheme}:// has no authentication tunnel installed"
    # A module still being written (or a namespace package) has no available().
    available = getattr(kerberos_module(), "available", None)
    if not callable(available):
        return KERBEROS_HINT
    reason = available()
    return f"{KERBEROS_HINT} ({reason})" if reason else None


def tunnel_factory(scheme: str) -> TunnelFactory | None:
    """The tunnel for ``scheme``: ``None`` for plain ``dcap``.

    Raises ``EPROTONOSUPPORT``, saying why, for a scheme whose tunnel cannot
    be had (``kdcap`` without Kerberos).
    """
    if scheme == "dcap":
        return None
    found = _FACTORIES.get(scheme)
    if found is not None:
        return found
    reason = unavailable(scheme)
    if reason:
        raise GError(reason, errno.EPROTONOSUPPORT)
    return _kerberos
