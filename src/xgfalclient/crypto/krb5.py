"""Kerberos 5 GSS-API contexts for Csec and dcap, raising gfal2's ``GError``.

Protocols that speak Kerberos (``kdcap``, LFC's Csec ``KRB5``) ferry opaque
GSS tokens between ``gss_init_sec_context`` and the server until the context
is established, then ``gss_wrap``/``gss_unwrap`` their messages::

    ctx = krb5.ClientContext("host", "door.example.org")
    token = ctx.step()
    while True:
        if token:
            send(token)
        if ctx.complete:
            break
        token = ctx.step(receive())
    line = ctx.unwrap(receive())

Nothing about Kerberos is implemented here. The contexts, the
python-gssapi binding and the status-code knowledge are
:mod:`xrdsec.krb5.gss` (shared with xrdclient); :func:`inspect_cache` reads
the cache with xrdsec's pure-Python reader (:func:`xrdsec.krb5.client.inspect_cache`:
``FILE:``, ``DIR:``, ``KCM:`` and ``KEYRING:`` caches, no native binding).
What stays in this module is gfal2's side of it:

* every failure is a :class:`KerberosError` - a ``GError`` (and an
  :class:`xrdsec.krb5.gss.KerberosError`, so library-level ``except``
  clauses catch it too) whose ``errno`` is ``EACCES`` for a refused or
  impossible authentication, ``ETIMEDOUT`` when no KDC answered, ``EPROTO``
  for a corrupt or replayed token and ``EPROTONOSUPPORT`` when there is no
  Kerberos library at all; the library's errors are re-raised as this class
  at each method, with the same message, ``errno``, statuses and token;
* ``$XGFAL_KRB5_BACKEND`` (:data:`BACKEND_ENV`) picks the binding, with the
  0.3 ``ctypes`` selection still accepted as an alias for ``gssapi``;
* the install hint (:data:`HINT`) names this package's ``krb5`` extra.

Credentials are the library's defaults: ``KRB5CCNAME`` or the configured
default cache for an initiator, ``KRB5_KTNAME`` or ``/etc/krb5.keytab`` for
an acceptor; ``ccache=`` and ``keytab=`` pick others per context. gfal2
itself has no Kerberos options, so none are read from its configuration.
Importing this module does not import ``gssapi``; the first context (or
:func:`available`) does.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Unpack

from xrdcore.errors import CredentialError
from xrdsec.krb5 import client, gss
from xrdsec.krb5.gss import CONF_FLAG as CONF_FLAG
from xrdsec.krb5.gss import DELEG_FLAG as DELEG_FLAG
from xrdsec.krb5.gss import INTEG_FLAG as INTEG_FLAG
from xrdsec.krb5.gss import MUTUAL_FLAG as MUTUAL_FLAG
from xrdsec.krb5.gss import REPLAY_FLAG as REPLAY_FLAG
from xrdsec.krb5.gss import SEQUENCE_FLAG as SEQUENCE_FLAG
from xrdsec.krb5.gss import reset as reset

from ..errors import GError

__all__ = [
    "BACKEND_ENV",
    "CONF_FLAG",
    "DELEG_FLAG",
    "HINT",
    "INTEG_FLAG",
    "MUTUAL_FLAG",
    "REPLAY_FLAG",
    "SEQUENCE_FLAG",
    "AcceptorContext",
    "ClientContext",
    "KerberosError",
    "available",
    "backend",
    "inspect_cache",
    "load_backend",
    "reset",
]

#: Forces a backend: ``gssapi`` (``ctypes`` is accepted as an alias for it).
BACKEND_ENV = "XGFAL_KRB5_BACKEND"

#: Appended to "not available" errors: how to get Kerberos support.
HINT = (
    "install the Kerberos extra with python -m pip install 'xgfalclient[krb5]'. "
    "Linux source installs also need Kerberos development headers and a C compiler"
)


class KerberosError(GError, gss.KerberosError):
    """A GSS-API failure as gfal2 reports it: a ``GError`` that also keeps the raw statuses.

    ``code`` is the ``errno``; ``major`` and ``minor`` are the GSS statuses
    (0 when the failure was not the library's); ``token`` is whatever the
    library produced alongside the failure - an acceptor's ``KRB-ERROR``
    reply, which the protocol may forward so the initiator learns why.
    """

    def __init__(
        self, message: str = "", code: int = 0, major: int = 0, minor: int = 0, token: bytes = b""
    ) -> None:
        """``GError``'s ``(message, code)``, then the statuses; xrdsec's constructor sets all."""
        gss.KerberosError.__init__(self, message, code, major, minor, token)

    def __reduce__(self) -> tuple[type[GError], tuple[str, int]]:
        """Pickle as message and code only (the token may be large and is not portable).

        Errors cross process boundaries in parallel test runs and in programs
        that use ``multiprocessing``; the raw statuses are diagnostic and are
        dropped rather than making unpickling depend on them.
        """
        return (KerberosError, (self.message, self.code))


def _as_gerror(exc: gss.KerberosError) -> KerberosError:
    """The library's error as this module's, every field kept."""
    return KerberosError(exc.message, exc.code, exc.major, exc.minor, exc.token)


@contextmanager
def _gerrors() -> Iterator[None]:
    """Re-raise any :class:`xrdsec.krb5.gss.KerberosError` from the block as a ``GError``."""
    try:
        yield
    except gss.KerberosError as exc:
        raise _as_gerror(exc) from exc


def _choice(name: str | None) -> str:
    """The binding asked for: ``name``, else ``$XGFAL_KRB5_BACKEND``, else ``auto``.

    ``ctypes`` - 0.3's own bindings, removed in 0.4.0 - names python-gssapi
    now, so scripts that set it keep working.
    """
    choice = name or os.environ.get(BACKEND_ENV) or "auto"
    return "gssapi" if choice == "ctypes" else choice


def load_backend(name: str | None = None) -> gss.GssapiBackend:
    """The binding to use: ``name``, else ``$XGFAL_KRB5_BACKEND``, else the best found.

    Cached per name by :mod:`xrdsec.krb5.gss` (:func:`reset` forgets);
    a missing binding is ``EPROTONOSUPPORT`` with :data:`HINT`, an unknown
    name ``EINVAL``.
    """
    with _gerrors():
        return gss.load_backend(_choice(name), hint=HINT)


def available(name: str | None = None) -> str | None:
    """``None`` if Kerberos can be used, else a sentence saying why not.

    LFC's Csec calls this before offering ``KRB5`` to a server, and the dcap
    plugin before claiming ``kdcap://``, so an unconfigured host falls
    through to the next mechanism (or reports why ``kdcap`` is unusable)
    instead of failing mid-handshake.
    """
    return gss.available(_choice(name), hint=HINT)


def backend(name: str | None = None) -> str | None:
    """``gssapi``; ``None`` if the system binding is unavailable."""
    return gss.backend(_choice(name))


class _Translated(gss.Context):
    """Message protection with the library's errors re-raised as :class:`KerberosError`."""

    def wrap(self, data: bytes, confidential: bool = True) -> bytes:
        """See :meth:`xrdsec.krb5.gss.Context.wrap`."""
        with _gerrors():
            return super().wrap(data, confidential)

    def unwrap(self, token: bytes, *, require_confidential: bool = False) -> bytes:
        """See :meth:`xrdsec.krb5.gss.Context.unwrap`."""
        with _gerrors():
            return super().unwrap(token, require_confidential=require_confidential)

    def get_mic(self, data: bytes) -> bytes:
        """See :meth:`xrdsec.krb5.gss.Context.get_mic`."""
        with _gerrors():
            return super().get_mic(data)

    def verify_mic(self, data: bytes, mic: bytes) -> None:
        """See :meth:`xrdsec.krb5.gss.Context.verify_mic`."""
        with _gerrors():
            super().verify_mic(data, mic)


class ClientContext(_Translated, gss.ClientContext):
    """The initiator: authenticates to ``service@host`` with the user's ticket.

    The options are :class:`xrdsec.krb5.gss.ClientContext`'s - ``principal``
    (a full target principal), ``mutual`` (the default; a server that does
    not prove itself is refused), ``delegate`` (forward the TGT), ``replay``,
    ``sequence``, ``integrity``, ``confidentiality`` and ``ccache`` - used by
    the LFC and dcap plugins. ``backend`` overrides ``$XGFAL_KRB5_BACKEND``.
    A missing ticket is a ``KerberosError`` with a ``kinit`` hint, raised
    here or by the first :meth:`step`, depending on when the library looks.
    """

    def __init__(
        self,
        service: str,
        host: str,
        *,
        backend: str | None = None,
        **options: Unpack[gss.InitiatorOptions],
    ) -> None:
        """Import the target name and prepare the context; no token is made yet."""
        name = load_backend(backend).name
        with _gerrors():
            super().__init__(service, host, backend=name, **options)

    def step(self, token: bytes = b"") -> bytes:
        """Consume the server's ``token`` (empty to start); return what to send."""
        with _gerrors():
            return super().step(token)


class AcceptorContext(_Translated, gss.AcceptorContext):
    """The acceptor: verifies a client's AP-REQ with a key from a keytab.

    With no ``service`` any key in the keytab will do, which is how a test
    server with a one-principal keytab wants it; ``keytab`` overrides
    ``KRB5_KTNAME``. Used by the fake dcap door in :mod:`xgfalclient.testing`.
    """

    def __init__(
        self,
        service: str | None = None,
        host: str | None = None,
        *,
        principal: str | None = None,
        keytab: str | None = None,
        backend: str | None = None,
    ) -> None:
        """Acquire acceptor credentials (``principal``, else ``service@host``, else any key)."""
        name = load_backend(backend).name
        with _gerrors():
            super().__init__(service, host, principal=principal, keytab=keytab, backend=name)

    def step(self, token: bytes) -> bytes:
        """Consume the client's ``token``; return the reply (AP-REP) to send, if any."""
        with _gerrors():
            return super().step(token)


def inspect_cache(name: str | None = None) -> dict[str, str | int]:
    """The cache's name, principal and latest ticket expiry, as ``klist`` would show them.

    ``name`` is a cache name (``FILE:/tmp/krb5cc_1000``, ``KCM:``); ``None``
    is the default, i.e. ``KRB5CCNAME`` or krb5.conf. The keys are ``name``,
    ``principal`` and ``expires_at`` (epoch seconds, 0 for an empty cache).
    Read with xrdsec's pure-Python reader: no key is exported, no KDC is
    contacted and nothing is written back. A cache that does not exist is a
    :class:`KerberosError` with ``ENOENT``; one that cannot be read (a macOS
    ``API:`` cache, a corrupt file, an unreachable KCM daemon) ``EACCES``.
    """
    shown = name or "default"
    try:
        info = client.inspect_cache(name)
    except FileNotFoundError as exc:
        raise KerberosError(
            f"No Kerberos cache {shown!r}: {exc}. Check KRB5CCNAME, then run kinit.",
            errno.ENOENT,
        ) from exc
    except CredentialError as exc:
        raise KerberosError(
            f"Cannot read Kerberos cache {shown!r}: {exc}. "
            "Check KRB5CCNAME and your file permissions, then run kinit.",
            errno.EACCES,
        ) from exc
    return {"name": info.name, "principal": info.principal, "expires_at": info.expires_at}
