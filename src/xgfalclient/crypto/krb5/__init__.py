"""Kerberos 5 as a GSS-API mechanism, driven by tokens like :mod:`..gsi`.

Protocols that speak Kerberos (``kdcap``, xrootd's ``krb5``, ssh's
``gssapi-with-mic``) all do the same thing: ferry opaque GSS tokens between
``gss_init_sec_context`` and the server until the context is established,
then ``gss_wrap``/``gss_unwrap`` their messages or sign them. That is the
whole API here::

    ctx = krb5.ClientContext("host", "door.example.org")
    token = ctx.step()
    while True:
        if token:
            send(token)
        if ctx.complete:
            break
        token = ctx.step(receive())
    line = ctx.unwrap(receive())

Nothing about Kerberos itself is implemented in Python. The tokens come
from the platform's GSS-API library, which is the only thing that can use
the machine's credential cache as configured (KCM via sssd on EL9,
``FILE:``, ``KEYRING:``, macOS's ``API:``) and the only thing the site's KDC
is tested against. Two ways to reach it, chosen once per process:

* the ``gssapi`` package (python-gssapi), when it is importable;
* otherwise ``ctypes`` straight into ``libgssapi_krb5`` (MIT) or Heimdal's
  library - Apple's ``GSS.framework`` on macOS - with no dependency at all.

``XGFAL_KRB5_BACKEND=gssapi|ctypes`` forces one, ``XGFAL_GSSAPI_LIBRARY``
names the library for the second. Credentials are the library's defaults:
``KRB5CCNAME`` or the configured default cache for an initiator,
``KRB5_KTNAME`` or ``/etc/krb5.keytab`` for an acceptor; ``ccache=`` and
``keytab=`` pick others per context. gfal2 itself has no Kerberos options,
so none are read from its configuration.

Every failure is a :class:`KerberosError` - a ``GError`` whose ``errno`` is
``EACCES`` for a refused or impossible authentication, ``ETIMEDOUT`` when no
KDC answered, ``EPROTO`` for a corrupt or replayed token and
``EPROTONOSUPPORT`` when there is no Kerberos library at all.

A context may be used from several threads; each call holds the context's
own lock, and the library handle is shared (GSS libraries are thread-safe
across distinct contexts).
"""

from __future__ import annotations

import errno
import os
import threading
from types import TracebackType

from ._base import HOSTBASED, PRINCIPAL, Backend, Mechanism, Target
from ._status import KerberosError

__all__ = [
    "KerberosError",
    "ClientContext",
    "AcceptorContext",
    "available",
    "backend",
    "load_backend",
    "reset",
    "BACKEND_ENV",
    "HINT",
    "DELEG_FLAG",
    "MUTUAL_FLAG",
    "REPLAY_FLAG",
    "SEQUENCE_FLAG",
    "CONF_FLAG",
    "INTEG_FLAG",
]

#: Forces a backend: ``gssapi`` or ``ctypes``.
BACKEND_ENV = "XGFAL_KRB5_BACKEND"

HINT = (
    "install the system Kerberos library (krb5-libs on EL, libgssapi-krb5-2 on Debian) "
    "or the Python gssapi package"
)

# ``gss_init_sec_context`` request flags (RFC 2744).
DELEG_FLAG = 1
MUTUAL_FLAG = 2
REPLAY_FLAG = 4
SEQUENCE_FLAG = 8
CONF_FLAG = 16
INTEG_FLAG = 32

_BACKENDS: dict[str, Backend] = {}
_LOCK = threading.Lock()


def _load_gssapi() -> Backend:
    import gssapi  # type: ignore[import-not-found,unused-ignore]

    from ._gssapi import GssapiBackend

    return GssapiBackend(gssapi)


def _load_ctypes() -> Backend:
    from ._ctypes import load

    return load()


def _select(choice: str) -> Backend:
    """The backend for ``choice`` (``auto``, ``gssapi`` or ``ctypes``), or raise."""
    if choice not in ("auto", "gssapi", "ctypes"):
        raise KerberosError(
            f"unknown Kerberos backend {choice!r} (expected gssapi or ctypes)", errno.EINVAL
        )
    reasons: list[str] = []
    if choice in ("auto", "gssapi"):
        try:
            return _load_gssapi()
        except ImportError as exc:
            reasons.append(f"the gssapi package cannot be imported ({exc})")
    if choice in ("auto", "ctypes"):
        try:
            return _load_ctypes()
        except OSError as exc:
            reasons.append(str(exc))
    raise KerberosError(
        "Kerberos 5 (GSS-API) is not available: " + "; ".join(reasons) + f"; {HINT}",
        errno.EPROTONOSUPPORT,
    )


def load_backend(name: str | None = None) -> Backend:
    """The backend to use: ``name``, else ``$XGFAL_KRB5_BACKEND``, else the best found.

    The result is cached per name, and so is a failure's absence of one:
    looking again costs a fresh search, so :func:`reset` exists for tests
    and for programs that install a library while running.
    """
    choice = name or os.environ.get(BACKEND_ENV) or "auto"
    with _LOCK:
        found = _BACKENDS.get(choice)
        if found is None:
            found = _BACKENDS[choice] = _select(choice)
        return found


def reset() -> None:
    """Forget the backends found so far."""
    with _LOCK:
        _BACKENDS.clear()


def available(name: str | None = None) -> str | None:
    """``None`` if Kerberos can be used, else a sentence saying why not."""
    try:
        load_backend(name)
    except KerberosError as exc:
        return exc.message
    return None


def backend(name: str | None = None) -> str | None:
    """``ctypes-mit``, ``ctypes-heimdal`` or ``gssapi``; ``None`` if there is none."""
    try:
        return load_backend(name).name
    except KerberosError:
        return None


class _Context:
    """What the two sides share: locking, message protection, names."""

    def __init__(self, mechanism: Mechanism, backend_name: str) -> None:
        self._mech: Mechanism | None = mechanism
        self._lock = threading.Lock()
        self._names: tuple[str, str, int] | None = None
        self.backend = backend_name
        self.complete = False

    def __enter__(self) -> _Context:
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def _established(self) -> Mechanism:
        if self._mech is None:
            raise KerberosError("the Kerberos context has been closed", errno.EBADF)
        if not self.complete:
            raise KerberosError("the Kerberos context is not yet established", errno.EPROTO)
        return self._mech

    def _step(self, token: bytes) -> bytes:
        with self._lock:
            if self._mech is None:
                raise KerberosError("the Kerberos context has been closed", errno.EBADF)
            if self.complete:
                raise KerberosError("the Kerberos context is already established", errno.EPROTO)
            out = self._mech.step(token)
            if self._mech.complete:
                self._names = self._mech.inquire()
                self._check()
                self.complete = True
            return out

    def _check(self) -> None:
        """A side's own demands of the negotiated context."""

    def wrap(self, data: bytes, confidential: bool = True) -> bytes:
        """``gss_wrap``: a token carrying ``data``, encrypted unless told otherwise."""
        with self._lock:
            token, encrypted = self._established().wrap(data, confidential)
        if confidential and not encrypted:
            raise KerberosError("gss_wrap could not provide confidentiality", errno.EPROTO)
        return token

    def unwrap(self, token: bytes, *, require_confidential: bool = False) -> bytes:
        """``gss_unwrap``: the data ``token`` carries, integrity checked."""
        with self._lock:
            data, encrypted = self._established().unwrap(token)
        if require_confidential and not encrypted:
            raise KerberosError("the peer sent an unencrypted token", errno.EPROTO)
        return data

    def get_mic(self, data: bytes) -> bytes:
        """``gss_get_mic``: a signature over ``data``."""
        with self._lock:
            return self._established().get_mic(data)

    def verify_mic(self, data: bytes, mic: bytes) -> None:
        """``gss_verify_mic``: raise ``EPROTO`` unless ``mic`` signs ``data``."""
        with self._lock:
            self._established().verify_mic(data, mic)

    @property
    def initiator_name(self) -> str | None:
        """The client principal (``user@REALM``), once established."""
        return None if self._names is None else self._names[0]

    @property
    def target_name(self) -> str | None:
        """The service principal (``host/door@REALM``), once established."""
        return None if self._names is None else self._names[1]

    @property
    def flags(self) -> int:
        """The negotiated ``*_FLAG`` bits; ``0`` until established."""
        return 0 if self._names is None else self._names[2]

    def close(self) -> None:
        """Delete the context and release what it holds. Idempotent."""
        lock = getattr(self, "_lock", None)
        if lock is None:  # __init__ failed before there was anything to close
            return
        with lock:
            mechanism, self._mech = self._mech, None
            if mechanism is not None:
                mechanism.close()


class ClientContext(_Context):
    """The initiator: authenticates to ``service@host`` with the user's ticket.

    ``principal`` names the target as a full Kerberos principal instead
    (``xrootd/host@REALM``). ``mutual`` (the default) makes the server prove
    itself, and an established context without it is refused. ``delegate``
    forwards the TGT. ``ccache`` picks a credential cache other than the
    default (``KRB5CCNAME`` already does that for the whole process).
    """

    def __init__(
        self,
        service: str,
        host: str,
        *,
        principal: str | None = None,
        mutual: bool = True,
        delegate: bool = False,
        replay: bool = True,
        sequence: bool = True,
        integrity: bool = True,
        confidentiality: bool = True,
        ccache: str | None = None,
        backend: str | None = None,
    ) -> None:
        if principal:
            target = Target(principal, PRINCIPAL)
        else:
            target = Target(f"{service}@{host}" if host else service, HOSTBASED)
        flags = (
            (DELEG_FLAG if delegate else 0)
            | (MUTUAL_FLAG if mutual else 0)
            | (REPLAY_FLAG if replay else 0)
            | (SEQUENCE_FLAG if sequence else 0)
            | (CONF_FLAG if confidentiality else 0)
            | (INTEG_FLAG if integrity else 0)
        )
        found = load_backend(backend)
        super().__init__(found.initiator(target, flags, ccache), found.name)
        self.target = target
        self.requested = flags

    def step(self, token: bytes = b"") -> bytes:
        """Consume the server's ``token`` (empty to start); return what to send."""
        return self._step(token)

    def _check(self) -> None:
        if self.requested & MUTUAL_FLAG and not self.flags & MUTUAL_FLAG:
            raise KerberosError(
                f"{self.target.name} did not authenticate itself (no mutual authentication)",
                errno.EACCES,
            )


class AcceptorContext(_Context):
    """The acceptor: verifies a client's AP-REQ with a key from a keytab.

    With no ``service`` any key in the keytab will do, which is how a test
    server with a one-principal keytab wants it; ``keytab`` overrides
    ``KRB5_KTNAME``. On Heimdal without ``gss_acquire_cred_from`` that
    override is process-wide.
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
        name: Target | None = None
        if principal:
            name = Target(principal, PRINCIPAL)
        elif service:
            name = Target(f"{service}@{host}" if host else service, HOSTBASED)
        found = load_backend(backend)
        super().__init__(found.acceptor(name, keytab), found.name)

    def step(self, token: bytes) -> bytes:
        """Consume the client's ``token``; return the reply (AP-REP) to send, if any."""
        if not token:
            raise KerberosError("an acceptor needs the client's token", errno.EINVAL)
        return self._step(token)
