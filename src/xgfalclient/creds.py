"""Credentials: what gfal2 calls ``cred_set``, and where it looks by default.

Two things live here.

**The credential store.** ``ctx.cred_set("davs://se.example/", cred)``
attaches a credential to every URL under a prefix; ``cred_get`` answers with
the longest prefix that matches, so a token for one directory beats a token
for its host. The types are gfal2's: ``BEARER``, ``X509_CERT``, ``X509_KEY``,
``USER`` and ``PASSWD``.

**Discovery.** With nothing set explicitly, credentials are found where the
grid expects them, in gfal2's order: the ``[X509]`` options, then
``$X509_USER_PROXY``, then ``/tmp/x509up_u<uid>``, then
``$X509_USER_CERT``/``$X509_USER_KEY``, then ``~/.globus``. Bearer tokens
follow the WLCG discovery specification: ``$BEARER_TOKEN``, the file named
by ``$BEARER_TOKEN_FILE``, ``$XDG_RUNTIME_DIR/bt_u<uid>``, ``/tmp/bt_u<uid>``.
"""

from __future__ import annotations

import errno
import os
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._compat import SLOTS
from .errors import GError
from .options import Options

if TYPE_CHECKING:  # ssl costs ~0.3 s to import; only TLS users pay it
    import ssl

__all__ = [
    "Credential",
    "CredentialStore",
    "X509Credential",
    "BEARER",
    "X509_CERT",
    "X509_KEY",
    "USER",
    "PASSWD",
    "find_x509",
    "find_bearer_token",
    "find_ca_path",
    "TLSContexts",
]

BEARER = "BEARER"
X509_CERT = "X509_CERT"
X509_KEY = "X509_KEY"
USER = "USER"
PASSWD = "PASSWD"


class Credential:
    """One credential: a ``type`` (``"BEARER"``, ``"X509_CERT"``...) and a ``value``."""

    __slots__ = ("type", "value")

    def __init__(self, type: str, value: str) -> None:
        self.type = type
        self.value = value

    def __repr__(self) -> str:
        shown = "<redacted>" if self.type in (BEARER, PASSWD) else repr(self.value)
        return f"Credential({self.type!r}, {shown})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Credential):
            return NotImplemented
        return (self.type, self.value) == (other.type, other.value)

    def __hash__(self) -> int:
        return hash((self.type, self.value))


class CredentialStore:
    """Credentials keyed by ``(type, URL prefix)``; the longest prefix wins."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str], str] = {}

    def set(self, prefix: str, credential: Credential) -> None:
        with self._lock:
            self._entries[(credential.type, prefix)] = credential.value

    def get(self, type: str, url: str) -> tuple[str, str]:
        """``(value, prefix)`` for the best match, ``("", "")`` for none."""
        with self._lock:
            best = ("", "")
            for (kind, prefix), value in self._entries.items():
                if kind == type and url.startswith(prefix) and len(prefix) >= len(best[1]):
                    best = (value, prefix)
            return best

    def delete(self, type: str, prefix: str) -> None:
        with self._lock:
            self._entries.pop((type, prefix), None)

    def clean(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


@dataclass(frozen=True, **SLOTS)
class X509Credential:
    """A certificate (or proxy) file and the file holding its key."""

    cert: str
    key: str

    @property
    def is_combined(self) -> bool:
        """True for a proxy file carrying the key alongside the chain."""
        return self.cert == self.key


def _uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else 0


def _existing(path: str | None) -> str | None:
    return path if path and os.path.isfile(path) else None


def find_x509(
    options: Options,
    store: CredentialStore | None = None,
    url: str = "",
    environ: Mapping[str, str] | None = None,
) -> X509Credential | None:
    """The client certificate to present for ``url``, in gfal2's search order."""
    env = os.environ if environ is None else environ
    if store is not None:
        cert, _ = store.get(X509_CERT, url)
        if cert:
            key, _ = store.get(X509_KEY, url)
            return X509Credential(cert, key or cert)
    cert = options.string("X509", "CERT")
    if cert:
        return X509Credential(cert, options.string("X509", "KEY") or cert)
    # Discovered (as opposed to configured) files count only if they exist,
    # as in davix: a stale X509_USER_PROXY must not break token-only access.
    proxy = _existing(env.get("X509_USER_PROXY")) or _existing(f"/tmp/x509up_u{_uid()}")
    if proxy:
        return X509Credential(proxy, proxy)
    user_cert = _existing(env.get("X509_USER_CERT"))
    user_key = _existing(env.get("X509_USER_KEY"))
    if user_cert and user_key:
        return X509Credential(user_cert, user_key)
    home = env.get("HOME") or os.path.expanduser("~")
    globus_cert = _existing(os.path.join(home, ".globus", "usercert.pem"))
    globus_key = _existing(os.path.join(home, ".globus", "userkey.pem"))
    if globus_cert and globus_key:
        return X509Credential(globus_cert, globus_key)
    return None


def _read_token(path: str | None) -> str | None:
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def find_bearer_token(
    options: Options,
    store: CredentialStore | None = None,
    url: str = "",
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """The bearer token for ``url``: explicit first, then WLCG discovery."""
    env = os.environ if environ is None else environ
    if store is not None:
        value, _ = store.get(BEARER, url)
        if value:
            return value
    configured = options.string("BEARER", "TOKEN")
    if configured:
        return configured
    inline = env.get("BEARER_TOKEN", "").strip()
    if inline:
        return inline
    if "BEARER_TOKEN_FILE" in env:
        return _read_token(env["BEARER_TOKEN_FILE"])
    runtime = env.get("XDG_RUNTIME_DIR")
    if runtime:
        found = _read_token(os.path.join(runtime, f"bt_u{_uid()}"))
        if found:
            return found
    return _read_token(f"/tmp/bt_u{_uid()}")


def find_ca_path(environ: Mapping[str, str] | None = None) -> str | None:
    """The trust-anchor directory: ``$X509_CERT_DIR`` or the grid default."""
    env = os.environ if environ is None else environ
    configured = env.get("X509_CERT_DIR")
    if configured:
        return configured
    default = "/etc/grid-security/certificates"
    return default if os.path.isdir(default) else None


class TLSContexts:
    """TLS client contexts, built once per distinct credential set.

    Building an ``SSLContext`` and loading a chain is milliseconds, which is
    noise once but real money across a thousand ``stat`` calls, so contexts
    are cached by what went into them. Session resumption comes free with
    reuse.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[tuple[object, ...], ssl.SSLContext] = {}

    def get(
        self,
        cred: X509Credential | None,
        *,
        verify: bool = True,
        ca_path: str | None = None,
        ca_file: str | None = None,
        alpn: tuple[str, ...] = (),
        check_hostname: bool = True,
    ) -> ssl.SSLContext:
        """A client context; ``check_hostname=False`` for GSI's own name check."""
        key = (cred, verify, ca_path, ca_file, alpn, check_hostname)
        with self._lock:
            found = self._cache.get(key)
            if found is None:
                found = _build(cred, verify, ca_path, ca_file, alpn, check_hostname)
                self._cache[key] = found
            return found

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


def _build(
    cred: X509Credential | None,
    verify: bool,
    ca_path: str | None,
    ca_file: str | None,
    alpn: tuple[str, ...],
    check_hostname: bool = True,
) -> ssl.SSLContext:
    import ssl

    context = ssl.create_default_context(cafile=ca_file, capath=ca_path)
    context.check_hostname = check_hostname and verify
    # Python 3.13 turned on RFC 5280 strict checking by default. Grid CAs
    # predate it and davix does not apply it, so neither does this.
    context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    if not verify:
        context.verify_mode = ssl.CERT_NONE
    if alpn:
        context.set_alpn_protocols(list(alpn))
    if cred is not None:
        try:
            context.load_cert_chain(cred.cert, cred.key)
        except (OSError, ssl.SSLError) as exc:
            # ssl.SSLError.errno is an OpenSSL reason code, not an errno.
            code = errno.ENOENT if isinstance(exc, FileNotFoundError) else errno.EACCES
            raise GError(f"Could not load the X.509 credential {cred.cert}: {exc}", code) from exc
    return context
