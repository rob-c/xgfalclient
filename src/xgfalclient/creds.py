"""Credentials: what gfal2 calls ``cred_set``, and where it looks by default.

Two things live here.

**The credential store.** ``ctx.cred_set("davs://se.example/", cred)``
attaches a credential to every URL under a prefix; ``cred_get`` answers with
the longest prefix that matches, so a token for one directory beats a token
for its host. The types are gfal2's: ``BEARER``, ``X509_CERT``, ``X509_KEY``,
``USER`` and ``PASSWD``.

**Discovery.** As gfal2 does when a context is created, :func:`seed_options`
copies the environment's credential into the options, over anything a
configuration file said: ``$BEARER_TOKEN`` into ``[BEARER] TOKEN`` (and then
nothing else), else ``$X509_USER_PROXY`` (not checked for existence),
``/tmp/x509up_u<uid>`` if it exists, ``$X509_USER_CERT``/``$X509_USER_KEY``,
or a readable ``~/.globus`` pair into ``[X509] CERT``/``KEY``. That is what
``cred_get`` falls back to, and what ``get_opt_string("X509", "CERT")``
shows.

When a plugin asks for a credential, the ``[X509]`` options come first, then
the same search again, lazily, so a variable set after the context was made
still counts. Two things deliberately go beyond gfal2 here. A seeded file
that does not exist is passed over rather than presented, so a stale
``$X509_USER_PROXY`` cannot break token-only access (davix behaves the same).
And bearer tokens follow the whole WLCG discovery specification:
``$BEARER_TOKEN``, the file named by ``$BEARER_TOKEN_FILE``,
``$XDG_RUNTIME_DIR/bt_u<uid>``, ``/tmp/bt_u<uid>``.
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
    "seed_options",
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


def _covers(prefix: str, url: str) -> bool:
    """Whether ``prefix`` names ``url`` or a directory above it, as gfal2 matches.

    A bare string prefix is not enough: a token for ``https://h/store/alice``
    must not go to ``https://h/store/alicebob/f``.
    """
    if not url.startswith(prefix):
        return False
    return len(prefix) == len(url) or prefix.endswith("/") or url[len(prefix)] == "/"


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
                if kind == type and _covers(prefix, url) and len(prefix) >= len(best[1]):
                    best = (value, prefix)
            return best

    def delete(self, type: str, prefix: str) -> bool:
        """Remove one exact entry; ``False`` if there was none."""
        with self._lock:
            return self._entries.pop((type, prefix), None) is not None

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


def _trimmed(env: Mapping[str, str], name: str) -> str | None:
    """``gfal2_trim_string(getenv(name))``: surrounding blanks dropped, ``""`` as unset."""
    return env.get(name, "").strip() or None


def seed_options(options: Options, environ: Mapping[str, str] | None = None) -> None:
    """Write the environment's credential into ``options``, as ``gfal2_context_new`` does."""
    env = os.environ if environ is None else environ
    token = _trimmed(env, "BEARER_TOKEN")
    if token:
        options.set_string("BEARER", "TOKEN", token)
        return
    found = _environment_x509(env)
    if found is not None:
        options.set_string("X509", "CERT", found.cert)
        options.set_string("X509", "KEY", found.key)


def _environment_x509(env: Mapping[str, str]) -> X509Credential | None:
    """gfal2's search, which trusts the variables without looking at the files."""
    proxy = _trimmed(env, "X509_USER_PROXY") or _existing(f"/tmp/x509up_u{_uid()}")
    if proxy:
        return X509Credential(proxy, proxy)
    cert, key = _trimmed(env, "X509_USER_CERT"), _trimmed(env, "X509_USER_KEY")
    if cert and key:
        return X509Credential(cert, key)
    home = _trimmed(env, "HOME")
    if home:
        pair = X509Credential(
            os.path.join(home, ".globus", "usercert.pem"),
            os.path.join(home, ".globus", "userkey.pem"),
        )
        if os.access(pair.cert, os.R_OK) and os.access(pair.key, os.R_OK):
            return pair
    return None


def _stale(cert: str, env: Mapping[str, str]) -> bool:
    """A configured certificate that is missing and came from the environment."""
    seeded = (_trimmed(env, "X509_USER_PROXY"), _trimmed(env, "X509_USER_CERT"))
    return cert in seeded and not os.path.isfile(cert)


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
    if cert and not _stale(cert, env):
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
