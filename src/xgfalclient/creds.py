"""Credentials: what gfal2 calls ``cred_set``, and where it looks by default.

Two things live here.

**The credential store.** ``ctx.cred_set("davs://se.example/", cred)``
attaches a credential to every URL under a prefix; ``cred_get`` answers with
the longest prefix that matches, so a token for one directory beats a token
for its host. The types are gfal2's: ``BEARER``, ``X509_CERT``, ``X509_KEY``,
``USER`` and ``PASSWD``. The store is gfal2's alone and stays here.

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
It is not replaced by anything, either: the variable says which proxy is
meant, and presenting ``/tmp/x509up_u<uid>`` or ``~/.globus`` instead - in a
pilot job, the pilot's own identity rather than the payload's - would act as
somebody the environment did not name. X.509 access then fails with the
server's refusal, and a warning says why.
And bearer tokens follow the whole WLCG discovery specification:
``$BEARER_TOKEN``, the file named by ``$BEARER_TOKEN_FILE``,
``$XDG_RUNTIME_DIR/bt_u<uid>``, ``/tmp/bt_u<uid>`` - the order xrdclient's
own discovery uses for ``root://``, so one shell presents one identity over
every protocol. A step that finds nothing (unset, no such file, only
whitespace) passes to the next.

**Built on xrdsec.** Since 0.4.0 neither search is implemented here. The
X.509 orders are data in :mod:`xrdsec.discovery` - :data:`~xrdsec.discovery.GFAL2_SEED`
for what the context seeds (variables trusted, files unchecked) and
:data:`~xrdsec.discovery.GFAL2` for what a plugin presents (files must exist,
a missing named proxy stops the search with that warning) - and the token
search is :func:`xrdsec.credentials.find_bearer_token` with gfal2's
``skip_unreadable=True``. The trust-anchor directory is
:func:`xrdsec.discovery.discover_ca_dir`, JWT claims are
:mod:`xrdsec.tokens`', and TLS client contexts come from
:func:`xrdsec.tls.client_context` with ``x509_strict=False``, as davix never
applies Python 3.13's RFC 5280 strict checks. What this module keeps is the
gfal2 boundary: the option names, the order (store, options, discovery), the
debug lines gfal2 logs, and the library's exceptions turned into the
``GError`` codes and messages gfal2 users see.

**Token files are secrets at guessable names.** ``/tmp/bt_u<uid>`` is in a
directory anyone may write, so another user can plant one there - or a
symbolic link of that name - and be logged in as. Every token file is
therefore read through :func:`xrdsec.credentials.read_private_file`, the
same reader ``root://`` uses: it must be a regular file owned by this
user that group and others can neither read nor write, and at the two
predictable locations a symbolic link is refused rather than followed. A
file that is *there* but fails those checks is not passed over - falling
through to the next location would quietly log in as somebody else - it
fails the operation with ``EACCES`` and a message naming the file and the
fix (``chmod 600 <file>``).

The xrdsec modules are imported inside the functions that need them:
``import gfal2`` must stay cheap, and a program that never presents a
credential never pays for the search, let alone for :mod:`ssl`.
"""

from __future__ import annotations

import errno
import os
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import _log
from .errors import GError
from .options import Options

if TYPE_CHECKING:  # ssl costs ~0.3 s to import; only TLS users pay it
    import ssl

    from xrdsec.discovery import X509Location

__all__ = [
    "BEARER",
    "PASSWD",
    "USER",
    "X509_CERT",
    "X509_KEY",
    "Credential",
    "CredentialStore",
    "TLSContexts",
    "X509Credential",
    "check_bearer_token",
    "find_bearer_token",
    "find_ca_path",
    "find_x509",
    "seed_options",
    "token_claims",
]

BEARER = "BEARER"
X509_CERT = "X509_CERT"
X509_KEY = "X509_KEY"
USER = "USER"
PASSWD = "PASSWD"


class Credential:
    """One credential: a ``type`` (``"BEARER"``, ``"X509_CERT"``...) and a ``value``.

    python3-gfal2's ``gfal2.Credential`` (``gfal2_cred_t``). The value is a
    token, a password or a file path, depending on the type.
    """

    __slots__ = ("type", "value")

    def __init__(self, type: str, value: str) -> None:
        """``Credential(type, value)``, the bindings' argument order; neither is validated."""
        self.type = type
        self.value = value

    def __repr__(self) -> str:
        """The type and value, with tokens and passwords redacted (reprs end up in logs)."""
        shown = "<redacted>" if self.type in (BEARER, PASSWD) else repr(self.value)
        return f"Credential({self.type!r}, {shown})"

    def __eq__(self, other: object) -> bool:
        """Equal when type and value are (an extension: the bindings compare identity)."""
        if not isinstance(other, Credential):
            return NotImplemented
        return (self.type, self.value) == (other.type, other.value)

    def __hash__(self) -> int:
        """Consistent with ``__eq__``, so credentials can key a dict or set."""
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
    """Credentials keyed by ``(type, URL prefix)``; the longest prefix wins.

    What ``cred_set``/``cred_get`` operate on. Lookups scan every entry:
    a context holds a handful, and a scan keeps the prefix rule (see
    :func:`_covers`) in one obvious place. Thread-safe.
    """

    def __init__(self) -> None:
        """An empty store."""
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str], str] = {}

    def set(self, prefix: str, credential: Credential) -> None:
        """Store ``credential`` for ``prefix``, replacing one of the same type there."""
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
        """Remove every entry (``cred_clean``)."""
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        """How many ``(type, prefix)`` entries are stored."""
        with self._lock:
            return len(self._entries)


@dataclass(frozen=True, slots=True)
class X509Credential:
    """A certificate (or proxy) file and the file holding its key.

    Paths, not contents: files are read when a TLS context is built, and a
    proxy renewed in place is picked up by the next one (the TLS cache is
    keyed by each file's ``stat``). Frozen and hashable, so it can key a
    cache of its own.
    """

    cert: str
    key: str

    @property
    def is_combined(self) -> bool:
        """True for a proxy file carrying the key alongside the chain."""
        return self.cert == self.key


def _trimmed(env: Mapping[str, str], name: str) -> str | None:
    """``gfal2_trim_string(getenv(name))``: surrounding blanks dropped, ``""`` as unset."""
    return env.get(name, "").strip() or None


def _found(location: X509Location | None) -> X509Credential | None:
    """xrdsec's answer as gfal2's pair of paths (a proxy names one file twice)."""
    return None if location is None else X509Credential(location.cert, location.key)


def seed_options(options: Options, environ: Mapping[str, str] | None = None) -> None:
    """Write the environment's credential into ``options``, as ``gfal2_context_new`` does.

    Each outcome is logged in gfal2's words (``gfal_initCredentialLocation``).

    Seeding happens once, at context creation, and writes over whatever a
    configuration file set - gfal2's precedence, which ``get_opt_string``
    callers observe. A ``$BEARER_TOKEN`` stops the search: gfal2 then seeds
    no X.509 at all. The places and their order are
    :data:`xrdsec.discovery.GFAL2_SEED`, which trusts the variables without
    looking at the files, as gfal2 does; the names it reports a credential
    by ("X509_USER_PROXY", "default proxy location", ...) are gfal2's.
    """
    env = os.environ if environ is None else environ
    token = _trimmed(env, "BEARER_TOKEN")
    if token:
        options.set_string("BEARER", "TOKEN", token)
        _log.LOGGER.debug("Using BEARER token credentials from the env")
        return
    from xrdsec import discovery

    found = discovery.discover_x509(discovery.GFAL2_SEED, environ=env)
    if found is None:
        _log.LOGGER.debug("Could not find the credentials in any of the known locations")
        return
    options.set_string("X509", "CERT", found.cert)
    options.set_string("X509", "KEY", found.key)
    _log.LOGGER.debug("Using credentials from %s", found.source)
    _log.LOGGER.debug("Certificate: %s", found.cert)
    _log.LOGGER.debug("Private key: %s", found.key)


def _stale(cert: str, env: Mapping[str, str]) -> bool:
    """A configured certificate that is missing and came from the environment.

    Such a value was written by :func:`seed_options`, not chosen by the
    user, so it is passed over like any other stale discovery; a missing
    file the user configured explicitly is still presented (and fails
    loudly when loaded).
    """
    seeded = (_trimmed(env, "X509_USER_PROXY"), _trimmed(env, "X509_USER_CERT"))
    return cert in seeded and not os.path.isfile(cert)


def find_x509(
    options: Options,
    store: CredentialStore | None = None,
    url: str = "",
    environ: Mapping[str, str] | None = None,
) -> X509Credential | None:
    """The client certificate to present for ``url``, in gfal2's search order.

    1. ``cred_set`` X.509 entries for the longest matching prefix;
    2. ``[X509] CERT``/``KEY`` (configured, or seeded from the environment
       and still present);
    3. discovery again, now requiring the files to exist
       (:data:`xrdsec.discovery.GFAL2`): the named ``$X509_USER_PROXY``
       (and nothing else if it is missing - see the module docstring),
       ``/tmp/x509up_u<uid>``, ``$X509_USER_CERT``/``KEY``, ``~/.globus``.

    A key path that is empty means the certificate file carries the key
    (a proxy). ``environ`` is for tests.
    """
    env = os.environ if environ is None else environ
    if store is not None:
        cert, _ = store.get(X509_CERT, url)
        if cert:
            key, _ = store.get(X509_KEY, url)
            return X509Credential(cert, key or cert)
    cert = options.string("X509", "CERT")
    if cert and not _stale(cert, env):
        return X509Credential(cert, options.string("X509", "KEY") or cert)
    from xrdsec import discovery

    # Discovered (as opposed to configured) files count only if they exist,
    # as in davix: a stale X509_USER_PROXY must not break token-only access.
    # Nor is it replaced by a proxy found elsewhere, which would be a
    # different identity from the one the environment named: GFAL2's
    # ``missing_named_proxy="stop"``, which warns once per path.
    return _found(discovery.discover_x509(discovery.GFAL2, environ=env))


def find_bearer_token(
    options: Options,
    store: CredentialStore | None = None,
    url: str = "",
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """The bearer token for ``url``: explicit first, then WLCG discovery.

    Raises ``GError(EACCES)`` for a token file that is there but not
    private to this user (see the module docstring), or too large to be a
    token; the message is xrdsec's, naming the file and the fix.

    Order: ``cred_set`` BEARER entries for the longest matching prefix,
    ``[BEARER] TOKEN``, then :func:`xrdsec.credentials.find_bearer_token`
    with ``skip_unreadable=True`` - a file that cannot be read for an
    ordinary reason is "no token here", as davix treats it. Nothing is
    cached: a token refreshed on disk is used from the next request on,
    which is how long-running jobs with ``htgettoken``-style refreshers work.
    """
    env = os.environ if environ is None else environ
    if store is not None:
        value, _ = store.get(BEARER, url)
        if value:
            return value
    configured = options.string("BEARER", "TOKEN")
    if configured:
        return configured
    # Imported here: ``import gfal2`` loads no xrdsec module
    # (tests/test_import_cost.py), and only a token search needs this one.
    from xrdcore.errors import CredentialError
    from xrdsec import credentials

    try:
        return credentials.find_bearer_token(env, skip_unreadable=True)
    except CredentialError as exc:
        # InsecureCredentialError (somebody else's file, or one others may
        # read) or a "token" too large to be one: never a reason to try the
        # next location, always gfal2's EACCES.
        raise GError(str(exc), errno.EACCES) from exc


def token_claims(token: str) -> dict[str, object]:
    """Unverified JWT claims for diagnostics only; never an authorization decision.

    :func:`xrdsec.tokens.token_claims` with gfal2's strict reading
    (``padding=False``): three dot-separated segments whose first two are
    canonical, unpadded base64url JSON objects (RFC 7519 s. 7.2). The
    signature is never examined, so nothing here may be used to decide
    access; it exists so an expired token can be named before a server
    refuses it. Anything else - a macaroon or other opaque credential, a
    malformed segment - has no claims, and ``{}`` says so.
    """
    from xrdsec import tokens

    return tokens.token_claims(token)


def check_bearer_token(token: str) -> None:
    """Fail early for an expired JWT; opaque tokens and macaroons remain usable.

    ``EACCES`` with a sentence saying what to do, instead of the server's
    bare 401: :func:`xrdsec.tokens.check_token`'s refusal, as a ``GError``.
    The ``exp`` claim is read unverified (see :func:`token_claims`): the
    check can only ever refuse a token, never grant anything, so an
    attacker gains nothing by forging it. A token without a usable ``exp``
    is left for the server to judge.
    """
    from xrdcore.errors import TokenExpiredError
    from xrdsec import tokens

    try:
        tokens.check_token(token)
    except TokenExpiredError as exc:
        raise GError(str(exc), errno.EACCES) from exc


def find_ca_path(environ: Mapping[str, str] | None = None) -> str | None:
    """The trust-anchor directory from the environment or grid installation.

    ``$X509_CERT_DIR`` as given (even if missing: the user named it), else
    the first existing of ``/etc/grid-security/certificates`` and, on
    macOS, Homebrew's ``etc/grid-security/certificates`` under
    ``/opt/homebrew`` or ``/usr/local`` - :func:`xrdsec.discovery.discover_ca_dir`
    under gfal2's search, which has no per-user directories. None means
    "system CAs only".
    """
    from xrdsec import discovery

    return discovery.discover_ca_dir(discovery.GFAL2, environ=environ)


class TLSContexts:
    """TLS client contexts for a gfal2 context's credentials.

    Building an ``SSLContext`` and loading a chain is milliseconds, which is
    noise once but real money across a thousand ``stat`` calls, so contexts
    are shared. The sharing is :func:`xrdsec.tls.client_context`'s: one
    process-wide cache keyed by every setting and by each file's ``stat``,
    so a proxy renewed in place gets a fresh context on the next call and
    two gfal2 contexts presenting the same files share one (and its TLS
    session cache). This class is the gfal2-shaped front of it: an
    :class:`X509Credential`, gfal2's lenient X.509 checks, and ``GError``
    for a credential that will not load.
    """

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
        """A client context; ``check_hostname=False`` for GSI's own name check.

        Every argument is part of the library's cache key, so two callers
        asking for the same thing share one context, while a GSI caller's
        ``check_hostname=False`` context is never handed to an HTTPS caller
        that relies on the hostname check. A proxy (one file) is loaded by
        name, as davix loads it; a separate key is read through xrdsec's
        private-file checks (yours, ``0600``) and piped to OpenSSL, never
        copied to disk.

        Raises ``GError`` (``ENOENT`` for a missing file, else ``EACCES``)
        if the credential cannot be loaded; nothing is cached in that case,
        so a fixed file is picked up by the next call. The returned context
        is shared and must not be modified.
        """
        from xrdcore.errors import CredentialError
        from xrdsec import tls

        try:
            return tls.client_context(
                cert=None if cred is None else cred.cert,
                key=None if cred is None or cred.is_combined else cred.key,
                ca_path=ca_path,
                ca_file=ca_file,
                verify=verify,
                x509_strict=False,
                check_hostname=check_hostname,
                alpn=alpn,
            )
        except (OSError, CredentialError) as exc:
            if cred is None:
                raise  # a trust store that will not load (a missing ca_file): not ours to word
            # ssl.SSLError (an OSError) carries an OpenSSL reason, not an errno.
            code = errno.ENOENT if isinstance(exc, FileNotFoundError) else errno.EACCES
            raise GError(f"Could not load the X.509 credential {cred.cert}: {exc}", code) from exc

    def clear(self) -> None:
        """Forget every cached context, so the next ``get`` builds afresh.

        Not needed for correctness - a changed file is a new cache key - but
        the context calls it on every ``cred_set``/``cred_del``/``cred_clean``
        and when it is freed, so a credential just replaced never shares a
        context built for its predecessor. Connections already made keep the
        context they were made with. A process that never built a context
        has nothing to forget, so :mod:`xrdsec.tls` - and with it :mod:`ssl`,
        a noticeable fraction of a second - is not imported just to say so:
        every ``gfal-*`` command frees its context on the way out.
        """
        tls = sys.modules.get("xrdsec.tls")
        if tls is not None:
            tls.clear_cache()
