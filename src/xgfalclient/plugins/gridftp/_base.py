"""The GridFTP plugin's sessions, and what every operation built on them shares.

Part of the :mod:`xgfalclient.plugins.gridftp.plugin` split (that module's
docstring has the layout and gfal2's behaviour): the option group and event
domains, the per-URL :class:`_Profile` (credential, TLS context, data-channel
security), pooled control :class:`_Session`\\ s, globus' view of a URL
(:func:`_path`, :func:`_explicit_port`, :func:`_check_url`) and gfal2's host
helpers (:func:`lookup_host`, :func:`_resolve_dns`). :class:`_GridFTPBase` is
the plugin class's root: connecting, logging in, pooling, ``MLST``/``SIZE``
stats and the ``MODE S`` fetch that listings, checksums and partial reads use.
The copy and file mixins (:mod:`._copy`, :mod:`._files`) build on it, and
:class:`~xgfalclient.plugins.gridftp.plugin.GridFTPPlugin` combines them.

Nothing here looks names up through the facade: no test or caller patches a
module-level name these functions use (a patch on the stdlib modules -
``socket.getaddrinfo``, ``os.pwrite`` - reaches every module alike). Patch a
helper in the module that defines it.

Sessions and the pool. Every operation borrows one control connection with
:meth:`_GridFTPBase._session` and gives it back when the ``with`` ends. The
pool is keyed by :attr:`_Profile.key` - everything that makes two sessions
interchangeable (host, port, credential files, data-channel security,
delegation; user and password for ``ftp://``) - so a pooled session is
never reused under different settings. A session is pooled again only if it
is still :meth:`~.control.Control.healthy`: anything that might have left
its reply stream out of step marks it ``broken`` and it is closed instead.
The plugin's lock guards only the pool and the credential cache, never I/O,
so sessions to different servers (or several to one) run in parallel.
"""

from __future__ import annotations

import contextlib
import errno
import os
import random
import socket
import ssl
import stat as _stat
import threading
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from xrdsec.der import DERError

from ..._version import GFAL2_VERSION
from ...crypto.x509 import Credential, load_credential
from ...errors import ECOMM, GError
from ...plugin import Plugin, shutdown_sockets
from ...types import Stat
from ...url import URL, parse
from .control import Control
from .data import (
    ChannelOptions,
    ConnSetup,
    DataConn,
    DataSecurity,
    DataTransfer,
    recv_stream,
)
from .gsi import data_contexts
from .protocol import check_path, parse_facts, stat_from_facts

#: gfal2's option group for this plugin (``[GRIDFTP PLUGIN]`` in its .conf).
GROUP = "GRIDFTP PLUGIN"
#: The event domain of gfal2's single-copy events (``GSIFTP``).
DOMAIN = "GSIFTP"
#: The domain of gfal2's bulk-copy events.
BULK_DOMAIN = "GridFTP::Filecopy"
#: gfal2's ``ENOATTR`` is Linux's ``ENODATA``.
ENOATTR: int = getattr(errno, "ENOATTR", errno.ENODATA)
_SCHEMES = ("gsiftp", "ftp")
#: ``checksum_mode`` bits, as gfal2's ``gfalt_checksum_mode_t``: check the
#: source before, the destination after (both is 3, ``GFALT_CHECKSUM_BOTH``).
_SOURCE, _TARGET = 1, 2
#: The text a GridFTP server fails ``SITE SETNETSTACK udt`` with.
_NO_UDT = "udt driver not whitelisted"


@dataclass(frozen=True, slots=True)
class _Profile:
    """Everything a session to one URL needs, worked out once per call.

    Built by :meth:`_GridFTPBase._profile` from the URL, the context's
    credentials and the ``[GRIDFTP PLUGIN]`` options; immutable, so the
    sessions borrowed with it can share it across threads.
    """

    #: The pool key: two profiles with equal keys may share sessions.
    key: tuple[object, ...]
    host: str
    port: int
    #: ``:globus-mapping:``/``dummy`` for GSI; the ``ftp://`` login otherwise.
    user: str
    password: str
    #: Seconds: the control channel's reply timeout and each data socket's.
    timeout: float
    #: The TLS context for GSI; ``None`` for cleartext ``ftp://``.
    tls: ssl.SSLContext | None = None
    #: The proxy to delegate during ``ADAT``; ``None`` with ``DELEGATION`` off.
    delegate: Credential | None = None
    #: ``DCAU A``/``PROT P`` set-up for data channels; ``None`` is ``DCAU N``.
    security: DataSecurity | None = None


class _Session:
    """A control connection lent out of the pool, with the profile it was made for.

    ``data`` holds the ``MODE S`` stream sockets opened on it, so that a
    ``cancel()`` can :meth:`abort` everything the session might be blocked on.
    """

    __slots__ = ("control", "data", "profile")

    def __init__(self, control: Control, profile: _Profile) -> None:
        """Pair a pooled or fresh ``control`` with the ``profile`` it was made for."""
        self.control = control
        self.profile = profile
        self.data: list[socket.socket] = []

    def abort(self) -> None:
        """Shut down the control and data sockets under a blocked thread; for ``cancel()``.

        The reply or the stream then ends at once, the session is broken, and
        it is closed rather than pooled when it is given back.
        """
        shutdown_sockets(self.control.sock, *self.data)


def _path(url: URL) -> str:
    """The path globus sends: percent-decoded, with any query as part of it."""
    raw = url.path or "/"
    if url.query:
        raw += "?" + url.query
    return check_path(urllib.parse.unquote(raw))


def _explicit_port(url: URL) -> int:
    """The port written in the URL, 0 without one (gfal2's ``gfal2_uri``)."""
    host = url.netloc.rpartition("@")[2]
    tail = host.rpartition("]")[2]
    text = tail.rpartition(":")[2] if ":" in tail else ""
    return int(text) if text.isdigit() else 0


def _check_url(url: URL) -> None:
    """``globus_url_parse``'s refusals, before any credential.

    No host, or a port that does not start with a digit (globus reads the
    leading number of ``h:0x``, as ``sscanf`` would).
    """
    tail = url.netloc.rpartition("@")[2].rpartition("]")[2]
    port = tail.rpartition(":")[2] if ":" in tail else "0"
    if not url.host or not port[:1].isdigit():
        raise GError("globus_ftp_client: an invalid value for url was used ", ECOMM)


def lookup_host(host: str, ipv6: bool) -> tuple[str, bool]:
    """gfal2's ``lookup_host``: an address of ``host`` and whether it has an IPv6 one.

    The last IPv4 and IPv6 addresses found are kept; the IPv6 one (in
    brackets) wins when ``ipv6`` is on.
    """
    try:
        found = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return "cant.be.resolved", False
    ip4 = ip6 = ""
    for family, _, _, _, address in found:
        if family == socket.AF_INET6:
            ip6 = str(address[0])
        else:
            ip4 = str(address[0])
    if ipv6 and ip6:
        return f"[{ip6}]", True
    return (ip4 or "cant.be.resolved"), bool(ip6)


def _host_and_port(url: str, ipv6: bool) -> str:
    """``ip:port`` for the transfer events: the resolved address, the URL's port or 0."""
    parsed = parse(url)
    return f"{lookup_host(parsed.host, ipv6)[0]}:{_explicit_port(parsed)}"


def _pair_text(source: str, target: str, ipv6: bool) -> str:
    """``(ip:port) source => (ip:port) target``: gfal2's TRANSFER:ENTER/EXIT text."""
    return f"({_host_and_port(source, ipv6)}) {source} => ({_host_and_port(target, ipv6)}) {target}"


def _resolve_dns(url: str, what: str, log: Any) -> str:
    """``[CORE] RESOLVE_DNS``: the host replaced by the name of one of its addresses.

    As gfal2's ``resolve_dns_helper``: an address is picked at random and
    reverse-resolved; any failure leaves the URL as it was.
    """
    parsed = parse(url)
    host = parsed.host
    try:
        found = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        address = random.choice(found)[4][0]
        name = socket.gethostbyaddr(str(address))[0]
    except (OSError, UnicodeError):
        log.warning("Could not resolve DNS alias: %s", host)
        return url
    log.info("%s: %s => %s", what, host, name)
    userinfo, at, _ = parsed.netloc.rpartition("@")
    port = _explicit_port(parsed)
    netloc = f"{userinfo}{at}{name}" + (f":{port}" if port else "")
    return str(URL(parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


class _GridFTPBase(Plugin):
    """Sessions and the pieces every GridFTP operation shares; see the module docstring."""

    def __init__(self, context: Any) -> None:
        """An empty pool for ``context`` (a :class:`~xgfalclient.context.Gfal2Context`)."""
        super().__init__(context)
        #: Guards :attr:`_idle` and :attr:`_credentials`; never held over I/O.
        self._lock = threading.Lock()
        #: Idle sessions by :attr:`_Profile.key`, most recently returned last.
        self._idle: dict[tuple[object, ...], list[Control]] = {}
        #: Parsed credentials by ``(cert, key, cert mtime)``.
        self._credentials: dict[tuple[object, ...], Credential] = {}

    # -- sessions --------------------------------------------------------------------

    def close(self) -> None:
        """``QUIT`` and close every idle session (the context is being freed).

        Sessions lent out at the time are not touched; they are closed or
        pooled when given back, as usual.
        """
        with self._lock:
            idle, self._idle = self._idle, {}
        for controls in idle.values():
            for control in controls:
                control.close()

    def _credential(self, cert: str, key: str) -> Credential:
        """The X.509 credential in ``cert``/``key``, parsed once per file version.

        Needed for delegation and for the user's identity under ``DCAU A``.
        Keyed by the certificate's mtime so a renewed proxy is picked up. The
        lock is released while parsing: two threads may parse the same file
        once each, which is harmless. ``EACCES`` if it cannot be read or
        parsed.
        """
        try:
            stamp = (cert, key, os.stat(cert).st_mtime)
            with self._lock:
                found = self._credentials.get(stamp)
            if found is None:
                found = load_credential(cert, key)
                with self._lock:
                    self._credentials[stamp] = found
        except (OSError, DERError, ValueError) as exc:
            raise GError(
                f"Could not load the X.509 credential {cert}: {exc}", errno.EACCES
            ) from exc
        return found

    def _profile(self, url: URL) -> _Profile:
        """Work out how to reach ``url``: credential, TLS, login and data security.

        ``gsiftp://`` needs an X.509 credential (``EACCES`` without one, in
        globus's words) and logs in as ``:globus-mapping:``; ``DCAU`` or
        ``ENCRYPTION`` turn on ``DCAU A``, with the identity taken from the
        first non-proxy certificate in the chain (the person, not the
        proxy). ``ftp://`` takes the URL's userinfo, else the context's
        ``USER``/``PASSWD`` credentials, else ``[FTP] USER``/``PASSWORD``,
        else anonymous - gfal2's order.
        """
        _check_url(url)
        text = str(url)
        timeout = float(self.option_timeout())
        if url.scheme == "gsiftp":
            x509 = self.context.x509(text)
            if x509 is None:
                raise GError(
                    "globus_gsi_gssapi: Error with GSI credential: no proxy or certificate found",
                    errno.EACCES,
                )
            tls = self.context.ssl_context(text, group=GROUP, check_hostname=False)
            credential = self._credential(x509.cert, x509.key)
            security = None
            encrypt = self.options.boolean(GROUP, "ENCRYPTION", False)
            if self.options.boolean(GROUP, "DCAU", False) or encrypt:
                initiator, acceptor = data_contexts(x509.cert, x509.key, self.context.ca_path())
                person = next((c for c in credential.chain if not c.is_proxy), credential.chain[-1])
                security = DataSecurity(initiator, acceptor, person.subject.rdns, encrypt)
            delegate = credential if self.options.boolean(GROUP, "DELEGATION", True) else None
            return _Profile(
                key=(
                    "gsiftp",
                    url.host,
                    url.port,
                    x509.cert,
                    x509.key,
                    security is not None,
                    encrypt,
                    delegate is not None,
                ),
                host=url.host,
                port=url.port,
                tls=tls,
                delegate=delegate,
                user=":globus-mapping:",
                password="dummy",
                security=security,
                timeout=timeout,
            )
        user, _, password = url.userinfo.partition(":")
        if not user:
            # gfal2's gfal_gridftp_get_credentials: the credential, else [FTP].
            user = self.context.credentials.get("USER", text)[0] or self.options.string(
                "FTP", "USER", "anonymous"
            )
            password = self.context.credentials.get("PASSWD", text)[0] or self.options.string(
                "FTP", "PASSWORD", "anonymous"
            )
        return _Profile(
            key=("ftp", url.host, url.port, user, password),
            host=url.host,
            port=url.port,
            user=user,
            password=password,
            timeout=timeout,
        )

    def _client_info(self, scheme: str) -> str:
        """``SITE CLIENTINFO``'s argument, as globus writes gfal2's clientinfo."""
        name, version = self.context.get_user_agent()
        if name:
            application, release = name, f"{version} (gfal2 {GFAL2_VERSION})"
        else:
            application, release = "gfal2", GFAL2_VERSION
        extra = self.context.client_info_string()
        return f'scheme={scheme};appname="{application}";appver="{release}";{extra}'

    def _connect(self, profile: _Profile) -> Control:
        """A new, logged-in session for ``profile``, set up as gfal2 sets one up.

        The sequence is gfal2's: greeting, ``AUTH GSSAPI``/``ADAT`` (GSI),
        ``USER``/``PASS``, ``FEAT``, ``SITE CLIENTINFO`` (a refusal is
        fine: not every server knows it), ``TYPE I``, then for GSI ``DCAU``
        and, when encrypting, ``PBSZ``/``PROT P`` (RFC 2228 §3 requires
        ``PBSZ`` before ``PROT``). Any failure
        - including ``KeyboardInterrupt`` - closes the half-made session.
        """
        control = Control(profile.host, profile.port, timeout=profile.timeout)
        try:
            control.connect()
            if profile.tls is not None:
                control.authenticate(profile.tls, profile.delegate)
            control.login(profile.user, profile.password)
            scheme = "ftp" if profile.tls is None else "gsiftp"
            control.command(f"SITE CLIENTINFO {self._client_info(scheme)}", ok=(2, 4, 5))
            control.setting("TYPE", "I")
            if profile.tls is not None:
                control.setting("DCAU", "N" if profile.security is None else "A")
                if profile.security is not None and profile.security.private:
                    control.setting("PBSZ", "1048576")
                    control.setting("PROT", "P")
        except BaseException:
            control.broken = True
            control.close()
            raise
        return control

    @contextlib.contextmanager
    def _session(self, url: URL) -> Iterator[_Session]:
        """Borrow a session to ``url``'s server for the ``with`` block.

        An idle session with the same profile key is reused if still
        healthy (stale ones found on the way are closed); otherwise a new
        one is connected - outside the lock, so a slow server does not block
        other threads. For the block's duration the session's
        :meth:`_Session.abort` is registered with the context, so
        ``cancel()`` can break a blocked read. On exit the session goes back
        to the pool or is closed (:meth:`_release`), whatever the outcome.
        """
        profile = self._profile(url)
        control = None
        with self._lock:
            idle = self._idle.get(profile.key, [])
            while idle and control is None:
                candidate = idle.pop()
                if candidate.healthy():
                    control = candidate
                else:
                    candidate.close()
        if control is None:
            control = self._connect(profile)
        session = _Session(control, profile)
        token = 0
        try:
            token = self.context.register_abort(session.abort)
            yield session
        finally:
            self.context.unregister_abort(token)
            self._release(profile, control)

    def _release(self, profile: _Profile, control: Control) -> None:
        """Pool ``control`` if ``SESSION_REUSE`` is on and it is still in step; else close it."""
        if self.options.boolean(GROUP, "SESSION_REUSE", True) and control.healthy():
            with self._lock:
                self._idle.setdefault(profile.key, []).append(control)
        else:
            control.close()

    # -- shared pieces -----------------------------------------------------------------

    def _stat_facts(self, control: Control, path: str) -> tuple[Stat, bool]:
        """The stat of ``path``, and whether the server gave its permissions.

        ``MLST`` (RFC 3659 §7) when the server advertises it: the facts are
        on the one continuation line that starts with a space. Without it,
        gfal2's fallback: ``SIZE`` (RFC 3659 §4) for a file, else ``CWD`` to
        tell a directory; the modes are then made up (``0644``/``0755``) and
        reported as known. When both fail, the ``SIZE`` error is the one
        raised, as it names the path's real problem. ``EPROTO`` for an
        ``MLST`` reply with no facts line.
        """
        if control.supports("MLST"):
            reply = control.command(f"MLST {path}")
            for line in reply.lines[1:]:
                if line.startswith(" "):
                    facts, _ = parse_facts(line[1:])
                    return stat_from_facts(facts), "unix.mode" in facts
            raise GError(f"[{path}]: Bad MLST response", errno.EPROTO)
        try:
            size = int(control.command(f"SIZE {path}").text.split()[0])
        except GError as exc:
            try:
                control.command(f"CWD {path}")
            except GError:
                raise exc from None
            return Stat(st_mode=_stat.S_IFDIR | 0o755, st_nlink=1), True
        return Stat(st_mode=_stat.S_IFREG | 0o644, st_size=size, st_nlink=1), True

    def _stat(self, control: Control, path: str) -> Stat:
        """:meth:`_stat_facts` without the "permissions known" flag."""
        return self._stat_facts(control, path)[0]

    def _data_options(self) -> ChannelOptions:
        """How this context's data channels open; read per operation, so option changes apply."""
        return ChannelOptions(
            ipv6=self.options.boolean(GROUP, "IPV6", False),
            spas=self.options.boolean(GROUP, "SPAS", False),
            delayed=self.options.boolean(GROUP, "DELAY_PASSV", True),
        )

    def _getput(self, *controls: Control) -> bool:
        """GridFTP v2 ``GET``/``PUT``: ``GRIDFTP_V2`` and servers advertising ``GETPUT``."""
        wanted = self.options.boolean(GROUP, "GRIDFTP_V2", True)
        return wanted and all(control.supports("GETPUT") for control in controls)

    def _buffer_size(self) -> int:
        """Bytes per read or write of this client's data movers (and per ``MODE E`` block).

        ``[GRIDFTP PLUGIN] BLOCK_SIZE`` when set (see the plugin docstring
        for how that differs from gfal2), else ``[CORE] COPY_BUFFERSIZE``
        with a 64 KiB floor so a tiny setting cannot make blocks all header.
        """
        block = self.options.integer(GROUP, "BLOCK_SIZE", 0)
        if block > 0:
            return int(block)
        return max(65536, int(self.options.integer("CORE", "COPY_BUFFERSIZE", 4194304)))

    def _fetch(self, session: _Session, command: str, kind: str = "I") -> bytes:
        """Run ``command`` over a ``MODE S`` data channel and collect what it sends.

        gfal2 lists names in ``TYPE A``; everything else moves in ``TYPE I``.
        The whole answer is held in memory, so this is for listings, ``ERET``
        partial reads and the like - never for file copies. One connection,
        passive, with the session's data security and timeout; failures
        propagate as :class:`~.data.DataTransfer` raises them.
        """
        control = session.control
        control.setting("TYPE", kind)
        control.setting("MODE", "S")
        chunks = bytearray()

        def worker(conn: DataConn, index: int) -> None:
            """Append the stream to ``chunks``; only one thread, so no lock."""
            recv_stream(conn, lambda view, _: chunks.extend(view), 65536, lambda n: None)

        DataTransfer(
            control,
            streams=1,
            worker=worker,
            check=lambda: None,
            setup=ConnSetup(session.profile.security, session.profile.timeout),
        ).run(command, self._data_options())
        return bytes(chunks)

    def _exists(self, url: str) -> bool:
        """gfal2's ``exists``: a stat, where only ``ENOENT`` means no."""
        try:
            self.stat(url)
        except GError as exc:
            if exc.code != errno.ENOENT:
                raise
            return False
        return True
