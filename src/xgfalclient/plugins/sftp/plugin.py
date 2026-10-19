"""The ``sftp://`` plugin: an ordinary SFTP file-transfer client, in Python.

This is the gfal2 ``sftp`` plugin (what ``gfal2-plugin-sftp`` gives through
libssh2) reimplemented on the standard library. It authenticates only with
the user's own configured credentials, to the servers the user names, exactly
like the ``sftp`` command.

**Three transport tiers**, chosen per connection (``[SFTP PLUGIN] TRANSPORT``
overrides: ``auto``, ``openssh``, ``python``, ``paramiko``):

#. **openssh** - the system ``ssh`` running ``sftp`` over its pipes
   (:mod:`.openssh`). Everything hard (host keys, the agent, Kerberos,
   ``~/.ssh/config``, C-speed ciphers) is OpenSSH's. It runs ``BatchMode=yes``
   and **never receives a password** - a password cannot be handed to an
   ``ssh`` subprocess safely - so a connection that must use a password is
   never given to this tier.
#. **paramiko** - when paramiko 3.4 or later (the first with strict KEX, the
   Terrapin fix) is installed: ``pip install xgfalclient[sftp]``. It is an
   optional extra, never a base dependency.
#. **python** - this package's own SSH-2 client (:mod:`.ssh`), which does
   :rfc:`4252` password authentication itself, the secret never leaving the
   process. It is the last resort, and the reason a base install (no
   paramiko, no ``ssh`` binary, or a password) still reaches an SFTP server
   as gfal2's libssh2 plugin does; the in-process test server is built on
   the same code.

``auto`` takes the first that can serve the connection: OpenSSH when there is
an ``ssh`` binary and no password, then paramiko, then the python tier. A
password always skips OpenSSH.

**Deliberate differences from gfal2 2.23.5**, each because gfal2's behaviour
is a bug or a missing feature, are noted at the operations below: real
``errno`` values instead of raw SFTP status codes; a real ``lstat``;
``posix-rename`` (an overwriting rename); ``.`` and ``..`` left out of
listings; ``ETIMEDOUT`` on a stall; the credential store's ``USER``/``PASSWD``
honoured; ``StrictHostKeyChecking=accept-new`` by default (gfal2 checks no
host key at all); and an optional checksum computed by reading the file when
the server has no ``check-file`` extension (any algorithm
:func:`xgfalclient.checksum.new` knows - ADLER32, CRC32 in decimal, MD5, the
SHAs - and ``EPROTONOSUPPORT``, gfal2's answer, for the rest). Where gfal2
patches the raw status itself, the answers are gfal2's: ``rmdir`` says
``ENOTEMPTY`` or ``ENOTDIR``, as it does, and ``unlink`` of a directory says
``EISDIR`` (gfal2 leaks 4). As in gfal2, ``access`` is ``EPROTONOSUPPORT``
(there is none, and the core does not fall back to ``stat``) and only a
lower-case ``sftp://`` is claimed. The default user is ``getpass``'s (the
login environment first), where gfal2 asks ``getpwuid``. Error messages
name the operation, the URL and the reason; gfal2's say only "SFTP Protocol
Error", "Could not resolve host" or "Could not connect" (the codes agree).

**Sessions are pooled.** An SFTP session costs a TCP connect, an SSH key
exchange and user authentication - or a whole ``ssh`` process - so each one
is kept, after the operation that opened it, in a per-endpoint idle list
and reused by the next operation on the same tier, user, host, port and
key. A session is checked out to one operation, or one open file, at a time,
and pooled again only while :attr:`SFTPClient.alive`; a session that failed
(or was aborted by ``cancel()``) is closed instead. The pool is bounded, as
the xrootd and dcap plugins' are: at most ``MAX_IDLE`` idle sessions per
endpoint (the most recently returned are kept, the older ones closed) and
none idle for longer than ``MAX_IDLE_SECONDS`` - each ``ssh`` process and
socket held for nothing is a cost on both ends, and the longer a session has
sat idle the likelier a firewall or the server's own idle timeout has cut
it. Concurrency itself is not capped: as many sessions are opened as there
are concurrent operations.
:meth:`SFTPPlugin.close` closes the idle ones.

**Errors.** A refusal from the server is a :class:`~.protocol.StatusError`
inside the client and becomes a :class:`GError` here, with the errno
:func:`~.protocol.errno_for_status` gives (or a closer one, see ``rmdir``)
and a message naming the operation and URL. Failures of the session itself
already are :class:`GError` (``ECONNRESET``, ``ETIMEDOUT``, ``EPROTO``,
``EACCES`` for authentication or host keys) and pass through untouched.

**Options** (``[SFTP PLUGIN]``): ``USER``, ``PASSWORD``, ``PRIVKEY`` (default
``~/.ssh/id_rsa``), ``PASSPHRASE``, ``KNOWN_HOSTS``,
``STRICT_HOST_KEY_CHECKING`` (``accept-new``), ``SSH_OPTIONS`` (extra ``-o``
settings for the openssh tier, which take precedence over the plugin's own
defaults), ``SSH_COMMAND``, ``TRANSPORT``, ``PIPELINE_DEPTH`` (64 requests in
flight), ``CHECKSUM_BY_READ`` (true), ``MAX_IDLE`` (4 pooled sessions per
endpoint; 0 disables pooling), ``MAX_IDLE_SECONDS`` (60; 0 or less: no
expiry) and the group's timeout.

**Module map.** This module resolves URLs and options, pools sessions and
maps errors; :mod:`.client` speaks SFTP over any stream; :mod:`.protocol` is
the v3 encoding; :mod:`.endpoint` is the connection record; :mod:`.openssh`,
:mod:`.paramiko_tier` and :mod:`.ssh` are the three transports, each
imported only when chosen, so loading the plugin stays cheap.
"""

from __future__ import annotations

import contextlib
import errno
import getpass
import os
import re
import stat as _stat
import threading
import time
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from ... import checksum
from ...crypto.sshkeys import KeyError_, PassphraseRequired, PrivateKey, load_private
from ...errors import GError, not_supported_url
from ...plugin import (
    O_ACCMODE_MASK,
    O_APPEND,
    O_CREAT,
    O_EXCL,
    O_RDWR,
    O_TRUNC,
    O_WRONLY,
    Plugin,
    PluginFile,
)
from ...types import Stat
from ...url import URL, parse, scheme_of
from . import protocol as fx
from .client import SFTPClient, StreamOptions, WriteBehind
from .endpoint import Endpoint
from .protocol import Attrs, StatusError

if TYPE_CHECKING:
    from ...transfer import Transfer

__all__ = ["SFTPPlugin"]

GROUP = "SFTP PLUGIN"

#: Default ``[SFTP PLUGIN] MAX_IDLE``: idle sessions kept per endpoint (the
#: xrootd and dcap plugins keep 4 too).
MAX_IDLE = 4
#: Default ``[SFTP PLUGIN] MAX_IDLE_SECONDS``: how long an idle session is kept.
MAX_IDLE_SECONDS = 60

#: A pooled session and the :func:`time.monotonic` time it went idle.
_Idle = tuple[float, SFTPClient]


def _sftp_error(exc: StatusError, path: str, op: str) -> GError:
    """A :class:`GError` with a *real* errno for an SFTP status (gfal2 leaks the raw code)."""
    return GError(f"{op} {path}: {exc.message}", exc.errno)


def _patched(exc: StatusError, path: str, op: str, code: int) -> GError:
    """:func:`_sftp_error`, with the errno a closer look found and its words."""
    if code == exc.errno:
        return _sftp_error(exc, path, op)
    return GError(f"{op} {path}: {os.strerror(code)}", code)


class SFTPPlugin(Plugin):
    """gfal2's ``sftp://`` plugin, reimplemented on the standard library.

    One instance per :class:`~xgfalclient.Gfal2Context`, used from any
    number of threads: the only shared state is the idle-session pool,
    guarded by ``_lock``, and every session is used by one operation at a
    time. ``priority`` 550 sits between gridftp and file; as only
    ``sftp://`` is claimed, the order hardly matters.
    """

    name = "sftp"
    schemes = ("sftp",)
    option_group = GROUP
    priority = 550
    event_domain = "SFTP"

    def __init__(self, context: Any) -> None:
        """Start with an empty pool; nothing connects until the first operation."""
        super().__init__(context)
        self._lock = threading.Lock()
        # Pool key (see _pool_key) -> (idle since, session), most recently returned last.
        self._idle: dict[tuple[object, ...], list[_Idle]] = {}

    def close(self) -> None:
        """Close every idle session (the context is being freed).

        Sessions checked out at the time are not touched: their operations
        or open files return them later, into the now-empty pool.
        """
        with self._lock:
            idle, self._idle = self._idle, {}
        for entries in idle.values():
            for _since, client in entries:
                client.close()

    def handles(self, url: str, operation: str) -> bool:
        """gfal2 matches ``sftp:`` case-sensitively: ``SFTP://`` is nobody's (93)."""
        return url.startswith("sftp://")

    # -- endpoint resolution -----------------------------------------------------

    def _endpoint(self, url: URL) -> Endpoint:
        """Resolve URL, credential store and options into where and as whom to connect.

        Each credential takes the first that is set: the URL's userinfo,
        then the context's credential store (``USER``/``PASSWD`` for the
        longest matching URL prefix, as gfal2's ``gfal2_cred_set`` keys them),
        then ``[SFTP PLUGIN] USER``/``PASSWORD``; the user finally falls back
        to :func:`getpass.getuser`. Nothing is read from disk here - the key
        file is only named, and loaded by the tier that needs it.
        """
        text = str(url)
        user, _, url_password = url.userinfo.partition(":")
        user = (
            user
            or self.context.credentials.get("USER", text)[0]
            or self.options.string(GROUP, "USER", "")
            or getpass.getuser()
        )
        password = (
            url_password
            or self.context.credentials.get("PASSWD", text)[0]
            or self.options.string(GROUP, "PASSWORD", "")
        )
        default_key = os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa")
        key_file = self.options.string(GROUP, "PRIVKEY", default_key)
        passphrase = self.options.string(GROUP, "PASSPHRASE", "")
        known_hosts = self.options.string(GROUP, "KNOWN_HOSTS", "")
        strict = self.options.string(GROUP, "STRICT_HOST_KEY_CHECKING", "accept-new")
        return Endpoint(
            host=url.host,
            port=url.port or 22,
            user=user,
            password=password,
            key_file=key_file,
            passphrase=passphrase,
            timeout=self.option_timeout(),
            known_hosts=known_hosts,
            strict_host_keys=strict,
            ssh_options=tuple(self.options.string_list(GROUP, "SSH_OPTIONS", [])),
            # Only a port written in the URL is forced on ``ssh -p``; otherwise
            # ~/.ssh/config's Port (or 22) applies, as for the ``sftp`` command.
            explicit_port=bool(url.port and ":" in url.netloc.rpartition("@")[2]),
        )

    def _tier(self, endpoint: Endpoint) -> str:
        """The transport tier for ``endpoint``: ``TRANSPORT``, or the ``auto`` choice.

        A forced tier is taken as given, even when it cannot work (OpenSSH
        with only a password fails authentication; a missing paramiko fails
        to import) - the error then says why. ``auto`` is described in the
        module docstring; probing for paramiko reads its metadata, never
        importing it.
        """
        choice = self.options.string(GROUP, "TRANSPORT", "auto").strip().lower() or "auto"
        if choice in ("openssh", "python", "paramiko"):
            return choice
        # auto: a password can only be used by an in-process transport.
        if endpoint.password:
            return "paramiko" if _has_paramiko() else "python"
        from .openssh import find_ssh

        if find_ssh(self.options.string(GROUP, "SSH_COMMAND", "")) is not None:
            return "openssh"
        return "paramiko" if _has_paramiko() else "python"

    def _pool_key(self, tier: str, endpoint: Endpoint) -> tuple[object, ...]:
        """Which pooled sessions may serve ``endpoint``: same tier, identity and server.

        The password and passphrase are left out: an idle session is already
        authenticated as ``user``, so a different password for the same user
        reuses it rather than proving itself again.
        """
        return (tier, endpoint.user, endpoint.host, endpoint.port, endpoint.key_file)

    # -- sessions ----------------------------------------------------------------

    def _new_client(self, tier: str, endpoint: Endpoint) -> SFTPClient:
        """Connect a fresh session: transport, then the SFTP ``INIT``/``VERSION``.

        A failed handshake closes the transport (ending the ``ssh`` process,
        or the socket) before the error propagates; the caller never sees a
        half-made client.
        """
        stream = self._connect_stream(tier, endpoint)
        client = SFTPClient(stream)
        try:
            client.handshake()
        except GError:
            client.close()
            raise
        return client

    def _connect_stream(self, tier: str, endpoint: Endpoint) -> Any:
        """Open the tier's transport, authenticated and running the ``sftp`` subsystem.

        Each tier's module is imported here, on first use, so a process that
        never touches ``sftp://`` (or uses only OpenSSH) never loads the SSH-2
        implementation or paramiko. Failures are the tier's
        :class:`GError`: ``ENOENT`` for no ``ssh`` binary; ``EACCES`` for a key
        that cannot be loaded, a refused login or a host key that fails
        verification; ``ECONNREFUSED`` or ``ETIMEDOUT`` from the network
        (and ``EREMOTE``, as in gfal2, when ``ssh`` cannot resolve the host).
        """
        if tier == "openssh":
            from .openssh import connect as openssh_connect
            from .openssh import find_ssh

            ssh_argv = find_ssh(self.options.string(GROUP, "SSH_COMMAND", ""))
            if ssh_argv is None:
                raise GError("No ssh binary was found for the openssh transport", errno.ENOENT)
            return openssh_connect(ssh_argv, endpoint)
        if tier == "paramiko":
            from .paramiko_tier import connect as paramiko_connect

            return paramiko_connect(endpoint, self._load_keys(endpoint))
        from . import ssh

        auth = ssh.Auth(
            username=endpoint.user, keys=self._load_keys(endpoint), password=endpoint.password
        )
        return ssh.connect(endpoint, auth)

    def _load_keys(self, endpoint: Endpoint) -> tuple[PrivateKey, ...]:
        """Parse the configured private key for the in-process transports.

        A key file that does not exist is simply no key - the password, if
        any, is then the only credential - since the default
        ``~/.ssh/id_rsa`` is often absent. One that exists but cannot be
        used is ``EACCES``, naming ``PASSPHRASE`` when that is what is
        missing, rather than a silent fall-through to a failed login.
        """
        if not endpoint.key_file or not os.path.isfile(endpoint.key_file):
            return ()
        try:
            with open(endpoint.key_file, "rb") as handle:
                data = handle.read()
            passphrase = endpoint.passphrase or None
            return (load_private(data, passphrase),)
        except PassphraseRequired as exc:
            raise GError(
                f"The private key {endpoint.key_file} is encrypted; set [SFTP PLUGIN] PASSPHRASE",
                errno.EACCES,
            ) from exc
        except (KeyError_, OSError) as exc:
            raise GError(
                f"Could not load the private key {endpoint.key_file}: {exc}", errno.EACCES
            ) from exc

    @contextlib.contextmanager
    def _session(self, url: str) -> Iterator[SFTPClient]:
        """Borrow a session for ``url`` for the ``with`` block, then give it back.

        The way every namespace operation and copy reaches the server. The
        session is checked out of the pool (or connected), the context's
        ``cancel()`` is wired to abort it for the block's duration, and it is
        returned - or closed, if the block killed it - however the block ends.
        """
        parsed = parse(url)
        endpoint = self._endpoint(parsed)
        tier = self._tier(endpoint)
        key = self._pool_key(tier, endpoint)
        client = self._checkout(tier, endpoint, key)
        try:
            # A cancel() breaks the session under a call blocked on a silent
            # server, rather than waiting out its timeout.
            with self.context.abort_on_cancel(client.abort):
                yield client
        finally:
            # Pooled again only while still alive: a hard failure has killed it.
            self._return(key, client)

    @staticmethod
    def _path(url: URL) -> bytes:
        """The URL's path as wire bytes; ``/`` for none, undecodable bytes round-tripped."""
        return (url.path or "/").encode("utf-8", "surrogateescape")

    # -- namespace ---------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        """``SSH_FXP_STAT`` (follows links); ``ENOENT``/``EACCES`` from the status."""
        with self._session(url) as client:
            try:
                return client.stat(self._path(parse(url))).to_stat()
            except StatusError as exc:
                raise _sftp_error(exc, url, "Could not stat") from exc

    def lstat(self, url: str) -> Stat:
        """``SSH_FXP_LSTAT``: a symlink is described, not followed."""
        # A real lstat: gfal2 aliases lstat to stat and never sees a symlink.
        with self._session(url) as client:
            try:
                return client.lstat(self._path(parse(url))).to_stat()
            except StatusError as exc:
                raise _sftp_error(exc, url, "Could not stat") from exc

    def chmod(self, url: str, mode: int) -> None:
        """``SSH_FXP_SETSTAT`` with only the permissions set."""
        with self._session(url) as client:
            try:
                client.setstat(self._path(parse(url)), Attrs(permissions=mode))
            except StatusError as exc:
                raise _sftp_error(exc, url, "Could not chmod") from exc

    def mkdir(self, url: str, mode: int) -> None:
        """``SSH_FXP_MKDIR`` with ``mode``; ``EEXIST`` when something is already there."""
        path = self._path(parse(url))
        with self._session(url) as client:
            try:
                client.mkdir(path, Attrs(permissions=mode))
            except StatusError as exc:
                # A server reports "already exists" as a bare FAILURE; turn it
                # into EEXIST so mkdir_rec (which relies on it) works.
                if exc.code == fx.FX_FAILURE and self._exists(client, path):
                    raise GError(f"Could not mkdir {url}: it already exists", errno.EEXIST) from exc
                raise _sftp_error(exc, url, "Could not mkdir") from exc

    @staticmethod
    def _exists(client: SFTPClient, path: bytes) -> bool:
        """Whether anything (a dangling symlink included) is at ``path``: an ``LSTAT``."""
        try:
            client.lstat(path)
        except StatusError:
            return False
        return True

    def rmdir(self, url: str) -> None:
        """gfal2 patches the codes an SFTP v3 server answers with; so does this.

        OpenSSH says ``FAILURE`` for a directory that is not empty and
        ``NO_SUCH_FILE`` for a file (``ENOTDIR`` travels as that); a look
        at what is there says which errno the status stands for.
        """
        path = self._path(parse(url))
        with self._session(url) as client:
            try:
                client.rmdir(path)
            except StatusError as exc:
                code = exc.errno
                if exc.code in (fx.FX_FAILURE, fx.FX_NO_SUCH_FILE):
                    kind = self._kind(client, path)
                    if kind is False:
                        code = errno.ENOTDIR
                    elif kind and exc.code == fx.FX_FAILURE:
                        code = errno.ENOTEMPTY
                raise _patched(exc, url, "Could not rmdir", code) from exc

    def unlink(self, url: str) -> None:
        """A directory is ``EISDIR``, where OpenSSH says ``FAILURE`` (and gfal2 leaks 4)."""
        path = self._path(parse(url))
        with self._session(url) as client:
            try:
                client.remove(path)
            except StatusError as exc:
                code = exc.errno
                if exc.code == fx.FX_FAILURE and self._kind(client, path):
                    code = errno.EISDIR
                raise _patched(exc, url, "Could not unlink", code) from exc

    @staticmethod
    def _kind(client: SFTPClient, path: bytes) -> bool | None:
        """``True`` for a directory, ``False`` for anything else, ``None`` if nothing is there."""
        try:
            return _stat.S_ISDIR(client.lstat(path).to_stat().st_mode)
        except StatusError:
            return None

    def access(self, url: str, mode: int) -> None:
        """gfal2's sftp plugin has no ``access``, and its core no fallback: ``EPROTONOSUPPORT``."""
        raise not_supported_url(url)

    def rename(self, old: str, new: str) -> None:
        """Rename within one server; the session is ``old``'s, ``new`` supplies only a path."""
        # posix-rename overwrites the target, unlike gfal2's plain v3 rename.
        with self._session(old) as client:
            try:
                client.rename(self._path(parse(old)), self._path(parse(new)))
            except StatusError as exc:
                raise _sftp_error(exc, old, "Could not rename") from exc

    def symlink(self, target: str, link: str) -> None:
        """Make ``link`` point at ``target``.

        An ``sftp://`` target is stored as its path (a link holds a path, not
        a URL); anything else - a relative path, typically - is stored as
        written, so relative links stay relative.
        """
        target_path = parse(target).path if scheme_of(target) == "sftp" else target
        with self._session(link) as client:
            try:
                client.symlink(
                    target_path.encode("utf-8", "surrogateescape"), self._path(parse(link))
                )
            except StatusError as exc:
                raise _sftp_error(exc, link, "Could not symlink") from exc

    def readlink(self, url: str) -> str:
        """``SSH_FXP_READLINK``: the link's target as stored (a path, not a URL)."""
        with self._session(url) as client:
            try:
                return client.readlink(self._path(parse(url)))
            except StatusError as exc:
                raise _sftp_error(exc, url, "Could not readlink") from exc

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        """Every entry with its ``stat``, read in full before the session goes back.

        The listing is collected eagerly so the session is returned to the
        pool at once rather than held for as long as the caller iterates.
        SFTP's ``READDIR`` carries each entry's ``ATTRS``, so every entry
        has its :class:`Stat` at no extra round trip.
        """
        path = self._path(parse(url))
        with self._session(url) as client:
            try:
                entries = list(client.listdir(path))
            except StatusError as exc:
                raise _sftp_error(exc, url, "Could not open directory") from exc
        # "." and ".." are omitted, unlike gfal2 (and OpenSSH's sftp-server).
        return iter(
            [(name, attrs.to_stat()) for name, _long, attrs in entries if name not in (".", "..")]
        )

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        """A checksum from ``check-file-name``, or, failing that, by reading the file.

        gfal2 answers ``EPROTONOSUPPORT``; computing one by reading is the
        deliberate difference (``[SFTP PLUGIN] CHECKSUM_BY_READ=false`` to
        refuse instead, matching gfal2).
        """
        name = algorithm.lower()
        path = self._path(parse(url))
        with self._session(url) as client:
            if "check-file-name" in client.extensions:
                with contextlib.suppress(StatusError):
                    _used, digest = client.check_file(path, name, offset, length)
                    return digest.hex()
            if not self.options.boolean(GROUP, "CHECKSUM_BY_READ", True):
                raise GError(
                    f"The server has no check-file extension for {url}", errno.EPROTONOSUPPORT
                )
            return self._checksum_by_read(client, url, name, offset, length)

    def _checksum_by_read(
        self, client: SFTPClient, url: str, name: str, offset: int, length: int
    ) -> str:
        """Hash ``length`` bytes from ``offset`` (``0``: to the end) by reading them.

        Plain sequential ``READ`` requests, one round trip each: a checksum
        is rarely on the hot path, and :func:`xgfalclient.checksum.new` is fed
        in order. ``EPROTONOSUPPORT`` for an algorithm it does not know, the
        mapped status for an open or read the server refuses.
        """
        path = self._path(parse(url))
        try:
            hasher = checksum.new(name)
        except ValueError as exc:
            # What gfal2 answers for every algorithm: it has no sftp checksum.
            raise not_supported_url(url) from exc
        try:
            handle = client.open(path, fx.FXF_READ)
        except StatusError as exc:
            raise _sftp_error(exc, path.decode(errors="replace"), "Could not open") from exc
        try:
            remaining = length or None
            position = offset
            chunk = client.max_read
            while remaining is None or remaining > 0:
                want = chunk if remaining is None else min(chunk, remaining)
                data = client.read(handle, position, want)
                if not data:
                    break
                hasher.update(data)
                position += len(data)
                if remaining is not None:
                    remaining -= len(data)
        finally:
            client.close_handle(handle, quiet=True)
        digest = hasher.hexdigest()
        # CRC32 in decimal, as gfal2's file plugin prints it.
        return str(int(digest, 16)) if checksum.normalise_name(name) == "crc32" else digest

    # -- file I/O ----------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        """Open a remote file; the returned file owns a pooled session until it is closed.

        Not :meth:`_session`: the session's lifetime is the file's, so it
        is checked out here and returned by the file's ``close``. POSIX
        ``flags`` become ``SSH_FXF_*`` (:func:`_pflags`); ``mode`` applies to
        a file ``O_CREAT`` creates. ``size`` (a hint some plugins use to
        pre-allocate) has no SFTP counterpart and is ignored. A write-only
        open gets :class:`_WriteFile` (pipelined, errors on ``close``); any
        open that reads gets :class:`_ReadWriteFile`, whose writes are
        acknowledged one by one so each error belongs to its own call.
        """
        parsed = parse(url)
        path = self._path(parsed)
        pflags = _pflags(flags)
        endpoint = self._endpoint(parsed)
        tier = self._tier(endpoint)
        key = self._pool_key(tier, endpoint)
        client = self._checkout(tier, endpoint, key)
        try:
            attrs = Attrs(permissions=mode) if flags & O_CREAT else None
            with self.context.abort_on_cancel(client.abort):
                handle = client.open(path, pflags, attrs)
        except StatusError as exc:
            self._return(key, client)
            raise GError(f"Failed opening remote file {url}: {exc.message}", exc.errno) from exc
        except GError:
            self._return(key, client)
            raise
        if flags & O_ACCMODE_MASK == O_WRONLY:
            return _WriteFile(self, key, client, handle, url)
        # A read-only handle's pwrite is refused by the server itself.
        return _ReadWriteFile(self, key, client, handle, url)

    def _checkout(self, tier: str, endpoint: Endpoint, key: tuple[object, ...]) -> SFTPClient:
        """An idle session for ``key`` (most recently used first), else a new one.

        Sessions idle past ``MAX_IDLE_SECONDS`` (for any endpoint) and dead
        ones found on the way are discarded, and closed once the lock is
        released: closing an ``ssh`` process can take a couple of seconds.
        Connecting also happens outside the lock, so a slow server does not
        hold up threads bound elsewhere. There is no cap on sessions in use
        per endpoint: as many are opened as there are concurrent operations.
        """
        found = None
        with self._lock:
            discard = self._expire_locked()
            idle = self._idle.get(key, [])
            while idle and found is None:
                _since, candidate = idle.pop()
                if candidate.alive:
                    found = candidate
                else:
                    discard.append(candidate)
        _close_all(discard)
        return found if found is not None else self._new_client(tier, endpoint)

    def _return(self, key: tuple[object, ...], client: SFTPClient) -> None:
        """Pool ``client`` again while it is alive and the pool has room; close it otherwise.

        The newly returned session joins the end of its list; when that
        makes more than ``MAX_IDLE`` the oldest go, since checkout takes the
        newest first and the oldest are the likeliest to have gone stale.
        """
        keep = max(0, int(self.options.integer(GROUP, "MAX_IDLE", MAX_IDLE)))
        if not client.alive or not keep:
            client.close()
            return
        with self._lock:
            discard = self._expire_locked()
            idle = self._idle.setdefault(key, [])
            idle.append((time.monotonic(), client))
            surplus = len(idle) - keep
            if surplus > 0:
                discard += [entry[1] for entry in idle[:surplus]]
                del idle[:surplus]
        _close_all(discard)

    def _expire_locked(self) -> list[SFTPClient]:
        """Take every session idle past ``MAX_IDLE_SECONDS`` out of the pool; called locked.

        Swept across all endpoints, so one no longer used is not held until
        :meth:`close`. The caller closes what is returned, after unlocking.
        """
        limit = int(self.options.integer(GROUP, "MAX_IDLE_SECONDS", MAX_IDLE_SECONDS))
        if limit <= 0:
            return []
        cutoff = time.monotonic() - limit
        expired: list[SFTPClient] = []
        for key, entries in list(self._idle.items()):
            # Each list is in return order, so the expired ones are a prefix.
            fresh = [entry for entry in entries if entry[0] >= cutoff]
            expired += [entry[1] for entry in entries if entry[0] < cutoff]
            if fresh:
                self._idle[key] = fresh
            else:
                del self._idle[key]
        return expired

    # -- copies ------------------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        """Claim ``file://`` <-> ``sftp://`` copies, which run pipelined in :meth:`copy`."""
        ends = (source.partition("://")[0], destination.partition("://")[0])
        # Claim only file<->sftp, where a direct pipelined copy beats the core
        # (which would go through a PluginFile). sftp<->sftp is left to the core.
        return ("sftp" in ends) and ("file" in ends)

    def copy(self, transfer: Transfer) -> None:
        """Upload or download one file; the core has done overwrite, parents and checksums.

        ``transfer.check`` is consulted between chunks, so a ``cancel()`` or
        the copy's timeout stops it promptly; a failed copy's partial
        destination is the core's to clean up.
        """
        if scheme_of(transfer.source) == "file":
            self._upload(transfer)
        else:
            self._download(transfer)

    def _download(self, transfer: Transfer) -> None:
        """``sftp://`` -> ``file://``: :meth:`SFTPClient.stream_read` into a local file.

        A ``STAT`` first refuses a directory (``EISDIR``) and gives the
        progress total. Each chunk is ``pwrite``-n at its own offset, so the
        local file needs no seeking, and counted towards progress as it is.
        The local file is created (or truncated) mode 0644 only after the
        remote one has opened, so a missing source leaves no empty file.
        """
        from ..file import local_path

        transfer.event("TRANSFER:TYPE", "streamed")
        parsed = parse(transfer.source)
        path = self._path(parsed)
        with self._session(transfer.source) as client:
            try:
                attrs = client.stat(path)
            except StatusError as exc:
                raise _sftp_error(exc, transfer.source, "Could not stat") from exc
            if attrs.is_dir:
                raise GError(f"{transfer.source} is a directory", errno.EISDIR)
            transfer.source_size = attrs.size
            try:
                handle = client.open(path, fx.FXF_READ)
            except StatusError as exc:
                raise _sftp_error(exc, transfer.source, "Could not open") from exc
            fd = os.open(
                local_path(transfer.destination), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644
            )
            try:

                def consume(offset: int, view: memoryview) -> None:
                    """Write one chunk where it belongs, before its buffer is reused."""
                    _pwrite_all(fd, view, offset)
                    transfer.add(len(view))

                total = client.stream_read(
                    handle,
                    0,
                    None,
                    consume,
                    StreamOptions(depth=self._depth(), check=transfer.check),
                )
            finally:
                os.close(fd)
                client.close_handle(handle, quiet=True)
        transfer.progress(total, force=True)

    def _upload(self, transfer: Transfer) -> None:
        """``file://`` -> ``sftp://``: local reads fed to a :class:`WriteBehind`.

        The local file is opened (and a directory refused, ``EISDIR``)
        before any connection is made. The remote file is opened
        ``WRITE|CREAT|TRUNC`` with no attributes, so the server's umask
        sets its mode. Reads are ``max_write`` sized so each becomes one
        ``WRITE``. Success means every write was acknowledged and, where the
        server offers ``fsync@openssh.com``, synced; the ``CLOSE`` after that
        is quiet, as it also runs as clean-up after a failure.
        """
        from ..file import local_path

        transfer.event("TRANSFER:TYPE", "streamed")
        parsed = parse(transfer.destination)
        path = self._path(parsed)
        try:
            fd = os.open(local_path(transfer.source), os.O_RDONLY)
        except OSError as exc:
            raise GError(
                f"Could not open source: {exc.strerror or exc}", exc.errno or errno.EIO
            ) from exc
        try:
            info = os.fstat(fd)
            if _stat.S_ISDIR(info.st_mode):
                raise GError(f"{transfer.source} is a directory", errno.EISDIR)
            transfer.source_size = info.st_size
            with self._session(transfer.destination) as client:
                try:
                    handle = client.open(path, fx.FXF_WRITE | fx.FXF_CREAT | fx.FXF_TRUNC, Attrs())
                except StatusError as exc:
                    raise _sftp_error(exc, transfer.destination, "Could not open") from exc
                writer = WriteBehind(client, handle, depth=self._depth())
                try:
                    offset = 0
                    chunk = client.max_write
                    while True:
                        data = os.read(fd, chunk)
                        if not data:
                            break
                        writer.write(offset, data)
                        offset += len(data)
                        transfer.add(len(data))
                        transfer.check()
                    writer.flush()
                    client.fsync(handle)
                finally:
                    client.close_handle(handle, quiet=True)
        finally:
            os.close(fd)
        transfer.progress(info.st_size, force=True)

    def _depth(self) -> int:
        """``[SFTP PLUGIN] PIPELINE_DEPTH``: requests kept in flight (at least 1)."""
        return max(1, int(self.options.integer(GROUP, "PIPELINE_DEPTH", 64)))


def _close_all(clients: list[SFTPClient]) -> None:
    """Close sessions taken out of the pool (never under the pool's lock)."""
    for client in clients:
        client.close()


def _pflags(flags: int) -> int:
    """Translate POSIX ``open`` flags into SFTP v3 ``SSH_FXP_OPEN`` flags.

    One to one: ``O_RDONLY``/``O_WRONLY``/``O_RDWR`` choose ``READ`` and
    ``WRITE``; ``O_CREAT``, ``O_TRUNC``, ``O_APPEND`` and ``O_EXCL`` map to
    their ``SSH_FXF_*`` namesakes. The draft gives ``EXCL`` meaning only
    with ``CREAT``, as POSIX does; it is passed through either way.
    """
    access = flags & O_ACCMODE_MASK
    if access == O_WRONLY:
        pflags = fx.FXF_WRITE
    elif access == O_RDWR:
        pflags = fx.FXF_READ | fx.FXF_WRITE
    else:
        pflags = fx.FXF_READ
    if flags & O_CREAT:
        pflags |= fx.FXF_CREAT
    if flags & O_TRUNC:
        pflags |= fx.FXF_TRUNC
    if flags & O_APPEND:
        pflags |= fx.FXF_APPEND
    if flags & O_EXCL:
        pflags |= fx.FXF_EXCL
    return pflags


def _pwrite_all(fd: int, view: memoryview, offset: int) -> None:
    """``os.pwrite`` all of ``view`` at ``offset``, looping over short writes.

    A write of 0 bytes would loop forever, so it is ``EIO`` instead; any
    other failure is the :class:`OSError` the core reports for the copy.
    """
    data = view
    while len(data):
        written = os.pwrite(fd, data, offset)
        if written <= 0:
            raise OSError(errno.EIO, "local pwrite made no progress")
        offset += written
        data = data[written:]


#: The oldest paramiko ``auto`` will use: 3.4 added strict KEX (CVE-2023-48795).
_PARAMIKO_MINIMUM = (3, 4)


def _has_paramiko() -> bool:
    """Is a paramiko that ``auto`` may choose installed?

    Found by its distribution metadata, without importing it (paramiko's
    import pulls in a good deal). A paramiko older than 3.4 - one that can be
    Terrapin-attacked - is passed over for the python tier, which does strict
    KEX itself; ``TRANSPORT=paramiko`` can still force it.
    """
    import importlib.metadata
    import importlib.util

    if importlib.util.find_spec("paramiko") is None:
        return False
    try:
        release = importlib.metadata.version("paramiko")
    except importlib.metadata.PackageNotFoundError:
        return False  # importable, but of unknown provenance and version
    match = re.match(r"(\d+)\.(\d+)", release)
    return match is not None and (int(match[1]), int(match[2])) >= _PARAMIKO_MINIMUM


class _RemoteFile(PluginFile):
    """Shared base: a remote handle borrowed from the plugin's session pool.

    Each call that waits on the server is registered with the context for
    its duration (:meth:`_io`), so ``cancel()`` breaks the session under a
    read or write blocked on a silent server. ``close`` is not: it is the
    clean-up a cancelled copy still does while the ``cancel()`` drains, and
    on a session that died it does nothing.
    """

    def __init__(
        self,
        plugin: SFTPPlugin,
        key: tuple[object, ...],
        client: SFTPClient,
        handle: bytes,
        url: str,
    ) -> None:
        """Take over ``client`` (checked out by :meth:`SFTPPlugin.open`) and its open ``handle``.

        ``key`` is the pool key the session goes back under on :meth:`close`.
        """
        super().__init__(url)
        self._plugin = plugin
        self._key = key
        self._client = client
        self._handle = handle
        self._size: int | None = None

    # The session is this file's alone between the plugin's open() and close():
    # it is checked out of the pool for it and returned by close().

    def _io(self) -> contextlib.AbstractContextManager[None]:
        """While the ``with`` block runs, the context's ``cancel()`` aborts the session."""
        return self._plugin.context.abort_on_cancel(self._client.abort)

    def size(self) -> int | None:
        """The remote size from ``SSH_FXP_FSTAT``, asked once and cached (for ``SEEK_END``).

        Not refreshed by later writes through this handle. A server that
        omits the size gives 0.
        """
        if self._size is None:
            try:
                with self._io():
                    self._size = self._client.fstat(self._handle).size or 0
            except StatusError as exc:
                raise _sftp_error(exc, self.url, "Could not stat") from exc
        return self._size

    def close(self) -> None:
        """``SSH_FXP_CLOSE`` the handle and return the session to the pool.

        Idempotent. The file counts as closed even if the server refuses
        the close (that is raised, mapped); the session goes back either way.
        """
        if self.closed:
            return
        self.closed = True
        try:
            # A session that has died - aborted by a cancel(), or lost - took
            # its handles with it; the failure that killed it was reported by
            # the call it broke, and closing has nothing left to close.
            if self._client.alive:
                self._client.close_handle(self._handle)
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not close") from exc
        finally:
            self._plugin._return(self._key, self._client)


class _ReadWriteFile(_RemoteFile):
    """A handle opened for reading (and possibly writing): positional and pipelined.

    Reads are positional; :meth:`readinto` pipelines one buffer's worth.
    Writes are synchronous - one ``WRITE`` acknowledged per call - so a
    read that follows reads what was written and an error belongs to the
    call that caused it. On a read-only handle the server refuses them.
    """

    def pread(self, offset: int, size: int) -> bytes:
        """One ``READ`` of up to ``size`` bytes at ``offset``; ``b""`` at the end.

        Possibly short without being at the end (the server's limit);
        :meth:`readinto` is the call that fills a buffer.
        """
        try:
            with self._io():
                return self._client.read(self._handle, offset, size)
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not read") from exc

    def readinto(self, buffer: Any) -> int:
        """Fill ``buffer`` from the cursor with pipelined reads; short only at EOF.

        The copy engine's fast path: up to ``64`` reads in flight, landing
        straight in ``buffer`` (:meth:`SFTPClient.read_into`), with no copies.
        """
        view = memoryview(buffer).cast("B")
        try:
            with self._io():
                got = self._client.read_into(self._handle, self.position, view)
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not read") from exc
        self.position += got
        return got

    def pwrite(self, data: Any, offset: int) -> int:
        """Write all of ``data`` at ``offset``, every piece acknowledged before returning.

        ``data`` is split into ``max_write`` pieces, pipelined up to
        ``PIPELINE_DEPTH`` deep (:class:`WriteBehind`), then flushed: a
        server is free to refuse - or, like some, to drop the session on -
        a ``WRITE`` longer than the length it announced in
        ``limits@openssh.com`` (32 KiB, the draft's minimum, without it).
        The first refusal is raised as ``Could not write``.
        """
        view = memoryview(data).cast("B")
        writer = WriteBehind(self._client, self._handle, depth=self._plugin._depth())
        try:
            with self._io():
                writer.write(offset, view)
                writer.flush()
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not write") from exc
        return len(view)


class _WriteFile(_RemoteFile):
    """A write-only handle with a pipelined write-behind; errors surface on ``close``.

    gfal2's contract for a written file: a write may succeed locally and
    fail later, and ``close`` is where the final verdict is given. Writes
    go out at once in ``max_write`` pieces with ``PIPELINE_DEPTH``
    acknowledgements outstanding (:class:`WriteBehind`).
    """

    def __init__(
        self,
        plugin: SFTPPlugin,
        key: tuple[object, ...],
        client: SFTPClient,
        handle: bytes,
        url: str,
    ) -> None:
        """Wrap the opened handle in a :class:`WriteBehind` sized by ``PIPELINE_DEPTH``."""
        super().__init__(plugin, key, client, handle, url)
        self._writer = WriteBehind(client, handle, depth=plugin._depth())

    def write(self, data: Any) -> int:
        """Queue ``data`` at the cursor and advance it; may raise an earlier write's error."""
        view = memoryview(data).cast("B")
        try:
            with self._io():
                self._writer.write(self.position, view)
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not write") from exc
        self.position += len(view)
        return len(view)

    def pwrite(self, data: Any, offset: int) -> int:
        """Queue ``data`` at ``offset``; the cursor is not moved."""
        view = memoryview(data).cast("B")
        try:
            with self._io():
                self._writer.write(offset, view)
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not write") from exc
        return len(view)

    def close(self) -> None:
        """Wait for every write's acknowledgement, then close: the verdict on the file.

        A refused write found here is raised as ``Could not write``; a broken
        session as its own :class:`GError`. Either way the file then counts
        as closed and the handle is still closed (:meth:`_abandon`), so a
        pooled session does not carry a leaked server handle for the rest
        of its life.
        """
        if self.closed:
            return
        try:
            with self._io():  # the last writes, not clean-up: a cancel() stops them
                self._writer.flush()
        except StatusError as exc:
            self._abandon()
            raise _sftp_error(exc, self.url, "Could not write") from exc
        except GError:
            self._abandon()
            raise
        super().close()

    def _abandon(self) -> None:
        """Clean up after a failed write: quiet ``CLOSE``, then the session goes back.

        Quiet, because the write's failure is the error to report. On a
        session that died there is nothing to close (it took its handles
        with it), and :meth:`SFTPPlugin._return` closes the session itself.
        """
        self.closed = True
        try:
            if self._client.alive:
                self._client.close_handle(self._handle, quiet=True)
        finally:
            self._plugin._return(self._key, self._client)
