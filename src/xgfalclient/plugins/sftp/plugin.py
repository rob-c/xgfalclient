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
#. **paramiko** - used only if importable; it is never a dependency.
#. **python** - this package's own SSH-2 client (:mod:`.ssh`), which does
   :rfc:`4252` password authentication itself, the secret never leaving the
   process. ``auto`` picks this (or paramiko) whenever a password is set.

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
"""

from __future__ import annotations

import contextlib
import errno
import getpass
import os
import stat as _stat
import struct
import threading
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, Optional

from ... import checksum
from ...crypto.sshkeys import KeyError_, PassphraseRequired, PrivateKey, load_private, string
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
from .client import SFTPClient, WriteBehind
from .endpoint import Endpoint
from .protocol import Attrs, StatusError

if TYPE_CHECKING:
    from ...transfer import Transfer

__all__ = ["SFTPPlugin"]

GROUP = "SFTP PLUGIN"


def _sftp_error(exc: StatusError, path: str, op: str) -> GError:
    """A :class:`GError` with a *real* errno for an SFTP status (gfal2 leaks the raw code)."""
    return GError(f"{op} {path}: {exc.message}", exc.errno)


def _patched(exc: StatusError, path: str, op: str, code: int) -> GError:
    """:func:`_sftp_error`, with the errno a closer look found and its words."""
    if code == exc.errno:
        return _sftp_error(exc, path, op)
    return GError(f"{op} {path}: {os.strerror(code)}", code)


class SFTPPlugin(Plugin):
    """gfal2's ``sftp://`` plugin, reimplemented on the standard library."""

    name = "sftp"
    schemes = ("sftp",)
    option_group = GROUP
    priority = 550
    event_domain = "SFTP"

    def __init__(self, context: Any) -> None:
        super().__init__(context)
        self._lock = threading.Lock()
        self._idle: dict[tuple[object, ...], list[SFTPClient]] = {}

    def close(self) -> None:
        with self._lock:
            idle, self._idle = self._idle, {}
        for clients in idle.values():
            for client in clients:
                client.close()

    def handles(self, url: str, operation: str) -> bool:
        """gfal2 matches ``sftp:`` case-sensitively: ``SFTP://`` is nobody's (93)."""
        return url.startswith("sftp://")

    # -- endpoint resolution -----------------------------------------------------

    def _endpoint(self, url: URL) -> Endpoint:
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
            explicit_port=bool(url.port and ":" in url.netloc.rpartition("@")[2]),
        )

    def _tier(self, endpoint: Endpoint) -> str:
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
        return (tier, endpoint.user, endpoint.host, endpoint.port, endpoint.key_file)

    # -- sessions ----------------------------------------------------------------

    def _new_client(self, tier: str, endpoint: Endpoint) -> SFTPClient:
        stream = self._connect_stream(tier, endpoint)
        client = SFTPClient(stream)
        try:
            client.handshake()
        except GError:
            client.close()
            raise
        return client

    def _connect_stream(self, tier: str, endpoint: Endpoint) -> Any:
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
        """Parse the configured private key for the in-process transports."""
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
        parsed = parse(url)
        endpoint = self._endpoint(parsed)
        tier = self._tier(endpoint)
        key = self._pool_key(tier, endpoint)
        client = self._checkout(tier, endpoint, key)
        try:
            yield client
        finally:
            # Pooled again only while still alive: a hard failure has killed it.
            self._return(key, client)

    @staticmethod
    def _path(url: URL) -> bytes:
        return (url.path or "/").encode("utf-8", "surrogateescape")

    # -- namespace ---------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        with self._session(url) as client:
            try:
                return client.stat(self._path(parse(url))).to_stat()
            except StatusError as exc:
                raise _sftp_error(exc, url, "Could not stat") from exc

    def lstat(self, url: str) -> Stat:
        # A real lstat: gfal2 aliases lstat to stat and never sees a symlink.
        with self._session(url) as client:
            try:
                return client.lstat(self._path(parse(url))).to_stat()
            except StatusError as exc:
                raise _sftp_error(exc, url, "Could not stat") from exc

    def chmod(self, url: str, mode: int) -> None:
        with self._session(url) as client:
            try:
                client.setstat(self._path(parse(url)), Attrs(permissions=mode))
            except StatusError as exc:
                raise _sftp_error(exc, url, "Could not chmod") from exc

    def mkdir(self, url: str, mode: int) -> None:
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
        # posix-rename overwrites the target, unlike gfal2's plain v3 rename.
        with self._session(old) as client:
            try:
                client.rename(self._path(parse(old)), self._path(parse(new)))
            except StatusError as exc:
                raise _sftp_error(exc, old, "Could not rename") from exc

    def symlink(self, target: str, link: str) -> None:
        target_path = parse(target).path if scheme_of(target) == "sftp" else target
        with self._session(link) as client:
            try:
                client.symlink(
                    target_path.encode("utf-8", "surrogateescape"), self._path(parse(link))
                )
            except StatusError as exc:
                raise _sftp_error(exc, link, "Could not symlink") from exc

    def readlink(self, url: str) -> str:
        with self._session(url) as client:
            try:
                return client.readlink(self._path(parse(url)))
            except StatusError as exc:
                raise _sftp_error(exc, url, "Could not readlink") from exc

    def opendir(self, url: str) -> Iterator[tuple[str, Optional[Stat]]]:
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
            return self._checksum_by_read(client, url, path, name, offset, length)

    def _checksum_by_read(
        self, client: SFTPClient, url: str, path: bytes, name: str, offset: int, length: int
    ) -> str:
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

    def open(
        self, url: str, flags: int, mode: int = 0o644, size: Optional[int] = None
    ) -> PluginFile:
        parsed = parse(url)
        path = self._path(parsed)
        pflags = _pflags(flags)
        endpoint = self._endpoint(parsed)
        tier = self._tier(endpoint)
        key = self._pool_key(tier, endpoint)
        client = self._checkout(tier, endpoint, key)
        try:
            attrs = Attrs(permissions=mode) if flags & O_CREAT else None
            handle = client.open(path, pflags, attrs)
        except StatusError as exc:
            self._return(key, client)
            raise GError(f"Failed opening remote file {url}: {exc.message}", exc.errno) from exc
        except GError:
            self._return(key, client)
            raise
        writing = bool(flags & O_ACCMODE_MASK)
        if flags & O_ACCMODE_MASK == O_WRONLY:
            return _WriteFile(self, key, client, handle, url)
        return _ReadWriteFile(self, key, client, handle, url, writable=writing)

    def _checkout(self, tier: str, endpoint: Endpoint, key: tuple[object, ...]) -> SFTPClient:
        with self._lock:
            idle = self._idle.get(key, [])
            while idle:
                candidate = idle.pop()
                if candidate.alive:
                    return candidate
                candidate.close()
        return self._new_client(tier, endpoint)

    def _return(self, key: tuple[object, ...], client: SFTPClient) -> None:
        if client.alive:
            with self._lock:
                self._idle.setdefault(key, []).append(client)
        else:
            client.close()

    # -- copies ------------------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        ends = (source.partition("://")[0], destination.partition("://")[0])
        # Claim only file<->sftp, where a direct pipelined copy beats the core
        # (which would go through a PluginFile). sftp<->sftp is left to the core.
        return ("sftp" in ends) and ("file" in ends)

    def copy(self, transfer: Transfer) -> None:
        if scheme_of(transfer.source) == "file":
            self._upload(transfer)
        else:
            self._download(transfer)

    def _download(self, transfer: Transfer) -> None:
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
                    _pwrite_all(fd, view, offset)
                    transfer.add(len(view))

                total = client.stream_read(
                    handle, 0, None, consume, depth=self._depth(), check=transfer.check
                )
            finally:
                os.close(fd)
                client.close_handle(handle, quiet=True)
        transfer.progress(total, force=True)

    def _upload(self, transfer: Transfer) -> None:
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
        return max(1, int(self.options.integer(GROUP, "PIPELINE_DEPTH", 64)))


def _pflags(flags: int) -> int:
    """Translate POSIX ``open`` flags into SFTP v3 ``SSH_FXP_OPEN`` flags."""
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
    data = view
    while len(data):
        written = os.pwrite(fd, data, offset)
        if written <= 0:
            raise OSError(errno.EIO, "local pwrite made no progress")
        offset += written
        data = data[written:]


def _has_paramiko() -> bool:
    import importlib.util

    return importlib.util.find_spec("paramiko") is not None


class _RemoteFile(PluginFile):
    """Shared base: a remote handle borrowed from the plugin's session pool."""

    def __init__(
        self,
        plugin: SFTPPlugin,
        key: tuple[object, ...],
        client: SFTPClient,
        handle: bytes,
        url: str,
    ) -> None:
        super().__init__(url)
        self._plugin = plugin
        self._key = key
        self._client = client
        self._handle = handle
        self._size: Optional[int] = None

    def size(self) -> Optional[int]:
        if self._size is None:
            try:
                self._size = self._client.fstat(self._handle).size or 0
            except StatusError as exc:
                raise _sftp_error(exc, self.url, "Could not stat") from exc
        return self._size

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self._client.close_handle(self._handle)
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not close") from exc
        finally:
            self._plugin._return(self._key, self._client)


class _ReadWriteFile(_RemoteFile):
    """A handle opened for reading (and possibly writing): positional and pipelined."""

    def __init__(
        self,
        plugin: SFTPPlugin,
        key: tuple[object, ...],
        client: SFTPClient,
        handle: bytes,
        url: str,
        *,
        writable: bool,
    ) -> None:
        super().__init__(plugin, key, client, handle, url)
        self._writable = writable

    def pread(self, offset: int, size: int) -> bytes:
        try:
            return self._client.read(self._handle, offset, size)
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not read") from exc

    def readinto(self, buffer: Any) -> int:
        view = memoryview(buffer).cast("B")
        try:
            got = self._client.read_into(self._handle, self.position, view)
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not read") from exc
        self.position += got
        return got

    def pwrite(self, data: Any, offset: int) -> int:
        view = memoryview(data).cast("B")
        try:
            self._client.status(
                self._client.request(
                    fx.WRITE,
                    string(self._handle),
                    struct.pack(">QI", offset, len(view)),
                    view,
                )
            )
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not write") from exc
        return len(view)


class _WriteFile(_RemoteFile):
    """A write-only handle with a pipelined write-behind; errors surface on ``close``."""

    def __init__(
        self,
        plugin: SFTPPlugin,
        key: tuple[object, ...],
        client: SFTPClient,
        handle: bytes,
        url: str,
    ) -> None:
        super().__init__(plugin, key, client, handle, url)
        self._writer = WriteBehind(client, handle, depth=plugin._depth())

    def write(self, data: Any) -> int:
        view = memoryview(data).cast("B")
        try:
            self._writer.write(self.position, view)
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not write") from exc
        self.position += len(view)
        return len(view)

    def pwrite(self, data: Any, offset: int) -> int:
        view = memoryview(data).cast("B")
        try:
            self._writer.write(offset, view)
        except StatusError as exc:
            raise _sftp_error(exc, self.url, "Could not write") from exc
        return len(view)

    def close(self) -> None:
        if self.closed:
            return
        try:
            self._writer.flush()
        except StatusError as exc:
            self.closed = True
            self._plugin._return(self._key, self._client)
            raise _sftp_error(exc, self.url, "Could not write") from exc
        super().close()
