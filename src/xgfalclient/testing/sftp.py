"""In-process SFTP and SSH-2 servers, and a fake ``ssh``, for testing the sftp plugin.

Three layers, each usable alone:

:class:`SFTPServer`
    An SFTP v3 server over a local directory, behaving like OpenSSH's
    ``sftp-server``: the same extensions, the same ``errno`` to status
    mapping (so ``EEXIST`` arrives as a bare ``FAILURE``, exactly the
    ambiguity a client has to resolve), ``.`` and ``..`` in listings.
    :meth:`SFTPServer.pair` connects a client stream to it over a
    socketpair. Faults: :meth:`~SFTPServer.inject` a status for the next
    request of a type, :attr:`~SFTPServer.faults` for short reads,
    reordered replies, dropped connections and garbage.

:class:`SSHServer`
    An SSH-2 server on loopback TCP speaking the same algorithms as the
    client transport (curve25519 and DH group KEX; ed25519, RSA and ECDSA
    host keys; AES-CTR+HMAC and ChaCha20-Poly1305), with password and
    public-key authentication, the ``sftp`` subsystem wired to an
    :class:`SFTPServer`, forced rekeying and handshake faults.

:func:`fake_ssh_main`
    What a test puts on ``PATH`` as ``ssh``: it parses OpenSSH's command
    line, logs it, fails the way ``ssh`` fails for magic host names, runs
    ``SSH_ASKPASS`` like ``ssh`` does when a password is needed, and then
    serves SFTP on stdin/stdout. :func:`write_fake_ssh` writes the
    executable.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import os
import posixpath
import socket
import stat as _stat
import struct
import sys
import threading
import time
from collections.abc import Callable
from typing import Any, BinaryIO

from ..crypto import ciphers as _ciphers
from ..crypto import x25519 as _x25519
from ..crypto.sshkeys import (
    KeyError_,
    PrivateKey,
    PublicKey,
    Reader,
    mpint,
    parse_public_blob,
    string,
    uint32,
)
from ..errors import GError as GError_
from ..plugins.sftp import protocol as fx
from ..plugins.sftp import ssh as _ssh
from ..plugins.sftp.protocol import Attrs

__all__ = [
    "SFTPServer",
    "SSHServer",
    "SocketStream",
    "portable_status",
    "fake_ssh_main",
    "write_fake_ssh",
    "FAKE_HOSTS",
]

#: OpenSSH ``sftp-server``'s announced extensions, in its order.
OPENSSH_EXTENSIONS: dict[str, bytes] = {
    "posix-rename@openssh.com": b"1",
    "statvfs@openssh.com": b"2",
    "fstatvfs@openssh.com": b"2",
    "hardlink@openssh.com": b"1",
    "fsync@openssh.com": b"1",
    "lsetstat@openssh.com": b"1",
    "limits@openssh.com": b"1",
}


def portable_status(code: int | None) -> int:
    """``errno_to_portable`` from OpenSSH's ``sftp-server.c``, verbatim in effect."""
    if code in (errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP):
        return fx.FX_NO_SUCH_FILE
    if code in (errno.EPERM, errno.EACCES, errno.EFAULT):
        return fx.FX_PERMISSION_DENIED
    if code in (errno.ENAMETOOLONG, errno.EINVAL):
        return fx.FX_BAD_MESSAGE
    if code == errno.ENOSYS:
        return fx.FX_OP_UNSUPPORTED
    return fx.FX_FAILURE


class SocketStream:
    """A client :class:`~xgfalclient.plugins.sftp.client.Stream` over a socket."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def send(self, *parts: Any) -> None:
        for part in parts:
            self.sock.sendall(part)

    def recv_into(self, view: memoryview) -> int:
        return self.sock.recv_into(view)

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class _Drop(Exception):
    """Raised inside the server to end the session abruptly."""


class _Handle:
    __slots__ = ("entries", "fd", "path")

    def __init__(self, path: str, fd: int = -1, entries: list[str] | None = None) -> None:
        self.path = path
        self.fd = fd
        self.entries = entries


class SFTPServer:
    """An SFTP v3 server over ``root``. Sessions run in their own threads."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        extensions: dict[str, bytes] | None = None,
        limits: tuple[int, int, int, int] | None = (262144, 261120, 261120, 0),
        version: int = 3,
        check_file: tuple[str, ...] = (),
        batch: int = 100,
    ) -> None:
        self.root = os.path.realpath(os.fspath(root))
        self.extensions = dict(OPENSSH_EXTENSIONS if extensions is None else extensions)
        self.limits = limits
        if limits is None:
            self.extensions.pop("limits@openssh.com", None)
        self.check_file = check_file
        if check_file:
            self.extensions["check-file-name"] = b"1"
        self.version = version
        self.batch = batch
        #: ``(type, first argument)`` for every request, in arrival order.
        self.log: list[tuple[int, bytes]] = []
        #: Named misbehaviours, each consumed when it fires:
        #: ``short_read`` (next READ returns half), ``reorder`` (answer the next
        #: two requests in reverse), ``drop`` (hang up on the next request),
        #: ``garbage`` (answer the next request with an absurd length),
        #: ``wrong_type`` (answer the next request with an unexpected packet),
        #: ``banner`` (text before VERSION), ``oversize`` (next READ sends more DATA
        #: than asked), ``hang`` (never answer the next request).
        self.faults: list[str] = []
        self._injected: dict[int, list[tuple[int, str]]] = {}
        self._lock = threading.Lock()
        self.threads: list[threading.Thread] = []
        self.sessions = 0

    # -- control -------------------------------------------------------------------

    def inject(self, ptype: int, code: int, message: str = "", count: int = 1) -> None:
        """Answer the next ``count`` requests of ``ptype`` with this status instead."""
        with self._lock:
            self._injected.setdefault(ptype, []).extend([(code, message)] * count)

    def _take_injection(self, ptype: int) -> tuple[int, str] | None:
        with self._lock:
            queue = self._injected.get(ptype)
            return queue.pop(0) if queue else None

    def _take_fault(self, name: str) -> bool:
        with self._lock:
            if name in self.faults:
                self.faults.remove(name)
                return True
            return False

    def pair(self) -> SocketStream:
        """A connected client stream; the server side runs in a thread."""
        client, server = socket.socketpair()
        self.start(lambda: _SocketIO(server))
        return SocketStream(client)

    def start(self, io_factory: Callable[[], Any]) -> threading.Thread:
        thread = threading.Thread(target=self._run, args=(io_factory,), daemon=True)
        thread.start()
        self.threads.append(thread)
        return thread

    def _run(self, io_factory: Callable[[], Any]) -> None:
        io = io_factory()
        try:
            self.serve(io.read_exact, io.write)
        finally:
            io.close()

    # -- the session -----------------------------------------------------------------

    def serve(self, read_exact: Callable[[int], bytes], write: Callable[[bytes], None]) -> None:
        """Serve one session until the client goes away (or a fault ends it)."""
        with self._lock:
            self.sessions += 1
        session = _Session(self, read_exact, write)
        try:
            session.run()
        except (_Drop, EOFError, OSError):
            pass
        finally:
            session.close_all()

    # -- paths ---------------------------------------------------------------------

    def local(self, path: bytes | str) -> str:
        """The local file an SFTP path names; never outside ``root``."""
        text = path.decode("utf-8", "surrogateescape") if isinstance(path, bytes) else path
        clean = posixpath.normpath("/" + text)
        return self.root + ("" if clean == "/" else clean)

    def remote(self, local: str) -> str:
        relative = os.path.relpath(local, self.root)
        return "/" if relative == "." else "/" + relative


class _SocketIO:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def read_exact(self, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            got = self.sock.recv(count - len(chunks))
            if not got:
                raise EOFError
            chunks += got
        return bytes(chunks)

    def write(self, data: bytes) -> None:
        self.sock.sendall(data)

    def close(self) -> None:
        self.sock.close()


def _longname(name: str, info: os.stat_result) -> str:
    mode = _stat.filemode(info.st_mode)
    when = time.strftime("%b %d %H:%M", time.gmtime(info.st_mtime))
    return (
        f"{mode} {info.st_nlink:3d} {info.st_uid:<8d} {info.st_gid:<8d} "
        f"{info.st_size:8d} {when} {name}"
    )


def _attrs(info: os.stat_result) -> Attrs:
    return Attrs(
        size=info.st_size,
        uid=info.st_uid,
        gid=info.st_gid,
        permissions=info.st_mode,
        atime=int(info.st_atime),
        mtime=int(info.st_mtime),
    )


class _Session:
    def __init__(
        self, server: SFTPServer, read_exact: Callable[[int], bytes], write: Callable[[bytes], None]
    ) -> None:
        self.server = server
        self.read_exact = read_exact
        self.raw_write = write
        self.handles: dict[bytes, _Handle] = {}
        self.counter = 0
        self.held: list[bytes] = []
        self.reorder = 0

    # -- framing -------------------------------------------------------------------

    def write(self, data: bytes) -> None:
        if self.reorder:
            self.held.append(data)
            self.reorder -= 1
            if not self.reorder:
                for packet in reversed(self.held):
                    self.raw_write(packet)
                self.held = []
            return
        self.raw_write(data)

    def send(self, ptype: int, rid: int, body: bytes) -> None:
        self.write(uint32(len(body) + 5) + bytes([ptype]) + uint32(rid) + body)

    def status(self, rid: int, code: int, message: str = "") -> None:
        text = message or fx.STATUS_NAMES.get(code, "").replace("_", " ").capitalize()
        if code == fx.FX_OK:
            text = message or "Success"
        self.send(fx.STATUS, rid, uint32(code) + string(text) + string(""))

    def error(self, rid: int, exc: OSError) -> None:
        self.status(rid, portable_status(exc.errno), os.strerror(exc.errno or errno.EIO))

    def run(self) -> None:
        length, ptype = struct.unpack(">IB", self.read_exact(5))
        body = self.read_exact(length - 1)
        if ptype != fx.INIT:
            raise _Drop
        if self.server._take_fault("banner"):
            self.raw_write(b"Welcome to the machine!\r\n")
        extensions = b"".join(string(k) + string(v) for k, v in self.server.extensions.items())
        payload = bytes([fx.VERSION_]) + uint32(self.server.version) + extensions
        self.raw_write(uint32(len(payload)) + payload)
        del body
        while True:
            length, ptype, rid = struct.unpack(">IBI", self.read_exact(9))
            reader = Reader(self.read_exact(length - 5))
            self.dispatch(ptype, rid, reader)

    def dispatch(self, ptype: int, rid: int, reader: Reader) -> None:
        server = self.server
        first = (
            reader.data[4 : 4 + struct.unpack(">I", reader.data[:4])[0]]
            if reader.remaining >= 4
            else b""
        )
        server.log.append((ptype, first))
        if server._take_fault("drop"):
            raise _Drop
        if server._take_fault("hang"):
            return
        if server._take_fault("garbage"):
            self.raw_write(b"\x7f\xff\xff\xff" + bytes([fx.STATUS]) + uint32(rid))
            raise _Drop
        if server._take_fault("wrong_type"):
            self.send(fx.HANDLE if ptype != fx.OPEN else fx.NAME, rid, string(b"x"))
            return
        if server._take_fault("reorder"):
            self.reorder = 2
        injected = server._take_injection(ptype)
        if injected is not None:
            self.status(rid, *injected)
            return
        handler = _HANDLERS.get(ptype)
        if handler is None:
            self.status(rid, fx.FX_OP_UNSUPPORTED, "Operation unsupported")
            return
        try:
            handler(self, rid, reader)
        except OSError as exc:
            self.error(rid, exc)
        except KeyError_:
            self.status(rid, fx.FX_BAD_MESSAGE, "Bad message")

    def close_all(self) -> None:
        for handle in self.handles.values():
            if handle.fd >= 0:
                os.close(handle.fd)
        self.handles.clear()

    def new_handle(self, handle: _Handle) -> bytes:
        self.counter += 1
        key = struct.pack(">I", self.counter)
        self.handles[key] = handle
        return key

    def handle(self, rid: int, reader: Reader) -> _Handle | None:
        found = self.handles.get(reader.string())
        if found is None:
            self.status(rid, fx.FX_FAILURE, "Failure")
        return found

    # -- handlers --------------------------------------------------------------------

    def op_open(self, rid: int, reader: Reader) -> None:
        path = self.server.local(reader.string())
        pflags = reader.uint32()
        attrs = Attrs.decode(reader)
        flags = 0
        if pflags & fx.FXF_READ and pflags & fx.FXF_WRITE:
            flags = os.O_RDWR
        elif pflags & fx.FXF_WRITE:
            flags = os.O_WRONLY
        for bit, value in (
            (fx.FXF_APPEND, os.O_APPEND),
            (fx.FXF_CREAT, os.O_CREAT),
            (fx.FXF_TRUNC, os.O_TRUNC),
            (fx.FXF_EXCL, os.O_EXCL),
        ):
            if pflags & bit:
                flags |= value
        mode = attrs.permissions & 0o7777 if attrs.permissions is not None else 0o666
        fd = os.open(path, flags, mode)
        if _stat.S_ISDIR(os.fstat(fd).st_mode):
            # Linux refuses O_WRONLY on a directory with EISDIR; reading one
            # "opens" and fails later. Report it now, as FAILURE, as sshd would.
            os.close(fd)
            raise IsADirectoryError(errno.EISDIR, "Is a directory")
        self.send(fx.HANDLE, rid, string(self.new_handle(_Handle(path, fd))))

    def op_close(self, rid: int, reader: Reader) -> None:
        key = reader.string()
        handle = self.handles.pop(key, None)
        if handle is None:
            self.status(rid, fx.FX_FAILURE, "Failure")
            return
        if handle.fd >= 0:
            os.close(handle.fd)
        self.status(rid, fx.FX_OK)

    def op_read(self, rid: int, reader: Reader) -> None:
        handle = self.handle(rid, reader)
        if handle is None:
            return
        offset = reader.uint64()
        size = min(reader.uint32(), self.server.limits[2] if self.server.limits else 1 << 20)
        if self.server._take_fault("short_read"):
            size = max(1, size // 2)
        data = os.pread(handle.fd, size, offset)
        if not data:
            self.status(rid, fx.FX_EOF, "End of file")
            return
        if self.server._take_fault("oversize"):
            data += b"!"
            self.write(
                uint32(len(data) + 9) + bytes([fx.DATA]) + uint32(rid) + string(data)[:4] + data
            )
            return
        self.send(fx.DATA, rid, string(data))

    def op_write(self, rid: int, reader: Reader) -> None:
        handle = self.handle(rid, reader)
        if handle is None:
            return
        offset = reader.uint64()
        data = reader.string()
        os.pwrite(handle.fd, data, offset)
        self.status(rid, fx.FX_OK)

    def _stat_reply(self, rid: int, info: os.stat_result) -> None:
        self.send(fx.ATTRS, rid, _attrs(info).encode())

    def op_stat(self, rid: int, reader: Reader) -> None:
        self._stat_reply(rid, os.stat(self.server.local(reader.string())))

    def op_lstat(self, rid: int, reader: Reader) -> None:
        self._stat_reply(rid, os.lstat(self.server.local(reader.string())))

    def op_fstat(self, rid: int, reader: Reader) -> None:
        handle = self.handle(rid, reader)
        if handle is not None:
            self._stat_reply(rid, os.fstat(handle.fd))

    def _apply(self, path: str, attrs: Attrs) -> None:
        if attrs.size is not None:
            os.truncate(path, attrs.size)
        if attrs.permissions is not None:
            os.chmod(path, attrs.permissions & 0o7777)
        if attrs.atime is not None:
            # ATTR_ACMODTIME carries both times: decode never sets one alone.
            assert attrs.mtime is not None
            os.utime(path, (attrs.atime, attrs.mtime))

    def op_setstat(self, rid: int, reader: Reader) -> None:
        path = self.server.local(reader.string())
        self._apply(path, Attrs.decode(reader))
        self.status(rid, fx.FX_OK)

    def op_fsetstat(self, rid: int, reader: Reader) -> None:
        handle = self.handle(rid, reader)
        if handle is not None:
            self._apply(handle.path, Attrs.decode(reader))
            self.status(rid, fx.FX_OK)

    def op_opendir(self, rid: int, reader: Reader) -> None:
        path = self.server.local(reader.string())
        names = [".", "..", *sorted(os.listdir(path))]
        self.send(fx.HANDLE, rid, string(self.new_handle(_Handle(path, entries=names))))

    def op_readdir(self, rid: int, reader: Reader) -> None:
        handle = self.handle(rid, reader)
        if handle is None:
            return
        if handle.entries is None:
            self.status(rid, fx.FX_FAILURE, "Failure")
            return
        batch, handle.entries = (
            handle.entries[: self.server.batch],
            handle.entries[self.server.batch :],
        )
        if not batch:
            self.status(rid, fx.FX_EOF, "End of file")
            return
        body = b""
        count = 0
        for name in batch:
            try:
                info = os.lstat(os.path.join(handle.path, name))
            except OSError:
                continue
            body += string(name.encode("utf-8", "surrogateescape"))
            body += string(_longname(name, info)) + _attrs(info).encode()
            count += 1
        self.send(fx.NAME, rid, uint32(count) + body)

    def op_remove(self, rid: int, reader: Reader) -> None:
        os.unlink(self.server.local(reader.string()))
        self.status(rid, fx.FX_OK)

    def op_mkdir(self, rid: int, reader: Reader) -> None:
        path = self.server.local(reader.string())
        attrs = Attrs.decode(reader)
        os.mkdir(path, attrs.permissions & 0o7777 if attrs.permissions is not None else 0o777)
        self.status(rid, fx.FX_OK)

    def op_rmdir(self, rid: int, reader: Reader) -> None:
        os.rmdir(self.server.local(reader.string()))
        self.status(rid, fx.FX_OK)

    def op_realpath(self, rid: int, reader: Reader) -> None:
        raw = reader.string().decode("utf-8", "surrogateescape")
        name = self.server.remote(os.path.realpath(self.server.local(raw or ".")))
        self.send(fx.NAME, rid, uint32(1) + string(name) + string(name) + Attrs().encode())

    def op_rename(self, rid: int, reader: Reader) -> None:
        old = self.server.local(reader.string())
        new = self.server.local(reader.string())
        # sftp-server's v3 rename refuses to replace an existing target.
        if os.path.lexists(new):
            self.status(rid, fx.FX_FAILURE, "Failure")
            return
        os.rename(old, new)
        self.status(rid, fx.FX_OK)

    def op_readlink(self, rid: int, reader: Reader) -> None:
        target = os.readlink(self.server.local(reader.string()))
        self.send(fx.NAME, rid, uint32(1) + string(target) + string(target) + Attrs().encode())

    def op_symlink(self, rid: int, reader: Reader) -> None:
        target = reader.string().decode("utf-8", "surrogateescape")
        link = self.server.local(reader.string())
        os.symlink(target, link)
        self.status(rid, fx.FX_OK)

    def op_extended(self, rid: int, reader: Reader) -> None:
        name = reader.text()
        if name not in self.server.extensions:
            self.status(rid, fx.FX_OP_UNSUPPORTED, "Operation unsupported")
            return
        if name == "posix-rename@openssh.com":
            os.rename(self.server.local(reader.string()), self.server.local(reader.string()))
            self.status(rid, fx.FX_OK)
        elif name == "hardlink@openssh.com":
            os.link(self.server.local(reader.string()), self.server.local(reader.string()))
            self.status(rid, fx.FX_OK)
        elif name == "fsync@openssh.com":
            handle = self.handle(rid, reader)
            if handle is not None:
                os.fsync(handle.fd)
                self.status(rid, fx.FX_OK)
        elif name == "limits@openssh.com":
            assert self.server.limits is not None
            body = b"".join(struct.pack(">Q", value) for value in self.server.limits)
            self.send(fx.EXTENDED_REPLY, rid, body)
        elif name == "statvfs@openssh.com":
            info = os.statvfs(self.server.local(reader.string()))
            values = (
                info.f_bsize,
                info.f_frsize,
                info.f_blocks,
                info.f_bfree,
                info.f_bavail,
                info.f_files,
                info.f_ffree,
                info.f_favail,
                0,
                info.f_flag,
                info.f_namemax,
            )
            self.send(fx.EXTENDED_REPLY, rid, b"".join(struct.pack(">Q", v) for v in values))
        elif name == "check-file-name":
            self._check_file(rid, reader)
        else:
            self.status(rid, fx.FX_OP_UNSUPPORTED, "Operation unsupported")

    def _check_file(self, rid: int, reader: Reader) -> None:
        import hashlib

        path = self.server.local(reader.string())
        wanted = reader.text().split(",")
        offset = reader.uint64()
        length = reader.uint64()
        chosen = next((a for a in wanted if a in self.server.check_file), None)
        if chosen is None:
            self.status(rid, fx.FX_FAILURE, "No supported hash algorithm")
            return
        with open(path, "rb") as handle:
            handle.seek(offset)
            data = handle.read(length) if length else handle.read()
        digest = hashlib.new(chosen, data).digest()
        self.send(fx.EXTENDED_REPLY, rid, string(chosen) + digest)


_HANDLERS: dict[int, Callable[[_Session, int, Reader], None]] = {
    fx.OPEN: _Session.op_open,
    fx.CLOSE: _Session.op_close,
    fx.READ: _Session.op_read,
    fx.WRITE: _Session.op_write,
    fx.LSTAT: _Session.op_lstat,
    fx.FSTAT: _Session.op_fstat,
    fx.SETSTAT: _Session.op_setstat,
    fx.FSETSTAT: _Session.op_fsetstat,
    fx.OPENDIR: _Session.op_opendir,
    fx.READDIR: _Session.op_readdir,
    fx.REMOVE: _Session.op_remove,
    fx.MKDIR: _Session.op_mkdir,
    fx.RMDIR: _Session.op_rmdir,
    fx.REALPATH: _Session.op_realpath,
    fx.STAT: _Session.op_stat,
    fx.RENAME: _Session.op_rename,
    fx.READLINK: _Session.op_readlink,
    fx.SYMLINK: _Session.op_symlink,
    fx.EXTENDED: _Session.op_extended,
}


# ===========================================================================
# An in-process SSH-2 server, for exercising the Python transport tier.
# ===========================================================================


def _read_exact_from(sock: socket.socket, count: int, buffer: bytearray) -> bytes:
    """Pull exactly ``count`` bytes off ``sock``, keeping the overrun in ``buffer``."""
    while len(buffer) < count:
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError
        buffer += chunk
    out = bytes(buffer[:count])
    del buffer[:count]
    return out


class SSHServer:
    """A minimal SSH-2 server: the algorithms the client speaks, over the ``sftp`` subsystem.

    It negotiates KEX (curve25519 or a DH group), signs with an
    ed25519/RSA/ECDSA host key, brings up ``aes-ctr``+HMAC or
    ChaCha20-Poly1305, authenticates a password or public key, and wires one
    session channel's ``sftp`` subsystem to an :class:`SFTPServer`. It is
    only as complete as the client it tests.
    """

    def __init__(
        self,
        sftp: SFTPServer,
        host_key: PrivateKey,
        *,
        password: str = "",
        username: str = "",
        authorized_keys: tuple[PublicKey, ...] = (),
        send_ext_info: bool = False,
        ext_info_algs: str = "rsa-sha2-512,rsa-sha2-256,ssh-ed25519,ecdsa-sha2-nistp256",
        rekey_after: int = 0,
        fault: str = "",
        backend: _ciphers.Backend | None = None,
    ) -> None:
        self.sftp = sftp
        self.host_key = host_key
        self.password = password
        self.username = username
        self.authorized_keys = authorized_keys
        self.send_ext_info = send_ext_info
        self.ext_info_algs = ext_info_algs
        self.rekey_after = rekey_after
        self.fault = fault
        self.backend = backend if backend is not None else _ciphers.get()
        self.threads: list[threading.Thread] = []

    def pair(self) -> socket.socket:
        """A client socket already connected to a server session in a thread."""
        client, server = socket.socketpair()
        thread = threading.Thread(target=self._serve, args=(server,), daemon=True)
        thread.start()
        self.threads.append(thread)
        return client

    def _serve(self, sock: socket.socket) -> None:
        conn = _SSHServerConn(self, sock)
        try:
            conn.run()
        except (EOFError, OSError, GError_, ValueError):
            pass
        finally:
            # shutdown() first: on Linux a bare close() neither wakes this
            # connection's reader thread, blocked in recv on the same socket,
            # nor sends the FIN the client is waiting for.
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()  # idempotent


#: The window and maximum packet the test server grants, as OpenSSH's sshd
#: does for a session channel - so a client upload runs into both.
_SERVER_WINDOW = 2 * 1024 * 1024
_SERVER_MAXPACKET = 32768


class _SSHServerConn:
    _VERSION = b"SSH-2.0-xgfaltest"

    def __init__(self, server: SSHServer, sock: socket.socket) -> None:
        self.server = server
        self.sock = sock
        self.buffer = bytearray()
        self.out: _ssh._Cipher = _ssh._NullCipher()
        self.inc: _ssh._Cipher = _ssh._NullCipher()
        self.out_seq = 0
        self.in_seq = 0
        self.send_lock = threading.Lock()
        self.kex_lock = threading.Lock()
        self.session_id = b""
        self.remote_channel = 0
        self.local_channel = 0
        self.client_window = 0
        self.client_maxpacket = 0
        self.local_window = _SERVER_WINDOW
        self.inbuf = bytearray()
        self.cond = threading.Condition()
        self.eof = False
        self.error: BaseException | None = None
        self.client_packets = 0
        self.rekeyed = False

    # -- framing ---------------------------------------------------------------

    def _recv_exact(self, count: int) -> bytes:
        return _read_exact_from(self.sock, count, self.buffer)

    def send_packet(self, payload: bytes) -> None:
        with self.send_lock:
            self.sock.sendall(self.out.seal(self.out_seq, payload))
            self.out_seq = (self.out_seq + 1) & 0xFFFFFFFF

    def recv_packet(self) -> bytes:
        payload = bytes(self.inc.read(self._recv_exact, self.in_seq))
        self.in_seq = (self.in_seq + 1) & 0xFFFFFFFF
        return payload

    # -- handshake -------------------------------------------------------------

    def run(self) -> None:
        self.client_version = self._exchange_versions()
        self._key_exchange(initial=True)
        if self.server.send_ext_info:
            self._send_ext_info()
        self._authenticate()
        self._open_channel()
        self._emit_channel_faults()
        reader = threading.Thread(target=self._run_reader, daemon=True)
        reader.start()
        self.server.sftp.serve(self._chan_read_exact, self._chan_write)

    def _exchange_versions(self) -> bytes:
        self.sock.sendall(self._VERSION + b"\r\n")
        line = b""
        while not line.endswith(b"\n"):
            line += self._recv_exact(1)
        return line.rstrip(b"\r\n")

    def _server_kexinit(self) -> bytes:
        def names(items: list[str]) -> bytes:
            return string(",".join(items))

        cipher = list(_ssh._ciphers_preferred(self.server.backend))
        host = [self._hostkey_alg()]
        body = bytes([_ssh.MSG_KEXINIT]) + os.urandom(16)
        body += names(list(_ssh._KEX_ALGS))
        body += names(host)
        body += names(cipher) + names(cipher)
        body += names(list(_ssh._MACS)) + names(list(_ssh._MACS))
        body += names(["none"]) + names(["none"])
        body += names([]) + names([])
        body += bytes([0]) + uint32(0)
        return body

    def _hostkey_alg(self) -> str:
        if self.server.host_key.kind == "ssh-rsa":
            return "rsa-sha2-512"
        return self.server.host_key.kind

    def _key_exchange(self, initial: bool) -> None:
        with self.kex_lock:
            self._key_exchange_locked(initial)

    def _fault(self, name: str) -> bool:
        return self.server.fault == name

    def _key_exchange_locked(self, initial: bool) -> None:
        server_kexinit = self._server_kexinit()
        if self._fault("ignore_before_kexinit"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        self.send_packet(server_kexinit)
        # The only client here is ours, which always sends KEXINIT first.
        client_kexinit = self.recv_packet()
        server_lists = _ssh.SSHTransport._parse_kexinit(server_kexinit)
        client_lists = _ssh.SSHTransport._parse_kexinit(client_kexinit)
        kex = _ssh._negotiate(client_lists[0], server_lists[0])
        cipher_cs = _ssh._negotiate(client_lists[2], server_lists[2])
        cipher_sc = _ssh._negotiate(client_lists[3], server_lists[3])
        mac_cs = _ssh._negotiate(client_lists[4], server_lists[4])
        mac_sc = _ssh._negotiate(client_lists[5], server_lists[5])
        reader = Reader(self.recv_packet()[1:])  # KEX_ECDH_INIT
        # Each kex returns the client and server public values already encoded
        # the way both the exchange hash and the reply want them.
        if kex in _ssh._DH_GROUP:
            shared, client_pub, server_pub = self._kex_dh(kex, reader)
        else:
            shared, client_pub, server_pub = self._kex_curve(reader)
        host_blob = self.server.host_key.public.blob
        exchange = client_pub + server_pub
        digest = _ssh._KEX_HASH[kex]
        h = hashlib.new(
            digest,
            string(self.client_version)
            + string(self._VERSION)
            + string(client_kexinit)
            + string(server_kexinit)
            + string(host_blob)
            + exchange
            + mpint(shared),
        ).digest()
        sig = self.server.host_key.sign(h, self._hostkey_alg())
        if self._fault("wrong_ecdh"):
            self.send_packet(bytes([_ssh.MSG_UNIMPLEMENTED]) + uint32(0))
            raise EOFError
        if self._fault("ignore_before_ecdh"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        if self._fault("bad_hostkey"):
            host_blob = b"\x00\x00\x00\x03bad"  # unparseable key blob
        if self._fault("bad_hostsig"):
            sig = self.server.host_key.sign(b"a different transcript", self._hostkey_alg())
        self.send_packet(
            bytes([_ssh.MSG_KEX_ECDH_REPLY]) + string(host_blob) + server_pub + string(sig)
        )
        if self._fault("bad_newkeys"):
            self.send_packet(bytes([_ssh.MSG_UNIMPLEMENTED]) + uint32(0))
            raise EOFError
        self.send_packet(bytes([_ssh.MSG_NEWKEYS]))
        if initial:
            self.session_id = h
        self.recv_packet()  # the client's NEWKEYS
        with self.send_lock:
            self.out = _ssh.make_cipher(
                self.server.backend,
                cipher_sc,
                mac_sc,
                shared,
                h,
                self.session_id,
                digest,
                ("B", "D", "F"),
            )
        self.inc = _ssh.make_cipher(
            self.server.backend,
            cipher_cs,
            mac_cs,
            shared,
            h,
            self.session_id,
            digest,
            ("A", "C", "E"),
        )

    def _kex_curve(self, reader: Reader) -> tuple[int, bytes, bytes]:
        client_pub = reader.string()
        private, public = _x25519.generate()
        shared = int.from_bytes(_x25519.x25519(private, client_pub), "big")
        return shared, string(client_pub), string(public)

    def _kex_dh(self, kex: str, reader: Reader) -> tuple[int, bytes, bytes]:
        p = _ssh._DH_GROUP[kex]
        e = reader.mpint()
        y = int.from_bytes(os.urandom(256), "big") % (p - 2) + 1
        f = pow(2, y, p)
        shared = pow(e, y, p)
        if self._fault("bad_dh_f"):
            return shared, mpint(e), mpint(1)  # f out of range
        return shared, mpint(e), mpint(f)

    # -- extension info & authentication ---------------------------------------

    def _send_ext_info(self) -> None:
        # Two entries, the first unrelated, so the client's parser skips it.
        body = (
            uint32(2)
            + string("first-ext@openssh.com")
            + string("1")
            + string("server-sig-algs")
            + string(self.server.ext_info_algs)
        )
        self.send_packet(bytes([_ssh.MSG_EXT_INFO]) + body)

    def _authenticate(self) -> None:
        self.recv_packet()  # the client's SERVICE_REQUEST
        if self._fault("bad_service_accept"):
            self.send_packet(bytes([_ssh.MSG_UNIMPLEMENTED]) + uint32(0))
            raise EOFError
        if self._fault("ignore_pre_auth"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        self.send_packet(bytes([_ssh.MSG_SERVICE_ACCEPT]) + string("ssh-userauth"))
        while True:
            payload = self.recv_packet()  # a USERAUTH_REQUEST
            reader = Reader(payload[1:])
            user = reader.text()
            reader.text()  # "ssh-connection"
            method = reader.text()
            if self._try_method(user, method, reader, payload):
                if self._fault("auth_banner"):
                    self.send_packet(
                        bytes([_ssh.MSG_USERAUTH_BANNER]) + string("welcome") + string("")
                    )
                if self._fault("auth_ignore"):
                    self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
                if self._fault("auth_pk_ok"):
                    self.send_packet(bytes([_ssh.MSG_USERAUTH_PK_OK]) + string("x") + string(b"y"))
                if self._fault("auth_unexpected"):
                    self.send_packet(bytes([_ssh.MSG_SERVICE_REQUEST]) + string("bogus"))
                    raise EOFError
                self.send_packet(bytes([_ssh.MSG_USERAUTH_SUCCESS]))
                return
            self.send_packet(
                bytes([_ssh.MSG_USERAUTH_FAILURE]) + string("publickey,password") + bytes([0])
            )

    def _try_method(self, user: str, method: str, reader: Reader, payload: bytes) -> bool:
        if self.server.username and user != self.server.username:
            return False
        if method == "password":
            reader.boolean()
            return bool(self.server.password) and reader.text() == self.server.password
        # publickey (the only other method our client sends).
        reader.boolean()  # the "signed" flag; our client always signs
        algorithm = reader.text()
        blob = reader.string()
        if not any(blob == k.blob for k in self.server.authorized_keys):
            return False
        signature = reader.string()
        request = payload[: len(payload) - len(string(signature))]
        data = string(self.session_id) + request
        return parse_public_blob(blob).verify(algorithm, data, signature)

    # -- channel ---------------------------------------------------------------

    def _open_channel(self) -> None:
        reader = Reader(self.recv_packet()[1:])  # CHANNEL_OPEN
        reader.text()  # "session"
        self.remote_channel = reader.uint32()
        self.client_window = reader.uint32()
        self.client_maxpacket = reader.uint32()
        if self._fault("global_before_open"):
            # A GLOBAL_REQUEST that wants a reply, before the confirmation.
            self.send_packet(
                bytes([_ssh.MSG_GLOBAL_REQUEST]) + string("hostkeys-00@openssh.com") + bytes([1])
            )
        if self._fault("channel_open_failure"):
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_OPEN_FAILURE])
                + uint32(self.remote_channel)
                + uint32(4)
                + string("administratively prohibited")
                + string("")
            )
            raise EOFError
        if self._fault("wrong_channel_confirm"):
            self.send_packet(bytes([_ssh.MSG_UNIMPLEMENTED]) + uint32(0))
            raise EOFError
        if self._fault("ignore_before_open"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        if self._fault("window_before_confirm"):
            # OpenSSH may credit the channel window before confirming it.
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_WINDOW_ADJUST]) + uint32(self.remote_channel) + uint32(4096)
            )
        self.send_packet(
            bytes([_ssh.MSG_CHANNEL_OPEN_CONFIRMATION])
            + uint32(self.remote_channel)
            + uint32(self.local_channel)
            + uint32(self.local_window)
            + uint32(_SERVER_MAXPACKET)
        )
        request = self.recv_packet()
        while request[0] in (_ssh.MSG_REQUEST_FAILURE, _ssh.MSG_REQUEST_SUCCESS):
            request = self.recv_packet()  # the client's reply to a global request
        r = Reader(request[1:])  # CHANNEL_REQUEST
        r.uint32()
        kind = r.text()
        r.boolean()  # want_reply; our client always wants one for the subsystem
        name = r.string()
        ok = kind == "subsystem" and name == b"sftp" and self.server.fault != "no-subsystem"
        if self._fault("ignore_before_subsystem"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        if self._fault("request_before_subsystem"):
            # A CHANNEL_REQUEST (no reply wanted) arriving before the confirmation.
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_REQUEST])
                + uint32(self.remote_channel)
                + string("exit-signal")
                + bytes([0])
                + string("TERM")
            )
        if self._fault("wrong_subsystem"):
            self.send_packet(bytes([_ssh.MSG_UNIMPLEMENTED]) + uint32(0))
            raise EOFError
        code = _ssh.MSG_CHANNEL_SUCCESS if ok else _ssh.MSG_CHANNEL_FAILURE
        self.send_packet(bytes([code]) + uint32(self.remote_channel))
        if not ok:
            raise EOFError

    def _emit_channel_faults(self) -> None:
        """After the subsystem is up, inject one channel-level oddity if asked."""
        ch = uint32(self.remote_channel)
        if self._fault("ignore_mid"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        elif self._fault("stderr"):
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_EXTENDED_DATA]) + ch + uint32(1) + string(b"warn")
            )
        elif self._fault("exit_status"):
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_REQUEST])
                + ch
                + string("exit-status")
                + bytes([1])
                + uint32(0)
            )
        elif self._fault("exit_status_noreply"):
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_REQUEST])
                + ch
                + string("exit-status")
                + bytes([0])
                + uint32(0)
            )
        elif self._fault("global_mid"):
            self.send_packet(
                bytes([_ssh.MSG_GLOBAL_REQUEST]) + string("keepalive@openssh.com") + bytes([1])
            )
        elif self._fault("global_mid_noreply"):
            self.send_packet(
                bytes([_ssh.MSG_GLOBAL_REQUEST]) + string("keepalive@openssh.com") + bytes([0])
            )
        elif self._fault("disconnect_mid"):
            self.send_packet(bytes([_ssh.MSG_DISCONNECT]) + uint32(11) + string("bye") + string(""))
            raise EOFError
        elif self._fault("eof_close"):
            self.send_packet(bytes([_ssh.MSG_CHANNEL_EOF]) + ch)
            self.send_packet(bytes([_ssh.MSG_CHANNEL_CLOSE]) + ch)
            raise EOFError
        elif self._fault("abrupt"):
            raise EOFError  # drop the connection with no framing at all

    def _run_reader(self) -> None:
        try:
            while True:
                payload = self.recv_packet()
                if not self._dispatch(payload):
                    return
        except (EOFError, OSError, GError_) as exc:
            with self.cond:
                self.error = exc
                self.eof = True
                self.cond.notify_all()

    def _dispatch(self, payload: bytes) -> bool:
        code = payload[0]
        if code == _ssh.MSG_CHANNEL_DATA:
            reader = Reader(payload[1:])
            reader.uint32()
            data = reader.string()
            # The window is topped up as data arrives, so it never falls below
            # half of _SERVER_WINDOW: only a packet over the maximum can overrun it.
            if len(data) > _SERVER_MAXPACKET:
                # A client overrunning the flow control it was granted.
                raise GError_("SSH protocol error: channel data beyond the window", errno.EPROTO)
            with self.cond:
                self.inbuf += data
                self.local_window -= len(data)
                self.client_packets += 1
                trigger = (
                    self.server.rekey_after
                    and not self.rekeyed
                    and self.client_packets >= self.server.rekey_after
                )
                self.cond.notify_all()
            self._credit_window()
            if trigger:
                self.rekeyed = True
                self._key_exchange(initial=False)
            return True
        if code == _ssh.MSG_CHANNEL_WINDOW_ADJUST:
            reader = Reader(payload[1:])
            reader.uint32()
            with self.cond:
                self.client_window += reader.uint32()
                self.cond.notify_all()
            return True
        if code in (_ssh.MSG_CHANNEL_EOF, _ssh.MSG_CHANNEL_CLOSE):
            with self.cond:
                self.eof = True
                self.cond.notify_all()
            return code != _ssh.MSG_CHANNEL_CLOSE
        # IGNORE / DEBUG / anything else: skip.
        return True

    def _credit_window(self) -> None:
        with self.cond:
            if self.local_window > _SERVER_WINDOW // 2:
                return
            top_up = _SERVER_WINDOW - self.local_window
            self.local_window = _SERVER_WINDOW
        self.send_packet(
            bytes([_ssh.MSG_CHANNEL_WINDOW_ADJUST]) + uint32(self.remote_channel) + uint32(top_up)
        )

    def _chan_read_exact(self, count: int) -> bytes:
        out = bytearray()
        with self.cond:
            while len(out) < count:
                if self.inbuf:
                    take = min(count - len(out), len(self.inbuf))
                    out += self.inbuf[:take]
                    del self.inbuf[:take]
                elif self.eof:  # set with self.error, too
                    raise EOFError
                else:
                    self.cond.wait()
        return bytes(out)

    def _chan_write(self, data: bytes) -> None:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            with self.cond:
                limit = min(self.client_maxpacket, self.client_window)
                while limit <= 0:
                    if self.error is not None:
                        raise EOFError
                    self.cond.wait()
                    limit = min(self.client_maxpacket, self.client_window)
                chunk = min(limit, len(view) - offset)
                self.client_window -= chunk
            piece = bytes(view[offset : offset + chunk])
            with self.kex_lock:
                self.send_packet(
                    bytes([_ssh.MSG_CHANNEL_DATA]) + uint32(self.remote_channel) + string(piece)
                )
            offset += chunk


# ===========================================================================
# A fake ``ssh`` executable for the OpenSSH transport tier.
# ===========================================================================

#: Magic host names a test can target to make the fake ssh fail like the real
#: one: ``name -> (stderr line, exit status)``.
FAKE_HOSTS: dict[str, tuple[str, int]] = {
    "refused.invalid": ("ssh: connect to host refused.invalid port 22: Connection refused", 255),
    "unknownhost.invalid": (
        "ssh: Could not resolve hostname unknownhost.invalid: Name or service not known",
        255,
    ),
    "badauth.invalid": ("badauth.invalid: Permission denied (publickey,password).", 255),
    "changedkey.invalid": (
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
        "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n"
        "Host key verification failed.",
        255,
    ),
    "nosubsystem.invalid": ("subsystem request failed on channel 0", 255),
    "timeout.invalid": ("ssh: connect to host timeout.invalid port 22: Operation timed out", 255),
}


def _fake_ssh_host(argv: list[str]) -> str:
    """The host name out of an ``ssh ... -- host sftp`` command line."""
    if "--" in argv:
        rest = argv[argv.index("--") + 1 :]
        return rest[0] if rest else ""
    # Fallback: the last non-option token before "sftp".
    tokens = [a for a in argv[1:] if not a.startswith("-")]
    return tokens[0] if tokens else ""


def fake_ssh_main(argv: list[str], stdin: BinaryIO, stdout: BinaryIO, stderr: BinaryIO) -> int:
    """Behave like ``ssh -s host sftp``: fail for a magic host, else serve SFTP on stdio.

    The SFTP root is ``$XGFAL_FAKE_ROOT``; ``$XGFAL_FAKE_CHECKFILE`` (comma
    separated) turns on ``check-file-name``. A test puts this on ``PATH`` as
    ``ssh`` through :func:`write_fake_ssh`.
    """
    host = _fake_ssh_host(argv)
    if host in FAKE_HOSTS:
        message, status = FAKE_HOSTS[host]
        stderr.write(message.encode() + b"\n")
        stderr.flush()
        return status
    root = os.environ.get("XGFAL_FAKE_ROOT", ".")
    check = tuple(a for a in os.environ.get("XGFAL_FAKE_CHECKFILE", "").split(",") if a)
    server = SFTPServer(root, check_file=check)

    def write(data: bytes) -> None:
        stdout.write(data)
        stdout.flush()

    # serve() swallows the end-of-stream that a client disconnect raises.
    server.serve(lambda n: _read_stdio(stdin, n), write)
    return 0


def _read_stdio(stdin: BinaryIO, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        got = stdin.read(count - len(chunks))
        if not got:
            raise EOFError
        chunks += got
    return bytes(chunks)


def write_fake_ssh(path: str | os.PathLike[str]) -> str:
    """Write an executable ``ssh`` stand-in at ``path`` and return its path."""
    target = os.fspath(path)
    script = (
        f"#!{sys.executable}\n"
        "import sys\n"
        "from xgfalclient.testing.sftp import fake_ssh_main\n"
        "sys.exit(\n"
        "    fake_ssh_main(sys.argv, sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer)\n"
        ")\n"
    )
    with open(target, "w", encoding="ascii") as handle:
        handle.write(script)
    os.chmod(target, 0o755)
    return target
