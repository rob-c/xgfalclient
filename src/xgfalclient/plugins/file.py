"""``file://`` - the local filesystem, behaving as gfal2's file plugin does.

Only ``file:///absolute/path`` is accepted; gfal2 refuses a host part
(``file://localhost/...``) and so does this. Errors are worded as that
plugin words them (``errno reported by local system call ...``), and the
checksum types are the three it supports - ADLER32, MD5 and CRC32, the last
printed in decimal, as gfal2 prints it. Directories are read with libc's
``opendir``/``readdir`` (:mod:`xgfalclient._libc`), as gfal2 reads them, so
``listdir``, ``opendir`` and ``gfal-ls`` give every entry in ``readdir``'s
order - ``.`` and ``..`` included, wherever the filesystem puts them - with
``readdir``'s own ``d_type``. Where that layout isn't known (see that module)
:func:`os.scandir` stands in and ``.`` and ``..`` come first. Entry stats
follow symbolic links, as gfal2's (a ``stat`` per entry) do: a link shows as
what it points to, and a dangling link fails the long listing with
``ENOENT``, as it does in gfal2.

Files ``ctx.open`` creates are ``0744`` before the umask, the mode gfal2's
``open`` passes; a FIFO or other unseekable file is read and written in
order rather than by offset, so the core can stream from ``/proc`` and pipes.

Knowingly different: ``symlink`` takes any target text (a relative path, or
a URL of another scheme, written into the link as it is); gfal2 wants the
target to be a ``file://`` URL too and refuses anything else with
``EPROTONOSUPPORT``.
"""

from __future__ import annotations

import errno
import hashlib
import io
import os
import time
import zlib
from collections.abc import Callable, Iterator
from typing import Any, TypeVar

from .. import _libc
from ..errors import GError, from_oserror
from ..plugin import DirEntry, Plugin, PluginFile
from ..types import DT_DIR, DT_UNKNOWN, Stat, dtype_for_mode
from ..url import scheme_of

__all__ = ["FilePlugin", "LocalFile", "local_path"]

T = TypeVar("T")

_CHUNK = 4 << 20
_TRANSIENT_READ_ERRORS = frozenset(
    getattr(errno, name)
    for name in ("EAGAIN", "EBUSY", "EINTR", "ESTALE", "ETIMEDOUT")
    if hasattr(errno, name)
)


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """Fields that distinguish a file generation even on inode-virtualising FUSE."""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _retry_pause(options: Any, attempts: int) -> None:
    interval = options.integer("CORE", "CONN_RETRY_INTERVAL", 0)
    if options.has("CORE", "CONN_RETRY_INTERVAL"):
        if interval > 0:
            time.sleep(float(interval))
        return
    time.sleep(min(0.05 * 2 ** max(attempts - 1, 0), 1.0))


def local_path(url: str) -> str:
    """The filesystem path in a ``file:///`` URL."""
    return url[len("file://") :]


class LocalFile(PluginFile):
    """An open local file: unbuffered, positional, GIL-releasing I/O.

    Errors are worded as gfal2's file plugin words them.
    """

    def __init__(self, url: str, path: str, flags: int, mode: int, options: Any = None) -> None:
        super().__init__(url)
        self._path = path
        self._flags = flags
        self._mode_bits = mode
        self._options = options
        self._raw = io.FileIO(
            os.open(path, flags, mode), "r+" if flags & os.O_RDWR else _mode(flags)
        )
        #: False for a FIFO, socket or terminal: writes go in order, offsets ignored.
        self._seekable = self._raw.seekable()
        try:
            info = os.fstat(self._raw.fileno())
        except BaseException:
            self._raw.close()
            raise
        self._identity = _file_identity(info)
        self._recovery_chunk: int | None = None

    def fileno(self) -> int:
        return self._raw.fileno()

    def read(self, size: int) -> bytes:
        buffer = bytearray(size)
        count = self.readinto(buffer)
        del buffer[count:]
        return bytes(buffer)

    def readinto(self, buffer: memoryview | bytearray) -> int:
        def read() -> int:
            if self._seekable:  # by position; a pipe has none and is read in order
                _os(self._raw.seek, self.position)
            view = memoryview(buffer)
            if self._recovery_chunk is not None:
                view = view[: self._recovery_chunk]
            return _os(self._raw.readinto, view) or 0

        count = self._recovering_read(read)
        self.position += count
        return count

    def pread(self, offset: int, size: int) -> bytes:
        def read() -> bytes:
            wanted = min(size, self._recovery_chunk) if self._recovery_chunk is not None else size
            return _os(os.pread, self.fileno(), wanted, offset)

        return self._recovering_read(read)

    def _recovering_read(self, operation: Callable[[], T]) -> T:
        """Retry a safe read after reopening the same local file generation."""
        attempts = 0
        while True:
            try:
                return operation()
            except GError as exc:
                attempts += 1
                if not self._can_recover_read(exc, attempts):
                    raise
                self._reopen_read(attempts, exc)

    def _can_recover_read(self, exc: GError, attempts: int) -> bool:
        retries = (
            max(0, int(self._options.integer("CORE", "CONN_RETRY", 3)))
            if self._options is not None
            else 0
        )
        return bool(
            self._seekable
            and not self._flags & (os.O_WRONLY | os.O_RDWR)
            and exc.code in _TRANSIENT_READ_ERRORS
            and attempts <= retries
        )

    def _reopen_read(self, attempts: int, cause: GError) -> None:
        """Replace a stale descriptor, refusing a different file generation."""
        self._recovery_chunk = 4096
        self._raw.close()
        _retry_pause(self._options, attempts)
        try:
            replacement = io.FileIO(os.open(self._path, self._flags, self._mode_bits), "r")
        except OSError as exc:
            raise from_oserror(exc) from exc
        try:
            info = os.fstat(replacement.fileno())
        except OSError as exc:
            replacement.close()
            raise from_oserror(exc) from exc
        if _file_identity(info) != self._identity:
            replacement.close()
            raise GError("local source changed while recovering", errno.ESTALE) from cause
        self._raw = replacement

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        view = memoryview(data)
        done = 0
        while done < len(view):
            if self._seekable:
                written = _os(os.pwrite, self.fileno(), view[done:], offset + done)
            else:
                written = _os(os.write, self.fileno(), view[done:])
            if written <= 0:
                raise from_oserror(OSError(errno.EIO, "write made no progress"))
            done += written
        return done

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        # The real lseek(2), for its errors (EINVAL, ESPIPE on a pipe); the
        # descriptor's offset is synced first, as reads go by position.
        fd = self.fileno()
        _os(os.lseek, fd, self.position, os.SEEK_SET)
        self.position = _os(os.lseek, fd, offset, whence)
        return self.position

    def size(self) -> int:
        return _os(os.fstat, self.fileno()).st_size

    def close(self) -> None:
        if not self.closed:
            self._raw.close()
        super().close()


def _mode(flags: int) -> str:
    return "w" if flags & os.O_WRONLY else "r"


class FilePlugin(Plugin):
    """The ``file`` plugin."""

    name = "file"
    schemes = ("file",)
    option_group = "FILE PLUGIN"
    priority = 600
    event_domain = "GFAL2::PLUGINS::FILE"

    def handles(self, url: str, operation: str) -> bool:
        return scheme_of(url) == "file" and url.startswith("file:///")

    # -- namespace ---------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        return Stat.from_os(_os(os.stat, local_path(url)))

    def lstat(self, url: str) -> Stat:
        return Stat.from_os(_os(os.lstat, local_path(url)))

    def access(self, url: str, mode: int) -> None:
        # os.access only says yes or no; access(2)'s errno is recovered in
        # its order: the path (ENOENT, ENOTDIR, ELOOP...), then the mode
        # word, then a read-only filesystem, then the permission bits.
        path = local_path(url)
        _os(os.stat, path)
        if mode & ~(os.R_OK | os.W_OK | os.X_OK):
            code = errno.EINVAL
        elif os.access(path, mode):
            return
        elif mode & os.W_OK and _os(os.statvfs, path).f_flag & os.ST_RDONLY:
            code = errno.EROFS
        else:
            code = errno.EACCES
        raise from_oserror(OSError(code, os.strerror(code)))

    def chmod(self, url: str, mode: int) -> None:
        _os(os.chmod, local_path(url), mode)

    def mkdir(self, url: str, mode: int) -> None:
        _os(os.mkdir, local_path(url), mode)

    def rmdir(self, url: str) -> None:
        _os(os.rmdir, local_path(url))

    def unlink(self, url: str) -> None:
        path = local_path(url)
        if os.path.isdir(path) and not os.path.islink(path):
            raise from_oserror(OSError(errno.EISDIR, os.strerror(errno.EISDIR)))
        _os(os.unlink, path)

    def rename(self, old: str, new: str) -> None:
        _os(os.rename, local_path(old), local_path(new))

    def readlink(self, url: str) -> str:
        return str(_os(os.readlink, local_path(url)))

    def symlink(self, target: str, link: str) -> None:
        destination = local_path(target) if target.startswith("file://") else target
        _os(os.symlink, destination, local_path(link))

    def opendir(self, url: str) -> Iterator[DirEntry]:
        path = local_path(url)
        return self._entries(path, _os(_read, path))

    def _entries(self, path: str, listing: list[tuple[str, int]]) -> Iterator[DirEntry]:
        for name, kind in listing:
            # d_type is the entry's own, as readdir reports it: a link is DT_LNK
            # although its stat (followed, as gfal2's) describes the target.
            try:
                yield name, Stat.from_os(os.stat(os.path.join(path, name))), kind
            except OSError:
                # Dangling, looping, or vanished: a long listing stats it
                # again and fails as gfal2's does.
                yield name, None, kind

    def listdir(self, url: str) -> list[str]:
        return [name for name, _ in _os(_read, local_path(url))]

    # -- I/O ---------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o744, size: int | None = None) -> PluginFile:
        attempts = 0
        while True:
            try:
                return LocalFile(url, local_path(url), flags, mode, self.options)
            except OSError as exc:
                attempts += 1
                retries = max(0, int(self.options.integer("CORE", "CONN_RETRY", 3)))
                if (
                    flags & (os.O_WRONLY | os.O_RDWR)
                    or exc.errno not in _TRANSIENT_READ_ERRORS
                    or attempts > retries
                ):
                    raise from_oserror(exc) from exc
                _retry_pause(self.options, attempts)

    # -- metadata ------------------------------------------------------------------

    def getxattr(self, url: str, name: str) -> str:
        getter = getattr(os, "getxattr", None)
        if getter is None:
            raise from_oserror(OSError(errno.ENODATA, os.strerror(errno.ENODATA)))
        value: bytes = _os(getter, local_path(url), name)
        return value.decode("utf-8", "replace")

    def setxattr(self, url: str, name: str, value: str, flags: int) -> None:
        setter = getattr(os, "setxattr", None)
        if setter is None:
            raise from_oserror(OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP)))
        _os(setter, local_path(url), name, value.encode("utf-8"), flags)

    def listxattr(self, url: str) -> list[str]:
        lister = getattr(os, "listxattr", None)
        if lister is None:
            return []
        return list(_os(lister, local_path(url)))

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        kind = algorithm.lower()
        if kind not in ("adler32", "crc32", "md5"):
            raise GError(f"Checksum type {algorithm} not supported for local files", errno.ENOSYS)
        # os.open, not open(): like gfal2, a directory opens and then fails to
        # read, which is where its "Error during checksum calculation" comes from.
        fd = _os(os.open, local_path(url), os.O_RDONLY)
        try:
            return _digest(kind, fd, offset, length)
        except OSError as exc:
            code = exc.errno or errno.EIO
            raise GError(
                "Error during checksum calculation, read: "
                f"errno reported by local system call {os.strerror(code)}",
                code,
            ) from exc
        finally:
            os.close(fd)


def _read(path: str) -> list[tuple[str, int]]:
    """``(name, d_type)`` for each entry of ``path``, in ``readdir``'s order."""
    reader = _libc.READER
    if reader is not None:
        return reader.entries(path)
    return _scandir(path)


def _scandir(path: str) -> list[tuple[str, int]]:
    """Where libc can't be read: ``.`` and ``..`` first, then :func:`os.scandir`'s order."""
    found = [(".", DT_DIR), ("..", DT_DIR)]
    for entry in os.scandir(path):
        try:
            kind = dtype_for_mode(entry.stat(follow_symlinks=False).st_mode)
        except OSError:
            kind = DT_UNKNOWN  # vanished since the listing was taken
        found.append((entry.name, kind))
    return found


def _digest(kind: str, fd: int, offset: int, length: int) -> str:
    os.lseek(fd, offset, os.SEEK_SET)
    remaining = length if length > 0 else -1
    buffer = bytearray(_CHUNK)
    view = memoryview(buffer)
    rolling = 1 if kind == "adler32" else 0
    md5 = hashlib.md5() if kind == "md5" else None
    while remaining:
        want = _CHUNK if remaining < 0 else min(_CHUNK, remaining)
        count = os.readv(fd, [view[:want]])
        if not count:
            break
        chunk = view[:count]
        if md5 is not None:
            md5.update(chunk)
        elif kind == "adler32":
            rolling = zlib.adler32(chunk, rolling)
        else:
            rolling = zlib.crc32(chunk, rolling)
        if remaining > 0:
            remaining -= count
    if md5 is not None:
        return md5.hexdigest()
    return f"{rolling:08x}" if kind == "adler32" else str(rolling)


def _os(function: Callable[..., T], *args: Any) -> T:
    """Call a local ``os`` function, rewording its ``OSError`` as gfal2 does."""
    try:
        return function(*args)
    except OSError as exc:
        raise from_oserror(exc) from exc
