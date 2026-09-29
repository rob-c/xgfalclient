"""``file://`` - the local filesystem, behaving as gfal2's file plugin does.

Only ``file:///absolute/path`` is accepted; gfal2 refuses a host part
(``file://localhost/...``) and so does this. Errors are worded as that
plugin words them (``errno reported by local system call ...``), and the
checksum types are the three it supports - ADLER32, MD5 and CRC32, the last
printed in decimal, as gfal2 prints it. Directory listings include ``.`` and
``..`` because ``readdir`` does, and their stats follow symbolic links, as
gfal2's (a ``stat`` per entry) do: a link shows as what it points to, and a
dangling link fails the long listing with ``ENOENT``, as it does in gfal2.

Files ``ctx.open`` creates are ``0744`` before the umask, the mode gfal2's
``open`` passes; a FIFO or other unseekable file is read and written in
order rather than by offset, so the core can stream from ``/proc`` and pipes.
"""

from __future__ import annotations

import errno
import hashlib
import io
import os
import zlib
from collections.abc import Callable, Iterator
from typing import Any, TypeVar

from ..errors import GError, from_oserror
from ..plugin import DirEntry, Plugin, PluginFile
from ..types import DT_UNKNOWN, Stat, dtype_for_mode
from ..url import scheme_of

__all__ = ["FilePlugin", "LocalFile", "local_path"]

T = TypeVar("T")

_CHUNK = 4 << 20


def local_path(url: str) -> str:
    """The filesystem path in a ``file:///`` URL."""
    return url[len("file://") :]


class LocalFile(PluginFile):
    """An open local file: unbuffered, positional, GIL-releasing I/O.

    Errors are worded as gfal2's file plugin words them.
    """

    def __init__(self, url: str, path: str, flags: int, mode: int) -> None:
        super().__init__(url)
        self._raw = io.FileIO(
            os.open(path, flags, mode), "r+" if flags & os.O_RDWR else _mode(flags)
        )
        #: False for a FIFO, socket or terminal: writes go in order, offsets ignored.
        self._seekable = self._raw.seekable()

    def fileno(self) -> int:
        return self._raw.fileno()

    def read(self, size: int) -> bytes:
        buffer = bytearray(size)
        count = self.readinto(buffer)
        del buffer[count:]
        return bytes(buffer)

    def readinto(self, buffer: memoryview | bytearray) -> int:
        if self._seekable:  # by position; a pipe has none and is read in order
            _os(self._raw.seek, self.position)
        count: int = _os(self._raw.readinto, buffer) or 0
        self.position += count
        return count

    def pread(self, offset: int, size: int) -> bytes:
        return _os(os.pread, self.fileno(), size, offset)  # type: ignore[no-any-return]

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        view = memoryview(data)
        done = 0
        while done < len(view):
            if self._seekable:
                done += _os(os.pwrite, self.fileno(), view[done:], offset + done)
            else:
                done += _os(os.write, self.fileno(), view[done:])
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
        entries = list(_os(os.scandir, path))
        return self._entries(path, entries)

    def _entries(self, path: str, entries: list[os.DirEntry[str]]) -> Iterator[DirEntry]:
        yield ".", self.stat("file://" + path)
        yield "..", self.stat("file://" + os.path.join(path, ".."))
        for entry in entries:
            # d_type is the entry's own, as readdir reports it: a link is DT_LNK
            # although its stat (followed, as gfal2's) describes the target.
            try:
                kind = dtype_for_mode(entry.stat(follow_symlinks=False).st_mode)
            except OSError:
                kind = DT_UNKNOWN  # vanished since the listing was taken
            try:
                yield entry.name, Stat.from_os(entry.stat()), kind
            except OSError:
                # Dangling, looping, or vanished: a long listing stats it
                # again and fails as gfal2's does.
                yield entry.name, None, kind

    def listdir(self, url: str) -> list[str]:
        return [".", "..", *(entry.name for entry in _os(os.scandir, local_path(url)))]

    # -- I/O ---------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o744, size: int | None = None) -> PluginFile:
        try:
            return LocalFile(url, local_path(url), flags, mode)
        except OSError as exc:
            raise from_oserror(exc) from exc

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
