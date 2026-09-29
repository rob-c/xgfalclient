"""``file://`` - the local filesystem, behaving as gfal2's file plugin does.

Only ``file:///absolute/path`` is accepted; gfal2 refuses a host part
(``file://localhost/...``) and so does this. Errors are worded as that
plugin words them (``errno reported by local system call ...``), and the
checksum types are the three it supports - ADLER32, MD5 and CRC32, the last
printed in decimal, as gfal2 prints it. Directory listings include ``.`` and
``..`` because ``readdir`` does.
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
from ..plugin import Plugin, PluginFile
from ..types import Stat
from ..url import scheme_of

__all__ = ["FilePlugin", "LocalFile", "local_path"]

T = TypeVar("T")

_CHUNK = 4 << 20


def local_path(url: str) -> str:
    """The filesystem path in a ``file:///`` URL."""
    return url[len("file://") :]


class LocalFile(PluginFile):
    """An open local file: unbuffered, positional, GIL-releasing I/O."""

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
        data = os.pread(self.fileno(), size, self.position)
        self.position += len(data)
        return data

    def readinto(self, buffer: memoryview | bytearray) -> int:
        self._raw.seek(self.position)
        count = self._raw.readinto(buffer) or 0
        self.position += count
        return count

    def pread(self, offset: int, size: int) -> bytes:
        return os.pread(self.fileno(), size, offset)

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        view = memoryview(data)
        done = 0
        while done < len(view):
            if self._seekable:
                done += os.pwrite(self.fileno(), view[done:], offset + done)
            else:
                done += os.write(self.fileno(), view[done:])
        return done

    def size(self) -> int:
        return os.fstat(self.fileno()).st_size

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
        path = local_path(url)
        if not os.access(path, mode):
            code = errno.ENOENT if not os.path.lexists(path) else errno.EACCES
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

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        path = local_path(url)
        entries = list(_os(os.scandir, path))
        return self._entries(path, entries)

    def _entries(
        self, path: str, entries: list[os.DirEntry[str]]
    ) -> Iterator[tuple[str, Stat | None]]:
        yield ".", self.stat("file://" + path)
        yield "..", self.stat("file://" + os.path.join(path, ".."))
        for entry in entries:
            try:
                yield entry.name, Stat.from_os(entry.stat(follow_symlinks=False))
            except OSError:
                yield entry.name, None  # vanished since the listing was taken

    def listdir(self, url: str) -> list[str]:
        return [".", "..", *(entry.name for entry in _os(os.scandir, local_path(url)))]

    # -- I/O ---------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
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
        kind = algorithm.strip().lower()
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
