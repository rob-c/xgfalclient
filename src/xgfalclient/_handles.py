"""The handles ``ctx.open`` and ``ctx.opendir`` return: gfal2's ``FileType`` and ``DirectoryType``.

They are thin: each holds the plugin's own :class:`~xgfalclient.plugin.PluginFile`
or directory iterator and routes every call through the context's
``_guard``, so a failure is a ``GError``, a call counts as a running
operation for ``cancel()``, and a cancelled call fails as cancelled. What
gfal2's core adds on top - ``readpp`` stat-ing an entry the plugin listed
without one, ``d_type`` from the mode, the running ``d_off`` - is here too.

These classes are part of :mod:`xgfalclient.context`'s public surface (and of
``Gfal2Context`` itself, as gfal2 binds them on the class); that module
re-exports them, and they are only defined here to keep the context's
module to the context. Their ``repr`` and behaviour are unchanged by the
move.
"""

from __future__ import annotations

import errno
import logging
import os
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, Self, cast

from .errors import GError
from .plugin import O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, DirEntry
from .types import Dirent, Stat, dtype_for_mode

if TYPE_CHECKING:
    from .context import Gfal2Context

__all__ = ["DirectoryType", "FileType"]

_log = logging.getLogger("gfal2")

#: The bindings' three ``open`` flags; anything else is refused before any I/O.
_OPEN_FLAGS = {
    "r": O_RDONLY,
    "w": O_WRONLY | O_CREAT | O_TRUNC,
    "rw": O_RDWR | O_CREAT,
}


class FileType:
    """An open file (``ctx.open``). ``read`` returns ``str``; ``read_bytes`` bytes.

    python3-gfal2's ``gfal2.FileType`` (a ``gfal2_open`` descriptor). The
    plugin's file is owned by this handle: ``close()``, the end of a
    ``with`` block or garbage collection closes it, whichever comes first.
    ``read_bytes``, ``pread_bytes``, ``readinto`` and the context-manager
    protocol are extensions; the bindings' ``read`` returns text only.
    """

    def __init__(self, context: Gfal2Context, path: str, flag: str) -> None:
        """Open ``path`` now; a bad ``flag`` is the bindings' ``RuntimeError``, not a ``GError``."""
        if flag not in _OPEN_FLAGS:
            raise RuntimeError("Invalid open flag, must be r, w, or rw")
        self._context = context
        self.path = path
        self._file = context._open(path, _OPEN_FLAGS[flag])

    def read(self, count: int) -> str:
        """``gfal2_read``: up to ``count`` bytes as text; ``""`` at end of file.

        Bytes that are not UTF-8 come back surrogate-escaped instead of
        raising (the bindings raise ``UnicodeDecodeError`` and lose the
        data); ``read_bytes`` avoids the question.
        """
        return self.read_bytes(count).decode("utf-8", "surrogateescape")

    def read_bytes(self, count: int) -> bytes:
        """Up to ``count`` bytes from the cursor; may be short before end of file."""
        return cast(bytes, self._call(self._file.read, count))

    def readinto(self, buffer: bytearray | memoryview) -> int:
        """Fill ``buffer`` from the cursor without an intermediate ``bytes``; the count read."""
        return cast(int, self._call(self._file.readinto, buffer))

    def pread(self, offset: int, count: int) -> str:
        """``gfal2_pread``: as :meth:`read` at ``offset``, the cursor unmoved."""
        return self.pread_bytes(offset, count).decode("utf-8", "surrogateescape")

    def pread_bytes(self, offset: int, count: int) -> bytes:
        """:meth:`pread` as bytes; ``ENOSYS`` from a streaming-only protocol."""
        return cast(bytes, self._call(self._file.pread, offset, count))

    def write(self, data: str | bytes | bytearray | memoryview) -> int:
        """``gfal2_write`` at the cursor; text is written as UTF-8. The count written."""
        return cast(int, self._call(self._file.write, _as_bytes(data)))

    def pwrite(self, data: str | bytes | bytearray | memoryview, offset: int) -> int:
        """``gfal2_pwrite`` at ``offset``, the cursor unmoved."""
        return cast(int, self._call(self._file.pwrite, _as_bytes(data), offset))

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """``gfal2_lseek``: the new position; ``SEEK_END`` needs a plugin that knows the size."""
        return cast(int, self._call(self._file.lseek, offset, whence))

    def close(self) -> None:
        """``gfal2_close``; closing twice is harmless.

        For a written file this is where many protocols commit (an HTTP
        upload completes, an xrootd ``kXR_close`` is acknowledged), so a
        failure here is a failed write and is raised.
        """
        if not self._file.closed:
            self._call(self._file.close)

    @property
    def closed(self) -> bool:
        """Whether :meth:`close` has run (an extension)."""
        return bool(self._file.closed)

    def _call(self, method: Any, *args: Any) -> Any:
        """Run one file operation through the context's ``_guard``; ``EBADF`` once closed."""
        if self._file.closed:
            raise GError("I/O operation on a closed file", errno.EBADF)
        return self._context._guard(method, *args)

    def __enter__(self) -> Self:
        """The handle itself; the block's end closes it."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close the file; a close failure propagates, as a failed write should."""
        self.close()

    def __del__(self) -> None:
        """Close a handle its owner forgot, quietly: a finaliser has nobody to raise to.

        Unlike :meth:`close`, this bypasses ``_guard``: a finaliser may run
        on any thread at any time, including while a ``cancel()`` drains,
        and must neither be refused nor counted.
        """
        file = getattr(self, "_file", None)
        if file is not None and not file.closed:
            try:
                file.close()
            except Exception:  # closing from a finaliser must never raise
                _log.debug("error closing %s from its finaliser", self.path, exc_info=True)

    def __repr__(self) -> str:
        """``<xgfalclient.FileType 'url'>``."""
        return f"<xgfalclient.FileType {self.path!r}>"


def _as_bytes(data: str | bytes | bytearray | memoryview) -> bytes | bytearray | memoryview:
    """``str`` as UTF-8 (surrogates restored to their bytes); buffers passed through uncopied."""
    return data.encode("utf-8", "surrogateescape") if isinstance(data, str) else data


class DirectoryType:
    """An open directory (``ctx.opendir``). ``read()`` returns an empty ``Dirent`` at the end.

    python3-gfal2's ``gfal2.DirectoryType`` (``gfal2_opendir``/``readdir``/
    ``readdirpp``). Iterating it (``for d in ctx.opendir(url)``) is an
    extension. There is no ``close``: the plugin's iterator is released with
    the handle, as the bindings close the directory in their destructor.
    """

    def __init__(self, context: Gfal2Context, path: str) -> None:
        """Open ``path`` now, so a missing directory fails here and not at the first read."""
        self._context = context
        self.path = path
        self._entries: Iterator[DirEntry] = context._opendir(path)
        self._offset = 0

    def _next(self) -> tuple[str, Stat | None, int | None] | None:
        """``(name, stat, d_type)``; ``d_type`` is ``None`` unless the plugin gave one."""
        try:
            entry: DirEntry = self._context._guard(next, self._entries)
        except StopIteration:
            return None
        return (entry[0], entry[1], entry[2] if len(entry) == 3 else None)

    def read(self) -> Dirent:
        """``gfal2_readdir``: the next entry, or an empty ``Dirent`` at the end.

        ``d_type`` is the plugin's own when it gave one (a link stays a link),
        else derived from the entry's mode, else ``DT_UNKNOWN``. ``d_off`` is
        the entry's 1-based position, as gfal2 numbers it.
        """
        entry = self._next()
        if entry is None:
            return Dirent()
        name, info, dtype = entry
        self._offset += 1
        if dtype is None:
            dtype = dtype_for_mode(info.st_mode) if info is not None else 0
        ino = info.st_ino if info is not None else 0
        return Dirent(name, dtype, ino, self._offset)

    def readpp(self) -> tuple[Dirent, Stat] | tuple[None, None]:
        """``gfal2_readdirpp``: ``(Dirent, Stat)``, or ``(None, None)`` at the end.

        An entry the plugin listed without metadata is ``stat``-ed here, one
        request per entry - what gfal2's core does for plugins without a
        native ``readdirpp``.
        """
        entry = self._next()
        if entry is None:
            return None, None
        name, info, dtype = entry
        if info is None:
            info = self._context.stat(_child(self.path, name))
        self._offset += 1
        if dtype is None:
            dtype = dtype_for_mode(info.st_mode)
        return Dirent(name, dtype, info.st_ino, self._offset), info

    def __iter__(self) -> Iterator[Dirent]:
        """Each remaining entry via :meth:`read`, stopping at the empty one."""
        while True:
            entry = self.read()
            if not entry.d_name:
                return
            yield entry

    def __repr__(self) -> str:
        """``<xgfalclient.DirectoryType 'url'>``."""
        return f"<xgfalclient.DirectoryType {self.path!r}>"


def _child(url: str, name: str) -> str:
    """The URL of entry ``name`` in directory ``url``, keeping the directory's query.

    Not :func:`xgfalclient.url.join`: this must also work for the opaque
    ``lfn:`` form, which ``join`` cannot parse, and ``name`` is used as the
    plugin returned it (no stripping of slashes).
    """
    head, sep, query = url.partition("?")
    joined = head if head.endswith("/") else head + "/"
    return joined + name + (sep + query if sep else "")
