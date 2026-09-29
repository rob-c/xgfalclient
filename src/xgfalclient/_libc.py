"""Directory entries in ``readdir``'s own order, through libc over ``ctypes``.

gfal2's file plugin lists a directory with ``opendir``/``readdir``, so ``.``
and ``..`` come wherever the filesystem puts them and each entry carries
``readdir``'s own ``d_type``. :func:`os.scandir` drops those two names, which
loses their place; this module calls the C library directly instead.

``struct dirent`` differs by platform, so only layouts known here are read:

* Linux: glibc's ``struct dirent64`` from ``readdir64`` (``d_ino``,
  ``d_off``, ``d_reclen``, ``d_type``, ``d_name``: type at 18, name at 19),
  on every architecture. Without ``readdir64`` (musl) plain ``readdir`` has
  the same layout, but is trusted only on 64-bit, where ``ino_t`` and
  ``off_t`` are 64-bit whatever the libc.
* macOS: the 64-bit-inode ``struct dirent`` (``d_ino``, ``d_seekoff``,
  ``d_reclen``, ``d_namlen``, ``d_type``: type at 20, name at 21), through
  ``opendir$INODE64``/``readdir$INODE64`` where those exist (x86-64, where the
  plain names are the old 32-bit-inode ABI) and the plain names otherwise
  (arm64, where they are the only ABI).

Anywhere else, or when libc or a symbol is missing, :data:`READER` is
``None`` and callers fall back to :func:`os.scandir`.

The library is opened as a :class:`ctypes.CDLL` with ``use_errno``, so each
call releases the GIL and ``errno`` is kept per thread by ``ctypes``. A
``DIR`` stream is private to one :meth:`Reader.entries` call and closed
before it returns, so concurrent listings never share one.
"""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

__all__ = ["Layout", "Reader", "READER", "layout", "load"]


@dataclass(frozen=True)
class Layout:
    """Where ``d_type`` and ``d_name`` sit in a ``struct dirent``, and the calls to use."""

    type_offset: int
    name_offset: int
    opendir: str
    readdir: str
    closedir: str = "closedir"


def layout(system: str, pointer_size: int, has: Callable[[str], bool]) -> Layout | None:
    """The layout for ``system`` (a :data:`sys.platform`), given which symbols libc ``has``."""
    if system.startswith("linux"):
        if has("readdir64"):
            return Layout(18, 19, "opendir", "readdir64")
        if pointer_size == 8:
            return Layout(18, 19, "opendir", "readdir")
        return None
    if system == "darwin":
        if has("readdir$INODE64"):
            return Layout(20, 21, "opendir$INODE64", "readdir$INODE64")
        return Layout(20, 21, "opendir", "readdir")
    return None


class Reader:
    """``opendir``/``readdir``/``closedir`` from one library, read with one :class:`Layout`."""

    def __init__(self, lib: Any, shape: Layout) -> None:
        self._layout = shape
        self._opendir = getattr(lib, shape.opendir)
        self._opendir.argtypes = [ctypes.c_char_p]
        self._opendir.restype = ctypes.c_void_p
        self._readdir = getattr(lib, shape.readdir)
        self._readdir.argtypes = [ctypes.c_void_p]
        self._readdir.restype = ctypes.c_void_p
        self._closedir = getattr(lib, shape.closedir)
        self._closedir.argtypes = [ctypes.c_void_p]
        self._closedir.restype = ctypes.c_int

    def entries(self, path: str) -> list[tuple[str, int]]:
        """``(name, d_type)`` for every entry of ``path``, ``.`` and ``..`` included, in order.

        Raises :class:`OSError` with ``opendir``'s or ``readdir``'s ``errno``.
        """
        ctypes.set_errno(0)
        stream = self._opendir(os.fsencode(path))
        if not stream:
            _raise(path)
        found: list[tuple[str, int]] = []
        try:
            while True:
                # NULL is both the end and an error; only errno tells them apart.
                ctypes.set_errno(0)
                entry = self._readdir(stream)
                if not entry:
                    if ctypes.get_errno():
                        _raise(path)
                    return found
                kind = ctypes.c_ubyte.from_address(entry + self._layout.type_offset).value
                name = ctypes.string_at(entry + self._layout.name_offset)
                found.append((os.fsdecode(name), kind))
        finally:
            self._closedir(stream)


def _raise(path: str) -> None:
    code = ctypes.get_errno()
    raise OSError(code, os.strerror(code), path)


def _open() -> Any:
    try:
        return ctypes.CDLL(None, use_errno=True)
    except (OSError, TypeError):  # TypeError: no NULL handle (Windows)
        return None


def load(system: str, pointer_size: int, opener: Callable[[], Any] = _open) -> Reader | None:
    """A :class:`Reader` for this platform, or ``None`` to fall back to :func:`os.scandir`."""
    lib = opener()
    if lib is None:
        return None
    shape = layout(system, pointer_size, lambda name: hasattr(lib, name))
    if shape is None:
        return None
    try:
        return Reader(lib, shape)
    except AttributeError:  # a symbol the layout names is missing
        return None


#: The reader :mod:`xgfalclient.plugins.file` uses; ``None`` where there is none.
READER = load(sys.platform, ctypes.sizeof(ctypes.c_void_p))
