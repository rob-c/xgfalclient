"""The records gfal2 hands back: ``Stat`` and ``Dirent``.

Both mirror the bindings field for field. ``str(stat)`` prints the same
nine lines gfal2 does, with the mode in bare octal (``mode: 100644``),
because scripts have been known to parse it.
"""

from __future__ import annotations

import os
import stat as _stat
from typing import Any

__all__ = ["Stat", "Dirent", "DT_UNKNOWN", "DT_DIR", "DT_REG", "DT_LNK", "dtype_for_mode"]

DT_UNKNOWN = 0
DT_DIR = 4
DT_REG = 8
DT_LNK = 10

_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_atime",
    "st_mtime",
    "st_ctime",
)


class Stat:
    """``struct stat`` as gfal2 fills it; unknown fields are zero.

    Not every protocol knows every field - WebDAV has no inode, SRM no
    ``nlink`` - and gfal2 leaves those at zero rather than inventing them.
    """

    __slots__ = _FIELDS

    st_dev: int
    st_ino: int
    st_mode: int
    st_nlink: int
    st_uid: int
    st_gid: int
    st_size: int
    st_atime: int
    st_mtime: int
    st_ctime: int

    def __init__(self, **fields: int) -> None:
        for name in _FIELDS:
            setattr(self, name, int(fields.pop(name, 0)))
        if fields:
            raise TypeError(f"unknown Stat field(s): {', '.join(sorted(fields))}")

    @classmethod
    def from_os(cls, result: os.stat_result) -> Stat:
        """Copy a local ``os.stat`` result, truncating times to seconds."""
        return cls(**{name: int(getattr(result, name)) for name in _FIELDS})

    # -- convenience beyond the bindings ---------------------------------------

    def is_dir(self) -> bool:
        return _stat.S_ISDIR(self.st_mode)

    def is_file(self) -> bool:
        return _stat.S_ISREG(self.st_mode)

    def is_link(self) -> bool:
        return _stat.S_ISLNK(self.st_mode)

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in _FIELDS}

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Stat):
            return NotImplemented
        return self.as_dict() == other.as_dict()

    __hash__ = None  # type: ignore[assignment]  # mutable, like gfal2's

    def __str__(self) -> str:
        return (
            f"uid: {self.st_uid}\n"
            f"gid: {self.st_gid}\n"
            f"mode: {self.st_mode:o}\n"
            f"size: {self.st_size}\n"
            f"nlink: {self.st_nlink}\n"
            f"ino: {self.st_ino}\n"
            f"ctime: {self.st_ctime}\n"
            f"atime: {self.st_atime}\n"
            f"mtime: {self.st_mtime}\n"
        )

    __repr__ = __str__


def dtype_for_mode(mode: int) -> int:
    """The ``d_type`` that goes with a ``st_mode``."""
    if _stat.S_ISDIR(mode):
        return DT_DIR
    if _stat.S_ISLNK(mode):
        return DT_LNK
    if _stat.S_ISREG(mode):
        return DT_REG
    return DT_UNKNOWN


class Dirent:
    """One directory entry. An empty name marks the end of a listing."""

    __slots__ = ("d_ino", "d_name", "d_off", "d_reclen", "d_type")

    def __init__(
        self, d_name: str = "", d_type: int = DT_UNKNOWN, d_ino: int = 0, d_off: int = 0
    ) -> None:
        self.d_name = d_name
        self.d_type = d_type
        self.d_ino = d_ino
        self.d_off = d_off
        self.d_reclen = _reclen(d_name) if d_name else 0

    def __repr__(self) -> str:
        return f"Dirent(d_name={self.d_name!r}, d_type={self.d_type})"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Dirent):
            return NotImplemented
        return (self.d_name, self.d_type, self.d_ino) == (other.d_name, other.d_type, other.d_ino)

    __hash__ = None  # type: ignore[assignment]


def _reclen(name: str) -> int:
    """``d_reclen`` as glibc computes it: header plus name, 8-byte aligned."""
    return (19 + len(name.encode("utf-8", "surrogateescape")) + 1 + 7) & ~7
