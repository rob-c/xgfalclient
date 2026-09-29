"""Mode strings for ``gfal-stat`` and ``gfal-ls -l``, exactly as gfal2-util prints them.

gfal2-util's rendering has quirks that scripts may have come to rely on, so
they are kept: a FIFO is ``f`` (not ``p``), a symbolic link is ``-`` (it has
no case for links), and set-uid/gid/sticky bits are not shown.
"""

from __future__ import annotations

import stat

__all__ = ["file_type_str", "file_mode_str"]

_TYPES = {
    stat.S_IFBLK: "block device",
    stat.S_IFCHR: "character device",
    stat.S_IFDIR: "directory",
    stat.S_IFIFO: "fifo",
    stat.S_IFLNK: "symbolic link",
    stat.S_IFREG: "regular file",
    stat.S_IFSOCK: "socket",
}


def file_type_str(kind: int) -> str:
    """``stat.S_IFMT(mode)`` in words."""
    return _TYPES.get(kind, "unknown")


def _triplet(mode: int) -> str:
    return (
        ("r" if mode & stat.S_IROTH else "-")
        + ("w" if mode & stat.S_IWOTH else "-")
        + ("x" if mode & stat.S_IXOTH else "-")
    )


def _type_letter(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "d"
    if stat.S_ISBLK(mode):
        return "b"
    if stat.S_ISCHR(mode):
        return "c"
    if stat.S_ISFIFO(mode):
        return "f"
    if stat.S_ISSOCK(mode):
        return "s"
    return "-"


def file_mode_str(mode: int) -> str:
    """``drwxr-xr-x`` and friends."""
    return _type_letter(mode) + _triplet(mode >> 6) + _triplet(mode >> 3) + _triplet(mode)
