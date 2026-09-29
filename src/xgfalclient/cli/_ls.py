"""``gfal-ls``: gfal2-util 1.9.1's listing, column for column.

Entries come out in the order the storage returns them (gfal2-util does not
sort), and ``--full-time`` selects ``long-iso``, not ``full-iso`` as its help
says: both are gfal2-util's behaviour, kept because scripts parse the output.
Layout and time formats are gfal2-util's (Apache-2.0, (c) CERN), reimplemented.
"""

from __future__ import annotations

import math
import os
import stat
import sys
from datetime import datetime
from typing import Callable

from ..types import Stat
from ._base import Command, Spec, arg, out, stdout_isatty, surl
from ._utils import file_mode_str

__all__ = ["SPECS", "size_to_human", "TIME_FORMATS"]


def _full_iso(stamp: int) -> str:
    return datetime.fromtimestamp(stamp).strftime("%Y-%m-%d %H:%M:%S.%f +0000")


def _long_iso(stamp: int) -> str:
    return datetime.fromtimestamp(stamp).strftime("%Y-%m-%d %H:%M")


def _recent(when: datetime) -> bool:
    """Within about six months, by gfal2-util's reckoning of 30-day months."""
    return (datetime.now() - when).days / 30 < 6


def _iso(stamp: int) -> str:
    when = datetime.fromtimestamp(stamp)
    return when.strftime("%m-%d %H:%M" if _recent(when) else "%Y-%m-%d")


def _locale(stamp: int) -> str:
    when = datetime.fromtimestamp(stamp)
    day = when.strftime("%d").lstrip("0").rjust(2)
    return when.strftime(f"%b {day} %H:%M" if _recent(when) else f"%b {day}  %Y")


TIME_FORMATS: dict[str, Callable[[int], str]] = {
    "full-iso": _full_iso,
    "long-iso": _long_iso,
    "iso": _iso,
    "locale": _locale,
}


def size_to_human(size: float) -> str:
    """``1.5K``, ``234M``: one decimal below 10, rounded up."""
    symbols = ["", "K", "M", "G", "T", "P"]
    degree = 0
    while float(size) >= 1024.0 and degree < len(symbols) - 1:
        size = float(size) / 1024.0
        degree += 1
    if size < 10.0:
        return f"{math.ceil(size * 10.0) / 10.0:0.1f}{symbols[degree]}"
    return f"{math.ceil(size):0.0f}{symbols[degree]}"


def _ls_colors() -> dict[str, str]:
    """``LS_COLORS`` as a dict, warning about entries gfal2-util cannot parse."""
    colors: dict[str, str] = {}
    for entry in os.environ.get("LS_COLORS", "").split(":"):
        if "=" not in entry:
            continue
        parts = entry.split("=")
        if len(parts) == 2:
            colors[parts[0]] = parts[1]
        else:
            sys.stderr.write(f"unparsable value for LS_COLORS environment variable: {entry}\n")
    return colors


class _Lister:
    def __init__(self, cmd: Command) -> None:
        self.cmd = cmd
        self.params = cmd.params
        if self.params.color == "always":
            self.colorize = True
        else:
            self.colorize = self.params.color == "auto" and stdout_isatty()
        self.colors = _ls_colors()

    def color(self, name: str, mode: int | None) -> str:
        if not self.colorize:
            return name
        color = "037"
        if mode is None:
            color = self.colors.get("no", color)
        elif stat.S_ISDIR(mode):
            color = self.colors.get("di", color)
        elif stat.S_ISLNK(mode):
            color = self.colors.get("ln", color)
        elif mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            color = self.colors.get("ex", color)
        return f"\033[{color}m{name}\033[0m"

    def extra(self, url: str) -> list[str]:
        if not self.params.long:
            return []
        return [self.cmd.context.getxattr(url, name) for name in self.params.xattr]

    def entry(self, name: str, info: Stat | None, extra: list[str]) -> None:
        """One line of output: long form given ``info``, just the name without it."""
        if info is None:
            out(f"{self.color(name, None)}\n")
            return
        size: object = info.st_size
        width = 9
        if self.params.human_readable:
            size, width = size_to_human(info.st_size), 4
        date = TIME_FORMATS[self.params.time_style](info.st_mtime)
        out(
            f"{file_mode_str(info.st_mode)} {str(info.st_nlink).rjust(3)} "
            f"{str(info.st_uid).ljust(5)} {str(info.st_gid).ljust(5)} "
            f"{str(size).rjust(width)} {date.ljust(11)} "
            f"{self.color(name, info.st_mode)}\t{chr(9).join(extra)}\n"
        )


def ls(cmd: Command) -> int:
    params = cmd.params
    if params.full_time:
        params.time_style = "long-iso"
    lister = _Lister(cmd)
    info = cmd.context.stat(params.file)
    if not stat.S_ISDIR(info.st_mode) or params.directory:
        lister.entry(params.file, info if params.long else None, lister.extra(params.file))
        return 0
    directory = cmd.context.opendir(params.file)
    while True:
        entry: Stat | None = None
        if params.long:
            dirent, entry = directory.readpp()
        else:
            dirent = directory.read()
        if dirent is None or not dirent.d_name:
            break
        if not params.all and dirent.d_name.startswith("."):
            continue
        lister.entry(dirent.d_name, entry, lister.extra(os.path.join(params.file, dirent.d_name)))
    return 0


SPECS = {
    "ls": Spec(
        "List directory's contents",
        [
            arg("-a", "--all", action="store_true", help="display hidden files"),
            arg("-l", "--long", action="store_true", help="long listing format"),
            arg(
                "-d",
                "--directory",
                action="store_true",
                help="list directory entries instead of contents",
            ),
            arg(
                "-H",
                "--human-readable",
                action="store_true",
                help="with -l, prints size in human readable format (e.g., 1K 234M 2G",
            ),
            arg(
                "--xattr",
                type=str,
                action="append",
                default=[],
                help="query additional attributes. Can be specified multiple times. "
                "Only works for --long output",
            ),
            arg(
                "--time-style",
                type=str,
                default="locale",
                choices=list(TIME_FORMATS),
                help="time style",
            ),
            arg("--full-time", action="store_true", help="same as --time-style=full-iso"),
            arg(
                "--color",
                type=str,
                choices=["always", "never", "auto"],
                default="auto",
                help="print colored entries with -l",
            ),
            arg("file", type=surl, help="file's uri"),
        ],
        ls,
    ),
}
