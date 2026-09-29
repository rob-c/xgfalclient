"""The ``gfal-*`` commands: a drop-in for gfal2-util 1.9.1.

Each console script is one of the functions below, taking the arguments
(default ``sys.argv[1:]``) and returning the exit status::

    gfal-ls -l davs://se.example.org/store/
    python -m xgfalclient.cli ls -l davs://se.example.org/store/

Options, output and exit statuses are gfal2-util's, so scripts that parse
``gfal-ls -l`` or ``gfal-stat`` keep working. Only the module a command needs
is imported.
"""

from __future__ import annotations

import importlib
from collections.abc import Sequence

__all__ = [
    "COMMANDS",
    "archivepoll",
    "bringonline",
    "cat",
    "chmod",
    "copy",
    "evict",
    "ls",
    "mkdir",
    "rename",
    "rm",
    "run",
    "save",
    "stat",
    "sum",
    "token",
    "xattr",
]

#: Command name to the module (in this package) that defines it.
COMMANDS = {
    "archivepoll": "tape",
    "bringonline": "tape",
    "cat": "commands",
    "chmod": "commands",
    "copy": "copy",
    "evict": "tape",
    "ls": "ls",
    "mkdir": "commands",
    "rename": "commands",
    "rm": "rm",
    "save": "commands",
    "stat": "commands",
    "sum": "commands",
    "token": "commands",
    "xattr": "commands",
}


def run(command: str, argv: Sequence[str] | None = None) -> int:
    """Run ``gfal-<command>``; its exit status."""
    from ._base import main

    module = importlib.import_module(f"{__name__}._{COMMANDS[command]}")
    return main(command, module.SPECS[command], argv)


def archivepoll(argv: Sequence[str] | None = None) -> int:
    return run("archivepoll", argv)


def bringonline(argv: Sequence[str] | None = None) -> int:
    return run("bringonline", argv)


def cat(argv: Sequence[str] | None = None) -> int:
    return run("cat", argv)


def chmod(argv: Sequence[str] | None = None) -> int:
    return run("chmod", argv)


def copy(argv: Sequence[str] | None = None) -> int:
    return run("copy", argv)


def evict(argv: Sequence[str] | None = None) -> int:
    return run("evict", argv)


def ls(argv: Sequence[str] | None = None) -> int:
    return run("ls", argv)


def mkdir(argv: Sequence[str] | None = None) -> int:
    return run("mkdir", argv)


def rename(argv: Sequence[str] | None = None) -> int:
    return run("rename", argv)


def rm(argv: Sequence[str] | None = None) -> int:
    return run("rm", argv)


def save(argv: Sequence[str] | None = None) -> int:
    return run("save", argv)


def stat(argv: Sequence[str] | None = None) -> int:
    return run("stat", argv)


def sum(argv: Sequence[str] | None = None) -> int:
    return run("sum", argv)


def token(argv: Sequence[str] | None = None) -> int:
    return run("token", argv)


def xattr(argv: Sequence[str] | None = None) -> int:
    return run("xattr", argv)
