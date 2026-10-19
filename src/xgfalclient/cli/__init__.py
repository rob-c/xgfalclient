"""The ``gfal-*`` commands: a drop-in for gfal2-util 1.9.1.

Each console script is one of the functions below, taking the arguments
(default ``sys.argv[1:]``) and returning the exit status::

    gfal-ls -l davs://se.example.org/store/
    python -m xgfalclient.cli ls -l davs://se.example.org/store/

Options, output and exit statuses are gfal2-util's, so scripts that parse
``gfal-ls -l`` or ``gfal-stat`` keep working. Only the module a command needs
is imported.

Also installed, as gfal2-util and gfal2 install them: the deprecated
``gfal-legacy-register``, ``-unregister``, ``-replicas`` (an LFC entry's
replicas) and ``-bringonline``; and ``gfal2_version`` and
``gfal_srm_ifce_version``, which print the versions of the gfal2 and
srm-ifce releases whose behaviour is reproduced.

For code that imports gfal2-util itself (``from gfal2_util.shell import
Gfal2Shell``), the ``gfal2_util`` package runs these same commands.

Layout: :mod:`._base` is the shared machinery (parser, logging, the worker
thread, exit statuses); each ``_<module>`` holds commands and a ``SPECS``
dict, which :data:`COMMANDS` maps names to. The functions below are the
console-script entry points named in ``pyproject.toml``; each is one line
because all the work is in :func:`run`.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Sequence

from .._version import GFAL2_VERSION
from ._base import output

__all__ = [
    "COMMANDS",
    "SRM_IFCE_VERSION",
    "TOOLS",
    "archivepoll",
    "bringonline",
    "cat",
    "chmod",
    "copy",
    "evict",
    "gfal2_version",
    "gfal_srm_ifce_version",
    "legacy_bringonline",
    "legacy_register",
    "legacy_replicas",
    "legacy_unregister",
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
    "legacy-bringonline": "tape",
    "legacy-register": "legacy",
    "legacy-replicas": "legacy",
    "legacy-unregister": "legacy",
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


#: The srm-ifce release ``gfal_srm_ifce_version`` reports: EL9's, with gfal2 2.23.5.
SRM_IFCE_VERSION = "1.24.8"


def run(command: str, argv: Sequence[str] | None = None) -> int:
    """Run ``gfal-<command>`` with ``argv`` (default ``sys.argv[1:]``); its exit status.

    The command's module is imported only now, so ``gfal-ls`` never pays
    for ``gfal-copy``'s imports. The run is wrapped in a report context
    for ``--json``/``--xml``.
    """
    return output.run_cli(f"gfal-{command}", argv, lambda: _run(command, argv))


def _run(command: str, argv: Sequence[str] | None = None) -> int:
    """Run ``gfal-<command>``; its exit status.

    What gfal2-util's scripts do before running the command is done here:
    ``gfal-copy`` exports ``XrdSecGSIDELEGPROXY=1`` (XRootD's GSI plugin then
    delegates a proxy, which xrootd third-party copies need), and
    ``gfal-legacy-bringonline`` prints its deprecation notice.
    """
    from ._base import main, out

    if command == "copy":
        os.environ["XrdSecGSIDELEGPROXY"] = "1"  # noqa: SIM112 - XRootD spells it so
    elif command == "legacy-bringonline":
        out("This command is deprecated. Please use gfal-bringonline instead.\n")
    module = importlib.import_module(f"{__name__}._{COMMANDS[command]}")
    return main(command, module.SPECS[command], argv)


def archivepoll(argv: Sequence[str] | None = None) -> int:
    """``gfal-archivepoll``: is each file on tape yet (see :mod:`._tape`)."""
    return run("archivepoll", argv)


def bringonline(argv: Sequence[str] | None = None) -> int:
    """``gfal-bringonline``: stage files from tape (see :mod:`._tape`)."""
    return run("bringonline", argv)


def cat(argv: Sequence[str] | None = None) -> int:
    """``gfal-cat``: files' bytes to stdout."""
    return run("cat", argv)


def chmod(argv: Sequence[str] | None = None) -> int:
    """``gfal-chmod``: set permission bits."""
    return run("chmod", argv)


def copy(argv: Sequence[str] | None = None) -> int:
    """``gfal-copy``: files, chains and trees (see :mod:`._copy`)."""
    return run("copy", argv)


def evict(argv: Sequence[str] | None = None) -> int:
    """``gfal-evict``: release a staged file's disk copy."""
    return run("evict", argv)


def legacy_bringonline(argv: Sequence[str] | None = None) -> int:
    """gfal2-util's deprecated ``gfal-legacy-bringonline``, mirrored, with its notice."""
    return run("legacy-bringonline", argv)


def legacy_register(argv: Sequence[str] | None = None) -> int:
    """``gfal-legacy-register``: add a replica to an LFC entry."""
    return run("legacy-register", argv)


def legacy_replicas(argv: Sequence[str] | None = None) -> int:
    """``gfal-legacy-replicas``: list an LFC entry's replicas."""
    return run("legacy-replicas", argv)


def legacy_unregister(argv: Sequence[str] | None = None) -> int:
    """``gfal-legacy-unregister``: remove a replica from an LFC entry."""
    return run("legacy-unregister", argv)


def ls(argv: Sequence[str] | None = None) -> int:
    """``gfal-ls``: list a directory or describe a file (see :mod:`._ls`)."""
    return run("ls", argv)


def mkdir(argv: Sequence[str] | None = None) -> int:
    """``gfal-mkdir``: create directories."""
    return run("mkdir", argv)


def rename(argv: Sequence[str] | None = None) -> int:
    """``gfal-rename``: rename within one storage."""
    return run("rename", argv)


def rm(argv: Sequence[str] | None = None) -> int:
    """``gfal-rm``: remove files or trees (see :mod:`._rm`)."""
    return run("rm", argv)


def save(argv: Sequence[str] | None = None) -> int:
    """``gfal-save``: stdin to a remote file."""
    return run("save", argv)


def stat(argv: Sequence[str] | None = None) -> int:
    """``gfal-stat``: one entry's metadata."""
    return run("stat", argv)


def sum(argv: Sequence[str] | None = None) -> int:
    """``gfal-sum``: a file's checksum."""
    return run("sum", argv)


def token(argv: Sequence[str] | None = None) -> int:
    """``gfal-token``: a storage-issued token."""
    return run("token", argv)


def xattr(argv: Sequence[str] | None = None) -> int:
    """``gfal-xattr``: list, get or set extended attributes."""
    return run("xattr", argv)


def gfal2_version(argv: Sequence[str] | None = None) -> int:
    """``gfal2_version``: gfal2's version tool, which ignores its arguments."""
    return output.run_cli(
        "gfal2_version", argv, lambda: _version(f"GFAL-client-{GFAL2_VERSION}", GFAL2_VERSION)
    )


def gfal_srm_ifce_version(argv: Sequence[str] | None = None) -> int:
    """``gfal_srm_ifce_version``: srm-ifce's, double dash and all."""
    return output.run_cli(
        "gfal_srm_ifce_version",
        argv,
        lambda: _version(f"gfal-srm-ifce--{SRM_IFCE_VERSION}", SRM_IFCE_VERSION),
    )


def _version(text: str, version: str) -> int:
    """Print a version tool's line and record the version for a report; status 0."""
    from ._base import out

    output.record("version", version=version)
    out(text + "\n")
    return 0


#: The commands that are not ``gfal-*``, for ``python -m xgfalclient.cli``.
TOOLS = {"gfal2_version": gfal2_version, "gfal_srm_ifce_version": gfal_srm_ifce_version}
