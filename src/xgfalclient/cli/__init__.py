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
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Sequence

from .._version import GFAL2_VERSION

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


def legacy_bringonline(argv: Sequence[str] | None = None) -> int:
    return run("legacy-bringonline", argv)


def legacy_register(argv: Sequence[str] | None = None) -> int:
    return run("legacy-register", argv)


def legacy_replicas(argv: Sequence[str] | None = None) -> int:
    return run("legacy-replicas", argv)


def legacy_unregister(argv: Sequence[str] | None = None) -> int:
    return run("legacy-unregister", argv)


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


def gfal2_version(argv: Sequence[str] | None = None) -> int:
    """``gfal2_version``: gfal2's version tool, which ignores its arguments."""
    from ._base import out

    out(f"GFAL-client-{GFAL2_VERSION}\n")
    return 0


def gfal_srm_ifce_version(argv: Sequence[str] | None = None) -> int:
    """``gfal_srm_ifce_version``: srm-ifce's, double dash and all."""
    from ._base import out

    out(f"gfal-srm-ifce--{SRM_IFCE_VERSION}\n")
    return 0


#: The commands that are not ``gfal-*``, for ``python -m xgfalclient.cli``.
TOOLS = {"gfal2_version": gfal2_version, "gfal_srm_ifce_version": gfal_srm_ifce_version}
