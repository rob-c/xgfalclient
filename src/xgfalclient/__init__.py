"""xgfalclient: gfal2, in pure Python.

A drop-in for the ``gfal2`` Python bindings, with no C library underneath::

    import xgfalclient as gfal2

    ctx = gfal2.creat_context()
    print(ctx.stat("davs://se.example.org/store/f").st_size)
    ctx.filecopy(ctx.transfer_parameters(), "file:///tmp/f", "davs://se.example.org/store/f")

The protocols are plugins, as in gfal2: ``http``/``https``/``dav``/``davs``
(WebDAV, HTTP third-party copy, the WLCG tape REST API), ``s3``/``s3s`` and
``gcloud``/``gclouds`` (object stores), ``root``/``roots`` (XRootD, through
``xrdclient``, itself pure Python), ``gsiftp``/``ftp`` (GridFTP with GSI),
``srm`` (SRM v2.2), ``sftp``, ``dcap``/``gsidcap``/``kdcap`` (dCache),
``lfc`` (the LCG File Catalog), ``file`` and ``mock``.

Code that must keep saying ``import gfal2`` can call :func:`install_as_gfal2`
once at start-up.
"""

from __future__ import annotations

import logging
import sys

from ._version import __version__
from .context import DirectoryType, FileType, Gfal2Context, creat_context
from .creds import Credential
from .enums import checksum_mode, event_side, verbose_level
from .errors import GError
from .events import GfaltEvent
from .transfer import TransferParameters
from .types import Dirent, Stat

__all__ = [
    "GError",
    "Gfal2Context",
    "Credential",
    "DirectoryType",
    "Dirent",
    "FileType",
    "GfaltEvent",
    "NullHandler",
    "Stat",
    "TransferParameters",
    "checksum_mode",
    "creat_context",
    "cred_clean",
    "cred_new",
    "cred_set",
    "event_side",
    "get_version",
    "install_as_gfal2",
    "set_verbose",
    "verbose_level",
    "__version__",
]

NullHandler = logging.NullHandler
logging.getLogger("xgfalclient").addHandler(logging.NullHandler())

#: gfal2 verbosity to the ``logging`` level that shows the same messages.
_LEVELS = {8: logging.ERROR, 16: logging.WARNING, 64: logging.INFO, 128: logging.DEBUG}


def get_version() -> str:
    return __version__


def set_verbose(level: int) -> int:
    """Set how much the ``xgfalclient`` logger lets through."""
    logging.getLogger("xgfalclient").setLevel(_LEVELS.get(int(level), logging.DEBUG))
    return 0


def cred_new(type: str, value: str) -> Credential:
    return Credential(type, value)


def cred_set(context: Gfal2Context, prefix: str, credential: Credential) -> int:
    return context.cred_set(prefix, credential)


def cred_clean(context: Gfal2Context) -> int:
    return context.cred_clean()


def install_as_gfal2() -> None:
    """Make ``import gfal2`` load this package, for unmodified gfal2 code."""
    sys.modules["gfal2"] = sys.modules[__name__]
