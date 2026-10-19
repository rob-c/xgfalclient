"""xgfalclient: gfal2, in Python 3.

A drop-in for the ``gfal2`` Python bindings, with no gfal2, davix, Globus or
XRootD C library underneath - only ``xrdclient`` and a small set of maintained
general-purpose libraries installed from wheels::

    import xgfalclient as gfal2

    ctx = gfal2.creat_context()
    print(ctx.stat("davs://se.example.org/store/f").st_size)
    ctx.filecopy(ctx.transfer_parameters(), "file:///tmp/f", "davs://se.example.org/store/f")

The protocols are plugins, as in gfal2: ``http``/``https``/``dav``/``davs``
(WebDAV, HTTP third-party copy, the WLCG tape REST API), ``s3``/``s3s`` and
``gcloud``/``gclouds`` (object stores), ``root``/``roots`` (XRootD, through
``xrdclient``, the sibling Python client), ``gsiftp``/``ftp`` (GridFTP with GSI),
``srm`` (SRM v2.2), ``sftp``, ``dcap``/``gsidcap``/``kdcap`` (dCache),
``lfc`` (the LCG File Catalog), ``file`` and ``mock``.

Code that says ``import gfal2`` runs unchanged: the distribution ships a
top-level ``gfal2`` package, a module holding exactly this API, reporting the
bindings' ``__version__`` (``1.13.1``) and gfal2's ``get_version()``
(``2.23.5``). Where a real python3-gfal2 would win on ``sys.path``,
:func:`install_as_gfal2` installs that same module object explicitly.
This package's own version is :data:`VERSION`.

Package map, for a new reader: :mod:`.context` (the ``Gfal2Context`` and
dispatch), :mod:`.plugin` (the plugin contract) and :mod:`.plugins` (which
plugin serves which scheme), :mod:`.transfer` (the copy sequence),
:mod:`.options`/:mod:`.creds` (configuration and credentials),
:mod:`.types`/:mod:`.enums`/:mod:`.errors`/:mod:`.events` (the bindings'
records), :mod:`.cli` (the ``gfal-*`` commands) and :mod:`.crypto`.

Importing this package is cheap by contract: no plugin, no TLS and no
xrdclient module is imported until a URL needs it
(``tests/test_import_cost.py``). Keep new top-level imports here to modules
that are themselves import-light.
"""

from __future__ import annotations

import logging
import sys
from types import ModuleType

from . import _log
from ._version import GFAL2_PYTHON_VERSION, GFAL2_VERSION, __version__
from .context import DirectoryType, FileType, Gfal2Context, creat_context
from .creds import Credential
from .enums import checksum_mode, event_side, verbose_level
from .errors import GError
from .events import GfaltEvent
from .transfer import TransferParameters
from .types import Dirent, Stat

__all__ = [
    "VERSION",
    "Credential",
    "DirectoryType",
    "Dirent",
    "FileType",
    "GError",
    "Gfal2Context",
    "GfaltEvent",
    "NullHandler",
    "Stat",
    "TransferParameters",
    "__version__",
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
]

#: xgfalclient's own release (``gfal2.__version__`` is the bindings' it replaces).
VERSION = __version__

#: The stdlib class, which does more than the bindings' no-op one; an instance
#: is attached to the ``gfal2`` logger, as there.
NullHandler = logging.NullHandler


def get_version() -> str:
    """The gfal2 release this reproduces, as ``gfal2.get_version()`` reports.

    The C library's version, not the bindings' (``gfal2.__version__``) nor
    this package's (:data:`VERSION`): programs gate features on it.
    """
    return GFAL2_VERSION


def set_verbose(level: int) -> int:
    """Set how much gfal2 logs to the ``gfal2`` logger; its level is left alone.

    ``gfal2.set_verbose``: ``level`` is a :class:`verbose_level` (or its
    int). An unknown value lets everything through (DEBUG). Process-wide,
    like gfal2's: there is one ``gfal2`` logger.
    """
    _log.set_threshold(_log.LEVELS.get(int(level), logging.DEBUG))
    return 0


def _deprecated(replacement: str) -> None:
    """Print python3-gfal2's deprecation notice for a module-level credential call.

    To stderr rather than as a ``DeprecationWarning``: that is what
    python3-gfal2 does, and scripts that filter warnings would otherwise
    see a difference.
    """
    sys.stderr.write(f"Deprecated: Please use context.{replacement}() instead!\n")


def cred_new(type: str, value: str) -> Credential:
    """python3-gfal2's deprecated ``gfal2.cred_new``, mirrored: a :class:`Credential`."""
    _deprecated("cred_new")
    return Credential(type, value)


def cred_set(context: Gfal2Context, prefix: str, credential: Credential) -> int:
    """python3-gfal2's deprecated ``gfal2.cred_set(ctx, ...)``, mirrored: ``ctx.cred_set``."""
    _deprecated("cred_set")
    return context.cred_set(prefix, credential)


def cred_clean(context: Gfal2Context) -> int:
    """python3-gfal2's deprecated ``gfal2.cred_clean(ctx)``, mirrored: ``ctx.cred_clean``."""
    _deprecated("cred_clean")
    return context.cred_clean()


#: The ``gfal2`` module, once built; ``import gfal2`` and ``install_as_gfal2``
#: must agree on one object.
_GFAL2: ModuleType | None = None


def _gfal2_module(module: ModuleType | None = None) -> ModuleType:
    """The ``gfal2`` module: this API with the bindings' ``__version__``.

    ``src/gfal2/__init__.py`` passes itself in to be filled; otherwise a
    module is made. Either way the first one is the one, from then on.

    One object matters because exception classes and enum members are
    compared by identity: ``except gfal2.GError`` must catch what
    ``xgfalclient`` raises, whichever way ``gfal2`` was imported.
    """
    global _GFAL2
    if _GFAL2 is None:
        _GFAL2 = module if module is not None else ModuleType("gfal2", __doc__)
        for name in __all__:
            if name not in ("install_as_gfal2", "VERSION", "__version__"):
                setattr(_GFAL2, name, globals()[name])
        vars(_GFAL2)["__version__"] = GFAL2_PYTHON_VERSION
        # Tracebacks print ``gfal2.GError``, and pickles name it so.
        GError.__module__ = "gfal2"
    return _GFAL2


def install_as_gfal2() -> ModuleType:
    """Make ``import gfal2`` load this API, even with a real python3-gfal2 installed.

    Call it before anything imports ``gfal2``; a module that already did
    keeps whatever it got. Answers the installed module.
    """
    module = _gfal2_module()
    sys.modules["gfal2"] = module
    return module
