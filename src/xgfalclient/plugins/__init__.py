"""Which plugins a context loads, and when.

Every built-in is described here - module, class, name, schemes, priority -
so a context can route a URL without importing anything. A plugin module is
imported the first time a URL with one of its schemes needs a plugin: a
``gfal-stat file:///x`` never pays for the HTTP stack or ``xrdclient``, which
is most of what a cold start used to cost.

A plugin whose module cannot be imported, or whose
:meth:`~xgfalclient.plugin.Plugin.available` names a missing dependency, is
skipped - and remembered, so that a ``root://`` URL on a machine without
``xrdclient`` says how to fix it rather than just "protocol not supported".

Third-party plugins register an entry point in the ``xgfalclient.plugins``
group naming a :class:`~xgfalclient.plugin.Plugin` subclass. Their schemes
are unknown until imported, so they are loaded with the context.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Any

from .._compat import SLOTS
from ..plugin import Plugin

__all__ = [
    "BUILTIN",
    "Entry",
    "ENTRY_POINT_GROUP",
    "entry_point_classes",
    "load",
    "missing_hint",
    "plugin_classes",
]

_log = logging.getLogger("xgfalclient.plugins")

ENTRY_POINT_GROUP = "xgfalclient.plugins"


@dataclass(frozen=True, **SLOTS)
class Entry:
    """A built-in plugin, described without importing it."""

    module: str
    cls: str
    name: str
    schemes: tuple[str, ...]
    priority: int


#: gfal2's priority order: http, srm, mock, xrootd, gridftp, (sftp,) file, dcap.
BUILTIN: list[Entry] = [
    Entry(
        "xgfalclient.plugins.http",
        "HTTPPlugin",
        "http",
        (
            "http",
            "https",
            "dav",
            "davs",
            "s3",
            "s3s",
            "http+3rd",
            "https+3rd",
            "dav+3rd",
            "davs+3rd",
            "gcloud",
            "gclouds",
        ),
        100,
    ),
    Entry("xgfalclient.plugins.lfc", "LFCPlugin", "lfc", ("lfc", "lfn", "guid"), 150),
    Entry("xgfalclient.plugins.srm", "SRMPlugin", "srm", ("srm",), 200),
    Entry("xgfalclient.plugins.mock", "MockPlugin", "mock", ("mock",), 300),
    Entry(
        "xgfalclient.plugins.xrootd",
        "XRootDPlugin",
        "xrootd",
        ("root", "roots", "xroot", "xroots"),
        400,
    ),
    Entry("xgfalclient.plugins.gridftp", "GridFTPPlugin", "gridftp", ("gsiftp", "ftp"), 500),
    Entry("xgfalclient.plugins.sftp", "SFTPPlugin", "sftp", ("sftp",), 550),
    Entry("xgfalclient.plugins.file", "FilePlugin", "file", ("file",), 600),
    Entry("xgfalclient.plugins.dcap", "DcapPlugin", "dcap", ("dcap", "gsidcap"), 700),
    Entry("xgfalclient.plugins.dcap", "KdcapPlugin", "kdcap", ("kdcap",), 710),
]

#: scheme -> why the plugin that would have handled it is not loaded.
_MISSING: dict[str, str] = {}


def _import(module: str, name: str) -> type[Plugin] | None:
    try:
        cls = getattr(importlib.import_module(module), name)
    except Exception as exc:  # one broken plugin must not break every URL
        _log.debug("plugin %s.%s not loadable: %s", module, name, exc)
        return None
    if not (isinstance(cls, type) and issubclass(cls, Plugin)):
        _log.warning("%s.%s is not a Plugin subclass; ignored", module, name)
        return None
    reason = cls.available()
    if reason:
        for scheme in cls.schemes:
            _MISSING[scheme] = reason
        return None
    return cls


def load(entry: Entry) -> type[Plugin] | None:
    """Import one built-in; ``None`` (and a remembered reason) if unusable."""
    cls = _import(entry.module, entry.cls)
    if cls is None:
        for scheme in entry.schemes:
            _MISSING.setdefault(scheme, f"the {entry.name} plugin could not be loaded")
    return cls


def _entry_points(found: Any = None) -> list[Any]:
    """Entry points in our group, from either shape ``entry_points()`` returns.

    3.10 and later return an object with ``select``; 3.9 returns a dict of
    group name to a list.
    """
    if found is None:
        from importlib import metadata  # slow to import; only paid when needed

        found = metadata.entry_points()
    select = getattr(found, "select", None)
    if select is not None:
        return list(select(group=ENTRY_POINT_GROUP))
    return list(found.get(ENTRY_POINT_GROUP, ()))


def entry_point_classes(extra: Any = None) -> list[type[Plugin]]:
    """Third-party plugins registered as entry points."""
    classes: list[type[Plugin]] = []
    for entry in _entry_points(extra):
        module, _, name = entry.value.partition(":")
        cls = _import(module, name)
        if cls is not None and cls not in classes:
            classes.append(cls)
    return classes


def plugin_classes(extra: Any = None) -> list[type[Plugin]]:
    """Every loadable plugin class, imported now: built-ins, then entry points."""
    classes = [cls for cls in map(load, BUILTIN) if cls is not None]
    for cls in entry_point_classes(extra):
        if cls not in classes:
            classes.append(cls)
    return classes


def missing_hint(scheme: str) -> str:
    """Why ``scheme`` has no plugin, if a plugin for it was skipped."""
    return _MISSING.get(scheme, "")
