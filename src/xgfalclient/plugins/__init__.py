"""Which plugins a context loads, and when.

Every built-in is described here - module, class, name, schemes, priority -
so a context can route a URL without importing anything. A plugin module is
imported the first time a URL with one of its schemes needs a plugin: a
``gfal-stat file:///x`` never imports the HTTP stack (urllib3, botocore), the
XRootD plugin, or xrdclient's client, session and copy engines, which is most
of what a cold start used to cost. ``import gfal2`` imports no xrdclient
module at all; the ``gfal-*`` commands import only xrdcore's small,
dependency-free report module (:mod:`xrdcore.report`) on top of it, and
no xrdclient engine. ``tests/test_import_cost.py`` holds this in place.

A plugin whose module cannot be imported, or whose
:meth:`~xgfalclient.plugin.Plugin.available` names a missing dependency, is
skipped - and remembered, so that a URL of its scheme says why rather than
just "protocol not supported". An entry may carry its own ``hint`` for a
failed import: a ``root://`` URL in an environment whose xrdclient is broken
says how to repair it.

Third-party plugins register an entry point in the ``xgfalclient.plugins``
group naming a :class:`~xgfalclient.plugin.Plugin` subclass. Their schemes
are unknown until imported, so all of them are imported together, the first
time a context meets a scheme no built-in claims (or is asked for every
plugin, as ``get_plugin_names`` is): ``importlib.metadata`` alone costs more
than a URL of a built-in scheme should ever pay.

Adding a built-in: one :class:`Entry` in :data:`BUILTIN`, whose ``schemes``
must match the plugin class's own (dispatch routes by the entry before the
class exists), and a priority that keeps gfal2's order.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Any

from ..plugin import Plugin

__all__ = [
    "BUILTIN",
    "ENTRY_POINT_GROUP",
    "XROOTD_HINT",
    "Entry",
    "entry_point_classes",
    "load",
    "missing_hint",
    "plugin_classes",
]

_log = logging.getLogger("gfal2")

#: The entry-point group third-party plugins register under.
ENTRY_POINT_GROUP = "xgfalclient.plugins"


#: What ``root://`` says when the XRootD plugin cannot be imported: its only
#: reason not to is a missing or broken xrdclient, a required dependency.
XROOTD_HINT = (
    "The required xrdclient package is missing or cannot be imported. "
    "Repair this environment with: python -m pip install --upgrade --force-reinstall xgfalclient"
)


@dataclass(frozen=True, slots=True)
class Entry:
    """A built-in plugin, described without importing it.

    ``hint`` is what a URL of its schemes says when the module cannot be
    imported; empty, it says that the plugin could not be loaded.
    """

    module: str
    cls: str
    name: str
    schemes: tuple[str, ...]
    priority: int
    hint: str = ""


#: gfal2's priority order: http, (lfc,) srm, mock, xrootd, gridftp, (sftp,) file,
#: dcap. The bracketed ones have no fixed place in gfal2's order; their schemes
#: overlap no other plugin's, so their position only shows in listings such as
#: ``get_plugin_names``. A lower number is asked first.
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
            "swift",
            "swifts",
            "cs3",
            "cs3s",
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
        XROOTD_HINT,
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
    """Import ``module.name`` as a usable plugin class, or None with the reason recorded.

    Any exception counts as "not loadable" - a plugin with a broken optional
    dependency must cost only its own schemes. A class whose ``available()``
    gives a reason has that reason remembered per scheme, for
    :func:`missing_hint`.
    """
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
        reason = entry.hint or f"the {entry.name} plugin could not be loaded"
        for scheme in entry.schemes:
            _MISSING.setdefault(scheme, reason)
    return cls


def _entry_points(found: Any = None) -> list[Any]:
    """Entry points in our group: installed ones, or from an injected ``found``.

    The installed set is asked for by group directly. ``found`` (the
    ``extra`` of the public helpers below) stands in for what
    ``importlib.metadata.entry_points()`` returns, in either shape callers
    have passed: an object with ``select`` or a mapping of group name to a
    list of entries.
    """
    if found is None:
        from importlib import metadata  # slow to import; only paid when needed

        return list(metadata.entry_points(group=ENTRY_POINT_GROUP))
    select = getattr(found, "select", None)
    if select is not None:
        return list(select(group=ENTRY_POINT_GROUP))
    return list(found.get(ENTRY_POINT_GROUP, ()))


def entry_point_classes(extra: Any = None) -> list[type[Plugin]]:
    """Third-party plugins registered as entry points.

    Each entry's ``value`` is ``module:Class``; duplicates (one class
    registered twice) are loaded once. ``extra`` replaces the installed
    entry points (see :func:`_entry_points`), for tests.
    """
    classes: list[type[Plugin]] = []
    for entry in _entry_points(extra):
        module, _, name = entry.value.partition(":")
        cls = _import(module, name)
        if cls is not None and cls not in classes:
            classes.append(cls)
    return classes


def plugin_classes(extra: Any = None) -> list[type[Plugin]]:
    """Every loadable plugin class, imported now: built-ins, then entry points.

    The eager counterpart of a context's lazy loading, for tools that list
    what is installed.
    """
    classes = [cls for cls in map(load, BUILTIN) if cls is not None]
    for cls in entry_point_classes(extra):
        if cls not in classes:
            classes.append(cls)
    return classes


def missing_hint(scheme: str) -> str:
    """Why ``scheme`` has no plugin, if a plugin for it was skipped.

    Process-wide: the first failure to load a plugin is remembered for
    every later context, since an import that failed once fails again.
    """
    return _MISSING.get(scheme, "")
