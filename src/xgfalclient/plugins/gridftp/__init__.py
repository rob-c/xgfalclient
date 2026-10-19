"""GridFTP: ``gsiftp://`` and ``ftp://`` (see :mod:`.plugin`).

Only :class:`GridFTPPlugin` is public; the plugin registry finds it here. The
submodules are internal and may change between releases, except that
:mod:`.plugin` keeps re-exporting the names of its old single-module layout.
"""

from __future__ import annotations

from .plugin import GridFTPPlugin

__all__ = ["GridFTPPlugin"]
