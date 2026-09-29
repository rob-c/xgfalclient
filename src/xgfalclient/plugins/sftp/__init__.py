"""The ``sftp://`` plugin package.

The plugin class lives in :mod:`.plugin`; it is re-exported here so the
registry entry ``Entry("xgfalclient.plugins.sftp", "SFTPPlugin", ...)`` finds
it. Importing this package must stay cheap - the transports, crypto and
``paramiko`` probe are all imported lazily inside the plugin.
"""

from __future__ import annotations

from .plugin import SFTPPlugin

__all__ = ["SFTPPlugin"]
