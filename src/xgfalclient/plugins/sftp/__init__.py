"""The ``sftp://`` plugin package.

The plugin class lives in :mod:`.plugin`; it is re-exported here so the
registry entry ``Entry("xgfalclient.plugins.sftp", "SFTPPlugin", ...)`` finds
it. Importing this package must stay cheap - the transports, crypto and
``paramiko`` probe are all imported lazily inside the plugin.

Modules: :mod:`.plugin` (gfal2 operations, tier choice, connection pool),
:mod:`.client` (the SFTP v3 client over any byte stream), :mod:`.protocol`
(wire constants and ``ATTRS``), :mod:`.endpoint` (resolved connection
settings), and the three transport tiers :mod:`.openssh`,
:mod:`.paramiko_tier` and :mod:`.ssh` (the in-process SSH client).
"""

from __future__ import annotations

from .plugin import SFTPPlugin

__all__ = ["SFTPPlugin"]
