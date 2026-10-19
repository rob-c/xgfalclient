"""dCache's dcap protocol: ``dcap://``, ``gsidcap://`` and (with Kerberos) ``kdcap://``.

Start with :mod:`.plugin` (the gfal2 operations), which uses :mod:`.control`
(door connections), :mod:`.file` (pool data channels and open files) and
:mod:`.tunnel` (GSI/Kerberos authentication); :mod:`.protocol` is the
socket-free wire format the in-process test server shares. Exported here:
the two plugins, and the tunnel API for installing another authentication
mechanism.
"""

from __future__ import annotations

from .plugin import DcapPlugin, KdcapPlugin
from .tunnel import GSITunnel, Tunnel, register_tunnel

__all__ = ["DcapPlugin", "GSITunnel", "KdcapPlugin", "Tunnel", "register_tunnel"]
