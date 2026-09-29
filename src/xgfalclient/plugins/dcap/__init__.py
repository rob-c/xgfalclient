"""dCache's dcap protocol: ``dcap://``, ``gsidcap://`` and (with Kerberos) ``kdcap://``."""

from __future__ import annotations

from .plugin import DcapPlugin, KdcapPlugin
from .tunnel import GSITunnel, Tunnel, register_tunnel

__all__ = ["DcapPlugin", "KdcapPlugin", "GSITunnel", "Tunnel", "register_tunnel"]
