"""``srm://``: SRM v2.2 over httpg, with TURL resolution for I/O and copies.

:mod:`.soap` writes and reads the envelopes, :mod:`.transport` carries them
over GSI-flavoured TLS, :mod:`.client` is the SRM operations, and
:mod:`.plugin` is what gfal2 callers see.
"""

from __future__ import annotations

from .plugin import SRMFile, SRMPlugin

__all__ = ["SRMPlugin", "SRMFile"]
