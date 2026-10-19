"""``srm://``: SRM v2.2 over httpg, with TURL resolution for I/O and copies.

:mod:`.soap` writes and reads the envelopes, :mod:`.transport` carries them
over GSI-flavoured TLS, :mod:`.client` is the SRM operations, and
:mod:`.plugin` is what gfal2 callers see. :mod:`.bdii` finds the web
service of a short SURL in the grid information system (LDAP, GLUE 1.3).

The protocol is SRM v2.2 (OGF GFD.129) as gfal2 2.23.5 and srm-ifce speak
it; :mod:`xgfalclient.testing.srm` is the server the tests run against.
Only :class:`SRMPlugin` and :class:`SRMFile` are this package's API; the
modules below them are internal and may change shape freely.
"""

from __future__ import annotations

from .plugin import SRMFile, SRMPlugin

__all__ = ["SRMFile", "SRMPlugin"]
