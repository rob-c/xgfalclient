"""Compatibility import; the shared implementation is :mod:`xrdsec.ed25519`.

Since 0.4.0 the grid's security code lives once, in xrdsec, for xrdclient,
xgfalclient and xrdarc alike. This module replaces itself in ``sys.modules``
with the xrdsec module rather than re-exporting its names: a test that
monkeypatches ``xgfalclient.crypto.ed25519.X`` must patch the very object the
code calls, and ``isinstance`` checks against its classes must agree whichever
name the class was imported under. The re-exported ``__all__`` is for type
checkers and readers; at run time the alias is what callers get. New code imports
:mod:`xrdsec.ed25519` directly.
"""

import sys

from xrdsec import ed25519 as _shared
from xrdsec.ed25519 import L, public_key, sign, verify

__all__ = ["L", "public_key", "sign", "verify"]

sys.modules[__name__] = _shared
