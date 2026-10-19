"""Compatibility import; the shared implementation is :mod:`xrdsec.p256`.

Since 0.4.0 the grid's security code lives once, in xrdsec, for xrdclient,
xgfalclient and xrdarc alike. This module replaces itself in ``sys.modules``
with the xrdsec module rather than re-exporting its names: a test that
monkeypatches ``xgfalclient.crypto.p256.X`` must patch the very object the
code calls, and ``isinstance`` checks against its classes must agree whichever
name the class was imported under. The re-exported ``__all__`` is for type
checkers and readers; at run time the alias is what callers get. New code imports
:mod:`xrdsec.p256` directly.
"""

import sys

from xrdsec import p256 as _shared
from xrdsec.p256 import G, N, P, decode_point, encode_point, public_key, sign, verify

__all__ = ["G", "N", "P", "decode_point", "encode_point", "public_key", "sign", "verify"]

sys.modules[__name__] = _shared
