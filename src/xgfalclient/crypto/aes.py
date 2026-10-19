"""Compatibility import; the shared implementation is :mod:`xrdsec.aes`.

Since 0.4.0 the grid's security code lives once, in xrdsec, for xrdclient,
xgfalclient and xrdarc alike. This module replaces itself in ``sys.modules``
with the xrdsec module rather than re-exporting its names: a test that
monkeypatches ``xgfalclient.crypto.aes.X`` must patch the very object the
code calls, and ``isinstance`` checks against its classes must agree whichever
name the class was imported under. The re-exported ``__all__`` is for type
checkers and readers; at run time the alias is what callers get. New code imports
:mod:`xrdsec.aes` directly.
"""

import sys

from xrdsec import aes as _shared
from xrdsec.aes import AES, BLOCK_SIZE, CTR, cbc_decrypt, cbc_encrypt, pkcs7_pad, pkcs7_unpad

__all__ = ["AES", "BLOCK_SIZE", "CTR", "cbc_decrypt", "cbc_encrypt", "pkcs7_pad", "pkcs7_unpad"]

sys.modules[__name__] = _shared
