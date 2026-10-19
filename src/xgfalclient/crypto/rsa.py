"""Compatibility import; the shared implementation is :mod:`xrdsec.rsa`.

Since 0.4.0 the grid's security code lives once, in xrdsec, for xrdclient,
xgfalclient and xrdarc alike. This module replaces itself in ``sys.modules``
with the xrdsec module rather than re-exporting its names: a test that
monkeypatches ``xgfalclient.crypto.rsa.X`` must patch the very object the
code calls, and ``isinstance`` checks against its classes must agree whichever
name the class was imported under. The re-exported ``__all__`` is for type
checkers and readers; at run time the alias is what callers get. New code imports
:mod:`xrdsec.rsa` directly.
"""

import sys

from xrdsec import rsa as _shared
from xrdsec.rsa import (
    RSA_OID,
    RSAPrivateKey,
    RSAPublicKey,
    load_library_key,
    load_private_key,
    load_public_key,
    pem_blocks,
    private_key_der,
    private_key_pem,
    public_key_from_bitstring,
)

__all__ = [
    "RSA_OID",
    "RSAPrivateKey",
    "RSAPublicKey",
    "load_library_key",
    "load_private_key",
    "load_public_key",
    "pem_blocks",
    "private_key_der",
    "private_key_pem",
    "public_key_from_bitstring",
]

sys.modules[__name__] = _shared
