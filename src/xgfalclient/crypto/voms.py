"""Compatibility import; the shared implementation is :mod:`xrdsec.voms`.

Since 0.4.0 the grid's security code lives once, in xrdsec, for xrdclient,
xgfalclient and xrdarc alike. This module replaces itself in ``sys.modules``
with the xrdsec module rather than re-exporting its names: a test that
monkeypatches ``xgfalclient.crypto.voms.X`` must patch the very object the
code calls, and ``isinstance`` checks against its classes must agree whichever
name the class was imported under. The re-exported ``__all__`` is for type
checkers and readers; at run time the alias is what callers get. New code imports
:mod:`xrdsec.voms` directly.
"""

import sys

from xrdsec import voms as _shared
from xrdsec.voms import (
    VOMS_AC_OID,
    VOMS_FQAN_OID,
    VOMSAttribute,
    VOMSDiagnostic,
    VOMSEntry,
    VOMSResult,
    VOMSStatus,
    check_vomses,
    default_ca_path,
    default_voms_dir,
    inspect_voms,
    validate_voms,
)

__all__ = [
    "VOMS_AC_OID",
    "VOMS_FQAN_OID",
    "VOMSAttribute",
    "VOMSDiagnostic",
    "VOMSEntry",
    "VOMSResult",
    "VOMSStatus",
    "check_vomses",
    "default_ca_path",
    "default_voms_dir",
    "inspect_voms",
    "validate_voms",
]

sys.modules[__name__] = _shared
