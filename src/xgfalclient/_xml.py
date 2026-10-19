"""Compatibility import; the shared implementation is :mod:`xrdcore.safexml`.

The DTD-free XML parsing (any ``<!DOCTYPE`` is refused, which rules out
entity expansion and external entities) that WebDAV ``PROPFIND`` replies,
SRM SOAP, BDII answers and metalinks go through is xrdcore's, shared with
xrdclient, xrdhttp and xrdarc. This module replaces itself in
``sys.modules`` with xrdcore's, rather than re-exporting names, so that a
test patching ``xgfalclient._xml.X`` patches the object the code calls.
xgfalclient's own modules import :mod:`xrdcore.safexml` directly.
"""

import sys

from xrdcore import safexml as _shared
from xrdcore.safexml import UnsafeXML, fromstring

__all__ = ["UnsafeXML", "fromstring"]

sys.modules[__name__] = _shared
