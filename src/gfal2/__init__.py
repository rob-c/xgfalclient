"""``import gfal2``, answered by xgfalclient.

The same names as python3-gfal2's module (``Gfal2Context``, ``GError``,
``creat_context``, the enums...), with its ``__version__`` (``1.13.1``) and
gfal2's ``get_version()`` (``2.23.5``). It is the very module object
``xgfalclient.install_as_gfal2()`` installs: whichever comes first makes it,
and any later import answers with that one.
"""

from __future__ import annotations

import sys

import xgfalclient

sys.modules[__name__] = xgfalclient._gfal2_module(sys.modules[__name__])
del annotations, sys, xgfalclient  # the bindings' module holds nothing else
