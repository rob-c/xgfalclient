"""Compatibility import; the shared implementation lives in xrdclient._xml.

Alias the module as well as its exports so existing imports and test hooks
refer to the same implementation, rather than a second copy.
"""

import sys

from xrdclient import _xml as _shared
from xrdclient._xml import *  # noqa: F403

sys.modules[__name__] = _shared
