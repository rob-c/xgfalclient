"""Compatibility import; the shared implementation lives in xrdclient.crypto.voms.

Alias the module as well as its exports so existing imports and test hooks
refer to the same implementation, rather than a second copy.
"""

import sys

from xrdclient.crypto import voms as _shared
from xrdclient.crypto.voms import *  # noqa: F403

sys.modules[__name__] = _shared
