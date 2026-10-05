"""Compatibility import; the shared implementation lives in xrdclient.crypto.p256.

Alias the module as well as its exports so existing imports and test hooks
refer to the same implementation, rather than a second copy.
"""

import sys

from xrdclient.crypto import p256 as _shared
from xrdclient.crypto.p256 import *  # noqa: F403

sys.modules[__name__] = _shared
