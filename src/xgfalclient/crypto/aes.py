"""Compatibility import; the shared implementation lives in xrdclient.crypto.aes.

Alias the module as well as its exports so existing imports and test hooks
refer to the same implementation, rather than a second copy.
"""

import sys

from xrdclient.crypto import aes as _shared
from xrdclient.crypto.aes import *  # noqa: F403

sys.modules[__name__] = _shared
