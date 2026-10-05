"""Compatibility import for the shared HTTP connections."""

from __future__ import annotations

import sys

from xrdclient.http import _connection as _shared
from xrdclient.http._connection import *  # noqa: F403

sys.modules[__name__] = _shared
