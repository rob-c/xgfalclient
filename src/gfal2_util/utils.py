"""``gfal2_util.utils``: mode strings, and an ``alarm``-based ``Timeout``."""

from __future__ import annotations

import signal
from typing import Any

from xgfalclient.cli._utils import file_mode_str, file_type_str

__all__ = ["Timeout", "file_mode_str", "file_type_str"]


class Timeout:
    """``with Timeout(seconds):`` raises ``Timeout.Timeout`` when ``SIGALRM`` fires.

    gfal2-util's ``gfal2_util.utils.Timeout``, kept for code that imports it;
    the commands themselves bound ``-t`` with a worker thread instead. Like
    any ``SIGALRM`` user it works only on the main thread and on POSIX, and
    it does not restore a previous ``SIGALRM`` handler (neither does
    gfal2-util's).
    """

    class Timeout(Exception):
        """Raised inside the ``with`` block when the alarm fires."""

    def __init__(self, sec: int) -> None:
        """Arm for ``sec`` whole seconds when the block is entered."""
        self.sec = sec

    def __enter__(self) -> None:
        """Install the handler and start the alarm."""
        signal.signal(signal.SIGALRM, self.raise_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args: object) -> None:
        """Cancel the alarm; exceptions from the block propagate."""
        signal.alarm(0)

    def raise_timeout(self, *args: Any) -> None:
        """The ``SIGALRM`` handler."""
        raise Timeout.Timeout()
