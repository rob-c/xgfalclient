"""``gfal2_util.utils``: mode strings, and an ``alarm``-based ``Timeout``."""

from __future__ import annotations

import signal
from typing import Any

from xgfalclient.cli._utils import file_mode_str, file_type_str

__all__ = ["Timeout", "file_mode_str", "file_type_str"]


class Timeout:
    """``with Timeout(seconds):`` raises ``Timeout.Timeout`` when ``SIGALRM`` fires."""

    class Timeout(Exception):
        pass

    def __init__(self, sec: int) -> None:
        self.sec = sec

    def __enter__(self) -> None:
        signal.signal(signal.SIGALRM, self.raise_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args: object) -> None:
        signal.alarm(0)

    def raise_timeout(self, *args: Any) -> None:
        raise Timeout.Timeout()
