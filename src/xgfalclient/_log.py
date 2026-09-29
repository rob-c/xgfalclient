"""The ``gfal2`` logger, and the verbosity threshold ``set_verbose`` moves.

gfal2's Python bindings send every library message to ``logging.getLogger("gfal2")``
itself - never a child - and ``set_verbose`` moves gfal2's own threshold
rather than the logger's level, which stays the application's to set. The
threshold starts at INFO, as the bindings set it on import, so copy events
(logged at INFO) reach a handler that asks for them.
"""

from __future__ import annotations

import logging

__all__ = ["LOGGER", "LEVELS", "threshold", "set_threshold"]

LOGGER = logging.getLogger("gfal2")

#: gfal2 verbosity (a GLib level) to the ``logging`` level it lets through.
LEVELS = {8: logging.ERROR, 16: logging.WARNING, 64: logging.INFO, 128: logging.DEBUG}


class _Threshold(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self.level = logging.INFO

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= self.level


_THRESHOLD = _Threshold()
LOGGER.addFilter(_THRESHOLD)
LOGGER.addHandler(logging.NullHandler())


def threshold() -> int:
    return _THRESHOLD.level


def set_threshold(level: int) -> None:
    """Let through records at ``level`` (a ``logging`` level) and above."""
    _THRESHOLD.level = level
