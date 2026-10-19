"""The ``gfal2`` logger, and the verbosity threshold ``set_verbose`` moves.

gfal2's Python bindings send every library message to ``logging.getLogger("gfal2")``
itself - never a child - and ``set_verbose`` moves gfal2's own threshold
rather than the logger's level, which stays the application's to set. The
threshold starts at INFO, as the bindings set it on import, so copy events
(logged at INFO) reach a handler that asks for them.

Not reproduced, knowingly: gfal2's C-level tracing at DEBUG (``->
Gfal::Transfer::FileCopy``, ``gfal_plugin_openG ->`` and the like), and the
``[gfal2_stat][gfal_plugin_statG]...`` chain of C function names it puts in
front of error messages at DEBUG verbosity. Messages read the same at every
verbosity, as gfal2's do at the default one.
"""

from __future__ import annotations

import logging

__all__ = ["LEVELS", "LOGGER", "set_threshold", "threshold"]

#: The one logger every module logs through (``from ._log import LOGGER``).
LOGGER = logging.getLogger("gfal2")

#: gfal2 verbosity (a GLib level) to the ``logging`` level it lets through.
LEVELS = {8: logging.ERROR, 16: logging.WARNING, 64: logging.INFO, 128: logging.DEBUG}


class _Threshold(logging.Filter):
    """A logger filter holding gfal2's verbosity, separate from the logger's level.

    A filter rather than ``LOGGER.setLevel`` because the level belongs to
    the application (``logging.basicConfig``, ``-v`` handling in a CLI), and
    python3-gfal2's ``set_verbose`` leaves it alone; with both in place a
    record must pass the application's level *and* gfal2's verbosity.
    """

    def __init__(self) -> None:
        """Start at INFO, the threshold python3-gfal2 sets on import."""
        super().__init__()
        self.level = logging.INFO

    def filter(self, record: logging.LogRecord) -> bool:
        """Let ``record`` through if it is at the threshold or above."""
        return record.levelno >= self.level


_THRESHOLD = _Threshold()
LOGGER.addFilter(_THRESHOLD)
# A library must not print through logging's last-resort handler when the
# application configured nothing; the bindings are silent in that case too.
LOGGER.addHandler(logging.NullHandler())


def threshold() -> int:
    """The current threshold, as a ``logging`` level (the CLI saves and restores it)."""
    return _THRESHOLD.level


def set_threshold(level: int) -> None:
    """Let through records at ``level`` (a ``logging`` level) and above."""
    _THRESHOLD.level = level
