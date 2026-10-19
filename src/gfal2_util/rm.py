"""``gfal2_util.rm``: ``gfal-rm``, whose exit status starts at 0."""

from __future__ import annotations

from xgfalclient.cli._rm import SPECS

from . import base

__all__ = ["CommandRm"]


class CommandRm(base.CommandBase):
    """gfal2-util's ``CommandRm``: ``gfal-rm``, its status starting at 0."""

    def __init__(self) -> None:
        """Start the exit status at 0, so ``gfal-rm`` reports only failures it saw."""
        super().__init__()
        self.return_code = 0

    execute_rm = base._method(SPECS["rm"])
