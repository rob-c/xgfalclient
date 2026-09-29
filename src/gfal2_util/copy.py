"""``gfal2_util.copy``: ``gfal-copy``."""

from __future__ import annotations

from xgfalclient.cli._copy import SPECS

from . import base

__all__ = ["CommandCopy"]


class CommandCopy(base.CommandBase):
    execute_copy = base._method(SPECS["copy"])
