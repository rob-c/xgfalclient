"""``gfal2_util.tape``: bringonline, archivepoll and evict."""

from __future__ import annotations

from xgfalclient.cli._tape import SPECS

from . import base

__all__ = ["CommandTape"]


class CommandTape(base.CommandBase):
    """Implement tape operations support via Gfal2 library"""

    execute_bringonline = base._method(SPECS["bringonline"])
    execute_archivepoll = base._method(SPECS["archivepoll"])
    execute_evict = base._method(SPECS["evict"])
