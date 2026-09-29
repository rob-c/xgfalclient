"""``gfal2_util.legacy``: register, unregister and list an LFC entry's replicas."""

from __future__ import annotations

from xgfalclient.cli._legacy import SPECS

from . import base

__all__ = ["CommandLegacy"]


class CommandLegacy(base.CommandBase):
    """Implement some legacy support around gfal2"""

    execute_unregister = base._method(SPECS["legacy-unregister"])
    execute_register = base._method(SPECS["legacy-register"])
    execute_replicas = base._method(SPECS["legacy-replicas"])
