"""``gfal2_util.commands``: mkdir, save, cat, xattr, sum, stat, rename, chmod and token."""

from __future__ import annotations

from xgfalclient.cli._commands import SPECS

from . import base

__all__ = ["GfalCommands"]


class GfalCommands(base.CommandBase):
    execute_mkdir = base._method(SPECS["mkdir"])
    execute_save = base._method(SPECS["save"])
    execute_cat = base._method(SPECS["cat"])
    execute_xattr = base._method(SPECS["xattr"])
    execute_sum = base._method(SPECS["sum"])
    execute_stat = base._method(SPECS["stat"])
    execute_rename = base._method(SPECS["rename"])
    execute_chmod = base._method(SPECS["chmod"])
    execute_token = base._method(SPECS["token"])
