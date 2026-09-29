"""``gfal2_util.ls``: ``gfal-ls``, its time styles, and ``LS_COLORS``.

As in gfal2-util, ``LS_COLORS`` is read (and an entry it cannot parse
warned about) when this module is imported, which the shell does for every
command.
"""

from __future__ import annotations

import os

from xgfalclient.cli._ls import SPECS, TIME_FORMATS, size_to_human
from xgfalclient.cli._utils import ls_colors

from . import base

__all__ = [
    "CommandLs",
    "color_dict",
    "full_iso",
    "long_iso",
    "time_formats",
    "time_iso",
    "time_locale",
]

time_formats = TIME_FORMATS
full_iso = TIME_FORMATS["full-iso"]
long_iso = TIME_FORMATS["long-iso"]
time_iso = TIME_FORMATS["iso"]
time_locale = TIME_FORMATS["locale"]

color_env = os.environ.get("LS_COLORS", None)
color_dict = ls_colors()


class CommandLs(base.CommandBase):
    execute_ls = base._method(SPECS["ls"])
    _size_to_human = staticmethod(size_to_human)
