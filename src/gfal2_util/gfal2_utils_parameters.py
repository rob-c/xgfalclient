"""``gfal2_util.gfal2_utils_parameters``: ``-D``, ``-C``, ``-4``/``-6`` and ``-t``."""

from __future__ import annotations

from typing import Union

from xgfalclient.cli._base import _set_definition, _value, apply_options, parse_definition
from xgfalclient.context import Gfal2Context

__all__ = [
    "apply_option",
    "get_parameter_from_str",
    "get_parameter_from_str_list",
    "parse_parameter",
    "set_gfal_tool_parameter",
]

Value = Union[int, bool, str]

#: What the common options do to a context: ``apply_option(context, params)``.
apply_option = apply_options
#: ``GROUP:KEY=VALUE[,VALUE...]`` into ``(group, key, [values])``.
parse_parameter = parse_definition
#: A value: an integer, else a boolean, else the string.
get_parameter_from_str = _value


def get_parameter_from_str_list(str_value_list: str) -> list[Value]:
    return [_value(item) for item in str_value_list.split(",")]


def set_gfal_tool_parameter(
    context: Gfal2Context, param_struct: tuple[str, str, list[Value]]
) -> None:
    """Set one parsed ``-D``: a list, an integer, a boolean or a string option.

    gfal2-util raises ``ValueError`` for a value of any other type, which
    ``parse_parameter`` never produces; here such a value is set as a string.
    """
    _set_definition(context, *param_struct)
