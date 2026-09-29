"""The integer enumerations gfal2's bindings expose.

Boost.Python enums are ``int`` subclasses with a ``name`` attribute and two
class-level dictionaries, ``names`` (name to member) and ``values`` (value to
member). Code in the wild reads all three - ``gfal2.checksum_mode.names`` is
how gfal2-util parses ``-K`` - so the same surface is reproduced exactly,
including ``values`` keeping only the first member for a duplicated value.
"""

from __future__ import annotations

from typing import Any, ClassVar, TypeVar

__all__ = ["BoostEnum", "checksum_mode", "verbose_level", "event_side"]

E = TypeVar("E", bound="BoostEnum")


class BoostEnum(int):
    """An ``int`` with a name, registered on its class."""

    names: ClassVar[dict[str, Any]]
    values: ClassVar[dict[int, Any]]
    name: str

    def __new__(cls: type[E], value: int, name: str) -> E:
        member = super().__new__(cls, value)
        member.name = name
        return member

    def __repr__(self) -> str:
        return f"gfal2.{type(self).__name__}.{self.name}"

    __str__ = __repr__

    def __reduce__(self) -> tuple[Any, tuple[int]]:
        return (_lookup, (type(self).__name__, int(self)))  # type: ignore[return-value]


def _define(cls: type[E], members: list[tuple[str, int]]) -> None:
    cls.names = {}
    cls.values = {}
    for name, value in members:
        member = cls(value, name)
        setattr(cls, name, member)
        cls.names[name] = member
        cls.values.setdefault(value, member)


class checksum_mode(BoostEnum):
    """Which end(s) of a copy are checksummed: ``none``/``source``/``target``/``both``."""

    none: ClassVar[checksum_mode]
    source: ClassVar[checksum_mode]
    target: ClassVar[checksum_mode]
    both: ClassVar[checksum_mode]


class verbose_level(BoostEnum):
    """Log levels, numbered as GLib numbers them."""

    normal: ClassVar[verbose_level]
    warning: ClassVar[verbose_level]
    verbose: ClassVar[verbose_level]
    debug: ClassVar[verbose_level]
    trace: ClassVar[verbose_level]


class event_side(BoostEnum):
    """Which end of a copy an event describes; ``event_none`` means both."""

    event_source: ClassVar[event_side]
    event_destination: ClassVar[event_side]
    event_none: ClassVar[event_side]


_define(checksum_mode, [("none", 0), ("source", 1), ("target", 2), ("both", 3)])
_define(
    verbose_level,
    [("normal", 8), ("warning", 16), ("verbose", 64), ("debug", 128), ("trace", 128)],
)
_define(event_side, [("event_source", 0), ("event_destination", 1), ("event_none", 2)])

_ENUMS: dict[str, type[BoostEnum]] = {
    "checksum_mode": checksum_mode,
    "verbose_level": verbose_level,
    "event_side": event_side,
}


def _lookup(kind: str, value: int) -> BoostEnum:
    """Unpickle a member: the first one registered for ``value``."""
    return _ENUMS[kind].values[value]  # type: ignore[no-any-return]
