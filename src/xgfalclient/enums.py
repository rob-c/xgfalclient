"""The integer enumerations gfal2's bindings expose.

Boost.Python enums are ``int`` subclasses with a ``name`` attribute and two
class-level dictionaries, ``names`` (name to member) and ``values`` (value to
member). Code in the wild reads all three - ``gfal2.checksum_mode.names`` is
how gfal2-util parses ``-K`` - so the same surface is reproduced exactly:
``str()`` is the bare name and ``repr()`` the qualified one, ``values`` keeps
the *last* member registered for a duplicated value (``verbose_level.values[128]``
is ``trace``, as Boost's registration order leaves it), and calling the class
with any int (``checksum_mode(2)``) gives a nameless instance equal to it,
printed ``gfal2.checksum_mode(2)``, whose ``name`` raises ``AttributeError``.

Knowingly looser than Boost: members accept new attributes, the classes
live in ``xgfalclient.enums`` (pickles name that module, so they load
without the ``gfal2`` shim) and have no class-level ``name`` descriptor.
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

    def __new__(cls: type[E], value: int, name: str | None = None) -> E:
        member = super().__new__(cls, value)
        if name is not None:
            member.name = name
        return member

    def __repr__(self) -> str:
        name = self.__dict__.get("name")
        kind = f"gfal2.{type(self).__name__}"
        return f"{kind}.{name}" if name is not None else f"{kind}({int(self)})"

    def __str__(self) -> str:
        name = self.__dict__.get("name")
        return str(name) if name is not None else repr(self)

    def __reduce__(self) -> tuple[Any, tuple[str, int, bool]]:
        named = "name" in self.__dict__
        return (_lookup, (type(self).__name__, int(self), named))


def _define(cls: type[E], members: list[tuple[str, int]]) -> None:
    cls.names = {}
    cls.values = {}
    for name, value in members:
        member = cls(value, name)
        setattr(cls, name, member)
        cls.names[name] = member
        cls.values[value] = member


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


def _lookup(kind: str, value: int, named: bool = True) -> BoostEnum:
    """Unpickle: the member registered for ``value``, or a nameless instance again."""
    cls = _ENUMS[kind]
    return cls.values[value] if named else cls(value)
