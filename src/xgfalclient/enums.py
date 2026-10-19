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

from typing import Any, ClassVar, Self, TypeVar

__all__ = ["BoostEnum", "checksum_mode", "event_side", "verbose_level"]

#: The concrete enum class :func:`_define` populates.
E = TypeVar("E", bound="BoostEnum")


class BoostEnum(int):
    """An ``int`` with a name, registered on its class.

    Members compare, hash and serialise as their integer, so a member can be
    passed wherever gfal2 takes an int (``set_checksum(checksum_mode.both,
    ...)`` and ``set_checksum(3, ...)`` are the same call), and an int from a
    configuration file can be compared with a member directly. The name is
    an instance attribute so that nameless instances (``checksum_mode(7)``)
    can exist, as Boost.Python allows.
    """

    names: ClassVar[dict[str, Any]]
    values: ClassVar[dict[int, Any]]
    name: str

    def __new__(cls, value: int, name: str | None = None) -> Self:
        """An instance equal to ``value``; ``name`` is given only when registering a member.

        Calling the class (``checksum_mode(2)``) does not look the member up:
        Boost.Python returns a fresh, nameless object, and so does this. Use
        ``checksum_mode.values[2]`` for the registered member.
        """
        member = super().__new__(cls, value)
        if name is not None:
            member.name = name
        return member

    def __repr__(self) -> str:
        """``gfal2.checksum_mode.both``, or ``gfal2.checksum_mode(7)`` when nameless."""
        # Read through __dict__, not getattr: a nameless instance must not
        # fall back to a class attribute that happens to be called ``name``.
        name = self.__dict__.get("name")
        kind = f"gfal2.{type(self).__name__}"
        return f"{kind}.{name}" if name is not None else f"{kind}({int(self)})"

    def __str__(self) -> str:
        """The bare name (``both``), as Boost prints it; the repr when nameless.

        Not ``int.__str__``: Boost.Python enums format as their name, so
        ``"%s" % mode`` in existing code prints ``both``, not ``3``.
        """
        name = self.__dict__.get("name")
        return str(name) if name is not None else repr(self)

    def __reduce__(self) -> tuple[Any, tuple[str, int, bool]]:
        """Pickle by class name and value, so a member unpickles as the same member.

        Plain ``int`` pickling would lose the class; pickling the instance's
        ``__dict__`` would make unpickled members distinct objects from the
        registered ones, breaking ``is`` comparisons in caller code.
        """
        named = "name" in self.__dict__
        return (_lookup, (type(self).__name__, int(self), named))


def _define(cls: type[E], members: list[tuple[str, int]]) -> None:
    """Register ``members`` on ``cls`` in order: attributes, ``names`` and ``values``.

    Registration order is significant for duplicated values: the later
    member wins in ``values`` (see the module docstring), as it does in
    Boost.Python's ``enum_<>.value()`` chain that gfal2's bindings use.
    """
    cls.names = {}
    cls.values = {}
    for name, value in members:
        member = cls(value, name)
        setattr(cls, name, member)
        cls.names[name] = member
        cls.values[value] = member


class checksum_mode(BoostEnum):
    """Which end(s) of a copy are checksummed: ``none``/``source``/``target``/``both``.

    gfal2's ``gfalt_checksum_mode_t``, a bit set: ``source`` (1) checks the
    source against the user's value, ``target`` (2) the destination, and
    ``both`` (3) compares the two ends with each other as well. See
    ``TransferParameters.set_checksum``.
    """

    none: ClassVar[checksum_mode]
    source: ClassVar[checksum_mode]
    target: ClassVar[checksum_mode]
    both: ClassVar[checksum_mode]


class verbose_level(BoostEnum):
    """Log levels, numbered as GLib numbers them.

    The values are GLib's ``GLogLevelFlags`` bits (``G_LOG_LEVEL_CRITICAL`` 8
    up to ``G_LOG_LEVEL_DEBUG`` 128), which is what gfal2's ``set_verbose``
    takes; ``debug`` and ``trace`` share 128 because gfal2 maps both to
    GLib's debug level. :data:`xgfalclient._log.LEVELS` turns them into
    ``logging`` levels.
    """

    normal: ClassVar[verbose_level]
    warning: ClassVar[verbose_level]
    verbose: ClassVar[verbose_level]
    debug: ClassVar[verbose_level]
    trace: ClassVar[verbose_level]


class event_side(BoostEnum):
    """Which end of a copy an event describes; ``event_none`` means both.

    gfal2's ``gfal_event_side_t``: the ``side`` of an event passed to an
    ``event_callback`` (see :mod:`xgfalclient.events`).
    """

    event_source: ClassVar[event_side]
    event_destination: ClassVar[event_side]
    event_none: ClassVar[event_side]


_define(checksum_mode, [("none", 0), ("source", 1), ("target", 2), ("both", 3)])
_define(
    verbose_level,
    [("normal", 8), ("warning", 16), ("verbose", 64), ("debug", 128), ("trace", 128)],
)
_define(event_side, [("event_source", 0), ("event_destination", 1), ("event_none", 2)])

#: Every enum class by name, for :func:`_lookup` (pickles name the class as text).
_ENUMS: dict[str, type[BoostEnum]] = {
    "checksum_mode": checksum_mode,
    "verbose_level": verbose_level,
    "event_side": event_side,
}


def _lookup(kind: str, value: int, named: bool = True) -> BoostEnum:
    """Unpickle: the member registered for ``value``, or a nameless instance again."""
    cls = _ENUMS[kind]
    return cls.values[value] if named else cls(value)
