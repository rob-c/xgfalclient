"""The records gfal2 hands back, ``Stat`` and ``Dirent``, and the one it takes,
``TransferParameters``.

``Stat`` and ``Dirent`` mirror the bindings field for field. ``str(stat)``
prints the same nine lines gfal2 does, with the mode in bare octal
(``mode: 100644``), because scripts have been known to parse it.

``TransferParameters`` fields are typed as the bindings type them: a
non-integer ``timeout`` raises ``TypeError`` and a negative one
``OverflowError`` on assignment (not a baffling failure of the copy later),
flags read back as ``bool``, and ``scitag`` must be in ``[65, 65535]``.
Setting ``timeout = 0`` is accepted; the copy engine treats it as "no limit"
where gfal2's local copy expires at once (README, "Where it differs").
``set_checksum`` still accepts a plain int for the mode, which gfal2 does not.

Knowingly friendlier than the bindings' records: fields are writable,
``Stat`` and ``Dirent`` compare by value and have readable reprs.

Plugins build ``Stat``/``Dirent`` directly; the core never post-processes
them, so whatever a plugin fills in is what the caller sees.
"""

from __future__ import annotations

import errno
import operator
import os
import stat as _stat
import warnings
from collections.abc import Callable
from typing import Any, Generic, TypeVar, overload

from .enums import checksum_mode
from .errors import GError
from .events import GfaltEvent

__all__ = [
    "DT_BLK",
    "DT_CHR",
    "DT_DIR",
    "DT_FIFO",
    "DT_LNK",
    "DT_REG",
    "DT_SOCK",
    "DT_UNKNOWN",
    "Dirent",
    "Stat",
    "TransferParameters",
    "dtype_for_mode",
]

# ``d_type`` values: the BSD/Linux ``DT_*`` constants (``<dirent.h>``), the
# same on every platform this runs on. gfal2 passes them through unchanged.
DT_UNKNOWN = 0
DT_FIFO = 1
DT_CHR = 2
DT_DIR = 4
DT_BLK = 6
DT_REG = 8
DT_LNK = 10
DT_SOCK = 12

#: ``S_IFMT`` bits to the ``d_type`` the kernel reports for them.
_DTYPES = {
    _stat.S_IFIFO: DT_FIFO,
    _stat.S_IFCHR: DT_CHR,
    _stat.S_IFDIR: DT_DIR,
    _stat.S_IFBLK: DT_BLK,
    _stat.S_IFREG: DT_REG,
    _stat.S_IFLNK: DT_LNK,
    _stat.S_IFSOCK: DT_SOCK,
}

#: Every ``Stat`` field, in ``struct stat`` order (the order ``as_dict`` keeps).
_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_atime",
    "st_mtime",
    "st_ctime",
)


class Stat:
    """``struct stat`` as gfal2 fills it; unknown fields are zero.

    Not every protocol knows every field - WebDAV has no inode, SRM no
    ``nlink`` - and gfal2 leaves those at zero rather than inventing them.
    """

    __slots__ = _FIELDS

    st_dev: int
    st_ino: int
    st_mode: int
    st_nlink: int
    st_uid: int
    st_gid: int
    st_size: int
    st_atime: int
    st_mtime: int
    st_ctime: int

    def __init__(self, **fields: int) -> None:
        """Fields by keyword; omitted ones are 0 and an unknown name is ``TypeError``.

        python3-gfal2's ``Stat()`` takes no arguments; the keywords are for
        plugins. Values are coerced with ``int()`` so a plugin may pass a
        float mtime or a numeric string from a protocol reply.
        """
        for name in _FIELDS:
            setattr(self, name, int(fields.pop(name, 0)))
        if fields:
            raise TypeError(f"unknown Stat field(s): {', '.join(sorted(fields))}")

    @classmethod
    def from_os(cls, result: os.stat_result) -> Stat:
        """Copy a local ``os.stat`` result, truncating times to seconds."""
        return cls(**{name: int(getattr(result, name)) for name in _FIELDS})

    # -- convenience beyond the bindings ---------------------------------------

    def is_dir(self) -> bool:
        """``S_ISDIR(st_mode)`` - not in python3-gfal2, which has only the raw mode."""
        return _stat.S_ISDIR(self.st_mode)

    def is_file(self) -> bool:
        """``S_ISREG(st_mode)``; False for devices, FIFOs and sockets."""
        return _stat.S_ISREG(self.st_mode)

    def is_link(self) -> bool:
        """``S_ISLNK(st_mode)``: only meaningful for a result from ``lstat``."""
        return _stat.S_ISLNK(self.st_mode)

    def as_dict(self) -> dict[str, int]:
        """Every field by name, for JSON output and comparisons."""
        return {name: getattr(self, name) for name in _FIELDS}

    def __eq__(self, other: object) -> bool:
        """Equal when every field is (an extension: the bindings compare identity)."""
        if not isinstance(other, Stat):
            return NotImplemented
        return self.as_dict() == other.as_dict()

    # No __hash__: defining __eq__ alone leaves the class unhashable, as a
    # mutable record should be, like gfal2's.

    def __str__(self) -> str:
        """gfal2's nine lines, in its order (``st_dev`` is not printed), each ending ``\n``."""
        return (
            f"uid: {self.st_uid}\n"
            f"gid: {self.st_gid}\n"
            f"mode: {self.st_mode:o}\n"
            f"size: {self.st_size}\n"
            f"nlink: {self.st_nlink}\n"
            f"ino: {self.st_ino}\n"
            f"ctime: {self.st_ctime}\n"
            f"atime: {self.st_atime}\n"
            f"mtime: {self.st_mtime}\n"
        )

    __repr__ = __str__


def dtype_for_mode(mode: int) -> int:
    """The ``d_type`` that goes with a ``st_mode`` (``DT_UNKNOWN`` if none does)."""
    return _DTYPES.get(_stat.S_IFMT(mode), DT_UNKNOWN)


class Dirent:
    """One directory entry. An empty name marks the end of a listing.

    python3-gfal2's ``Dirent`` (gfal2's ``struct dirent``): ``readdir``
    returns one per call and an empty ``d_name`` at the end, which is how
    existing loops stop (``while d.d_name:``).
    """

    __slots__ = ("d_ino", "d_name", "d_off", "d_reclen", "d_type")

    def __init__(
        self, d_name: str = "", d_type: int = DT_UNKNOWN, d_ino: int = 0, d_off: int = 0
    ) -> None:
        """An entry; ``d_reclen`` is derived from the name, as the kernel would set it."""
        self.d_name = d_name
        self.d_type = d_type
        self.d_ino = d_ino
        self.d_off = d_off
        self.d_reclen = _reclen(d_name) if d_name else 0

    def __repr__(self) -> str:
        """Name and type only: the two fields every protocol fills in."""
        return f"Dirent(d_name={self.d_name!r}, d_type={self.d_type})"

    def __eq__(self, other: Any) -> bool:
        """Equal on name, type and inode; ``d_off``/``d_reclen`` are positional detail."""
        if not isinstance(other, Dirent):
            return NotImplemented
        return (self.d_name, self.d_type, self.d_ino) == (other.d_name, other.d_type, other.d_ino)

    # No __hash__: defining __eq__ alone leaves the class unhashable (mutable).


def _reclen(name: str) -> int:
    """``d_reclen`` as glibc computes it: header plus name, 8-byte aligned."""
    return (19 + len(name.encode("utf-8", "surrogateescape")) + 1 + 7) & ~7


# -- transfer parameters ------------------------------------------------------------

#: The Python type a :class:`_Field` holds.
T = TypeVar("T")


class _Field(Generic[T]):
    """A typed ``TransferParameters`` property, stored as ``_<name>`` on the instance.

    The private slot keeps ``copy()`` (which clones ``vars()``) from running
    values through validation again, and an unset field reads as its default.
    """

    def __init__(self, default: T) -> None:
        """A field reading as ``default`` until set; the name comes from ``__set_name__``."""
        self.default = default
        self.name = ""

    def __set_name__(self, owner: type, name: str) -> None:
        """Learn the attribute name, used for storage and in error messages."""
        self.name = name

    @overload
    def __get__(self, instance: None, owner: type | None = None) -> _Field[T]:
        """On the class: the descriptor itself."""
        ...

    @overload
    def __get__(self, instance: object, owner: type | None = None) -> T:
        """On an instance: the field's value."""
        ...

    def __get__(self, instance: object | None, owner: type | None = None) -> Any:
        """The stored value or the default; the descriptor itself on class access."""
        if instance is None:
            return self
        return instance.__dict__.get("_" + self.name, self.default)

    def __set__(self, instance: object, value: Any) -> None:
        """Validate ``value`` now, so a bad setting fails at the assignment."""
        instance.__dict__["_" + self.name] = self.convert(value)

    def convert(self, value: Any) -> T:
        """``value`` as this field's type, or the exception Boost.Python would raise."""
        raise NotImplementedError

    def mismatch(self, value: Any, wanted: str) -> TypeError:
        """What Boost.Python raises (an ``ArgumentError``, a ``TypeError``)."""
        return TypeError(
            f"TransferParameters.{self.name} must be {wanted}, not {type(value).__name__}"
        )


class _Unsigned(_Field[int]):
    """An unsigned C integer of ``bits`` bits."""

    def __init__(self, default: int, bits: int) -> None:
        """``bits`` is the C type's width: 32 for ``guint``, 64 for ``guint64``."""
        super().__init__(default)
        self.limit = 1 << bits

    def convert(self, value: Any) -> int:
        """An int in ``[0, 2**bits)``; the messages are Boost.Python's for the same errors.

        ``operator.index`` rather than ``int()``: Boost refuses a float or a
        numeric string, and silently truncating ``timeout = 1.5`` would hide
        a caller's mistake.
        """
        try:
            number = operator.index(value)
        except TypeError:
            raise self.mismatch(value, "an int") from None
        if number < 0:
            raise OverflowError("can't convert negative value to unsigned int")
        if number >= self.limit:
            raise OverflowError("bad numeric conversion: positive overflow")
        return number


class _SciTag(_Unsigned):
    """``gfalt_set_scitag``: an unsigned int in gfal2's SciTag range."""

    def convert(self, value: Any) -> int:
        """An unsigned int, then gfal2's own range check (a ``GError``, as gfal2 raises)."""
        number = super().convert(value)
        if not 65 <= number <= 65535:
            raise GError("Invalid SciTag value (must be in the [65, 65535] range)", errno.EINVAL)
        return number


class _Flag(_Field[bool]):
    """A ``gboolean``: any integer (``True``/``False`` included), read back as ``bool``."""

    def convert(self, value: Any) -> bool:
        """``bool`` of an integer; a string (even ``"false"``) is ``TypeError``, as in Boost."""
        try:
            return bool(operator.index(value))
        except TypeError:
            raise self.mismatch(value, "a bool") from None


class _Text(_Field[str]):
    """A C string: only ``str`` is accepted (``None`` included in the refusal)."""

    def convert(self, value: Any) -> str:
        """``value`` itself, if it is a ``str``."""
        if not isinstance(value, str):
            raise self.mismatch(value, "a str")
        return value


#: ``params.event_callback``: called with each :class:`GfaltEvent`.
EventCallback = Callable[[GfaltEvent], Any]
#: ``params.monitor_callback(src, dst, average, instant, transferred, elapsed)``:
#: gfal2's ``gfalt_monitor_func`` as the bindings flatten it - average and
#: instantaneous rates in bytes/s, bytes so far, seconds so far.
MonitorCallback = Callable[[str, str, int, int, int, int], Any]


class TransferParameters:
    """What ``ctx.transfer_parameters()`` returns: the knobs of one copy.

    Attribute names, types and defaults are gfal2's. ``checksum_check`` and
    the ``*_user_defined_checksum`` pair mirror python3-gfal2's own deprecated
    ``gfal2.TransferParameters`` API: they are kept because that surface is
    emulated, and warn exactly as python3-gfal2 2.23.5 does.

    One object may be reused for many copies: the copy engine only reads it
    (a bulk copy's per-file checksums do not modify it, unlike gfal2's).
    """

    # Each field is a ``gfalt_set_*`` setter in gfal2's C API: timeout
    # (seconds for the whole copy), nbstreams and tcp_buffersize (GridFTP
    # and xrootd tuning; 0 = the plugin's default), scitag (the SciTags flow
    # label), overwrite (``replace_existing_file``), strict_copy (skip the
    # checks around the bytes: checksums, the existence check, parent
    # creation), create_parent, local_transfers (may stream through this
    # host when no plugin copies directly), proxy_delegation,
    # transfer_cleanup (remove a failed copy's destination), evict (release
    # the source's disk copy afterwards, ``gfal-copy --evict``) and the SRM
    # space tokens.
    timeout = _Unsigned(3600, 64)
    nbstreams = _Unsigned(0, 32)
    tcp_buffersize = _Unsigned(0, 64)
    scitag = _SciTag(0, 32)
    overwrite = _Flag(False)
    strict_copy = _Flag(False)
    create_parent = _Flag(False)
    local_transfers = _Flag(True)
    proxy_delegation = _Flag(True)
    transfer_cleanup = _Flag(True)
    evict = _Flag(False)
    src_spacetoken = _Text("")
    dst_spacetoken = _Text("")

    def __init__(self) -> None:
        """gfal2's defaults: no callbacks, no checksum; the fields' defaults are on the class."""
        self.event_callback: EventCallback | None = None
        self.monitor_callback: MonitorCallback | None = None
        self._mode = checksum_mode.none
        self._algorithm = ""
        self._value = ""

    def copy(self) -> TransferParameters:
        """An independent copy (``gfalt_params_handle_copy``); callbacks are shared, not copied."""
        clone = TransferParameters()
        clone.__dict__.update(vars(self))
        return clone

    # -- checksums ---------------------------------------------------------------

    def set_checksum(self, mode: int, algorithm: str | None, value: str | None) -> None:
        """Which ends to verify, with which algorithm, against which value.

        ``None`` for ``algorithm`` or ``value`` is ``""``, as python3-gfal2's
        callers pass it for "none".

        ``source`` and ``target`` compare one end with ``value``, so they
        need one; ``both`` compares the ends with each other and ``value``
        is optional. An empty ``algorithm`` lets the plugins pick (ADLER32
        for most). The checks and messages are gfal2's
        ``gfalt_set_checksum``; accepting a plain int ``mode`` is an
        extension.
        """
        member = checksum_mode.values.get(int(mode))
        if member is None:
            raise GError(f"Invalid checksum mode {mode}", errno.EINVAL)
        if member in (checksum_mode.source, checksum_mode.target) and not value:
            raise GError("Checksum value required if mode is not end to end", errno.EINVAL)
        self._mode, self._algorithm, self._value = member, algorithm or "", value or ""

    def get_checksum(self) -> tuple[checksum_mode, str, str]:
        """``(mode, algorithm, value)``, as :meth:`set_checksum` stored them."""
        return self._mode, self._algorithm, self._value

    @property
    def checksum_mode(self) -> checksum_mode:
        """The mode alone (a convenience; the bindings offer only :meth:`get_checksum`)."""
        return self._mode

    @property
    def checksum_algorithm(self) -> str:
        """The algorithm name as given (``""`` for the plugin's choice)."""
        return self._algorithm

    @property
    def checksum_value(self) -> str:
        """The expected value as given, or ``""``."""
        return self._value

    @property
    def checksum_check(self) -> bool:
        """python3-gfal2's deprecated ``checksum_check`` getter: whether any mode is set."""
        warnings.warn(
            "checksum_check is deprecated. Use get_checksum_mode instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._mode != checksum_mode.none

    @checksum_check.setter
    def checksum_check(self, enabled: bool) -> None:
        """python3-gfal2's deprecated setter: True is ``both``, False ``none`` (its mapping)."""
        warnings.warn(
            "checksum_check is deprecated. Use set_checksum instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self._mode = checksum_mode.both if enabled else checksum_mode.none

    def set_user_defined_checksum(self, algorithm: str, value: str) -> None:
        """python3-gfal2's deprecated ``set_user_defined_checksum``: keeps the current mode.

        Refused as :meth:`set_checksum` would be.
        """
        warnings.warn(
            "set_user_defined_checksum is deprecated. Use set_checksum instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.set_checksum(self._mode, algorithm, value)

    def get_user_defined_checksum(self) -> tuple[str, str]:
        """python3-gfal2's deprecated ``get_user_defined_checksum``: ``(algorithm, value)``."""
        warnings.warn(
            "get_user_defined_checksum is deprecated. Use get_checksum instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._algorithm, self._value

    def __repr__(self) -> str:
        """The settings that most often explain a copy's behaviour (an extension)."""
        return (
            f"TransferParameters(timeout={self.timeout}, nbstreams={self.nbstreams}, "
            f"overwrite={self.overwrite}, checksum={self._mode.name})"
        )
