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
    "Stat",
    "Dirent",
    "TransferParameters",
    "DT_UNKNOWN",
    "DT_FIFO",
    "DT_CHR",
    "DT_DIR",
    "DT_BLK",
    "DT_REG",
    "DT_LNK",
    "DT_SOCK",
    "dtype_for_mode",
]

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
        return _stat.S_ISDIR(self.st_mode)

    def is_file(self) -> bool:
        return _stat.S_ISREG(self.st_mode)

    def is_link(self) -> bool:
        return _stat.S_ISLNK(self.st_mode)

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in _FIELDS}

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Stat):
            return NotImplemented
        return self.as_dict() == other.as_dict()

    __hash__ = None  # type: ignore[assignment]  # mutable, like gfal2's

    def __str__(self) -> str:
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
    """One directory entry. An empty name marks the end of a listing."""

    __slots__ = ("d_ino", "d_name", "d_off", "d_reclen", "d_type")

    def __init__(
        self, d_name: str = "", d_type: int = DT_UNKNOWN, d_ino: int = 0, d_off: int = 0
    ) -> None:
        self.d_name = d_name
        self.d_type = d_type
        self.d_ino = d_ino
        self.d_off = d_off
        self.d_reclen = _reclen(d_name) if d_name else 0

    def __repr__(self) -> str:
        return f"Dirent(d_name={self.d_name!r}, d_type={self.d_type})"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Dirent):
            return NotImplemented
        return (self.d_name, self.d_type, self.d_ino) == (other.d_name, other.d_type, other.d_ino)

    __hash__ = None  # type: ignore[assignment]


def _reclen(name: str) -> int:
    """``d_reclen`` as glibc computes it: header plus name, 8-byte aligned."""
    return (19 + len(name.encode("utf-8", "surrogateescape")) + 1 + 7) & ~7


# -- transfer parameters ------------------------------------------------------------

T = TypeVar("T")


class _Field(Generic[T]):
    """A typed ``TransferParameters`` property, stored as ``_<name>`` on the instance.

    The private slot keeps ``copy()`` (which clones ``vars()``) from running
    values through validation again, and an unset field reads as its default.
    """

    def __init__(self, default: T) -> None:
        self.default = default
        self.name = ""

    def __set_name__(self, owner: type, name: str) -> None:
        self.name = name

    @overload
    def __get__(self, instance: None, owner: type | None = None) -> _Field[T]: ...

    @overload
    def __get__(self, instance: object, owner: type | None = None) -> T: ...

    def __get__(self, instance: object | None, owner: type | None = None) -> Any:
        if instance is None:
            return self
        return instance.__dict__.get("_" + self.name, self.default)

    def __set__(self, instance: object, value: Any) -> None:
        instance.__dict__["_" + self.name] = self.convert(value)

    def convert(self, value: Any) -> T:
        raise NotImplementedError

    def mismatch(self, value: Any, wanted: str) -> TypeError:
        """What Boost.Python raises (an ``ArgumentError``, a ``TypeError``)."""
        return TypeError(
            f"TransferParameters.{self.name} must be {wanted}, not {type(value).__name__}"
        )


class _Unsigned(_Field[int]):
    """An unsigned C integer of ``bits`` bits."""

    def __init__(self, default: int, bits: int) -> None:
        super().__init__(default)
        self.limit = 1 << bits

    def convert(self, value: Any) -> int:
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
        number = super().convert(value)
        if not 65 <= number <= 65535:
            raise GError("Invalid SciTag value (must be in the [65, 65535] range)", errno.EINVAL)
        return number


class _Flag(_Field[bool]):
    def convert(self, value: Any) -> bool:
        try:
            return bool(operator.index(value))
        except TypeError:
            raise self.mismatch(value, "a bool") from None


class _Text(_Field[str]):
    def convert(self, value: Any) -> str:
        if not isinstance(value, str):
            raise self.mismatch(value, "a str")
        return value


EventCallback = Callable[[GfaltEvent], Any]
MonitorCallback = Callable[[str, str, int, int, int, int], Any]


class TransferParameters:
    """What ``ctx.transfer_parameters()`` returns: the knobs of one copy.

    Attribute names, types and defaults are gfal2's. ``checksum_check`` and
    the ``*_user_defined_checksum`` pair are gfal2's deprecated spellings of
    :meth:`set_checksum` and still work, with the same warnings.
    """

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
        self.event_callback: EventCallback | None = None
        self.monitor_callback: MonitorCallback | None = None
        self._mode = checksum_mode.none
        self._algorithm = ""
        self._value = ""

    def copy(self) -> TransferParameters:
        clone = TransferParameters()
        clone.__dict__.update(vars(self))
        return clone

    # -- checksums ---------------------------------------------------------------

    def set_checksum(self, mode: int, algorithm: str, value: str) -> None:
        """Which ends to verify, with which algorithm, against which value.

        ``source`` and ``target`` compare one end with ``value``, so they
        need one; ``both`` compares the ends with each other and ``value``
        is optional.
        """
        member = checksum_mode.values.get(int(mode))
        if member is None:
            raise GError(f"Invalid checksum mode {mode}", errno.EINVAL)
        if member in (checksum_mode.source, checksum_mode.target) and not value:
            raise GError("Checksum value required if mode is not end to end", errno.EINVAL)
        self._mode, self._algorithm, self._value = member, algorithm or "", value or ""

    def get_checksum(self) -> tuple[checksum_mode, str, str]:
        return self._mode, self._algorithm, self._value

    @property
    def checksum_mode(self) -> checksum_mode:
        return self._mode

    @property
    def checksum_algorithm(self) -> str:
        return self._algorithm

    @property
    def checksum_value(self) -> str:
        return self._value

    @property
    def checksum_check(self) -> bool:
        warnings.warn(
            "checksum_check is deprecated. Use get_checksum_mode instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._mode != checksum_mode.none

    @checksum_check.setter
    def checksum_check(self, enabled: bool) -> None:
        warnings.warn(
            "checksum_check is deprecated. Use set_checksum instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self._mode = checksum_mode.both if enabled else checksum_mode.none

    def set_user_defined_checksum(self, algorithm: str, value: str) -> None:
        """Keeps the current mode, and is refused as :meth:`set_checksum` would be."""
        warnings.warn(
            "set_user_defined_checksum is deprecated. Use set_checksum instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.set_checksum(self._mode, algorithm, value)

    def get_user_defined_checksum(self) -> tuple[str, str]:
        warnings.warn(
            "get_user_defined_checksum is deprecated. Use get_checksum instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._algorithm, self._value

    def __repr__(self) -> str:
        return (
            f"TransferParameters(timeout={self.timeout}, nbstreams={self.nbstreams}, "
            f"overwrite={self.overwrite}, checksum={self._mode.name})"
        )
