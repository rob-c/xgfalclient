"""Checksum algorithms by the names storage elements use, and how to compare them.

Every algorithm has the incremental ``hashlib`` shape, so a streamed copy can
digest as it goes::

    >>> digest = new("ADLER32")
    >>> digest.update(b"hello world\\n")
    >>> digest.hexdigest()
    '1e720467'

ADLER32, CRC32, MD5 and the SHA family come from ``zlib`` and ``hashlib``,
which are C. CRC-32C has no stdlib implementation; a slice-by-eight pure
Python one is used unless ``google-crc32c`` happens to be importable, in
which case that is.
"""

from __future__ import annotations

import hashlib
import importlib
import zlib
from collections.abc import Callable, Iterable
from typing import Protocol, Union

__all__ = [
    "Digest",
    "new",
    "algorithms",
    "normalise_name",
    "checksum_bytes",
    "checksum_chunks",
    "checksums_match",
    "format_adler32",
    "crc32c",
    "IS_ACCELERATED",
]

Buffer = Union[bytes, bytearray, memoryview]

_POLY = 0x82F63B78
_MASK = 0xFFFFFFFF


def _tables() -> list[list[int]]:
    first = []
    for n in range(256):
        crc = n
        for _ in range(8):
            crc = (crc >> 1) ^ _POLY if crc & 1 else crc >> 1
        first.append(crc)
    tables = [first]
    for k in range(1, 8):
        tables.append([(v >> 8) ^ first[v & 0xFF] for v in tables[k - 1]])
    return tables


_T0, _T1, _T2, _T3, _T4, _T5, _T6, _T7 = _tables()


def crc32c_py(data: Buffer, crc: int = 0) -> int:
    """Slice-by-eight software CRC-32C, chained onto ``crc``."""
    view = memoryview(data).cast("B")
    size = len(view)
    value = (crc ^ _MASK) & _MASK
    index = 0
    limit = size - (size % 8)
    while index < limit:
        value ^= int.from_bytes(view[index : index + 4], "little")
        value = (
            _T7[value & 0xFF]
            ^ _T6[(value >> 8) & 0xFF]
            ^ _T5[(value >> 16) & 0xFF]
            ^ _T4[value >> 24]
            ^ _T3[view[index + 4]]
            ^ _T2[view[index + 5]]
            ^ _T1[view[index + 6]]
            ^ _T0[view[index + 7]]
        )
        index += 8
    while index < size:
        value = _T0[(value ^ view[index]) & 0xFF] ^ (value >> 8)
        index += 1
    return value ^ _MASK


def _accelerated(module: str = "google_crc32c") -> Callable[[Buffer, int], int] | None:
    """A C CRC-32C from an optional package, if one is importable."""
    try:
        extend = importlib.import_module(module).extend
    except (ImportError, AttributeError):
        return None

    def crc32c_c(data: Buffer, crc: int = 0) -> int:
        return int(extend(crc, bytes(data)))

    return crc32c_c


def _select(fast: Callable[[Buffer, int], int] | None) -> Callable[[Buffer, int], int]:
    """The accelerated CRC-32C if there is one, else the pure Python one."""
    return fast or crc32c_py


_FAST = _accelerated()
crc32c: Callable[[Buffer, int], int] = _select(_FAST)
IS_ACCELERATED = _FAST is not None


class Digest(Protocol):
    name: str

    def update(self, data: Buffer) -> None: ...

    def hexdigest(self) -> str: ...


class _Rolling:
    """A 32-bit rolling checksum (``zlib.adler32`` shaped) as a digest."""

    __slots__ = ("_step", "_value", "name")

    def __init__(self, name: str, step: Callable[[Buffer, int], int], seed: int) -> None:
        self.name = name
        self._step = step
        self._value = seed

    def update(self, data: Buffer) -> None:
        self._value = self._step(data, self._value)

    @property
    def value(self) -> int:
        return self._value

    def hexdigest(self) -> str:
        return f"{self._value:08x}"


class _Hash:
    __slots__ = ("_hash", "name")

    def __init__(self, name: str) -> None:
        self.name = name
        self._hash = hashlib.new(name)

    def update(self, data: Buffer) -> None:
        self._hash.update(data)

    def hexdigest(self) -> str:
        return self._hash.hexdigest()


_ROLLING: dict[str, tuple[Callable[[Buffer, int], int], int]] = {
    "adler32": (zlib.adler32, 1),
    "crc32": (zlib.crc32, 0),
    "crc32c": (lambda data, crc: crc32c(data, crc), 0),
}
_HASHES = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")
_ALIASES = {"sha-1": "sha1", "sha-256": "sha256", "sha-512": "sha512", "unixcksum": "crc32"}


def normalise_name(name: str) -> str:
    """``"ADLER32"``, ``"Adler32"`` and ``"adler32"`` are the same algorithm."""
    key = name.strip().lower()
    return _ALIASES.get(key, key)


def algorithms() -> tuple[str, ...]:
    return (*_ROLLING, *_HASHES)


def new(name: str) -> _Rolling | _Hash:
    """A fresh incremental digest; ``ValueError`` for an unknown algorithm."""
    key = normalise_name(name)
    if key in _ROLLING:
        step, seed = _ROLLING[key]
        return _Rolling(key, step, seed)
    if key in _HASHES:
        return _Hash(key)
    raise ValueError(f"unknown checksum algorithm {name!r}")


def checksum_bytes(name: str, data: Buffer) -> str:
    digest = new(name)
    digest.update(data)
    return digest.hexdigest()


def checksum_chunks(name: str, chunks: Iterable[Buffer]) -> str:
    digest = new(name)
    for chunk in chunks:
        digest.update(chunk)
    return digest.hexdigest()


def format_adler32(value: str) -> str:
    """Zero-pad an ADLER32 to eight hex digits (``FORMAT_ADLER32_CHECKSUM``).

    Some servers drop leading zeros; gfal2 pads them back so the value
    compares equal to one computed locally.
    """
    text = value.strip().lower()
    return text.rjust(8, "0") if len(text) < 8 else text


def checksums_match(first: str, second: str) -> bool:
    """Equal ignoring case, surrounding space, and leading zeros."""
    left = first.strip().lower().lstrip("0")
    right = second.strip().lower().lstrip("0")
    return left == right
