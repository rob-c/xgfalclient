"""Checksum algorithms by the names storage elements use, and how to compare them.

Every algorithm has the incremental ``hashlib`` shape, so a streamed copy can
digest as it goes::

    >>> digest = new("ADLER32")
    >>> digest.update(b"hello world\\n")
    >>> digest.hexdigest()
    '1e720467'

The digests themselves are xrdcore's (:mod:`xrdcore.checksum`,
:mod:`xrdcore.crc32c`; until 0.4.0 they were reached through xrdclient's
``crypto.checksum``): ADLER32, CRC32, MD5 and the SHA family come from
``zlib`` and ``hashlib``, and CRC-32C is ``google-crc32c``'s C extension when
that is installed, else xrdcore's slice-by-eight pure Python one. One
implementation serves every client, so a CRC-32C an XRootD paged read checks
and one a gfal2 copy compares are the same function.

What stays here is gfal2's *naming policy*, which is not XrdCl's:

* the algorithm set is gfal2's - ADLER32, CRC32, CRC32C, MD5 and the SHAs -
  so an algorithm gfal2 would not know (xrdcore's ``crc64``) is still the
  ``ValueError`` callers turn into gfal2's "not supported" answer;
* names are case- and space-insensitive, ``SHA-256`` is ``sha256``, and
  ``UNIXcksum`` is answered as CRC32, as gfal2's file plugin does;
* the ADLER32 zero-padding and the leading-zero-insensitive comparison gfal2
  applies before calling two checksums different.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from xrdcore.crc32c import IS_ACCELERATED as IS_ACCELERATED
    from xrdcore.crc32c import crc32c as crc32c
    from xrdcore.crc32c import crc32c_py as crc32c_py

__all__ = [
    "IS_ACCELERATED",
    "Digest",
    "algorithms",
    "checksum_bytes",
    "checksum_chunks",
    "checksums_match",
    "crc32c",
    "crc32c_py",
    "format_adler32",
    "new",
    "normalise_name",
]

Buffer = bytes | bytearray | memoryview

#: What gfal2 can compute, in the order gfal2 lists them: the rolling
#: checksums first, then the hashes.
_GFAL2_ALGORITHMS = (
    "adler32",
    "crc32",
    "crc32c",
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
)
#: Spellings servers and users use for the same algorithm. ``UNIXcksum`` is
#: answered with CRC32 because gfal2's file plugin does so; it is *not* the
#: POSIX ``cksum`` algorithm, and a value from a real ``cksum`` will differ.
_ALIASES = {"sha-1": "sha1", "sha-256": "sha256", "sha-512": "sha512", "unixcksum": "crc32"}


class Digest(Protocol):
    """The incremental digest shape every algorithm here has."""

    #: The algorithm's lower-case name, as :func:`normalise_name` spells it.
    name: str

    def update(self, data: Buffer) -> None:
        """Feed ``data`` in; may be called any number of times, in stream order."""

    def hexdigest(self) -> str:
        """The digest of everything fed so far, as lower-case hex.

        For ADLER32 and the CRCs this is the 32-bit value as eight hex
        digits; storage elements that drop leading zeros are reconciled by
        :func:`format_adler32` and :func:`checksums_match`, not here.
        """


def normalise_name(name: str) -> str:
    """``"ADLER32"``, ``"Adler32"`` and ``"adler32"`` are the same algorithm."""
    key = name.strip().lower()
    return _ALIASES.get(key, key)


def algorithms() -> tuple[str, ...]:
    """Every algorithm gfal2 (and so this module) computes."""
    return _GFAL2_ALGORITHMS


def new(name: str) -> Digest:
    """A fresh incremental digest; ``ValueError`` for an algorithm gfal2 does not know."""
    from xrdcore.checksum import new as shared_new

    key = normalise_name(name)
    if key not in _GFAL2_ALGORITHMS:
        raise ValueError(f"unknown checksum algorithm {name!r}")
    return shared_new(key)


#: The names resolved from :mod:`xrdcore.crc32c` on first use. ``crc32c_py``
#: is the pure Python CRC-32C, accelerator or no, which the test servers use
#: to compute what a client must match.
_SHARED = frozenset({"crc32c", "IS_ACCELERATED", "crc32c_py"})


def __getattr__(name: str) -> object:
    """``crc32c``, ``crc32c_py`` and ``IS_ACCELERATED``, from xrdcore when first asked for.

    ``import gfal2`` must stay cheap (tests/test_import_cost.py): probing for
    the ``google-crc32c`` accelerator is not free, and the copy core imports
    this module for its comparison helpers alone.
    """
    if name in _SHARED:
        import importlib

        # By path: the ``xrdcore.crc32c`` module itself, never an attribute
        # of the package that might shadow it.
        shared = importlib.import_module("xrdcore.crc32c")
        value = getattr(shared, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def checksum_bytes(name: str, data: Buffer) -> str:
    """Hex digest of ``data``."""
    digest = new(name)
    digest.update(data)
    return digest.hexdigest()


def checksum_chunks(name: str, chunks: Iterable[Buffer]) -> str:
    """Hex digest of a stream of chunks."""
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
    """Equal ignoring case, surrounding space, and leading zeros.

    gfal2's copy compares checksums this way so that a server's unpadded
    ADLER32 (``"1e72"``) and a locally computed one (``"00001e72"``) agree;
    hex digests of the hash family are fixed-width, so stripping zeros
    cannot make two different ones equal.
    """
    left = first.strip().lower().lstrip("0")
    right = second.strip().lower().lstrip("0")
    return left == right
