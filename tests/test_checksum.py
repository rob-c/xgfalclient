"""Checksum algorithms, comparison rules, and the optional CRC-32C accelerator."""

from __future__ import annotations

import zlib

import pytest
from xrdcore.checksum import Checksum

from xgfalclient import checksum

HELLO = b"hello world\n"
HELLO_CRC32 = format(zlib.crc32(HELLO), "08x")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("adler32", "1e720467"),
        ("ADLER32", "1e720467"),
        ("crc32", HELLO_CRC32),
        ("md5", "6f5902ac237024bdd0c176cb93063dc4"),
        ("sha-256", "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"),
        ("UNIXcksum", HELLO_CRC32),
    ],
)
def test_known_digests(name: str, expected: str) -> None:
    assert checksum.checksum_bytes(name, b"hello world\n") == expected


def test_crc32c_reference_vectors() -> None:
    # RFC 3720 appendix B.4 and the "123456789" check value.
    assert checksum.crc32c_py(b"123456789") == 0xE3069283
    assert checksum.crc32c_py(bytes(32)) == 0x8A9136AA
    assert checksum.crc32c_py(b"\xff" * 32) == 0x62A8AB43
    assert checksum.checksum_bytes("crc32c", b"123456789") == "e3069283"
    # Chaining equals one pass, across the slice-by-eight boundary.
    data = bytes(range(256)) * 3
    assert checksum.crc32c_py(data[100:], checksum.crc32c_py(data[:100])) == checksum.crc32c_py(
        data
    )


def test_incremental_equals_one_shot() -> None:
    for name in checksum.algorithms():
        digest = checksum.new(name)
        digest.update(b"hello ")
        digest.update(memoryview(b"world\n"))
        assert digest.hexdigest() == checksum.checksum_bytes(name, b"hello world\n")
        assert digest.name == name
    assert checksum.checksum_chunks("adler32", [b"hello ", b"world\n"]) == "1e720467"
    rolling = checksum.new("adler32")
    assert isinstance(rolling, Checksum) and rolling.value == 1


def test_unknown_algorithm() -> None:
    with pytest.raises(ValueError, match="bogus"):
        checksum.new("bogus")


def test_normalise_and_compare() -> None:
    assert checksum.normalise_name(" SHA-1 ") == "sha1"
    assert checksum.format_adler32("abc") == "00000abc"
    assert checksum.format_adler32("1E720467") == "1e720467"
    assert checksum.checksums_match("00ABC", "abc ")
    assert not checksum.checksums_match("abc", "abd")


def test_crc32c_is_the_shared_implementation() -> None:
    """One CRC-32C for every client: xrdcore's, accelerator probe and all."""
    import importlib

    shared = importlib.import_module("xrdcore.crc32c")

    assert checksum.crc32c is shared.crc32c
    assert checksum.crc32c_py is shared.crc32c_py
    assert checksum.IS_ACCELERATED is shared.IS_ACCELERATED
    with pytest.raises(AttributeError, match="no_such_name"):
        _ = checksum.no_such_name


def test_gfal2_algorithm_set_is_kept() -> None:
    """xrdcore computes CRC-64 too; gfal2 knows no such algorithm."""
    assert "crc64" not in checksum.algorithms()
    with pytest.raises(ValueError, match="crc64"):
        checksum.new("crc64")
