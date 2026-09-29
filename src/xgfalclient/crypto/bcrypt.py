"""``bcrypt_pbkdf``: the key derivation behind passphrase-protected OpenSSH keys.

``ssh-keygen`` encrypts a private key with ``aes256-ctr`` under a key and IV
drawn from OpenBSD's ``bcrypt_pbkdf`` (a PBKDF2 whose PRF is the eksblowfish
"bcrypt hash"). It is deliberately slow - that is its job - and in pure
Python it is slower still: a few seconds for ``ssh-keygen``'s default 16
rounds. Keys are decrypted once per process and cached by the caller, so
that is paid once, and only on the rare machine with no ``ssh`` binary
(OpenSSH decrypts its own keys).

Blowfish's initial state is the fractional hexadecimal digits of pi. Rather
than carry a 4 KiB table, they are computed on first use with Machin's
formula, which is exact integer arithmetic and takes milliseconds.
"""

from __future__ import annotations

import hashlib
import struct
import threading

__all__ = ["bcrypt_pbkdf", "bcrypt_hash", "pi_words"]

_WORDS_NEEDED = 18 + 4 * 256
_lock = threading.Lock()
_pi: list[int] = []


def _arctan_inverse(x: int, one: int) -> int:
    """``arctan(1/x) * one`` by its Taylor series, in integers."""
    power = one // x
    total = power
    x2 = x * x
    n = 1
    sign = -1
    while power:
        power //= x2
        n += 2
        total += sign * (power // n)
        sign = -sign
    return total


def pi_words() -> list[int]:
    """The first 1042 32-bit words of pi's fractional part: Blowfish's P and S."""
    with _lock:
        if not _pi:
            bits = 32 * _WORDS_NEEDED
            guard = 64
            one = 1 << (bits + guard)
            pi = 4 * (4 * _arctan_inverse(5, one) - _arctan_inverse(239, one))
            fraction = (pi - 3 * one) >> guard
            _pi.extend(
                (fraction >> (bits - 32 * (i + 1))) & 0xFFFFFFFF for i in range(_WORDS_NEEDED)
            )
        return list(_pi)


class _Blowfish:
    """The mutable eksblowfish state: ``p`` (18 words) and ``s`` (4 x 256)."""

    def __init__(self) -> None:
        words = pi_words()
        self.p = words[:18]
        self.s = [words[18 + 256 * i : 18 + 256 * (i + 1)] for i in range(4)]

    def encipher(self, left: int, right: int) -> tuple[int, int]:
        p = self.p
        s0, s1, s2, s3 = self.s
        left ^= p[0]
        for i in range(1, 17, 2):
            right ^= (
                ((s0[left >> 24] + s1[(left >> 16) & 255]) ^ s2[(left >> 8) & 255]) + s3[left & 255]
            ) & 0xFFFFFFFF ^ p[i]
            left ^= (
                ((s0[right >> 24] + s1[(right >> 16) & 255]) ^ s2[(right >> 8) & 255])
                + s3[right & 255]
            ) & 0xFFFFFFFF ^ p[i + 1]
        return right ^ p[17], left

    def _refill(self, data: list[int] | None) -> None:
        """Re-encrypt P and S in place, chaining, optionally XOR-ing in ``data``."""
        left = right = 0
        position = 0
        length = len(data) if data else 0
        tables = [self.p, *self.s]
        for table in tables:
            for index in range(0, len(table), 2):
                if data:
                    left ^= data[position % length]
                    right ^= data[(position + 1) % length]
                    position += 2
                left, right = self.encipher(left, right)
                table[index] = left
                table[index + 1] = right

    def expand(self, data: list[int] | None, key: list[int]) -> None:
        """``Blowfish_expandstate`` (with ``data``) or ``expand0state`` (without)."""
        for i in range(18):
            self.p[i] ^= key[i % len(key)]
        self._refill(data)


def _words(data: bytes) -> list[int]:
    """Big-endian words, cycling as ``Blowfish_stream2word`` does (``len % 4 == 0`` here)."""
    return list(struct.unpack(f">{len(data) // 4}I", data))


_MAGIC = _words(b"OxychromaticBlowfishSwatDynamite")


def bcrypt_hash(sha2pass: bytes, sha2salt: bytes) -> bytes:
    """OpenBSD's ``bcrypt_hash``: 32 bytes from two 64-byte SHA-512 digests."""
    password = _words(sha2pass)
    salt = _words(sha2salt)
    state = _Blowfish()
    state.expand(salt, password)
    for _ in range(64):
        state.expand(None, salt)
        state.expand(None, password)
    cdata = list(_MAGIC)
    for _ in range(64):
        for i in range(0, 8, 2):
            cdata[i], cdata[i + 1] = state.encipher(cdata[i], cdata[i + 1])
    return struct.pack("<8I", *cdata)


def bcrypt_pbkdf(password: bytes, salt: bytes, length: int, rounds: int) -> bytes:
    """``length`` bytes of key material, byte-for-byte what OpenSSH derives."""
    if rounds < 1 or not password or not salt or not 0 < length <= 1024:
        raise ValueError("bcrypt_pbkdf needs a password, a salt, rounds >= 1 and 1-1024 bytes")
    stride = (length + 31) // 32
    amount = (length + stride - 1) // stride
    sha2pass = hashlib.sha512(password).digest()
    key = bytearray(length)
    remaining = length
    count = 1
    while remaining > 0:
        tmp = bcrypt_hash(sha2pass, hashlib.sha512(salt + struct.pack(">I", count)).digest())
        out = bytearray(tmp)
        for _ in range(1, rounds):
            tmp = bcrypt_hash(sha2pass, hashlib.sha512(tmp).digest())
            for i in range(32):
                out[i] ^= tmp[i]
        amount = min(amount, remaining)
        written = 0
        for i in range(amount):
            destination = i * stride + (count - 1)
            if destination >= length:
                break
            key[destination] = out[i]
            written += 1
        remaining -= written
        count += 1
    return bytes(key)
