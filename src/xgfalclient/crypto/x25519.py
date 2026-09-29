"""X25519 (:rfc:`7748`) in pure Python, for SSH's ``curve25519-sha256`` key exchange.

One scalar multiplication on the Montgomery curve per handshake, done with
the RFC's constant-structure ladder. Python integers make the field
arithmetic a line each; a ladder is about 255 steps of a dozen modular
multiplications, well under ten milliseconds, which is noise next to a TCP
round trip. Nothing here is constant-time in the side-channel sense - the
secret is ephemeral, used once, and never touches attacker-chosen input in
a loop.
"""

from __future__ import annotations

import os

__all__ = ["P", "BASE_POINT", "x25519", "generate", "public_key"]

P = 2**255 - 19
_A24 = 121665
#: The u-coordinate of the base point, encoded.
BASE_POINT = (9).to_bytes(32, "little")


def _decode_scalar(k: bytes) -> int:
    if len(k) != 32:
        raise ValueError("X25519 scalars are 32 bytes")
    value = bytearray(k)
    value[0] &= 248
    value[31] &= 127
    value[31] |= 64
    return int.from_bytes(value, "little")


def _decode_u(u: bytes) -> int:
    if len(u) != 32:
        raise ValueError("X25519 u-coordinates are 32 bytes")
    return (int.from_bytes(u, "little") & ((1 << 255) - 1)) % P


def x25519(k: bytes, u: bytes) -> bytes:
    """The shared u-coordinate ``k * u``; raises on the all-zero result.

    :rfc:`8731` requires refusing a zero shared secret (a small-order peer
    key), so that check is made here rather than left to every caller.
    """
    scalar = _decode_scalar(k)
    x1 = _decode_u(u)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = x2 + z2
        aa = a * a % P
        b = x2 - z2
        bb = b * b % P
        e = aa - bb
        c = x3 + z3
        d = x3 - z3
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + _A24 * e) % P
    # RFC 7748 ends with one more conditional swap, on the last bit processed;
    # clamping clears scalar bit 0, so that swap never happens and is left out.
    result = x2 * pow(z2, P - 2, P) % P
    if result == 0:
        raise ValueError("X25519 produced the all-zero shared secret")
    return result.to_bytes(32, "little")


def public_key(private: bytes) -> bytes:
    return x25519(private, BASE_POINT)


def generate() -> tuple[bytes, bytes]:
    """A fresh ``(private, public)`` pair."""
    private = os.urandom(32)
    return private, public_key(private)
