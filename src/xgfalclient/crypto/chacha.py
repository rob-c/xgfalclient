"""ChaCha20 and Poly1305 (:rfc:`8439`) in pure Python - the fallback backend.

SSH uses these as ``chacha20-poly1305@openssh.com``, which is DJB's
original ChaCha20 layout (64-bit block counter, 64-bit nonce) rather than
the RFC's (32-bit counter, 96-bit nonce). The two differ only in how the
last four state words are filled, so :func:`chacha20_xor` takes the raw
16-byte "counter and nonce" block and serves both.

This is correct and slow (a few MB/s): it exists so the SSH transport works
where no libcrypto can be found. :mod:`.libcrypto` is the fast path.
"""

from __future__ import annotations

import struct

__all__ = ["chacha20_block", "chacha20_xor", "poly1305", "djb_iv", "rfc_iv"]

_MASK = 0xFFFFFFFF
_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_WORDS = struct.Struct("<16I")


def _rounds(state: list[int]) -> list[int]:
    x = list(state)
    for _ in range(10):
        for a, b, c, d in (
            (0, 4, 8, 12),
            (1, 5, 9, 13),
            (2, 6, 10, 14),
            (3, 7, 11, 15),
            (0, 5, 10, 15),
            (1, 6, 11, 12),
            (2, 7, 8, 13),
            (3, 4, 9, 14),
        ):
            x[a] = (x[a] + x[b]) & _MASK
            v = x[d] ^ x[a]
            x[d] = ((v << 16) | (v >> 16)) & _MASK
            x[c] = (x[c] + x[d]) & _MASK
            v = x[b] ^ x[c]
            x[b] = ((v << 12) | (v >> 20)) & _MASK
            x[a] = (x[a] + x[b]) & _MASK
            v = x[d] ^ x[a]
            x[d] = ((v << 8) | (v >> 24)) & _MASK
            x[c] = (x[c] + x[d]) & _MASK
            v = x[b] ^ x[c]
            x[b] = ((v << 7) | (v >> 25)) & _MASK
    return [(x[i] + state[i]) & _MASK for i in range(16)]


def chacha20_block(key: bytes, iv: bytes) -> bytes:
    """One 64-byte keystream block for ``key`` and the 16-byte ``iv`` words."""
    state = [*_CONSTANTS, *struct.unpack("<8I", key), *struct.unpack("<4I", iv)]
    return _WORDS.pack(*_rounds(state))


def djb_iv(counter: int, nonce: bytes) -> bytes:
    """State words 12-15 for a 64-bit counter and 8-byte nonce (OpenSSH's layout)."""
    return struct.pack("<Q", counter) + nonce


def rfc_iv(counter: int, nonce: bytes) -> bytes:
    """State words 12-15 for :rfc:`8439`'s 32-bit counter and 12-byte nonce."""
    return struct.pack("<I", counter) + nonce


def chacha20_xor(key: bytes, iv: bytes, data: bytes | bytearray | memoryview) -> bytes:
    """XOR ``data`` with the keystream starting at ``iv`` (counter in its low word(s)).

    The counter is incremented as a 64-bit little-endian value over the
    first eight IV bytes, which is right for both layouts as long as an RFC
    counter never wraps (256 GiB per nonce - never, for a packet).
    """
    if len(key) != 32 or len(iv) != 16:
        raise ValueError("ChaCha20 takes a 32-byte key and a 16-byte IV block")
    length = len(data)
    counter = struct.unpack("<Q", iv[:8])[0]
    tail = iv[8:]
    stream = bytearray()
    for index in range((length + 63) // 64):
        stream += chacha20_block(key, struct.pack("<Q", (counter + index) & (2**64 - 1)) + tail)
    if not length:
        return b""
    mixed = int.from_bytes(data, "little") ^ int.from_bytes(stream[:length], "little")
    return mixed.to_bytes(length, "little")


_P1305 = (1 << 130) - 5


def poly1305(key: bytes, message: bytes | bytearray | memoryview) -> bytes:
    """The 16-byte Poly1305 tag of ``message`` under a one-time 32-byte ``key``."""
    if len(key) != 32:
        raise ValueError("Poly1305 keys are 32 bytes")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    view = memoryview(message).cast("B")
    accumulator = 0
    for offset in range(0, len(view), 16):
        block = view[offset : offset + 16]
        value = int.from_bytes(block, "little") | (1 << (8 * len(block)))
        accumulator = (accumulator + value) * r % _P1305
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")
