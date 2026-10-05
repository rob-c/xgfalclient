"""SSH ChaCha20 layouts and Poly1305 backed by cryptography.

SSH uses the original 64-bit counter/64-bit nonce layout. RFC 8439's
32-bit counter/96-bit nonce produces the same state before counter wrap.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305

__all__ = ["chacha20_block", "chacha20_xor", "poly1305", "djb_iv", "rfc_iv"]


def djb_iv(counter: int, nonce: bytes) -> bytes:
    return struct.pack("<Q", counter) + nonce


def rfc_iv(counter: int, nonce: bytes) -> bytes:
    return struct.pack("<I", counter) + nonce


def chacha20_xor(key: bytes, iv: bytes, data: bytes | bytearray | memoryview) -> bytes:
    if len(key) != 32 or len(iv) != 16:
        raise ValueError("ChaCha20 takes a 32-byte key and a 16-byte IV block")
    return Cipher(algorithms.ChaCha20(key, iv), mode=None).encryptor().update(data)


def chacha20_block(key: bytes, iv: bytes) -> bytes:
    return chacha20_xor(key, iv, bytes(64))


def poly1305(key: bytes, message: bytes | bytearray | memoryview) -> bytes:
    return Poly1305.generate_tag(key, message)
