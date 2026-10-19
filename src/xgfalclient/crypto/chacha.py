"""SSH ChaCha20 layouts and Poly1305 backed by cryptography.

``chacha20-poly1305@openssh.com`` (OpenSSH's ``PROTOCOL.chacha20poly1305``)
uses Bernstein's original ChaCha20: a 64-bit block counter and a 64-bit nonce
(the packet sequence number). pyca ``cryptography`` takes a single 16-byte
"nonce" that is really the last four words of the ChaCha state - counter
first, little-endian - so either layout can be fed to it by building those 16
bytes: :func:`djb_iv` for the original layout, :func:`rfc_iv` for RFC 8439's
32-bit counter and 96-bit nonce. The two produce the same state as long as the
counter does not wrap 32 bits, which an SSH packet (at most 256 KiB, i.e. 4096
blocks) never approaches.

Nothing here is a general-purpose AEAD: OpenSSH's construction (a separate
key for the length field, the Poly1305 key taken from block 0) is assembled in
:mod:`xgfalclient.plugins.sftp.ssh` from these primitives.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305

__all__ = ["chacha20_block", "chacha20_xor", "djb_iv", "poly1305", "rfc_iv"]


def djb_iv(counter: int, nonce: bytes) -> bytes:
    """The 16-byte IV block for the original layout: 64-bit LE counter, 8-byte nonce."""
    return struct.pack("<Q", counter) + nonce


def rfc_iv(counter: int, nonce: bytes) -> bytes:
    """The 16-byte IV block for RFC 8439: 32-bit LE counter, 12-byte nonce."""
    return struct.pack("<I", counter) + nonce


def chacha20_xor(key: bytes, iv: bytes, data: bytes | bytearray | memoryview) -> bytes:
    """``data`` XORed with the ChaCha20 keystream starting at ``iv``.

    Encryption and decryption are the same operation. ``iv`` is a full
    16-byte state block from :func:`djb_iv` or :func:`rfc_iv`; the sizes are
    checked here so that a slicing mistake in the SSH framing is a
    ``ValueError`` naming ChaCha20 rather than the library's generic message.
    A fresh cipher object per call is deliberate: the SSH construction
    re-keys the counter for every packet, so there is no stream to keep.
    """
    if len(key) != 32 or len(iv) != 16:
        raise ValueError("ChaCha20 takes a 32-byte key and a 16-byte IV block")
    return Cipher(algorithms.ChaCha20(key, iv), mode=None).encryptor().update(data)


def chacha20_block(key: bytes, iv: bytes) -> bytes:
    """One raw 64-byte keystream block (the RFC 8439 §2.3 block function's output)."""
    return chacha20_xor(key, iv, bytes(64))


def poly1305(key: bytes, message: bytes | bytearray | memoryview) -> bytes:
    """The 16-byte Poly1305 tag of ``message`` under a 32-byte one-time ``key``.

    The key must never be reused; OpenSSH derives a new one per packet from
    the first ChaCha20 block. Callers compare tags with
    ``hmac.compare_digest``, never ``==``.
    """
    return Poly1305.generate_tag(key, message)
