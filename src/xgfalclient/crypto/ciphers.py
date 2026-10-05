"""SSH cipher API backed by cryptography, without local OpenSSL ABI bindings."""

from __future__ import annotations

from typing import Protocol, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import aes, chacha

__all__ = ["Aead", "Backend", "Keystream", "ChaCha20", "get", "PURE", "BACKENDS"]

Buffer = Union[bytes, bytearray, memoryview]


class Keystream(Protocol):
    def update(self, data: Buffer) -> bytes | bytearray: ...


class ChaCha20(Protocol):
    def xor(self, iv: bytes, data: Buffer) -> bytes | bytearray: ...


class Aead(Protocol):
    def apply(
        self, nonce: bytes, aad: bytes, buffer: bytearray, start: int, length: int
    ) -> bool: ...


class _ChaCha:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("ChaCha20 keys are 32 bytes")
        self._key = key

    def xor(self, iv: bytes, data: Buffer) -> bytes:
        return chacha.chacha20_xor(self._key, iv, data)


class _Gcm:
    def __init__(self, key: bytes, encrypt: bool) -> None:
        self._cipher = AESGCM(key)
        self._encrypt = encrypt

    def apply(self, nonce: bytes, aad: bytes, buffer: bytearray, start: int, length: int) -> bool:
        if start < 0 or length < 0 or start + length + 16 > len(buffer):
            raise ValueError("AES-GCM data and tag must fit in the packet buffer")
        end = start + length
        if self._encrypt:
            buffer[start : end + 16] = self._cipher.encrypt(nonce, bytes(buffer[start:end]), aad)
            return True
        try:
            plain = self._cipher.decrypt(nonce, bytes(buffer[start : end + 16]), aad)
        except InvalidTag:
            # Never expose unauthenticated plaintext, even temporarily.
            return False
        buffer[start:end] = plain
        return True


class Backend:
    name = "cryptography"
    accelerated = True
    fast_chacha = True
    has_gcm = True

    def aes_ctr(self, key: bytes, iv: bytes) -> Keystream:
        return aes.CTR(key, iv)

    def aes_gcm(self, key: bytes, encrypt: bool) -> Aead:
        return _Gcm(key, encrypt)

    def chacha20(self, key: bytes) -> ChaCha20:
        return _ChaCha(key)

    def poly1305(self, key: bytes, data: Buffer) -> bytes:
        return chacha.poly1305(key, data)

    def __repr__(self) -> str:
        return f"<cipher backend {self.name}>"


# Keep the old selection names as compatibility aliases; no fallback crypto
# implementations remain. All selections receive accelerated AES-GCM support.
PURE = Backend()
BACKENDS = ("auto", "cryptography", "libcrypto", "pure")


def get(name: str = "auto") -> Backend:
    name = name.strip().lower() or "auto"
    if name not in BACKENDS:
        raise ValueError(f"unknown cipher backend {name!r}")
    return PURE
