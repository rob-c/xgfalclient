"""Pluggable symmetric-crypto backends for the SSH transport.

The SSH packet layer needs, per packet: an AES-CTR keystream (stateful
across packets), a ChaCha20 keystream restarted at a given counter and
nonce, a Poly1305 tag, or - libcrypto only - one AES-GCM seal or open in
place. A :class:`Backend` supplies them.

``libcrypto``
    :mod:`.libcrypto` - C speed through ``ctypes``. Poly1305 there needs
    OpenSSL 3's ``EVP_MAC``; on an older library it falls back to Python,
    and :attr:`Backend.fast_chacha` says so, which is how the transport
    decides to prefer AES-CTR. AES-GCM (:attr:`Backend.has_gcm`) is the
    fastest SSH cipher of all here - one EVP pass encrypts and authenticates.
``pure``
    :mod:`.aes` and :mod:`.chacha` - correct everywhere, a few MB/s. It
    offers no AES-GCM, so the transport does not negotiate it.

:func:`get` picks one by name (``auto`` is the best available); the
selection is visible as :attr:`Backend.name` so a user can see why a copy
is slow.
"""

from __future__ import annotations

from typing import Protocol, Union

from . import aes, chacha
from . import libcrypto as _libcrypto

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


class _PureChaCha:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def xor(self, iv: bytes, data: Buffer) -> bytes:
        return chacha.chacha20_xor(self._key, iv, data)


class _LibChaCha:
    def __init__(self, lib: _libcrypto.LibCrypto, key: bytes) -> None:
        self._cipher = lib.chacha20(key)

    def xor(self, iv: bytes, data: Buffer) -> bytearray:
        self._cipher.reset(iv)
        return self._cipher.update(data)


class Backend:
    """The pure-Python backend; :class:`_LibBackend` overrides the fast parts."""

    name = "pure"
    accelerated = False

    @property
    def fast_chacha(self) -> bool:
        return self.accelerated

    @property
    def has_gcm(self) -> bool:
        return False

    def aes_ctr(self, key: bytes, iv: bytes) -> Keystream:
        return aes.CTR(key, iv)

    def aes_gcm(self, key: bytes, encrypt: bool) -> Aead:
        raise ValueError(f"AES-GCM needs the libcrypto backend, not {self.name}")

    def chacha20(self, key: bytes) -> ChaCha20:
        return _PureChaCha(key)

    def poly1305(self, key: bytes, data: Buffer) -> bytes:
        return chacha.poly1305(key, data)

    def __repr__(self) -> str:
        return f"<cipher backend {self.name}>"


class _LibBackend(Backend):
    accelerated = True

    def __init__(self, lib: _libcrypto.LibCrypto) -> None:
        self.lib = lib
        self.name = f"libcrypto ({lib.version})"

    @property
    def fast_chacha(self) -> bool:
        return self.lib.has_poly1305

    @property
    def has_gcm(self) -> bool:
        return self.lib.has_gcm

    def aes_ctr(self, key: bytes, iv: bytes) -> Keystream:
        return self.lib.aes_ctr(key, iv)

    def aes_gcm(self, key: bytes, encrypt: bool) -> Aead:
        return self.lib.aes_gcm(key, encrypt)

    def chacha20(self, key: bytes) -> ChaCha20:
        return _LibChaCha(self.lib, key)

    def poly1305(self, key: bytes, data: Buffer) -> bytes:
        if self.lib.has_poly1305:
            return self.lib.poly1305(key, data)
        return chacha.poly1305(key, data)


PURE = Backend()
BACKENDS = ("auto", "libcrypto", "pure")


def get(name: str = "auto") -> Backend:
    """The backend called ``name``; ``auto`` is libcrypto when it can be found.

    ``ValueError`` for an unknown name, or for ``libcrypto`` when there is none.
    """
    key = name.strip().lower() or "auto"
    if key == "pure":
        return PURE
    if key not in ("auto", "libcrypto"):
        raise ValueError(f"unknown cipher backend {name!r} (choose from {', '.join(BACKENDS)})")
    lib = _libcrypto.load()
    if lib is None:
        if key == "libcrypto":
            raise ValueError("no usable libcrypto was found for the libcrypto cipher backend")
        return PURE
    return _LibBackend(lib)
