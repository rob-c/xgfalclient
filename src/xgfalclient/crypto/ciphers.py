"""SSH cipher API backed by cryptography, without local OpenSSL ABI bindings.

The SSH transport (:mod:`xgfalclient.plugins.sftp.ssh`) asks a *backend* for
three primitives - AES-CTR keystreams, AES-GCM sealing in place, ChaCha20 and
Poly1305 - and orders its cipher proposal by what the backend says is fast.
Before 0.4.0 there were several backends (ctypes bindings to libcrypto, and
pure Python fallbacks), chosen by name. Every one is now pyca
``cryptography``; :func:`get` still accepts the old names, so configuration
and tests that name a backend keep working, but all of them return the one
:data:`PURE` instance.

The protocols below are the contract the transport relies on, written as
``typing.Protocol`` so a test can substitute a recording fake.
"""

from __future__ import annotations

from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import aes, chacha

__all__ = ["BACKENDS", "PURE", "Aead", "Backend", "ChaCha20", "Keystream", "get"]

Buffer = bytes | bytearray | memoryview


class Keystream(Protocol):
    """A running stream cipher (AES-CTR): ``update`` continues where the last left off.

    One keystream per direction lives for the whole key epoch, so the
    counter state carries across packets as RFC 4344 requires.
    """

    def update(self, data: Buffer) -> bytes | bytearray:
        """``data`` XORed with the next ``len(data)`` keystream bytes."""
        ...


class ChaCha20(Protocol):
    """A keyed ChaCha20 that is positioned afresh by ``iv`` on every call.

    Unlike :class:`Keystream`, it keeps no position: OpenSSH's construction
    sets the nonce (the sequence number) and block counter per packet.
    """

    def xor(self, iv: bytes, data: Buffer) -> bytes | bytearray:
        """``data`` XORed with the keystream at the 16-byte state block ``iv``."""
        ...


class Aead(Protocol):
    """AES-GCM bound to a key and a direction, working inside a packet buffer."""

    def apply(self, nonce: bytes, aad: bytes, buffer: bytearray, start: int, length: int) -> bool:
        """Seal or open ``buffer[start:start+length]`` in place.

        The 16-byte tag lives straight after the data, so the buffer must
        have room for it. Sealing always returns True. Opening returns False
        - leaving the buffer's ciphertext untouched - when the tag does not
        verify; the caller turns that into a protocol error.
        """
        ...


class _ChaCha:
    """:class:`ChaCha20` over :func:`.chacha.chacha20_xor`, holding only the key."""

    def __init__(self, key: bytes) -> None:
        """Keep ``key``; checked once here so each packet need not."""
        if len(key) != 32:
            raise ValueError("ChaCha20 keys are 32 bytes")
        self._key = key

    def xor(self, iv: bytes, data: Buffer) -> bytes:
        """See :meth:`ChaCha20.xor`."""
        return chacha.chacha20_xor(self._key, iv, data)


class _Gcm:
    """:class:`Aead` over ``AESGCM``; ``encrypt`` fixes the direction for its lifetime.

    The library works on whole byte strings, so "in place" here means the
    result is copied back over the same slice of the caller's buffer; the
    transport still gains from framing each packet in one ``bytearray``.
    """

    def __init__(self, key: bytes, encrypt: bool) -> None:
        """Key the AEAD (16 or 32 bytes: AES-128 or AES-256, per the negotiated name)."""
        self._cipher = AESGCM(key)
        self._encrypt = encrypt

    def apply(self, nonce: bytes, aad: bytes, buffer: bytearray, start: int, length: int) -> bool:
        """See :meth:`Aead.apply`; a slice that does not fit is a ``ValueError``."""
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
    """The cipher primitives the SSH transport builds its record protection from.

    The class attributes are what the transport's algorithm proposal reads:
    ``has_gcm`` offers ``aes*-gcm@openssh.com`` at all, and ``fast_chacha``
    ranks ``chacha20-poly1305@openssh.com`` above AES-CTR (it was below when
    the only ChaCha20 was pure Python). ``accelerated`` is informational
    (benchmarks print it). All three are True now that every primitive is
    native code.
    """

    name = "cryptography"
    accelerated = True
    fast_chacha = True
    has_gcm = True

    def aes_ctr(self, key: bytes, iv: bytes) -> Keystream:
        """An AES-CTR keystream (``aes{128,192,256}-ctr``, RFC 4344); key size picks AES."""
        return aes.CTR(key, iv)

    def aes_gcm(self, key: bytes, encrypt: bool) -> Aead:
        """An AES-GCM sealer (``encrypt=True``) or opener for one direction (RFC 5647)."""
        return _Gcm(key, encrypt)

    def chacha20(self, key: bytes) -> ChaCha20:
        """A ChaCha20 for a 32-byte key; ``ValueError`` for any other length."""
        return _ChaCha(key)

    def poly1305(self, key: bytes, data: Buffer) -> bytes:
        """The Poly1305 tag of ``data`` under the one-time ``key``."""
        return chacha.poly1305(key, data)

    def __repr__(self) -> str:
        """``<cipher backend cryptography>``, for logs and benchmark labels."""
        return f"<cipher backend {self.name}>"


# Keep the old selection names as compatibility aliases; no fallback crypto
# implementations remain. All selections receive accelerated AES-GCM support.
PURE = Backend()
BACKENDS = ("auto", "cryptography", "libcrypto", "pure")


def get(name: str = "auto") -> Backend:
    """The backend for ``name`` (case and surrounding space ignored; blank means auto).

    Any name in :data:`BACKENDS` returns the single cryptography backend;
    anything else is a ``ValueError``, so a typo in configuration is still
    reported rather than silently accepted.
    """
    name = name.strip().lower() or "auto"
    if name not in BACKENDS:
        raise ValueError(f"unknown cipher backend {name!r}")
    return PURE
