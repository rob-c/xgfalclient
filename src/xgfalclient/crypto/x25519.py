"""SSH X25519 key exchange backed by cryptography.

Used for ``curve25519-sha256`` (RFC 8731), the key exchange the SSH client
prefers. The functions speak raw 32-byte strings, the form SSH puts on the
wire, so that the transport never handles a library key object.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

__all__ = ["BASE_POINT", "P", "generate", "public_key", "x25519"]

#: The field prime 2^255 - 19 (RFC 7748 §4.1); kept for callers and tests
#: that reason about u-coordinates.
P = 2**255 - 19
#: The base point u = 9, little-endian, as RFC 7748 encodes it.
BASE_POINT = (9).to_bytes(32, "little")


def x25519(k: bytes, u: bytes) -> bytes:
    """Exchange keys, rejecting small-order peers with an all-zero result.

    ``k`` is our private scalar, ``u`` the peer's public value. RFC 8731 §3
    requires a client to abort if the shared secret is all zeros (a peer
    that sent a small-order point would otherwise force a known secret).
    The library raises ``ValueError`` for that case; it is re-raised with a
    message that says so. A wrong-length private key is the caller's bug and
    keeps the library's own error.
    """
    if len(u) != 32:
        raise ValueError("X25519 u-coordinates are 32 bytes")
    try:
        return X25519PrivateKey.from_private_bytes(k).exchange(X25519PublicKey.from_public_bytes(u))
    except ValueError as exc:
        if len(k) != 32:
            raise
        raise ValueError("X25519 produced the all-zero shared secret") from exc


def public_key(private: bytes) -> bytes:
    """The 32-byte public value for a 32-byte private scalar."""
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def generate() -> tuple[bytes, bytes]:
    """A fresh ephemeral ``(private, public)`` pair, each 32 raw bytes.

    One pair per key exchange: SSH's forward secrecy depends on the private
    half never being reused or stored.
    """
    key = X25519PrivateKey.generate()
    return key.private_bytes_raw(), key.public_key().public_bytes_raw()
