"""SSH X25519 key exchange backed by cryptography."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

__all__ = ["P", "BASE_POINT", "x25519", "generate", "public_key"]

P = 2**255 - 19
BASE_POINT = (9).to_bytes(32, "little")


def x25519(k: bytes, u: bytes) -> bytes:
    """Exchange keys, rejecting small-order peers with an all-zero result."""
    if len(u) != 32:
        raise ValueError("X25519 u-coordinates are 32 bytes")
    try:
        return X25519PrivateKey.from_private_bytes(k).exchange(X25519PublicKey.from_public_bytes(u))
    except ValueError as exc:
        if len(k) != 32:
            raise
        raise ValueError("X25519 produced the all-zero shared secret") from exc


def public_key(private: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def generate() -> tuple[bytes, bytes]:
    key = X25519PrivateKey.generate()
    return key.private_bytes_raw(), key.public_key().public_bytes_raw()
