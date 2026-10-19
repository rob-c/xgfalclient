"""``bcrypt_pbkdf``: the key derivation behind passphrase-protected OpenSSH keys.

``ssh-keygen`` encrypts a private key with ``aes256-ctr`` under a key and IV
drawn from OpenBSD's ``bcrypt_pbkdf`` (a PBKDF2 whose PRF is the eksblowfish
"bcrypt hash"). It is deliberately slow - that is its job - and so it must
run at native speed: in pure Python the ``ssh-keygen`` default of 16 rounds
took close to a minute, which made a passphrase key unusable on the in-process
transports. The derivation is therefore pyca's ``bcrypt`` package (a runtime
dependency; abi3 wheels for every supported platform and packaged by every
distribution we target), which implements exactly OpenBSD's algorithm.

This module stays as a thin, stable name for that call - it lived here when
the implementation was local, and callers (and tests) import it from here.
"""

from __future__ import annotations

import bcrypt as _bcrypt

__all__ = ["bcrypt_pbkdf"]

#: The library's ceiling on derived bytes (OpenSSH asks for at most 48).
_MAX_LENGTH = 512


def bcrypt_pbkdf(password: bytes, salt: bytes, length: int, rounds: int) -> bytes:
    """``length`` bytes of key material, byte-for-byte what OpenSSH derives.

    Arguments are validated here, with one message, rather than leaving each
    bad value to the library's own wording. Few rounds are allowed without the
    library's warning: the round count is the key file's, not ours to judge.
    """
    if rounds < 1 or not password or not salt or not 0 < length <= _MAX_LENGTH:
        raise ValueError(
            f"bcrypt_pbkdf needs a password, a salt, rounds >= 1 and 1-{_MAX_LENGTH} bytes"
        )
    return _bcrypt.kdf(password, salt, length, rounds, ignore_few_rounds=True)
