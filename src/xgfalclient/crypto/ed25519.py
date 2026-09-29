"""Ed25519 (:rfc:`8032`) in pure Python: SSH's ``ssh-ed25519`` host and user keys.

Verification is what a client needs for a host key; signing is what it
needs to log in with an ed25519 user key (and what the in-process test
server needs for its host key). Points are kept in extended twisted-Edwards
coordinates so an addition is one inversion-free formula, and scalar
multiplication is plain double-and-add - a signature or a verification is
a few milliseconds, once per connection. Not constant-time: the signing
key is the user's own, used on a server-chosen session hash once.
"""

from __future__ import annotations

import hashlib

__all__ = ["sign", "verify", "public_key", "Point", "L"]

_P = 2**255 - 19
#: The prime order of the base point.
L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

#: ``(X, Y, Z, T)`` with ``x = X/Z``, ``y = Y/Z``, ``xy = T/Z``.
Point = tuple[int, int, int, int]


def _add(p: Point, q: Point) -> Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(scalar: int, point: Point) -> Point:
    result: Point = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p: Point, q: Point) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
assert _GX is not None
_G: Point = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(point: Point) -> bytes:
    zinv = pow(point[2], _P - 2, _P)
    x = point[0] * zinv % _P
    y = point[1] * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(data: bytes) -> Point | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _sha512_int(*parts: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _expand(secret: bytes) -> tuple[int, bytes]:
    if len(secret) != 32:
        raise ValueError("Ed25519 secret keys are 32 bytes")
    digest = hashlib.sha512(secret).digest()
    a = int.from_bytes(digest[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, digest[32:]


def public_key(secret: bytes) -> bytes:
    """The 32-byte public key for a 32-byte secret seed."""
    a, _ = _expand(secret)
    return _compress(_multiply(a, _G))


def sign(secret: bytes, message: bytes) -> bytes:
    """The 64-byte signature of ``message``."""
    a, prefix = _expand(secret)
    public = _compress(_multiply(a, _G))
    r = _sha512_int(prefix, message) % L
    big_r = _compress(_multiply(r, _G))
    h = _sha512_int(big_r, public, message) % L
    s = (r + h * a) % L
    return big_r + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True if ``signature`` is valid for ``message`` under ``public``."""
    if len(signature) != 64:
        return False
    point = _decompress(public)
    if point is None:
        return False
    big_r = _decompress(signature[:32])
    if big_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = _sha512_int(signature[:32], public, message) % L
    return _equal(_multiply(s, _G), _add(big_r, _multiply(h, point)))
