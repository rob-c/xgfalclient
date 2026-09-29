"""ECDSA over NIST P-256 in pure Python: SSH's ``ecdsa-sha2-nistp256`` keys.

A client verifies one host-key signature per connection and, with an
ECDSA user key, makes one signature; the test server makes one per
handshake. Points are in Jacobian coordinates (no inversion per addition)
and nonces are :rfc:`6979` deterministic, so signing needs no randomness
and gives reproducible test vectors. Not constant-time; see
:mod:`.ed25519` for why that is acceptable here.
"""

from __future__ import annotations

import hashlib
import hmac

__all__ = ["P", "N", "G", "sign", "verify", "public_key", "encode_point", "decode_point"]

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

_Jacobian = tuple[int, int, int]
_INFINITY: _Jacobian = (1, 1, 0)


def _double(p: _Jacobian) -> _Jacobian:
    x, y, z = p
    if not y or not z:
        return _INFINITY
    ysq = y * y % P
    s = 4 * x * ysq % P
    zsq = z * z % P
    m = 3 * (x - zsq) * (x + zsq) % P
    nx = (m * m - 2 * s) % P
    ny = (m * (s - nx) - 8 * ysq * ysq) % P
    nz = 2 * y * z % P
    return (nx, ny, nz)


def _add(p: _Jacobian, q: _Jacobian) -> _Jacobian:
    if not p[2]:
        return q
    if not q[2]:
        return p
    z1sq = p[2] * p[2] % P
    z2sq = q[2] * q[2] % P
    u1 = p[0] * z2sq % P
    u2 = q[0] * z1sq % P
    s1 = p[1] * z2sq * q[2] % P
    s2 = q[1] * z1sq * p[2] % P
    if u1 == u2:
        return _double(p) if s1 == s2 else _INFINITY
    h = u2 - u1
    r = s2 - s1
    hsq = h * h % P
    hcu = hsq * h % P
    u1h = u1 * hsq % P
    nx = (r * r - hcu - 2 * u1h) % P
    ny = (r * (u1h - nx) - s1 * hcu) % P
    nz = h * p[2] * q[2] % P
    return (nx, ny, nz)


def _multiply(k: int, point: tuple[int, int]) -> _Jacobian:
    result = _INFINITY
    addend: _Jacobian = (point[0], point[1], 1)
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _double(addend)
        k >>= 1
    return result


def _affine(p: _Jacobian) -> tuple[int, int] | None:
    if not p[2]:
        return None
    zinv = pow(p[2], P - 2, P)
    zinv2 = zinv * zinv % P
    return (p[0] * zinv2 % P, p[1] * zinv2 * zinv % P)


def _on_curve(x: int, y: int) -> bool:
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + _A * x + _B)) % P == 0


def encode_point(point: tuple[int, int]) -> bytes:
    """SEC1 uncompressed: ``04 || X || Y``, as SSH carries the key."""
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def decode_point(data: bytes) -> tuple[int, int]:
    """Parse an uncompressed point; ``ValueError`` if it is not on the curve."""
    if len(data) != 65 or data[0] != 4:
        raise ValueError("expected an uncompressed P-256 point")
    x = int.from_bytes(data[1:33], "big")
    y = int.from_bytes(data[33:], "big")
    if not _on_curve(x, y):
        raise ValueError("point is not on P-256")
    return (x, y)


def public_key(d: int) -> tuple[int, int]:
    # Checked first: the ladder never ends for a negative scalar.
    if not 0 < d < N:
        raise ValueError("private scalar out of range")
    point = _affine(_multiply(d, G))
    assert point is not None  # G has prime order N, so d*G is never infinity
    return point


def _bits2int(data: bytes) -> int:
    return int.from_bytes(data, "big") % N


def _rfc6979_nonce(d: int, digest: bytes, order: int = N) -> int:
    """The deterministic nonce; ``order`` is a parameter so tests can force a retry."""
    key = d.to_bytes(32, "big")
    h1 = _bits2int(digest).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.digest(k, v + b"\x00" + key + h1, "sha256")
    v = hmac.digest(k, v, "sha256")
    k = hmac.digest(k, v + b"\x01" + key + h1, "sha256")
    v = hmac.digest(k, v, "sha256")
    while True:
        v = hmac.digest(k, v, "sha256")
        candidate = int.from_bytes(v, "big")
        if 0 < candidate < order:
            return candidate
        k = hmac.digest(k, v + b"\x00", "sha256")
        v = hmac.digest(k, v, "sha256")


def sign(d: int, message: bytes) -> tuple[int, int]:
    """``(r, s)`` over SHA-256 of ``message``, with an :rfc:`6979` nonce."""
    digest = hashlib.sha256(message).digest()
    e = _bits2int(digest)
    k = _rfc6979_nonce(d, digest)
    point = _affine(_multiply(k, G))
    assert point is not None
    r = point[0] % N
    s = pow(k, N - 2, N) * (e + r * d) % N
    return r, s


def verify(public: tuple[int, int], message: bytes, r: int, s: int) -> bool:
    """True if ``(r, s)`` is a valid signature over SHA-256 of ``message``."""
    if not (0 < r < N and 0 < s < N):
        return False
    e = _bits2int(hashlib.sha256(message).digest())
    w = pow(s, N - 2, N)
    point = _affine(_add(_multiply(e * w % N, G), _multiply(r * w % N, public)))
    return point is not None and point[0] % N == r
