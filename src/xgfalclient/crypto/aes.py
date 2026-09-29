"""AES (FIPS 197) encryption and CTR mode in pure Python - the fallback backend.

SSH's ``aes128-ctr``/``aes256-ctr`` and the ``aes256-ctr`` that protects an
encrypted OpenSSH private key only ever run the cipher forwards, so there
is no decryption here. The round function uses the classic four T-tables,
built at import from the S-box, so a block is sixteen table lookups per
round. That is still only a couple of MB/s: correct, and meant for when
:mod:`.libcrypto` is unavailable.
"""

from __future__ import annotations

import struct

__all__ = ["AES", "CTR", "SBOX"]


def _sbox() -> list[int]:
    box = [0] * 256
    p = q = 1
    while True:
        # p walks the multiplicative group by 3, q by its inverse 1/3.
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        rotated = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        box[p] = rotated ^ 0x63
        if p == 1:
            break
    box[0] = 0x63
    return box


def _rotl8(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


SBOX = _sbox()


def _xtime(value: int) -> int:
    value <<= 1
    return (value ^ 0x11B) if value & 0x100 else value


def _tables() -> tuple[list[int], list[int], list[int], list[int]]:
    t0 = []
    for byte in SBOX:
        two = _xtime(byte)
        three = two ^ byte
        t0.append((two << 24) | (byte << 16) | (byte << 8) | three)
    t1 = [((w >> 8) | (w << 24)) & 0xFFFFFFFF for w in t0]
    t2 = [((w >> 16) | (w << 16)) & 0xFFFFFFFF for w in t0]
    t3 = [((w >> 24) | (w << 8)) & 0xFFFFFFFF for w in t0]
    return t0, t1, t2, t3


_T0, _T1, _T2, _T3 = _tables()
_BLOCK = struct.Struct(">4I")


class AES:
    """An AES key schedule; :meth:`encrypt_block` is the forward cipher."""

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("AES keys are 16, 24 or 32 bytes")
        nk = len(key) // 4
        self.rounds = nk + 6
        words = list(struct.unpack(f">{nk}I", key))
        rcon = 1
        for i in range(nk, 4 * (self.rounds + 1)):
            temp = words[i - 1]
            if i % nk == 0:
                temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
                temp = self._sub_word(temp) ^ (rcon << 24)
                rcon = _xtime(rcon)
            elif nk > 6 and i % nk == 4:
                temp = self._sub_word(temp)
            words.append(words[i - nk] ^ temp)
        self._keys = [words[4 * r : 4 * r + 4] for r in range(self.rounds + 1)]

    @staticmethod
    def _sub_word(word: int) -> int:
        return (
            (SBOX[word >> 24] << 24)
            | (SBOX[(word >> 16) & 0xFF] << 16)
            | (SBOX[(word >> 8) & 0xFF] << 8)
            | SBOX[word & 0xFF]
        )

    def encrypt_block(self, block: bytes) -> bytes:
        keys = self._keys
        k = keys[0]
        s0, s1, s2, s3 = _BLOCK.unpack(block)
        s0 ^= k[0]
        s1 ^= k[1]
        s2 ^= k[2]
        s3 ^= k[3]
        t0, t1, t2, t3 = _T0, _T1, _T2, _T3
        for r in range(1, self.rounds):
            k = keys[r]
            n0 = t0[s0 >> 24] ^ t1[(s1 >> 16) & 255] ^ t2[(s2 >> 8) & 255] ^ t3[s3 & 255] ^ k[0]
            n1 = t0[s1 >> 24] ^ t1[(s2 >> 16) & 255] ^ t2[(s3 >> 8) & 255] ^ t3[s0 & 255] ^ k[1]
            n2 = t0[s2 >> 24] ^ t1[(s3 >> 16) & 255] ^ t2[(s0 >> 8) & 255] ^ t3[s1 & 255] ^ k[2]
            n3 = t0[s3 >> 24] ^ t1[(s0 >> 16) & 255] ^ t2[(s1 >> 8) & 255] ^ t3[s2 & 255] ^ k[3]
            s0, s1, s2, s3 = n0, n1, n2, n3
        k = keys[self.rounds]
        sb = SBOX
        out = (
            (sb[s0 >> 24] << 24 | sb[(s1 >> 16) & 255] << 16 | sb[(s2 >> 8) & 255] << 8)
            | sb[s3 & 255],
            (sb[s1 >> 24] << 24 | sb[(s2 >> 16) & 255] << 16 | sb[(s3 >> 8) & 255] << 8)
            | sb[s0 & 255],
            (sb[s2 >> 24] << 24 | sb[(s3 >> 16) & 255] << 16 | sb[(s0 >> 8) & 255] << 8)
            | sb[s1 & 255],
            (sb[s3 >> 24] << 24 | sb[(s0 >> 16) & 255] << 16 | sb[(s1 >> 8) & 255] << 8)
            | sb[s2 & 255],
        )
        return _BLOCK.pack(out[0] ^ k[0], out[1] ^ k[1], out[2] ^ k[2], out[3] ^ k[3])


class CTR:
    """AES-CTR with a 128-bit big-endian counter, as SSH (:rfc:`4344`) uses it.

    Stateful: successive :meth:`update` calls continue the keystream, and a
    partial block left over from one call is used up by the next.
    """

    def __init__(self, key: bytes, iv: bytes) -> None:
        if len(iv) != 16:
            raise ValueError("the CTR counter block is 16 bytes")
        self._aes = AES(key)
        self._counter = int.from_bytes(iv, "big")
        self._spare = b""

    def update(self, data: bytes | bytearray | memoryview) -> bytes:
        length = len(data)
        if not length:
            return b""
        stream = bytearray(self._spare)
        encrypt = self._aes.encrypt_block
        counter = self._counter
        while len(stream) < length:
            stream += encrypt(counter.to_bytes(16, "big"))
            counter = (counter + 1) & ((1 << 128) - 1)
        self._counter = counter
        self._spare = bytes(stream[length:])
        mixed = int.from_bytes(data, "big") ^ int.from_bytes(stream[:length], "big")
        return mixed.to_bytes(length, "big")
