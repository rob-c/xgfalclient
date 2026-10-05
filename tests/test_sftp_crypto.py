"""Published test vectors and cross-checks for the SFTP plugin's crypto.

Every primitive is pinned to a standard vector - RFC 7748 (X25519), RFC 8032
(Ed25519), RFC 6979 (deterministic ECDSA P-256), FIPS-197/SP 800-38A (AES and
CTR), NIST SP 800-38D / McGrew-Viega (AES-GCM), RFC 8439 (ChaCha20 and
Poly1305) and the OpenBSD/Go ``bcrypt_pbkdf``
known-answers. All production primitives now use cryptography.
"""

from __future__ import annotations

import os
from binascii import unhexlify as U

import pytest

from xgfalclient.crypto import aes, bcrypt, chacha, ciphers, ed25519, p256, x25519

# ---------------------------------------------------------------------------
# X25519 - RFC 7748 section 5.2
# ---------------------------------------------------------------------------

X25519_VECTORS = [
    (
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    ),
    (
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    ),
]


@pytest.mark.parametrize(("k", "u", "out"), X25519_VECTORS)
def test_x25519_rfc7748(k: str, u: str, out: str) -> None:
    assert x25519.x25519(U(k), U(u)).hex() == out


def test_x25519_generate_and_public() -> None:
    private, public = x25519.generate()
    assert len(private) == 32 and len(public) == 32
    assert x25519.public_key(private) == public
    # A Diffie-Hellman agreement is symmetric.
    a_priv, a_pub = x25519.generate()
    b_priv, b_pub = x25519.generate()
    assert x25519.x25519(a_priv, b_pub) == x25519.x25519(b_priv, a_pub)


def test_x25519_rejects_bad_lengths_and_zero() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        x25519.x25519(b"short", x25519.BASE_POINT)
    with pytest.raises(ValueError, match="u-coordinates"):
        x25519.x25519(os.urandom(32), b"short")
    # A small-order u that yields the all-zero shared secret is refused (RFC 8731).
    with pytest.raises(ValueError, match="all-zero"):
        x25519.x25519(os.urandom(32), bytes(32))


# ---------------------------------------------------------------------------
# Ed25519 - RFC 8032 section 7.1
# ---------------------------------------------------------------------------

ED25519_VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


@pytest.mark.parametrize(("sk", "pk", "msg", "sig"), ED25519_VECTORS)
def test_ed25519_rfc8032(sk: str, pk: str, msg: str, sig: str) -> None:
    message = U(msg) if msg else b""
    assert ed25519.public_key(U(sk)).hex() == pk
    assert ed25519.sign(U(sk), message).hex() == sig
    assert ed25519.verify(U(pk), message, U(sig))


def test_ed25519_rejects_bad_signatures() -> None:
    sk = U("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = ed25519.public_key(sk)
    good = ed25519.sign(sk, b"hi")
    assert not ed25519.verify(pk, b"hi", good[:-1])  # wrong length
    tampered = bytearray(good)
    tampered[0] ^= 1
    assert not ed25519.verify(pk, b"hi", bytes(tampered))
    # S out of range, a bad R and a non-canonical public key are all rejected.
    assert not ed25519.verify(pk, b"hi", good[:32] + (ed25519.L + 1).to_bytes(32, "little"))
    assert not ed25519.verify(pk, b"hi", b"\xff" * 32 + good[32:])
    assert not ed25519.verify(b"\xff" * 32, b"hi", good)


def test_ed25519_expand_rejects_bad_seed() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        ed25519.public_key(b"short")


# ---------------------------------------------------------------------------
# ECDSA P-256 - RFC 6979 appendix A.2.5
# ---------------------------------------------------------------------------

P256_X = int("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16)
P256_UX = int("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16)
P256_UY = int("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16)
P256_SIGS = {
    b"sample": (
        int("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", 16),
        int("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", 16),
    ),
    b"test": (
        int("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", 16),
        int("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083", 16),
    ),
}


def test_p256_public_key() -> None:
    assert p256.public_key(P256_X) == (P256_UX, P256_UY)


@pytest.mark.parametrize("message", list(P256_SIGS))
def test_p256_rfc6979(message: bytes) -> None:
    r, s = p256.sign(P256_X, message)
    assert (r, s) == P256_SIGS[message]
    assert p256.verify((P256_UX, P256_UY), message, r, s)


def test_p256_point_encoding_round_trip() -> None:
    point = p256.public_key(P256_X)
    blob = p256.encode_point(point)
    assert p256.decode_point(blob) == point
    with pytest.raises(ValueError, match="uncompressed"):
        p256.decode_point(b"\x02" + b"\x00" * 32)
    with pytest.raises(ValueError, match="not on P-256"):
        p256.decode_point(b"\x04" + b"\x00" * 64)


def test_p256_rejects_bad_scalars_and_signatures() -> None:
    with pytest.raises(ValueError, match="out of range"):
        p256.public_key(0)
    with pytest.raises(ValueError, match="out of range"):
        p256.public_key(p256.N)
    pub = p256.public_key(P256_X)
    assert not p256.verify(pub, b"sample", 0, 1)
    assert not p256.verify(pub, b"sample", 1, 0)
    r, s = p256.sign(P256_X, b"sample")
    assert not p256.verify(pub, b"other", r, s)


# ---------------------------------------------------------------------------
# AES / AES-CTR - FIPS-197 and SP 800-38A
# ---------------------------------------------------------------------------

FIPS197_KEY = "000102030405060708090a0b0c0d0e0f"
FIPS197_PT = "00112233445566778899aabbccddeeff"
FIPS197_CT = "69c4e0d86a7b0430d8cdb78070b4c55a"

# SP 800-38A F.5.1 CTR-AES128.Encrypt
CTR_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
CTR_IV = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
CTR_PT = (
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
CTR_CT = (
    "874d6191b620e3261bef6864990db6ce"
    "9806f66b7970fdff8617187bb9fffdff"
    "5ae4df3edbd5d35e5b4f09020db03eab"
    "1e031dda2fbe03d1792170a0f3009cee"
)


def test_aes_block_fips197() -> None:
    assert aes.AES(U(FIPS197_KEY)).encrypt_block(U(FIPS197_PT)).hex() == FIPS197_CT


def test_aes_ctr_sp80038a() -> None:
    out = aes.CTR(U(CTR_KEY), U(CTR_IV)).update(U(CTR_PT))
    assert out.hex() == CTR_CT


def test_aes_ctr_is_stateful_across_calls() -> None:
    whole = aes.CTR(U(CTR_KEY), U(CTR_IV)).update(U(CTR_PT))
    stream = aes.CTR(U(CTR_KEY), U(CTR_IV))
    data = U(CTR_PT)
    piecemeal = bytearray()
    # Odd split sizes force the spare-keystream path.
    for start in range(0, len(data), 7):
        piecemeal += stream.update(data[start : start + 7])
    assert bytes(piecemeal) == whole
    assert stream.update(b"") == b""


def test_aes_key_sizes() -> None:
    for size in (16, 24, 32):
        assert len(aes.AES(os.urandom(size)).encrypt_block(bytes(16))) == 16
    with pytest.raises(ValueError, match="16, 24 or 32"):
        aes.AES(b"tooshort")
    with pytest.raises(ValueError, match="counter block"):
        aes.CTR(os.urandom(16), b"short")


# ---------------------------------------------------------------------------
# ChaCha20 / Poly1305 - RFC 8439
# ---------------------------------------------------------------------------

CHACHA_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
CHACHA_NONCE = "000000000000004a00000000"
CHACHA_PT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only "
    b"one tip for the future, sunscreen would be it."
)
CHACHA_CT = (
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
    "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
    "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
    "5af90bbf74a35be6b40b8eedf2785e42874d"
)
POLY_KEY = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
POLY_MSG = b"Cryptographic Forum Research Group"
POLY_TAG = "a8061dc1305136c6c22b8baf0c0127a9"


def test_chacha20_rfc8439() -> None:
    ct = chacha.chacha20_xor(U(CHACHA_KEY), chacha.rfc_iv(1, U(CHACHA_NONCE)), CHACHA_PT)
    assert ct.hex() == CHACHA_CT
    # Decryption is the same operation.
    assert chacha.chacha20_xor(U(CHACHA_KEY), chacha.rfc_iv(1, U(CHACHA_NONCE)), ct) == CHACHA_PT


def test_chacha20_empty_and_iv_layouts() -> None:
    assert chacha.chacha20_xor(U(CHACHA_KEY), chacha.djb_iv(0, b"\x00" * 8), b"") == b""
    with pytest.raises(ValueError, match="32-byte key"):
        chacha.chacha20_xor(b"short", bytes(16), b"data")
    with pytest.raises(ValueError, match="16-byte IV"):
        chacha.chacha20_xor(bytes(32), bytes(12), b"data")


def test_poly1305_rfc8439() -> None:
    assert chacha.poly1305(U(POLY_KEY), POLY_MSG).hex() == POLY_TAG
    with pytest.raises(ValueError, match="32 bytes"):
        chacha.poly1305(b"short", POLY_MSG)


# ---------------------------------------------------------------------------
# bcrypt_pbkdf - OpenBSD / golang.org/x/crypto known-answers
# ---------------------------------------------------------------------------


def test_bcrypt_pbkdf_known_answers() -> None:
    assert (
        bcrypt.bcrypt_pbkdf(b"password", b"salt", 32, 12).hex()
        == "1ae42c05d487bc02f64921a4ebe4ea93bcacfe135fda99974c06b7b01fae149a"
    )
    assert (
        bcrypt.bcrypt_pbkdf(b"passwordy\x00PASSWORD\x00", b"salty\x00SALT\x00", 32, 3).hex()
        == "7f310bd3e78c3280c59ce4595211a2928e8d4ec744c1ed2efc9f764e3388e0ad"
    )


def test_bcrypt_pbkdf_validates_arguments() -> None:
    for kwargs in (
        dict(password=b"", salt=b"salt", length=32, rounds=1),
        dict(password=b"p", salt=b"", length=32, rounds=1),
        dict(password=b"p", salt=b"s", length=0, rounds=1),
        dict(password=b"p", salt=b"s", length=32, rounds=0),
    ):
        with pytest.raises(ValueError):
            bcrypt.bcrypt_pbkdf(**kwargs)  # type: ignore[arg-type]


def test_bcrypt_pbkdf_output_striping_overshoot() -> None:
    # A length whose stride overshoots the key end exercises the guard that
    # stops writing past it; rounds=1 keeps it fast.
    out = bcrypt.bcrypt_pbkdf(b"password", b"salt", 67, 1)
    assert len(out) == 67
    assert out == bcrypt.bcrypt_pbkdf(b"password", b"salt", 67, 1)


def test_bcrypt_pi_words_are_cached() -> None:
    first = bcrypt.pi_words()
    assert bcrypt.pi_words() == first
    assert len(first) == 18 + 4 * 256
    # The classic first fractional word of pi is 0x243f6a88.
    assert first[0] == 0x243F6A88


@pytest.mark.parametrize("name", ciphers.BACKENDS)
def test_cipher_backend_aliases(name: str) -> None:
    backend = ciphers.get(name)
    assert backend.name == "cryptography"
    assert backend.accelerated and backend.fast_chacha and backend.has_gcm
    assert "cryptography" in repr(backend)
    key, iv = bytes(32), bytes(16)
    assert backend.aes_ctr(key, iv).update(b"abc") == aes.CTR(key, iv).update(b"abc")
    assert backend.chacha20(key).xor(iv, b"abc") == chacha.chacha20_xor(key, iv, b"abc")
    assert backend.poly1305(U(POLY_KEY), POLY_MSG).hex() == POLY_TAG


def test_ciphers_unknown_name() -> None:
    with pytest.raises(ValueError, match="unknown cipher backend"):
        ciphers.get("rot13")


# ---------------------------------------------------------------------------
# AES-GCM - NIST SP 800-38D, test cases 1, 2, 4 and 16 of McGrew & Viega's
# "The Galois/Counter Mode of Operation" (the vectors NIST publishes)
# ---------------------------------------------------------------------------

_GCM_P = (
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
)
_GCM_A = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
GCM_VECTORS = [
    # key, iv, plaintext, aad, ciphertext, tag
    ("00" * 16, "00" * 12, "", "", "", "58e2fccefa7e3061367f1d57a4e7455a"),
    (
        "00" * 16,
        "00" * 12,
        "00" * 16,
        "",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf",
    ),
    (
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        _GCM_P,
        _GCM_A,
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47",
    ),
    (
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        _GCM_P,
        _GCM_A,
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b",
    ),
]


@pytest.mark.parametrize(("key", "iv", "plain", "aad", "cipher", "tag"), GCM_VECTORS)
def test_cryptography_gcm_nist(
    key: str, iv: str, plain: str, aad: str, cipher: str, tag: str
) -> None:
    backend = ciphers.get("libcrypto")
    assert backend.has_gcm
    # Sealed in place, the tag written straight after the ciphertext.
    buffer = bytearray(b"hdr" + U(plain) + bytes(16))
    assert backend.aes_gcm(U(key), True).apply(U(iv), U(aad), buffer, 3, len(U(plain)))
    assert buffer[:3] == b"hdr" and buffer[3:].hex() == cipher + tag
    # Opened in place: the plaintext comes back only with a good tag.
    opener = backend.aes_gcm(U(key), False)
    assert opener.apply(U(iv), U(aad), buffer, 3, len(U(plain)))
    assert buffer[3 : 3 + len(U(plain))].hex() == plain
    wire = b"hdr" + U(cipher) + U(tag)
    for position in (3, len(wire) - 1):  # a flipped first ciphertext (or tag) bit, last tag bit
        bad = bytearray(wire)
        bad[position] ^= 1
        assert not opener.apply(U(iv), U(aad), bad, 3, len(U(plain)))
    # A wrong nonce or AAD fails too - and the context recovers afterwards.
    other = bytes(b ^ 1 for b in U(iv))
    assert not opener.apply(other, U(aad), bytearray(wire), 3, len(U(plain)))
    assert not opener.apply(U(iv), U(aad) + b"x", bytearray(wire), 3, len(U(plain)))
    assert opener.apply(U(iv), U(aad), bytearray(wire), 3, len(U(plain)))


@pytest.mark.parametrize("key", [b"", bytes(15), bytes(33)])
def test_gcm_rejects_bad_keys(key: bytes) -> None:
    with pytest.raises(ValueError):
        ciphers.get().aes_gcm(key, True)


@pytest.mark.parametrize(("start", "length"), [(-1, 1), (0, -1), (0, 2)])
def test_gcm_rejects_bad_buffer_bounds(start: int, length: int) -> None:
    with pytest.raises(ValueError, match="fit in the packet"):
        ciphers.get().aes_gcm(bytes(16), True).apply(bytes(12), b"", bytearray(17), start, length)


def test_gcm_invalid_tag_does_not_modify_buffer() -> None:
    wire = bytearray(bytes(32))
    before = bytes(wire)
    assert not ciphers.get().aes_gcm(bytes(16), False).apply(bytes(12), b"", wire, 0, 16)
    assert bytes(wire) == before
