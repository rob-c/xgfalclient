"""Published test vectors and cross-checks for the SFTP plugin's crypto.

Every primitive is pinned to a standard vector - RFC 7748 (X25519), RFC 8032
(Ed25519), RFC 6979 (deterministic ECDSA P-256), FIPS-197/SP 800-38A (AES and
CTR), NIST SP 800-38D / McGrew-Viega (AES-GCM), RFC 8439 (ChaCha20 and
Poly1305) and the OpenBSD/Go ``bcrypt_pbkdf``
known-answers - and the pure-Python backends are cross-checked against
libcrypto where it is present. "libcrypto not found" is exercised by
monkeypatching the lookup.
"""

from __future__ import annotations

import os
from binascii import unhexlify as U

import pytest

from xgfalclient.crypto import aes, bcrypt, chacha, ciphers, ed25519, libcrypto, p256, x25519

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


def test_ed25519_decompress_edges() -> None:
    # A y >= p has no point; a wrong-length input has none either.
    assert ed25519._decompress(b"\xff" * 32) is None
    assert ed25519._decompress(b"short") is None


def test_ed25519_recover_x_edges() -> None:
    # y == 1 gives x^2 == 0: x is 0 for an even sign, undefined for an odd one.
    assert ed25519._recover_x(1, 0) == 0
    assert ed25519._recover_x(1, 1) is None
    # y >= p is out of range.
    assert ed25519._recover_x(ed25519._P, 0) is None
    # A y with no square root on the curve is rejected.
    assert ed25519._recover_x(2, 0) is None


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


def test_p256_nonce_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    # RFC 6979's rejection loop almost never fires for P-256, so drive the PRF
    # with a fixed sequence: the first candidate is out of range (>= N) and the
    # regenerated one is valid, exercising the retry branch deterministically.
    sequence = iter(
        [
            b"\x11" * 32,  # k after step d
            b"\x22" * 32,  # v after step e
            b"\x33" * 32,  # k after step f
            b"\x44" * 32,  # v after step g
            b"\xff" * 32,  # candidate 1: >= N, rejected
            b"\x55" * 32,  # k regenerated
            b"\x66" * 32,  # v regenerated
            (12345).to_bytes(32, "big"),  # candidate 2: in range, accepted
        ]
    )

    def fake_digest(key: bytes, msg: bytes, name: str) -> bytes:
        return next(sequence)

    monkeypatch.setattr(p256.hmac, "digest", fake_digest)
    assert p256._rfc6979_nonce(P256_X, b"\x00" * 32) == 12345


def test_p256_infinity_paths() -> None:
    # Doubling the identity and adding it are both the identity.
    assert p256._double(p256._INFINITY) == p256._INFINITY
    assert p256._affine(p256._INFINITY) is None
    inf_double = p256._double((0, 0, 1))
    assert inf_double == p256._INFINITY
    # p + (-p) is the point at infinity.
    px, py = p256.public_key(P256_X)
    neg = (px, (-py) % p256.P, 1)
    assert p256._affine(p256._add((px, py, 1), neg)) is None
    assert p256._add(p256._INFINITY, (px, py, 1)) == (px, py, 1)
    assert p256._add((px, py, 1), p256._INFINITY) == (px, py, 1)


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


# ---------------------------------------------------------------------------
# ciphers backend selection and libcrypto
# ---------------------------------------------------------------------------


def _reset_libcrypto() -> None:
    libcrypto._loaded.clear()


def test_ciphers_pure_backend() -> None:
    pure = ciphers.get("pure")
    assert pure.name == "pure" and not pure.accelerated and not pure.fast_chacha
    key, iv = os.urandom(32), os.urandom(16)
    assert bytes(pure.aes_ctr(key, iv).update(b"abc" * 8)) == aes.CTR(key, iv).update(b"abc" * 8)
    cc = pure.chacha20(key)
    assert bytes(cc.xor(bytes(16), b"x" * 40)) == chacha.chacha20_xor(key, bytes(16), b"x" * 40)
    assert pure.poly1305(U(POLY_KEY), POLY_MSG).hex() == POLY_TAG
    assert "pure" in repr(pure)


def test_ciphers_unknown_name() -> None:
    with pytest.raises(ValueError, match="unknown cipher backend"):
        ciphers.get("rot13")


def test_ciphers_auto_without_libcrypto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(libcrypto, "load", lambda: None)
    assert ciphers.get("auto") is ciphers.PURE
    # A blank name means auto.
    assert ciphers.get("  ") is ciphers.PURE
    with pytest.raises(ValueError, match="no usable libcrypto"):
        ciphers.get("libcrypto")


@pytest.mark.skipif(libcrypto.load() is None, reason="no libcrypto on this platform")
def test_libcrypto_backend_matches_pure() -> None:
    _reset_libcrypto()
    backend = ciphers.get("libcrypto")
    assert backend.accelerated and "libcrypto" in backend.name and "libcrypto" in repr(backend)
    key, iv = os.urandom(32), os.urandom(16)
    data = os.urandom(1000)
    assert bytes(backend.aes_ctr(key, iv).update(data)) == aes.CTR(key, iv).update(data)
    for klen in (16, 24, 32):
        k = os.urandom(klen)
        assert bytes(backend.aes_ctr(k, iv).update(data)) == aes.CTR(k, iv).update(data)
    cc = backend.chacha20(key)
    iv16 = os.urandom(16)
    assert bytes(cc.xor(iv16, data)) == chacha.chacha20_xor(key, iv16, data)
    # reset restarts the keystream at a new IV.
    again = backend.chacha20(key)
    assert bytes(again.xor(iv16, data)) == bytes(backend.chacha20(key).xor(iv16, data))
    assert backend.fast_chacha == backend.lib.has_poly1305
    if backend.lib.has_poly1305:
        assert backend.poly1305(U(POLY_KEY), POLY_MSG).hex() == POLY_TAG


@pytest.mark.skipif(libcrypto.load() is None, reason="no libcrypto on this platform")
def test_libcrypto_rejects_bad_sizes() -> None:
    lib = libcrypto.load()
    assert lib is not None
    with pytest.raises(ValueError, match="AES-CTR"):
        lib.aes_ctr(b"short", bytes(16))
    with pytest.raises(ValueError, match="AES-CTR"):
        lib.aes_ctr(os.urandom(32), b"short")
    with pytest.raises(ValueError, match="32-byte key"):
        lib.chacha20(b"short")


def test_libcrypto_poly1305_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    lib = libcrypto.load()
    if lib is None:
        pytest.skip("no libcrypto")
    backend = ciphers._LibBackend(lib)
    monkeypatch.setattr(type(lib), "has_poly1305", property(lambda self: False))
    # With no EVP_MAC, the backend falls back to the pure Poly1305.
    assert backend.poly1305(U(POLY_KEY), POLY_MSG).hex() == POLY_TAG
    assert not backend.fast_chacha


def test_libcrypto_candidates_and_load() -> None:
    cands = libcrypto.candidates()
    assert None in cands  # the running executable is always a candidate
    _reset_libcrypto()
    first = libcrypto.load()
    assert libcrypto.load() is first  # memoised


def test_libcrypto_find_returns_none_when_symbols_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(libcrypto, "candidates", lambda: [None])
    monkeypatch.setattr(libcrypto, "_open", lambda path: None)
    _reset_libcrypto()
    assert libcrypto.load() is None
    _reset_libcrypto()


def test_libcrypto_open_handles_oserror() -> None:
    assert libcrypto._open("/no/such/library.so.9") is None


def test_libcrypto_candidates_env_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes.util
    import sys

    # _ssl unavailable: the except branch is taken and nothing is appended for it.
    monkeypatch.setitem(sys.modules, "_ssl", None)  # type: ignore[misc]
    monkeypatch.setattr(ctypes.util, "find_library", lambda name: None)
    assert libcrypto.candidates() == [None]
    # A macOS /usr/lib stub is skipped (it aborts the process if loaded).
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(ctypes.util, "find_library", lambda name: "/usr/lib/libcrypto.dylib")
    assert "/usr/lib/libcrypto.dylib" not in libcrypto.candidates()
    # A library elsewhere is a candidate.
    monkeypatch.setattr(ctypes.util, "find_library", lambda name: "/opt/lib/libcrypto.so")
    assert "/opt/lib/libcrypto.so" in libcrypto.candidates()


class _Fn:
    """A stand-in for a ctypes function: callable, with settable restype/argtypes."""

    def __init__(self, result: object = 1) -> None:
        self.result = result
        self.restype: object = None
        self.argtypes: object = None

    def __call__(self, *args: object) -> object:
        return self.result() if callable(self.result) else self.result


def _fake_handle(
    *, with_mac: bool = True, version: bool = True, with_gcm: bool = True, **results: object
) -> object:
    names = list(libcrypto._REQUIRED)
    if with_mac:
        names += list(libcrypto._MAC)
    if with_gcm:
        names += list(libcrypto._GCM)
    if version:
        names.append("OpenSSL_version")
    handle = type("FakeHandle", (), {})()
    for name in names:
        setattr(handle, name, _Fn(results.get(name, 1)))
    # Sensible non-zero pointers by default.
    handle.EVP_CIPHER_CTX_new = _Fn(results.get("EVP_CIPHER_CTX_new", 0x1000))
    for cipher in ("EVP_aes_128_ctr", "EVP_aes_192_ctr", "EVP_aes_256_ctr", "EVP_chacha20"):
        handle.__dict__[cipher] = _Fn(0x2000)
    if version:
        handle.OpenSSL_version = _Fn(b"FakeSSL 1.0")
    if with_mac:
        handle.EVP_MAC_fetch = _Fn(results.get("EVP_MAC_fetch", 0x3000))
    return handle


def test_libcrypto_version_without_symbol() -> None:
    lib = libcrypto.LibCrypto(_fake_handle(version=False), "fake")
    assert lib.version == "libcrypto"


def test_libcrypto_rejects_a_bad_aes_ctr_known_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    class BadCipher:
        @staticmethod
        def update(_payload: bytes) -> bytes:
            return bytes(16)

    lib = libcrypto.LibCrypto.__new__(libcrypto.LibCrypto)
    monkeypatch.setattr(lib, "aes_ctr", lambda _key, _iv: BadCipher())
    with pytest.raises(RuntimeError, match="AES-CTR known answer failed"):
        lib._ctr_known_answer()


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("seal", "AES-GCM seal failed"),
        ("ciphertext", "AES-GCM known answer failed"),
        ("open", "AES-GCM open failed"),
        ("roundtrip", "AES-GCM round trip failed"),
    ],
)
def test_libcrypto_rejects_bad_gcm_known_answers(
    monkeypatch: pytest.MonkeyPatch, failure: str, message: str
) -> None:
    sealed = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")

    class FakeGCM:
        def __init__(self, encrypt: bool) -> None:
            self.encrypt = encrypt

        def apply(
            self,
            _iv: bytes,
            _aad: bytes,
            buffer: bytearray,
            _offset: int,
            _length: int,
        ) -> bool:
            if self.encrypt:
                if failure == "seal":
                    return False
                buffer[:] = bytes(32) if failure == "ciphertext" else sealed
                return True
            if failure == "open":
                return False
            buffer[:16] = b"x" * 16 if failure == "roundtrip" else bytes(16)
            return True

    lib = libcrypto.LibCrypto.__new__(libcrypto.LibCrypto)
    monkeypatch.setattr(lib, "aes_gcm", lambda _key, encrypt: FakeGCM(encrypt))
    with pytest.raises(RuntimeError, match=message):
        lib._gcm_known_answer()


def test_libcrypto_without_mac_symbols() -> None:
    lib = libcrypto.LibCrypto(_fake_handle(with_mac=False), "fake")
    assert not lib.has_poly1305
    with pytest.raises(RuntimeError, match="no EVP_MAC"):
        lib.poly1305(b"\x00" * 32, b"data")


def test_libcrypto_cipher_init_failures() -> None:
    lib = libcrypto.LibCrypto(_fake_handle(EVP_CIPHER_CTX_new=0), "fake")
    with pytest.raises(RuntimeError, match="EVP_CipherInit_ex failed"):
        lib.aes_ctr(b"\x00" * 32, b"\x00" * 16)
    lib2 = libcrypto.LibCrypto(_fake_handle(EVP_CipherInit_ex=0), "fake")
    with pytest.raises(RuntimeError, match="EVP_CipherInit_ex failed"):
        lib2.aes_ctr(b"\x00" * 32, b"\x00" * 16)


def test_libcrypto_cipher_update_and_reset_failures() -> None:
    lib = libcrypto.LibCrypto(_fake_handle(EVP_CipherUpdate=0), "fake")
    cipher = lib.aes_ctr(b"\x00" * 32, b"\x00" * 16)
    with pytest.raises(RuntimeError, match="EVP_CipherUpdate failed"):
        cipher.update(b"data")
    assert cipher.update(b"") == b""  # nothing to encrypt: no call
    reset_fail = libcrypto._Cipher.__new__(libcrypto._Cipher)
    reset_fail._lib = libcrypto.LibCrypto(_fake_handle(EVP_CipherInit_ex=0), "fake")
    reset_fail._ctx = 0x1  # nonzero so reset attempts the call
    with pytest.raises(RuntimeError, match="EVP_CipherInit_ex failed"):
        reset_fail.reset(b"\x00" * 16)


def test_libcrypto_poly1305_evp_failure() -> None:
    lib = libcrypto.LibCrypto(_fake_handle(EVP_MAC_init=0), "fake")
    assert lib.has_poly1305
    with pytest.raises(RuntimeError, match="EVP_MAC Poly1305 failed"):
        lib.poly1305(b"\x00" * 32, b"data")


def test_libcrypto_poly1305_reuses_thread_context() -> None:
    # A second call on the same thread reuses the cached EVP_MAC context.
    lib = libcrypto.LibCrypto(_fake_handle(), "fake")
    assert lib.poly1305(b"\x00" * 32, b"a") == b"\x00" * 16
    assert lib.poly1305(b"\x00" * 32, b"b") == b"\x00" * 16


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

_needs_gcm = pytest.mark.skipif(
    libcrypto.load() is None or not libcrypto.load().has_gcm,  # type: ignore[union-attr]
    reason="no libcrypto AES-GCM on this platform",
)


@_needs_gcm
@pytest.mark.parametrize(("key", "iv", "plain", "aad", "cipher", "tag"), GCM_VECTORS)
def test_libcrypto_gcm_nist(key: str, iv: str, plain: str, aad: str, cipher: str, tag: str) -> None:
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


@_needs_gcm
def test_libcrypto_gcm_rejects_bad_keys() -> None:
    lib = libcrypto.load()
    assert lib is not None
    with pytest.raises(ValueError, match="16 or 32-byte key"):
        lib.aes_gcm(bytes(24), True)


def test_pure_backend_has_no_gcm() -> None:
    assert not ciphers.PURE.has_gcm
    with pytest.raises(ValueError, match="needs the libcrypto backend"):
        ciphers.PURE.aes_gcm(bytes(16), True)


def test_libcrypto_without_gcm_symbols() -> None:
    lib = libcrypto.LibCrypto(_fake_handle(with_gcm=False), "fake")
    assert not lib.has_gcm and not ciphers._LibBackend(lib).has_gcm
    with pytest.raises(RuntimeError, match="no AES-GCM"):
        lib.aes_gcm(bytes(16), True)


def test_libcrypto_gcm_failures(monkeypatch) -> None:
    # The fakes fail on purpose; keep the known-answer gate from hiding them.
    monkeypatch.setattr(libcrypto.LibCrypto, "_gcm_known_answer", lambda self: None)
    buffer = bytearray(48)
    # The context cannot be made.
    with pytest.raises(RuntimeError, match="EVP_CipherInit_ex failed"):
        libcrypto.LibCrypto(_fake_handle(EVP_CIPHER_CTX_new=0), "fake").aes_gcm(bytes(16), True)
    # A step before the tag fails.
    lib = libcrypto.LibCrypto(_fake_handle(EVP_CipherUpdate=0), "fake")
    with pytest.raises(RuntimeError, match="AES-GCM failed"):
        lib.aes_gcm(bytes(16), True).apply(bytes(12), b"aad", buffer, 0, 32)
    # Opening: a failed final is a bad tag.
    lib = libcrypto.LibCrypto(_fake_handle(EVP_CipherFinal_ex=0), "fake")
    assert (
        not ciphers._LibBackend(lib)
        .aes_gcm(bytes(32), False)
        .apply(bytes(12), b"aad", buffer, 0, 32)
    )
    # Sealing: the tag cannot be read back.
    lib = libcrypto.LibCrypto(_fake_handle(EVP_CIPHER_CTX_ctrl=0), "fake")
    with pytest.raises(RuntimeError, match="get tag failed"):
        lib.aes_gcm(bytes(16), True).apply(bytes(12), b"aad", buffer, 0, 0)
    # Everything succeeding (as far as the fake can tell).
    lib = libcrypto.LibCrypto(_fake_handle(), "fake")
    assert lib.aes_gcm(bytes(16), True).apply(bytes(12), b"aad", buffer, 0, 32)
    # A context whose construction never finished frees nothing.
    libcrypto._Gcm.__new__(libcrypto._Gcm).__del__()
