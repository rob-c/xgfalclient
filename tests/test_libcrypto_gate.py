"""libcrypto is only trusted for the primitives it gets right.

Apple's LibreSSL exports AES-GCM and ChaCha20 but fails the one and derives
another keystream for the other, so each is proven against a known answer at
load time and the pure-Python code takes over for whichever fails.
"""

import pytest

from xgfalclient.crypto import chacha, ciphers, libcrypto

pytestmark = pytest.mark.skipif(libcrypto.load() is None, reason="no libcrypto here")


def _fail(self):
    raise RuntimeError("known answer failed")


def test_a_wrong_aes_ctr_rejects_the_library(monkeypatch):
    monkeypatch.setattr(libcrypto.LibCrypto, "_ctr_known_answer", _fail)
    assert libcrypto._find() is None


def test_a_wrong_chacha_falls_back_to_pure_python(monkeypatch):
    monkeypatch.setattr(libcrypto.LibCrypto, "_chacha_known_answer", _fail)
    lib = libcrypto._find()
    assert lib is not None and not lib.has_chacha
    backend = ciphers._LibBackend(lib)
    assert isinstance(backend.chacha20(bytes(32)), ciphers._PureChaCha)
    assert not backend.fast_chacha


def test_a_wrong_gcm_is_not_offered(monkeypatch):
    monkeypatch.setattr(libcrypto.LibCrypto, "_gcm_known_answer", _fail)
    lib = libcrypto._find()
    assert lib is not None and not lib.has_gcm


def test_the_chosen_backend_agrees_with_pure_python():
    key, iv, data = bytes(range(32)), chacha.djb_iv(7, b"\x00" * 7 + b"\x03"), bytes(100)
    assert bytes(ciphers.get().chacha20(key).xor(iv, data)) == chacha.chacha20_xor(key, iv, data)
    assert bytes(ciphers.get().aes_ctr(bytes(16), bytes(16)).update(data)) == bytes(
        ciphers.PURE.aes_ctr(bytes(16), bytes(16)).update(data)
    )
