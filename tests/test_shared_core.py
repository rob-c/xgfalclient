"""Old import paths are true aliases of the one shared implementation."""

from __future__ import annotations

import importlib
import pickle

import pytest
from xrdclient.crypto.x509 import Name

from xgfalclient.crypto import x509


@pytest.mark.parametrize("name", ["aes", "der", "ed25519", "p256", "rsa", "voms"])
def test_crypto_compatibility_modules_are_shared(name):
    previous = importlib.import_module(f"xgfalclient.crypto.{name}")
    canonical = importlib.import_module(f"xrdclient.crypto.{name}")
    assert previous is canonical
    assert previous.__file__ == canonical.__file__


def test_xml_guard_is_shared():
    assert importlib.import_module("xgfalclient._xml") is importlib.import_module("xrdclient._xml")


def test_both_certificate_models_share_names_and_key_types(pki):
    from xrdclient.crypto.x509 import load_proxy

    from xgfalclient.crypto.x509 import load_credential

    previous = load_credential(str(pki.proxy_path))
    canonical = load_proxy(str(pki.proxy_path))
    assert previous.certificate.subject == canonical.certificate.subject
    assert previous.certificate.issuer == canonical.certificate.issuer
    assert previous.certificate.public_key == canonical.certificate.public_key
    assert x509.Name is Name


def test_shared_value_objects_remain_pickleable():
    name = x509.Name((("CN", "A physicist"),), b"preserved")
    restored = pickle.loads(pickle.dumps(name))
    assert restored == name
    assert restored.der == name.der


@pytest.mark.parametrize("data", [b"", b"short", b"a" * 16])
def test_shared_padding_error_boundaries(data):
    from xrdclient.crypto.aes import pkcs7_unpad

    with pytest.raises(ValueError):
        pkcs7_unpad(data)


@pytest.mark.parametrize("pad", [False, True])
def test_shared_cbc_modes(pad):
    from xrdclient.crypto.aes import cbc_decrypt, cbc_encrypt

    key = bytes(range(16))
    plain = b"a" * 32
    encrypted = cbc_encrypt(key, plain, pad=pad)
    assert cbc_decrypt(key, encrypted, pad=pad) == plain


@pytest.mark.parametrize("data", [b"", b"short"])
def test_shared_cbc_rejects_incomplete_ciphertext(data):
    from xrdclient.crypto.aes import cbc_decrypt

    with pytest.raises(ValueError):
        cbc_decrypt(bytes(16), data)


@pytest.mark.parametrize("kind", ["header", "short-padding", "wrong-padding"])
def test_shared_rsa_recovery_rejects_invalid_padding(kind):
    from xgfalclient.testing.pki import test_key

    key = test_key(0)
    blocks = {
        "header": b"\x00\x02" + b"\xff" * 8 + b"\x00",
        "short-padding": b"\x00\x01" + b"\xff" * 7 + b"\x00",
        "wrong-padding": b"\x00\x01" + b"\xff" * 7 + b"x\x00",
    }
    plain = blocks[kind].ljust(key.size, b"x")
    signature = key._power(int.from_bytes(plain, "big")).to_bytes(key.size, "big")
    with pytest.raises(ValueError, match="padding"):
        key.public.recover(signature)


def test_shared_rsa_public_decryption_preserves_raw_gsi_contract():
    from xgfalclient.testing.pki import test_key

    key = test_key(0)
    assert key.public.decrypt_public(key.sign(b"one") + key.sign(b"two")) == b"onetwo"
    for invalid in (b"", b"short"):
        with pytest.raises(ValueError, match="whole number"):
            key.public.decrypt_public(invalid)


@pytest.mark.parametrize("extensions", [(), ("1.3.6.1.5.5.7.1.14",), ("1.3.6.1.4.1.3536.1.222",)])
def test_shared_proxy_detection_extensions(pki, extensions):
    from dataclasses import replace

    from xrdclient.crypto.x509 import parse_certificate

    user = parse_certificate(pki.user.der)
    assert replace(user, extensions=extensions).is_proxy == bool(extensions)
    assert not replace(user, subject=Name(), extensions=()).is_proxy
    proxy_name = Name((*user.issuer.rdns, ("CN", "proxy")))
    assert replace(user, subject=proxy_name, extensions=()).is_proxy


@pytest.mark.parametrize(
    "rdns", [(), (("O", "lab"),), (("CN", "physicist"),), (("CN", "proxy"),), (("CN", "123"),)]
)
def test_shared_proxy_identity_stops_at_the_end_entity(pki, rdns):
    from dataclasses import replace

    from xrdclient.crypto.x509 import ProxyCredential, parse_certificate

    certificate = replace(parse_certificate(pki.user.der), subject=Name(rdns))
    proxy = ProxyCredential((certificate,), pki.user_key)
    expected = str(Name(rdns))
    if rdns in ((("CN", "proxy"),), (("CN", "123"),)):
        expected = ""
    assert proxy.identity == expected


@pytest.mark.parametrize("anchors_only", [False, True])
def test_shared_proxy_wire_chain_keeps_anchor_fallback(pki, anchors_only):
    from xrdclient.crypto.x509 import ProxyCredential, parse_certificate

    ca = parse_certificate(pki.ca.der)
    user = parse_certificate(pki.user.der)
    chain = (ca,) if anchors_only else (user, ca)
    proxy = ProxyCredential(chain, pki.user_key)
    assert proxy.pem() == (ca.pem() if anchors_only else user.pem())


@pytest.mark.parametrize("empty", [False, True])
def test_shared_certificate_body_policy(pki, empty):
    from xrdclient.crypto import der
    from xrdclient.crypto.x509 import certificate_fields, parse_certificate

    outer = der.raw_children(pki.user.der)
    fields = der.raw_children(outer[0])
    fields = [] if empty else fields[1:]
    altered = der.sequence(der.sequence(*fields), *outer[1:])
    if empty:
        with pytest.raises(der.DERError, match="required fields"):
            parse_certificate(altered)
        with pytest.raises(der.DERError, match="required fields"):
            certificate_fields(altered)
    else:
        assert parse_certificate(altered).serial == pki.user.serial
        assert certificate_fields(altered)["spki"] == pki.user.spki
        fields[0] = der.null()
        malformed_serial = der.sequence(der.sequence(*fields), *outer[1:])
        assert parse_certificate(malformed_serial).serial == 0


@pytest.mark.parametrize("spki", [b"\x30\x00", b"\x30\x04\x05\x00\x05\x00"])
def test_shared_certificate_key_shape_is_bounded(spki):
    from xrdclient.crypto import der
    from xrdclient.crypto.x509 import _certificate_key

    assert _certificate_key(der.parse_one(spki)) is None


@pytest.mark.parametrize(
    "raw",
    [
        b"\x30\x00",
        b"\x30\x04\x05\x00\x04\x00",
        b"\x30\x06\x06\x02\x2a\x03\x05\x00",
    ],
)
def test_shared_extension_parser_rejects_bad_shapes(raw):
    from xrdclient.crypto.der import DERError
    from xrdclient.crypto.x509 import parse_extension

    with pytest.raises(DERError, match="malformed"):
        parse_extension(raw)


@pytest.mark.parametrize("critical", [b"\x01\x01\xff", b"\x01\x01\x00", b"\x05\x00", b""])
def test_shared_extension_critical_flag(critical):
    from xrdclient.crypto import der
    from xrdclient.crypto.x509 import parse_extension

    raw = der.sequence(der.oid("1.2.3"), critical, der.octet_string(b"content"))
    assert parse_extension(raw).critical == (critical == b"\x01\x01\xff")


@pytest.mark.parametrize("signature", [b"\x05\x00", b"\x03\x02\x01x"])
def test_shared_signed_object_checks_bitstring_shape(pki, signature):
    from xrdclient.crypto import der
    from xrdclient.crypto.x509 import verify_signed

    parts = der.raw_children(pki.user.der)
    assert not verify_signed(der.sequence(*parts[:2], signature), pki.ca_key.public)


@pytest.mark.parametrize(
    "tag, encoding, value",
    [
        (0x0C, "utf-8", "  Ångström  LAB "),
        (0x13, "ascii", " Example \t CA "),
        (0x12, "ascii", "12 34"),
    ],
)
def test_shared_ca_name_canonicalisation(tag, encoding, value):
    from xrdclient.crypto import der
    from xrdclient.crypto.x509 import _canonical_value, name_hashes

    encoded = der.tlv(tag, value.encode(encoding))
    canonical = _canonical_value(tag, value.encode(encoding))
    if tag == 0x12:
        assert canonical == encoded
    else:
        expected = "Ångström lab" if tag == 0x0C else "example ca"
        assert der.parse_one(canonical).value.decode("utf-8") == expected
    original_name = der.sequence(der.set_of(der.sequence(der.oid("2.5.4.3"), encoded)))
    hashes = name_hashes(original_name)
    assert len(hashes[0]) == 8
    assert len(hashes[1]) == 8
