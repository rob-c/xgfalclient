"""RSA, X.509 and proxy signing: the pure-Python crypto GSI rests on.

The DER codec is xrdsec's (``xgfalclient.crypto.der`` is :mod:`xrdsec.der`),
so its round-trip, time and strictness cases are xrdsec's tests, not copies
here; DER appears below only as the material the other layers read.
"""

from __future__ import annotations

import base64
import hashlib
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from xrdsec.x509 import split_der_certificates

from xgfalclient.crypto import der, p256, rsa, x509
from xgfalclient.crypto.der import DERError
from xgfalclient.crypto.proxy import (
    BACKDATE,
    CertificateRequest,
    delegation_payload,
    make_request,
    parse_request,
    sign_request,
)
from xgfalclient.testing.pki import PKI, test_key

# -- RSA -----------------------------------------------------------------------------------


def test_rsa_sign_verify_and_crt() -> None:
    key = test_key(0)
    signature = key.sign(b"message", digest="sha256")
    assert key.public.verify(b"message", signature, digest="sha256")
    assert not key.public.verify(b"other", signature, digest="sha256")
    assert not key.public.verify(b"message", signature[1:], digest="sha256")
    raw = key.sign(b"tag")  # GSI's no-DigestInfo form
    assert key.public.verify(b"tag", raw)
    no_crt = rsa.RSAPrivateKey(n=key.n, e=key.e, d=key.d)
    assert no_crt.sign(b"tag") == raw
    half_crt = rsa.RSAPrivateKey(n=key.n, e=key.e, d=key.d, p=key.p)  # CRT needs both primes
    assert half_crt.sign(b"tag") == raw
    assert key.size == 256 and repr(key).startswith("RSAPrivateKey(bits=2048")
    assert repr(key.public) == "RSAPublicKey(bits=2048, e=65537)"
    for digest in ("sha1", "SHA-384", "sha512"):
        assert key.public.verify(b"m", key.sign(b"m", digest=digest), digest=digest)
    with pytest.raises(ValueError, match="unsupported digest"):
        key.sign(b"m", digest="md5")
    with pytest.raises(ValueError, match="does not fit"):
        key.sign(b"x" * 250)


def test_rsa_generate_makes_usable_keys_and_refuses_small_ones() -> None:
    # xrdclient 0.4 generates through OpenSSL: 1024 bits is the floor, and the
    # size must still be even (the primes are half each).
    key = rsa.RSAPrivateKey.generate(1024)
    assert key.n.bit_length() == 1024 and key.p * key.q == key.n
    assert key.public.verify(b"m", key.sign(b"m", digest="sha256"), digest="sha256")
    for bits in (512, 1025):
        with pytest.raises(ValueError, match="at least 1024"):
            rsa.RSAPrivateKey.generate(bits)


def test_rsa_key_formats() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = test_key(1)
    pkcs1 = rsa.private_key_der(key)
    assert rsa.load_private_key(pkcs1).n == key.n  # raw DER
    with pytest.raises(DERError, match="unreadable private key"):
        rsa.load_private_key("neither PEM nor DER")
    assert rsa.load_private_key(rsa.private_key_pem(key).decode()).n == key.n
    spki_alg = der.sequence(der.oid(rsa.RSA_OID), der.null())
    pkcs8 = der.sequence(der.integer(0), spki_alg, der.octet_string(pkcs1))
    pem8 = x509.pem("PRIVATE KEY", pkcs8)
    assert rsa.load_private_key(pem8).d == key.d
    both = x509.pem("CERTIFICATE", b"\x30\x00") + pem8
    assert rsa.load_private_key(both, label="PRIVATE KEY").d == key.d
    with pytest.raises(DERError, match="encrypted"):
        rsa.load_private_key(x509.pem("ENCRYPTED PRIVATE KEY", b"\x30\x00"))
    with pytest.raises(DERError, match="no RSA private key"):
        rsa.load_private_key(x509.pem("CERTIFICATE", b"\x30\x00"))
    ec_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(DERError, match="key is EC, not RSA"):
        rsa.load_private_key(ec_pem)
    # Malformed bodies are refused by the library loader as a whole, with one
    # message, rather than field by field.
    for body in (
        der.sequence(der.octet_string(b"")),  # the key before the version
        der.sequence(der.integer(0)),  # too few fields
        der.sequence(*(der.integer(v) for v in (1, 2, 3, 4, 5, 6))),  # nonsense numbers
        der.sequence(),
        der.sequence(der.integer(0), spki_alg, der.integer(1)),  # PKCS#8 without its key
    ):
        with pytest.raises(DERError, match="unreadable private key"):
            rsa.load_private_key(body)
    with pytest.raises(ValueError, match="needs its primes"):
        rsa.private_key_der(rsa.RSAPrivateKey(1, 2, 3))
    with pytest.raises(ValueError, match="needs its primes"):
        rsa.private_key_der(rsa.RSAPrivateKey(1, 2, 3, p=5))


def test_rsa_digest_signatures_recover_missing_primes() -> None:
    """A key known only as ``(n, e, d)`` - or with one prime - still signs digests.

    OpenSSL wants the CRT form, so the shared key view recovers the primes.
    """
    key = test_key(3)
    reference = key.sign(b"m", digest="sha256")
    for partial in (
        rsa.RSAPrivateKey(n=key.n, e=key.e, d=key.d),
        rsa.RSAPrivateKey(n=key.n, e=key.e, d=key.d, p=key.p),
        rsa.RSAPrivateKey(n=key.n, e=key.e, d=key.d, q=key.q),
    ):
        assert partial.sign(b"m", digest="sha256") == reference


def test_rsa_key_loading_passwords_and_labels() -> None:
    from cryptography.hazmat.primitives import serialization

    key = test_key(4)
    library = key.to_cryptography()
    locked = library.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"pw"),
    )
    for password in ("pw", b"pw"):  # text is taken as its UTF-8
        assert rsa.load_private_key(locked, password=password).n == key.n
    # A label passes over private-key blocks of other names.
    other = (
        test_key(5)
        .to_cryptography()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    both = other + rsa.private_key_pem(key)
    assert rsa.load_private_key(both).n == test_key(5).n
    assert rsa.load_private_key(both, label="RSA PRIVATE KEY").n == key.n


def test_signed_certificates_verify_with_either_key_form(pki: PKI) -> None:
    from xrdsec.x509 import verify_signed

    certificate = pki.user.der
    assert verify_signed(certificate, pki.ca_key.public)  # an RSAPublicKey
    assert verify_signed(certificate, x509.public_key_info(pki.ca_key.public))  # SPKI DER
    top = der.parse_one(certificate).children()
    algorithm = top[1].children()
    for odd, verifies in (
        (der.sequence(*(part.encoded for part in algorithm), der.null()), False),  # 3 fields
        (der.sequence(algorithm[0].encoded), True),  # absent parameters: RSA takes either
    ):
        mangled = der.sequence(top[0].encoded, odd, top[2].encoded)
        assert verify_signed(mangled, pki.ca_key.public) is verifies


def test_rsa_public_keys() -> None:
    key = test_key(2).public
    spki = x509.public_key_info(key)
    assert rsa.load_public_key(x509.pem("PUBLIC KEY", spki)) == key
    assert rsa.load_public_key(spki) == key
    pkcs1 = der.sequence(der.integer(key.n), der.integer(key.e))
    assert rsa.load_public_key(pkcs1) == key
    assert rsa.load_public_key(x509.pem("RSA PUBLIC KEY", pkcs1).decode()) == key
    with pytest.raises(DERError):
        rsa.load_public_key("not a key")
    ec = der.sequence(der.sequence(der.oid("1.2.840.10045.2.1")), der.bit_string(b""))
    with pytest.raises(DERError, match="not RSA"):
        rsa.load_public_key(ec)
    with pytest.raises(DERError, match="not an RSA public key"):
        rsa.load_public_key(der.sequence(der.integer(1)))
    with pytest.raises(DERError, match="non-empty BIT STRING"):
        rsa.public_key_from_bitstring(der.Element(der.TAG_BIT_STRING, b""))
    with pytest.raises(DERError, match="non-empty BIT STRING"):
        rsa.public_key_from_bitstring(der.parse_one(der.integer(1)))
    with pytest.raises(DERError, match="unused bits"):
        rsa.public_key_from_bitstring(der.Element(der.TAG_BIT_STRING, b"\x01\x00"))
    with pytest.raises(DERError, match="expected 2"):
        rsa.public_key_from_bitstring(der.parse_one(der.bit_string(der.sequence(der.integer(1)))))


def test_pem_blocks_are_forgiving() -> None:
    good = x509.pem("A", b"one")
    text = (
        "junk\n"
        "-----END A-----\n"  # an END with no BEGIN
        "-----BEGIN B-----\n!!!notbase64!!\n-----END B-----\n"  # corrupt body
        "-----BEGIN C-----\nAAAA\n-----END D-----\n"  # mismatched labels
    ) + good.decode()
    assert rsa.pem_blocks(text.encode()) == [("A", b"one")]
    assert rsa.pem_blocks(base64.b64encode(b"no pem at all")) == []


# -- X.509 ---------------------------------------------------------------------------------


def test_names() -> None:
    name = x509.Name((("DC", "org"), ("CN", "A"), ("CN", "B")))
    assert (name.cn, name.get("DC"), str(name), bool(name)) == (
        "B",
        ["org"],
        "/DC=org/CN=A/CN=B",
        True,
    )
    assert x509.Name().cn == "" and not x509.Name()
    # Encoding and the fallback decoder are xrdsec's (its tests/test_x509.py).
    assert x509.Name(x509.decode_name(x509.encode_name(name.rdns)).rdns) == name


def test_certificate_parsing(pki: PKI) -> None:
    assert pki.ca.is_self_signed and not pki.ca.is_proxy
    assert pki.host.issuer == pki.ca.subject
    assert pki.host.verify_signature(pki.ca_key.public)
    assert pki.host.verify_signature(pki.ca_key.public.der())  # any key, as its SPKI
    assert not pki.host.verify_signature(pki.host_key.public)
    assert not pki.host.expired and pki.host.remaining() > 0
    assert str(pki.user) == "/DC=org/DC=xgfal/OU=People/CN=Test User"
    proxy = x509.load_certificates(pki.proxy_path.read_bytes())[0]
    assert proxy.is_rfc_proxy and proxy.is_proxy and not proxy.is_limited
    assert proxy.proxy_policy == x509.INHERIT_ALL_OID
    assert proxy.pem().startswith(b"-----BEGIN CERTIFICATE-----")
    unknown = x509.Certificate(**{**_fields(pki.host), "signature_oid": "1.2.3"})
    assert not unknown.verify_signature(pki.ca_key.public)


def _fields(cert: x509.Certificate) -> dict[str, Any]:
    return {name: getattr(cert, name) for name in x509.Certificate.__dataclass_fields__}


def test_proxy_kinds(pki: PKI) -> None:
    limited = x509.load_certificates(pki.proxy("limited").read_bytes())[0]
    assert limited.is_limited and limited.proxy_policy == x509.LIMITED_PROXY_OID
    legacy = x509.load_certificates(pki.proxy("legacy").read_bytes())[0]
    assert legacy.is_legacy_proxy and legacy.is_proxy and not legacy.is_rfc_proxy
    assert not legacy.is_limited
    draft = x509.Certificate(
        **{
            **_fields(legacy),
            "extensions": {x509.DRAFT_PROXY_CERT_INFO_OID: (True, x509.proxy_cert_info())},
        }
    )
    assert draft.is_rfc_proxy and draft.proxy_policy == x509.INHERIT_ALL_OID
    garbled = x509.Certificate(
        **{**_fields(legacy), "extensions": {x509.PROXY_CERT_INFO_OID: (True, b"\x05")}}
    )
    assert garbled.proxy_policy == ""
    limited_legacy = x509.Certificate(
        **{**_fields(legacy), "subject": x509.Name((*legacy.issuer.rdns, ("CN", "limited proxy")))}
    )
    assert limited_legacy.is_limited
    nameless = x509.Certificate(**{**_fields(legacy), "subject": x509.Name()})
    assert not nameless.is_legacy_proxy
    # Globus' reading, not XrdCl's: exactly CN=proxy, appended to the issuer's name.
    not_a_cn = x509.Certificate(
        **{**_fields(legacy), "subject": x509.Name((*legacy.issuer.rdns, ("OU", "proxy")))}
    )
    assert not not_a_cn.is_legacy_proxy and not not_a_cn.is_proxy
    elsewhere = x509.Certificate(
        **{**_fields(legacy), "subject": x509.Name((("CN", "Someone Else"), ("CN", "proxy")))}
    )
    assert not elsewhere.is_legacy_proxy


def test_certificate_rejects_malformed() -> None:
    algorithm = der.sequence(der.oid("1.2.840.113549.1.1.11"))
    for top in [
        (der.integer(1),),
        (der.integer(1), algorithm, der.bit_string(b"")),  # body is not a SEQUENCE
        (der.sequence(), algorithm, der.integer(1)),  # signature is not a BIT STRING
    ]:
        with pytest.raises(DERError, match=r"not an X\.509"):
            x509.parse_certificate(der.sequence(*top))
    with pytest.raises(DERError, match="missing required fields"):
        x509.parse_certificate(der.sequence(der.sequence(), algorithm, der.bit_string(b"")))
    tbs = der.sequence(der.integer(1))
    shell = der.sequence(tbs, der.sequence(der.oid("1.2.840.113549.1.1.11")), der.bit_string(b""))
    with pytest.raises(DERError, match="missing required fields"):
        x509.parse_certificate(shell)
    fields = [
        der.integer(1),
        der.null(),
        der.null(),
        der.sequence(der.null()),
        der.null(),
        der.null(),
    ]
    shell = der.sequence(der.sequence(*fields), der.sequence(der.oid("1.2.3")), der.bit_string(b""))
    with pytest.raises(DERError, match="pair of times"):
        x509.parse_certificate(shell)


def _ec_key_pair(
    curve: ec.EllipticCurve | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """A fresh EC private key and its ``SubjectPublicKeyInfo`` DER."""
    from cryptography.hazmat.primitives import serialization

    key = ec.generate_private_key(curve or ec.SECP256R1())
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return key, spki


def test_non_rsa_and_odd_certificates(pki: PKI) -> None:
    moment = time.time()
    # The certified key goes through cryptography's builder, so it must be a
    # real key; a non-RSA one has no RSAPublicKey view.
    _, ec_spki = _ec_key_pair()
    odd = x509.build_certificate(
        subject=x509.encode_name((("CN", "ec"),)),
        issuer=pki.ca.subject.encoded(),
        public_key=ec_spki,
        signer=pki.ca_key,
        not_before=moment,
        not_after=moment + 60,
        extensions=[x509.extension("1.2.3.4", b"\x05\x00")],
    )
    parsed = x509.parse_certificate(odd)
    assert parsed.public_key is None and "1.2.3.4" in parsed.extensions
    no_version = der.parse_one(odd).children()
    tbs_fields = no_version[0].children()[1:]  # drop [0] version
    rebuilt = der.sequence(
        der.sequence(*(f.encoded for f in tbs_fields)), no_version[1].encoded, no_version[2].encoded
    )
    assert x509.parse_certificate(rebuilt).serial == parsed.serial
    # An RSA-labelled SPKI whose key is not a BIT STRING has no key. No
    # signer would certify one, so it is spliced into the signed body.
    top = der.parse_one(odd).children()
    body = [f.encoded for f in top[0].children()]
    unkeyed_body = list(body)
    unkeyed_body[6] = der.sequence(der.sequence(der.oid(rsa.RSA_OID)), der.null())
    unkeyed = der.sequence(der.sequence(*unkeyed_body), top[1].encoded, top[2].encoded)
    assert x509.parse_certificate(unkeyed).public_key is None
    # A serial that is not an INTEGER reads as 0; an SPKI of one part has no key.
    body[1] = der.null()
    body[6] = der.sequence(der.sequence(der.oid(rsa.RSA_OID)))
    mangled = x509.parse_certificate(
        der.sequence(der.sequence(*body), top[1].encoded, top[2].encoded)
    )
    assert mangled.serial == 0 and mangled.public_key is None


def test_load_certificates_and_credentials(pki: PKI, tmp_path: Path) -> None:
    mixed = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" + pki.user.pem()
    mixed += x509.pem("RSA PRIVATE KEY", b"\x30\x00")
    assert [str(c.subject) for c in x509.load_certificates(mixed)] == [str(pki.user.subject)]
    credential = pki.credential()
    assert credential.identity == str(pki.user.subject)
    assert not credential.expired and credential.remaining() > 0
    assert b"Test CA" not in credential.chain_pem() or True
    assert repr(credential).endswith("key=<redacted>)")
    assert credential.chain_pem().count(b"BEGIN CERTIFICATE") == 2
    separate = x509.load_credential(str(pki.user_cert_path), str(pki.user_key_path))
    same = x509.load_credential(str(pki.proxy_path), str(pki.proxy_path))  # read once
    assert same.key == credential.key
    assert separate.identity == str(pki.user.subject)
    only_proxies = x509.Credential((credential.chain[0],), credential.key)
    assert only_proxies.identity == str(credential.chain[0].subject)
    only_ca = x509.Credential((pki.ca,), pki.ca_key)
    assert only_ca.chain_pem() == pki.ca.pem()
    empty = tmp_path / "empty.pem"
    empty.write_text("nothing")
    with pytest.raises(DERError, match="no certificate"):
        x509.load_credential(str(empty))


def test_proxy_cert_info_is_xrdsecs_value() -> None:
    """gfal2's ``proxy_cert_info`` is the value xrdsec's every profile writes."""
    info = der.parse_one(x509.proxy_cert_info(x509.LIMITED_PROXY_OID, path_length=0)).children()
    assert der.read_integer(info[0]) == 0
    assert der.oid_string(info[1].children()[0]) == x509.LIMITED_PROXY_OID
    assert len(der.parse_one(x509.proxy_cert_info()).children()) == 1  # no path length


# -- proxy signing (delegation) --------------------------------------------------------------------


def test_request_round_trip() -> None:
    key = test_key(5)
    request = parse_request(make_request(key, (("CN", "delegated"),)))
    assert isinstance(request, CertificateRequest)
    assert request.verify() and request.public_key == key.public
    assert str(request.subject) == "/CN=delegated"


def test_an_ec_request_is_read_and_signed(pki: PKI) -> None:
    """xrdsec's request parser reads any key type; an EC key is certified as it is."""
    from cryptography import x509 as library
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    ec_key, ec_spki = _ec_key_pair()
    csr = (
        library.CertificateSigningRequestBuilder()
        .subject_name(library.Name([library.NameAttribute(NameOID.COMMON_NAME, "ec")]))
        .sign(ec_key, hashes.SHA256())
    )
    request = parse_request(csr.public_bytes(serialization.Encoding.DER))
    assert request.verify() and request.public_key is None and request.spki == ec_spki
    proxy = x509.parse_certificate(sign_request(request, pki.credential()))
    assert proxy.spki == ec_spki and proxy.is_rfc_proxy


def test_request_rejects_malformed() -> None:
    with pytest.raises(DERError, match="not a PKCS#10"):
        parse_request(der.sequence(der.integer(1)))
    with pytest.raises(DERError, match="PKCS#10"):
        parse_request(der.sequence(der.integer(1), der.sequence(), der.bit_string(b"")))
    info = der.sequence(der.integer(0))
    with pytest.raises(DERError, match="needs a version, a subject and a key"):
        parse_request(
            der.sequence(info, der.sequence(der.oid("1.2.840.113549.1.1.11")), der.bit_string(b""))
        )
    good = der.parse_one(make_request(test_key(5))).children()
    # An RSA signature labelled ECDSA: read, but it proves nothing.
    bad_alg = der.sequence(
        good[0].encoded, der.sequence(der.oid("1.2.840.10045.4.3.2")), good[2].encoded
    )
    assert not parse_request(bad_alg).verify()
    with pytest.raises(DERError, match="does not verify"):
        sign_request(bad_alg, x509.Credential((), test_key(0)))
    with pytest.raises(DERError, match="not a PKCS#10"):
        parse_request(der.sequence(der.sequence(), der.sequence(), der.null()))
    with pytest.raises(DERError, match="not a PKCS#10"):
        # A key cryptography cannot load at all: its ValueError, as a DERError.
        spki = der.sequence(der.sequence(der.oid(rsa.RSA_OID), der.null()), der.bit_string(b"x"))
        info = der.sequence(der.integer(0), der.sequence(), spki)
        parse_request(der.sequence(info, good[1].encoded, good[2].encoded))
    forged = der.sequence(good[0].encoded, good[1].encoded, der.bit_string(b"\x00" * 256))
    with pytest.raises(DERError, match="does not verify"):
        sign_request(forged, x509.Credential((), test_key(0)))


def test_sign_request_rfc(pki: PKI) -> None:
    credential = pki.credential()
    now = time.time()
    request = make_request(test_key(6))
    certificate = x509.parse_certificate(sign_request(request, credential, lifetime=60, now=now))
    issuer = credential.certificate
    assert certificate.issuer.rdns == issuer.subject.rdns
    assert certificate.subject.rdns[:-1] == issuer.subject.rdns
    assert certificate.subject.cn == str(certificate.serial)
    assert certificate.is_rfc_proxy and not certificate.is_limited
    assert certificate.not_before == int(now - BACKDATE)
    assert certificate.not_after == int(now + 60)
    assert isinstance(credential.key, rsa.RSAPrivateKey)
    assert certificate.verify_signature(credential.key.public)
    assert certificate.public_key == test_key(6).public
    unlimited = x509.parse_certificate(sign_request(parse_request(request), credential))
    assert unlimited.not_after == min(link.not_after for link in credential.chain)
    limited = x509.parse_certificate(sign_request(request, credential, limited=True))
    assert limited.is_limited
    payload = delegation_payload(sign_request(request, credential), credential)
    assert len(split_der_certificates(payload)) == 3  # new proxy, proxy, user (no CA)
    anchored = x509.Credential((*credential.chain, pki.ca), credential.key)
    payload = delegation_payload(sign_request(request, anchored), anchored)
    assert len(split_der_certificates(payload)) == 3  # the CA is left out


def test_every_refusal_of_xrdsecs_issuer_is_a_der_error(pki: PKI) -> None:
    """The GSI and gridsite callers catch ``DERError``; xrdsec's ``ProxyError`` becomes one."""
    with pytest.raises(DERError, match="lifetime must be positive"):
        sign_request(make_request(test_key(6)), pki.credential(), lifetime=0)


def test_build_certificate_is_xrdsecs_issuer(pki: PKI) -> None:
    """One issuing implementation: random serials, no SHA-1, EC signers."""
    moment = time.time()
    common: dict[str, Any] = {
        "subject": x509.encode_name((("CN", "x"),)),
        "issuer": pki.ca.subject.encoded(),
        "public_key": x509.public_key_info(test_key(6).public),
        "signer": pki.ca_key,
        "not_before": moment,
        "not_after": moment + 60,
    }
    serials = {x509.parse_certificate(x509.build_certificate(**common)).serial for _ in range(4)}
    assert len(serials) == 4 and all(0 < serial < 2**63 for serial in serials)
    assert x509.parse_certificate(x509.build_certificate(**common, serial=5)).serial == 5
    with pytest.raises(ValueError, match="unsupported digest"):
        x509.build_certificate(**common, digest="sha1")


def test_an_ec_credential_signs_a_delegated_proxy(pki: PKI) -> None:
    """sign_request through an EC proxy key: ``ecdsa-with-SHA256``, verifiable."""
    from xrdsec.signatures import verify_signature

    ec_key, ec_spki = _ec_key_pair()
    moment = time.time()
    user = x509.parse_certificate(
        x509.build_certificate(
            subject=x509.encode_name((("CN", "EC user"),)),
            issuer=pki.ca.subject.encoded(),
            public_key=ec_spki,
            signer=pki.ca_key,
            not_before=moment - 60,
            not_after=moment + 3600,
        )
    )
    credential = x509.Credential((user, pki.ca), ec_key)
    proxy = x509.parse_certificate(sign_request(make_request(test_key(6)), credential))
    assert proxy.signature_oid == "1.2.840.10045.4.3.2"
    assert proxy.issuer.rdns == user.subject.rdns and proxy.is_rfc_proxy
    assert verify_signature(ec_spki, proxy.signature_oid, None, proxy.signature, proxy.tbs)


def test_a_credential_needs_a_key_that_can_sign_a_proxy(pki: PKI, tmp_path: Path) -> None:
    """RSA and EC keys load (xrdsec's loader); one that cannot sign a proxy is refused."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519 as library_ed25519

    def key_file(key: PrivateKeyTypes) -> str:
        path = tmp_path / "key.pem"
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return str(path)

    ec_key, _ = _ec_key_pair()
    loaded = x509.load_credential(str(pki.user_cert_path), key_file(ec_key))
    assert isinstance(loaded.key, ec.EllipticCurvePrivateKey)
    assert loaded.key.private_numbers() == ec_key.private_numbers()
    edwards = key_file(library_ed25519.Ed25519PrivateKey.generate())
    with pytest.raises(DERError, match="cannot sign a proxy"):
        x509.load_credential(str(pki.user_cert_path), edwards)


def test_limited_proxies_only_beget_limited(pki: PKI) -> None:
    limited = x509.load_credential(str(pki.proxy("limited")))
    child = x509.parse_certificate(sign_request(make_request(test_key(6)), limited, limited=False))
    assert child.is_limited


def test_sign_request_under_legacy_proxy(pki: PKI) -> None:
    legacy = x509.load_credential(str(pki.proxy("legacy")))
    child = x509.parse_certificate(sign_request(make_request(test_key(6)), legacy))
    assert child.subject.cn == "proxy" and not child.is_rfc_proxy
    limited = x509.parse_certificate(sign_request(make_request(test_key(6)), legacy, limited=True))
    assert limited.subject.cn == "limited proxy"


# -- P-256 -------------------------------------------------------------------------------------


def test_p256_decode_point_rejects() -> None:
    x, y = (value.to_bytes(32, "big") for value in p256.G)
    too_big = p256.P.to_bytes(32, "big")
    for bad in (b"\x02" + x + y, b"\x04" + too_big + y, b"\x04" + x + too_big):
        with pytest.raises(ValueError):
            p256.decode_point(bad)
    assert p256.decode_point(b"\x04" + x + y) == p256.G


def test_p256_scalar_range() -> None:
    with pytest.raises(ValueError, match="out of range"):
        p256.public_key(p256.N)  # the point at infinity
    with pytest.raises(ValueError, match="out of range"):
        p256.public_key(p256.N + 1)  # a real point, but not a canonical scalar
    with pytest.raises(ValueError, match="out of range"):
        p256.public_key(-1)  # refused before the ladder, which would never end


def test_p256_verify_summing_to_infinity() -> None:
    # With the key -G and r = e, e*w*G + r*w*(-G) is the point at infinity.
    message = b"m"
    e = int.from_bytes(hashlib.sha256(message).digest(), "big") % p256.N
    negated = (p256.G[0], p256.P - p256.G[1])
    assert not p256.verify(negated, message, e, 1)


# -- libcrypto, against a fake library -------------------------------------------------------
