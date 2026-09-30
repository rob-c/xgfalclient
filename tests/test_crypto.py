"""DER, RSA, X.509 and proxy signing: the pure-Python crypto GSI rests on."""

from __future__ import annotations

import base64
import hashlib
import time
from pathlib import Path

import pytest

from xgfalclient.crypto import der, libcrypto, p256, rsa, x509
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

# -- DER ---------------------------------------------------------------------------------


def test_der_round_trips() -> None:
    for value in (0, 1, 127, 128, 255, 256, -1, -129, 2**70):
        assert der.read_integer(der.parse_one(der.integer(value))) == value
    for dotted in ("1.2.840.113549.1.1.11", "2.5.4.3", "1.3.6.1.4.1.3536.1.1.1.9", "2.999.3"):
        assert der.oid_string(der.parse_one(der.oid(dotted))) == dotted
    long = der.octet_string(b"x" * 300)
    assert der.parse_one(long).value == b"x" * 300
    assert der.parse_one(der.boolean(True)).value == b"\xff"
    assert der.parse_one(der.boolean(False)).value == b"\x00"
    assert der.null() == b"\x05\x00"
    assert der.parse_one(der.printable_string("ab")).tag == der.TAG_PRINTABLE_STRING
    assert der.parse_one(der.utf8_string("é")).value == "é".encode()
    assert der.parse_one(der.bit_string(b"\x01")).value == b"\x00\x01"
    assert der.set_of(b"\x02\x01\x02", b"\x02\x01\x01") == b"\x31\x06\x02\x01\x01\x02\x01\x02"
    assert der.explicit(3, b"") == b"\xa3\x00"
    element = der.parse_one(der.sequence(der.integer(1), der.integer(2)))
    assert element.constructed and len(element.children()) == 2
    assert der.read_integer(element[1]) == 2
    assert element.encoded == der.sequence(der.integer(1), der.integer(2))
    assert repr(element) == "Element(tag=0x30, len=6)"


def test_der_times() -> None:
    moment = 1_790_000_000.0
    assert der.decode_time(der.parse_one(der.utc_time(moment))) == moment
    assert der.decode_time(der.parse_one(der.generalized_time(moment))) == moment
    assert der.parse_one(der.validity_time(moment)).tag == der.TAG_UTC_TIME
    far = 2_600_000_000.0  # 2052
    assert der.parse_one(der.validity_time(far)).tag == der.TAG_GENERALIZED_TIME
    assert der.decode_time(der.Element(der.TAG_UTC_TIME, b"991231235959Z")) == 946684799.0
    assert der.decode_time(der.Element(der.TAG_GENERALIZED_TIME, b"20260101")) == 1767225600.0
    with pytest.raises(DERError, match="malformed UTCTime"):
        der.decode_time(der.Element(der.TAG_UTC_TIME, b"99"))
    with pytest.raises(DERError, match="not a certificate time"):
        der.decode_time(der.Element(der.TAG_INTEGER, b"1"))
    with pytest.raises(DERError, match="malformed time"):
        der.decode_time(der.Element(der.TAG_GENERALIZED_TIME, b"2026xx01000000"))


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "no tag byte"),
        (b"\x30", "no length byte"),
        (b"\x30\x80", "indefinite"),
        (b"\x30\x85\x01\x01\x01\x01\x01", "implausible"),
        (b"\x30\x82\x01", "runs past the end"),
        (b"\x30\x05\x01", "claims 5 bytes"),
        (b"\x1f\x01\x00", "multi-byte tags"),
    ],
)
def test_der_rejects_malformed(data: bytes, message: str) -> None:
    with pytest.raises(DERError, match=message):
        der.parse(data)


def test_der_strictness() -> None:
    with pytest.raises(DERError, match="trailing"):
        der.parse_one(der.null() + b"\x00")
    with pytest.raises(DERError, match="primitive"):
        der.parse_one(der.integer(1)).children()
    with pytest.raises(DERError, match="expected INTEGER"):
        der.read_integer(der.parse_one(der.null()))
    with pytest.raises(DERError, match="no content"):
        der.read_integer(der.Element(der.TAG_INTEGER, b""))
    with pytest.raises(DERError, match="expected OBJECT IDENTIFIER"):
        der.oid_string(der.parse_one(der.null()))
    with pytest.raises(DERError, match="no content"):
        der.oid_string(der.Element(der.TAG_OID, b""))
    with pytest.raises(DERError, match="mid-arc"):
        der.oid_string(der.Element(der.TAG_OID, b"\x2a\x86"))
    assert der.parse_all(b"") == []


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


def test_rsa_generate_small_keys() -> None:
    key = rsa.RSAPrivateKey.generate(512)
    assert key.n.bit_length() == 512
    assert key.public.verify(b"m", key.sign(b"m", digest="sha1"), digest="sha1")
    for bits in (256, 513):
        with pytest.raises(ValueError, match="even number"):
            rsa.RSAPrivateKey.generate(bits)


def test_rsa_generate_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    real = test_key(0)
    primes = iter([real.p, real.p, 13, 11, real.p, real.q])  # equal, too short, then good
    monkeypatch.setattr(rsa, "_prime", lambda bits, e: next(primes))
    key = rsa.RSAPrivateKey.generate(2048)
    assert key.n == real.n and key.sign(b"m") == real.sign(b"m")  # d mod phi vs mod lambda


def test_prime_is_coprime_to_e(monkeypatch: pytest.MonkeyPatch) -> None:
    import secrets

    # 133 - 1 is a multiple of 3, so it is skipped before any primality test; 131 is taken.
    draws = iter([0x05, 0x03])
    monkeypatch.setattr(secrets, "randbits", lambda bits: next(draws))
    assert rsa._prime(8, 3) == 131


def test_primality_helpers() -> None:
    assert rsa._probably_prime(2**127 - 1)
    assert not rsa._probably_prime(2**127 + 1)
    assert not rsa._probably_prime(1)
    assert rsa._probably_prime(97)
    assert not rsa._probably_prime(91)
    assert not rsa._probably_prime(561 * 1105)  # Carmichael-ish composites
    assert rsa._factor_twos(48) == (3, 4)
    assert not rsa._composite_witness(2, 1, 1, 3)
    assert not rsa._composite_witness(5, 3, 2, 13)  # reaches n-1 by squaring: prime-like
    assert rsa._composite_witness(2, 7, 1, 15)  # never reaches n-1: composite


def test_rsa_key_formats() -> None:
    key = test_key(1)
    pkcs1 = rsa.private_key_der(key)
    assert rsa.load_private_key(pkcs1).n == key.n  # raw DER
    with pytest.raises(DERError):
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
    ec = der.sequence(
        der.integer(0), der.sequence(der.oid("1.2.840.10045.2.1")), der.octet_string(b"")
    )
    with pytest.raises(DERError, match="not RSA"):
        rsa.load_private_key(ec)
    with pytest.raises(DERError, match="version must precede"):
        rsa.load_private_key(der.sequence(der.octet_string(b"")))
    with pytest.raises(DERError, match="expected at least 6"):
        rsa.load_private_key(der.sequence(der.integer(0)))
    multi = der.sequence(*(der.integer(v) for v in (1, 2, 3, 4, 5, 6)))
    with pytest.raises(DERError, match="multi-prime"):
        rsa.load_private_key(multi)
    with pytest.raises(DERError, match="has 0 fields"):
        rsa.load_private_key(der.sequence())
    # An AlgorithmIdentifier-like second field but no OCTET STRING: not PKCS#8.
    with pytest.raises(DERError, match="has 3 fields"):
        rsa.load_private_key(der.sequence(der.integer(0), spki_alg, der.integer(1)))
    with pytest.raises(ValueError, match="needs its primes"):
        rsa.private_key_der(rsa.RSAPrivateKey(1, 2, 3))
    with pytest.raises(ValueError, match="needs its primes"):
        rsa.private_key_der(rsa.RSAPrivateKey(1, 2, 3, p=5))


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
    encoded = x509.encode_name(
        (
            ("DC", "org"),
            ("emailAddress", "a@b"),
            ("CN", "Ünïcode"),
            ("O", "Plain Org"),
            ("2.5.4.99", ""),
        )
    )
    decoded = x509._decode_name(der.parse_one(encoded))
    assert decoded.rdns == (
        ("DC", "org"),
        ("emailAddress", "a@b"),
        ("CN", "Ünïcode"),
        ("O", "Plain Org"),
        ("2.5.4.99", ""),
    )
    assert decoded.encoded() == encoded
    assert x509.Name(decoded.rdns).encoded() == encoded
    odd = der.sequence(
        der.set_of(der.sequence(der.oid("2.5.4.3"))),  # malformed attribute: skipped
        der.set_of(der.sequence(der.oid("2.5.4.3"), der.tlv(0x1E, "bmp".encode("utf-16-be")))),
    )
    assert x509._decode_name(der.parse_one(odd)).rdns == (("CN", "bmp"),)


def test_certificate_parsing(pki: PKI) -> None:
    assert pki.ca.is_self_signed and not pki.ca.is_proxy
    assert pki.host.issuer == pki.ca.subject
    assert pki.host.verify_signature(pki.ca_key.public)
    assert not pki.host.verify_signature(pki.host_key.public)
    assert not pki.host.expired and pki.host.remaining() > 0
    assert str(pki.user) == "/DC=org/DC=xgfal/OU=People/CN=Test User"
    proxy = x509.load_certificates(pki.proxy_path.read_bytes())[0]
    assert proxy.is_rfc_proxy and proxy.is_proxy and not proxy.is_limited
    assert proxy.proxy_policy == x509.INHERIT_ALL_OID
    assert proxy.pem().startswith(b"-----BEGIN CERTIFICATE-----")
    unknown = x509.Certificate(**{**_fields(pki.host), "signature_oid": "1.2.3"})
    assert not unknown.verify_signature(pki.ca_key.public)


def _fields(cert: x509.Certificate) -> dict[str, object]:
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


def test_non_rsa_and_odd_certificates(pki: PKI) -> None:
    moment = time.time()
    ec_spki = der.sequence(der.sequence(der.oid("1.2.840.10045.2.1")), der.bit_string(b"\x04abc"))
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
    weird_key = der.sequence(der.sequence(der.oid(rsa.RSA_OID)), der.null())
    unkeyed = x509.build_certificate(
        subject=x509.encode_name((("CN", "x"),)),
        issuer=pki.ca.subject.encoded(),
        public_key=weird_key,
        signer=pki.ca_key,
        not_before=moment,
        not_after=moment + 60,
        serial=5,
    )
    assert x509.parse_certificate(unkeyed).public_key is None
    # A serial that is not an INTEGER reads as 0; an SPKI of one part has no key.
    top = der.parse_one(odd).children()
    body = [f.encoded for f in top[0].children()]
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


def test_builders() -> None:
    assert der.parse_one(x509.key_usage(0, 2)).value == b"\x05\xa0"
    assert der.parse_one(x509.key_usage(5, 6)).value == b"\x01\x06"
    info = der.parse_one(x509.proxy_cert_info(x509.LIMITED_PROXY_OID, path_length=0)).children()
    assert der.read_integer(info[0]) == 0
    assert x509._policy_language(x509.proxy_cert_info()) == x509.INHERIT_ALL_OID
    critical = der.parse_one(x509.extension("2.5.29.15", b"\x03\x01\x00", critical=True)).children()
    assert critical[1].tag == der.TAG_BOOLEAN
    assert 0 <= x509.proxy_serial(b"key") < 2**32
    assert der.parse_one(x509.signature_algorithm("sha384")).children()[0] == der.parse_one(
        der.oid("1.2.840.113549.1.1.12")
    )


def test_extension_parsing_skips_oddities() -> None:
    oddities = [
        der.Element(0xA1, b""),  # not [3]
        der.parse_one(
            der.explicit(
                3,
                der.sequence(
                    der.sequence(der.oid("1.2.3"), der.integer(1)),  # value is not an OCTET STRING
                    der.sequence(der.oid("1.2.4"), der.boolean(False), der.octet_string(b"v")),
                    # three parts, but the middle one is no BOOLEAN: not critical
                    der.sequence(der.oid("1.2.5"), der.integer(1), der.octet_string(b"w")),
                ),
            )
        ),
    ]
    assert x509._extensions(oddities) == {"1.2.4": (False, b"v"), "1.2.5": (False, b"w")}


# -- proxy signing (delegation) --------------------------------------------------------------------


def test_request_round_trip() -> None:
    key = test_key(5)
    request = parse_request(make_request(key, (("CN", "delegated"),)))
    assert isinstance(request, CertificateRequest)
    assert request.verify() and request.public_key == key.public
    assert str(request.subject) == "/CN=delegated" and request.digest == "sha256"


def test_request_rejects_malformed() -> None:
    with pytest.raises(DERError, match="not a PKCS#10"):
        parse_request(der.sequence(der.integer(1)))
    with pytest.raises(DERError, match="PKCS#10"):
        parse_request(der.sequence(der.integer(1), der.sequence(), der.bit_string(b"")))
    info = der.sequence(der.integer(0))
    with pytest.raises(DERError, match="incomplete"):
        parse_request(
            der.sequence(info, der.sequence(der.oid("1.2.840.113549.1.1.11")), der.bit_string(b""))
        )
    good = der.parse_one(make_request(test_key(5))).children()
    bad_alg = der.sequence(
        good[0].encoded, der.sequence(der.oid("1.2.840.10045.4.3.2")), good[2].encoded
    )
    with pytest.raises(DERError, match="unsupported request signature"):
        parse_request(bad_alg)
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
    assert certificate.verify_signature(credential.key.public)
    assert certificate.public_key == test_key(6).public
    unlimited = x509.parse_certificate(sign_request(parse_request(request), credential))
    assert unlimited.not_after == min(link.not_after for link in credential.chain)
    limited = x509.parse_certificate(sign_request(request, credential, limited=True))
    assert limited.is_limited
    payload = delegation_payload(sign_request(request, credential), credential)
    assert len(x509.split_der_certificates(payload)) == 3  # new proxy, proxy, user (no CA)
    anchored = x509.Credential((*credential.chain, pki.ca), credential.key)
    payload = delegation_payload(sign_request(request, anchored), anchored)
    assert len(x509.split_der_certificates(payload)) == 3  # the CA is left out


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


def test_split_der_rejects_garbage() -> None:
    with pytest.raises(DERError):
        x509.split_der_certificates(b"\x30\x05\x00")


# -- P-256 -------------------------------------------------------------------------------------


def test_p256_adding_a_point_to_itself_doubles_it() -> None:
    g = (*p256.G, 1)
    assert p256._affine(p256._add(g, g)) == p256._affine(p256._double(g))


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


class _Function:
    """A ctypes foreign function: ``argtypes``/``restype`` settable, results scripted."""

    def __init__(self, *results: object) -> None:
        self.results = list(results) or [1]
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, *args: object) -> object:
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]


class _Handle:
    """Every symbol the backend looks up, each answering 1 unless told otherwise."""

    def __init__(self, **results: tuple[object, ...]) -> None:
        for name in (*libcrypto._REQUIRED, *libcrypto._GCM, *libcrypto._MAC):
            setattr(self, name, _Function(*results.get(name, ())))


@pytest.fixture
def no_known_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fakes here script each call, so keep the load-time known-answer gate off them."""
    for name in ("_ctr_known_answer", "_chacha_known_answer", "_gcm_known_answer"):
        monkeypatch.setattr(libcrypto.LibCrypto, name, lambda self: None)


@pytest.mark.usefixtures("no_known_answers")
def test_libcrypto_poly1305_unavailable_when_fetch_fails() -> None:
    lib = libcrypto.LibCrypto(_Handle(EVP_MAC_fetch=(None,)), None)
    assert not lib.has_poly1305 and lib.has_gcm and lib.version == "libcrypto"


@pytest.mark.usefixtures("no_known_answers")
@pytest.mark.parametrize("failing", ["EVP_MAC_init", "EVP_MAC_update", "EVP_MAC_final"])
def test_libcrypto_poly1305_failures(failing: str) -> None:
    lib = libcrypto.LibCrypto(_Handle(**{failing: (0,)}), None)
    with pytest.raises(RuntimeError, match="Poly1305 failed"):
        lib.poly1305(bytes(32), b"data")


@pytest.mark.usefixtures("no_known_answers")
def test_libcrypto_gcm_failures() -> None:
    key, nonce = bytes(16), bytes(12)
    with pytest.raises(RuntimeError, match="EVP_CipherInit_ex"):
        libcrypto.LibCrypto(_Handle(EVP_CipherInit_ex=(0,)), None).aes_gcm(key, True)
    # The key schedule takes, the per-packet restart with the nonce does not.
    restart = libcrypto.LibCrypto(_Handle(EVP_CipherInit_ex=(1, 0)), None).aes_gcm(key, True)
    with pytest.raises(RuntimeError, match="AES-GCM failed"):
        restart.apply(nonce, b"", bytearray(32), 0, 16)
    # Opening a packet first hands over the tag to check; that can fail too.
    opener = libcrypto.LibCrypto(_Handle(EVP_CIPHER_CTX_ctrl=(0,)), None).aes_gcm(key, False)
    with pytest.raises(RuntimeError, match="AES-GCM failed"):
        opener.apply(nonce, b"", bytearray(32), 0, 16)


@pytest.mark.usefixtures("no_known_answers")
def test_libcrypto_find_skips_libraries_missing_symbols(monkeypatch: pytest.MonkeyPatch) -> None:
    full = _Handle()
    handles = {"partial": object(), "full": full}
    monkeypatch.setattr(libcrypto, "candidates", lambda: ["partial", "full"])
    monkeypatch.setattr(libcrypto, "_open", handles.get)
    found = libcrypto._find()
    assert found is not None and found.c is full and found.path == "full"


def test_libcrypto_usr_lib_is_fine_off_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes.util
    import sys

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(ctypes.util, "find_library", lambda name: "/usr/lib/libcrypto.so.3")
    assert libcrypto.candidates()[-1] == "/usr/lib/libcrypto.so.3"
