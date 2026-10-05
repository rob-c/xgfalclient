"""VOMS attribute certificate decoding and verification."""

from __future__ import annotations

import os
import time
from dataclasses import replace
from pathlib import Path

import pytest

from xgfalclient.crypto import ed25519, p256, voms
from xgfalclient.crypto.der import (
    DERError,
    bit_string,
    integer,
    oid,
    sequence,
    set_of,
    tlv,
)
from xgfalclient.crypto.rsa import private_key_pem
from xgfalclient.crypto.voms import (
    VOMS_AC_OID,
    VOMS_FQAN_OID,
    VOMSStatus,
    default_ca_path,
    default_voms_dir,
    inspect_voms,
    validate_voms,
)
from xgfalclient.crypto.x509 import (
    PROXY_CERT_INFO_OID,
    Name,
    build_certificate,
    encode_name,
    extension,
    load_credential,
    parse_certificate,
    pem,
    proxy_cert_info,
    public_key_info,
)
from xgfalclient.testing.pki import test_key

SHA1 = "1.2.840.113549.1.1.5"
SHA256 = "1.2.840.113549.1.1.11"
SHA384 = "1.2.840.113549.1.1.12"
SHA512 = "1.2.840.113549.1.1.13"
RSA_PSS = "1.2.840.113549.1.1.10"
MGF1 = "1.2.840.113549.1.1.8"
ECDSA_SHA256 = "1.2.840.10045.4.3.2"
EC_PUBLIC_KEY = "1.2.840.10045.2.1"
P256 = "1.2.840.10045.3.1.7"
ED25519 = "1.3.101.112"
DIGEST_SHA256 = "2.16.840.1.101.3.4.2.1"
VOMS_CERTS = "1.3.6.1.4.1.8005.100.100.10"
VOMS_ATTRIBUTES = "1.3.6.1.4.1.8005.100.100.11"
PROXY_CERT_INFO = proxy_cert_info()
NULL = tlv(0x05, b"")


def name(*pairs):
    return encode_name(pairs)


def make_certificate(
    subject,
    issuer,
    subject_key,
    signer,
    *,
    serial=1,
    not_before=None,
    not_after=None,
    extensions=(),
    subject_spki=None,
):
    now = time.time()
    return build_certificate(
        subject=subject,
        issuer=issuer,
        public_key=subject_spki if subject_spki is not None else public_key_info(subject_key),
        signer=signer,
        serial=serial,
        not_before=now - 3600 if not_before is None else not_before,
        not_after=now + 43200 if not_after is None else not_after,
        extensions=[extension(key, value) for key, value in extensions],
    )


def _algorithm(value=SHA256, parameters=NULL):
    return sequence(oid(value), parameters)


def _general_names(encoded_name):
    return sequence(tlv(0xA4, encoded_name))


def _gentime(when):
    return tlv(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(when)).encode())


def _extension(key, value, critical=False):
    flag = tlv(0x01, b"\xff") if critical else b""
    return sequence(oid(key), flag, tlv(0x04, value))


def _ac(
    user_name,
    user_serial,
    voms_name,
    voms_der,
    voms_key,
    *,
    version=1,
    fqan="/atlas/Role=production/Capability=NULL",
    uri="voms.example:15000",
    not_before=None,
    not_after=None,
    holder_serial=None,
    issuer_name=None,
    inner_algorithm=SHA256,
    outer_algorithm=SHA256,
    signature_key=None,
    signature_digest="sha256",
    algorithm_parameters=NULL,
    signature_function=None,
    embedded=None,
    extra_extensions=(),
    generic=False,
):
    now = time.time()
    values = sequence(tlv(0x04, fqan.encode())) if fqan else sequence()
    syntax = sequence(tlv(0xA0, tlv(0x86, f"atlas://{uri}".encode())), values)
    attributes = (
        sequence(sequence(oid(VOMS_FQAN_OID), set_of(syntax))) if fqan is not None else sequence()
    )
    certs = sequence(sequence(*(embedded if embedded is not None else (voms_der,))))
    extensions = [_extension(VOMS_CERTS, certs), _extension("2.5.29.56", tlv(0x05, b""))]
    if generic:
        triple = sequence(tlv(0x04, b"nickname"), tlv(0x04, b"atlas"), tlv(0x04, b"alice"))
        provider = sequence(_general_names(voms_name), sequence(triple))
        extensions.append(_extension(VOMS_ATTRIBUTES, sequence(sequence(provider))))
    extensions.extend(extra_extensions)
    tbs = sequence(
        integer(version),
        sequence(tlv(0xA0, _general_names(user_name) + integer(holder_serial or user_serial))),
        tlv(0xA0, _general_names(issuer_name or voms_name)),
        _algorithm(inner_algorithm, algorithm_parameters),
        integer(55),
        sequence(_gentime(not_before or now - 300), _gentime(not_after or now + 3600)),
        attributes,
        sequence(*extensions),
    )
    signature = (
        signature_function(tbs)
        if signature_function is not None
        else (signature_key or voms_key).sign(tbs, digest=signature_digest)
    )
    return sequence(tbs, _algorithm(outer_algorithm, algorithm_parameters), bit_string(signature))


def _fixture(
    tmp_path,
    *,
    ac_options=None,
    acs=None,
    parent_carrier=False,
    voms_ski=None,
    voms_spki=None,
):
    tmp_path.mkdir(parents=True, exist_ok=True)
    ca_key, user_key, proxy_key, voms_key = (test_key(slot) for slot in range(1, 5))
    ca_name = name(("0.9.2342.19200300.100.1.25", "org"), ("2.5.4.3", "Grid CA"))
    user_name = name(
        ("0.9.2342.19200300.100.1.25", "org"),
        ("0.9.2342.19200300.100.1.25", "example"),
        ("2.5.4.3", "Alice"),
    )
    voms_name = name(("0.9.2342.19200300.100.1.25", "org"), ("2.5.4.3", "voms.example"))
    ca_der = make_certificate(ca_name, ca_name, ca_key.public, ca_key, serial=1)
    user_der = make_certificate(user_name, ca_name, user_key.public, ca_key, serial=2)
    voms_extensions = (("2.5.29.14", voms_ski),) if voms_ski is not None else ()
    voms_der = make_certificate(
        voms_name,
        ca_name,
        voms_key.public,
        ca_key,
        serial=3,
        extensions=voms_extensions,
        subject_spki=voms_spki,
    )
    options = dict(ac_options or {})
    built = acs or [_ac(user_name, 2, voms_name, voms_der, voms_key, **options)]
    acseq = sequence(sequence(*built))
    parent_name = name(
        ("0.9.2342.19200300.100.1.25", "org"),
        ("0.9.2342.19200300.100.1.25", "example"),
        ("2.5.4.3", "Alice"),
        ("2.5.4.3", "1234"),
    )
    voms_extension = ((VOMS_AC_OID, acseq),)
    if parent_carrier:
        parent_der = make_certificate(
            parent_name,
            user_name,
            proxy_key.public,
            user_key,
            serial=4,
            extensions=(*voms_extension, (PROXY_CERT_INFO_OID, PROXY_CERT_INFO)),
        )
        leaf_key = test_key(5)
        leaf_name = name(
            ("0.9.2342.19200300.100.1.25", "org"),
            ("0.9.2342.19200300.100.1.25", "example"),
            ("2.5.4.3", "Alice"),
            ("2.5.4.3", "1234"),
            ("2.5.4.3", "5678"),
        )
        proxy_der = make_certificate(
            leaf_name,
            parent_name,
            leaf_key.public,
            proxy_key,
            serial=5,
            extensions=((PROXY_CERT_INFO_OID, PROXY_CERT_INFO),),
        )
        key = leaf_key
        between = pem("CERTIFICATE", parent_der)
    else:
        proxy_der = make_certificate(
            parent_name,
            user_name,
            proxy_key.public,
            user_key,
            serial=4,
            extensions=(*voms_extension, (PROXY_CERT_INFO_OID, PROXY_CERT_INFO)),
        )
        key = proxy_key
        between = b""
    proxy_path = tmp_path / "x509up"
    proxy_path.write_bytes(
        pem("CERTIFICATE", proxy_der)
        + private_key_pem(key)
        + between
        + pem("CERTIFICATE", user_der)
        + pem("CERTIFICATE", ca_der)
    )
    ca_dir = tmp_path / "certificates"
    ca_dir.mkdir()
    (ca_dir / "12345678.0").write_bytes(pem("CERTIFICATE", ca_der))
    voms_dir = tmp_path / "vomsdir" / "atlas"
    voms_dir.mkdir(parents=True)
    proxy = load_credential(str(proxy_path))
    # Names are deliberately taken from the parser, pinning the LSC rendering.
    parsed_voms = load_proxy_from_der(voms_der)
    (voms_dir / "voms.example.lsc").write_text(
        f"# trusted server\n{parsed_voms.subject}\n{parsed_voms.issuer}\n"
    )
    return (
        proxy,
        ca_dir,
        voms_dir.parent,
        {
            "ca_name": ca_name,
            "user_name": user_name,
            "voms_name": voms_name,
            "voms_der": voms_der,
            "voms_key": voms_key,
            "ca_der": ca_der,
            "ca_key": ca_key,
            "user_key": user_key,
        },
    )


def load_proxy_from_der(der):
    return parse_certificate(der)


def _pss_parameters(digest=DIGEST_SHA256, salt_length=32):
    digest_algorithm = sequence(oid(digest), NULL)
    return sequence(
        tlv(0xA0, digest_algorithm),
        tlv(0xA1, sequence(oid(MGF1), digest_algorithm)),
        tlv(0xA2, integer(salt_length)),
    )


def _pss_sign(key, message, salt=b"\x42" * 32):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    numbers = rsa.RSAPrivateNumbers(
        key.p,
        key.q,
        key.d,
        key.d % (key.p - 1),
        key.d % (key.q - 1),
        pow(key.q, -1, key.p),
        rsa.RSAPublicNumbers(key.e, key.n),
    )
    return numbers.private_key().sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=len(salt)),
        hashes.SHA256(),
    )


def _ec_spki(public):
    return sequence(
        sequence(oid(EC_PUBLIC_KEY), oid(P256)),
        bit_string(p256.encode_point(public)),
    )


def _ed25519_spki(public):
    return sequence(sequence(oid(ED25519)), bit_string(public))


@pytest.mark.parametrize("kind", ["pss", "ecdsa", "ed25519"])
def test_modern_voms_signature_algorithms(tmp_path, kind):
    options = {}
    spki = None
    if kind == "pss":
        signer = test_key(7)
        spki = public_key_info(signer.public)
        options = {
            "inner_algorithm": RSA_PSS,
            "outer_algorithm": RSA_PSS,
            "algorithm_parameters": _pss_parameters(),
            "signature_function": lambda message: _pss_sign(signer, message),
        }
        expected_digest = "rsassa-pss"
    elif kind == "ecdsa":
        secret = int.from_bytes(b"p256 VOMS signer".ljust(32, b"\0"), "big")
        spki = _ec_spki(p256.public_key(secret))
        options = {
            "inner_algorithm": ECDSA_SHA256,
            "outer_algorithm": ECDSA_SHA256,
            "algorithm_parameters": b"",
            "signature_function": lambda message: sequence(
                *map(integer, p256.sign(secret, message))
            ),
        }
        expected_digest = "sha256"
    else:
        secret = bytes(range(32))
        spki = _ed25519_spki(ed25519.public_key(secret))
        options = {
            "inner_algorithm": ED25519,
            "outer_algorithm": ED25519,
            "algorithm_parameters": b"",
            "signature_function": lambda message: ed25519.sign(secret, message),
        }
        expected_digest = "ed25519"
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path, ac_options=options, voms_spki=spki)
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK
    assert result.verified[0].digest == expected_digest


def test_signature_algorithm_rejection_edges(tmp_path):
    proxy, _, _, _ = _fixture(tmp_path / "rsa")
    entry = inspect_voms(proxy.chain).entries[0]
    signer = entry._embedded[0]

    malformed = replace(entry, _outer_algorithm=sequence())
    assert voms._signature_status(malformed, signer) == (
        VOMSStatus.SIGNATURE_ALGORITHM,
        "",
    )
    bad_pss = replace(
        entry,
        _outer_algorithm=_algorithm(RSA_PSS, integer(1)),
        _signature=b"bad",
    )
    assert voms._signature_status(bad_pss, signer)[0] is VOMSStatus.SIGNATURE_ALGORITHM

    ecdsa = replace(
        entry,
        _outer_algorithm=_algorithm(ECDSA_SHA256, b""),
        _signature=sequence(integer(1)),
    )
    assert voms._signature_status(ecdsa, signer) == (VOMSStatus.SIGNATURE, "sha256")
    ec_secret = 42
    ec_der = make_certificate(
        signer.subject.encoded(),
        signer.issuer.encoded(),
        test_key(1).public,
        test_key(1),
        subject_spki=_ec_spki(p256.public_key(ec_secret)),
    )
    ec_signer = parse_certificate(ec_der)
    assert voms._signature_status(ecdsa, ec_signer) == (VOMSStatus.SIGNATURE, "sha256")
    assert voms._signature_status(ecdsa, replace(ec_signer, der=sequence())) == (
        VOMSStatus.SIGNATURE,
        "sha256",
    )

    ed = replace(entry, _outer_algorithm=_algorithm(ED25519, b""), _signature=b"bad")
    assert voms._signature_status(ed, signer) == (VOMSStatus.SIGNATURE, "ed25519")
    assert voms._signature_status(ed, replace(signer, der=sequence())) == (
        VOMSStatus.SIGNATURE,
        "ed25519",
    )
    pss_without_rsa_key = replace(
        entry, _outer_algorithm=_algorithm(RSA_PSS, b""), _signature=b"bad"
    )
    assert voms._signature_status(pss_without_rsa_key, ec_signer) == (
        VOMSStatus.SIGNATURE,
        "rsassa-pss",
    )

    assert voms._signature_digest(entry) == "sha256"
    assert voms._signature_digest(replace(entry, _outer_algorithm=_algorithm(RSA_PSS, b""))) == (
        "rsassa-pss"
    )
    assert voms._signature_digest(ecdsa) == "sha256"
    assert voms._signature_digest(ed) == "ed25519"
    assert voms._signature_digest(replace(entry, _outer_algorithm=_algorithm("1.2.3", b""))) is None


def test_pss_parameter_rejection_edges():
    parsed = voms._one(_pss_parameters())
    assert voms._pss_parameters([]) == voms._PSSParameters()
    assert voms._pss_parameters([parsed, parsed]) is None
    assert voms._pss_parameters([voms._one(integer(1))]) is None

    duplicate = sequence(tlv(0xA2, integer(1)), tlv(0xA2, integer(2)))
    assert voms._pss_parameters([voms._one(duplicate)]) is None
    invalid_fields = [
        tlv(0xA4, integer(1)),
        tlv(0xA0, integer(1) + integer(2)),
        tlv(0xA0, sequence(oid("1.2.3"))),
        tlv(0xA1, sequence(oid("1.2.3"))),
        tlv(0xA1, sequence(oid(MGF1))),
        tlv(0xA1, sequence(oid(MGF1), sequence(oid(DIGEST_SHA256), NULL), NULL)),
        tlv(0xA1, sequence(oid(MGF1), sequence(oid("1.2.3")))),
        tlv(0xA0, sequence(oid(DIGEST_SHA256), integer(1))),
        tlv(0xA0, sequence(oid(DIGEST_SHA256), NULL, NULL)),
        tlv(0xA2, tlv(0x02, b"\xff")),
        tlv(0xA3, integer(2)),
        tlv(0xA3, sequence()),
    ]
    for field in invalid_fields:
        assert voms._pss_parameters([voms._one(sequence(field))]) is None
    trailer = sequence(tlv(0xA3, integer(1)))
    assert voms._pss_parameters([voms._one(trailer)]) == voms._PSSParameters()


def test_strict_der_and_algorithm_shapes(tmp_path):
    proxy, _, _, _ = _fixture(tmp_path)
    entry = inspect_voms(proxy.chain).entries[0]
    signer = entry._embedded[0]
    bad_parameters = replace(entry, _outer_algorithm=_algorithm(SHA256, integer(1)))
    assert voms._signature_status(bad_parameters, signer)[0] is VOMSStatus.SIGNATURE_ALGORITHM
    assert voms._signature_digest(bad_parameters) is None
    assert voms._rsa_signer_key(replace(signer, der=sequence())) is None

    assert voms._null_parameters([])
    assert not voms._null_parameters([voms._one(integer(1))])
    assert not voms._null_parameters([voms._one(tlv(0x05, b"x"))])
    with pytest.raises(DERError, match="no OID"):
        voms._algorithm_identifier(voms._one(integer(1)))
    with pytest.raises(DERError, match="no OID"):
        voms._algorithm_identifier(voms._one(sequence(oid(SHA256), NULL, NULL)))

    with pytest.raises(DERError, match="wrong shape"):
        voms._decode_extension(set_of(sequence()), 0)
    too_many = sequence(sequence(*(sequence() for _ in range(33))))
    with pytest.raises(DERError, match="too many"):
        voms._decode_extension(too_many, 0)
    malformed_extension = sequence(oid("1.2.3"), integer(1), tlv(0x04, b"x"))
    with pytest.raises(DERError, match="malformed VOMS AC extension"):
        voms._extension_map(voms._one(sequence(malformed_extension)))
    with pytest.raises(DERError, match="malformed VOMS attribute certificate"):
        voms._decode_ac(voms._one(set_of(sequence(), _algorithm(), bit_string(b"x"))), 0)
    assert voms._pss_parameters([voms._one(set_of())]) is None
    assert voms._pss_parameters([voms._one(tlv(0x30, b"\x02"))]) is None
    with pytest.raises(DERError, match="malformed VOMS AC extension"):
        voms._extension_map(voms._one(sequence(integer(1))))


def test_pss_encoding_rejection_edges():
    key = test_key(7)
    valid = _pss_sign(key, b"message")
    assert voms._verify_pss(key.n, key.e, b"message", valid, "sha256", "sha256", 32)
    assert not voms._verify_pss(key.n, key.e, b"message", b"bad", "sha256", "sha256", 32)
    assert not voms._verify_pss(
        key.n, key.e, b"message", b"\0" * len(valid), "sha256", "sha256", 32
    )
    assert not voms._verify_pss(key.n, key.e, b"other", valid, "sha256", "sha256", 32)
    assert not voms._verify_pss(
        key.n, key.e, b"message", key.n.to_bytes(len(valid), "big"), "sha256", "sha256", 32
    )
    assert not voms._verify_pss(257, 1, b"message", b"\x01\x00", "sha256", "sha256", 32)


def test_subject_public_key_rejection_edges(tmp_path):
    proxy, _, _, _ = _fixture(tmp_path)
    signer = inspect_voms(proxy.chain).entries[0]._embedded[0]
    with pytest.raises(DERError, match="no body"):
        voms._subject_public_key(replace(signer, der=sequence()))
    with pytest.raises(DERError, match="no subject public key"):
        voms._subject_public_key(replace(signer, der=sequence(sequence())))

    fields = b"".join(integer(index) for index in range(5))
    malformed_spki = sequence(sequence(fields + sequence(integer(1))))
    with pytest.raises(DERError, match="malformed subject public key"):
        voms._subject_public_key(replace(signer, der=malformed_spki))
    unused_bits_spki = sequence(
        sequence(fields + sequence(sequence(oid(ED25519)), tlv(0x03, b"\x01x")))
    )
    with pytest.raises(DERError, match="unused bits"):
        voms._subject_public_key(replace(signer, der=unused_bits_spki))
    assert voms._only_oid([]) is None


def test_a_voms_proxy_is_decoded_and_fully_verified(tmp_path):
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path, ac_options={"generic": True})
    inspected = inspect_voms(proxy.chain)
    assert inspected.status is VOMSStatus.UNCHECKED
    assert inspected.entries[0].status is VOMSStatus.UNCHECKED
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK
    assert result.vos == ("atlas",)
    assert result.fqans == ("/atlas/Role=production/Capability=NULL",)
    entry = result.verified[0]
    assert entry.verified and entry.digest == "sha256" and entry.carrier == 0
    assert entry.attributes[0].name == "nickname"
    assert entry.attributes[0].value == "alice"
    assert entry.attributes[0].qualifier == "atlas"
    assert 0 < entry.remaining(now=time.time()) <= 3601


def test_a_delegated_proxy_finds_the_ac_on_its_parent(tmp_path):
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path, parent_carrier=True)
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK
    assert result.entries[0].carrier == 1


def test_one_bad_ac_does_not_poison_another_vo_entry(tmp_path):
    _, _, _, facts = _fixture(tmp_path / "facts")
    arguments = (
        facts["user_name"],
        2,
        facts["voms_name"],
        facts["voms_der"],
        facts["voms_key"],
    )
    bad = _ac(*arguments, holder_serial=999)
    good = _ac(*arguments)
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path / "proxy", acs=(bad, good))
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK
    assert tuple(entry.status for entry in result.entries) == (VOMSStatus.HOLDER, VOMSStatus.OK)
    assert result.verified == (result.entries[1],)


@pytest.mark.parametrize(
    ("options", "status"),
    [
        ({"version": 2}, VOMSStatus.VERSION),
        ({"holder_serial": 999}, VOMSStatus.HOLDER),
        ({"not_before": time.time() + 1000}, VOMSStatus.NOT_YET_VALID),
        ({"not_after": time.time() - 1000}, VOMSStatus.EXPIRED),
        ({"embedded": ()}, VOMSStatus.NO_SIGNER),
        ({"inner_algorithm": SHA1}, VOMSStatus.SIGNATURE_ALGORITHM),
        ({"fqan": None}, VOMSStatus.ATTRIBUTES),
    ],
)
def test_intrinsic_failures_are_typed(tmp_path, options, status):
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path, ac_options=options)
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is status
    assert not result.verified and not result.entries[0].verified


def test_signature_issuer_target_and_extension_failures_are_typed(tmp_path):
    _, _, _, facts = _fixture(tmp_path / "base")
    unknown = _extension("1.2.3.4.5", tlv(0x05, b""), critical=True)
    targets = _extension("2.5.29.55", sequence(sequence(tlv(0xA0, tlv(0x82, b"elsewhere")))))
    cases = [
        ({"signature_key": test_key(2)}, VOMSStatus.SIGNATURE),
        ({"issuer_name": facts["user_name"]}, VOMSStatus.ISSUER),
        ({"extra_extensions": (targets,)}, VOMSStatus.TARGET),
        ({"extra_extensions": (unknown,)}, VOMSStatus.EXTENSION),
        ({"outer_algorithm": "1.2.840.113549.1.1.4"}, VOMSStatus.SIGNATURE_ALGORITHM),
    ]
    for index, (options, expected) in enumerate(cases):
        proxy, ca_dir, voms_dir, _ = _fixture(tmp_path / str(index), ac_options=options)
        result = validate_voms(
            proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir), host="this-host"
        )
        assert result.status is expected


def test_external_trust_failures_are_not_silently_downgraded(tmp_path):
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path)
    untrusted = validate_voms(proxy.chain, ca_path=str(tmp_path / "none"), voms_dir=str(voms_dir))
    no_lsc = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(tmp_path / "none"))
    assert untrusted.status is VOMSStatus.UNTRUSTED
    assert no_lsc.status is VOMSStatus.LSC


def test_legacy_voms_certificate_and_rfc2253_lsc_are_accepted(tmp_path):
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path)
    entry = inspect_voms(proxy.chain).entries[0]
    assert entry._embedded
    lsc = next(Path(voms_dir, "atlas").glob("*.lsc"))
    lsc.unlink()
    Path(voms_dir, "atlas", "server.pem").write_bytes(entry._embedded[0].pem())
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK
    Path(voms_dir, "atlas", "server.pem").unlink()
    lsc.write_text("CN=voms.example,DC=org\nCN=Grid CA,DC=org\n")
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK


def test_missing_and_malformed_extensions_have_distinct_results(tmp_path):
    proxy, _, _, _ = _fixture(tmp_path)
    assert inspect_voms(proxy.chain[1:]).status is VOMSStatus.NO_EXTENSION
    broken = proxy.chain[0]
    # Rebuild the certificate object with a parser-visible malformed extension.
    extensions = {**broken.extensions, VOMS_AC_OID: (False, b"\x30")}
    malformed = replace(broken, extensions=extensions)
    assert inspect_voms((malformed,)).status is VOMSStatus.DECODE


def test_default_directories_honour_environment_and_homebrew(monkeypatch, tmp_path):
    certs, voms = tmp_path / "certs", tmp_path / "voms"
    certs.mkdir()
    voms.mkdir()
    monkeypatch.setenv("X509_CERT_DIR", str(certs))
    monkeypatch.setenv("X509_VOMS_DIR", str(voms))
    assert default_ca_path() == str(certs)
    assert default_voms_dir() == str(voms)
    monkeypatch.delenv("X509_CERT_DIR")
    monkeypatch.delenv("X509_VOMS_DIR")
    monkeypatch.setattr(os.path, "isdir", lambda path: path.startswith("/opt/homebrew"))
    monkeypatch.setattr("xgfalclient.crypto.voms.sys.platform", "darwin")
    assert default_ca_path() == "/opt/homebrew/etc/grid-security/certificates"
    assert default_voms_dir() == "/opt/homebrew/etc/grid-security/vomsdir"


def test_der_helpers_reject_malformed_ac_fields(tmp_path, monkeypatch):
    empty = voms._one(sequence())
    assert not voms._first_directory_name(empty)
    nested = voms._one(sequence(sequence(), tlv(0xA4, name(("2.5.4.3", "server")))))
    assert voms._first_directory_name(nested).cn == "server"
    assert not voms._first_directory_name(
        voms._one(tlv(0xA4, name(("2.5.4.3", "one")) + name(("2.5.4.3", "two"))))
    )

    with pytest.raises(DERError, match="trailing"):
        voms._one(sequence() + b"\x00")
    with pytest.raises(DERError, match="GeneralizedTime"):
        voms._time(voms._one(integer(1)))
    with pytest.raises(DERError, match="UTC"):
        voms._time(voms._one(tlv(0x18, b"20260101000000")))
    with pytest.raises(DERError, match="malformed VOMS time"):
        voms._time(voms._one(tlv(0x18, b"not-a-timeZ")))

    assert voms._extension_map(None) == {}
    with pytest.raises(DERError, match="malformed VOMS AC extension"):
        voms._extension_map(voms._one(sequence(sequence(integer(1), tlv(0x04, b"x")))))
    with pytest.raises(DERError, match="no OCTET STRING"):
        voms._extension_map(voms._one(sequence(sequence(oid("1.2.3"), integer(1)))))

    syntax = sequence(
        integer(1),
        sequence(integer(1), tlv(0x04, b"bad,fqan"), tlv(0x04, b"/atlas/good")),
    )
    plain_policy = sequence(tlv(0xA0, tlv(0x86, b"not-a-uri")), sequence())
    empty_syntax = sequence()
    attributes = voms._one(
        sequence(
            sequence(oid("1.2.3"), set_of()),
            sequence(oid(VOMS_FQAN_OID), set_of(empty_syntax, plain_policy, syntax)),
        )
    )
    vo, uri, fqans = voms._attributes(attributes)
    assert (vo, uri, fqans) == ("atlas", "", ("/atlas/good",))
    assert not voms._general_name_text(voms._one(sequence(integer(1))))

    assert voms._generic_attributes(None) == ()
    assert voms._generic_attributes(sequence()) == ()
    short_provider = sequence(sequence(sequence(integer(1))))
    assert voms._generic_attributes(short_provider) == ()
    bad_triple = sequence(
        sequence(
            sequence(_general_names(name(("2.5.4.3", "server"))), sequence(sequence(integer(1))))
        )
    )
    assert voms._generic_attributes(bad_triple) == ()

    assert voms._embedded_certificates(None) == ()
    with pytest.raises(DERError, match="one-element"):
        voms._embedded_certificates(sequence(sequence(), sequence()))
    assert voms._targets(None) is None
    targets = sequence(sequence(integer(1), tlv(0xA0, sequence())))
    assert voms._targets(targets) == ()
    assert voms._authority_key_id(None) is None
    assert voms._authority_key_id(sequence(integer(1))) is None

    with pytest.raises(DERError, match="malformed VOMS attribute certificate"):
        voms._decode_ac(voms._one(sequence()), 0)
    with pytest.raises(DERError, match="missing required fields"):
        voms._decode_ac(voms._one(sequence(sequence(), _algorithm(), bit_string(b"x"))), 0)
    short_validity = sequence(
        integer(1),
        sequence(),
        sequence(),
        _algorithm(),
        integer(1),
        sequence(_gentime(time.time())),
        sequence(),
    )
    with pytest.raises(DERError, match="validity is not a pair"):
        voms._decode_ac(voms._one(sequence(short_validity, _algorithm(), bit_string(b"x"))), 0)
    empty_base_holder = sequence(
        integer(1),
        sequence(tlv(0xA0, b"")),
        sequence(),
        _algorithm(),
        integer(1),
        sequence(_gentime(time.time() - 10), _gentime(time.time() + 10)),
        sequence(),
    )
    assert not voms._decode_ac(
        voms._one(sequence(empty_base_holder, _algorithm(), bit_string(b"x"))), 0
    ).holder
    with pytest.raises(DERError, match="wrong shape"):
        voms._decode_extension(sequence(sequence(), sequence()), 0)
    with pytest.raises(DERError, match="empty"):
        voms._decode_extension(sequence(sequence()), 0)

    proxy, _, _, _ = _fixture(tmp_path)
    entry = inspect_voms(proxy.chain).entries[0]
    assert voms._signature_digest(replace(entry, _outer_algorithm=sequence())) is None
    assert voms._certificate_extension(entry._embedded[0], "1.2.3") is None
    assert validate_voms(()).status is VOMSStatus.NO_EXTENSION

    def broken_extension(_certificate):
        raise DERError("x")

    monkeypatch.setattr(voms, "_voms_extension", broken_extension)
    assert inspect_voms(proxy.chain).status is VOMSStatus.DECODE


@pytest.mark.parametrize(
    ("ski", "aki", "status"),
    [
        (tlv(0x04, b"key-id"), b"key-id", VOMSStatus.OK),
        (tlv(0x04, b"key-id"), b"other", VOMSStatus.ISSUER),
        (b"\x30", b"key-id", VOMSStatus.ISSUER),
        (None, b"key-id", VOMSStatus.OK),
    ],
)
def test_authority_key_identifier_binding(tmp_path, ski, aki, status):
    aki_extension = _extension("2.5.29.35", sequence(tlv(0x80, aki)))
    proxy, ca_dir, voms_dir, _ = _fixture(
        tmp_path,
        voms_ski=ski,
        ac_options={"extra_extensions": (aki_extension,)},
    )
    assert validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir)).status is status


def test_matching_unknown_signature_algorithm_is_rejected(tmp_path):
    proxy, ca_dir, voms_dir, _ = _fixture(
        tmp_path,
        ac_options={
            "inner_algorithm": "1.2.840.113549.1.1.4",
            "outer_algorithm": "1.2.840.113549.1.1.4",
        },
    )
    assert (
        validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir)).status
        is VOMSStatus.SIGNATURE_ALGORITHM
    )


@pytest.mark.parametrize(
    ("algorithm", "digest"),
    [(SHA1, "sha1"), (SHA256, "sha256"), (SHA384, "sha384"), (SHA512, "sha512")],
)
def test_supported_rsa_signature_algorithms(tmp_path, algorithm, digest):
    proxy, ca_dir, voms_dir, _ = _fixture(
        tmp_path,
        ac_options={
            "inner_algorithm": algorithm,
            "outer_algorithm": algorithm,
            "signature_digest": digest,
        },
    )
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK
    assert result.verified[0].digest == digest


def test_trust_and_lsc_failure_edges(tmp_path, monkeypatch):
    proxy, ca_dir, voms_dir, facts = _fixture(tmp_path / "fixture")
    entry = inspect_voms(proxy.chain).entries[0]
    signer = entry._embedded[0]
    now = time.time()

    assert not voms._trusted_chain((replace(signer, not_after=0),), str(ca_dir), now)
    assert not voms._trusted_chain(
        (replace(signer, issuer=Name((("CN", "nobody"),))),), str(ca_dir), now
    )
    bad_der = make_certificate(
        facts["voms_name"],
        facts["ca_name"],
        facts["voms_key"].public,
        facts["user_key"],
        serial=9,
    )
    assert not voms._trusted_chain((parse_certificate(bad_der),), str(ca_dir), now)

    middle_key = test_key(6)
    middle_name = name(("2.5.4.3", "Intermediate"))
    middle_der = make_certificate(
        middle_name, facts["ca_name"], middle_key.public, facts["ca_key"], serial=10
    )
    leaf_der = make_certificate(
        facts["voms_name"], middle_name, facts["voms_key"].public, middle_key, serial=11
    )
    assert voms._trusted_chain(
        (parse_certificate(leaf_der), parse_certificate(middle_der)), str(ca_dir), now
    )

    key_a, key_b = test_key(7), test_key(5)
    name_a, name_b = name(("2.5.4.3", "A")), name(("2.5.4.3", "B"))
    cert_a = parse_certificate(make_certificate(name_a, name_b, key_a.public, key_b, serial=12))
    cert_b = parse_certificate(make_certificate(name_b, name_a, key_b.public, key_a, serial=13))
    assert not voms._trusted_chain((cert_a, cert_b, cert_a), str(ca_dir), now)

    anchors = tmp_path / "anchors"
    anchors.mkdir()
    (anchors / "README").write_text("ignored")
    (anchors / "12345678.0").mkdir()
    assert voms._load_anchors(str(anchors)) == []

    assert not voms._lsc_matches(str(voms_dir), "../atlas", (signer,))
    legacy = Path(voms_dir, "atlas", "wrong.pem")
    legacy.write_bytes(pem("CERTIFICATE", facts["ca_der"]))
    next(Path(voms_dir, "atlas").glob("*.lsc")).unlink()
    assert not voms._lsc_matches(str(voms_dir), "atlas", (signer,))

    lsc = tmp_path / "test.lsc"
    lsc.write_text("\n# only comments\n")
    assert not voms._lsc_file_matches(lsc, (signer,))
    lsc.write_text("a\nb\nc\nd\n")
    assert not voms._lsc_file_matches(lsc, (signer,))
    lsc.write_text(f"CN=wrong\n{signer.issuer}\n")
    assert not voms._lsc_file_matches(lsc, (signer,))
    lsc.write_text(f"{signer.subject}\nCN=wrong\n")
    assert not voms._lsc_file_matches(lsc, (signer,))

    original_read_text = Path.read_text

    def fail_read_text(path, *args, **kwargs):
        if path == lsc:
            raise OSError("unreadable")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_read_text)
    assert not voms._lsc_file_matches(lsc, (signer,))

    monkeypatch.setattr(voms, "load_certificates", lambda _data: (_ for _ in ()).throw(OSError()))
    assert not voms._lsc_matches(str(voms_dir), "atlas", (signer,))

    assert voms._escape_dn(" #comma, ") == r"\ #comma\,\ "
    monkeypatch.setattr(voms.sys, "platform", "linux")
    assert voms._candidate_directories("vomsdir") == ("/etc/grid-security/vomsdir",)
    monkeypatch.delenv("X509_CERT_DIR", raising=False)
    monkeypatch.setattr(os.path, "isdir", lambda _path: False)
    assert default_ca_path() is None

    assert not voms._holder_matches(replace(entry, holder=Name()), proxy.chain)
    orphan = replace(proxy.chain[0], issuer=Name((("CN", "missing"),)))
    assert not voms._holder_matches(entry, (orphan,))
    first = replace(proxy.chain[0], serial=999)
    second = replace(
        proxy.chain[1],
        serial=998,
        subject=first.issuer,
        issuer=first.subject,
        extensions={PROXY_CERT_INFO_OID: (False, PROXY_CERT_INFO)},
    )
    assert not voms._holder_matches(entry, (first, second))
