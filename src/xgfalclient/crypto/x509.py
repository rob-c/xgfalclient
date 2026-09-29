"""X.509 certificates and RFC 3820 proxies, read and built in pure Python.

The client needs three things from X.509:

* to **look at** the credential it is about to present - is it a proxy,
  whose, when does it expire - so a stale proxy is a clear sentence rather
  than an opaque TLS alert;
* to **build and sign** a proxy certificate when a server asks for a
  delegated credential (GSI delegation, gridsite delegation);
* to **verify** a signature, which the in-process test servers use to check
  what was delegated to them.

Trust decisions - path building, revocation - belong to the server and to
``ssl``; nothing here pretends to make them.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import textwrap
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

from .._compat import SLOTS
from .der import (
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_SEQUENCE,
    DERError,
    Element,
    bit_string,
    boolean,
    decode_time,
    explicit,
    integer,
    null,
    octet_string,
    oid,
    oid_string,
    parse,
    parse_one,
    printable_string,
    read_integer,
    sequence,
    set_of,
    tlv,
    utf8_string,
    validity_time,
)
from .rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    load_private_key,
    pem_blocks,
    public_key_from_bitstring,
)

__all__ = [
    "Name",
    "Certificate",
    "Credential",
    "load_certificates",
    "load_credential",
    "pem",
    "encode_name",
    "public_key_info",
    "build_certificate",
    "signature_algorithm",
    "PROXY_CERT_INFO_OID",
    "LEGACY_PROXY_OID",
    "INHERIT_ALL_OID",
    "LIMITED_PROXY_OID",
    "INDEPENDENT_OID",
]

ATTRIBUTE_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
}
ATTRIBUTE_OIDS = {short: dotted for dotted, short in ATTRIBUTE_NAMES.items()}

#: ``id-pe-proxyCertInfo``: its presence makes a certificate an RFC 3820 proxy.
PROXY_CERT_INFO_OID = "1.3.6.1.5.5.7.1.14"
#: The draft-era proxyCertInfo OID Globus used before the RFC.
DRAFT_PROXY_CERT_INFO_OID = "1.3.6.1.4.1.3536.1.222"
LEGACY_PROXY_OID = DRAFT_PROXY_CERT_INFO_OID
#: Proxy policy languages: full impersonation, limited, and independent.
INHERIT_ALL_OID = "1.3.6.1.5.5.7.21.1"
INDEPENDENT_OID = "1.3.6.1.5.5.7.21.2"
LIMITED_PROXY_OID = "1.3.6.1.4.1.3536.1.1.1.9"
KEY_USAGE_OID = "2.5.29.15"
BASIC_CONSTRAINTS_OID = "2.5.29.19"
SUBJECT_ALT_NAME_OID = "2.5.29.17"

_SIGNATURE_OIDS = {
    "sha1": "1.2.840.113549.1.1.5",
    "sha256": "1.2.840.113549.1.1.11",
    "sha384": "1.2.840.113549.1.1.12",
    "sha512": "1.2.840.113549.1.1.13",
}
_DIGEST_FOR_OID = {value: key for key, value in _SIGNATURE_OIDS.items()}
_RSA_OID = "1.2.840.113549.1.1.1"


@dataclass(frozen=True, **SLOTS)
class Name:
    """A distinguished name: ``(type, value)`` pairs plus the DER they came from."""

    rdns: tuple[tuple[str, str], ...] = ()
    der: bytes = field(default=b"", compare=False, repr=False)

    @property
    def cn(self) -> str:
        common = [value for key, value in self.rdns if key == "CN"]
        return common[-1] if common else ""

    def get(self, key: str) -> list[str]:
        return [value for name, value in self.rdns if name == key]

    def __str__(self) -> str:
        """OpenSSL's one-line form: ``/DC=org/DC=example/CN=Jane Doe``."""
        return "".join(f"/{key}={value}" for key, value in self.rdns)

    def __bool__(self) -> bool:
        return bool(self.rdns)

    def encoded(self) -> bytes:
        return self.der or encode_name(self.rdns)


def encode_name(rdns: Sequence[tuple[str, str]]) -> bytes:
    """A ``Name`` from ``(type, value)`` pairs, one attribute per RDN."""
    parts = []
    for key, value in rdns:
        kind = ATTRIBUTE_OIDS.get(key, key)
        parts.append(set_of(sequence(oid(kind), _attribute_value(kind, value))))
    return sequence(*parts)


#: Attributes RFC 4519 types as IA5String: domainComponent and emailAddress.
_IA5_ATTRIBUTES = ("0.9.2342.19200300.100.1.25", "1.2.840.113549.1.9.1")


def _attribute_value(kind: str, value: str) -> bytes:
    if kind in _IA5_ATTRIBUTES:
        return tlv(0x16, value.encode("ascii"))
    if _printable(value):
        return printable_string(value)
    return utf8_string(value)


def _printable(value: str) -> bool:
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?")
    return bool(value) and all(char in allowed for char in value)


def _decode_name(element: Element) -> Name:
    rdns: list[tuple[str, str]] = []
    for rdn in element.children():
        for attribute in rdn.children():
            parts = attribute.children()
            if len(parts) != 2:
                continue
            key = oid_string(parts[0])
            rdns.append((ATTRIBUTE_NAMES.get(key, key), _decode_string(parts[1])))
    return Name(tuple(rdns), element.encoded)


def _decode_string(element: Element) -> str:
    if element.tag == 0x1E:  # BMPString
        return element.value.decode("utf-16-be", "replace")
    return element.value.decode("utf-8", "replace")


def pem(label: str, der: bytes) -> bytes:
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode("ascii")


def public_key_info(key: RSAPublicKey) -> bytes:
    """``SubjectPublicKeyInfo`` for an RSA key."""
    return sequence(
        sequence(oid(_RSA_OID), null()),
        bit_string(sequence(integer(key.n), integer(key.e))),
    )


def signature_algorithm(digest: str) -> bytes:
    return sequence(oid(_SIGNATURE_OIDS[digest]), null())


@dataclass(frozen=True, **SLOTS)
class Certificate:
    """One X.509 certificate, decoded far enough to use and to sign from."""

    subject: Name
    issuer: Name
    serial: int
    not_before: float
    not_after: float
    public_key: RSAPublicKey | None
    #: extension OID -> (critical, DER of extnValue's contents)
    extensions: dict[str, tuple[bool, bytes]] = field(default_factory=dict, repr=False)
    der: bytes = field(default=b"", repr=False)
    tbs: bytes = field(default=b"", repr=False)
    signature: bytes = field(default=b"", repr=False)
    signature_oid: str = ""
    spki: bytes = field(default=b"", repr=False)

    @property
    def proxy_policy(self) -> str | None:
        """The proxy policy language OID, or ``None`` for a non-RFC certificate."""
        for extension in (PROXY_CERT_INFO_OID, DRAFT_PROXY_CERT_INFO_OID):
            found = self.extensions.get(extension)
            if found is not None:
                return _policy_language(found[1])
        return None

    @property
    def is_rfc_proxy(self) -> bool:
        return self.proxy_policy is not None

    @property
    def is_legacy_proxy(self) -> bool:
        """A Globus pre-RFC proxy: no extension, subject ends ``CN=proxy``."""
        last = self.subject.rdns[-1] if self.subject.rdns else ("", "")
        return (
            not self.is_rfc_proxy
            and last in (("CN", "proxy"), ("CN", "limited proxy"))
            and self.subject.rdns[:-1] == self.issuer.rdns
        )

    @property
    def is_proxy(self) -> bool:
        return self.is_rfc_proxy or self.is_legacy_proxy

    @property
    def is_limited(self) -> bool:
        return self.proxy_policy == LIMITED_PROXY_OID or (
            self.is_legacy_proxy and self.subject.cn == "limited proxy"
        )

    @property
    def is_self_signed(self) -> bool:
        return self.subject.rdns == self.issuer.rdns

    @property
    def expired(self) -> bool:
        return self.not_after <= time.time()

    def remaining(self) -> float:
        return self.not_after - time.time()

    def pem(self) -> bytes:
        return pem("CERTIFICATE", self.der)

    def verify_signature(self, issuer_key: RSAPublicKey) -> bool:
        digest = _DIGEST_FOR_OID.get(self.signature_oid)
        if digest is None:
            return False
        return issuer_key.verify(self.tbs, self.signature, digest=digest)

    def __str__(self) -> str:
        return str(self.subject)


def _policy_language(value: bytes) -> str:
    """The policy language OID inside a ``ProxyCertInfo``."""
    try:
        info = parse_one(value).children()
        policy = info[-1].children()
        return oid_string(policy[0])
    except (DERError, IndexError):
        return ""


def _extensions(fields: list[Element]) -> dict[str, tuple[bool, bytes]]:
    found: dict[str, tuple[bool, bytes]] = {}
    for extra in fields:
        if extra.tag != 0xA3:
            continue
        for extension in extra.children()[0].children():
            parts = extension.children()
            critical = len(parts) == 3 and parts[1].tag == TAG_BOOLEAN and parts[1].value != b"\x00"
            if parts[-1].tag == TAG_OCTET_STRING:
                found[oid_string(parts[0])] = (critical, parts[-1].value)
    return found


def parse_certificate(der: bytes) -> Certificate:
    """Decode one DER certificate; ``DERError`` if it is not one."""
    certificate = parse_one(der)
    top = certificate.children()
    if len(top) != 3 or top[0].tag != TAG_SEQUENCE or top[2].tag != TAG_BIT_STRING:
        raise DERError("not an X.509 certificate")
    fields = top[0].children()
    index = 1 if fields and fields[0].tag == 0xA0 else 0
    if len(fields) < index + 6:
        raise DERError("certificate body is missing required fields")
    serial = read_integer(fields[index]) if fields[index].tag == TAG_INTEGER else 0
    validity = fields[index + 3].children()
    if len(validity) != 2:
        raise DERError("certificate validity is not a pair of times")
    spki = fields[index + 5]
    parts = spki.children()
    key: RSAPublicKey | None = None
    if len(parts) == 2 and parts[1].tag == TAG_BIT_STRING:
        try:
            key = public_key_from_bitstring(parts[1])
        except DERError:
            key = None  # an EC certificate: readable, just not RSA
    return Certificate(
        subject=_decode_name(fields[index + 4]),
        issuer=_decode_name(fields[index + 2]),
        serial=serial,
        not_before=decode_time(validity[0]),
        not_after=decode_time(validity[1]),
        public_key=key,
        extensions=_extensions(fields[index + 6 :]),
        der=bytes(der),
        tbs=top[0].encoded,
        signature=top[2].value[1:],
        signature_oid=oid_string(top[1].children()[0]),
        spki=spki.encoded,
    )


def load_certificates(data: bytes | str) -> list[Certificate]:
    """Every parseable ``CERTIFICATE`` block, in file order."""
    out: list[Certificate] = []
    for label, der in pem_blocks(data):
        if label != "CERTIFICATE":
            continue
        try:
            out.append(parse_certificate(der))
        except (DERError, ValueError):
            continue
    return out


def split_der_certificates(data: bytes) -> list[Certificate]:
    """Consecutive DER certificates, as GSI delegation sends them."""
    out: list[Certificate] = []
    pos = 0
    while pos < len(data):
        _, end = parse(data, pos)
        out.append(parse_certificate(data[pos:end]))
        pos = end
    return out


@dataclass(frozen=True, **SLOTS)
class Credential:
    """A certificate chain and its private key: what a client authenticates with."""

    chain: tuple[Certificate, ...]
    key: RSAPrivateKey
    path: str = ""

    @property
    def certificate(self) -> Certificate:
        return self.chain[0]

    @property
    def identity(self) -> str:
        """The end entity behind any proxies: the first non-proxy subject."""
        for link in self.chain:
            if not link.is_proxy:
                return str(link.subject)
        return str(self.chain[-1].subject)

    @property
    def expired(self) -> bool:
        return any(link.expired for link in self.chain)

    def remaining(self) -> float:
        return min(link.remaining() for link in self.chain)

    def chain_pem(self) -> bytes:
        """The chain without any trust anchor, which servers refuse to receive."""
        links = [link for link in self.chain if not link.is_self_signed] or list(self.chain)
        return b"".join(link.pem() for link in links)

    def __repr__(self) -> str:
        return f"Credential(subject={str(self.certificate.subject)!r}, key=<redacted>)"


def load_credential(cert_path: str, key_path: str | None = None) -> Credential:
    """A proxy file (chain and key together) or a certificate/key pair."""
    with open(cert_path, "rb") as handle:
        cert_data = handle.read()
    key_data = cert_data
    if key_path and key_path != cert_path:
        with open(key_path, "rb") as handle:
            key_data = handle.read()
    chain = load_certificates(cert_data)
    if not chain:
        raise DERError(f"no certificate in {cert_path}")
    return Credential(tuple(chain), load_private_key(key_data), cert_path)


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def extension(extension_oid: str, value: bytes, critical: bool = False) -> bytes:
    parts = [oid(extension_oid)]
    if critical:
        parts.append(boolean(True))
    parts.append(octet_string(value))
    return sequence(*parts)


def key_usage(*bits: int) -> bytes:
    """A KeyUsage BIT STRING from bit numbers (0 = digitalSignature)."""
    value = 0
    for bit in bits:
        value |= 1 << (7 - bit)
    top = max(bits)
    unused = 7 - top
    return tlv(TAG_BIT_STRING, bytes([unused, value]))


def proxy_cert_info(policy: str = INHERIT_ALL_OID, path_length: int | None = None) -> bytes:
    parts = [] if path_length is None else [integer(path_length)]
    parts.append(sequence(oid(policy)))
    return sequence(*parts)


def build_certificate(
    *,
    subject: bytes,
    issuer: bytes,
    public_key: bytes,
    signer: RSAPrivateKey,
    not_before: float,
    not_after: float,
    serial: int | None = None,
    extensions: Sequence[bytes] = (),
    digest: str = "sha256",
) -> bytes:
    """Sign a v3 certificate. ``subject``/``issuer``/``public_key`` are DER."""
    number = serial if serial is not None else secrets.randbits(63) | 1
    fields = [
        explicit(0, integer(2)),
        integer(number),
        signature_algorithm(digest),
        issuer,
        sequence(validity_time(not_before), validity_time(not_after)),
        subject,
        public_key,
    ]
    if extensions:
        fields.append(explicit(3, sequence(*extensions)))
    tbs = sequence(*fields)
    signature = signer.sign(tbs, digest=digest)
    return sequence(tbs, signature_algorithm(digest), bit_string(signature))


def proxy_serial(public_key_der: bytes) -> int:
    """Globus names a proxy after its key: the first four bytes of its SHA-1."""
    return int.from_bytes(hashlib.sha1(public_key_der).digest()[:4], "big")
