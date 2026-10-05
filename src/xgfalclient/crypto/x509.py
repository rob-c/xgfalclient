"""Library-backed X.509 inspection and RFC 3820 proxy adapters.

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

from xrdclient.crypto.x509 import ATTRIBUTE_NAMES as ATTRIBUTE_NAMES
from xrdclient.crypto.x509 import ATTRIBUTE_OIDS as ATTRIBUTE_OIDS
from xrdclient.crypto.x509 import Name as Name
from xrdclient.crypto.x509 import _decode_name as _decode_name
from xrdclient.crypto.x509 import _extensions as _extensions
from xrdclient.crypto.x509 import certificate_data
from xrdclient.crypto.x509 import decode_name as decode_name
from xrdclient.crypto.x509 import encode_name as encode_name

from .._compat import SLOTS
from .der import (
    TAG_BIT_STRING,
    DERError,
    bit_string,
    boolean,
    explicit,
    integer,
    null,
    octet_string,
    oid,
    oid_string,
    parse,
    parse_one,
    sequence,
    tlv,
    validity_time,
)
from .rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    load_private_key,
    pem_blocks,
)

__all__ = [
    "Name",
    "Certificate",
    "Credential",
    "decode_name",
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


def parse_certificate(der: bytes) -> Certificate:
    """Adapt the canonical decoded view without parsing a second time."""
    data = certificate_data(der)
    return Certificate(
        subject=data.subject,
        issuer=data.issuer,
        serial=data.serial,
        not_before=data.not_before,
        not_after=data.not_after,
        public_key=data.public_key,
        extensions=data.extension_values,
        der=data.der,
        tbs=data.tbs,
        signature=data.signature,
        signature_oid=data.signature_oid,
        spki=data.spki,
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
