"""gfal2's view of X.509: certificates, credentials and proxies, on xrdsec.

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

Decoding, PEM reading, key loading, the proxy-policy questions and the
certificate building blocks (:func:`extension`, :func:`key_usage`,
:func:`public_key_info`, :func:`signature_algorithm`, which moved there from
here in 0.4.0) are :mod:`xrdsec.x509`'s, and issuing is
:func:`xrdsec.delegation.issue_certificate` (here :func:`build_certificate`):
one decoder, one key loader (RSA or EC), one reading of ``ProxyCertInfo``,
one issuer for every client. What this module keeps is gfal2's *view* of the
result - a :class:`Certificate` whose ``extensions`` map each OID to its
value, and Globus' strict reading of what a proxy is (an RFC 3820
extension, or a GT2 ``CN=proxy``/``CN=limited proxy`` name), where XrdCl
counts any appended ``CN``. :class:`Credential` names its identity by the
first non-proxy subject in the chain, as Globus does. Those types are what
the GSI plugins and the test PKI are written against, so they stay
xgfalclient's own.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from xrdsec.delegation import SigningKey, proxy_cert_info_extension
from xrdsec.delegation import issue_certificate as build_certificate
from xrdsec.der import DERError
from xrdsec.rsa import RSAPublicKey
from xrdsec.x509 import ATTRIBUTE_NAMES as ATTRIBUTE_NAMES
from xrdsec.x509 import ATTRIBUTE_OIDS as ATTRIBUTE_OIDS
from xrdsec.x509 import BASIC_CONSTRAINTS_OID as BASIC_CONSTRAINTS_OID
from xrdsec.x509 import INDEPENDENT_OID as INDEPENDENT_OID
from xrdsec.x509 import INHERIT_ALL_OID as INHERIT_ALL_OID
from xrdsec.x509 import KEY_USAGE_OID as KEY_USAGE_OID
from xrdsec.x509 import LEGACY_PROXY_OID as LEGACY_PROXY_OID
from xrdsec.x509 import LIMITED_PROXY_OID as LIMITED_PROXY_OID
from xrdsec.x509 import PROXY_CERT_INFO_OID as PROXY_CERT_INFO_OID
from xrdsec.x509 import SUBJECT_ALT_NAME_OID as SUBJECT_ALT_NAME_OID
from xrdsec.x509 import Name as Name
from xrdsec.x509 import (
    certificate_data,
    certificates_in,
    credential_key,
    legacy_proxy_kind,
    parse_extension,
    proxy_policy,
    read_credential_files,
    signed_by,
)
from xrdsec.x509 import decode_name as decode_name
from xrdsec.x509 import encode_name as encode_name
from xrdsec.x509 import extension as extension
from xrdsec.x509 import key_usage as key_usage
from xrdsec.x509 import pem_encode as pem
from xrdsec.x509 import public_key_info as public_key_info
from xrdsec.x509 import signature_algorithm as signature_algorithm

__all__ = [
    "INDEPENDENT_OID",
    "INHERIT_ALL_OID",
    "LEGACY_PROXY_OID",
    "LIMITED_PROXY_OID",
    "PROXY_CERT_INFO_OID",
    "Certificate",
    "Credential",
    "Name",
    "build_certificate",
    "decode_name",
    "encode_name",
    "load_certificates",
    "load_credential",
    "pem",
    "public_key_info",
    "signature_algorithm",
]

#: The draft-era proxyCertInfo OID Globus used before the RFC (GT3 proxies),
#: :data:`xrdsec.x509.LEGACY_PROXY_OID` under the name this module gave it.
#: Exported for callers that inspect old credentials; nothing here treats a
#: certificate carrying it as an RFC 3820 proxy, as Globus does not either.
DRAFT_PROXY_CERT_INFO_OID = LEGACY_PROXY_OID


@dataclass(frozen=True, slots=True)
class Certificate:
    """One X.509 certificate, decoded far enough to use and to sign from.

    Normally built by :func:`parse_certificate` from xrdsec's
    :class:`~xrdsec.x509.CertificateData`; the raw ``der``,
    ``tbs``, ``signature`` and ``spki`` are kept so a signature can be
    checked and a proxy issued without decoding again. Immutable, so one
    parsed chain can be shared between threads (and contexts) freely.
    ``public_key`` is ``None`` for a non-RSA key; ``spki`` always has it.
    """

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
        return proxy_policy(self.extensions)

    @property
    def is_rfc_proxy(self) -> bool:
        """An RFC 3820 proxy: one that carries the ``proxyCertInfo`` extension."""
        return self.proxy_policy is not None

    @property
    def is_legacy_proxy(self) -> bool:
        """A Globus pre-RFC proxy: no extension, subject ends ``CN=proxy``."""
        return not self.is_rfc_proxy and legacy_proxy_kind(self.subject, self.issuer) is not None

    @property
    def is_proxy(self) -> bool:
        """A proxy by Globus' strict reading: RFC 3820, or a GT2 legacy one.

        XrdCl's looser test (any ``CN`` appended to the issuer's subject)
        would also count an ordinary end-entity certificate whose name
        happens to extend its CA's; Globus, and so gfal2, would not.
        """
        return self.is_rfc_proxy or self.is_legacy_proxy

    @property
    def is_limited(self) -> bool:
        """A limited proxy: the RFC 3820 limited policy, or GT2 ``CN=limited proxy``.

        The limited policy language is Globus' own OID, not one RFC 3820
        defines (that has only inherit-all and independent). Globus lets a
        limited proxy issue only further limited proxies, which
        :func:`~.proxy.sign_request` enforces, and services use it to refuse
        operations such as job submission.
        """
        return self.proxy_policy == LIMITED_PROXY_OID or (
            self.is_legacy_proxy and self.subject.cn == "limited proxy"
        )

    @property
    def is_self_signed(self) -> bool:
        """Subject equals issuer: a trust anchor, which is never sent to a peer.

        A name comparison only (RDN by RDN), not a signature check: deciding
        trust is the server's job, and this only decides what to leave out
        of a chain.
        """
        return self.subject.rdns == self.issuer.rdns

    @property
    def expired(self) -> bool:
        """Past ``notAfter`` by this host's clock, with no allowance for skew."""
        return self.not_after <= time.time()

    def remaining(self) -> float:
        """Seconds until ``notAfter``; negative once expired."""
        return self.not_after - time.time()

    def pem(self) -> bytes:
        """The certificate as one PEM ``CERTIFICATE`` block (RFC 7468)."""
        return pem("CERTIFICATE", self.der)

    def verify_signature(self, issuer_key: RSAPublicKey | bytes) -> bool:
        """Whether ``issuer_key`` (RSA, or any key as SPKI DER) signed this certificate."""
        return signed_by(self.tbs, self.signature_oid, self.signature, issuer_key)

    def __str__(self) -> str:
        """The subject in OpenSSL's ``/C=../O=../CN=..`` one-line form, as gfal2 prints it."""
        return str(self.subject)


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
    return certificates_in(data, parse_certificate)


@dataclass(frozen=True, slots=True)
class Credential:
    """A certificate chain and its private key: what a client authenticates with.

    The key is RSA (:class:`~xrdsec.rsa.RSAPrivateKey`) or a
    ``cryptography`` EC key; either signs a delegated proxy. ``chain`` is
    leaf first, as a proxy file stores it (proxy, then the certificates it
    was issued from); ``path`` is where it was read from, for messages.
    The key never appears in ``repr`` - credentials end up in logs.
    """

    chain: tuple[Certificate, ...]
    key: SigningKey
    path: str = ""

    @property
    def certificate(self) -> Certificate:
        """The leaf: the certificate presented in TLS and the issuer of any delegation."""
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
        """Whether any link has expired: a proxy cannot outlive what issued it.

        Globus checks every certificate in the path, so a live proxy under
        an expired user certificate is as dead as an expired proxy.
        """
        return any(link.expired for link in self.chain)

    def remaining(self) -> float:
        """Seconds the whole chain stays valid: the earliest ``notAfter`` of any link.

        The same bound caps a delegated proxy's lifetime
        (:func:`~.proxy.sign_request`): nothing issued from this chain can
        be valid for longer than the chain itself.
        """
        return min(link.remaining() for link in self.chain)

    def chain_pem(self) -> bytes:
        """The chain without any trust anchor, which servers refuse to receive."""
        links = [link for link in self.chain if not link.is_self_signed] or list(self.chain)
        return b"".join(link.pem() for link in links)

    def __repr__(self) -> str:
        """The subject only: the private key must never reach a log or a traceback."""
        return f"Credential(subject={str(self.certificate.subject)!r}, key=<redacted>)"


def load_credential(cert_path: str, key_path: str | None = None) -> Credential:
    """A proxy file (chain and key together) or a certificate/key pair.

    Read through xrdsec's
    :func:`~xrdsec.x509.read_credential_files` and
    :func:`~xrdsec.x509.credential_key`, so an EC key loads as well
    as an RSA one.
    """
    # ``key_path=None`` means a proxy file: the key is in the same PEM file
    # (after the first certificate, by Globus convention, though any order
    # is read) and the file is read once.
    cert_data, key_data = read_credential_files(cert_path, key_path)
    chain = load_certificates(cert_data)
    if not chain:
        raise DERError(f"no certificate in {cert_path}")
    return Credential(tuple(chain), _signing_key(credential_key(key_data)), cert_path)


def _signing_key(key: object) -> SigningKey:
    """``key`` as a :data:`~xrdsec.delegation.SigningKey`, or ``DERError``.

    Only RSA and EC keys can sign an X.509 proxy that grid middleware
    accepts; an Ed25519 or DSA key would load but be refused by every peer,
    so it is refused here with a message naming the key type instead.
    ``cryptography`` is imported here, not at module level, to keep
    ``import gfal2`` cheap for programs that never touch a credential.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from xrdsec.rsa import RSAPrivateKey

    if isinstance(key, RSAPrivateKey | ec.EllipticCurvePrivateKey):
        return key
    raise DERError(f"the private key is {type(key).__name__}, which cannot sign a proxy")


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def proxy_cert_info(policy: str = INHERIT_ALL_OID, path_length: int | None = None) -> bytes:
    """The RFC 3820 ``ProxyCertInfo`` value (section 3.8), ready for :func:`extension`.

    ``SEQUENCE { pCPathLenConstraint INTEGER OPTIONAL, proxyPolicy
    SEQUENCE { policyLanguage OID } }``: ``policy`` is inherit-all (the
    normal proxy), independent, or Globus' limited language; no policy
    *body* is ever sent, as Globus sends none for these languages.
    ``path_length=None`` leaves further delegation unbounded, which is what
    ``grid-proxy-init`` does. The encoding is xrdsec's
    (:func:`~xrdsec.delegation.proxy_cert_info_extension`, the one every
    proxy profile writes); this answers its value alone, for callers that
    build the extension themselves - the test PKI and the VOMS fixtures.
    """
    return parse_extension(proxy_cert_info_extension(policy, path_length)).value
