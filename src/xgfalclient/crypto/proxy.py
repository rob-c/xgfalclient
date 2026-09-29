"""Proxy delegation: turn a peer's certificate request into a signed proxy.

When a GridFTP server, an SRM endpoint or a gridsite delegation service
wants to act on the user's behalf, it generates a key pair and sends a
PKCS#10 certificate request. The client signs it with its own proxy key,
producing a new proxy one link further down the chain, and returns that
certificate followed by its own chain. The server now holds a credential
whose private key never crossed the wire.

The certificate made here is what ``globus_gsi_proxy_sign_req`` makes:

* subject = issuer subject + ``CN=<serial>`` (RFC 3820), or ``CN=proxy``
  under a legacy Globus proxy;
* serial = the first four bytes of SHA-1 of the new public key;
* a critical ``proxyCertInfo`` with the issuer's policy - a limited proxy
  can only beget limited proxies;
* a critical key usage of digitalSignature and keyEncipherment;
* a lifetime no longer than the issuer's.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .._compat import SLOTS
from .der import (
    TAG_SEQUENCE,
    DERError,
    bit_string,
    explicit,
    integer,
    oid,
    oid_string,
    parse_one,
    printable_string,
    sequence,
    set_of,
)
from .rsa import RSAPrivateKey, RSAPublicKey, public_key_from_bitstring
from .x509 import (
    INHERIT_ALL_OID,
    KEY_USAGE_OID,
    LIMITED_PROXY_OID,
    PROXY_CERT_INFO_OID,
    Credential,
    Name,
    _decode_name,
    build_certificate,
    encode_name,
    extension,
    key_usage,
    proxy_cert_info,
    proxy_serial,
    public_key_info,
    signature_algorithm,
)

__all__ = [
    "CertificateRequest",
    "parse_request",
    "make_request",
    "sign_request",
    "delegation_payload",
    "BACKDATE",
]

#: How far before "now" a delegated proxy is dated, for clock skew.
BACKDATE = 300

_DIGESTS = {
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}


@dataclass(frozen=True, **SLOTS)
class CertificateRequest:
    """A decoded PKCS#10 request: who it names and the key to certify."""

    subject: Name
    public_key: RSAPublicKey
    spki: bytes
    info: bytes
    signature: bytes
    digest: str

    def verify(self) -> bool:
        """Proof of possession: the request is signed by the key it carries."""
        return self.public_key.verify(self.info, self.signature, digest=self.digest)


def parse_request(der: bytes) -> CertificateRequest:
    """Decode a DER ``CertificationRequest``; ``DERError`` if it is not one."""
    top = parse_one(der).children()
    if len(top) != 3 or top[0].tag != TAG_SEQUENCE:
        raise DERError("not a PKCS#10 certificate request")
    info = top[0].children()
    if len(info) < 3:
        raise DERError("certificate request info is incomplete")
    spki = info[2]
    parts = spki.children()
    algorithm = oid_string(top[1].children()[0])
    digest = _DIGESTS.get(algorithm)
    if digest is None:
        raise DERError(f"unsupported request signature algorithm {algorithm}")
    return CertificateRequest(
        subject=_decode_name(info[1]),
        public_key=public_key_from_bitstring(parts[1]),
        spki=spki.encoded,
        info=top[0].encoded,
        signature=top[2].value[1:],
        digest=digest,
    )


def make_request(
    key: RSAPrivateKey, rdns: tuple[tuple[str, str], ...] = (("CN", "proxy"),)
) -> bytes:
    """A signed PKCS#10 request for ``key`` - what a delegation *target* sends."""
    info = sequence(
        integer(0),
        encode_name(rdns),
        public_key_info(key.public),
        explicit(0, b""),
    )
    return sequence(
        info, signature_algorithm("sha256"), bit_string(key.sign(info, digest="sha256"))
    )


def _proxy_subject(issuer: Name, common_name: str) -> bytes:
    rdns = parse_one(issuer.encoded()).children()
    extra = set_of(sequence(oid("2.5.4.3"), printable_string(common_name)))
    return sequence(*(rdn.encoded for rdn in rdns), extra)


def sign_request(
    request: bytes | CertificateRequest,
    credential: Credential,
    *,
    lifetime: float | None = None,
    limited: bool | None = None,
    digest: str = "sha256",
    now: float | None = None,
) -> bytes:
    """Sign ``request`` as a proxy of ``credential``; returns the DER certificate."""
    parsed = parse_request(request) if isinstance(request, bytes) else request
    if not parsed.verify():
        raise DERError("the certificate request's signature does not verify")
    issuer = credential.certificate
    moment = time.time() if now is None else now
    expires = min(link.not_after for link in credential.chain)
    if lifetime is not None:
        expires = min(expires, moment + lifetime)
    is_limited = issuer.is_limited if limited is None else (limited or issuer.is_limited)
    serial = proxy_serial(parsed.spki)
    extensions = [extension(KEY_USAGE_OID, key_usage(0, 2), critical=True)]
    if issuer.is_legacy_proxy:
        subject = _proxy_subject(issuer.subject, "limited proxy" if is_limited else "proxy")
    else:
        policy = LIMITED_PROXY_OID if is_limited else INHERIT_ALL_OID
        subject = _proxy_subject(issuer.subject, str(serial))
        extensions.append(extension(PROXY_CERT_INFO_OID, proxy_cert_info(policy), critical=True))
    return build_certificate(
        subject=subject,
        issuer=issuer.subject.encoded(),
        public_key=parsed.spki,
        signer=credential.key,
        not_before=moment - BACKDATE,
        not_after=expires,
        serial=serial,
        extensions=extensions,
        digest=digest,
    )


def delegation_payload(certificate: bytes, credential: Credential) -> bytes:
    """The new proxy followed by the signer's chain, anchors left out.

    This is the shape gridsite delegation (``putProxy``) takes, as PEM. It
    is *not* what GSI delegation sends: Globus acceptors read the new
    certificate alone and take the chain from the TLS handshake.
    """
    links = [link.der for link in credential.chain if not link.is_self_signed]
    return certificate + b"".join(links)
