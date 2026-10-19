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

Since 0.4.0 that policy is :mod:`xrdsec.proxies`' ``"globus"`` profile -
it moved there from this module, so every client that delegates to a
GridFTP, SRM or gridsite peer issues the proxy Globus would have made, and
not XrdCrypto's (the ``"xrootd"`` profile, which takes the subject and the
serial from the request and copies the signer's extensions). Reading the
request is :func:`xrdsec.delegation.parse_proxy_request`; signing one the
Globus way is :func:`xrdsec.delegation.sign_globus_request` and making one,
as a delegation *target* does, :func:`xrdsec.delegation.make_proxy_request`
(here :func:`make_request`) - both moved there from this module in 0.4.0 with
GSI itself (:mod:`xrdsec.gsi.gss`). What stays here is the interface the
gridsite code was written against - :class:`~xgfalclient.crypto.x509.Credential`
in, DER out, :class:`DERError` for every refusal - and what only a gridsite
client needs (:func:`delegation_payload`).
"""

from __future__ import annotations

from xrdsec.delegation import DelegationError, parse_proxy_request, sign_globus_request
from xrdsec.delegation import ProxyRequest as CertificateRequest
from xrdsec.delegation import make_proxy_request as make_request
from xrdsec.der import DERError
from xrdsec.proxies import NOT_BEFORE_SKEW

from .x509 import Credential

__all__ = [
    "BACKDATE",
    "CertificateRequest",
    "delegation_payload",
    "make_request",
    "parse_request",
    "sign_request",
]

#: How far before "now" a delegated proxy is dated, for clock skew: five
#: minutes, Globus' own allowance, so a peer whose clock runs behind ours
#: does not reject the proxy as not yet valid (:data:`xrdsec.proxies.NOT_BEFORE_SKEW`).
BACKDATE = NOT_BEFORE_SKEW


def parse_request(der: bytes) -> CertificateRequest:
    """Decode a DER ``CertificationRequest``; ``DERError`` if it is not one.

    xrdsec's parser (:func:`~xrdsec.delegation.parse_proxy_request`),
    so a request for any key type - RSA, EC - is read, and its proof of
    possession (:meth:`CertificateRequest.verify`) checks whatever algorithm
    it is signed with.
    """
    return parse_proxy_request(der)


def sign_request(
    request: bytes | CertificateRequest,
    credential: Credential,
    *,
    lifetime: float | None = None,
    limited: bool | None = None,
    digest: str = "sha256",
    now: float | None = None,
) -> bytes:
    """Sign ``request`` as a proxy of ``credential``; returns the DER certificate.

    The rules are Globus' ``globus_gsi_proxy_sign_req``, as
    :func:`xrdsec.proxies.issue_proxy` applies them under the ``"globus"``
    profile:

    * ``lifetime`` (seconds) can only shorten the proxy; it never outlives
      any link of ``credential``'s chain;
    * ``limited=None`` inherits the issuer's limitation; ``False`` cannot
      lift it (a limited proxy only begets limited ones), ``True`` imposes it;
    * a legacy (GT2) issuer gets a legacy child named ``CN=proxy`` or
      ``CN=limited proxy`` and no ``proxyCertInfo``, as Globus keeps a
      chain in one proxy style; anything else gets an RFC 3820 child.

    ``now`` pins the clock, for tests. The request's own signature is
    checked first (``DERError`` if it fails): signing a key whose holder
    has not proved possession would hand a credential to whoever forged
    the request. ``digest`` is the signature's hash; SHA-1 is refused.
    Every refusal xrdsec makes (an expired chain, a key that is not the
    credential's, a path length that forbids delegating) is a ``DERError``
    too, which is what the gridsite caller catches.
    """
    try:
        return sign_globus_request(
            request,
            [link.der for link in credential.chain],
            credential.key,
            lifetime=lifetime,
            limited=limited,
            digest=digest,
            now=now,
        )
    except DelegationError as exc:
        raise DERError(str(exc)) from exc


def delegation_payload(certificate: bytes, credential: Credential) -> bytes:
    """The new proxy followed by the signer's chain, anchors left out.

    This is the shape gridsite delegation (``putProxy``) takes, as PEM. It
    is *not* what GSI delegation sends: Globus acceptors read the new
    certificate alone and take the chain from the TLS handshake.
    """
    # A self-signed root is left out: the receiver must find it in its own
    # trust store, and servers refuse to receive one (as for
    # Credential.chain_pem).
    links = [link.der for link in credential.chain if not link.is_self_signed]
    return certificate + b"".join(links)
