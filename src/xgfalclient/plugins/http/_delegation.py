"""Gridsite proxy delegation, for a third-party copy that must use X.509.

When neither side of a copy can be given a token, the active endpoint needs
a credential of its own to present to the other: the user's proxy,
delegated. The endpoint says where it wants it in an ``X-Delegate-To``
header on its ``COPY`` response, and the client speaks the gridsite
delegation SOAP service there, as davix does:

1. ``getNewProxyReq`` (delegation-2) - the service generates a key pair and
   answers with a PKCS#10 request and a delegation id;
2. the client signs that request with its proxy key
   (:func:`~xgfalclient.crypto.proxy.sign_request`), making a proxy one link
   further down the chain;
3. ``putProxy`` hands back that certificate and the chain above it.

A service that only speaks delegation-1 gets ``getProxyReq`` with an id
chosen here instead. The private key never leaves the service.
"""

from __future__ import annotations

import errno
import hashlib
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape

from ...crypto.der import DERError
from ...crypto.proxy import sign_request
from ...crypto.rsa import pem_blocks
from ...crypto.x509 import Credential, load_credential, pem
from ...errors import GError
from ._client import status_text
from ._dav import parse_xml

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["delegate", "NS_V1", "NS_V2"]

NS_V1 = "http://www.gridsite.org/namespaces/delegation-1"
NS_V2 = "http://www.gridsite.org/namespaces/delegation-2"
#: The lifetime asked of a delegated proxy (capped by the proxy it comes from).
LIFETIME = 12 * 3600


def _envelope(namespace: str, body: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
        f'xmlns:deleg="{namespace}"><SOAP-ENV:Body>{body}</SOAP-ENV:Body></SOAP-ENV:Envelope>'
    ).encode()


def _find(root: ET.Element, name: str) -> str | None:
    for element in root.iter():
        if element.tag.rpartition("}")[2] == name:
            return (element.text or "").strip()
    return None


class _Soap:
    def __init__(self, plugin: HTTPPlugin, endpoint: str, cred_url: str) -> None:
        self.plugin = plugin
        self.endpoint = endpoint
        self.cred_url = cred_url

    def call(self, namespace: str, body: str) -> ET.Element:
        response = self.plugin._request(
            "POST",
            self.endpoint,
            body=_envelope(namespace, body),
            headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '""'},
            cred_url=self.cred_url,
            x509_only=True,
        )
        payload = response.body()
        root = parse_xml(payload, "delegation response") if payload.strip() else None
        fault = _find(root, "faultstring") if root is not None else None
        if response.status != 200 or root is None or fault is not None:
            detail = fault or status_text(response.status, response.reason)
            raise GError(f"Delegation to {self.endpoint} failed: {detail}", errno.EACCES)
        return root


def _request_der(text: str) -> bytes:
    for label, der in pem_blocks(text):
        if "REQUEST" in label:
            return der
    raise GError("The delegation service sent no certificate request", errno.EPROTO)


def _sign(credential: Credential, request_pem: str) -> str:
    try:
        certificate = sign_request(_request_der(request_pem), credential, lifetime=LIFETIME)
    except DERError as exc:
        raise GError(f"Could not sign the delegation request: {exc}", errno.EPROTO) from exc
    return (pem("CERTIFICATE", certificate) + credential.chain_pem()).decode("ascii")


def delegate(plugin: HTTPPlugin, endpoint: str, cred_url: str) -> str:
    """Delegate the proxy for ``cred_url`` to the service at ``endpoint``; the id."""
    found = plugin.context.x509(cred_url)
    if found is None:
        raise GError("Delegation needs an X.509 proxy, and there is none", errno.EACCES)
    try:
        credential = load_credential(found.cert, found.key)
    except (OSError, DERError, ValueError) as exc:
        raise GError(f"Could not load the user credentials: {exc}", errno.EACCES) from exc
    soap = _Soap(plugin, endpoint, cred_url)
    try:
        reply = soap.call(NS_V2, "<deleg:getNewProxyReq/>")
        request_pem = _find(reply, "proxyRequest")
        delegation_id = _find(reply, "delegationID")
        if not request_pem or not delegation_id:
            raise GError("getNewProxyReq answered without a request", errno.EPROTO)
        namespace = NS_V2
    except GError:
        # A delegation-1 service: the client names the delegation itself.
        delegation_id = hashlib.sha1(credential.identity.encode()).hexdigest()[:16]
        reply = soap.call(
            NS_V1,
            f"<deleg:getProxyReq><delegationID>{delegation_id}</delegationID></deleg:getProxyReq>",
        )
        request_pem = _find(reply, "getProxyReqReturn")
        if not request_pem:
            raise GError(
                f"Delegation to {endpoint} failed: no certificate request", errno.EPROTO
            ) from None
        namespace = NS_V1
    proxy = _sign(credential, request_pem)
    soap.call(
        namespace,
        f"<deleg:putProxy><delegationID>{escape(delegation_id)}</delegationID>"
        f"<proxy>{escape(proxy)}</proxy></deleg:putProxy>",
    )
    return delegation_id
