"""An in-process WebDAV / HTTP-TPC / S3 / tape-REST server, for tests.

One threaded HTTP(S) server speaking what grid storage speaks over HTTP,
backed by a real directory so that large files are cheap::

    with WebDAVServer(tmp_path) as server:
        ctx.stat(server.url("/data/f"))            # dav://127.0.0.1:<port>/data/f
        server.requests[-1].method                  # "PROPFIND"

Since 0.4.0 the server is xrdhttp's shared fake storage element,
:class:`xrdhttp.testing.StorageServer`, in its davix style - the same one
xrdclient's suite runs against - so everything it answers is documented
there: WebDAV with ranges and RFC 3230 digests, HTTP third-party ``COPY``
with performance markers, the WLCG tape REST API (:class:`Tape`),
macaroon and OAuth token issuance, CDMI QoS, the S3/GCS (:class:`S3`) and
Swift (:class:`Swift`) dialects, bearer/Basic/certificate authorisation,
and fault injection (:meth:`~xrdhttp.testing.StorageServer.fault`). Every
request is recorded in ``requests`` (:class:`Request`: ``target`` is the
wire form, ``path`` the decoded path).

:class:`WebDAVServer` is the thin preset that keeps this package's names
- the directory store under :attr:`~WebDAVServer.root`, :meth:`~WebDAVServer.url`
with a ``dav``/``davs`` scheme, :meth:`~WebDAVServer.local` - and adds the
one dialect that needs X.509: gridsite proxy delegation (versions 1 and
2), served at ``/gridsite-delegation`` when a ``COPY`` asks for it
(``delegation = True``). The delegation exchange is real: the client must
sign the server's certificate request with its proxy, so tests catch a
client that delegates the wrong key or a broken chain.
"""

from __future__ import annotations

import base64
import os
import posixpath
import ssl
import urllib.parse
import uuid
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from xrdhttp.testing import S3 as S3
from xrdhttp.testing import DirectoryStore, Reply, StorageServer
from xrdhttp.testing import Fault as Fault
from xrdhttp.testing import Request as Request
from xrdhttp.testing import Swift as Swift
from xrdhttp.testing import Tape as Tape

from ..crypto.proxy import make_request, parse_request
from ..crypto.x509 import load_certificates
from .pki import test_key

__all__ = ["S3", "Fault", "Request", "Swift", "Tape", "WebDAVServer"]

#: A SOAP 1.1 fault, as the gridsite delegation service reports one.
_SOAP_FAULT = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV='
    '"http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><SOAP-ENV:Fault>'
    "<faultstring>{}</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>"
)


class WebDAVServer(StorageServer):
    """A threaded HTTP(S) storage element rooted at a local directory.

    The listener is bound when its address is first asked for, so
    :meth:`url` works before :meth:`start`. Every public attribute is a
    switch or a record: set switches before the client acts, read records
    after.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        tls: ssl.SSLContext | None = None,
        host: str = "127.0.0.1",
    ) -> None:
        """Serve ``root`` (created if missing) on ``host``; ``tls`` makes it HTTPS.

        For client-certificate (and grid proxy) authentication pass a context
        that requests a certificate, such as the test PKI's
        ``server_context()``.
        """
        self._directory = DirectoryStore(root)
        super().__init__(self._directory, tls=tls, host=host, style="davix", name="xgfal-webdav")
        #: ``2`` speaks delegation-2 (and 1); ``1`` only delegation-1.
        self.delegation_version = 2
        # Delegation id -> the public key of the request we issued for it.
        self._delegation_keys: dict[str, Any] = {}
        self.delegation_service = self._gridsite

    @property
    def root(self) -> Path:
        """The directory served as ``/``."""
        return self._directory.root

    def url(self, path: str = "/", scheme: str | None = None) -> str:
        """A URL for ``path`` with ``scheme`` (default ``dav``/``davs``)."""
        chosen = scheme or ("davs" if self.tls is not None else "dav")
        return f"{chosen}://{self.host}:{self.port}{path}"

    def local(self, path: str) -> Path:
        """The file behind a server path (decoded, query dropped, as a request names it)."""
        clean = posixpath.normpath("/" + urllib.parse.unquote(path.split("?")[0]).lstrip("/"))
        return self.root / clean.lstrip("/")

    # -- gridsite delegation -----------------------------------------------------------------

    def _gridsite(self, server: StorageServer, body: bytes) -> Reply:
        """The gridsite delegation service (SOAP 1.1): new/get proxy request, put proxy.

        delegation-2 clients start with ``getNewProxyReq`` (the server picks
        the id); delegation-1 clients use ``getProxyReq`` with their own id.
        In both the client then signs the returned request and sends the
        chain back with ``putProxy``. Operations are told apart by substring
        rather than by parsing the envelope, which keeps the fake indifferent
        to how a client prefixes its SOAP namespaces. A delegation-1 server
        answers ``getNewProxyReq`` as an unknown operation, so the client
        must fall back.
        """
        text = body.decode()
        if "getNewProxyReq" in text and self.delegation_version >= 2:
            delegation_id = uuid.uuid4().hex[:16]
            return _soap(
                "getNewProxyReqResponse",
                f"<getNewProxyReqReturn><proxyRequest>{self._new_request(delegation_id)}"
                f"</proxyRequest><delegationID>{delegation_id}</delegationID>"
                "</getNewProxyReqReturn>",
            )
        if "getProxyReq" in text:
            delegation_id = _element(text, "delegationID")
            inner = f"<getProxyReqReturn>{self._new_request(delegation_id)}</getProxyReqReturn>"
            return _soap("getProxyReqResponse", inner)
        if "putProxy" in text:
            return self._put_proxy(server, _element(text, "delegationID"), _element(text, "proxy"))
        return 500, _SOAP_FAULT.format("unknown operation").encode(), {}

    def _put_proxy(self, server: StorageServer, delegation_id: str, proxy: str) -> Reply:
        """Check a delegated chain against the request issued for ``delegation_id``, keep it.

        The PEM arrives XML-escaped inside ``<proxy>``; ``&amp;`` is
        unescaped last so an escaped ``&lt;`` in the text is not turned into
        ``<`` twice. The delegated proxy must carry the key of *our* request:
        anything else means the client signed a stale or foreign request.
        """
        chain = load_certificates(
            proxy.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        )
        expected = self._delegation_keys.get(delegation_id)
        if not chain or expected is None or chain[0].public_key != expected:
            fault = _SOAP_FAULT.format("the proxy does not match the request")
            return 500, fault.encode(), {}
        server.accept_delegation(delegation_id, chain)
        return _soap("putProxyResponse", "")

    def _new_request(self, delegation_id: str) -> str:
        """A PEM certificate request for ``delegation_id``, XML-escaped for the SOAP reply.

        The key is one of :mod:`xgfalclient.testing.pki`'s pre-generated
        test keys (RSA generation would dominate the test time); its public
        half is remembered so ``putProxy`` can be checked against it.
        """
        request = make_request(test_key(4))
        self._delegation_keys[delegation_id] = parse_request(request).public_key
        der = base64.encodebytes(request).decode("ascii")
        return escape(
            f"-----BEGIN CERTIFICATE REQUEST-----\n{der}-----END CERTIFICATE REQUEST-----\n"
        )


def _element(text: str, name: str) -> str:
    """The text of the first ``<name>`` element in a SOAP body."""
    return text.split(f"<{name}>")[1].split(f"</{name}>")[0]


def _soap(element: str, inner: str) -> Reply:
    """A SOAP 1.1 envelope whose body is ``<ns:element>inner</ns:element>``."""
    document = (
        '<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope '
        'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:ns="http://www.gridsite.org/namespaces/delegation-2"><SOAP-ENV:Body>'
        f"<ns:{element}>{inner}</ns:{element}></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )
    return 200, document.encode(), {"Content-Type": "text/xml"}
