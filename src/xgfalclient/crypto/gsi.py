"""Compatibility import; the shared implementation is :mod:`xrdsec.gsi.gss`.

Globus GSI - TLS carried in tokens, the TLS 1.3 turn, the delegation byte and
GSI's host-name check - moved to xrdsec in 0.4.0, so the GSS mechanism the
GridFTP, LFC, dcap and SRM plugins (and their test servers) use exists once,
beside XRootD's XrdSecgsi. This module replaces itself in ``sys.modules`` with
the xrdsec module rather than re-exporting its names one by one: a test that
monkeypatches ``xgfalclient.crypto.gsi.X`` must patch the very object the code
calls, and ``except GSIError`` must catch what xrdsec raises whichever name it
was imported under. The re-exported ``__all__`` is for type checkers and
readers; at run time the alias is what callers get. New code imports
:mod:`xrdsec.gsi.gss` directly.

Since the move, a :class:`~xrdsec.gsi.gss.SecurityContext` delegates with any
credential that has a ``chain`` and a ``key`` (this package's
:class:`~xgfalclient.crypto.x509.Credential` included), certificates come
back as :class:`xrdsec.x509.CertificateData`, and
:meth:`~xrdsec.gsi.gss.DelegatedCredential.credential` returns an
:class:`xrdsec.x509.ProxyCredential`.
"""

import sys

from xrdsec.gsi import gss as _shared
from xrdsec.gsi.gss import (
    DELEGATE,
    NO_DELEGATION,
    TURN,
    DelegatedCredential,
    DelegatingCredential,
    GSIError,
    SecurityContext,
    check_host,
    dns_names,
    peer_chain_der,
)

__all__ = [
    "DELEGATE",
    "NO_DELEGATION",
    "TURN",
    "DelegatedCredential",
    "DelegatingCredential",
    "GSIError",
    "SecurityContext",
    "check_host",
    "dns_names",
    "peer_chain_der",
]

sys.modules[__name__] = _shared
