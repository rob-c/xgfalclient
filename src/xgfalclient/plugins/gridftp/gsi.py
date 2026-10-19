"""GSI exactly as globus speaks it, and the TLS contexts data channels need.

Two details of globus's GSI (``globus_gssapi_gsi`` 14, GCT 6.2, as run by
globus-gridftp-server 13) each break a real server when got wrong. They
were first fixed here, in a GridFTP-only subclass; since then
:class:`~xrdsec.gsi.gss.SecurityContext` (xgfalclient's ``crypto.gsi`` until
0.4.0) itself speaks GSI this way, so :data:`GlobusContext` is now just that
class under its old name. What the two details are, for whoever touches the
core:

* **The TLS 1.3 turn.** Under TLS 1.2 the server's ``Finished`` is the last
  handshake message and the client sends its delegation flag straight
  after it. Under TLS 1.3 the *client* sends the last handshake message, so
  a globus acceptor answers the client's ``Finished`` with a one-byte
  application record, ``0x00`` (:data:`TURN`), and only then reads the
  flag. The initiator must wait for that byte before sending the flag, and
  an acceptor must send it. (Seen on the wire: ``335 ADAT=``
  carrying an 18-byte record for one byte of payload.)
* **The delegation reply.** globus answers the server's certificate
  request with the new proxy certificate *alone*
  (``globus_gsi_proxy_sign_req`` writes one DER certificate); the acceptor
  reads exactly one certificate with ``d2i_X509_bio`` and completes the
  chain from the TLS session's peer chain. Sending the signer's chain after
  it leaves those bytes in the server's TLS stream, where they are read as
  the start of the first command: ``USER :globus-mapping:`` gets ``501
  Syntax error``. So the initiator sends the certificate only, and the
  acceptor completes the chain from the peer's TLS chain (or takes a whole
  chain when a client sends one).

Data channels authenticated with ``DCAU A`` run the same mechanism over the
raw TCP stream, with the connecting side as initiator. Both ends present
the *user's* credential (the server its delegated proxy) and check that the
peer is the same identity (:func:`same_identity`), so both need TLS contexts
that load a proxy chain and accept one from the peer - which the cached
client contexts in :mod:`xgfalclient.creds` do not do.
:func:`~xrdsec.gsi.gss.data_contexts` builds that pair; it lived here until
0.4.0 and is re-exported under its old name.
"""

from __future__ import annotations

import ssl

# TURN (the byte a TLS 1.3 Globus acceptor sends to hand the turn back) is
# re-exported for this package's callers; xrdsec's context is what sends it.
from xrdsec.gsi.gss import TURN as TURN
from xrdsec.gsi.gss import SecurityContext

# The DCAU data-channel context pair, built (and cached) by xrdsec since 0.4.0.
from xrdsec.gsi.gss import data_contexts as data_contexts
from xrdsec.x509 import CertificateData

from ...crypto.x509 import Certificate

__all__ = ["ALLOW_PROXY", "TURN", "GlobusContext", "data_contexts", "same_identity"]

#: ``X509_V_FLAG_ALLOW_PROXY_CERTS``, as a plain ``int`` (kept for callers).
#: Without it OpenSSL rejects RFC 3820 proxy certificates in the peer chain.
ALLOW_PROXY = int(ssl.VERIFY_ALLOW_PROXY_CERTS)


#: The core context already speaks GSI the Globus way (the TLS 1.3 turn,
#: certificate-only delegation, ``ssl_compatible`` for PROT P data channels);
#: the name is kept for this package's callers.
GlobusContext = SecurityContext


def same_identity(
    peer: CertificateData | Certificate | None, identity: tuple[tuple[str, str], ...]
) -> bool:
    """Whether ``peer`` is ``identity`` or a proxy of it (DCAU A's check).

    A proxy's subject is its issuer's subject plus one or more ``CN``
    RDNs (RFC 3820), so "is a proxy of" is a prefix match on the RDN
    sequence. This is a name check only; the TLS handshake has already
    verified the chain against the CA directory. ``peer`` is what the GSI
    context reports (xrdsec's view) or a certificate of this package's own;
    ``None`` (no certificate presented) is never the user.
    """
    if peer is None:
        return False
    rdns = peer.subject.rdns
    return len(rdns) >= len(identity) and rdns[: len(identity)] == identity
