"""GSI exactly as globus speaks it, and the TLS contexts data channels need.

:class:`~xgfalclient.crypto.gsi.SecurityContext` differs from globus
(``globus_gssapi_gsi`` 14, GCT 6.2, as run by globus-gridftp-server 13) in
two places, both of which break a real server. :class:`GlobusContext`
fixes them:

* **The TLS 1.3 turn.** Under TLS 1.2 the server's ``Finished`` is the last
  handshake message and the client sends its delegation flag straight
  after it, which is what the core does. Under TLS 1.3 the *client* sends
  the last handshake message, so a globus acceptor answers the client's
  ``Finished`` with a one-byte application record, ``0x00``, and only then
  reads the flag. The initiator here waits for that byte before sending
  the flag, and the acceptor sends it. (Seen on the wire: ``335 ADAT=``
  carrying an 18-byte record for one byte of payload.)
* **The delegation reply.** globus answers the server's certificate
  request with the new proxy certificate *alone*
  (``globus_gsi_proxy_sign_req`` writes one DER certificate); the acceptor
  reads exactly one certificate with ``d2i_X509_bio`` and completes the
  chain from the TLS session's peer chain. Sending the signer's chain after
  it, as the core does, leaves those bytes in the server's TLS stream, where
  they are read as the start of the first command: ``USER :globus-mapping:``
  gets ``501 Syntax error``. Here the initiator sends the certificate only,
  and the acceptor completes the chain from the peer's TLS chain (or takes
  the whole chain when a core client sends one).

Data channels authenticated with ``DCAU A`` run the same mechanism over the
raw TCP stream, with the connecting side as initiator. Both ends present
the *user's* credential (the server its delegated proxy) and check that the
peer is the same identity, so both need TLS contexts that load a proxy
chain and accept one from the peer - which the cached client contexts in
:mod:`xgfalclient.creds` do not do. :func:`data_contexts` builds them.
"""

from __future__ import annotations

import os
import ssl
import threading

from ...crypto.gsi import (
    SecurityContext,
)
from ...crypto.x509 import Certificate

__all__ = ["GlobusContext", "TURN", "data_contexts", "same_identity", "ALLOW_PROXY"]

#: The byte a TLS 1.3 globus acceptor sends to hand the turn back.
TURN = b"\x00"

#: ``X509_V_FLAG_ALLOW_PROXY_CERTS``; the ``ssl`` constant only exists on 3.10+.
ALLOW_PROXY = int(getattr(ssl, "VERIFY_ALLOW_PROXY_CERTS", 0x40))


#: The core context already speaks GSI the Globus way (the TLS 1.3 turn,
#: certificate-only delegation, ``ssl_compatible`` for PROT P data channels);
#: the name is kept for this package's callers.
GlobusContext = SecurityContext


def same_identity(peer: Certificate | None, identity: tuple[tuple[str, str], ...]) -> bool:
    """Whether ``peer`` is ``identity`` or a proxy of it (DCAU A's check)."""
    if peer is None:
        return False
    rdns = peer.subject.rdns
    return len(rdns) >= len(identity) and rdns[: len(identity)] == identity


_CACHE: dict[tuple[object, ...], tuple[ssl.SSLContext, ssl.SSLContext]] = {}
_CACHE_LOCK = threading.Lock()


def data_contexts(
    cert: str, key: str, ca_path: str | None
) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """``(initiator, acceptor)`` TLS contexts for a GSI data channel.

    Both present the credential in ``cert``/``key`` (a proxy, typically)
    and verify the peer against the CA directory, proxies allowed. Host
    names mean nothing here - the peer is a person - so the check is
    :func:`same_identity` after the handshake. Session tickets are off:
    after the handshake the stream may carry clear data, and a ticket
    arriving there would be read as file content.
    """
    key_id = (cert, key, ca_path, os.stat(cert).st_mtime)
    with _CACHE_LOCK:
        found = _CACHE.get(key_id)
        if found is None:
            initiator = _context(ssl.PROTOCOL_TLS_CLIENT, cert, key, ca_path)
            acceptor = _context(ssl.PROTOCOL_TLS_SERVER, cert, key, ca_path)
            acceptor.num_tickets = 0
            found = _CACHE[key_id] = (initiator, acceptor)
        return found


def _context(protocol: int, cert: str, key: str, ca_path: str | None) -> ssl.SSLContext:
    context = ssl.SSLContext(protocol)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags |= ALLOW_PROXY
    context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    if ca_path:
        context.load_verify_locations(capath=ca_path)
    context.load_cert_chain(cert, key)
    return context
