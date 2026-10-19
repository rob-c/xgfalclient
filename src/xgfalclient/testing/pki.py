"""The throwaway grid PKI, as xgfalclient's test suite sees it.

Since 0.4.0 the PKI itself - minting, the ``X509_CERT_DIR`` layout with
OpenSSL subject hashes and IGTF signing policies, proxies of every kind,
CRLs, TLS contexts - lives once, in :mod:`xrdsec.testing.pki`, shared
with xrdsec's, xrdclient's and xrdarc's suites. This module is the thin layer that
keeps every name it used to define, with the types xgfalclient's tests were
written against:

* :class:`PKI` presents certificates as :class:`xgfalclient.crypto.x509.Certificate`,
  keys as :class:`xrdsec.rsa.RSAPrivateKey` (the clients' RSA view,
  with ``.public`` and ``.sign``), and loads credentials with
  :func:`xgfalclient.crypto.x509.load_credential`, so it checks that a file
  is one *this* client accepts;
* :func:`test_key` returns that same RSA view, cached so that
  ``test_key(n) is test_key(n)``; :func:`xrdsec.testing.pki.test_key` is
  the ``cryptography`` key behind it;
* the subjects stay ``/DC=org/DC=xgfal/...``, which tests pin.

    >>> pki = create_pki(tmp_path)
    >>> server = pki.server_context()          # host cert, trusts the CA
    >>> os.environ.update(pki.environment())   # X509_USER_PROXY, X509_CERT_DIR

The keys are the frozen ones of :mod:`xrdsec.testing._keys` (re-exported
by :mod:`._keys` under its old name), so material minted here and there is
interchangeable slot for slot.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.asymmetric import rsa
from xrdsec.rsa import RSAPrivateKey
from xrdsec.testing.pki import ALLOW_PROXY_CERTS as ALLOW_PROXY_CERTS
from xrdsec.testing.pki import DAY as DAY
from xrdsec.testing.pki import DEFAULT_HOSTS, BasePKI, PrivateKey, Rdns
from xrdsec.testing.pki import KEYS as KEYS
from xrdsec.testing.pki import subject_hash as subject_hash
from xrdsec.testing.pki import test_key as _library_key

from ..crypto.x509 import Certificate, Credential, load_credential, parse_certificate

__all__ = ["CA_SUBJECT", "PKI", "USER_SUBJECT", "create_pki", "subject_hash", "test_key"]

#: The CA's subject, which tests (and the signing-policy text) pin.
CA_SUBJECT: Rdns = (("DC", "org"), ("DC", "xgfal"), ("CN", "xgfal Test CA"))
#: The user's subject: the identity a server sees.
USER_SUBJECT: Rdns = (("DC", "org"), ("DC", "xgfal"), ("OU", "People"), ("CN", "Test User"))

# The RSA view of each slot, made once: tests compare keys by identity as
# well as by value, and the view's CRT values are worth computing only once.
_VIEWS: dict[int, RSAPrivateKey] = {}


def test_key(slot: int) -> RSAPrivateKey:
    """Frozen key number ``slot`` (0-7) as the clients' RSA view, made once per process.

    ``IndexError`` past the last slot. Code that wants a ``cryptography``
    key should call :func:`xrdsec.testing.pki.test_key` instead.
    """
    found = _VIEWS.get(slot)
    if found is None:
        found = _VIEWS[slot] = RSAPrivateKey.from_cryptography(_library_key(slot))
    return found


# A helper, not a test: stop pytest collecting it from test modules that import it.
# Set through the function's ``__dict__`` (typed ``dict[str, Any]``), as
# xrdsec.testing.pki does for its own ``test_key``.
test_key.__dict__["__test__"] = False


class PKI(BasePKI[Certificate, RSAPrivateKey, Credential]):
    """One throwaway PKI on disk, in xgfalclient's types (see :class:`xrdsec.testing.pki.BasePKI`).

    Attributes are the base class's: ``directory``, ``ca``/``host``/``user``
    (:class:`~xgfalclient.crypto.x509.Certificate`), ``ca_key``/``host_key``/
    ``user_key`` (:class:`~xrdsec.rsa.RSAPrivateKey`), the
    ``*_path`` files, ``ca_dir`` and ``ca_file``; and methods ``proxy``,
    ``credential``, ``server_context``, ``client_context``, ``environment``,
    ``crl`` and ``install_crl``.
    """

    CA_SUBJECT = CA_SUBJECT
    USER_SUBJECT = USER_SUBJECT
    HOST_PREFIX = (("DC", "org"), ("DC", "xgfal"))

    def _certificate_view(self, der: bytes) -> Certificate:
        """xgfalclient's certificate view, with Globus's reading of what a proxy is."""
        return parse_certificate(der)

    def _key_view(self, key: PrivateKey) -> RSAPrivateKey:
        """The RSA view of the frozen key (the PKI only ever mints with RSA test keys)."""
        # Every key the PKI mints with is a frozen RSA test key, so the EC half
        # of the union never arrives here; the cast says so to the type checker.
        return RSAPrivateKey.from_cryptography(cast("rsa.RSAPrivateKey", key))

    def _load_credential(self, cert_path: str, key_path: str | None) -> Credential:
        """Through :func:`xgfalclient.crypto.x509.load_credential`, as gfal2's code loads it."""
        return load_credential(cert_path, key_path)


def create_pki(
    directory: Path | str,
    *,
    hosts: Sequence[str] = DEFAULT_HOSTS,
    host_cn: str = "host/localhost",
    lifetime: float = 7 * DAY,
    key_slots: tuple[int, int, int] = (0, 1, 2),
) -> PKI:
    """Mint a CA, a host certificate for ``hosts`` and a user certificate.

    ``key_slots`` picks the frozen keys for the CA, host and user; a second,
    distinct PKI needs different ones, or its CA would be the same CA. Every
    certificate is valid from an hour ago (clock skew) for ``lifetime``; the
    host one has a ``subjectAltName`` for ``hosts`` and ``CN=<host_cn>``
    (globus's ``host/<name>`` form by default). ``directory`` is created if
    missing. See :meth:`xrdsec.testing.pki.BasePKI.create`.
    """
    return PKI.create(
        directory, hosts=hosts, host_cn=host_cn, lifetime=lifetime, key_slots=key_slots
    )
