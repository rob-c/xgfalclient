"""A throwaway grid PKI, minted in process: CA, host, user, and proxies.

Every certificate is made at run time with today's validity, so nothing in
the repository expires. The CA directory is laid out the way
``X509_CERT_DIR`` is - ``<subject hash>.0`` files - with the hash computed
exactly as OpenSSL computes it, so a context built with ``capath=`` trusts
it just as it would ``/etc/grid-security/certificates``.

    >>> pki = create_pki(tmp_path)
    >>> server = pki.server_context()          # host cert, trusts the CA
    >>> os.environ.update(pki.environment())   # X509_USER_PROXY, X509_CERT_DIR
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..crypto.der import (
    TAG_SEQUENCE,
    boolean,
    oid,
    parse_one,
    sequence,
    set_of,
    tlv,
    utf8_string,
)
from ..crypto.proxy import make_request, sign_request
from ..crypto.rsa import RSAPrivateKey, load_private_key, private_key_pem
from ..crypto.x509 import (
    BASIC_CONSTRAINTS_OID,
    KEY_USAGE_OID,
    SUBJECT_ALT_NAME_OID,
    Certificate,
    Credential,
    build_certificate,
    encode_name,
    extension,
    key_usage,
    parse_certificate,
    public_key_info,
)
from ._keys import KEYS

__all__ = ["PKI", "create_pki", "test_key", "subject_hash", "CA_SUBJECT", "USER_SUBJECT"]

CA_SUBJECT = (("DC", "org"), ("DC", "xgfal"), ("CN", "xgfal Test CA"))
USER_SUBJECT = (("DC", "org"), ("DC", "xgfal"), ("OU", "People"), ("CN", "Test User"))
DAY = 86400.0
#: OpenSSL's ``X509_V_FLAG_ALLOW_PROXY_CERTS``, for interpreters with no name for it.
ALLOW_PROXY_CERTS = 0x40

_KEY_CACHE: dict[int, RSAPrivateKey] = {}


def test_key(slot: int) -> RSAPrivateKey:
    """Frozen key number ``slot`` (0-7), parsed once."""
    found = _KEY_CACHE.get(slot)
    if found is None:
        found = _KEY_CACHE[slot] = load_private_key(KEYS[slot])
    return found


# A helper, not a test: stop pytest collecting it from test modules that import it.
test_key.__test__ = False  # type: ignore[attr-defined]


def _canonical(value: bytes) -> bytes:
    text = value.decode("utf-8", "replace").strip()
    text = " ".join(text.split())
    return text.lower().encode("utf-8")


def subject_hash(name_der: bytes) -> str:
    """OpenSSL's ``X509_NAME_hash``: the file name in a CA directory."""
    canonical = []
    for rdn in parse_one(name_der).children():
        attributes = []
        for attribute in rdn.children():
            kind, value = attribute.children()
            attributes.append(sequence(kind.encoded, utf8_string(_canonical(value.value).decode())))
        canonical.append(set_of(*attributes))
    digest = hashlib.sha1(b"".join(canonical)).digest()
    return f"{int.from_bytes(digest[:4], 'little'):08x}"


def _san(hosts: tuple[str, ...]) -> bytes:
    names = []
    for host in hosts:
        try:
            names.append(tlv(0x87, ipaddress.ip_address(host).packed))
        except ValueError:
            names.append(tlv(0x82, host.encode("ascii")))
    return sequence(*names)


SUBJECT_KEY_ID_OID = "2.5.29.14"
AUTHORITY_KEY_ID_OID = "2.5.29.35"


def _key_id(key: RSAPrivateKey) -> bytes:
    """RFC 5280 method 1: SHA-1 of the subjectPublicKey bits."""
    spki = parse_one(public_key_info(key.public)).children()
    return hashlib.sha1(spki[1].value[1:]).digest()


def _key_ids(subject: RSAPrivateKey, issuer: RSAPrivateKey) -> list[bytes]:
    """Subject and authority key identifiers, which strict verifiers demand."""
    return [
        extension(SUBJECT_KEY_ID_OID, tlv(0x04, _key_id(subject))),
        extension(AUTHORITY_KEY_ID_OID, sequence(tlv(0x80, _key_id(issuer)))),
    ]


def _write(path: Path, data: bytes, mode: int = 0o644) -> Path:
    path.write_bytes(data)
    os.chmod(path, mode)
    return path


@dataclass
class PKI:
    """Files and objects for one throwaway grid PKI rooted at ``directory``."""

    directory: Path
    ca: Certificate
    ca_key: RSAPrivateKey
    host: Certificate
    host_key: RSAPrivateKey
    user: Certificate
    user_key: RSAPrivateKey
    proxy_path: Path = field(init=False)
    ca_dir: Path = field(init=False)
    ca_file: Path = field(init=False)
    host_cert_path: Path = field(init=False)
    host_key_path: Path = field(init=False)
    user_cert_path: Path = field(init=False)
    user_key_path: Path = field(init=False)

    def __post_init__(self) -> None:
        self.ca_dir = self.directory / "certificates"
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        ca_pem = self.ca.pem()
        self.ca_file = _write(self.directory / "ca.pem", ca_pem)
        name_hash = subject_hash(self.ca.subject.encoded())
        _write(self.ca_dir / f"{name_hash}.0", ca_pem)
        # Globus refuses a CA without an IGTF signing policy beside it.
        _write(self.ca_dir / f"{name_hash}.signing_policy", self.signing_policy())
        self.host_cert_path = _write(self.directory / "hostcert.pem", self.host.pem())
        self.host_key_path = _write(
            self.directory / "hostkey.pem", private_key_pem(self.host_key), 0o600
        )
        self.user_cert_path = _write(self.directory / "usercert.pem", self.user.pem())
        self.user_key_path = _write(
            self.directory / "userkey.pem", private_key_pem(self.user_key), 0o600
        )
        self.proxy_path = self.proxy()

    def signing_policy(self) -> bytes:
        """The CA's ``.signing_policy``: it may sign anything under its own DC prefix."""
        prefix = "".join(f"/{key}={value}" for key, value in self.ca.subject.rdns if key == "DC")
        return (
            f"access_id_CA X509 '{self.ca.subject}'\n"
            "pos_rights globus CA:sign\n"
            f"cond_subjects globus '\"{prefix}/*\"'\n"
        ).encode()

    # -- credentials -------------------------------------------------------------------

    @property
    def user_credential(self) -> Credential:
        return Credential((self.user, self.ca), self.user_key)

    def proxy(
        self,
        kind: str = "rfc",
        *,
        lifetime: float = 12 * 3600,
        path: Path | None = None,
        key_slot: int = 3,
        issuer: Credential | None = None,
    ) -> Path:
        """Write a proxy file (cert, key, chain); ``kind`` is rfc, limited or legacy."""
        signer = issuer or self.user_credential
        key = test_key(key_slot)
        if kind == "legacy":
            rdns = parse_one(signer.certificate.subject.encoded()).children()
            common = set_of(sequence(oid("2.5.4.3"), utf8_string("proxy")))
            der = build_certificate(
                subject=tlv(TAG_SEQUENCE, b"".join(r.encoded for r in rdns) + common),
                issuer=signer.certificate.subject.encoded(),
                public_key=public_key_info(key.public),
                signer=signer.key,
                not_before=time.time() - 300,
                not_after=min(signer.certificate.not_after, time.time() + lifetime),
            )
        else:
            der = sign_request(
                make_request(key), signer, lifetime=lifetime, limited=(kind == "limited")
            )
        certificate = parse_certificate(der)
        chain = [certificate, *signer.chain]
        body = certificate.pem() + private_key_pem(key)
        body += b"".join(link.pem() for link in chain[1:] if not link.is_self_signed)
        target = path or self.directory / f"x509up_{kind}"
        return _write(target, body, 0o600)

    def credential(self, path: Path | None = None) -> Credential:
        from ..crypto.x509 import load_credential

        return load_credential(str(path or self.proxy_path))

    # -- TLS contexts ------------------------------------------------------------------

    def server_context(self, *, require_client: bool = True) -> ssl.SSLContext:
        """A server context presenting the host certificate.

        With ``require_client`` the server asks for, and verifies, a client
        certificate, proxies included. Python 3.9's ``ssl`` has no name for
        OpenSSL's ``X509_V_FLAG_ALLOW_PROXY_CERTS``, but takes its value.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.host_cert_path), str(self.host_key_path))
        context.load_verify_locations(cafile=str(self.ca_file))
        context.verify_mode = ssl.CERT_REQUIRED if require_client else ssl.CERT_NONE
        context.verify_flags |= getattr(ssl, "VERIFY_ALLOW_PROXY_CERTS", ALLOW_PROXY_CERTS)
        return context

    def client_context(self, *, proxy: Path | None = None) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=str(self.ca_file))
        credential = str(proxy or self.proxy_path)
        context.load_cert_chain(credential, credential)
        return context

    def environment(self) -> dict[str, str]:
        """Variables that point a client at this PKI's proxy and CA directory."""
        return {"X509_USER_PROXY": str(self.proxy_path), "X509_CERT_DIR": str(self.ca_dir)}


def create_pki(
    directory: Path | str,
    *,
    hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "::1"),
    host_cn: str = "host/localhost",
    lifetime: float = 7 * DAY,
    key_slots: tuple[int, int, int] = (0, 1, 2),
) -> PKI:
    """Mint a CA, a host certificate for ``hosts`` and a user certificate.

    ``key_slots`` picks the frozen keys for the CA, host and user; a second,
    distinct PKI needs different ones, or its CA would be the same CA.
    """
    base = Path(directory)
    base.mkdir(parents=True, exist_ok=True)
    now = time.time()
    ca_key, host_key, user_key = (test_key(slot) for slot in key_slots)
    ca_name = encode_name(CA_SUBJECT)
    ca = parse_certificate(
        build_certificate(
            subject=ca_name,
            issuer=ca_name,
            public_key=public_key_info(ca_key.public),
            signer=ca_key,
            not_before=now - 3600,
            not_after=now + lifetime,
            extensions=[
                extension(BASIC_CONSTRAINTS_OID, sequence(boolean(True)), critical=True),
                extension(KEY_USAGE_OID, key_usage(5, 6), critical=True),
                *_key_ids(ca_key, ca_key),
            ],
        )
    )
    host = parse_certificate(
        build_certificate(
            subject=encode_name((("DC", "org"), ("DC", "xgfal"), ("CN", host_cn))),
            issuer=ca_name,
            public_key=public_key_info(host_key.public),
            signer=ca_key,
            not_before=now - 3600,
            not_after=now + lifetime,
            extensions=[
                extension(KEY_USAGE_OID, key_usage(0, 2), critical=True),
                extension(SUBJECT_ALT_NAME_OID, _san(hosts)),
                *_key_ids(host_key, ca_key),
            ],
        )
    )
    user = parse_certificate(
        build_certificate(
            subject=encode_name(USER_SUBJECT),
            issuer=ca_name,
            public_key=public_key_info(user_key.public),
            signer=ca_key,
            not_before=now - 3600,
            not_after=now + lifetime,
            extensions=[
                extension(KEY_USAGE_OID, key_usage(0, 2), critical=True),
                *_key_ids(user_key, ca_key),
            ],
        )
    )
    return PKI(base, ca, ca_key, host, host_key, user, user_key)
