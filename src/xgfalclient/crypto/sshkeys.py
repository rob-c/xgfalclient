"""SSH keys: wire encoding, OpenSSH private-key files, signatures, known_hosts.

Everything the SSH-2 client and the in-process test server need to prove
or check an identity:

* the :rfc:`4251` wire types (``string``, ``mpint``, ``uint32``...) as
  :func:`string`/:func:`mpint` and a :class:`Reader`;
* key files - OpenSSH's ``-----BEGIN OPENSSH PRIVATE KEY-----`` format
  (``ssh-keygen``'s default since 7.8), plain or passphrase-protected with
  ``bcrypt`` (pyca's native ``bcrypt_pbkdf``) + ``aes{128,192,256}-ctr``,
  and PEM RSA via :mod:`.rsa`;
* signing and verification for ``ssh-ed25519``, ``rsa-sha2-256``,
  ``rsa-sha2-512`` (and legacy ``ssh-rsa`` verification) and
  ``ecdsa-sha2-nistp256``/``-nistp384``/``-nistp521`` (:rfc:`5656`), all
  through ``cryptography``'s primitives;
* ``known_hosts`` lookups, hashed (``|1|salt|hmac``) entries included.

The SFTP plugin's transport (:mod:`xgfalclient.plugins.sftp.ssh`) and the
test server (:mod:`xgfalclient.testing.sftp`) are the two consumers; neither
touches a ``cryptography`` key object directly. Keys are plain frozen
dataclasses holding integers and byte strings, and a library key is built
for the one operation that needs it - signing happens a handful of times per
connection, so caching library objects would buy nothing and would make the
dataclasses unhashable.

What a maintainer must not break: every encoder here must stay byte-for-byte
what OpenSSH writes (keys made by :func:`encode_openssh_private` are loaded
by paramiko in ``tests/test_sftp_paramiko.py``), and every verifier must return False -
never raise - for a malformed signature, because a peer controls those bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import struct
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from xrdsec.rsa import RSAPrivateKey, RSAPublicKey, load_private_key, pem_blocks

__all__ = [
    "HostKeyResult",
    "KeyError_",
    "KnownHosts",
    "PrivateKey",
    "PublicKey",
    "Reader",
    "encode_openssh_private",
    "fingerprint",
    "load_private",
    "mpint",
    "parse_public_blob",
    "string",
    "uint32",
]


class KeyError_(ValueError):
    """A key file or blob that cannot be used (named to avoid ``KeyError``).

    A ``ValueError`` so that callers which only care that input was bad can
    catch the broad class; the SSH transport maps it to an authentication
    or protocol failure with the message intact.
    """


# ---------------------------------------------------------------------------
# Wire types
# ---------------------------------------------------------------------------


def uint32(value: int) -> bytes:
    """RFC 4251 §5 ``uint32``: four bytes, network order."""
    return struct.pack(">I", value)


def string(data: bytes | str) -> bytes:
    """RFC 4251 §5 ``string``: a ``uint32`` length then the bytes (``str`` as UTF-8)."""
    raw = data.encode() if isinstance(data, str) else bytes(data)
    return struct.pack(">I", len(raw)) + raw


def mpint(value: int) -> bytes:
    """A two's-complement big-endian integer with a length prefix.

    RFC 4251 §5: zero is the empty string, and a positive number whose top
    bit is set gets a leading zero byte so it does not read as negative -
    hence ``bit_length() + 8`` rather than ``+ 7``. Getting this wrong only
    shows on about half of all keys and DH values, which is why it is spelt
    out.
    """
    if value == 0:
        return b"\x00\x00\x00\x00"
    length = (value.bit_length() + 8) // 8
    return string(value.to_bytes(length, "big", signed=True))


class Reader:
    """Sequential reads over one message; ``KeyError_`` when it runs short.

    Used for key blobs and files here and for every SSH message the
    transport parses, so a truncated or lying length field from the peer
    always surfaces as ``KeyError_`` and never as an ``IndexError`` or a
    silently short slice. The data is copied once into ``bytes`` so a
    caller's buffer may be reused while the reader is alive.
    """

    def __init__(self, data: bytes | bytearray | memoryview, position: int = 0) -> None:
        """Read ``data`` (copied) from byte ``position`` on."""
        self.data = bytes(data)
        self.position = position

    def take(self, count: int) -> bytes:
        """The next ``count`` bytes; a negative or overlong count is ``KeyError_``."""
        end = self.position + count
        if count < 0 or end > len(self.data):
            raise KeyError_("message truncated")
        chunk = self.data[self.position : end]
        self.position = end
        return chunk

    def byte(self) -> int:
        """One ``byte`` (a message number, a flag)."""
        return self.take(1)[0]

    def boolean(self) -> bool:
        """RFC 4251 ``boolean``: any non-zero byte is True, as the RFC says."""
        return self.byte() != 0

    def uint32(self) -> int:
        """A big-endian ``uint32``."""
        return int(struct.unpack(">I", self.take(4))[0])

    def uint64(self) -> int:
        """A big-endian ``uint64`` (SFTP sizes and offsets)."""
        return int(struct.unpack(">Q", self.take(8))[0])

    def string(self) -> bytes:
        """A length-prefixed ``string``, as raw bytes."""
        return self.take(self.uint32())

    def text(self) -> str:
        """A ``string`` as UTF-8 text; undecodable bytes are replaced, not fatal.

        Names and messages from a server are shown to people, never compared
        for security, so a lossy decode is preferable to failing the session.
        """
        return self.string().decode("utf-8", "replace")

    def mpint(self) -> int:
        """An ``mpint`` (see :func:`mpint`), sign included."""
        return int.from_bytes(self.string(), "big", signed=True)

    def name_list(self) -> list[str]:
        """A ``name-list``: comma-separated names, the empty string meaning none."""
        raw = self.text()
        return raw.split(",") if raw else []

    def rest(self) -> bytes:
        """Everything not yet read (a payload whose length the outer layer fixed)."""
        return self.take(len(self.data) - self.position)

    @property
    def remaining(self) -> int:
        """Bytes left to read; callers check it to reject trailing garbage."""
        return len(self.data) - self.position


# ---------------------------------------------------------------------------
# Public keys
# ---------------------------------------------------------------------------

_NISTP256 = "ecdsa-sha2-nistp256"


@dataclass(frozen=True, slots=True)
class _Curve:
    """One :rfc:`5656` ECDSA key type: its curve, its hash and its point size."""

    #: The curve identifier SSH writes after the key type (``nistp256``).
    name: str
    #: How an error names the curve (``P-256``).
    label: str
    curve: type[ec.EllipticCurve]
    #: RFC 5656 s. 6.2.1: the hash follows the curve size.
    hash: type[hashes.HashAlgorithm]
    #: Bytes per coordinate in the uncompressed SEC1 point.
    size: int


_CURVES = {
    _NISTP256: _Curve("nistp256", "P-256", ec.SECP256R1, hashes.SHA256, 32),
    "ecdsa-sha2-nistp384": _Curve("nistp384", "P-384", ec.SECP384R1, hashes.SHA384, 48),
    "ecdsa-sha2-nistp521": _Curve("nistp521", "P-521", ec.SECP521R1, hashes.SHA512, 66),
}

#: Every ECDSA key type, in the order a client offers them.
ECDSA_KINDS = tuple(_CURVES)


def _encode_point(kind: str, point: tuple[int, int]) -> bytes:
    """The uncompressed SEC1 encoding of ``point`` on ``kind``'s curve."""
    size = _CURVES[kind].size
    return b"\x04" + point[0].to_bytes(size, "big") + point[1].to_bytes(size, "big")


def _decode_point(kind: str, data: bytes) -> tuple[int, int]:
    """An uncompressed point on ``kind``'s curve; ``ValueError`` for anything else.

    OpenSSH writes and accepts only the uncompressed form, so a compressed
    point (which ``cryptography`` would take) is refused here as it is there.
    """
    curve = _CURVES[kind]
    if len(data) != 1 + 2 * curve.size or data[0] != 4:
        raise ValueError(f"expected an uncompressed {curve.label} point")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(curve.curve(), data)
    except ValueError:
        raise ValueError(f"point is not on {curve.label}") from None
    numbers = key.public_numbers()
    return numbers.x, numbers.y


def _ecdsa_verify(kind: str, point: tuple[int, int], data: bytes, r: int, s: int) -> bool:
    """Whether ``(r, s)`` is ``kind``'s ECDSA signature of ``data`` by ``point``."""
    curve = _CURVES[kind]
    try:
        key = ec.EllipticCurvePublicNumbers(*point, curve.curve()).public_key()
        key.verify(utils.encode_dss_signature(r, s), data, ec.ECDSA(curve.hash()))
    except (InvalidSignature, ValueError):  # ValueError: r or s out of range
        return False
    return True


def _ed25519_verify(public: bytes, data: bytes, signature: bytes) -> bool:
    """Whether ``signature`` is an RFC 8032 Ed25519 signature of ``data`` by ``public``.

    ``ValueError`` (a wrong-length key or signature, which the peer controls)
    is a failed verification, not an error.
    """
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, data)
    except (InvalidSignature, ValueError):
        return False
    return True


#: The hash behind each RSA signature algorithm name (RFC 8332); ``ssh-rsa``
#: is SHA-1, verified for old servers but never chosen when signing.
_RSA_DIGESTS = {"rsa-sha2-256": "sha256", "rsa-sha2-512": "sha512", "ssh-rsa": "sha1"}


@dataclass(frozen=True, slots=True)
class PublicKey:
    """A public key as SSH names it: ``kind`` and the parsed material.

    ``blob`` is the exact wire encoding the key arrived in (or was built
    as); it is what fingerprints, ``known_hosts`` comparisons and the
    exchange hash use, so it is kept rather than re-encoded. Exactly one of
    ``ed25519``/``rsa``/``ecdsa`` is set, according to ``kind``.
    """

    kind: str
    blob: bytes
    ed25519: bytes = b""
    rsa: RSAPublicKey | None = None
    ecdsa: tuple[int, int] | None = None

    def algorithms(self) -> tuple[str, ...]:
        """The signature algorithms this key can verify, best first.

        One RSA key serves three algorithm names (RFC 8332): the SHA-2 ones
        first, so that SHA-1 ``ssh-rsa`` is used only with a server that
        offers nothing else.
        """
        if self.kind == "ssh-rsa":
            return ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa")
        return (self.kind,)

    def verify(self, algorithm: str, data: bytes, signature_blob: bytes) -> bool:
        """Check an SSH signature blob (``string algorithm, string sig``).

        The algorithm named inside the blob must be the one negotiated: a
        server may not answer an ``rsa-sha2-512`` negotiation with a SHA-1
        signature (the downgrade RFC 8332 §3 warns about). Every malformed
        input is False.
        """
        try:
            reader = Reader(signature_blob)
            named = reader.text()
            signature = reader.string()
        except KeyError_:
            return False
        if named != algorithm or algorithm not in self.algorithms():
            return False
        if self.kind == "ssh-ed25519":
            return _ed25519_verify(self.ed25519, data, signature)
        if self.rsa is not None:
            return self.rsa.verify(data, _pad_rsa(signature, self.rsa), digest=_RSA_DIGESTS[named])
        assert self.ecdsa is not None
        # RFC 5656 §3.1.2: the ECDSA signature is itself two mpints, r and s.
        try:
            inner = Reader(signature)
            r, s = inner.mpint(), inner.mpint()
        except KeyError_:
            return False
        return _ecdsa_verify(self.kind, self.ecdsa, data, r, s)


def _pad_rsa(signature: bytes, key: RSAPublicKey) -> bytes:
    """OpenSSH may drop a signature's leading zero bytes; RSA verify wants them."""
    return signature.rjust(key.size, b"\x00") if len(signature) < key.size else signature


def parse_public_blob(blob: bytes) -> PublicKey:
    """Parse the ``string key-type, ...`` form SSH sends a public key in.

    The layouts are RFC 4253 §6.6 (``ssh-rsa``: ``e`` then ``n``), RFC 8709
    (``ssh-ed25519``: the 32-byte point) and RFC 5656 §3.1 (ECDSA: curve
    name, then the SEC1 point). ``KeyError_`` for anything else, including
    an ECDSA blob whose curve name contradicts its key type.
    """
    reader = Reader(blob)
    kind = reader.text()
    if kind == "ssh-ed25519":
        ed_point = reader.string()
        if len(ed_point) != 32:
            raise KeyError_("ssh-ed25519 public keys are 32 bytes")
        return PublicKey(kind, bytes(blob), ed25519=ed_point)
    if kind == "ssh-rsa":
        e = reader.mpint()
        n = reader.mpint()
        return PublicKey(kind, bytes(blob), rsa=RSAPublicKey(n, e))
    if kind in _CURVES:
        if reader.text() != _CURVES[kind].name:
            raise KeyError_("ecdsa key curve does not match its type")
        try:
            ec_point = _decode_point(kind, reader.string())
        except ValueError as exc:
            raise KeyError_(str(exc)) from None
        return PublicKey(kind, bytes(blob), ecdsa=ec_point)
    raise KeyError_(f"unsupported public key type {kind!r}")


def fingerprint(blob: bytes) -> str:
    """``SHA256:...``, the way ``ssh-keygen -l`` prints it (unpadded base64).

    This is what error messages show so that a user can compare against
    ``ssh-keygen -lf`` on the server.
    """
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


# ---------------------------------------------------------------------------
# Private keys
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PrivateKey:
    """A private key able to make SSH signatures.

    As with :class:`PublicKey`, exactly one of ``ed25519_seed`` (the 32-byte
    RFC 8032 seed, not the 64-byte expanded key OpenSSH stores), ``rsa`` or
    ``ecdsa`` (the private scalar) is set. ``comment`` is the file's comment,
    shown in logs and written back by :func:`encode_openssh_private`.
    """

    kind: str
    public: PublicKey
    ed25519_seed: bytes = b""
    rsa: RSAPrivateKey | None = None
    ecdsa: int = 0
    comment: str = ""

    def algorithms(self) -> tuple[str, ...]:
        """The signature algorithms this key can sign with, best first."""
        return self.public.algorithms()

    def sign(self, data: bytes, algorithm: str | None = None) -> bytes:
        """An SSH signature blob over ``data`` with ``algorithm`` (the key's best by default)."""
        algorithm = algorithm or self.algorithms()[0]
        if algorithm not in self.algorithms():
            raise KeyError_(f"a {self.kind} key cannot sign with {algorithm}")
        if self.kind == "ssh-ed25519":
            signature = Ed25519PrivateKey.from_private_bytes(self.ed25519_seed).sign(data)
        elif self.rsa is not None:
            signature = self.rsa.sign(data, digest=_RSA_DIGESTS[algorithm])
        else:
            curve = _CURVES[self.kind]
            private = ec.derive_private_key(self.ecdsa, curve.curve())
            r, s = utils.decode_dss_signature(private.sign(data, ec.ECDSA(curve.hash())))
            signature = mpint(r) + mpint(s)
        return string(algorithm) + string(signature)

    @classmethod
    def from_ed25519_seed(cls, seed: bytes, comment: str = "") -> PrivateKey:
        """The Ed25519 key for a 32-byte seed, its public half derived."""
        point = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
        blob = string("ssh-ed25519") + string(point)
        return cls(
            "ssh-ed25519", PublicKey("ssh-ed25519", blob, ed25519=point), seed, comment=comment
        )

    @classmethod
    def from_rsa(cls, key: RSAPrivateKey, comment: str = "") -> PrivateKey:
        """The ``ssh-rsa`` key for ``key``; the blob is ``e`` before ``n`` (RFC 4253)."""
        blob = string("ssh-rsa") + mpint(key.e) + mpint(key.n)
        return cls("ssh-rsa", PublicKey("ssh-rsa", blob, rsa=key.public), rsa=key, comment=comment)

    @classmethod
    def from_ecdsa(cls, d: int, comment: str = "", *, kind: str = _NISTP256) -> PrivateKey:
        """The ``kind`` ECDSA key with private scalar ``d`` (``ValueError`` if out of range)."""
        curve = _CURVES[kind]
        numbers = ec.derive_private_key(d, curve.curve()).public_key().public_numbers()
        point = (numbers.x, numbers.y)
        blob = string(kind) + string(curve.name) + string(_encode_point(kind, point))
        return cls(kind, PublicKey(kind, blob, ecdsa=point), ecdsa=d, comment=comment)

    def public_line(self) -> str:
        """The ``authorized_keys`` / ``.pub`` line."""
        text = base64.b64encode(self.public.blob).decode("ascii")
        return f"{self.kind} {text}" + (f" {self.comment}" if self.comment else "")

    def __repr__(self) -> str:
        """Type and fingerprint only: a repr must never leak key material into a log."""
        return f"PrivateKey({self.kind}, {fingerprint(self.public.blob)})"


#: The start of an ``openssh-key-v1`` blob (OpenSSH ``PROTOCOL.key``).
_OPENSSH_MAGIC = b"openssh-key-v1\x00"
#: The ciphers ``ssh-keygen`` can protect a key with: (key bytes, IV bytes).
_KDF_CIPHERS = {"aes256-ctr": (32, 16), "aes128-ctr": (16, 16), "aes192-ctr": (24, 16)}


class PassphraseRequired(KeyError_):
    """The key file is encrypted and no (or the wrong) passphrase was given.

    Separate from :class:`KeyError_` so the plugin can tell "ask for a
    passphrase" (``[SFTP PLUGIN] PASSPHRASE``) from "this file is unusable".
    """


def load_private(data: bytes | str, passphrase: bytes | str | None = None) -> PrivateKey:
    """Load an OpenSSH-format or PEM RSA private key.

    ``PassphraseRequired`` if it is encrypted and ``passphrase`` is missing
    or wrong; ``KeyError_`` for anything unusable.

    Encrypted PEM and PKCS#8 keys are refused with the ``ssh-keygen -p``
    conversion hint rather than decrypted: they need the legacy OpenSSL KDFs
    (MD5-based for PEM), and every OpenSSH since 7.8 writes the openssh-key-v1
    format anyway. The first usable PEM block wins, as with ``ssh -i``.
    """
    raw = data.encode() if isinstance(data, str) else bytes(data)
    blocks = pem_blocks(raw)
    for label, der in blocks:
        if label == "OPENSSH PRIVATE KEY":
            secret = passphrase.encode() if isinstance(passphrase, str) else passphrase
            return _load_openssh(der, secret)
        if label in ("RSA PRIVATE KEY", "PRIVATE KEY"):
            return _load_pem_rsa(raw, der)
        if label == "ENCRYPTED PRIVATE KEY":
            raise KeyError_("encrypted PKCS#8 keys are not supported; convert with ssh-keygen -p")
    raise KeyError_("no supported private key found (expected OpenSSH or PEM RSA format)")


def _load_pem_rsa(raw: bytes, der: bytes) -> PrivateKey:
    """A PEM (PKCS#1 or PKCS#8) RSA key; an encrypted one (``Proc-Type``) is refused."""
    if b"ENCRYPTED" in raw.split(b"-----END", 1)[0]:
        raise KeyError_("encrypted PEM keys are not supported; convert with ssh-keygen -p")
    try:
        return PrivateKey.from_rsa(load_private_key(der))
    except ValueError as exc:
        raise KeyError_(str(exc)) from None


def _load_openssh(blob: bytes, passphrase: bytes | None) -> PrivateKey:
    """Parse an ``openssh-key-v1`` blob (OpenSSH ``PROTOCOL.key``).

    Layout: magic, cipher name, KDF name, KDF options, key count (only 1 is
    supported, as ``ssh-keygen`` writes), the public blob, then the private
    section - encrypted as a whole when a cipher is named. The private
    section starts with the same random ``uint32`` twice; after decryption
    they differ only if the passphrase was wrong, which is the one way the
    format lets a reader tell, hence ``PassphraseRequired`` there.
    """
    if not blob.startswith(_OPENSSH_MAGIC):
        raise KeyError_("not an openssh-key-v1 file")
    reader = Reader(blob, len(_OPENSSH_MAGIC))
    cipher = reader.text()
    kdf = reader.text()
    options = reader.string()
    if reader.uint32() != 1:
        raise KeyError_("only single-key OpenSSH files are supported")
    reader.string()  # the public key, repeated inside
    private = reader.string()
    if cipher != "none":
        if not passphrase:
            raise PassphraseRequired("the private key is encrypted and no passphrase was given")
        private = _decrypt(cipher, kdf, options, private, passphrase)
    inner = Reader(private)
    if inner.uint32() != inner.uint32():
        if cipher != "none":
            raise PassphraseRequired("wrong passphrase for the private key")
        raise KeyError_("corrupt private key (check bytes differ)")
    kind = inner.text()
    if kind == "ssh-ed25519":
        inner.string()  # the public point, repeated
        # OpenSSH stores seed || public point (64 bytes); the seed is the key.
        secret = inner.string()
        key = PrivateKey.from_ed25519_seed(secret[:32], inner.text())
    elif kind == "ssh-rsa":
        # Private section order differs from the public blob: n before e.
        n = inner.mpint()
        e = inner.mpint()
        d = inner.mpint()
        inner.mpint()  # iqmp
        p = inner.mpint()
        q = inner.mpint()
        key = PrivateKey.from_rsa(RSAPrivateKey(n=n, e=e, d=d, p=p, q=q), inner.text())
    elif kind in _CURVES:
        inner.string()  # the curve name
        inner.string()  # the public point, derived again from the scalar
        try:
            key = PrivateKey.from_ecdsa(inner.mpint(), inner.text(), kind=kind)
        except ValueError as exc:
            raise KeyError_(f"corrupt {kind} private key: {exc}") from None
    else:
        raise KeyError_(f"unsupported private key type {kind!r}")
    return key


def _decrypt(cipher: str, kdf: str, options: bytes, data: bytes, passphrase: bytes) -> bytes:
    """The private section of a passphrase-protected key, decrypted.

    ``options`` is the bcrypt KDF's ``string salt, uint32 rounds``; the KDF
    yields key and IV back to back. AES-CTR needs no padding check, so a wrong
    passphrase is noticed by the caller's check bytes, not here. Imported
    lazily: most key files are not encrypted.
    """
    from . import ciphers
    from .bcrypt import bcrypt_pbkdf

    if kdf != "bcrypt" or cipher not in _KDF_CIPHERS:
        raise KeyError_(f"unsupported key encryption {cipher}/{kdf}")
    params = Reader(options)
    salt = params.string()
    rounds = params.uint32()
    key_length, iv_length = _KDF_CIPHERS[cipher]
    material = _derive(passphrase, salt, key_length + iv_length, rounds, bcrypt_pbkdf)
    stream = ciphers.get().aes_ctr(material[:key_length], material[key_length:])
    return bytes(stream.update(data))


#: Memo for :func:`_derive`: (SHA-256 of passphrase, salt, length, rounds) ->
#: key material. Process-wide and unbounded, which is fine because a process
#: holds a handful of key files at most.
_derived: dict[tuple[bytes, bytes, int, int], bytes] = {}


def _derive(
    passphrase: bytes,
    salt: bytes,
    length: int,
    rounds: int,
    kdf: Callable[[bytes, bytes, int, int], bytes],
) -> bytes:
    """``bcrypt_pbkdf``, memoised: keys are reloaded per connection.

    The KDF is native now (:mod:`.bcrypt`), but it is slow by design - a
    tenth of a second or more at ``ssh-keygen``'s default rounds - and a
    pooled plugin reconnects often enough for that to show; the cache is
    keyed by a digest of the passphrase, never the passphrase itself.
    """
    token = (hashlib.sha256(passphrase).digest(), salt, length, rounds)
    found = _derived.get(token)
    if found is None:
        found = _derived[token] = kdf(passphrase, salt, length, rounds)
    return found


def encode_openssh_private(
    key: PrivateKey, passphrase: bytes | None = None, rounds: int = 16
) -> bytes:
    """Write ``key`` as an OpenSSH private-key file (encrypted with ``aes256-ctr`` if asked).

    Used to make test keys; the output is what ``ssh-keygen`` writes and
    ``ssh`` reads. The padding is OpenSSH's (bytes 1, 2, 3...) to the cipher's
    block size (8 unencrypted, 16 for AES), and the base64 is wrapped at 70
    columns, as ``ssh-keygen`` does, so a diff against a real key is clean.
    """
    from . import ciphers
    from .bcrypt import bcrypt_pbkdf

    check = os.urandom(4)
    body = check + check + string(key.kind)
    if key.kind == "ssh-ed25519":
        point = key.public.ed25519
        body += string(point) + string(key.ed25519_seed + point)
    elif key.rsa is not None:
        r = key.rsa
        body += b"".join(mpint(v) for v in (r.n, r.e, r.d, pow(r.q, -1, r.p), r.p, r.q))
    else:
        assert key.public.ecdsa is not None
        point = _encode_point(key.kind, key.public.ecdsa)
        body += string(_CURVES[key.kind].name) + string(point) + mpint(key.ecdsa)
    body += string(key.comment)
    block = 16 if passphrase else 8
    pad = 1
    while len(body) % block:
        body += bytes([pad])
        pad += 1
    if passphrase:
        salt = os.urandom(16)
        material = bcrypt_pbkdf(passphrase, salt, 48, rounds)
        body = bytes(ciphers.get().aes_ctr(material[:32], material[32:]).update(body))
        head = string("aes256-ctr") + string("bcrypt") + string(string(salt) + uint32(rounds))
    else:
        head = string("none") + string("none") + string(b"")
    blob = _OPENSSH_MAGIC + head + uint32(1) + string(key.public.blob) + string(body)
    text = base64.b64encode(blob).decode("ascii")
    lines = [text[i : i + 70] for i in range(0, len(text), 70)]
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(lines)
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    ).encode("ascii")


# ---------------------------------------------------------------------------
# known_hosts
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HostKeyResult:
    """The outcome of a lookup: ``"match"``, ``"unknown"``, ``"changed"`` or ``"revoked"``.

    ``detail`` is text for the user. The SFTP plugin decides what to do with
    each status according to ``[SFTP PLUGIN] STRICT_HOST_KEY_CHECKING``;
    ``changed`` and ``revoked`` always fail, whatever the policy.
    """

    status: str
    detail: str = ""


def host_pattern(host: str, port: int) -> str:
    """How ``known_hosts`` names a host: ``host`` on 22, ``[host]:port`` elsewhere."""
    return host if port == 22 else f"[{host}]:{port}"


def _glob(pattern: str, name: str) -> bool:
    """OpenSSH's ``match_pattern``: ``*`` and ``?`` are the only wildcards.

    Not :mod:`fnmatch`, whose ``[...]`` is a character class: the
    ``[host]:port`` form every non-22 entry is written in would then match
    one character of ``host`` and never the entry itself - such a host would
    look unknown on every connection, so ``accept-new`` would take a
    *changed* key without a word.
    """
    regex = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(regex, name, re.DOTALL) is not None


def _matches(pattern_field: str, name: str) -> bool:
    """One ``known_hosts`` host field against a name (hashed or comma-separated globs)."""
    if pattern_field.startswith("|1|"):
        try:
            _, _, salt_text, hash_text = pattern_field.split("|", 3)
            salt = base64.b64decode(salt_text)
            wanted = base64.b64decode(hash_text)
        except (ValueError, binascii.Error):
            return False
        return hmac.compare_digest(hmac.digest(salt, name.encode(), "sha1"), wanted)
    matched = False
    for pattern in pattern_field.split(","):
        negated = pattern.startswith("!")
        if _glob(pattern.lstrip("!").lower(), name.lower()):
            if negated:
                return False
            matched = True
    return matched


class KnownHosts:
    """The entries of one or more ``known_hosts`` files.

    Parsing follows ``sshd(8)``'s ``SSH_KNOWN_HOSTS FILE FORMAT``: an
    optional ``@revoked``/``@cert-authority`` marker, a host field (globs, or
    one hashed ``|1|`` entry), the key type and the base64 key. Lines that do
    not parse are skipped, as OpenSSH skips them, rather than failing every
    connection because of one bad line.
    """

    def __init__(self, lines: Iterable[str] = ()) -> None:
        """Parse ``lines`` (the text of one or more files, in order of precedence)."""
        self.entries: list[tuple[str, str, str, bytes]] = []  # marker, hosts, kind, blob
        for line in lines:
            self._add_line(line)

    @classmethod
    def load(cls, paths: Iterable[str]) -> KnownHosts:
        """Every entry of the readable files among ``paths``; missing ones are skipped.

        A missing ``~/.ssh/known_hosts`` is the normal state of a fresh
        account, so it means "nothing known" rather than an error.
        """
        lines: list[str] = []
        for path in paths:
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    lines.extend(handle)
            except OSError:
                continue
        return cls(lines)

    def _add_line(self, line: str) -> None:
        """Record one line's entry, or nothing for a comment or malformed line."""
        fields = line.strip().split()
        if not fields or fields[0].startswith("#"):
            return
        marker = ""
        if fields[0].startswith("@"):
            marker, fields = fields[0], fields[1:]
        if len(fields) < 3:
            return
        try:
            blob = base64.b64decode(fields[2], validate=True)
        except (ValueError, binascii.Error):
            return
        self.entries.append((marker, fields[0], fields[1], blob))

    def check(self, host: str, port: int, key: PublicKey) -> HostKeyResult:
        """Is ``key`` the known key for ``host:port``?

        OpenSSH's precedence: a revoked key fails at once; a matching entry of
        the same type wins over any non-matching one (a host may have several
        keys); a same-type entry that does not match makes the key
        ``changed``. Entries only of other types leave the host ``unknown``,
        with a detail saying so, as ``ssh`` reports it.
        """
        other_kinds = False
        changed = False
        for marker, kind, blob in self._for_host(host_pattern(host, port)):
            if marker == "@revoked":
                if blob == key.blob:
                    return HostKeyResult("revoked", "the host key has been revoked")
            elif marker:
                continue  # @cert-authority: host certificates are not supported
            elif kind != key.kind:
                other_kinds = True
            elif blob == key.blob:
                return HostKeyResult("match")
            else:
                changed = True
        if changed:
            return HostKeyResult("changed", "REMOTE HOST IDENTIFICATION HAS CHANGED")
        detail = "only keys of other types are known" if other_kinds else ""
        return HostKeyResult("unknown", detail)

    def _for_host(self, name: str) -> Iterator[tuple[str, str, bytes]]:
        """``(marker, kind, blob)`` of each entry whose host patterns match ``name``, in order."""
        for marker, hosts, kind, blob in self.entries:
            if _matches(hosts, name):
                yield marker, kind, blob

    @staticmethod
    def line_for(host: str, port: int, key: PublicKey) -> str:
        """The unhashed line ``accept-new`` appends for a newly trusted host."""
        return f"{host_pattern(host, port)} {key.kind} {base64.b64encode(key.blob).decode()}\n"
