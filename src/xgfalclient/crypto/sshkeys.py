"""SSH keys: wire encoding, OpenSSH private-key files, signatures, known_hosts.

Everything the SSH-2 client and the in-process test server need to prove
or check an identity:

* the :rfc:`4251` wire types (``string``, ``mpint``, ``uint32``...) as
  :func:`string`/:func:`mpint` and a :class:`Reader`;
* key files - OpenSSH's ``-----BEGIN OPENSSH PRIVATE KEY-----`` format
  (``ssh-keygen``'s default since 7.8), plain or passphrase-protected with
  ``bcrypt`` + ``aes256-ctr``/``aes256-cbc``..., and PEM RSA via
  :mod:`.rsa`;
* signing and verification for ``ssh-ed25519``, ``rsa-sha2-256``,
  ``rsa-sha2-512`` (and legacy ``ssh-rsa`` verification) and
  ``ecdsa-sha2-nistp256``;
* ``known_hosts`` lookups, hashed (``|1|salt|hmac``) entries included.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import struct
from collections.abc import Iterable
from dataclasses import dataclass

from .._compat import SLOTS
from . import ed25519, p256
from .rsa import RSAPrivateKey, RSAPublicKey, load_private_key, pem_blocks

__all__ = [
    "KeyError_",
    "Reader",
    "string",
    "mpint",
    "uint32",
    "PublicKey",
    "PrivateKey",
    "parse_public_blob",
    "load_private",
    "encode_openssh_private",
    "fingerprint",
    "KnownHosts",
    "HostKeyResult",
]


class KeyError_(ValueError):
    """A key file or blob that cannot be used (named to avoid ``KeyError``)."""


# ---------------------------------------------------------------------------
# Wire types
# ---------------------------------------------------------------------------


def uint32(value: int) -> bytes:
    return struct.pack(">I", value)


def string(data: bytes | str) -> bytes:
    raw = data.encode() if isinstance(data, str) else bytes(data)
    return struct.pack(">I", len(raw)) + raw


def mpint(value: int) -> bytes:
    """A two's-complement big-endian integer with a length prefix."""
    if value == 0:
        return b"\x00\x00\x00\x00"
    length = (value.bit_length() + 8) // 8
    return string(value.to_bytes(length, "big", signed=True))


class Reader:
    """Sequential reads over one message; ``KeyError_`` when it runs short."""

    def __init__(self, data: bytes | bytearray | memoryview, position: int = 0) -> None:
        self.data = bytes(data)
        self.position = position

    def take(self, count: int) -> bytes:
        end = self.position + count
        if count < 0 or end > len(self.data):
            raise KeyError_("message truncated")
        chunk = self.data[self.position : end]
        self.position = end
        return chunk

    def byte(self) -> int:
        return self.take(1)[0]

    def boolean(self) -> bool:
        return self.byte() != 0

    def uint32(self) -> int:
        return int(struct.unpack(">I", self.take(4))[0])

    def uint64(self) -> int:
        return int(struct.unpack(">Q", self.take(8))[0])

    def string(self) -> bytes:
        return self.take(self.uint32())

    def text(self) -> str:
        return self.string().decode("utf-8", "replace")

    def mpint(self) -> int:
        return int.from_bytes(self.string(), "big", signed=True)

    def name_list(self) -> list[str]:
        raw = self.text()
        return raw.split(",") if raw else []

    def rest(self) -> bytes:
        return self.take(len(self.data) - self.position)

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position


# ---------------------------------------------------------------------------
# Public keys
# ---------------------------------------------------------------------------

_NISTP256 = "ecdsa-sha2-nistp256"
_RSA_DIGESTS = {"rsa-sha2-256": "sha256", "rsa-sha2-512": "sha512", "ssh-rsa": "sha1"}


@dataclass(frozen=True, **SLOTS)
class PublicKey:
    """A public key as SSH names it: ``kind`` and the parsed material."""

    kind: str
    blob: bytes
    ed25519: bytes = b""
    rsa: RSAPublicKey | None = None
    ecdsa: tuple[int, int] | None = None

    def algorithms(self) -> tuple[str, ...]:
        """The signature algorithms this key can verify, best first."""
        if self.kind == "ssh-rsa":
            return ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa")
        return (self.kind,)

    def verify(self, algorithm: str, data: bytes, signature_blob: bytes) -> bool:
        """Check an SSH signature blob (``string algorithm, string sig``)."""
        try:
            reader = Reader(signature_blob)
            named = reader.text()
            signature = reader.string()
        except KeyError_:
            return False
        if named != algorithm or algorithm not in self.algorithms():
            return False
        if self.kind == "ssh-ed25519":
            return ed25519.verify(self.ed25519, data, signature)
        if self.rsa is not None:
            return self.rsa.verify(data, _pad_rsa(signature, self.rsa), digest=_RSA_DIGESTS[named])
        assert self.ecdsa is not None
        try:
            inner = Reader(signature)
            r, s = inner.mpint(), inner.mpint()
        except KeyError_:
            return False
        return p256.verify(self.ecdsa, data, r, s)


def _pad_rsa(signature: bytes, key: RSAPublicKey) -> bytes:
    """OpenSSH may drop a signature's leading zero bytes; RSA verify wants them."""
    return signature.rjust(key.size, b"\x00") if len(signature) < key.size else signature


def parse_public_blob(blob: bytes) -> PublicKey:
    """Parse the ``string key-type, ...`` form SSH sends a public key in."""
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
    if kind == _NISTP256:
        if reader.text() != "nistp256":
            raise KeyError_("ecdsa key curve does not match its type")
        try:
            ec_point = p256.decode_point(reader.string())
        except ValueError as exc:
            raise KeyError_(str(exc)) from None
        return PublicKey(kind, bytes(blob), ecdsa=ec_point)
    raise KeyError_(f"unsupported public key type {kind!r}")


def fingerprint(blob: bytes) -> str:
    """``SHA256:...``, the way ``ssh-keygen -l`` prints it."""
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


# ---------------------------------------------------------------------------
# Private keys
# ---------------------------------------------------------------------------


@dataclass(frozen=True, **SLOTS)
class PrivateKey:
    """A private key able to make SSH signatures."""

    kind: str
    public: PublicKey
    ed25519_seed: bytes = b""
    rsa: RSAPrivateKey | None = None
    ecdsa: int = 0
    comment: str = ""

    def algorithms(self) -> tuple[str, ...]:
        return self.public.algorithms()

    def sign(self, data: bytes, algorithm: str | None = None) -> bytes:
        """An SSH signature blob over ``data`` with ``algorithm`` (the key's best by default)."""
        algorithm = algorithm or self.algorithms()[0]
        if algorithm not in self.algorithms():
            raise KeyError_(f"a {self.kind} key cannot sign with {algorithm}")
        if self.kind == "ssh-ed25519":
            signature = ed25519.sign(self.ed25519_seed, data)
        elif self.rsa is not None:
            signature = self.rsa.sign(data, digest=_RSA_DIGESTS[algorithm])
        else:
            r, s = p256.sign(self.ecdsa, data)
            signature = mpint(r) + mpint(s)
        return string(algorithm) + string(signature)

    @classmethod
    def from_ed25519_seed(cls, seed: bytes, comment: str = "") -> PrivateKey:
        point = ed25519.public_key(seed)
        blob = string("ssh-ed25519") + string(point)
        return cls(
            "ssh-ed25519", PublicKey("ssh-ed25519", blob, ed25519=point), seed, comment=comment
        )

    @classmethod
    def from_rsa(cls, key: RSAPrivateKey, comment: str = "") -> PrivateKey:
        blob = string("ssh-rsa") + mpint(key.e) + mpint(key.n)
        return cls("ssh-rsa", PublicKey("ssh-rsa", blob, rsa=key.public), rsa=key, comment=comment)

    @classmethod
    def from_ecdsa(cls, d: int, comment: str = "") -> PrivateKey:
        point = p256.public_key(d)
        blob = string(_NISTP256) + string("nistp256") + string(p256.encode_point(point))
        return cls(_NISTP256, PublicKey(_NISTP256, blob, ecdsa=point), ecdsa=d, comment=comment)

    def public_line(self) -> str:
        """The ``authorized_keys`` / ``.pub`` line."""
        text = base64.b64encode(self.public.blob).decode("ascii")
        return f"{self.kind} {text}" + (f" {self.comment}" if self.comment else "")

    def __repr__(self) -> str:
        return f"PrivateKey({self.kind}, {fingerprint(self.public.blob)})"


_OPENSSH_MAGIC = b"openssh-key-v1\x00"
_KDF_CIPHERS = {"aes256-ctr": (32, 16), "aes128-ctr": (16, 16), "aes192-ctr": (24, 16)}


class PassphraseRequired(KeyError_):
    """The key file is encrypted and no (or the wrong) passphrase was given."""


def load_private(data: bytes | str, passphrase: bytes | str | None = None) -> PrivateKey:
    """Load an OpenSSH-format or PEM RSA private key.

    ``PassphraseRequired`` if it is encrypted and ``passphrase`` is missing
    or wrong; ``KeyError_`` for anything unusable.
    """
    raw = data.encode() if isinstance(data, str) else bytes(data)
    blocks = pem_blocks(raw)
    for label, der in blocks:
        if label == "OPENSSH PRIVATE KEY":
            secret = passphrase.encode() if isinstance(passphrase, str) else passphrase
            return _load_openssh(der, secret)
        if label in ("RSA PRIVATE KEY", "PRIVATE KEY"):
            if b"ENCRYPTED" in raw.split(b"-----END", 1)[0]:
                raise KeyError_("encrypted PEM keys are not supported; convert with ssh-keygen -p")
            try:
                return PrivateKey.from_rsa(load_private_key(der))
            except ValueError as exc:
                raise KeyError_(str(exc)) from None
        if label == "ENCRYPTED PRIVATE KEY":
            raise KeyError_("encrypted PKCS#8 keys are not supported; convert with ssh-keygen -p")
    raise KeyError_("no supported private key found (expected OpenSSH or PEM RSA format)")


def _load_openssh(blob: bytes, passphrase: bytes | None) -> PrivateKey:
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
        inner.string()
        secret = inner.string()
        key = PrivateKey.from_ed25519_seed(secret[:32], inner.text())
    elif kind == "ssh-rsa":
        n = inner.mpint()
        e = inner.mpint()
        d = inner.mpint()
        inner.mpint()  # iqmp
        p = inner.mpint()
        q = inner.mpint()
        key = PrivateKey.from_rsa(RSAPrivateKey(n=n, e=e, d=d, p=p, q=q), inner.text())
    elif kind == _NISTP256:
        inner.string()
        inner.string()
        key = PrivateKey.from_ecdsa(inner.mpint(), inner.text())
    else:
        raise KeyError_(f"unsupported private key type {kind!r}")
    return key


def _decrypt(cipher: str, kdf: str, options: bytes, data: bytes, passphrase: bytes) -> bytes:
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


_derived: dict[tuple[bytes, bytes, int, int], bytes] = {}


def _derive(passphrase: bytes, salt: bytes, length: int, rounds: int, kdf: object) -> bytes:
    """``bcrypt_pbkdf``, memoised: it is seconds in Python, and keys are reloaded per connection."""
    token = (hashlib.sha256(passphrase).digest(), salt, length, rounds)
    found = _derived.get(token)
    if found is None:
        found = _derived[token] = kdf(passphrase, salt, length, rounds)  # type: ignore[operator]
    return found


def encode_openssh_private(
    key: PrivateKey, passphrase: bytes | None = None, rounds: int = 16
) -> bytes:
    """Write ``key`` as an OpenSSH private-key file (encrypted with ``aes256-ctr`` if asked).

    Used to make test keys; the output is what ``ssh-keygen`` writes and
    ``ssh`` reads.
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
        body += string("nistp256") + string(p256.encode_point(key.public.ecdsa)) + mpint(key.ecdsa)
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


@dataclass(frozen=True, **SLOTS)
class HostKeyResult:
    """The outcome of a lookup: ``"match"``, ``"unknown"``, ``"changed"`` or ``"revoked"``."""

    status: str
    detail: str = ""


def host_pattern(host: str, port: int) -> str:
    """How ``known_hosts`` names a host: ``host`` on 22, ``[host]:port`` elsewhere."""
    return host if port == 22 else f"[{host}]:{port}"


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
    import fnmatch

    matched = False
    for pattern in pattern_field.split(","):
        negated = pattern.startswith("!")
        if fnmatch.fnmatchcase(name.lower(), pattern.lstrip("!").lower()):
            if negated:
                return False
            matched = True
    return matched


class KnownHosts:
    """The entries of one or more ``known_hosts`` files."""

    def __init__(self, lines: Iterable[str] = ()) -> None:
        self.entries: list[tuple[str, str, str, bytes]] = []  # marker, hosts, kind, blob
        for line in lines:
            self._add_line(line)

    @classmethod
    def load(cls, paths: Iterable[str]) -> KnownHosts:
        lines: list[str] = []
        for path in paths:
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    lines.extend(handle)
            except OSError:
                continue
        return cls(lines)

    def _add_line(self, line: str) -> None:
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
        """Is ``key`` the known key for ``host:port``?"""
        names = [host_pattern(host, port)]
        other_kinds = False
        changed = False
        for marker, hosts, kind, blob in self.entries:
            if not any(_matches(hosts, name) for name in names):
                continue
            if marker == "@revoked":
                if blob == key.blob:
                    return HostKeyResult("revoked", "the host key has been revoked")
                continue
            if marker:
                continue  # @cert-authority: host certificates are not supported
            if kind != key.kind:
                other_kinds = True
                continue
            if blob == key.blob:
                return HostKeyResult("match")
            changed = True
        if changed:
            return HostKeyResult("changed", "REMOTE HOST IDENTIFICATION HAS CHANGED")
        detail = "only keys of other types are known" if other_kinds else ""
        return HostKeyResult("unknown", detail)

    @staticmethod
    def line_for(host: str, port: int, key: PublicKey) -> str:
        return f"{host_pattern(host, port)} {key.kind} {base64.b64encode(key.blob).decode()}\n"
