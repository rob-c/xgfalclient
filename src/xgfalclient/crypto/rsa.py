"""RSA in pure Python — key loading and the PKCS#1 v1.5 signature GSI needs.

Python's integers are arbitrary-precision and ``pow(base, exp, mod)`` is
already the fast modular exponentiation, so the arithmetic costs nothing to
write. What is left is DER: PKCS#1 (``RSA PRIVATE KEY``) and PKCS#8
(``PRIVATE KEY``) for private keys, and ``SubjectPublicKeyInfo`` for public
ones. :mod:`xgfalclient.crypto.der` does the decoding.

Two warnings, both deliberate. This signs with :rfc:`8017` EMSA-PKCS1-v1_5
*with no DigestInfo* — the raw message inside the padding — because that is
what ``XrdCryptosslRSA::EncryptPrivate`` does for the GSI proof of
possession, and interoperating means matching it. And ``sign`` is not
constant-time; it is used once per connection on a random tag, not on
attacker-chosen data in a loop.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .._compat import SLOTS
from .der import (
    TAG_BIT_STRING,
    TAG_OCTET_STRING,
    DERError,
    Element,
    oid_string,
    parse,
    read_integer,
)

__all__ = [
    "RSAPrivateKey",
    "RSAPublicKey",
    "load_private_key",
    "load_public_key",
    "pem_blocks",
    "private_key_der",
    "private_key_pem",
    "RSA_OID",
]

#: ``rsaEncryption``, the algorithm identifier a PKCS#8 RSA key carries.
RSA_OID = "1.2.840.113549.1.1.1"

_DIGEST_PREFIXES = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def pem_blocks(data: bytes | str) -> list[tuple[str, bytes]]:
    """Every ``-----BEGIN X-----`` block in ``data`` as ``(label, DER)``.

    A GSI proxy is one file holding a certificate, a key, and the issuer
    chain, so splitting on labels is how everything downstream starts.
    """
    import base64

    text = data.decode("ascii", "replace") if isinstance(data, bytes) else data
    out: list[tuple[str, bytes]] = []
    label: str | None = None
    body: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if _pem_boundary(line, "BEGIN"):
            label, body = line[11:-5].strip(), []
        elif _pem_boundary(line, "END"):
            decoded = _decoded_pem(label, line[9:-5].strip(), body, base64.b64decode)
            if decoded is not None:
                out.append(decoded)
            label, body = None, []
        elif label is not None:
            body.append(line)
    return out


def _pem_boundary(line: str, kind: str) -> bool:
    return line.startswith(f"-----{kind} ") and line.endswith("-----")


def _decoded_pem(
    label: str | None, end: str, body: list[str], decode: object
) -> tuple[str, bytes] | None:
    if label is None or end != label:
        return None
    try:
        return label, decode("".join(body))  # type: ignore[operator]
    except ValueError:  # a corrupt block must not lose the good ones
        return None


@dataclass(frozen=True, **SLOTS)
class RSAPublicKey:
    """An RSA public key: modulus and public exponent."""

    n: int
    e: int

    @property
    def size(self) -> int:
        """The modulus length in bytes — the size of every signature block."""
        return (self.n.bit_length() + 7) // 8

    def verify(self, message: bytes, signature: bytes, *, digest: str | None = None) -> bool:
        """True if ``signature`` is this key's PKCS#1 v1.5 signature over ``message``."""
        if len(signature) != self.size:
            return False
        recovered = pow(int.from_bytes(signature, "big"), self.e, self.n)
        expected = _pkcs1_v15_pad(message, self.size, digest)
        return recovered.to_bytes(self.size, "big") == expected

    def __repr__(self) -> str:
        return f"RSAPublicKey(bits={self.n.bit_length()}, e={self.e})"


@dataclass(frozen=True, **SLOTS)
class RSAPrivateKey:
    """An RSA private key. ``p``/``q`` enable the CRT path when present."""

    n: int
    e: int
    d: int
    p: int = 0
    q: int = 0

    @property
    def size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def public(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)

    @classmethod
    def generate(cls, bits: int = 2048, *, e: int = 65537) -> RSAPrivateKey:
        """A fresh key pair.

        Pure Python, so a 2048-bit key takes seconds — this is here to make
        proxies for tests and one-off tooling, not to replace ``openssl``
        in anything that mints keys at volume.
        """
        if bits < 512 or bits % 2:
            raise ValueError("RSA key size must be an even number of bits, at least 512")
        while True:
            p = _prime(bits // 2, e)
            q = _prime(bits - bits // 2, e)
            if p == q:
                continue
            n = p * q
            if n.bit_length() != bits:
                continue
            return cls(n=n, e=e, d=pow(e, -1, (p - 1) * (q - 1)), p=p, q=q)

    def sign(self, message: bytes, *, digest: str | None = None) -> bytes:
        """PKCS#1 v1.5 signature over ``message``.

        ``digest=None`` signs the message bytes with no DigestInfo wrapper,
        which is what GSI's proof of possession expects; naming a hash
        (``"sha256"``) gives the ordinary :rfc:`8017` construction.
        """
        block = _pkcs1_v15_pad(message, self.size, digest)
        return self._power(int.from_bytes(block, "big")).to_bytes(self.size, "big")

    def _power(self, value: int) -> int:
        """``value ** d mod n``, by CRT when the primes are known."""
        if self.p and self.q:
            mp = pow(value % self.p, self.d % (self.p - 1), self.p)
            mq = pow(value % self.q, self.d % (self.q - 1), self.q)
            coefficient = pow(self.q, -1, self.p)
            return (mq + self.q * ((coefficient * (mp - mq)) % self.p)) % self.n
        return pow(value, self.d, self.n)

    def __repr__(self) -> str:
        return f"RSAPrivateKey(bits={self.n.bit_length()}, d=<redacted>)"


_SMALL_PRIMES = (
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
)


def _probably_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin. ``rounds`` random bases put the error below 2^-80."""
    small_result = _small_prime_result(n)
    if small_result is not None:
        return small_result
    import secrets

    d, r = _factor_twos(n - 1)
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        if _composite_witness(a, d, r, n):
            return False
    return True


def _small_prime_result(n: int) -> bool | None:
    if n < 2:
        return False
    for small in _SMALL_PRIMES:
        if n == small:
            return True
        if n % small == 0:
            return False
    return None


def _factor_twos(value: int) -> tuple[int, int]:
    power = 0
    while not value & 1:
        value >>= 1
        power += 1
    return value, power


def _composite_witness(base: int, odd: int, power: int, modulus: int) -> bool:
    value = pow(base, odd, modulus)
    if value in (1, modulus - 1):
        return False
    for _ in range(power - 1):
        value = value * value % modulus
        if value == modulus - 1:
            return False
    return True


def _prime(bits: int, e: int) -> int:
    """A random prime of exactly ``bits`` bits, coprime to ``e``."""
    import secrets

    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if (candidate - 1) % e and _probably_prime(candidate):
            return candidate


def _pkcs1_v15_pad(message: bytes, size: int, digest: str | None) -> bytes:
    """``0x00 0x01 0xFF... 0x00 || [DigestInfo] || message``."""
    if digest is not None:
        name = digest.lower().replace("-", "")
        prefix = _DIGEST_PREFIXES.get(name)
        if prefix is None:
            raise ValueError(f"unsupported digest {digest!r} for PKCS#1 v1.5")
        message = prefix + hashlib.new(name, message).digest()
    if len(message) + 11 > size:
        raise ValueError(f"message of {len(message)} bytes does not fit a {size}-byte key")
    return b"\x00\x01" + b"\xff" * (size - len(message) - 3) + b"\x00" + message


def _private_from_pkcs1(element: Element) -> RSAPrivateKey:
    """``RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, ... }``."""
    fields = element.children()
    if len(fields) < 6:
        raise DERError(f"PKCS#1 private key has {len(fields)} fields, expected at least 6")
    values = [read_integer(f) for f in fields[:6]]
    if values[0] != 0:
        raise DERError(f"multi-prime RSA (version {values[0]}) is not supported")
    return RSAPrivateKey(n=values[1], e=values[2], d=values[3], p=values[4], q=values[5])


def load_private_key(data: bytes | str, label: str | None = None) -> RSAPrivateKey:
    """Load an RSA private key from PEM or raw DER.

    Accepts PKCS#1 (``RSA PRIVATE KEY``) and unencrypted PKCS#8
    (``PRIVATE KEY``). Encrypted keys are refused by name rather than
    failing as a parse error, because the fix is to decrypt them.
    """
    blocks = pem_blocks(data)
    if not blocks:
        der = data if isinstance(data, bytes) else data.encode()
        return _private_from_der(der)
    for name, der in blocks:
        if label is not None and name != label:
            continue
        if name == "ENCRYPTED PRIVATE KEY":
            raise DERError("the private key is encrypted; decrypt it first")
        if name in ("RSA PRIVATE KEY", "PRIVATE KEY"):
            return _private_from_der(der)
    raise DERError("no RSA private key in the PEM given")


def _private_from_der(der: bytes) -> RSAPrivateKey:
    element, _ = parse(der)
    fields = element.children()
    if fields and fields[0].tag == TAG_OCTET_STRING:  # PKCS#8, key nested inside
        raise DERError("malformed PKCS#8: version must precede the algorithm")
    if len(fields) >= 3 and fields[1].tag == 0x30 and fields[2].tag == TAG_OCTET_STRING:
        algorithm = oid_string(fields[1].children()[0])
        if algorithm != RSA_OID:
            raise DERError(f"private key is {algorithm}, not RSA")
        inner, _ = parse(fields[2].value)
        return _private_from_pkcs1(inner)
    return _private_from_pkcs1(element)


def load_public_key(data: bytes | str) -> RSAPublicKey:
    """Load an RSA public key from a ``SubjectPublicKeyInfo`` or PKCS#1 body."""
    blocks = pem_blocks(data)
    der = blocks[0][1] if blocks else (data if isinstance(data, bytes) else data.encode())
    element, _ = parse(der)
    fields = element.children()
    if len(fields) == 2 and fields[1].tag == TAG_BIT_STRING:
        algorithm = oid_string(fields[0].children()[0])
        if algorithm != RSA_OID:
            raise DERError(f"public key is {algorithm}, not RSA")
        return public_key_from_bitstring(fields[1])
    if len(fields) == 2:
        return RSAPublicKey(read_integer(fields[0]), read_integer(fields[1]))
    raise DERError("not an RSA public key")


def public_key_from_bitstring(element: Element) -> RSAPublicKey:
    """Decode the ``RSAPublicKey`` inside a ``subjectPublicKey`` BIT STRING."""
    if element.tag != TAG_BIT_STRING or not element.value:
        raise DERError("expected a non-empty BIT STRING")
    if element.value[0]:
        raise DERError(f"subjectPublicKey has {element.value[0]} unused bits")
    inner, _ = parse(element.value[1:])
    fields = inner.children()
    if len(fields) != 2:
        raise DERError(f"RSAPublicKey has {len(fields)} fields, expected 2")
    return RSAPublicKey(read_integer(fields[0]), read_integer(fields[1]))


def private_key_der(key: RSAPrivateKey) -> bytes:
    """PKCS#1 ``RSAPrivateKey`` DER, with the CRT fields OpenSSL expects."""
    from .der import integer, sequence

    if not (key.p and key.q):
        raise ValueError("encoding a private key needs its primes")
    return sequence(
        integer(0),
        integer(key.n),
        integer(key.e),
        integer(key.d),
        integer(key.p),
        integer(key.q),
        integer(key.d % (key.p - 1)),
        integer(key.d % (key.q - 1)),
        integer(pow(key.q, -1, key.p)),
    )


def private_key_pem(key: RSAPrivateKey) -> bytes:
    """``-----BEGIN RSA PRIVATE KEY-----``: the unencrypted form proxies use."""
    import base64
    import textwrap

    body = "\n".join(textwrap.wrap(base64.b64encode(private_key_der(key)).decode("ascii"), 64))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n".encode()
