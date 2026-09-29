"""SSH key parsing, signing, verification and known_hosts."""

from __future__ import annotations

import base64
import os

import pytest

from xgfalclient.crypto import sshkeys
from xgfalclient.crypto.rsa import RSAPrivateKey
from xgfalclient.crypto.sshkeys import (
    KeyError_,
    KnownHosts,
    PassphraseRequired,
    PrivateKey,
    Reader,
    encode_openssh_private,
    fingerprint,
    host_pattern,
    load_private,
    mpint,
    parse_public_blob,
    string,
    uint32,
)
from xgfalclient.testing._keys import KEY_0


def _rsa_key() -> RSAPrivateKey:
    from xgfalclient.crypto.rsa import load_private_key, pem_blocks

    der = next(der for label, der in pem_blocks(KEY_0) if label == "RSA PRIVATE KEY")
    return load_private_key(der)


def _make_key(maker: str) -> PrivateKey:
    if maker == "ed25519":
        return PrivateKey.from_ed25519_seed(os.urandom(32))
    if maker == "rsa":
        return PrivateKey.from_rsa(_rsa_key())
    return PrivateKey.from_ecdsa(0x1234567890ABCDEF1234567890ABCDEF)


def _openssh_container(inner_key: bytes, check: tuple[int, int] = (0, 0)) -> bytes:
    import struct

    check_bytes = struct.pack(">II", *check) if check != (0, 0) else os.urandom(4) * 2
    body = check_bytes + inner_key + string("")
    while len(body) % 8:
        body += bytes([1])
    pub = string("ssh-ed25519") + string(bytes(32))
    return (
        sshkeys._OPENSSH_MAGIC
        + string("none")
        + string("none")
        + string(b"")
        + uint32(1)
        + string(pub)
        + string(body)
    )


# ---------------------------------------------------------------------------
# Wire types
# ---------------------------------------------------------------------------


def test_wire_primitives() -> None:
    assert uint32(1) == b"\x00\x00\x00\x01"
    assert string("hi") == b"\x00\x00\x00\x02hi"
    assert string(b"hi") == b"\x00\x00\x00\x02hi"
    assert mpint(0) == b"\x00\x00\x00\x00"
    # A high bit set forces a leading zero byte (two's complement positivity).
    assert mpint(0x80) == b"\x00\x00\x00\x02\x00\x80"
    assert mpint(1) == b"\x00\x00\x00\x01\x01"


def test_reader_all_types() -> None:
    data = uint32(7) + string(b"abc") + b"\x01" + b"\x00" + struct_u64(2**40)
    reader = Reader(data)
    assert reader.uint32() == 7
    assert reader.string() == b"abc"
    assert reader.boolean() is True
    assert reader.boolean() is False
    assert reader.uint64() == 2**40
    assert reader.remaining == 0
    with pytest.raises(KeyError_, match="truncated"):
        reader.byte()
    with pytest.raises(KeyError_, match="truncated"):
        Reader(b"\x00").take(-1)


def test_reader_name_list_and_rest_and_text() -> None:
    reader = Reader(string("a,b,c") + b"tail")
    assert reader.name_list() == ["a", "b", "c"]
    assert reader.rest() == b"tail"
    assert Reader(string("")).name_list() == []
    assert Reader(string(b"\xff\xfe")).text() == "��"  # replaced
    assert Reader(mpint(0x1234)).mpint() == 0x1234


def struct_u64(value: int) -> bytes:
    import struct

    return struct.pack(">Q", value)


# ---------------------------------------------------------------------------
# Public keys: parse and verify
# ---------------------------------------------------------------------------


def test_ed25519_public_and_sign() -> None:
    key = PrivateKey.from_ed25519_seed(os.urandom(32), "me@host")
    assert key.kind == "ssh-ed25519"
    assert key.algorithms() == ("ssh-ed25519",)
    sig = key.sign(b"payload")
    assert key.public.verify("ssh-ed25519", b"payload", sig)
    # A round-trip through the blob parser.
    pub = parse_public_blob(key.public.blob)
    assert pub.verify("ssh-ed25519", b"payload", sig)
    assert not pub.verify("ssh-ed25519", b"other", sig)
    assert key.public_line().startswith("ssh-ed25519 ")
    assert key.public_line().endswith("me@host")
    assert "SHA256:" in repr(key)
    # Without a comment the line is just type and key.
    assert len(PrivateKey.from_ed25519_seed(os.urandom(32)).public_line().split()) == 2


def test_rsa_public_and_sign_algorithms() -> None:
    key = PrivateKey.from_rsa(_rsa_key(), "rsa@host")
    assert key.kind == "ssh-rsa"
    assert key.algorithms() == ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa")
    for alg in key.algorithms():
        sig = key.sign(b"data", alg)
        assert key.public.verify(alg, b"data", sig)
    # A default signature uses the strongest algorithm.
    assert key.public.verify("rsa-sha2-512", b"data", key.sign(b"data"))
    with pytest.raises(KeyError_, match="cannot sign"):
        key.sign(b"data", "ecdsa-sha2-nistp256")


def test_ecdsa_public_and_sign() -> None:
    key = PrivateKey.from_ecdsa(0x1234567890ABCDEF, "ec@host")
    assert key.kind == "ecdsa-sha2-nistp256"
    sig = key.sign(b"data")
    assert key.public.verify("ecdsa-sha2-nistp256", b"data", sig)
    # A malformed inner signature blob fails cleanly.
    assert not key.public.verify(
        "ecdsa-sha2-nistp256", b"data", string("ecdsa-sha2-nistp256") + string(b"\x00")
    )


def test_public_verify_rejects_mismatches() -> None:
    key = PrivateKey.from_ed25519_seed(os.urandom(32))
    sig = key.sign(b"x")
    # Truncated blob, wrong algorithm name, and an algorithm the key cannot do.
    assert not key.public.verify("ssh-ed25519", b"x", b"\x00\x00")
    assert not key.public.verify("rsa-sha2-256", b"x", sig)
    # A blob that names the algorithm asked for, but one this key cannot verify.
    forged = string("rsa-sha2-256") + sig[len(string("ssh-ed25519")) :]
    assert not key.public.verify("rsa-sha2-256", b"x", forged)


def test_rsa_verify_pads_a_short_signature() -> None:
    # OpenSSH drops a signature's leading zero byte; b"m386" is a message whose
    # rsa-sha2-256 signature under KEY_0 begins with one.
    key = PrivateKey.from_rsa(_rsa_key())
    reader = Reader(key.sign(b"m386", "rsa-sha2-256"))
    reader.text()
    full = reader.string()
    assert full[0] == 0
    short = string("rsa-sha2-256") + string(full[1:])
    assert key.public.verify("rsa-sha2-256", b"m386", short)


def test_parse_public_blob_errors() -> None:
    with pytest.raises(KeyError_, match="32 bytes"):
        parse_public_blob(string("ssh-ed25519") + string(b"short"))
    with pytest.raises(KeyError_, match="curve does not match"):
        parse_public_blob(string("ecdsa-sha2-nistp256") + string("nistp999") + string(b"\x04"))
    with pytest.raises(KeyError_, match="not on P-256"):
        parse_public_blob(
            string("ecdsa-sha2-nistp256") + string("nistp256") + string(b"\x04" + b"\x00" * 64)
        )
    with pytest.raises(KeyError_, match="unsupported public key type"):
        parse_public_blob(string("ssh-dss") + string(b"x"))


def test_parse_public_blob_rsa_and_ecdsa() -> None:
    rsa = PrivateKey.from_rsa(_rsa_key())
    parsed = parse_public_blob(rsa.public.blob)
    assert parsed.kind == "ssh-rsa" and parsed.rsa is not None
    assert parsed.verify("rsa-sha2-256", b"x", rsa.sign(b"x", "rsa-sha2-256"))
    ec = PrivateKey.from_ecdsa(0x1234567890ABCDEF1234567890ABCDEF)
    parsed_ec = parse_public_blob(ec.public.blob)
    assert parsed_ec.ecdsa is not None
    assert parsed_ec.verify("ecdsa-sha2-nistp256", b"x", ec.sign(b"x"))


def test_fingerprint() -> None:
    key = PrivateKey.from_ed25519_seed(bytes(32))
    fp = fingerprint(key.public.blob)
    assert fp.startswith("SHA256:") and "=" not in fp


# ---------------------------------------------------------------------------
# Private key files
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("maker", ["ed25519", "rsa", "ecdsa"])
def test_openssh_private_round_trip_plain(maker: str) -> None:
    key = _make_key(maker)
    blob = encode_openssh_private(key)
    loaded = load_private(blob)
    assert loaded.kind == key.kind
    assert loaded.public.blob == key.public.blob
    # It signs the same as the original.
    assert loaded.public.verify(loaded.algorithms()[0], b"m", loaded.sign(b"m"))


def test_openssh_private_round_trip_encrypted() -> None:
    key = PrivateKey.from_ed25519_seed(os.urandom(32))
    blob = encode_openssh_private(key, passphrase=b"hunter2", rounds=1)
    with pytest.raises(PassphraseRequired):
        load_private(blob)
    with pytest.raises(PassphraseRequired, match="wrong passphrase"):
        load_private(blob, "wrong-one")
    loaded = load_private(blob, "hunter2")
    assert loaded.public.blob == key.public.blob
    # Bytes and str passphrases are equivalent.
    assert load_private(blob, b"hunter2").public.blob == key.public.blob


def test_load_pem_rsa() -> None:
    loaded = load_private(KEY_0)
    assert loaded.kind == "ssh-rsa"
    assert loaded.public.verify("rsa-sha2-256", b"x", loaded.sign(b"x", "rsa-sha2-256"))


def test_load_private_rejects_unusable() -> None:
    with pytest.raises(KeyError_, match="no supported private key"):
        load_private(b"not a key at all")
    # A valid RSA block preceded by an ENCRYPTED marker: the block parses, but
    # the loader refuses it (the classic Proc-Type header lives before the body).
    with pytest.raises(KeyError_, match="encrypted PEM"):
        load_private("Comment: Proc-Type: 4,ENCRYPTED\n" + KEY_0)
    with pytest.raises(KeyError_, match="encrypted PKCS#8"):
        load_private(
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
        )
    # A PRIVATE KEY block whose DER is garbage propagates as KeyError_.
    with pytest.raises(KeyError_):
        load_private("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")


def test_load_private_skips_unrelated_blocks() -> None:
    # A leading CERTIFICATE block is stepped over to reach the real key.
    ed = PrivateKey.from_ed25519_seed(os.urandom(32))
    combined = (
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        + encode_openssh_private(ed)
    )
    loaded = load_private(combined)
    assert loaded.public.blob == ed.public.blob


def test_openssh_loader_edge_errors() -> None:
    with pytest.raises(KeyError_, match="not an openssh-key-v1"):
        sshkeys._load_openssh(b"bogus", None)
    # A well-formed header but an unknown inner key type.
    blob = _openssh_container(string("ssh-dss") + string(b"x"))
    with pytest.raises(KeyError_, match="unsupported private key type"):
        sshkeys._load_openssh(blob, None)
    # Mismatched check integers on an unencrypted key mean corruption.
    corrupt = _openssh_container(b"", check=(1, 2))
    with pytest.raises(KeyError_, match="corrupt private key"):
        sshkeys._load_openssh(corrupt, None)


def test_openssh_multikey_and_bad_cipher() -> None:
    body = sshkeys._OPENSSH_MAGIC + string("none") + string("none") + string(b"") + uint32(2)
    with pytest.raises(KeyError_, match="single-key"):
        sshkeys._load_openssh(body, None)


def test_decrypt_rejects_unknown_cipher() -> None:
    PrivateKey.from_ed25519_seed(os.urandom(32))
    with pytest.raises(KeyError_, match="unsupported key encryption"):
        sshkeys._decrypt("aes256-gcm@openssh.com", "bcrypt", b"", b"data", b"pw")
    with pytest.raises(KeyError_, match="unsupported key encryption"):
        sshkeys._decrypt("aes256-ctr", "scrypt", b"", b"data", b"pw")


# ---------------------------------------------------------------------------
# known_hosts
# ---------------------------------------------------------------------------


def test_host_pattern() -> None:
    assert host_pattern("h", 22) == "h"
    assert host_pattern("h", 2222) == "[h]:2222"


def test_known_hosts_match_unknown_changed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    key = PrivateKey.from_ed25519_seed(os.urandom(32)).public
    other = PrivateKey.from_ed25519_seed(os.urandom(32)).public
    line = KnownHosts.line_for("host", 22, key)
    known = KnownHosts([line])
    assert known.check("host", 22, key).status == "match"
    assert known.check("elsewhere", 22, key).status == "unknown"
    assert known.check("host", 22, other).status == "changed"


def test_known_hosts_other_key_type() -> None:
    ed = PrivateKey.from_ed25519_seed(os.urandom(32)).public
    rsa = PrivateKey.from_rsa(_rsa_key()).public
    known = KnownHosts([KnownHosts.line_for("host", 22, rsa)])
    result = known.check("host", 22, ed)
    assert result.status == "unknown" and "other types" in result.detail


def test_known_hosts_hashed_entry() -> None:
    import hmac

    key = PrivateKey.from_ed25519_seed(os.urandom(32)).public
    salt = os.urandom(20)
    digest = hmac.digest(salt, b"host", "sha1")
    hashed = "|1|" + base64.b64encode(salt).decode() + "|" + base64.b64encode(digest).decode()
    line = f"{hashed} {key.kind} {base64.b64encode(key.blob).decode()}\n"
    known = KnownHosts([line])
    assert known.check("host", 22, key).status == "match"
    assert known.check("nothost", 22, key).status == "unknown"
    # A malformed hashed field never matches.
    bad = KnownHosts(["|1|not-base64 ssh-ed25519 " + base64.b64encode(key.blob).decode()])
    assert bad.check("host", 22, key).status == "unknown"


def test_known_hosts_revoked_and_cert_authority() -> None:
    key = PrivateKey.from_ed25519_seed(os.urandom(32)).public
    revoked = "@revoked " + KnownHosts.line_for("host", 22, key)
    known = KnownHosts([revoked])
    assert known.check("host", 22, key).status == "revoked"
    # A different key under @revoked does not match; falls through to unknown.
    other = PrivateKey.from_ed25519_seed(os.urandom(32)).public
    assert known.check("host", 22, other).status == "unknown"
    # @cert-authority markers are ignored (host certs unsupported).
    ca = "@cert-authority " + KnownHosts.line_for("host", 22, key)
    assert KnownHosts([ca]).check("host", 22, key).status == "unknown"


def test_known_hosts_glob_and_negation() -> None:
    key = PrivateKey.from_ed25519_seed(os.urandom(32)).public
    line = f"*.example.org,!secret.example.org {key.kind} {base64.b64encode(key.blob).decode()}\n"
    known = KnownHosts([line])
    assert known.check("web.example.org", 22, key).status == "match"
    assert known.check("secret.example.org", 22, key).status == "unknown"


def test_known_hosts_load_and_skips(tmp_path) -> None:  # type: ignore[no-untyped-def]
    key = PrivateKey.from_ed25519_seed(os.urandom(32)).public
    path = tmp_path / "known_hosts"
    path.write_text(
        "# a comment\n"
        "\n"
        "tooshort fields\n"
        "host ssh-ed25519 not-valid-base64!!!\n" + KnownHosts.line_for("host", 22, key)
    )
    known = KnownHosts.load([str(path), str(tmp_path / "missing")])
    assert known.check("host", 22, key).status == "match"
