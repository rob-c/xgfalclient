"""The throwaway PKI: files on disk, TLS contexts, and OpenSSL-compatible CA hashes."""

from __future__ import annotations

import os
import shutil
import ssl
import subprocess
from pathlib import Path

import pytest

from xgfalclient.crypto import x509
from xgfalclient.testing import pki as pki_module
from xgfalclient.testing.pki import PKI, create_pki, subject_hash, test_key


def test_layout(pki: PKI) -> None:
    for path in (pki.ca_file, pki.host_cert_path, pki.user_cert_path, pki.proxy_path):
        assert path.exists()
    assert oct(pki.host_key_path.stat().st_mode & 0o777) == "0o600"
    assert oct(pki.proxy_path.stat().st_mode & 0o777) == "0o600"
    hashed = pki.ca_dir / f"{subject_hash(pki.ca.subject.encoded())}.0"
    assert hashed.read_bytes() == pki.ca.pem()
    policy = hashed.with_suffix(".signing_policy").read_text()
    assert policy == (
        "access_id_CA X509 '/DC=org/DC=xgfal/CN=xgfal Test CA'\n"
        "pos_rights globus CA:sign\n"
        "cond_subjects globus '\"/DC=org/DC=xgfal/*\"'\n"
    )
    assert pki.environment() == {
        "X509_USER_PROXY": str(pki.proxy_path),
        "X509_CERT_DIR": str(pki.ca_dir),
    }
    assert pki.credential().certificate.is_proxy
    assert pki.user_credential.identity == str(pki.user.subject)


def test_key_cache() -> None:
    assert test_key(3) is test_key(3)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")
def test_subject_hash_matches_openssl(pki: PKI) -> None:
    result = subprocess.run(
        ["openssl", "x509", "-hash", "-noout", "-in", str(pki.ca_file)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == subject_hash(pki.ca.subject.encoded())


def test_canonical_form_folds_case_and_space() -> None:
    upper = x509.encode_name((("CN", "  Some   CA "),))
    lower = x509.encode_name((("CN", "some ca"),))
    assert subject_hash(upper) == subject_hash(lower)


def test_tls_contexts_interoperate(pki: PKI) -> None:
    server = pki.server_context()
    assert server.verify_mode in (ssl.CERT_REQUIRED, ssl.CERT_NONE)
    assert pki.server_context(require_client=False).verify_mode == ssl.CERT_NONE
    client = pki.client_context()
    capath = ssl.create_default_context(capath=str(pki.ca_dir))
    anonymous = pki.server_context(require_client=False)
    for context, responder in ((client, server), (capath, anonymous)):
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        c = context.wrap_bio(incoming, outgoing, server_hostname="localhost")
        s = responder.wrap_bio(s_in, s_out, server_side=True)
        done = set()
        for _ in range(10):
            for name, side, out, peer_in in (("c", c, outgoing, s_in), ("s", s, s_out, incoming)):
                try:
                    side.do_handshake()
                    done.add(name)
                except ssl.SSLWantReadError:
                    pass
                peer_in.write(out.read())
            if done == {"c", "s"}:
                break
        assert done == {"c", "s"}


def test_proxy_variants_and_custom_paths(pki: PKI, tmp_path: Path) -> None:
    target = tmp_path / "custom"
    path = pki.proxy("rfc", lifetime=60, path=target, key_slot=4)
    assert path == target
    credential = x509.load_credential(str(path))
    assert credential.key == test_key(4)
    assert credential.certificate.not_after <= credential.certificate.not_before + 60 + 300 + 1
    nested = pki.proxy("rfc", issuer=credential, key_slot=5, path=tmp_path / "nested")
    chain = x509.load_credential(str(nested)).chain
    assert len(chain) == 3 and chain[0].issuer.rdns == chain[1].subject.rdns
    legacy = x509.load_credential(str(pki.proxy("legacy", lifetime=60)))
    assert legacy.certificate.is_legacy_proxy
    # The custom proxy, rather than the default one, when a path is named.
    assert pki.credential(path).key == test_key(4)
    assert pki.client_context(proxy=path).verify_mode == ssl.CERT_REQUIRED


def test_custom_hosts(tmp_path: Path) -> None:
    other = create_pki(tmp_path, hosts=("se.example.org", "10.0.0.1"), host_cn="se.example.org")
    assert other.host.subject.cn == "se.example.org"
    from xgfalclient.crypto.gsi import dns_names

    assert dns_names(other.host) == ["se.example.org"]
    assert os.path.isdir(other.ca_dir)


def test_keys_module_is_frozen() -> None:
    assert len(pki_module.KEYS) == 8
