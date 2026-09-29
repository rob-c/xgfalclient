"""Credential store, discovery order, and the TLS context cache."""

from __future__ import annotations

import errno
import os
import ssl
from pathlib import Path

import pytest

from conftest import REAL_UID, UNUSED_UID
from xgfalclient import GError
from xgfalclient.creds import (
    BEARER,
    PASSWD,
    X509_CERT,
    X509_KEY,
    Credential,
    CredentialStore,
    TLSContexts,
    X509Credential,
    find_bearer_token,
    find_ca_path,
    find_x509,
    seed_options,
)
from xgfalclient.options import Options
from xgfalclient.testing.pki import PKI


def test_credential_repr_redacts_secrets() -> None:
    assert repr(Credential(BEARER, "secret")) == "Credential('BEARER', <redacted>)"
    assert repr(Credential(PASSWD, "pw")) == "Credential('PASSWD', <redacted>)"
    assert repr(Credential(X509_CERT, "/p")) == "Credential('X509_CERT', '/p')"
    assert Credential(BEARER, "a") == Credential(BEARER, "a")
    assert Credential(BEARER, "a") != Credential(BEARER, "b")
    assert Credential(BEARER, "a") != "a"
    assert len({Credential(BEARER, "a"), Credential(BEARER, "a")}) == 1


def test_store_longest_prefix_wins() -> None:
    store = CredentialStore()
    store.set("https://se/", Credential(BEARER, "host"))
    store.set("https://se/data/", Credential(BEARER, "dir"))
    store.set("https://se/data/", Credential(X509_CERT, "cert"))
    assert store.get(BEARER, "https://se/data/f") == ("dir", "https://se/data/")
    assert store.get(BEARER, "https://se/other") == ("host", "https://se/")
    assert store.get(BEARER, "https://elsewhere/") == ("", "")
    assert len(store) == 3
    assert store.delete(BEARER, "https://se/data/") is True
    assert store.delete(BEARER, "https://never/") is False
    assert store.get(BEARER, "https://se/data/f") == ("host", "https://se/")
    store.clean()
    assert len(store) == 0
    # A shorter prefix seen after a longer one does not displace it.
    store.set("https://se/data/", Credential(BEARER, "dir"))
    store.set("https://se/", Credential(BEARER, "host"))
    assert store.get(BEARER, "https://se/data/f") == ("dir", "https://se/data/")


def test_x509_from_store_and_options(tmp_path: Path) -> None:
    options = Options(load_system=False)
    store = CredentialStore()
    store.set("davs://se/", Credential(X509_CERT, "/c"))
    assert find_x509(options, store, "davs://se/f", {}) == X509Credential("/c", "/c")
    store.set("davs://se/", Credential(X509_KEY, "/k"))
    assert find_x509(options, store, "davs://se/f", {}) == X509Credential("/c", "/k")
    options.set_string("X509", "CERT", "/oc")
    assert find_x509(options, None, "", {}) == X509Credential("/oc", "/oc")
    options.set_string("X509", "KEY", "/ok")
    assert find_x509(options, None, "", {}) == X509Credential("/oc", "/ok")
    assert X509Credential("/a", "/a").is_combined
    assert not X509Credential("/a", "/b").is_combined


def test_x509_discovery_order(tmp_path: Path) -> None:
    options = Options(load_system=False)
    proxy = tmp_path / "proxy"
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    home = tmp_path / "home"
    (home / ".globus").mkdir(parents=True)
    for path in (
        proxy,
        cert,
        key,
        home / ".globus" / "usercert.pem",
        home / ".globus" / "userkey.pem",
    ):
        path.write_text("x")
    env = {"X509_USER_PROXY": str(proxy), "X509_USER_CERT": str(cert), "X509_USER_KEY": str(key)}
    assert find_x509(options, None, "", {**env, "HOME": str(home)}).cert == str(proxy)  # type: ignore[union-attr]
    env["X509_USER_PROXY"] = str(tmp_path / "stale")
    found = find_x509(options, None, "", {**env, "HOME": str(home)})
    assert found == X509Credential(str(cert), str(key))
    found = find_x509(options, None, "", {"HOME": str(home)})
    assert found is not None and found.cert.endswith("usercert.pem")
    assert find_x509(options, None, "", {"HOME": str(tmp_path / "nobody")}) is None


def test_x509_discovery_needs_both_halves(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    options = Options(load_system=False)
    cert = tmp_path / "c.pem"
    cert.write_text("x")
    (tmp_path / ".globus").mkdir()
    (tmp_path / ".globus" / "usercert.pem").write_text("x")
    # A certificate without its key, from either place, is no credential.
    env = {"X509_USER_CERT": str(cert), "X509_USER_KEY": str(tmp_path / "no-key.pem")}
    assert find_x509(options, None, "", {**env, "HOME": str(tmp_path)}) is None
    # With no HOME in the environment given, ~ is where .globus is looked for.
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".globus" / "userkey.pem").write_text("x")
    found = find_x509(options, None, "", {})
    assert found == X509Credential(
        str(tmp_path / ".globus" / "usercert.pem"), str(tmp_path / ".globus" / "userkey.pem")
    )


def test_x509_default_proxy_location(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    proxy = Path(f"/tmp/x509up_u{UNUSED_UID}")
    try:
        proxy.write_text("x")
        found = find_x509(Options(load_system=False), None, "", {"HOME": str(tmp_path)})
        assert found == X509Credential(str(proxy), str(proxy))
    finally:
        proxy.unlink()


def test_x509_uses_real_environment_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    proxy = tmp_path / "p"
    proxy.write_text("x")
    monkeypatch.setenv("X509_USER_PROXY", str(proxy))
    assert find_x509(Options(load_system=False)) == X509Credential(str(proxy), str(proxy))


def test_bearer_token_discovery(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    options = Options(load_system=False)
    store = CredentialStore()
    assert find_bearer_token(options, store, "https://se/f", {}) is None
    token_file = tmp_path / "tok"
    token_file.write_text("  from-file \n")
    assert (
        find_bearer_token(options, None, "", {"BEARER_TOKEN_FILE": str(token_file)}) == "from-file"
    )
    assert find_bearer_token(options, None, "", {"BEARER_TOKEN_FILE": str(tmp_path / "no")}) is None
    empty = tmp_path / "empty"
    empty.write_text("\n")
    assert find_bearer_token(options, None, "", {"BEARER_TOKEN_FILE": str(empty)}) is None
    runtime = tmp_path / "run"
    runtime.mkdir()
    (runtime / f"bt_u{UNUSED_UID}").write_text("from-runtime")
    assert find_bearer_token(options, None, "", {"XDG_RUNTIME_DIR": str(runtime)}) == "from-runtime"
    assert find_bearer_token(options, None, "", {"XDG_RUNTIME_DIR": str(tmp_path)}) is None
    assert find_bearer_token(options, None, "", {"BEARER_TOKEN": " inline "}) == "inline"
    options.set_string("BEARER", "TOKEN", "configured")
    assert find_bearer_token(options, None, "", {"BEARER_TOKEN": "inline"}) == "configured"
    store.set("https://se/", Credential(BEARER, "stored"))
    assert find_bearer_token(options, store, "https://se/f", {}) == "stored"
    monkeypatch.setenv("BEARER_TOKEN", "ambient")
    assert find_bearer_token(Options(load_system=False)) == "ambient"


def test_bearer_token_tmp_fallback() -> None:
    path = Path(f"/tmp/bt_u{UNUSED_UID}")
    try:
        path.write_text("tmp-token")
        assert find_bearer_token(Options(load_system=False), None, "", {}) == "tmp-token"
    finally:
        path.unlink()


def test_ca_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert find_ca_path({"X509_CERT_DIR": str(tmp_path)}) == str(tmp_path)
    monkeypatch.setattr("os.path.isdir", lambda path: path == "/etc/grid-security/certificates")
    assert find_ca_path({}) == "/etc/grid-security/certificates"
    monkeypatch.setattr("os.path.isdir", lambda path: False)
    assert find_ca_path({}) is None
    monkeypatch.setenv("X509_CERT_DIR", "/x")
    assert find_ca_path() == "/x"


def test_tls_contexts_are_cached_and_configured(pki: PKI) -> None:
    contexts = TLSContexts()
    proxy = X509Credential(str(pki.proxy_path), str(pki.proxy_path))
    first = contexts.get(proxy, ca_file=str(pki.ca_file))
    assert contexts.get(proxy, ca_file=str(pki.ca_file)) is first
    assert first.check_hostname and first.verify_mode == ssl.CERT_REQUIRED
    assert not first.verify_flags & getattr(ssl, "VERIFY_X509_STRICT", 0)
    gsi = contexts.get(proxy, ca_file=str(pki.ca_file), check_hostname=False)
    assert gsi is not first and not gsi.check_hostname
    insecure = contexts.get(None, verify=False, alpn=("http/1.1",))
    assert insecure.verify_mode == ssl.CERT_NONE and not insecure.check_hostname
    contexts.clear()
    assert contexts.get(proxy, ca_file=str(pki.ca_file)) is not first


def test_tls_context_bad_credentials(tmp_path: Path, pki: PKI) -> None:
    contexts = TLSContexts()
    with pytest.raises(GError) as caught:
        contexts.get(X509Credential(str(tmp_path / "none"), str(tmp_path / "none")))
    assert caught.value.code == errno.ENOENT
    garbage = tmp_path / "garbage.pem"
    garbage.write_text("not a certificate")
    with pytest.raises(GError) as caught:
        contexts.get(X509Credential(str(garbage), str(garbage)))
    assert caught.value.code == errno.EACCES
    assert "garbage.pem" in caught.value.message


def test_real_uid_and_empty_token_file_variable() -> None:
    assert REAL_UID() == os.geteuid()
    with pytest.MonkeyPatch.context() as patch:
        patch.delattr(os, "geteuid")  # as on Windows
        assert REAL_UID() == 0
    assert (
        find_bearer_token(Options(load_system=False), None, "", {"BEARER_TOKEN_FILE": ""}) is None
    )


def test_store_prefix_must_end_on_a_directory() -> None:
    """A token for one directory never reaches a sibling that merely shares its spelling."""
    store = CredentialStore()
    store.set("https://se/store/alice", Credential(BEARER, "alice"))
    assert store.get(BEARER, "https://se/store/alicebob/f") == ("", "")
    assert store.get(BEARER, "https://se/store/alice") == ("alice", "https://se/store/alice")
    assert store.get(BEARER, "https://se/store/alice/f") == ("alice", "https://se/store/alice")
    store.set("https://se/store/", Credential(BEARER, "store"))
    assert store.get(BEARER, "https://se/store/alicebob/f") == ("store", "https://se/store/")
    store.set("davs://h", Credential(BEARER, "h"))
    assert store.get(BEARER, "davs://hx/y") == ("", "")
    assert store.get(BEARER, "davs://h:443/x") == ("", "")
    assert store.get(BEARER, "davs://h/x") == ("h", "davs://h")


def _seeded(env: dict[str, str]) -> tuple[str, str, str]:
    options = Options(load_system=False)
    seed_options(options, env)
    return (
        options.string("X509", "CERT"),
        options.string("X509", "KEY"),
        options.string("BEARER", "TOKEN"),
    )


def test_seed_options_follows_gfal2_order(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".globus").mkdir(parents=True)
    assert _seeded({"BEARER_TOKEN": " t ", "X509_USER_PROXY": "/p"}) == ("", "", "t")
    # The proxy variable is trusted without looking at the file.
    assert _seeded({"X509_USER_PROXY": " /nowhere ", "HOME": str(home)}) == (
        "/nowhere",
        "/nowhere",
        "",
    )
    assert _seeded({"X509_USER_CERT": "/c", "X509_USER_KEY": "/k"}) == ("/c", "/k", "")
    assert _seeded({"X509_USER_CERT": "/c", "HOME": str(home)}) == ("", "", "")
    for name in ("usercert.pem", "userkey.pem"):
        (home / ".globus" / name).write_text("x")
    assert _seeded({"HOME": str(home)}) == (
        str(home / ".globus" / "usercert.pem"),
        str(home / ".globus" / "userkey.pem"),
        "",
    )
    (home / ".globus" / "userkey.pem").unlink()
    assert _seeded({"HOME": str(home)}) == ("", "", "")
    assert _seeded({}) == ("", "", "")


def test_seed_options_default_proxy_and_real_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy = Path(f"/tmp/x509up_u{UNUSED_UID}")
    try:
        proxy.write_text("x")
        assert _seeded({"X509_USER_CERT": "/c", "X509_USER_KEY": "/k"})[0] == str(proxy)
    finally:
        proxy.unlink()
    monkeypatch.setenv("BEARER_TOKEN", "from-env")
    options = Options(load_system=False)
    seed_options(options)
    assert options.string("BEARER", "TOKEN") == "from-env"


def test_a_stale_seeded_certificate_is_passed_over(tmp_path: Path) -> None:
    """A missing file copied in from the environment must not break token-only access."""
    real = tmp_path / "proxy"
    real.write_text("x")
    for variable in ("X509_USER_PROXY", "X509_USER_CERT"):
        env = {variable: str(tmp_path / "stale"), "HOME": str(tmp_path)}
        options = Options(load_system=False)
        seed_options(options, {**env, "X509_USER_KEY": "/k"})
        assert find_x509(options, None, "", env) is None
    # Configured by hand, a missing file is still presented (and fails loudly later).
    options = Options(load_system=False)
    options.set_string("X509", "CERT", str(tmp_path / "typo"))
    assert find_x509(options, None, "", {"HOME": str(tmp_path)}) is not None
    # Seeded and present: used as is.
    options.set_string("X509", "CERT", str(real))
    assert find_x509(options, None, "", {"X509_USER_PROXY": str(real)}) is not None
