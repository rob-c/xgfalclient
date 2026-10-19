"""Credential store, discovery order, and the TLS context cache."""

from __future__ import annotations

import errno
import logging
import os
import ssl
import sys
from pathlib import Path

import pytest
from xrdsec import credentials

import xgfalclient
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
    found = find_x509(options, None, "", {**env, "HOME": str(home)})
    assert found is not None and found.cert == str(proxy)
    # A stale X509_USER_PROXY stands for nothing: not the user certificate,
    # not ~/.globus - the variable named the identity, and it is not there.
    env["X509_USER_PROXY"] = str(tmp_path / "stale")
    assert find_x509(options, None, "", {**env, "HOME": str(home)}) is None
    env.pop("X509_USER_PROXY")
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


def _default_proxy() -> Path:
    """``/tmp/x509up_u<euid>``, in the tests' own ``/tmp`` (xrdsec.testing.fixtures)."""
    proxy = Path(credentials.TMP_DIR) / f"x509up_u{os.geteuid()}"
    proxy.write_text("x")
    return proxy


def test_x509_default_proxy_location(tmp_path: Path) -> None:
    proxy = _default_proxy()
    found = find_x509(Options(load_system=False), None, "", {"HOME": str(tmp_path)})
    assert found == X509Credential(str(proxy), str(proxy))


def test_a_missing_named_proxy_is_not_replaced_by_the_default_one(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """In a pilot, /tmp/x509up_u<uid> is the pilot's proxy, not the payload's."""
    _default_proxy()
    missing = str(tmp_path / "payload-proxy")
    env = {"X509_USER_PROXY": missing, "HOME": str(tmp_path)}
    with caplog.at_level("WARNING"):
        assert find_x509(Options(load_system=False), None, "", env) is None
        assert find_x509(Options(load_system=False), None, "", env) is None
    warnings = [r for r in caplog.records if missing in r.getMessage()]
    assert len(warnings) == 1  # said once, not once per request
    assert "no X.509 credential will be presented" in warnings[0].getMessage()


def test_x509_uses_real_environment_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    proxy = tmp_path / "p"
    proxy.write_text("x")
    monkeypatch.setenv("X509_USER_PROXY", str(proxy))
    assert find_x509(Options(load_system=False)) == X509Credential(str(proxy), str(proxy))


def _private(path: Path, text: str) -> Path:
    """Write a token file the way ``htgettoken`` and ``oidc-token`` do: mode 0600."""
    path.write_text(text)
    path.chmod(0o600)
    return path


def test_bearer_token_discovery(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    options = Options(load_system=False)
    store = CredentialStore()
    assert find_bearer_token(options, store, "https://se/f", {}) is None
    token_file = _private(tmp_path / "tok", "  from-file \n")
    assert (
        find_bearer_token(options, None, "", {"BEARER_TOKEN_FILE": str(token_file)}) == "from-file"
    )
    assert find_bearer_token(options, None, "", {"BEARER_TOKEN_FILE": str(tmp_path / "no")}) is None
    empty = _private(tmp_path / "empty", "\n")
    assert find_bearer_token(options, None, "", {"BEARER_TOKEN_FILE": str(empty)}) is None
    runtime = tmp_path / "run"
    runtime.mkdir()
    _private(runtime / f"bt_u{os.geteuid()}", "from-runtime")
    assert find_bearer_token(options, None, "", {"XDG_RUNTIME_DIR": str(runtime)}) == "from-runtime"
    assert find_bearer_token(options, None, "", {"XDG_RUNTIME_DIR": str(tmp_path)}) is None
    assert find_bearer_token(options, None, "", {"BEARER_TOKEN": " inline "}) == "inline"
    options.set_string("BEARER", "TOKEN", "configured")
    assert find_bearer_token(options, None, "", {"BEARER_TOKEN": "inline"}) == "configured"
    store.set("https://se/", Credential(BEARER, "stored"))
    assert find_bearer_token(options, store, "https://se/f", {}) == "stored"
    monkeypatch.setenv("BEARER_TOKEN", "ambient")
    assert find_bearer_token(Options(load_system=False)) == "ambient"


def test_bearer_token_discovery_order(tmp_path: Path) -> None:
    """WLCG order, as xrdclient follows it for ``root://``: an empty step passes to the next."""
    options = Options(load_system=False)
    runtime = tmp_path / "run"
    runtime.mkdir()
    _private(runtime / f"bt_u{os.geteuid()}", "from-runtime")
    named = _private(tmp_path / "named", "from-named")
    env = {"XDG_RUNTIME_DIR": str(runtime), "BEARER_TOKEN_FILE": str(named)}
    assert find_bearer_token(options, None, "", {**env, "BEARER_TOKEN": "inline"}) == "inline"
    assert find_bearer_token(options, None, "", env) == "from-named"
    # A named file that is missing or blank is passed over, not final.
    env["BEARER_TOKEN_FILE"] = str(tmp_path / "missing")
    assert find_bearer_token(options, None, "", env) == "from-runtime"


def test_bearer_token_tmp_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The search ends in xrdsec's ``TMP_DIR`` (``/tmp``; conftest points it elsewhere)."""
    monkeypatch.setattr(credentials, "TMP_DIR", str(tmp_path))
    _private(tmp_path / f"bt_u{os.geteuid()}", "tmp-token")
    assert find_bearer_token(Options(load_system=False), None, "", {}) == "tmp-token"


def _refused(env: dict[str, str]) -> GError:
    with pytest.raises(GError) as caught:
        find_bearer_token(Options(load_system=False), None, "", env)
    assert caught.value.code == errno.EACCES
    return caught.value


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o620])
def test_shared_token_file_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: int
) -> None:
    """A token file group or others can touch is not used, nor passed over for the next."""
    monkeypatch.setattr(credentials, "TMP_DIR", str(tmp_path))
    planted = tmp_path / f"bt_u{os.geteuid()}"
    planted.write_text("somebody-elses")
    planted.chmod(mode)
    error = _refused({})
    assert str(planted) in error.message and f"chmod 600 {planted}" in error.message
    # Not skipped in favour of a later location, either.
    runtime = tmp_path / "run"
    runtime.mkdir()
    shared = runtime / f"bt_u{os.geteuid()}"
    shared.write_text("leaked")
    shared.chmod(mode)
    assert str(shared) in _refused({"XDG_RUNTIME_DIR": str(runtime)}).message
    named = tmp_path / "named"
    named.write_text("named")
    named.chmod(mode)
    assert str(named) in _refused({"BEARER_TOKEN_FILE": str(named)}).message


def test_token_file_owned_by_another_user_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    named = _private(tmp_path / "theirs", "theirs")
    real = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)  # as if somebody else wrote it
    assert "not to you" in _refused({"BEARER_TOKEN_FILE": str(named)}).message


def test_symlink_at_a_predictable_name_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``/tmp/bt_u<uid>`` as a link to an attacker's file is refused; a named link is followed."""
    target = _private(tmp_path / "target", "linked")
    monkeypatch.setattr(credentials, "TMP_DIR", str(tmp_path))
    (tmp_path / f"bt_u{os.geteuid()}").symlink_to(target)
    assert "symbolic link" in _refused({}).message
    named = tmp_path / "named-link"
    named.symlink_to(target)
    found = find_bearer_token(
        Options(load_system=False), None, "", {"BEARER_TOKEN_FILE": str(named)}
    )
    assert found == "linked"


def test_token_file_that_is_not_a_regular_file_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(credentials, "TMP_DIR", str(tmp_path))
    (tmp_path / f"bt_u{os.geteuid()}").mkdir(mode=0o700)
    assert "not a regular file" in _refused({}).message
    huge = _private(tmp_path / "huge", "x" * ((1 << 20) + 1))
    assert "larger than" in _refused({"BEARER_TOKEN_FILE": str(huge)}).message


def test_insecure_token_file_fails_the_operation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, ctx: xgfalclient.Gfal2Context
) -> None:
    """Through the context, as a plugin asks for its token: EACCES, the file named."""
    named = tmp_path / "tok"
    named.write_text("leaked")
    named.chmod(0o644)
    monkeypatch.setenv("BEARER_TOKEN_FILE", str(named))
    with pytest.raises(GError) as caught:
        ctx.bearer_token("davs://se.example/f")
    assert caught.value.code == errno.EACCES and str(named) in caught.value.message


def test_ca_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert find_ca_path({"X509_CERT_DIR": str(tmp_path)}) == str(tmp_path)
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", None)  # the platform's own
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr("os.path.isdir", lambda path: path == "/etc/grid-security/certificates")
    assert find_ca_path({}) == "/etc/grid-security/certificates"
    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr("os.path.isdir", lambda path: path.startswith("/opt/homebrew"))
    assert find_ca_path({}) == "/opt/homebrew/etc/grid-security/certificates"
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
    # A certificate and its separate key: the key read through xrdsec's checks.
    pair = X509Credential(str(pki.user_cert_path), str(pki.user_key_path))
    assert contexts.get(pair, ca_file=str(pki.ca_file)).verify_mode == ssl.CERT_REQUIRED


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
    # A key others may read is refused before OpenSSL sees it.
    key = tmp_path / "shared-key.pem"
    key.write_bytes(pki.user_key_path.read_bytes())
    key.chmod(0o644)
    with pytest.raises(GError) as caught:
        contexts.get(X509Credential(str(pki.user_cert_path), str(key)))
    assert caught.value.code == errno.EACCES and "chmod 600" in caught.value.message
    # With no credential, a trust store that will not load is not worded as one.
    with pytest.raises(FileNotFoundError):
        contexts.get(None, ca_file=str(tmp_path / "no-such-ca.pem"))


def test_an_empty_token_file_variable_is_unset() -> None:
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
    proxy = _default_proxy()
    assert _seeded({"X509_USER_CERT": "/c", "X509_USER_KEY": "/k"})[0] == str(proxy)
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


def test_seed_options_says_where_it_looked(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """gfal2's debug lines for each outcome of the credential search."""
    home = tmp_path / "home"
    (home / ".globus").mkdir(parents=True)
    for name in ("usercert.pem", "userkey.pem"):
        (home / ".globus" / name).write_text("x")
    xgfalclient.set_verbose(xgfalclient.verbose_level.debug)
    try:
        with caplog.at_level(logging.DEBUG, logger="gfal2"):
            for env in (
                {"BEARER_TOKEN": "t"},
                {"X509_USER_PROXY": "/p"},
                {"X509_USER_CERT": "/c", "X509_USER_KEY": "/k"},
                {"HOME": str(home)},
                {},
            ):
                _seeded(env)
    finally:
        xgfalclient.set_verbose(xgfalclient.verbose_level.verbose)
    cert, key = home / ".globus" / "usercert.pem", home / ".globus" / "userkey.pem"
    assert [r.getMessage() for r in caplog.records] == [
        "Using BEARER token credentials from the env",
        "Using credentials from X509_USER_PROXY",
        "Certificate: /p",
        "Private key: /p",
        "Using credentials from X509_USER_CERT and X509_USER_KEY",
        "Certificate: /c",
        "Private key: /k",
        "Using credentials from default certificate location",
        f"Certificate: {cert}",
        f"Private key: {key}",
        "Could not find the credentials in any of the known locations",
    ]


def test_clearing_before_any_tls_imports_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A context freed without ever making a TLS connection does not import ``ssl`` to say so."""
    monkeypatch.delitem(sys.modules, "xrdsec.tls", raising=False)
    TLSContexts().clear()
    assert "xrdsec.tls" not in sys.modules
