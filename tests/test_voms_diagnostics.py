"""User-facing VOMS trust and endpoint configuration regression contract.

The same offline cases run against both client adapters; failures must retain
their path and cause.
"""

from __future__ import annotations

import errno
import os
import shutil
import subprocess
import time
from dataclasses import replace
from pathlib import Path

import pytest

from test_voms import _fixture, make_certificate, pem, private_key_pem
from xgfalclient.crypto import voms
from xgfalclient.crypto.voms import VOMSResult, VOMSStatus, check_vomses, validate_voms

ENDPOINT = '"atlas" "voms.example" "15000" "/DC=org/CN=voms.example" "atlas"\n'


@pytest.fixture
def installation(tmp_path):
    return _fixture(tmp_path / "installation")


def _validate(installation, **overrides):
    proxy, ca_dir, voms_dir, _ = installation
    options = {"ca_path": str(ca_dir), "voms_dir": str(voms_dir)}
    options.update(overrides)
    return validate_voms(proxy.chain, **options)


def _codes(result):
    return {issue.code for issue in result.diagnostics}


def _bad_ca_store(store, kind):
    if kind == "missing":
        return
    if kind == "wrong_type":
        store.write_text("not a directory")
        return
    store.mkdir()
    if kind == "empty":
        return
    if kind == "directory_certificate":
        (store / "12345678.0").mkdir()
    elif kind == "broken_symlink":
        (store / "12345678.0").symlink_to(store / "nonexistent")
    else:
        filename, data = {
            "readme_only": ("README", b"no certificates"),
            "empty_certificate": ("12345678.0", b""),
            "garbage": ("12345678.0", b"not a certificate"),
            "truncated_pem": ("12345678.0", b"-----BEGIN CERTIFICATE-----\nAAAA\n"),
            "invalid_der": ("12345678.0", pem("CERTIFICATE", b"\x30\x00")),
        }[kind]
        (store / filename).write_bytes(data)


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        ("missing", "ca_directory_missing"),
        ("empty", "ca_store_empty"),
        ("wrong_type", "ca_directory_wrong_type"),
        ("readme_only", "ca_store_empty"),
        ("empty_certificate", "ca_file_corrupt"),
        ("garbage", "ca_file_corrupt"),
        ("truncated_pem", "ca_file_corrupt"),
        ("invalid_der", "ca_file_corrupt"),
        ("directory_certificate", "ca_file_wrong_type"),
        ("broken_symlink", "ca_file_missing"),
    ],
)
def test_ca_installation_failures_are_actionable(installation, tmp_path, kind, code):
    store = tmp_path / "bad-ca"
    _bad_ca_store(store, kind)
    result = _validate(installation, ca_path=str(store))
    assert result.status is VOMSStatus.UNTRUSTED
    assert not result.verified
    assert code in _codes(result)
    assert str(store) in result.message
    assert any(word in result.message for word in ("Install", "Reinstall", "Check"))


@pytest.mark.parametrize(
    ("content", "code"),
    [
        (None, "lsc_missing"),
        (b"", "lsc_corrupt"),
        (b"# comments only\n\n", "lsc_corrupt"),
        (b"one line\n", "lsc_corrupt"),
        (b"one\ntwo\nthree\n", "lsc_corrupt"),
        (b"\xff\xfe", "lsc_corrupt"),
        (b"/CN=wrong\n/CN=wrong\n", "lsc_mismatch"),
    ],
)
def test_missing_damaged_and_stale_lsc_are_distinct(installation, content, code):
    _, _, voms_dir, _ = installation
    lsc = voms_dir / "atlas" / "voms.example.lsc"
    if content is None:
        lsc.unlink()
    else:
        lsc.write_bytes(content)
    result = _validate(installation)
    assert result.status is VOMSStatus.LSC
    assert code in _codes(result)
    assert str(lsc.parent if content is None else lsc) in result.message
    assert "official .lsc" in result.message or "VO administrator" in result.message


def test_lsc_incomplete_trailing_pair_cannot_authorize(installation):
    _, _, voms_dir, _ = installation
    lsc = voms_dir / "atlas" / "voms.example.lsc"
    lsc.write_text(lsc.read_text() + "/CN=unexpected trailing line\n")
    result = _validate(installation)
    assert result.status is VOMSStatus.LSC
    assert "lsc_corrupt" in _codes(result)


@pytest.mark.parametrize("remove_root", [False, True])
def test_missing_voms_directory_explains_the_vo(installation, remove_root):
    _, _, voms_dir, _ = installation
    (voms_dir / "atlas" / "voms.example.lsc").unlink()
    (voms_dir / "atlas").rmdir()
    if remove_root:
        voms_dir.rmdir()
    result = _validate(installation)
    assert {"voms_directory_missing", "lsc_missing"} <= _codes(result)
    assert "atlas" in result.message
    assert "X509_VOMS_DIR" in result.message


@pytest.mark.parametrize(
    ("target", "role"),
    [
        ("ca_directory", "ca_directory"),
        ("ca_file", "ca_file"),
        ("voms_directory", "voms_directory"),
        ("lsc_file", "lsc_file"),
    ],
)
@pytest.mark.parametrize(
    ("error_number", "suffix"),
    [(errno.EACCES, "permissions"), (errno.EPERM, "permissions"), (errno.EIO, "unreadable")],
)
def test_filesystem_errors_preserve_cause_and_path(
    installation, monkeypatch, target, role, error_number, suffix
):
    _, ca_dir, voms_dir, _ = installation
    blocked = {
        "ca_directory": ca_dir,
        "ca_file": ca_dir / "12345678.0",
        "voms_directory": voms_dir / "atlas",
        "lsc_file": voms_dir / "atlas" / "voms.example.lsc",
    }[target]

    owner, method = {
        "ca_directory": (os, "listdir"),
        "ca_file": (Path, "read_bytes"),
        "voms_directory": (Path, "iterdir"),
        "lsc_file": (Path, "read_text"),
    }[target]
    original = getattr(owner, method)

    def read(path, *args, **kwargs):
        if Path(path) == blocked:
            raise OSError(error_number, "injected filesystem failure", str(blocked))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(owner, method, read)
    result = _validate(installation)
    issue = next(issue for issue in result.diagnostics if issue.code == f"{role}_{suffix}")
    assert issue.path == str(blocked)
    assert issue.errno == error_number
    assert str(blocked) in issue.message
    if suffix == "permissions":
        assert "your account" in issue.message
        assert "parent directories" in issue.message
        assert "world-readable" in issue.message


@pytest.mark.parametrize(
    ("not_before_offset", "not_after_offset", "code"),
    [(-3600, -1, "ca_certificate_expired"), (60, 3600, "ca_certificate_not_yet_valid")],
)
def test_ca_expiry_is_not_reported_as_a_bad_lsc(
    installation, not_before_offset, not_after_offset, code
):
    _, ca_dir, _, facts = installation
    now = int(time.time())
    der = make_certificate(
        facts["ca_name"],
        facts["ca_name"],
        facts["ca_key"].public,
        facts["ca_key"],
        serial=1,
        not_before=now + not_before_offset,
        not_after=now + not_after_offset,
    )
    (ca_dir / "12345678.0").write_bytes(pem("CERTIFICATE", der))
    result = _validate(installation, now=now)
    assert result.status is VOMSStatus.UNTRUSTED
    assert code in _codes(result)
    assert "UTC" in result.message
    assert "trusted CA bundle" in result.message
    assert "lsc_missing" not in _codes(result)


@pytest.mark.parametrize("expired", [True, False])
def test_signer_time_failure_is_not_confused_with_root_ca(installation, tmp_path, expired):
    _, _, _, facts = installation
    now = int(time.time())
    signer = make_certificate(
        facts["voms_name"],
        facts["ca_name"],
        facts["voms_key"].public,
        facts["ca_key"],
        serial=3,
        not_before=now - 3600 if expired else now + 60,
        not_after=now - 1 if expired else now + 3600,
    )
    other = _fixture(tmp_path / "signer", ac_options={"embedded": (signer,)})
    result = _validate(other, now=now)
    assert result.status is VOMSStatus.UNTRUSTED
    wanted = "signer_certificate_expired" if expired else "signer_certificate_not_yet_valid"
    assert wanted in _codes(result)
    assert "VO administrator" in result.message
    assert "UTC" in result.message


@pytest.mark.parametrize("trust_type", ["corrupt_ca", "corrupt_lsc", "legacy_pin"])
def test_unrelated_bad_file_does_not_poison_valid_trust(installation, trust_type):
    _, ca_dir, voms_dir, facts = installation
    if trust_type == "corrupt_ca":
        (ca_dir / "87654321.0").write_bytes(b"broken unrelated CA")
    elif trust_type == "corrupt_lsc":
        (voms_dir / "atlas" / "a-broken.lsc").write_bytes(b"\xff")
    else:
        (voms_dir / "atlas" / "voms.example.lsc").unlink()
        (voms_dir / "legacy.pem").write_bytes(pem("CERTIFICATE", facts["voms_der"]))
    result = _validate(installation)
    assert result.status is VOMSStatus.OK
    assert result.verified
    assert result.diagnostics == ()
    assert result.message == "VOMS validation passed."


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("dn_style", ["slash", "rfc2253"])
def test_lsc_standard_layouts_remain_supported(installation, newline, dn_style):
    proxy, _, voms_dir, _ = installation
    signer = voms.inspect_voms(proxy.chain).entries[0]._embedded[0]
    render = str if dn_style == "slash" else voms._rfc2253
    lines = ["# trusted server", "", render(signer.subject), render(signer.issuer), ""]
    (voms_dir / "atlas" / "voms.example.lsc").write_bytes(newline.join(lines).encode())
    assert _validate(installation).status is VOMSStatus.OK


@pytest.mark.parametrize("status", list(VOMSStatus))
def test_every_status_has_a_plain_nonempty_message(status):
    result = VOMSResult((), status)
    assert result.message
    assert result.message != status.value
    assert "\n" not in result.message
    assert "PRIVATE KEY" not in result.message


def test_entry_diagnostics_and_mixed_vo_failure_are_visible(installation):
    entry = _validate(installation).entries[0]
    expired = replace(entry, status=VOMSStatus.EXPIRED)
    result = VOMSResult((entry, expired), VOMSStatus.OK)
    assert result.verified == (entry,)
    assert "atlas" in result.message
    assert "expired" in result.message
    assert result.diagnostics == ()


@pytest.mark.parametrize("vo", ["", ".", "..", "../atlas", "atlas/../../etc", "atlas\\..", "a\0b"])
def test_invalid_vo_names_do_not_access_the_filesystem(monkeypatch, vo):
    def unexpected(_path):
        pytest.fail("invalid VO name must not trigger filesystem access")

    monkeypatch.setattr(voms, "_trust_files", unexpected)
    issues = []
    assert not voms._lsc_matches("/does/not/matter", vo, (object(),), issues)
    assert issues[0].code == "vo_name_invalid"


@pytest.mark.parametrize("vo", ["atlas", "lhcb", "vo.example.org", "vo-with-hyphen", "vo_1"])
def test_standard_vo_names_remain_supported(vo):
    assert voms._safe_vo(vo)


@pytest.mark.parametrize("layout", ["file", "directory"])
def test_vomses_file_and_directory_layouts_are_supported(tmp_path, layout):
    path = tmp_path / "vomses"
    if layout == "file":
        path.write_text(ENDPOINT)
    else:
        path.mkdir()
        (path / "atlas").write_text("# official endpoint\n" + ENDPOINT)
        (path / ".ignored").write_bytes(b"\xff")
    assert check_vomses(str(path)) == ()


@pytest.mark.parametrize("content", ["", "\n", "# comments only\n"])
@pytest.mark.parametrize("layout", ["file", "directory"])
def test_empty_vomses_explains_issuance_not_validation(tmp_path, content, layout):
    path = tmp_path / "vomses"
    if layout == "file":
        path.write_text(content)
    else:
        path.mkdir()
        if content:
            (path / "atlas").write_text(content)
    issues = check_vomses(str(path))
    assert issues[0].code == "vomses_empty"
    assert str(path) in issues[0].message
    assert "existing proxy" in issues[0].message


@pytest.mark.parametrize(
    "line",
    [
        '"atlas" "host" "15000" "/CN=server"',  # missing alias
        '"atlas" "host" "15000" "/CN=server" "atlas" "extra"',
        '"atlas" "host" "0" "/CN=server" "atlas"',
        '"atlas" "host" "65536" "/CN=server" "atlas"',
        '"atlas" "host" "abc" "/CN=server" "atlas"',
        '"atlas" "host" "-1" "/CN=server" "atlas"',
        '"atlas" "" "15000" "/CN=server" "atlas"',
        '"../atlas" "host" "15000" "/CN=server" "atlas"',
        '"atlas" "unclosed',
    ],
)
def test_malformed_vomses_reports_file_and_line(tmp_path, line):
    path = tmp_path / "vomses"
    path.write_text("# header\n" + line + "\n")
    issues = check_vomses(str(path))
    assert issues[0].code == "vomses_malformed"
    assert issues[0].path == str(path)
    assert "line 2" in issues[0].message
    assert "five fields" in issues[0].message


def test_vomses_preflight_reports_all_bad_lines(tmp_path):
    path = tmp_path / "vomses"
    path.write_text(ENDPOINT + "bad\nalso bad\n")
    issues = check_vomses(str(path))
    assert [issue.code for issue in issues] == ["vomses_malformed"] * 2
    assert "line 2" in issues[0].message
    assert "line 3" in issues[1].message


def test_missing_vomses_has_a_stable_code_and_exact_path(tmp_path):
    path = tmp_path / "missing-vomses"
    issue = check_vomses(str(path))[0]
    assert issue.code == "vomses_path_missing"
    assert issue.path == str(path)
    assert issue.errno == errno.ENOENT


def test_corrupt_vomses_does_not_escape_as_unicode_error(tmp_path):
    path = tmp_path / "vomses"
    path.write_bytes(b"\xff\xfe")
    issue = check_vomses(str(path))[0]
    assert issue.code == "vomses_corrupt"
    assert "UTF-8" in issue.message


@pytest.mark.parametrize("layout", ["file", "directory", "stat"])
def test_vomses_permissions_have_an_actionable_fix(tmp_path, monkeypatch, layout):
    path = tmp_path / "vomses"
    path.write_text(ENDPOINT)

    def denied(*_args, **_kwargs):
        raise PermissionError(errno.EACCES, "denied", str(path))

    if layout == "directory":
        path.unlink()
        path.mkdir()
        monkeypatch.setattr(Path, "iterdir", denied)
    elif layout == "stat":
        monkeypatch.setattr(Path, "stat", denied)
    else:
        monkeypatch.setattr(Path, "read_text", denied)
    issue = check_vomses(str(path))[0]
    assert issue.code.endswith("_permissions")
    assert issue.path == str(path)
    assert issue.errno == errno.EACCES
    assert "your account" in issue.message


def test_vomses_special_file_is_not_opened(tmp_path):
    path = tmp_path / "vomses"
    os.mkfifo(path)
    assert check_vomses(str(path))[0].code == "vomses_path_wrong_type"


def test_existing_proxy_validation_does_not_require_vomses(installation, monkeypatch, tmp_path):
    monkeypatch.setenv("VOMS_USERCONF", str(tmp_path / "missing-vomses"))

    def unexpected(_path):
        pytest.fail("existing proxy validation must not inspect vomses")

    monkeypatch.setattr(voms, "check_vomses", unexpected)
    assert _validate(installation).status is VOMSStatus.OK


@pytest.mark.parametrize("variable", ["X509_CERT_DIR", "X509_VOMS_DIR"])
def test_missing_explicit_environment_path_is_not_silently_ignored(
    installation, monkeypatch, tmp_path, variable
):
    missing = tmp_path / "explicit-but-missing"
    monkeypatch.setenv(variable, str(missing))
    options = {"ca_path": None} if variable == "X509_CERT_DIR" else {"voms_dir": None}
    result = _validate(installation, **options)
    assert not result.verified
    assert str(missing) in result.message


@pytest.mark.parametrize("platform", ["linux", "darwin"])
@pytest.mark.parametrize("kind", ["certificates", "vomsdir"])
def test_no_default_trust_installation_has_a_clear_setup_error(
    installation, monkeypatch, platform, kind
):
    monkeypatch.setattr(voms.sys, "platform", platform)
    monkeypatch.setattr(os.path, "isdir", lambda _path: False)
    variable = "X509_CERT_DIR" if kind == "certificates" else "X509_VOMS_DIR"
    monkeypatch.delenv(variable, raising=False)
    options = {"ca_path": None} if kind == "certificates" else {"voms_dir": None}
    result = _validate(installation, **options)
    assert not result.verified
    assert variable in result.message


@pytest.mark.parametrize("failure", [IndexError, ValueError, voms.DERError])
def test_certificate_parser_failures_become_diagnostics(installation, monkeypatch, failure):
    def broken(_data):
        raise failure("malformed certificate")

    monkeypatch.setattr(voms, "load_certificates", broken)
    assert "ca_file_corrupt" in _codes(_validate(installation))


def test_corrupt_legacy_signer_cannot_crash_validation(installation, monkeypatch):
    _, _, voms_dir, _ = installation
    (voms_dir / "atlas" / "voms.example.lsc").unlink()
    broken = voms_dir / "bad.pem"
    broken.write_bytes(pem("CERTIFICATE", b"\x30\x00"))
    original = voms.load_certificates

    def malformed(data):
        if data == broken.read_bytes():
            raise IndexError("missing certificate body")
        return original(data)

    monkeypatch.setattr(voms, "load_certificates", malformed)
    result = _validate(installation)
    assert result.status is VOMSStatus.LSC
    assert "legacy_signer_file_corrupt" in _codes(result)
    assert str(broken) in result.message


def test_internal_status_only_call_remains_compatible(installation, tmp_path):
    proxy, _, voms_dir, _ = installation
    entry = voms.inspect_voms(proxy.chain).entries[0]
    assert (
        voms._external_trust_status(
            entry, entry._embedded, str(tmp_path / "missing"), str(voms_dir), time.time()
        )
        is VOMSStatus.UNTRUSTED
    )


def test_anchor_loader_without_diagnostics_remains_compatible(installation):
    _, ca_dir, _, facts = installation
    assert [certificate.der for certificate in voms._load_anchors(str(ca_dir))] == [facts["ca_der"]]


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses ordinary file permissions")
@pytest.mark.parametrize("target", ["ca_file", "lsc_file"])
def test_real_os_unreadable_file_has_a_permissions_diagnostic(installation, target):
    _, ca_dir, voms_dir, _ = installation
    path = ca_dir / "12345678.0" if target == "ca_file" else voms_dir / "atlas" / "voms.example.lsc"
    original_mode = path.stat().st_mode & 0o777
    try:
        path.chmod(0)
        result = _validate(installation)
        assert f"{target}_permissions" in _codes(result)
        assert str(path) in result.message
    finally:
        path.chmod(original_mode)


@pytest.mark.parametrize(
    ("not_before", "not_after", "now", "skew", "expected"),
    [
        (1001, 2000, 1000, 0, VOMSStatus.NOT_YET_VALID),
        (1001, 2000, 1000, 1, VOMSStatus.OK),
        (1000, 2000, 1000, 0, VOMSStatus.OK),
        (500, 1000, 1000, 0, VOMSStatus.OK),
        (500, 999, 1000, 0, VOMSStatus.EXPIRED),
        (500, 999, 1000, 300, VOMSStatus.EXPIRED),
    ],
)
def test_ac_time_boundaries_and_clock_skew_are_explicit(
    installation, not_before, not_after, now, skew, expected
):
    entry = voms.inspect_voms(installation[0].chain).entries[0]
    entry = replace(entry, not_before=not_before, not_after=not_after)
    assert voms._validity_status(entry, now, skew) is expected


@pytest.mark.skipif(
    shutil.which("openssl") is None, reason="independent OpenSSL oracle unavailable"
)
def test_voms_rsa_signature_is_verified_by_independent_openssl(installation, tmp_path):
    entry = voms.inspect_voms(installation[0].chain).entries[0]
    signer = tmp_path / "signer.pem"
    public = tmp_path / "public.pem"
    message = tmp_path / "attributes.der"
    signature = tmp_path / "signature"
    signer.write_bytes(pem("CERTIFICATE", entry._embedded[0].der))
    message.write_bytes(entry._tbs)
    signature.write_bytes(entry._signature)
    result = subprocess.run(
        ["openssl", "x509", "-in", str(signer), "-pubkey", "-noout"],
        capture_output=True,
        check=True,
        timeout=10,
    )
    public.write_bytes(result.stdout)
    result = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public),
            "-signature",
            str(signature),
            str(message),
        ],
        capture_output=True,
        check=True,
        timeout=10,
    )
    assert b"Verified OK" in result.stdout


@pytest.mark.skipif(
    shutil.which("openssl") is None, reason="independent OpenSSL oracle unavailable"
)
def test_ca_parser_accepts_certificate_generated_by_independent_openssl(installation, tmp_path):
    key_path = tmp_path / "key.pem"
    certificate_path = tmp_path / "ca.pem"
    key_path.write_bytes(private_key_pem(installation[3]["ca_key"]))
    key_path.chmod(0o600)
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            str(key_path),
            "-subj",
            "/CN=Independent CA",
            "-days",
            "1",
            "-sha256",
            "-out",
            str(certificate_path),
        ],
        capture_output=True,
        check=True,
        timeout=10,
    )
    store = tmp_path / "independent-ca"
    store.mkdir()
    (store / "12345678.0").write_bytes(certificate_path.read_bytes())
    issues = []
    anchors = voms._load_anchors(str(store), issues)
    assert len(anchors) == 1
    assert str(anchors[0].subject) == "/CN=Independent CA"
    assert issues == []


@pytest.mark.parametrize("fraction", range(32))
def test_truncated_voms_attributes_always_return_a_clear_error(installation, monkeypatch, fraction):
    proxy = installation[0]
    encoded = voms._voms_extension(proxy.chain[0])
    assert encoded is not None
    truncated = encoded[: len(encoded) * fraction // 32]
    monkeypatch.setattr(voms, "_voms_extension", lambda certificate: truncated)
    result = validate_voms(proxy.chain)
    assert result.status is VOMSStatus.DECODE
    assert not result.verified
    assert "Obtain a new proxy" in result.message


@pytest.mark.parametrize("seed", range(64))
def test_unrecognised_attribute_bytes_never_escape_as_parser_errors(
    installation, monkeypatch, seed
):
    import random

    data = random.Random(seed).randbytes(seed * 2)
    monkeypatch.setattr(voms, "_voms_extension", lambda certificate: data)
    result = validate_voms(installation[0].chain)
    assert result.status is VOMSStatus.DECODE
    assert not result.verified
    assert "damaged or malformed" in result.message


@pytest.mark.parametrize("status", [status for status in VOMSStatus if status is not VOMSStatus.OK])
def test_every_failed_status_names_a_safe_next_step(status):
    message = VOMSResult((), status).message
    assert any(
        action in message
        for action in ("Obtain", "Check", "Install", "Update", "Request", "Ask", "Do not trust")
    )
    assert len(message) <= 180
    assert "chmod 777" not in message


@pytest.mark.parametrize("character", ["\0", "\t", "\n", "\r", "\x1f", "\x7f", " "])
@pytest.mark.parametrize("field", [1, 3, 4])
def test_vomses_control_characters_and_blank_fields_are_actionable(tmp_path, character, field):
    fields = ["atlas", "voms.example", "15000", "/DC=org/CN=voms.example", "atlas"]
    fields[field] = character
    path = tmp_path / "vomses"
    path.write_text(" ".join('"' + value + '"' for value in fields) + "\n")
    issue = check_vomses(str(path))[0]
    assert issue.code == "vomses_malformed"
    assert issue.path == str(path)
    assert "line 1" in issue.message
    assert "Reinstall" in issue.message


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses ordinary folder permissions")
@pytest.mark.parametrize("target", ["ca_directory", "voms_directory"])
def test_real_folder_permissions_report_the_folder_not_a_missing_lsc(installation, target):
    _, ca_dir, voms_dir, _ = installation
    path = ca_dir if target == "ca_directory" else voms_dir / "atlas"
    original_mode = path.stat().st_mode & 0o777
    try:
        path.chmod(0)
        result = _validate(installation)
        issue = next(issue for issue in result.diagnostics if issue.code == target + "_permissions")
        assert issue.path == str(path)
        assert issue.errno in (errno.EACCES, errno.EPERM)
        assert "folder" in issue.message
        assert "your account" in issue.message
    finally:
        path.chmod(original_mode)


@pytest.mark.parametrize("layout", ["file", "directory"])
@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses ordinary filesystem permissions")
def test_real_vomses_permissions_preserve_the_cause(tmp_path, layout):
    path = tmp_path / "vomses"
    if layout == "file":
        path.write_text(ENDPOINT)
    else:
        path.mkdir()
        (path / "atlas").write_text(ENDPOINT)
    original_mode = path.stat().st_mode & 0o777
    try:
        path.chmod(0)
        issue = check_vomses(str(path))[0]
        assert issue.code.endswith("_permissions")
        assert issue.errno in (errno.EACCES, errno.EPERM)
        assert issue.path == str(path)
        assert "your account" in issue.message
    finally:
        path.chmod(original_mode)


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_root_certificate_expiry_boundary_has_the_correct_role(installation, offset):
    _, ca_dir, _, facts = installation
    now = int(time.time())
    certificate = make_certificate(
        facts["ca_name"],
        facts["ca_name"],
        facts["ca_key"].public,
        facts["ca_key"],
        serial=1,
        not_before=now - 3600,
        not_after=now + offset,
    )
    path = ca_dir / "12345678.0"
    path.write_bytes(pem("CERTIFICATE", certificate))
    result = _validate(installation, now=now)
    if offset > 0:
        assert result.status is VOMSStatus.OK
    else:
        issue = next(
            issue for issue in result.diagnostics if issue.code == "ca_certificate_expired"
        )
        assert issue.path == str(path)
        assert issue.message.startswith("CA certificate")
        assert "UTC" in issue.message
        assert "Update the trusted CA bundle" in issue.message
