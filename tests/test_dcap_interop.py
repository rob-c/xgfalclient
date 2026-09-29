"""The dcap plugin against a real dCache, and against real gfal2 where it is installed.

Skipped unless ``XGFAL_INTEROP=1``. The doors default to the docker setup
the plugin was developed against (a ``dcache/dcache:11.2`` container called
``xgfal-dcap-dcache`` with a writable ``/data``), reached from a container on
the same network - the door hands out pool addresses that only resolve
there::

    XGFAL_INTEROP=1 python3 -m pytest tests/test_dcap_interop.py

``XGFAL_DCAP_URL`` and ``XGFAL_GSIDCAP_URL`` name other directories;
``XGFAL_DCAP_PROXY`` and ``XGFAL_DCAP_CERT_DIR`` the GSI credential and trust
anchors (the test suite clears the usual ``X509_*`` variables). When the
real ``gfal2`` bindings are importable too, error cases are compared with
them message for message.
"""

from __future__ import annotations

import errno
import os
import uuid
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from test_dcap import code_of, with_dcap
from xgfalclient.errors import GError

pytestmark = [
    pytest.mark.interop,
    pytest.mark.skipif(os.environ.get("XGFAL_INTEROP") != "1", reason="XGFAL_INTEROP=1 not set"),
]

DCAP = os.environ.get("XGFAL_DCAP_URL", "dcap://xgfal-dcap-dcache:22125/data")
GSIDCAP = os.environ.get("XGFAL_GSIDCAP_URL", "gsidcap://xgfal-dcap-dcache:22128/data")
PROXY = os.environ.get("XGFAL_DCAP_PROXY", "/pki/x509up_rfc")
CERT_DIR = os.environ.get("XGFAL_DCAP_CERT_DIR", "/pki/certificates")


@pytest.fixture
def real(
    ctx: xgfalclient.Gfal2Context, monkeypatch: pytest.MonkeyPatch
) -> xgfalclient.Gfal2Context:
    monkeypatch.setenv("X509_USER_PROXY", PROXY)
    monkeypatch.setenv("X509_CERT_DIR", CERT_DIR)
    with_dcap(ctx)
    return ctx


@pytest.fixture(params=["dcap", "gsidcap"])
def base(request: pytest.FixtureRequest, real: xgfalclient.Gfal2Context) -> Iterator[str]:
    """A fresh, world-writable directory (anonymous dcap needs one)."""
    top = DCAP if request.param == "dcap" else GSIDCAP
    url = f"{top}/xgfal-{uuid.uuid4().hex[:8]}"
    mask = os.umask(0)
    try:
        from xgfalclient.plugins.dcap import plugin

        plugin._umask[:] = [0]
        real.mkdir(url, 0o777)
    finally:
        os.umask(mask)
    yield url
    for name in real.listdir(url):
        try:
            real.unlink(f"{url}/{name}")
        except GError:
            real.rmdir(f"{url}/{name}")
    real.rmdir(url)


def test_namespace(real: xgfalclient.Gfal2Context, base: str) -> None:
    info = real.stat(base)
    assert info.is_dir()
    real.mkdir(f"{base}/sub", 0o777)
    assert code_of(real.mkdir, f"{base}/sub", 0o777) == errno.EEXIST
    assert code_of(real.mkdir, f"{base}/no/such", 0o777) == errno.ENOENT
    assert code_of(real.stat, f"{base}/missing") == errno.ENOENT
    assert code_of(real.unlink, f"{base}/sub") == errno.EISDIR
    assert code_of(real.unlink, f"{base}/missing") == errno.ENOENT
    assert code_of(real.rmdir, f"{base}/missing") == errno.ENOENT
    assert code_of(real.listdir, f"{base}/missing") == errno.ENOENT
    assert real.listdir(base) == ["sub"]
    real.rmdir(f"{base}/sub")


def test_io(real: xgfalclient.Gfal2Context, base: str) -> None:
    data = os.urandom(9 * 1024 * 1024 + 11)
    url = f"{base}/file.bin"
    with real.open(url, "w") as handle:
        view = memoryview(data)
        for start in range(0, len(data), 4 << 20):
            handle.write(view[start : start + (4 << 20)])
    info = real.stat(url)
    assert info.st_size == len(data) and info.is_file()
    with real.open(url, "r") as handle:
        assert handle.read_bytes(10) == data[:10]
        assert handle.pread_bytes(5_000_000, 7) == data[5_000_000:5_000_007]
        assert handle.lseek(0, os.SEEK_END) == len(data)
        handle.lseek(0)
        buffer = bytearray(len(data))
        got = 0
        while got < len(data):
            count = handle.readinto(memoryview(buffer)[got:])
            assert count
            got += count
        assert zlib.adler32(buffer) == zlib.adler32(data)
    # dCache files are write-once
    with pytest.raises(GError) as info_:
        real.open(url, "w")
    assert info_.value.code == errno.EIO and "File is readOnly" in info_.value.message
    assert code_of(real.open, base, "r") == errno.EIO  # "Not a File"
    assert code_of(real.open, f"{base}/missing", "r") == errno.ENOENT
    real.rename(url, f"{base}/renamed.bin")
    assert real.stat(f"{base}/renamed.bin").st_size == len(data)
    entries = dict(
        (entry.d_name, info) for entry, info in iter(real.opendir(base).readpp, (None, None))
    )
    assert entries["renamed.bin"].st_size == len(data)


def test_copies(real: xgfalclient.Gfal2Context, base: str, tmp_path: Path) -> None:
    source = tmp_path / "up.bin"
    source.write_bytes(os.urandom(3 * 1024 * 1024 + 1))
    params = real.transfer_parameters()
    real.filecopy(params, f"file://{source}", f"{base}/up.bin")
    assert code_of(real.filecopy, params, f"file://{source}", f"{base}/up.bin") == errno.EEXIST
    params.overwrite = True
    real.filecopy(params, f"file://{source}", f"{base}/up.bin")
    real.filecopy(params, f"{base}/up.bin", f"file://{tmp_path}/down.bin")
    assert (tmp_path / "down.bin").read_bytes() == source.read_bytes()


# -- side by side with gfal2 ----------------------------------------------------------------


#: Schemes real gfal2 has been driven with in this process.
_GFAL2_SCHEMES: set[str] = set()


@pytest.fixture
def gfal2_ctx(monkeypatch: pytest.MonkeyPatch, base: str) -> object:
    gfal2 = pytest.importorskip("gfal2")
    scheme = base.partition(":")[0]
    if _GFAL2_SCHEMES - {scheme}:
        # libdcap keys its one control line per process by host name alone, so
        # after dcap:// it sends gsidcap:// requests down the plain connection
        # and hangs. Each scheme needs a process of its own.
        pytest.skip("libdcap cannot use dcap:// and gsidcap:// to one host in one process")
    _GFAL2_SCHEMES.add(scheme)
    monkeypatch.delenv("GFAL_CONFIG_DIR")  # the real one needs its /etc/gfal2.d
    monkeypatch.setenv("X509_USER_PROXY", PROXY)
    monkeypatch.setenv("X509_CERT_DIR", CERT_DIR)
    return gfal2.creat_context()


def test_errors_match_gfal2(real: xgfalclient.Gfal2Context, base: str, gfal2_ctx: object) -> None:
    import gfal2

    real.mkdir(f"{base}/dir", 0o777)
    with real.open(f"{base}/file", "w") as handle:
        handle.write(b"x")
    cases = [
        ("stat", f"{base}/missing"),
        ("lstat", f"{base}/missing"),
        ("mkdir", f"{base}/dir", 0o755),
        ("mkdir", f"{base}/no/such", 0o755),
        ("unlink", f"{base}/dir"),
        ("unlink", f"{base}/missing"),
        ("rmdir", base),
        ("rmdir", f"{base}/file"),
        ("rmdir", f"{base}/missing"),
        ("chmod", f"{base}/missing", 0o600),
        ("open", f"{base}/missing", "r"),
        ("open", f"{base}/dir", "r"),
        ("open", f"{base}/file", "w"),
    ]
    for name, *args in cases:
        with pytest.raises(gfal2.GError) as theirs:
            getattr(gfal2_ctx, name)(*args)
        with pytest.raises(GError) as ours:
            getattr(real, name)(*args)
        assert (ours.value.code, ours.value.message) == (theirs.value.code, theirs.value.message), (
            name,
            args,
        )
