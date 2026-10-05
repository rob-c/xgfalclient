"""Fixtures shared by every test module.

Every test runs hermetically: no site ``/etc/gfal2.d``, no ambient proxy or
token from the developer's shell, no ``/tmp/x509up_u<uid>`` that happens to
exist on this machine. A test that wants credentials asks for ``grid_env``
(an in-process PKI) or sets them itself.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

import condcov

if condcov.ENABLED:
    condcov.install()

import xgfalclient
from xgfalclient import creds
from xgfalclient.testing.pki import PKI, create_pki

_AMBIENT = (
    "X509_USER_PROXY",
    "X509_USER_CERT",
    "X509_USER_KEY",
    "X509_CERT_DIR",
    "X509_VOMS_DIR",
    "BEARER_TOKEN",
    "BEARER_TOKEN_FILE",
    "XDG_RUNTIME_DIR",
    "GFAL_CONFIG_DIR",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "XRD_PLUGINCONFDIR",
    "KRB5CCNAME",
    "KRB5_KTNAME",
    "KRB5_CONFIG",
    "XGFAL_KRB5_BACKEND",
    "XRD_KRB5_BACKEND",
    "XGFAL_GSSAPI_LIBRARY",
    "LS_COLORS",
    "LCG_GFAL_INFOSYS",
    "XrdSecGSIDELEGPROXY",
)

#: Rebuilding a delegated proxy's chain from the TLS handshake needs the
#: peer's whole chain, which Python 3.9's ssl cannot report. This limits
#: Python *servers* accepting delegation only.
needs_peer_chain = pytest.mark.skipif(
    sys.version_info < (3, 10), reason="Python 3.9's ssl cannot report a TLS peer's chain"
)

#: The real uid lookup, saved before the fixture below replaces it.
REAL_UID = creds._uid

#: A uid nobody has, so ``/tmp/x509up_u<uid>`` and ``/tmp/bt_u<uid>`` never exist.
UNUSED_UID = 7_654_321


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    for name in _AMBIENT:
        monkeypatch.delenv(name, raising=False)
    config = tmp_path_factory.mktemp("gfal2.d")
    # The BDII is on by default and names lcg-bdii.cern.ch: point it at a
    # closed local port, so a stray srm:// lookup is refused at once.
    (config / "bdii.conf").write_text("[BDII]\nLCG_GFAL_INFOSYS=127.0.0.1:1\nCACHE_FILE=\n")
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("GFAL_CONFIG_DIR", str(config))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(creds, "_uid", lambda: UNUSED_UID)


@pytest.fixture
def ctx() -> Iterator[xgfalclient.Gfal2Context]:
    context = xgfalclient.creat_context()
    yield context
    context.free()


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> PKI:
    return create_pki(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def grid_env(monkeypatch: pytest.MonkeyPatch, pki: PKI) -> PKI:
    """Point discovery at the test PKI's proxy and CA directory."""
    for key, value in pki.environment().items():
        monkeypatch.setenv(key, value)
    return pki


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """A scratch directory with one small file in it."""
    (tmp_path / "hello.txt").write_bytes(b"hello world\n")
    return tmp_path


def file_url(path: Path | str) -> str:
    return "file://" + os.fspath(path)


#: Interop tests build and start Docker containers; the hermetic 120 s limit
#: is for unit tests, not for an image build on a busy machine.
INTEROP_TIMEOUT = 1800


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if item.get_closest_marker("interop") and not item.get_closest_marker("timeout"):
            item.add_marker(pytest.mark.timeout(INTEROP_TIMEOUT))


def pytest_configure(config: pytest.Config) -> None:
    if condcov.ENABLED:
        config.pluginmanager.register(condcov.Plugin(config), "condcov")
