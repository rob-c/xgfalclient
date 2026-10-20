"""Fixtures shared by every test module.

Every test runs hermetically: no site ``/etc/gfal2.d``, no ambient proxy or
token from the developer's shell, no ``/tmp/x509up_u<uid>`` that happens to
exist on this machine. The credential side of that is
:mod:`xrdsec.testing.fixtures`, the plugin every suite on the stack loads
(it also provides ``home``, ``tmp_dir``, ``grid_security`` and
``grid_env``); :func:`pytest_xrdsec_hermetic` adds xgfal's own inputs. A
test that wants credentials asks for ``grid_env`` (an in-process PKI) or
sets them itself.
"""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import condcov

# Before anything imports the shipped packages - or the library modules
# condcov.SHARED_MODULES holds to the same rule, which xrdclient imports too.
if condcov.ENABLED:
    condcov.install()

from xrdclient import _tokens

import xgfalclient
from xgfalclient.plugins.gridftp.control import Control
from xgfalclient.plugins.gridftp.protocol import Reply
from xgfalclient.testing.pki import PKI, create_pki

if TYPE_CHECKING:
    from xrdsec.testing.fixtures import Hermetic

pytest_plugins = ["xrdsec.testing.fixtures"]

#: xgfal's own inputs, cleared on top of the credential variables the
#: plugin clears: S3 keys, XrdCl's plugin directory, the Kerberos backend
#: selectors, colour settings, the BDII, the delegation-proxy override.
_OWN = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "XRD_PLUGINCONFDIR",
    "XGFAL_KRB5_BACKEND",
    "XRD_KRB5_BACKEND",
    "XGFAL_GSSAPI_LIBRARY",
    "LS_COLORS",
    "LCG_GFAL_INFOSYS",
    "XrdSecGSIDELEGPROXY",
)


def pytest_xrdsec_hermetic(hermetic: Hermetic) -> None:
    """xgfal's own inputs, on top of xrdsec's hermetic environment.

    No site ``/etc/gfal2.d``: ``$GFAL_CONFIG_DIR`` is a directory of the
    test's own, whose BDII names a closed local port (the BDII is on by
    default and names lcg-bdii.cern.ch), so a stray ``srm://`` lookup is
    refused at once. And a context with no token of its own leaves
    ``root://`` to xrdclient, whose Config-shaped token search ends in
    ``xrdclient._tokens.TMP_DIR`` rather than xrdsec's: it is pointed at the
    same empty ``/tmp`` (:func:`~xrdsec.testing.fixtures.tmp_dir`).
    """
    hermetic.unset(*_OWN)
    config = hermetic.directory("gfal2.d")
    (config / "bdii.conf").write_text("[BDII]\nLCG_GFAL_INFOSYS=127.0.0.1:1\nCACHE_FILE=\n")
    hermetic.monkeypatch.setenv("GFAL_CONFIG_DIR", str(config))
    hermetic.monkeypatch.setattr(_tokens, "TMP_DIR", str(hermetic.tmp_dir))


@pytest.fixture
def ctx() -> Iterator[xgfalclient.Gfal2Context]:
    context = xgfalclient.creat_context()
    yield context
    context.free()


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> PKI:
    """xgfal's view of the session PKI: its own ``Certificate``/``Credential`` types.

    Overrides the plugin's ``pki``, so the plugin's ``grid_env`` hands this
    one out too.
    """
    return create_pki(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """A scratch directory with one small file in it."""
    (tmp_path / "hello.txt").write_bytes(b"hello world\n")
    return tmp_path


@pytest.fixture
def hang_up_controls(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Hang up, at teardown, every GridFTP control connection the test opened.

    The control-channel tests drive sessions into failures (timeouts, resets,
    refused logins) and leave them there; their sockets are closed here
    rather than by the garbage collector. The session is marked broken
    first, so no ``QUIT`` waits on a server that was told to hang.
    """
    opened: list[Control] = []
    connect = Control.connect

    def tracked(self: Control) -> Reply:
        opened.append(self)
        return connect(self)

    monkeypatch.setattr(Control, "connect", tracked)
    yield
    for control in opened:
        control.broken = True
        control.close()


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


@pytest.fixture
def refused_port() -> Iterator[int]:
    """A loopback port that refuses connections for the whole test.

    Bound and never listening: a connection is refused at once, and - unlike
    a probe socket closed straight away - no other xdist worker can take the
    port while the test still means it to be dead.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        yield probe.getsockname()[1]
