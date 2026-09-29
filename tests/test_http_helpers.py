"""Fixtures shared by the ``test_http_*`` modules (imported by name from each).

The http plugin is tested end to end against :mod:`xgfalclient.testing.webdav`,
an in-process server on an ephemeral loopback port, through the gfal2 API a
user would call - ``ctx.stat``, ``ctx.filecopy`` - so what is covered is what
is used.
"""

from __future__ import annotations

import ssl
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from xgfalclient.testing.pki import PKI
from xgfalclient.testing.webdav import WebDAVServer


def make_server(root: Path, **kwargs: object) -> WebDAVServer:
    (root / "data").mkdir(parents=True, exist_ok=True)
    return WebDAVServer(root, **kwargs).start()  # type: ignore[arg-type]


@pytest.fixture
def dav(tmp_path: Path) -> Iterator[WebDAVServer]:
    server = make_server(tmp_path / "srv1")
    yield server
    server.stop()


@pytest.fixture
def dav2(tmp_path: Path) -> Iterator[WebDAVServer]:
    server = make_server(tmp_path / "srv2")
    yield server
    server.stop()


@pytest.fixture
def davs(tmp_path: Path, grid_env: PKI) -> Iterator[WebDAVServer]:
    """HTTPS that verifies a client certificate when one is offered, as SEs do."""
    tls = grid_env.server_context()
    tls.verify_mode = ssl.CERT_OPTIONAL
    server = make_server(tmp_path / "srvs", tls=tls)
    server.client_tls = grid_env.client_context()
    yield server
    server.stop()


@pytest.fixture
def davs_open(tmp_path: Path, grid_env: PKI) -> Iterator[WebDAVServer]:
    """HTTPS that does not ask for a client certificate."""
    server = make_server(tmp_path / "srvso", tls=grid_env.server_context(require_client=False))
    yield server
    server.stop()


@pytest.fixture
def hctx() -> Iterator[xgfalclient.Gfal2Context]:
    context = xgfalclient.creat_context()
    yield context
    context.free()


def write(server: WebDAVServer, path: str, data: bytes) -> Path:
    local = server.local(path)
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(data)
    return local


def plugin_of(context: xgfalclient.Gfal2Context) -> object:
    return context.plugin("davs://example.org/", "stat")


class Events:
    """Collects ``event_callback`` events as ``(side, domain, stage, description)``."""

    def __init__(self) -> None:
        self.seen: list[tuple[int, str, str, str]] = []

    def __call__(self, event: xgfalclient.GfaltEvent) -> None:
        self.seen.append((event.side, event.domain, event.stage, event.description))

    def stages(self, domain: str = "http_plugin") -> list[str]:
        return [f"{stage} {desc}".strip() for _, dom, stage, desc in self.seen if dom == domain]
