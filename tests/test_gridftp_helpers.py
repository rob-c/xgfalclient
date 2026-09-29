"""Fixtures and helpers shared by the gridftp tests (no tests of its own)."""

from __future__ import annotations

import os
import socket
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import xgfalclient
from xgfalclient.plugins.gridftp.data import DataTransfer
from xgfalclient.plugins.gridftp.plugin import GROUP, GridFTPPlugin, _ThirdParty
from xgfalclient.testing.gridftp import GridFTPServer
from xgfalclient.testing.pki import PKI, test_key

__all__ = [
    "GROUP",
    "FakeServer",
    "Events",
    "code_of",
    "ftp",
    "gctx",
    "gsi",
    "gsi_pair",
    "make_gsi",
    "plugin_of",
    "write",
]


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Short poll and grace intervals so failure paths finish quickly."""
    monkeypatch.setattr(DataTransfer, "POLL", 0.02)
    monkeypatch.setattr(DataTransfer, "GRACE", 0.3)
    monkeypatch.setattr(_ThirdParty, "POLL", 0.02)


@pytest.fixture
def gctx() -> Iterator[xgfalclient.Gfal2Context]:
    context = xgfalclient.creat_context()
    context.set_opt_integer(GROUP, "OPERATION_TIMEOUT", 10)
    yield context
    context.free()


def plugin_of(context: xgfalclient.Gfal2Context) -> GridFTPPlugin:
    found = context.plugin("gsiftp://host/", "stat")
    assert isinstance(found, GridFTPPlugin)
    return found


def write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


@pytest.fixture
def ftp(tmp_path: Path) -> Iterator[GridFTPServer]:
    """A cleartext, anonymous server over ``tmp_path/ftp``."""
    root = tmp_path / "ftp"
    root.mkdir()
    with GridFTPServer(root) as server:
        yield server


def make_gsi(pki: PKI, root: Path, **options: Any) -> GridFTPServer:
    root.mkdir(parents=True, exist_ok=True)
    return GridFTPServer(
        root,
        gsi=pki.server_context(),
        ca_path=str(pki.ca_dir),
        delegation_key=test_key(4),
        **options,
    )


@pytest.fixture
def gsi(grid_env: PKI, tmp_path: Path) -> Iterator[GridFTPServer]:
    """A GSI server over ``tmp_path/gsi``, the client pointed at the test PKI."""
    with make_gsi(grid_env, tmp_path / "gsi") as server:
        yield server


@pytest.fixture
def gsi_pair(grid_env: PKI, tmp_path: Path) -> Iterator[tuple[GridFTPServer, GridFTPServer]]:
    """Two GSI servers, for third-party copies."""
    with (
        make_gsi(grid_env, tmp_path / "a", perf_interval=0.01) as one,
        make_gsi(grid_env, tmp_path / "b", perf_interval=0.01) as two,
    ):
        yield one, two


def code_of(call: Callable[[], Any]) -> tuple[int, str]:
    """``(errno, message)`` of the GError ``call`` raises."""
    with pytest.raises(xgfalclient.GError) as caught:
        call()
    return caught.value.code, caught.value.message


class Events:
    """Collects copy events."""

    def __init__(self) -> None:
        self.items: list[Any] = []

    def __call__(self, event: Any) -> None:
        self.items.append(event)

    def stages(self) -> list[tuple[str, str, str]]:
        return [(e.domain, e.stage, e.description) for e in self.items]


class FakeServer:
    """A one-connection TCP server that plays ``script(sock)``: for replies a
    real server would never send."""

    def __init__(self, script: Callable[[socket.socket], None]) -> None:
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.script = script
        self.received: list[bytes] = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        sock, _ = self.listener.accept()
        try:
            self.script(sock)
        finally:
            sock.close()
            self.listener.close()

    def url(self, path: str = "/f") -> str:
        return f"ftp://127.0.0.1:{self.port}{path}"

    def join(self) -> None:
        self.thread.join(5)


def lines(sock: socket.socket) -> Iterator[str]:
    """Command lines as a client sends them."""
    buffer = b""
    while True:
        while b"\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                return
            buffer += chunk
        line, buffer = buffer.split(b"\n", 1)
        yield line.rstrip(b"\r").decode()


def login_script(
    after: Callable[[socket.socket, Iterator[str]], None],
) -> Callable[[socket.socket], None]:
    """Greet, accept an anonymous login and an empty FEAT, then hand over."""

    def script(sock: socket.socket) -> None:
        sock.sendall(b"220 fake ready\r\n")
        commands = lines(sock)
        for line in commands:
            verb = line.split()[0]
            if verb == "USER":
                sock.sendall(b"331 pass\r\n")
            elif verb == "PASS":
                sock.sendall(b"230 ok\r\n")
            elif verb == "FEAT":
                sock.sendall(b"211-Extensions supported\r\n211 End.\r\n")
            elif verb == "SITE":
                sock.sendall(b"250 OK.\r\n")
            elif verb == "TYPE":
                sock.sendall(b"200 Type set.\r\n")
                after(sock, commands)
                return

    return script


def slow_file(path: Path, size: int) -> Path:
    return write(path, os.urandom(size))
