# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""The bulk data path: bodies read straight off the socket, and TLS uploads in big blocks."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

import xgfalclient
from test_http_helpers import dav, davs, hctx, write  # noqa: F401 - fixtures
from xgfalclient import GError
from xgfalclient.errors import ECOMM
from xgfalclient.plugins.http import _copy
from xgfalclient.plugins.http._client import FileBody, TransportError
from xgfalclient.testing.pki import PKI
from xgfalclient.testing.webdav import WebDAVServer

MB = 1 << 20


def file_url(path: Path) -> str:
    return "file://" + os.fspath(path)


@pytest.fixture(params=["dav", "davs"])
def server(request: pytest.FixtureRequest, tmp_path: Path) -> WebDAVServer:
    """Both transports: a plain socket and a TLS one take different read paths."""
    if request.param == "dav":
        return request.getfixturevalue("dav")  # type: ignore[no-any-return]
    request.getfixturevalue("grid_env")
    return request.getfixturevalue("davs")  # type: ignore[no-any-return]


def test_round_trip(hctx: xgfalclient.Gfal2Context, server: WebDAVServer, tmp_path: Path) -> None:
    data = os.urandom(5 * MB + 3)
    source = tmp_path / "up"
    source.write_bytes(data)
    hctx.filecopy(file_url(source), server.url("/data/f"))
    assert server.local("/data/f").read_bytes() == data
    hctx.filecopy(server.url("/data/f"), file_url(tmp_path / "down"))
    assert (tmp_path / "down").read_bytes() == data


def test_direct_reads_in_pieces(hctx: xgfalclient.Gfal2Context, server: WebDAVServer) -> None:
    data = b"first line\n" + os.urandom(MB + 5)
    write(server, "/data/f", data)
    plugin = hctx.plugin(server.url("/data/f"), "stat")
    buffer = bytearray(200_000)
    with plugin._get(server.url("/data/f"), {}) as response:  # type: ignore[attr-defined]
        # A buffered read first leaves http.client holding some of the body.
        got = bytearray(response.readline())
        while True:
            count = response.readinto(buffer)
            if not count:
                break
            got += buffer[:count]
    assert bytes(got) == data
    # Read to the end, the connection went back to the pool for the next request.
    assert plugin.client.idle_count() == 1  # type: ignore[attr-defined]
    assert plugin.stat(server.url("/data/f")).st_size == len(data)


def test_parallel_download_over_tls_uses_two_streams(
    hctx: xgfalclient.Gfal2Context,
    davs: WebDAVServer,
    grid_env: PKI,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_copy, "PARALLEL_THRESHOLD", MB)
    data = os.urandom(3 * MB + 17)
    write(davs, "/data/big", data)
    hctx.filecopy(davs.url("/data/big"), file_url(tmp_path / "big"))
    assert (tmp_path / "big").read_bytes() == data
    ranges = [r.header("Range") for r in davs.requests if r.method == "GET"]
    assert len(ranges) == _copy.TLS_STREAMS
    assert _copy._default_streams("https://h/f") == _copy.TLS_STREAMS
    assert _copy._default_streams("dav://h/f") == _copy.DEFAULT_STREAMS


def test_body_cut_short(hctx: xgfalclient.Gfal2Context, server: WebDAVServer) -> None:
    body = os.urandom(MB)
    server.fault("GET", status=200, body=body, truncate=300_000)
    plugin = hctx.plugin(server.url("/data/f"), "stat")
    buffer = bytearray(MB)
    with plugin._get(server.url("/data/f"), {}) as response:  # type: ignore[attr-defined]
        got = 0
        with pytest.raises(TransportError) as caught:
            while True:
                count = response.readinto(buffer)
                assert count
                got += count
        assert got == 300_000
    assert caught.value.code == ECOMM
    assert "never arrived" in caught.value.message


def test_tls_upload_of_a_short_file(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI, tmp_path: Path
) -> None:
    source = tmp_path / "up"
    source.write_bytes(b"x" * 1000)
    plugin = hctx.plugin(davs.url("/data/f"), "stat")
    with source.open("rb") as handle, pytest.raises(GError) as caught:
        plugin._put_file(  # type: ignore[attr-defined]
            davs.url("/data/f"), FileBody(handle, 0, 2000), 2000
        )
    assert caught.value.code == errno.EIO and "Short read" in caught.value.message
