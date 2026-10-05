"""The GFAL adapters retain error, callback and buffer-policy contracts."""

from __future__ import annotations

import errno
import hashlib
import http.client
import io
from types import SimpleNamespace

import pytest
from xrdclient.copy import _pipeline
from xrdclient.http import _connection as shared_connection
from xrdclient.http import expect

from xgfalclient import GError
from xgfalclient.plugin import PluginFile
from xgfalclient.plugins.http import _connection
from xgfalclient.transfer import Transfer, pump


def test_connection_compatibility_path_is_the_shared_module():
    assert _connection is shared_connection


class Reader(PluginFile):
    def __init__(self):
        super().__init__("file:///source")
        self.file = io.BytesIO(b"abcdefghijkl")

    def readinto(self, view):
        return self.file.readinto(view)


@pytest.mark.parametrize("count", [0, -1, 100])
def test_gfal_preserves_io_error_code_for_invalid_writes(ctx, count):
    transfer = Transfer(ctx, ctx.transfer_parameters(), "file:///source", "file:///target")
    writer = SimpleNamespace(write=lambda view: count)
    with pytest.raises(GError) as caught:
        pump(transfer, Reader(), writer, buffer_size=4)
    assert caught.value.code == errno.EIO


def test_gfal_partial_writer_reports_only_committed_chunks(ctx):
    transfer = Transfer(ctx, ctx.transfer_parameters(), "file:///source", "file:///target")
    received = bytearray()

    def write(view):
        received.extend(view[:1])
        return 1

    assert pump(transfer, Reader(), SimpleNamespace(write=write), buffer_size=4) == 12
    assert received == b"abcdefghijkl"
    assert transfer.transferred == 12


@pytest.mark.parametrize("recycle", [False, True])
@pytest.mark.parametrize("depth", [1, 2])
def test_shared_pipeline_buffer_policies_and_read_only_fallback(recycle, depth):
    source = SimpleNamespace(read=io.BytesIO(b"abcde").read)
    target = io.BytesIO()
    digest = hashlib.sha256()
    assert _pipeline.pump(source, target, None, 2, None, digest, depth, recycle=recycle) == 5
    assert target.getvalue() == b"abcde"
    assert digest.digest() == hashlib.sha256(b"abcde").digest()


def test_shared_pipeline_zero_write_has_a_default_error():
    with pytest.raises(OSError):
        _pipeline.write_all(SimpleNamespace(write=lambda view: 0), memoryview(b"x"))


def test_shared_pipeline_accepts_legacy_writer_without_byte_count():
    received = []
    _pipeline.write_all(
        SimpleNamespace(write=lambda view: received.append(bytes(view))), memoryview(b"x")
    )
    assert received == [b"x"]


@pytest.mark.parametrize("headers", [None, {"User-Agent": "contract-test"}])
def test_shared_connection_retains_stdlib_request_header_contract(headers):
    class Connection(shared_connection._ResponseCompatibility, http.client.HTTPConnection):
        def send(self, data):
            pass  # record framing without opening a socket

    conn = Connection("localhost")
    conn.request("GET", "/", headers=headers)
    conn.close()


@pytest.mark.parametrize(
    ("method", "length", "wanted"),
    [("GET", None, False), ("PUT", None, True), ("PUT", 0, False), ("POST", 16384, True)],
)
def test_shared_expect_threshold_remains_xrd_policy(method, length, wanted):
    assert expect.wants_expect(method, length) is wanted


def test_shared_interim_reader_accepts_lf_terminated_headers():
    incoming = iter(bytes([byte]) for byte in b"HTTP/1.1 100 Continue\n\n")
    sock = SimpleNamespace(
        gettimeout=lambda: 5, settimeout=lambda wait: None, recv=lambda count: next(incoming, b"")
    )
    assert expect._read_head(sock, 1) == b"HTTP/1.1 100 Continue\n\n"


def test_shared_interim_reader_rejects_an_incomplete_status_line(monkeypatch):
    monkeypatch.setattr(expect, "_read_head", lambda sock, wait: b"bad\r\n\r\n")
    sock = SimpleNamespace(recv_into=lambda view: 0, close=lambda: None)
    with pytest.raises(http.client.BadStatusLine):
        expect.await_continue(SimpleNamespace(sock=sock), "PUT")
