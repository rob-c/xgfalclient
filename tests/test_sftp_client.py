"""The pipelined SFTP v3 client, against the in-process SFTP server."""

from __future__ import annotations

import errno
import os
import threading
from pathlib import Path

import pytest

from xgfalclient.crypto.sshkeys import string
from xgfalclient.errors import GError
from xgfalclient.plugins.sftp import protocol as fx
from xgfalclient.plugins.sftp.client import MAX_PACKET, SFTPClient, WriteBehind
from xgfalclient.plugins.sftp.protocol import Attrs, StatusError
from xgfalclient.testing.sftp import SFTPServer


@pytest.fixture
def server(tmp_path: Path) -> SFTPServer:
    (tmp_path / "hello.txt").write_bytes(b"hello world\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "inner.bin").write_bytes(b"\x00\x01\x02\x03")
    return SFTPServer(tmp_path)


def connect(server: SFTPServer) -> SFTPClient:
    client = SFTPClient(server.pair())
    client.handshake()
    return client


def test_handshake_extensions_and_limits(server: SFTPServer) -> None:
    client = connect(server)
    assert "posix-rename@openssh.com" in client.extensions
    assert client.max_read == 261120 and client.max_write == 261120
    client.close()


def test_handshake_without_limits(tmp_path: Path) -> None:
    server = SFTPServer(tmp_path, limits=None)
    client = connect(server)
    assert "limits@openssh.com" not in client.extensions
    assert client.max_read == 32768  # the draft default
    # Without limits the server caps a READ at 1 MiB of its own accord.
    (tmp_path / "f").write_bytes(b"x" * 10)
    handle = client.open(b"/f", fx.FXF_READ)
    assert client.read(handle, 0, 100) == b"x" * 10
    client.close()


def test_handshake_rejects_banner(tmp_path: Path) -> None:
    server = SFTPServer(tmp_path)
    server.faults.append("banner")
    client = SFTPClient(server.pair())
    with pytest.raises(GError, match=r"login shell printing text|length"):
        client.handshake()


def test_stat_and_missing(server: SFTPServer) -> None:
    client = connect(server)
    info = client.stat(b"/hello.txt")
    assert info.size == 12
    with pytest.raises(StatusError) as caught:
        client.stat(b"/nope")
    assert caught.value.errno == errno.ENOENT
    client.close()


def test_read_write_seek(server: SFTPServer) -> None:
    client = connect(server)
    handle = client.open(b"/hello.txt", fx.FXF_READ)
    assert client.read(handle, 0, 5) == b"hello"
    assert client.read(handle, 6, 100) == b"world\n"
    assert client.read(handle, 100, 10) == b""  # EOF
    client.close_handle(handle)
    # Write a new file.
    wh = client.open(b"/new.txt", fx.FXF_WRITE | fx.FXF_CREAT | fx.FXF_TRUNC)
    writer = WriteBehind(client, wh, chunk=4)  # three WRITEs
    writer.write(0, b"some data")
    writer.flush()
    client.fsync(wh)
    client.close_handle(wh)
    assert (Path(server.root) / "new.txt").read_bytes() == b"some data"
    client.close()


def test_namespace_operations(server: SFTPServer) -> None:
    client = connect(server)
    client.mkdir(b"/d", Attrs(permissions=0o755))
    client.setstat(b"/hello.txt", Attrs(permissions=0o600))
    assert client.stat(b"/hello.txt").permissions & 0o777 == 0o600
    client.rename(b"/hello.txt", b"/d/renamed.txt")  # posix-rename
    assert client.stat(b"/d/renamed.txt").size == 12
    client.symlink(b"/d/renamed.txt", b"/link")
    assert client.readlink(b"/link") == "/d/renamed.txt"
    assert client.lstat(b"/link").is_link
    entries = {name for name, _long, _a in client.listdir(b"/d")}
    assert "renamed.txt" in entries and "." in entries
    client.remove(b"/link")
    client.mkdir(b"/empty", Attrs(permissions=0o755))
    client.rmdir(b"/empty")
    with pytest.raises(StatusError):
        client.stat(b"/empty")
    client.close()


def test_rename_without_posix_extension(tmp_path: Path) -> None:
    from xgfalclient.testing.sftp import OPENSSH_EXTENSIONS

    (tmp_path / "a").write_bytes(b"x")
    exts = {k: v for k, v in OPENSSH_EXTENSIONS.items() if k != "posix-rename@openssh.com"}
    server = SFTPServer(tmp_path, extensions=exts)
    client = connect(server)
    assert "posix-rename@openssh.com" not in client.extensions
    client.rename(b"/a", b"/b")  # plain v3 rename
    assert (tmp_path / "b").exists()
    client.close()


def test_fsync_absent_is_noop(tmp_path: Path) -> None:
    from xgfalclient.testing.sftp import OPENSSH_EXTENSIONS

    exts = {k: v for k, v in OPENSSH_EXTENSIONS.items() if k != "fsync@openssh.com"}
    server = SFTPServer(tmp_path, extensions=exts)
    client = connect(server)
    wh = client.open(b"/f", fx.FXF_WRITE | fx.FXF_CREAT)
    client.fsync(wh)  # no extension: silently does nothing
    client.close_handle(wh)
    client.close()


def test_limits_reply_not_extended(tmp_path: Path) -> None:
    server = SFTPServer(tmp_path)
    server.inject(fx.EXTENDED, fx.FX_FAILURE, "no")  # the limits probe gets a STATUS
    client = SFTPClient(server.pair())
    client.handshake()
    assert client.max_read == 32768  # kept the default
    client.close()


def test_realpath_and_statvfs(server: SFTPServer) -> None:
    client = connect(server)
    assert client.realpath(b".") == "/"
    vfs = client.statvfs(b"/")
    assert set(vfs) >= {"bsize", "blocks", "namemax"}
    client.close()


def test_fstat(server: SFTPServer) -> None:
    client = connect(server)
    handle = client.open(b"/hello.txt", fx.FXF_READ)
    assert client.fstat(handle).size == 12
    client.close_handle(handle)
    client.close()


def test_check_file_extension(tmp_path: Path) -> None:
    import hashlib

    (tmp_path / "f.bin").write_bytes(b"abc" * 100)
    server = SFTPServer(tmp_path, check_file=("md5", "sha1"))
    client = connect(server)
    algo, digest = client.check_file(b"/f.bin", "sha1,md5")
    # The server picks the first requested algorithm it supports.
    assert algo == "sha1"
    assert digest == hashlib.sha1(b"abc" * 100).digest()
    # A range: 30 bytes from offset 3.
    _, digest = client.check_file(b"/f.bin", "md5", offset=3, length=30)
    assert digest == hashlib.md5(b"abc" * 10).digest()
    client.close()


def test_hardlink(tmp_path: Path) -> None:
    (tmp_path / "orig").write_bytes(b"data")
    server = SFTPServer(tmp_path)
    client = connect(server)
    client.hardlink(b"/orig", b"/link")
    assert (tmp_path / "link").read_bytes() == b"data"
    client.close()


def test_read_into_pipelined(tmp_path: Path) -> None:
    payload = os.urandom(400_000)
    (tmp_path / "big.bin").write_bytes(payload)
    server = SFTPServer(tmp_path)
    client = connect(server)
    handle = client.open(b"/big.bin", fx.FXF_READ)
    buf = bytearray(len(payload) + 5000)  # ask past EOF
    got = client.read_into(handle, 0, memoryview(buf), depth=8)
    assert got == len(payload)
    assert bytes(buf[:got]) == payload
    client.close_handle(handle)
    client.close()


def test_read_into_short_reads(tmp_path: Path) -> None:
    payload = os.urandom(200_000)
    (tmp_path / "big.bin").write_bytes(payload)
    server = SFTPServer(tmp_path)
    server.faults.extend(["short_read", "short_read"])
    client = connect(server)
    handle = client.open(b"/big.bin", fx.FXF_READ)
    buf = bytearray(len(payload))
    got = client.read_into(handle, 0, memoryview(buf), depth=4)
    assert got == len(payload) and bytes(buf) == payload
    client.close_handle(handle)
    client.close()


def test_stream_read(tmp_path: Path) -> None:
    payload = os.urandom(300_000)
    (tmp_path / "big.bin").write_bytes(payload)
    server = SFTPServer(tmp_path)
    server.faults.append("short_read")
    client = connect(server)
    handle = client.open(b"/big.bin", fx.FXF_READ)
    chunks: dict[int, bytes] = {}
    total = client.stream_read(
        handle, 0, None, lambda off, mv: chunks.__setitem__(off, bytes(mv)), depth=4
    )
    assert total == len(payload)
    joined = b"".join(chunks[k] for k in sorted(chunks))
    assert joined == payload
    client.close_handle(handle)
    client.close()


def test_stream_read_with_length(tmp_path: Path) -> None:
    payload = os.urandom(100_000)
    (tmp_path / "big.bin").write_bytes(payload)
    server = SFTPServer(tmp_path)
    client = connect(server)
    handle = client.open(b"/big.bin", fx.FXF_READ)
    seen = bytearray()
    total = client.stream_read(handle, 10, 5000, lambda off, mv: seen.extend(mv), depth=2)
    assert total == 5000 and bytes(seen) == payload[10:5010]
    client.close_handle(handle)
    client.close()


def test_write_behind_error_surfaces(server: SFTPServer) -> None:
    client = connect(server)
    wh = client.open(b"/w.bin", fx.FXF_WRITE | fx.FXF_CREAT | fx.FXF_TRUNC)
    server.inject(fx.WRITE, fx.FX_FAILURE, "disk full")
    writer = WriteBehind(client, wh, depth=2)
    with pytest.raises(StatusError):
        for i in range(10):
            writer.write(i * 100, b"x" * 100)
        writer.flush()
    # After a failure the writer refuses further writes.
    with pytest.raises(StatusError):
        writer.write(0, b"more")
    client.close()


def test_readdir_eof_and_batches(tmp_path: Path) -> None:
    for i in range(5):
        (tmp_path / f"f{i}").write_bytes(b"x")
    server = SFTPServer(tmp_path, batch=2)
    client = connect(server)
    names = [name for name, _long, _a in client.listdir(b"/")]
    assert sorted(n for n in names if n.startswith("f")) == ["f0", "f1", "f2", "f3", "f4"]
    client.close()


def test_pipelined_multithreaded(tmp_path: Path) -> None:
    for i in range(8):
        (tmp_path / f"f{i}").write_bytes(bytes([i]) * 1000)
    server = SFTPServer(tmp_path)
    client = connect(server)
    results: dict[int, int] = {}
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            results[i] = client.stat(f"/f{i}".encode()).size
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and all(v == 1000 for v in results.values())
    client.close()


# -- fault injection and protocol errors -------------------------------------


def test_inject_status(server: SFTPServer) -> None:
    server.inject(fx.STAT, fx.FX_PERMISSION_DENIED, "nope")
    client = connect(server)
    with pytest.raises(StatusError) as caught:
        client.stat(b"/hello.txt")
    assert caught.value.errno == errno.EACCES
    client.close()


def test_reorder_fault(server: SFTPServer) -> None:
    # The client files responses by id, so a reversed pair still resolves.
    # Inject after the handshake so the fault lands on our own requests.
    client = connect(server)
    server.faults.append("reorder")
    a = client.send(fx.STAT, string(b"/hello.txt"))
    b = client.send(fx.STAT, string(b"/sub"))
    assert client._attrs(client.wait(a)).size == 12
    assert client._attrs(client.wait(b)).is_dir
    client.close()


def test_drop_fault(server: SFTPServer) -> None:
    client = connect(server)
    server.faults.append("drop")
    with pytest.raises(GError):
        client.stat(b"/hello.txt")
    assert not client.alive
    client.close()


def test_garbage_length(server: SFTPServer) -> None:
    client = connect(server)
    server.faults.append("garbage")
    with pytest.raises(GError, match="length"):
        client.stat(b"/hello.txt")
    client.close()


def test_wrong_reply_type(server: SFTPServer) -> None:
    client = connect(server)
    server.faults.append("wrong_type")
    with pytest.raises(GError, match="expected"):
        client.stat(b"/hello.txt")
    # An OPEN is answered with a NAME rather than the HANDLE it wants.
    server.faults.append("wrong_type")
    with pytest.raises(GError, match=f"expected packet {fx.HANDLE}, got {fx.NAME}"):
        client.open(b"/hello.txt", fx.FXF_READ)
    client.close()


def test_oversize_data(tmp_path: Path) -> None:
    (tmp_path / "f.bin").write_bytes(b"abcdef")
    server = SFTPServer(tmp_path)
    server.faults.append("oversize")
    client = connect(server)
    handle = client.open(b"/f.bin", fx.FXF_READ)
    buf = bytearray(6)
    with pytest.raises(GError, match="DATA"):
        client.read_into(handle, 0, memoryview(buf))
    client.close()


def test_forget_releases_pending(tmp_path: Path) -> None:
    payload = os.urandom(300_000)
    (tmp_path / "big.bin").write_bytes(payload)
    server = SFTPServer(tmp_path)
    client = connect(server)
    handle = client.open(b"/big.bin", fx.FXF_READ)
    # A small view over a large file leaves reads outstanding, which the
    # finally-clause forgets.
    buf = bytearray(1000)
    got = client.read_into(handle, 0, memoryview(buf), chunk=100, depth=16)
    assert got == 1000
    client.close_handle(handle)
    client.close()


def test_send_after_close_raises(server: SFTPServer) -> None:
    client = connect(server)
    client.close()
    with pytest.raises(GError):
        client.stat(b"/hello.txt")


def test_close_handle_quiet(server: SFTPServer) -> None:
    client = connect(server)
    # Closing an invalid handle raises unless quiet.
    with pytest.raises((StatusError, GError)):
        client.close_handle(b"\x00\x00\x00\x99")
    client.close_handle(b"\x00\x00\x00\x99", quiet=True)
    client.close()


def test_max_packet_guard(server: SFTPServer) -> None:
    assert MAX_PACKET == 64 * 1024 * 1024


def test_readdir_error_status(server: SFTPServer) -> None:
    client = connect(server)
    server.inject(fx.READDIR, fx.FX_PERMISSION_DENIED, "denied")
    with pytest.raises(StatusError) as caught:
        list(client.listdir(b"/"))
    assert caught.value.errno == errno.EACCES
    client.close()


def test_read_error_status(server: SFTPServer) -> None:
    client = connect(server)
    handle = client.open(b"/hello.txt", fx.FXF_READ)
    server.inject(fx.READ, fx.FX_PERMISSION_DENIED, "denied")
    with pytest.raises(StatusError):
        client.read(handle, 0, 5)
    client.close()


def test_status_helper_wrong_packet(server: SFTPServer) -> None:
    client = connect(server)
    server.faults.append("wrong_type")
    # mkdir expects STATUS but the fault answers with a HANDLE.
    with pytest.raises(GError, match="expected STATUS"):
        client.mkdir(b"/newdir", Attrs(permissions=0o755))
    client.close()


def test_read_into_answered_with_ok(tmp_path: Path) -> None:
    (tmp_path / "f.bin").write_bytes(b"abcdef")
    server = SFTPServer(tmp_path)
    client = connect(server)
    handle = client.open(b"/f.bin", fx.FXF_READ)
    server.inject(fx.READ, fx.FX_OK, "")  # a bogus OK to a READ
    buf = bytearray(6)
    with pytest.raises(GError, match="answered with OK"):
        client.read_into(handle, 0, memoryview(buf))
    client.close()


def test_stream_read_error_status(tmp_path: Path) -> None:
    (tmp_path / "big.bin").write_bytes(os.urandom(100_000))
    server = SFTPServer(tmp_path)
    client = connect(server)
    handle = client.open(b"/big.bin", fx.FXF_READ)
    server.inject(fx.READ, fx.FX_FAILURE, "io error")
    with pytest.raises(StatusError):
        client.stream_read(handle, 0, None, lambda off, mv: None, depth=4)
    client.close()


def test_read_into_fills_to_depth(tmp_path: Path) -> None:
    payload = os.urandom(2000)
    (tmp_path / "f.bin").write_bytes(payload)
    server = SFTPServer(tmp_path)
    client = connect(server)
    handle = client.open(b"/f.bin", fx.FXF_READ)
    buf = bytearray(len(payload))
    # Small chunks and a small depth make the pipeline fill to its limit.
    got = client.read_into(handle, 0, memoryview(buf), chunk=100, depth=4)
    assert got == len(payload) and bytes(buf) == payload
    client.close()


def test_read_into_error_status(tmp_path: Path) -> None:
    (tmp_path / "big.bin").write_bytes(os.urandom(100_000))
    server = SFTPServer(tmp_path)
    client = connect(server)
    handle = client.open(b"/big.bin", fx.FXF_READ)
    server.inject(fx.READ, fx.FX_FAILURE, "io error")
    buf = bytearray(100_000)
    # Small chunks keep several reads in flight, so the failure leaves pending
    # requests for the finally-clause to forget.
    with pytest.raises(StatusError):
        client.read_into(handle, 0, memoryview(buf), chunk=1000, depth=4)
    client.close()


def test_stream_read_clean_eof_with_check(tmp_path: Path) -> None:
    payload = os.urandom(40_000)
    (tmp_path / "f.bin").write_bytes(payload)
    server = SFTPServer(tmp_path)
    client = connect(server)
    handle = client.open(b"/f.bin", fx.FXF_READ)
    calls = []
    seen = bytearray()
    # A chunk smaller than the file makes a later read land exactly on EOF,
    # so the server answers with an EOF status rather than a short DATA.
    total = client.stream_read(
        handle,
        0,
        None,
        lambda off, mv: seen.extend(mv),
        chunk=10_000,
        depth=8,
        check=lambda: calls.append(1),
    )
    assert total == len(payload) and bytes(seen) == payload and calls
    client.close()


def test_stream_read_answered_with_ok(tmp_path: Path) -> None:
    (tmp_path / "f.bin").write_bytes(os.urandom(50_000))
    server = SFTPServer(tmp_path)
    client = connect(server)
    handle = client.open(b"/f.bin", fx.FXF_READ)
    server.inject(fx.READ, fx.FX_OK, "")
    with pytest.raises(GError, match="answered with OK"):
        client.stream_read(handle, 0, None, lambda off, mv: None, depth=4)
    client.close()


def test_stream_read_short_to_eof(tmp_path: Path) -> None:
    payload = os.urandom(50_000)
    (tmp_path / "big.bin").write_bytes(payload)
    server = SFTPServer(tmp_path)
    server.faults.append("short_read")
    client = connect(server)
    handle = client.open(b"/big.bin", fx.FXF_READ)
    seen = bytearray()
    total = client.stream_read(handle, 0, None, lambda off, mv: seen.extend(mv), depth=8)
    assert total == len(payload) and bytes(seen) == payload
    client.close()


def test_write_behind_flush_reraises_stored_error(server: SFTPServer) -> None:
    client = connect(server)
    wh = client.open(b"/w.bin", fx.FXF_WRITE | fx.FXF_CREAT | fx.FXF_TRUNC)
    server.inject(fx.WRITE, fx.FX_FAILURE, "full", count=5)
    writer = WriteBehind(client, wh, depth=1)
    writer.write(0, b"x" * 10)  # queued, not yet acknowledged
    with pytest.raises(StatusError):
        writer.write(10, b"y" * 10)  # settles the first, which failed
    # The error is stored; flush re-raises it rather than hanging.
    with pytest.raises(StatusError):
        writer.flush()
    client.close()
