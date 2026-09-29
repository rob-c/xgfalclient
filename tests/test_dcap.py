"""The dcap plugin against the in-process door: namespace, I/O, copies, failures."""

from __future__ import annotations

import errno
import os
import socket
import stat
import threading
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from xgfalclient.errors import GError
from xgfalclient.plugin import O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY
from xgfalclient.plugins.dcap import DcapPlugin, KdcapPlugin, control, file, plugin, tunnel
from xgfalclient.plugins.dcap.control import ControlConnection, Door
from xgfalclient.plugins.dcap.protocol import (
    HEADER,
    INT,
    IOCMD_CLOSE,
    IOCMD_READ,
    IOCMD_SEEK,
    parse_url,
)
from xgfalclient.testing.dcap import DROP, DcapServer, Raw

GROUP = "DCAP PLUGIN"


def with_dcap(context: xgfalclient.Gfal2Context) -> DcapPlugin:
    """The context's dcap plugin, loading it if the registry does not list it yet."""
    for loaded in context.plugins:
        if type(loaded) is DcapPlugin:
            return loaded
    added = context.add_plugin(DcapPlugin)
    assert isinstance(added, DcapPlugin)
    return added


@pytest.fixture
def root(tmp_path: Path) -> Path:
    base = tmp_path / "ns"
    (base / "data" / "sub").mkdir(parents=True)
    (base / "data" / "hello.txt").write_bytes(b"hello world\n")
    return base


@pytest.fixture
def door(root: Path) -> Iterator[DcapServer]:
    with DcapServer(root) as server:
        yield server


@pytest.fixture
def dctx(ctx: xgfalclient.Gfal2Context) -> xgfalclient.Gfal2Context:
    with_dcap(ctx)
    ctx.set_opt_integer(GROUP, "OPERATION_TIMEOUT", 20)
    return ctx


def code_of(call: object, *args: object) -> int:
    with pytest.raises(GError) as info:
        call(*args)  # type: ignore[operator]
    return info.value.code


# -- identity ----------------------------------------------------------------------------


def test_identity(dctx: xgfalclient.Gfal2Context) -> None:
    loaded = with_dcap(dctx)
    assert loaded.label.startswith("dcap-")
    assert loaded.handles("dcap://door/f", "stat")
    assert loaded.handles("gsidcap://door/f", "open")
    assert not loaded.handles("kdcap://door/f", "stat")
    assert not DcapPlugin.implements("checksum")
    assert not DcapPlugin.implements("getxattr")
    assert DcapPlugin.implements("rename")


# -- namespace ---------------------------------------------------------------------------


def test_stat(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    info = dctx.stat(door.url("/data/hello.txt"))
    local = os.stat(root / "data" / "hello.txt")
    assert info.st_size == 12
    assert info.st_mode == local.st_mode
    assert (info.st_uid, info.st_gid) == (local.st_uid, local.st_gid)
    assert info.st_mtime == int(local.st_mtime)
    assert info.st_ino == local.st_ino & 0xFFFFFFF
    assert dctx.stat(door.url("/data/sub")).is_dir()
    assert door.log[0].startswith('0 0 client hello 0 0 2 47 14 "" -uid=')
    assert door.log[1] == f'1 0 client stat "dcap://127.0.0.1/data/hello.txt" -uid={control.UID}'


def test_stat_missing(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    with pytest.raises(GError) as info:
        dctx.stat(door.url("/data/nope"))
    assert info.value.code == errno.ENOENT
    # gfal2 2.23.5 against dCache 11.2, verbatim
    assert info.value.message == (
        'Error reported by the external library dcap : "No such file or directory", number : 30'
    )


def test_stat_failure_is_always_enoent(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    door.inject("stat", '{s} {c} client failed 2 "Permission denied" EACCES')
    assert code_of(dctx.stat, door.url("/data/hello.txt")) == errno.ENOENT


def test_stat_unexpected_answer(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    door.inject("stat", "{s} {c} client ok")
    assert code_of(dctx.stat, door.url("/data/hello.txt")) == errno.EPROTO


def test_failed_without_a_message(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    """A ``failed`` line with only its return code: the message is what there is."""
    door.inject("mkdir", "{s} {c} client failed 5")
    with pytest.raises(GError) as info:
        dctx.mkdir(door.url("/data/new"), 0o755)
    assert info.value.code == errno.EIO
    assert '"5"' in info.value.message


def test_lstat(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    (root / "data" / "link").symlink_to("hello.txt")
    assert dctx.lstat(door.url("/data/link")).is_link()
    assert dctx.stat(door.url("/data/link")).is_file()
    assert door.log[-2].split()[3] == "lstat"


def test_access(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    url = door.url("/data/hello.txt")
    os.chmod(root / "data" / "hello.txt", 0o644)
    assert dctx.access(url, os.F_OK) == 0
    assert dctx.access(url, os.R_OK | os.W_OK) == 0
    assert code_of(dctx.access, url, os.X_OK) == errno.EACCES
    assert code_of(dctx.access, door.url("/data/nope"), os.F_OK) == errno.ENOENT


def test_access_by_group_and_other(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    gid = os.getegid()
    door.inject("stat", f"{{s}} {{c}} client stat -st_uid=4242 -st_gid={gid} -st_mode=-rwxr-x---")
    assert dctx.access(door.url("/data/hello.txt"), os.R_OK | os.X_OK) == 0
    door.inject("stat", "{s} {c} client stat -st_uid=4242 -st_gid=4242 -st_mode=-rwxr-x--x")
    assert dctx.access(door.url("/data/hello.txt"), os.X_OK) == 0
    door.inject("stat", "{s} {c} client stat -st_uid=4242 -st_gid=4242 -st_mode=-rwxr-x---")
    assert code_of(dctx.access, door.url("/data/hello.txt"), os.R_OK) == errno.EACCES


def test_mkdir(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    dctx.mkdir(door.url("/data/new"), 0o777)
    umask = plugin.process_umask()
    assert stat.S_IMODE(os.stat(root / "data" / "new").st_mode) == 0o777 & ~umask
    assert door.log[-1].split()[5] == f"-mode={0o777 & ~umask}"
    assert code_of(dctx.mkdir, door.url("/data/new"), 0o755) == errno.EEXIST
    assert code_of(dctx.mkdir, door.url("/data/no/such"), 0o755) == errno.ENOENT


def test_mkdir_rec(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    dctx.mkdir_rec(door.url("/data/a/b/c"), 0o755)
    assert (root / "data" / "a" / "b" / "c").is_dir()


def test_chmod(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    dctx.chmod(door.url("/data/hello.txt"), 0o600)
    assert stat.S_IMODE(os.stat(root / "data" / "hello.txt").st_mode) == 0o600
    assert door.log[-1].split()[5] == "-mode=384"
    assert code_of(dctx.chmod, door.url("/data/nope"), 0o600) == errno.ENOENT


def test_rmdir(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    (root / "data" / "empty").mkdir()
    dctx.rmdir(door.url("/data/empty"))
    assert not (root / "data" / "empty").exists()
    (root / "data" / "sub" / "f").write_bytes(b"")
    # dCache says "Directory is not empty", which gfal2's ENOTEMPTY patch misses
    assert code_of(dctx.rmdir, door.url("/data/sub")) == errno.EACCES
    assert code_of(dctx.rmdir, door.url("/data/hello.txt")) == errno.EACCES
    assert code_of(dctx.rmdir, door.url("/data/nope")) == errno.ENOENT


def test_unlink(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    dctx.unlink(door.url("/data/hello.txt"))
    assert not (root / "data" / "hello.txt").exists()
    assert code_of(dctx.unlink, door.url("/data/hello.txt")) == errno.ENOENT
    assert code_of(dctx.unlink, door.url("/data/sub")) == errno.EISDIR


def test_rename(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    dctx.rename(door.url("/data/hello.txt"), door.url("/data/sub/moved one"))
    assert (root / "data" / "sub" / "moved one").read_bytes() == b"hello world\n"
    assert door.log[-1].endswith(f'"/data/sub/moved one" -uid={control.UID}')
    assert code_of(dctx.rename, door.url("/data/nope"), door.url("/data/x")) == errno.ENOENT
    other = f"dcap://127.0.0.2:{door.port}/data/x"
    assert code_of(dctx.rename, door.url("/data/sub"), other) == errno.EXDEV
    (root / "data" / "full").mkdir()
    (root / "data" / "full" / "f").write_bytes(b"")
    assert code_of(dctx.rename, door.url("/data/sub"), door.url("/data/full")) in (
        errno.EACCES,  # the local rename(2) says EEXIST or ENOTEMPTY; the door says EACCES
        errno.ENOTEMPTY,
    )


def test_listdir(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    for name in ("a:b", "with space", "ünï"):
        (root / "data" / name).write_bytes(b"x")
    names = dctx.listdir(door.url("/data"))
    assert sorted(names) == sorted(["a:b", "hello.txt", "sub", "with space", "ünï"])
    assert dctx.listdir(door.url("/data/sub")) == []
    assert code_of(dctx.listdir, door.url("/data/hello.txt")) == errno.ENOENT  # as dCache 11
    assert code_of(dctx.listdir, door.url("/data/nope")) == errno.ENOENT


def test_opendir_readpp(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    directory = dctx.opendir(door.url("/data"))
    entries = {}
    while True:
        dirent, info = directory.readpp()
        if dirent is None:
            break
        entries[dirent.d_name] = info
    assert entries["sub"].is_dir()
    assert entries["hello.txt"].st_size == 12


def test_listdir_in_chunks(
    dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(file, "LISTING_CHUNK", 16)
    for index in range(20):
        (root / "data" / "sub" / f"file-{index:02d}").write_bytes(b"")
    assert len(dctx.listdir(door.url("/data/sub"))) == 20


def test_parse_listing() -> None:
    data = b"0001:d:0:dir\n0002:f:12:a:b:c\r\nPath /x does not exist.\n0003:f:0:\n\n"
    assert plugin.parse_listing(data) == ["dir", "a:b:c"]


def test_listdir_reply_host(
    dctx: xgfalclient.Gfal2Context, door: DcapServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DCACHE_REPLY", "127.0.0.1")
    assert "sub" in dctx.listdir(door.url("/data"))
    assert door.log[-1].split()[5] == "127.0.0.1"


# -- reading -----------------------------------------------------------------------------


def test_read(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    data = os.urandom(3 * 1024 * 1024 + 17)
    (root / "data" / "big").write_bytes(data)
    with dctx.open(door.url("/data/big"), "r") as handle:
        assert handle.read_bytes(10) == data[:10]
        assert handle.pread_bytes(1000, 5) == data[1000:1005]
        assert handle.read_bytes(10) == data[10:20]
        assert handle.lseek(0, os.SEEK_END) == len(data)
        assert handle.read_bytes(10) == b""
        assert handle.lseek(-7, os.SEEK_END) == len(data) - 7
        assert handle.read_bytes(100) == data[-7:]
        handle.lseek(0)
        buffer = bytearray(len(data) + 100)
        assert handle.readinto(buffer) == len(data)
        assert bytes(buffer[: len(data)]) == data
        assert handle.read_bytes(0) == b""
    assert "open" in door.log[-1] or door.log[-1].split()[3] == "open"
    assert door.log[-1].split()[5:] == [
        "r",
        "127.0.0.1",
        door.log[-1].split()[7],
        "-timeout=-1",
        "-onerror=default",
        "-passive",
        f"-uid={control.UID}",
    ]


def test_read_missing(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    with pytest.raises(GError) as info:
        dctx.open(door.url("/data/nope"), "r")
    assert info.value.code == errno.ENOENT
    assert info.value.message.startswith("Error reported by the external library dcap")


def test_open_directory(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    assert code_of(dctx.open, door.url("/data/sub"), "r") == errno.EIO


def test_read_through_callback(dctx: xgfalclient.Gfal2Context, root: Path) -> None:
    with DcapServer(root, callback=True) as server:
        server.decoy_callback = True
        with dctx.open(server.url("/data/hello.txt"), "r") as handle:
            assert handle.read_bytes(100) == b"hello world\n"


def test_write_to_read_only_handle(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    handle = dctx.open(door.url("/data/hello.txt"), "r")
    with pytest.raises(GError) as info:
        handle.write(b"x")
    assert info.value.code == errno.EIO
    assert "WRITE denied" in info.value.message
    # The channel is now in an unknown state: everything else fails the same way.
    assert code_of(handle.read_bytes, 1) == errno.EIO
    handle.close()  # a reader's close never fails


# -- writing -----------------------------------------------------------------------------


def test_write(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    big = os.urandom(200_000)
    with dctx.open(door.url("/data/new"), "w") as handle:
        handle.write(b"abc")
        handle.write(big)
        handle.write(b"")
    assert (root / "data" / "new").read_bytes() == b"abc" + big
    assert door.checksums[-1] == zlib.adler32(b"abc" + big)
    line = door.log[-1].split()
    assert line[5:8] == ["w", "-mode=0644", "-truncate"]


def test_write_random_access(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    with dctx.open(door.url("/data/rw"), "rw") as handle:
        handle.write(b"0123456789")
        handle.pwrite(b"AB", 2)
        handle.pwrite(b"cd", 12)
        assert handle.pread_bytes(0, 20) == b"01AB456789\x00\x00cd"
        handle.lseek(4)
        handle.write(b"xy")
        handle.lseek(0, os.SEEK_END)
        handle.write(b"!")
    assert (root / "data" / "rw").read_bytes() == b"01ABxy6789\x00\x00cd!"
    assert door.checksums[-1] is None  # no checksum once writes stopped being sequential
    assert door.log[-1].split()[5:7] == ["rw", "-mode=0644"]


def test_write_existing(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    with pytest.raises(GError) as info:
        dctx.open(door.url("/data/hello.txt"), "w")
    assert info.value.code == errno.EIO
    assert "File is readOnly" in info.value.message
    door.truncate = True
    with dctx.open(door.url("/data/hello.txt"), "w") as handle:
        handle.write(b"new")
    assert (root / "data" / "hello.txt").read_bytes() == b"new"
    # Without O_TRUNC there is no -truncate, and a door that could truncate still refuses.
    with pytest.raises(GError) as info:
        with_dcap(dctx).open(door.url("/data/hello.txt"), O_WRONLY | O_CREAT)
    assert "File is readOnly" in info.value.message


def test_write_without_create(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    loaded = with_dcap(dctx)
    handle = loaded.open(door.url("/data/empty"), O_WRONLY)
    handle.close()
    assert door.log[-1].split()[5:7] == ["w", "127.0.0.1"]
    handle = loaded.open(door.url("/data/empty2"), O_WRONLY | O_CREAT, 0o600)
    handle.close()
    assert door.log[-1].split()[5:7] == ["w", "-mode=0600"]


def test_write_empty_file_again(
    dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path
) -> None:
    (root / "data" / "zero").write_bytes(b"")
    with dctx.open(door.url("/data/zero"), "w") as handle:
        handle.write(b"now")
    assert (root / "data" / "zero").read_bytes() == b"now"


def test_write_no_parent(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    assert code_of(dctx.open, door.url("/data/no/f"), "w") == errno.EIO


def test_write_failure_on_close(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    handle = dctx.open(door.url("/data/new"), "w")
    door.fault("fin-error")
    handle.write(b"data")
    with pytest.raises(GError) as info:
        handle.close()
    assert info.value.code == errno.EIO
    assert "No space left" in info.value.message
    handle.close()  # closed already: nothing more to report


def test_transfer_failure_reported_by_door(
    dctx: xgfalclient.Gfal2Context, door: DcapServer
) -> None:
    handle = dctx.open(door.url("/data/new"), "w")
    handle.write(b"data")
    door.fault("close-failed")
    with pytest.raises(GError) as info:
        handle.close()
    assert info.value.code == errno.EIO
    assert "Injected transfer failure" in info.value.message


def test_checksum_mismatch(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    loaded = with_dcap(dctx)
    handle = loaded.open(door.url("/data/new"), O_WRONLY | O_CREAT | O_TRUNC)
    handle.write(b"data")
    handle._adler = 12345  # type: ignore[attr-defined]
    with pytest.raises(GError) as info:
        handle.close()
    assert "Checksum mismatch" in info.value.message


def test_reader_ignores_close_failure(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    handle = dctx.open(door.url("/data/hello.txt"), "r")
    door.fault("close-failed")
    handle.close()


def test_size_and_locate(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    handle = with_dcap(dctx).open(door.url("/data/new"), O_RDWR | O_CREAT)
    handle.write(b"12345")
    assert handle.size() == 5
    door.fault("short-locate")
    assert code_of(handle.size) == errno.EPROTO
    assert code_of(handle.close) == errno.EPROTO  # a writer reports what broke it


# -- copies ------------------------------------------------------------------------------


def test_copy_both_ways(
    dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path, tmp_path: Path
) -> None:
    source = tmp_path / "src.bin"
    source.write_bytes(os.urandom(5 * 1024 * 1024 + 3))
    params = dctx.transfer_parameters()
    dctx.filecopy(params, f"file://{source}", door.url("/data/up.bin"))
    assert (root / "data" / "up.bin").read_bytes() == source.read_bytes()
    back = tmp_path / "back.bin"
    params = dctx.transfer_parameters()
    dctx.filecopy(params, door.url("/data/up.bin"), f"file://{back}")
    assert back.read_bytes() == source.read_bytes()
    params.overwrite = True
    dctx.filecopy(params, f"file://{source}", door.url("/data/up.bin"))
    # dcap has no checksum query, so a verified copy fails as it does in gfal2.
    params.set_checksum(xgfalclient.checksum_mode.both, "ADLER32", "")
    assert code_of(dctx.filecopy, params, f"file://{source}", door.url("/data/up.bin")) == (
        errno.EPROTONOSUPPORT
    )


# -- faults on the data channel ----------------------------------------------------------


@pytest.mark.parametrize(
    ("fault", "code", "text"),
    [
        ("ack-error", errno.EIO, "Injected failure"),
        ("ack-bare-error", errno.EIO, "no reason given"),
        ("wrong-reply", errno.EPROTO, "Expected ACK"),
        ("wrong-command", errno.EPROTO, "answered command"),
        ("bad-length", errno.EPROTO, "Bad reply length"),
        ("overflow", errno.EPROTO, "more than was asked"),
        ("fin-error", errno.EIO, "READ failed"),
        ("hangup", errno.EIO, "closed the connection"),
    ],
)
def test_read_faults(
    dctx: xgfalclient.Gfal2Context, door: DcapServer, fault: str, code: int, text: str
) -> None:
    handle = dctx.open(door.url("/data/hello.txt"), "r")
    door.fault(fault)
    with pytest.raises(GError) as info:
        handle.read_bytes(5)
    assert info.value.code == code
    assert text in info.value.message
    handle.close()


def test_sequential_reads_are_pipelined(
    dctx: xgfalclient.Gfal2Context,
    door: DcapServer,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file, "READ_AHEAD", 1000)
    data = os.urandom(10_000)
    (root / "data" / "seq").write_bytes(data)
    handle = with_dcap(dctx).open(door.url("/data/seq"), O_RDONLY)
    got = bytearray()
    for size in (300, 300, 700, 2500, 1, 5000, 2000):
        got += handle.read(size)
        if 300 < len(got) < len(data):
            # Past the first read, the next request is on the wire already.
            assert handle._requests  # type: ignore[attr-defined]
    assert bytes(got) == data
    assert handle.read(10) == b""
    assert handle.read(10) == b""
    # A read elsewhere discards the read-ahead; so do LOCATE and CLOSE.
    handle.position = 0
    assert handle.read(300) == data[:300]
    assert handle.read(300) == data[300:600]
    assert handle.pread(9000, 10) == data[9000:9010]
    assert handle.read(10) == data[600:610]
    assert handle.read(10) == data[610:620]
    assert handle.size() == len(data)
    assert handle.read(10) == data[620:630]
    assert handle.read(10) == data[630:640]
    handle.close()
    assert door.data_log[-1] == IOCMD_CLOSE


def test_write_after_read_ahead(
    dctx: xgfalclient.Gfal2Context,
    door: DcapServer,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file, "READ_AHEAD", 100)
    (root / "data" / "rw").write_bytes(b"")
    handle = with_dcap(dctx).open(door.url("/data/rw"), O_RDWR)
    handle.write(bytes(range(256)) * 4)
    handle.position = 0
    assert handle.read(10) == bytes(range(10))
    assert handle.read(10) == bytes(range(10, 20))  # starts the read-ahead
    handle.write(b"XY")  # lands at 20, whatever the mover had read ahead
    handle.close()
    expected = bytearray(bytes(range(256)) * 4)
    expected[20:22] = b"XY"
    assert (root / "data" / "rw").read_bytes() == bytes(expected)


def test_failed_read_ahead_is_reported(
    dctx: xgfalclient.Gfal2Context,
    door: DcapServer,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file, "READ_AHEAD", 100)
    (root / "data" / "f").write_bytes(os.urandom(1000))
    handle = with_dcap(dctx).open(door.url("/data/f"), O_RDONLY)
    handle.read(10)
    door.fault("fin-error", times=2)  # both requests of the read-ahead
    with pytest.raises(GError) as info:
        while handle.read(10):
            pass
    assert "READ failed" in info.value.message
    assert code_of(handle.read, 1) == errno.EIO  # the channel stays broken
    handle.close()


def test_data_channel_send_failure(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    handle = dctx.open(door.url("/data/hello.txt"), "r")
    handle._file._channel.sock.close()  # type: ignore[attr-defined]
    assert code_of(handle.read_bytes, 5) == errno.EBADF
    handle.close()


def test_listing_fault(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    door.fault("hangup")
    assert code_of(dctx.listdir, door.url("/data")) == errno.EIO


def test_listing_overflow() -> None:
    """A lister block bigger than the READ asked for."""
    with socket.create_server(("127.0.0.1", 0)) as listener:
        near = socket.create_connection(listener.getsockname())
        far, _ = listener.accept()
    with near, far:
        far.sendall(INT.pack(10) + b"x" * 10)
        channel = file.DataChannel(near, "directory lister")
        with pytest.raises(GError) as info:
            channel.receive(memoryview(bytearray(5)))
    assert info.value.code == errno.EPROTO
    assert "more than was asked" in info.value.message


@pytest.mark.parametrize(
    ("reply", "text"),
    [
        (INT.pack((1 << 20) + 1), "Bad reply length"),  # longer than any reply
        (HEADER.pack(4, file.IOCMD_DATA), "got DATA"),  # DATA where an ACK belongs
        (HEADER.pack(8, file.IOCMD_ACK) + INT.pack(IOCMD_READ), "got ACK"),  # too short
    ],
)
def test_malformed_replies(reply: bytes, text: str) -> None:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        near = socket.create_connection(listener.getsockname())
        far, _ = listener.accept()
    with near, far:
        far.sendall(reply)
        channel = file.DataChannel(near, "pool")
        with pytest.raises(GError) as info:
            channel.expect(file.IOCMD_ACK, IOCMD_READ)
    assert info.value.code == errno.EPROTO
    assert text in info.value.message


# -- the control line --------------------------------------------------------------------


def test_connection_reuse(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    for _ in range(5):
        dctx.stat(door.url("/data/hello.txt"))
    assert door.connections == 1


def test_stale_connection_is_replaced(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    dctx.stat(door.url("/data/hello.txt"))
    door.inject("stat", DROP)
    assert dctx.stat(door.url("/data/hello.txt")).st_size == 12
    assert door.connections == 2


def test_dropped_fresh_connection(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    # A connection failure keeps its errno (dc_stat() would say ENOENT).
    door.inject("stat", DROP)
    assert code_of(dctx.stat, door.url("/data/hello.txt")) == errno.ECONNRESET


def test_timeout_is_not_retried(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    dctx.set_opt_integer(GROUP, "OPERATION_TIMEOUT", 1)
    dctx.stat(door.url("/data/hello.txt"))
    door.inject("mkdir", "999 0 client ok")
    assert code_of(dctx.mkdir, door.url("/data/x"), 0o755) == errno.ETIMEDOUT
    assert door.connections == 1


def test_other_sessions_are_skipped(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    door.inject("mkdir", "999 0 client failed 1 x\nshort line\n{s} {c} client ok")
    dctx.mkdir(door.url("/data/x"), 0o755)


def test_open_waits_through_noise(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    door.inject(
        "open", '{s} {c} client pong\n7 7 client ok\n{s} {c} client failed 2 "No such file"'
    )
    assert code_of(dctx.open, door.url("/data/hello.txt"), "r") == errno.ENOENT


def test_open_retry(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    door.inject("open", "{s} {c} client retry")
    assert code_of(dctx.open, door.url("/data/hello.txt"), "r") == errno.EAGAIN


def test_open_timeout(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    dctx.set_opt_integer(GROUP, "OPERATION_TIMEOUT", 1)
    door.inject("open", "{s} {c} client pong")
    assert code_of(dctx.open, door.url("/data/hello.txt"), "r") == errno.ETIMEDOUT


@pytest.mark.parametrize("args", ["", "host", "host notaport challenge"])
def test_malformed_connect(dctx: xgfalclient.Gfal2Context, door: DcapServer, args: str) -> None:
    door.inject("open", "{s} {c} client connect " + args)
    assert code_of(dctx.open, door.url("/data/hello.txt"), "r") == errno.EPROTO


def test_pool_unreachable(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    with socket.socket() as spare:
        spare.bind(("127.0.0.1", 0))
        port = spare.getsockname()[1]
    door.inject("open", f"{{s}} {{c}} client connect 127.0.0.1 {port} abc")
    assert code_of(dctx.open, door.url("/data/hello.txt"), "r") == errno.ECONNREFUSED


def test_door_unreachable(dctx: xgfalclient.Gfal2Context) -> None:
    with socket.socket() as spare:
        spare.bind(("127.0.0.1", 0))
        port = spare.getsockname()[1]
    assert code_of(dctx.mkdir, f"dcap://127.0.0.1:{port}/x", 0o755) == errno.ECONNREFUSED


def test_hello_rejected(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    door.welcome = '0 0 server reject 1 "Client version rejected"'
    with pytest.raises(GError) as info:
        dctx.mkdir(door.url("/data/x"), 0o755)
    assert info.value.code == errno.EIO
    assert 'rejected "hello": reject' in info.value.message
    door.inject("hello", DROP)
    with pytest.raises(GError) as info:
        dctx.mkdir(door.url("/data/x"), 0o755)
    assert "closed the connection" in info.value.message


def test_invalid_url(dctx: xgfalclient.Gfal2Context) -> None:
    assert code_of(dctx.stat, "dcap:///no/host") == errno.EINVAL


def test_pool_limit(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    handles = [dctx.open(door.url("/data/hello.txt"), "r") for _ in range(control.MAX_IDLE + 2)]
    for handle in handles:
        handle.close()
    assert door.connections == control.MAX_IDLE + 2
    for _ in range(control.MAX_IDLE + 2):
        dctx.stat(door.url("/data/hello.txt"))
    assert door.connections == control.MAX_IDLE + 2


def test_threads(dctx: xgfalclient.Gfal2Context, door: DcapServer, root: Path) -> None:
    errors: list[BaseException] = []

    def work(index: int) -> None:
        try:
            url = door.url(f"/data/t{index}")
            with dctx.open(url, "w") as handle:
                handle.write(str(index).encode() * 1000)
            assert dctx.stat(url).st_size == len(str(index)) * 1000
            with dctx.open(url, "r") as handle:
                assert handle.read_bytes(10_000) == str(index).encode() * 1000
        except BaseException as exc:  # reported below
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors


def test_free_closes_connections(door: DcapServer) -> None:
    context = xgfalclient.creat_context()
    with_dcap(context)
    context.stat(door.url("/data/hello.txt"))
    context.free()
    context2 = xgfalclient.creat_context()
    with_dcap(context2).close()
    context2.free()


# -- callbacks -----------------------------------------------------------------------------


def test_callback_listener_failure(
    dctx: xgfalclient.Gfal2Context, door: DcapServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    dctx.stat(door.url("/data/hello.txt"))  # connect first, with the real socket class

    class Unbindable(socket.socket):
        def bind(self, address: object) -> None:
            raise OSError(errno.EADDRNOTAVAIL, "no address")

    monkeypatch.setattr(file.socket, "socket", Unbindable)
    assert code_of(dctx.listdir, door.url("/data")) == errno.EADDRNOTAVAIL


def test_callback_accept_failure(
    dctx: xgfalclient.Gfal2Context, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = file.callback_listener

    class Refusing(socket.socket):
        def accept(self) -> tuple[socket.socket, object]:
            raise OSError(errno.EMFILE, "too many files")

    def listener(conn: ControlConnection) -> tuple[socket.socket, str, int]:
        sock, host, port = real(conn)
        refusing = Refusing(sock.family, sock.type, fileno=sock.detach())
        return refusing, host, port

    monkeypatch.setattr(plugin, "callback_listener", listener)
    with DcapServer(root, callback=True) as server:
        assert code_of(dctx.open, server.url("/data/hello.txt"), "r") == errno.EMFILE


@pytest.mark.parametrize(("session", "length"), [(1, -1), (1, 5000), (1, None)])
def test_callback_bad_hello(
    dctx: xgfalclient.Gfal2Context,
    door: DcapServer,
    session: int,
    length: int | None,
) -> None:
    """A pool calling back with a broken greeting."""

    def open_reply(s: int, args: list[str]) -> str:
        host, port = args[2], int(args[3])
        with socket.create_connection((host, port)) as caller:
            if length is None:
                caller.sendall(b"\x00\x00")
            else:
                caller.sendall(HEADER.pack(s, length))
            caller.shutdown(socket.SHUT_WR)
            caller.recv(1)
        return "{s} {c} client pong"

    door.inject("open", open_reply)
    code = code_of(dctx.open, door.url("/data/hello.txt"), "r")
    assert code == (errno.EIO if length is None else errno.EPROTO)


# -- kdcap -----------------------------------------------------------------------------------


def test_kdcap_unavailable(dctx: xgfalclient.Gfal2Context, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tunnel, "kerberos_module", lambda: None)
    assert KdcapPlugin.available() is not None
    assert "Kerberos" in str(KdcapPlugin.available())
    kdcap = dctx.add_plugin(KdcapPlugin)
    with pytest.raises(GError) as info:
        kdcap.stat("kdcap://door/f")
    assert info.value.code == errno.EPROTONOSUPPORT
    assert "Kerberos" in info.value.message


# -- the connection pool, directly -------------------------------------------------------------


def test_door_call_non_gerror(door: DcapServer) -> None:
    url = parse_url(door.url("/"))
    opened: list[ControlConnection] = []

    def connect() -> ControlConnection:
        opened.append(ControlConnection.open(url, None, 5))
        return opened[-1]

    pool = Door(url, connect)

    def broken(conn: ControlConnection, session: int) -> None:
        raise ValueError("bug")

    with pytest.raises(ValueError):
        pool.call(broken)
    assert opened[0].closed
    closed = ControlConnection.open(url, None, 5)
    closed.close()
    pool.release(closed)
    assert not pool._idle
    pool.close()


def test_socket_error_without_errno() -> None:
    error = control.socket_error(OSError("gone"), "The door")
    assert error.code == errno.EIO
    assert error.message == "The door: gone"


def test_ipv6_door(dctx: xgfalclient.Gfal2Context, root: Path) -> None:
    with DcapServer(root, host="::1") as door:
        url = door.url("/data/hello.txt")
        assert url.startswith("dcap://[::1]:")
        with dctx.open(url, "r") as handle:
            assert handle.read_bytes(100) == b"hello world\n"


def test_raw_injection_breaks_plain_line(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    door.inject("stat", Raw(b"1 0 client stat -st_size=3\n"))
    assert dctx.stat(door.url("/data/hello.txt")).st_size == 3


def test_seek_and_plain_read_on_the_mover(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    """Commands libdcap sends that this client does not: SEEK and plain READ."""
    handle = dctx.open(door.url("/data/hello.txt"), "r")
    channel = handle._file._channel  # type: ignore[attr-defined]
    channel.send(file._SEEK_WRITE.pack(16, IOCMD_SEEK, 6, 0))
    assert channel.expect(file.IOCMD_ACK, IOCMD_SEEK) == (6).to_bytes(8, "big")
    channel.send(file._READ.pack(12, IOCMD_READ, 100))
    channel.expect(file.IOCMD_ACK, IOCMD_READ)
    channel.expect(file.IOCMD_DATA)
    buffer = bytearray(100)
    assert channel.receive(memoryview(buffer)) == 6
    channel.expect(file.IOCMD_FIN, IOCMD_READ)
    assert bytes(buffer[:6]) == b"world\n"
    handle.close()


def test_open_flags_reach_the_door(dctx: xgfalclient.Gfal2Context, door: DcapServer) -> None:
    loaded = with_dcap(dctx)
    loaded.open(door.url("/data/hello.txt"), O_RDONLY).close()
    assert door.log[-1].split()[5] == "r"
