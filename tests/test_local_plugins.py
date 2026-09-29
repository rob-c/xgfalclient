"""The file and mock plugins, the plugin registry, and the package-level functions."""

from __future__ import annotations

import errno
import logging
import os
import signal
import sys
import threading
import types
import zlib
from pathlib import Path
from typing import Any

import pytest

import xgfalclient
from conftest import file_url
from xgfalclient import GError, Gfal2Context, checksum_mode, plugins
from xgfalclient.plugin import O_CREAT, O_RDWR, O_WRONLY, Plugin, PluginFile
from xgfalclient.plugins import file as file_plugin
from xgfalclient.plugins import mock as mock_module
from xgfalclient.plugins.file import FilePlugin, LocalFile
from xgfalclient.plugins.mock import MockPlugin
from xgfalclient.transfer import Transfer

LOCAL = f"errno reported by local system call {os.strerror(errno.ENOENT)}"


# -- file:// -------------------------------------------------------------------------------


def test_file_urls_need_an_empty_host(ctx: Gfal2Context, data_dir: Path) -> None:
    assert ctx.stat(file_url(data_dir / "hello.txt")).st_size == 12
    for url in ("file://localhost/tmp", "file:tmp", "/tmp"):
        with pytest.raises(GError) as caught:
            ctx.stat(url)
        assert caught.value.code == errno.EPROTONOSUPPORT


def test_file_namespace(ctx: Gfal2Context, data_dir: Path) -> None:
    base = file_url(data_dir)
    with pytest.raises(GError) as caught:
        ctx.stat(base + "/nope")
    assert (caught.value.code, caught.value.message) == (errno.ENOENT, LOCAL)
    assert ctx.mkdir(base + "/sub", 0o755) == 0
    with pytest.raises(GError) as caught:
        ctx.mkdir(base + "/sub", 0o755)
    assert caught.value.code == errno.EEXIST
    assert ctx.mkdir_rec(base + "/a/b/c", 0o755) == 0
    assert (data_dir / "a" / "b" / "c").is_dir()
    with pytest.raises(GError) as caught:
        ctx.rmdir(base + "/a")
    assert caught.value.code == errno.ENOTEMPTY
    with pytest.raises(GError) as caught:
        ctx.rmdir(base + "/hello.txt")
    assert caught.value.code == errno.ENOTDIR
    with pytest.raises(GError) as caught:
        ctx.unlink(base + "/sub")
    assert caught.value.code == errno.EISDIR
    assert ctx.rename(base + "/hello.txt", base + "/moved.txt") == 0
    assert ctx.chmod(base + "/moved.txt", 0o600) == 0
    assert (data_dir / "moved.txt").stat().st_mode & 0o777 == 0o600
    assert ctx.access(base + "/moved.txt", os.R_OK) == 0
    assert ctx.symlink(base + "/moved.txt", base + "/link") == 0
    assert ctx.symlink("relative-target", base + "/rel") == 0
    assert ctx.readlink(base + "/link") == str(data_dir / "moved.txt")
    assert ctx.lstat(base + "/link").is_link()
    assert ctx.unlink(base + "/link") == 0
    assert ctx.symlink(base + "/sub", base + "/dirlink") == 0
    assert ctx.unlink(base + "/dirlink") == 0  # a link to a directory is still just a link
    assert ctx.rmdir(base + "/sub") == 0


def test_file_access_errors(ctx: Gfal2Context, data_dir: Path) -> None:
    base = file_url(data_dir)
    with pytest.raises(GError) as caught:
        ctx.access(base + "/nope", os.F_OK)
    assert caught.value.code == errno.ENOENT
    locked = data_dir / "locked"
    locked.write_text("x")
    locked.chmod(0)
    try:
        if os.access(locked, os.R_OK):  # running as root: permissions never deny
            pytest.skip("root ignores permission bits")
        with pytest.raises(GError) as caught:
            ctx.access(base + "/locked", os.R_OK)
        assert caught.value.code == errno.EACCES
    finally:
        locked.chmod(0o600)


def test_file_listing_includes_dot_entries(ctx: Gfal2Context, data_dir: Path) -> None:
    (data_dir / "sub").mkdir()
    base = file_url(data_dir)
    assert sorted(ctx.listdir(base)) == [".", "..", "hello.txt", "sub"]
    entries = {e.d_name: e.d_type for e in ctx.opendir(base)}
    assert entries == {".": 4, "..": 4, "hello.txt": 8, "sub": 4}
    with pytest.raises(GError) as caught:
        ctx.listdir(base + "/hello.txt")
    assert caught.value.code == errno.ENOTDIR


def test_file_listing_tolerates_vanishing_entries(ctx: Gfal2Context, data_dir: Path) -> None:
    class Gone:
        name = "gone"

        def stat(self, follow_symlinks: bool = True) -> os.stat_result:
            raise FileNotFoundError(errno.ENOENT, "gone")

    plugin = ctx.plugin("file:///", "opendir")
    assert isinstance(plugin, FilePlugin)
    entries = list(plugin._entries(str(data_dir), [Gone()]))  # type: ignore[list-item]
    assert entries[-1] == ("gone", None, 0)


def test_file_listing_reports_each_entrys_own_type(ctx: Gfal2Context, data_dir: Path) -> None:
    """d_type as readdir gives it: a link is DT_LNK, a FIFO DT_FIFO, whatever they point at."""
    (data_dir / "link").symlink_to(data_dir / "hello.txt")
    (data_dir / "dangling").symlink_to(data_dir / "nowhere")
    os.mkfifo(data_dir / "fifo")
    entries = {e.d_name: e.d_type for e in ctx.opendir(file_url(data_dir))}
    assert (entries["link"], entries["dangling"], entries["fifo"]) == (10, 10, 1)
    (data_dir / "dangling").unlink()
    directory = ctx.opendir(file_url(data_dir))
    found = {}
    for _ in range(6):  # ., .., hello.txt, link, fifo, then the end
        entry, info = directory.readpp()
        if entry is not None:
            found[entry.d_name] = (entry.d_type, info.st_size)  # type: ignore[union-attr]
    assert found["link"] == (10, 12)  # its stat is the target's


def test_file_io(ctx: Gfal2Context, data_dir: Path) -> None:
    base = file_url(data_dir)
    with ctx.open(base + "/hello.txt", "r") as handle:
        assert handle.read(5) == "hello"
        assert handle.pread(6, 5) == "world"
        buffer = bytearray(4)
        assert handle.readinto(buffer) == 4 and buffer == b" wor"
        assert handle.lseek(-2, os.SEEK_END) == 10
        assert handle.read_bytes(10) == b"d\n"
        assert handle.read(10) == ""
    with ctx.open(base + "/new.txt", "w") as handle:
        assert handle.write("abc") == 3
        assert handle.pwrite(b"Z", 0) == 1
    assert (data_dir / "new.txt").read_bytes() == b"Zbc"
    with ctx.open(base + "/new.txt", "rw") as handle:
        handle.lseek(0, os.SEEK_END)
        handle.write("d")
    assert (data_dir / "new.txt").read_bytes() == b"Zbcd"
    with pytest.raises(GError) as caught:
        ctx.open(base + "/missing/x", "w")
    assert caught.value.code == errno.ENOENT


def test_file_io_errors_are_worded_as_gfal2(ctx: Gfal2Context, data_dir: Path) -> None:
    with ctx.open(file_url(data_dir) + "/hello.txt", "r") as handle:
        with pytest.raises(GError) as caught:
            handle.write("x")
        assert caught.value.args == (
            "errno reported by local system call Bad file descriptor",
            errno.EBADF,
        )
        with pytest.raises(GError) as caught:
            handle.lseek(-100, os.SEEK_SET)
        assert caught.value.args == (
            "errno reported by local system call Invalid argument",
            errno.EINVAL,
        )


def test_file_pwrite_retries_short_writes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    real = os.pwrite
    monkeypatch.setattr(
        file_plugin.os, "pwrite", lambda fd, data, offset: real(fd, bytes(data[:2]), offset)
    )
    handle = LocalFile("file://x", str(tmp_path / "f"), O_WRONLY | O_CREAT, 0o644)
    assert handle.pwrite(b"abcdefg", 0) == 7
    handle.close()
    handle.close()
    assert (tmp_path / "f").read_bytes() == b"abcdefg"
    rw = LocalFile("file://x", str(tmp_path / "f"), O_RDWR, 0o644)
    assert rw.size() == 7
    rw.close()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ADLER32", "1e720467"),
        ("md5", "6f5902ac237024bdd0c176cb93063dc4"),
        ("crc32", str(zlib.crc32(b"hello world\n"))),  # decimal, as gfal2 prints it
    ],
)
def test_file_checksums(ctx: Gfal2Context, data_dir: Path, name: str, expected: str) -> None:
    assert ctx.checksum(file_url(data_dir / "hello.txt"), name) == expected


def test_file_checksum_ranges_and_errors(ctx: Gfal2Context, data_dir: Path) -> None:
    url = file_url(data_dir / "hello.txt")
    assert ctx.checksum(url, "adler32", 2, 3) == f"{zlib.adler32(b'llo'):08x}"
    assert ctx.checksum(url, "adler32", 6, 0) == f"{zlib.adler32(b'world' + bytes([10])):08x}"
    assert ctx.checksum(url, "md5", 0, 1000) == "6f5902ac237024bdd0c176cb93063dc4"
    with pytest.raises(GError) as caught:
        ctx.checksum(url, "sha256")
    assert (caught.value.code, caught.value.message) == (
        errno.ENOSYS,
        "Checksum type sha256 not supported for local files",
    )
    with pytest.raises(GError) as caught:
        ctx.checksum(file_url(data_dir), "adler32")
    assert caught.value.code == errno.EISDIR
    assert caught.value.message.startswith("Error during checksum calculation, read:")


def test_file_checksum_read_error_without_errno(
    ctx: Gfal2Context, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: object) -> str:
        raise OSError("short read")

    monkeypatch.setattr(file_plugin, "_digest", fail)
    with pytest.raises(GError) as caught:
        ctx.checksum(file_url(data_dir / "hello.txt"), "adler32")
    assert caught.value.code == errno.EIO


def test_file_checksum_of_large_files(ctx: Gfal2Context, tmp_path: Path) -> None:
    big = tmp_path / "big"
    payload = os.urandom((4 << 20) + 5)
    big.write_bytes(payload)
    assert ctx.checksum(file_url(big), "adler32") == f"{zlib.adler32(payload):08x}"
    length = (4 << 20) + 2
    assert ctx.checksum(file_url(big), "crc32", 1, length) == str(
        zlib.crc32(payload[1 : 1 + length])
    )


def test_file_xattrs(ctx: Gfal2Context, data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    url = file_url(data_dir / "hello.txt")
    store: dict[str, bytes] = {}
    monkeypatch.setattr(
        file_plugin.os, "setxattr", lambda p, n, v, f: store.__setitem__(n, v), raising=False
    )
    monkeypatch.setattr(
        file_plugin.os,
        "getxattr",
        lambda p, n: store[n] if n in store else _enodata(),
        raising=False,
    )
    monkeypatch.setattr(file_plugin.os, "listxattr", lambda p: list(store), raising=False)
    assert ctx.setxattr(url, "user.k", "v", 0) == 0
    assert ctx.getxattr(url, "user.k") == "v"
    assert ctx.listxattr(url) == ["user.k"]
    with pytest.raises(GError) as caught:
        ctx.getxattr(url, "user.missing")
    assert caught.value.code == errno.ENODATA


def _enodata() -> bytes:
    raise OSError(errno.ENODATA, os.strerror(errno.ENODATA))


def test_file_xattrs_without_os_support(
    ctx: Gfal2Context, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("getxattr", "setxattr", "listxattr"):
        monkeypatch.delattr(file_plugin.os, name, raising=False)
    url = file_url(data_dir / "hello.txt")
    assert ctx.listxattr(url) == []
    with pytest.raises(GError) as caught:
        ctx.getxattr(url, "user.status")
    assert caught.value.code == errno.ENODATA
    with pytest.raises(GError) as caught:
        ctx.setxattr(url, "user.k", "v", 0)
    assert caught.value.code == errno.ENOTSUP


def _local(code: int) -> str:
    return f"errno reported by local system call {os.strerror(code)}"


def test_file_access_reports_the_real_errno(
    ctx: Gfal2Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = file_url(tmp_path)
    (tmp_path / "afile").write_text("x")
    (tmp_path / "dangle").symlink_to(tmp_path / "nothere")
    (tmp_path / "loop1").symlink_to(tmp_path / "loop2")
    (tmp_path / "loop2").symlink_to(tmp_path / "loop1")
    for path, mode, code in [
        ("/afile/b", os.R_OK, errno.ENOTDIR),
        ("/dangle", os.F_OK, errno.ENOENT),
        ("/loop1", os.F_OK, errno.ELOOP),
        ("/afile", os.X_OK, errno.EACCES),  # no execute bit: even root is refused
        ("/afile", 64, errno.EINVAL),
    ]:
        with pytest.raises(GError) as caught:
            ctx.access(base + path, mode)
        assert (caught.value.code, caught.value.message) == (code, _local(code))
    monkeypatch.setattr(file_plugin.os, "access", lambda path, mode: False)
    monkeypatch.setattr(
        file_plugin.os, "statvfs", lambda path: types.SimpleNamespace(f_flag=os.ST_RDONLY)
    )
    with pytest.raises(GError) as caught:
        ctx.access(base + "/afile", os.W_OK)
    assert caught.value.code == errno.EROFS
    monkeypatch.setattr(file_plugin.os, "statvfs", lambda path: types.SimpleNamespace(f_flag=0))
    with pytest.raises(GError) as caught:
        ctx.access(base + "/afile", os.W_OK)
    assert caught.value.code == errno.EACCES


def test_file_listing_follows_links(ctx: Gfal2Context, tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"hello!")
    (tmp_path / "lnk").symlink_to(tmp_path / "a.txt")
    os.mkfifo(tmp_path / "fifo")
    base = file_url(tmp_path)
    directory = ctx.opendir(base)
    found = {}
    while True:
        dirent, info = directory.readpp()
        if dirent is None:
            break
        found[dirent.d_name] = info
    assert found["lnk"].st_size == 6 and found["lnk"].is_file()  # the target, as gfal2 shows it
    (tmp_path / "gone").symlink_to(tmp_path / "nothere")
    directory = ctx.opendir(base)
    with pytest.raises(GError) as caught:  # gfal2 aborts the long listing here too
        while directory.readpp()[0] is not None:
            pass
    assert caught.value.code == errno.ENOENT
    assert "gone" in [e.d_name for e in ctx.opendir(base)]  # a plain listing still works


def test_file_open_modes_and_errors(ctx: Gfal2Context, tmp_path: Path) -> None:
    base = file_url(tmp_path)
    old = os.umask(0o022)
    try:
        with ctx.open(base + "/new", "w") as handle:
            handle.write("x")
    finally:
        os.umask(old)
    assert (tmp_path / "new").stat().st_mode & 0o777 == 0o744  # gfal2's S_IRWXU|S_IRGRP|S_IROTH
    with ctx.open(base + "/new", "r") as handle:
        with pytest.raises(GError) as caught:
            handle.write("y")
        assert (caught.value.code, caught.value.message) == (errno.EBADF, _local(errno.EBADF))
        for offset, whence in ((-10, os.SEEK_SET), (0, 7)):
            with pytest.raises(GError) as caught:
                handle.lseek(offset, whence)
            assert caught.value.message == _local(errno.EINVAL)
        assert handle.lseek(1, os.SEEK_SET) == 1 and handle.lseek(-1, os.SEEK_CUR) == 0


def test_file_reads_a_fifo_in_order(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    writer = threading.Thread(target=lambda: fifo.write_bytes(b"abcdef"), daemon=True)
    writer.start()
    handle = LocalFile("file://x", str(fifo), os.O_RDONLY, 0)
    assert handle.read(3) == b"abc"
    buffer = bytearray(10)
    assert handle.readinto(buffer) == 3 and buffer[:3] == b"def"
    assert handle.readinto(buffer) == 0
    with pytest.raises(GError) as caught:
        handle.lseek(0)
    assert caught.value.code == errno.ESPIPE
    handle.close()
    writer.join(10)


def test_file_checksum_names_are_not_trimmed(ctx: Gfal2Context, data_dir: Path) -> None:
    with pytest.raises(GError) as caught:
        ctx.checksum(file_url(data_dir / "hello.txt"), "Adler32 ")
    assert caught.value.code == errno.ENOSYS


# -- mock:// -------------------------------------------------------------------------------
# Expected values are gfal2 2.23.5's, observed in the gfal-ref image.

M = "mock://host/path"


def mock_plugin(ctx: Gfal2Context) -> MockPlugin:
    found = ctx.plugin(M, "stat")
    assert isinstance(found, MockPlugin)
    return found


def entries(ctx: Gfal2Context, url: str) -> list[tuple[str, str, int]]:
    listing = mock_plugin(ctx).opendir(url)
    return [(name, oct(info.st_mode), info.st_size) for name, info in listing if info]


@pytest.fixture
def slept(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record, rather than sleep, the mock plugin's waits."""
    calls: list[float] = []
    monkeypatch.setattr(mock_module.time, "sleep", calls.append)
    return calls


def test_mock_query_is_parsed_as_gfal2_does(ctx: Gfal2Context) -> None:
    def size(query: str) -> int:
        return ctx.stat(M + query).st_size

    assert (size(""), size("?size=1234"), size("?sizefoo&size=3")) == (0, 1234, 3)
    assert oct(ctx.stat(M + "?size=1").st_mode) == "0o100755"
    # the first argument whose name starts with the key, taken raw
    assert (size("?size_pre=3&size=10"), size("?size_post=7&size=10")) == (3, 7)
    assert (size("?size=1%30"), size("?size=1&size=2"), size("#?size=4")) == (1, 1, 4)
    # strtoull: a leading number, junk is 0, negatives wrap and overflows saturate
    assert (size("?size=12abc"), size("?size=bogus"), size("?size= 7"), size("?size=-0")) == (
        12,
        0,
        7,
        0,
    )
    assert size("?size=-5") == 2**64 - 5
    assert size("?size=99999999999999999999") == 2**64 - 1
    assert ctx.stat(M + "?listing=a").is_dir() and not ctx.stat(M + "?list=").is_dir()
    for query in ("?errno=13", "?errnox=13", "?errno=4294967309"):
        with pytest.raises(GError) as caught:
            ctx.stat(M + query)
        assert (caught.value.code, caught.value.message) == (errno.EACCES, "Permission denied")
    assert ctx.stat(M + "?errno=-1").st_size == 0  # only a positive errno fails
    assert ctx.stat(M + "?errno=+abc").st_size == 0
    assert mock_module._strtol("-99999999999999999999") == (-(2**63), 21)


def test_mock_scheme_is_a_prefix(ctx: Gfal2Context) -> None:
    plugin = mock_plugin(ctx)
    assert plugin.handles("mock:foo?size=3", "stat")
    assert not plugin.handles("MOCK://h/p", "stat")
    assert plugin.copy_check("mock:a", "mock://h/b")
    assert not plugin.copy_check("mock:a", "file:///b")
    assert not plugin.copy_check("file:///a", "mock:b")


def test_mock_wait_and_signals(
    ctx: Gfal2Context, slept: list[float], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert ctx.stat(M + "?wait=2&size=1").st_size == 1
    assert ctx.unlink(M + "?wait=-1") == 0  # a negative wait does not sleep
    received: list[int] = []
    monkeypatch.setattr(signal, "signal", signal.signal)  # restored after the test
    signal.signal(signal.SIGUSR1, lambda number, frame: received.append(number))
    ctx.stat(M + f"?signal={int(signal.SIGUSR1)}")  # [MOCK PLUGIN] SIGNALS is off
    assert received == [] and slept == [2]
    fresh = xgfalclient.creat_context()
    fresh.set_opt_boolean("MOCK PLUGIN", "SIGNALS", True)
    try:
        assert fresh.stat(M + f"?signal={int(signal.SIGUSR1)}&size=2").st_size == 2
        assert fresh.stat(M + "?signal=100000").st_size == 0  # raise() of no signal is ignored
    finally:
        fresh.free()
    assert received == [signal.SIGUSR1] and slept == [2, 1, 1]
    signal.signal(signal.SIGUSR1, signal.SIG_DFL)


def test_mock_load_time_signal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[int] = []
    monkeypatch.setattr(signal, "signal", signal.signal)
    previous = signal.signal(signal.SIGUSR2, lambda number, frame: received.append(number))
    try:
        cmdline = tmp_path / "cmdline"
        cmdline.write_bytes(b"python3\0-c\0xMOCK_LOAD_TIME_SIGNAL%d\0" % int(signal.SIGUSR2))
        mock_module._load_time_signal(str(cmdline))
        assert received == [signal.SIGUSR2]
        cmdline.write_bytes(b"python3\0-c\0")
        mock_module._load_time_signal(str(cmdline))
        mock_module._load_time_signal(str(tmp_path / "missing"))  # no /proc: nothing
        assert received == [signal.SIGUSR2]
    finally:
        signal.signal(signal.SIGUSR2, previous)


def test_mock_stat_stages_for_fts_url_copy(ctx: Gfal2Context) -> None:
    ctx.set_user_agent("some_tool", "1.0")
    assert ctx.stat(M + "?size_pre=4&size=1").st_size == 4
    ctx.set_user_agent("fts_url_copy", "3.12")
    destination = M + "/d?size=9&size_pre=4&size_post=10"
    assert ctx.stat(M + "/s?size=7").st_size == 7  # the source
    assert ctx.stat(destination).st_size == 4  # the destination before the copy
    assert ctx.stat(destination).st_size == 10  # ... and after
    ctx.stat(M + "/s?size=7")
    with pytest.raises(GError) as caught:  # size_pre=0 is "no destination yet"
        ctx.stat(M + "/d?size=9&size_post=10")
    assert caught.value.code == errno.ENOENT
    params = ctx.transfer_parameters()
    ctx.filecopy(params, M + "/s?size=10", destination + "&time=0")  # the copy skips a stage
    assert ctx.stat(destination).st_size == 10


def test_mock_access(ctx: Gfal2Context) -> None:
    plugin = mock_plugin(ctx)
    for query in ("?access=1", "?exists=1", "?access_errno=13", "?errno=13&exists=1"):
        assert plugin.access(M + query, os.R_OK) == 1  # gfal2's binding returns the 1 too
    for query, code in (
        ("", errno.ENOENT),
        ("?exists=0", errno.ENOENT),
        ("?size=1", errno.ENOENT),
        ("?access=0&access_errno=13", errno.EACCES),
    ):
        with pytest.raises(GError) as caught:
            ctx.access(M + query, os.R_OK)
        assert caught.value.code == code


def test_mock_namespace(ctx: Gfal2Context, slept: list[float]) -> None:
    assert ctx.mkdir(M + "/d?access_errno=13&errno=2", 0o755) == 0
    assert ctx.mkdir_rec(M + "/x/y/z", 0o755) == 0
    assert ctx.mkdir(M + "/a/b?rd_path=mock://host/path/a", 0o755) == 0  # rd_path is shorter
    for url in (
        M + "/a/?rd_path=mock://host/path/a/",
        M + "/?rd_path=mock://host/path/a/",  # a URL that prefixes a read-only path
        M + "/a?xrd_path=mock://host/path/a",
        M + "/a?rd_path=&rd_path=mock://host/path/a/b",
    ):
        for call in (ctx.mkdir, ctx.mkdir_rec):
            with pytest.raises(GError) as caught:
                call(url, 0o755)
            assert (caught.value.code, caught.value.message) == (
                errno.EPERM,
                "Operation not permitted",
            )
    assert mock_module._values(M, "rd_path") == []
    # unlink is a stat
    assert ctx.unlink(M + "?access_errno=13&wait=1") == 0 and slept == [1]
    with pytest.raises(GError) as caught:
        ctx.unlink(M + "?errno=13")
    assert caught.value.code == errno.EACCES
    results = ctx.unlink([M + "?errno=2", M])
    assert isinstance(results, list) and results[0].code == errno.ENOENT and results[1] is None
    for call in (
        lambda: ctx.rmdir(M + "/d?list=a"),
        lambda: ctx.rename(M + "/a", M + "/b"),
        lambda: ctx.chmod(M + "/a", 0o700),
        lambda: ctx.listxattr(M),
        lambda: ctx.setxattr(M, "user.x", "1", 0),
        lambda: ctx.token_retrieve(M, "", 60, False),
    ):
        with pytest.raises(GError) as caught:
            call()
        assert caught.value.code == errno.EPROTONOSUPPORT


def test_mock_listing(ctx: Gfal2Context) -> None:
    listing = M + "?list=a:0644:10,b:040755:3,,c,d:10,e:x:5"
    assert ctx.listdir(listing) == ["a", "b", "c", "d", "e"]
    # gfal2 reads a size one character past the end of the mode
    assert entries(ctx, listing) == [
        ("a", "0o100644", 10),
        ("b", "0o40755", 3),
        ("c", "0o0", 0),
        ("d", "0o100010", 0),
        ("e", "0o100000", 0),
    ]
    assert entries(ctx, M + "?list=a:0644,5:x,b: 7:9,c:-1:2,d:0644:") == [
        ("a", "0o100644", 5),
        ("5", "0o100000", 0),
        ("b", "0o100007", 9),
        ("c", "0o37777777777", 2),
        ("d", "0o100644", 0),
    ]
    assert entries(ctx, M + "?list=x:0644:-3")[0][2] == 2**64 - 3
    assert ctx.listdir(M + "?list=,,a,") == ["a"]
    long = ",".join(f"n{i:03d}" for i in range(300))
    assert len(ctx.listdir(M + "?list=" + long)) == 205  # gfal2 reads 1023 characters
    with pytest.raises(GError) as caught:
        ctx.listdir(M + "?size=1")
    assert caught.value.code == errno.ENOTDIR
    with pytest.raises(GError) as caught:
        ctx.listdir(M + "?errno=2&list=a")
    assert caught.value.code == errno.ENOENT


def test_mock_reads(ctx: Gfal2Context, slept: list[float]) -> None:
    with ctx.open(M + "?size=5", "r") as handle:
        data = handle.read_bytes(10)
        assert len(data) == 5 and data != handle.pread_bytes(0, 5)  # random, as gfal2's
        assert handle.lseek(0, os.SEEK_END) == 5
        assert len(handle.pread_bytes(4, 10)) == 1
        assert handle.pread_bytes(9, 10) == b""
    with ctx.open(M + "?size=4&read_wait=3", "r") as handle:
        assert len(handle.read_bytes(4)) == 4 and slept == [3]
    with ctx.open(M + "?size=5&read_errno=5", "r") as handle, pytest.raises(GError) as caught:
        handle.read_bytes(5)
    assert caught.value.code == errno.EIO
    for url, code in ((M + "?open_errno=13", errno.EACCES), (M + "?errno=2", errno.ENOENT)):
        with pytest.raises(GError) as caught:
            ctx.open(url, "r")
        assert caught.value.code == code
    assert ctx.open(M + "?size=1&wait=2", "r") and slept == [3, 2]  # open stats first
    for flag in ("w", "rw"):
        with pytest.raises(GError) as caught:
            ctx.open(M, flag)
        assert (caught.value.code, caught.value.message) == (
            errno.ENOSYS,
            "Mock plugin does not support read and write",
        )
    with mock_plugin(ctx).open(M, O_WRONLY) as sink:  # only a bare O_WRONLY: /dev/null
        assert sink.write(b"hello") == 5


def test_mock_checksum_and_xattrs(ctx: Gfal2Context) -> None:
    assert ctx.checksum(M + "?checksum=abc123", "adler32") == "00abc123"
    assert ctx.checksum(M + "?checksum=a", "FOO", 5, 10) == "a"
    assert ctx.checksum(M, "md5") == ""
    with pytest.raises(GError) as caught:
        ctx.checksum(M + "?errno=2&checksum=a", "md5")
    assert caught.value.code == errno.ENOENT
    query = "?user.status=ONLINE&user.replicas=a,b&user.guid=g1&user.comment=c&spacetoken=T"
    answers = [ctx.getxattr(M + query, name) for name in mock_module._XATTRS]
    assert answers == ["ONLINE", "a,b", "g1", "c", "T"]
    assert ctx.getxattr(M + "?user.guidx=5", "user.guid") == "5"
    assert ctx.getxattr(M + "?errno=0", "anything") == ""  # gfal2 tests the errno buffer
    for url, name in (
        (M, "user.status"),
        (M + "?staging_time=100", "user.status"),
        (M + "?replicas=a", "user.replicas"),
        (M + "?errno=0", "user.guid"),
        (M + "?foo=1", "foo"),
        (M + "?checksum=abc", "user.checksum"),
    ):
        with pytest.raises(GError) as caught:
            ctx.getxattr(url, name)
        assert (caught.value.code, caught.value.message) == (
            errno.ENODATA,
            f"Failed to retrieve xattr {name}",
        )
    with pytest.raises(GError) as caught:
        ctx.getxattr(M + "?errno=5&user.status=ONLINE", "user.status")
    assert caught.value.code == errno.EIO


def test_mock_staging(ctx: Gfal2Context) -> None:
    base = M + "/test_mock_staging"
    slow = base + "/slow?staging_time=3600"
    status, token = ctx.bring_online(slow, 10, 10, False)
    assert status == 1 and token  # a synchronous request is done at once
    assert ctx.bring_online(slow, 10, 10, True)[0] == 0
    assert ctx.bring_online_poll(slow, token) == 0
    assert ctx.abort_bring_online(slow, token) == 0
    assert ctx.bring_online_poll(slow, token) == 0  # gfal2's abort changes nothing
    assert mock_plugin(ctx).bring_online_poll([slow, base + "/other"], token) == [False, True]
    assert xgfalclient.creat_context().bring_online_poll(slow, token) == 0  # process-wide
    failing = base + "/f?staging_time=3600&staging_errno=5"
    assert ctx.bring_online(failing, 10, 10, True)[0] == 0  # the error waits for the time
    with pytest.raises(GError) as caught:
        ctx.bring_online(failing, 10, 10, False)
    assert caught.value.code == errno.EIO
    errors, _ = ctx.bring_online([base + "/e?staging_errno=5", slow, base], 10, 10, True)
    assert errors[0].code == errno.EIO and errors[1:] == [None, None]
    assert ctx.bring_online_poll(base + "/never", "t") == 1
    assert ctx.bring_online(base + "/now", 10, 10, True)[0] == 1
    assert ctx.bring_online_poll(base + "/now", "t") == 1
    with pytest.raises(GError) as caught:
        ctx.bring_online_poll(base + "/never?staging_errno=2", "t")
    assert caught.value.code == errno.ENOENT
    assert ctx.release(base, "t") == 0 and ctx.release(base) == 0
    assert [e and e.code for e in ctx.release([base + "?release_errno=13", base], "t")] == [
        errno.EACCES,
        None,
    ]


def test_mock_archiving(ctx: Gfal2Context) -> None:
    base = M + "/test_mock_archiving"
    assert ctx.archive_poll(base) == 1
    assert base not in mock_module._archiving_end  # done: the next poll starts again
    with pytest.raises(GError) as caught:
        ctx.archive_poll(base + "?archiving_errno=5")
    assert caught.value.code == errno.EIO
    pending = base + "/p?archiving_time=3600&archiving_errno=5"
    assert ctx.archive_poll(pending) == 0 and ctx.archive_poll(pending) == 0
    plugin = mock_plugin(ctx)
    assert plugin.archive_poll([base + "/q?archiving_time=3600", base]) == [False, True]


def copy_events(
    ctx: Gfal2Context,
    source: str,
    destination: str,
    events: list[tuple[str, str]] | None = None,
    **settings: Any,
) -> list[tuple[str, str]]:
    """Copy, answering the ``(stage, description)`` of each event (also into ``events``)."""
    seen = [] if events is None else events
    params = ctx.transfer_parameters()
    params.event_callback = lambda e: seen.append((e.stage, e.description))
    for name, value in settings.items():
        if name == "checksum":
            params.set_checksum(*value)
        else:
            setattr(params, name, value)
    ctx.filecopy(params, source, destination)
    return seen


@pytest.fixture
def ticks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mock_module, "_TICK", 0.01)  # a mock copy's "second"


def test_mock_copy(ctx: Gfal2Context, ticks: None) -> None:
    source = M + "/s?size=10&transfer_errno=5&time=3"  # neither counts on the source
    events = copy_events(ctx, source, M + "/d?size=10&time=0")  # an existing destination
    assert [stage for stage, _ in events if not stage.startswith("LIST")] == [
        "TRANSFER:ENTER",
        "TRANSFER:TYPE",
        "TRANSFER:EXIT",
    ]
    assert events[-3:] == [
        ("TRANSFER:ENTER", "Mock copy start, sleep 0"),
        ("TRANSFER:TYPE", "mock"),
        ("TRANSFER:EXIT", "Mock copy start, sleep 0"),
    ]
    copy_events(ctx, source, M + "/d?time=0&transfer_errno=5")  # fails only while sleeping
    assert copy_events(ctx, source, M + "/d?time=2")[-1] == (
        "TRANSFER:EXIT",
        "Mock copy start, sleep 0",
    )
    events = []
    with pytest.raises(GError) as caught:
        copy_events(ctx, source, M + "/d?time=3&transfer_errno=5", events, overwrite=True)
    assert (caught.value.code, caught.value.message) == (errno.EIO, "Input/output error")
    assert events[-1] == ("TRANSFER:EXIT", "Mock copy start, sleep 2")
    ctx.set_opt_integer("MOCK PLUGIN", "MIN_TRANSFER_TIME", 2)
    ctx.set_opt_integer("MOCK PLUGIN", "MAX_TRANSFER_TIME", 2)
    assert copy_events(ctx, source, M + "/d")[-3][1] == "Mock copy start, sleep 2"
    ctx.set_opt_integer("MOCK PLUGIN", "MAX_TRANSFER_TIME", 3)  # rand() % (max - min) + min
    assert copy_events(ctx, source, M + "/d")[-3][1] == "Mock copy start, sleep 2"
    ctx.set_opt_integer("MOCK PLUGIN", "MIN_TRANSFER_TIME", 4)  # max < min
    assert copy_events(ctx, source, M + "/d")[-3][1] == "Mock copy start, sleep 4"


def test_mock_copy_checksums(ctx: Gfal2Context) -> None:
    both, source, target = checksum_mode.both, checksum_mode.source, checksum_mode.target
    src, dst = M + "/s?checksum=aa", M + "/d?time=0&checksum="
    for mode, user, src_sum, dst_sum, message in (
        (both, "aa", "aa", "aa", None),
        (both, "", "aa", "", None),  # an empty checksum matches anything
        (source, "aa", "bb", "cc", "User and source checksums do not match"),
        (both, "", "aa", "bb", "Source and destination checksums do not match"),
        (target, "aa", "", "bb", "User and destination checksums do not match"),
        (target, "aa", "", "aa", None),
    ):
        settings = {"checksum": (mode, "ADLER32", user)}
        pair = (src.replace("aa", src_sum), dst + dst_sum)
        events: list[tuple[str, str]] = []
        if message is None:
            copy_events(ctx, *pair, events, **settings)
            continue
        with pytest.raises(GError) as caught:
            copy_events(ctx, *pair, events, **settings)
        assert (caught.value.code, caught.value.message) == (errno.EIO, message)
        # a source mismatch fails before the copy starts
        started = any(stage == "TRANSFER:ENTER" for stage, _ in events)
        assert started == (mode != source)


def test_mock_copy_cancel_and_timeout(ctx: Gfal2Context, ticks: None) -> None:
    plugin = mock_plugin(ctx)
    params = ctx.transfer_parameters()
    for destination, code in (
        (M + "/d?time=5", errno.ECANCELED),
        (M + "/d?time=5&transfer_errno=5", errno.EIO),  # the copy's own error wins
    ):
        transfer = Transfer(ctx, params, M + "/s", destination)
        ctx.cancel()
        with pytest.raises(GError) as caught:
            plugin.copy(transfer)
        assert caught.value.code == code
    params.timeout = 1  # gfal2's mock copy ignores the timeout
    transfer = Transfer(ctx, params, M + "/s", M + "/d?time=2")
    transfer.started -= 10
    plugin.copy(transfer)


def test_mock_copy_honours_cancel(ctx: Gfal2Context) -> None:
    params = ctx.transfer_parameters()
    timer = threading.Timer(0.1, ctx.cancel)
    timer.start()
    try:
        with pytest.raises(GError) as caught:
            ctx.filecopy(params, M + "/src", M + "/dst?time=30")
        assert (caught.value.code, caught.value.message) == (errno.ECANCELED, "Transfer canceled")
    finally:
        timer.cancel()


def test_mock_is_its_own_class() -> None:
    assert MockPlugin.name == "mock" and MockPlugin.schemes == ("mock",)


# -- the registry ---------------------------------------------------------------------------


class ThirdParty(Plugin):
    name = "third"
    schemes = ("third",)


class Unavailable(Plugin):
    name = "missing"
    schemes = ("missing", "missings")

    @classmethod
    def available(cls) -> str | None:
        return "needs the missing package"


def test_registry_loads_what_it_can(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    fake = types.ModuleType("fake_plugins")
    fake.ThirdParty = ThirdParty  # type: ignore[attr-defined]
    fake.Unavailable = Unavailable  # type: ignore[attr-defined]
    fake.NotAPlugin = object  # type: ignore[attr-defined]
    fake.NotAClass = "not even a class"  # type: ignore[attr-defined]
    fake.__getattr__ = lambda name: (_ for _ in ()).throw(RuntimeError("broken module"))  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fake_plugins", fake)
    monkeypatch.setattr(
        plugins,
        "BUILTIN",
        [
            plugins.Entry("fake_plugins", "ThirdParty", "third", ("third",), 1),
            plugins.Entry("fake_plugins", "Unavailable", "missing", ("missing",), 2),
            plugins.Entry("fake_plugins", "NotAPlugin", "notaplugin", ("nap",), 3),
            plugins.Entry("fake_plugins", "NotAClass", "notaclass", ("nac",), 3),
            plugins.Entry("fake_plugins", "Broken", "broken", ("broken",), 4),
            plugins.Entry("no.such.module", "X", "nosuch", ("nosuch",), 5),
        ],
    )
    monkeypatch.setattr(plugins, "_MISSING", {})
    with caplog.at_level(logging.WARNING, logger="gfal2"):
        found = plugins.plugin_classes(extra={})
    assert found == [ThirdParty]
    assert "not a Plugin subclass" in caplog.text
    assert plugins.missing_hint("missings") == "needs the missing package"
    assert plugins.missing_hint("nosuch") == "the nosuch plugin could not be loaded"
    assert plugins.missing_hint("broken") == "the broken plugin could not be loaded"
    assert plugins.missing_hint("http") == ""


def test_builtin_entries_describe_their_classes() -> None:
    """The routing table must agree with the classes it stands for."""
    for entry in plugins.BUILTIN:
        cls = plugins.load(entry)
        if cls is None:  # an optional dependency is missing here
            continue
        assert (cls.name, cls.priority) == (entry.name, entry.priority), entry
        assert set(cls.schemes) <= set(entry.schemes), entry


def test_plugins_load_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = types.ModuleType("fake_lazy")
    fake.ThirdParty = ThirdParty  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fake_lazy", fake)
    monkeypatch.setattr(
        plugins, "BUILTIN", [plugins.Entry("fake_lazy", "ThirdParty", "third", ("third",), 1)]
    )
    context = Gfal2Context()
    assert context.plugins == [] and "pending=1" in repr(context)
    assert context._find("file:///x", "stat") is None
    assert context._copy_plugin("third://a", "file:///b") is None  # loads "third"
    assert [p.name for p in context.plugins] == ["third"]
    assert context._pending == []
    assert context.get_plugin_names() == ["third-2.23.5"]
    empty = Gfal2Context(load_plugins=False)
    assert empty.get_plugin_names() == []
    monkeypatch.setattr(
        plugins, "BUILTIN", [plugins.Entry("no.such.module", "X", "gone", ("gone",), 1)]
    )
    broken = Gfal2Context()
    with pytest.raises(GError) as caught:
        broken.stat("gone://h/x")
    assert "the gone plugin could not be loaded" in caught.value.message


def test_duplicate_entry_points_load_once(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = types.ModuleType("fake_dup")
    fake.ThirdParty = ThirdParty  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fake_dup", fake)
    monkeypatch.setattr(
        plugins, "BUILTIN", [plugins.Entry("fake_dup", "ThirdParty", "third", ("third",), 1)]
    )
    assert plugins.plugin_classes(
        extra={plugins.ENTRY_POINT_GROUP: [_Entry("fake_dup:ThirdParty")]}
    ) == [ThirdParty]


class _Entry:
    def __init__(self, value: str) -> None:
        self.value = value


class _Selectable:
    def __init__(self, entries: list[_Entry]) -> None:
        self.entries = entries

    def select(self, group: str) -> list[_Entry]:
        return self.entries if group == plugins.ENTRY_POINT_GROUP else []


def test_registry_entry_points_in_both_shapes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = types.ModuleType("fake_ep")
    fake.ThirdParty = ThirdParty  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fake_ep", fake)
    entry = _Entry("fake_ep:ThirdParty")
    unloadable = _Entry("no.such.module:X")
    assert plugins.entry_point_classes(extra=_Selectable([entry, unloadable, entry])) == [
        ThirdParty
    ]
    assert plugins.entry_point_classes(extra={plugins.ENTRY_POINT_GROUP: [entry]}) == [ThirdParty]
    assert plugins.entry_point_classes(extra={}) == []
    monkeypatch.setattr(plugins, "BUILTIN", [])
    assert plugins.plugin_classes(extra=_Selectable([entry])) == [ThirdParty]
    assert isinstance(plugins._entry_points(), list)
    monkeypatch.setattr(plugins, "_entry_points", lambda extra=None: [entry])
    monkeypatch.setattr(
        plugins,
        "BUILTIN",
        [plugins.Entry("xgfalclient.plugins.mock", "MockPlugin", "mock", ("mock",), 300)],
    )
    context = Gfal2Context()
    assert context._find("mock://h/x", "stat") is not None  # a built-in scheme: no lookup
    assert context._entry_points_pending
    assert context._find("third://h/x", "stat") is None  # unknown scheme: entry points loaded
    assert not context._entry_points_pending and "third" in [p.name for p in context.plugins]
    context._find("other://h/x", "stat")  # already looked up once
    later = Gfal2Context()
    assert "third-2.23.5" in later.get_plugin_names()
    assert later.get_plugin_names() == later.get_plugin_names()


# -- package level ---------------------------------------------------------------------------


def test_package_functions(monkeypatch: pytest.MonkeyPatch) -> None:
    assert xgfalclient.get_version() == "2.23.5"  # gfal2's, which callers gate on
    gfal2 = logging.getLogger("gfal2")
    assert any(isinstance(h, logging.NullHandler) for h in gfal2.handlers)
    level = gfal2.level
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = records.append  # type: ignore[method-assign]
    gfal2.addHandler(handler)
    gfal2.setLevel(logging.DEBUG)  # the application's choice; gfal2's threshold still applies
    try:
        gfal2.debug("hidden")
        assert xgfalclient.set_verbose(xgfalclient.verbose_level.debug) == 0
        gfal2.debug("shown")
        xgfalclient.set_verbose(xgfalclient.verbose_level.normal)
        gfal2.warning("hidden")
        gfal2.error("shown")
        xgfalclient.set_verbose(12345)
        gfal2.debug("shown")
        assert gfal2.level == logging.DEBUG  # set_verbose never touches the logger's level
    finally:
        gfal2.setLevel(level)
        gfal2.removeHandler(handler)
        xgfalclient.set_verbose(xgfalclient.verbose_level.verbose)
    assert [r.getMessage() for r in records] == ["shown"] * 3
    credential = xgfalclient.cred_new("BEARER", "t")
    context = xgfalclient.creat_context()
    assert xgfalclient.cred_set(context, "https://se/", credential) == 0
    assert context.cred_get("BEARER", "https://se/f") == ("t", "https://se/")
    assert xgfalclient.cred_clean(context) == 0
    assert xgfalclient.NullHandler is logging.NullHandler
    monkeypatch.delitem(sys.modules, "gfal2", raising=False)
    xgfalclient.install_as_gfal2()
    import gfal2  # type: ignore[import-not-found]

    assert gfal2.Gfal2Context is xgfalclient.Gfal2Context and gfal2.__version__ == "1.13.1"
    assert gfal2.creat_context().get_plugin_names()
    monkeypatch.delitem(sys.modules, "gfal2")


def test_plugin_file_defaults() -> None:
    handle = PluginFile("x://f")
    with pytest.raises(GError) as caught:
        handle.read(1)
    assert caught.value.code == errno.ENOSYS
    with pytest.raises(GError):
        handle.write(b"x")
    assert handle.size() is None
    with pytest.raises(GError) as caught:
        handle.lseek(0, os.SEEK_END)
    assert caught.value.code == errno.ESPIPE
    with pytest.raises(GError) as caught:
        handle.lseek(0, 99)
    assert caught.value.code == errno.EINVAL
    with pytest.raises(GError) as caught:
        handle.lseek(-1, os.SEEK_CUR)
    assert caught.value.code == errno.EINVAL
    assert handle.lseek(5) == 5
    with handle as same:
        assert same is handle
    assert handle.closed


def test_plugin_base_helpers(ctx: Gfal2Context) -> None:
    class Bare(Plugin):
        name = "bare"
        option_group = "BARE PLUGIN"

    plugin: Any = Bare(ctx)
    assert plugin.label == "bare-2.23.5"
    assert plugin.available() is None
    assert plugin.handles("bare://x", "stat") is False
    assert not Bare.implements("stat") and not Bare.implements("no_such_operation")
    assert plugin.option_timeout() == 300
    assert plugin.checksum_type() == "ADLER32"
    ctx.set_opt_string("BARE PLUGIN", "COPY_CHECKSUM_TYPE", "MD5")
    assert plugin.checksum_type() == "MD5"
    assert plugin.options is ctx.options
    assert (Bare.narrates_transfer, Bare.copy_manages_destination) == (False, False)
    assert Bare.copy_manages_checksums is False
    plugin.close()


@pytest.mark.parametrize(
    ("operation", "args"),
    [
        ("access", ("bare://x", 0)),
        ("chmod", ("bare://x", 0o644)),
        ("rename", ("bare://x", "bare://y")),
        ("stat", ("bare://x",)),
        ("lstat", ("bare://x",)),
        ("mkdir", ("bare://x", 0o755)),
        ("mkdir_rec", ("bare://x", 0o755)),
        ("rmdir", ("bare://x",)),
        ("opendir", ("bare://x",)),
        ("listdir", ("bare://x",)),
        ("readlink", ("bare://x",)),
        ("symlink", ("bare://x", "bare://y")),
        ("unlink", ("bare://x",)),
        ("unlink_bulk", (["bare://x"],)),
        ("open", ("bare://x", 0)),
        ("getxattr", ("bare://x", "user.a")),
        ("setxattr", ("bare://x", "user.a", "v", 0)),
        ("listxattr", ("bare://x",)),
        ("checksum", ("bare://x", "ADLER32", 0, 0)),
        ("bring_online", (["bare://x"], [], 0, 0, False)),
        ("bring_online_poll", (["bare://x"], "token")),
        ("release", (["bare://x"], "token")),
        ("abort_bring_online", (["bare://x"], "token")),
        ("archive_poll", (["bare://x"],)),
        ("check_file_qos", ("bare://x",)),
        ("check_available_qos_transitions", ("bare://x",)),
        ("check_target_qos", ("bare://x",)),
        ("change_object_qos", ("bare://x", "disk")),
        ("qos_check_classes", ("bare://x", "file")),
        ("token_retrieve", ("bare://x", "", 60, False, [])),
        ("copy", (None,)),
        ("copy_bulk", (None, [])),
    ],
)
def test_plugin_base_operations_are_unimplemented(
    ctx: Gfal2Context, operation: str, args: tuple[Any, ...]
) -> None:
    """The defaults only mark an operation as absent: the context never dispatches to them."""
    plugin: Any = Plugin(ctx)
    assert not Plugin.implements(operation)
    with pytest.raises(NotImplementedError):
        getattr(plugin, operation)(*args)
    assert plugin.copy_check("bare://x", "bare://y") is False
