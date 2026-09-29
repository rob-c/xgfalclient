"""The file and mock plugins, the plugin registry, and the package-level functions."""

from __future__ import annotations

import errno
import logging
import os
import sys
import types
import zlib
from pathlib import Path
from typing import Any

import pytest

import xgfalclient
from conftest import file_url
from xgfalclient import GError, Gfal2Context, plugins
from xgfalclient.plugin import O_CREAT, O_RDWR, O_WRONLY, Plugin, PluginFile
from xgfalclient.plugins import file as file_plugin
from xgfalclient.plugins.file import FilePlugin, LocalFile
from xgfalclient.plugins.mock import MockPlugin

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
    assert entries[-1] == ("gone", None)


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


# -- mock:// -------------------------------------------------------------------------------


def test_mock_stat_grammar(ctx: Gfal2Context) -> None:
    info = ctx.stat("mock://host/path/file?size=1234")
    assert (info.st_size, oct(info.st_mode)) == (1234, "0o100755")
    assert ctx.stat("mock://h/d?list=a:1").is_dir()
    assert ctx.stat("mock://h/f").st_size == 0
    assert ctx.stat("mock://h/f?size=bogus").st_size == 0
    assert ctx.stat("mock://h/f?size_pre=7").st_size == 7
    assert ctx.stat("mock://h/f?size_post=9").st_size == 9  # exists before a copy, as in gfal2
    with pytest.raises(GError) as caught:
        ctx.stat("mock://host/path/file?errno=13")
    assert (caught.value.code, caught.value.message) == (errno.EACCES, "Permission denied")


def test_mock_namespace_errors(ctx: Gfal2Context) -> None:
    for call in (
        lambda: ctx.access("mock://h/f?access_errno=1", os.R_OK),
        lambda: ctx.mkdir("mock://h/f?access_errno=1", 0o755),
        lambda: ctx.mkdir_rec("mock://h/f?access_errno=1", 0o755),
        lambda: ctx.rmdir("mock://h/f?access_errno=1"),
        lambda: ctx.unlink("mock://h/f?access_errno=1"),
        lambda: ctx.rename("mock://h/f?access_errno=1", "mock://h/g"),
    ):
        with pytest.raises(GError) as caught:
            call()
        assert caught.value.code == errno.EPERM
    assert ctx.access("mock://h/f", os.R_OK) == 0
    assert ctx.mkdir("mock://h/d", 0o755) == 0
    assert ctx.mkdir_rec("mock://h/d", 0o755) == 0
    assert ctx.rmdir("mock://h/d") == 0
    assert ctx.rename("mock://h/f", "mock://h/g") == 0
    assert ctx.unlink("mock://h/f") == 0


def test_mock_listing(ctx: Gfal2Context) -> None:
    assert ctx.listdir("mock://host/path?list=a:10,b:20,,c/:0") == ["a", "b", "c"]
    entries = {e.d_name: e.d_type for e in ctx.opendir("mock://h/p?list=a:10,c/")}
    assert entries == {"a": 8, "c": 4}
    with pytest.raises(GError) as caught:
        ctx.listdir("mock://h/f?size=1")
    assert caught.value.code == errno.ENOTDIR
    with pytest.raises(GError):
        ctx.listdir("mock://h/f?errno=2")


def test_mock_reads(ctx: Gfal2Context, data_dir: Path) -> None:
    with ctx.open("mock://h/f?size=5", "r") as handle:
        assert handle.read_bytes(10) == bytes(5)
        assert handle.lseek(0, os.SEEK_END) == 5
        assert handle.pread_bytes(4, 10) == bytes(1)
        assert handle.pread_bytes(9, 10) == b""
    with ctx.open(f"mock://h/f?rd_path={data_dir / 'hello.txt'}", "r") as handle:
        assert handle.pread(6, 5) == "world"
    with pytest.raises(GError) as caught:
        ctx.open("mock://h/f?open_errno=2", "r")
    assert caught.value.code == errno.ENOENT
    with pytest.raises(GError) as caught:
        ctx.open("mock://h/f", "w")
    assert (caught.value.code, caught.value.message) == (
        errno.ENOSYS,
        "Mock plugin does not support read and write",
    )


def test_mock_metadata(ctx: Gfal2Context) -> None:
    assert ctx.checksum("mock://h/f?checksum=abc123", "adler32") == "00abc123"
    assert ctx.checksum("mock://h/f", "md5") == ""
    with pytest.raises(GError):
        ctx.checksum("mock://h/f?errno=5", "md5")
    assert ctx.getxattr("mock://h/f", "user.status") == "ONLINE"
    # Not staged (the staging check failed), but with no staging_time it is on disk anyway.
    assert ctx.getxattr("mock://h/f?staging_errno=5", "user.status") == "ONLINE"
    assert ctx.getxattr("mock://h/f?replicas=a", "user.replicas") == "a"
    assert ctx.getxattr("mock://h/f?spacetoken=T", "spacetoken") == "T"
    with pytest.raises(GError) as caught:
        ctx.getxattr("mock://h/f", "user.bogus")
    assert caught.value.message == "Failed to retrieve xattr user.bogus"
    assert "user.status" in ctx.listxattr("mock://h/f")
    assert ctx.token_retrieve("mock://h/f", "", 60, False) == "mock-token"


def test_mock_staging(ctx: Gfal2Context) -> None:
    status, token = ctx.bring_online("mock://h/f?staging_time=0", 10, 10, True)
    assert status == 1 and token
    status, _ = ctx.bring_online("mock://h/slow?staging_time=3600", 10, 10, True)
    assert status == 0
    assert ctx.bring_online_poll("mock://h/slow?staging_time=3600", token) == 0
    assert ctx.getxattr("mock://h/slow?staging_time=3600", "user.status") == "NEARLINE"
    assert ctx.abort_bring_online("mock://h/slow?staging_time=3600", token) == 0
    assert ctx.bring_online_poll("mock://h/slow?staging_time=3600", token) == 1
    with pytest.raises(GError) as caught:
        ctx.bring_online("mock://h/f?staging_errno=5", 10, 10, True)
    assert caught.value.code == errno.EIO
    assert ctx.release("mock://h/f") == 0
    with pytest.raises(GError):
        ctx.release("mock://h/f?release_errno=5")
    assert ctx.archive_poll("mock://h/f") == 1
    assert ctx.archive_poll("mock://h/slow?archiving_time=3600") == 0
    with pytest.raises(GError):
        ctx.archive_poll("mock://h/f?archiving_errno=5")
    errors = ctx.archive_poll(["mock://h/f", "mock://h/x?archiving_errno=2"])
    assert errors[0] is None and errors[1].code == errno.ENOENT


def test_mock_copy(ctx: Gfal2Context) -> None:
    events: list[xgfalclient.GfaltEvent] = []
    params = ctx.transfer_parameters()
    params.event_callback = events.append
    with pytest.raises(GError) as caught:  # gfal2: a size_post destination already exists
        ctx.filecopy(params, "mock://h/src?size=10&time=0", "mock://h/dst?size_post=10")
    assert caught.value.code == errno.EEXIST
    params.overwrite = True
    ctx.filecopy(params, "mock://h/src?size=10&time=0", "mock://h/dst?size_post=10")
    assert ctx.stat("mock://h/dst?size_post=10").st_size == 10
    assert ("TRANSFER:TYPE", "mock") in [(e.stage, e.description) for e in events]
    ctx.filecopy(params, "mock://h/src?size=10&time=0", "mock://h/new?size_pre=0&size_post=3")
    assert ctx.stat("mock://h/new?size_pre=0&size_post=3").st_size == 3
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, "mock://h/src?time=0&transfer_errno=110", "mock://h/d2?size_post=1")
    assert caught.value.code == 110
    ctx.set_opt_integer("MOCK PLUGIN", "MIN_TRANSFER_TIME", 0)
    ctx.set_opt_integer("MOCK PLUGIN", "MAX_TRANSFER_TIME", 0)
    ctx.filecopy(params, "mock://h/src?size=1", "mock://h/d3?size_post=1")
    ctx.filecopy(params, "mock://h/src?size=1", "mock://h/d4?size_post=1&time=0")


def test_mock_copy_honours_cancel(ctx: Gfal2Context) -> None:
    import threading

    params = ctx.transfer_parameters()
    params.overwrite = True
    timer = threading.Timer(0.1, ctx.cancel)
    timer.start()
    try:
        with pytest.raises(GError) as caught:
            ctx.filecopy(params, "mock://h/src?time=30", "mock://h/dst?size_post=1")
        assert caught.value.code == errno.ECANCELED
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

    assert gfal2 is xgfalclient
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
