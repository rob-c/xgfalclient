"""The context: dispatch, gfal2's fallbacks, return shapes, and the file/dir handles."""

from __future__ import annotations

import errno
import logging
import os
import ssl
import threading
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

import xgfalclient
from xgfalclient import GError, Gfal2Context, plugins
from xgfalclient.creds import Credential
from xgfalclient.options import Options
from xgfalclient.plugin import Plugin, PluginFile, StagingResult
from xgfalclient.transfer import Transfer
from xgfalclient.types import DT_DIR, DT_REG, Stat
from xgfalclient.url import parent

DIR = Stat(st_mode=0o40755, st_ino=1)
FILE = Stat(st_mode=0o100644, st_size=5, st_ino=2)


class MemoryFile(PluginFile):
    def __init__(self, url: str, store: dict[str, bytearray]) -> None:
        super().__init__(url)
        self.store = store
        store.setdefault(url, bytearray())

    def pread(self, offset: int, size: int) -> bytes:
        return bytes(self.store[self.url][offset : offset + size])

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        buffer = self.store[self.url]
        buffer[offset : offset + len(data)] = data
        return len(data)

    def size(self) -> int:
        return len(self.store[self.url])


class Fake(Plugin):
    """Implements everything, over an in-memory namespace."""

    name = "fake"
    schemes = ("fake",)
    option_group = "FAKE PLUGIN"
    priority = 10

    def __init__(self, context: Gfal2Context) -> None:
        super().__init__(context)
        self.files: dict[str, bytearray] = {"fake://h/f": bytearray(b"hello")}
        self.dirs = {"fake://h", "fake://h/", "fake://h/d"}
        self.calls: list[tuple[Any, ...]] = []
        self.staging: list[StagingResult] = [True]
        self.closed = False

    def _info(self, url: str) -> Stat:
        if url in self.dirs:
            return DIR
        if url in self.files:
            return Stat(st_mode=0o100644, st_size=len(self.files[url]), st_ino=2)
        raise GError("No such file", errno.ENOENT)

    def stat(self, url: str) -> Stat:
        return self._info(url)

    def access(self, url: str, mode: int) -> None:
        self.calls.append(("access", url, mode))

    def chmod(self, url: str, mode: int) -> None:
        self.calls.append(("chmod", url, mode))

    def rename(self, old: str, new: str) -> None:
        self.files[new] = self.files.pop(old)

    def mkdir(self, url: str, mode: int) -> None:
        if url in self.dirs or url in self.files:
            raise GError("exists", errno.EEXIST)
        parent_url = url.rsplit("/", 1)[0] or "fake://h/"
        if parent_url in self.files:
            raise GError("not a directory", errno.ENOTDIR)
        if parent_url not in self.dirs and parent_url != "fake:/":
            raise GError("no parent", errno.ENOENT)
        self.dirs.add(url)

    def rmdir(self, url: str) -> None:
        self.dirs.discard(url)

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        self._info(url)
        return iter([("d", DIR), ("f", None)])

    def readlink(self, url: str) -> str:
        return "target"

    def symlink(self, target: str, link: str) -> None:
        self.calls.append(("symlink", target, link))

    def unlink(self, url: str) -> None:
        if url not in self.files:
            raise GError("No such file", errno.ENOENT)
        del self.files[url]

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        self.calls.append(("open", url, flags, size))
        return MemoryFile(url, self.files)

    def getxattr(self, url: str, name: str) -> str:
        return f"{name}-value"

    def setxattr(self, url: str, name: str, value: str, flags: int) -> None:
        self.calls.append(("setxattr", name, value, flags))

    def listxattr(self, url: str) -> list[str]:
        return ["user.status"]

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        return "abc"

    def bring_online(
        self,
        urls: Sequence[str],
        metadata: Sequence[str],
        pintime: int,
        timeout: int,
        is_async: bool,
    ) -> tuple[list[StagingResult], str]:
        self.calls.append(("bring_online", list(urls), list(metadata), pintime, timeout, is_async))
        return list(self.staging), "token"

    def bring_online_poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        return list(self.staging)

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        return [None if url.endswith("ok") else GError("nope", errno.EINVAL) for url in urls]

    def abort_bring_online(self, urls: Sequence[str], token: str) -> list[GError | None]:
        return [None for _ in urls]

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        return list(self.staging)

    def check_file_qos(self, url: str) -> str:
        return "disk"

    def check_available_qos_transitions(self, url: str) -> list[str]:
        return ["tape"]

    def check_target_qos(self, url: str) -> str:
        return "tape"

    def change_object_qos(self, url: str, target: str) -> None:
        self.calls.append(("qos", target))

    def qos_check_classes(self, url: str, kind: str) -> list[str]:
        return [kind]

    def token_retrieve(
        self, url: str, issuer: str, validity: int, write_access: bool, activities: list[str]
    ) -> str:
        return f"{issuer}:{validity}:{write_access}:{','.join(activities)}"

    def close(self) -> None:
        self.closed = True


class Minimal(Plugin):
    """Implements only stat and listdir, to exercise the core's fallbacks."""

    name = "minimal"
    schemes = ("min",)
    priority = 20

    def stat(self, url: str) -> Stat:
        if url.endswith("/missing") or url.startswith("min://gone"):
            raise GError("No such file", errno.ENOENT)
        if url.endswith("/denied"):
            raise GError("denied", errno.EACCES)
        if url.endswith("/file"):
            return FILE
        return DIR

    def listdir(self, url: str) -> list[str]:
        return ["a", "b"]

    def mkdir(self, url: str, mode: int) -> None:
        if url.endswith("/race"):
            raise GError("exists", errno.EEXIST)
        if url.endswith("/broken"):
            raise GError("io", errno.EIO)


@pytest.fixture
def fctx() -> Iterator[Gfal2Context]:
    context = Gfal2Context(options=Options(load_system=False), load_plugins=False)
    context.add_plugin(Minimal)
    context.add_plugin(Fake)
    yield context
    if not context._freed:
        context.free()


def fake(context: Gfal2Context) -> Fake:
    return next(p for p in context.plugins if isinstance(p, Fake))


# -- dispatch -----------------------------------------------------------------------


def test_plugins_sorted_by_priority(fctx: Gfal2Context) -> None:
    assert fctx.get_plugin_names() == ["fake-2.23.5", "minimal-2.23.5"]
    assert isinstance(fctx.plugin("fake://h/f", "stat"), Fake)


def test_unclaimed_url_and_unimplemented_operation(fctx: Gfal2Context) -> None:
    with pytest.raises(GError) as caught:
        fctx.stat("nope://h/f")
    assert caught.value.code == errno.EPROTONOSUPPORT
    with pytest.raises(GError) as caught:
        fctx.chmod("min://h/f", 0o644)
    assert caught.value.code == errno.EPROTONOSUPPORT


def test_missing_plugin_hint(fctx: Gfal2Context, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(plugins._MISSING, "nope", "install something")
    with pytest.raises(GError) as caught:
        fctx.stat("nope://h/f")
    assert caught.value.message.endswith("(install something)")
    assert caught.value.args == (caught.value.message, errno.EPROTONOSUPPORT)


def test_guard_translates_oserror_and_refuses_after_free(fctx: Gfal2Context) -> None:
    def boom(code: int | None) -> None:
        raise OSError(code, "bad") if code else OSError("bad")

    with pytest.raises(GError) as caught:
        fctx._guard(boom, errno.EPIPE)
    assert caught.value.args == ("errno reported by local system call Broken pipe", errno.EPIPE)
    with pytest.raises(GError) as caught:
        fctx._guard(boom, None)
    assert caught.value.code == errno.EIO
    handle = fctx.open("fake://h/f", "r")
    fctx.free()
    for call in (
        lambda: fctx.stat("fake://h/f"),
        lambda: fctx.get_opt_string("CORE", "NAMESPACE_TIMEOUT"),
        lambda: fctx.cred_get("BEARER", "fake://h/f"),
        fctx.cancel,
        fctx.get_plugin_names,
        lambda: handle.read(1),
    ):
        with pytest.raises(GError) as caught:
            call()
        assert caught.value.args == ("gfal2 context has been freed", errno.EFAULT)
    assert Gfal2Context.stat.__name__ == "stat"  # the guard keeps the method's identity
    fctx.free()  # again: nothing happens (gfal2 raises; fixtures free what tests freed)


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (ValueError("substring not found"), ("substring not found", errno.EINVAL)),
        (RuntimeError("odd"), ("odd", errno.EIO)),
        (KeyError(), ("KeyError", errno.EIO)),
    ],
)
def test_guard_turns_every_exception_into_gerror(
    fctx: Gfal2Context, exc: Exception, expected: tuple[str, int]
) -> None:
    def boom() -> None:
        raise exc

    with pytest.raises(GError) as caught:
        fctx._guard(boom)
    assert caught.value.args == expected and caught.value.__cause__ is exc
    assert fctx._running == 0 and fctx._running_by_thread == {}


# -- namespace ----------------------------------------------------------------------


def test_namespace_operations(fctx: Gfal2Context) -> None:
    plugin = fake(fctx)
    assert fctx.stat("fake://h/f").st_size == 5
    assert fctx.lstat("fake://h/f").st_size == 5  # no lstat: falls back to stat
    assert fctx.access("fake://h/f", os.R_OK) == 0
    assert fctx.chmod("fake://h/f", 0o600) == 0
    assert fctx.rename("fake://h/f", "fake://h/g") == 0
    assert "fake://h/g" in plugin.files
    assert fctx.mkdir("fake://h/n", 0o755) == 0
    assert fctx.rmdir("fake://h/n") == 0
    assert fctx.readlink("fake://h/l") == "target"
    assert fctx.symlink("fake://h/g", "fake://h/l") == 0
    assert ("symlink", "fake://h/g", "fake://h/l") in plugin.calls
    assert fctx.unlink("fake://h/g") == 0
    assert ("access", "fake://h/f", os.R_OK) in plugin.calls


def test_access_passes_a_plugin_answer_through(fctx: Gfal2Context, monkeypatch: Any) -> None:
    monkeypatch.setattr(fake(fctx), "access", lambda url, mode: 1)  # as gfal2's mock answers
    assert fctx.access("fake://h/f", os.R_OK) == 1


def test_bare_scheme_urls_load_their_plugin() -> None:
    """gfal2's mock takes ``mock:anything``; the lazy loader must find it from that."""
    context = xgfalclient.creat_context()
    assert context.stat("mock:foo?size=3").st_size == 3
    assert [p.name for p in context.plugins] == ["mock"]


def test_access_falls_back_to_stat(fctx: Gfal2Context) -> None:
    assert fctx.access("min://h/file", os.F_OK) == 0
    with pytest.raises(GError):
        fctx.access("min://h/missing", os.F_OK)


def test_mkdir_rec_generic(fctx: Gfal2Context) -> None:
    plugin = fake(fctx)
    assert fctx.mkdir_rec("fake://h/a/b/c", 0o755) == 0
    assert {"fake://h/a", "fake://h/a/b", "fake://h/a/b/c"} <= plugin.dirs
    assert fctx.mkdir_rec("fake://h/a", 0o755) == 0  # already there
    assert fctx.mkdir_rec("fake://h/f", 0o755) == 0  # a file there counts too, as in gfal2
    with pytest.raises(GError) as caught:
        fctx.mkdir_rec("fake://h/f/x", 0o755)
    assert caught.value.code == errno.ENOTDIR
    with pytest.raises(GError) as caught:
        fctx.mkdir_rec("min://h/broken", 0o755)
    assert caught.value.code == errno.EIO


class Climbing(Plugin):
    """mkdir fails ENOENT until the parent exists; scripted races and failures."""

    name = "climb"
    schemes = ("climb",)

    def __init__(self, context: Gfal2Context) -> None:
        super().__init__(context)
        self.dirs = {"climb://h"}
        self.calls: list[str] = []
        self.script: dict[str, list[int]] = {}

    def mkdir(self, url: str, mode: int) -> None:
        self.calls.append(url)
        scripted = self.script.get(url)
        if scripted:
            raise GError("scripted", scripted.pop(0))
        if url.rstrip("/") in self.dirs:
            raise GError("exists", errno.EEXIST)
        if parent(url).rstrip("/") not in self.dirs:
            raise GError("no parent", errno.ENOENT)
        self.dirs.add(url.rstrip("/"))


def test_mkdir_rec_climbs_then_descends(fctx: Gfal2Context) -> None:
    plugin: Any = fctx.add_plugin(Climbing)
    assert fctx.mkdir_rec("climb://h/a/b", 0o755) == 0
    assert plugin.calls == ["climb://h/a/b", "climb://h/a", "climb://h/a/b"]
    # a directory made by someone else between the climb and the descent
    plugin.calls.clear()
    plugin.script = {"climb://h/c/d": [errno.ENOENT, errno.EEXIST]}
    assert fctx.mkdir_rec("climb://h/c/d", 0o755) == 0
    assert plugin.calls == ["climb://h/c/d", "climb://h/c", "climb://h/c/d"]
    plugin.script = {"climb://h/e/f": [errno.ENOENT, errno.EACCES]}
    with pytest.raises(GError) as caught:
        fctx.mkdir_rec("climb://h/e/f", 0o755)
    assert caught.value.code == errno.EACCES


def test_mkdir_rec_with_even_the_root_missing(fctx: Gfal2Context) -> None:
    plugin: Any = fctx.add_plugin(Climbing)
    plugin.dirs.clear()
    with pytest.raises(GError) as caught:
        fctx.mkdir_rec("climb://h/a", 0o755)
    assert caught.value.code == errno.ENOENT
    assert plugin.calls == ["climb://h/a", "climb://h/", "climb://h/"]
    assert fctx.mkdir_rec("min://gone/", 0o755) == 0


def test_mkdir_rec_prefers_the_plugin(fctx: Gfal2Context) -> None:
    class WithRec(Fake):
        name = "rec"
        schemes = ("rec",)

        def mkdir_rec(self, url: str, mode: int) -> None:
            self.calls.append(("mkdir_rec", url))
            if url.endswith("/there"):
                raise GError("exists", errno.EEXIST)  # gfal2 answers 0 for that
            if url.endswith("/broken"):
                raise GError("io", errno.EIO)

    plugin = fctx.add_plugin(WithRec)
    assert fctx.mkdir_rec("rec://h/x/y", 0o700) == 0
    assert plugin.calls == [("mkdir_rec", "rec://h/x/y")]  # type: ignore[attr-defined]
    assert fctx.mkdir_rec("rec://h/there", 0o700) == 0
    with pytest.raises(GError):
        fctx.mkdir_rec("rec://h/broken", 0o700)


def test_listdir_and_opendir_fallbacks(fctx: Gfal2Context) -> None:
    assert fctx.listdir("fake://h/d") == ["d", "f"]  # from opendir
    assert fctx.listdir("min://h/d") == ["a", "b"]  # the plugin's own
    directory = fctx.opendir("min://h/d")  # no opendir: built from listdir
    first = directory.read()
    assert (first.d_name, first.d_type, first.d_off) == ("a", 0, 1)
    assert fctx.directory is not None


def test_directory_read_and_readpp(fctx: Gfal2Context) -> None:
    fake(fctx).files["fake://h/d/f"] = bytearray(b"xyz")
    directory = fctx.opendir("fake://h/d")
    assert repr(directory) == "<xgfalclient.DirectoryType 'fake://h/d'>"
    entry, info = directory.readpp()
    assert entry is not None and info is not None
    assert (entry.d_name, entry.d_type, info.st_mode) == ("d", DT_DIR, DIR.st_mode)
    entry, info = directory.readpp()  # stat of None is fetched from the child
    assert entry is not None and info is not None
    assert (entry.d_name, entry.d_type, info.st_size) == ("f", DT_REG, 3)
    assert directory.readpp() == (None, None)
    end = directory.read()
    assert end.d_name == ""
    assert [e.d_name for e in fctx.opendir("fake://h/d")] == ["d", "f"]
    with pytest.raises(GError):
        fctx.opendir("fake://h/missing")


def test_plugins_may_give_each_entry_its_own_type(
    fctx: Gfal2Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = fake(fctx)
    listing = [("l", Stat(st_mode=0o100644, st_size=3), 10), ("x", None, 1)]
    monkeypatch.setattr(plugin, "opendir", lambda url: iter(listing))
    assert [(e.d_name, e.d_type) for e in fctx.opendir("fake://h/d")] == [("l", 10), ("x", 1)]
    entry, info = fctx.opendir("fake://h/d").readpp()
    assert (entry.d_type, info.st_size) == (10, 3)  # type: ignore[union-attr]
    assert fctx.listdir("fake://h/d") == ["l", "x"]  # Fake has no listdir: from opendir


def test_readpp_child_url_keeps_query(fctx: Gfal2Context, monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = fake(fctx)
    plugin.dirs.add("fake://h/q?x=1")
    plugin.files["fake://h/q/f?x=1"] = bytearray(b"ab")
    plugin.dirs.add("fake://h/s/")
    plugin.files["fake://h/s/f"] = bytearray(b"a")
    assert fctx.opendir("fake://h/q?x=1").readpp()[1] == DIR
    handle = fctx.opendir("fake://h/q?x=1")
    handle.readpp()
    assert handle.readpp()[1].st_size == 2  # type: ignore[union-attr]
    handle = fctx.opendir("fake://h/s/")
    handle.readpp()
    assert handle.readpp()[1].st_size == 1  # type: ignore[union-attr]


def test_unlink_list_forms(fctx: Gfal2Context) -> None:
    with pytest.raises(GError) as caught:
        fctx.unlink([])
    assert caught.value.args == ("Empty list of files", errno.EINVAL)
    results = fctx.unlink(["fake://h/f", "fake://h/nope"])
    assert results[0] is None
    assert isinstance(results[1], GError) and results[1].code == errno.ENOENT

    class Bulk(Fake):
        name = "bulk"
        schemes = ("bulk",)

        def unlink_bulk(self, urls: Sequence[str]) -> list[GError | None]:
            return [None] * len(urls)

    fctx.add_plugin(Bulk)
    assert fctx.unlink(["bulk://h/a", "bulk://h/b"]) == [None, None]


# -- files ----------------------------------------------------------------------------


def test_file_handle(fctx: Gfal2Context) -> None:
    handle = fctx.open("fake://h/f", "r")
    assert repr(handle) == "<xgfalclient.FileType 'fake://h/f'>"
    assert handle.read(2) == "he"
    assert handle.read_bytes(2) == b"ll"
    assert handle.pread(1, 3) == "ell"
    assert handle.pread_bytes(4, 10) == b"o"
    assert handle.lseek(0, os.SEEK_SET) == 0
    buffer = bytearray(3)
    assert handle.readinto(buffer) == 3 and buffer == b"hel"
    assert not handle.closed
    handle.close()
    assert handle.closed
    handle.close()  # idempotent
    with pytest.raises(GError) as caught:
        handle.read(1)
    assert caught.value.code == errno.EBADF


def test_open_passes_the_size_to_writers(fctx: Gfal2Context) -> None:
    fctx._open("fake://h/up", os.O_WRONLY, 42).close()
    assert fake(fctx).calls[-1] == ("open", "fake://h/up", os.O_WRONLY, 42)


def test_file_writes_and_modes(fctx: Gfal2Context) -> None:
    with fctx.file("fake://h/w", "w") as handle:
        assert handle.write("abc") == 3
        assert handle.write(b"def") == 3
        assert handle.pwrite("ZZ", 1) == 2
        assert handle.lseek(0, os.SEEK_END) == 6
    assert fake(fctx).files["fake://h/w"] == b"aZZdef"
    assert fctx.open("fake://h/w", "rw").read(1) == "a"
    with pytest.raises(RuntimeError, match="Invalid open flag"):
        fctx.open("fake://h/w", "z")


def test_file_finaliser(fctx: Gfal2Context, caplog: pytest.LogCaptureFixture) -> None:
    handle = fctx.open("fake://h/f", "r")
    handle.__del__()
    assert handle.closed

    class Bad(MemoryFile):
        def close(self) -> None:
            raise GError("close failed", errno.EIO)

    broken = fctx.open("fake://h/f", "r")
    broken._file = Bad("fake://h/f", {})
    xgfalclient.set_verbose(xgfalclient.verbose_level.debug)
    try:
        with caplog.at_level(logging.DEBUG, logger="gfal2"):
            broken.__del__()
    finally:
        xgfalclient.set_verbose(xgfalclient.verbose_level.verbose)
    assert "finaliser" in caplog.text
    half = xgfalclient.FileType.__new__(xgfalclient.FileType)
    half.__del__()  # never got a file: nothing to close


# -- metadata, tape, qos, tokens ----------------------------------------------------------


def test_xattrs_and_checksum(fctx: Gfal2Context) -> None:
    plugin = fake(fctx)
    assert fctx.getxattr("fake://h/f", "user.status") == "user.status-value"
    assert fctx.setxattr("fake://h/f", "k", "v", 0) == 0
    assert fctx.setxattr("fake://h/f", "k", "v") == 0
    assert ("setxattr", "k", "v", 0) in plugin.calls
    assert fctx.listxattr("fake://h/f") == ["user.status"]
    assert fctx.checksum("fake://h/f", "md5") == "abc"
    assert fctx.checksum("fake://h/f", "ADLER32") == "00000abc"
    fctx.set_opt_boolean("CORE", "FORMAT_ADLER32_CHECKSUM", False)
    assert fctx.checksum("fake://h/f", "adler32", 0, 0) == "abc"


def test_getxattr_checksum_falls_back_to_checksum(fctx: Gfal2Context, monkeypatch: Any) -> None:
    plugin = fake(fctx)

    def unknown(url: str, name: str) -> str:
        raise GError("no such attribute", errno.ENODATA)

    monkeypatch.setattr(plugin, "getxattr", unknown)
    assert fctx.getxattr("fake://h/f", "user.checksum.adler32") == "00000abc"
    assert fctx.getxattr("fake://h/f", "user.checksum.md5") == "abc"
    with pytest.raises(GError) as caught:
        fctx.getxattr("fake://h/f", "user.status")
    assert caught.value.code == errno.ENODATA
    # min:// has no getxattr at all: the fallback still needs a checksum plugin.
    with pytest.raises(GError) as caught:
        fctx.getxattr("min://h/f", "user.checksum.md5")
    assert caught.value.code == errno.EPROTONOSUPPORT


def test_rename_needs_one_plugin_for_both_urls(fctx: Gfal2Context) -> None:
    for new in ("min://h/g", "nope://h/g"):
        with pytest.raises(GError) as caught:
            fctx.rename("fake://h/f", new)
        assert caught.value.args == (
            f"Protocol not supported or path/url invalid: {new}",
            errno.EPROTONOSUPPORT,
        )
    assert "fake://h/f" in fake(fctx).files


def test_bring_online_overloads(fctx: Gfal2Context) -> None:
    plugin = fake(fctx)
    assert fctx.bring_online("fake://h/f", 10, 20, True) == (1, "token")
    assert plugin.calls[-1] == ("bring_online", ["fake://h/f"], [""], 10, 20, True)
    plugin.staging = [False]
    assert fctx.bring_online("fake://h/f", "meta", 1, 2, False) == (0, "token")
    assert plugin.calls[-1][2] == ["meta"]
    plugin.staging = [True, False, GError("lost", errno.EIO)]
    urls = ["fake://h/a", "fake://h/b", "fake://h/c"]
    errors, token = fctx.bring_online(urls, ["m1", "m2", "m3"], 1, 2, True)
    assert errors[:2] == [None, None] and errors[2].code == errno.EIO and token == "token"
    errors, _ = fctx.bring_online(urls, 1, 2, True)
    assert plugin.calls[-1][2] == ["", "", ""]
    with pytest.raises(TypeError):
        fctx.bring_online("fake://h/f", 1)
    with pytest.raises(GError) as caught:
        fctx.bring_online(urls, ["only one"], 1, 2, True)
    assert caught.value.args == (
        "List of urls and list of metadata with different sizes",
        errno.EINVAL,
    )
    plugin.staging = [GError("gone", errno.ENOENT)]
    with pytest.raises(GError):
        fctx.bring_online("fake://h/f", 1, 2, True)


def test_polls_release_abort(fctx: Gfal2Context) -> None:
    plugin = fake(fctx)
    plugin.staging = [False]
    assert fctx.bring_online_poll("fake://h/f", "t") == 0
    assert fctx.archive_poll("fake://h/f") == 0
    plugin.staging = [True, False, GError("x", errno.EIO)]
    polled = fctx.bring_online_poll(["fake://h/a", "fake://h/b", "fake://h/c"], "t")
    assert polled[0] is None and polled[1].code == errno.EAGAIN and polled[2].code == errno.EIO
    archived = fctx.archive_poll(["fake://h/a", "fake://h/b", "fake://h/c"])
    assert archived[0] is None and archived[1].code == errno.EAGAIN
    assert fctx.release("fake://h/ok") == 0
    assert fctx.release("fake://h/ok", "tok") == 0
    with pytest.raises(GError):
        fctx.release("fake://h/bad")
    released = fctx.release(["fake://h/ok", "fake://h/bad"], "t")
    assert released[0] is None and released[1].code == errno.EINVAL
    assert fctx.abort_bring_online("fake://h/f", "t") == 0
    assert fctx.abort_bring_online(["fake://h/f"], "t") == [None]
    # A plugin may answer "not yet" as an EAGAIN of its own: 0 alone, the error in a list.
    plugin.staging = [GError("Not ready", errno.EAGAIN)]
    assert fctx.bring_online_poll("fake://h/f", "t") == 0
    assert fctx.archive_poll("fake://h/f") == 0
    assert fctx.bring_online_poll(["fake://h/f"], "t")[0].message == "Not ready"
    with pytest.raises(GError):
        fctx.bring_online("fake://h/f", 1, 2, True)  # bring_online itself does raise it


@pytest.mark.parametrize(
    "call",
    [
        lambda c, urls: c.bring_online(urls, 1, 2, True),
        lambda c, urls: c.bring_online(urls, ["m"] * len(urls), 1, 2, True),
        lambda c, urls: c.bring_online_poll(urls, "t"),
        lambda c, urls: c.release(urls),
        lambda c, urls: c.abort_bring_online(urls, "t"),
        lambda c, urls: c.archive_poll(urls),
    ],
)
def test_tape_list_forms_answer_per_file(fctx: Gfal2Context, call: Any) -> None:
    with pytest.raises(GError) as caught:
        call(fctx, [])
    assert caught.value.args == ("Empty list of files", errno.EINVAL)
    # No plugin for the first URL: every file gets that error, nothing raises.
    found = call(fctx, ["nope://h/a", "fake://h/b"])
    errors = found[0] if isinstance(found, tuple) else found
    assert [e.code for e in errors] == [errno.EPROTONOSUPPORT] * 2
    assert errors[0].message.endswith("nope://h/a")
    if isinstance(found, tuple):
        assert found[1] == ""
    # min:// claims the URLs but has no tape support.
    errors = call(fctx, ["min://h/a"])
    errors = errors[0] if isinstance(errors, tuple) else errors
    assert errors[0].code == errno.EPROTONOSUPPORT


def test_tape_list_call_failing_as_a_whole(fctx: Gfal2Context, monkeypatch: Any) -> None:
    def down(*args: Any) -> None:
        raise GError("service down", errno.EIO)

    monkeypatch.setattr(fake(fctx), "release", down)
    errors = fctx.release(["fake://h/a", "fake://h/b"], "t")
    assert [(e.message, e.code) for e in errors] == [("service down", errno.EIO)] * 2


def test_qos_and_tokens(fctx: Gfal2Context) -> None:
    assert fctx.check_file_qos("fake://h/f") == "disk"
    assert fctx.check_available_qos_transitions("fake://h/f") == ["tape"]
    assert fctx.check_target_qos("fake://h/f") == "tape"
    assert fctx.change_object_qos("fake://h/f", "tape") == 0
    assert fctx.qos_check_classes("fake://h/f", "file") == ["file"]
    assert fctx.token_retrieve("fake://h/f", "iss", 60, True) == "iss:60:True:"
    assert (
        fctx.token_retrieve("fake://h/f", "", 5, ["DOWNLOAD", "LIST"]) == ":5:False:DOWNLOAD,LIST"
    )
    # Given activities, gfal2 passes write_access=False; the activities decide.
    assert fctx.token_retrieve("fake://h/f", "", 5, ["upload"]) == ":5:False:upload"
    assert fctx.token_retrieve("fake://h/f", "", 5, ("LIST",)) == ":5:False:LIST"
    assert fctx.token_retrieve("fake://h/f", "", 5, True, ["LIST"]) == ":5:True:LIST"
    assert fctx.token_retrieve("fake://h/f", "", 5, 1) == ":5:True:"  # Boost's int to bool
    with pytest.raises(GError) as caught:
        fctx.token_retrieve("fake://h/f", "", 5, [])
    assert caught.value.args == ("Empty list of activities", errno.EINVAL)
    with pytest.raises(TypeError):
        fctx.token_retrieve("fake://h/f", "", 5)


# -- options, credentials, identity, lifecycle ------------------------------------------------


def test_option_wrappers(fctx: Gfal2Context, tmp_path: Path) -> None:
    assert fctx.set_opt_string("G", "S", "v") == 0
    assert fctx.get_opt_string("G", "S") == "v"
    assert fctx.set_opt_integer("G", "I", 3) == 0
    assert fctx.get_opt_integer("G", "I") == 3
    assert fctx.set_opt_boolean("G", "B", True) == 0
    assert fctx.get_opt_boolean("G", "B") is True
    assert fctx.set_opt_string_list("G", "L", ["a"]) == 0
    assert fctx.get_opt_string_list("G", "L") == ["a"]
    assert fctx.remove_opt("G", "S") is True
    conf = tmp_path / "x.conf"
    conf.write_text("[G]\nS=w\n")
    assert fctx.load_opts_from_file(str(conf)) == 0
    assert fctx.get_opt_string("G", "S") == "w"
    with pytest.raises(GError) as caught:
        fctx.load_opts_from_file(str(tmp_path / "nope.conf"))
    assert caught.value.args == (
        f"Error while loading configuration file {tmp_path / 'nope.conf'}: "
        "No such file or directory",
        4,
    )


def test_credential_wrappers(fctx: Gfal2Context, tmp_path: Path) -> None:
    credential = fctx.cred_new("BEARER", "tok")
    assert isinstance(credential, Credential)
    assert fctx.cred_set("fake://h/", credential) == 0
    assert fctx.cred_get("BEARER", "fake://h/f") == ("tok", "fake://h/")
    assert fctx.bearer_token("fake://h/f") == "tok"
    assert fctx.cred_del("BEARER", "fake://h/") == 0
    assert fctx.cred_del("BEARER", "fake://h/") == -1  # nothing left there
    assert fctx.cred_get("BEARER", "fake://h/f") == ("", "")
    fctx.cred_set("fake://h/", Credential("X509_CERT", "/c"))
    assert fctx.x509("fake://h/f") is not None
    assert fctx.cred_clean() == 0
    assert fctx.x509("fake://h/f") is None
    assert fctx.ca_path() is None or isinstance(fctx.ca_path(), str)


def test_cred_get_falls_back_to_the_configuration(fctx: Gfal2Context) -> None:
    fctx.set_opt_string("X509", "CERT", "/cfg/cert.pem")
    fctx.set_opt_string("X509", "KEY", "/cfg/key.pem")
    fctx.set_opt_string("BEARER", "TOKEN", "configured")
    assert fctx.cred_get("X509_CERT", "https://z/") == ("/cfg/cert.pem", "")
    assert fctx.cred_get("X509_KEY", "https://z/") == ("/cfg/key.pem", "")
    assert fctx.cred_get("BEARER", "https://z/") == ("configured", "")
    assert fctx.cred_get("PASSWD", "https://z/") == ("", "")
    fctx.cred_set("https://z/", Credential("BEARER", "mapped"))
    assert fctx.cred_get("BEARER", "https://z/f") == ("mapped", "https://z/")


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"X509_USER_PROXY": " /nowhere/px "}, ("/nowhere/px", "/nowhere/px", None)),
        ({"X509_USER_PROXY": "/p", "BEARER_TOKEN": " tok "}, (None, None, "tok")),
        ({"X509_USER_CERT": "/c", "X509_USER_KEY": "/k"}, ("/c", "/k", None)),
        ({"X509_USER_CERT": "/c"}, (None, None, None)),
        ({"BEARER_TOKEN": "  "}, (None, None, None)),
    ],
)
def test_context_copies_the_environment_credentials(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], expected: tuple[Any, ...]
) -> None:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    config = Options(load_system=False)
    config.set_string("X509", "CERT", "/from/a/file")  # the environment wins, as in gfal2
    context = Gfal2Context(options=config, load_plugins=False)
    cert = expected[0] or "/from/a/file"
    found = (
        context.options.string("X509", "CERT"),
        context.options.string("X509", "KEY") or None,
        context.options.string("BEARER", "TOKEN") or None,
    )
    assert found == (cert, expected[1], expected[2])
    assert context.cred_get("X509_CERT", "https://h/") == (cert, "")


def test_ssl_context_helper(fctx: Gfal2Context) -> None:
    assert fctx.ssl_context("https://h/").verify_mode == ssl.CERT_REQUIRED
    fctx.set_opt_boolean("FAKE PLUGIN", "INSECURE", True)
    insecure = fctx.ssl_context("https://h/", group="FAKE PLUGIN", check_hostname=False)
    assert insecure.verify_mode == ssl.CERT_NONE
    assert fctx.ssl_context(group="OTHER").verify_mode == ssl.CERT_REQUIRED


def test_identity(fctx: Gfal2Context) -> None:
    assert fctx.get_user_agent() == (None, None)
    assert fctx.user_agent_string() == "gfal2/2.23.5"
    assert fctx.set_user_agent("fts", "3.12") == 0
    assert fctx.get_user_agent() == ("fts", "3.12")
    assert fctx.user_agent_string() == "fts/3.12 gfal2/2.23.5"
    fctx.set_user_agent("fts", "")
    assert fctx.user_agent_string() == "fts/ gfal2/2.23.5"
    assert fctx.client_info_string() == ""
    assert fctx.add_client_info("job-id", "1") == 0
    fctx.add_client_info("file-id", "2")
    assert fctx.get_client_info() == {"job-id": "1", "file-id": "2"}
    assert fctx.client_info_string() == "job-id=1;file-id=2"
    assert fctx.remove_client_info("job-id") == 0
    with pytest.raises(GError) as caught:
        fctx.remove_client_info("absent")
    assert caught.value.args == ("Key absent not found", errno.EINVAL)
    assert fctx.clear_client_info() == 0
    assert fctx.get_client_info() == {}


def test_client_info_order_and_encoding(fctx: Gfal2Context) -> None:
    for key, value in [("a", "1"), ("b", "x y;z"), ("c", "é~"), ("a", "2")]:
        fctx.add_client_info(key, value)
    # Re-adding "a" moved the last entry into its slot, then appended it.
    assert list(fctx.get_client_info().items()) == [("c", "é~"), ("b", "x y;z"), ("a", "2")]
    assert fctx.client_info_string() == "c=%C3%A9%7E;b=x%20y%3Bz;a=2"
    fctx.remove_client_info("a")  # the last one: nothing moves
    assert list(fctx.get_client_info()) == ["c", "b"]


def test_lifecycle(caplog: pytest.LogCaptureFixture) -> None:
    class Unclosable(Fake):
        def close(self) -> None:
            raise RuntimeError("no")

    with Gfal2Context(options=Options(load_system=False), load_plugins=False) as context:
        context.add_plugin(Unclosable)
        assert "fake-2.23.5" in repr(context)
        assert context.cancel() == 0
        assert context._cancel_generation == 1
    assert context._freed
    with context:  # leaving a with block on a freed context does not free it again
        pass
    assert context.Stat is Stat
    assert isinstance(xgfalclient.creat_context(), Gfal2Context)


def test_nested_names_are_the_bindings(fctx: Gfal2Context) -> None:
    assert Gfal2Context.TransferParameters is xgfalclient.TransferParameters
    assert Gfal2Context.transfer_parameters is xgfalclient.TransferParameters
    assert isinstance(fctx.transfer_parameters(), fctx.transfer_parameters)
    assert Gfal2Context.cred_new is Credential is Gfal2Context.Credential
    assert Gfal2Context.event_side is xgfalclient.event_side  # type: ignore[attr-defined]
    assert Gfal2Context.gfalt_event is xgfalclient.GfaltEvent  # type: ignore[attr-defined]
    assert Gfal2Context.NullHandler is logging.NullHandler  # type: ignore[attr-defined]


def test_cancel_waits_for_other_threads(fctx: Gfal2Context) -> None:
    started, release = threading.Event(), threading.Event()
    answers: list[int] = []

    def slow() -> None:
        started.set()
        release.wait(10)

    worker = threading.Thread(target=fctx._guard, args=(slow,))
    worker.start()
    started.wait(10)
    canceller = threading.Thread(target=lambda: answers.append(fctx.cancel()))
    canceller.start()
    while not fctx._cancelling:
        time.sleep(0.001)
    with pytest.raises(GError) as caught:  # nothing starts while a cancel drains
        fctx.stat("fake://h/f")
    assert caught.value.args == ("[gfal2_cancel] operation canceled by user", errno.ECANCELED)
    assert canceller.is_alive()
    release.set()
    canceller.join(10)
    worker.join(10)
    assert answers == [1] and fctx._cancelling == 0
    assert fctx.stat("fake://h/f").st_size == 5


def test_cancel_from_inside_an_operation_does_not_wait_for_it(fctx: Gfal2Context) -> None:
    def nested() -> int:
        return fctx._guard(fctx.cancel)  # type: ignore[no-any-return]

    assert fctx._guard(nested) == 2
    assert fctx._running == 0


def test_filecopy_overloads(fctx: Gfal2Context, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        "xgfalclient.context.run_copy", lambda ctx, params, src, dst: seen.append(("one", src, dst))
    )
    monkeypatch.setattr(
        "xgfalclient.context.run_bulk",
        lambda ctx, params, srcs, dsts, cks: seen.append(("bulk", srcs, dsts, cks)) or [None],
    )
    params = fctx.transfer_parameters()
    assert fctx.filecopy(params, "fake://h/a", "fake://h/b") == 0
    assert fctx.filecopy("fake://h/a", "fake://h/b") == 0
    assert fctx.filecopy(params, ["a"], ["b"]) == [None]
    assert fctx.filecopy(["a"], ["b"], ["adler32:1"]) == [None]
    assert seen == [
        ("one", "fake://h/a", "fake://h/b"),
        ("one", "fake://h/a", "fake://h/b"),
        ("bulk", ["a"], ["b"], []),
        ("bulk", ["a"], ["b"], ["adler32:1"]),
    ]
    for wrong in [(), (params, "only-one"), ("fake://h/a", ["b"])]:
        with pytest.raises(TypeError):
            fctx.filecopy(*wrong)
    assert fctx._running == 0


def test_copy_plugin_selection(fctx: Gfal2Context) -> None:
    class Copier(Fake):
        name = "copier"
        schemes = ("cp",)

        def copy_check(self, source: str, destination: str) -> bool:
            return source.startswith("cp://")

        def copy(self, transfer: Transfer) -> None:
            pass

    assert fctx._copy_plugin("cp://a", "cp://b") is None
    plugin = fctx.add_plugin(Copier)
    assert fctx._copy_plugin("cp://a", "cp://b") is plugin
    assert fctx._copy_plugin("fake://a", "cp://b") is None
    assert Plugin.copy_check(plugin, "a", "b") is False
