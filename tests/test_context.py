"""The context: dispatch, gfal2's fallbacks, return shapes, and the file/dir handles."""

from __future__ import annotations

import errno
import logging
import os
import ssl
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
        if url in self.dirs:
            raise GError("exists", errno.EEXIST)
        parent_url = url.rsplit("/", 1)[0] or "fake://h/"
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
    context.free()


def fake(context: Gfal2Context) -> Fake:
    return next(p for p in context.plugins if isinstance(p, Fake))


# -- dispatch -----------------------------------------------------------------------


def test_plugins_sorted_by_priority(fctx: Gfal2Context) -> None:
    assert fctx.get_plugin_names() == ["fake-0.1.0", "minimal-0.1.0"]
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
    assert caught.value.code == errno.EPIPE
    with pytest.raises(GError) as caught:
        fctx._guard(boom, None)
    assert caught.value.code == errno.EIO
    fctx.free()
    with pytest.raises(GError) as caught:
        fctx.stat("fake://h/f")
    assert caught.value.code == errno.EBADF


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


def test_access_falls_back_to_stat(fctx: Gfal2Context) -> None:
    assert fctx.access("min://h/file", os.F_OK) == 0
    with pytest.raises(GError):
        fctx.access("min://h/missing", os.F_OK)


def test_mkdir_rec_generic(fctx: Gfal2Context) -> None:
    plugin = fake(fctx)
    assert fctx.mkdir_rec("fake://h/a/b/c", 0o755) == 0
    assert {"fake://h/a", "fake://h/a/b", "fake://h/a/b/c"} <= plugin.dirs
    assert fctx.mkdir_rec("fake://h/a", 0o755) == 0  # already there
    with pytest.raises(GError) as caught:
        fctx.mkdir_rec("fake://h/f/x", 0o755)
    assert caught.value.code == errno.ENOTDIR
    with pytest.raises(GError) as caught:
        fctx.mkdir_rec("min://h/denied", 0o755)
    assert caught.value.code == errno.EACCES


def test_mkdir_rec_tolerates_races_but_not_failures(
    fctx: Gfal2Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    minimal = next(p for p in fctx.plugins if isinstance(p, Minimal))
    original = minimal.stat
    monkeypatch.setattr(
        minimal,
        "stat",
        lambda url: (
            original(url + "/missing") if url.endswith(("race", "broken")) else original(url)
        ),
    )
    assert fctx.mkdir_rec("min://h/race", 0o755) == 0
    with pytest.raises(GError) as caught:
        fctx.mkdir_rec("min://h/broken", 0o755)
    assert caught.value.code == errno.EIO


def test_mkdir_rec_stops_at_the_root(fctx: Gfal2Context) -> None:
    assert fctx.mkdir_rec("min://gone/", 0o755) == 0


def test_mkdir_rec_prefers_the_plugin(fctx: Gfal2Context) -> None:
    class WithRec(Fake):
        name = "rec"
        schemes = ("rec",)

        def mkdir_rec(self, url: str, mode: int) -> None:
            self.calls.append(("mkdir_rec", url))

    plugin = fctx.add_plugin(WithRec)
    assert fctx.mkdir_rec("rec://h/x/y", 0o700) == 0
    assert plugin.calls == [("mkdir_rec", "rec://h/x/y")]  # type: ignore[attr-defined]


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
    assert fctx.unlink([]) == []
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
    with caplog.at_level(logging.DEBUG, logger="xgfalclient"):
        broken.__del__()
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
    assert caught.value.code == errno.EINVAL
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
    assert fctx.token_retrieve("fake://h/f", "", 5, ["upload"]).startswith(":5:True")


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


def test_credential_wrappers(fctx: Gfal2Context, tmp_path: Path) -> None:
    credential = fctx.cred_new("BEARER", "tok")
    assert isinstance(credential, Credential)
    assert fctx.cred_set("fake://h/", credential) == 0
    assert fctx.cred_get("BEARER", "fake://h/f") == ("tok", "fake://h/")
    assert fctx.bearer_token("fake://h/f") == "tok"
    assert fctx.cred_del("BEARER", "fake://h/") == 0
    assert fctx.cred_get("BEARER", "fake://h/f") == ("", "")
    fctx.cred_set("fake://h/", Credential("X509_CERT", "/c"))
    assert fctx.x509("fake://h/f") is not None
    assert fctx.cred_clean() == 0
    assert fctx.x509("fake://h/f") is None
    assert fctx.ca_path() is None or isinstance(fctx.ca_path(), str)


def test_ssl_context_helper(fctx: Gfal2Context) -> None:
    assert fctx.ssl_context("https://h/").verify_mode == ssl.CERT_REQUIRED
    fctx.set_opt_boolean("FAKE PLUGIN", "INSECURE", True)
    insecure = fctx.ssl_context("https://h/", group="FAKE PLUGIN", check_hostname=False)
    assert insecure.verify_mode == ssl.CERT_NONE
    assert fctx.ssl_context(group="OTHER").verify_mode == ssl.CERT_REQUIRED


def test_identity(fctx: Gfal2Context) -> None:
    assert fctx.get_user_agent() == (None, None)
    assert fctx.user_agent_string() == f"xgfalclient/{xgfalclient.__version__}"
    assert fctx.set_user_agent("fts", "3.12") == 0
    assert fctx.get_user_agent() == ("fts", "3.12")
    assert fctx.user_agent_string() == "fts/3.12"
    fctx.set_user_agent("fts", "")
    assert fctx.user_agent_string() == "fts"
    assert fctx.add_client_info("job-id", "1") == 0
    fctx.add_client_info("file-id", "2")
    assert fctx.get_client_info() == {"job-id": "1", "file-id": "2"}
    assert fctx.client_info_string() == "job-id=1;file-id=2"
    assert fctx.remove_client_info("job-id") == 0
    assert fctx.remove_client_info("absent") == 0
    assert fctx.clear_client_info() == 0
    assert fctx.get_client_info() == {}


def test_lifecycle(caplog: pytest.LogCaptureFixture) -> None:
    class Unclosable(Fake):
        def close(self) -> None:
            raise RuntimeError("no")

    with Gfal2Context(options=Options(load_system=False), load_plugins=False) as context:
        context.add_plugin(Unclosable)
        assert "fake-0.1.0" in repr(context)
        assert context.cancel() == 0
        assert context._cancel_generation == 1
    assert context._freed
    assert context.Stat is Stat
    assert Gfal2Context.TransferParameters is xgfalclient.TransferParameters
    assert isinstance(xgfalclient.creat_context(), Gfal2Context)


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
