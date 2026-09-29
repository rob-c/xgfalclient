"""The ``lfc`` plugin against the in-process LFC: gfal2's operations, end to end."""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from conftest import file_url
from xgfalclient import events as ev
from xgfalclient.errors import ECOMM, GError
from xgfalclient.plugins.lfc import LFCPlugin
from xgfalclient.plugins.lfc import plugin as lfc_plugin
from xgfalclient.plugins.lfc.client import CnsError
from xgfalclient.testing.lfc import USER_DN, Hangup, LFCServer, Raw
from xgfalclient.testing.pki import PKI

_ENV = ("LFC_HOST", "LFC_PORT", "CSEC_MECH", "LFC_CONNTIMEOUT", "LFC_CONRETRY", "LFC_CONRETRYINT")


@pytest.fixture(autouse=True)
def _lfc_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LFC_CONRETRY", "0")


@pytest.fixture
def lfc(pki: PKI) -> Iterator[LFCServer]:
    with LFCServer(gsi=pki.server_context(), mapfile={USER_DN: "xgfal"}) as server:
        server.mkdir("/grid", 0o777)
        yield server


@pytest.fixture
def lctx(grid_env: PKI) -> Iterator[xgfalclient.Gfal2Context]:
    context = xgfalclient.Gfal2Context(load_plugins=False)
    context.add_plugin(LFCPlugin)
    yield context
    context.free()


def plugin_of(context: xgfalclient.Gfal2Context) -> LFCPlugin:
    found = context.plugins[0]
    assert isinstance(found, LFCPlugin)
    return found


def user_file(lfc: LFCServer, path: str, **fields: object) -> None:
    lfc.add_file(path, uid=101, gid=101, **fields)  # type: ignore[arg-type]


# -- dispatch and URLs -----------------------------------------------------------------


def test_handles_and_copy_check(lctx: xgfalclient.Gfal2Context) -> None:
    plugin = plugin_of(lctx)
    assert plugin.handles("lfc://host/p", "rename")
    assert plugin.handles("LFC://host/p", "stat")
    assert not plugin.handles("lfc://", "stat")
    assert plugin.handles("lfn:/grid/x", "mkdir")
    assert not plugin.handles("lfn:/", "stat")
    assert plugin.handles("guid:abc", "stat")
    assert not plugin.handles("guid:abc", "rename")
    assert not plugin.handles("guid:", "stat")
    assert not plugin.handles("file:///x", "stat")
    assert plugin.copy_check("file:///x", "lfc://h/p")
    assert plugin.copy_check("file:///x", "lfn:/grid/p")
    assert not plugin.copy_check("file:///x", "guid:abc")
    assert not plugin.copy_check("file:///x", "lfc://")
    assert not plugin.copy_check("lfc://h/p", "file:///x")


def test_parse_forms(lctx: xgfalclient.Gfal2Context, monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = plugin_of(lctx)
    parsed = plugin.parse("lfc://host:5011//grid//a/")
    assert (parsed.host, parsed.path) == ("host:5011", "//grid//a/")
    assert plugin.parse("lfc:///host/x").host == "host"
    for bad in ("lfc://host", "lfc:///", "file:///x", "guid:"):
        with pytest.raises(GError) as info:
            plugin.parse(bad)
        assert info.value.code == errno.EINVAL
    with pytest.raises(GError, match="No LFC host") as info:
        plugin.parse("lfn:/grid/a")
    assert info.value.code == errno.EINVAL
    lctx.set_opt_string("LFC PLUGIN", "LFC_HOST", "configured")
    assert plugin.parse("lfn:/grid//a//b/").host == "configured"
    assert plugin.parse("lfn:/grid//a//b/").path == "/grid/a/b"
    assert plugin.parse("lfn://").path == "/"
    monkeypatch.setenv("LFC_HOST", "fromenv")
    assert plugin.parse("lfn:/x").host == "fromenv"


def test_split_host() -> None:
    split = lfc_plugin._split_host
    assert split("h", 5010) == ("h", 5010)
    assert split("h:1", 5010) == ("h", 1)
    assert split("[::1]:7", 5010) == ("::1", 7)
    assert split("[::1]", 5010) == ("::1", 5010)
    assert split("::1", 5010) == ("::1", 5010)
    assert split("[::1", 5010) == ("[::1", 5010)  # no closing bracket: not a bracketed host
    with pytest.raises(GError) as info:
        split("h:x", 5010)
    assert info.value.code == errno.EINVAL


def test_lfn_and_env_port(
    lctx: xgfalclient.Gfal2Context, lfc: LFCServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LFC_HOST", lfc.host)
    monkeypatch.setenv("LFC_PORT", str(lfc.port))
    lctx.mkdir("lfn:/grid/viaenv", 0o755)
    assert lctx.stat("lfn:/grid//viaenv/").is_dir()


# -- namespace ---------------------------------------------------------------------------


def test_stat_mkdir_listdir(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    lctx.mkdir(lfc.url("/grid/a"), 0o775)
    info = lctx.stat(lfc.url("/grid/a"))
    assert info.is_dir()
    assert (info.st_uid, info.st_gid, info.st_ino, info.st_nlink) == (101, 101, 0, 0)
    assert stat.S_IMODE(info.st_mode) == 0o775 & ~lfc_client_umask()
    with pytest.raises(GError) as exists:
        lctx.mkdir(lfc.url("/grid/a"), 0o755)
    assert exists.value.code == errno.EEXIST
    assert exists.value.message == "Error while mkdir call in the lfc " + os.strerror(errno.EEXIST)
    user_file(lfc, "/grid/a/f", size=5)
    assert lctx.listdir(lfc.url("/grid")) == ["a"]
    assert lctx.stat(lfc.url("/grid")).st_nlink == 1
    entries = list(lctx.opendir(lfc.url("/grid/a")))
    assert [(entry.d_name, entry.d_type) for entry in entries] == [("f", 8)]
    directory = lctx.opendir(lfc.url("/grid/a"))
    dirent, st = directory.readpp()
    assert (dirent.d_name, st.st_size) == ("f", 5)


def lfc_client_umask() -> int:
    from xgfalclient.plugins.lfc.client import process_umask

    return process_umask()


def test_mkdir_rec(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    lctx.mkdir_rec(lfc.url("/grid/x/y/z"), 0o755)
    assert lctx.stat(lfc.url("/grid/x/y/z")).is_dir()
    lctx.mkdir_rec(lfc.url("/grid/x/y/z"), 0o755)  # exists: fine
    lctx.mkdir_rec(lfc.url("/grid/x/w"), 0o755)  # parent exists, no recursion
    user_file(lfc, "/grid/file")
    with pytest.raises(GError) as info:
        lctx.mkdir_rec(lfc.url("/grid/file/sub/leaf"), 0o755)
    assert info.value.code == errno.ENOTDIR
    lfc.mkdir("/locked", 0o755)
    with pytest.raises(GError) as denied:  # the EACCES on /locked/a is ignored, as in gfal2
        lctx.mkdir_rec(lfc.url("/locked/a/b"), 0o755)
    assert denied.value.code == errno.ENOENT


def test_mkdir_rec_race(
    lctx: xgfalclient.Gfal2Context, lfc: LFCServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Somebody else creates the leaf between our attempts: still a success."""
    plugin = plugin_of(lctx)
    real = plugin._mkdir
    calls: list[str] = []

    def racing(server: object, path: str, mode: int) -> None:
        calls.append(path)
        if path == "/grid/r/leaf" and len(calls) > 1:
            real(server, path, mode)  # type: ignore[arg-type]
        real(server, path, mode)  # type: ignore[arg-type]

    monkeypatch.setattr(plugin, "_mkdir", racing)
    lctx.mkdir_rec(lfc.url("/grid/r/leaf"), 0o755)
    assert calls == ["/grid/r/leaf", "/grid", "/grid/r", "/grid/r/leaf"]


def test_mkdir_rec_intermediate_failure(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    from xgfalclient.plugins.lfc import wire

    lfc.inject(wire.MKDIR, errno.ENOENT, errno.EIO)
    with pytest.raises(GError) as info:
        lctx.mkdir_rec(lfc.url("/grid/p/q"), 0o755)
    assert info.value.code == errno.EIO


def test_unlink_request_failure(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    from xgfalclient.plugins.lfc import wire

    lfc.inject(wire.DELFILES, errno.EIO)
    with pytest.raises(GError) as info:
        lctx.unlink(lfc.url("/grid/x"))
    assert info.value.code == errno.EIO


def test_stat_errors(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    with pytest.raises(GError) as info:
        lctx.stat(lfc.url("/grid/missing"))
    assert (info.value.code, info.value.message) == (
        errno.ENOENT,
        "Error report from LFC : No such file or directory",
    )
    user_file(lfc, "/grid/f")
    with pytest.raises(GError) as notdir:
        lctx.stat(lfc.url("/grid/f/x"))
    assert notdir.value.code == errno.ENOTDIR
    with pytest.raises(GError) as toolong:
        lctx.stat(lfc.url("/grid/" + "n" * 300))
    assert toolong.value.code == errno.ENAMETOOLONG
    with pytest.raises(GError) as pathlong:
        lctx.stat(lfc.url("/" + "d/" * 600))
    assert pathlong.value.code == errno.ENAMETOOLONG


def test_access_chmod(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    user_file(lfc, "/grid/f", mode=0o600)
    lctx.access(lfc.url("/grid/f"), os.R_OK | os.W_OK)
    lctx.chmod(lfc.url("/grid/f"), 0o400)
    with pytest.raises(GError) as info:
        lctx.access(lfc.url("/grid/f"), os.W_OK)
    assert info.value.code == errno.EACCES
    assert info.value.message.startswith("lfc access error, file : lfc://")
    lfc.add_file("/grid/root", mode=0o644)
    with pytest.raises(GError) as perm:
        lctx.chmod(lfc.url("/grid/root"), 0o777)
    assert (perm.value.code, perm.value.message) == (
        errno.EPERM,
        "Errno reported from lfc : Operation not permitted ",
    )
    with pytest.raises(GError) as inval:
        lctx.access(lfc.url("/grid/f"), 0o10)
    assert inval.value.code == errno.EINVAL


def test_rmdir(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    lctx.mkdir(lfc.url("/grid/d"), 0o755)
    user_file(lfc, "/grid/d/f")
    with pytest.raises(GError) as info:
        lctx.rmdir(lfc.url("/grid/d"))
    assert (info.value.code, info.value.message) == (
        errno.ENOTEMPTY,
        "Error report from LFC File exists",
    )
    with pytest.raises(GError) as notdir:
        lctx.rmdir(lfc.url("/grid/d/f"))
    assert notdir.value.code == errno.ENOTDIR
    lctx.unlink(lfc.url("/grid/d/f"))
    lctx.rmdir(lfc.url("/grid/d"))
    with pytest.raises(GError):
        lctx.stat(lfc.url("/grid/d"))


def test_rename_symlink_readlink(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    user_file(lfc, "/grid/f", size=3)
    lctx.rename(lfc.url("/grid/f"), lfc.url("/grid/g"))
    assert lctx.stat(lfc.url("/grid/g")).st_size == 3
    lctx.symlink(lfc.url("/grid/g"), lfc.url("/grid/link"))
    lctx.symlink("/grid/g", lfc.url("/grid/link2"))
    assert lctx.readlink(lfc.url("/grid/link")) == "lfn:/grid/g"
    assert stat.S_ISLNK(lctx.lstat(lfc.url("/grid/link")).st_mode)
    assert lctx.stat(lfc.url("/grid/link")).st_size == 3
    with pytest.raises(GError) as notlink:
        lctx.readlink(lfc.url("/grid/g"))
    assert notlink.value.code == errno.EINVAL
    with pytest.raises(GError) as exists:
        lctx.symlink("/grid/g", lfc.url("/grid/link"))
    assert exists.value.code == errno.EEXIST
    with pytest.raises(GError) as relative:
        lctx.symlink("relative/target", lfc.url("/grid/link3"))
    assert relative.value.code == errno.EINVAL
    with pytest.raises(GError) as missing:
        lctx.rename(lfc.url("/grid/nope"), lfc.url("/grid/other"))
    assert missing.value.code == errno.ENOENT
    with pytest.raises(GError) as lstat_missing:
        lctx.lstat(lfc.url("/grid/nope"))
    assert lstat_missing.value.code == errno.ENOENT


def test_unlink(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    user_file(lfc, "/grid/f", replicas=("srm://se/f",))
    lctx.unlink(lfc.url("/grid/f"))  # force: the replica records go too
    with pytest.raises(GError) as info:
        lctx.unlink(lfc.url("/grid/f"))
    assert (info.value.code, info.value.message) == (
        errno.ENOENT,
        "Error report from LFC : No such file or directory",
    )
    lctx.mkdir(lfc.url("/grid/d"), 0o755)
    with pytest.raises(GError) as isdir:
        lctx.unlink(lfc.url("/grid/d"))
    assert isdir.value.code == errno.EPERM


def test_unlink_without_statuses(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    """A server that reports no per-file status: gfal2 takes that for success."""
    from xgfalclient.plugins.lfc import wire

    none = wire.Packer().long(0).bytes()
    lfc.inject(wire.DELFILES, Raw(wire.HEADER.pack(wire.MAGIC2, wire.MSG_DATA, len(none)) + none))
    user_file(lfc, "/grid/f")
    lctx.unlink(lfc.url("/grid/f"))
    assert lfc.lookup("/grid/f")  # nothing was done, and nothing said


def test_opendir_errors(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    with pytest.raises(GError) as info:
        lctx.listdir(lfc.url("/grid/none"))
    assert (info.value.code, info.value.message) == (
        errno.ENOENT,
        "Error report from LFC No such file or directory",
    )
    user_file(lfc, "/grid/f")
    with pytest.raises(GError) as notdir:
        lctx.listdir(lfc.url("/grid/f"))
    assert notdir.value.code == errno.ENOTDIR


def test_large_listing(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    """More entries than one DIRBUFSZ batch: the server carries the rest over."""
    lfc.mkdir("/grid/many", 0o755)
    names = sorted(f"entry-{index:04d}-" + "x" * 40 for index in range(120))
    for name in names:
        lfc.add_file(f"/grid/many/{name}")
    assert lctx.listdir(lfc.url("/grid/many")) == names
    assert lctx.listdir(lfc.url("/grid")) == ["many"]


# -- metadata ------------------------------------------------------------------------------


def test_xattrs(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    user_file(
        lfc,
        "/grid/f",
        guid="11111111-2222-3333-4444-555555555555",
        csumtype="AD",
        csumvalue="0a0b0c0d",
        replicas=("srm://se1/f", "gsiftp://se2/f"),
    )
    url = lfc.url("/grid/f")
    assert lctx.getxattr(url, "user.guid") == "11111111-2222-3333-4444-555555555555"
    assert lctx.getxattr(url, "user.replicas") == "srm://se1/f\ngsiftp://se2/f"
    assert lctx.getxattr(url, "user.chksumtype") == "AD"
    assert lctx.getxattr(url, "user.checksum") == "0a0b0c0d"
    assert lctx.getxattr(url, "user.comment") == ""
    lctx.setxattr(url, "user.comment", "a comment")
    assert lctx.getxattr(url, "user.comment") == "a comment"
    with pytest.raises(GError) as info:
        lctx.getxattr(url, "user.status")
    assert info.value.code == lfc_plugin.ENOATTR
    with pytest.raises(GError) as setbad:
        lctx.setxattr(url, "user.guid", "x")
    assert setbad.value.code == lfc_plugin.ENOATTR
    with pytest.raises(GError) as empty:
        lctx.setxattr(url, "user.comment", "")
    assert empty.value.code == errno.EINVAL
    with pytest.raises(GError) as toolong:
        lctx.setxattr(url, "user.comment", "c" * 300)
    assert toolong.value.code == errno.EINVAL
    assert lctx.listxattr(url) == lfc_plugin.FILE_XATTRS
    assert lctx.listxattr(lfc.url("/grid")) == ["user.comment"]
    with pytest.raises(GError):
        lctx.getxattr(lfc.url("/grid/nope"), "user.replicas")


def test_comment_permissions(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    lfc.add_file("/grid/private", mode=0o600, comment="secret")
    with pytest.raises(GError) as info:
        lctx.getxattr(lfc.url("/grid/private"), "user.comment")
    assert info.value.code == errno.EACCES
    with pytest.raises(GError) as write:
        lctx.setxattr(lfc.url("/grid/private"), "user.comment", "mine")
    assert write.value.code == errno.EACCES


def test_checksum(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    user_file(lfc, "/grid/f", csumtype="AD", csumvalue="1a2b3c4d")
    user_file(lfc, "/grid/none")
    url = lfc.url("/grid/f")
    assert lctx.checksum(url, "adler32") == "1a2b3c4d"
    for algorithm, offset, length in (("MD5", 0, 0), ("ADLER32", 1, 0), ("ADLER32", 0, 5)):
        with pytest.raises(GError) as info:
            lctx.checksum(url, algorithm, offset, length)
        assert info.value.code == errno.ENOTSUP
    with pytest.raises(GError, match="has none") as none:
        lctx.checksum(lfc.url("/grid/none"), "ADLER32")
    assert none.value.code == errno.ENOTSUP


# -- replicas, open and registration --------------------------------------------------------


def test_open_reads_replica(lctx: xgfalclient.Gfal2Context, lfc: LFCServer, data_dir: Path) -> None:
    from xgfalclient.plugins.file import FilePlugin

    lctx.add_plugin(FilePlugin)
    user_file(lfc, "/grid/f", replicas=(file_url(data_dir / "missing.txt"),))
    with pytest.raises(GError) as info:
        lctx.open(lfc.url("/grid/f"), "r")
    assert info.value.code == errno.ENOENT
    lfc.add_file("/grid/g", replicas=(file_url(data_dir / "hello.txt"), "srm://se/f"))
    handle = lctx.open(lfc.url("/grid/g"), "r")
    assert handle.read(100) == "hello world\n"
    handle.close()
    lfc.add_file("/grid/unsupported", replicas=("srm://se/f", file_url(data_dir / "hello.txt")))
    with pytest.raises(GError) as proto:  # like gfal2, only ECOMM moves on to the next
        lctx.open(lfc.url("/grid/unsupported"), "r")
    assert proto.value.code == errno.EPROTONOSUPPORT
    lfc.add_file("/grid/empty")
    with pytest.raises(GError, match="No replica") as none:
        lctx.open(lfc.url("/grid/empty"), "r")
    assert none.value.code == errno.EBADF


def test_open_skips_communication_errors(
    lctx: xgfalclient.Gfal2Context, lfc: LFCServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    lfc.add_file("/grid/f", replicas=("x://a/f", "x://b/f"))
    plugin = plugin_of(lctx)
    tried: list[str] = []

    def failing(url: str, flags: int, size: int | None = None) -> object:
        tried.append(url)
        raise GError("down", ECOMM)

    monkeypatch.setattr(lctx, "_open", failing)
    with pytest.raises(GError) as info:
        plugin.open(lfc.url("/grid/f"), os.O_RDONLY)
    assert info.value.code == ECOMM
    assert tried == ["x://a/f", "x://b/f"]


def mock_source(name: str = "f", size: int = 12, checksum: str = "0000abcd") -> str:
    return f"mock://se.example.org/{name}?size={size}&checksum={checksum}"


@pytest.fixture
def with_mock(lctx: xgfalclient.Gfal2Context) -> xgfalclient.Gfal2Context:
    from xgfalclient.plugins.mock import MockPlugin

    lctx.add_plugin(MockPlugin)
    return lctx


def test_replica_xattr_registration(with_mock: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    lctx = with_mock
    source = mock_source()
    url = lfc.url("/grid/new/dir/f")
    lctx.setxattr(url, "user.replicas", "+" + source)
    entry = lfc.lookup("/grid/new/dir/f")
    assert (entry.size, entry.csumtype, entry.csumvalue) == (12, "AD", "0000abcd")
    assert (entry.replicas[0].sfn, entry.replicas[0].host) == (source, "se.example.org")
    assert lctx.getxattr(url, "user.replicas") == source
    lctx.setxattr(url, "user.replicas", "+" + source)  # already registered: fine
    other = mock_source("g")
    lctx.setxattr(url, "user.replicas", "+" + other)
    assert len(lfc.lookup("/grid/new/dir/f").replicas) == 2
    lctx.setxattr(url, "user.replicas", "-" + source)
    assert lctx.getxattr(url, "user.replicas") == other
    for value in ("", "*x"):
        with pytest.raises(GError) as info:
            lctx.setxattr(url, "user.replicas", value)
        assert info.value.code == errno.EINVAL
    with pytest.raises(GError) as gone:
        lctx.setxattr(url, "user.replicas", "-" + source)
    assert gone.value.code == errno.ENOENT
    with pytest.raises(GError) as nofile:
        lctx.setxattr(lfc.url("/grid/none"), "user.replicas", "-" + source)
    assert nofile.value.code == errno.ENOENT


def test_registration_validation(with_mock: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    lctx = with_mock
    source = mock_source()
    user_file(lfc, "/grid/sized", size=99)
    with pytest.raises(GError, match="do not match") as size:
        lctx.setxattr(lfc.url("/grid/sized"), "user.replicas", "+" + source)
    assert size.value.code == errno.EINVAL
    user_file(lfc, "/grid/summed", size=12, csumtype="AD", csumvalue="deadbeef")
    with pytest.raises(GError, match="checksum") as checksum:
        lctx.setxattr(lfc.url("/grid/summed"), "user.replicas", "+" + source)
    assert checksum.value.code == errno.EINVAL
    user_file(lfc, "/grid/nosum", size=12)
    lctx.setxattr(lfc.url("/grid/nosum"), "user.replicas", "+" + source)
    # checksums compare only when both sides have one, of the same type
    user_file(lfc, "/grid/md5", size=12, csumtype="MD", csumvalue="deadbeef")
    lctx.setxattr(lfc.url("/grid/md5"), "user.replicas", "+" + source)
    unsummed = "mock://se.example.org/u?size=12"  # an empty checksum, left unpadded:
    lctx.set_opt_boolean("CORE", "FORMAT_ADLER32_CHECKSUM", False)
    lctx.setxattr(lfc.url("/grid/summed"), "user.replicas", "+" + unsummed)
    assert lfc.lookup("/grid/summed").replicas[0].sfn == unsummed
    lctx.set_opt_boolean("CORE", "FORMAT_ADLER32_CHECKSUM", True)
    with pytest.raises(GError, match="not a valid url") as bad:
        lctx.setxattr(lfc.url("/grid/x"), "user.replicas", "+file:///no/host")
    assert bad.value.code == errno.EINVAL
    lfc.add_file("/grid/rootfile", size=12)
    lfc.readonly = True
    with pytest.raises(GError, match="Could not register") as readonly:
        lctx.setxattr(lfc.url("/grid/nosum"), "user.replicas", "+" + mock_source("h"))
    assert readonly.value.code == errno.EROFS
    with pytest.raises(GError, match="Could not create") as create:
        lctx.setxattr(lfc.url("/grid/fresh"), "user.replicas", "+" + source)
    assert create.value.code == errno.EROFS
    lfc.readonly = False
    lfc.mkdir("/sealed", 0o755)
    lfc.mkdir("/sealed/inner", 0o700)
    with pytest.raises(GError, match="Failed to stat") as stat_fail:
        lctx.setxattr(lfc.url("/sealed/inner/f"), "user.replicas", "+" + source)
    assert stat_fail.value.code == errno.EACCES
    with pytest.raises(GError, match="Could not register") as unreg:
        lctx.setxattr(lfc.url("/grid/rootfile"), "user.replicas", "-srm://nowhere/f")
    assert unreg.value.code == errno.ENOENT


def test_registration_under_the_root(with_mock: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    lfc.lookup("/").mode = stat.S_IFDIR | 0o777
    with_mock.setxattr(lfc.url("/top"), "user.replicas", "+" + mock_source())
    assert lfc.lookup("/top").size == 12


def test_registration_setfsize_failure(with_mock: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    from xgfalclient.plugins.lfc import wire

    lfc.inject(wire.SETFSIZEG, errno.EACCES)
    with pytest.raises(GError, match="Could not set file size") as info:
        with_mock.setxattr(lfc.url("/grid/f"), "user.replicas", "+" + mock_source())
    assert info.value.code == errno.EACCES


def test_replica_info_without_checksum(
    lctx: xgfalclient.Gfal2Context, lfc: LFCServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = plugin_of(lctx)
    monkeypatch.setattr(lctx, "stat", lambda url: xgfalclient.Stat(st_size=4))

    def no_checksum(url: str, algorithm: str, offset: int = 0, length: int = 0) -> str:
        raise GError("no", errno.ENOTSUP)

    monkeypatch.setattr(lctx, "checksum", no_checksum)
    assert plugin._replica_info("mock://x/y") == (4, "", "")


def test_copy_registers(with_mock: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    params = with_mock.transfer_parameters()
    seen: list[str] = []
    params.event_callback = lambda event: seen.append(event.stage)
    params.strict_copy = True  # the core must not stat and unlink the catalogue entry
    source = mock_source()
    with_mock.filecopy(params, source, lfc.url("/grid/copied"))
    assert lfc.lookup("/grid/copied").replicas[0].sfn == source
    assert ev.TRANSFER_TYPE in seen


# -- GUIDs ---------------------------------------------------------------------------------


def test_guid_urls(
    lctx: xgfalclient.Gfal2Context, lfc: LFCServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    user_file(lfc, "/grid/f", guid=guid, size=7)
    lfc.add_link("/grid/alias", "/grid/f")
    monkeypatch.setenv("LFC_HOST", lfc.hostport)
    assert lctx.stat(f"guid:{guid}").st_size == 7
    assert lctx.getxattr(f"guid:{guid}", "user.guid") == guid
    plugin = plugin_of(lctx)
    server = plugin.server(lfc.hostport, "")
    assert server.getlinks(None, guid) == ["/grid/f", "/grid/alias"]
    assert server.getlinks("/grid/alias") == ["/grid/f", "/grid/alias"]
    lfc.add_link("/grid/elsewhere", "/grid/g")
    assert server.getlinks("/grid/elsewhere") == ["/grid/g", "/grid/elsewhere"]  # dangling
    assert server.getlinks("/grid/f") == ["/grid/f", "/grid/alias"]
    with pytest.raises(GError) as info:
        lctx.stat("guid:00000000-0000-0000-0000-000000000000")
    assert info.value.code == errno.ENOENT
    assert info.value.message.startswith("Error while getlinks() with lfclib")
    with pytest.raises(GError) as rename:
        lctx.rename(f"guid:{guid}", lfc.url("/grid/g"))
    assert rename.value.code == errno.EPROTONOSUPPORT
    monkeypatch.setattr(server, "getlinks", lambda path, guid=None: [])
    with pytest.raises(GError, match="no links") as none:
        lctx.stat(f"guid:{guid}")
    assert none.value.code == errno.EINVAL


def test_server_api_extras(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    """Calls gfal2 did not make but the client offers: ping, stat, statr, unlink."""
    plugin = plugin_of(lctx)
    server = plugin.server(lfc.hostport, "")
    assert server.ping() == "1.13.0-1"
    user_file(lfc, "/grid/f", size=2, replicas=("srm://se/f",))
    assert server.stat("/grid/f").size == 2
    assert server.statr("srm://se/f").size == 2
    with pytest.raises(CnsError) as info:
        server.statr("srm://se/none")
    assert info.value.code == errno.ENOENT
    with pytest.raises(CnsError) as replicas:
        server.unlink("/grid/f")
    assert replicas.value.code == errno.EEXIST
    assert server.delfiles(["/grid/f", "/grid/none"], True) == [0, errno.ENOENT]
    assert server.getreplica("/grid", se="nowhere") == []
    user_file(lfc, "/grid/g", size=3, replicas=("srm://se/g",))
    guid = lfc.lookup("/grid/g").guid
    assert server.statg(None, guid).size == 3
    server.delreplica(guid, 0, "srm://se/g")
    assert lfc.lookup("/grid/g").replicas == []


# -- connections -------------------------------------------------------------------------------


def test_sessions_are_reused(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    for _ in range(5):
        lctx.stat(lfc.url("/grid"))
    assert (lfc.connections, lfc.sessions) == (1, 1)
    lctx.free()
    from xgfalclient.plugins.lfc import wire

    assert lfc.log[-1][0] == wire.ENDSESS


def test_without_sessions(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    lctx.set_opt_boolean("LFC PLUGIN", "SESSION_REUSE", False)
    for _ in range(3):
        lctx.stat(lfc.url("/grid"))
    assert lctx.listdir(lfc.url("/")) == ["grid"]
    assert (lfc.connections, lfc.sessions) == (4, 0)


def test_stale_session_is_replaced(lctx: xgfalclient.Gfal2Context, pki: PKI) -> None:
    with LFCServer(
        gsi=pki.server_context(), mapfile={USER_DN: "xgfal"}, session_timeout=0.2
    ) as lfc:
        lctx.stat(lfc.url("/"))
        import time

        time.sleep(0.5)  # the server gives up on the idle session
        lctx.stat(lfc.url("/"))
        assert lfc.connections == 2


def test_dead_pooled_connection_is_retried(lctx: xgfalclient.Gfal2Context, lfc: LFCServer) -> None:
    from xgfalclient.plugins.lfc import wire

    lctx.stat(lfc.url("/grid"))
    lfc.inject(wire.STATG, Hangup())
    assert lctx.stat(lfc.url("/grid")).is_dir()
    assert lfc.connections == 2


def test_connection_refused(lctx: xgfalclient.Gfal2Context) -> None:
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(GError) as info:
        lctx.stat(f"lfc://127.0.0.1:{port}/grid")
    assert info.value.code == errno.ECONNREFUSED


def test_unresolvable_host(lctx: xgfalclient.Gfal2Context) -> None:
    with pytest.raises(GError) as info:
        lctx.stat("lfc://no-such-host.invalid/grid")
    assert info.value.code == errno.EHOSTUNREACH


def test_connect_retries(lctx: xgfalclient.Gfal2Context, monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    monkeypatch.setenv("LFC_CONRETRY", "2")
    monkeypatch.setenv("LFC_CONRETRYINT", "0")
    slept: list[float] = []
    monkeypatch.setattr("xgfalclient.plugins.lfc.client.time.sleep", slept.append)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(GError):
        lctx.stat(f"lfc://127.0.0.1:{port}/grid")
    assert slept == [0.0, 0.0]


def test_no_credential(pki: PKI, lfc: LFCServer) -> None:
    context = xgfalclient.Gfal2Context(load_plugins=False)
    context.add_plugin(LFCPlugin)
    try:
        with pytest.raises(GError, match=r"No X\.509 credential") as info:
            context.stat(lfc.url("/grid"))
        assert info.value.code == errno.EACCES
    finally:
        context.free()


def test_unmapped_user(pki: PKI, grid_env: PKI) -> None:
    with LFCServer(gsi=pki.server_context(), mapfile={}) as lfc:
        context = xgfalclient.Gfal2Context(load_plugins=False)
        context.add_plugin(LFCPlugin)
        try:
            with pytest.raises(GError) as info:
                context.stat(lfc.url("/"))
            assert info.value.code == ECOMM  # SENOMAPFND, which gfal2 calls ECOMM
            assert info.value.message == "Error report from LFC : No user mapping"
        finally:
            context.free()


def test_id_mechanism(
    lctx: xgfalclient.Gfal2Context, lfc: LFCServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CSEC_MECH", "ID")
    lctx.mkdir(lfc.url("/rootdir"), 0o755)  # a trusted host is root
    assert lctx.stat(lfc.url("/rootdir")).st_uid == 0
    lfc.trusted = ()
    plugin_of(lctx).close()
    with pytest.raises(GError) as info:
        lctx.stat(lfc.url("/rootdir"))
    assert info.value.code == errno.EACCES


def test_unavailable_mechanisms(
    lctx: xgfalclient.Gfal2Context, lfc: LFCServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CSEC_MECH", "KRB5 NOPE")
    monkeypatch.setattr(lfc_plugin, "available_krb5", lambda: False)
    with pytest.raises(GError, match="share no authentication") as info:
        lctx.stat(lfc.url("/"))
    assert info.value.code == errno.EACCES


def test_krb5_offered(lctx: xgfalclient.Gfal2Context, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CSEC_MECH", "KRB5")
    monkeypatch.setattr(lfc_plugin, "available_krb5", lambda: True)
    found = plugin_of(lctx)._mechanisms("lfc://h/p")
    assert [mech.name for mech in found] == ["KRB5"]


def test_env_settings(lctx: xgfalclient.Gfal2Context, monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = plugin_of(lctx)
    monkeypatch.setenv("LFC_CONNTIMEOUT", "7")
    assert plugin._setting("LFC_CONNTIMEOUT", 15) == 7
    monkeypatch.setenv("LFC_CONNTIMEOUT", "junk")
    lctx.set_opt_integer("LFC PLUGIN", "LFC_CONNTIMEOUT", 9)
    assert plugin._setting("LFC_CONNTIMEOUT", 15) == 9
    monkeypatch.delenv("LFC_CONNTIMEOUT")
    lctx.remove_opt("LFC PLUGIN", "LFC_CONNTIMEOUT")
    assert plugin._setting("LFC_CONNTIMEOUT", 15) == 15
