# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""The gridftp plugin through the gfal2 API, against the in-process server."""

from __future__ import annotations

import errno
import json
import os
import socket
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import xgfalclient
from conftest import needs_peer_chain
from test_gridftp_helpers import (  # noqa: F401 - fixtures
    GROUP,
    Events,
    FakeServer,
    _fast_polls,
    code_of,
    ftp,
    gctx,
    gsi,
    gsi_pair,
    login_script,
    make_gsi,
    plugin_of,
    write,
)
from xgfalclient.errors import ECOMM, GError
from xgfalclient.plugins.gridftp.data import DataConn
from xgfalclient.testing.gridftp import FEATURES, GridFTPServer
from xgfalclient.testing.pki import PKI

Ctx = xgfalclient.Gfal2Context


def root_of(server: GridFTPServer) -> Path:
    return Path(server.root)


@pytest.fixture(params=["ftp", "gsi"])
def server(request: pytest.FixtureRequest) -> GridFTPServer:
    return request.getfixturevalue(request.param)  # type: ignore[no-any-return]


# -- namespace -------------------------------------------------------------------


def test_stat_file_and_dir(gctx: Ctx, server: GridFTPServer) -> None:
    write(root_of(server) / "d" / "f", b"hello world\n")
    os.chmod(root_of(server) / "d" / "f", 0o640)
    info = gctx.stat(server.url("/d/f"))
    assert info.st_mode == stat.S_IFREG | 0o640
    assert info.st_size == 12 and info.st_nlink == 1 and info.st_atime == 0
    assert gctx.stat(server.url("/d")).is_dir()
    code, message = code_of(lambda: gctx.stat(server.url("/missing")))
    assert code == errno.ENOENT
    assert message.startswith("globus_ftp_client: the server responded with an error 550 550-")


def test_sessions_are_reused(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "f", b"x")
    for _ in range(3):
        gctx.stat(ftp.url("/f"))
    assert ftp.sessions == 1
    gctx.set_opt_boolean(GROUP, "SESSION_REUSE", False)
    gctx.stat(ftp.url("/f"))  # the pooled session, then closed
    gctx.stat(ftp.url("/f"))
    gctx.stat(ftp.url("/f"))
    assert ftp.sessions == 3


def test_stale_pooled_session_is_replaced(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "f", b"x")
    gctx.stat(ftp.url("/f"))
    ftp.faults["NOOP"] = "close"
    idle = next(iter(plugin_of(gctx)._idle.values()))
    idle[0].send("NOOP")  # the server hangs up on it: no longer healthy
    import time

    time.sleep(0.1)
    gctx.stat(ftp.url("/f"))
    assert ftp.sessions == 2


def test_one_of_several_pooled_sessions_is_taken(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "f", b"0123456789")
    first, second = gctx.open(ftp.url("/f"), "w"), gctx.open(ftp.url("/g"), "w")
    first.close()
    second.close()
    assert len(next(iter(plugin_of(gctx)._idle.values()))) == 2
    gctx.stat(ftp.url("/f"))
    assert ftp.sessions == 2
    assert len(next(iter(plugin_of(gctx)._idle.values()))) == 2  # the other one stays put


def test_url_without_a_path(gctx: Ctx, ftp: GridFTPServer) -> None:
    assert gctx.stat(f"ftp://localhost:{ftp.port}").is_dir()
    assert "MLST /" in ftp.log


def test_stat_without_mlst(gctx: Ctx, tmp_path: Path) -> None:
    features = tuple(f for f in FEATURES if not f.startswith("MLST"))
    root = tmp_path / "old"
    write(root / "f", b"12345")
    (root / "d").mkdir()
    with GridFTPServer(root, features=features) as old:
        assert gctx.stat(old.url("/f")).st_size == 5
        assert gctx.stat(old.url("/d")).is_dir()
        assert code_of(lambda: gctx.stat(old.url("/nope")))[0] == errno.ENOENT
        assert sorted(gctx.listdir(old.url("/"))) == [".", "..", "d", "f"]
        assert [d.d_name for d in gctx.opendir(old.url("/"))] == [".", "..", "d", "f"]


def test_bad_mlst_reply(gctx: Ctx, ftp: GridFTPServer) -> None:
    ftp.faults["MLST"] = "250 no body"
    assert code_of(lambda: gctx.stat(ftp.url("/f")))[0] == errno.EPROTO
    ftp.faults["MLST"] = "250-status\r\n250 End."
    assert code_of(lambda: gctx.stat(ftp.url("/f")))[0] == errno.EPROTO


def test_access(gctx: Ctx, server: GridFTPServer) -> None:
    path = write(root_of(server) / "f", b"x")
    os.chmod(path, 0o400)
    assert gctx.access(server.url("/f"), os.R_OK) == 0
    assert gctx.access(server.url("/f"), os.F_OK) == 0
    assert code_of(lambda: gctx.access(server.url("/f"), os.W_OK))[0] == errno.EACCES
    assert code_of(lambda: gctx.access(server.url("/nope"), os.F_OK))[0] == errno.ENOENT


def test_mkdir_rmdir_unlink_rename_chmod(gctx: Ctx, server: GridFTPServer) -> None:
    root = root_of(server)
    gctx.mkdir(server.url("/d"), 0o755)
    assert (root / "d").is_dir()
    assert code_of(lambda: gctx.mkdir(server.url("/d"), 0o755))[0] == errno.EEXIST
    gctx.mkdir_rec(server.url("/a/b/c"), 0o755)
    assert (root / "a/b/c").is_dir()
    write(root / "d" / "f", b"x")
    assert code_of(lambda: gctx.rmdir(server.url("/d")))[0] == ECOMM  # as gfal2
    gctx.chmod(server.url("/d/f"), 0o600)
    assert stat.S_IMODE((root / "d/f").stat().st_mode) == 0o600
    gctx.rename(server.url("/d/f"), server.url("/d/g"))
    assert (root / "d/g").exists()
    # As gfal2: RNTO's "501 Invalid command arguments" is what gets reported.
    code, message = code_of(lambda: gctx.rename(server.url("/d/f"), server.url("/d/h")))
    assert code == ECOMM and "501 Invalid command arguments." in message
    gctx.unlink(server.url("/d/g"))
    assert code_of(lambda: gctx.unlink(server.url("/d/g")))[0] == errno.ENOENT
    gctx.rmdir(server.url("/d"))
    assert not (root / "d").exists()


def test_listdir_and_opendir(gctx: Ctx, server: GridFTPServer) -> None:
    write(root_of(server) / "d" / "a", b"123")
    (root_of(server) / "d" / "sub").mkdir()
    assert gctx.listdir(server.url("/d")) == [".", "..", "a", "sub"]
    entries = {}
    directory = gctx.opendir(server.url("/d"))
    while True:
        dirent, info = directory.readpp()
        if dirent is None:
            break
        entries[dirent.d_name] = info
    assert entries["a"].st_size == 3 and entries["sub"].is_dir() and entries["."].is_dir()
    assert code_of(lambda: gctx.listdir(server.url("/nope")))[0] == errno.ENOENT
    # gfal2 stats first: a file is EISDIR, "not a directory".
    url = server.url("/d/a")
    assert code_of(lambda: gctx.opendir(url)) == (errno.EISDIR, f"{url} is not a directory")
    assert code_of(lambda: gctx.listdir(url)) == (errno.EISDIR, f"{url} is not a directory")
    os.chmod(root_of(server) / "d" / "sub", 0o300)
    try:
        url = server.url("/d/sub")
        assert code_of(lambda: gctx.listdir(url)) == (errno.EACCES, f"Can not read {url}")
    finally:
        os.chmod(root_of(server) / "d" / "sub", 0o755)


def test_listing_without_modes(gctx: Ctx, ftp: GridFTPServer) -> None:
    """A server that gives no ``UNIX.mode`` is taken at its word that a listing works."""
    (root_of(ftp) / "d").mkdir()
    ftp.faults["MLST"] = "250-status\r\n Type=dir;Size=0; /d\r\n250 End."
    ftp.faults["NLST"] = "500 no"  # stop right after the checks
    assert code_of(lambda: gctx.listdir(ftp.url("/d")))[0] == ECOMM
    assert "NLST /d" in ftp.log


def test_listdir_on_a_lost_session(gctx: Ctx, ftp: GridFTPServer) -> None:
    ftp.faults["NLST"] = "close"
    assert code_of(lambda: gctx.listdir(ftp.url("/")))[0] == errno.ECONNRESET


def test_data_channel_authentication_failure(
    gctx: Ctx, gsi: GridFTPServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    from xgfalclient.plugins.gridftp.data import DataSecurity

    def refuse(self: DataSecurity, sock: object, initiator: bool) -> None:
        raise GError("Data channel authentication failed: nope", errno.EACCES)

    write(root_of(gsi) / "f", b"x")
    gctx.set_opt_boolean(GROUP, "DCAU", True)
    monkeypatch.setattr(DataSecurity, "secure", refuse)
    with gctx.open(gsi.url("/f"), "r") as handle:
        assert code_of(lambda: handle.read_bytes(1))[0] == errno.EACCES


def test_open_refused_after_connecting(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "f", b"x")
    gctx.set_opt_boolean(GROUP, "DELAY_PASSV", False)
    ftp.faults["RETR"] = "451 not today"
    with gctx.open(ftp.url("/f"), "r") as handle:
        assert code_of(lambda: handle.read_bytes(1))[0] == ECOMM


def test_listdir_keeps_the_session_usable_after_failure(gctx: Ctx, ftp: GridFTPServer) -> None:
    ftp.faults["NLST"] = "451 injected"
    assert code_of(lambda: gctx.listdir(ftp.url("/")))[0] == ECOMM
    del ftp.faults["NLST"]
    assert gctx.listdir(ftp.url("/")) == [".", ".."]


def test_checksum(gctx: Ctx, server: GridFTPServer) -> None:
    write(root_of(server) / "f", b"hello world\n")
    assert gctx.checksum(server.url("/f"), "ADLER32") == "1e720467"
    assert gctx.checksum(server.url("/f"), "MD5") == "6f5902ac237024bdd0c176cb93063dc4"
    assert gctx.checksum(server.url("/f"), "md5", 1, 4) == "9ecb0b2f7994a8a3a2919212f764b81a"
    assert code_of(lambda: gctx.checksum(server.url("/f"), "FOO"))[0] == ECOMM
    assert code_of(lambda: gctx.checksum(server.url("/nope"), "MD5"))[0] == errno.ENOENT
    assert server.log[-1] == "CKSM MD5 0 -1 /nope"


def test_checksum_timeout(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "f", b"x")
    gctx.set_opt_integer(GROUP, "CHECKSUM_CALC_TIMEOUT", 1)
    ftp.faults["CKSM"] = "hang"
    assert code_of(lambda: gctx.checksum(ftp.url("/f"), "MD5"))[0] == errno.ETIMEDOUT


def test_checksum_preliminary_replies(gctx: Ctx, ftp: GridFTPServer) -> None:
    ftp.faults["CKSM"] = "raw:113 working\r\n213 abcd"
    assert gctx.checksum(ftp.url("/f"), "MD5") == "abcd"


def test_xattrs(gctx: Ctx, ftp: GridFTPServer) -> None:
    assert gctx.listxattr(ftp.url("/")) == ["spacetoken"]
    usage = json.loads(gctx.getxattr(ftp.url("/"), "spacetoken"))
    assert list(usage) == ["totalsize", "unusedsize", "usedsize"] and usage["totalsize"] > 0
    assert ftp.log[-1] == "SITE USAGE /"
    # gfal2's names: any "spacetoken..." name, the token after a "?".
    ftp.usage = "250 USAGE 10 FREE 5 TOTAL 15"
    text = gctx.getxattr(ftp.url("/d"), "spacetoken.description?T1")
    assert text == '{ "totalsize": 15, "unusedsize": 5, "usedsize": 10 }'
    assert ftp.log[-1] == "SITE USAGE TOKEN T1 /d"
    ftp.usage = "250 USAGE 10 FREE 5 TOTAL -1"  # no total: used + free
    assert json.loads(gctx.getxattr(ftp.url("/"), "spacetoken"))["totalsize"] == 15
    ftp.usage = "250 USAGE -1 FREE 5 TOTAL -1"
    assert json.loads(gctx.getxattr(ftp.url("/"), "spacetoken"))["totalsize"] == -1
    ftp.usage = "250 USAGE 1 FREE -1 TOTAL -1"
    assert json.loads(gctx.getxattr(ftp.url("/"), "spacetoken"))["totalsize"] == -1
    _, message = code_of(lambda: gctx.getxattr(ftp.url("/"), "user.status"))
    assert message == "'user.status' extended attributed not supported by GridFTP plugin"
    for bad in ("250 USAGE lots", "250 USAGE 1 FREE 2 TOTAL x", "250 SPACE 1 FREE 2 TOTAL 3"):
        ftp.usage = bad
        assert code_of(lambda: gctx.getxattr(ftp.url("/"), "spacetoken")) == (
            ECOMM,
            "Invalid SITE USAGE response from server.",
        )
    ftp.usage = "500 Invalid command."
    assert code_of(lambda: gctx.getxattr(ftp.url("/"), "spacetoken?TOK")) == (
        ECOMM,
        "500 Invalid command.   ",
    )


def test_bad_path(gctx: Ctx, ftp: GridFTPServer) -> None:
    assert code_of(lambda: gctx.stat(ftp.url("/a\r\nDELE b")))[0] == errno.EINVAL


# -- logins -------------------------------------------------------------------------


def test_ftp_user_and_password(gctx: Ctx, tmp_path: Path) -> None:
    root = tmp_path / "r"
    write(root / "f", b"x")
    with GridFTPServer(root, users={"bob": "secret"}) as server:
        code, message = code_of(lambda: gctx.stat(server.url("/f")))
        assert code == errno.EACCES and "Login incorrect" in message
        url = f"ftp://bob:secret@localhost:{server.port}/f"
        assert gctx.stat(url).st_size == 1
        gctx.cred_set(server.url("/"), gctx.cred_new("USER", "bob"))
        gctx.cred_set(server.url("/"), gctx.cred_new("PASSWD", "secret"))
        assert gctx.stat(server.url("/f")).st_size == 1


def test_connection_refused(gctx: Ctx) -> None:
    probe = socket.create_server(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    code, message = code_of(lambda: gctx.stat(f"ftp://127.0.0.1:{port}/f"))
    assert code == errno.ECONNREFUSED
    assert message.startswith(f"globus_xio: Unable to connect to 127.0.0.1:{port}")


def test_gsi_login_details(gctx: Ctx, gsi: GridFTPServer) -> None:
    write(root_of(gsi) / "f", b"x")
    gctx.stat(gsi.url("/f"))
    assert gsi.log[:3] == ["AUTH GSSAPI", gsi.log[1], gsi.log[2]]
    assert "USER :globus-mapping:" in gsi.log and "PASS dummy" in gsi.log
    assert "DCAU N" in gsi.log
    assert any(line.startswith("SITE CLIENTINFO scheme=gsiftp;appname=") for line in gsi.log)


def test_client_info_names_the_application(gctx: Ctx, ftp: GridFTPServer) -> None:
    gctx.stat(ftp.url("/"))
    assert 'SITE CLIENTINFO scheme=ftp;appname="gfal2";appver="2.23.5";' in ftp.log
    gctx.set_user_agent("myapp", "1.2")
    gctx.add_client_info("job", "42")
    plugin_of(gctx).close()  # sent once per session: start a new one
    gctx.stat(ftp.url("/"))
    assert 'SITE CLIENTINFO scheme=ftp;appname="myapp";appver="1.2 (gfal2 2.23.5)";job=42' in (
        ftp.log
    )


def test_gsi_without_credentials(
    gctx: Ctx, gsi: GridFTPServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("X509_USER_PROXY")
    assert code_of(lambda: gctx.stat(gsi.url("/f")))[0] == errno.EACCES


def test_gsi_unreadable_credential(gctx: Ctx, gsi: GridFTPServer, tmp_path: Path) -> None:
    bad = write(tmp_path / "bad.pem", b"not a certificate")
    gctx.set_opt_string("X509", "CERT", str(bad))
    gctx.set_opt_string("X509", "KEY", str(bad))
    plugin = plugin_of(gctx)
    code, message = code_of(lambda: plugin._credential(str(bad), str(bad)))
    assert code == errno.EACCES and "Could not load the X.509 credential" in message


def test_gsi_host_name_mismatch(gctx: Ctx, gsi: GridFTPServer) -> None:
    code, message = code_of(lambda: gctx.stat(f"gsiftp://127.0.0.1:{gsi.port}/f"))
    assert code == errno.EACCES and "does not match host 127.0.0.1" in message


def test_gsi_gridmap(gctx: Ctx, grid_env: PKI, tmp_path: Path) -> None:
    with make_gsi(grid_env, tmp_path / "g", gridmap={}) as server:
        assert code_of(lambda: gctx.stat(server.url("/")))[0] == errno.EACCES
    dn = "/DC=org/DC=xgfal/OU=People/CN=Test User"
    with make_gsi(grid_env, tmp_path / "h", gridmap={dn: "tester"}) as server:
        assert gctx.stat(server.url("/")).is_dir()


def test_gsi_without_delegation(gctx: Ctx, gsi: GridFTPServer) -> None:
    gctx.set_opt_boolean(GROUP, "DELEGATION", False)
    write(root_of(gsi) / "f", b"x")
    assert gctx.stat(gsi.url("/f")).st_size == 1
    gctx.set_opt_boolean(GROUP, "DCAU", True)
    _, message = code_of(lambda: gctx.stat(gsi.url("/f")))
    assert "Bad DCAU mode" in message


# -- files ------------------------------------------------------------------------


@needs_peer_chain
@pytest.mark.parametrize("option", ["", "DCAU", "ENCRYPTION"])
def test_read_handles(gctx: Ctx, gsi: GridFTPServer, option: str) -> None:
    if option:
        gctx.set_opt_boolean(GROUP, option, True)
    data = os.urandom(300_000)
    write(root_of(gsi) / "f", data)
    with gctx.open(gsi.url("/f"), "r") as handle:
        assert handle.read_bytes(10) == data[:10]
        assert handle.read_bytes(1000) == data[10:1010]
        handle.lseek(200_000)
        assert handle.read_bytes(1 << 20) == data[200_000:]
        assert handle.read_bytes(10) == b""
        assert handle.pread_bytes(5, 7) == data[5:12]
        assert code_of(lambda: handle.lseek(-3, os.SEEK_END)) == (errno.EINVAL, "Invalid whence")
        assert handle.lseek(-3, os.SEEK_CUR) == len(data) - 3
        assert handle.read_bytes(10) == data[-3:]


def test_read_handle_edges(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "f", b"0123456789")
    (root_of(ftp) / "d").mkdir()
    with gctx.open(ftp.url("/f"), "r") as handle:
        assert handle.pread_bytes(20, 5) == b""
        assert handle.pread_bytes(5, 0) == b""
        assert handle.pread_bytes(8, 100) == b"89"
        handle.read_bytes(3)  # a stream in flight...
    # ...closed by closing the handle: the session was abandoned, not reused.
    code, message = code_of(lambda: gctx.open(ftp.url("/nope"), "r"))
    assert code == errno.ENOENT
    assert message == f" gridftp open error : No such file or directory on url {ftp.url('/nope')}"
    # gfal2 opens a directory, and reads nothing from it.
    with gctx.open(ftp.url("/d"), "r") as handle:
        assert handle.read_bytes(3) == b""
        assert handle.pread_bytes(0, 3) == b""
    ftp.faults["MLST"] = "550 Permission denied"  # not ENOENT: reported as it is
    code, message = code_of(lambda: gctx.open(ftp.url("/f"), "r"))
    assert code == errno.EACCES and message.startswith("globus_ftp_client:")
    del ftp.faults["MLST"]
    # Python's "rw" is O_RDWR|O_CREAT, which gfal2 opens as a (truncating) upload.
    with gctx.open(ftp.url("/f"), "rw") as handle:
        handle.write(b"new")
    assert (root_of(ftp) / "f").read_bytes() == b"new"


def test_read_without_a_stat(gctx: Ctx, ftp: GridFTPServer) -> None:
    """``STAT_ON_OPEN=false`` (the SRM plugin's Castor setting): the stream ends the file."""
    write(root_of(ftp) / "f", b"0123456789")
    gctx.set_opt_boolean(GROUP, "STAT_ON_OPEN", False)
    before = len(ftp.log)
    with gctx.open(ftp.url("/f"), "r") as handle:
        assert not any(line.startswith("MLST") for line in ftp.log[before:])
        assert handle.pread_bytes(8, 100) == b"89"
        assert handle.read_bytes(100) == b"0123456789"
        assert handle.read_bytes(100) == b""
        assert handle.pread_bytes(20, 5) == b""
    with gctx.open(ftp.url("/nope"), "r") as handle:
        assert code_of(lambda: handle.read_bytes(1))[0] == errno.ENOENT


def test_partial_read_write(gctx: Ctx, ftp: GridFTPServer) -> None:
    """``O_RDWR`` alone: gfal2's partial mode, ``ERET`` to read and ``ESTO`` to write."""
    write(root_of(ftp) / "f", b"0123456789")
    handle = plugin_of(gctx).open(ftp.url("/f"), os.O_RDWR)
    assert handle.read(3) == b"012"
    handle.lseek(5)
    assert handle.write(b"ab") == 2
    assert handle.pread(4, 4) == b"4ab7"
    assert code_of(lambda: handle.lseek(0, os.SEEK_END))[0] == errno.EINVAL
    handle.close()
    assert (root_of(ftp) / "f").read_bytes() == b"01234ab789"
    assert "ESTO A 5 /f" in ftp.log and "ERET P 0 3 /f" in ftp.log
    ftp.faults["ESTO"] = "553 Permission denied"
    handle = plugin_of(gctx).open(ftp.url("/f"), os.O_RDWR)
    assert code_of(lambda: handle.pwrite(b"x", 0))[0] == errno.EACCES


def test_read_without_eret(gctx: Ctx, tmp_path: Path) -> None:
    features = tuple(f for f in FEATURES if f != "ERET")
    root = tmp_path / "r"
    write(root / "f", b"0123456789")
    with GridFTPServer(root, features=features) as server:
        with gctx.open(server.url("/f"), "r") as handle:
            assert handle.read_bytes(2) == b"01"
            assert handle.pread_bytes(4, 3) == b"456"
            assert handle.read_bytes(2) == b"23"
        assert "REST 4" in server.log


def test_read_failures(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "f", b"0123456789")
    ftp.after["RETR"] = "426 Transfer aborted"
    with gctx.open(ftp.url("/f"), "r") as handle:
        assert code_of(lambda: handle.read_bytes(100))[0] == ECOMM
    del ftp.after["RETR"]
    ftp.faults["RETR"] = "451 no"
    with gctx.open(ftp.url("/f"), "r") as handle:
        assert code_of(lambda: handle.read_bytes(100))[0] == ECOMM


def test_read_open_needs_a_data_channel(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "f", b"0123456789")
    ftp.faults["RETR"] = "150 Beginning transfer."
    with gctx.open(ftp.url("/f"), "r") as handle:
        assert code_of(lambda: handle.read_bytes(4))[0] == errno.EPROTO


def test_write_handles(gctx: Ctx, server: GridFTPServer) -> None:
    with gctx.open(server.url("/w"), "w") as handle:
        handle.write(b"abc")
        handle.write("def")
    assert (root_of(server) / "w").read_bytes() == b"abcdef"
    plugin = plugin_of(gctx)
    handle = plugin.open(server.url("/x"), os.O_WRONLY | os.O_CREAT, size=3)
    handle.write(b"xyz")
    handle.lseek(3)  # where the stream is: nothing to do
    handle.lseek(1)  # elsewhere: the upload is committed, and ESTO takes over
    assert (root_of(server) / "x").read_bytes() == b"xyz"
    handle.write(b"Y")
    assert handle.pwrite(b"!", 0) == 1
    handle.lseek(10)
    handle.close()
    handle.close()
    assert code_of(lambda: handle.write(b"late"))[0] == errno.EBADF
    assert code_of(lambda: handle.pwrite(b"late", 0))[0] == errno.EBADF
    assert (root_of(server) / "x").read_bytes() == b"!Yz"
    assert "ALLO 3" in server.log and "ESTO A 1 /x" in server.log


def test_write_failures(gctx: Ctx, ftp: GridFTPServer) -> None:
    (root_of(ftp) / "d").mkdir()
    code, message = code_of(lambda: gctx.open(ftp.url("/d/nope/f"), "w"))
    assert code == errno.ENOENT and message.startswith(" gridftp open error :")
    ftp.after["STOR"] = "451 disk full"
    handle = gctx.open(ftp.url("/f"), "w")
    handle.write(b"data")
    assert code_of(handle.close)[0] == ECOMM
    del ftp.after["STOR"]
    ftp.data_faults["STOR"] = "drop"
    handle = gctx.open(ftp.url("/f"), "w")
    code, _ = code_of(lambda: [handle.write(b"x" * 262144) for _ in range(4000)])
    assert code == errno.EIO
    handle.close()  # the server itself was content: 226


def test_write_open_failure_releases_session(gctx: Ctx, ftp: GridFTPServer) -> None:
    ftp.faults["MODE"] = "500 no modes here"
    assert code_of(lambda: gctx.open(ftp.url("/f"), "w"))[0] == ECOMM


def test_write_timeout(gctx: Ctx, ftp: GridFTPServer, monkeypatch: pytest.MonkeyPatch) -> None:
    handle = gctx.open(ftp.url("/w"), "w")

    def stalled(self: DataConn, data: object) -> None:
        raise socket.timeout("timed out")  # no strerror: the exception is the text

    monkeypatch.setattr(DataConn, "sendall", stalled)
    code, message = code_of(lambda: handle.write(b"x"))
    assert code == errno.EIO
    assert message == f"gridftp write error : timed out on url {ftp.url('/w')}"
    monkeypatch.undo()
    handle.close()


def test_immediate_passive_and_ipv6_options(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "f", b"0123456789")
    gctx.set_opt_boolean(GROUP, "DELAY_PASSV", False)
    assert gctx.listdir(ftp.url("/")) == [".", "..", "f"]
    assert "PASV" in ftp.log and "OPTS PASV AllowDelayed=1;" not in ftp.log
    gctx.set_opt_boolean(GROUP, "IPV6", True)
    assert gctx.open(ftp.url("/f"), "r").read_bytes(4) == b"0123"
    assert "EPSV" in ftp.log
    gctx.set_opt_boolean(GROUP, "IPV6", False)
    gctx.set_opt_boolean(GROUP, "SPAS", True)
    assert gctx.open(ftp.url("/f"), "r").read_bytes(4) == b"0123"
    assert "SPAS" in ftp.log


def test_passive_on_a_server_that_cannot_delay_it(gctx: Ctx, tmp_path: Path) -> None:
    features = tuple(f for f in FEATURES if not f.startswith("PASV"))
    root = tmp_path / "r"
    write(root / "f", b"x")
    with GridFTPServer(root, features=features) as server:
        assert gctx.listdir(server.url("/")) == [".", "..", "f"]
        assert "PASV" in server.log
        assert not any(line.startswith("OPTS PASV") for line in server.log)


def test_ipv6_option_in_active_mode(gctx: Ctx, ftp: GridFTPServer, tmp_path: Path) -> None:
    write(root_of(ftp) / "f", b"0123456789")
    gctx.set_opt_boolean(GROUP, "IPV6", True)
    target = tmp_path / "out"
    gctx.filecopy(_params(gctx, 2), ftp.url("/f"), "file://" + str(target))
    assert target.read_bytes() == b"0123456789"
    assert any(line.startswith("EPRT |1|127.0.0.1|") for line in ftp.log)  # over IPv4


def _passive_and_delayed(received: list[bytes]) -> Callable[[socket.socket, Iterator[str]], None]:
    """A server that answers ``PASV`` with an address and then, as if it had delayed
    it, sends a ``127`` before each transfer anyway. Listings have blank lines."""

    def after(sock: socket.socket, commands: Iterator[str]) -> None:
        with socket.create_server(("127.0.0.1", 0)) as listener:
            port = listener.getsockname()[1]
            address = f"127,0,0,1,{port // 256},{port % 256}"
            for line in commands:
                verb = line.split()[0]
                if verb == "PASV":
                    sock.sendall(f"227 Entering Passive Mode ({address})\r\n".encode())
                elif verb == "SIZE":  # no MLST, and "/" is not a file: a directory
                    sock.sendall(b"550 not a plain file.\r\n")
                elif verb in ("NLST", "STOR"):
                    sock.sendall(f"127 Entering Passive Mode ({address})\r\n".encode())
                    sock.sendall(b"150 Opening data connection.\r\n")
                    data, _ = listener.accept()
                    with data:
                        if verb == "NLST":
                            data.sendall(b"a\r\n\r\nb\r\n")
                        else:
                            received.append(data.recv(100))
                    sock.sendall(b"226 Transfer complete.\r\n")
                elif verb == "QUIT":
                    return
                else:
                    sock.sendall(b"200 OK.\r\n")

    return after


def test_passive_address_then_127(gctx: Ctx) -> None:
    """The ``127`` is ignored once there is an address, for listings and streams alike."""
    received: list[bytes] = []
    fake = FakeServer(login_script(_passive_and_delayed(received)))
    assert gctx.listdir(fake.url("/")) == ["a", "b"]
    with gctx.open(fake.url("/f"), "w") as handle:
        handle.write(b"data")
    assert received == [b"data"]
    plugin_of(gctx).close()
    fake.join()


def test_ipv6_control_connection(gctx: Ctx, tmp_path: Path) -> None:
    root = tmp_path / "v6"
    write(root / "f", b"six")
    with GridFTPServer(root, host="::1") as server:
        url = f"ftp://[::1]:{server.port}/f"
        assert gctx.open(url, "r").read_bytes(10) == b"six"
        params = gctx.transfer_parameters()
        params.nbstreams = 2
        target = tmp_path / "back"
        gctx.filecopy(params, url, "file://" + str(target))
        assert target.read_bytes() == b"six"
        assert any(line.startswith("EPRT |2|::1|") for line in server.log)


def test_advertised_unspecified_address(gctx: Ctx, tmp_path: Path) -> None:
    root = tmp_path / "r"
    write(root / "f", b"data")
    with GridFTPServer(root, advertise="0.0.0.0") as server:
        assert gctx.open(server.url("/f"), "r").read_bytes(10) == b"data"
        assert gctx.listdir(server.url("/")) == [".", "..", "f"]


def test_passive_connection_refused(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "f", b"data")
    gctx.set_opt_boolean(GROUP, "DELAY_PASSV", False)
    ftp.faults["PASV"] = "227 Entering Passive Mode (127,0,0,1,0,1)"
    assert code_of(lambda: gctx.open(ftp.url("/f"), "r").read_bytes(4))[0] == errno.ECONNREFUSED
    # The server's own complaint (no listener behind that address) wins.
    assert code_of(lambda: gctx.listdir(ftp.url("/")))[0] == ECOMM


# -- copies -----------------------------------------------------------------------


def _params(gctx: Ctx, streams: int = 0, events: Events | None = None) -> object:
    params = gctx.transfer_parameters()
    params.overwrite = True
    params.nbstreams = streams
    if events is not None:
        params.event_callback = events
    return params


def test_copy_check(gctx: Ctx) -> None:
    plugin = plugin_of(gctx)
    assert plugin.copy_check("gsiftp://a/x", "ftp://b/y")
    assert plugin.copy_check("file:///x", "gsiftp://b/y")
    assert plugin.copy_check("gsiftp://b/y", "file:///x")
    assert not plugin.copy_check("file:///x", "file:///y")
    assert not plugin.copy_check("gsiftp://b/y", "https://h/x")


@needs_peer_chain
@pytest.mark.parametrize("streams", [0, 3])
@pytest.mark.parametrize("option", ["", "DCAU", "ENCRYPTION"])
def test_upload_and_download(
    gctx: Ctx, gsi: GridFTPServer, tmp_path: Path, streams: int, option: str
) -> None:
    if option:
        gctx.set_opt_boolean(GROUP, option, True)
    gctx.set_opt_integer("CORE", "COPY_BUFFERSIZE", 100_000)
    data = os.urandom(1_234_567)
    source = write(tmp_path / "src.bin", data)
    events = Events()
    gctx.filecopy(_params(gctx, streams, events), "file://" + str(source), gsi.url("/up.bin"))
    assert (root_of(gsi) / "up.bin").read_bytes() == data
    assert ("GSIFTP", "TRANSFER:TYPE", "streamed") in events.stages()
    target = tmp_path / "down.bin"
    gctx.filecopy(_params(gctx, streams), gsi.url("/up.bin"), "file://" + str(target))
    assert target.read_bytes() == data
    mode = "E" if streams else "S"
    assert f"MODE {mode}" in gsi.log
    if streams:
        assert f"OPTS RETR Parallelism={streams},{streams},{streams};" in gsi.log
        assert any(line.startswith("PORT ") for line in gsi.log)


def test_rd_nb_stream_option(gctx: Ctx, ftp: GridFTPServer, tmp_path: Path) -> None:
    gctx.set_opt_integer(GROUP, "RD_NB_STREAM", 2)
    source = write(tmp_path / "s", b"x" * 1000)
    gctx.filecopy(_params(gctx), "file://" + str(source), ftp.url("/f"))
    assert "MODE E" in ftp.log


def test_empty_file_copies(gctx: Ctx, ftp: GridFTPServer, tmp_path: Path) -> None:
    source = write(tmp_path / "empty", b"")
    for streams in (0, 2):
        gctx.filecopy(_params(gctx, streams), "file://" + str(source), ftp.url(f"/e{streams}"))
        target = tmp_path / f"back{streams}"
        gctx.filecopy(_params(gctx, streams), ftp.url(f"/e{streams}"), "file://" + str(target))
        assert target.read_bytes() == b""


def test_copy_failures(gctx: Ctx, ftp: GridFTPServer, tmp_path: Path) -> None:
    (root_of(ftp) / "dir").mkdir()
    write(root_of(ftp) / "f", b"0123456789")
    local = tmp_path / "local"
    local.mkdir()
    url = "file://" + str(tmp_path / "out")
    assert code_of(lambda: gctx.filecopy(_params(gctx), ftp.url("/dir"), url))[0] == errno.EISDIR
    assert (
        code_of(lambda: gctx.filecopy(_params(gctx), "file://" + str(local), ftp.url("/x")))[0]
        == errno.EISDIR
    )
    plugin = plugin_of(gctx)
    from xgfalclient.transfer import Transfer

    transfer = Transfer(gctx, gctx.transfer_parameters(), "file:///no/such/file", ftp.url("/x"))
    assert code_of(lambda: plugin.copy(transfer))[0] == errno.ENOENT
    ftp.data_faults["RETR"] = "truncate"
    code, message = code_of(lambda: gctx.filecopy(_params(gctx), ftp.url("/f"), url))
    assert code == errno.EIO and "sizes do not match: 10 != 5" in message
    ftp.faults["STOR"] = "553 Permission denied"
    source = write(tmp_path / "s", b"abc")
    assert (
        code_of(lambda: gctx.filecopy(_params(gctx), "file://" + str(source), ftp.url("/y")))[0]
        == errno.EACCES
    )


def test_mode_e_download_failures(gctx: Ctx, ftp: GridFTPServer, tmp_path: Path) -> None:
    write(root_of(ftp) / "f", os.urandom(100_000))
    url = "file://" + str(tmp_path / "out")
    ftp.data_faults["RETR"] = "drop"
    code, message = code_of(lambda: gctx.filecopy(_params(gctx, 2), ftp.url("/f"), url))
    assert "closed before its EOD" in message or code == ECOMM
    del ftp.data_faults["RETR"]
    ftp.faults["PORT"] = "500 no active mode"
    assert code_of(lambda: gctx.filecopy(_params(gctx, 2), ftp.url("/f"), url))[0] == ECOMM


def test_server_opens_fewer_streams_than_offered(
    gctx: Ctx, ftp: GridFTPServer, tmp_path: Path
) -> None:
    data = os.urandom(300_000)
    write(root_of(ftp) / "f", data)
    ftp.faults["OPTS"] = "200 OPTS Command Successful."  # but it sends on one connection
    target = tmp_path / "out"
    gctx.filecopy(_params(gctx, 3), ftp.url("/f"), "file://" + str(target))
    assert target.read_bytes() == data


def test_upload_source_error_without_errno(
    gctx: Ctx, ftp: GridFTPServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write(tmp_path / "s", b"abc")
    real_open = os.open

    def fake_open(path: str, *args: Any, **kwargs: Any) -> int:
        if path == str(source):
            raise OSError("unreadable")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", fake_open)
    code, message = code_of(
        lambda: gctx.filecopy(_params(gctx), "file://" + str(source), ftp.url("/y"))
    )
    assert code == errno.EIO and "Could not open source" in message


def test_upload_worker_failure_waits_for_the_server(
    gctx: Ctx, ftp: GridFTPServer, tmp_path: Path
) -> None:
    source = write(tmp_path / "s", b"x" * 100)
    gctx.set_opt_boolean(GROUP, "DELAY_PASSV", False)
    ftp.faults["PASV"] = "227 Entering Passive Mode (127,0,0,1,0,1)"
    ftp.faults["STOR"] = "hang"
    code, _ = code_of(lambda: gctx.filecopy(_params(gctx), "file://" + str(source), ftp.url("/y")))
    assert code == errno.ECONNREFUSED


def test_copy_cancel(gctx: Ctx, ftp: GridFTPServer, tmp_path: Path) -> None:
    source = write(tmp_path / "s", b"x" * 100)
    ftp.faults["STOR"] = "hang"
    params = _params(gctx)
    params.timeout = 1  # type: ignore[attr-defined]
    code, _ = code_of(lambda: gctx.filecopy(params, "file://" + str(source), ftp.url("/y")))
    assert code == errno.ETIMEDOUT


@pytest.mark.parametrize("streams", [0, 3])
def test_third_party(
    gctx: Ctx,
    gsi_pair: tuple[GridFTPServer, GridFTPServer],
    streams: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from xgfalclient import transfer

    monkeypatch.setattr(transfer, "MONITOR_INTERVAL", 0.0)
    one, two = gsi_pair
    data = os.urandom(700_000)
    write(root_of(one) / "src", data)
    events = Events()
    progress: list[int] = []
    params = _params(gctx, streams, events)
    params.monitor_callback = lambda *args: progress.append(args[4])  # type: ignore[attr-defined]
    gctx.filecopy(params, one.url("/src"), two.url("/dst"))
    assert (root_of(two) / "dst").read_bytes() == data
    assert ("GSIFTP", "TRANSFER:TYPE", "3rd push") in events.stages()
    assert any(line.startswith("PORT ") for line in one.log)
    assert progress[-1] == len(data)


@needs_peer_chain
def test_third_party_dcau_and_encryption(
    gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]
) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"secret" * 1000)
    for option in ("DCAU", "ENCRYPTION"):
        gctx.set_opt_boolean(GROUP, option, True)
        gctx.filecopy(_params(gctx), one.url("/src"), two.url(f"/{option}"))
        assert (root_of(two) / option).read_bytes() == b"secret" * 1000
    assert "DCAU A" in two.log and "PROT P" in two.log


def test_third_party_address_options(
    gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]
) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    gctx.set_opt_boolean(GROUP, "DELAY_PASSV", False)
    gctx.filecopy(_params(gctx), one.url("/src"), two.url("/a"))
    gctx.set_opt_boolean(GROUP, "SPAS", True)
    gctx.filecopy(_params(gctx), one.url("/src"), two.url("/b"))
    assert any(line.startswith("SPOR ") for line in one.log)
    gctx.set_opt_boolean(GROUP, "SPAS", False)
    gctx.set_opt_boolean(GROUP, "IPV6", True)
    gctx.filecopy(_params(gctx), one.url("/src"), two.url("/c"))
    assert any(line.startswith("EPRT |1|") for line in one.log)
    assert (root_of(two) / "c").read_bytes() == b"abc"


def test_third_party_failures(gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    (root_of(one) / "dir").mkdir()
    code, message = code_of(lambda: gctx.filecopy(_params(gctx), one.url("/nope"), two.url("/x")))
    assert code == errno.ENOENT and message.startswith("TRANSFER  globus_ftp_client:")
    assert "globus_l_gfs_file_open failed" in message  # RETR's complaint, as gfal2 reports
    assert (
        code_of(lambda: gctx.filecopy(_params(gctx), one.url("/dir"), two.url("/x")))[0]
        == errno.EISDIR
    )
    one.faults["RETR"] = "451 source failed"
    assert code_of(lambda: gctx.filecopy(_params(gctx), one.url("/src"), two.url("/x")))[0] == ECOMM
    del one.faults["RETR"]
    two.faults["STOR"] = "553 Permission denied"
    assert (
        code_of(lambda: gctx.filecopy(_params(gctx), one.url("/src"), two.url("/x")))[0]
        == errno.EACCES
    )
    del two.faults["STOR"]
    one.data_faults["RETR"] = "truncate"
    code, message = code_of(lambda: gctx.filecopy(_params(gctx), one.url("/src"), two.url("/x")))
    assert code == errno.EIO and "sizes do not match" in message


def test_third_party_without_a_source_size(
    gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]
) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    one.faults["MLST"] = "550 stat is broken here"
    gctx.filecopy(_params(gctx), one.url("/src"), two.url("/x"))
    assert (root_of(two) / "x").read_bytes() == b"abc"
    assert not any(line.startswith("ALLO") for line in two.log)


def test_third_party_over_ipv6(gctx: Ctx, tmp_path: Path) -> None:
    write(tmp_path / "a" / "src", b"abc")
    (tmp_path / "b").mkdir()
    gctx.set_opt_integer(GROUP, "PERF_MARKER_TIMEOUT", 0)  # no watchdog
    with (
        GridFTPServer(tmp_path / "a", host="::1") as one,
        GridFTPServer(tmp_path / "b", host="::1") as two,
    ):
        source, target = f"ftp://[::1]:{one.port}/src", f"ftp://[::1]:{two.port}/dst"
        gctx.filecopy(_params(gctx), source, target)
        assert (tmp_path / "b" / "dst").read_bytes() == b"abc"
        assert any(line.startswith("EPRT |2|::1|") for line in one.log)
        assert "EPSV" in two.log


def test_rename_reports_rnfr_when_rnto_succeeds(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "f", b"x")
    ftp.faults["RNFR"] = "550 Permission denied"
    ftp.faults["RNTO"] = "250 fine"
    assert code_of(lambda: gctx.rename(ftp.url("/f"), ftp.url("/g")))[0] == errno.EACCES


def test_third_party_marker_timeout(
    gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]
) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    gctx.set_opt_integer(GROUP, "PERF_MARKER_TIMEOUT", 1)
    one.faults["RETR"] = "hang"
    code, message = code_of(lambda: gctx.filecopy(_params(gctx), one.url("/src"), two.url("/x")))
    assert code == errno.ETIMEDOUT and "performance marker timeout of 1 seconds" in message


def test_ftp_login_from_the_ftp_group(gctx: Ctx, tmp_path: Path) -> None:
    """gfal2 reads ``[FTP] USER``/``PASSWORD`` when there is no credential."""
    root = tmp_path / "r"
    write(root / "f", b"x")
    with GridFTPServer(root, users={"bob": "secret"}) as server:
        gctx.set_opt_string("FTP", "USER", "bob")
        gctx.set_opt_string("FTP", "PASSWORD", "secret")
        assert gctx.stat(server.url("/f")).st_size == 1
        gctx.set_opt_string("FTP", "PASSWORD", "wrong")
        assert code_of(lambda: gctx.stat(server.url("/f")))[0] == errno.EACCES


def test_paths_are_decoded_and_keep_their_query(gctx: Ctx, ftp: GridFTPServer) -> None:
    write(root_of(ftp) / "a b.txt", b"12")
    assert gctx.stat(ftp.url("/a%20b%2etxt")).st_size == 2
    assert "MLST /a b.txt" in ftp.log
    assert code_of(lambda: gctx.stat(ftp.url("/a b.txt?x=1")))[0] == errno.ENOENT
    assert "MLST /a b.txt?x=1" in ftp.log
    assert code_of(lambda: gctx.stat(ftp.url("/a%0d%0aDELE%20b")))[0] == errno.EINVAL


def test_access_follows_gfal2(gctx: Ctx, ftp: GridFTPServer) -> None:
    """Any of user, group or other grants a permission; the messages are gfal2's."""
    path = write(root_of(ftp) / "f", b"x")
    os.chmod(path, 0o044)
    assert gctx.access(ftp.url("/f"), os.R_OK) == 0
    os.chmod(path, 0o645)
    assert gctx.access(ftp.url("/f"), os.X_OK) == 0
    os.chmod(path, 0o444)
    assert code_of(lambda: gctx.access(ftp.url("/f"), os.W_OK)) == (errno.EACCES, "No write access")
    assert code_of(lambda: gctx.access(ftp.url("/f"), os.X_OK)) == (
        errno.EACCES,
        "No execute access",
    )
    os.chmod(path, 0o200)
    assert code_of(lambda: gctx.access(ftp.url("/f"), os.R_OK)) == (errno.EACCES, "No read access")
    os.chmod(path, 0o644)
    # A server that keeps modes to itself grants everything, as gfal2 assumes.
    ftp.faults["MLST"] = "250-status\r\n Type=file;Size=1; /f\r\n250 End."
    assert gctx.access(ftp.url("/f"), os.R_OK | os.W_OK | os.X_OK) == 0


def test_checksum_reply_sanity(gctx: Ctx, ftp: GridFTPServer) -> None:
    ftp.faults["CKSM"] = "213 not/a-checksum"
    assert gctx.checksum(ftp.url("/f"), "ADLER32") == "0" * 16


def test_block_size_option(gctx: Ctx, ftp: GridFTPServer, tmp_path: Path) -> None:
    gctx.set_opt_integer(GROUP, "BLOCK_SIZE", 1000)
    assert plugin_of(gctx)._buffer_size() == 1000
    data = os.urandom(10_000)
    source = write(tmp_path / "s", data)
    gctx.filecopy(_params(gctx), "file://" + str(source), ftp.url("/f"))
    assert (root_of(ftp) / "f").read_bytes() == data


def test_upload_and_download_checks(gctx: Ctx, ftp: GridFTPServer, tmp_path: Path) -> None:
    """``file://`` <-> gridftp keeps the core's checks, messages and events."""
    source = write(tmp_path / "s", b"abc")
    write(root_of(ftp) / "f", b"old")
    params = _params(gctx)
    params.overwrite = False  # type: ignore[attr-defined]
    code, _ = code_of(lambda: gctx.filecopy(params, "file://" + str(source), ftp.url("/f")))
    assert code == errno.EEXIST and (root_of(ftp) / "f").read_bytes() == b"old"
    events = Events()
    params = _params(gctx, events=events)
    params.set_checksum(xgfalclient.checksum_mode.both, "ADLER32", "")  # type: ignore[attr-defined]
    gctx.filecopy(params, "file://" + str(source), ftp.url("/f"))
    stages = [stage for _, stage, _ in events.stages()]
    assert stages[3:] == [
        "CHECKSUM:ENTER",
        "CHECKSUM:EXIT",
        "OVERWRITE",
        "TRANSFER:ENTER",
        "TRANSFER:TYPE",
        "TRANSFER:EXIT",
        "CHECKSUM:ENTER",
        "CHECKSUM:EXIT",
    ]
    # A failed upload is removed, once, and narrated.
    events = Events()
    ftp.after["STOR"] = "451 Aborted"
    params = _params(gctx, events=events)
    assert code_of(lambda: gctx.filecopy(params, "file://" + str(source), ftp.url("/g")))[0] == (
        ECOMM
    )
    assert [stage for _, stage, _ in events.stages()].count("CLEANUP") == 1
    assert not (root_of(ftp) / "g").exists()
    # Strict mode checks nothing and removes nothing.
    params = _params(gctx)
    params.strict_copy = True  # type: ignore[attr-defined]
    assert code_of(lambda: gctx.filecopy(params, "file://" + str(source), ftp.url("/h")))[0] == (
        ECOMM
    )
    assert (root_of(ftp) / "h").exists()
    del ftp.after["STOR"]
    gctx.filecopy(params, ftp.url("/f"), "file://" + str(tmp_path / "back"))
    assert (tmp_path / "back").read_bytes() == b"abc"


# -- third-party copies, as gfal2's GridFTPModule::filecopy ------------------------------


def _pair(url: str) -> str:
    port = url.split(":")[2].split("/")[0]
    return f"(127.0.0.1:{port}) {url}"


def test_third_party_events_and_order(
    gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]
) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    write(root_of(two) / "dst", b"old")
    events = Events()
    params = _params(gctx, events=events)
    params.set_checksum(xgfalclient.checksum_mode.both, "ADLER32", "")  # type: ignore[attr-defined]
    source, target = one.url("/src"), two.url("/dst")
    gctx.filecopy(params, source, target)
    assert (root_of(two) / "dst").read_bytes() == b"abc"
    text = f"{_pair(source)} => {_pair(target)}"
    found = [(e.domain, e.stage, e.description, int(e.side)) for e in events.items[3:]]
    assert found == [
        ("GSIFTP", "CHECKSUM:ENTER", "ADLER32", 0),
        ("GSIFTP", "CHECKSUM:EXIT", "ADLER32=024d0127", 0),
        ("GSIFTP", "TRANSFER:ENTER", text, 2),
        ("GSIFTP", "TRANSFER:TYPE", "3rd push", 2),
        ("GSIFTP", "OVERWRITE", f"Deleted {target}", 1),
        ("GSIFTP", "TRANSFER:EXIT", text, 2),
        ("GSIFTP", "CHECKSUM:ENTER", "ADLER32", 1),
        ("GSIFTP", "CHECKSUM:EXIT", "ADLER32", 1),
    ]


def test_third_party_destination_checks(
    gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    write(root_of(two) / "dst", b"old")
    source, target = one.url("/src"), two.url("/dst")
    events = Events()
    params = _params(gctx, events=events)
    params.overwrite = False  # type: ignore[attr-defined]
    params.create_parent = True  # type: ignore[attr-defined]
    assert code_of(lambda: gctx.filecopy(params, source, target)) == (
        errno.EEXIST,
        f"DESTINATION EXISTS  Destination already exist {target}, Cancel",
    )
    assert [stage for _, stage, _ in events.stages()][3:] == ["TRANSFER:ENTER", "TRANSFER:TYPE"]
    assert (root_of(two) / "dst").read_bytes() == b"old"  # refused, not cleaned
    # The parent: created, or refused when it is a file.
    gctx.filecopy(params, source, two.url("/p/q/f"))
    assert (root_of(two) / "p" / "q" / "f").read_bytes() == b"abc"
    gctx.filecopy(params, source, two.url("/p/q/g"))  # the parent is there already
    assert "MKD /p/q" not in two.log[-8:]
    # Beneath a file, the existence check itself fails: a TRANSFER error, as gfal2's.
    code, message = code_of(lambda: gctx.filecopy(params, source, two.url("/dst/f")))
    assert code == errno.ENOTDIR and message.startswith("TRANSFER  globus_ftp_client:")
    # Any other failure to stat the parent is reported as it is.
    plugin = plugin_of(gctx)
    real = plugin.stat

    def stat(url: str) -> Any:
        if url.endswith("/r"):
            raise GError("stat is broken", errno.EIO)
        return real(url)

    monkeypatch.setattr(plugin, "stat", stat)
    assert code_of(lambda: gctx.filecopy(params, source, two.url("/r/f"))) == (
        errno.EIO,
        "TRANSFER  stat is broken",
    )
    # A parent that is a file, where the destination itself is missing.

    def missing(url: str) -> Any:
        if url.endswith("/dst/g"):
            raise GError("No such file", errno.ENOENT)
        return real(url)

    monkeypatch.setattr(plugin, "stat", missing)
    assert code_of(lambda: gctx.filecopy(params, source, two.url("/dst/g"))) == (
        errno.ENOTDIR,
        "DESTINATION  The parent of the destination file exists, but it is not a directory",
    )


def test_third_party_failure_cleanup(
    gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]
) -> None:
    """A failed transfer's destination goes quietly, as in gfal2: no CLEANUP event."""
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    one.after["RETR"] = "451 Aborted"
    events = Events()
    code, message = code_of(
        lambda: gctx.filecopy(_params(gctx, events=events), one.url("/src"), two.url("/x"))
    )
    assert code == ECOMM and message.startswith("TRANSFER  ")
    assert "CLEANUP" not in [stage for _, stage, _ in events.stages()]
    assert "DELE /x" in two.log
    two.faults["DELE"] = "550 Permission denied"  # a failed clean-up changes nothing
    assert code_of(lambda: gctx.filecopy(_params(gctx), one.url("/src"), two.url("/y")))[0] == (
        ECOMM
    )
    # EEXIST is someone else's file: gfal2 leaves it alone.
    del one.after["RETR"], two.faults["DELE"]
    two.faults["STOR"] = "553 File exists"
    before = len(two.log)
    assert code_of(lambda: gctx.filecopy(_params(gctx), one.url("/src"), two.url("/z")))[0] == (
        errno.EEXIST
    )
    assert not any(line.startswith("DELE") for line in two.log[before:])


def test_third_party_checksums(gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    source, target = one.url("/src"), two.url("/dst")
    good = "024d0127"

    def copy(mode: Any, value: str, events: Events | None = None, **extra: Any) -> None:
        params = _params(gctx, events=events)
        params.set_checksum(mode, "ADLER32", value)  # type: ignore[attr-defined]
        for name, setting in extra.items():
            setattr(params, name, setting)
        gctx.filecopy(params, source, target)

    mode = xgfalclient.checksum_mode
    assert code_of(lambda: copy(mode.source, "deadbeef")) == (
        errno.EIO,
        f"TRANSFER CHECKSUM MISMATCH USER_DEFINE and SRC checksums are different. "
        f"deadbeef != {good}",
    )
    copy(mode.source, good.upper())
    events = Events()
    assert code_of(lambda: copy(mode.target, "deadbeef", events)) == (
        errno.EIO,
        f"TRANSFER CHECKSUM MISMATCH USER_DEFINE and DST checksums are different. "
        f"deadbeef != {good}",
    )
    # Deliberately more than gfal2: the bad copy is removed, and that is narrated.
    assert ("GSIFTP", "CLEANUP", "0") in events.stages()
    assert not (root_of(two) / "dst").exists()
    two.faults["CKSM"] = "213 0badf00d"
    assert code_of(lambda: copy(mode.both, "")) == (
        errno.EIO,
        "TRANSFER CHECKSUM MISMATCH SRC and DST checksum are different. "
        f"Source: {good} Destination: 0badf00d",
    )
    two.faults["DELE"] = "550 Permission denied"
    events = Events()
    assert code_of(lambda: copy(mode.both, "", events))[0] == errno.EIO
    assert ("GSIFTP", "CLEANUP", str(errno.EACCES)) in events.stages()
    del two.faults["DELE"]
    events = Events()
    assert code_of(lambda: copy(mode.both, "", events, transfer_cleanup=False))[0] == errno.EIO
    assert "CLEANUP" not in [stage for _, stage, _ in events.stages()]
    copy(mode.both, "", strict_copy=True)  # strict: no checksums at all
    # SKIP_SOURCE_CHECKSUM leaves only the destination's, against the user's value.
    gctx.set_opt_boolean(GROUP, "SKIP_SOURCE_CHECKSUM", True)
    del two.faults["CKSM"]
    events = Events()
    copy(mode.both, good, events)
    sides = [(stage, int(e.side)) for e, (_, stage, _) in zip(events.items, events.stages())]
    assert ("CHECKSUM:ENTER", 0) not in sides and ("CHECKSUM:ENTER", 1) in sides


def test_ftp_third_party_is_stream_mode(gctx: Ctx, tmp_path: Path) -> None:
    """gfal2 copies with ``ftp://`` at either end in MODE S, one stream, no markers."""
    write(tmp_path / "a" / "src", b"abc" * 1000)
    (tmp_path / "b").mkdir()
    gctx.set_opt_integer(GROUP, "PERF_MARKER_TIMEOUT", 1)
    with GridFTPServer(tmp_path / "a") as one, GridFTPServer(tmp_path / "b") as two:
        one.delays["RETR"] = 1.5  # longer than the marker timeout, which is off
        gctx.filecopy(_params(gctx, 3), one.url("/src"), two.url("/dst"))
        assert (tmp_path / "b" / "dst").read_bytes() == b"abc" * 1000
        for server in (one, two):
            assert "MODE S" in server.log and "MODE E" not in server.log
        assert not any(line.startswith("OPTS RETR") for line in one.log)


def test_third_party_streams_and_buffers(
    gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]
) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    params = _params(gctx, 4)
    params.tcp_buffersize = 1048576  # type: ignore[attr-defined]
    gctx.set_opt_integer(GROUP, "RD_NB_STREAM", 2)  # overrides nbstreams, as in gfal2
    gctx.filecopy(params, one.url("/src"), two.url("/dst"))
    assert "OPTS RETR Parallelism=2,2,2;" in one.log
    assert "SITE RETRBUFSIZE 1048576" in one.log and "SITE STORBUFSIZE 1048576" in two.log


def test_pasv_plugin_events(gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    gctx.set_opt_boolean(GROUP, "ENABLE_PASV_PLUGIN", True)
    for option, value in (("DELAY_PASSV", True), ("DELAY_PASSV", False), ("IPV6", True)):
        gctx.set_opt_boolean(GROUP, option, value)
        events = Events()
        gctx.filecopy(_params(gctx, events=events), one.url("/src"), two.url("/dst"))
        found = [
            (e.stage, e.description, int(e.side))
            for e in events.items
            if e.stage in ("PASV", "IPV4", "IPV6")
        ]
        (stage, text, side), (kind, address, _) = found
        assert stage == "PASV" and side == 1 and text.startswith("localhost:")
        assert text == f"localhost:{address}" and kind in ("IPV4", "IPV6")
    gctx.set_opt_boolean(GROUP, "ENABLE_PASV_PLUGIN", False)
    events = Events()
    gctx.filecopy(_params(gctx, events=events), one.url("/src"), two.url("/dst"))
    assert "PASV" not in [stage for _, stage, _ in events.stages()]


def test_udt_is_tried_then_dropped(
    gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]
) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    gctx.set_opt_boolean(GROUP, "ENABLE_UDT", True)
    events = Events()
    gctx.filecopy(_params(gctx, events=events), one.url("/src"), two.url("/dst"))
    stages = [(stage, text) for _, stage, text in events.stages()]
    assert ("UDT:ENABLE", "Trying UDT") in stages
    assert any(
        stage == "UDT:DISABLE" and "udt driver not whitelisted" in text for stage, text in stages
    )
    assert (root_of(two) / "dst").read_bytes() == b"abc"
    one.udt = two.udt = True
    events = Events()
    gctx.filecopy(_params(gctx, events=events), one.url("/src"), two.url("/dst"))
    assert "UDT:DISABLE" not in [stage for _, stage, _ in events.stages()]
    assert "SITE SETNETSTACK udt" in one.log
    one.faults["RETR"] = "451 no"  # any other failure is not retried
    assert code_of(lambda: gctx.filecopy(_params(gctx), one.url("/src"), two.url("/x")))[0] == (
        ECOMM
    )


def test_resolve_dns(
    gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    one, two = gsi_pair
    write(root_of(one) / "src", b"abc")
    gctx.set_opt_boolean("CORE", "RESOLVE_DNS", True)
    names = iter(["localhost", "nowhere.invalid"])

    def reverse(address: str) -> tuple[str, list[str], list[str]]:
        name = next(names)
        if name.endswith(".invalid"):
            raise socket.herror("no name")
        return name, [], [address]

    monkeypatch.setattr(socket, "gethostbyaddr", reverse)
    events = Events()
    gctx.filecopy(_params(gctx, events=events), one.url("/src"), two.url("/dst"))
    enter = next(text for _, stage, text in events.stages() if stage == "TRANSFER:ENTER")
    assert f"localhost:{one.port}/src" in enter and f"localhost:{two.port}/dst" in enter


def test_host_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    from xgfalclient.plugins.gridftp import plugin as module

    assert module.lookup_host("nowhere.invalid", False) == ("cant.be.resolved", False)
    six = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0))
    four = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a: [four, six])
    assert module.lookup_host("h", True) == ("[::1]", True)
    assert module.lookup_host("h", False) == ("10.0.0.1", True)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a: [four])
    assert module.lookup_host("h", True) == ("10.0.0.1", False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a: [six])
    assert module.lookup_host("h", False) == ("cant.be.resolved", True)
    monkeypatch.setattr(socket, "gethostbyaddr", lambda a: ("name", [], [a]))
    resolve = module._resolve_dns
    log = plugin_of.__globals__["xgfalclient"].creat_context().plugin("gsiftp://h/", "stat").log
    assert resolve("gsiftp://u@h:2811/p?q", "x", log) == "gsiftp://u@name:2811/p?q"
    assert resolve("gsiftp://h/p", "x", log) == "gsiftp://name/p"
    assert module._explicit_port(module.parse("gsiftp://[::1]/p")) == 0
    assert module._explicit_port(module.parse("gsiftp://[::1]:5/p")) == 5


def test_gridftp_v2_get_and_put(gctx: Ctx, tmp_path: Path) -> None:
    """With ``GRIDFTP_V2`` and a server offering ``GETPUT``: GET/PUT ...;pasv;."""
    features = (*FEATURES, "GETPUT")
    write(tmp_path / "a" / "src", b"abc")
    (tmp_path / "b").mkdir()
    gctx.set_opt_integer(GROUP, "PERF_MARKER_TIMEOUT", 0)
    with (
        GridFTPServer(tmp_path / "a", features=features) as one,
        GridFTPServer(tmp_path / "b", features=features) as two,
    ):
        gctx.filecopy(_params(gctx), one.url("/src"), two.url("/dst"))
        assert (tmp_path / "b" / "dst").read_bytes() == b"abc"
        assert "PUT file=/dst;pasv;" in two.log
        assert any(line.startswith("GET file=/src;port=") for line in one.log)
        with gctx.open(one.url("/src"), "r") as handle:
            assert handle.read_bytes(10) == b"abc"
        assert "GET file=/src;pasv;" in one.log
        with gctx.open(one.url("/new"), "w") as handle:
            handle.write(b"xyz")
        assert (tmp_path / "a" / "new").read_bytes() == b"xyz"
        target = tmp_path / "down"
        gctx.filecopy(_params(gctx), one.url("/new"), "file://" + str(target))
        assert target.read_bytes() == b"xyz"
        gctx.filecopy(_params(gctx), "file://" + str(target), one.url("/up"))
        assert "PUT file=/up;pasv;" in one.log
        for option, verb in (("SPAS", "SPOR "), ("IPV6", "EPRT ")):  # not with GET/PUT
            gctx.set_opt_boolean(GROUP, option, True)
            gctx.filecopy(_params(gctx), one.url("/src"), two.url(f"/{option}"))
            assert any(line.startswith(verb) for line in one.log)
            gctx.set_opt_boolean(GROUP, option, False)
        gctx.set_opt_boolean(GROUP, "GRIDFTP_V2", False)
        gctx.filecopy(_params(gctx), one.url("/src"), two.url("/dst2"))
        assert "STOR /dst2" in two.log


# -- bulk copies ---------------------------------------------------------------------


def _bulk(
    gctx: Ctx, params: Any, pairs: list[tuple[str, str]], sums: list[str] | None = None
) -> list[GError | None]:
    from xgfalclient.transfer import Transfer

    transfers = [
        Transfer(
            gctx,
            params,
            source,
            target,
            domain="GSIFTP",
            user_checksum=None if sums is None else ("ADLER32", sums[index]),
        )
        for index, (source, target) in enumerate(pairs)
    ]
    return plugin_of(gctx).copy_bulk(params, transfers)


def test_bulk_copy(gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]) -> None:
    one, two = gsi_pair
    write(root_of(one) / "a", b"abc")
    write(root_of(one) / "b", b"defg")
    (root_of(one) / "dir").mkdir()
    write(root_of(two) / "exists", b"old")
    write(root_of(two) / "file", b"f")
    events = Events()
    params = _params(gctx, events=events)
    params.overwrite = False  # type: ignore[attr-defined]
    params.create_parent = True  # type: ignore[attr-defined]
    params.set_checksum(xgfalclient.checksum_mode.both, "ADLER32", "")  # type: ignore[attr-defined]
    pairs = [
        (one.url("/a"), two.url("/p/a")),
        (one.url("/missing"), two.url("/p/m")),
        (one.url("/dir"), two.url("/p/d")),
        (one.url("/b"), two.url("/exists")),
        (one.url("/b"), two.url("/p/b")),
        (one.url("/b"), two.url("/file/b")),
    ]
    results = _bulk(gctx, params, pairs)
    assert results[5] is not None and results[5].code == errno.ENOTDIR
    assert results[0] is None and results[4] is None
    assert (root_of(two) / "p" / "a").read_bytes() == b"abc"
    assert results[1] is not None and results[1].code == errno.ENOENT
    assert results[1].message.startswith("globus_ftp_client:")  # the stat's, no prefix
    assert results[2] is not None and (results[2].code, results[2].message) == (
        errno.EISDIR,
        "File is a directory",
    )
    assert results[3] is not None and (results[3].code, results[3].message) == (
        errno.EEXIST,
        f" Destination already exist {two.url('/exists')}, Cancel",
    )
    stages = [(domain, stage) for domain, stage, _ in events.stages()]
    assert stages[0] == ("GridFTP::Filecopy", "PREPARE:ENTER")
    assert ("GridFTP::Filecopy", "PREPARE:EXIT") in stages
    assert ("GSIFTP", "TRANSFER:TYPE") in stages
    assert stages[-1] == ("GridFTP::Filecopy", "CLOSE:EXIT")
    exits = [text for _, stage, text in events.stages() if stage == "TRANSFER:EXIT"]
    assert exits == [f"Done {pairs[0][0]} => {pairs[0][1]}", f"Done {pairs[4][0]} => {pairs[4][1]}"]


def test_bulk_copy_checks(gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]) -> None:
    one, two = gsi_pair
    write(root_of(one) / "a", b"abc")
    params = _params(gctx)
    params.set_checksum(xgfalclient.checksum_mode.both, "ADLER32", "")  # type: ignore[attr-defined]
    pairs = [(one.url("/a"), two.url("/x"))]
    assert _bulk(gctx, params, pairs, ["024D0127"]) == [None]
    (error,) = _bulk(gctx, params, pairs, ["deadbeef"])
    assert error is not None and error.message == (
        "SOURCE CHECKSUM MISMATCH User checksum and source checksum do not match: "
        "deadbeef != 024d0127"
    )
    two.faults["CKSM"] = "213 0badf00d"
    (error,) = _bulk(gctx, params, pairs)
    assert error is not None and error.message == (
        "DESTINATION CHECKSUM MISMATCH Destination checksum do not match: 024d0127 != 0badf00d"
    )
    del two.faults["CKSM"]
    one.data_faults["RETR"] = "truncate"
    one.faults["MLST"] = "250-status\r\n Type=file;Size=3; /a\r\n250 End."
    params = _params(gctx)
    (error,) = _bulk(gctx, params, [(one.url("/a"), two.url("/y"))])
    assert error is not None and (error.code, error.message) == (
        errno.EIO,
        "DESTINATION SIZE MISMATCH Source and destination file sizes do not match: 3 != 1",
    )
    del one.faults["MLST"], one.data_faults["RETR"]
    one.after["RETR"] = "451 Aborted"
    (error,) = _bulk(gctx, params, [(one.url("/a"), two.url("/z"))])
    assert error is not None and error.code == ECOMM
    del one.after["RETR"]
    params.strict_copy = True  # type: ignore[attr-defined]
    params.set_checksum(xgfalclient.checksum_mode.both, "ADLER32", "")  # type: ignore[attr-defined]
    assert _bulk(gctx, params, pairs) == [None]
    # Mixed pairs are copied one by one, as the core would.
    params = _params(gctx)
    local = root_of(one).parent / "local"
    mixed = [(one.url("/a"), "file://" + str(local)), (one.url("/none"), two.url("/n"))]
    results = _bulk(gctx, params, mixed)
    assert results[0] is None and local.read_bytes() == b"abc"
    assert results[1] is not None and results[1].code == errno.ENOENT
    assert _bulk(gctx, params, [("file://" + str(local), two.url("/up"))]) == [None]
    # A bulk entry with no value: the destination is checksummed, but against nothing.
    params = _params(gctx)
    params.set_checksum(xgfalclient.checksum_mode.target, "ADLER32", "x")  # type: ignore[attr-defined]
    assert _bulk(gctx, params, [(one.url("/a"), two.url("/t"))], [""]) == [None]


def test_bulk_copy_through_the_context(
    gctx: Ctx, gsi_pair: tuple[GridFTPServer, GridFTPServer]
) -> None:
    one, two = gsi_pair
    write(root_of(one) / "a", b"abc")
    events = Events()
    params = _params(gctx, events=events)
    results = gctx.filecopy(
        params, [one.url("/a"), one.url("/missing")], [two.url("/a"), two.url("/b")]
    )
    assert results[0] is None and results[1].code == errno.ENOENT
    assert (root_of(two) / "a").read_bytes() == b"abc"
    assert ("GridFTP::Filecopy", "PREPARE:ENTER", "") in events.stages()
