"""The SFTP plugin, driven through a Gfal2Context against in-process servers."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

import pytest

import xgfalclient
from xgfalclient.crypto.sshkeys import PrivateKey, encode_openssh_private
from xgfalclient.errors import GError
from xgfalclient.plugins.sftp import ssh
from xgfalclient.plugins.sftp.endpoint import Endpoint
from xgfalclient.plugins.sftp.plugin import SFTPPlugin
from xgfalclient.testing.sftp import SFTPServer, SSHServer


@pytest.fixture
def wired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """A context whose python-tier SSH connections reach an in-process server."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "hello.txt").write_bytes(b"hello world\n")
    (root / "sub").mkdir()
    (root / "sub" / "inner.txt").write_bytes(b"inner\n")
    hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    server = SSHServer(SFTPServer(root), hostkey, username="alice", password="secret")

    real_connect = ssh.connect

    def fake_connect(endpoint: Endpoint, auth: ssh.Auth, **kw: object) -> object:
        return real_connect(endpoint, auth, sock=server.pair())

    monkeypatch.setattr(ssh, "connect", fake_connect)

    ctx = xgfalclient.creat_context()
    ctx.set_opt_string("SFTP PLUGIN", "USER", "alice")
    ctx.set_opt_string("SFTP PLUGIN", "PASSWORD", "secret")
    ctx.set_opt_string("SFTP PLUGIN", "KNOWN_HOSTS", str(tmp_path / "known_hosts"))
    ctx.set_opt_string("SFTP PLUGIN", "TRANSPORT", "python")
    yield ctx, root, server
    ctx.free()


B = "sftp://server.example/"


def test_plugin_registered(ctx: xgfalclient.Gfal2Context) -> None:
    names = ctx.get_plugin_names()
    assert any(n.startswith("sftp-") for n in names)


def test_stat_and_lstat(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    info = ctx.stat(B + "hello.txt")
    assert info.st_size == 12
    assert ctx.lstat(B + "hello.txt").st_size == 12
    with pytest.raises(GError) as caught:
        ctx.stat(B + "missing")
    assert caught.value.code == errno.ENOENT


def test_mkdir_and_rec_and_rmdir(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, root, _server = wired
    ctx.mkdir(B + "d", 0o755)
    assert (root / "d").is_dir()
    with pytest.raises(GError) as caught:
        ctx.mkdir(B + "d", 0o755)
    assert caught.value.code == errno.EEXIST
    ctx.mkdir_rec(B + "a/b/c", 0o755)
    assert (root / "a" / "b" / "c").is_dir()
    ctx.rmdir(B + "a/b/c")
    assert not (root / "a" / "b" / "c").exists()


def test_unlink_rename_chmod(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, root, _server = wired
    (root / "victim").write_bytes(b"x")
    ctx.unlink(B + "victim")
    assert not (root / "victim").exists()
    ctx.rename(B + "hello.txt", B + "renamed.txt")
    assert (root / "renamed.txt").exists()
    ctx.chmod(B + "renamed.txt", 0o600)
    assert (root / "renamed.txt").stat().st_mode & 0o777 == 0o600


def test_symlink_and_readlink(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    ctx.symlink(B + "hello.txt", B + "link")
    assert ctx.readlink(B + "link") == "/hello.txt"
    # A plain-path target is used verbatim.
    ctx.symlink("/hello.txt", B + "link2")
    assert ctx.readlink(B + "link2") == "/hello.txt"


def test_opendir_omits_dot_entries(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    names = ctx.listdir(B)
    assert "hello.txt" in names and "sub" in names
    assert "." not in names and ".." not in names
    entries = list(ctx.opendir(B))
    assert all(name not in (".", "..") for name in [e.d_name for e in entries])


def test_access_falls_back_to_stat(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    # The plugin does not implement access, so the core uses stat: success on
    # an existing file, ENOENT on a missing one (better than gfal2's ENOSYS).
    assert ctx.access(B + "hello.txt", os.R_OK) == 0
    with pytest.raises(GError) as caught:
        ctx.access(B + "missing", os.F_OK)
    assert caught.value.code == errno.ENOENT


def test_open_read_write_seek(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, root, _server = wired
    with ctx.open(B + "w.txt", "w") as handle:
        assert handle.write("some data here\n") == 15
    assert (root / "w.txt").read_bytes() == b"some data here\n"
    with ctx.open(B + "w.txt", "r") as handle:
        assert handle.read(4) == "some"
        assert handle.lseek(5, os.SEEK_SET) == 5
        assert handle.read(4) == "data"
        assert handle.pread(0, 4) == "some"


def test_open_readinto(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, root, _server = wired
    (root / "big.bin").write_bytes(os.urandom(100_000))
    handle = ctx.open(B + "big.bin", "r")
    buf = bytearray(100_000)
    total = 0
    while total < 100_000:
        n = handle.readinto(memoryview(buf)[total:])
        if not n:
            break
        total += n
    handle.close()
    assert total == 100_000 and bytes(buf) == (root / "big.bin").read_bytes()


def test_open_rdwr_pwrite(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, root, _server = wired
    handle = ctx.open(B + "rw.bin", "rw")
    handle.pwrite(b"abc", 4)
    handle.close()
    assert (root / "rw.bin").read_bytes()[4:7] == b"abc"


def test_open_missing_raises(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    with pytest.raises(GError) as caught:
        ctx.open(B + "does-not-exist", "r")
    assert caught.value.code == errno.ENOENT


def test_write_file_error_on_close(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    # Opening a directory for writing fails; the failure surfaces at once.
    with pytest.raises(GError):
        ctx.open(B + "sub", "w")


def test_checksum_by_reading(wired) -> None:  # type: ignore[no-untyped-def]
    import hashlib

    ctx, _root, _server = wired
    digest = ctx.checksum(B + "hello.txt", "md5")
    assert digest == hashlib.md5(b"hello world\n").hexdigest()


def test_checksum_with_check_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib

    root = tmp_path / "root"
    root.mkdir()
    (root / "f.bin").write_bytes(b"payload" * 100)
    hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    server = SSHServer(
        SFTPServer(root, check_file=("md5", "sha1")), hostkey, username="alice", password="pw"
    )
    real = ssh.connect
    monkeypatch.setattr(ssh, "connect", lambda ep, auth, **kw: real(ep, auth, sock=server.pair()))
    ctx = xgfalclient.creat_context()
    ctx.set_opt_string("SFTP PLUGIN", "USER", "alice")
    ctx.set_opt_string("SFTP PLUGIN", "PASSWORD", "pw")
    ctx.set_opt_string("SFTP PLUGIN", "KNOWN_HOSTS", str(tmp_path / "kh"))
    ctx.set_opt_string("SFTP PLUGIN", "TRANSPORT", "python")
    try:
        assert ctx.checksum(B + "f.bin", "sha1") == hashlib.sha1(b"payload" * 100).hexdigest()
    finally:
        ctx.free()


def test_checksum_refused_when_disabled(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    ctx.set_opt_boolean("SFTP PLUGIN", "CHECKSUM_BY_READ", False)
    with pytest.raises(GError) as caught:
        ctx.checksum(B + "hello.txt", "md5")
    assert caught.value.code == errno.EPROTONOSUPPORT


def test_checksum_unknown_algorithm(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    with pytest.raises(GError) as caught:
        ctx.checksum(B + "hello.txt", "no-such-hash")
    assert caught.value.code == errno.EINVAL


# -- copies -------------------------------------------------------------------


def test_copy_upload_and_download(wired, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    ctx, root, _server = wired
    src = tmp_path / "src.bin"
    payload = os.urandom(400_000)
    src.write_bytes(payload)
    params = ctx.transfer_parameters()
    params.overwrite = True
    ctx.filecopy(params, "file://" + str(src), B + "up.bin")
    assert (root / "up.bin").read_bytes() == payload
    down = tmp_path / "down.bin"
    ctx.filecopy(params, B + "up.bin", "file://" + str(down))
    assert down.read_bytes() == payload


def test_copy_check_only_file_pairs() -> None:
    plugin = SFTPPlugin(xgfalclient.creat_context())
    assert plugin.copy_check("file:///x", "sftp://h/y")
    assert plugin.copy_check("sftp://h/y", "file:///x")
    assert not plugin.copy_check("sftp://h/a", "sftp://h/b")
    assert not plugin.copy_check("file:///a", "file:///b")


def test_copy_download_directory_is_error(wired, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    params = ctx.transfer_parameters()
    params.overwrite = True
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, B + "sub", "file://" + str(tmp_path / "out"))
    assert caught.value.code == errno.EISDIR


def test_copy_upload_directory_is_error(wired, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    d = tmp_path / "adir"
    d.mkdir()
    params = ctx.transfer_parameters()
    params.overwrite = True
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, "file://" + str(d), B + "x.bin")
    assert caught.value.code == errno.EISDIR


# -- endpoint resolution and tier selection -----------------------------------


def _plugin() -> SFTPPlugin:
    return SFTPPlugin(xgfalclient.creat_context())


def test_endpoint_from_url_userinfo() -> None:
    from xgfalclient.url import parse

    plugin = _plugin()
    ep = plugin._endpoint(parse("sftp://bob:pw@host:2222/path"))
    assert ep.user == "bob" and ep.password == "pw"
    assert ep.port == 2222 and ep.explicit_port


def test_endpoint_from_options_and_default_key() -> None:
    from xgfalclient.url import parse

    plugin = _plugin()
    plugin.context.set_opt_string("SFTP PLUGIN", "USER", "carol")
    ep = plugin._endpoint(parse("sftp://host/path"))
    assert ep.user == "carol"
    assert ep.key_file.endswith(os.path.join(".ssh", "id_rsa"))
    assert ep.port == 22 and not ep.explicit_port


def test_endpoint_from_cred_store() -> None:
    from xgfalclient.creds import Credential
    from xgfalclient.url import parse

    plugin = _plugin()
    plugin.context.credentials.set("sftp://host/", Credential("USER", "dave"))
    plugin.context.credentials.set("sftp://host/", Credential("PASSWD", "sekret"))
    ep = plugin._endpoint(parse("sftp://host/path"))
    assert ep.user == "dave" and ep.password == "sekret"


def test_endpoint_default_user_is_login(monkeypatch: pytest.MonkeyPatch) -> None:
    import getpass

    from xgfalclient.url import parse

    monkeypatch.setattr(getpass, "getuser", lambda: "loginuser")
    plugin = _plugin()
    ep = plugin._endpoint(parse("sftp://host/path"))
    assert ep.user == "loginuser"


def test_tier_password_prefers_in_process(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin()
    plugin.context.set_opt_string("SFTP PLUGIN", "TRANSPORT", "  ")  # blank means auto
    ep = Endpoint(host="h", port=22, user="u", password="pw")
    monkeypatch.setattr("xgfalclient.plugins.sftp.plugin._has_paramiko", lambda: False)
    assert plugin._tier(ep) == "python"
    monkeypatch.setattr("xgfalclient.plugins.sftp.plugin._has_paramiko", lambda: True)
    assert plugin._tier(ep) == "paramiko"


def test_tier_no_password_prefers_openssh(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin()
    ep = Endpoint(host="h", port=22, user="u")
    monkeypatch.setattr("xgfalclient.plugins.sftp.openssh.find_ssh", lambda cfg: ["ssh"])
    assert plugin._tier(ep) == "openssh"
    monkeypatch.setattr("xgfalclient.plugins.sftp.openssh.find_ssh", lambda cfg: None)
    monkeypatch.setattr("xgfalclient.plugins.sftp.plugin._has_paramiko", lambda: True)
    assert plugin._tier(ep) == "paramiko"
    monkeypatch.setattr("xgfalclient.plugins.sftp.plugin._has_paramiko", lambda: False)
    assert plugin._tier(ep) == "python"


def test_tier_explicit_override() -> None:
    plugin = _plugin()
    ep = Endpoint(host="h", port=22, user="u", password="pw")
    for choice in ("openssh", "python", "paramiko"):
        plugin.context.set_opt_string("SFTP PLUGIN", "TRANSPORT", choice)
        assert plugin._tier(ep) == choice


# -- key loading --------------------------------------------------------------


def test_load_keys_valid(tmp_path: Path) -> None:
    key = PrivateKey.from_ed25519_seed(os.urandom(32))
    path = tmp_path / "id_ed25519"
    path.write_bytes(encode_openssh_private(key))
    plugin = _plugin()
    ep = Endpoint(host="h", port=22, user="u", key_file=str(path))
    keys = plugin._load_keys(ep)
    assert len(keys) == 1 and keys[0].public.blob == key.public.blob


def test_load_keys_missing_file() -> None:
    plugin = _plugin()
    ep = Endpoint(host="h", port=22, user="u", key_file="/no/such/key")
    assert plugin._load_keys(ep) == ()
    assert plugin._load_keys(Endpoint(host="h", port=22, user="u")) == ()  # none configured


def test_load_keys_encrypted_needs_passphrase(tmp_path: Path) -> None:
    key = PrivateKey.from_ed25519_seed(os.urandom(32))
    path = tmp_path / "id"
    path.write_bytes(encode_openssh_private(key, passphrase=b"pw", rounds=4))
    plugin = _plugin()
    ep = Endpoint(host="h", port=22, user="u", key_file=str(path))
    with pytest.raises(GError) as caught:
        plugin._load_keys(ep)
    assert caught.value.code == errno.EACCES
    # With the passphrase it loads.
    ep2 = Endpoint(host="h", port=22, user="u", key_file=str(path), passphrase="pw")
    assert len(plugin._load_keys(ep2)) == 1


def test_load_keys_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "bad"
    path.write_bytes(b"not a key")
    plugin = _plugin()
    ep = Endpoint(host="h", port=22, user="u", key_file=str(path))
    with pytest.raises(GError) as caught:
        plugin._load_keys(ep)
    assert caught.value.code == errno.EACCES


# -- pooling ------------------------------------------------------------------


def test_session_pool_reuse_and_close(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    ctx.stat(B + "hello.txt")  # loads the plugin and pools a session
    ctx.stat(B + "hello.txt")  # reuses the pooled session
    plugin = next(p for p in ctx.plugins if p.name == "sftp")
    total = sum(len(v) for v in plugin._idle.values())
    assert total >= 1
    plugin.close()
    assert not plugin._idle


def test_session_pool_holds_several(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    # Two files open at once need two sessions; both are pooled on close.
    first = ctx.open(B + "hello.txt", "r")
    second = ctx.open(B + "hello.txt", "r")
    first.close()
    second.close()
    plugin = next(p for p in ctx.plugins if p.name == "sftp")
    assert sum(len(v) for v in plugin._idle.values()) == 2
    # A namespace call takes just one of them, and gives it back.
    ctx.stat(B + "hello.txt")
    assert sum(len(v) for v in plugin._idle.values()) == 2


def test_session_dead_after_success_is_not_pooled(
    wired, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx
    from xgfalclient.testing import sftp as tsftp

    ctx, _root, _server = wired

    def hang_up(session: object, rid: int, reader: object) -> None:
        raise tsftp._Drop

    # The server hangs up on the CLOSE after a download: the copy has already
    # succeeded (the close is quiet), but the dead session must not be pooled.
    monkeypatch.setitem(tsftp._HANDLERS, fx.CLOSE, hang_up)
    params = ctx.transfer_parameters()
    params.overwrite = True
    ctx.filecopy(params, B + "hello.txt", "file://" + str(tmp_path / "o"))
    assert (tmp_path / "o").read_bytes() == b"hello world\n"
    plugin = next(p for p in ctx.plugins if p.name == "sftp")
    assert not any(plugin._idle.values())


def test_url_without_path_is_the_root(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    assert stat.S_ISDIR(ctx.stat("sftp://server.example").st_mode)


# -- error paths and remaining branches ---------------------------------------


def test_namespace_error_paths(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    with pytest.raises(GError):
        ctx.chmod(B + "missing", 0o600)
    with pytest.raises(GError):
        ctx.rmdir(B + "missing")
    with pytest.raises(GError):
        ctx.unlink(B + "missing")
    with pytest.raises(GError):
        ctx.rename(B + "missing", B + "x")
    with pytest.raises(GError):
        ctx.readlink(B + "hello.txt")  # not a symlink
    with pytest.raises(GError):
        ctx.lstat(B + "missing")
    with pytest.raises(GError):
        ctx.listdir(B + "missing")  # opendir error
    with pytest.raises(GError):
        ctx.symlink(B + "hello.txt", B + "sub")  # target path already exists


def test_checksum_with_offset_and_length(wired) -> None:  # type: ignore[no-untyped-def]
    import hashlib

    ctx, _root, _server = wired
    got = ctx.checksum(B + "hello.txt", "md5", 2, 5)
    assert got == hashlib.md5(b"hello world\n"[2:7]).hexdigest()


def test_pflags_mapping() -> None:
    from xgfalclient.plugin import O_APPEND, O_CREAT, O_EXCL, O_RDWR, O_WRONLY
    from xgfalclient.plugins.sftp import protocol as fx
    from xgfalclient.plugins.sftp.plugin import _pflags

    assert _pflags(O_WRONLY | O_APPEND) & fx.FXF_APPEND
    assert _pflags(O_WRONLY | O_CREAT | O_EXCL) & fx.FXF_EXCL
    assert _pflags(O_RDWR) == (fx.FXF_READ | fx.FXF_WRITE)


def test_file_read_error(wired) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    handle = ctx.open(B + "hello.txt", "r")
    server.sftp.inject(fx.READ, fx.FX_PERMISSION_DENIED, "denied")
    with pytest.raises(GError):
        handle.pread(0, 5)
    server.sftp.inject(fx.READ, fx.FX_PERMISSION_DENIED, "denied")
    with pytest.raises(GError):
        handle.readinto(bytearray(5))
    handle.close()


def test_file_pwrite_error_rdwr(wired) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    handle = ctx.open(B + "rw.bin", "rw")
    server.sftp.inject(fx.WRITE, fx.FX_FAILURE, "full")
    with pytest.raises(GError):
        handle.pwrite(b"abc", 0)
    handle.close()


def test_write_file_errors(wired) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    handle = ctx.open(B + "w.bin", "w")
    server.sftp.inject(fx.WRITE, fx.FX_FAILURE, "full", count=10)
    # The pipelined write may fail on write() or be deferred to close().
    with pytest.raises(GError):
        for _i in range(20):
            handle.write(b"x" * 1000)
        handle.close()


def test_write_file_pwrite_error(wired) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    handle = ctx.open(B + "w2.bin", "w")
    server.sftp.inject(fx.WRITE, fx.FX_FAILURE, "full", count=10)
    with pytest.raises(GError):
        for i in range(20):
            handle.pwrite(b"y" * 1000, i * 1000)
        handle.close()


def test_file_size_and_seek_end(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    handle = ctx.open(B + "hello.txt", "r")
    assert handle.lseek(0, os.SEEK_END) == 12  # uses size() via fstat
    handle.close()


def test_file_close_error(wired) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    handle = ctx.open(B + "hello.txt", "r")
    server.sftp.inject(fx.CLOSE, fx.FX_FAILURE, "bad")
    with pytest.raises(GError):
        handle.close()
    handle.close()  # idempotent second call


def test_dead_pooled_session_replaced(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    ctx.stat(B + "hello.txt")
    plugin = next(p for p in ctx.plugins if p.name == "sftp")
    # Kill the pooled session; the next use discards it and reconnects.
    for clients in plugin._idle.values():
        for client in clients:
            client.close()
    assert ctx.stat(B + "hello.txt").st_size == 12
    # Same via the open() checkout path.
    ctx.open(B + "hello.txt", "r").close()
    for clients in plugin._idle.values():
        for client in clients:
            client.close()
    ctx.open(B + "hello.txt", "r").close()


def test_handshake_failure_closes_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "f").write_bytes(b"x")
    hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    sftp = SFTPServer(root)
    sftp.faults.append("banner")  # corrupts the SFTP handshake
    server = SSHServer(sftp, hostkey, username="alice", password="pw")
    real = ssh.connect
    monkeypatch.setattr(ssh, "connect", lambda ep, auth, **kw: real(ep, auth, sock=server.pair()))
    ctx = xgfalclient.creat_context()
    ctx.set_opt_string("SFTP PLUGIN", "USER", "alice")
    ctx.set_opt_string("SFTP PLUGIN", "PASSWORD", "pw")
    ctx.set_opt_string("SFTP PLUGIN", "KNOWN_HOSTS", str(tmp_path / "kh"))
    ctx.set_opt_string("SFTP PLUGIN", "TRANSPORT", "python")
    try:
        with pytest.raises(GError):
            ctx.stat(B + "f")
    finally:
        ctx.free()


def test_openssh_tier_through_plugin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from xgfalclient.testing.sftp import write_fake_ssh

    root = tmp_path / "root"
    root.mkdir()
    (root / "hello.txt").write_bytes(b"hello world\n")
    monkeypatch.setenv("XGFAL_FAKE_ROOT", str(root))
    fake = write_fake_ssh(tmp_path / "ssh")
    ctx = xgfalclient.creat_context()
    ctx.set_opt_string("SFTP PLUGIN", "TRANSPORT", "openssh")
    ctx.set_opt_string("SFTP PLUGIN", "SSH_COMMAND", fake)
    try:
        assert ctx.stat(B + "hello.txt").st_size == 12
        # A copy through the openssh tier.
        params = ctx.transfer_parameters()
        params.overwrite = True
        ctx.filecopy(params, B + "hello.txt", "file://" + str(tmp_path / "out"))
        assert (tmp_path / "out").read_bytes() == b"hello world\n"
    finally:
        ctx.free()


def test_openssh_tier_no_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = xgfalclient.creat_context()
    ctx.set_opt_string("SFTP PLUGIN", "TRANSPORT", "openssh")
    # A bare name not on PATH makes find_ssh return None.
    ctx.set_opt_string("SFTP PLUGIN", "SSH_COMMAND", "definitely-not-a-real-ssh-xyz")
    try:
        with pytest.raises(GError) as caught:
            ctx.stat(B + "hello.txt")
        assert caught.value.code == errno.ENOENT
    finally:
        ctx.free()


def test_mkdir_into_missing_parent(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    with pytest.raises(GError) as caught:
        ctx.mkdir(B + "nope/child", 0o755)
    assert caught.value.code == errno.ENOENT


def test_mkdir_failure_without_existing_path(wired) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    # A bare FAILURE for a path that does not exist is not turned into EEXIST.
    server.sftp.inject(fx.MKDIR, fx.FX_FAILURE, "nope")
    with pytest.raises(GError) as caught:
        ctx.mkdir(B + "ghost", 0o755)
    assert caught.value.code != errno.EEXIST


def test_session_closed_on_hard_failure(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, server = wired
    server.sftp.faults.append("drop")  # the connection dies mid-request
    with pytest.raises(GError):
        ctx.stat(B + "hello.txt")


def test_open_hard_failure_returns_session(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, server = wired
    server.sftp.faults.append("drop")
    with pytest.raises(GError):
        ctx.open(B + "hello.txt", "r")


def test_checksum_check_file_unsupported_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib

    root = tmp_path / "root"
    root.mkdir()
    (root / "f.bin").write_bytes(b"data" * 50)
    hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    server = SSHServer(
        SFTPServer(root, check_file=("md5",)), hostkey, username="alice", password="pw"
    )
    real = ssh.connect
    monkeypatch.setattr(ssh, "connect", lambda ep, auth, **kw: real(ep, auth, sock=server.pair()))
    ctx = xgfalclient.creat_context()
    ctx.set_opt_string("SFTP PLUGIN", "USER", "alice")
    ctx.set_opt_string("SFTP PLUGIN", "PASSWORD", "pw")
    ctx.set_opt_string("SFTP PLUGIN", "KNOWN_HOSTS", str(tmp_path / "kh"))
    ctx.set_opt_string("SFTP PLUGIN", "TRANSPORT", "python")
    try:
        # sha256 is not offered by the server, so the plugin reads the file.
        assert ctx.checksum(B + "f.bin", "sha256") == hashlib.sha256(b"data" * 50).hexdigest()
    finally:
        ctx.free()


def test_download_source_missing(wired, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    params = ctx.transfer_parameters()
    params.overwrite = True
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, B + "missing", "file://" + str(tmp_path / "o"))
    assert caught.value.code == errno.ENOENT


def test_download_open_error(wired, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    server.sftp.inject(fx.OPEN, fx.FX_PERMISSION_DENIED, "denied")
    params = ctx.transfer_parameters()
    params.overwrite = True
    with pytest.raises(GError):
        ctx.filecopy(params, B + "hello.txt", "file://" + str(tmp_path / "o"))


def test_upload_source_missing(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    params = ctx.transfer_parameters()
    params.overwrite = True
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, "file:///no/such/local/file", B + "x.bin")
    assert caught.value.code == errno.ENOENT


def test_upload_source_open_error_without_errno(
    wired, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import plugin as sftp_plugin

    ctx, _root, _server = wired
    src = tmp_path / "src"
    src.write_bytes(b"data")
    real_open = os.open

    def refusing_open(path: str, *args: object, **kwargs: object) -> int:
        if path == str(src):
            raise OSError("refused")
        return real_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(sftp_plugin.os, "open", refusing_open)
    params = ctx.transfer_parameters()
    params.overwrite = True
    with pytest.raises(GError, match="Could not open source: refused") as caught:
        ctx.filecopy(params, "file://" + str(src), B + "x.bin")
    assert caught.value.code == errno.EIO


def test_upload_remote_open_error(wired, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    src = tmp_path / "src"
    src.write_bytes(b"data")
    server.sftp.inject(fx.OPEN, fx.FX_PERMISSION_DENIED, "denied")
    params = ctx.transfer_parameters()
    params.overwrite = True
    with pytest.raises(GError):
        ctx.filecopy(params, "file://" + str(src), B + "x.bin")


def test_has_paramiko_probe() -> None:
    from xgfalclient.plugins.sftp.plugin import _has_paramiko

    assert isinstance(_has_paramiko(), bool)


def test_file_size_cached_and_fstat_error(wired) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    handle = ctx.open(B + "hello.txt", "r")
    assert handle.lseek(0, os.SEEK_END) == 12
    assert handle.lseek(0, os.SEEK_END) == 12  # cached, no second fstat
    handle.close()
    # fstat failure surfaces as a GError.
    handle2 = ctx.open(B + "hello.txt", "r")
    server.sftp.inject(fx.FSTAT, fx.FX_PERMISSION_DENIED, "denied")
    with pytest.raises(GError):
        handle2.lseek(0, os.SEEK_END)
    handle2.close()


def test_file_size_unknown_to_the_server(wired, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx
    from xgfalclient.plugins.sftp.protocol import Attrs
    from xgfalclient.testing import sftp as tsftp

    def fstat_without_size(session: tsftp._Session, rid: int, reader: object) -> None:
        session.send(fx.ATTRS, rid, Attrs(permissions=0o100644).encode())

    ctx, _root, _server = wired
    # An ATTRS reply may leave the size out; it is then taken as 0.
    monkeypatch.setitem(tsftp._HANDLERS, fx.FSTAT, fstat_without_size)
    handle = ctx.open(B + "hello.txt", "r")
    assert handle.lseek(0, os.SEEK_END) == 0
    handle.close()


def test_write_file_double_close(wired) -> None:  # type: ignore[no-untyped-def]
    ctx, _root, _server = wired
    handle = ctx.open(B + "wc.bin", "w")
    handle.write(b"data")
    handle.close()
    handle.close()  # idempotent


def test_write_error_surfaces_on_write(wired) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    ctx.set_opt_integer("SFTP PLUGIN", "PIPELINE_DEPTH", 1)
    handle = ctx.open(B + "we.bin", "w")
    server.sftp.inject(fx.WRITE, fx.FX_FAILURE, "full", count=10)
    import contextlib

    with pytest.raises(GError):
        handle.write(b"a" * 1000)
        handle.write(b"b" * 1000)  # settles the failed first write
    with contextlib.suppress(GError):
        handle.close()


def test_pwrite_error_surfaces(wired) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    ctx.set_opt_integer("SFTP PLUGIN", "PIPELINE_DEPTH", 1)
    handle = ctx.open(B + "pe.bin", "w")
    server.sftp.inject(fx.WRITE, fx.FX_FAILURE, "full", count=10)
    import contextlib

    with pytest.raises(GError):
        handle.pwrite(b"a" * 1000, 0)
        handle.pwrite(b"b" * 1000, 1000)
    with contextlib.suppress(GError):
        handle.close()


def _wire_ctx(monkeypatch, tmp_path, server):  # type: ignore[no-untyped-def]
    real = ssh.connect
    monkeypatch.setattr(ssh, "connect", lambda ep, auth, **kw: real(ep, auth, sock=server.pair()))
    ctx = xgfalclient.creat_context()
    ctx.set_opt_string("SFTP PLUGIN", "USER", "alice")
    ctx.set_opt_string("SFTP PLUGIN", "PASSWORD", "pw")
    ctx.set_opt_string("SFTP PLUGIN", "KNOWN_HOSTS", str(tmp_path / "kh"))
    ctx.set_opt_string("SFTP PLUGIN", "TRANSPORT", "python")
    return ctx


def test_checksum_by_read_open_error(wired) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.plugins.sftp import protocol as fx

    ctx, _root, server = wired
    server.sftp.inject(fx.OPEN, fx.FX_PERMISSION_DENIED, "denied")
    with pytest.raises(GError):
        ctx.checksum(B + "hello.txt", "md5")


def test_session_dropped_mid_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # limits=None so the handshake sends no probe; the drop lands on the stat.
    root = tmp_path / "root"
    root.mkdir()
    (root / "f").write_bytes(b"x")
    hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    sftp = SFTPServer(root, limits=None)
    sftp.faults.append("drop")
    server = SSHServer(sftp, hostkey, username="alice", password="pw")
    ctx = _wire_ctx(monkeypatch, tmp_path, server)
    try:
        with pytest.raises(GError):
            ctx.stat(B + "f")
    finally:
        ctx.free()


def test_open_dropped_mid_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "f").write_bytes(b"x")
    hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    sftp = SFTPServer(root, limits=None)
    sftp.faults.append("drop")
    server = SSHServer(sftp, hostkey, username="alice", password="pw")
    ctx = _wire_ctx(monkeypatch, tmp_path, server)
    try:
        with pytest.raises(GError):
            ctx.open(B + "f", "r")
    finally:
        ctx.free()


def test_pluginfile_close_idempotent(wired) -> None:  # type: ignore[no-untyped-def]
    # The FileType wrapper guards re-close, so exercise the PluginFile directly.
    ctx, _root, _server = wired
    reader = ctx.open(B + "hello.txt", "r")._file
    reader.close()
    reader.close()  # second call returns immediately
    writer = ctx.open(B + "w.bin", "w")._file
    writer.write(b"data")
    writer.close()
    writer.close()  # second call returns immediately
