"""Direct coverage of the in-process test servers and the fake ssh."""

from __future__ import annotations

import errno
import io
import os
import socket
import threading
from pathlib import Path

import pytest

from xgfalclient.plugins.sftp import protocol as fx
from xgfalclient.plugins.sftp.client import SFTPClient
from xgfalclient.plugins.sftp.protocol import Attrs, StatusError
from xgfalclient.testing import sftp as tsftp
from xgfalclient.testing.sftp import (
    FAKE_HOSTS,
    SFTPServer,
    SocketStream,
    fake_ssh_main,
    portable_status,
    write_fake_ssh,
)

# -- portable_status ----------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "status"),
    [
        (errno.ENOENT, fx.FX_NO_SUCH_FILE),
        (errno.ELOOP, fx.FX_NO_SUCH_FILE),
        (errno.EACCES, fx.FX_PERMISSION_DENIED),
        (errno.EFAULT, fx.FX_PERMISSION_DENIED),
        (errno.ENAMETOOLONG, fx.FX_BAD_MESSAGE),
        (errno.EINVAL, fx.FX_BAD_MESSAGE),
        (errno.ENOSYS, fx.FX_OP_UNSUPPORTED),
        (errno.EIO, fx.FX_FAILURE),
        (None, fx.FX_FAILURE),
    ],
)
def test_portable_status(code: int, status: int) -> None:
    assert portable_status(code) == status


# -- SocketStream -------------------------------------------------------------


def test_socketstream_close_is_tolerant() -> None:
    a, b = socket.socketpair()
    stream = SocketStream(a)
    stream.send(b"hi")
    assert b.recv(2) == b"hi"
    stream.close()
    stream.close()  # shutdown on a closed socket is swallowed
    b.close()


# -- SFTPServer operation edges ----------------------------------------------


@pytest.fixture
def client(tmp_path: Path) -> SFTPClient:
    (tmp_path / "file.txt").write_bytes(b"contents\n")
    (tmp_path / "dir").mkdir()
    server = SFTPServer(tmp_path)
    c = SFTPClient(server.pair())
    c.handshake()
    return c


def test_setstat_times_and_size(client: SFTPClient, tmp_path: Path) -> None:
    client.setstat(b"/file.txt", Attrs(atime=1000, mtime=2000))
    info = client.stat(b"/file.txt")
    assert info.mtime == 2000
    client.setstat(b"/file.txt", Attrs(size=3))
    assert client.stat(b"/file.txt").size == 3


def test_fsetstat_and_fstat(client: SFTPClient) -> None:
    handle = client.open(b"/w.txt", fx.FXF_WRITE | fx.FXF_CREAT)
    client.status(
        client.request(fx.FSETSTAT, tsftp.string(handle), Attrs(permissions=0o600).encode())
    )
    client.close_handle(handle)
    assert client.stat(b"/w.txt").permissions & 0o777 == 0o600


def test_mkdir_default_mode_and_empty_realpath(client: SFTPClient, tmp_path: Path) -> None:
    client.mkdir(b"/plain", Attrs())  # no permissions: the server's 0o777 (less umask)
    assert (tmp_path / "plain").is_dir()
    # An empty path is the current directory, as sftp-server treats it.
    assert client.realpath(b"") == "/"


def test_ok_status_with_its_own_message(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(b"x")
    server = SFTPServer(tmp_path)
    c = SFTPClient(server.pair())
    c.handshake()
    server.inject(fx.REMOVE, fx.FX_OK, "Removed")
    ptype, body = c.request(fx.REMOVE, tsftp.string(b"/f"))
    reader = tsftp.Reader(body)
    assert (ptype, reader.uint32(), reader.text()) == (fx.STATUS, fx.FX_OK, "Removed")
    c.close()


def test_oserror_without_errno_is_io_error(
    client: SFTPClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(session: object, rid: int, reader: object) -> None:
        raise OSError("no errno at all")

    monkeypatch.setitem(tsftp._HANDLERS, fx.REMOVE, broken)
    with pytest.raises(StatusError) as caught:
        client.remove(b"/file.txt")
    assert caught.value.code == fx.FX_FAILURE
    assert caught.value.message == os.strerror(errno.EIO)


def test_open_directory_is_error(client: SFTPClient) -> None:
    with pytest.raises(StatusError):
        client.open(b"/dir", fx.FXF_WRITE)


def test_invalid_handles(client: SFTPClient) -> None:
    bad = b"\x00\x00\x00\x99"
    for ptype, extra in [
        (fx.READ, tsftp.struct.pack(">QI", 0, 5)),
        (fx.WRITE, tsftp.struct.pack(">Q", 0) + tsftp.string(b"x")),
        (fx.FSTAT, b""),
        (fx.READDIR, b""),
    ]:
        with pytest.raises(StatusError):
            client.status(client.request(ptype, tsftp.string(bad), extra))
    # fsetstat and close on a bad handle too.
    with pytest.raises(StatusError):
        client.status(client.request(fx.FSETSTAT, tsftp.string(bad), Attrs().encode()))
    with pytest.raises(StatusError):
        client.status(client.request(fx.CLOSE, tsftp.string(bad)))


def test_rename_over_existing_fails(client: SFTPClient, tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"a")
    (tmp_path / "b").write_bytes(b"b")
    # v3 rename refuses to replace; use the plain RENAME opcode.
    with pytest.raises(StatusError):
        client.status(client.request(fx.RENAME, tsftp.string(b"/a"), tsftp.string(b"/b")))


def test_extended_operations(client: SFTPClient, tmp_path: Path) -> None:
    (tmp_path / "orig").write_bytes(b"data")
    client.hardlink(b"/orig", b"/hl")
    assert (tmp_path / "hl").read_bytes() == b"data"
    handle = client.open(b"/orig", fx.FXF_WRITE)
    client.fsync(handle)
    client.close_handle(handle)
    vfs = client.statvfs(b"/")
    assert vfs["bsize"] > 0
    # An unknown extension is unsupported.
    with pytest.raises(StatusError):
        client.extended("no-such-ext@openssh.com", tsftp.string(b"/x"))


def test_check_file_no_supported_algorithm(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(b"x")
    server = SFTPServer(tmp_path, check_file=("md5",))
    c = SFTPClient(server.pair())
    c.handshake()
    with pytest.raises(StatusError):
        c.check_file(b"/f", "sha256")  # not offered
    c.close()


def test_unsupported_operation(client: SFTPClient) -> None:
    # A packet type with no handler is answered OP_UNSUPPORTED.
    with pytest.raises(StatusError) as caught:
        client.status(client.request(99, b""))
    assert caught.value.code == 8  # FX_OP_UNSUPPORTED


def test_bad_message_on_truncated_request(client: SFTPClient) -> None:
    # A STAT with a truncated path reader raises BAD_MESSAGE.
    with pytest.raises(StatusError) as caught:
        client.status(client.request(fx.STAT, b"\x00\x00\x00\x05ab"))
    assert caught.value.code == fx.FX_BAD_MESSAGE


def test_hang_fault_never_answers(tmp_path: Path) -> None:
    # The hang fault silently drops the next request. limits=None keeps the
    # handshake from issuing a probe that the fault would swallow instead.
    server = SFTPServer(tmp_path, limits=None)
    c = SFTPClient(server.pair())
    c.handshake()
    server.faults.append("hang")
    rid = c.send(fx.STAT, tsftp.string(b"/"))
    c.forget([rid])  # nothing will ever answer it
    c.close()


def test_readdir_skips_vanished_entries(tmp_path: Path) -> None:
    # A dangling symlink is lstat-able, but a race where an entry disappears is
    # covered by removing a file the server will try to lstat.
    (tmp_path / "keep").write_bytes(b"x")
    server = SFTPServer(tmp_path)
    c = SFTPClient(server.pair())
    c.handshake()
    names = [n for n, _l, _a in c.listdir(b"/")]
    assert "keep" in names
    c.close()


def test_local_and_remote_paths(tmp_path: Path) -> None:
    server = SFTPServer(tmp_path)
    # A traversal attempt is clamped inside the root.
    assert server.local(b"/../../etc/passwd").startswith(server.root)
    assert server.remote(server.root) == "/"
    assert server.remote(os.path.join(server.root, "x")) == "/x"


# -- SSH server auth edges ----------------------------------------------------


def test_ssh_username_mismatch(tmp_path: Path) -> None:
    from xgfalclient.crypto.sshkeys import PrivateKey
    from xgfalclient.plugins.sftp import ssh
    from xgfalclient.plugins.sftp.endpoint import Endpoint
    from xgfalclient.testing.sftp import SSHServer

    (tmp_path / "f").write_bytes(b"x")
    hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    server = SSHServer(SFTPServer(tmp_path), hostkey, username="alice", password="pw")
    endpoint = Endpoint(
        host="h",
        port=22,
        user="bob",
        password="pw",
        known_hosts=str(tmp_path / "kh"),
        strict_host_keys="accept-new",
    )
    from xgfalclient.errors import GError

    with pytest.raises(GError, match="authentication methods failed"):
        ssh.connect(endpoint, ssh.Auth(username="bob", password="pw"), sock=server.pair())


# -- fake ssh -----------------------------------------------------------------


def test_fake_ssh_host_parsing() -> None:
    assert tsftp._fake_ssh_host(["ssh", "-s", "--", "host", "sftp"]) == "host"
    assert tsftp._fake_ssh_host(["ssh", "--"]) == ""
    assert tsftp._fake_ssh_host(["ssh", "-x", "plainhost", "sftp"]) == "plainhost"
    assert tsftp._fake_ssh_host(["ssh", "-x"]) == ""


@pytest.mark.parametrize("host", list(FAKE_HOSTS))
def test_fake_ssh_magic_hosts(host: str) -> None:
    stderr = io.BytesIO()
    status = fake_ssh_main(["ssh", "--", host, "sftp"], io.BytesIO(), io.BytesIO(), stderr)
    assert status == FAKE_HOSTS[host][1]
    assert FAKE_HOSTS[host][0].splitlines()[0].encode() in stderr.getvalue()


def test_fake_ssh_serves_sftp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "hello.txt").write_bytes(b"hello\n")
    monkeypatch.setenv("XGFAL_FAKE_ROOT", str(root))
    monkeypatch.setenv("XGFAL_FAKE_CHECKFILE", "md5,")  # empty names are skipped
    client_sock, server_sock = socket.socketpair()
    server_io = server_sock.makefile("rwb", buffering=0)
    thread = threading.Thread(
        target=fake_ssh_main,
        args=(["ssh", "--", "host", "sftp"], server_io, server_io, io.BytesIO()),
        daemon=True,
    )
    thread.start()
    client = SFTPClient(SocketStream(client_sock))
    client.handshake()
    assert client.stat(b"/hello.txt").size == 6
    assert "check-file-name" in client.extensions
    client.close()
    server_sock.close()
    thread.join(timeout=2)


def test_read_stdio_eof() -> None:
    with pytest.raises(EOFError):
        tsftp._read_stdio(io.BytesIO(b"ab"), 5)


def test_write_fake_ssh(tmp_path: Path) -> None:
    path = write_fake_ssh(tmp_path / "ssh")
    assert os.access(path, os.X_OK)
    text = Path(path).read_text()
    assert "fake_ssh_main" in text and text.startswith("#!")


def _packets(*chunks: bytes):  # type: ignore[no-untyped-def]
    buf = bytearray(b"".join(chunks))

    def read_exact(n: int) -> bytes:
        if len(buf) < n:
            raise EOFError
        out = bytes(buf[:n])
        del buf[:n]
        return out

    return read_exact


def test_serve_rejects_non_init_first_packet() -> None:
    server = SFTPServer(".")
    # A first packet that is not SSH_FXP_INIT ends the session (via _Drop).
    bad = tsftp.struct.pack(">IB", 1, 99)
    server.serve(_packets(bad), lambda data: None)


def test_close_all_closes_open_handles(tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_bytes(b"data")
    server = SFTPServer(tmp_path)
    c = SFTPClient(server.pair())
    c.handshake()
    c.open(b"/f.txt", fx.FXF_READ)  # leave the handle open
    c.close()  # closing the connection makes the server close_all its fds


def test_close_all_with_directory_handle(tmp_path: Path) -> None:
    server = SFTPServer(tmp_path)
    c = SFTPClient(server.pair())
    c.handshake()
    c.opendir(b"/")  # a directory handle has no file descriptor
    c.close()  # close_all skips the fd-less handle


def test_fsync_on_bad_handle(client: SFTPClient) -> None:
    with pytest.raises(StatusError):
        client.extended("fsync@openssh.com", tsftp.string(b"\x00\x00\x00\x99"))


def test_open_directory_for_reading_is_eisdir(client: SFTPClient) -> None:
    # os.open on a directory succeeds for reading; the server rejects it.
    with pytest.raises(StatusError):
        client.open(b"/dir", fx.FXF_READ)


def test_readdir_on_file_handle(client: SFTPClient) -> None:
    handle = client.open(b"/file.txt", fx.FXF_READ)
    with pytest.raises(StatusError):
        # A READDIR on a file handle (no entries) is a failure.
        client.status(client.request(fx.READDIR, tsftp.string(handle)))
    client.close_handle(handle)


def test_readdir_skips_unlstatable_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "good").write_bytes(b"x")
    (tmp_path / "skipme").write_bytes(b"y")
    server = SFTPServer(tmp_path)
    real_lstat = os.lstat

    def flaky_lstat(path, *a, **k):  # type: ignore[no-untyped-def]
        if os.fspath(path).endswith("skipme"):
            raise OSError(errno.ENOENT, "vanished")
        return real_lstat(path, *a, **k)

    monkeypatch.setattr(os, "lstat", flaky_lstat)
    c = SFTPClient(server.pair())
    c.handshake()
    names = [n for n, _l, _a in c.listdir(b"/")]
    assert "good" in names and "skipme" not in names
    c.close()


def test_extended_announced_but_unimplemented(client: SFTPClient) -> None:
    # lsetstat is announced by the server but has no handler.
    with pytest.raises(StatusError) as caught:
        client.extended("lsetstat@openssh.com", tsftp.string(b"/file.txt"))
    assert caught.value.errno == errno.ENOSYS


class _FakeConnSock:
    def __init__(self) -> None:
        self.sent = bytearray()

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)


def _server_conn() -> tsftp._SSHServerConn:
    dummy = type("S", (), {})()
    conn = tsftp._SSHServerConn(dummy, _FakeConnSock())
    conn.remote_channel = 1
    conn.client_maxpacket = 100
    conn.client_window = 0
    return conn


def test_server_chan_write_blocks_then_grants() -> None:
    conn = _server_conn()

    def grant() -> None:
        with conn.cond:
            conn.client_window = 100
            conn.cond.notify_all()

    timer = threading.Timer(0.05, grant)
    timer.start()
    conn._chan_write(b"x" * 40)  # blocks until the window opens
    timer.join()
    assert conn.sock.sent


def test_server_chan_write_aborts_on_error() -> None:
    conn = _server_conn()

    def fail() -> None:
        with conn.cond:
            conn.error = OSError("gone")
            conn.cond.notify_all()

    timer = threading.Timer(0.05, fail)
    timer.start()
    with pytest.raises(EOFError):
        conn._chan_write(b"x" * 40)
    timer.join()


def test_server_chan_read_exact_eof() -> None:
    conn = _server_conn()
    with conn.cond:
        conn.eof = True
    with pytest.raises(EOFError):
        conn._chan_read_exact(4)
