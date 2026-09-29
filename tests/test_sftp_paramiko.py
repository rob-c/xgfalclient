"""The paramiko transport tier, driven by a fake ``paramiko`` module.

paramiko is never a dependency, so a stand-in module - implementing exactly
the small API :mod:`.paramiko_tier` uses - stands in for it. Its transport
bridges to an in-process :class:`SFTPServer`, so the adapter's glue and our
own SFTP client run for real on top.
"""

from __future__ import annotations

import errno
import os
import socket
import sys
import types
from pathlib import Path

import pytest

import xgfalclient
from xgfalclient.crypto.sshkeys import PrivateKey
from xgfalclient.errors import GError
from xgfalclient.plugins.sftp import paramiko_tier
from xgfalclient.plugins.sftp.endpoint import Endpoint
from xgfalclient.testing.sftp import (
    SFTPServer,
    _SocketIO,  # type: ignore[attr-defined]
)


class _SSHException(Exception):
    pass


def _make_fake_paramiko(
    root: Path,
    host_pub_blob: bytes,
    *,
    password: str = "secret",
    accept_key: bool = True,
    fail_start: bool = False,
    fail_subsystem: bool = False,
):  # type: ignore[no-untyped-def]
    module = types.ModuleType("paramiko")
    module.SSHException = _SSHException  # type: ignore[attr-defined]

    class _Key:
        def asbytes(self) -> bytes:
            return host_pub_blob

    class _Channel:
        def __init__(self, sock: socket.socket) -> None:
            self._sock = sock

        def invoke_subsystem(self, name: str) -> None:
            if fail_subsystem:
                raise _SSHException("no subsystem")

        def sendall(self, data: bytes) -> None:
            self._sock.sendall(data)

        def recv(self, count: int) -> bytes:
            return self._sock.recv(count)

        def close(self) -> None:
            self._sock.close()

    class _Transport:
        def __init__(self, sock: object) -> None:
            self._authed = False

        def start_client(self, timeout: object = None) -> None:
            if fail_start:
                raise _SSHException("handshake failed")

        def get_remote_server_key(self) -> _Key:
            return _Key()

        def auth_publickey(self, user: str, pkey: object) -> None:
            if accept_key:
                self._authed = True
            else:
                raise _SSHException("key rejected")

        def auth_password(self, user: str, secret: str) -> None:
            if secret == password:
                self._authed = True
            else:
                raise _SSHException("bad password")

        def is_authenticated(self) -> bool:
            return self._authed

        def open_session(self, timeout: object = None) -> _Channel:
            server = SFTPServer(root)
            client_sock, server_sock = socket.socketpair()
            server.start(lambda: _SocketIO(server_sock))
            return _Channel(client_sock)

        def close(self) -> None:
            pass

    class _PKey:
        @staticmethod
        def from_path(path: str, passphrase: object = None) -> object:
            module.passphrases.append(passphrase)  # type: ignore[attr-defined]
            return object()

    module.passphrases = []  # type: ignore[attr-defined]

    module.Transport = _Transport  # type: ignore[attr-defined]
    module.PKey = _PKey  # type: ignore[attr-defined]
    return module


@pytest.fixture
def fake_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    root = tmp_path / "root"
    root.mkdir()
    (root / "hello.txt").write_bytes(b"hello world\n")
    hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: _DummySock())
    return root, hostkey, monkeypatch


class _DummySock:
    def close(self) -> None:
        pass


def _endpoint(tmp_path: Path, **kw: object) -> Endpoint:
    defaults: dict[str, object] = dict(
        host="h",
        port=22,
        user="alice",
        known_hosts=str(tmp_path / "kh"),
        strict_host_keys="accept-new",
    )
    defaults.update(kw)
    return Endpoint(**defaults)  # type: ignore[arg-type]


def test_paramiko_password_auth(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    from xgfalclient.plugins.sftp.client import SFTPClient

    stream = paramiko_tier.connect(_endpoint(tmp_path, password="secret"))
    client = SFTPClient(stream)
    client.handshake()
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_paramiko_key_auth(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    key = tmp_path / "id_ed25519"
    key.write_bytes(b"dummy-key")
    from xgfalclient.plugins.sftp.client import SFTPClient

    stream = paramiko_tier.connect(_endpoint(tmp_path, key_file=str(key)))
    client = SFTPClient(stream)
    client.handshake()
    assert client.stat(b"/hello.txt").size == 12
    client.close()
    # A passphrase goes to paramiko's key loader; no passphrase goes as None.
    paramiko_tier.connect(_endpoint(tmp_path, key_file=str(key), passphrase="pp")).close()
    assert fake.passphrases == [None, "pp"]


def test_paramiko_key_rejected_then_password(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob, accept_key=False)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    key = tmp_path / "id"
    key.write_bytes(b"dummy")
    from xgfalclient.plugins.sftp.client import SFTPClient

    stream = paramiko_tier.connect(_endpoint(tmp_path, key_file=str(key), password="secret"))
    client = SFTPClient(stream)
    client.handshake()
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_paramiko_all_auth_fails(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob, accept_key=False)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError) as caught:
        paramiko_tier.connect(_endpoint(tmp_path, password="wrong"))
    assert caught.value.code == errno.EACCES


def test_paramiko_auth_reports_what_was_tried(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob, accept_key=False)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    key = tmp_path / "id"
    key.write_bytes(b"dummy")
    # A rejected key and no password to fall back on.
    with pytest.raises(GError, match=r"failed for alice@h:22 \(tried publickey\)"):
        paramiko_tier.connect(_endpoint(tmp_path, key_file=str(key)))
    # Nothing to offer at all; with no user the label is just host:port.
    with pytest.raises(GError, match=r"failed for h:22 \(tried none\)"):
        paramiko_tier.connect(_endpoint(tmp_path, user=""))


def test_paramiko_host_key_unknown_rejected(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError, match="not known"):
        paramiko_tier.connect(_endpoint(tmp_path, password="secret", strict_host_keys="yes"))


def test_paramiko_host_key_changed_rejected(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.crypto.sshkeys import KnownHosts

    root, hostkey, monkeypatch = fake_env
    other = PrivateKey.from_ed25519_seed(os.urandom(32)).public
    (tmp_path / "kh").write_text(KnownHosts.line_for("h", 22, other))
    fake = _make_fake_paramiko(root, hostkey.public.blob)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError, match="verification failed"):
        paramiko_tier.connect(_endpoint(tmp_path, password="secret"))


def test_paramiko_host_key_match_and_accept_all(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from xgfalclient.crypto.sshkeys import KnownHosts
    from xgfalclient.plugins.sftp.client import SFTPClient

    root, hostkey, monkeypatch = fake_env
    (tmp_path / "kh").write_text(KnownHosts.line_for("h", 22, hostkey.public))
    fake = _make_fake_paramiko(root, hostkey.public.blob)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    stream = paramiko_tier.connect(_endpoint(tmp_path, password="secret", strict_host_keys="yes"))
    SFTPClient(stream).close()
    # And the "no checking" policy.
    stream2 = paramiko_tier.connect(
        _endpoint(tmp_path, password="secret", strict_host_keys="no", known_hosts="")
    )
    SFTPClient(stream2).close()


def test_paramiko_bad_host_key_blob(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, _hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, b"\x00\x00\x00\x03bad")  # unparseable
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError, match="Unreadable host key"):
        paramiko_tier.connect(_endpoint(tmp_path, password="secret"))


def test_paramiko_start_client_fails(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob, fail_start=True)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError, match="SSH error") as caught:
        paramiko_tier.connect(_endpoint(tmp_path, password="secret"))
    assert caught.value.code == errno.ECONNRESET


def test_paramiko_subsystem_fails(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob, fail_subsystem=True)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError, match="SSH error"):
        paramiko_tier.connect(_endpoint(tmp_path, password="secret"))


def test_paramiko_connect_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = types.ModuleType("paramiko")
    fake.SSHException = _SSHException  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "paramiko", fake)

    timeouts: list[object] = []

    def refused(addr: object, timeout: object = None) -> None:
        timeouts.append(timeout)
        raise OSError(errno.ECONNREFUSED, "refused")

    monkeypatch.setattr(socket, "create_connection", refused)
    with pytest.raises(GError) as caught:
        paramiko_tier.connect(_endpoint(tmp_path, password="pw"))
    assert caught.value.code == errno.ECONNREFUSED
    # A timeout of 0 means none at all.
    with pytest.raises(GError):
        paramiko_tier.connect(_endpoint(tmp_path, password="pw", timeout=0))
    assert timeouts == [60.0, None]


def test_paramiko_connect_error_without_errno(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = types.ModuleType("paramiko")
    fake.SSHException = _SSHException  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "paramiko", fake)

    def broken(addr: object, timeout: object = None) -> None:
        raise OSError("no errno")

    monkeypatch.setattr(socket, "create_connection", broken)
    with pytest.raises(GError) as caught:
        paramiko_tier.connect(_endpoint(tmp_path, password="pw"))
    assert caught.value.code == errno.ECONNREFUSED


def test_paramiko_connect_resolve_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = types.ModuleType("paramiko")
    fake.SSHException = _SSHException  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "paramiko", fake)

    def gai(addr: object, timeout: object = None) -> None:
        raise socket.gaierror("no host")

    monkeypatch.setattr(socket, "create_connection", gai)
    with pytest.raises(GError, match="resolve") as caught:
        paramiko_tier.connect(_endpoint(tmp_path, password="pw"))
    assert caught.value.code == errno.EREMOTE


def test_paramiko_stream_send_skips_empty(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    stream = paramiko_tier.connect(_endpoint(tmp_path, password="secret"))
    stream.send(b"", b"")  # empty parts are skipped without error
    stream.close()


def test_paramiko_stream_recv_eof() -> None:
    class _Chan:
        def recv(self, n: int) -> bytes:
            return b""

        def close(self) -> None:
            pass

    class _T:
        def close(self) -> None:
            pass

    stream = paramiko_tier.ParamikoStream(_T(), _Chan())
    assert stream.recv_into(memoryview(bytearray(8))) == 0


def test_paramiko_tier_through_plugin(fake_env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    ctx = xgfalclient.creat_context()
    ctx.set_opt_string("SFTP PLUGIN", "USER", "alice")
    ctx.set_opt_string("SFTP PLUGIN", "PASSWORD", "secret")
    ctx.set_opt_string("SFTP PLUGIN", "KNOWN_HOSTS", str(tmp_path / "kh"))
    ctx.set_opt_string("SFTP PLUGIN", "TRANSPORT", "paramiko")
    try:
        assert ctx.stat("sftp://h/hello.txt").st_size == 12
    finally:
        ctx.free()
