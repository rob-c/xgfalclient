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
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import xgfalclient
from xgfalclient.crypto.sshkeys import PrivateKey
from xgfalclient.errors import GError
from xgfalclient.plugins.sftp import paramiko_tier
from xgfalclient.plugins.sftp.endpoint import Endpoint
from xgfalclient.testing.sftp import (
    SFTPServer,
    SSHServer,
    _SocketIO,
)


class _SSHException(Exception):
    pass


class _FakeParamiko(types.ModuleType):
    """A stand-in ``paramiko`` module: just the names :mod:`.paramiko_tier` uses."""

    SSHException: type[Exception]
    Transport: type
    PKey: type
    #: Every passphrase ``PKey.from_path`` was given.
    passphrases: list[object]


#: What ``fake_env`` gives a test: the served root, the host key and ``monkeypatch``.
FakeEnv = tuple[Path, PrivateKey, pytest.MonkeyPatch]
#: What ``real_paramiko`` gives a test: a server factory and the served root.
RealParamiko = tuple[Callable[..., SSHServer], Path]


def _make_fake_paramiko(
    root: Path,
    host_pub_blob: bytes,
    *,
    password: str = "secret",
    accept_key: bool = True,
    fail_start: bool = False,
    fail_subsystem: bool = False,
) -> _FakeParamiko:
    module = _FakeParamiko("paramiko")
    module.SSHException = _SSHException

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
        """Like paramiko's: closing the transport closes its socket and channels."""

        def __init__(self, sock: socket.socket) -> None:
            self._authed = False
            self._sock = sock
            self._channels: list[_Channel] = []

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
            channel = _Channel(client_sock)
            self._channels.append(channel)
            return channel

        def close(self) -> None:
            for channel in self._channels:
                channel.close()
            self._sock.close()

    class _PKey:
        @staticmethod
        def from_path(path: str, passphrase: object = None) -> object:
            module.passphrases.append(passphrase)
            return object()

    module.passphrases = []

    module.Transport = _Transport
    module.PKey = _PKey
    return module


@pytest.fixture
def fake_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeEnv:
    root = tmp_path / "root"
    root.mkdir()
    (root / "hello.txt").write_bytes(b"hello world\n")
    hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: _DummySock())
    return root, hostkey, monkeypatch


class _DummySock:
    def close(self) -> None:
        pass


def _endpoint(tmp_path: Path, **kw: Any) -> Endpoint:
    defaults: dict[str, Any] = {
        "host": "h",
        "port": 22,
        "user": "alice",
        "known_hosts": str(tmp_path / "kh"),
        "strict_host_keys": "accept-new",
    }
    defaults.update(kw)
    return Endpoint(**defaults)


def test_paramiko_password_auth(fake_env: FakeEnv, tmp_path: Path) -> None:
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    from xgfalclient.plugins.sftp.client import SFTPClient

    stream = paramiko_tier.connect(_endpoint(tmp_path, password="secret"))
    client = SFTPClient(stream)
    client.handshake()
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_paramiko_key_auth(fake_env: FakeEnv, tmp_path: Path) -> None:
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
    assert fake.passphrases == [None, b"pp"]


def test_paramiko_key_rejected_then_password(fake_env: FakeEnv, tmp_path: Path) -> None:
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


def test_paramiko_all_auth_fails(fake_env: FakeEnv, tmp_path: Path) -> None:
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob, accept_key=False)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError) as caught:
        paramiko_tier.connect(_endpoint(tmp_path, password="wrong"))
    assert caught.value.code == errno.EACCES


def test_paramiko_auth_reports_what_was_tried(fake_env: FakeEnv, tmp_path: Path) -> None:
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


def test_paramiko_host_key_unknown_rejected(fake_env: FakeEnv, tmp_path: Path) -> None:
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError, match="not known"):
        paramiko_tier.connect(_endpoint(tmp_path, password="secret", strict_host_keys="yes"))


def test_paramiko_host_key_changed_rejected(fake_env: FakeEnv, tmp_path: Path) -> None:
    from xgfalclient.crypto.sshkeys import KnownHosts

    root, hostkey, monkeypatch = fake_env
    other = PrivateKey.from_ed25519_seed(os.urandom(32)).public
    (tmp_path / "kh").write_text(KnownHosts.line_for("h", 22, other))
    fake = _make_fake_paramiko(root, hostkey.public.blob)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError, match="verification failed"):
        paramiko_tier.connect(_endpoint(tmp_path, password="secret"))


def test_paramiko_host_key_match_and_accept_all(fake_env: FakeEnv, tmp_path: Path) -> None:
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


def test_paramiko_bad_host_key_blob(fake_env: FakeEnv, tmp_path: Path) -> None:
    root, _hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, b"\x00\x00\x00\x03bad")  # unparseable
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError, match="Unreadable host key"):
        paramiko_tier.connect(_endpoint(tmp_path, password="secret"))


def test_paramiko_start_client_fails(fake_env: FakeEnv, tmp_path: Path) -> None:
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob, fail_start=True)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError, match="SSH error") as caught:
        paramiko_tier.connect(_endpoint(tmp_path, password="secret"))
    assert caught.value.code == errno.ECONNRESET


def test_paramiko_subsystem_fails(fake_env: FakeEnv, tmp_path: Path) -> None:
    root, hostkey, monkeypatch = fake_env
    fake = _make_fake_paramiko(root, hostkey.public.blob, fail_subsystem=True)
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    with pytest.raises(GError, match="SSH error"):
        paramiko_tier.connect(_endpoint(tmp_path, password="secret"))


def test_paramiko_connect_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeParamiko("paramiko")
    fake.SSHException = _SSHException
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
    fake = _FakeParamiko("paramiko")
    fake.SSHException = _SSHException
    monkeypatch.setitem(sys.modules, "paramiko", fake)

    def broken(addr: object, timeout: object = None) -> None:
        raise OSError("no errno")

    monkeypatch.setattr(socket, "create_connection", broken)
    with pytest.raises(GError) as caught:
        paramiko_tier.connect(_endpoint(tmp_path, password="pw"))
    assert caught.value.code == errno.ECONNREFUSED


def test_paramiko_connect_resolve_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeParamiko("paramiko")
    fake.SSHException = _SSHException
    monkeypatch.setitem(sys.modules, "paramiko", fake)

    def gai(addr: object, timeout: object = None) -> None:
        raise socket.gaierror("no host")

    monkeypatch.setattr(socket, "create_connection", gai)
    with pytest.raises(GError, match="resolve") as caught:
        paramiko_tier.connect(_endpoint(tmp_path, password="pw"))
    assert caught.value.code == errno.EREMOTE


def test_paramiko_stream_send_skips_empty(fake_env: FakeEnv, tmp_path: Path) -> None:
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


@pytest.mark.parametrize("error", [EOFError(), BrokenPipeError(errno.EPIPE, "Broken pipe")])
def test_paramiko_stream_close_tolerates_a_peer_that_hung_up(error: BaseException) -> None:
    closed: list[str] = []

    class _Chan:
        def close(self) -> None:
            closed.append("channel")
            raise error

    class _T:
        def close(self) -> None:
            closed.append("transport")

    paramiko_tier.ParamikoStream(_T(), _Chan()).close()
    assert closed == ["channel", "transport"]


def test_paramiko_tier_through_plugin(fake_env: FakeEnv, tmp_path: Path) -> None:
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


# -- the real paramiko, against the in-process SSH server ----------------------
#
# With paramiko installed (the ``sftp`` extra), the tier runs end to end
# against :class:`SSHServer`: paramiko's handshake - strict KEX included,
# which paramiko has from 3.4 - and our KnownHosts policy on its host key.


@pytest.fixture
def real_paramiko(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> RealParamiko:
    """``(make_server, root)``; each server's connections reach paramiko via a socketpair."""
    pytest.importorskip("paramiko", minversion="3.4")
    root = tmp_path / "root"
    root.mkdir()
    (root / "hello.txt").write_bytes(b"hello world\n")
    servers: list[SSHServer] = []

    def make_server(**kw: Any) -> SSHServer:
        hostkey = kw.pop("host_key", None) or PrivateKey.from_ed25519_seed(os.urandom(32))
        server = SSHServer(SFTPServer(root), hostkey, username="alice", **kw)
        servers.append(server)
        return server

    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: servers[-1].pair())
    return make_server, root


def _stat_through(stream: paramiko_tier.ParamikoStream) -> int | None:
    from xgfalclient.plugins.sftp.client import SFTPClient

    client = SFTPClient(stream)
    try:
        client.handshake()
        return client.stat(b"/hello.txt").size
    finally:
        client.close()


@pytest.mark.parametrize("strict", [True, False])
def test_real_paramiko_password_and_strict_kex(
    real_paramiko: RealParamiko, tmp_path: Path, strict: bool
) -> None:
    make_server, _root = real_paramiko
    server = make_server(password="secret", strict_kex=strict)
    stream = paramiko_tier.connect(_endpoint(tmp_path, password="secret"))
    assert _stat_through(stream) == 12
    # paramiko and the test server agreed strict KEX whenever it was offered,
    # and the sequence-number resets matched (or no packet would have verified).
    assert server.strict_negotiated == [strict]
    # accept-new recorded the host key with our KnownHosts writer.
    from xgfalclient.crypto.sshkeys import KnownHosts

    known = KnownHosts.load([str(tmp_path / "kh")])
    assert known.check("h", 22, server.host_key.public).status == "match"


def test_real_paramiko_encrypted_key(real_paramiko: RealParamiko, tmp_path: Path) -> None:
    from xgfalclient.crypto.sshkeys import encode_openssh_private

    make_server, _root = real_paramiko
    userkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    make_server(authorized_keys=(userkey.public,))
    key_file = tmp_path / "id_ed25519"
    key_file.write_bytes(encode_openssh_private(userkey, passphrase=b"pp", rounds=2))
    stream = paramiko_tier.connect(_endpoint(tmp_path, key_file=str(key_file), passphrase="pp"))
    assert _stat_through(stream) == 12


def test_real_paramiko_host_key_policy(real_paramiko: RealParamiko, tmp_path: Path) -> None:
    from xgfalclient.crypto.sshkeys import KnownHosts

    make_server, _root = real_paramiko
    server = make_server(password="secret")
    # Unknown, under StrictHostKeyChecking=yes: refused, nothing recorded.
    with pytest.raises(GError, match="not known") as caught:
        paramiko_tier.connect(_endpoint(tmp_path, password="secret", strict_host_keys="yes"))
    assert caught.value.code == errno.EACCES
    assert not (tmp_path / "kh").exists()
    # Known and matching: accepted under "yes".
    (tmp_path / "kh").write_text(KnownHosts.line_for("h", 22, server.host_key.public))
    stream = paramiko_tier.connect(_endpoint(tmp_path, password="secret", strict_host_keys="yes"))
    assert _stat_through(stream) == 12
    # A different key on record: refused, whatever the policy.
    other = PrivateKey.from_ed25519_seed(os.urandom(32)).public
    (tmp_path / "kh").write_text(KnownHosts.line_for("h", 22, other))
    make_server(password="secret", host_key=server.host_key)
    with pytest.raises(GError, match="verification failed") as caught:
        paramiko_tier.connect(_endpoint(tmp_path, password="secret", strict_host_keys="no"))
    assert caught.value.code == errno.EACCES


@pytest.mark.parametrize("kind", ["ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"])
def test_real_paramiko_accepts_larger_ecdsa_host_keys(
    real_paramiko: RealParamiko, tmp_path: Path, kind: str
) -> None:
    """A server whose only host key is P-384 or P-521: paramiko negotiates it,
    and our KnownHosts parser reads it, records it and matches it next time."""
    from xgfalclient.crypto.sshkeys import KnownHosts

    make_server, _root = real_paramiko
    server = make_server(password="secret", host_key=PrivateKey.from_ecdsa(0xC0FFEE, kind=kind))
    stream = paramiko_tier.connect(_endpoint(tmp_path, password="secret"))
    assert _stat_through(stream) == 12
    known = KnownHosts.load([str(tmp_path / "kh")])
    assert known.check("h", 22, server.host_key.public).status == "match"
    make_server(password="secret", host_key=server.host_key)
    stream = paramiko_tier.connect(_endpoint(tmp_path, password="secret", strict_host_keys="yes"))
    assert _stat_through(stream) == 12


def test_sftp_extra_and_bcrypt_dependency_are_declared() -> None:
    """paramiko is the optional ``sftp`` extra (3.4+, strict KEX); bcrypt is a base dependency."""
    import tomllib

    from packaging.requirements import Requirement

    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())["project"]
    extra = [Requirement(value) for value in project["optional-dependencies"]["sftp"]]
    assert [(r.name, str(r.specifier)) for r in extra] == [("paramiko", ">=3.4")]
    base = {Requirement(value).name: Requirement(value) for value in project["dependencies"]}
    assert "paramiko" not in base
    assert str(base["bcrypt"].specifier) == ">=4"
