"""The in-Python SSH-2 transport, against the in-process SSH server."""

from __future__ import annotations

import errno
import os
import socket
from pathlib import Path

import pytest

from xgfalclient.crypto import ciphers
from xgfalclient.crypto.sshkeys import KnownHosts, PrivateKey, load_private
from xgfalclient.errors import GError
from xgfalclient.plugins.sftp import ssh
from xgfalclient.plugins.sftp.client import SFTPClient
from xgfalclient.plugins.sftp.endpoint import Endpoint
from xgfalclient.testing._keys import KEY_0
from xgfalclient.testing.sftp import SFTPServer, SSHServer


@pytest.fixture
def hostkey() -> PrivateKey:
    return PrivateKey.from_ed25519_seed(os.urandom(32))


@pytest.fixture
def sftp_root(tmp_path: Path) -> Path:
    (tmp_path / "hello.txt").write_bytes(b"hello world\n")
    return tmp_path


def _endpoint(tmp_path: Path, **kw: object) -> Endpoint:
    defaults: dict[str, object] = dict(
        host="testhost",
        port=22,
        user="alice",
        known_hosts=str(tmp_path / "known_hosts"),
        strict_host_keys="accept-new",
    )
    defaults.update(kw)
    return Endpoint(**defaults)  # type: ignore[arg-type]


def _dial(server: SSHServer, endpoint: Endpoint, auth: ssh.Auth, **kw: object) -> SFTPClient:
    transport = ssh.connect(endpoint, auth, sock=server.pair(), **kw)  # type: ignore[arg-type]
    client = SFTPClient(transport)
    client.handshake()
    return client


def test_password_auth_end_to_end(sftp_root: Path, hostkey: PrivateKey) -> None:
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="secret")
    endpoint = _endpoint(sftp_root, password="secret")
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="secret"))
    assert client.stat(b"/hello.txt").size == 12
    client.close()
    # The host key was recorded (accept-new).
    assert (sftp_root / "known_hosts").exists()


@pytest.mark.parametrize("kind", ["ed25519", "rsa", "ecdsa"])
def test_host_key_types(sftp_root: Path, kind: str) -> None:
    if kind == "ed25519":
        hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    elif kind == "rsa":
        hostkey = load_private(KEY_0)
    else:
        hostkey = PrivateKey.from_ecdsa(0x1234567890ABCDEF1234567890ABCDEF)
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw")
    endpoint = _endpoint(sftp_root, password="pw")
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_public_key_auth(sftp_root: Path, hostkey: PrivateKey) -> None:
    userkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    server = SSHServer(
        SFTPServer(sftp_root), hostkey, username="alice", authorized_keys=(userkey.public,)
    )
    endpoint = _endpoint(sftp_root)
    client = _dial(server, endpoint, ssh.Auth(username="alice", keys=(userkey,)))
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_rsa_public_key_with_ext_info(sftp_root: Path, hostkey: PrivateKey) -> None:
    userkey = PrivateKey.from_rsa(load_private(KEY_0).rsa)  # type: ignore[arg-type]
    server = SSHServer(
        SFTPServer(sftp_root),
        hostkey,
        username="alice",
        authorized_keys=(userkey.public,),
        send_ext_info=True,
    )
    endpoint = _endpoint(sftp_root)
    client = _dial(server, endpoint, ssh.Auth(username="alice", keys=(userkey,)))
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_key_then_password_fallback(sftp_root: Path, hostkey: PrivateKey) -> None:
    # An unauthorised key is refused, then the password succeeds.
    wrong = PrivateKey.from_ed25519_seed(os.urandom(32))
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw")
    endpoint = _endpoint(sftp_root, password="pw")
    client = _dial(server, endpoint, ssh.Auth(username="alice", keys=(wrong,), password="pw"))
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_all_auth_fails(sftp_root: Path, hostkey: PrivateKey) -> None:
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="right")
    endpoint = _endpoint(sftp_root, password="wrong")
    with pytest.raises(GError, match="authentication methods failed") as caught:
        _dial(server, endpoint, ssh.Auth(username="alice", password="wrong"))
    assert caught.value.code == errno.EACCES


def test_refused_key_and_no_password(sftp_root: Path, hostkey: PrivateKey) -> None:
    wrong = PrivateKey.from_ed25519_seed(os.urandom(32))
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw")
    with pytest.raises(GError, match="authentication methods failed"):
        _dial(server, _endpoint(sftp_root), ssh.Auth(username="alice", keys=(wrong,)))


def test_password_offered_to_a_key_only_server(sftp_root: Path, hostkey: PrivateKey) -> None:
    userkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    server = SSHServer(SFTPServer(sftp_root), hostkey, authorized_keys=(userkey.public,))
    endpoint = _endpoint(sftp_root, password="pw")
    # Without a password of its own the server refuses every password.
    with pytest.raises(GError, match="authentication methods failed"):
        _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    # With no username configured it takes the key for any user.
    client = _dial(server, endpoint, ssh.Auth(username="bob", keys=(userkey,)))
    assert client.stat(b"/hello.txt").size == 12
    client.close()


@pytest.mark.parametrize(
    ("kex", "macs"),
    [
        (("curve25519-sha256",), ("hmac-sha2-256-etm@openssh.com",)),
        (("diffie-hellman-group14-sha256",), ("hmac-sha2-256",)),
        (("diffie-hellman-group16-sha512",), ("hmac-sha2-512",)),
    ],
)
def test_kex_and_mac_matrix(
    sftp_root: Path, hostkey: PrivateKey, monkeypatch: pytest.MonkeyPatch, kex: tuple, macs: tuple
) -> None:
    monkeypatch.setattr(ssh, "_KEX_ALGS", kex)
    monkeypatch.setattr(ssh, "_MACS", macs)
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw")
    endpoint = _endpoint(sftp_root, password="pw")
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_aes_ctr_via_pure_backend(sftp_root: Path, hostkey: PrivateKey) -> None:
    pure = ciphers.PURE  # no fast chacha, so AES-CTR is negotiated first
    server = SSHServer(
        SFTPServer(sftp_root), hostkey, username="alice", password="pw", backend=pure
    )
    endpoint = _endpoint(sftp_root, password="pw")
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"), backend=pure)
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_bulk_transfer_and_rekey(tmp_path: Path, hostkey: PrivateKey) -> None:
    payload = os.urandom(3_000_000)
    (tmp_path / "big.bin").write_bytes(payload)
    server = SSHServer(
        SFTPServer(tmp_path), hostkey, username="alice", password="pw", rekey_after=3
    )
    endpoint = _endpoint(tmp_path, password="pw")
    from xgfalclient.plugins.sftp import protocol as fx

    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    handle = client.open(b"/big.bin", fx.FXF_READ)
    buf = bytearray(len(payload))
    assert client.read_into(handle, 0, memoryview(buf)) == len(payload)
    assert bytes(buf) == payload
    client.close()


def test_upload_flow(tmp_path: Path, hostkey: PrivateKey) -> None:
    from xgfalclient.plugins.sftp import protocol as fx
    from xgfalclient.plugins.sftp.client import WriteBehind

    payload = os.urandom(3_000_000)  # larger than the 2 MiB window, so send() blocks
    server = SSHServer(SFTPServer(tmp_path), hostkey, username="alice", password="pw")
    endpoint = _endpoint(tmp_path, password="pw")
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    handle = client.open(b"/up.bin", fx.FXF_WRITE | fx.FXF_CREAT | fx.FXF_TRUNC)
    writer = WriteBehind(client, handle)
    writer.write(0, payload)
    writer.flush()
    client.close_handle(handle)
    assert (tmp_path / "up.bin").read_bytes() == payload
    client.close()


# -- host key policies --------------------------------------------------------


def test_host_key_match(sftp_root: Path, hostkey: PrivateKey) -> None:
    known = sftp_root / "known_hosts"
    known.write_text(KnownHosts.line_for("testhost", 22, hostkey.public))
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw")
    endpoint = _endpoint(sftp_root, password="pw", strict_host_keys="yes")
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    assert client.alive
    client.close()


def test_host_key_unknown_strict_rejected(sftp_root: Path, hostkey: PrivateKey) -> None:
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw")
    endpoint = _endpoint(sftp_root, password="pw", strict_host_keys="yes")
    with pytest.raises(GError, match="not known"):
        _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))


def test_host_key_changed_rejected(sftp_root: Path, hostkey: PrivateKey) -> None:
    known = sftp_root / "known_hosts"
    other = PrivateKey.from_ed25519_seed(os.urandom(32))
    known.write_text(KnownHosts.line_for("testhost", 22, other.public))
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw")
    endpoint = _endpoint(sftp_root, password="pw", strict_host_keys="accept-new")
    with pytest.raises(GError, match="IDENTIFICATION HAS CHANGED"):
        _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))


def test_host_key_revoked_rejected(sftp_root: Path, hostkey: PrivateKey) -> None:
    known = sftp_root / "known_hosts"
    known.write_text("@revoked " + KnownHosts.line_for("testhost", 22, hostkey.public))
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw")
    endpoint = _endpoint(sftp_root, password="pw", strict_host_keys="accept-new")
    with pytest.raises(GError, match="revoked"):
        _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))


def test_host_key_unknown_accepted_when_disabled(sftp_root: Path, hostkey: PrivateKey) -> None:
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw")
    endpoint = _endpoint(sftp_root, password="pw", strict_host_keys="no")
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    assert client.alive
    # Nothing recorded when checking is off.
    assert not (sftp_root / "known_hosts").exists()
    client.close()


def test_accept_new_records_into_default_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # With no explicit known_hosts, accept-new writes ~/.ssh/known_hosts.
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    root = tmp_path / "root"
    root.mkdir()
    (root / "hello.txt").write_bytes(b"hi\n")
    server = SSHServer(SFTPServer(root), hostkey, username="alice", password="pw")
    endpoint = Endpoint(
        host="h", port=22, user="alice", password="pw", strict_host_keys="accept-new"
    )
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    client.close()
    assert (home / ".ssh" / "known_hosts").exists()


def test_record_host_key_survives_readonly(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # A known_hosts that cannot be written must not fail the connection.
    hostkey = PrivateKey.from_ed25519_seed(os.urandom(32))
    root = tmp_path / "root"
    root.mkdir()
    (root / "hello.txt").write_bytes(b"hi\n")
    kh = tmp_path / "nowhere" / "known_hosts"  # parent creation will be blocked

    def boom(*a: object, **k: object) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(os, "makedirs", boom)
    server = SSHServer(SFTPServer(root), hostkey, username="alice", password="pw")
    endpoint = Endpoint(
        host="h",
        port=22,
        user="alice",
        password="pw",
        known_hosts=str(kh),
        strict_host_keys="accept-new",
    )
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    assert client.alive
    client.close()


# -- connection-level errors --------------------------------------------------


def test_connect_refused() -> None:
    # A closed loopback port refuses immediately.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    endpoint = Endpoint(host="127.0.0.1", port=port, user="a", timeout=5)
    with pytest.raises(GError) as caught:
        ssh.connect(endpoint, ssh.Auth(username="a"))
    assert caught.value.code in (errno.ECONNREFUSED, errno.ECONNRESET)


def test_connect_resolve_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(addr: object, timeout: object = None) -> None:
        raise socket.gaierror("name resolution")

    monkeypatch.setattr(socket, "create_connection", boom)
    endpoint = Endpoint(host="no.such.host.invalid", port=22, user="a")
    with pytest.raises(GError, match="resolve") as caught:
        ssh.connect(endpoint, ssh.Auth(username="a"))
    assert caught.value.code == errno.EREMOTE


def test_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(addr: object, timeout: object = None) -> None:
        raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "create_connection", boom)
    endpoint = Endpoint(host="h", port=22, user="a", timeout=1)
    with pytest.raises(GError, match="timed out") as caught:
        ssh.connect(endpoint, ssh.Auth(username="a"))
    assert caught.value.code == errno.ETIMEDOUT


def test_connect_without_timeout_or_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    timeouts: list[object] = []

    def boom(addr: object, timeout: object = None) -> None:
        timeouts.append(timeout)
        raise OSError("no route")

    monkeypatch.setattr(socket, "create_connection", boom)
    endpoint = Endpoint(host="h", port=22, user="a", timeout=0)
    with pytest.raises(GError, match="Could not connect to a@h:22: no route") as caught:
        ssh.connect(endpoint, ssh.Auth(username="a"))
    assert caught.value.code == errno.ECONNREFUSED
    assert timeouts == [None]  # a timeout of 0 means none


def test_connect_generic_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(addr: object, timeout: object = None) -> None:
        raise OSError(errno.ENETUNREACH, "unreachable")

    monkeypatch.setattr(socket, "create_connection", boom)
    endpoint = Endpoint(host="h", port=22, user="a")
    with pytest.raises(GError) as caught:
        ssh.connect(endpoint, ssh.Auth(username="a"))
    assert caught.value.code == errno.ENETUNREACH


def test_no_subsystem(sftp_root: Path, hostkey: PrivateKey) -> None:
    server = SSHServer(
        SFTPServer(sftp_root), hostkey, username="alice", password="pw", fault="no-subsystem"
    )
    endpoint = _endpoint(sftp_root, password="pw")
    with pytest.raises(GError, match="sftp subsystem"):
        _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))


@pytest.mark.parametrize(("ours", "theirs"), [("subsystem", "exec"), ("sftp", "shell")])
def test_server_refuses_other_channel_requests(
    sftp_root: Path, hostkey: PrivateKey, monkeypatch: pytest.MonkeyPatch, ours: str, theirs: str
) -> None:
    # The test server grants only "subsystem sftp": ask for anything else.
    real = ssh.string
    monkeypatch.setattr(ssh, "string", lambda v: real(theirs if v == ours else v))
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw")
    endpoint = _endpoint(sftp_root, password="pw")
    with pytest.raises(GError, match="sftp subsystem"):
        _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))


def test_rsa_key_without_ext_info(sftp_root: Path, hostkey: PrivateKey) -> None:
    # No server-sig-algs: the RSA algorithm falls back to the key's default.
    userkey = PrivateKey.from_rsa(load_private(KEY_0).rsa)  # type: ignore[arg-type]
    server = SSHServer(
        SFTPServer(sftp_root), hostkey, username="alice", authorized_keys=(userkey.public,)
    )
    endpoint = _endpoint(sftp_root)
    client = _dial(server, endpoint, ssh.Auth(username="alice", keys=(userkey,)))
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def _fault_endpoint(sftp_root: Path, **kw: object) -> Endpoint:
    return _endpoint(sftp_root, password="pw", **kw)


@pytest.mark.parametrize(
    ("fault", "match"),
    [
        ("wrong_ecdh", "expected KEX_ECDH_REPLY"),
        ("bad_hostkey", "unreadable host key"),
        ("bad_hostsig", "did not verify"),
        ("bad_newkeys", "expected NEWKEYS"),
        ("bad_service_accept", "expected SERVICE_ACCEPT"),
        ("channel_open_failure", "Could not open an SSH session channel"),
        ("wrong_channel_confirm", "unexpected message .* setting up the channel"),
        ("wrong_subsystem", "unexpected message .* setting up the channel"),
    ],
)
def test_handshake_faults(sftp_root: Path, hostkey: PrivateKey, fault: str, match: str) -> None:
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw", fault=fault)
    with pytest.raises(GError, match=match):
        _dial(server, _fault_endpoint(sftp_root), ssh.Auth(username="alice", password="pw"))


@pytest.mark.parametrize(
    "fault",
    [
        "ignore_before_kexinit",
        "ignore_before_ecdh",
        "ignore_before_subsystem",
        "ignore_before_open",
        "ignore_pre_auth",
        "global_before_open",
        "window_before_confirm",
        "request_before_subsystem",
        "auth_ignore",
        "auth_pk_ok",
    ],
)
def test_tolerated_noise(sftp_root: Path, hostkey: PrivateKey, fault: str) -> None:
    server = SSHServer(
        SFTPServer(sftp_root),
        hostkey,
        username="alice",
        password="pw",
        fault=fault,
        send_ext_info=(fault == "ignore_pre_auth"),
    )
    client = _dial(server, _fault_endpoint(sftp_root), ssh.Auth(username="alice", password="pw"))
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_auth_unexpected_message(sftp_root: Path, hostkey: PrivateKey) -> None:
    server = SSHServer(
        SFTPServer(sftp_root), hostkey, username="alice", password="pw", fault="auth_unexpected"
    )
    with pytest.raises(GError, match="unexpected message"):
        _dial(server, _fault_endpoint(sftp_root), ssh.Auth(username="alice", password="pw"))


def test_auth_banner_without_callback(sftp_root: Path, hostkey: PrivateKey) -> None:
    # A banner with no callback configured is simply dropped.
    server = SSHServer(
        SFTPServer(sftp_root), hostkey, username="alice", password="pw", fault="auth_banner"
    )
    client = _dial(server, _fault_endpoint(sftp_root), ssh.Auth(username="alice", password="pw"))
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_rsa_algorithm_fallback(sftp_root: Path, hostkey: PrivateKey) -> None:
    # The server advertises only non-RSA signature algorithms, so the RSA key
    # falls back to its own default rather than a negotiated one.
    userkey = PrivateKey.from_rsa(load_private(KEY_0).rsa)  # type: ignore[arg-type]
    server = SSHServer(
        SFTPServer(sftp_root),
        hostkey,
        username="alice",
        authorized_keys=(userkey.public,),
        send_ext_info=True,
        ext_info_algs="ssh-ed25519",
    )
    client = _dial(server, _endpoint(sftp_root), ssh.Auth(username="alice", keys=(userkey,)))
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_bad_dh_value(
    sftp_root: Path, hostkey: PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "_KEX_ALGS", ("diffie-hellman-group14-sha256",))
    server = SSHServer(
        SFTPServer(sftp_root), hostkey, username="alice", password="pw", fault="bad_dh_f"
    )
    with pytest.raises(GError, match="DH value out of range"):
        _dial(server, _fault_endpoint(sftp_root), ssh.Auth(username="alice", password="pw"))


def test_auth_banner_delivered(sftp_root: Path, hostkey: PrivateKey) -> None:
    banners: list[str] = []
    server = SSHServer(
        SFTPServer(sftp_root), hostkey, username="alice", password="pw", fault="auth_banner"
    )
    transport = ssh.connect(
        _fault_endpoint(sftp_root),
        ssh.Auth(username="alice", password="pw", banner=banners.append),
        sock=server.pair(),
    )
    client = SFTPClient(transport)
    client.handshake()
    assert banners == ["welcome"]
    client.close()


@pytest.mark.parametrize(
    "fault",
    [
        "ignore_mid",
        "stderr",
        "exit_status",
        "exit_status_noreply",
        "global_mid",
        "global_mid_noreply",
    ],
)
def test_channel_noise_ignored(sftp_root: Path, hostkey: PrivateKey, fault: str) -> None:
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw", fault=fault)
    client = _dial(server, _fault_endpoint(sftp_root), ssh.Auth(username="alice", password="pw"))
    assert client.stat(b"/hello.txt").size == 12
    client.close()


@pytest.mark.parametrize("fault", ["disconnect_mid", "eof_close", "abrupt"])
def test_channel_teardown(sftp_root: Path, hostkey: PrivateKey, fault: str) -> None:
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw", fault=fault)
    transport = ssh.connect(
        _fault_endpoint(sftp_root), ssh.Auth(username="alice", password="pw"), sock=server.pair()
    )
    # The reader observes the teardown; a read then sees EOF or an error.
    view = memoryview(bytearray(16))
    try:
        result = transport.recv_into(view)
        assert result == 0  # clean EOF/close
    except GError:
        pass  # disconnect or abrupt drop
    transport.close()


def test_open_socket_success(sftp_root: Path) -> None:
    # A real loopback listener exercises the socket setup path.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    endpoint = Endpoint(host="127.0.0.1", port=port, user="a", timeout=5)
    sock = ssh._open_socket(endpoint)
    assert sock is not None
    sock.close()
    listener.close()


def test_connect_cleanup_close_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from test_sftp_transport_edges import FakeSock

    sock = FakeSock(b"SSH-1.5-nope\r\n")

    def boom() -> None:
        raise OSError("close failed")

    sock.close = boom  # type: ignore[method-assign]
    monkeypatch.setattr(ssh, "_open_socket", lambda endpoint: sock)
    with pytest.raises(GError, match="unsupported server version"):
        ssh.connect(Endpoint(host="h", port=22, user="a"), ssh.Auth(username="a"))


def test_recv_into_eof_returns_zero(sftp_root: Path, hostkey: PrivateKey) -> None:
    server = SSHServer(SFTPServer(sftp_root), hostkey, username="alice", password="pw")
    endpoint = _endpoint(sftp_root, password="pw")
    transport = ssh.connect(endpoint, ssh.Auth(username="alice", password="pw"), sock=server.pair())
    client = SFTPClient(transport)
    client.handshake()
    assert client.stat(b"/hello.txt").size == 12
    client.close()
    # After close, a fresh recv_into observes end-of-stream as zero.
    assert transport.recv_into(memoryview(bytearray(16))) in (0, 16)


_LIB = ciphers.get()


@pytest.mark.parametrize(
    "cipher",
    [
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
        "aes128-ctr",
    ],
)
def test_cipher_matrix(
    tmp_path: Path, hostkey: PrivateKey, monkeypatch: pytest.MonkeyPatch, cipher: str
) -> None:
    from xgfalclient.plugins.sftp import protocol as fx
    from xgfalclient.plugins.sftp.client import WriteBehind

    if cipher.endswith("-gcm@openssh.com") and not _LIB.has_gcm:
        pytest.skip("no libcrypto AES-GCM here")
    monkeypatch.setattr(ssh, "_ciphers_preferred", lambda backend: (cipher,))
    payload = os.urandom(300_000)
    (tmp_path / "in.bin").write_bytes(payload)
    server = SSHServer(SFTPServer(tmp_path), hostkey, username="alice", password="pw")
    endpoint = _endpoint(tmp_path, password="pw")
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    expected = {
        "aes128-gcm@openssh.com": ssh._GcmCipher,
        "aes256-gcm@openssh.com": ssh._GcmCipher,
        "chacha20-poly1305@openssh.com": ssh._ChachaCipher,
        "aes128-ctr": ssh._CtrCipher,
    }[cipher]
    transport = client.stream
    assert isinstance(transport, ssh.SSHTransport) and isinstance(transport._in, expected)
    handle = client.open(b"/in.bin", fx.FXF_READ)
    buf = bytearray(len(payload))
    assert client.read_into(handle, 0, memoryview(buf)) == len(payload)
    assert bytes(buf) == payload
    handle = client.open(b"/out.bin", fx.FXF_WRITE | fx.FXF_CREAT | fx.FXF_TRUNC)
    writer = WriteBehind(client, handle)
    writer.write(0, payload)
    writer.flush()
    client.close_handle(handle)
    assert (tmp_path / "out.bin").read_bytes() == payload
    client.close()


def test_bulk_download_beyond_the_window(tmp_path: Path, hostkey: PrivateKey) -> None:
    """More than half our window: the client tops it up, the server takes the credit."""
    from xgfalclient.plugins.sftp import protocol as fx

    payload = os.urandom(ssh._LOCAL_WINDOW // 2 + 3_000_000)
    (tmp_path / "big.bin").write_bytes(payload)
    server = SSHServer(SFTPServer(tmp_path), hostkey, username="alice", password="pw")
    endpoint = _endpoint(tmp_path, password="pw")
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    handle = client.open(b"/big.bin", fx.FXF_READ)
    chunks: list[bytes] = []
    total = client.stream_read(handle, 0, None, lambda offset, view: chunks.append(bytes(view)))
    assert total == len(payload) and b"".join(chunks) == payload
    client.close()


def test_server_refuses_data_beyond_its_window(tmp_path: Path, hostkey: PrivateKey) -> None:
    server = SSHServer(SFTPServer(tmp_path), hostkey, username="alice", password="pw")
    endpoint = _endpoint(tmp_path, password="pw")
    client = _dial(server, endpoint, ssh.Auth(username="alice", password="pw"))
    transport = client.stream
    assert isinstance(transport, ssh.SSHTransport)
    transport._remote_maxpacket = 1 << 20  # pretend we may
    transport.send(b"x" * 40_000)  # one packet over the server's 32 KiB maximum
    with pytest.raises(GError):
        client.stat(b"/")
