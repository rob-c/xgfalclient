"""gsidcap: the dcap control line through the GSI tunnel, and pluggable tunnels."""

from __future__ import annotations

import errno
import ssl
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from test_dcap import GROUP, code_of, with_dcap
from xgfalclient.crypto.gsi import SecurityContext
from xgfalclient.errors import GError
from xgfalclient.plugins.dcap import KdcapPlugin, register_tunnel, tunnel
from xgfalclient.plugins.dcap.tunnel import TokenLink, Tunnel
from xgfalclient.testing.dcap import DcapServer, Raw
from xgfalclient.testing.pki import PKI, create_pki


@pytest.fixture
def root(tmp_path: Path) -> Path:
    base = tmp_path / "ns"
    (base / "data").mkdir(parents=True)
    (base / "data" / "hello.txt").write_bytes(b"hello world\n")
    return base


@pytest.fixture
def gctx(ctx: xgfalclient.Gfal2Context, grid_env: PKI) -> xgfalclient.Gfal2Context:
    with_dcap(ctx)
    ctx.set_opt_integer(GROUP, "OPERATION_TIMEOUT", 20)
    return ctx


@pytest.fixture
def gsi_door(root: Path, pki: PKI) -> Iterator[DcapServer]:
    with DcapServer(root, gsi=pki.server_context()) as server:
        yield server


def test_gsidcap_namespace_and_io(
    gctx: xgfalclient.Gfal2Context, gsi_door: DcapServer, root: Path
) -> None:
    url = gsi_door.url("/data/hello.txt", host="localhost")
    assert url.startswith("gsidcap://localhost:")
    assert gctx.stat(url).st_size == 12
    assert "hello.txt" in gctx.listdir(gsi_door.url("/data", host="localhost"))
    with gctx.open(url, "r") as handle:
        assert handle.read_bytes(100) == b"hello world\n"
    with gctx.open(gsi_door.url("/data/new", host="localhost"), "w") as handle:
        handle.write(b"over gsi")
    assert (root / "data" / "new").read_bytes() == b"over gsi"
    assert gsi_door.connections == 1
    # the wire name keeps the tunnel prefix, as libdcap's get_url_string does
    assert gsi_door.log[1] == f'1 0 client stat "gsidcap://localhost/data/hello.txt" -uid={_uid()}'


def _uid() -> int:
    from xgfalclient.plugins.dcap.control import UID

    return UID


def test_gsidcap_tls12(gctx: xgfalclient.Gfal2Context, root: Path, pki: PKI) -> None:
    context = pki.server_context()
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    with DcapServer(root, gsi=context) as server:
        assert gctx.stat(server.url("/data/hello.txt", host="localhost")).st_size == 12


def test_gsidcap_host_mismatch(gctx: xgfalclient.Gfal2Context, gsi_door: DcapServer) -> None:
    with pytest.raises(GError) as info:
        gctx.stat(gsi_door.url("/data/hello.txt"))  # 127.0.0.1 is not in the certificate's CN
    assert info.value.code == errno.EACCES
    assert "GSI authentication" in info.value.message


def test_gsidcap_untrusted_door(gctx: xgfalclient.Gfal2Context, root: Path, tmp_path: Path) -> None:
    stranger = create_pki(tmp_path / "other", key_slots=(5, 6, 7))
    with DcapServer(root, gsi=stranger.server_context(require_client=False)) as server:
        assert code_of(gctx.stat, server.url("/data/hello.txt", host="localhost")) == errno.EACCES


@pytest.mark.parametrize("reply", [b"garbage\n", b"enc !!!notbase64\n"])
def test_gsidcap_broken_framing(
    gctx: xgfalclient.Gfal2Context, gsi_door: DcapServer, reply: bytes
) -> None:
    gsi_door.handshake_reply = reply
    assert code_of(gctx.stat, gsi_door.url("/data/f", host="localhost")) == errno.EPROTO


def test_gsidcap_undecryptable_token(gctx: xgfalclient.Gfal2Context, gsi_door: DcapServer) -> None:
    gsi_door.inject("stat", Raw(b"enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"))
    assert code_of(gctx.stat, gsi_door.url("/data/f", host="localhost")) == errno.EPROTO


def test_gsidcap_without_credentials(
    ctx: xgfalclient.Gfal2Context, gsi_door: DcapServer, pki: PKI, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not hasattr(ssl, "VERIFY_ALLOW_PROXY_CERTS"):
        pytest.skip("the 3.9 test door cannot ask for a client certificate")
    monkeypatch.setenv("X509_CERT_DIR", str(pki.ca_dir))
    with_dcap(ctx)
    # Under TLS 1.3 the door refuses the missing certificate after the client
    # thinks the handshake is done, so it is the "hello" that fails.
    with pytest.raises(GError) as info:
        ctx.stat(gsi_door.url("/data/f", host="localhost"))
    assert info.value.code in (errno.EACCES, errno.EIO, errno.ECONNRESET)


class SplittingLink(TokenLink):
    """Talks to a server context in memory, handing its tokens over in halves."""

    def __init__(self, server: SecurityContext) -> None:
        self.server = server
        self.pending: list[bytes] = []

    def send_token(self, token: bytes) -> None:
        reply = self.server.step(token)
        if reply:
            half = len(reply) // 2
            self.pending += [reply[:half], reply[half:]]

    def read_token(self) -> bytes:
        return self.pending.pop(0)


def test_gsi_tunnel_with_fragmented_tokens(pki: PKI, grid_env: PKI) -> None:
    client = ssl.create_default_context(cafile=str(pki.ca_file))
    client.check_hostname = False
    client.load_cert_chain(str(pki.proxy_path))
    server = SecurityContext(pki.server_context(), server_side=True)
    gsi = tunnel.GSITunnel(client)
    gsi.handshake(SplittingLink(server), "localhost")
    assert server.unwrap(gsi.wrap(b"line\n")) == b"line\n"


# -- a tunnel of one's own (how kdcap plugs in) ------------------------------------------------


class Rot13(Tunnel):
    """A toy mechanism: two-token handshake, then bytes XOR-ed with 13."""

    def __init__(self, server: bool = False) -> None:
        self.server = server

    def handshake(self, link: TokenLink, host: str) -> None:
        if self.server:
            assert link.read_token() == b"HELLO " + host.encode()
            link.send_token(b"WELCOME")
        else:
            link.send_token(b"HELLO " + host.encode())
            assert link.read_token() == b"WELCOME"

    def wrap(self, data: bytes) -> bytes:
        return bytes(byte ^ 13 for byte in data)

    def unwrap(self, token: bytes) -> bytes:
        return bytes(byte ^ 13 for byte in token)


@pytest.fixture
def no_kerberos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tunnel, "kerberos_module", lambda: None)


def test_registered_tunnel(ctx: xgfalclient.Gfal2Context, root: Path, no_kerberos: None) -> None:
    assert KdcapPlugin.available() == tunnel.KERBEROS_HINT
    register_tunnel("kdcap", lambda plugin, url: Rot13())
    try:
        assert KdcapPlugin.available() is None
        kdcap = ctx.add_plugin(KdcapPlugin)
        with DcapServer(root, tunnel=lambda: Rot13(server=True), scheme="kdcap") as server:
            server_url = server.url("/data/hello.txt", host="127.0.0.1")
            assert server_url.startswith("kdcap://")
            assert kdcap.stat(server_url).st_size == 12
            handle = kdcap.open(server_url, 0)
            assert handle.read(100) == b"hello world\n"
            handle.close()
            assert server.log[1].startswith('1 0 client stat "kdcap://127.0.0.1/data/hello.txt"')
    finally:
        register_tunnel("kdcap", None)
        register_tunnel("kdcap", None)  # removing twice is harmless
    assert KdcapPlugin.available() == tunnel.KERBEROS_HINT
    assert tunnel.unavailable("dcap") is None
    assert tunnel.unavailable("gsidcap") is None


def test_missing_gsi_tunnel() -> None:
    register_tunnel("gsidcap", None)
    try:
        assert tunnel.unavailable("gsidcap") == "gsidcap:// has no authentication tunnel installed"
        with pytest.raises(GError) as info:
            tunnel.tunnel_factory("gsidcap")
        assert info.value.code == errno.EPROTONOSUPPORT
    finally:
        register_tunnel("gsidcap", tunnel._gsi)


def test_incomplete_kerberos_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tunnel, "kerberos_module", lambda: object())
    assert tunnel.unavailable("kdcap") == tunnel.KERBEROS_HINT


def test_kerberos_module_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = object()
    monkeypatch.setattr(tunnel.importlib, "import_module", lambda name: sentinel)
    assert tunnel.kerberos_module() is sentinel

    def missing(name: str) -> object:
        raise ImportError(name)

    monkeypatch.setattr(tunnel.importlib, "import_module", missing)
    assert tunnel.kerberos_module() is None


class FakeKrb5:
    """What ``xgfalclient.crypto.krb5`` offers, reduced to a toy."""

    reason: str | None = None
    fail_step: BaseException | None = None
    fail_unwrap: BaseException | None = None
    closed = 0

    @classmethod
    def available(cls) -> str | None:
        return cls.reason

    class ClientContext:
        def __init__(self, service: str, host: str) -> None:
            self.name = f"{service}@{host}".encode()
            self.complete = False

        def step(self, token: bytes) -> bytes:
            if FakeKrb5.fail_step is not None:
                raise FakeKrb5.fail_step
            if not token:
                return b"AP-REQ " + self.name
            assert token == b"AP-REP"
            self.complete = True
            return b""

        def wrap(self, data: bytes, confidential: bool = True) -> bytes:
            return bytes(byte ^ 42 for byte in data)

        def unwrap(self, token: bytes) -> bytes:
            if FakeKrb5.fail_unwrap is not None:
                raise FakeKrb5.fail_unwrap
            return bytes(byte ^ 42 for byte in token)

        def close(self) -> None:
            FakeKrb5.closed += 1


class FakeAcceptor(Tunnel):
    def handshake(self, link: TokenLink, host: str) -> None:
        assert link.read_token() == b"AP-REQ host@127.0.0.1"
        link.send_token(b"AP-REP")

    def wrap(self, data: bytes) -> bytes:
        return bytes(byte ^ 42 for byte in data)

    def unwrap(self, token: bytes) -> bytes:
        return bytes(byte ^ 42 for byte in token)


@pytest.fixture
def krb5(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[FakeKrb5]]:
    monkeypatch.setattr(tunnel, "kerberos_module", lambda: FakeKrb5)
    yield FakeKrb5
    FakeKrb5.reason = FakeKrb5.fail_step = FakeKrb5.fail_unwrap = None


@pytest.fixture
def kdoor(root: Path) -> Iterator[DcapServer]:
    with DcapServer(root, tunnel=FakeAcceptor, scheme="kdcap") as server:
        yield server


def test_kdcap_through_krb5(
    ctx: xgfalclient.Gfal2Context, krb5: type[FakeKrb5], kdoor: DcapServer
) -> None:
    assert KdcapPlugin.available() is None
    kdcap = ctx.add_plugin(KdcapPlugin)
    assert kdcap.stat(kdoor.url("/data/hello.txt")).st_size == 12
    assert "hello.txt" in [name for name, _ in kdcap.opendir(kdoor.url("/data"))]


def test_kdcap_mechanism_unavailable(ctx: xgfalclient.Gfal2Context, krb5: type[FakeKrb5]) -> None:
    krb5.reason = "libgssapi_krb5.so.2 not found"
    assert KdcapPlugin.available() == f"{tunnel.KERBEROS_HINT} (libgssapi_krb5.so.2 not found)"
    kdcap = ctx.add_plugin(KdcapPlugin)
    with pytest.raises(GError) as info:
        kdcap.stat("kdcap://door/f")
    assert info.value.code == errno.EPROTONOSUPPORT
    assert "libgssapi_krb5" in info.value.message


@pytest.mark.parametrize(
    ("step", "unwrap", "code"),
    [
        (RuntimeError("no ticket"), None, errno.EACCES),
        (GError("expired", errno.EPERM), None, errno.EPERM),
        (None, RuntimeError("bad MIC"), errno.EPROTO),
        (None, GError("replay", errno.EBADMSG), errno.EBADMSG),
    ],
)
def test_kdcap_failures(
    ctx: xgfalclient.Gfal2Context,
    krb5: type[FakeKrb5],
    kdoor: DcapServer,
    step: BaseException | None,
    unwrap: BaseException | None,
    code: int,
) -> None:
    kdcap = ctx.add_plugin(KdcapPlugin)
    krb5.fail_step = step
    if unwrap is not None:
        kdcap.stat(kdoor.url("/data/hello.txt"))  # a connection, established
        krb5.fail_unwrap = unwrap
    assert code_of(kdcap.stat, kdoor.url("/data/hello.txt")) == code


def test_kdcap_with_the_real_krb5_module(
    ctx: xgfalclient.Gfal2Context, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """kdcap through :mod:`xgfalclient.crypto.krb5` over the fake GSS-API library."""
    import sys

    from krb5_fakes import fake_gssapi_module
    from xgfalclient.crypto import krb5
    from xgfalclient.testing.dcap import ServerKerberosTunnel

    monkeypatch.setitem(sys.modules, "gssapi", fake_gssapi_module())
    monkeypatch.setenv(krb5.BACKEND_ENV, "ctypes")
    krb5.reset()
    try:
        assert krb5.available() is None
        assert KdcapPlugin.available() is None
        kdcap = ctx.add_plugin(KdcapPlugin)
        with DcapServer(root, tunnel=ServerKerberosTunnel, scheme="kdcap") as server:
            url = server.url("/data/hello.txt")
            assert kdcap.stat(url).st_size == 12
            handle = kdcap.open(url, 0)
            assert handle.read(100) == b"hello world\n"
            handle.close()
        kdcap.close()
    finally:
        krb5.reset()


def test_kerberos_tunnel_edges() -> None:
    class Broken:
        @staticmethod
        def ClientContext(service: str, host: str) -> object:
            raise RuntimeError("no credentials cache")

    krb = tunnel.KerberosTunnel(Broken)
    with pytest.raises(GError) as info:
        krb.handshake(SplittingLink(None), "door")  # type: ignore[arg-type]
    assert info.value.code == errno.EACCES
    krb.close()  # nothing to release


def test_tunnel_interfaces_are_unimplemented() -> None:
    """Every tunnel and link overrides these; the bases only state the shape."""
    link, tun = TokenLink(), Tunnel()
    for call in (
        lambda: link.send_token(b"x"),
        link.read_token,
        lambda: tun.handshake(link, "door.example.org"),
        lambda: tun.wrap(b"x"),
        lambda: tun.unwrap(b"x"),
    ):
        with pytest.raises(NotImplementedError):
            call()
    tun.close()
