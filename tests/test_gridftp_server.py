# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""The in-process GridFTP server's own corners: what a well-behaved client never sends."""

from __future__ import annotations

import errno
import functools
import os
import socket
import ssl
import time
from pathlib import Path
from typing import Any

import pytest

import xgfalclient
from test_gridftp_helpers import (  # noqa: F401 - fixtures
    GROUP,
    _fast_polls,
    code_of,
    ftp,
    gctx,
    gsi,
    write,
)
from xgfalclient.crypto.rsa import private_key_pem
from xgfalclient.crypto.x509 import (
    build_certificate,
    encode_name,
    parse_certificate,
    public_key_info,
)
from xgfalclient.plugins.gridftp import control as control_module
from xgfalclient.plugins.gridftp.control import Control
from xgfalclient.plugins.gridftp.data import DataConn, Ranges, send_blocks
from xgfalclient.plugins.gridftp.gsi import GlobusContext
from xgfalclient.plugins.gridftp.protocol import parse_pasv
from xgfalclient.testing import gridftp as server_module
from xgfalclient.testing.gridftp import GridFTPServer
from xgfalclient.testing.pki import PKI, test_key

Ctx = xgfalclient.Gfal2Context


def raw(server: GridFTPServer, login: bool = True) -> Control:
    control = Control(server.host, server.port, timeout=5)
    control.connect()
    if login:
        control.login("anonymous", "x")
    return control


def answer(control: Control, command: str) -> str:
    control.send(command)
    return str(control.reply())


def test_pre_login_and_unknown_commands(ftp: GridFTPServer) -> None:
    control = raw(ftp, login=False)
    assert answer(control, "PWD").startswith("530 Please login")
    assert answer(control, "PASS x").startswith("503 Login with USER first")
    assert answer(control, "AUTH GSSAPI").startswith("504")  # not a GSI server
    assert answer(control, "ADAT AAAA").startswith("503 You must issue the AUTH")
    assert answer(control, "USER mallory").startswith("331")
    assert answer(control, "PASS x").startswith("530 Login incorrect")
    assert answer(control, "XYZZY").startswith("500 Invalid command")
    assert answer(control, "SYST") == "215 UNIX Type: L8"
    assert answer(control, "NOOP").startswith("200")


def test_session_settings(ftp: GridFTPServer) -> None:
    (Path(ftp.root) / "sub").mkdir()
    control = raw(ftp)
    assert answer(control, "PWD") == '257 "/" is current directory.'
    assert answer(control, "CWD sub").startswith("250")
    assert answer(control, "PWD") == '257 "/sub" is current directory.'
    assert answer(control, "CWD nope").startswith("550")
    assert answer(control, "TYPE X").startswith("504")
    assert answer(control, "MODE B").startswith("504")
    assert answer(control, "DCAU A").startswith("504")
    assert answer(control, "DCAU S").startswith("504")
    assert answer(control, "PROT P").startswith("536")
    assert answer(control, "PROT S").startswith("536")
    assert answer(control, "PROT C").startswith("200")
    assert answer(control, "PBSZ 0") == "200 PBSZ=0"
    assert answer(control, "OPTS FOO bar").startswith("501")
    assert answer(control, "OPTS RETR StripeLayout=Blocked;").startswith("501")
    assert answer(control, "OPTS PASV AllowSomething=1;").startswith("501")
    assert answer(control, "SITE CHMOD 0644 /nope").startswith("550")
    assert answer(control, "SITE HELP").startswith("500")
    assert answer(control, "ABOR").startswith("226")
    assert answer(control, "RNTO /x").startswith("501 Invalid command arguments")
    assert answer(control, "ERET X 0 1 /f").startswith("501")
    assert answer(control, "RETR /f").startswith("500")  # no such file, before any channel
    write(Path(ftp.root) / "f", b"0123456789")
    assert answer(control, "RETR /f").startswith("425 Use PORT or PASV first")
    assert answer(control, "MDTM /f").startswith("213 ")
    assert answer(control, "MDTM /nope").startswith("550")
    assert answer(control, "SIZE /sub").startswith("550")
    assert answer(control, "SIZE /nope").startswith("550")
    assert answer(control, "CKSM CRC32 0 -1 /f") == "213 a684c7c6"
    assert answer(control, "CKSM ADLER32 0 -1 /nope").startswith("550")
    control.close()


def _passive_fetch(control: Control, command: str) -> bytes:
    host, port = parse_pasv(control.command("PASV").text)
    sock = socket.create_connection((host, port))
    control.send(command)
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    sock.close()
    control.final()
    return b"".join(chunks)


def test_listings(ftp: GridFTPServer) -> None:
    write(Path(ftp.root) / "d" / "f", b"abc")
    control = raw(ftp)
    listing = _passive_fetch(control, "LIST /d").decode()
    assert listing.splitlines()[-1].endswith(" 3 " + listing.splitlines()[-1].split(" 3 ")[1])
    assert listing.splitlines()[-1].startswith("-rw")
    assert _passive_fetch(control, "LIST /d/f").decode().strip().endswith(" f")
    assert _passive_fetch(control, "NLST /d/f") == b"f\r\n"
    assert _passive_fetch(control, "NLST") == b".\r\n..\r\nd\r\n"  # the current directory
    assert answer(control, "LIST /nope").startswith("550")


def test_active_connect_failure(ftp: GridFTPServer) -> None:
    write(Path(ftp.root) / "f", b"x")
    probe = socket.create_server(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    control = raw(ftp)
    control.command(f"PORT 127,0,0,1,{port // 256},{port % 256}")
    control.send("RETR /f")
    assert control.reply().code == 150
    assert control.reply().code == 425


def test_passive_timeout(ftp: GridFTPServer, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server_module, "DATA_TIMEOUT", 0.2)
    write(Path(ftp.root) / "f", b"x")
    control = raw(ftp)
    control.command("MODE E")
    control.command("PASV")
    control.send("STOR /g")
    assert control.reply().code == 150
    assert str(control.reply()).startswith("425 Can't open data connection: timed out")


@pytest.mark.parametrize("protection", ["DCAU A", "PROT P"])  # authenticated, or encrypted too
def test_dcau_peer_that_does_not_authenticate(
    gsi: GridFTPServer, grid_env: PKI, gctx: Ctx, protection: str
) -> None:
    from test_gridftp_control import gsi_control

    write(Path(gsi.root) / "f", b"x")
    control = gsi_control(gsi, grid_env, gctx)
    control.command(protection)
    host, port = parse_pasv(control.command("PASV").text)
    socket.create_connection((host, port)).close()
    control.send("RETR /f")
    assert control.reply().code == 150
    assert control.reply().code == 425


def test_protection_is_enforced(gsi: GridFTPServer, grid_env: PKI, gctx: Ctx) -> None:
    from test_gridftp_control import gsi_control

    control = Control(gsi.host, gsi.port, timeout=5)
    control.connect()
    assert answer(control, "USER :globus-mapping:").startswith("530 Must perform GSSAPI")
    assert answer(control, "AUTH TLS").startswith("504")  # GSSAPI is all it speaks
    control.command("AUTH GSSAPI", ok=(3,))
    assert answer(control, "ADAT A").startswith("535")
    control = gsi_control(gsi, grid_env, gctx)
    assert control.sock is not None
    control.sock.sendall(b"PWD\r\n")
    assert control.reply().code == 533
    control.security = control.security  # still in step
    token = control.security.wrap(b"PWD\r\n")  # type: ignore[union-attr]
    import base64

    control.sock.sendall(b"MIC " + base64.b64encode(token) + b"\r\n")
    assert control.reply().code == 257


def test_perf_markers_while_waiting(gctx: Ctx, tmp_path: Path) -> None:
    root = tmp_path / "r"
    data = os.urandom(3_000_000)
    write(root / "f", data)
    with GridFTPServer(root, perf_interval=0.0001, block_size=1024) as server:
        params = gctx.transfer_parameters()
        params.nbstreams = 2
        target = tmp_path / "out"
        gctx.filecopy(params, server.url("/f"), "file://" + str(target))
        assert target.read_bytes() == data


def test_stop_breaks_sessions(tmp_path: Path) -> None:
    server = GridFTPServer(tmp_path).start()
    control = raw(server)
    server.stop()
    time.sleep(0.05)
    code, _ = code_of(lambda: control.command("NOOP"))
    assert code == errno.ECONNRESET
    assert server.url("/x") == f"ftp://localhost:{server.port}/x"


def test_client_abandons_a_download(ftp: GridFTPServer) -> None:
    write(Path(ftp.root) / "big", os.urandom(20_000_000))
    control = raw(ftp)
    host, port = parse_pasv(control.command("PASV").text)
    sock = socket.create_connection((host, port))
    control.send("RETR /big")
    assert control.reply().code == 150
    sock.recv(1000)
    sock.close()
    assert control.reply().code == 426


def test_append_after_rest(ftp: GridFTPServer) -> None:
    target = write(Path(ftp.root) / "f", b"0123456789")
    control = raw(ftp)
    control.command("REST 4", ok=(3,))
    host, port = parse_pasv(control.command("PASV").text)
    sock = socket.create_connection((host, port))
    control.send("STOR /f")
    assert control.reply().code == 150
    sock.sendall(b"XY")
    sock.close()
    control.final()
    assert target.read_bytes() == b"0123XY6789"  # written in place, not truncated


def test_errors_without_an_errno(ftp: GridFTPServer, monkeypatch: pytest.MonkeyPatch) -> None:
    """An ``OSError`` that names no ``errno`` is reported as ``EIO``."""
    write(Path(ftp.root) / "f", b"x")
    local = os.path.join(ftp.root, "f")
    real_open, real_chmod = os.open, os.chmod

    def fake_open(path: str, *args: Any, **kwargs: Any) -> int:
        if path == local:
            raise OSError("the disk said no")
        return real_open(path, *args, **kwargs)

    def fake_chmod(path: str, *args: Any, **kwargs: Any) -> None:
        if path == local:
            raise OSError("the disk said no")
        real_chmod(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "chmod", fake_chmod)
    control = raw(ftp)
    retr = answer(control, "RETR /f")
    assert retr.startswith("500") and os.strerror(errno.EIO) in retr
    chmod = answer(control, "SITE CHMOD 0644 /f")
    assert chmod.startswith("451") and f"GridFTP-Errno: {errno.EIO}" in chmod
    control.close()


def _minted(pki: PKI, directory: Path, subject: tuple[tuple[str, str], ...]) -> ssl.SSLContext:
    """A client context presenting a certificate for ``subject``, signed by the CA."""
    key = test_key(5)
    certificate = parse_certificate(
        build_certificate(
            subject=encode_name(subject),
            issuer=pki.ca.subject.encoded(),
            public_key=public_key_info(key.public),
            signer=pki.ca_key,
            not_before=time.time() - 300,
            not_after=time.time() + 3600,
        )
    )
    pem = directory / "minted.pem"
    pem.write_bytes(certificate.pem() + private_key_pem(key))
    context = ssl.create_default_context(cafile=str(pki.ca_file))
    context.check_hostname = False
    context.load_cert_chain(str(pem))
    return context


@pytest.mark.parametrize(
    ("subject", "dn"),
    [
        # A trailing CN=proxy is a legacy proxy's, and not part of the identity.
        (
            (("DC", "org"), ("DC", "xgfal"), ("CN", "Alice"), ("CN", "proxy")),
            "/DC=org/DC=xgfal/CN=Alice",
        ),
        ((("DC", "org"), ("DC", "xgfal"), ("OU", "robots")), "/DC=org/DC=xgfal/OU=robots"),
    ],
)
def test_identity_from_the_client_certificate(
    pki: PKI, tmp_path: Path, subject: tuple[tuple[str, str], ...], dn: str
) -> None:
    tls = _minted(pki, tmp_path, subject)
    with GridFTPServer(tmp_path, gsi=pki.server_context(), gridmap={dn: "mapped"}) as server:
        control = Control(server.host, server.port, timeout=5)
        control.connect()
        control.authenticate(tls, None)
        assert answer(control, "USER :globus-mapping:").startswith("331")
        assert answer(control, "PASS x") == "230 User mapped logged in."
        control.close()


def test_anonymous_client_that_does_not_wait_for_the_turn(
    pki: PKI, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No client certificate: an empty identity. A client that sends its delegation
    flag with its ``Finished`` (as dCache's doors expect) gets the turn in ``235``."""
    monkeypatch.setattr(
        control_module, "GlobusContext", functools.partial(GlobusContext, turn=False)
    )
    tls = ssl.create_default_context(cafile=str(pki.ca_file))
    tls.check_hostname = False
    context = pki.server_context(require_client=False)
    with GridFTPServer(tmp_path, gsi=context, gridmap={"": "nobody"}) as server:
        control = Control(server.host, server.port, timeout=5)
        control.connect()
        control.authenticate(tls, None)
        assert answer(control, "USER :globus-mapping:").startswith("331")
        assert answer(control, "PASS x") == "230 User nobody logged in."
        control.close()


def test_active_mode_e_upload(ftp: GridFTPServer) -> None:
    """The server connects out and receives blocks on the connections it opened."""
    data = b"0123456789"

    def read(view: memoryview, offset: int) -> int:
        chunk = data[offset : offset + len(view)]
        view[: len(chunk)] = chunk
        return len(chunk)

    control = raw(ftp)
    control.command("MODE E")
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]
        control.command(f"PORT 127,0,0,1,{port // 256},{port % 256}")
        control.send("STOR /g")
        assert control.reply().code == 150
        sock, _ = listener.accept()
    with sock:
        send_blocks(DataConn(sock), read, Ranges(0, len(data), 4), lambda n: None, 4, 1)
    control.final()
    assert (Path(ftp.root) / "g").read_bytes() == data
    control.close()
