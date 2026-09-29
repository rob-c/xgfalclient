# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""The control channel: replies, protection, login - including what servers get wrong."""

from __future__ import annotations

import base64
import errno
import socket
import struct
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from test_gridftp_helpers import (  # noqa: F401 - fixtures
    FakeServer,
    _fast_polls,
    code_of,
    ftp,
    gctx,
    gsi,
    lines,
    write,
)
from xgfalclient.errors import ECOMM
from xgfalclient.plugins.gridftp import control as control_module
from xgfalclient.plugins.gridftp.control import Control, connect_error
from xgfalclient.testing.gridftp import GridFTPServer
from xgfalclient.testing.pki import PKI

Ctx = xgfalclient.Gfal2Context


def logged_in(server: GridFTPServer) -> Control:
    control = Control(server.host, server.port, timeout=5)
    control.connect()
    control.login("anonymous", "x")
    return control


def gsi_control(server: GridFTPServer, pki: PKI, gctx: Ctx) -> Control:
    control = Control(server.host, server.port, timeout=5)
    control.connect()
    tls = gctx.ssl_context(server.url(), group="GRIDFTP PLUGIN", check_hostname=False)
    control.authenticate(tls, pki.credential())
    control.login(":globus-mapping:", "dummy")
    return control


def test_connect_error_mapping() -> None:
    assert connect_error(socket.timeout("slow"), "h", 1).code == errno.ETIMEDOUT
    unknown = connect_error(socket.gaierror(8, "nodename nor servname"), "h", 1)
    assert unknown.code == errno.EHOSTUNREACH
    assert unknown.message == "globus_xio: Unable to connect to h:1 nodename nor servname"
    assert connect_error(OSError(), "h", 1).code == errno.ECONNREFUSED


def test_unwelcome_greeting() -> None:
    fake = FakeServer(lambda sock: sock.sendall(b"421 Too many users\r\n"))
    control = Control("127.0.0.1", fake.port, timeout=5)
    with pytest.raises(xgfalclient.GError) as caught:
        control.connect()
    assert caught.value.code == ECOMM and control.broken
    control.close()
    control.close()  # already closed: nothing to do
    fake.join()


def test_multiline_and_unprotected_replies(ftp: GridFTPServer) -> None:
    control = logged_in(ftp)
    assert control.supports("MLST") and "ALLOWDELAYED" in control.features["PASV"].upper()
    reply = control.command("FEAT")
    assert reply.lines[0] == "211-Extensions supported" and reply.lines[-1] == "211 End."
    control.setting("TYPE", "I")
    control.setting("TYPE", "I")
    assert ftp.log.count("TYPE I") == 1
    assert control.healthy()
    ftp.faults["NOOP"] = "raw:hello there"
    code, message = code_of(lambda: control.command("NOOP"))
    assert code == errno.EPROTO and "Malformed reply" in message
    assert not control.healthy()
    control.close()


class _Cleartext:
    """A security context that protects nothing: ``631`` replies carry plain text."""

    def unwrap(self, data: bytes) -> bytes:
        return data


def test_healthy_only_when_in_step() -> None:
    """A session is reused only with nothing of a reply left over, whole or in part."""
    assert not Control("127.0.0.1", 1, timeout=5).healthy()  # never connected
    wrapped = base64.b64encode(b"200 one\r\n200 two\r\n").decode()

    def script(sock: socket.socket) -> None:
        sock.sendall(f"220 hi\r\n631 {wrapped}\r\n".encode())
        commands = lines(sock)
        next(commands)
        sock.sendall(b"200-first part\r\n")
        next(commands, None)

    fake = FakeServer(script)
    control = Control("127.0.0.1", fake.port, timeout=5)
    control.connect()
    assert not control.healthy()  # the 631 is still in the buffer
    control.security = _Cleartext()  # type: ignore[assignment]
    assert control.reply().text == "one"
    assert not control.healthy()  # "200 two" came in the same token
    assert control.reply().text == "two"
    control.security = None
    control.send("NOOP")
    assert control.poll(0.2) is None
    assert not control.healthy()  # half a multi-line reply
    control.close()
    fake.join()


def test_reply_line_too_long(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(control_module, "MAX_LINE", 100)
    fake = FakeServer(lambda sock: sock.sendall(b"220-" + b"x" * 70000))
    control = Control("127.0.0.1", fake.port, timeout=5)
    code, message = code_of(control.connect)
    assert code == errno.EPROTO and "too long" in message
    fake.join()


def test_reply_timeout(ftp: GridFTPServer) -> None:
    control = logged_in(ftp)
    control.timeout = 0.2
    ftp.faults["NOOP"] = "hang"
    code, message = code_of(lambda: control.command("NOOP"))
    assert code == errno.ETIMEDOUT and "0.2 seconds" in message
    assert control.broken


def test_server_hangs_up(ftp: GridFTPServer) -> None:
    control = logged_in(ftp)
    ftp.faults["NOOP"] = "close"
    code, message = code_of(lambda: control.command("NOOP"))
    assert code == errno.ECONNRESET and "closed by the server" in message
    control.close()


def test_connection_reset() -> None:
    def script(sock: socket.socket) -> None:
        sock.sendall(b"220 hello\r\n")
        next(lines(sock))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))

    fake = FakeServer(script)
    control = Control("127.0.0.1", fake.port, timeout=5)
    control.connect()
    code, message = code_of(lambda: control.command("NOOP"))
    assert code == errno.ECONNRESET and "lost" in message
    fake.join()


def test_send_on_a_dead_socket(ftp: GridFTPServer) -> None:
    control = logged_in(ftp)
    assert control.sock is not None
    control.sock.close()
    code, _ = code_of(lambda: control.send("NOOP"))
    assert code == errno.ECONNRESET and control.broken


def test_login_variants(ftp: GridFTPServer) -> None:
    ftp.faults["USER"] = "230 Welcome, no password needed."
    ftp.faults["FEAT"] = "500 FEAT? never heard of it"
    control = Control(ftp.host, ftp.port, timeout=5)
    control.connect()
    control.login("anonymous", "x")
    assert control.features == {} and "PASS x" not in ftp.log
    assert not control.supports("MLST")


def test_quit_on_close(ftp: GridFTPServer) -> None:
    control = logged_in(ftp)
    control.close()
    assert ftp.log[-1] == "QUIT"


def test_gsi_protected_replies(gsi: GridFTPServer, grid_env: PKI, gctx: Ctx) -> None:
    control = gsi_control(gsi, grid_env, gctx)
    assert control.security is not None
    reply = control.command("FEAT")  # every line wrapped on its own
    assert reply.lines[-1] == "211 End."
    gsi.faults["NOOP"] = "raw:200 plain, even though protected"
    assert control.command("NOOP").text == "plain, even though protected"
    gsi.faults["NOOP"] = "raw:633"  # nothing to unwrap: an ordinary (odd) reply
    code, message = code_of(lambda: control.command("NOOP"))
    assert "633" in message
    bogus = base64.b64encode(b"\x17\x03\x03\x00\x20" + b"\x00" * 32).decode()
    gsi.faults["NOOP"] = f"raw:632 {bogus}"
    code, message = code_of(lambda: control.command("NOOP"))
    assert code == errno.EPROTO and "unwrap" in message


@pytest.mark.parametrize(
    ("reply", "needle"),
    [
        ("335 ADAT=", "wants a token"),
        ("235 GSSAPI Authentication successful.", "before the client did"),
        ("335 ADAT=A", "failed"),
    ],
)
def test_gsi_exchange_failures(
    gsi: GridFTPServer, grid_env: PKI, gctx: Ctx, reply: str, needle: str
) -> None:
    gsi.faults["ADAT"] = reply
    code, message = code_of(lambda: gsi_control(gsi, grid_env, gctx))
    assert code == errno.EACCES and needle in message


def test_gsi_client_still_talking(monkeypatch: pytest.MonkeyPatch) -> None:
    """The server says ``235`` while the client's mechanism has a token left to send."""

    class Talkative:
        complete = True

        def __init__(self, tls: object, delegate: object = None) -> None:
            pass

        def step(self, data: bytes | None = None) -> bytes:
            return b"more"

    def script(sock: socket.socket) -> None:
        sock.sendall(b"220 hi\r\n")
        commands = lines(sock)
        next(commands)
        sock.sendall(b"334 Using authentication type GSSAPI\r\n")
        next(commands)
        sock.sendall(b"235 ADAT=eA==\r\n")
        next(commands, None)

    monkeypatch.setattr(control_module, "GlobusContext", Talkative)
    fake = FakeServer(script)
    control = Control("127.0.0.1", fake.port, timeout=5)
    control.connect()
    code, message = code_of(lambda: control.authenticate(None, None))  # type: ignore[arg-type]
    assert code == errno.EACCES and "before the client did" in message
    control.close()
    fake.join()


def test_iterator_helper_is_exhausted_on_close() -> None:
    left, right = socket.socketpair()
    right.sendall(b"ONE\r\n")
    right.close()
    found: Iterator[str] = lines(left)
    assert list(found) == ["ONE"]
    left.close()


def test_server_log_and_path_helpers(ftp: GridFTPServer, tmp_path: Path) -> None:
    write(Path(ftp.root) / "f", b"x")
    control = logged_in(ftp)
    assert control.command("SIZE f").text == "1"
    assert control.peer == control.local == "127.0.0.1"
    assert not control.ipv6
