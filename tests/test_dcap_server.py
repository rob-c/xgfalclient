"""The in-process dcap door itself, driven with raw control lines and data blocks."""

from __future__ import annotations

import base64
import errno
import socket
import struct
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from test_dcap import GROUP, code_of, with_dcap
from xgfalclient.errors import GError
from xgfalclient.plugins.dcap import file
from xgfalclient.plugins.dcap.control import ControlConnection
from xgfalclient.plugins.dcap.file import DataChannel
from xgfalclient.plugins.dcap.protocol import (
    HEADER,
    INT,
    IOCMD_ACK,
    IOCMD_DATA,
    IOCMD_FIN,
    IOCMD_READ,
    IOCMD_SEEK,
    IOCMD_WRITE,
    SEEK_CURRENT,
    SEEK_END,
    parse_reply,
    parse_url,
)
from xgfalclient.testing.dcap import DcapServer


@pytest.fixture
def root(tmp_path: Path) -> Path:
    base = tmp_path / "ns"
    (base / "data").mkdir(parents=True)
    (base / "data" / "hello.txt").write_bytes(b"hello world\n")
    return base


@pytest.fixture
def door(root: Path) -> Iterator[DcapServer]:
    with DcapServer(root, accept_timeout=2) as server:
        yield server


def connect(door: DcapServer) -> ControlConnection:
    return ControlConnection.open(parse_url(door.url("/")), None, 10)


def ask(conn: ControlConnection, line: str) -> str:
    conn.send_line(line)
    return conn.read_line()


def open_passive(conn: ControlConnection, door: DcapServer, name: str, mode: str) -> DataChannel:
    """Open ``name`` and connect to the mover the way the plugin does."""
    reply = parse_reply(
        ask(conn, f'1 0 client open "{door.url(name)}" {mode} 127.0.0.1 1 -passive')
    )
    assert reply is not None and reply.verb == "connect"
    host, port, challenge = reply.args
    sock = socket.create_connection((host, int(port)), timeout=10)
    sock.sendall(HEADER.pack(1, len(challenge)) + challenge.encode())
    return DataChannel(sock)


def test_door_verbs(door: DcapServer) -> None:
    conn = connect(door)
    assert ask(conn, "5 0 client ping") == "5 0 server pong"
    assert ask(conn, "6 0 client frobnicate x") == (
        "6 0 client failed 669 \"protocolViolation : Invalid command 'frobnicate'\""
    )
    conn.send_line("too short")
    assert ask(conn, "7 0 client ping") == "7 0 server pong"
    assert door.local("/data/hello.txt").read_bytes() == b"hello world\n"
    conn.send_line("8 0 client byebye")
    with pytest.raises(GError):
        conn.read_line()
    conn.close()


def test_mkdir_default_mode(door: DcapServer) -> None:
    conn = connect(door)
    assert ask(conn, '1 0 client mkdir "/data/plain"') == "1 0 client ok"
    assert (door.local("/data/plain").stat().st_mode & 0o777) == 0o700
    conn.close()


def test_open_without_parent(door: DcapServer) -> None:
    conn = connect(door)
    line = ask(conn, f'1 0 client open "{door.url("/no/such/f")}" w 127.0.0.1 1')
    assert line == '1 0 client failed 1 "Parent directory does not exist" '
    conn.close()


def test_rename_failure(door: DcapServer) -> None:
    conn = connect(door)
    line = ask(conn, f'1 0 client rename "{door.url("/data/hello.txt")}" /missing/dir/x')
    assert line.startswith('1 0 client failed 19 "') and line.endswith("EACCES")
    conn.close()


def test_unknown_fault(door: DcapServer) -> None:
    with pytest.raises(ValueError):
        door.fault("meteor")


def test_mover_extras(door: DcapServer) -> None:
    """SEEK with each whence, a zero-length READ, a bogus command."""
    conn = connect(door)
    channel = open_passive(conn, door, "/data/hello.txt", "r")
    channel.send(struct.pack(">iiqi", 16, IOCMD_SEEK, 6, 0))
    assert channel.expect(IOCMD_ACK, IOCMD_SEEK) == struct.pack(">q", 6)
    channel.send(struct.pack(">iiqi", 16, IOCMD_SEEK, 2, SEEK_CURRENT))
    assert channel.expect(IOCMD_ACK, IOCMD_SEEK) == struct.pack(">q", 8)
    channel.send(struct.pack(">iiqi", 16, IOCMD_SEEK, -3, SEEK_END))
    assert channel.expect(IOCMD_ACK, IOCMD_SEEK) == struct.pack(">q", 9)
    channel.send(struct.pack(">iiq", 12, IOCMD_READ, 0))
    channel.expect(IOCMD_ACK, IOCMD_READ)
    channel.expect(IOCMD_DATA)
    assert channel.receive(memoryview(bytearray(1))) == 0
    channel.expect(IOCMD_FIN, IOCMD_READ)
    channel.send(HEADER.pack(4, 99))
    with pytest.raises(GError) as info:
        channel.expect(IOCMD_ACK, 99)
    assert "Invalid mover command" in info.value.message
    channel.close()
    assert conn.read_line() == "1 0 client ok"  # the door's verdict once the mover is gone
    conn.close()


@pytest.mark.parametrize("abuse", ["not-data", "short-block"])
def test_mover_write_abuse(door: DcapServer, abuse: str) -> None:
    conn = connect(door)
    channel = open_passive(conn, door, "/data/new", "w")
    channel.send(HEADER.pack(4, IOCMD_WRITE))
    channel.expect(IOCMD_ACK, IOCMD_WRITE)
    if abuse == "not-data":
        channel.send(HEADER.pack(4, 5))
    else:
        channel.send(HEADER.pack(4, IOCMD_DATA) + INT.pack(100) + b"x" * 10)
        channel.sock.shutdown(socket.SHUT_WR)
    assert conn.read_line() == "1 0 client ok"
    channel.close()
    conn.close()


def test_passive_mover_ignores_impostors(door: DcapServer) -> None:
    conn = connect(door)
    reply = parse_reply(ask(conn, f'1 0 client open "{door.url("/data/hello.txt")}" r h 1'))
    assert reply is not None
    host, port, challenge = reply.args
    with socket.create_connection((host, int(port))) as impostor:
        impostor.sendall(HEADER.pack(1, 5) + b"wrong")
        assert impostor.recv(1) == b""
    with socket.create_connection((host, int(port))) as stranger:  # someone else's session
        stranger.sendall(HEADER.pack(2, len(challenge)) + challenge.encode())
        assert stranger.recv(1) == b""
    with socket.create_connection((host, int(port))) as quitter:
        quitter.sendall(b"\x00")
    sock = socket.create_connection((host, int(port)), timeout=10)
    sock.sendall(HEADER.pack(1, len(challenge)) + challenge.encode())
    channel = DataChannel(sock)
    channel.send(HEADER.pack(4, 4))
    channel.expect(IOCMD_ACK, 4)
    assert conn.read_line() == "1 0 client ok"
    channel.close()
    conn.close()


def test_passive_mover_gives_up(door: DcapServer) -> None:
    conn = connect(door)
    reply = parse_reply(ask(conn, f'1 0 client open "{door.url("/data/hello.txt")}" r h 1'))
    assert reply is not None and reply.verb == "connect"
    # nobody connects; the mover times out and says nothing more
    time.sleep(2.5)
    assert ask(conn, "2 0 client ping") == "2 0 server pong"
    conn.close()


def test_callback_refused(root: Path) -> None:
    with socket.socket() as spare:
        spare.bind(("127.0.0.1", 0))
        port = spare.getsockname()[1]
    with DcapServer(root, callback=True) as door:
        conn = connect(door)
        conn.send_line(f'1 0 client open "{door.url("/data/hello.txt")}" r 127.0.0.1 {port}')
        conn.send_line(f'2 0 client opendir "{door.url("/data")}" 127.0.0.1 {port}')
        assert ask(conn, "3 0 client ping") == "3 0 server pong"
        conn.close()


def test_client_gone_before_verdict(door: DcapServer) -> None:
    conn = connect(door)
    channel = open_passive(conn, door, "/data/hello.txt", "r")
    conn.close()
    time.sleep(0.2)
    channel.send(HEADER.pack(4, 4))
    channel.expect(IOCMD_ACK, 4)
    channel.close()
    time.sleep(0.2)


def test_listing_abandoned(door: DcapServer, root: Path) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    conn = connect(door)
    conn.send_line(
        f'1 0 client opendir "{door.url("/data")}" 127.0.0.1 {listener.getsockname()[1]}'
    )
    sock, _ = listener.accept()
    assert struct.unpack(">ii", sock.recv(8)) == (1, 0)
    sock.close()  # hang up without asking for anything
    listener.close()
    assert ask(conn, "2 0 client ping") == "2 0 server pong"
    conn.close()


def test_data_timeout(root: Path, ctx: xgfalclient.Gfal2Context) -> None:
    with_dcap(ctx)
    ctx.set_opt_integer(GROUP, "OPERATION_TIMEOUT", 1)
    with DcapServer(root) as door:
        handle = ctx.open(door.url("/data/hello.txt"), "r")
        door.fault("stall")
        assert code_of(handle.read_bytes, 5) == errno.ETIMEDOUT
        handle.close()


def test_double_close(root: Path, ctx: xgfalclient.Gfal2Context) -> None:
    with_dcap(ctx)
    with DcapServer(root) as door:
        handle = ctx.open(door.url("/data/hello.txt"), "r")
        inner = handle._file  # type: ignore[attr-defined]
        inner.close()
        inner.close()
        assert handle.closed


def test_gsi_server_rejects_garbage(root: Path, pki: object) -> None:
    from xgfalclient.testing.pki import PKI

    assert isinstance(pki, PKI)
    with DcapServer(root, gsi=pki.server_context()) as door:  # noqa: SIM117 - 3.9 syntax
        with socket.create_connection(("127.0.0.1", door.port)) as sock:
            sock.sendall(b"enc " + base64.b64encode(b"GET / HTTP/1.0\r\n\r\n") + b"\n")
            sock.settimeout(10)
            assert sock.recv(100) == b""


def test_listing_chunk_constant() -> None:
    assert file.LISTING_CHUNK >= 1 << 16
