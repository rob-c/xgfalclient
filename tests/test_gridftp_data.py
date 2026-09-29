# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""Data-channel pieces in isolation: records, blocks, EOD counting, the transfer loop."""

from __future__ import annotations

import errno
import socket
import threading

import pytest

from test_gridftp_helpers import _fast_polls, code_of, ftp  # noqa: F401 - fixtures
from xgfalclient.errors import GError
from xgfalclient.plugins.gridftp import data
from xgfalclient.plugins.gridftp.control import Control
from xgfalclient.plugins.gridftp.data import (
    BLOCK_HEADER,
    ChannelOptions,
    DataConn,
    DataTransfer,
    EodCounter,
    Ranges,
    read_record,
    recv_blocks,
    recv_exact,
    send_blocks,
)
from xgfalclient.testing.gridftp import GridFTPServer


def pair() -> tuple[socket.socket, socket.socket]:
    return socket.socketpair()


def test_recv_exact_and_records() -> None:
    left, right = pair()
    right.sendall(b"ab")
    right.close()
    with pytest.raises(GError, match="middle of a record"):
        recv_exact(left, memoryview(bytearray(4)))
    left.close()
    left, right = pair()
    right.sendall(b"\x17\x03\x03\x00\x05ab")
    right.close()
    with pytest.raises(GError, match="middle of a record"):
        read_record(left)
    left.close()
    left, right = pair()
    right.sendall(b"\x17\x03\x03\x00\x05")
    right.close()
    with pytest.raises(GError, match="middle of a record"):
        read_record(left)
    left.close()
    left, right = pair()
    right.sendall(b"\x17\x03\x03\x00\x00")
    right.close()
    assert read_record(left) == b"\x17\x03\x03\x00\x00"
    assert read_record(left) == b""


def test_block_receiver_edges() -> None:
    written: list[tuple[bytes, int]] = []

    def write(view: memoryview, offset: int) -> None:
        written.append((bytes(view), offset))

    left, right = pair()
    right.sendall(BLOCK_HEADER.pack(0, 10, 100) + b"12345")
    right.close()
    with pytest.raises(GError, match="middle of a block"):
        recv_blocks(DataConn(left), write, 4, lambda n: None, EodCounter())
    assert written == [(b"1234", 100)]
    left, right = pair()
    right.sendall(BLOCK_HEADER.pack(0, 10, 100) + b"1234")
    right.close()
    with pytest.raises(GError, match="middle of a block"):
        recv_blocks(DataConn(left), write, 4, lambda n: None, EodCounter())
    left, right = pair()
    right.sendall(BLOCK_HEADER.pack(0, 0, 0)[:5])
    right.close()
    with pytest.raises(GError, match="middle of a block"):
        recv_blocks(DataConn(left), write, 4, lambda n: None, EodCounter())


def test_eod_counting() -> None:
    eods = EodCounter()
    eods.eod()
    assert not eods.done.is_set()
    eods.eof(2)
    assert not eods.done.is_set()
    eods.eod()
    assert eods.done.is_set()


def test_ranges() -> None:
    ranges = Ranges(10, 25, 10)
    assert [ranges.take(), ranges.take(), ranges.take()] == [(10, 10), (20, 5), None]


def test_short_source_read() -> None:
    left, right = pair()
    with pytest.raises(GError, match="Short read") as caught:
        send_blocks(DataConn(left), lambda view, offset: 1, Ranges(0, 10, 10), lambda n: None, 10)
    assert caught.value.code == errno.EIO
    right.close()


def test_finish_twice() -> None:
    left, right = pair()
    conn = DataConn(left)
    conn.finish()
    conn.finish()  # shutting down a closed socket is not an error here
    right.close()


def test_as_gerror() -> None:
    same = GError("x", 1)
    assert data._as_gerror(same) is same
    assert data._as_gerror(socket.timeout()).code == errno.ETIMEDOUT
    assert data._as_gerror(ConnectionResetError(errno.ECONNRESET, "reset")).code == errno.ECONNRESET
    assert data._as_gerror(OSError()).code == errno.EIO
    assert data._as_gerror(RuntimeError("bug")).code == errno.EIO


def test_transfer_bookkeeping(ftp: GridFTPServer) -> None:
    control = Control(ftp.host, ftp.port, timeout=5)
    control.connect()
    run = DataTransfer(
        control, streams=1, worker=lambda c, i: None, security=None, check=lambda: None
    )
    run.finished = True
    left, right = pair()
    run._track(left)  # a socket arriving after an abort is closed at once
    assert left.fileno() == -1
    run._run(0, lambda: (_ for _ in ()).throw(OSError(errno.EPIPE, "late")), True)
    assert run.errors == []  # nor does a failure after the end count
    right.close()
    control.close()


def test_transfer_checks_while_joining(ftp: GridFTPServer) -> None:
    control = Control(ftp.host, ftp.port, timeout=5)
    control.connect()
    control.login("anonymous", "x")
    release = threading.Event()
    calls: list[int] = []

    def check() -> None:
        calls.append(1)
        if len(calls) > 3:
            release.set()

    def worker(conn: DataConn, index: int) -> None:
        while conn.recv_into(memoryview(bytearray(10))):
            pass
        release.wait(5)

    run = DataTransfer(control, streams=1, worker=worker, security=None, check=check)
    run.run("NLST /", ChannelOptions(delayed=False))
    assert len(calls) > 3
    control.close()


def test_worker_failure_without_a_server_reply(ftp: GridFTPServer) -> None:
    control = Control(ftp.host, ftp.port, timeout=5)
    control.connect()
    control.login("anonymous", "x")
    ftp.faults["NLST"] = "hang"

    def worker(conn: DataConn, index: int) -> None:
        raise GError("worker broke", errno.EIO)

    run = DataTransfer(control, streams=1, worker=worker, security=None, check=lambda: None)
    _, message = code_of(lambda: run.run("NLST /", ChannelOptions(delayed=False)))
    assert message == "worker broke" and control.broken
