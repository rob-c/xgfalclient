"""Data-channel pieces in isolation: records, blocks, EOD counting, the transfer loop."""

from __future__ import annotations

import errno
import os
import socket
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from test_gridftp_helpers import _fast_polls as _fast_polls
from test_gridftp_helpers import code_of
from test_gridftp_helpers import ftp as ftp
from xgfalclient.errors import GError
from xgfalclient.plugins.gridftp import data
from xgfalclient.plugins.gridftp.control import Control
from xgfalclient.plugins.gridftp.data import (
    ChannelOptions,
    ConnSetup,
    DataConn,
    DataTransfer,
    EodCounter,
    Feed,
    Ranges,
    read_record,
    recv_blocks,
    recv_exact,
    send_blocks,
)
from xgfalclient.plugins.gridftp.protocol import BLOCK_HEADER
from xgfalclient.testing.gridftp import GridFTPServer

#: Control sessions the tests leave mid-failure are hung up at teardown.
pytestmark = pytest.mark.usefixtures("hang_up_controls")


#: Every socket :func:`pair` made in the running test; closed at its teardown.
_PAIRS: list[socket.socket] = []


def pair() -> tuple[socket.socket, socket.socket]:
    """A connected socket pair, closed when the test ends (closing twice is harmless)."""
    left, right = socket.socketpair()
    _PAIRS.extend((left, right))
    return left, right


@pytest.fixture(autouse=True)
def _close_pairs() -> Iterator[None]:
    yield
    while _PAIRS:
        _PAIRS.pop().close()


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
        feed = Feed(lambda view, offset: 1, 10, lambda n: None)
        send_blocks(DataConn(left), feed, Ranges(0, 10, 10))
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
    assert data._as_gerror(TimeoutError()).code == errno.ETIMEDOUT
    assert data._as_gerror(ConnectionResetError(errno.ECONNRESET, "reset")).code == errno.ECONNRESET
    assert data._as_gerror(OSError()).code == errno.EIO
    assert data._as_gerror(RuntimeError("bug")).code == errno.EIO


def test_transfer_bookkeeping(ftp: GridFTPServer) -> None:
    control = Control(ftp.host, ftp.port, timeout=5)
    control.connect()
    run = DataTransfer(
        control, streams=1, worker=lambda c, i: None, check=lambda: None, setup=ConnSetup()
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

    run = DataTransfer(control, streams=1, worker=worker, check=check, setup=ConnSetup())
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

    run = DataTransfer(control, streams=1, worker=worker, check=lambda: None, setup=ConnSetup())
    _, message = code_of(lambda: run.run("NLST /", ChannelOptions(delayed=False)))
    assert message == "worker broke" and control.broken


@pytest.mark.parametrize("has_preadv", [True, False], ids=["preadv", "pread"])
def test_positional_reader_with_and_without_preadv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, has_preadv: bool
) -> None:
    """Both readers fill the caller's buffer, short only at the end of the file.

    A CPython built for macOS before 11 (conda's Intel macOS one) has no
    ``os.preadv``; the reader must still work there, through ``os.pread``.
    """
    if has_preadv and not hasattr(os, "preadv"):
        pytest.skip("this Python has no os.preadv")
    if not has_preadv:
        monkeypatch.delattr(os, "preadv", raising=False)
    path = tmp_path / "source"
    path.write_bytes(bytes(range(10)))
    fd = os.open(path, os.O_RDONLY)
    try:
        read = data.positional_reader(fd)
        buffer = bytearray(4)
        assert read(memoryview(buffer), 3) == 4 and buffer == bytes(range(3, 7))
        assert read(memoryview(buffer), 8) == 2 and buffer[:2] == bytes([8, 9])
        assert read(memoryview(buffer), 10) == 0
    finally:
        os.close(fd)
