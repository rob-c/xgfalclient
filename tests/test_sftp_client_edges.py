"""Low-level client branches driven by a scripted byte stream.

Some transport and framing paths - a bad handshake, a buffer that must be
compacted, a response received for a request already abandoned - are awkward
to provoke through a real server, so they are driven here with a hand-built
stream of SFTP packets.
"""

from __future__ import annotations

import errno
import struct
import threading

import pytest

from xgfalclient.crypto.sshkeys import string, uint32
from xgfalclient.errors import GError
from xgfalclient.plugins.sftp import protocol as fx
from xgfalclient.plugins.sftp.client import SFTPClient


def _version(version: int = 3, ext: bytes = b"") -> bytes:
    body = uint32(version) + ext
    return struct.pack(">IB", 1 + len(body), fx.VERSION_) + body


def _resp(ptype: int, rid: int, body: bytes = b"") -> bytes:
    return struct.pack(">IBI", 5 + len(body), ptype, rid) + body


def _status(rid: int, code: int, message: str = "ok") -> bytes:
    return _resp(fx.STATUS, rid, uint32(code) + string(message) + string(""))


class FakeStream:
    """A byte stream replaying canned server packets and recording sends."""

    def __init__(self, *packets: bytes) -> None:
        self.buffer = b"".join(packets)
        self.pos = 0
        self.sent: list[bytes] = []
        self.closed = False
        self.fail_send: BaseException | None = None
        self.recv_hook = None  # type: ignore[assignment]

    def feed(self, *packets: bytes) -> None:
        self.buffer += b"".join(packets)

    def send(self, *parts: object) -> None:
        if self.fail_send is not None:
            raise self.fail_send
        self.sent.append(b"".join(bytes(p) for p in parts))  # type: ignore[arg-type]

    def recv_into(self, view: memoryview) -> int:
        if self.recv_hook is not None:
            self.recv_hook()
        if self.pos >= len(self.buffer):
            return 0
        n = min(len(view), len(self.buffer) - self.pos)
        view[:n] = self.buffer[self.pos : self.pos + n]
        self.pos += n
        return n

    def close(self) -> None:
        self.closed = True


def test_handshake_wrong_first_packet() -> None:
    client = SFTPClient(FakeStream(_status(0, fx.FX_OK)))
    with pytest.raises(GError, match="expected VERSION"):
        client.handshake()


def test_handshake_old_version() -> None:
    client = SFTPClient(FakeStream(_version(version=2)))
    with pytest.raises(GError, match="version 2"):
        client.handshake()


def test_handshake_malformed_extensions() -> None:
    # A truncated extension name (claims 5 bytes, supplies 2).
    client = SFTPClient(FakeStream(_version(ext=b"\x00\x00\x00\x05ab")))
    with pytest.raises(GError, match="malformed VERSION"):
        client.handshake()


def test_handshake_end_of_stream() -> None:
    client = SFTPClient(FakeStream())  # nothing to read
    with pytest.raises(GError, match=r"end of stream|closed"):
        client.handshake()


def _handshaked(*packets: bytes) -> tuple[SFTPClient, FakeStream]:
    stream = FakeStream(_version(), *packets)
    client = SFTPClient(stream)
    client.handshake()
    return client, stream


def test_send_failure_marks_client_dead() -> None:
    client, stream = _handshaked()
    stream.fail_send = GError("broken pipe", errno.EPIPE)
    with pytest.raises(GError, match="broken pipe"):
        client.stat(b"/x")
    assert not client.alive


def test_status_expects_status_packet() -> None:
    # A HANDLE where a STATUS is required.
    client, _ = _handshaked(_resp(fx.HANDLE, 1, string(b"h")))
    with pytest.raises(GError, match="expected STATUS"):
        client.remove(b"/x")


def test_empty_readlink_and_realpath() -> None:
    client, stream = _handshaked(_resp(fx.NAME, 1, uint32(0)))
    with pytest.raises(GError, match="empty READLINK"):
        client.readlink(b"/x")
    stream.feed(_resp(fx.NAME, 2, uint32(0)))
    with pytest.raises(GError, match="empty REALPATH"):
        client.realpath(b"/x")


def test_small_buffer_forces_compaction_and_large_take() -> None:
    # A tiny read buffer makes _fill compact and _take/_into read straight
    # through for a packet larger than the buffer.
    payload = bytes(range(200)) * 2  # 400 bytes
    body = string(payload)
    stream = FakeStream(_version(), _resp(fx.DATA, 1, body), _resp(fx.DATA, 2, body))
    client = SFTPClient(stream, buffer_size=64)
    client.handshake()
    handle = b"h"
    # A direct READ returns the DATA payload (larger than the buffer).
    got = client.read(handle, 0, len(payload))
    assert got == payload
    # A second one exercises the buffered path again.
    assert client.read(handle, 0, len(payload)) == payload
    client.close()


def test_discarded_response_is_dropped() -> None:
    # Forget a request, then let its (late) response arrive: the reader drops it
    # and moves on to the next.
    client, stream = _handshaked()
    rid = client.send(fx.STAT, string(b"/x"))
    client.forget([rid])
    # Now feed the forgotten response followed by a real one for rid+1.
    stream.feed(_resp(fx.ATTRS, rid, _attrs_body()), _resp(fx.ATTRS, rid + 1, _attrs_body()))
    got = client.request(fx.STAT, string(b"/y"))
    assert got[0] == fx.ATTRS
    client.close()


def test_wait_error_releases_sink() -> None:
    client, _stream = _handshaked()
    view = memoryview(bytearray(16))
    rid = client.send(fx.READ, string(b"h"), struct.pack(">QI", 0, 16), sink=view)
    # End of stream while waiting: the sink is released and the error raised.
    with pytest.raises(GError, match=r"end of stream|closed"):
        client.wait(rid)
    assert not client.alive
    client.close()


def test_double_failure_keeps_first_error() -> None:
    client, _stream = _handshaked()
    first = GError("first", errno.EIO)
    client._fail(first)
    client._fail(GError("second", errno.EPIPE))
    assert client._error is not None and client._error.message == "first"


def test_fail_ignores_close_error() -> None:
    client, stream = _handshaked()

    def boom() -> None:
        raise OSError("close failed")

    stream.close = boom  # type: ignore[assignment]
    client._fail(GError("x", errno.EIO))  # must not propagate the close error
    assert not client.alive


def test_leader_follower_handoff() -> None:
    # Two threads wait on distinct ids; one becomes the reader and files the
    # other's response, exercising the follower's condition wait.
    client, stream = _handshaked()
    started = threading.Event()

    def slow_recv() -> None:
        started.wait(1.0)

    rid_a = client.send(fx.STAT, string(b"/a"))
    rid_b = client.send(fx.STAT, string(b"/b"))
    stream.recv_hook = slow_recv  # type: ignore[assignment]
    stream.feed(_resp(fx.ATTRS, rid_b, _attrs_body()), _resp(fx.ATTRS, rid_a, _attrs_body()))
    results: dict[int, int] = {}

    def wait_for(rid: int) -> None:
        results[rid] = client.wait(rid)[0]

    tb = threading.Thread(target=wait_for, args=(rid_b,))
    ta = threading.Thread(target=wait_for, args=(rid_a,))
    tb.start()
    ta.start()
    started.set()
    tb.join(2)
    ta.join(2)
    assert results[rid_a] == fx.ATTRS and results[rid_b] == fx.ATTRS
    client.close()


def test_wait_with_error_already_set_releases_sink() -> None:
    client, _stream = _handshaked()
    view = memoryview(bytearray(8))
    rid = client.send(fx.READ, string(b"h"), struct.pack(">QI", 0, 8), sink=view)
    client._fail(GError("gone", errno.ECONNRESET))
    with pytest.raises(GError, match="gone"):
        client.wait(rid)
    assert rid not in client._sinks
    client.close()


def test_into_end_of_stream_mid_sink() -> None:
    # A DATA header promising more sink bytes than the stream delivers.
    size = 16
    truncated = struct.pack(">IBI", 5 + 4 + size, fx.DATA, 1) + uint32(size) + b"onlyfour"
    stream = FakeStream(_version(), truncated)
    client = SFTPClient(stream)
    client.handshake()
    view = memoryview(bytearray(size))
    rid = client.send(fx.READ, string(b"h"), struct.pack(">QI", 0, size), sink=view)
    with pytest.raises(GError, match=r"end of stream|closed"):
        client.wait(rid)
    client.close()


def test_forget_waits_for_active_fill() -> None:
    client, _stream = _handshaked()
    rid = 5
    released = threading.Event()

    with client._cond:
        client._filling = rid  # pretend the reader is filling this sink

    def releaser() -> None:
        released.wait(1.0)
        with client._cond:
            client._filling = 0
            client._cond.notify_all()

    thread = threading.Thread(target=releaser)
    thread.start()
    released.set()
    client.forget([rid])  # blocks until _filling clears
    thread.join(2)
    assert client._filling == 0
    client.close()


def _attrs_body() -> bytes:
    return uint32(0)  # ATTRS with no flags set


def test_limits_of_zero_keep_the_defaults() -> None:
    # limits@openssh.com says 0 for "no limit": the safe defaults stay.
    limits = _resp(fx.EXTENDED_REPLY, 1, struct.pack(">QQQQ", 262144, 0, 0, 16))
    stream = FakeStream(_version(ext=string("limits@openssh.com") + string("1")), limits)
    client = SFTPClient(stream)
    client.handshake()
    assert client.max_read == client.max_write == 32768
    assert client.max_handles == 16
    client.close()


def test_request_ids_wrap_past_zero() -> None:
    client, _stream = _handshaked()
    client._next_id = 0xFFFFFFFF
    assert client.send(fx.STAT, string(b"/a")) == 0xFFFFFFFF
    assert client.send(fx.STAT, string(b"/b")) == 1  # 0 is skipped
    client.close()


def test_forget_after_failure_marks_nothing_for_discard() -> None:
    client, _stream = _handshaked()
    rid = client.send(fx.STAT, string(b"/x"))
    client._fail(GError("gone", errno.ECONNRESET))
    client.forget([rid])
    assert rid not in client._discard
    client.close()


def test_short_length_is_a_protocol_error() -> None:
    client, _stream = _handshaked(struct.pack(">IBI", 4, fx.STATUS, 1))
    with pytest.raises(GError, match=r"length 4$"):
        client.stat(b"/x")


def test_data_during_handshake_is_not_filed_to_a_sink() -> None:
    # A DATA packet where VERSION belongs is read whole, not into a sink.
    client = SFTPClient(FakeStream(_resp(fx.DATA, 0, string(b"xx"))))
    client._sinks[0] = memoryview(bytearray(2))
    with pytest.raises(GError, match="expected VERSION"):
        client.handshake()


def test_data_size_disagreeing_with_packet_length() -> None:
    # The DATA string claims 4 bytes inside a packet that carries 8.
    bad = struct.pack(">IBI", 5 + 4 + 8, fx.DATA, 1) + uint32(4) + b"12345678"
    client, _stream = _handshaked(bad)
    view = memoryview(bytearray(16))
    rid = client.send(fx.READ, string(b"h"), struct.pack(">QI", 0, 16), sink=view)
    with pytest.raises(GError, match="4 bytes of DATA for a request of 16"):
        client.wait(rid)


def test_status_without_a_message() -> None:
    # Some servers end a STATUS after the code.
    client, _stream = _handshaked(_resp(fx.STATUS, 1, uint32(fx.FX_FAILURE)))
    with pytest.raises(fx.StatusError) as caught:
        client.remove(b"/x")
    assert caught.value.code == fx.FX_FAILURE


def _data(rid: int, payload: bytes) -> bytes:
    return _resp(fx.DATA, rid, string(payload))


def test_read_into_short_read_after_the_file_shrank() -> None:
    # Two 10-byte reads in flight. The first comes back short (2 bytes) and its
    # rest (rid 3) is queued; the second short (3 bytes), its rest (rid 4)
    # queued. Rid 3 then meets EOF at offset 2 - the file shrank - so rid 4's
    # short answer lies beyond the end and is not asked for again.
    client, stream = _handshaked()
    stream.feed(
        _data(1, b"ab"),
        _data(2, b"klm"),
        _status(3, fx.FX_EOF, "End of file"),
        _data(4, b"n"),
    )
    buf = bytearray(30)
    assert client.read_into(b"h", 0, memoryview(buf), chunk=10, depth=2) == 2
    assert bytes(buf[:2]) == b"ab"
    client.close()
