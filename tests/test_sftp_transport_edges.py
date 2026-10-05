"""Unit-level branches of the SSH transport: ciphers, framing and errors."""

from __future__ import annotations

import errno
import os
import socket
import struct
import threading

import pytest

from xgfalclient.crypto import ciphers
from xgfalclient.errors import GError
from xgfalclient.plugins.sftp import ssh
from xgfalclient.plugins.sftp.endpoint import Endpoint


class Recv:
    """A callable feeding fixed bytes, as the cipher ``read`` helpers expect."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def __call__(self, n: int) -> bytes:
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk


def _mac(name: str = "sha256") -> ssh._MAC:
    return ssh._MAC(name, os.urandom(ssh.hashlib.new(name).digest_size))


@pytest.mark.parametrize("etm", [True, False])
def test_ctr_cipher_round_trip_and_bad_mac(etm: bool) -> None:
    key, iv = os.urandom(32), os.urandom(16)
    mac = _mac()
    out = ssh._CtrCipher(ciphers.PURE.aes_ctr(key, iv), ssh._MAC(mac.name, mac.key), etm)
    reader = ssh._CtrCipher(ciphers.PURE.aes_ctr(key, iv), ssh._MAC(mac.name, mac.key), etm)
    for seq, payload in enumerate([b"hello", b"a much longer payload " * 4]):
        wire = out.seal(seq, payload)
        assert reader.read(Recv(wire), seq) == payload
    # Tampering the tag is caught (a fresh reader at seq 0).
    bad = bytearray(
        ssh._CtrCipher(ciphers.PURE.aes_ctr(key, iv), ssh._MAC(mac.name, mac.key), etm).seal(
            0, b"data"
        )
    )
    bad[-1] ^= 0xFF
    fresh = ssh._CtrCipher(ciphers.PURE.aes_ctr(key, iv), ssh._MAC(mac.name, mac.key), etm)
    with pytest.raises(GError, match="bad MAC"):
        fresh.read(Recv(bytes(bad)), 0)


def test_chacha_cipher_round_trip_and_bad_tag() -> None:
    key = os.urandom(64)
    out = ssh._ChachaCipher(ciphers.PURE, key)
    reader = ssh._ChachaCipher(ciphers.PURE, key)
    for seq, payload in enumerate([b"hi", b"payload" * 100]):
        assert reader.read(Recv(out.seal(seq, payload)), seq) == payload
    bad = bytearray(out.seal(5, b"data"))
    bad[-1] ^= 0xFF
    with pytest.raises(GError, match="Poly1305"):
        ssh._ChachaCipher(ciphers.PURE, key).read(Recv(bytes(bad)), 5)


def test_null_cipher_round_trip() -> None:
    null = ssh._NullCipher()
    wire = null.seal(0, b"payload")
    assert ssh._NullCipher().read(Recv(wire), 0) == b"payload"


def test_check_length_rejects_absurd() -> None:
    null = ssh._NullCipher()
    huge = struct.pack(">I", 5_000_000) + b"\x00" * 20
    with pytest.raises(GError, match="implausible packet length"):
        null.read(Recv(huge), 0)
    # Too short to hold even the padding length and minimum padding.
    with pytest.raises(GError, match="implausible packet length 4"):
        null.read(Recv(struct.pack(">I", 4) + b"\x00" * 20), 0)


def test_negotiate_no_common_algorithm() -> None:
    with pytest.raises(GError, match="no common algorithm"):
        ssh._negotiate(["a", "b"], ["c"])


class FakeSock:
    def __init__(self, data: bytes = b"", recv_exc: BaseException | None = None) -> None:
        self.data = data
        self.pos = 0
        self.recv_exc = recv_exc
        self.sent = b""
        self.closed = False
        self.sendall_exc: BaseException | None = None
        self.shutdown_exc: BaseException | None = None

    def recv(self, n: int) -> bytes:
        if self.recv_exc is not None:
            raise self.recv_exc
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def recv_into(self, view: memoryview) -> int:
        chunk = self.recv(len(view))
        view[: len(chunk)] = chunk
        return len(chunk)

    def sendall(self, data: bytes | bytearray | memoryview) -> None:
        if self.sendall_exc is not None:
            raise self.sendall_exc
        self.sent += bytes(data)

    def shutdown(self, how: int) -> None:
        if self.shutdown_exc is not None:
            raise self.shutdown_exc

    def close(self) -> None:
        self.closed = True

    def settimeout(self, t: object) -> None:
        pass


def _transport(sock: FakeSock) -> ssh.SSHTransport:
    endpoint = Endpoint(host="h", port=22, user="a")
    return ssh.SSHTransport(endpoint, ssh.Auth(username="a"), sock)  # type: ignore[arg-type]


def test_exchange_versions_skips_banner() -> None:
    sock = FakeSock(b"a text banner line\r\nSSH-2.0-realserver\r\n")
    transport = _transport(sock)
    assert transport._exchange_versions() == b"SSH-2.0-realserver"
    assert sock.sent.startswith(b"SSH-2.0-xgfalclient")


def test_exchange_versions_accepts_compatibility_version() -> None:
    # "1.99" is a server speaking both protocols; version 2 is fine.
    transport = _transport(FakeSock(b"SSH-1.99-dualstack\r\n"))
    assert transport._exchange_versions() == b"SSH-1.99-dualstack"


def test_exchange_versions_rejects_old_protocol() -> None:
    transport = _transport(FakeSock(b"SSH-1.5-ancient\r\n"))
    with pytest.raises(GError, match="unsupported server version"):
        transport._exchange_versions()


def test_exchange_versions_line_too_long() -> None:
    transport = _transport(FakeSock(b"x" * 5000))
    with pytest.raises(GError, match="too long"):
        transport._exchange_versions()


def test_exchange_versions_eof() -> None:
    transport = _transport(FakeSock(b""))
    with pytest.raises(GError, match="closed"):
        transport._exchange_versions()


def test_recv_exact_timeout() -> None:
    transport = _transport(FakeSock(recv_exc=socket.timeout("slow")))
    with pytest.raises(GError, match="Timed out") as caught:
        transport._recv_exact(5)
    assert caught.value.code == errno.ETIMEDOUT


def test_recv_exact_oserror() -> None:
    transport = _transport(FakeSock(recv_exc=OSError(errno.ECONNRESET, "reset")))
    with pytest.raises(GError) as caught:
        transport._recv_exact(5)
    assert caught.value.code == errno.ECONNRESET


def test_write_all_oserror() -> None:
    sock = FakeSock()
    sock.sendall_exc = OSError(errno.EPIPE, "broken")
    transport = _transport(sock)
    with pytest.raises(GError) as caught:
        transport._write_all(b"data")
    assert caught.value.code == errno.EPIPE


def test_io_failure_without_errno() -> None:
    err = _transport(FakeSock())._io_failure(OSError("socket gone"))
    assert err.code == errno.ECONNRESET
    assert err.message == "Connection to a@h:22 failed: socket gone"


def test_dispatch_transport_ignore_then_packet() -> None:
    # An IGNORE in the initial KEX loop is skipped and the next packet returned.
    inner = ssh._NullCipher().seal(0, bytes([ssh.MSG_KEXINIT]) + b"body")
    sock = FakeSock(inner)
    transport = _transport(sock)
    result = transport._dispatch_transport(bytes([ssh.MSG_IGNORE]))
    assert result[0] == ssh.MSG_KEXINIT


def test_dispatch_transport_unexpected_message() -> None:
    transport = _transport(FakeSock())
    with pytest.raises(GError, match="expected KEXINIT"):
        transport._dispatch_transport(bytes([ssh.MSG_UNIMPLEMENTED]))


def test_send_raises_when_errored() -> None:
    transport = _transport(FakeSock())
    transport._error = GError("dead", errno.ECONNRESET)
    transport._remote_maxpacket = 100
    transport._remote_window = 100
    with pytest.raises(GError, match="dead"):
        transport.send(b"data")


def test_send_waits_for_window_then_errors() -> None:
    transport = _transport(FakeSock())
    transport._remote_maxpacket = 100
    transport._remote_window = 0  # no credit: send() must wait

    def fail_soon() -> None:
        with transport._cond:
            transport._error = GError("gone", errno.ECONNRESET)
            transport._cond.notify_all()

    timer = threading.Timer(0.05, fail_soon)
    timer.start()
    with pytest.raises(GError, match="gone"):
        transport.send(b"payload")
    timer.join()


def test_send_waits_for_a_packet_size() -> None:
    # A window but no maximum packet yet: send() waits rather than spin.
    transport = _transport(FakeSock())
    transport._remote_maxpacket = 0
    transport._remote_window = 100

    def fail_soon() -> None:
        with transport._cond:
            transport._error = GError("gone", errno.ECONNRESET)
            transport._cond.notify_all()

    timer = threading.Timer(0.05, fail_soon)
    timer.start()
    with pytest.raises(GError, match="gone"):
        transport.send(b"payload")
    timer.join()


def test_send_blocks_then_window_granted() -> None:
    sock = FakeSock()
    transport = _transport(sock)
    transport._remote_channel = 1
    transport._remote_maxpacket = 100
    transport._remote_window = 0  # blocked until credited

    def grant() -> None:
        with transport._cond:
            transport._remote_window = 100
            transport._cond.notify_all()

    timer = threading.Timer(0.05, grant)
    timer.start()
    transport.send(b"x" * 40)  # waits, then proceeds when the window opens
    timer.join()
    assert sock.sent  # a CHANNEL_DATA packet went out


def test_recv_into_error() -> None:
    transport = _transport(FakeSock())
    transport._error = GError("boom", errno.EIO)
    with pytest.raises(GError, match="boom"):
        transport.recv_into(memoryview(bytearray(8)))


def test_recv_into_eof() -> None:
    transport = _transport(FakeSock())
    transport._eof = True
    assert transport.recv_into(memoryview(bytearray(8))) == 0


def test_close_ignores_send_and_shutdown_errors() -> None:
    sock = FakeSock()
    sock.sendall_exc = OSError(errno.EPIPE, "broken")
    sock.shutdown_exc = OSError(errno.ENOTCONN, "not connected")
    transport = _transport(sock)
    transport._remote_channel = 1
    transport.close()
    assert sock.closed
    transport.close()  # idempotent


def test_connect_closes_owned_socket_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = FakeSock(b"SSH-1.5-nope\r\n")  # a version the handshake will reject
    monkeypatch.setattr(ssh, "_open_socket", lambda endpoint: sock)
    endpoint = Endpoint(host="h", port=22, user="a")
    with pytest.raises(GError, match="unsupported server version"):
        ssh.connect(endpoint, ssh.Auth(username="a"))
    assert sock.closed  # the owned socket was cleaned up


# -- AES-GCM framing, flow control and the bulk data path ------------------------

_GCM = ciphers.get()
_needs_gcm = pytest.mark.skipif(not _GCM.has_gcm, reason="no libcrypto AES-GCM here")


@_needs_gcm
@pytest.mark.parametrize("keylen", [16, 32])
def test_gcm_cipher_round_trip_and_rejections(keylen: int) -> None:
    key, iv = os.urandom(keylen), os.urandom(12)
    out, reader = ssh._GcmCipher(_GCM, key, iv), ssh._GcmCipher(_GCM, key, iv)
    # Sizes around the block boundaries exercise both padding branches; many
    # packets exhaust the pooled padding bytes more than once.
    payloads = [b"", b"x", b"y" * 11, b"z" * 12, b"q" * 100_000] + [os.urandom(40)] * 300
    for seq, payload in enumerate(payloads):
        wire = out.seal(seq, payload[:3], payload[3:])  # parts are framed without a join
        assert len(wire) % 16 == 4 and len(wire) >= 4 + 16 + 16
        assert reader.read(Recv(bytes(wire)), seq) == payload  # bytes in: copied once
    # A flipped bit anywhere - length (the AAD), body or tag - is refused.
    wire = bytes(ssh._GcmCipher(_GCM, key, iv).seal(0, b"secret payload"))
    for position in (3, 10, len(wire) - 1):
        bad = bytearray(wire)
        bad[position] ^= 1
        with pytest.raises(GError, match=r"AES-GCM tag|block size|implausible"):
            ssh._GcmCipher(_GCM, key, iv).read(Recv(bytes(bad)), 0)
    # A replayed packet (the nonce has moved on) is refused.
    fresh = ssh._GcmCipher(_GCM, key, iv)
    assert fresh.read(Recv(wire), 0) == b"secret payload"
    with pytest.raises(GError, match="AES-GCM tag"):
        fresh.read(Recv(wire), 1)
    # A length that is not whole blocks is refused before any decryption.
    with pytest.raises(GError, match="not a multiple of the block size"):
        ssh._GcmCipher(_GCM, key, iv).read(Recv(struct.pack(">I", 20) + bytes(40)), 0)


@_needs_gcm
def test_gcm_negotiated_first_with_libcrypto() -> None:
    preferred = ssh._ciphers_preferred(_GCM)
    assert preferred[:2] == ("aes128-gcm@openssh.com", "aes256-gcm@openssh.com")
    assert ssh._ciphers_preferred(ciphers.PURE) == preferred
    cipher = ssh.make_cipher(
        _GCM, "aes256-gcm@openssh.com", "hmac-sha2-256", 12345, b"h" * 32, b"s" * 32, "sha256",
        ("A", "C", "E"),
    )  # fmt: skip
    assert isinstance(cipher, ssh._GcmCipher) and len(cipher._key) == 32


def test_unpad_rejects_padding_beyond_the_packet() -> None:
    body = bytes([200]) + bytes(15)  # padding length 200 in a 16-byte body
    wire = struct.pack(">I", len(body)) + body
    with pytest.raises(GError, match="padding length 200 exceeds"):
        ssh._NullCipher().read(Recv(wire), 0)


def _data(size: int, actual: int | None = None) -> bytes:
    body = os.urandom(size if actual is None else actual)
    return bytes([ssh.MSG_CHANNEL_DATA]) + struct.pack(">II", 0, size) + body


def test_channel_data_checks() -> None:
    transport = _transport(FakeSock())
    with pytest.raises(GError, match="truncated CHANNEL_DATA"):
        transport._handle_channel(bytes([ssh.MSG_CHANNEL_DATA, 0, 0]))
    with pytest.raises(GError, match="truncated CHANNEL_DATA"):
        transport._handle_channel(_data(100, actual=10))
    with pytest.raises(GError, match="beyond the window"):
        transport._handle_channel(_data(ssh._LOCAL_MAXPACKET + 1))
    transport._local_window = 50
    with pytest.raises(GError, match="beyond the window"):
        transport._handle_channel(_data(51))
    assert transport._inlen == 0


def test_channel_data_window_top_up_and_batched_delivery() -> None:
    sock = FakeSock()
    transport = _transport(sock)
    transport._remote_channel = 7
    chunk = ssh._LOCAL_MAXPACKET
    count = ssh._LOCAL_WINDOW // 2 // chunk
    payloads = [os.urandom(chunk) for _ in range(count)]
    for payload in payloads[:-1]:
        transport._handle_channel(
            bytes([ssh.MSG_CHANNEL_DATA]) + struct.pack(">II", 0, chunk) + payload
        )
    assert not sock.sent  # still more than half the window left
    transport._handle_channel(
        memoryview(bytes([ssh.MSG_CHANNEL_DATA]) + struct.pack(">II", 0, chunk) + payloads[-1])
    )
    # Half used: one WINDOW_ADJUST restores it in full.
    adjust = ssh._NullCipher().read(Recv(sock.sent), 0)
    assert adjust[0] == ssh.MSG_CHANNEL_WINDOW_ADJUST
    assert struct.unpack(">II", adjust[1:9]) == (7, ssh._LOCAL_WINDOW // 2)
    assert transport._local_window == ssh._LOCAL_WINDOW
    # recv_into hands out whole views across packet boundaries, in order.
    want = b"".join(payloads)
    got = bytearray()
    view = memoryview(bytearray(chunk + 1000))
    while len(got) < len(want):
        count_ = transport.recv_into(view)
        got += view[:count_]
    assert bytes(got) == want and transport._inlen == 0


def test_recv_into_batches_until_full_or_idle() -> None:
    transport = _transport(FakeSock())
    transport._idle = False  # a reader that is busy decoding more packets
    view = memoryview(bytearray(100))
    results: list[int] = []
    waiter = threading.Thread(target=lambda: results.append(transport.recv_into(view)), daemon=True)
    waiter.start()
    transport._handle_channel(_data(40))  # not enough to fill the view: no wake-up yet
    waiter.join(0.2)
    assert waiter.is_alive() and transport._want == 100
    transport._handle_channel(_data(70))  # now there is: woken with everything that fits
    waiter.join(5)
    assert results == [100] and transport._inlen == 10
    # With the reader about to block, whatever is there is handed over at once.
    transport._idle = True
    assert transport.recv_into(view) == 10


def test_recv_into_wakes_when_reader_goes_idle() -> None:
    sock = FakeSock(b"")  # its recv returns end-of-stream
    transport = _transport(sock)
    transport._idle = False
    transport._handle_channel(_data(10))
    results: list[int] = []
    waiter = threading.Thread(
        target=lambda: results.append(transport.recv_into(memoryview(bytearray(64)))),
        daemon=True,
    )
    waiter.start()
    waiter.join(0.2)
    assert waiter.is_alive()
    with pytest.raises(GError, match="closed"):
        transport._recv_exact(4)  # the reader, before blocking, hands over the 10 bytes
    waiter.join(5)
    assert results == [10]


def test_recv_into_returns_buffered_data_before_error_or_eof() -> None:
    transport = _transport(FakeSock())
    transport._idle = False
    transport._handle_channel(_data(10))
    transport._error = GError("boom", errno.EIO)
    assert transport.recv_into(memoryview(bytearray(64))) == 10
    with pytest.raises(GError, match="boom"):
        transport.recv_into(memoryview(bytearray(64)))
    transport._error = None
    transport._handle_channel(_data(5))
    transport._eof = True
    assert transport.recv_into(memoryview(bytearray(64))) == 5
    assert transport.recv_into(memoryview(bytearray(64))) == 0


def test_extended_data_is_charged_to_the_window() -> None:
    transport = _transport(FakeSock())
    stderr = b"warning"
    transport._handle_channel(
        bytes([ssh.MSG_CHANNEL_EXTENDED_DATA]) + struct.pack(">II", 0, 1) + ssh.string(stderr)
    )
    assert transport._local_window == ssh._LOCAL_WINDOW - len(stderr)
    assert transport._inlen == 0  # never delivered as channel data


def test_recv_buffer_grows_for_a_large_read() -> None:
    data = os.urandom(ssh._RECV_BUFFER + 5000)
    transport = _transport(FakeSock(b"ab" + data))
    assert transport._recv_exact(2) == b"ab"
    assert transport._recv_exact(len(data)) == data
    assert len(transport._rbuf) >= len(data)


class GatherSock(FakeSock):
    """A socket whose ``sendmsg`` accepts at most ``limit`` bytes per call."""

    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit = limit
        self.calls = 0

    def sendmsg(self, buffers: list[memoryview]) -> int:
        if self.sendall_exc is not None:
            raise self.sendall_exc
        self.calls += 1
        data = b"".join(bytes(b) for b in buffers)[: self.limit]
        self.sent += data
        return len(data)


def test_gathered_write_resumes_after_partial_sends() -> None:
    sock = GatherSock(limit=7)
    transport = _transport(sock)  # type: ignore[arg-type]
    packets: list[ssh.Buffer] = [b"abc", bytearray(b"defghij"), b"", b"klmnopqrstuvwxyz"]
    transport._write_gathered(packets)
    assert sock.sent == b"abcdefghijklmnopqrstuvwxyz" and sock.calls == 4
    sock.sendall_exc = OSError(errno.EPIPE, "broken")
    with pytest.raises(GError) as caught:
        transport._write_gathered([b"a", b"b"])
    assert caught.value.code == errno.EPIPE


def test_gathered_write_without_sendmsg_joins_packets() -> None:
    sock = FakeSock()  # no sendmsg: one sendall of the packets joined
    transport = _transport(sock)
    transport._write_gathered([b"abc", b"def"])
    assert sock.sent == b"abcdef"


def test_send_slices_parts_into_packets_and_gathers_them() -> None:
    sock = GatherSock(limit=1 << 30)
    transport = _transport(sock)  # type: ignore[arg-type]
    transport._remote_channel = 3
    transport._remote_maxpacket = 10
    transport._remote_window = 1000
    parts = [b"0123", memoryview(b"456789abcdef"), bytearray(b""), b"ghijklmnopq"]
    transport.send(*parts)
    assert sock.calls == 1 and transport._remote_window == 1000 - 27
    wire, received = Recv(sock.sent), b""
    for seq in range(3):  # 27 bytes in packets of at most 10
        payload = ssh._NullCipher().read(wire, seq)
        assert payload[0] == ssh.MSG_CHANNEL_DATA and struct.unpack(">I", payload[1:5])[0] == 3
        received += bytes(payload[9:])
    assert received == b"".join(bytes(p) for p in parts)


def test_cipher_interface_is_unimplemented() -> None:
    """Every record cipher overrides these; the base only states the shape."""
    cipher = ssh._Cipher()
    with pytest.raises(NotImplementedError):
        cipher.seal(0, b"payload")
    with pytest.raises(NotImplementedError):
        cipher.read(None, 0)  # type: ignore[arg-type]
