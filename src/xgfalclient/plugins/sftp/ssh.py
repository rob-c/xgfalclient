"""Transport tier 3: an SSH-2 client, in Python, carrying the ``sftp`` subsystem.

When there is no ``ssh`` binary and paramiko is not importable - and always
when a *password* must be used, because a password must never leave the
process (see :mod:`.openssh`) - the plugin speaks SSH itself. This module is
that client: the :rfc:`4253` transport (version exchange, key exchange,
binary packet protocol), :rfc:`4252` user authentication, and :rfc:`4254`
one session channel running ``subsystem sftp``.

What it negotiates, best first, matching what OpenSSH offers:

* **key exchange** ``curve25519-sha256`` (and its ``@libssh.org`` alias),
  ``diffie-hellman-group16-sha512``, ``diffie-hellman-group14-sha256``;
* **host key** ``ssh-ed25519``, ``rsa-sha2-512``/``256``,
  ``ecdsa-sha2-nistp256`` (and legacy ``ssh-rsa`` verification), checked
  against ``known_hosts`` with the endpoint's ``StrictHostKeyChecking``
  policy - a first key recorded, a changed key refused, a ``@revoked`` key
  always refused;
* **cipher** ``aes{128,256}-gcm@openssh.com`` (cryptography - one native
  pass per packet encrypts and authenticates, the fastest by far here),
  ``chacha20-poly1305@openssh.com`` and ``aes{128,192,256}-ctr``, the fast
  one first depending on what :func:`ciphers.get` found;
* **MAC** ``hmac-sha2-{256,512}`` and their encrypt-then-MAC
  ``-etm@openssh.com`` forms (the AEAD ciphers carry their own).

Authentication tries every configured public key, then the password. A
background thread reads the connection, so channel-window credit keeps
flowing while a bulk upload blocks waiting for it - the deadlock a
single-threaded reader would hit when the SFTP write pipeline outruns the
channel window.

Bulk speed is per-packet Python overhead, so the data path avoids it: the
socket is read with ``recv_into`` into one reusable buffer, a packet is
framed and encrypted in a single ``bytearray`` (in place, for AES-GCM),
payloads travel as ``memoryview`` slices rather than copies, the reader
wakes the consuming thread once per buffer-full rather than once per
packet, outgoing packets leave in one gathered write per window-full, and
the channel advertises a large window and maximum packet so the server may
send big packets.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import os
import socket
import struct
import threading
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Optional, Union

from ..._compat import SLOTS, TIMEOUTS
from ...crypto import ciphers, x25519
from ...crypto.sshkeys import (
    KeyError_,
    KnownHosts,
    PrivateKey,
    PublicKey,
    Reader,
    mpint,
    parse_public_blob,
    string,
    uint32,
)
from ...errors import GError
from .endpoint import Endpoint

__all__ = ["Auth", "SSHTransport", "connect"]

_VERSION = b"SSH-2.0-xgfalclient"

# -- message numbers (RFC 4253/4252/4254) ------------------------------------
MSG_DISCONNECT = 1
MSG_IGNORE = 2
MSG_UNIMPLEMENTED = 3
MSG_DEBUG = 4
MSG_SERVICE_REQUEST = 5
MSG_SERVICE_ACCEPT = 6
MSG_EXT_INFO = 7
MSG_KEXINIT = 20
MSG_NEWKEYS = 21
MSG_KEX_ECDH_INIT = 30  # also KEXDH_INIT
MSG_KEX_ECDH_REPLY = 31  # also KEXDH_REPLY
MSG_USERAUTH_REQUEST = 50
MSG_USERAUTH_FAILURE = 51
MSG_USERAUTH_SUCCESS = 52
MSG_USERAUTH_BANNER = 53
MSG_USERAUTH_PK_OK = 60
MSG_GLOBAL_REQUEST = 80
MSG_REQUEST_SUCCESS = 81
MSG_REQUEST_FAILURE = 82
MSG_CHANNEL_OPEN = 90
MSG_CHANNEL_OPEN_CONFIRMATION = 91
MSG_CHANNEL_OPEN_FAILURE = 92
MSG_CHANNEL_WINDOW_ADJUST = 93
MSG_CHANNEL_DATA = 94
MSG_CHANNEL_EXTENDED_DATA = 95
MSG_CHANNEL_EOF = 96
MSG_CHANNEL_CLOSE = 97
MSG_CHANNEL_REQUEST = 98
MSG_CHANNEL_SUCCESS = 99
MSG_CHANNEL_FAILURE = 100

#: Our channel's flow-control window and the largest DATA we let the peer send.
_LOCAL_WINDOW = 8 * 1024 * 1024
_LOCAL_MAXPACKET = 256 * 1024
#: Initial size of the socket read buffer (it grows for a larger packet).
_RECV_BUFFER = 1024 * 1024

_DATA_HEADER = struct.Struct(">BII")  # CHANNEL_DATA: message, channel, data length

Buffer = Union[bytes, bytearray, memoryview]
#: Reads exactly ``count`` bytes from the connection.
Recv = Callable[[int], Buffer]

# Diffie-Hellman groups (RFC 3526), generator 2.
_GROUP14_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_GROUP16_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8"
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
    16,
)


@dataclass(**SLOTS)
class Auth:
    """How to authenticate: a username, optional keys and an optional password."""

    username: str
    keys: tuple[PrivateKey, ...] = ()
    password: str = ""
    banner: Optional[Callable[[str], None]] = None


def _pad(payload: Buffer, block: int, header: int = 0) -> bytes:
    """A binary-packet body: ``padding_length || payload || random padding``.

    ``header`` is the number of bytes that precede this body inside the region
    the padding must block-align. For a standard packet (and any packet before
    the keys are in place) that region includes the 4-byte ``packet_length``
    field (RFC 4253 §6), so ``header`` is 4; for encrypt-then-MAC and for
    ``chacha20-poly1305`` the length is sent apart and ``header`` is 0.
    """
    size = header + 1 + len(payload)
    pad = block - (size % block)
    if pad < 4:
        pad += block
    return bytes([pad]) + bytes(payload) + os.urandom(pad)


def _unpad(body: Buffer, start: int, length: int) -> memoryview:
    """The payload of the ``length``-byte packet body at ``body[start:]``.

    Its first byte is the padding length; a value that does not fit the
    packet is a protocol error (it would otherwise slice from the end).
    """
    pad = body[start]
    if pad + 1 > length:
        raise _protocol_error(f"padding length {pad} exceeds the packet")
    return memoryview(body)[start + 1 : start + length - pad]


def _chacha_iv(seqno: int, counter: int) -> bytes:
    """The 16-byte ChaCha20 IV block for ``chacha20-poly1305@openssh.com``.

    OpenSSH uses the packet sequence number as the nonce (the low state
    words) and a plain block counter; the same 16 bytes drive both the pure
    and compatibility backend aliases (:mod:`..crypto.ciphers`).
    """
    return struct.pack("<I", counter) + b"\x00\x00\x00\x00" + struct.pack(">Q", seqno)


class _Cipher:
    """One direction's record protection: framing, encryption and MAC."""

    block = 8
    has_mac = False

    def seal(self, seqno: int, *parts: Buffer) -> Buffer:
        """The wire form of the packet whose payload is ``parts`` concatenated."""
        raise NotImplementedError

    def read(self, recv: Recv, seqno: int) -> memoryview:
        """Read, authenticate and decrypt one packet; its payload."""
        raise NotImplementedError


class _NullCipher(_Cipher):
    """No encryption or MAC - the transport before ``NEWKEYS``."""

    def seal(self, seqno: int, *parts: Buffer) -> bytes:
        body = _pad(b"".join(parts), self.block, header=4)  # length is block-aligned too
        return uint32(len(body)) + body

    def read(self, recv: Recv, seqno: int) -> memoryview:
        length = struct.unpack(">I", recv(4))[0]
        _check_length(length)
        return _unpad(recv(length), 0, length)


class _MAC:
    """A keyed HMAC over ``seqno || data``, as :rfc:`4253` computes it."""

    def __init__(self, name: str, key: bytes) -> None:
        self.name = name
        self.key = key
        self.length = hashlib.new(name).digest_size

    def compute(self, seqno: int, data: Buffer) -> bytes:
        return hmac.digest(self.key, struct.pack(">I", seqno) + data, self.name)


class _CtrCipher(_Cipher):
    """AES-CTR with an HMAC, encrypt-and-MAC or encrypt-then-MAC."""

    block = 16
    has_mac = True

    def __init__(self, keystream: ciphers.Keystream, mac: _MAC, etm: bool) -> None:
        self._stream = keystream
        self._mac = mac
        self._etm = etm

    def seal(self, seqno: int, *parts: Buffer) -> bytes:
        # Encrypt-then-MAC sends the length in clear (header=0); encrypt-and-MAC
        # blocks the whole packet, length field included (header=4).
        body = _pad(b"".join(parts), self.block, header=0 if self._etm else 4)
        if self._etm:
            length = uint32(len(body))
            cipher = bytes(self._stream.update(body))
            return length + cipher + self._mac.compute(seqno, length + cipher)
        packet = uint32(len(body)) + body
        tag = self._mac.compute(seqno, packet)
        return bytes(self._stream.update(packet)) + tag

    def read(self, recv: Recv, seqno: int) -> memoryview:
        if self._etm:
            length_bytes = bytes(recv(4))
            length = struct.unpack(">I", length_bytes)[0]
            _check_length(length)
            cipher = recv(length)
            tag = recv(self._mac.length)
            if not hmac.compare_digest(tag, self._mac.compute(seqno, length_bytes + cipher)):
                raise _protocol_error("bad MAC on an incoming packet")
            return _unpad(self._stream.update(cipher), 0, length)
        first = bytes(self._stream.update(recv(self.block)))
        length = struct.unpack(">I", first[:4])[0]
        _check_length(length)
        packet = first + self._stream.update(recv(4 + length - self.block))
        tag = recv(self._mac.length)
        if not hmac.compare_digest(tag, self._mac.compute(seqno, packet)):
            raise _protocol_error("bad MAC on an incoming packet")
        return _unpad(packet, 4, length)


class _ChachaCipher(_Cipher):
    """``chacha20-poly1305@openssh.com``: a Poly1305 tag, the length encrypted apart."""

    block = 8
    has_mac = True

    def __init__(self, backend: ciphers.Backend, key: bytes) -> None:
        self._backend = backend
        self._main = backend.chacha20(key[:32])
        self._header = backend.chacha20(key[32:64])

    def _poly_key(self, seqno: int) -> bytes:
        return bytes(self._main.xor(_chacha_iv(seqno, 0), bytes(32)))

    def seal(self, seqno: int, *parts: Buffer) -> bytes:
        body = _pad(b"".join(parts), self.block)
        enc_length = bytes(self._header.xor(_chacha_iv(seqno, 0), uint32(len(body))))
        enc_body = bytes(self._main.xor(_chacha_iv(seqno, 1), body))
        tag = self._backend.poly1305(self._poly_key(seqno), enc_length + enc_body)
        return enc_length + enc_body + tag

    def read(self, recv: Recv, seqno: int) -> memoryview:
        enc_length = bytes(recv(4))
        length = struct.unpack(">I", self._header.xor(_chacha_iv(seqno, 0), enc_length))[0]
        _check_length(length)
        enc_body = recv(length)
        tag = recv(16)
        if not hmac.compare_digest(
            tag, self._backend.poly1305(self._poly_key(seqno), enc_length + enc_body)
        ):
            raise _protocol_error("bad Poly1305 tag on an incoming packet")
        return _unpad(self._main.xor(_chacha_iv(seqno, 1), enc_body), 0, length)


class _GcmCipher(_Cipher):
    """``aes{128,256}-gcm@openssh.com``: AES-GCM, the length sent clear as AAD.

    The 12-byte nonce is a fixed 4-byte field and a 64-bit invocation
    counter, both from key derivation, the counter incremented per packet
    (the OpenSSH scheme). A packet is framed in one ``bytearray`` and
    sealed or opened there in place; an incoming payload is released only
    after its tag has verified.
    """

    block = 16
    has_mac = True

    def __init__(self, backend: ciphers.Backend, key: bytes, iv: bytes) -> None:
        self._backend = backend
        self._key = key
        self._fixed = iv[:4]
        self._counter = int.from_bytes(iv[4:12], "big")
        self._sealer: Optional[ciphers.Aead] = None
        self._opener: Optional[ciphers.Aead] = None
        self._random = b""  # padding bytes, fetched from os.urandom in bulk
        self._random_at = 0

    def _nonce(self) -> bytes:
        nonce = self._fixed + self._counter.to_bytes(8, "big")
        self._counter = (self._counter + 1) & 0xFFFFFFFFFFFFFFFF
        return nonce

    def seal(self, seqno: int, *parts: Buffer) -> bytearray:
        size = sum(len(part) for part in parts)
        pad = 16 - (1 + size) % 16
        if pad < 4:
            pad += 16
        length = 1 + size + pad
        packet = bytearray(4 + length + 16)
        struct.pack_into(">IB", packet, 0, length, pad)
        at = 5
        for part in parts:
            end = at + len(part)
            packet[at:end] = part
            at = end
        taken = self._random_at
        if taken + pad > len(self._random):
            self._random, taken = os.urandom(4096), 0
        self._random_at = taken + pad
        packet[at : at + pad] = self._random[taken : taken + pad]
        if self._sealer is None:
            self._sealer = self._backend.aes_gcm(self._key, True)
        self._sealer.apply(self._nonce(), uint32(length), packet, 4, length)
        return packet

    def read(self, recv: Recv, seqno: int) -> memoryview:
        head = bytes(recv(4))
        length = struct.unpack(">I", head)[0]
        _check_length(length)
        if length % 16:
            raise _protocol_error(f"packet length {length} is not a multiple of the block size")
        rest = recv(length + 16)
        body = rest if isinstance(rest, bytearray) else bytearray(rest)
        if self._opener is None:
            self._opener = self._backend.aes_gcm(self._key, False)
        if not self._opener.apply(self._nonce(), head, body, 0, length):
            raise _protocol_error("bad AES-GCM tag on an incoming packet")
        return _unpad(body, 0, length)


class _Pieces:
    """Byte-exact slicing across a sequence of buffers, without joining them."""

    def __init__(self, parts: Sequence[Buffer]) -> None:
        self._views = deque(memoryview(part).cast("B") for part in parts)
        self.remaining = sum(len(view) for view in self._views)

    def take(self, count: int) -> list[memoryview]:
        """The next ``count`` bytes, as views (``count`` must not exceed :attr:`remaining`)."""
        out = []
        self.remaining -= count
        while count:
            view = self._views.popleft()
            if len(view) > count:
                self._views.appendleft(view[count:])
                view = view[:count]
            out.append(view)
            count -= len(view)
        return out


def _check_length(length: int) -> None:
    # A text banner (or garbage) read as a 32-bit length is enormous; refuse it.
    if length < 8 or length > 1024 * 1024 + 4096:
        raise _protocol_error(f"implausible packet length {length}")


def _protocol_error(detail: str) -> GError:
    return GError(f"SSH protocol error: {detail}", errno.EPROTO)


# -- algorithm catalogues ----------------------------------------------------

_KEX_ALGS = (
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group14-sha256",
)
_HOSTKEY_ALGS = (
    "ssh-ed25519",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ecdsa-sha2-nistp256",
    "ssh-rsa",
)
_MACS = (
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
)
_MAC_HASH = {
    "hmac-sha2-256-etm@openssh.com": ("sha256", True),
    "hmac-sha2-512-etm@openssh.com": ("sha512", True),
    "hmac-sha2-256": ("sha256", False),
    "hmac-sha2-512": ("sha512", False),
}
_CIPHER_KEYLEN = {
    "aes128-gcm@openssh.com": (16, 12),
    "aes256-gcm@openssh.com": (32, 12),
    "chacha20-poly1305@openssh.com": (64, 0),
    "aes256-ctr": (32, 16),
    "aes192-ctr": (24, 16),
    "aes128-ctr": (16, 16),
}
_KEX_HASH = {
    "curve25519-sha256": "sha256",
    "curve25519-sha256@libssh.org": "sha256",
    "diffie-hellman-group14-sha256": "sha256",
    "diffie-hellman-group16-sha512": "sha512",
}
_DH_GROUP = {
    "diffie-hellman-group14-sha256": _GROUP14_P,
    "diffie-hellman-group16-sha512": _GROUP16_P,
}


def _ciphers_preferred(backend: ciphers.Backend) -> tuple[str, ...]:
    """AES-GCM first, then AES-CTR and ChaCha20 through cryptography."""
    gcm = ("aes128-gcm@openssh.com", "aes256-gcm@openssh.com") if backend.has_gcm else ()
    aes = ("aes256-ctr", "aes192-ctr", "aes128-ctr")
    chacha = ("chacha20-poly1305@openssh.com",)
    return gcm + ((chacha + aes) if backend.fast_chacha else (aes + chacha))


def _negotiate(mine: Sequence[str], theirs: Sequence[str]) -> str:
    for candidate in mine:
        if candidate in theirs:
            return candidate
    raise _protocol_error(f"no common algorithm between {list(mine)} and {list(theirs)}")


def derive_key(
    shared: int, h: bytes, session_id: bytes, letter: str, length: int, digest: str
) -> bytes:
    """:rfc:`4253` §7.2 key material: ``HASH(K || H || letter || session_id)``, extended."""
    if length == 0:
        return b""
    material = hashlib.new(digest, mpint(shared) + h + letter.encode() + session_id).digest()
    while len(material) < length:
        material += hashlib.new(digest, mpint(shared) + h + material).digest()
    return material[:length]


def make_cipher(
    backend: ciphers.Backend,
    cipher: str,
    mac: str,
    shared: int,
    h: bytes,
    session_id: bytes,
    digest: str,
    letters: tuple[str, str, str],
) -> _Cipher:
    """Build one direction's record protection from the exchanged secret.

    ``letters`` are the :rfc:`4253` IV/key/MAC labels for the direction:
    ``("A", "C", "E")`` client->server, ``("B", "D", "F")`` server->client.
    """
    key_len, iv_len = _CIPHER_KEYLEN[cipher]
    iv = derive_key(shared, h, session_id, letters[0], iv_len, digest)
    key = derive_key(shared, h, session_id, letters[1], key_len, digest)
    if cipher == "chacha20-poly1305@openssh.com":
        return _ChachaCipher(backend, key)
    if cipher.endswith("-gcm@openssh.com"):
        return _GcmCipher(backend, key, iv)
    name, etm = _MAC_HASH[mac]
    mac_key = derive_key(shared, h, session_id, letters[2], hashlib.new(name).digest_size, digest)
    return _CtrCipher(backend.aes_ctr(key, iv), _MAC(name, mac_key), etm)


@dataclass(**SLOTS)
class _Negotiated:
    kex: str
    hostkey: str
    cipher_cs: str
    cipher_sc: str
    mac_cs: str
    mac_sc: str


class SSHTransport:
    """A live SSH connection exposing the byte-stream the SFTP client wants."""

    def __init__(
        self,
        endpoint: Endpoint,
        auth: Auth,
        sock: socket.socket,
        *,
        backend: Optional[ciphers.Backend] = None,
    ) -> None:
        self.endpoint = endpoint
        self.auth = auth
        self._sock = sock
        self._backend = backend if backend is not None else ciphers.get()
        # Socket bytes land in _rbuf; _rbuf[_rstart:_rend] is not yet consumed.
        self._rbuf = bytearray(_RECV_BUFFER)
        self._rstart = 0
        self._rend = 0
        self._send_lock = threading.Lock()
        # Held for a whole key exchange so no channel data is sent between our
        # KEXINIT and NEWKEYS (RFC 4253 §7.1); a data send takes it per packet.
        self._kex_lock = threading.Lock()
        self._out: _Cipher = _NullCipher()
        self._in: _Cipher = _NullCipher()
        self._out_seq = 0
        self._in_seq = 0
        self._client_kexinit = b""
        self._session_id = b""
        self._server_version = b""
        self._server_sig_algs: tuple[str, ...] = ()
        # channel state
        self._channel = 0
        self._remote_channel = 0
        self._remote_window = 0
        self._remote_maxpacket = 0
        self._local_window = _LOCAL_WINDOW
        # Received channel data: views of the decrypted packets, not yet
        # copied anywhere, and their total length.
        self._inbuf: deque[memoryview] = deque()
        self._inlen = 0
        self._lock = threading.Lock()  # guards channel state; _cond waits on it
        self._cond = threading.Condition(self._lock)
        # Wake-up batching: a waiting recv_into wants _want bytes, and is woken
        # early only when the reader goes _idle (about to block on the socket);
        # _idled counts those moments, so a wake-up is never missed.
        self._want = 1
        self._idle = True
        self._idled = 0
        self._eof = False
        self._error: Optional[GError] = None
        self._reader: Optional[threading.Thread] = None
        self._closed = False

    # -- low-level I/O -----------------------------------------------------------

    def _recv_exact(self, count: int) -> bytearray:
        """The next ``count`` bytes of the connection, as a fresh ``bytearray``."""
        start = self._rstart
        if self._rend - start < count:
            self._fill(count)
            start = self._rstart
        self._rstart = start + count
        return self._rbuf[start : start + count]

    def _fill(self, count: int) -> None:
        """Receive until ``count`` unconsumed bytes are buffered, reading all that is ready."""
        buf = self._rbuf
        pending = self._rend - self._rstart
        if len(buf) - self._rstart < count:  # no room after the unread bytes: compact
            target = buf if count <= len(buf) else bytearray(count)
            target[:pending] = buf[self._rstart : self._rend]
            self._rbuf = buf = target
            self._rstart, self._rend = 0, pending
        with memoryview(buf) as view:
            while self._rend - self._rstart < count:
                self._rend += self._recv_idle(view[self._rend :])

    def _recv_idle(self, view: memoryview) -> int:
        """:meth:`_recv_some`, first handing a waiting consumer whatever data there is.

        Channel data is delivered in batches (see :meth:`recv_into`); this is
        the other half - nothing buffered is held back while we might block.
        """
        with self._lock:
            self._idle = True
            self._idled += 1
            if self._inlen:
                self._cond.notify_all()
        try:
            return self._recv_some(view)
        finally:
            self._idle = False

    def _recv_some(self, view: memoryview) -> int:
        try:
            got = self._sock.recv_into(view)
        except TIMEOUTS as exc:
            raise GError(f"Timed out reading from {self.endpoint.label}", errno.ETIMEDOUT) from exc
        except OSError as exc:
            raise self._io_failure(exc) from exc
        if not got:
            raise GError(
                f"Connection to {self.endpoint.label} closed by the server", errno.ECONNRESET
            )
        return got

    def _write_all(self, data: Buffer) -> None:
        try:
            self._sock.sendall(data)
        except OSError as exc:
            raise self._io_failure(exc) from exc

    def _io_failure(self, exc: OSError) -> GError:
        return GError(
            f"Connection to {self.endpoint.label} failed: {exc.strerror or exc}",
            exc.errno or errno.ECONNRESET,
        )

    def _send_packet(self, *parts: Buffer) -> None:
        with self._send_lock:
            self._write_all(self._out.seal(self._out_seq, *parts))
            self._out_seq = (self._out_seq + 1) & 0xFFFFFFFF

    def _read_payload(self) -> memoryview:
        payload = self._in.read(self._recv_exact, self._in_seq)
        self._in_seq = (self._in_seq + 1) & 0xFFFFFFFF
        return payload

    def _recv_packet(self) -> bytes:
        return bytes(self._read_payload())

    # -- version exchange --------------------------------------------------------

    def _exchange_versions(self) -> bytes:
        self._write_all(_VERSION + b"\r\n")
        server = b""
        while True:
            line = self._read_line()
            if line.startswith(b"SSH-"):
                server = line
                break
            # RFC 4253: a server may print banner lines before its identifier.
        if not server.startswith(b"SSH-2.0-") and not server.startswith(b"SSH-1.99-"):
            raise _protocol_error(f"unsupported server version {server!r}")
        return server

    def _read_line(self) -> bytes:
        line = b""
        while not line.endswith(b"\n"):
            line += self._recv_exact(1)
            if len(line) > 4096:
                raise _protocol_error("server identification line too long")
        return line.rstrip(b"\r\n")

    # -- key exchange ------------------------------------------------------------

    def _build_kexinit(self) -> bytes:
        def names(items: Sequence[str]) -> bytes:
            return string(",".join(items))

        kex = [*_KEX_ALGS, "ext-info-c"]
        cipher = list(_ciphers_preferred(self._backend))
        body = bytes([MSG_KEXINIT]) + os.urandom(16)
        body += names(kex)
        body += names(_HOSTKEY_ALGS)
        body += names(cipher) + names(cipher)
        body += names(_MACS) + names(_MACS)
        body += names(["none"]) + names(["none"])
        body += names([]) + names([])
        body += bytes([0]) + uint32(0)  # first_kex_packet_follows, reserved
        return body

    @staticmethod
    def _parse_kexinit(payload: bytes) -> list[list[str]]:
        reader = Reader(payload)
        reader.take(17)  # message id + cookie
        lists = [reader.name_list() for _ in range(10)]
        reader.byte()  # first_kex_packet_follows
        reader.uint32()
        return lists

    def _negotiate_algs(self, server_kexinit: bytes) -> _Negotiated:
        server = self._parse_kexinit(server_kexinit)
        cipher = list(_ciphers_preferred(self._backend))
        return _Negotiated(
            kex=_negotiate(_KEX_ALGS, server[0]),
            hostkey=_negotiate(_HOSTKEY_ALGS, server[1]),
            cipher_cs=_negotiate(cipher, server[2]),
            cipher_sc=_negotiate(cipher, server[3]),
            mac_cs=_negotiate(_MACS, server[4]),
            mac_sc=_negotiate(_MACS, server[5]),
        )

    def _key_exchange(
        self, server_version: bytes, initial: bool, server_kexinit: Optional[bytes] = None
    ) -> None:
        with self._kex_lock:
            self._key_exchange_locked(server_version, initial, server_kexinit)

    def _key_exchange_locked(
        self, server_version: bytes, initial: bool, server_kexinit: Optional[bytes]
    ) -> None:
        client_kexinit = self._build_kexinit()
        self._send_packet(client_kexinit)
        if server_kexinit is None:
            payload = self._recv_packet()
            while payload[0] != MSG_KEXINIT:
                payload = self._dispatch_transport(payload)
            server_kexinit = payload
        chosen = self._negotiate_algs(server_kexinit)
        if chosen.kex in _DH_GROUP:
            shared, host_blob, host_sig, exchange = self._kex_dh(chosen)
        else:
            shared, host_blob, host_sig, exchange = self._kex_curve(chosen)
        digest = _KEX_HASH[chosen.kex]
        h = hashlib.new(
            digest,
            string(_VERSION)
            + string(server_version)
            + string(client_kexinit)
            + string(server_kexinit)
            + string(host_blob)
            + exchange
            + mpint(shared),
        ).digest()
        self._verify_host_key(chosen.hostkey, host_blob, host_sig, h)
        if initial:
            self._session_id = h
        # NEWKEYS both ways, then swap ciphers in.
        reply = self._recv_packet()
        if reply[0] != MSG_NEWKEYS:
            raise _protocol_error(f"expected NEWKEYS, got message {reply[0]}")
        self._send_packet(bytes([MSG_NEWKEYS]))
        with self._send_lock:
            self._out = make_cipher(
                self._backend,
                chosen.cipher_cs,
                chosen.mac_cs,
                shared,
                h,
                self._session_id,
                digest,
                ("A", "C", "E"),
            )
        self._in = make_cipher(
            self._backend,
            chosen.cipher_sc,
            chosen.mac_sc,
            shared,
            h,
            self._session_id,
            digest,
            ("B", "D", "F"),
        )

    def _kex_curve(self, chosen: _Negotiated) -> tuple[int, bytes, bytes, bytes]:
        private, public = x25519.generate()
        self._send_packet(bytes([MSG_KEX_ECDH_INIT]) + string(public))
        reply = self._expect(MSG_KEX_ECDH_REPLY, "KEX_ECDH_REPLY")
        host_blob = reply.string()
        server_pub = reply.string()
        host_sig = reply.string()
        shared_bytes = x25519.x25519(private, server_pub)
        shared = int.from_bytes(shared_bytes, "big")
        exchange = string(public) + string(server_pub)
        return shared, host_blob, host_sig, exchange

    def _kex_dh(self, chosen: _Negotiated) -> tuple[int, bytes, bytes, bytes]:
        p = _DH_GROUP[chosen.kex]
        x = int.from_bytes(os.urandom(256), "big") % (p - 2) + 1
        e = pow(2, x, p)
        self._send_packet(bytes([MSG_KEX_ECDH_INIT]) + mpint(e))
        reply = self._expect(MSG_KEX_ECDH_REPLY, "KEXDH_REPLY")
        host_blob = reply.string()
        f = reply.mpint()
        host_sig = reply.string()
        if not 1 < f < p - 1:
            raise _protocol_error("server DH value out of range")
        shared = pow(f, x, p)
        exchange = mpint(e) + mpint(f)
        return shared, host_blob, host_sig, exchange

    def _expect(self, msg: int, name: str) -> Reader:
        payload = self._recv_packet()
        while payload[0] in (MSG_IGNORE, MSG_DEBUG):
            payload = self._recv_packet()
        if payload[0] != msg:
            raise _protocol_error(f"expected {name}, got message {payload[0]}")
        return Reader(payload[1:])

    # -- host key verification ---------------------------------------------------

    def _verify_host_key(
        self, algorithm: str, host_blob: bytes, host_sig: bytes, h: bytes
    ) -> PublicKey:
        try:
            key = parse_public_blob(host_blob)
        except KeyError_ as exc:
            raise _protocol_error(f"unreadable host key: {exc}") from None
        if not key.verify(algorithm, h, host_sig):
            raise GError(
                f"Host key signature from {self.endpoint.label} did not verify", errno.EACCES
            )
        self._check_known_host(key)
        return key

    def _check_known_host(self, key: PublicKey) -> None:
        policy = self.endpoint.strict_host_keys
        paths = _known_hosts_paths(self.endpoint)
        known = KnownHosts.load(paths)
        result = known.check(self.endpoint.host, self.endpoint.port, key)
        if result.status == "match":
            return
        if result.status == "revoked":
            raise GError(f"Host key for {self.endpoint.label} has been revoked", errno.EACCES)
        if result.status == "changed":
            raise GError(
                "Host key verification failed: REMOTE HOST IDENTIFICATION HAS CHANGED "
                f"for {self.endpoint.label}",
                errno.EACCES,
            )
        # unknown
        if policy in ("no", "off", "accept-all"):
            return
        if policy == "accept-new":
            _record_host_key(paths, self.endpoint, key)
            return
        raise GError(
            f"Host key for {self.endpoint.label} is not known (StrictHostKeyChecking={policy})",
            errno.EACCES,
        )

    # -- authentication ----------------------------------------------------------

    def _authenticate(self) -> None:
        self._send_packet(bytes([MSG_SERVICE_REQUEST]) + string("ssh-userauth"))
        reply = self._recv_packet()
        while reply[0] in (MSG_IGNORE, MSG_DEBUG, MSG_EXT_INFO):
            if reply[0] == MSG_EXT_INFO:
                self._parse_ext_info(reply)
            reply = self._recv_packet()
        if reply[0] != MSG_SERVICE_ACCEPT:
            raise _protocol_error(f"expected SERVICE_ACCEPT, got message {reply[0]}")
        methods = "publickey/password"
        for key in self.auth.keys:
            if self._auth_publickey(key):
                return
        if self.auth.password and self._auth_password():
            return
        raise GError(
            f"All supported authentication methods failed for {self.endpoint.label} "
            f"(tried {methods})",
            errno.EACCES,
        )

    def _parse_ext_info(self, payload: bytes) -> None:
        reader = Reader(payload[1:])
        for _ in range(reader.uint32()):
            name = reader.text()
            value = reader.string()
            if name == "server-sig-algs":
                self._server_sig_algs = tuple(value.decode("utf-8", "replace").split(","))

    def _rsa_algorithm(self, key: PrivateKey) -> str:
        if self._server_sig_algs:
            for candidate in key.algorithms():
                if candidate in self._server_sig_algs:
                    return candidate
        return key.algorithms()[0]

    def _auth_publickey(self, key: PrivateKey) -> bool:
        algorithm = self._rsa_algorithm(key) if key.kind == "ssh-rsa" else key.algorithms()[0]
        request = (
            bytes([MSG_USERAUTH_REQUEST])
            + string(self.auth.username)
            + string("ssh-connection")
            + string("publickey")
            + bytes([1])
            + string(algorithm)
            + string(key.public.blob)
        )
        signed = string(self._session_id) + request
        request += string(key.sign(signed, algorithm))
        self._send_packet(request)
        return self._auth_result()

    def _auth_password(self) -> bool:
        request = (
            bytes([MSG_USERAUTH_REQUEST])
            + string(self.auth.username)
            + string("ssh-connection")
            + string("password")
            + bytes([0])
            + string(self.auth.password)
        )
        self._send_packet(request)
        return self._auth_result()

    def _auth_result(self) -> bool:
        while True:
            reply = self._recv_packet()
            code = reply[0]
            if code == MSG_USERAUTH_SUCCESS:
                return True
            if code == MSG_USERAUTH_FAILURE:
                return False
            if code == MSG_USERAUTH_BANNER:
                if self.auth.banner is not None:
                    self.auth.banner(Reader(reply[1:]).text())
                continue
            if code in (MSG_IGNORE, MSG_DEBUG, MSG_USERAUTH_PK_OK):
                continue
            raise _protocol_error(f"unexpected message {code} during authentication")

    # -- channel & subsystem -----------------------------------------------------

    def _await_reply(self, stop: tuple[int, ...]) -> bytes:
        """Read until a packet in ``stop``, handling housekeeping in between.

        OpenSSH interleaves ``CHANNEL_WINDOW_ADJUST``, global requests (a
        ``hostkeys-00@openssh.com`` announcement) and the like with the channel
        confirmations we are waiting for; each is dealt with here.
        """
        while True:
            reply = self._recv_packet()
            code = reply[0]
            if code in stop:
                return reply
            if code == MSG_CHANNEL_WINDOW_ADJUST:
                r = Reader(reply[1:])
                r.uint32()
                with self._cond:
                    self._remote_window += r.uint32()
            elif code == MSG_GLOBAL_REQUEST:
                self._decline_global(reply)
            elif code == MSG_CHANNEL_REQUEST:
                self._decline_channel_request(reply)
            elif code in (MSG_IGNORE, MSG_DEBUG):
                continue
            else:
                raise _protocol_error(f"unexpected message {code} setting up the channel")

    def _open_channel(self) -> None:
        self._send_packet(
            bytes([MSG_CHANNEL_OPEN])
            + string("session")
            + uint32(self._channel)
            + uint32(self._local_window)
            + uint32(_LOCAL_MAXPACKET)
        )
        reply = self._await_reply((MSG_CHANNEL_OPEN_CONFIRMATION, MSG_CHANNEL_OPEN_FAILURE))
        if reply[0] == MSG_CHANNEL_OPEN_FAILURE:
            r = Reader(reply[1:])
            r.uint32()
            r.uint32()
            raise GError(f"Could not open an SSH session channel: {r.text()}", errno.ECONNREFUSED)
        r = Reader(reply[1:])
        r.uint32()  # our channel
        self._remote_channel = r.uint32()
        self._remote_window = r.uint32()
        self._remote_maxpacket = r.uint32()

    def _start_subsystem(self) -> None:
        self._send_packet(
            bytes([MSG_CHANNEL_REQUEST])
            + uint32(self._remote_channel)
            + string("subsystem")
            + bytes([1])
            + string("sftp")
        )
        reply = self._await_reply((MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE))
        if reply[0] == MSG_CHANNEL_FAILURE:
            raise GError(
                f"The server at {self.endpoint.label} has no sftp subsystem", errno.EPROTONOSUPPORT
            )

    # -- background reader -------------------------------------------------------

    def _run_reader(self) -> None:
        try:
            while True:
                if not self._handle_channel(self._read_payload()):
                    return
        except GError as exc:
            with self._cond:
                # Nothing else sets _error while this thread runs (a DISCONNECT
                # ends it), so only a deliberate close() hides the failure.
                if not self._closed:
                    self._error = exc
                self._cond.notify_all()

    def _handle_channel(self, payload: Buffer) -> bool:
        code = payload[0]
        if code == MSG_CHANNEL_DATA:
            # The bulk path: the data stays where it was decrypted until
            # recv_into copies it, once, to where the SFTP client wants it.
            size = int.from_bytes(payload[5:9], "big") if len(payload) >= 9 else -1
            if size < 0 or 9 + size > len(payload):
                raise _protocol_error("truncated CHANNEL_DATA")
            if size > _LOCAL_MAXPACKET or size > self._local_window:
                # Flow control is what bounds the memory channel data may take.
                raise _protocol_error("channel data beyond the window the server was given")
            self._account(size, memoryview(payload)[9 : 9 + size])
            return True
        if code == MSG_CHANNEL_EXTENDED_DATA:
            reader = Reader(payload[1:])
            reader.uint32()
            reader.uint32()
            self._account(len(reader.string()))  # stderr from the subsystem: drained
            return True
        if code == MSG_CHANNEL_WINDOW_ADJUST:
            reader = Reader(payload[1:])
            reader.uint32()
            with self._cond:
                self._remote_window += reader.uint32()
                self._cond.notify_all()
            return True
        if code in (MSG_CHANNEL_EOF, MSG_CHANNEL_CLOSE):
            with self._cond:
                self._eof = True
                self._cond.notify_all()
            return code != MSG_CHANNEL_CLOSE
        if code == MSG_CHANNEL_REQUEST:
            self._decline_channel_request(payload)
            return True
        if code == MSG_GLOBAL_REQUEST:
            self._decline_global(payload)
            return True
        if code == MSG_KEXINIT:
            self._rekey(bytes(payload))
            return True
        if code == MSG_DISCONNECT:
            reader = Reader(payload[1:])
            reader.uint32()
            with self._cond:
                self._eof = True
                self._error = GError(
                    f"Server {self.endpoint.label} disconnected: {reader.text()}", errno.ECONNRESET
                )
                self._cond.notify_all()
            return False
        # IGNORE, DEBUG, UNIMPLEMENTED, and anything else: skip.
        return True

    def _rekey(self, server_kexinit: bytes) -> None:
        # A server-initiated rekey: run the exchange inline in the reader.
        self._key_exchange(self._server_version, initial=False, server_kexinit=server_kexinit)

    def _decline_channel_request(self, payload: Buffer) -> None:
        reader = Reader(payload[1:])
        reader.uint32()
        reader.text()
        if reader.boolean():
            self._send_packet(bytes([MSG_CHANNEL_FAILURE]) + uint32(self._remote_channel))

    def _decline_global(self, payload: Buffer) -> None:
        reader = Reader(payload[1:])
        reader.text()
        if reader.boolean():
            self._send_packet(bytes([MSG_REQUEST_FAILURE]))

    def _account(self, size: int, data: Optional[memoryview] = None) -> None:
        """Charge ``size`` received bytes to our window, queueing ``data`` for :meth:`recv_into`.

        Once half the window is used it is topped up in one adjustment. One
        lock round trip per packet: this runs for every packet of a download.
        """
        with self._lock:
            if data is not None:
                self._inbuf.append(data)
                self._inlen += size
                if self._inlen >= self._want:
                    self._cond.notify_all()
            self._local_window -= size
            if self._local_window > _LOCAL_WINDOW // 2:
                return
            top_up = _LOCAL_WINDOW - self._local_window
            self._local_window = _LOCAL_WINDOW
        self._send_packet(
            bytes([MSG_CHANNEL_WINDOW_ADJUST]) + uint32(self._remote_channel) + uint32(top_up)
        )

    # -- the Stream interface ----------------------------------------------------

    def connect(self, server_version: bytes) -> None:
        self._server_version = server_version
        self._key_exchange(server_version, initial=True)
        self._authenticate()
        self._open_channel()
        self._start_subsystem()
        self._reader = threading.Thread(
            target=self._run_reader, name=f"xgfal-ssh-{self.endpoint.host}", daemon=True
        )
        self._reader.start()

    def _dispatch_transport(self, payload: bytes) -> bytes:
        # During the initial KEX loop, tolerate DEBUG/IGNORE before KEXINIT.
        if payload[0] in (MSG_IGNORE, MSG_DEBUG):
            return self._recv_packet()
        raise _protocol_error(f"expected KEXINIT, got message {payload[0]}")

    def send(self, *parts: Buffer) -> None:
        """Write ``parts``, in order, as channel data in packets the peer's limits allow.

        The parts are sliced into packets without being joined first, and as
        many packets as the window admits are sealed together and handed to
        the socket in one gathered write: one system call and no extra copy,
        rather than one of each per 32 KiB packet.
        """
        pieces = _Pieces(parts)
        while pieces.remaining:
            with self._cond:
                if self._error is not None:
                    raise GError(self._error.message, self._error.code)
                while self._remote_window <= 0 or self._remote_maxpacket <= 0:
                    self._cond.wait()
                    if self._error is not None:
                        raise GError(self._error.message, self._error.code)
                budget = min(self._remote_window, pieces.remaining)
                self._remote_window -= budget
                maxpacket = self._remote_maxpacket
            with self._kex_lock, self._send_lock:
                packets = []
                while budget:
                    chunk = min(maxpacket, budget)
                    header = _DATA_HEADER.pack(MSG_CHANNEL_DATA, self._remote_channel, chunk)
                    packets.append(self._out.seal(self._out_seq, header, *pieces.take(chunk)))
                    self._out_seq = (self._out_seq + 1) & 0xFFFFFFFF
                    budget -= chunk
                self._write_gathered(packets)

    def _write_gathered(self, packets: list[Buffer]) -> None:
        """Send every packet, in order, with as few system calls as the socket allows."""
        if len(packets) == 1 or not hasattr(self._sock, "sendmsg"):
            self._write_all(packets[0] if len(packets) == 1 else b"".join(packets))
            return
        views = deque(memoryview(packet) for packet in packets)
        try:
            while views:
                sent = self._sock.sendmsg(views)
                while views and sent >= len(views[0]):
                    sent -= len(views.popleft())
                if sent:
                    views[0] = views[0][sent:]
        except OSError as exc:
            raise self._io_failure(exc) from exc

    def recv_into(self, view: memoryview) -> int:
        """Channel data into ``view``: as much as fits, once it is there.

        Waking this thread per packet would cost a context switch each, so
        it waits until ``view`` can be filled - or until the reader is about
        to block on the socket, the stream ends or fails, whichever is first
        - and then takes everything available.
        """
        want = len(view)
        taken: list[memoryview] = []
        with self._cond:
            idled = self._idled
            while True:
                have = self._inlen
                ready = self._idle or self._idled != idled or self._eof or self._error is not None
                if have >= want or (have and ready):
                    break
                if self._error is not None:
                    raise GError(self._error.message, self._error.code)
                if self._eof:
                    return 0
                self._want = want
                self._cond.wait()
            count = min(want, have)
            room = count
            while room:
                chunk = self._inbuf.popleft()
                if len(chunk) > room:
                    self._inbuf.appendleft(chunk[room:])
                    chunk = chunk[:room]
                taken.append(chunk)
                room -= len(chunk)
            self._inlen -= count
        # Only this thread consumes, so the copy can run outside the lock.
        at = 0
        for chunk in taken:
            view[at : at + len(chunk)] = chunk
            at += len(chunk)
        return count

    def close(self) -> None:
        with self._cond:
            if self._closed:
                return
            self._closed = True
            self._eof = True
            self._cond.notify_all()
        try:
            self._send_packet(bytes([MSG_CHANNEL_CLOSE]) + uint32(self._remote_channel))
        except GError:
            pass
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()


def _known_hosts_paths(endpoint: Endpoint) -> list[str]:
    if endpoint.known_hosts:
        return [endpoint.known_hosts]
    home = os.path.expanduser("~")
    return [
        os.path.join(home, ".ssh", "known_hosts"),
        "/etc/ssh/ssh_known_hosts",
    ]


def _record_host_key(paths: Sequence[str], endpoint: Endpoint, key: PublicKey) -> None:
    line = KnownHosts.line_for(endpoint.host, endpoint.port, key)
    target = paths[0]
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        # Recording is best-effort; a read-only known_hosts must not fail the
        # connection when the policy has already accepted the key.
        pass


def _open_socket(endpoint: Endpoint) -> socket.socket:
    timeout = float(endpoint.timeout) if endpoint.timeout > 0 else None
    try:
        sock = socket.create_connection((endpoint.host, endpoint.port), timeout=timeout)
    except socket.gaierror as exc:
        raise GError(f"Could not resolve host {endpoint.host}: {exc}", errno.EREMOTE) from exc
    except TIMEOUTS as exc:
        raise GError(f"Connection to {endpoint.label} timed out", errno.ETIMEDOUT) from exc
    except OSError as exc:
        code = exc.errno or errno.ECONNREFUSED
        raise GError(f"Could not connect to {endpoint.label}: {exc.strerror or exc}", code) from exc
    sock.settimeout(timeout)
    # Packets are written whole, one send each; Nagle would hold back each
    # one's short tail (and every small SFTP request) for the peer's delayed
    # ACK - tens of milliseconds per stall on a bulk copy.
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def connect(
    endpoint: Endpoint,
    auth: Auth,
    *,
    sock: Optional[socket.socket] = None,
    backend: Optional[ciphers.Backend] = None,
) -> SSHTransport:
    """Open an SSH connection to ``endpoint`` and start the ``sftp`` subsystem."""
    owned = sock is None
    connection = _open_socket(endpoint) if sock is None else sock
    transport = SSHTransport(endpoint, auth, connection, backend=backend)
    try:
        server_version = transport._exchange_versions()
        transport.connect(server_version)
    except BaseException:
        if owned:
            try:
                connection.close()
            except OSError:
                pass
        raise
    return transport
