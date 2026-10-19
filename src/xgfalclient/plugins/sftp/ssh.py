"""Transport tier 3: an SSH-2 client, in Python, carrying the ``sftp`` subsystem.

The last-resort tier: ``auto`` prefers OpenSSH and then paramiko (the
``sftp`` extra), and comes here only when neither can serve the connection.
The in-process test server (:mod:`xgfalclient.testing.sftp`) is built on
the same transport code.

When there is no ``ssh`` binary and no usable paramiko - with a *password*
the ``ssh`` binary is never used, because a password must never leave the
process (see :mod:`.openssh`) - the plugin speaks SSH itself. This module is
that client: the :rfc:`4253` transport (version exchange, key exchange,
binary packet protocol), :rfc:`4252` user authentication, and :rfc:`4254`
one session channel running ``subsystem sftp``.

What it negotiates, best first, matching what OpenSSH offers:

* **key exchange** ``curve25519-sha256`` (and its ``@libssh.org`` alias),
  ``diffie-hellman-group16-sha512``, ``diffie-hellman-group14-sha256``;
* **host key** ``ssh-ed25519``, ``rsa-sha2-512``/``256``,
  ``ecdsa-sha2-nistp{256,384,521}`` (and legacy ``ssh-rsa`` verification), checked
  against ``known_hosts`` with the endpoint's ``StrictHostKeyChecking``
  policy - a first key recorded, a changed key refused, a ``@revoked`` key
  always refused;
* **cipher** ``aes{128,256}-gcm@openssh.com`` (one native pass per packet
  encrypts and authenticates, the fastest by far here), then
  ``chacha20-poly1305@openssh.com``, then ``aes{128,192,256}-ctr``. Since
  0.4.0 every primitive comes from ``cryptography`` through
  :mod:`..crypto.ciphers`, whose single backend reports both GCM and fast
  ChaCha20, so that is the order on every platform;
* **MAC** ``hmac-sha2-{256,512}`` and their encrypt-then-MAC
  ``-etm@openssh.com`` forms (the AEAD ciphers carry their own);
* **strict KEX** (``kex-strict-c-v00@openssh.com``, OpenSSH's ``PROTOCOL``
  section 1.10), the countermeasure to the Terrapin prefix-truncation attack
  (CVE-2023-48795): with a server that offers it, the initial key exchange
  admits no message it does not need, and every ``NEWKEYS`` restarts that
  direction's sequence number at zero.

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

Where to start reading: :func:`connect` opens the socket, runs
:meth:`SSHTransport._exchange_versions`, then :meth:`SSHTransport.connect`
walks the phases in order - key exchange, ``ssh-userauth``, one ``session``
channel, ``subsystem sftp`` - and starts the reader thread. After that the
object is a plain byte stream (``send`` / ``recv_into`` / ``abort`` /
``close``) for :class:`~.client.SFTPClient`. Record protection lives in the
``_Cipher`` subclasses, one object per direction, swapped in at ``NEWKEYS``.

What must not break:

* the test server (:mod:`xgfalclient.testing._sftp`) imports the message
  numbers, algorithm catalogues, :class:`SessionKeys`, :func:`make_cipher` and
  the cipher classes from here, so a change to any of them changes both ends
  of every in-tree SFTP test - interop tests against a real ``sshd`` are the
  only independent check;
* the lock order is ``_kex_lock`` then ``_send_lock`` then ``_lock``; the
  reader thread never holds ``_lock`` while it sends;
* under strict KEX the sequence numbers restart at every ``NEWKEYS`` in both
  directions, and nothing but the key-exchange messages may arrive before the
  first one (see :meth:`SSHTransport._begin_strict_kex`).
"""

from __future__ import annotations

import contextlib
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
from ...plugin import shutdown_sockets
from .endpoint import Endpoint

__all__ = ["Auth", "SSHTransport", "connect"]

#: Our identification string (:rfc:`4253` §4.2), sent with CRLF. It is also
#: ``V_C`` in the exchange hash, so it must be byte-identical in both places.
_VERSION = b"SSH-2.0-xgfalclient"

#: The strict-KEX pseudo-algorithms (OpenSSH ``PROTOCOL`` 1.10). Each side
#: appends its own to the kex list of its *first* KEXINIT only; strict mode is
#: on when we sent ours and the server's first KEXINIT carries its one.
STRICT_KEX_CLIENT = "kex-strict-c-v00@openssh.com"
STRICT_KEX_SERVER = "kex-strict-s-v00@openssh.com"

# -- message numbers (RFC 4253/4252/4254) ------------------------------------
# The first payload byte of every packet. RFC 4250 §4.1 assigns the ranges:
# 1-19 transport generic, 20-29 algorithm negotiation, 30-49 specific to the
# key-exchange method (so 30/31 are KEXDH_* for classic DH and KEX_ECDH_* for
# curve25519, RFC 8731), 50-79 user authentication (60 is method-specific:
# PK_OK for publickey), 80-127 connection protocol. EXT_INFO is RFC 8308.
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
#: :rfc:`4254` §5.2: the peer may send at most the window before we adjust it,
#: so the window is also the bound on queued, unread download data; 8 MiB
#: keeps a long fat link busy while capping that memory.
_LOCAL_WINDOW = 8 * 1024 * 1024
#: The ``maximum packet size`` we advertise. Bigger than OpenSSH's 32 KiB
#: default so a server that honours it sends fewer, larger packets - per
#: packet, not per byte, is where the Python cost is.
_LOCAL_MAXPACKET = 256 * 1024
#: Initial size of the socket read buffer (it grows for a larger packet).
_RECV_BUFFER = 1024 * 1024

#: The fixed head of ``SSH_MSG_CHANNEL_DATA`` (:rfc:`4254` §5.2): message
#: byte, recipient channel, then the uint32 length of the ``string`` data -
#: packed once per packet so the data itself is never re-copied.
_DATA_HEADER = struct.Struct(">BII")

Buffer = bytes | bytearray | memoryview
#: Reads exactly ``count`` bytes from the connection.
Recv = Callable[[int], Buffer]

# Diffie-Hellman groups (RFC 3526 §3 and §5: the 2048-bit and 4096-bit MODP
# groups), generator 2, as RFC 8268 names them group14 and group16.
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


@dataclass(slots=True)
class Auth:
    """How to authenticate: a username, optional keys and an optional password.

    The plugin builds one per connection from the :class:`Endpoint` and the
    keys it has already parsed (so a bad passphrase fails before any network
    traffic). Methods are tried in a fixed order - every key, then the
    password - with no ``none`` probe and no keyboard-interactive.
    """

    #: The ``user name`` of every ``USERAUTH_REQUEST`` (:rfc:`4252` §5).
    username: str
    #: Decrypted private keys, offered in order; empty skips publickey.
    keys: tuple[PrivateKey, ...] = ()
    #: Sent only after every key failed; empty skips password authentication.
    password: str = ""
    #: Called with the text of any ``USERAUTH_BANNER``; ``None`` drops banners.
    banner: Callable[[str], None] | None = None


def _pad(payload: Buffer, block: int, header: int = 0) -> bytes:
    """A binary-packet body: ``padding_length || payload || random padding``.

    ``header`` is the number of bytes that precede this body inside the region
    the padding must block-align. For a standard packet (and any packet before
    the keys are in place) that region includes the 4-byte ``packet_length``
    field (RFC 4253 §6), so ``header`` is 4; for encrypt-then-MAC and for
    ``chacha20-poly1305`` the length is sent apart and ``header`` is 0.

    RFC 4253 §6 wants at least 4 bytes of padding, so a remainder under 4
    takes a whole extra block. The padding is random, not zero, as the RFC
    recommends; it is never read back, only skipped by :func:`_unpad`.
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
    The result is a view into ``body``: no copy is made, so ``body`` must not
    be reused while the payload is alive (each packet gets a fresh buffer).
    """
    pad = body[start]
    if pad + 1 > length:
        raise _protocol_error(f"padding length {pad} exceeds the packet")
    return memoryview(body)[start + 1 : start + length - pad]


def _chacha_iv(seqno: int, counter: int) -> bytes:
    """The 16-byte ChaCha20 IV block for ``chacha20-poly1305@openssh.com``.

    OpenSSH runs the original ChaCha20 (a 64-bit block counter and a 64-bit
    nonce), with the packet sequence number, big-endian, as the nonce.
    ``cryptography`` takes the 16-byte initial state block instead: a
    little-endian counter, then the nonce words. So the counter goes in the
    first 8 bytes (its high half always zero - no packet is 256 GiB) and the
    sequence number in the last 8. Counter 0 yields the Poly1305 key and
    encrypts the length; the payload starts at counter 1.
    """
    return struct.pack("<I", counter) + b"\x00\x00\x00\x00" + struct.pack(">Q", seqno)


class _Cipher:
    """One direction's record protection: framing, encryption and MAC.

    The :rfc:`4253` §6 binary packet is ``uint32 packet_length || byte
    padding_length || payload || padding || mac``; each subclass differs in
    what it encrypts, what the MAC covers and whether the length travels in
    clear. Instances are stateful (keystream position, GCM counter), owned by
    one :class:`SSHTransport` direction and never shared: the sealing side is
    called only under ``_send_lock``, the opening side only by whichever
    thread is reading (the connecting thread, then the reader thread).
    ``seqno`` is the transport's implicit 32-bit packet counter (§6.4), which
    the HMAC and ChaCha20 modes authenticate and AES-GCM ignores.
    """

    #: The alignment unit for padding (§6: the cipher block size, at least 8).
    block = 8
    #: Whether the record carries an integrity check (false only before keys).
    has_mac = False

    def seal(self, seqno: int, *parts: Buffer) -> Buffer:
        """The wire form of the packet whose payload is ``parts`` concatenated.

        ``parts`` lets a caller pass a header and data slices without joining
        them first; the result is ready for one socket write.
        """
        raise NotImplementedError

    def read(self, recv: Recv, seqno: int) -> memoryview:
        """Read, authenticate and decrypt one packet; its payload.

        ``recv`` must return exactly the bytes asked for (or raise). Any
        framing or integrity failure raises ``GError(EPROTO)``, and no
        payload byte is returned unless it authenticated.
        """
        raise NotImplementedError


class _NullCipher(_Cipher):
    """No encryption or MAC - the transport before ``NEWKEYS``.

    It only frames the initial ``KEXINIT`` and key-exchange messages;
    ``seqno`` is ignored, though the transport still counts it (strict KEX
    checks that count when the server's ``KEXINIT`` arrives).
    """

    def seal(self, seqno: int, *parts: Buffer) -> bytes:
        """``packet_length || body``, the whole packet aligned to 8 bytes."""
        body = _pad(b"".join(parts), self.block, header=4)  # length is block-aligned too
        return uint32(len(body)) + body

    def read(self, recv: Recv, seqno: int) -> memoryview:
        """Length, sanity-checked, then the body; nothing to verify."""
        length = struct.unpack(">I", recv(4))[0]
        _check_length(length)
        return _unpad(recv(length), 0, length)


class _MAC:
    """A keyed HMAC over ``seqno || data``, as :rfc:`4253` §6.4 computes it.

    ``hmac-sha2-256``/``-512`` are :rfc:`6668`; the key is as long as the
    digest, derived with letter ``E`` or ``F``. The tag is not truncated.
    """

    def __init__(self, name: str, key: bytes) -> None:
        """``name`` is a :mod:`hashlib` name (``sha256``, ``sha512``)."""
        self.name = name
        self.key = key
        #: Tag size in bytes - how much to read after each packet.
        self.length = hashlib.new(name).digest_size

    def compute(self, seqno: int, data: Buffer) -> bytes:
        """The tag for ``data`` as packet number ``seqno`` (a uint32 on the wire)."""
        return hmac.digest(self.key, struct.pack(">I", seqno) + data, self.name)


class _CtrCipher(_Cipher):
    """AES-CTR (:rfc:`4344`) with an HMAC, encrypt-and-MAC or encrypt-then-MAC.

    Encrypt-and-MAC is :rfc:`4253` §6.4: the MAC covers the *plaintext*
    packet and the length field is encrypted, so a reader must decrypt the
    first block to learn how much to read - before anything is
    authenticated. Acting on an unauthenticated length is what the
    Albrecht-Paterson-Watson plaintext recovery (2009) exploited against
    CBC-mode SSH; CTR resists that attack, but the ``-etm@openssh.com``
    forms remove the ordering altogether, which is why they are offered
    first: they send the length in clear and MAC ``length || ciphertext``, so a
    packet is verified before any of it is decrypted (OpenSSH ``PROTOCOL``
    section 1.5). CTR is one continuous keystream per direction across
    packets, so packets must be sealed and opened strictly in order.
    """

    block = 16
    has_mac = True

    def __init__(self, keystream: ciphers.Keystream, mac: _MAC, etm: bool) -> None:
        """Take ownership of ``keystream``; ``etm`` picks the MAC layout."""
        self._stream = keystream
        self._mac = mac
        self._etm = etm

    def seal(self, seqno: int, *parts: Buffer) -> bytes:
        """Pad, encrypt and append the HMAC, in the negotiated order."""
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
        """Verify then decrypt (EtM), or decrypt then verify (encrypt-and-MAC).

        The tag comparison is constant-time either way; a mismatch is
        ``EPROTO``, fatal to the connection - there is no resynchronising a
        stream whose packet boundaries can no longer be trusted.
        """
        if self._etm:
            length_bytes = bytes(recv(4))
            length = struct.unpack(">I", length_bytes)[0]
            _check_length(length)
            cipher = recv(length)
            tag = recv(self._mac.length)
            if not hmac.compare_digest(tag, self._mac.compute(seqno, length_bytes + cipher)):
                raise _protocol_error("bad MAC on an incoming packet")
            return _unpad(self._stream.update(cipher), 0, length)
        # Encrypt-and-MAC: the first block holds the encrypted length, so it
        # is decrypted alone to learn how much more of the packet to read.
        first = bytes(self._stream.update(recv(self.block)))
        length = struct.unpack(">I", first[:4])[0]
        _check_length(length)
        packet = first + self._stream.update(recv(4 + length - self.block))
        tag = recv(self._mac.length)
        if not hmac.compare_digest(tag, self._mac.compute(seqno, packet)):
            raise _protocol_error("bad MAC on an incoming packet")
        return _unpad(packet, 4, length)


class _ChachaCipher(_Cipher):
    """``chacha20-poly1305@openssh.com``: a Poly1305 tag, the length encrypted apart.

    OpenSSH's ``PROTOCOL.chacha20poly1305``: the 64-byte derived key is two
    ChaCha20 keys. The first 32 bytes (the "main" key) encrypt the payload
    and, at block counter 0, produce the one-time Poly1305 key; the second 32
    (the "header" key) encrypt only the 4-byte length, so a reader can learn
    the length without touching the body. The tag covers ``encrypted length
    || encrypted body`` and is checked before the body is decrypted. The
    nonce is the sequence number, so no state is carried between packets and
    a reordered or replayed packet fails its tag. The negotiated MAC is
    ignored; the IV length is 0 (nothing is derived for letters A/B).
    """

    block = 8
    has_mac = True

    def __init__(self, backend: ciphers.Backend, key: bytes) -> None:
        """Split the 64-byte ``key`` into the main and header ChaCha20 keys."""
        self._backend = backend
        self._main = backend.chacha20(key[:32])
        self._header = backend.chacha20(key[32:64])

    def _poly_key(self, seqno: int) -> bytes:
        """The Poly1305 key for packet ``seqno``: main keystream block 0, first 32 bytes."""
        return bytes(self._main.xor(_chacha_iv(seqno, 0), bytes(32)))

    def seal(self, seqno: int, *parts: Buffer) -> bytes:
        """Encrypted length, encrypted body, then the 16-byte Poly1305 tag."""
        body = _pad(b"".join(parts), self.block)
        enc_length = bytes(self._header.xor(_chacha_iv(seqno, 0), uint32(len(body))))
        enc_body = bytes(self._main.xor(_chacha_iv(seqno, 1), body))
        tag = self._backend.poly1305(self._poly_key(seqno), enc_length + enc_body)
        return enc_length + enc_body + tag

    def read(self, recv: Recv, seqno: int) -> memoryview:
        """Decrypt the length, read body and tag, verify, then decrypt the body.

        The length is used (bounded by :func:`_check_length`) before it is
        authenticated - unavoidable, since it says where the tag is - but the
        tag check that follows covers it.
        """
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

    This is :rfc:`5647` as OpenSSH adapted it (``PROTOCOL`` section 1.6):
    the 4-byte length is the AEAD's associated data, sent in clear but
    authenticated, and padding aligns only the encrypted part (``header=0``
    in :func:`_pad` terms). The negotiated MAC is ignored, and the sequence
    number plays no part - the nonce counter carries replay protection. A
    strict-KEX sequence reset does not touch it: each ``NEWKEYS`` brings a
    new cipher object with a freshly derived counter.
    """

    block = 16
    has_mac = True

    def __init__(self, backend: ciphers.Backend, key: bytes, iv: bytes) -> None:
        """``iv`` is the 12 derived bytes: 4 fixed, then the 8-byte initial counter.

        The AEAD object is made on first use, and only the one this
        direction needs (sealer or opener) ever is.
        """
        self._backend = backend
        self._key = key
        self._fixed = iv[:4]
        self._counter = int.from_bytes(iv[4:12], "big")
        self._sealer: ciphers.Aead | None = None
        self._opener: ciphers.Aead | None = None
        self._random = b""  # padding bytes, fetched from os.urandom in bulk
        self._random_at = 0

    def _nonce(self) -> bytes:
        """This packet's nonce; advances the counter (wrapping at 2**64, :rfc:`5647` §7.1)."""
        nonce = self._fixed + self._counter.to_bytes(8, "big")
        self._counter = (self._counter + 1) & 0xFFFFFFFFFFFFFFFF
        return nonce

    def seal(self, seqno: int, *parts: Buffer) -> bytearray:
        """Frame ``length || pad_len || payload || padding || tag`` and encrypt in place.

        The buffer is sized for the tag up front so the AEAD can write it
        without a reallocation, and the returned ``bytearray`` is the wire
        form. Padding bytes come from a 4 KiB :func:`os.urandom` pool: one
        system call per hundreds of packets rather than one each.
        """
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
        """Read ``length || ciphertext || tag``; decrypt in place only if the tag verifies.

        A length that is not whole blocks is refused before any decryption.
        The transport's ``recv`` already returns a fresh ``bytearray``, which
        is decrypted where it lies; other buffers (tests) are copied once.
        """
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
    """Byte-exact slicing across a sequence of buffers, without joining them.

    :meth:`SSHTransport.send` gets an SFTP header and a large data buffer as
    separate parts; this cuts them into packet-sized runs of views so that
    the only copy of the data is the one the cipher makes. Single-use and
    single-threaded; the caller's buffers must stay unchanged until sent.
    """

    def __init__(self, parts: Sequence[Buffer]) -> None:
        """View every part as raw bytes (``cast("B")`` flattens typed arrays)."""
        self._views = deque(memoryview(part).cast("B") for part in parts)
        #: Bytes not yet taken.
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
    """Refuse a ``packet_length`` no real packet has, before reading that much.

    The bound is the guard against a hostile or confused peer making us
    allocate and wait for gigabytes. The ceiling, 1 MiB plus slack, is far
    above the 256 KiB maximum packet we advertise plus framing, and RFC 4253
    §6.1 only obliges 35000 bytes; the floor, 8, is the smallest body any
    mode produces (``padding_length``, a 1-byte payload, 4 bytes of padding,
    aligned to 8).
    """
    # A text banner (or garbage) read as a 32-bit length is enormous; refuse it.
    if length < 8 or length > 1024 * 1024 + 4096:
        raise _protocol_error(f"implausible packet length {length}")


def _protocol_error(detail: str) -> GError:
    """The error for anything the peer sent that SSH does not allow: ``EPROTO``.

    One errno for every framing, MAC, negotiation and sequencing failure, so
    callers (and tests) tell them apart by message, not code.
    """
    return GError(f"SSH protocol error: {detail}", errno.EPROTO)


# -- algorithm catalogues ----------------------------------------------------
# Each tuple is in our order of preference, which is what wins: RFC 4253
# §7.1 picks the first algorithm on the *client's* list that the server also
# lists. The test server imports these same tuples, so adding a name here
# needs its implementation on both sides. Compression is always ``none``.

#: curve25519 (RFC 8731) first: fast, constant-time and no group to trust;
#: then the RFC 8268 MODP groups for servers without it.
_KEX_ALGS = (
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group14-sha256",
)
#: Signature algorithms we can verify a host key with: Ed25519 (RFC 8709),
#: RSA with SHA-2 (RFC 8332), ECDSA (RFC 5656), and SHA-1 ``ssh-rsa`` last
#: for old servers only.
_HOSTKEY_ALGS = (
    "ssh-ed25519",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
)
#: MACs for the CTR ciphers, encrypt-then-MAC first (see :class:`_CtrCipher`).
#: An AEAD cipher still negotiates one of these - the KEXINIT field is
#: mandatory - and then ignores it.
_MACS = (
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
)
#: MAC name -> (:mod:`hashlib` name, encrypt-then-MAC?).
_MAC_HASH = {
    "hmac-sha2-256-etm@openssh.com": ("sha256", True),
    "hmac-sha2-512-etm@openssh.com": ("sha512", True),
    "hmac-sha2-256": ("sha256", False),
    "hmac-sha2-512": ("sha512", False),
}
#: Cipher name -> (key bytes, IV bytes) to derive. GCM's 12-byte "IV" is the
#: fixed field plus initial counter; ChaCha20 needs no IV (the sequence
#: number is its nonce) and a double-length key (see :class:`_ChachaCipher`).
_CIPHER_KEYLEN = {
    "aes128-gcm@openssh.com": (16, 12),
    "aes256-gcm@openssh.com": (32, 12),
    "chacha20-poly1305@openssh.com": (64, 0),
    "aes256-ctr": (32, 16),
    "aes192-ctr": (24, 16),
    "aes128-ctr": (16, 16),
}
#: Key exchange -> the HASH of the exchange hash and of key derivation.
_KEX_HASH = {
    "curve25519-sha256": "sha256",
    "curve25519-sha256@libssh.org": "sha256",
    "diffie-hellman-group14-sha256": "sha256",
    "diffie-hellman-group16-sha512": "sha512",
}
#: Classic Diffie-Hellman exchanges -> their prime; anything else is curve25519.
_DH_GROUP = {
    "diffie-hellman-group14-sha256": _GROUP14_P,
    "diffie-hellman-group16-sha512": _GROUP16_P,
}


def _ciphers_preferred(backend: ciphers.Backend) -> tuple[str, ...]:
    """Our cipher preference for ``backend``: AES-GCM, ChaCha20-Poly1305, then AES-CTR.

    The ``has_gcm`` and ``fast_chacha`` flags come from the days of a pure
    Python fallback, when ChaCha20 was slow and GCM sometimes missing; the
    ``cryptography`` backend sets both, so today the order is fixed. The
    flags are kept so a test can model a backend without them.
    """
    gcm = ("aes128-gcm@openssh.com", "aes256-gcm@openssh.com") if backend.has_gcm else ()
    aes = ("aes256-ctr", "aes192-ctr", "aes128-ctr")
    chacha = ("chacha20-poly1305@openssh.com",)
    return gcm + ((chacha + aes) if backend.fast_chacha else (aes + chacha))


def _negotiate(mine: Sequence[str], theirs: Sequence[str]) -> str:
    """The first of ``mine`` that ``theirs`` also offers (RFC 4253 §7.1).

    The test server calls it too, with the client's list as ``mine``: the
    rule is the client's preference whichever end applies it. No overlap is
    ``EPROTO``; the message lists both sides so the operator can see what
    the server lacks.
    """
    for candidate in mine:
        if candidate in theirs:
            return candidate
    raise _protocol_error(f"no common algorithm between {list(mine)} and {list(theirs)}")


@dataclass(frozen=True, slots=True)
class SessionKeys:
    """What one key exchange leaves behind: the inputs of :rfc:`4253` §7.2.

    Every key, IV and MAC key of both directions is derived from these four
    values plus a one-letter label, so they travel together. Both ends build
    one per exchange - this client in ``_key_exchange_locked`` and the test
    server in :mod:`xgfalclient.testing._sftp.transport` - and hand it to
    :func:`make_cipher` once per direction. The object holds the shared
    secret: it lives only for the duration of the exchange.
    """

    #: ``K``, the shared secret, as an integer: the DH value, or the X25519
    #: output read as an unsigned big-endian number (RFC 8731 §3.1). It is
    #: always hashed in its ``mpint`` encoding.
    shared: int
    #: ``H``, the exchange hash of this key exchange.
    exchange_hash: bytes
    #: The ``H`` of the *first* exchange, kept for the connection's life;
    #: equal to ``exchange_hash`` on the initial exchange only.
    session_id: bytes
    #: The key exchange's hash, by :mod:`hashlib` name (``_KEX_HASH``).
    digest: str

    def derive(self, letter: str, length: int) -> bytes:
        """``length`` bytes of key material for ``letter`` (``"A"`` ... ``"F"``).

        :rfc:`4253` §7.2: ``K1 = HASH(K || H || letter || session_id)``, and
        while that is too short, ``Kn = HASH(K || H || K1 || ... || Kn-1)``
        is appended - the ``while`` below, which hashes all material so far.
        Only a 64-byte key - ChaCha20's pair, an ``hmac-sha2-512`` key -
        needs extending, and only under a SHA-256 exchange.
        A zero length (ChaCha20's IV) is the empty string, not a hash.
        """
        if length == 0:
            return b""
        k_h = mpint(self.shared) + self.exchange_hash
        material = hashlib.new(self.digest, k_h + letter.encode() + self.session_id).digest()
        while len(material) < length:
            material += hashlib.new(self.digest, k_h + material).digest()
        return material[:length]


def make_cipher(
    backend: ciphers.Backend,
    cipher: str,
    mac: str,
    keys: SessionKeys,
    letters: tuple[str, str, str],
) -> _Cipher:
    """Build one direction's record protection from the exchanged secret.

    ``letters`` are the :rfc:`4253` §7.2 IV/key/MAC labels for the direction:
    ``("A", "C", "E")`` client->server, ``("B", "D", "F")`` server->client.
    ``cipher`` and ``mac`` are the names negotiated for that direction; for
    the AEAD ciphers ``mac`` is ignored and no MAC key is derived. The result
    is a fresh object with its own keystream or counter, owned by the caller.
    """
    key_len, iv_len = _CIPHER_KEYLEN[cipher]
    iv = keys.derive(letters[0], iv_len)
    key = keys.derive(letters[1], key_len)
    if cipher == "chacha20-poly1305@openssh.com":
        return _ChachaCipher(backend, key)
    if cipher.endswith("-gcm@openssh.com"):
        return _GcmCipher(backend, key, iv)
    name, etm = _MAC_HASH[mac]
    mac_key = keys.derive(letters[2], hashlib.new(name).digest_size)
    return _CtrCipher(backend.aes_ctr(key, iv), _MAC(name, mac_key), etm)


@dataclass(slots=True)
class _Negotiated:
    """The algorithms one KEXINIT round agreed; ``_cs`` client->server, ``_sc`` back.

    Compression and languages are not recorded: we offer only ``none`` and
    no languages, so there is nothing to choose.
    """

    kex: str
    hostkey: str
    cipher_cs: str
    cipher_sc: str
    mac_cs: str
    mac_sc: str


class SSHTransport:
    """A live SSH connection exposing the byte-stream the SFTP client wants.

    One connection, one ``session`` channel (our channel number is always
    0), one ``sftp`` subsystem: the SFTP client above it multiplexes its own
    requests by id, so there is no channel multiplexing here. It satisfies
    the :class:`~.client.Stream` protocol, like the OpenSSH and paramiko
    tiers.

    Threads: until :meth:`connect` returns, only the connecting thread
    touches the object. Afterwards one daemon reader thread owns the inbound
    direction (decrypting, flow control, answering requests, server rekeys),
    one consumer calls :meth:`recv_into`, and senders call :meth:`send`.
    :meth:`abort` may be called from any thread; :meth:`close` by the owner.
    A failure the reader sees is stored in ``_error`` and re-raised to every
    later ``send``/``recv_into`` as a fresh ``GError`` with the same errno.

    Rekeying is server-initiated only (OpenSSH's server rekeys after a
    cipher-dependent volume of data by default); this client never sends a
    KEXINIT after the first.
    """

    def __init__(
        self,
        endpoint: Endpoint,
        auth: Auth,
        sock: socket.socket,
        *,
        backend: ciphers.Backend | None = None,
    ) -> None:
        """Wrap a connected ``sock``, which this object then owns (``close`` closes it).

        Nothing is sent yet: :func:`connect` drives the handshake. ``backend``
        selects the cipher provider; tests pass one, everything else gets
        :func:`ciphers.get`'s default.
        """
        self.endpoint = endpoint
        self.auth = auth
        self._sock = sock
        self._backend = backend if backend is not None else ciphers.get()
        # Socket bytes land in _rbuf; _rbuf[_rstart:_rend] is not yet consumed.
        self._rbuf = bytearray(_RECV_BUFFER)
        self._rstart = 0
        self._rend = 0
        # Lock order: _kex_lock, then _send_lock, then _lock - never the other
        # way. _send_lock makes "seal with this seqno, write, bump seqno" atomic,
        # because the stream ciphers and the MACs depend on that order.
        self._send_lock = threading.Lock()
        # Held for a whole key exchange so no channel data is sent between our
        # KEXINIT and NEWKEYS (RFC 4253 §7.1); a data send takes it per packet.
        self._kex_lock = threading.Lock()
        self._out: _Cipher = _NullCipher()
        self._in: _Cipher = _NullCipher()
        # RFC 4253 §6.4 sequence numbers: every packet counts, from 0, mod 2**32.
        self._out_seq = 0
        self._in_seq = 0
        # Strict KEX: _strict_kex, once the server's first KEXINIT agreed to
        # it, holds for the life of the connection (sequence numbers restart
        # at every NEWKEYS); _strict_initial only until the first NEWKEYS
        # arrives, the window in which no other message may appear.
        self._strict_kex = False
        self._strict_initial = False
        self._client_kexinit = b""
        # H of the first key exchange: part of every later key derivation and
        # of every publickey signature (RFC 4252 §7).
        self._session_id = b""
        # The server's identification line, without CRLF (V_S in every H).
        self._server_version = b""
        # From EXT_INFO "server-sig-algs" (RFC 8308 §3.1); () if never sent.
        self._server_sig_algs: tuple[str, ...] = ()
        # Channel state (RFC 4254 §5): our id, the server's id for the same
        # channel, how much we may still send and in what largest piece, and
        # how much the server may still send us before we adjust.
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
        # _eof: the channel or connection ended (CHANNEL_EOF/CLOSE, DISCONNECT,
        # or close()); _error: why the reader stopped, if it failed. Both are
        # written under _lock and only ever go from unset to set.
        self._eof = False
        self._error: GError | None = None
        self._reader: threading.Thread | None = None
        self._closed = False

    # -- low-level I/O -----------------------------------------------------------

    def _recv_exact(self, count: int) -> bytearray:
        """The next ``count`` bytes of the connection, as a fresh ``bytearray``.

        This is the ``recv`` every :class:`_Cipher` reads through. Slicing a
        ``bytearray`` copies, so the result is the caller's to keep (or to
        decrypt in place) while ``_rbuf`` is reused underneath it. Only one
        thread reads at a time, so the buffer indices need no lock.
        """
        start = self._rstart
        if self._rend - start < count:
            self._fill(count)
            start = self._rstart
        self._rstart = start + count
        return self._rbuf[start : start + count]

    def _fill(self, count: int) -> None:
        """Receive until ``count`` unconsumed bytes are buffered, reading all that is ready.

        Each ``recv_into`` asks for all the free space, so one system call
        usually brings in many packets, which later calls then serve from
        memory. When the free space after the unread bytes is too small they
        are moved to the front; when ``count`` exceeds the whole buffer it
        grows to fit (bounded by :func:`_check_length`) and never shrinks.
        """
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
        """One ``recv_into`` on the socket; never returns 0.

        The socket timeout (the endpoint's, set in :func:`_open_socket`) is
        ``ETIMEDOUT``; the server closing TCP (``recv`` returning 0) or a
        reset is ``ECONNRESET``. SSH ends cleanly with ``DISCONNECT`` or
        ``CHANNEL_CLOSE``, so reaching the end of the TCP stream here never is.
        """
        try:
            got = self._sock.recv_into(view)
        except TimeoutError as exc:
            raise GError(f"Timed out reading from {self.endpoint.label}", errno.ETIMEDOUT) from exc
        except OSError as exc:
            raise self._io_failure(exc) from exc
        if not got:
            raise GError(
                f"Connection to {self.endpoint.label} closed by the server", errno.ECONNRESET
            )
        return got

    def _write_all(self, data: Buffer) -> None:
        """``sendall``, with a socket error as a ``GError``; callers hold ``_send_lock``."""
        try:
            self._sock.sendall(data)
        except OSError as exc:
            raise self._io_failure(exc) from exc

    def _io_failure(self, exc: OSError) -> GError:
        """A socket ``OSError`` as a ``GError``, keeping its errno (``ECONNRESET`` if none).

        A send timeout lands here too; Python's socket ``TimeoutError``
        carries no errno, so it is reported as ``ECONNRESET`` (only the read
        path maps timeouts to ``ETIMEDOUT``). After an :meth:`abort` from
        another thread a send typically fails with ``EPIPE``.
        """
        return GError(
            f"Connection to {self.endpoint.label} failed: {exc.strerror or exc}",
            exc.errno or errno.ECONNRESET,
        )

    def _send_packet(self, *parts: Buffer) -> None:
        """Seal and send one packet whose payload is ``parts`` concatenated.

        The control-message path; bulk data goes through :meth:`send`. It
        does not take ``_kex_lock``: it is called by the thread running a
        key exchange (which holds it), by the reader thread, which runs
        server rekeys itself and so never sends in the middle of one, and by
        :meth:`close`, when a stray ``CHANNEL_CLOSE`` no longer matters.
        """
        with self._send_lock:
            self._write_all(self._out.seal(self._out_seq, *parts))
            self._out_seq = (self._out_seq + 1) & 0xFFFFFFFF

    def _read_payload(self) -> memoryview:
        """The next packet's payload, as a view into its own fresh buffer."""
        payload = self._in.read(self._recv_exact, self._in_seq)
        self._in_seq = (self._in_seq + 1) & 0xFFFFFFFF
        return payload

    def _recv_packet(self) -> bytes:
        """The next payload as ``bytes``, for the handshake code that parses it."""
        return bytes(self._read_payload())

    # -- version exchange --------------------------------------------------------

    def _exchange_versions(self) -> bytes:
        """Send our identification, read the server's; its line without CRLF.

        :rfc:`4253` §4.2: both sides send ``SSH-protoversion-softwareversion``
        and CRLF, and the server may send other lines first. ``SSH-1.99-``
        is a server that also speaks SSH-1 and is accepted as 2.0 (§5.1);
        anything else - SSH-1 only - is ``EPROTO``. We send ours without
        waiting, as the RFC allows, to save a round trip. Bytes that arrive
        after the line stay in ``_rbuf`` for the first binary packet.
        """
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
        """One LF-terminated line, CR/LF stripped; over 4096 bytes is ``EPROTO``.

        Byte at a time, but from the buffer: :meth:`_fill` reads ahead, so
        this costs no system call per byte. The cap stops a server that never
        sends a newline from growing the line forever.
        """
        line = b""
        while not line.endswith(b"\n"):
            line += self._recv_exact(1)
            if len(line) > 4096:
                raise _protocol_error("server identification line too long")
        return line.rstrip(b"\r\n")

    # -- key exchange ------------------------------------------------------------

    def _build_kexinit(self, initial: bool) -> bytes:
        """Our KEXINIT; the strict-KEX marker goes in the initial one only.

        ``PROTOCOL`` 1.10 makes the marker meaningful only in the first
        KEXINIT (and a peer must ignore it later), so a rekey leaves it out.

        The layout is :rfc:`4253` §7.1: message byte, a 16-byte random
        cookie, ten name-lists (kex, host key, cipher c->s and s->c, MAC
        c->s and s->c, compression both ways, languages both ways), the
        ``first_kex_packet_follows`` boolean (always false: we never guess)
        and a reserved uint32. ``ext-info-c`` (:rfc:`8308` §2.1) is a
        pseudo-algorithm, never chosen, that asks the server for
        ``EXT_INFO`` - which is how we learn which RSA signature algorithm
        it accepts. The exact bytes returned are ``I_C`` in the exchange hash.
        """

        def names(items: Sequence[str]) -> bytes:
            """A :rfc:`4251` §5 ``name-list``: comma-joined, as a ``string``."""
            return string(",".join(items))

        kex = [*_KEX_ALGS, "ext-info-c"] + ([STRICT_KEX_CLIENT] if initial else [])
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
        """The ten name-lists of a server ``KEXINIT``, in :rfc:`4253` §7.1 order.

        The server's ``first_kex_packet_follows`` is read and ignored: a
        server that guessed would send a key-exchange packet we then reject
        as unexpected. OpenSSH never guesses. A truncated payload raises
        ``KeyError_`` from :class:`Reader`.
        """
        reader = Reader(payload)
        reader.take(17)  # message id + cookie
        lists = [reader.name_list() for _ in range(10)]
        reader.byte()  # first_kex_packet_follows
        reader.uint32()
        return lists

    def _negotiate_algs(self, server: list[list[str]]) -> _Negotiated:
        """Pick each algorithm against the server's lists; no overlap is ``EPROTO``.

        Kex and host key are chosen independently, which :rfc:`4253` §7.1's
        stricter kex rule (the kex must work with some common host-key
        algorithm) reduces to, since every exchange we offer takes any of
        our signature algorithms.
        """
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
        self, server_version: bytes, initial: bool, server_kexinit: bytes | None = None
    ) -> None:
        """Run one complete key exchange with ``_kex_lock`` held throughout.

        ``initial`` is the first exchange (from :meth:`connect`); otherwise
        it is a server-initiated rekey whose ``server_kexinit`` the reader
        thread has already read. Holding the lock stops :meth:`send` from
        slipping channel data between our KEXINIT and NEWKEYS, which
        :rfc:`4253` §7.1 forbids.
        """
        with self._kex_lock:
            self._key_exchange_locked(server_version, initial, server_kexinit)

    def _key_exchange_locked(
        self, server_version: bytes, initial: bool, server_kexinit: bytes | None
    ) -> None:
        """KEXINIT both ways, the ECDH/DH round, host-key check, NEWKEYS, new ciphers.

        The exchange hash is :rfc:`4253` §8 / :rfc:`8731` §3:
        ``H = HASH(V_C || V_S || I_C || I_S || K_S || exchange || K)``, the
        versions and KEXINIT payloads as ``string`` (without CRLF, without
        packet framing), ``K_S`` the host key blob, ``exchange`` the two
        public values (``e``/``f`` as mpint, or ``Q_C``/``Q_S`` as string)
        and ``K`` as mpint. The host key's signature over ``H`` is checked
        before any key is derived from it. Any failure leaves the
        connection unusable; the caller closes it.
        """
        client_kexinit = self._build_kexinit(initial)
        self._send_packet(client_kexinit)
        if server_kexinit is None:
            payload = self._recv_packet()
            while payload[0] != MSG_KEXINIT:
                payload = self._dispatch_transport(payload)
            server_kexinit = payload
        server_lists = self._parse_kexinit(server_kexinit)
        if initial:
            self._begin_strict_kex(server_lists[0])
        chosen = self._negotiate_algs(server_lists)
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
        keys = SessionKeys(shared, h, self._session_id, digest)
        # NEWKEYS both ways, then swap ciphers in. Under strict KEX each
        # direction's sequence number restarts at zero right after its NEWKEYS
        # - every rekey, not just the first - so a packet an attacker slipped
        # into the clear handshake cannot shift the numbers the MACs cover.
        self._expect(MSG_NEWKEYS, "NEWKEYS")
        if self._strict_kex:
            self._in_seq = 0
        with self._send_lock:
            # NEWKEYS, the sequence reset and the new cipher under one hold
            # of the lock, so no other packet can be sealed in between.
            self._write_all(self._out.seal(self._out_seq, bytes([MSG_NEWKEYS])))
            self._out_seq = 0 if self._strict_kex else (self._out_seq + 1) & 0xFFFFFFFF
            self._out = make_cipher(
                self._backend, chosen.cipher_cs, chosen.mac_cs, keys, ("A", "C", "E")
            )
        # The server's NEWKEYS has already been read under the old cipher, so
        # the very next packet read is the first under the new one.
        self._in = make_cipher(
            self._backend, chosen.cipher_sc, chosen.mac_sc, keys, ("B", "D", "F")
        )
        self._strict_initial = False

    def _begin_strict_kex(self, server_kex_algs: Sequence[str]) -> None:
        """Turn strict KEX on if the server's first KEXINIT offers it.

        We always offer it, so the server's marker alone decides. The server's
        KEXINIT must then have been the very first packet it sent (sequence
        number 0): anything before it - an ``IGNORE`` we tolerated while we
        could not yet know the mode - is exactly the prefix an attacker
        inserts to shift the sequence numbers, so it is fatal.
        """
        if STRICT_KEX_SERVER not in server_kex_algs:
            return
        if self._in_seq != 1:
            raise _protocol_error("strict KEX violation: KEXINIT was not the first packet")
        self._strict_kex = True
        self._strict_initial = True

    def _kex_curve(self, chosen: _Negotiated) -> tuple[int, bytes, bytes, bytes]:
        """``curve25519-sha256`` (:rfc:`8731`): one ``KEX_ECDH_INIT``/``REPLY`` round.

        Returns ``(K, host key blob, signature, Q_C || Q_S as strings)``.
        A fresh ephemeral key per exchange. The all-zero shared secret that
        a low-order server point produces is rejected inside
        :func:`x25519.x25519`, as RFC 8731 §3 requires, as is a ``Q_S`` that
        is not 32 bytes; both arrive as ``ValueError`` and leave here as the
        transport's ``EPROTO``, so :func:`connect` never leaks a bare
        ``ValueError`` for what is a server's protocol violation.
        """
        private, public = x25519.generate()
        self._send_packet(bytes([MSG_KEX_ECDH_INIT]) + string(public))
        reply = self._expect(MSG_KEX_ECDH_REPLY, "KEX_ECDH_REPLY")
        host_blob = reply.string()
        server_pub = reply.string()
        host_sig = reply.string()
        try:
            shared_bytes = x25519.x25519(private, server_pub)
        except ValueError as exc:
            raise _protocol_error(f"bad curve25519 public value from the server: {exc}") from None
        shared = int.from_bytes(shared_bytes, "big")
        exchange = string(public) + string(server_pub)
        return shared, host_blob, host_sig, exchange

    def _kex_dh(self, chosen: _Negotiated) -> tuple[int, bytes, bytes, bytes]:
        """Classic Diffie-Hellman (:rfc:`4253` §8) over a fixed MODP group.

        Returns ``(K, host key blob, signature, e || f as mpints)``. The
        exponent is 2048 random bits reduced into ``[1, p-2]``: the modulo
        bias is negligible against a 2048- or 4096-bit ``p``. The server's
        ``f`` must lie strictly inside ``(1, p-1)`` - stricter than the
        RFC's ``[1, p-1]`` - because 1 and ``p-1`` force a shared secret an
        attacker can predict.
        """
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
        """The next key-exchange message, which must be ``msg``.

        ``IGNORE`` and ``DEBUG`` may appear anywhere (:rfc:`4253` 11.2) and are
        skipped - except during a strict initial key exchange, where they are
        a protocol violation like any other message the exchange does not need.
        """
        payload = self._recv_packet()
        while payload[0] in (MSG_IGNORE, MSG_DEBUG):
            if self._strict_initial:
                raise _protocol_error(
                    f"strict KEX violation: unexpected message {payload[0]} "
                    "during the initial key exchange"
                )
            payload = self._recv_packet()
        if payload[0] != msg:
            raise _protocol_error(f"expected {name}, got message {payload[0]}")
        return Reader(payload[1:])

    # -- host key verification ---------------------------------------------------

    def _verify_host_key(
        self, algorithm: str, host_blob: bytes, host_sig: bytes, h: bytes
    ) -> PublicKey:
        """Prove the server holds the host key, then check that key is the expected one.

        The signature over ``H`` with the negotiated ``algorithm`` comes
        first: it is what binds this exchange to the key, so a man in the
        middle cannot reuse the real server's key blob. A bad signature is
        ``EACCES`` (an authentication failure, not a protocol one); an
        unparseable blob is ``EPROTO``. Then :meth:`_check_known_host`.
        """
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
        """Apply ``known_hosts`` and the ``StrictHostKeyChecking`` policy, as OpenSSH does.

        A ``@revoked`` key and a changed key are refused whatever the policy
        (``EACCES``; the changed-key message echoes OpenSSH's so operators
        recognise it). An unknown key is accepted silently with ``no``,
        ``off`` or ``accept-all``, accepted and recorded with
        ``accept-new`` (the default), and refused with anything else
        (``yes``, ``ask`` - there is no one to ask). The paramiko tier
        applies the same rules in :func:`.paramiko_tier._check_host_key`.
        """
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
        """Request ``ssh-userauth`` (:rfc:`4253` §10), then try each key, then the password.

        ``EXT_INFO`` arrives right after the server's first ``NEWKEYS``
        (:rfc:`8308` §2.4), so it is read while waiting for
        ``SERVICE_ACCEPT``. Each method's ``USERAUTH_FAILURE`` simply moves
        on to the next; the ``partial success`` flag and the server's list
        of methods that can continue are not consulted, so a server that
        demands two factors fails here. When everything fails the error is
        ``EACCES`` with gfal2's "All supported authentication methods
        failed" wording.
        """
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
        """Record ``server-sig-algs`` from an ``EXT_INFO``; other extensions are skipped.

        :rfc:`8308` §2.3: ``uint32 count`` then ``count`` pairs of ``string
        name, string value``.
        """
        reader = Reader(payload[1:])
        for _ in range(reader.uint32()):
            name = reader.text()
            value = reader.string()
            if name == "server-sig-algs":
                self._server_sig_algs = tuple(value.decode("utf-8", "replace").split(","))

    def _rsa_algorithm(self, key: PrivateKey) -> str:
        """The signature algorithm for an RSA key: the best the server listed.

        :rfc:`8332` §3.3: a client should sign with ``rsa-sha2-512`` or
        ``-256`` only when ``server-sig-algs`` says the server accepts it.
        Without that list (or with no RSA name on it) we use the key's
        first, ``rsa-sha2-512``, which a modern server accepts and a
        SHA-1-only one refuses.
        """
        if self._server_sig_algs:
            for candidate in key.algorithms():
                if candidate in self._server_sig_algs:
                    return candidate
        return key.algorithms()[0]

    def _auth_publickey(self, key: PrivateKey) -> bool:
        """One signed ``publickey`` request (:rfc:`4252` §7); whether it was accepted.

        We skip the optional query round (``has signature`` false, answered
        by ``PK_OK``) and sign straight away: one round trip, and we already
        hold the private key. The signature covers ``string session_id``
        followed by the request exactly as sent, up to and including the
        public key blob - so the request bytes are built once and reused.
        """
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
        """A ``password`` request (:rfc:`4252` §8); whether it was accepted.

        The ``FALSE`` byte means "not a password change". Safe to send only
        because the transport is already encrypted and the host key checked.
        There is no password-change support: a server's ``PASSWD_CHANGEREQ``
        (also message 60) is skipped by :meth:`_auth_result`.
        """
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
        """Wait for ``SUCCESS`` (true) or ``FAILURE`` (false) to the last request.

        Banners (:rfc:`4252` §5.4) go to :attr:`Auth.banner`; ``IGNORE``,
        ``DEBUG`` and message 60 are skipped. Anything else is ``EPROTO``.
        """
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
        """Open the ``session`` channel (:rfc:`4254` §5.1) and learn the server's limits.

        We advertise ``_LOCAL_WINDOW`` and ``_LOCAL_MAXPACKET``; the
        confirmation carries the server's channel id (used as the recipient
        of everything we send), its initial window for our data and its
        maximum packet. ``OPEN_FAILURE`` (reason code, description,
        language) is ``ECONNREFUSED`` with the server's description.
        """
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
        """``subsystem "sftp"`` with ``want reply`` (:rfc:`4254` §6.5).

        A ``CHANNEL_FAILURE`` means the server has no sftp subsystem
        configured (``EPROTONOSUPPORT``, as the OpenSSH tier reports
        "subsystem request failed"). From the ``SUCCESS`` on, channel data
        is the SFTP byte stream.
        """
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
        """The reader thread: dispatch every packet until the channel closes or fails.

        It ends quietly on ``CHANNEL_CLOSE`` or ``DISCONNECT``. On a
        ``GError`` (socket failure, timeout, protocol error) it publishes the
        error and wakes every waiter, so blocked ``send``/``recv_into``
        calls fail promptly instead of hanging. A message too short for its
        fields makes :class:`Reader` raise ``KeyError_`` (a ``ValueError``),
        and an empty payload has no message number (``IndexError``): both are
        the peer breaking the protocol, published as ``EPROTO`` like any
        other, since a reader that died without waking the waiters would
        leave them blocked for ever.
        """
        try:
            try:
                while True:
                    if not self._handle_channel(self._read_payload()):
                        return
            except (ValueError, IndexError) as exc:
                raise _protocol_error(f"malformed message: {exc}") from exc
        except GError as exc:
            with self._cond:
                # Nothing else sets _error while this thread runs (a DISCONNECT
                # ends it), so only a deliberate close() hides the failure.
                if not self._closed:
                    self._error = exc
                self._cond.notify_all()

    def _channel_data(self, payload: Buffer) -> None:
        """``CHANNEL_DATA``, the bulk path: checked against the window, then accounted.

        The data stays where it was decrypted until ``recv_into`` copies it,
        once, to where the SFTP client wants it.
        """
        size = int.from_bytes(payload[5:9], "big") if len(payload) >= 9 else -1
        if size < 0 or 9 + size > len(payload):
            raise _protocol_error("truncated CHANNEL_DATA")
        if size > _LOCAL_MAXPACKET or size > self._local_window:
            # Flow control is what bounds the memory channel data may take.
            raise _protocol_error("channel data beyond the window the server was given")
        self._account(size, memoryview(payload)[9 : 9 + size])

    def _disconnected(self, payload: Buffer) -> None:
        """``DISCONNECT``: the stream ends, and every later call fails with its reason."""
        reader = Reader(payload[1:])
        reader.uint32()
        with self._cond:
            self._eof = True
            self._error = GError(
                f"Server {self.endpoint.label} disconnected: {reader.text()}", errno.ECONNRESET
            )
            self._cond.notify_all()

    def _handle_channel(self, payload: Buffer) -> bool:
        """Act on one post-handshake packet; false once the reader should stop.

        ``CHANNEL_DATA`` is first because it is nearly every packet of a
        download. The checks on it are flow control enforced: data beyond
        the window we granted is a protocol error, since honouring it would
        let the server grow our buffers without bound. ``CHANNEL_EOF`` marks
        the end of the stream but keeps reading (the server's
        ``CHANNEL_CLOSE`` or an ``exit-status`` request follows); a
        ``KEXINIT`` starts a server rekey right here on this thread.
        """
        code = payload[0]
        if code == MSG_CHANNEL_DATA:
            self._channel_data(payload)
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
            self._disconnected(payload)
            return False
        # IGNORE, DEBUG, UNIMPLEMENTED, and anything else: skip.
        return True

    def _rekey(self, server_kexinit: bytes) -> None:
        """A server-initiated rekey (:rfc:`4253` §9), run inline in the reader.

        Running it here, not on another thread, means no other packet is
        read until the new keys are in place, and ``_kex_lock`` holds
        senders off meanwhile. Download data simply waits in the socket.
        """
        self._key_exchange(self._server_version, initial=False, server_kexinit=server_kexinit)

    def _decline_channel_request(self, payload: Buffer) -> None:
        """Refuse a channel request (:rfc:`4254` §5.4) if a reply is wanted.

        Typical ones are ``exit-status`` (no reply wanted) and OpenSSH's
        ``keepalive@openssh.com`` (reply wanted; any reply, even
        ``CHANNEL_FAILURE``, proves we are alive).
        """
        reader = Reader(payload[1:])
        reader.uint32()
        reader.text()
        if reader.boolean():
            self._send_packet(bytes([MSG_CHANNEL_FAILURE]) + uint32(self._remote_channel))

    def _decline_global(self, payload: Buffer) -> None:
        """Refuse a global request (:rfc:`4254` §4) if a reply is wanted.

        OpenSSH sends ``hostkeys-00@openssh.com`` (no reply wanted; we do
        not learn extra host keys) and ``keepalive@openssh.com`` (answered
        with ``REQUEST_FAILURE``, which counts as alive).
        """
        reader = Reader(payload[1:])
        reader.text()
        if reader.boolean():
            self._send_packet(bytes([MSG_REQUEST_FAILURE]))

    def _account(self, size: int, data: memoryview | None = None) -> None:
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
        """Run the handshake after the version exchange, then start the reader thread.

        Key exchange, authentication, channel open and ``subsystem sftp``,
        all on the calling thread. Raises ``GError`` (``EACCES`` for host
        key or authentication failures, ``EPROTO`` for protocol errors,
        socket errnos otherwise) and leaves socket cleanup to the caller,
        as :func:`connect` does it. The reader is a daemon thread so a
        forgotten transport never blocks interpreter exit.
        """
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
        """Skip a pre-``KEXINIT`` ``IGNORE``/``DEBUG``; the next payload. Else ``EPROTO``."""
        # During the initial KEX loop, tolerate DEBUG/IGNORE before KEXINIT:
        # the mode is unknown until KEXINIT arrives, and a strict server's
        # KEXINIT then fails _begin_strict_kex for not being first.
        if payload[0] in (MSG_IGNORE, MSG_DEBUG):
            return self._recv_packet()
        raise _protocol_error(f"expected KEXINIT, got message {payload[0]}")

    def send(self, *parts: Buffer) -> None:
        """Write ``parts``, in order, as channel data in packets the peer's limits allow.

        The parts are sliced into packets without being joined first, and as
        many packets as the window admits are sealed together and handed to
        the socket in one gathered write: one system call and no extra copy,
        rather than one of each per 32 KiB packet.

        Flow control (:rfc:`4254` §5.2): window credit is reserved under
        ``_lock`` before sealing, and when there is none the call blocks
        until the reader applies a ``WINDOW_ADJUST`` - or until the reader
        fails, which is re-raised here. There is no timeout on that wait
        beyond the socket's own on the reader side. Sealing and writing run
        under ``_kex_lock`` so a rekey cannot start mid-batch, and under
        ``_send_lock`` so sequence numbers stay in step. Safe to call from
        several threads, though packets of concurrent calls may interleave.
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
        """Send every packet, in order, with as few system calls as the socket allows.

        ``sendmsg`` with a list of buffers is a gathered write; it may send
        only part, so the loop drops what went and trims the first view.
        Sockets without ``sendmsg`` (Windows, some test doubles) get one
        joined ``sendall``. Called with ``_send_lock`` held.
        """
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

        Returns 0 at end of stream (channel EOF/CLOSE or :meth:`close`) once
        everything buffered has been taken, and re-raises the reader's
        failure otherwise. ``_idled`` is sampled on entry so a reader that
        went idle and woke again while we were not yet waiting still counts.
        One consumer only: the copy out of the queued views runs after the
        lock is released.
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

    def abort(self) -> None:
        """Shut the socket down under the reader thread and any sender; for ``cancel()``.

        The reader then sees the end of the stream and fails every waiter;
        :meth:`close` is still the owner's to call.
        """
        shutdown_sockets(self._sock)

    def close(self) -> None:
        """Close the channel and the socket; idempotent, never raises for I/O.

        Waiters are woken first (they see end of stream, not an error, since
        a close is deliberate), then a best-effort ``CHANNEL_CLOSE`` goes out
        and the socket is shut down, which ends the reader thread. The
        reader is not joined: it is a daemon and exits on its own.
        """
        with self._cond:
            if self._closed:
                return
            self._closed = True
            self._eof = True
            self._cond.notify_all()
        with contextlib.suppress(GError):
            self._send_packet(bytes([MSG_CHANNEL_CLOSE]) + uint32(self._remote_channel))
        with contextlib.suppress(OSError):
            self._sock.shutdown(socket.SHUT_RDWR)
        self._sock.close()


def _known_hosts_paths(endpoint: Endpoint) -> list[str]:
    """The ``known_hosts`` files to consult; the first is where a new key is recorded.

    ``[SFTP PLUGIN] KNOWN_HOSTS`` replaces both defaults, like OpenSSH's
    ``UserKnownHostsFile`` plus no global file. Otherwise the user's file,
    then the system-wide one (read only). Missing files are fine. Shared
    with :mod:`.paramiko_tier`.
    """
    if endpoint.known_hosts:
        return [endpoint.known_hosts]
    home = os.path.expanduser("~")
    return [
        os.path.join(home, ".ssh", "known_hosts"),
        "/etc/ssh/ssh_known_hosts",
    ]


def _record_host_key(paths: Sequence[str], endpoint: Endpoint, key: PublicKey) -> None:
    """Append ``key`` for ``endpoint`` to ``paths[0]`` (``accept-new``), creating the dir.

    The line is in OpenSSH's format (``[host]:port`` for a non-22 port),
    so ``ssh`` itself honours it afterwards. Appends are not locked:
    concurrent first contacts may write the same line twice, which is
    harmless. A directory created for it gets mode 0700, as OpenSSH creates
    ``~/.ssh``: the file lists every host the user reaches, and sshd's
    ``StrictModes`` refuses keys under a ``~/.ssh`` others can write. An
    existing directory's mode is not touched.
    """
    line = KnownHosts.line_for(endpoint.host, endpoint.port, key)
    target = paths[0]
    try:
        # makedirs applies ``mode`` (less the umask) to the directories it creates.
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        # Recording is best-effort; a read-only known_hosts must not fail the
        # connection when the policy has already accepted the key.
        pass


def _open_socket(endpoint: Endpoint) -> socket.socket:
    """A TCP connection to the endpoint, with gfal2's errnos for each failure.

    A resolution failure is ``EREMOTE`` (gfal2's choice), a connect timeout
    ``ETIMEDOUT``, anything else the socket's errno. The endpoint timeout
    (``0`` meaning none) stays on the socket for every later read and write,
    so it also bounds how long the reader thread waits for the server.
    """
    timeout = float(endpoint.timeout) if endpoint.timeout > 0 else None
    try:
        sock = socket.create_connection((endpoint.host, endpoint.port), timeout=timeout)
    except socket.gaierror as exc:
        raise GError(f"Could not resolve host {endpoint.host}: {exc}", errno.EREMOTE) from exc
    except TimeoutError as exc:
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
    sock: socket.socket | None = None,
    backend: ciphers.Backend | None = None,
) -> SSHTransport:
    """Open an SSH connection to ``endpoint`` and start the ``sftp`` subsystem.

    ``sock`` is an already-connected socket to run over instead of dialling
    (the tests pass one end of a socket pair to the in-process server). On
    success the transport owns the socket either way. On failure a socket
    we opened is closed here, while a caller's ``sock`` is left to the
    caller. Every exception propagates, ``KeyboardInterrupt`` included.
    """
    owned = sock is None
    connection = _open_socket(endpoint) if sock is None else sock
    transport = SSHTransport(endpoint, auth, connection, backend=backend)
    try:
        server_version = transport._exchange_versions()
        transport.connect(server_version)
    except BaseException:
        if owned:
            with contextlib.suppress(OSError):
                connection.close()
        raise
    return transport
