"""The SSH-2 transport half of the test SSH server: framing, key exchange, user auth.

:class:`_SSHTransport` is everything up to a logged-in connection: packet
framing over the (re)negotiated ciphers, KEXINIT and the curve25519 / DH
group exchanges with OpenSSH's strict-KEX rules (the Terrapin
countermeasure), ``EXT_INFO``, and password or public-key authentication,
with the handshake faults :class:`~.ssh.SSHServer` can be told to commit.
The channel and the ``sftp`` subsystem on top of it are
:class:`~.ssh._SSHServerConn`, its subclass.

The protocol pieces and where they come from:

* version exchange and the binary packet protocol - RFC 4253 sections 4.2
  and 6, with the packet sealing and opening done by the client's own cipher
  objects (:func:`xgfalclient.plugins.sftp.ssh.make_cipher`), so both ends
  share one implementation of AES-GCM, ChaCha20-Poly1305 and AES-CTR with
  HMAC (plain and encrypt-then-MAC);
* ``KEXINIT`` and algorithm negotiation - RFC 4253 section 7.1, the
  server's lists being exactly the client's preferences, so whatever the
  client prefers is what is agreed;
* the exchanges - curve25519-sha256 (RFC 8731) and the RFC 8268 MODP
  groups 14 and 16 with SHA-2 (RFC 4253 section 8's exchange hash), keys
  derived as RFC 4253 section 7.2 says (:class:`~xgfalclient.plugins.sftp.ssh.SessionKeys`);
* strict KEX - OpenSSH ``PROTOCOL`` section 1.10, the Terrapin
  (CVE-2023-48795) countermeasure;
* ``EXT_INFO`` with ``server-sig-algs`` - RFC 8308;
* ``ssh-userauth`` - RFC 4252 sections 5 to 8 (``password`` and
  ``publickey`` with the signature over the session id and request).

It is deliberately the server half of the client and no more: it assumes
the client sends ``KEXINIT`` straight away and never guesses a first KEX
packet, it offers one host key algorithm (the key it was given), and it does
not enforce the rules a hostile client would break, except where a test
needs the client's own compliance checked (strict KEX). A protocol
violation from either side ends the connection with :class:`GError_` or
``EOFError``, which :meth:`~.ssh.SSHServer._serve` swallows.

Threading: :meth:`_SSHTransport.send_packet` may be called from the
connection thread and from the channel reader thread (a window adjust, a
rekey), so the outgoing cipher and sequence number are guarded by
``send_lock``; receiving happens on one thread at a time (first the
connection thread, then only the reader). ``kex_lock`` keeps channel data
from being sent mid-rekey.
"""

from __future__ import annotations

import errno
import hashlib
import os
import socket
import threading
from typing import TYPE_CHECKING

from ...crypto import x25519 as _x25519
from ...crypto.sshkeys import (
    Reader,
    mpint,
    parse_public_blob,
    string,
    uint32,
)
from ...errors import GError as GError_
from ...plugins.sftp import ssh as _ssh

if TYPE_CHECKING:
    from .ssh import SSHServer


def _read_exact_from(sock: socket.socket, count: int, buffer: bytearray) -> bytes:
    """Pull exactly ``count`` bytes off ``sock``, keeping the overrun in ``buffer``.

    The ciphers read a packet in two steps (the length, then the rest), and
    each ``recv`` may return more than that step asked for; the excess stays
    in ``buffer`` for the next call, so reads are large without losing bytes.
    ``EOFError`` if the client hangs up first.
    """
    while len(buffer) < count:
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError
        buffer += chunk
    out = bytes(buffer[:count])
    del buffer[:count]
    return out


class _SSHTransport:
    """One server connection's transport and authentication; see :class:`~.ssh._SSHServerConn`.

    Owns nothing it did not create: the socket belongs to
    :meth:`~.ssh.SSHServer._serve`, which closes it. All configuration and
    faults are read from the :class:`~.ssh.SSHServer`.
    """

    # The identification string (RFC 4253 section 4.2); it goes into the
    # exchange hash, so it must be exactly what was sent, without CR LF.
    _VERSION = b"SSH-2.0-xgfaltest"
    #: The client's identification line, set by ``run`` before the first exchange.
    client_version: bytes

    def __init__(self, server: SSHServer, sock: socket.socket) -> None:
        """Start in the clear, as every SSH connection does, with sequence numbers at 0."""
        self.server = server
        self.sock = sock
        # Bytes received but not yet consumed; see _read_exact_from.
        self.buffer = bytearray()
        # The ciphers of each direction, replaced at every NEWKEYS. The null
        # cipher frames packets (RFC 4253 section 6) with no MAC.
        self.out: _ssh._Cipher = _ssh._NullCipher()
        self.inc: _ssh._Cipher = _ssh._NullCipher()
        # Packet sequence numbers (RFC 4253 section 6.4): uint32, wrapping, one
        # per direction, the input of every MAC and of ChaCha20's nonce.
        self.out_seq = 0
        self.in_seq = 0
        self.send_lock = threading.Lock()
        self.kex_lock = threading.Lock()
        # The first exchange hash H; it stays the session id across rekeys.
        self.session_id = b""
        # Strict KEX, as in the client: for the connection once agreed, and
        # the no-stray-messages rule until the client's first NEWKEYS.
        self.strict = False
        self.strict_initial = False

    # -- framing ---------------------------------------------------------------

    def _recv_exact(self, count: int) -> bytes:
        """``count`` bytes off the socket; the read callback the ciphers are given."""
        return _read_exact_from(self.sock, count, self.buffer)

    def send_packet(self, payload: bytes) -> None:
        """Seal one payload with the current outgoing cipher and send it.

        Thread-safe: sealing and sending under ``send_lock`` keeps packets
        whole and their sequence numbers in the order they reach the wire.
        """
        with self.send_lock:
            self.sock.sendall(self.out.seal(self.out_seq, payload))
            self.out_seq = (self.out_seq + 1) & 0xFFFFFFFF

    def recv_packet(self) -> bytes:
        """The next packet's payload, decrypted and its MAC checked.

        A bad MAC or length raises (``GError_``/``ValueError`` from the
        cipher), ending the connection. Not thread-safe; one reader at a time.
        """
        payload = bytes(self.inc.read(self._recv_exact, self.in_seq))
        self.in_seq = (self.in_seq + 1) & 0xFFFFFFFF
        return payload

    def _exchange_versions(self) -> bytes:
        """Send our identification line and return the client's, CR LF stripped.

        Read a byte at a time so nothing after the line (the client's
        ``KEXINIT``) is consumed early. RFC 4253 lets a server see other lines
        before the version; our client sends none, so none are skipped.
        """
        self.sock.sendall(self._VERSION + b"\r\n")
        line = b""
        while not line.endswith(b"\n"):
            line += self._recv_exact(1)
        return line.rstrip(b"\r\n")

    def _server_kexinit(self, initial: bool) -> bytes:
        """Our ``SSH_MSG_KEXINIT``: a random cookie and the ten name-lists of RFC 4253 7.1.

        The order of lists is kex, host key, cipher c->s, cipher s->c, MAC
        c->s, MAC s->c, compression both ways (``none`` only), language
        both ways (empty); then ``first_kex_packet_follows`` false and the
        reserved ``uint32`` 0. The strict-KEX marker goes in the kex list of
        the first ``KEXINIT`` only: ``PROTOCOL`` 1.10 has it ignored later, and
        leaving it out of a rekey is what OpenSSH does.
        """

        def names(items: list[str]) -> bytes:
            """An SSH ``name-list``: comma-joined names as one ``string``."""
            return string(",".join(items))

        cipher = list(_ssh._ciphers_preferred(self.server.backend))
        host = [self._hostkey_alg()]
        kex = list(_ssh._KEX_ALGS)
        if initial and self.server.strict_kex:
            kex.append(_ssh.STRICT_KEX_SERVER)  # first KEXINIT only (PROTOCOL 1.10)
        body = bytes([_ssh.MSG_KEXINIT]) + os.urandom(16)
        body += names(kex)
        body += names(host)
        body += names(cipher) + names(cipher)
        body += names(list(_ssh._MACS)) + names(list(_ssh._MACS))
        body += names(["none"]) + names(["none"])
        body += names([]) + names([])
        body += bytes([0]) + uint32(0)
        return body

    def _hostkey_alg(self) -> str:
        """The signature algorithm offered for our host key.

        An RSA key signs with ``rsa-sha2-512`` (RFC 8332), never SHA-1
        ``ssh-rsa``, as OpenSSH 8.8+ does; other kinds are their own name.
        """
        if self.server.host_key.kind == "ssh-rsa":
            return "rsa-sha2-512"
        return self.server.host_key.kind

    def _key_exchange(self, initial: bool) -> None:
        """Run one key exchange, the first or a rekey, holding ``kex_lock`` throughout.

        The lock keeps :meth:`~.ssh._SSHServerConn._chan_write` from sending
        channel data between our ``KEXINIT`` and ``NEWKEYS``, which RFC 4253
        section 7.1 forbids.
        """
        with self.kex_lock:
            self._key_exchange_locked(initial)

    def _fault(self, name: str) -> bool:
        """Whether the server was configured with this fault (it is never consumed)."""
        return self.server.fault == name

    def _begin_strict(self, client_kex_algs: list[str]) -> None:
        """Agree strict KEX if both first KEXINITs carry the markers.

        Then the client's KEXINIT must have been its first packet (sequence
        number 0), as ``PROTOCOL`` 1.10 requires of the receiving side.
        """
        if not (self.server.strict_kex and _ssh.STRICT_KEX_CLIENT in client_kex_algs):
            return
        if self.in_seq != 1:
            raise GError_(
                "SSH protocol error: strict KEX violation: KEXINIT not first", errno.EPROTO
            )
        self.strict = self.strict_initial = True

    def _kex_recv(self, expected: int) -> bytes:
        """The client's next key-exchange packet, checked only in a strict initial KEX.

        Otherwise this server stays as lenient as it always was: the only
        client it serves is ours, which sends the exchange in order.
        """
        payload = self.recv_packet()
        if self.strict_initial and payload[0] != expected:
            raise GError_(
                f"SSH protocol error: strict KEX violation: unexpected message {payload[0]}",
                errno.EPROTO,
            )
        return payload

    def _key_exchange_locked(self, initial: bool) -> None:
        """One exchange, server side: KEXINITs, ECDH/DH, host key signature, NEWKEYS.

        The server sends its ``KEXINIT`` and reads the client's, negotiates
        with the client's lists first (RFC 4253 7.1: the client's preference
        wins), answers ``KEX_ECDH_INIT``/``KEXDH_INIT`` (both message 30) with
        ``KEX_ECDH_REPLY``/``KEXDH_REPLY`` (31): ``string K_S`` (host key blob),
        our public value, ``string`` signature of the exchange hash ``H``. Both
        sides then send ``NEWKEYS``, and the new ciphers take effect on each
        direction at its own ``NEWKEYS``. Server-to-client keys use the
        derivation letters B, D, F (IV, key, MAC key) and client-to-server A,
        C, E, per RFC 4253 section 7.2.

        Each handshake fault replaces or precedes one step of this, at the
        point named: ``ignore_before_kexinit``, ``wrong_ecdh`` (an
        ``UNIMPLEMENTED`` instead of the reply), ``ignore_before_ecdh``,
        ``bad_hostkey`` (an unparseable ``K_S``), ``bad_hostsig`` (a valid
        signature over the wrong data), ``bad_newkeys``,
        ``ignore_before_newkeys`` (the Terrapin injection) and, in
        :meth:`_kex_dh`, ``bad_dh_f``. The faults apply to rekeys too.
        """
        server_kexinit = self._server_kexinit(initial)
        if self._fault("ignore_before_kexinit"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        self.send_packet(server_kexinit)
        # Our client sends KEXINIT first; IGNORE/DEBUG ahead of it are skipped
        # here, for _begin_strict to judge once the mode is known.
        client_kexinit = self.recv_packet()
        while client_kexinit[0] in (_ssh.MSG_IGNORE, _ssh.MSG_DEBUG):
            client_kexinit = self.recv_packet()
        server_lists = _ssh.SSHTransport._parse_kexinit(server_kexinit)
        client_lists = _ssh.SSHTransport._parse_kexinit(client_kexinit)
        if initial:
            self._begin_strict(client_lists[0])
        kex = _ssh._negotiate(client_lists[0], server_lists[0])
        cipher_cs = _ssh._negotiate(client_lists[2], server_lists[2])
        cipher_sc = _ssh._negotiate(client_lists[3], server_lists[3])
        mac_cs = _ssh._negotiate(client_lists[4], server_lists[4])
        mac_sc = _ssh._negotiate(client_lists[5], server_lists[5])
        reader = Reader(self._kex_recv(_ssh.MSG_KEX_ECDH_INIT)[1:])
        # Each kex returns the client and server public values already encoded
        # the way both the exchange hash and the reply want them.
        if kex in _ssh._DH_GROUP:
            shared, client_pub, server_pub = self._kex_dh(kex, reader)
        else:
            shared, client_pub, server_pub = self._kex_curve(reader)
        host_blob = self.server.host_key.public.blob
        exchange = client_pub + server_pub
        digest = _ssh._KEX_HASH[kex]
        h = hashlib.new(
            digest,
            string(self.client_version)
            + string(self._VERSION)
            + string(client_kexinit)
            + string(server_kexinit)
            + string(host_blob)
            + exchange
            + mpint(shared),
        ).digest()
        sig = self.server.host_key.sign(h, self._hostkey_alg())
        if self._fault("wrong_ecdh"):
            self.send_packet(bytes([_ssh.MSG_UNIMPLEMENTED]) + uint32(0))
            raise EOFError
        if self._fault("ignore_before_ecdh"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        if self._fault("bad_hostkey"):
            host_blob = b"\x00\x00\x00\x03bad"  # unparseable key blob
        if self._fault("bad_hostsig"):
            sig = self.server.host_key.sign(b"a different transcript", self._hostkey_alg())
        self.send_packet(
            bytes([_ssh.MSG_KEX_ECDH_REPLY]) + string(host_blob) + server_pub + string(sig)
        )
        if self._fault("bad_newkeys"):
            self.send_packet(bytes([_ssh.MSG_UNIMPLEMENTED]) + uint32(0))
            raise EOFError
        if self._fault("ignore_before_newkeys"):
            # What a Terrapin attacker injects to shift the client's sequence.
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        self.send_packet(bytes([_ssh.MSG_NEWKEYS]))
        if initial:
            self.session_id = h
        self._kex_recv(_ssh.MSG_NEWKEYS)
        if self.strict:
            # Nothing is sent between our NEWKEYS and here, so both
            # directions restart where PROTOCOL 1.10 says: right after NEWKEYS.
            self.in_seq = 0
        keys = _ssh.SessionKeys(shared, h, self.session_id, digest)
        with self.send_lock:
            if self.strict:
                self.out_seq = 0
            self.out = _ssh.make_cipher(
                self.server.backend, cipher_sc, mac_sc, keys, ("B", "D", "F")
            )
        self.inc = _ssh.make_cipher(self.server.backend, cipher_cs, mac_cs, keys, ("A", "C", "E"))
        if initial:
            self.strict_initial = False
            self.server.strict_negotiated.append(self.strict)

    def _kex_curve(self, reader: Reader) -> tuple[int, bytes, bytes]:
        """curve25519-sha256 (RFC 8731): ``Q_C`` in, ephemeral ``Q_S`` out.

        Returns the shared secret as the integer ``K`` (RFC 8731 section
        3.1 encodes the X25519 output as an ``mpint``, big-endian) and both
        public keys as ``string``, the encoding of the exchange hash and reply.
        The client's point is not checked for low order: the only client is ours.
        """
        client_pub = reader.string()
        private, public = _x25519.generate()
        shared = int.from_bytes(_x25519.x25519(private, client_pub), "big")
        return shared, string(client_pub), string(public)

    def _kex_dh(self, kex: str, reader: Reader) -> tuple[int, bytes, bytes]:
        """Finite-field Diffie-Hellman (RFC 4253 section 8) over ``kex``'s MODP group.

        ``e`` comes from the client; the server's secret ``y`` is 2048 random
        bits reduced into ``[1, p-2]``, ``f = 2^y mod p`` and ``K = e^y mod
        p``, ``e`` and ``f`` as ``mpint``. ``bad_dh_f`` sends ``f = 1``, which
        forces the shared secret to 1; the client accepts only ``1 < f < p-1``.
        """
        p = _ssh._DH_GROUP[kex]
        e = reader.mpint()
        y = int.from_bytes(os.urandom(256), "big") % (p - 2) + 1
        f = pow(2, y, p)
        shared = pow(e, y, p)
        if self._fault("bad_dh_f"):
            return shared, mpint(e), mpint(1)  # f out of range
        return shared, mpint(e), mpint(f)

    # -- extension info & authentication ---------------------------------------

    def _send_ext_info(self) -> None:
        """Send ``SSH_MSG_EXT_INFO`` (RFC 8308) right after the first ``NEWKEYS``.

        ``server-sig-algs`` tells the client which signature algorithms a
        public key may use - how the client learns it may sign with
        ``rsa-sha2-*`` instead of SHA-1 ``ssh-rsa``. Sent only when
        :attr:`~.ssh.SSHServer.send_ext_info` is set. RFC 8308 allows it only
        to a client that offered ``ext-info-c``; ours always does, so this
        server does not check.
        """
        # Two entries, the first unrelated, so the client's parser skips it.
        body = (
            uint32(2)
            + string("first-ext@openssh.com")
            + string("1")
            + string("server-sig-algs")
            + string(self.server.ext_info_algs)
        )
        self.send_packet(bytes([_ssh.MSG_EXT_INFO]) + body)

    def _authenticate(self) -> None:
        """Accept ``ssh-userauth`` and loop over ``USERAUTH_REQUEST`` until one succeeds.

        Each request is ``string user, string service, string method`` and
        the method's fields (RFC 4252 section 5). A refusal is
        ``USERAUTH_FAILURE`` listing ``publickey,password`` with
        partial-success false; the client gives up on its own. The auth
        faults: ``bad_service_accept``, ``ignore_pre_auth``, and on success,
        before ``USERAUTH_SUCCESS``: a ``USERAUTH_BANNER`` (``auth_banner``), an
        ``IGNORE`` (``auth_ignore``), a stray ``USERAUTH_PK_OK``
        (``auth_pk_ok``), or a message that does not belong
        (``auth_unexpected``) after which the server hangs up.
        """
        self.recv_packet()  # the client's SERVICE_REQUEST
        if self._fault("bad_service_accept"):
            self.send_packet(bytes([_ssh.MSG_UNIMPLEMENTED]) + uint32(0))
            raise EOFError
        if self._fault("ignore_pre_auth"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        self.send_packet(bytes([_ssh.MSG_SERVICE_ACCEPT]) + string("ssh-userauth"))
        while True:
            payload = self.recv_packet()  # a USERAUTH_REQUEST
            reader = Reader(payload[1:])
            user = reader.text()
            reader.text()  # "ssh-connection"
            method = reader.text()
            if self._try_method(user, method, reader, payload):
                self._accept_user()
                return
            self.send_packet(
                bytes([_ssh.MSG_USERAUTH_FAILURE]) + string("publickey,password") + bytes([0])
            )

    def _accept_user(self) -> None:
        """``USERAUTH_SUCCESS``, after whatever the success-time auth faults send first.

        ``auth_unexpected`` sends a message that does not belong and hangs up
        (``EOFError``) instead.
        """
        if self._fault("auth_banner"):
            self.send_packet(bytes([_ssh.MSG_USERAUTH_BANNER]) + string("welcome") + string(""))
        if self._fault("auth_ignore"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        if self._fault("auth_pk_ok"):
            self.send_packet(bytes([_ssh.MSG_USERAUTH_PK_OK]) + string("x") + string(b"y"))
        if self._fault("auth_unexpected"):
            self.send_packet(bytes([_ssh.MSG_SERVICE_REQUEST]) + string("bogus"))
            raise EOFError
        self.send_packet(bytes([_ssh.MSG_USERAUTH_SUCCESS]))

    def _try_method(self, user: str, method: str, reader: Reader, payload: bytes) -> bool:
        """Check one authentication attempt; ``True`` means the user is in.

        An empty :attr:`~.ssh.SSHServer.username` accepts any user name, an
        empty password accepts no password. ``password`` is RFC 4252 section
        8: a ``FALSE`` change-password flag and the password. ``publickey``
        is section 7: the key must be authorized, and the signature must
        verify over ``string session_id`` followed by the request up to the
        signature itself, which is why the original ``payload`` is passed in.
        The unsigned probe (flag false, answered ``PK_OK``) is not
        implemented, because the client always signs straight away.
        """
        if self.server.username and user != self.server.username:
            return False
        if method == "password":
            reader.boolean()
            return bool(self.server.password) and reader.text() == self.server.password
        # publickey (the only other method our client sends).
        reader.boolean()  # the "signed" flag; our client always signs
        algorithm = reader.text()
        blob = reader.string()
        if not any(blob == k.blob for k in self.server.authorized_keys):
            return False
        signature = reader.string()
        request = payload[: len(payload) - len(string(signature))]
        data = string(self.session_id) + request
        return parse_public_blob(blob).verify(algorithm, data, signature)
