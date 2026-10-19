"""The test SSH-2 server: :class:`SSHServer` and the channel half of its connections.

:class:`SSHServer` accepts connections (over a socketpair) and runs each as
an :class:`_SSHServerConn`: the transport and authentication of
:class:`~.transport._SSHTransport`, then one session channel with OpenSSH's
window and packet limits whose ``sftp`` subsystem is wired to an
:class:`~.server.SFTPServer`, plus the channel-level faults and forced
rekeying a test can ask for.

The connection protocol is RFC 4254, cut down to what an ``sftp`` client
does: one ``session`` channel (section 6.1), one ``subsystem`` request
(section 6.5), ``CHANNEL_DATA`` both ways under each side's window (section
5.2), ``EOF``/``CLOSE`` to end it. No shells, no port forwarding, no second
channel; global requests from the client are not expected.

Threads per connection: the connection thread runs the handshake and then
the SFTP session itself (:meth:`SFTPServer.serve` reading and writing the
channel), and a reader thread receives every packet after the channel is
open (:meth:`_SSHServerConn._run_reader`). They meet in
``_SSHServerConn.cond``: the reader appends incoming data and window
credit, the session waits for them. A forced rekey runs on the reader
thread, holding ``kex_lock`` so the session's writes pause until it is done;
channel data the client sent before it read our ``KEXINIT`` is queued as
usual meanwhile, and the window credit it earns waits for ``NEWKEYS``.
Both threads are daemons; there is no ``stop``, a connection ends when
either side hangs up.
"""

from __future__ import annotations

import contextlib
import errno
import socket
import threading

from ...crypto import ciphers as _ciphers
from ...crypto.sshkeys import (
    PrivateKey,
    PublicKey,
    Reader,
    string,
    uint32,
)
from ...errors import GError as GError_
from ...plugins.sftp import ssh as _ssh
from .server import SFTPServer
from .transport import _SSHTransport


class SSHServer:
    """A minimal SSH-2 server: the algorithms the client speaks, over the ``sftp`` subsystem.

    It negotiates KEX (curve25519 or a DH group), signs with an
    ed25519/RSA/ECDSA host key, brings up ``aes-ctr``+HMAC or
    ChaCha20-Poly1305, authenticates a password or public key, and wires one
    session channel's ``sftp`` subsystem to an :class:`SFTPServer`. It is
    only as complete as the client it tests.

    ``strict_kex`` (the default, as in OpenSSH 9.6 and later) offers
    ``kex-strict-s-v00@openssh.com``; when the client offers its half the
    server holds itself and the client to ``PROTOCOL`` 1.10 - the client's
    KEXINIT must be its first packet, nothing but the exchange's own messages
    during the initial exchange, sequence numbers reset at every ``NEWKEYS``.
    ``strict_kex=False`` is a pre-9.6 server, for the tolerant path.

    Args:
        sftp: The SFTP server every connection's subsystem is served by.
        host_key: Signs the exchange hash; its kind picks the one host key
            algorithm offered.
        password: The password accepted; empty accepts none.
        username: The only user accepted; empty accepts any.
        authorized_keys: Public keys accepted for ``publickey`` auth.
        send_ext_info: Send ``EXT_INFO`` after the first ``NEWKEYS``.
        ext_info_algs: Its ``server-sig-algs`` value, comma-separated.
        rekey_after: Start a server-initiated rekey once the client has sent
            this many ``CHANNEL_DATA`` packets (once per connection; 0 never).
        fault: One named misbehaviour for every connection; the handshake
            ones are listed at :meth:`~.transport._SSHTransport._key_exchange_locked`
            and :meth:`~.transport._SSHTransport._authenticate`, the channel
            ones at :meth:`_SSHServerConn._open_channel` and
            :meth:`_SSHServerConn._emit_channel_faults`. Unlike
            :attr:`SFTPServer.faults` it is not consumed.
        backend: The cipher backend, normally the default one; a test passes
            a stand-in to model a backend without GCM or fast ChaCha20.
        strict_kex: Offer OpenSSH strict KEX (see above).
    """

    def __init__(
        self,
        sftp: SFTPServer,
        host_key: PrivateKey,
        *,
        password: str = "",
        username: str = "",
        authorized_keys: tuple[PublicKey, ...] = (),
        send_ext_info: bool = False,
        ext_info_algs: str = "rsa-sha2-512,rsa-sha2-256,ssh-ed25519,ecdsa-sha2-nistp256",
        rekey_after: int = 0,
        fault: str = "",
        backend: _ciphers.Backend | None = None,
        strict_kex: bool = True,
    ) -> None:
        """Configure the server; nothing listens until :meth:`pair` is called."""
        self.sftp = sftp
        self.host_key = host_key
        self.password = password
        self.username = username
        self.authorized_keys = authorized_keys
        self.send_ext_info = send_ext_info
        self.ext_info_algs = ext_info_algs
        self.rekey_after = rekey_after
        self.fault = fault
        self.backend = backend if backend is not None else _ciphers.get()
        self.strict_kex = strict_kex
        #: Every connection thread started, so a test can ``join`` them.
        self.threads: list[threading.Thread] = []
        #: Each finished connection's negotiated strict-KEX mode, for tests.
        self.strict_negotiated: list[bool] = []

    def pair(self) -> socket.socket:
        """A client socket already connected to a server session in a thread.

        The caller owns the returned socket; the server reads the client's
        version line from it as soon as the client writes one.
        """
        client, server = socket.socketpair()
        thread = threading.Thread(target=self._serve, args=(server,), daemon=True)
        thread.start()
        self.threads.append(thread)
        return client

    def _serve(self, sock: socket.socket) -> None:
        """A connection thread's body: run one connection and always close its socket.

        Every way a connection ends - a hang-up, a fault, a protocol error
        found by either side's checks (``GError_``), a malformed packet
        (``ValueError`` from a reader) - is expected in a test server and
        swallowed; the test sees the outcome on the client side.
        """
        conn = _SSHServerConn(self, sock)
        try:
            conn.run()
        except (EOFError, OSError, GError_, ValueError):
            pass
        finally:
            # shutdown() first: on Linux a bare close() neither wakes this
            # connection's reader thread, blocked in recv on the same socket,
            # nor sends the FIN the client is waiting for.
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()  # idempotent


#: The window and maximum packet the test server grants, as OpenSSH's sshd
#: does for a session channel - so a client upload runs into both. sshd's are
#: ``CHAN_SES_WINDOW_DEFAULT`` (64 packets of 32 KiB) and ``CHAN_SES_PACKET_DEFAULT``.
_SERVER_WINDOW = 2 * 1024 * 1024
_SERVER_MAXPACKET = 32768


class _SSHServerConn(_SSHTransport):
    """One server connection: the transport, then the session channel and its subsystem.

    The windows, the receive buffer and the end-of-channel state are shared
    between the session thread and the reader thread and are touched only
    under ``cond``; the transport's own locks cover sending.
    """

    def __init__(self, server: SSHServer, sock: socket.socket) -> None:
        """Set up the channel state; :meth:`run` does the rest."""
        super().__init__(server, sock)
        # Channel numbers (RFC 4254 section 5.1): the client's, which every
        # channel message we send must carry, and ours, always 0.
        self.remote_channel = 0
        self.local_channel = 0
        # What the client lets us send: its window (decremented as we send,
        # credited by its WINDOW_ADJUST) and its maximum packet size.
        self.client_window = 0
        self.client_maxpacket = 0
        # What we let the client send before our next WINDOW_ADJUST.
        self.local_window = _SERVER_WINDOW
        self.cond = threading.Condition()
        # Received channel data the SFTP session has not read yet.
        self.inbuf = bytearray()
        # The client sent EOF/CLOSE, or the reader died (then ``error`` is why).
        self.eof = False
        self.error: BaseException | None = None
        # CHANNEL_DATA packets received, against SSHServer.rekey_after.
        self.client_packets = 0
        self.rekeyed = False

    # -- handshake -------------------------------------------------------------

    def run(self) -> None:
        """The whole connection, in RFC order, on the connection thread.

        Version exchange, the initial key exchange, ``EXT_INFO`` if asked,
        authentication, the channel and its subsystem, any channel fault;
        then the reader thread starts and this thread becomes the SFTP
        session until the channel ends.
        """
        self.client_version = self._exchange_versions()
        self._key_exchange(initial=True)
        if self.server.send_ext_info:
            self._send_ext_info()
        self._authenticate()
        self._open_channel()
        self._emit_channel_faults()
        reader = threading.Thread(target=self._run_reader, daemon=True)
        reader.start()
        self.server.sftp.serve(self._chan_read_exact, self._chan_write)

    # -- channel ---------------------------------------------------------------

    def _open_channel(self) -> None:
        """Accept the ``session`` channel, then its ``subsystem`` request for ``sftp``.

        ``CHANNEL_OPEN`` is ``string type, uint32 sender channel, uint32
        initial window, uint32 maximum packet``; the confirmation returns
        ours. The request is ``uint32 channel, string "subsystem", boolean
        want-reply, string name``; anything but ``sftp`` (or the
        ``no-subsystem`` fault) gets ``CHANNEL_FAILURE`` and a hang-up,
        which is what ``ssh -s`` reports as "subsystem request failed".

        The faults here, in the order they can fire: ``global_before_open``,
        ``channel_open_failure`` (reason code 4, ``SSH_OPEN_RESOURCE_SHORTAGE``
        in RFC 4254 section 5.1, though the text sent is that of code 1,
        "administratively prohibited"), ``wrong_channel_confirm``,
        ``ignore_before_open``, ``window_before_confirm``,
        ``ignore_before_subsystem``, ``request_before_subsystem`` and
        ``wrong_subsystem``. Each is a message a real server may legally
        send at that point, or one it must not, for the client to reject.
        """
        reader = Reader(self.recv_packet()[1:])  # CHANNEL_OPEN
        reader.text()  # "session"
        self.remote_channel = reader.uint32()
        self.client_window = reader.uint32()
        self.client_maxpacket = reader.uint32()
        if self._fault("global_before_open"):
            # A GLOBAL_REQUEST that wants a reply, before the confirmation.
            self.send_packet(
                bytes([_ssh.MSG_GLOBAL_REQUEST]) + string("hostkeys-00@openssh.com") + bytes([1])
            )
        if self._fault("channel_open_failure"):
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_OPEN_FAILURE])
                + uint32(self.remote_channel)
                + uint32(4)
                + string("administratively prohibited")
                + string("")
            )
            raise EOFError
        if self._fault("wrong_channel_confirm"):
            self.send_packet(bytes([_ssh.MSG_UNIMPLEMENTED]) + uint32(0))
            raise EOFError
        if self._fault("ignore_before_open"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        if self._fault("window_before_confirm"):
            # OpenSSH may credit the channel window before confirming it.
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_WINDOW_ADJUST]) + uint32(self.remote_channel) + uint32(4096)
            )
        self.send_packet(
            bytes([_ssh.MSG_CHANNEL_OPEN_CONFIRMATION])
            + uint32(self.remote_channel)
            + uint32(self.local_channel)
            + uint32(self.local_window)
            + uint32(_SERVER_MAXPACKET)
        )
        request = self.recv_packet()
        while request[0] in (_ssh.MSG_REQUEST_FAILURE, _ssh.MSG_REQUEST_SUCCESS):
            request = self.recv_packet()  # the client's reply to a global request
        r = Reader(request[1:])  # CHANNEL_REQUEST
        r.uint32()
        kind = r.text()
        r.boolean()  # want_reply; our client always wants one for the subsystem
        name = r.string()
        ok = kind == "subsystem" and name == b"sftp" and self.server.fault != "no-subsystem"
        if self._fault("ignore_before_subsystem"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        if self._fault("request_before_subsystem"):
            # A CHANNEL_REQUEST (no reply wanted) arriving before the confirmation.
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_REQUEST])
                + uint32(self.remote_channel)
                + string("exit-signal")
                + bytes([0])
                + string("TERM")
            )
        if self._fault("wrong_subsystem"):
            self.send_packet(bytes([_ssh.MSG_UNIMPLEMENTED]) + uint32(0))
            raise EOFError
        code = _ssh.MSG_CHANNEL_SUCCESS if ok else _ssh.MSG_CHANNEL_FAILURE
        self.send_packet(bytes([code]) + uint32(self.remote_channel))
        if not ok:
            raise EOFError

    def _emit_channel_faults(self) -> None:
        """After the subsystem is up, inject one channel-level oddity if asked.

        The benign ones the client must skip and carry on: ``ignore_mid``,
        ``stderr`` (``EXTENDED_DATA`` type 1, the subsystem's stderr),
        ``exit_status`` and ``exit_status_noreply`` (a ``CHANNEL_REQUEST``
        with and without want-reply), ``global_mid`` and
        ``global_mid_noreply`` (OpenSSH's ``keepalive@openssh.com``, which a
        client must answer ``REQUEST_FAILURE`` when a reply is wanted). The
        fatal ones end the connection: ``disconnect_mid`` (``DISCONNECT``
        reason 11, ``SSH_DISCONNECT_BY_APPLICATION``), ``eof_close`` (an
        orderly channel end) and ``abrupt`` (the socket closed with no message).
        """
        ch = uint32(self.remote_channel)
        if self._fault("ignore_mid"):
            self.send_packet(bytes([_ssh.MSG_IGNORE]) + string(b"noise"))
        elif self._fault("stderr"):
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_EXTENDED_DATA]) + ch + uint32(1) + string(b"warn")
            )
        elif self._fault("exit_status"):
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_REQUEST])
                + ch
                + string("exit-status")
                + bytes([1])
                + uint32(0)
            )
        elif self._fault("exit_status_noreply"):
            self.send_packet(
                bytes([_ssh.MSG_CHANNEL_REQUEST])
                + ch
                + string("exit-status")
                + bytes([0])
                + uint32(0)
            )
        elif self._fault("global_mid"):
            self.send_packet(
                bytes([_ssh.MSG_GLOBAL_REQUEST]) + string("keepalive@openssh.com") + bytes([1])
            )
        elif self._fault("global_mid_noreply"):
            self.send_packet(
                bytes([_ssh.MSG_GLOBAL_REQUEST]) + string("keepalive@openssh.com") + bytes([0])
            )
        elif self._fault("disconnect_mid"):
            self.send_packet(bytes([_ssh.MSG_DISCONNECT]) + uint32(11) + string("bye") + string(""))
            raise EOFError
        elif self._fault("eof_close"):
            self.send_packet(bytes([_ssh.MSG_CHANNEL_EOF]) + ch)
            self.send_packet(bytes([_ssh.MSG_CHANNEL_CLOSE]) + ch)
            raise EOFError
        elif self._fault("abrupt"):
            raise EOFError  # drop the connection with no framing at all

    def _run_reader(self) -> None:
        """The reader thread: dispatch packets until ``CHANNEL_CLOSE`` or the stream fails.

        A failure is recorded as ``error`` with ``eof`` set, waking a session
        blocked in :meth:`_chan_read_exact` or :meth:`_chan_write` so it ends
        too rather than wait forever; the session's end then closes the
        socket, so the client sees the failure instead of a silent stall. A
        malformed packet (``ValueError`` from a reader) is such a failure too.
        """
        try:
            while True:
                payload = self.recv_packet()
                if not self._dispatch(payload):
                    return
        except (EOFError, OSError, GError_, ValueError) as exc:
            with self.cond:
                self.error = exc
                self.eof = True
                self.cond.notify_all()

    def _dispatch(self, payload: bytes) -> bool:
        """Handle one packet from the client; ``False`` once the channel is closed.

        The message itself is taken by :meth:`_take_channel_message`. Then,
        the first time the count of ``CHANNEL_DATA`` packets reaches
        :attr:`SSHServer.rekey_after`, a rekey is started from our side - the
        case where the client must handle ``KEXINIT`` arriving amid its own
        data, and this server the client's data arriving amid the rekey.
        Last, our window is topped up if due: after the rekey, as nothing but
        key-exchange messages may go out between our ``KEXINIT`` and ``NEWKEYS``.
        """
        still_open = self._take_channel_message(payload)
        if self._rekey_due():
            self._key_exchange(initial=False)
        self._credit_window()
        return still_open

    def _take_channel_message(self, payload: bytes) -> bool:
        """Apply one client message to the channel state; ``False`` for ``CHANNEL_CLOSE``.

        ``CHANNEL_DATA`` (``uint32 channel, string data``) is queued for the
        session and charged to our window, ``WINDOW_ADJUST`` adds to what we
        may send, ``EOF``/``CLOSE`` end the stream; ``IGNORE``, ``DEBUG`` and
        anything else are skipped. Nothing is sent from here, so it is safe
        mid-rekey too. Channel numbers are not checked: there is only one channel.
        """
        code = payload[0]
        if code == _ssh.MSG_CHANNEL_DATA:
            reader = Reader(payload[1:])
            reader.uint32()
            data = reader.string()
            # The window is topped up as data arrives, so it never falls below
            # half of _SERVER_WINDOW: only a packet over the maximum can overrun it.
            if len(data) > _SERVER_MAXPACKET:
                # A client overrunning the flow control it was granted.
                raise GError_("SSH protocol error: channel data beyond the window", errno.EPROTO)
            with self.cond:
                self.inbuf += data
                self.local_window -= len(data)
                self.client_packets += 1
                self.cond.notify_all()
            return True
        if code == _ssh.MSG_CHANNEL_WINDOW_ADJUST:
            reader = Reader(payload[1:])
            reader.uint32()
            with self.cond:
                self.client_window += reader.uint32()
                self.cond.notify_all()
            return True
        if code in (_ssh.MSG_CHANNEL_EOF, _ssh.MSG_CHANNEL_CLOSE):
            with self.cond:
                self.eof = True
                self.cond.notify_all()
            return code != _ssh.MSG_CHANNEL_CLOSE
        return True

    def _before_client_kexinit(self, payload: bytes) -> None:
        """Channel traffic the client sent before it read our rekey ``KEXINIT``: kept.

        RFC 4253 section 7.1 allows it, and a client streaming an upload
        always has some in flight. It is applied like any other message, and
        the window credit it earns is sent once the exchange is over (see
        :meth:`_dispatch`). A ``CHANNEL_CLOSE`` here marks the end of the
        stream; the exchange then fails on the client's hang-up.
        """
        self._take_channel_message(payload)

    def _rekey_due(self) -> bool:
        """Whether to start our one rekey now (:attr:`SSHServer.rekey_after`); marks it started."""
        with self.cond:
            due = (
                self.server.rekey_after > 0
                and not self.rekeyed
                and self.client_packets >= self.server.rekey_after
            )
            if due:
                self.rekeyed = True
        return due

    def _credit_window(self) -> None:
        """Top our window back up once half of it is used, as sshd does.

        One ``WINDOW_ADJUST`` per half-window rather than one per packet,
        so a client that waits for credit is exercised without flooding it.
        Sent outside ``cond``, so the session thread is not held up by it.
        """
        with self.cond:
            if self.local_window > _SERVER_WINDOW // 2:
                return
            top_up = _SERVER_WINDOW - self.local_window
            self.local_window = _SERVER_WINDOW
        self.send_packet(
            bytes([_ssh.MSG_CHANNEL_WINDOW_ADJUST]) + uint32(self.remote_channel) + uint32(top_up)
        )

    def _chan_read_exact(self, count: int) -> bytes:
        """The SFTP session's ``read_exact`` over the channel: wait for ``count`` bytes.

        Data arrives in channel packets of any size, so one SFTP packet may
        span many and one channel packet hold several. ``EOFError`` once the
        channel is closed (or the reader failed) with too little buffered.
        """
        out = bytearray()
        with self.cond:
            while len(out) < count:
                if self.inbuf:
                    take = min(count - len(out), len(self.inbuf))
                    out += self.inbuf[:take]
                    del self.inbuf[:take]
                elif self.eof:  # set with self.error, too
                    raise EOFError
                else:
                    self.cond.wait()
        return bytes(out)

    def _chan_write(self, data: bytes) -> None:
        """The SFTP session's ``write`` over the channel, honouring the client's flow control.

        Data goes out in pieces no larger than the client's maximum packet
        or its remaining window (RFC 4254 section 5.2), waiting for a
        ``WINDOW_ADJUST`` when the window is spent - which is how tests check
        that the client grants credit as it consumes data. Each piece is sent
        under ``kex_lock`` so none goes out during a rekey. ``EOFError`` if
        the reader has failed, as no more credit can then arrive.
        """
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            with self.cond:
                limit = min(self.client_maxpacket, self.client_window)
                while limit <= 0:
                    if self.error is not None:
                        raise EOFError
                    self.cond.wait()
                    limit = min(self.client_maxpacket, self.client_window)
                chunk = min(limit, len(view) - offset)
                self.client_window -= chunk
            piece = bytes(view[offset : offset + chunk])
            with self.kex_lock:
                self.send_packet(
                    bytes([_ssh.MSG_CHANNEL_DATA]) + uint32(self.remote_channel) + string(piece)
                )
            offset += chunk
