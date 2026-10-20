"""The test GridFTP server's data channels and the verbs that move file data.

Set-up (``PASV``, ``EPSV``, ``SPAS`` and delayed passive; ``PORT``,
``EPRT``, ``SPOR``; GridFTP v2 ``GET``/``PUT`` options), the ``DCAU``/``PROT``
handshake on each new connection, and :meth:`~_DataChannel.transfer`, which
runs one piece of work per data connection in ``MODE S`` or ``MODE E``,
sends perf and range markers meanwhile and replies ``226`` (or the injected
``after`` reply). ``RETR``/``ERET``/``GET`` and ``STOR``/``ESTO``/``PUT`` are
built on it; listings, which are transfers too, are in :mod:`.namespace`.

The byte-moving itself is the client's own code
(:func:`~xgfalclient.plugins.gridftp.data.send_blocks`,
:func:`~xgfalclient.plugins.gridftp.data.recv_blocks` and the stream
pair), run from the server's side. That keeps the framing in one place, and
the interop tests against a real globus server are what keep that framing
honest. What is the server's own is *who connects*, *when connections are
taken*, and *what the control channel says meanwhile*:

* ``MODE E`` sender: this server, for ``RETR``; it opens ``parallelism``
  connections (``PORT``/``SPOR``) or accepts that many (``PASV``) and the
  first carries the ``EOF`` block with the stream count.
* ``MODE E`` receiver on a passive listener: it keeps accepting until the
  ``EOF`` count and the ``EOD``\\ s seen agree, however many connections the
  sender chose, as GFD.20 requires.
* every connection is secured per ``DCAU``/``PROT`` before any data.

``DATA_TIMEOUT`` is read from the facade, :mod:`xgfalclient.testing.gridftp`,
each time it is needed, so a test that patches it there reaches the code here.

Data-channel faults (``server.data_faults[verb]``): ``drop`` closes each
connection without a byte, ``truncate`` sends half the requested range and
then ends normally, ``stall`` sends half and then holds a ``MODE S``
connection open until the server stops (in ``MODE E`` it is ``truncate``).
They are keyed on the verb :meth:`~_DataChannel.transfer` is given, which is
not always the command's: see each verb.
"""

from __future__ import annotations

import errno
import os
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

from ...errors import GError
from ...plugins.gridftp.data import (
    DataConn,
    EodCounter,
    Feed,
    Ranges,
    authenticate,
    positional_reader,
    recv_blocks,
    recv_stream,
    send_blocks,
    send_stream,
)
from ...plugins.gridftp.gsi import data_contexts
from ...plugins.gridftp.protocol import parse_epsv, parse_pasv
from .base import _SessionBase
from .common import _family, _Moved, _Reply


def _drop(conn: DataConn, index: int, moved: _Moved) -> None:
    """The ``drop`` fault's work: close each connection without a byte."""


class _DataChannel(_SessionBase):
    """Data-channel set-up, transfers, and the file-moving verbs."""

    def listen(self) -> int:
        """Open a passive listener beside the control connection; its port.

        It binds the address the control connection arrived on, so a client
        that reached the server over IPv6 is answered over IPv6. Any earlier
        passive listener or active address is forgotten first.
        """
        self.close_passive()
        self.active = []
        host = self.sock.getsockname()[0]
        self.passive = self.server.track(socket.create_server((host, 0), family=_family(host)))
        return int(self.passive.getsockname()[1])

    def pasv(self) -> str:
        """Listen, and say where as ``h1,h2,h3,h4,p1,p2``.

        The host shown is the server's ``advertise`` setting if given - to
        model a server behind NAT that names an address the client cannot
        use - and the listening address otherwise. RFC 959's form is IPv4
        only; an IPv6 client should use ``EPSV``.
        """
        port = self.listen()
        shown = self.server.advertise or self.sock.getsockname()[0]
        return ",".join([*shown.split("."), str(port // 256), str(port % 256)])

    def do_PASV(self, arg: str) -> None:
        """``PASV``: ``227`` with an address, or ``200 Passive delayed``.

        After ``OPTS PASV AllowDelayed=1`` no listener opens yet: the
        transfer command opens one and announces it with a ``127`` before
        its ``150`` (see :meth:`connections`), which is what lets dCache
        point the client at a pool chosen per file.
        """
        if self.allow_delayed:
            self.close_passive()
            self.active = []
            self.delayed = True
            raise _Reply("200 Passive delayed.")
        raise _Reply(f"227 Entering Passive Mode ({self.pasv()})")

    def do_EPSV(self, arg: str) -> None:
        """``EPSV``: RFC 2428's ``229 (|||port|)``; the client reuses the control host."""
        raise _Reply(f"229 Entering Extended Passive Mode (|||{self.listen()}|)")

    def do_SPAS(self, arg: str) -> None:
        """``SPAS``: GFD.20 striped passive, one stripe, as a multi-line ``229``."""
        raise _Reply(f"229-Entering Striped Passive Mode\r\n {self.pasv()}\r\n229 End")

    def do_PORT(self, arg: str) -> None:
        """``PORT h1,h2,h3,h4,p1,p2``: RFC 959 active mode; this server will connect."""
        self.close_passive()
        self.active = [parse_pasv(arg)]
        raise _Reply("200 PORT Command successful.")

    def do_EPRT(self, arg: str) -> None:
        """``EPRT |proto|addr|port|``: RFC 2428 active mode, IPv4 or IPv6."""
        self.close_passive()
        self.active = [parse_epsv(f"({arg})")]
        raise _Reply("200 EPRT Command successful.")

    def do_SPOR(self, arg: str) -> None:
        """``SPOR a1 a2 ...``: GFD.20 striped active; connections go round-robin over them."""
        self.close_passive()
        self.active = [parse_pasv(part) for part in arg.split()]
        raise _Reply("200 SPOR Command successful.")

    def secure(self, sock: socket.socket, initiator: bool) -> DataConn:
        """``DCAU A`` and/or ``PROT P`` on a fresh data connection.

        Both ends present the delegated proxy (the server got it from the
        client's ``ADAT``), so the peer must authenticate as the client's
        own DN - :attr:`identity` - or the connection fails with an
        ``EACCES`` :class:`~xgfalclient.errors.GError`, which the caller
        turns into a ``425``. ``initiator`` is the connecting side, which
        speaks first in the TLS handshake; ``PROT P`` then keeps the TLS
        session to wrap the data, ``PROT C`` drops it after authentication.
        """
        from .. import gridftp as facade  # looked up at call time: tests patch it there

        sock.settimeout(facade.DATA_TIMEOUT)
        if self.dcau == "N" and self.prot == "C":
            return DataConn(sock)
        assert self.delegated is not None
        pair = data_contexts(self.delegated, self.delegated, self.server.ca_path)
        context = authenticate(
            sock,
            pair[0] if initiator else pair[1],
            initiator=initiator,
            identity=self.identity,
            ssl_compatible=self.prot == "P",
        )
        return DataConn(sock, context if self.prot == "P" else None)

    def connections(self, open_ended: bool) -> Callable[[], DataConn | None]:
        """Where the transfer's data connections come from; ``None`` is "none yet".

        Active: each call connects to the next ``PORT``/``SPOR`` address in
        turn. Passive: each call accepts one connection on the listener -
        opening it now, with a ``127``, if ``PASV`` was delayed - and a
        missing ``PASV``/``PORT`` is RFC 959's ``425``. With ``open_ended``
        (a ``MODE E`` receiver that does not know how many connections are
        coming) the accept polls every 50 ms and returns ``None`` when none
        arrived, so :meth:`transfer` can check whether the ``EOF`` count is
        already met; otherwise it waits up to ``DATA_TIMEOUT``. A connection
        that fails to open or authenticate raises ``425``.
        """
        from .. import gridftp as facade  # looked up at call time: tests patch it there

        if self.active:
            addresses = list(self.active)
            used: list[int] = []

            def connect_out() -> DataConn:
                """Connect to the next active address and secure the connection."""
                host, port = addresses[len(used) % len(addresses)]
                used.append(port)
                try:
                    timeout = facade.DATA_TIMEOUT
                    sock = self.server.track(socket.create_connection((host, port), timeout))
                    return self.secure(sock, initiator=True)
                except (OSError, GError) as exc:
                    raise _Reply(f"425 Can't open data connection: {exc}") from None

            return connect_out
        if self.passive is None:
            if not self.delayed:
                raise _Reply("425 Use PORT or PASV first.")
            self.reply(f"127 Entering Passive Mode ({self.pasv()})")
        listener = self.passive
        assert listener is not None
        listener.settimeout(0.05 if open_ended else facade.DATA_TIMEOUT)

        def accept() -> DataConn | None:
            """Accept and secure one connection; ``None`` if none came within the poll."""
            try:
                sock, _ = listener.accept()
            except TimeoutError:
                return None
            try:
                return self.secure(self.server.track(sock), initiator=False)
            except (OSError, GError) as exc:
                raise _Reply(f"425 Can't open data connection: {exc}") from None

        return accept

    # -- transfers ------------------------------------------------------------------------

    def transfer(
        self,
        verb: str,
        count: int,
        work: Callable[[DataConn, int, _Moved], Any],
        eods: EodCounter | None = None,
    ) -> None:
        """Run ``work`` on ``count`` data connections, then reply ``226`` (or ``after``).

        A passive ``MODE E`` receiver (``eods`` given) takes connections until
        the sender's ``EOF`` count is met, however many that turns out to be.
        Perf markers go out on the control channel meanwhile.

        ``work(conn, index, moved)`` runs on its own daemon thread per
        connection (``index`` 0 is the first; ``moved`` is the shared byte
        counter) and the connection is closed when it returns. Getting all
        the connections must finish within ``DATA_TIMEOUT`` or the answer is
        ``425``; a ``work`` that raises makes the answer ``426`` with the
        first error. Either way the data-channel set-up and ``REST`` are
        consumed: the next transfer needs a new ``PASV``/``PORT``, as in
        RFC 959. The final reply is raised as :class:`~.common._Reply`; the
        server's ``after[verb]`` replaces a successful ``226``, so a test
        can fail a transfer whose data all arrived.
        """
        # Set once a passive receiver has everything; it takes connections until then.
        complete = eods.done if eods is not None and not self.active else None
        obtain = self.connections(complete is not None)
        self.reply("150 Beginning transfer.")
        if self.server.data_faults.get(verb) == "drop":
            work = _drop
        moved = _Moved()
        errors: list[BaseException] = []
        threads: list[threading.Thread] = []

        def run(conn: DataConn, index: int) -> None:
            """One connection's thread: do the work, keep its error, always close."""
            try:
                work(conn, index, moved)
            except BaseException as exc:  # reported on the control channel
                errors.append(exc)
            finally:
                conn.sock.close()

        from .. import gridftp as facade  # looked up at call time: tests patch it there

        deadline = time.monotonic() + facade.DATA_TIMEOUT
        try:
            # Two ways to know there are no more connections: an open-ended
            # receiver stops when the EOF/EOD count is met (or a connection
            # failed); everyone else stops at ``count``.
            while (
                not complete.is_set() and not errors
                if complete is not None
                else len(threads) < count
            ):
                if time.monotonic() > deadline:
                    raise _Reply("425 Can't open data connection: timed out.")
                conn = obtain()
                if conn is not None:
                    thread = threading.Thread(target=run, args=(conn, len(threads)), daemon=True)
                    threads.append(thread)
                    thread.start()
            self.wait(threads, moved)
        finally:
            self.close_passive()
            self.active = []
            self.rest = 0
        if errors:
            raise _Reply(f"426 Data connection failed: {errors[0]}")
        self._final_markers(moved, receiver=eods is not None)
        raise _Reply(self.server.after.get(verb, "226 Transfer Complete."))

    def _final_markers(self, moved: _Moved, receiver: bool) -> None:
        """In ``MODE E`` with perf markers on: the total, and a receiver's range marker.

        The final perf marker carries the total; a ``receiver`` also sends a
        range marker (GFD.20 ``111``) for what it now holds, as globus does.
        """
        if self.mode == "E" and self.server.perf_interval:
            self.marker(moved.count)
            if receiver:
                self.reply(f"111 Range Marker 0-{moved.count}")

    def wait(self, threads: list[threading.Thread], moved: _Moved) -> None:
        """Join the data threads, sending a perf marker every ``perf_interval`` seconds.

        Markers are ``MODE E`` only, as on globus; ``perf_interval`` 0 sends
        none. The 20 ms join slices bound how late a marker can be.
        """
        last = time.monotonic()
        interval = self.server.perf_interval
        for thread in threads:
            while thread.is_alive():
                thread.join(0.02)
                if self.mode == "E" and interval and time.monotonic() - last >= interval:
                    last = time.monotonic()
                    self.marker(moved.count)

    def marker(self, count: int) -> None:
        """A GFD.20 ``112`` perf marker for one stripe that has moved ``count`` bytes."""
        self.reply(
            "112-Perf Marker\r\n"
            f" Timestamp: {time.time():.1f}\r\n"
            " Stripe Index: 0\r\n"
            f" Stripe Bytes Transferred: {count}\r\n"
            " Total Stripe Count: 1\r\n"
            "112 End."
        )

    def send_file(self, verb: str, path: str, start: int, end: int | None) -> None:
        """Send ``path`` from ``start`` to ``end`` (``None``: EOF) in the session's mode.

        A directory and an unopenable file fail before ``150`` with the
        globus_xio ``500`` blocks a real server sends (the client reads
        "Is a directory" or the ``strerror`` out of them). In ``MODE E`` the
        range is cut into ``block_size`` blocks shared by ``parallelism``
        sender threads, the first of which also sends the ``EOF`` block
        (count = streams). ``truncate`` and ``stall`` faults halve the range.
        """
        if os.path.isdir(self.local(path)):
            raise _Reply(
                "500-Command failed. : callback failed.\r\n"
                "500-globus_xio: System error in read: Is a directory\r\n"
                "500-globus_xio: A system call failed: Is a directory\r\n"
                "500 End."
            )
        try:
            fd = os.open(self.local(path), os.O_RDONLY)
        except OSError as exc:
            raise _Reply(
                "500-Command failed. : globus_l_gfs_file_open failed.\r\n"
                f"500-globus_xio: Unable to open file {path}\r\n"
                f"500-globus_xio: System error in open: {os.strerror(exc.errno or errno.EIO)}\r\n"
                "500 End."
            ) from None
        try:
            size = os.fstat(fd).st_size
            stop = size if end is None else min(size, end)
            fault = self.server.data_faults.get(verb)
            if fault in ("truncate", "stall"):
                stop = start + (stop - start) // 2
            read = positional_reader(fd)
            if self.mode == "E":
                ranges = Ranges(start, stop, self.server.block_size)
                streams, block = self.parallelism, self.server.block_size
                self.transfer(
                    verb,
                    streams,
                    lambda conn, index, moved: send_blocks(
                        conn, Feed(read, block, moved.add), ranges, streams if index == 0 else 0
                    ),
                )
            else:
                self.transfer(
                    verb,
                    1,
                    lambda conn, index, moved: (
                        self._stall(conn, read, start, stop)
                        if fault == "stall"
                        else send_stream(conn, Feed(read, 65536, moved.add), start, stop)
                    ),
                )
        finally:
            os.close(fd)

    def _stall(
        self, conn: DataConn, read: Callable[[memoryview, int], int], start: int, stop: int
    ) -> None:
        """``MODE S`` that sends up to ``stop``, then holds the connection open, silent.

        As a hung server does, whatever the client does, until the server stops.
        """
        buffer = memoryview(bytearray(stop - start))
        conn.sendall(buffer[: read(buffer, start)])
        self.server._stop.wait()  # as "hang" does: only the server's stop ends it

    def do_RETR(self, arg: str) -> None:
        """``RETR <path>``: send the file, from the ``REST`` offset if one was given."""
        self.send_file("RETR", arg, self.rest, None)

    def do_ERET(self, arg: str) -> None:
        """``ERET P <offset> <length> <path>``: GFD.20 partial retrieve.

        Only the ``P`` (partial) module exists here, which is the only one
        clients use; the range is clipped to the file. Data faults and the
        ``after`` reply are keyed on ``ERET``, not ``RETR``.
        """
        module, offset, length, path = arg.split(" ", 3)
        if module != "P":
            raise _Reply("501 Unsupported ERET module.")
        self.send_file("ERET", path, int(offset), int(offset) + int(length))

    def do_ESTO(self, arg: str) -> None:
        """``ESTO A <offset> <path>``: GFD.20 adjusted store, written from ``offset``.

        The ``A`` (adjusted) module shifts incoming data by ``offset``. In
        ``MODE S`` the stream is written from there; in ``MODE E`` this
        server writes blocks at their own offsets and ignores it (the plugin
        sends ``ESTO`` in stream mode). The file is not truncated. Data
        faults and the ``after`` reply are keyed on ``STOR``.
        """
        module, offset, path = arg.split(" ", 2)
        if module != "A":
            raise _Reply("501 Unsupported ESTO module.")
        self.store(path, int(offset), truncate=False)

    def do_STOR(self, arg: str) -> None:
        """``STOR <path>``: receive the file; after ``REST`` write from there, untruncated."""
        self.store(arg, self.rest, truncate=not self.rest)

    def getput(self, arg: str) -> str:
        """Set up a GridFTP v2 ``GET``/``PUT``'s data channel; the file it names.

        GFD.47 folds data-channel set-up into the transfer command:
        ``GET path=<path>;pasv;`` makes the server listen and announce the
        address as a ``127 PORT (...)`` reply; ``port=h1,...,p2;`` makes it
        connect out. With neither, an earlier ``PASV``/``PORT`` still applies.
        The file is named by ``path=``, as Globus's client writes it; a
        command without one is refused the way dCache refuses it, before any
        data channel is set up.
        """
        options = dict(item.partition("=")[::2] for item in arg.split(";") if item)
        if not options.get("path"):
            raise _Reply("501 Missing path")
        if "port" in options:
            self.close_passive()
            self.active = [parse_pasv(options["port"])]
        elif "pasv" in options:
            self.reply(f"127 PORT ({self.pasv()})")
        return options["path"]

    def do_GET(self, arg: str) -> None:
        """GFD.47 ``GET``: ``RETR`` of the whole file, with its own data-channel options.

        Data faults and the ``after`` reply are keyed on ``RETR``, so one
        entry covers both; control-channel ``faults`` use ``GET``.
        """
        self.send_file("RETR", self.getput(arg), 0, None)

    def do_PUT(self, arg: str) -> None:
        """GFD.47 ``PUT``: ``STOR`` of a whole, truncated file with its own options."""
        self.store(self.getput(arg), 0, truncate=True)

    def store(self, arg: str, start: int, *, truncate: bool) -> None:
        """Receive into ``arg`` - a ``STOR`` in the session's mode - writing from ``start``.

        The file is created ``0644`` if missing; an open failure is the
        globus error block (``PATH_NOT_FOUND`` for a missing directory).
        ``MODE S`` writes the stream sequentially from ``start``. ``MODE E``
        writes each block at its own offset (``pwrite``, so threads need no
        lock) and ignores ``start``, since block offsets are absolute; it
        expects ``parallelism`` connections when connecting out, and when
        listening takes as many as the sender's ``EOF`` count says.
        Its data faults and ``after`` reply are keyed on ``STOR``, whichever
        verb (``STOR``, ``ESTO``, ``PUT``) called it.
        """
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if truncate else 0)
        try:
            fd = os.open(self.local(arg), flags, 0o644)
        except OSError as exc:
            raise self.failure(exc, "open") from None

        def write(view: memoryview, offset: int) -> None:
            """Positional write, safe to share between receiver threads."""
            os.pwrite(fd, view, offset)

        try:
            if self.mode == "E":
                eods = EodCounter()
                self.transfer(
                    "STOR",
                    self.parallelism,
                    lambda conn, index, moved: recv_blocks(conn, write, 65536, moved.add, eods),
                    eods,
                )
            else:
                self.transfer(
                    "STOR",
                    1,
                    lambda conn, index, moved: recv_stream(conn, write, 65536, moved.add, start),
                )
        finally:
            os.close(fd)
