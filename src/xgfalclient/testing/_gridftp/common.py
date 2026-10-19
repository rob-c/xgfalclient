"""Small pieces every part of the test GridFTP server's session shares.

The two control-flow exceptions a command handler raises (:class:`_Reply`
answers, :class:`_Hangup` ends the session), the byte counter perf markers
read, the ``CKSM`` arithmetic, and the error and verb tables. They are
defined here, below everything that uses them, so the mixins in
:mod:`xgfalclient.testing._gridftp` can import them without a cycle; the
facade :mod:`xgfalclient.testing.gridftp` re-exports each one.

Handlers answer by *raising* rather than calling ``reply`` and returning so
that every exit from a verb - success, refusal, or an ``OSError`` turned
into a globus error block - goes through the one ``except _Reply`` in
:meth:`~.base._SessionBase.handle`, and a handler cannot accidentally send
two final replies. Preliminary replies (``150``, ``127``, ``112``) are sent
directly; only the final one is raised.
"""

from __future__ import annotations

import errno
import hashlib
import socket
import threading
import zlib
from collections.abc import Callable

#: ``errno`` to the ``c=`` of a globus error block; anything else is 451.
#: globus-gridftp-server names only these three; every other failure it reports
#: as ``INTERNAL_ERROR`` with a ``451``. Clients (gfal2, and
#: :func:`xgfalclient.plugins.gridftp.protocol.errno_for_reply`) ignore both the
#: code and ``c=`` and read the errno off the block's text, so the
#: ``GridFTP-Error-String`` line (``strerror``) is what a test really pins.
_GLOBUS_CODES = {
    errno.ENOENT: "PATH_NOT_FOUND",
    errno.EEXIST: "PATH_EXISTS",
    errno.EACCES: "PERMISSION_DENIED",
}
#: Verbs a client may send before logging in.
#: Everything else answers ``530`` until ``PASS`` succeeds, as RFC 959 servers do;
#: ``FEAT`` is open because clients probe features before choosing to authenticate.
_OPEN = frozenset({"AUTH", "ADAT", "USER", "PASS", "FEAT", "QUIT", "NOOP", "SYST"})


class _Reply(Exception):
    """Raised by a handler to answer with ``text`` (``"550 ..."``).

    ``text`` is the complete reply: one line, or several joined by ``\\r\\n``
    in RFC 959 multi-line form (``"211-..."`` lines then ``"211 End."``).
    :meth:`~.base._SessionBase.reply` adds the final ``\\r\\n`` and, on a
    protected session, wraps each line separately.
    """

    def __init__(self, text: str) -> None:
        """Carry ``text`` as both the exception message and :attr:`text`."""
        super().__init__(text)
        self.text = text


class _Hangup(Exception):
    """End the session without another word.

    Raised for ``QUIT`` (after its ``221``) and for the ``close``/``hang``
    faults; :meth:`~.base._SessionBase.run` swallows it and closes the socket,
    so the client sees EOF on the control connection.
    """


class _Moved:
    """Bytes moved by a transfer's data threads, for perf markers.

    Every data-connection thread of a transfer adds to the one counter
    (under a lock, since ``MODE E`` runs several threads), and the control
    thread reads :attr:`count` to fill ``112`` perf markers. A read without
    the lock is fine: a marker only needs a recent value, not an exact one.
    """

    def __init__(self) -> None:
        """Start at zero; one counter per transfer."""
        self._lock = threading.Lock()
        #: Payload bytes moved so far, across every connection.
        self.count = 0

    def add(self, count: int) -> None:
        """Account ``count`` more bytes; the ``on_bytes`` callback of the data helpers."""
        with self._lock:
            self.count += count


def _checksum(path: str, algorithm: str, offset: int, length: int) -> str:
    """The globus ``CKSM`` value of ``length`` bytes of ``path`` from ``offset``.

    ``length`` of ``-1`` (any negative) means "to the end of the file", as
    the ``CKSM <algorithm> <offset> <length> <path>`` command defines it.
    ``ADLER32`` and ``CRC32`` are the zlib functions, printed as eight hex
    digits (zero-padded, as globus prints them and gfal2 compares them);
    anything else is a :mod:`hashlib` name. An unknown algorithm is the
    ``500`` globus sends; an unreadable file raises ``OSError`` for the
    caller to word as an error block. The file is read whole into memory,
    which is fine for test-sized files.
    """
    name = algorithm.upper()
    with open(path, "rb") as handle:
        handle.seek(offset)
        data = handle.read() if length < 0 else handle.read(length)
    if name == "ADLER32":
        return f"{zlib.adler32(data):08x}"
    if name == "CRC32":
        return f"{zlib.crc32(data):08x}"
    try:
        return hashlib.new(name.lower(), data).hexdigest()
    except ValueError:
        raise _Reply("500 Unknown checksum algorithm requested.") from None


def _family(host: str) -> socket.AddressFamily:
    """``AF_INET6`` for an IPv6 literal, else ``AF_INET`` (names resolve to IPv4 here)."""
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _slice(data: bytes) -> Callable[[memoryview, int], int]:
    """A ``Reader`` over in-memory ``data``, for sending a listing as a file.

    The data helpers in :mod:`xgfalclient.plugins.gridftp.data` read through
    ``read(view, offset) -> count`` (the shape of ``os.preadv``); this gives
    a listing's text that shape, returning ``0`` past the end as EOF.
    """

    def read(view: memoryview, offset: int) -> int:
        """Copy what fits of ``data[offset:]`` into ``view``; the count copied."""
        chunk = data[offset : offset + len(view)]
        view[: len(chunk)] = chunk
        return len(chunk)

    return read
