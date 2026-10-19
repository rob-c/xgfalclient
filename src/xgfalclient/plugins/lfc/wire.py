"""The Cns wire format: LFC's marshalling, request codes and error numbers.

Everything the LFC (and DPNS, and CASTOR's name server - they share one code
base, lcgdm's ``ns/``) says on the wire is built by the ``marshall_*``
macros of ``h/marshall.h``: big-endian ``LONG`` (4 bytes), ``WORD`` (2),
``BYTE`` (1), ``HYPER`` (8) and ``TIME_T`` (a ``HYPER``), and
NUL-terminated strings. A request is a 12-byte header - magic, request
type, total length including the header - and a body; ``send2nsd.c``
reads replies as a stream of 12-byte headers (magic, reply type, length or
status) each followed, for data replies, by that many bytes:

``MSG_ERR``
    a human-readable string the client library prints on stderr;
``MSG_DATA``
    the request's fixed-size answer (a ``stat`` record, a count...);
``MSG_LINKS``/``MSG_REPLIC``/``MSG_STATUSES``...
    lists too long for one reply, in as many messages as it takes;
``CNS_RC``
    the final status - the server closes the connection after it;
``CNS_IRC``
    an intermediate status, inside a session, transaction or listing.

A header is three big-endian ``LONG`` values; for a request they are::

    magic (CNS_MAGIC..CNS_MAGIC4)  type (CNS_STAT, ...)  length (header + body)

and for a reply ``magic``, the reply type above, and either the payload
length (``MSG_*``) or the status, ``0`` or a serrno (``CNS_RC``/``CNS_IRC``).
The client never looks at a reply's magic.

**The magic is a request version.** The server reads a request body by the
magic it carries: ``CNS_MAGIC2`` adds fields the original layout lacked
(the GUID of ``Cns_mkdirg``/``Cns_creatg``, the GUID and checksum columns
of a ``readdir`` record, a new replica's status and pool), ``CNS_MAGIC3``
adds a replica's file type and file system, and so on. So a request must
be sent with the magic of the layout it was packed in - :mod:`.client`
does this per call, copying ``ns/Cns_*.c`` - and the test server
(``xgfalclient.testing.lfc``) decodes by the same rule, so a wrong magic
shows up as a misread field.

**Errors** come back as serrno values: plain ``errno`` numbers below
:data:`SEBASEOFF`, Castor's own codes from 1000 (``SE*``), the name
server's from 1400 (``ENS*``) and Csec's from 2700 (``ESEC_*``).
:func:`serrno_text` gives liblfc's message, :func:`errno_for` the
``errno`` the plugin reports.

This module is pure - no sockets - and shared by the client
(:mod:`.client`, :mod:`.csec`) and the in-process test server, so the two
cannot drift apart on a byte layout.

Sources (lcgdm 1.13.0): ``h/Cns.h`` (magics, codes, reply types),
``h/marshall.h``, ``ns/send2nsd.c`` (reply loop), ``ns/sendrep.c``,
``h/serrno.h`` and ``common/serror.c`` (error numbers and their text).
"""

from __future__ import annotations

import errno
import os
import struct

from ...errors import ECOMM, GError

__all__ = [
    "HEADER",
    "Packer",
    "Unpacker",
    "WireError",
    "errno_for",
    "request",
    "serrno_text",
]

# -- magics (h/Cns.h) ------------------------------------------------------------
# Request-layout versions, not protocol versions: see the module docstring.
MAGIC = 0x030E1301
MAGIC2 = 0x030E1302
MAGIC3 = 0x030E1303
MAGIC4 = 0x030E1304

#: Default port, ``CNS_PORT`` in ``h/Cns_constants.h``; ``$LFC_PORT`` overrides it.
PORT = 5010

# -- request types (h/Cns.h) -------------------------------------------------------
# Only the codes this client sends (or the test server answers); the numbering
# has gaps because the server knows many more (ACLs, user and group admin...).
ACCESS = 0
CHMOD = 2
CREAT = 4
MKDIR = 5
RENAME = 6
RMDIR = 7
STAT = 8
UNLINK = 9
OPENDIR = 10
READDIR = 11
CLOSEDIR = 12
SETFSIZE = 16
GETCOMMENT = 32
SETCOMMENT = 33
LSTAT = 40
READLINK = 41
SYMLINK = 42
ADDREPLICA = 43
DELREPLICA = 44
STARTTRANS = 46
ENDTRANS = 47
ABORTTRANS = 48
SETFSIZEG = 50
STATG = 51
STATR = 52
STARTSESS = 59
ENDSESS = 60
GETLINKS = 71
GETREPLICA = 72
PING = 82
DELFILES = 83

# -- reply types (h/Cns.h) ---------------------------------------------------------
# The ``MSG_*`` list types (5 and up) are collected by type in ``Reply.lists``;
# each carries back-to-back records of the shape its request defines.
MSG_ERR = 1
MSG_DATA = 2
CNS_RC = 3
CNS_IRC = 4
MSG_LINKS = 5
MSG_REPLIC = 6
MSG_REPLICP = 7
MSG_REPLICX = 8
MSG_REPLICS = 9
MSG_GROUPS = 10
MSG_STATUSES = 11
MSG_FILEST = 12
MSG_GRPINFO = 13
MSG_USRINFO = 14

# -- sizes (h/Cns.h, h/Castor_limits.h) ----------------------------------------------
# The ``MAX*LEN`` limits exclude the terminating NUL, as in Castor_limits.h.
REQBUFSZ = 2854
#: The largest reply payload the server sends in one message; anything
#: bigger is a corrupt stream, refused before it is read (``WireError``).
REPBUFSZ = 4100
#: The server's buffer for one ``readdir`` batch: how many records fit
#: depends on the entry size the client announces (``DIRENTSZ``).
DIRBUFSZ = 4096
MAXPATHLEN = 1023
MAXNAMELEN = 255
MAXCOMMENTLEN = 255
MAXGUIDLEN = 36
MAXHOSTNAMELEN = 63
MAXSFNLEN = 1103
MAXSYMLINKS = 5
#: ``getreq``'s cap on one request (``ONE_MB`` in ``Cns_main.c``).
MAXREQUEST = 1024 * 1024

#: The 12-byte header of every request and reply: magic, type, length/status.
#: Signed, because a status is a C ``int``.
HEADER = struct.Struct(">iii")
_LONG = struct.Struct(">i")
_ULONG = struct.Struct(">I")
_WORD = struct.Struct(">H")
_HYPER = struct.Struct(">Q")
_SHYPER = struct.Struct(">q")

# -- serrno (h/serrno.h) -------------------------------------------------------------
# Only the values this package names; the tables below cover the rest for messages.
#: The first Castor-specific serrno; below it a serrno is an ``errno``.
SEBASEOFF = 1000
SENOSHOST = 1001
SETIMEDOUT = 1004
SENAMETOOLONG = 1008
SEINTERNAL = 1015
SECONNDROP = 1016
SECOMERR = 1018
SENOMAPFND = 1020
SEOPNOTSUP = 1022
SELOOP = 1038
ENSNACT = 1401
ESEC_SYSTEM = 2701
ESEC_BAD_CREDENTIALS = 2702
ESEC_NO_CONTEXT = 2703
ESEC_BAD_MAGIC = 2704
ESEC_PROTNOTSUPP = 2709
ESEC_BAD_PEER_RESP = 2714

#: ``sys_serrlist`` of ``common/serror.c``, from ``SEBASEOFF + 1``.
_SERRLIST = (
    "Host not known",
    "Service unknown",
    "Not a remote file",
    "Timed out",
    "Unsupported FORTRAN format",
    "Unknown FORTRAN option",
    "Incompatible FORTRAN options",
    "File name too long",
    "Can't open configuration file",
    "Version ID mismatch",
    "User buffer too small",
    "Invalid reply number",
    "User message too long",
    "Entry not found",
    "Internal error",
    "Connection closed by remote end",
    "Can't find interface name",
    "Communication error",
    "Can't open mapping database",
    "No user mapping",
    "Retry count exhausted",
    "Operation not supported",
    "Resource temporarily unavailable",
    "Operation now in progress",
    "Cthread initialization error",
    "Thread interface call error",
    "System error",
    "adns_init() error",
    "adns_submit() error",
    "adns resolving error",
    "adns returned more than one entry",
    "requestor is not administrator",
    "User unknown",
    "Duplicate key value",
    "Entry already exists",
    "Group unknown",
    "Bad checksum",
    "Too many symbolic links encountered",
)

#: ``sys_secerrlist``, from ``ESECBASEOFF + 1`` (``ESECBASEOFF`` is 2700).
_SECERRLIST = (
    "System error",
    "Bad credentials",
    "Could not secure the connection",
    "Bad magic number",
    "Could not map username to uid/gid",
    "Could not map principal to username",
    "Could not load a security plugin",
    "Context not initialized",
    "Security protocol not supported",
    "Could not set service name",
    "Service type not set",
    "Could not lookup security protocol",
    "Csec incompatability",
    "Unexpected response from peer",
)


def serrno_text(code: int) -> str:
    """``sstrerror``: the message liblfc prints for ``code``.

    ``errno`` values get the C library's text (``os.strerror``), Castor and
    Csec values the tables above, ``ENSNACT`` (the one name-server code a
    client meets) its own; anything else is
    ``"Unknown error <code>"`` rather than an exception, because the text
    only decorates a :class:`~.client.CnsError` whose code is what matters.
    """
    if code < SEBASEOFF:
        return os.strerror(code)
    for base, table in ((SEBASEOFF, _SERRLIST), (2700, _SECERRLIST)):
        if 0 < code - base <= len(table):
            return table[code - base - 1]
    if code == ENSNACT:
        return "Name server not active"
    return f"Unknown error {code}"


#: serrno values with an ``errno`` of their own.
#:
#: gfal2's ``gfal_lfc_get_errno`` maps ``ESEC_BAD_CREDENTIALS`` to ``EPERM``
#: and everything else above 1000 to ``ECOMM``; the few below say more and
#: follow the project's rules (a refused connection is ``ECONNREFUSED``).
_ERRNO = {
    ESEC_BAD_CREDENTIALS: errno.EPERM,
    SENAMETOOLONG: errno.ENAMETOOLONG,
    SETIMEDOUT: errno.ETIMEDOUT,
    SELOOP: errno.ELOOP,
    ENSNACT: errno.ECONNREFUSED,
    SENOSHOST: errno.EHOSTUNREACH,
    SEOPNOTSUP: errno.EOPNOTSUPP,
}


def errno_for(code: int) -> int:
    """The ``errno`` gfal2 reports for a serrno ``code``.

    An ``errno`` passes through; a serrno in :data:`_ERRNO` gets its
    mapping; every other serrno - including a status of ``0`` or a negative
    one, which a broken server could send - is ``ECOMM``, gfal2's catch-all
    for "the catalogue failed".
    """
    if code in _ERRNO:
        return _ERRNO[code]
    return code if 0 < code < SEBASEOFF else ECOMM


class WireError(GError):
    """A reply that does not parse: truncated, unterminated, oversized.

    Always ``EPROTO``: the stream can no longer be trusted, and the caller
    (:class:`~.client.Connection`) closes the connection rather than try to
    resynchronise on the next header.
    """

    def __init__(self, message: str) -> None:
        """``message`` names the fault; the prefix says it was the server's."""
        super().__init__(f"Malformed reply from the LFC: {message}", errno.EPROTO)


class Packer:
    """Builds a request body with the ``marshall_*`` macros.

    Each method appends one field and returns the packer, so a body reads
    in wire order: ``Packer().long(uid).long(gid).hyper(0).string(path)``.
    Integers are masked to the field width, as the C macros' casts do, so
    a negative value goes out in two's complement (``-1`` as
    ``0xFFFFFFFF``) instead of raising ``struct.error``. Not thread-safe;
    build one body per packer.
    """

    def __init__(self) -> None:
        """Start an empty body (the caller adds the ``uid``/``gid`` prefix)."""
        #: The body so far; :meth:`bytes` snapshots it.
        self.buffer = bytearray()

    def long(self, value: int) -> Packer:
        """``marshall_LONG``: 4 bytes (uids, gids, modes, counts)."""
        self.buffer += _ULONG.pack(value & 0xFFFFFFFF)
        return self

    def word(self, value: int) -> Packer:
        """``marshall_WORD``: 2 bytes (the umask, flags, a directory entry size)."""
        self.buffer += _WORD.pack(value & 0xFFFF)
        return self

    def byte(self, value: int | str) -> Packer:
        """``marshall_BYTE``: one byte; a one-character ``str`` is its code point.

        The ``str`` form is for the C ``char`` fields (a replica's status
        ``'-'`` and file type ``'P'``); it must be a single character below
        256, or :func:`ord`/the bytearray raises.
        """
        self.buffer.append(ord(value) if isinstance(value, str) else value & 0xFF)
        return self

    def hyper(self, value: int) -> Packer:
        """``marshall_HYPER``: 8 bytes (file ids, sizes, the ``cwd`` of ``0``)."""
        self.buffer += _HYPER.pack(value & 0xFFFFFFFFFFFFFFFF)
        return self

    def string(self, value: str) -> Packer:
        """``marshall_STRING``: UTF-8 and a NUL; ``EINVAL`` for an embedded NUL.

        ``surrogateescape`` lets a name that came off the wire as non-UTF-8
        bytes go back byte for byte. A NUL inside the value would end the
        string early on the server and shift every field after it, so it
        is refused here rather than sent. Lengths are the server's to
        check (it answers ``ENAMETOOLONG``/``EINVAL``).
        """
        data = value.encode("utf-8", "surrogateescape")
        if b"\0" in data:
            raise GError("A name sent to the LFC may not contain NUL", errno.EINVAL)
        self.buffer += data + b"\0"
        return self

    def raw(self, data: bytes) -> Packer:
        """Append already-marshalled bytes (a nested structure built by another packer)."""
        self.buffer += data
        return self

    def bytes(self) -> bytes:
        """The body so far, as an immutable copy."""
        return bytes(self.buffer)


def request(magic: int, kind: int, body: bytes = b"") -> bytes:
    """Header and body: ``msglen`` counts the header too, as ``send2nsd`` expects.

    The server rejects a length over :data:`MAXREQUEST`, and takes a
    request with no body at all (length 12) for a short read - which is
    how ``CLOSEDIR`` ends a listing (see :meth:`.client.Server.listdir`).
    """
    return HEADER.pack(magic, kind, HEADER.size + len(body)) + body


class Unpacker:
    """Reads a reply with the ``unmarshall_N*`` macros, bounds-checked.

    Fields are read in order from :attr:`pos`; reading past the end raises
    :class:`WireError` (``EPROTO``) naming the field type instead of
    returning garbage, which is what liblfc's unchecked macros would do.
    The test server parses requests with this same class, so both ends
    are equally strict.
    """

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        """Read ``data`` from the start; it is copied, so the caller may reuse it."""
        self.data = bytes(data)
        #: Offset of the next unread byte.
        self.pos = 0

    def _take(self, size: int, what: str) -> bytes:
        """The next ``size`` bytes, or ``WireError("truncated <what>")``."""
        end = self.pos + size
        if end > len(self.data):
            raise WireError(f"truncated {what}")
        chunk = self.data[self.pos : end]
        self.pos = end
        return chunk

    def long(self) -> int:
        """A signed ``LONG`` (``nlink``, statuses, counts that may be ``-1``)."""
        return int(_LONG.unpack(self._take(4, "LONG"))[0])

    def ulong(self) -> int:
        """An unsigned ``LONG`` (uids and gids, which are ``uid_t``/``gid_t``)."""
        return int(_ULONG.unpack(self._take(4, "LONG"))[0])

    def word(self) -> int:
        """A ``WORD``, unsigned (``mode``, ``fileclass``, batch counts)."""
        return int(_WORD.unpack(self._take(2, "WORD"))[0])

    def byte(self) -> int:
        """A ``BYTE`` as an int."""
        return self._take(1, "BYTE")[0]

    def char(self) -> str:
        """A ``BYTE`` holding a C ``char`` (a status letter), as a 1-char ``str``."""
        return chr(self.byte())

    def hyper(self) -> int:
        """An unsigned ``HYPER`` (file ids and sizes are ``u_signed64``)."""
        return int(_HYPER.unpack(self._take(8, "HYPER"))[0])

    def time(self) -> int:
        """A ``TIME_T``: a ``HYPER`` read as signed, since ``time_t`` is."""
        return int(_SHYPER.unpack(self._take(8, "TIME_T"))[0])

    def string(self, limit: int = 0) -> str:
        """``unmarshall_STRINGN``: up to the next NUL, which is consumed.

        ``limit`` (the C buffer's size less one, e.g. ``MAXGUIDLEN``) bounds
        the text: a longer string is ``WireError``, where liblfc would
        silently truncate it into its fixed buffer. ``0`` means unbounded,
        for fields the reply's own length already bounds. Bytes that are
        not UTF-8 survive as surrogates (see :meth:`Packer.string`).
        """
        end = self.data.find(b"\0", self.pos)
        if end < 0:
            raise WireError("unterminated string")
        if limit and end - self.pos > limit:
            raise WireError("string too long")
        text = self.data[self.pos : end].decode("utf-8", "surrogateescape")
        self.pos = end + 1
        return text

    @property
    def remaining(self) -> int:
        """Bytes not yet read."""
        return len(self.data) - self.pos

    def at_end(self) -> bool:
        """Whether every byte has been read: how list payloads are walked."""
        return self.pos >= len(self.data)
