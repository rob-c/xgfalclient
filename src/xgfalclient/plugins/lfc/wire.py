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
    "Packer",
    "Unpacker",
    "WireError",
    "serrno_text",
    "errno_for",
    "request",
    "HEADER",
]

# -- magics (h/Cns.h) ------------------------------------------------------------
MAGIC = 0x030E1301
MAGIC2 = 0x030E1302
MAGIC3 = 0x030E1303
MAGIC4 = 0x030E1304

#: Default port, ``CNS_PORT`` in ``h/Cns_constants.h``.
PORT = 5010

# -- request types (h/Cns.h) -------------------------------------------------------
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
REQBUFSZ = 2854
REPBUFSZ = 4100
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

HEADER = struct.Struct(">iii")
_LONG = struct.Struct(">i")
_ULONG = struct.Struct(">I")
_WORD = struct.Struct(">H")
_HYPER = struct.Struct(">Q")
_SHYPER = struct.Struct(">q")

# -- serrno (h/serrno.h) -------------------------------------------------------------
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

#: ``sys_secerrlist``, from ``ESECBASEOFF + 1``.
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
    """``sstrerror``: the message liblfc prints for ``code``."""
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
    """The ``errno`` gfal2 reports for a serrno ``code``."""
    if code in _ERRNO:
        return _ERRNO[code]
    return code if 0 < code < SEBASEOFF else ECOMM


class WireError(GError):
    """A reply that does not parse: truncated, unterminated, oversized."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Malformed reply from the LFC: {message}", errno.EPROTO)


class Packer:
    """Builds a request body with the ``marshall_*`` macros."""

    def __init__(self) -> None:
        self.buffer = bytearray()

    def long(self, value: int) -> Packer:
        self.buffer += _ULONG.pack(value & 0xFFFFFFFF)
        return self

    def word(self, value: int) -> Packer:
        self.buffer += _WORD.pack(value & 0xFFFF)
        return self

    def byte(self, value: int | str) -> Packer:
        self.buffer.append(ord(value) if isinstance(value, str) else value & 0xFF)
        return self

    def hyper(self, value: int) -> Packer:
        self.buffer += _HYPER.pack(value & 0xFFFFFFFFFFFFFFFF)
        return self

    def string(self, value: str) -> Packer:
        data = value.encode("utf-8", "surrogateescape")
        if b"\0" in data:
            raise GError("A name sent to the LFC may not contain NUL", errno.EINVAL)
        self.buffer += data + b"\0"
        return self

    def raw(self, data: bytes) -> Packer:
        self.buffer += data
        return self

    def bytes(self) -> bytes:
        return bytes(self.buffer)


def request(magic: int, kind: int, body: bytes = b"") -> bytes:
    """Header and body: ``msglen`` counts the header too, as ``send2nsd`` expects."""
    return HEADER.pack(magic, kind, HEADER.size + len(body)) + body


class Unpacker:
    """Reads a reply with the ``unmarshall_N*`` macros, bounds-checked."""

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self.data = bytes(data)
        self.pos = 0

    def _take(self, size: int, what: str) -> bytes:
        end = self.pos + size
        if end > len(self.data):
            raise WireError(f"truncated {what}")
        chunk = self.data[self.pos : end]
        self.pos = end
        return chunk

    def long(self) -> int:
        return int(_LONG.unpack(self._take(4, "LONG"))[0])

    def ulong(self) -> int:
        return int(_ULONG.unpack(self._take(4, "LONG"))[0])

    def word(self) -> int:
        return int(_WORD.unpack(self._take(2, "WORD"))[0])

    def byte(self) -> int:
        return self._take(1, "BYTE")[0]

    def char(self) -> str:
        return chr(self.byte())

    def hyper(self) -> int:
        return int(_HYPER.unpack(self._take(8, "HYPER"))[0])

    def time(self) -> int:
        return int(_SHYPER.unpack(self._take(8, "TIME_T"))[0])

    def string(self, limit: int = 0) -> str:
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
        return len(self.data) - self.pos

    def at_end(self) -> bool:
        return self.pos >= len(self.data)
