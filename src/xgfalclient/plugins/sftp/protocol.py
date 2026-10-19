"""SFTP version 3 on the wire: packet types, attributes, status codes.

``draft-ietf-secsh-filexfer-02`` is the version every server speaks -
OpenSSH's ``sftp-server`` has never gone past it - and the extensions worth
having are OpenSSH's, announced in the server's ``SSH_FXP_VERSION``:
``posix-rename@openssh.com``, ``statvfs@openssh.com``, ``fsync@openssh.com``,
``hardlink@openssh.com``, ``limits@openssh.com`` and, on servers that have
it (ProFTPD, some appliances), ``check-file-name`` for server-side hashes.

This module is pure encoding; :mod:`.client` does the talking. Every SFTP
packet (draft-02 §3) is ``uint32 length || byte type || uint32 request-id ||
...`` (``INIT``/``VERSION`` carry a version instead of an id), with the
:rfc:`4251` §5 data types - ``uint32``, ``uint64``, ``string`` - that
:mod:`..crypto.sshkeys` encodes for the SSH layer as well. Names drop the
spec's ``SSH_FXP_``/``SSH_FX_``/``SSH_FILEXFER_`` prefixes; the in-tree
test server (:mod:`xgfalclient.testing._sftp`) uses the same constants, so a
wrong value here would not be caught by the in-process tests - only by the
interop tests against OpenSSH.
"""

from __future__ import annotations

import errno
import stat as _stat
import struct
from dataclasses import dataclass, field

from ...crypto.sshkeys import Reader, string, uint32
from ...types import Stat

__all__ = [
    "STATUS_NAMES",
    "VERSION",
    "Attrs",
    "StatusError",
    "errno_for_status",
]

#: The protocol version we send in ``INIT``; a server answering lower is refused.
VERSION = 3

# Packet types (draft-02 §3), ``SSH_FXP_*``. Requests are 1-20 and 200,
# responses 101-105 and 201. ``VERSION_`` has a trailing underscore only to
# keep it apart from the protocol number above.
INIT = 1
VERSION_ = 2
OPEN = 3
CLOSE = 4
READ = 5
WRITE = 6
LSTAT = 7
FSTAT = 8
SETSTAT = 9
FSETSTAT = 10
OPENDIR = 11
READDIR = 12
REMOVE = 13
MKDIR = 14
RMDIR = 15
REALPATH = 16
STAT = 17
RENAME = 18
READLINK = 19
SYMLINK = 20
# Responses, each after its uint32 request id (draft-02 §7):
#   STATUS  uint32 code, string message, string language tag
#   HANDLE  string handle (opaque, at most 256 bytes)
#   DATA    string data (may be shorter than asked; EOF comes as a STATUS)
#   NAME    uint32 count, then count x (string filename, string longname, ATTRS)
#   ATTRS   ATTRS
# EXTENDED carries a string request name (``statvfs@openssh.com`` ...) and
# request-specific fields; its success answer is EXTENDED_REPLY or STATUS.
STATUS = 101
HANDLE = 102
DATA = 103
NAME = 104
ATTRS = 105
EXTENDED = 200
EXTENDED_REPLY = 201

# SSH_FXP_OPEN ``pflags`` (draft-02 §6.3), the POSIX ``open(2)`` flags by
# another name: CREAT/TRUNC/EXCL are O_CREAT/O_TRUNC/O_EXCL, and APPEND forces
# every write to the end of file regardless of its offset.
FXF_READ = 0x01
FXF_WRITE = 0x02
FXF_APPEND = 0x04
FXF_CREAT = 0x08
FXF_TRUNC = 0x10
FXF_EXCL = 0x20

# ATTRS ``flags`` bits (draft-02 §5): which optional fields follow, in this
# order. UIDGID and ACMODTIME each cover a pair of fields.
ATTR_SIZE = 0x01
ATTR_UIDGID = 0x02
ATTR_PERMISSIONS = 0x04
ATTR_ACMODTIME = 0x08
ATTR_EXTENDED = 0x80000000

# Status codes (draft-02 §7, ``SSH_FX_*``). 0-8 are version 3; the rest are
# later drafts' (versions 4-6), which some servers send regardless of the
# negotiated version, so they are named and mapped too.
FX_OK = 0
FX_EOF = 1
FX_NO_SUCH_FILE = 2
FX_PERMISSION_DENIED = 3
FX_FAILURE = 4
FX_BAD_MESSAGE = 5
FX_NO_CONNECTION = 6
FX_CONNECTION_LOST = 7
FX_OP_UNSUPPORTED = 8

#: Status code -> spec name, the message when the server sent none.
STATUS_NAMES = {
    0: "OK",
    1: "EOF",
    2: "NO_SUCH_FILE",
    3: "PERMISSION_DENIED",
    4: "FAILURE",
    5: "BAD_MESSAGE",
    6: "NO_CONNECTION",
    7: "CONNECTION_LOST",
    8: "OP_UNSUPPORTED",
    9: "INVALID_HANDLE",
    10: "NO_SUCH_PATH",
    11: "FILE_ALREADY_EXISTS",
    12: "WRITE_PROTECT",
    13: "NO_MEDIA",
    14: "NO_SPACE_ON_FILESYSTEM",
    15: "QUOTA_EXCEEDED",
    16: "UNKNOWN_PRINCIPAL",
    17: "LOCK_CONFLICT",
    18: "DIR_NOT_EMPTY",
    19: "NOT_A_DIRECTORY",
    20: "INVALID_FILENAME",
    21: "LINK_LOOP",
    22: "CANNOT_DELETE",
    23: "INVALID_PARAMETER",
    24: "FILE_IS_A_DIRECTORY",
    25: "BYTE_RANGE_LOCK_CONFLICT",
    26: "BYTE_RANGE_LOCK_REFUSED",
    27: "DELETE_PENDING",
    28: "FILE_CORRUPT",
    29: "OWNER_INVALID",
    30: "GROUP_INVALID",
    31: "NO_MATCHING_BYTE_RANGE_LOCK",
}

# Status code -> errno, the closest POSIX meaning. FX_EOF maps to EIO
# because the client handles a real end of file itself (reads, READDIR) and
# only an EOF where none belongs reaches the errno; FX_FAILURE is v3's
# catch-all, so the plugin refines it by looking at the path afterwards
# (EEXIST for mkdir, ENOTEMPTY for rmdir, EISDIR for unlink), as gfal2 does.
_STATUS_ERRNO = {
    FX_EOF: errno.EIO,
    FX_NO_SUCH_FILE: errno.ENOENT,
    FX_PERMISSION_DENIED: errno.EACCES,
    FX_FAILURE: errno.EIO,
    FX_BAD_MESSAGE: errno.EINVAL,
    FX_NO_CONNECTION: errno.ENOTCONN,
    FX_CONNECTION_LOST: errno.ECONNRESET,
    FX_OP_UNSUPPORTED: errno.ENOSYS,
    9: errno.EBADF,
    10: errno.ENOENT,
    11: errno.EEXIST,
    12: errno.EROFS,
    13: errno.ENODEV,
    14: errno.ENOSPC,
    15: errno.EDQUOT,
    16: errno.EINVAL,
    17: errno.EBUSY,
    18: errno.ENOTEMPTY,
    19: errno.ENOTDIR,
    20: errno.EINVAL,
    21: errno.ELOOP,
    22: errno.EPERM,
    23: errno.EINVAL,
    24: errno.EISDIR,
    25: errno.EBUSY,
    26: errno.EACCES,
    27: errno.EBUSY,
    28: errno.EIO,
    29: errno.EINVAL,
    30: errno.EINVAL,
    31: errno.ENOLCK,
}


def errno_for_status(code: int) -> int:
    """The ``errno`` an SFTP status stands for; ``EIO`` for anything unknown.

    ``FX_OK`` is not in the table and so is ``EIO`` too: callers only ask
    for a status that is an error. The plugin may still replace the result
    where v3's codes are too coarse (see the table's comment).
    """
    return _STATUS_ERRNO.get(code, errno.EIO)


class StatusError(Exception):
    """An ``SSH_FXP_STATUS`` that was not ``OK``; the plugin turns it into a ``GError``.

    Raised by :class:`~.client.SFTPClient` and caught by the plugin, which
    may patch the errno with context the status lacks. It is a plain
    exception rather than a ``GError`` so code can tell a server's answer
    (the connection is fine) from a transport failure (it is not).
    """

    def __init__(self, code: int, message: str = "") -> None:
        """``message`` is the status's error text; the code's name if it was empty."""
        super().__init__(code, message)
        self.code = code
        self.message = message or STATUS_NAMES.get(code, f"status {code}")

    @property
    def errno(self) -> int:
        """The POSIX errno for :attr:`code` (see :func:`errno_for_status`)."""
        return errno_for_status(self.code)

    def __str__(self) -> str:
        """The server's message alone, ready to follow ``"<op> <path>: "``."""
        return self.message


@dataclass(slots=True)
class Attrs:
    """``ATTRS``: every field optional, as the ``flags`` word says.

    Wire layout (draft-02 §5): ``uint32 flags``, then only the fields whose
    bit is set - ``uint64 size``, ``uint32 uid, gid``, ``uint32
    permissions``, ``uint32 atime, mtime`` - then, with ``ATTR_EXTENDED``,
    ``uint32 count`` and that many ``string type, string data`` pairs.
    ``None`` means "absent": in a SETSTAT it leaves the field unchanged.
    ``permissions`` is the full ``st_mode``, file-type bits included, as
    OpenSSH sends it; v3 times are whole seconds since the epoch.
    """

    size: int | None = None
    uid: int | None = None
    gid: int | None = None
    permissions: int | None = None
    atime: int | None = None
    mtime: int | None = None
    extended: list[tuple[bytes, bytes]] = field(default_factory=list)

    def encode(self) -> bytes:
        """The wire form, flags first.

        uid and gid are sent only as a pair, likewise atime and mtime, since
        one flag covers both; setting just one of a pair sends neither.
        Times are masked to 32 bits so a pre-1970 or post-2106 value wraps
        instead of raising from :mod:`struct`.
        """
        flags = 0
        body = b""
        if self.size is not None:
            flags |= ATTR_SIZE
            body += struct.pack(">Q", self.size)
        if self.uid is not None and self.gid is not None:
            flags |= ATTR_UIDGID
            body += struct.pack(">II", self.uid, self.gid)
        if self.permissions is not None:
            flags |= ATTR_PERMISSIONS
            body += uint32(self.permissions)
        if self.atime is not None and self.mtime is not None:
            flags |= ATTR_ACMODTIME
            body += struct.pack(">II", self.atime & 0xFFFFFFFF, self.mtime & 0xFFFFFFFF)
        if self.extended:
            flags |= ATTR_EXTENDED
            body += uint32(len(self.extended))
            body += b"".join(string(k) + string(v) for k, v in self.extended)
        return uint32(flags) + body

    @classmethod
    def decode(cls, reader: Reader) -> Attrs:
        """Read one ``ATTRS`` at ``reader``'s position, consuming exactly its bytes.

        Unknown flag bits are ignored: v3 defines no other field, and a
        server that set one would be using a layout we never negotiated.
        A short packet raises ``KeyError_`` from the :class:`Reader`.
        """
        flags = reader.uint32()
        attrs = cls()
        if flags & ATTR_SIZE:
            attrs.size = reader.uint64()
        if flags & ATTR_UIDGID:
            attrs.uid = reader.uint32()
            attrs.gid = reader.uint32()
        if flags & ATTR_PERMISSIONS:
            attrs.permissions = reader.uint32()
        if flags & ATTR_ACMODTIME:
            attrs.atime = reader.uint32()
            attrs.mtime = reader.uint32()
        if flags & ATTR_EXTENDED:
            for _ in range(reader.uint32()):
                attrs.extended.append((reader.string(), reader.string()))
        return attrs

    def to_stat(self) -> Stat:
        """gfal2's ``struct stat`` from an ``ATTRS``: no inode, nlink or ctime in v3.

        gfal2's sftp plugin leaves ``st_nlink``, ``st_ino`` and ``st_ctime``
        at zero, since SFTP v3 does not carry them; so does this.
        """
        return Stat(
            st_mode=self.permissions or 0,
            st_uid=self.uid or 0,
            st_gid=self.gid or 0,
            st_size=self.size or 0,
            st_atime=self.atime or 0,
            st_mtime=self.mtime or 0,
        )

    @property
    def is_dir(self) -> bool:
        """A directory; false when the server sent no permissions."""
        return self.permissions is not None and _stat.S_ISDIR(self.permissions)

    @property
    def is_link(self) -> bool:
        """A symbolic link (only an ``LSTAT`` or ``READDIR`` can say so)."""
        return self.permissions is not None and _stat.S_ISLNK(self.permissions)
