"""SFTP version 3 on the wire: packet types, attributes, status codes.

``draft-ietf-secsh-filexfer-02`` is the version every server speaks -
OpenSSH's ``sftp-server`` has never gone past it - and the extensions worth
having are OpenSSH's, announced in the server's ``SSH_FXP_VERSION``:
``posix-rename@openssh.com``, ``statvfs@openssh.com``, ``fsync@openssh.com``,
``hardlink@openssh.com``, ``limits@openssh.com`` and, on servers that have
it (ProFTPD, some appliances), ``check-file-name`` for server-side hashes.

This module is pure encoding; :mod:`.client` does the talking.
"""

from __future__ import annotations

import errno
import stat as _stat
import struct
from dataclasses import dataclass, field

from ..._compat import SLOTS
from ...crypto.sshkeys import Reader, string, uint32
from ...types import Stat

__all__ = [
    "VERSION",
    "Attrs",
    "StatusError",
    "errno_for_status",
    "STATUS_NAMES",
]

VERSION = 3

# Packet types.
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
STATUS = 101
HANDLE = 102
DATA = 103
NAME = 104
ATTRS = 105
EXTENDED = 200
EXTENDED_REPLY = 201

# SSH_FXP_OPEN flags.
FXF_READ = 0x01
FXF_WRITE = 0x02
FXF_APPEND = 0x04
FXF_CREAT = 0x08
FXF_TRUNC = 0x10
FXF_EXCL = 0x20

# Attribute flags.
ATTR_SIZE = 0x01
ATTR_UIDGID = 0x02
ATTR_PERMISSIONS = 0x04
ATTR_ACMODTIME = 0x08
ATTR_EXTENDED = 0x80000000

# Status codes. 0-8 are version 3; the rest are later drafts', which some
# servers send regardless of the negotiated version.
FX_OK = 0
FX_EOF = 1
FX_NO_SUCH_FILE = 2
FX_PERMISSION_DENIED = 3
FX_FAILURE = 4
FX_BAD_MESSAGE = 5
FX_NO_CONNECTION = 6
FX_CONNECTION_LOST = 7
FX_OP_UNSUPPORTED = 8

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
    """The ``errno`` an SFTP status stands for; ``EIO`` for anything unknown."""
    return _STATUS_ERRNO.get(code, errno.EIO)


class StatusError(Exception):
    """An ``SSH_FXP_STATUS`` that was not ``OK``; the plugin turns it into a ``GError``."""

    def __init__(self, code: int, message: str = "") -> None:
        super().__init__(code, message)
        self.code = code
        self.message = message or STATUS_NAMES.get(code, f"status {code}")

    @property
    def errno(self) -> int:
        return errno_for_status(self.code)

    def __str__(self) -> str:
        return self.message


@dataclass(**SLOTS)
class Attrs:
    """``ATTRS``: every field optional, as the ``flags`` word says."""

    size: int | None = None
    uid: int | None = None
    gid: int | None = None
    permissions: int | None = None
    atime: int | None = None
    mtime: int | None = None
    extended: list[tuple[bytes, bytes]] = field(default_factory=list)

    def encode(self) -> bytes:
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
        return self.permissions is not None and _stat.S_ISDIR(self.permissions)

    @property
    def is_link(self) -> bool:
        return self.permissions is not None and _stat.S_ISLNK(self.permissions)
