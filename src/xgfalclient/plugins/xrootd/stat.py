"""A server's metadata answers as ``XrdPosix`` and gfal2 present them.

Stat: ``st_mode`` from the XRootD flags as ``XrdPosixMap::Flags2Mode``
builds it - owner bits only - with the caller's uid and gid and ``nlink``
1. Listings: one ``kXR_dirlist`` with ``kXR_dstat``, its entries reduced to
the stat gfal2's ``readdirpp`` fills in, and stat'ed one by one when the
server ignored the flag. Then the smaller answers: ``user.status``, the
space token's JSON, and a ``kXR_Qcksum`` answer checked for its type.

Listing a long directory is where the time goes, so :func:`parse_listing`
reads only the three fields an entry shows instead of building a full
:class:`~xrdclient.StatInfo` per entry, which is what xrdclient's own
``scandir`` does.

Everything here works on an already checked-out
:class:`xrdclient.FileSystem` (the plugin owns it, see
:meth:`~.plugin.XRootDPlugin._fs`) and words failures through
:mod:`.errors`; nothing keeps state between calls.
"""

from __future__ import annotations

import errno
import os
import stat as _stat
import time
from typing import TYPE_CHECKING

from xrdclient import errors as xe

from ...errors import GError
from ...types import Stat
from .errors import describe, status_error

if TYPE_CHECKING:
    from xrdclient import FileSystem, StatInfo

#: ``kXR_*`` stat flags, as ``XrdCl::StatInfo`` numbers them: ``kXR_xset``
#: (executable or searchable), ``kXR_isDir``, ``kXR_other`` (neither file nor
#: directory), ``kXR_offline`` (on tape only, must be staged), ``kXR_readable``
#: and ``kXR_writable`` (for *this* client, not mode bits), ``kXR_poscpend``
#: (a persist-on-successful-close file still being written) and
#: ``kXR_bkpexist`` (a tape copy exists).
X_SET, IS_DIR, OTHER, OFFLINE = 0x01, 0x02, 0x04, 0x08
READABLE, WRITABLE, POSC_PENDING, BACKUP = 0x10, 0x20, 0x40, 0x80

#: What a listing entry's stat is reduced to: flags, size and mtime, in that
#: order (not the wire order, which is ``id size flags mtime``).
Brief = tuple[int, int, int]
#: A stat the server sent and nobody asked to read.
_UNREAD: Brief = (0, 0, 0)


# -- stat ------------------------------------------------------------------------------


def _ids() -> tuple[int, int]:
    """The caller's uid and gid, which ``XrdPosix`` puts in every stat.

    XRootD's ``kXR_stat`` names no owner a client could map, so the file is
    reported as the caller's - which keeps ``ls``-style tools from showing
    every remote file as root's. ``0`` where the platform has no uid.
    """
    uid = getattr(os, "getuid", None)
    gid = getattr(os, "getgid", None)
    return (uid() if uid else 0), (gid() if gid else 0)


def flags_to_mode(flags: int) -> int:
    """``XrdPosixMap::Flags2Mode``: owner permission bits and the file type."""
    mode = 0
    if flags & X_SET:
        mode |= _stat.S_IXUSR
    if flags & READABLE:
        mode |= _stat.S_IRUSR
    if flags & WRITABLE:
        mode |= _stat.S_IWUSR
    if flags & OTHER:
        mode |= _stat.S_IFBLK
    elif flags & IS_DIR:
        mode |= _stat.S_IFDIR
    else:
        mode |= _stat.S_IFREG
    if flags & POSC_PENDING:
        mode |= _stat.S_ISUID  # XRDSFS_POSCPEND
    return mode


def _inode(identifier: str) -> int:
    """``strtoll(id, 0, 10)``: the leading decimal digits, else zero.

    The stat ``id`` is the server's opaque file id, often but not always a
    number; ``XrdPosix`` takes whatever number it starts with as the inode
    rather than fail the stat over it.
    """
    digits = ""
    for character in identifier.strip():
        if not character.isdigit():
            break
        digits += character
    return int(digits) if digits else 0


def posix_stat(info: StatInfo) -> Stat:
    """What ``XrdPosixXrootd::Stat`` fills in for one ``kXR_stat`` answer.

    A protocol-5 server sends ctime and atime too; an older one sends only
    the mtime, and ``XrdPosix`` then reports ctime as the mtime and atime as
    now.
    """
    uid, gid = _ids()
    extended = bool(info.mode_str)
    return Stat(
        st_ino=_inode(info.id),
        st_mode=flags_to_mode(int(info.flags)),
        st_nlink=1,
        st_uid=uid,
        st_gid=gid,
        st_size=info.st_size,
        st_mtime=info.st_mtime,
        st_ctime=info.st_ctime if extended else info.st_mtime,
        st_atime=info.st_atime if extended else int(time.time()),
    )


def listing_stat(info: StatInfo) -> Stat:
    """The reduced stat gfal2's ``readdirpp`` fills from a listing entry.

    Size, mtime and ``rwx`` for all three classes from the flags, nothing
    else. gfal2 sets no type bit for a file; ``S_IFREG`` is kept here so the
    entry's ``d_type`` is the ``DT_REG`` gfal2 reports for it.
    """
    return reduced((int(info.flags), info.st_size, info.st_mtime))


def reduced(brief: Brief) -> Stat:
    """:func:`listing_stat` from the three fields a listing entry keeps."""
    flags, size, mtime = brief
    mode = _stat.S_IFDIR if flags & IS_DIR else _stat.S_IFREG
    if flags & READABLE:
        mode |= 0o444
    if flags & WRITABLE:
        mode |= 0o222
    if flags & X_SET:
        mode |= 0o111
    return Stat(st_mode=mode, st_size=size, st_mtime=mtime)


def is_dir(fs: FileSystem, path: str) -> bool:
    """Whether ``path`` is a directory; anything that cannot be stat'ed is not."""
    try:
        return bool(int(fs.stat(path).flags) & IS_DIR)
    except Exception:
        return False


def rmdir_errno(fs: FileSystem, path: str, exc: BaseException) -> int:
    """gfal2's ``errno`` massaging after a failed ``rmdir``, for EOS's sake."""
    code = describe(exc).code
    if code == errno.EEXIST:
        return errno.ENOTEMPTY
    if code == errno.EIO:
        return errno.ENOTEMPTY if is_dir(fs, path) else errno.ENOTDIR
    if code == errno.ENOENT:
        try:
            fs.stat(path)
        except Exception:
            return code
        return errno.ENOTDIR
    return code


# -- listings --------------------------------------------------------------------------


def parse_listing(data: bytes, path: str, *, brief: bool = True) -> list[tuple[str, Brief | None]]:
    """A ``kXR_dirlist`` answer as ``xrdclient``'s ``parse_dirlist`` reads it, only faster.

    With ``kXR_dstat`` the server sends a ``.`` entry and then name and stat
    lines in turn; a server that ignored the flag sends names alone, and
    those entries come back without a stat. The same entries are refused
    (a name that is not one path component, a stat line that is short).
    What is kept of a stat is what a listing entry shows, and only if
    ``brief``; otherwise the line is checked and stands as :data:`_UNREAD`,
    for a caller that wants names. ``xrdclient`` builds a full ``StatInfo``
    per entry, which is most of the time a long listing takes.
    """
    text = data.split(b"\x00", 1)[0].decode("utf-8", "replace")
    lines = [line for line in text.split("\n") if line]
    if lines[:1] != ["."]:
        return [(_entry_name(name, path), None) for name in lines]
    found: list[tuple[str, Brief | None]] = []
    for name, line in zip(lines[::2], lines[1::2], strict=False):
        if name == ".":
            continue
        parts = line.split()
        # A stat line is ``id size flags mtime``, then, from protocol 5,
        # ``ctime atime mode owner group``; only the first four are promised.
        if len(parts) < 4:
            raise xe.ProtocolError(
                f"kXR_stat returned {len(parts)} fields, expected >= 4: {line!r}"
            )
        fields = (int(parts[2]), int(parts[1]), int(parts[3])) if brief else _UNREAD
        found.append((_entry_name(name, path), fields))
    return found


def _entry_name(name: str, path: str) -> str:
    """``name``, refused (``ProtocolError``) if it is not one path component.

    A listing that named ``..`` or ``a/b`` would let the server steer a
    recursive caller (``gfal-copy -r``, ``gfal-rm -r``) outside the
    directory it listed, so such an entry fails the listing instead.
    """
    if "/" in name or name == "..":
        raise xe.ProtocolError(f"kXR_dirlist entry {name!r} in {path!r} is not a name")
    return name


def entries(fs: FileSystem, path: str, *, brief: bool) -> list[tuple[str, Brief]]:
    """Each entry's name and stat. One the server sent none for is stat'ed, as gfal2 does.

    Those stats are made one at a time on the same filesystem, and the
    first that fails fails the listing: gfal2's ``readdirpp`` cannot return
    an entry without its stat.
    """
    found = []
    for name, fields in _listed(fs, path, brief=brief):
        if fields is None:
            try:
                info = fs.stat(f"{path.rstrip('/')}/{name}")
            except Exception as exc:
                raise status_error("Failed reading directory: ", exc, terse=True) from exc
            fields = (int(info.flags), info.st_size, info.st_mtime)
        found.append((name, fields))
    return found


def _listed(fs: FileSystem, path: str, *, brief: bool) -> list[tuple[str, Brief | None]]:
    """A directory's entries, failing as gfal2's stat-then-list fails.

    gfal2 stats first, which is what turns a file into ``ENOTDIR`` rather
    than a listing error. The stat only matters when the listing does not
    already prove a directory, so it is made then and only then - after a
    refused listing, or an empty one - which saves a round trip per listing
    and says exactly what gfal2 says in every case.

    The listing is the server's own bytes (:meth:`xrdclient.FileSystem.dirlist`,
    redirects followed and the filesystem's CGI on the path), parsed here;
    see :func:`parse_listing`.
    """
    refused: Exception | None = None
    found: list[tuple[str, Brief | None]] = []
    try:
        found = parse_listing(fs.dirlist(path, stat=True), path, brief=brief)
    except Exception as exc:
        refused = exc
    if found:
        return found
    info = fs.stat(path)
    if not int(info.flags) & IS_DIR:
        code = errno.ENOTDIR
        raise GError(f"Not a directory ({os.strerror(code)})", code)
    if refused is not None:
        raise status_error("Failed to open dir: ", refused, terse=True) from refused
    return found


# -- smaller answers -------------------------------------------------------------------


def status_word(flags: int) -> str:
    """``user.status``: gfal2's ``StatInfo2Xattr``.

    ``kXR_bkpexist`` says a tape copy exists and ``kXR_offline`` that no disk
    copy does; a file with neither flag on a disk-only server is ``ONLINE``.
    ``UNKNOWN`` is what gfal2 says for an offline file with no tape copy.
    """
    on_tape = bool(flags & BACKUP)
    on_disk = not flags & OFFLINE
    if on_tape and on_disk:
        return "ONLINE_AND_NEARLINE"
    if on_tape:
        return "NEARLINE"
    return "ONLINE" if on_disk else "UNKNOWN"


def space_json(total: int, free: int, used: int, largest: int) -> str:
    """``gfal2_space_generate_json``, byte for byte as json-c prints it."""
    return (
        f'{{ "totalsize": {total}, "unusedsize": {free}, "usedsize": {used}, '
        f'"guaranteedsize": {largest} }}'
    )


def checksum_name(algorithm: str) -> str:
    """gfal2's ``predefined_checksum_type_to_lower``: three names are lowered, others kept.

    Servers register their checksums under lower-case names (``adler32``),
    but an algorithm a site added itself may be case-sensitive, so only the
    three predefined ones are normalised and the rest go as the user wrote.
    """
    lower = algorithm.lower()
    return lower if lower in ("adler32", "crc32", "md5") else algorithm


def checksum_value(answer: bytes, wanted: str) -> str:
    """The value in a ``kXR_Qcksum`` answer (``adler32 1a2b3c4d``), checked for its type."""
    text = answer.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
    kind, space, value = text.partition(" ")
    if not space:
        raise GError("Could not get the checksum (Wrong format)", errno.EIO)
    if kind.lower() != wanted.lower():
        raise GError(f"Got '{kind}' while expecting '{wanted}'", errno.EIO)
    return value.strip()
