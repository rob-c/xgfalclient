"""``root://``, ``roots://``, ``xroot://`` and ``xroots://``, spoken by xrdclient.

gfal2's xrootd plugin is a thin layer over ``libXrdCl`` (and ``XrdPosix``,
which it uses for most of the namespace). This one is the same thin layer
over `xrdclient <https://github.com/rob-c/xrdclient>`_, the same author's
pure-Python XRootD client, which is an optional dependency: without it the
plugin reports itself unavailable and a ``root://`` URL says how to install
it.

Everything a user can observe is gfal2's, read off its source (2.23.5) and
checked against it:

* **Errors.** A server's ``kXR_*`` code becomes an ``errno`` through
  ``XProtocol::toErrno`` exactly as ``XrdPosix`` maps it, and the message is
  worded as that operation words it in gfal2 (``Failed to stat file (No such
  file or directory)``). The client-side failures take ``XrdPosix``'s mapping
  of the corresponding ``XrdCl`` status: a refused connection is
  ``ECONNREFUSED``, an unresolvable host ``EHOSTUNREACH``, a failed login
  ``EAUTH``.
* **Stat.** ``st_mode`` is built from the XRootD flags the way
  ``XrdPosixMap::Flags2Mode`` builds it - owner bits only - with the caller's
  uid and gid and ``nlink`` 1, and a directory listing's entries carry the
  reduced stat gfal2's ``readdirpp`` fills in.
* **Quirks kept.** ``mkdir`` stats first and answers ``EEXIST`` itself (EOS
  says yes to an existing directory), always creates parents, and ``rmdir``
  massages ``errno`` the way gfal2 does. Extended attributes are the four
  gfal2 invents (``xroot.cksum``, ``xroot.space``, ``xroot.xattr``,
  ``spacetoken``) plus ``user.status``; ``setxattr`` is ``ENOSYS``.
* **Copies.** gfal2 hands a copy to XrdCl whole, and so does this plugin
  to itself: the core checks no destination and computes no checksum.
  ``root`` to ``root`` is a third-party copy (``TRANSFER:TYPE`` ``3rd
  pull``); any other pair of XRootD schemes is announced as ``streamed``, as
  gfal2 announces a job XrdCl may run either way; ``root`` to and from
  ``file://`` streams through this process. The events are XrdCl's: the
  prepared URLs on ``TRANSFER:ENTER``, ``Job finished, [SUCCESS]`` or the
  error on ``TRANSFER:EXIT``, ``EVICT`` after it (``-1`` for a local
  source), and gfal2's own ``CLEANUP``. An existing destination is refused
  by whoever holds it (``EEXIST``, nothing cleaned), a pull and an upload
  make the destination's path and a download the local one, whatever
  ``create_parent`` says. Checksums are XrdCl's ``checkSumMode``: no
  ``CHECKSUM`` events, and a mismatch is ``EILSEQ`` (``[ERROR] CheckSum
  error``). A pull is XrdCl's third-party job step by step (see
  :class:`_Rendezvous`): with ``proxy_delegation`` on (gfal2 sets XrdCl's
  ``delegate`` from it for ``root`` to ``root``) the destination's login
  delegates the proxy and its open says ``tpc.dlgon=1``, and a destination
  that advertises ``tpcdlg`` pulls with that proxy ("TPC lite") - no key,
  and a source this client cannot open itself is no obstacle. Otherwise it
  is the classic rendezvous, and a source that cannot be opened is
  "Destination does not support delegation.". A pull that must stop -
  ``cancel()``, the copy's timeout, a callback that raised - sends the
  destination XrdCl's ``ofs.tpc cancel`` on the pull's handle (see
  :class:`_Pull`), waits for its answer and closes the handles: a
  cancelled pull fails with that answer (``ECANCELED``, "destination file
  prematurely closed"), one out of time as XrdCl's expired sync
  (``[ERROR] Operation expired``), and the clean-up then finds nothing
  busy to remove. ``XRD_SUBSTREAMSPERCHANNEL`` above 1 asks the
  destination for that many streams less one (``tpc.str``). A download runs
  on xrdclient's bulk data plane, pipelined over ``nbstreams`` connections
  (two by default) and landed straight in the file, which is where this is
  an order of magnitude faster than gfal2; an upload is one handle, because
  xrootd admits one writer per file, with several writes in flight on it
  and nothing copied on the way.

Where gfal2 is wrong, this is not, and says so where it differs:
``gfal2_xrootd_set_error`` reports whatever the global ``errno`` happens to
hold rather than the code it was given, which is how ``chmod`` of a missing
file comes back as ``EILSEQ``; the code given is used here. A timeout is
``ETIMEDOUT`` (``XrdPosix`` says ``ETIME``, gfal2's own map ``ESTALE``). A
listing entry's mode keeps ``S_IFREG`` so that its ``d_type`` is ``DT_REG``,
which gfal2 reports without the mode to match. A local file's failure in a
copy carries its real ``errno``: gfal2 passes XrdCl's ``kXR_*`` number on
(3018 for an existing file), fails to see ``EEXIST`` in it, and deletes the
local file it has just refused to overwrite; here the file is kept and
nothing is cleaned. The ``CLEANUP`` after a failed download is ``0`` for a
file that was never made, where gfal2 reports 3011. A pull out of time
stops at the copy's deadline with the same cancel a cancelled one sends;
XrdCl lets its sync expire (on a timer that ticks every 15 seconds) and
closes the destination, which the server takes the same way. A classic pull whose
close fails names the end that failed it; XrdCl's ``RunTPC`` names the
other one. A pull's destination login delegates exactly when
``proxy_delegation`` says so, as XrdCl intends when it sets
``XrdSecGSIDELEGPROXY`` for the job; in gfal2 that comes too late, since
XrdSecgsi reads the variable once, at the process's first GSI login (the
source's), so its bindings delegate only when the variable was exported
beforehand, and then even with ``proxy_delegation`` off (``gfal-copy
--no-delegation`` still hands the destination a proxy).

Not done, deliberately: ``[XROOTD PLUGIN] NORMALIZE_PATH=false`` (gfal2
then sends ``root://h/p`` as the relative path ``p``, which a stock server
refuses); ``PARALLEL_COPIES`` (a bulk copy runs one file at a time through
the core); falling back from a pull to a stream for non-``root`` pairs
(XrdCl's ``thirdParty=first``), which gfal2 does not do against a stock
server either; the ``xrd.gsiusrpxy=`` (or ``xrd.gsiusrcrt=``/``gsiusrkey=``)
CGI gfal2 adds to a URL whose X.509 credential came from ``cred_set``: the
credential reaches xrdclient through its configuration instead, so only
the copy events' URLs read differently. XrdCl sets
``XrdSecGSIDELEGPROXY`` process-wide for a pull, so that every later login
in the process follows the last pull's setting; here only the pull's
destination login does, and everything else follows
the environment (``gfal-copy`` exports ``XrdSecGSIDELEGPROXY=1``, as
upstream's does, which xrdclient honours by signing the server's proxy
request at login, as XrdCl does).
"""

from __future__ import annotations

import errno
import importlib
import json
import os
import queue
import socket
import stat as _stat
import struct
import tempfile
import threading
import time
import urllib.parse
import uuid
import weakref
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, NoReturn, TypeVar

from .. import events as ev
from .._compat import TIMEOUTS
from ..checksum import checksums_match
from ..enums import checksum_mode
from ..errors import ECOMM, GError, not_supported_url
from ..plugin import (
    O_ACCMODE_MASK,
    O_CREAT,
    O_EXCL,
    O_TRUNC,
    Plugin,
    PluginFile,
    StagingResult,
)
from ..types import Stat
from ..url import parent, scheme_of

if TYPE_CHECKING:
    from xrdclient import Config, FileSystem, StatInfo, XRootDURL
    from xrdclient.client.file import File

    from ..creds import X509Credential
    from ..transfer import Transfer

__all__ = ["XRootDPlugin", "XRootDFile", "MISSING_HINT", "KXR_ERRNO", "SCHEMES"]

T = TypeVar("T")

#: What ``root://`` says when xrdclient cannot be imported.
MISSING_HINT = "root:// needs xrdclient: pip install 'xgfalclient[xrootd]'"

SCHEMES = ("root", "roots", "xroot", "xroots")

#: gfal2's event domain for this plugin (``g_quark_from_static_string("xroot")``).
DOMAIN = "xroot"
TYPE_PULL = "3rd pull"
TYPE_STREAMED = "streamed"
EVICT = "EVICT"


def _errno(name: str, fallback: int) -> int:
    """An ``errno`` constant this platform may not have, as XProtocol.hh falls back."""
    return int(getattr(errno, name, fallback))


EAUTH = _errno("EAUTH", _errno("EBADE", errno.EACCES))
EBADRQC = _errno("EBADRQC", _errno("EBADRPC", errno.EINVAL))
ENOATTR = _errno("ENOATTR", errno.ENODATA)
ETIME = _errno("ETIME", errno.ETIMEDOUT)

#: ``XProtocol::toErrno`` from XRootD 5.9: a ``kXR_*`` error code as ``errno``.
#: Anything else is ``ENOMSG``. ``kXR_ReqTimedOut`` is the one ``ETIMEDOUT``.
KXR_ERRNO: dict[int, int] = {
    3000: errno.EINVAL,  # kXR_ArgInvalid
    3001: errno.EINVAL,  # kXR_ArgMissing
    3002: errno.ENAMETOOLONG,  # kXR_ArgTooLong
    3003: errno.EDEADLK,  # kXR_FileLocked
    3004: errno.EBADF,  # kXR_FileNotOpen
    3005: errno.ENODEV,  # kXR_FSError
    3006: EBADRQC,  # kXR_InvalidRequest
    3007: errno.EIO,  # kXR_IOError
    3008: errno.ENOMEM,  # kXR_NoMemory
    3009: errno.ENOSPC,  # kXR_NoSpace
    3010: errno.EACCES,  # kXR_NotAuthorized
    3011: errno.ENOENT,  # kXR_NotFound
    3012: errno.EFAULT,  # kXR_ServerError
    3013: errno.ENOTSUP,  # kXR_Unsupported
    3014: errno.EHOSTUNREACH,  # kXR_noserver
    3015: errno.ENOTBLK,  # kXR_NotFile
    3016: errno.EISDIR,  # kXR_isDirectory
    3017: errno.ECANCELED,  # kXR_Cancelled
    3018: errno.EEXIST,  # kXR_ItExists
    3019: errno.EDOM,  # kXR_ChkSumErr
    3020: errno.EINPROGRESS,  # kXR_inProgress
    3021: errno.EDQUOT,  # kXR_overQuota
    3022: errno.EILSEQ,  # kXR_SigVerErr
    3023: errno.ERANGE,  # kXR_DecryptErr
    3024: errno.EUSERS,  # kXR_Overloaded
    3025: errno.EROFS,  # kXR_fsReadOnly
    3026: errno.EINVAL,  # kXR_BadPayload
    3027: ENOATTR,  # kXR_AttrNotFound
    3028: errno.EPROTOTYPE,  # kXR_TLSRequired
    3029: errno.EADDRNOTAVAIL,  # kXR_noReplicas
    3030: EAUTH,  # kXR_AuthFailed
    3031: errno.EIDRM,  # kXR_Impossible
    3032: errno.ENOTTY,  # kXR_Conflict
    3033: errno.ETOOMANYREFS,  # kXR_TooManyErrs
    3034: errno.ETIMEDOUT,  # kXR_ReqTimedOut
    3035: ETIME,  # kXR_TimerExpired
}

#: What a vendor opcode sounds like on a server that does not have it.
_NO_SUCH_REQUEST = (3006, 3013)

#: gfal2 masks these as ``ECOMM`` when a staging poll fails, so that a
#: network hiccup reads as "try again" rather than as the file's fault.
_NETWORK_ERRNOS = frozenset(
    {
        errno.EHOSTUNREACH,
        errno.ENOTSOCK,
        errno.ETIMEDOUT,
        errno.ENOTCONN,
        errno.ECONNRESET,
        errno.ECONNREFUSED,
        errno.ENETRESET,
        errno.ECONNABORTED,
    }
)

#: The attribute names gfal2's ``listxattr`` makes up, in its order.
XATTRS = ["xroot.cksum", "xroot.space", "xroot.xattr", "spacetoken"]
#: gfal2 ``xroot.*`` attribute to ``kXR_query`` code (``XrdPosixXrootd::Getxattr``).
_XATTR_QUERY = {"xroot.cksum": 3, "xroot.space": 5, "xroot.xattr": 4}

#: ``kXR_*`` stat flags, as ``XrdCl::StatInfo`` numbers them.
_X_SET, _IS_DIR, _OTHER, _OFFLINE = 0x01, 0x02, 0x04, 0x08
_READABLE, _WRITABLE, _POSC_PENDING, _BACKUP = 0x10, 0x20, 0x40, 0x80

#: ``kXR_open`` options, spelled out so an open is one integer.
_READ, _UPDATE, _NEW, _DELETE, _MKPATH = 0x0010, 0x0020, 0x0008, 0x0002, 0x0100
_POSC = 0x1000

#: How often a third-party copy's waiter wakes to check the clock, and how
#: often it asks the destination how far the pull has got, in seconds.
TPC_POLL = 0.05
TPC_PROGRESS = 1.0
#: How long a stopped pull waits for the destination to answer its cancel.
TPC_CANCEL_WAIT = 60.0
#: What XrdCl's ``Fcntl`` sends a pull's destination to stop it: the string
#: with its NUL, which ``XrdOfsFile::fctl`` insists on.
TPC_CANCEL = b"ofs.tpc cancel\x00"


#: How many idle :class:`~xrdclient.FileSystem` objects to keep per endpoint and
#: identity, and for how many endpoints; see :meth:`XRootDPlugin._fs`.
IDLE_PER_ENDPOINT = 4
IDLE_ENDPOINTS = 32
#: How many parsed URLs to remember; see :meth:`XRootDPlugin._target`.
TARGET_CACHE = 512

#: An upload's request size and how many are in flight on its connection.
#: A megabyte keeps the one buffer in cache; four hide the round trip.
UPLOAD_CHUNK = 1 << 20
UPLOAD_DEPTH = 4
#: Buffers the upload's reader fills ahead of the sender.
UPLOAD_BUFFERS = 4

_KXR_DSTAT = 0x02
_KXR_CANCEL = 0x01

_modules: dict[str, Any] = {}


def _import() -> Any:
    """``xrdclient``, imported on first use so that ``import xgfalclient`` never needs it."""
    found = _modules.get("xrdclient")
    if found is None:
        found = _modules["xrdclient"] = importlib.import_module("xrdclient")
    return found


def _requests() -> Any:
    """``xrdclient.proto.requests``, for the one request made here by hand."""
    found = _modules.get("requests")
    if found is None:
        found = _modules["requests"] = importlib.import_module("xrdclient.proto.requests")
    return found


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def _chain(exc: BaseException) -> Iterator[BaseException]:
    """``exc`` and everything it was raised from, without looping."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def e2t(code: int) -> str:
    """``XrdSysE2T``: ``strerror`` with its first letter lowered."""
    text = os.strerror(code)
    return text[:1].lower() + text[1:]


class Failure:
    """What a failure from below looks like to gfal2, in each of its spellings.

    ``code`` is the ``errno``. ``to_str`` is ``XrdCl::XRootDStatus::ToStr``,
    which gfal2 puts in the messages of the calls it makes on XrdCl directly
    (``chmod``, copies) and which scripts match on: ``[ERROR] Server
    responded with an error: [3011] ...``. ``to_string`` is ``ToString``, the
    terser ``[ERROR] Error response: no such file or directory`` the staging
    calls use, and ``message`` is the server's bare text.
    """

    __slots__ = ("code", "message", "to_str", "to_string")

    def __init__(self, code: int, to_string: str, message: str, to_str: str = "") -> None:
        self.code = code
        self.to_string = to_string
        self.message = message
        self.to_str = to_str or (f"{to_string}: {message}" if message else to_string)


def describe(exc: BaseException) -> Failure:
    """Classify a failure from xrdclient (or the socket under it) as XrdCl would."""
    from xrdclient import errors as xe

    if isinstance(exc, _CopyError):
        return exc.failure
    detail = str(exc)
    if isinstance(exc, xe.ServerError):
        code = KXR_ERRNO.get(exc.code, errno.ENOMSG)
        return Failure(
            code,
            f"[ERROR] Error response: {e2t(code)}",
            exc.message,
            # ToStr ends a server's answer with a newline, and gfal2 keeps it.
            f"[ERROR] Server responded with an error: [{exc.code}] {exc.message}\n",
        )
    if isinstance(exc, xe.ChecksumMismatchError):
        return Failure(errno.EILSEQ, "[ERROR] Checksum error", detail)
    if isinstance(exc, xe.AuthenticationError):
        return Failure(EAUTH, "[FATAL] Auth failed", detail)
    if isinstance(exc, xe.RedirectLimitError):
        return Failure(errno.ELOOP, "[FATAL] Redirect limit has been reached", detail)
    if isinstance(exc, xe.TooLargeError):
        return Failure(errno.EFBIG, "[ERROR] Invalid operation", detail)
    if isinstance(exc, xe.ProtocolError):
        return Failure(errno.EPROTO, "[FATAL] Invalid message", detail)
    if isinstance(exc, xe.WaitLimitError):
        return Failure(errno.EAGAIN, "[ERROR] Retry", detail)
    if isinstance(exc, TIMEOUTS):
        return Failure(errno.ETIMEDOUT, "[ERROR] Operation expired", detail)
    for link in _chain(exc):
        if isinstance(link, socket.gaierror):
            return Failure(errno.EHOSTUNREACH, "[FATAL] Invalid address", "")
        if isinstance(link, OSError) and not isinstance(link, xe.XRootDError) and link.errno:
            if isinstance(link, ConnectionRefusedError):
                return Failure(link.errno, "[FATAL] Connection error", "")
            return Failure(link.errno, "[FATAL] Socket error", detail)
    if isinstance(exc, ConnectionError):
        return Failure(errno.ECONNRESET, "[FATAL] Connection error", detail)
    if isinstance(exc, (ValueError, TypeError)):
        return Failure(errno.EINVAL, "[ERROR] Invalid arguments", detail)
    return Failure(errno.EIO, "[ERROR] Unknown error", detail)


def posix_error(description: str, exc: BaseException, code: int | None = None) -> GError:
    """``description (strerror)``: how every ``XrdPosix``-backed call words a failure."""
    found = describe(exc).code if code is None else code
    return GError(f"{description} ({os.strerror(found)})", found)


def status_error(
    prefix: str,
    exc: BaseException,
    *,
    strerror: bool = True,
    terse: bool = False,
    end: str = "",
) -> GError:
    """``prefix`` and the XrdCl status (``ToStr``, or ``ToString`` if ``terse``).

    ``end`` names the side of a copy that failed, which XrdCl's copy process
    appends to the server's text: ``... no such file or directory (source)``.
    """
    failure = describe(exc)
    text = failure.to_string if terse else failure.to_str
    if end:
        newline = "\n" if text.endswith("\n") else ""
        text = f"{text.rstrip(chr(10))} ({end}){newline}"
    tail = f" ({os.strerror(failure.code)})" if strerror else ""
    return GError(f"{prefix}{text}{tail}", failure.code)


# ---------------------------------------------------------------------------
# Stat
# ---------------------------------------------------------------------------


def _ids() -> tuple[int, int]:
    """The caller's uid and gid, which ``XrdPosix`` puts in every stat."""
    uid = getattr(os, "getuid", None)
    gid = getattr(os, "getgid", None)
    return (uid() if uid else 0), (gid() if gid else 0)


def flags_to_mode(flags: int) -> int:
    """``XrdPosixMap::Flags2Mode``: owner permission bits and the file type."""
    mode = 0
    if flags & _X_SET:
        mode |= _stat.S_IXUSR
    if flags & _READABLE:
        mode |= _stat.S_IRUSR
    if flags & _WRITABLE:
        mode |= _stat.S_IWUSR
    if flags & _OTHER:
        mode |= _stat.S_IFBLK
    elif flags & _IS_DIR:
        mode |= _stat.S_IFDIR
    else:
        mode |= _stat.S_IFREG
    if flags & _POSC_PENDING:
        mode |= _stat.S_ISUID  # XRDSFS_POSCPEND
    return mode


def _inode(identifier: str) -> int:
    """``strtoll(id, 0, 10)``: the leading decimal digits, else zero."""
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
    return _reduced((int(info.flags), info.st_size, info.st_mtime))


#: What a listing entry's stat is reduced to: flags, size and mtime.
Brief = tuple[int, int, int]
#: A stat the server sent and nobody asked to read.
_UNREAD: Brief = (0, 0, 0)


def _reduced(brief: Brief) -> Stat:
    flags, size, mtime = brief
    mode = _stat.S_IFDIR if flags & _IS_DIR else _stat.S_IFREG
    if flags & _READABLE:
        mode |= 0o444
    if flags & _WRITABLE:
        mode |= 0o222
    if flags & _X_SET:
        mode |= 0o111
    return Stat(st_mode=mode, st_size=size, st_mtime=mtime)


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
    for name, line in zip(lines[::2], lines[1::2]):
        if name == ".":
            continue
        parts = line.split()
        if len(parts) < 4:
            raise _import().errors.ProtocolError(
                f"kXR_stat returned {len(parts)} fields, expected >= 4: {line!r}"
            )
        fields = (int(parts[2]), int(parts[1]), int(parts[3])) if brief else _UNREAD
        found.append((_entry_name(name, path), fields))
    return found


def _entry_name(name: str, path: str) -> str:
    if "/" in name or name == "..":
        raise _import().errors.ProtocolError(
            f"kXR_dirlist entry {name!r} in {path!r} is not a name"
        )
    return name


def status_word(flags: int) -> str:
    """``user.status``: gfal2's ``StatInfo2Xattr``."""
    on_tape = bool(flags & _BACKUP)
    on_disk = not flags & _OFFLINE
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


def collapse_slashes(path: str) -> str:
    """gfal2's ``collapse_slashes``: ``//a///b`` is ``/a/b``."""
    while "//" in path:
        path = path.replace("//", "/")
    return path


def local_path(url: str) -> str:
    """The path in a ``file://`` URL, with or without a host part."""
    rest = url[len("file://") :]
    if rest.startswith("/"):
        return rest
    slash = rest.find("/")
    return rest[slash:] if slash >= 0 else "/"


def is_root(url: str) -> bool:
    return scheme_of(url) in SCHEMES


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


class XRootDFile(PluginFile):
    """An open ``root://`` file: positional reads and writes on one handle.

    ``readinto`` hands the whole buffer to xrdclient, which fills a large one
    over its pipelined bulk path straight from the socket; that is what makes
    the core's streamed copy out of ``root://`` fast.
    """

    def __init__(self, url: str, handle: File, *, writable: bool) -> None:
        super().__init__(url)
        self._handle = handle
        self._writable = writable

    def _io(self, description: str, action: Callable[[], T]) -> T:
        try:
            return action()
        except Exception as exc:
            raise posix_error(description, exc) from exc

    def read(self, size: int) -> bytes:
        data = self._read(self.position, size)
        self.position += len(data)
        return data

    def pread(self, offset: int, size: int) -> bytes:
        """Read at ``offset`` and leave the cursor after it.

        The plugin has no ``preadG``, so gfal2 emulates one with ``lseek``
        and ``read`` and the cursor stays where the read ended; code that
        mixes the two sees the same file here as there.
        """
        data = self._read(offset, size)
        self.position = offset + len(data)
        return data

    def _read(self, offset: int, size: int) -> bytes:
        return self._io(
            "Failed while reading from file", lambda: bytes(self._handle.read(size, offset))
        )

    def readinto(self, buffer: memoryview | bytearray) -> int:
        count = self._io(
            "Failed while reading from file",
            lambda: int(self._handle.readinto(buffer, self.position)),
        )
        self.position += count
        return count

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        if not self._writable:
            code = errno.EBADF
            raise GError(f"Failed while writing to file ({os.strerror(code)})", code)
        view = memoryview(data).cast("B")
        return self._io(
            "Failed while writing to file",
            lambda: int(self._handle.write(view, offset)),  # type: ignore[arg-type]
        )

    def size(self) -> int:
        return self._io("Failed to seek within file", lambda: int(self._handle.size))

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._io("Failed to close file", self._handle.close)


# ---------------------------------------------------------------------------
# The plugin
# ---------------------------------------------------------------------------


class XRootDPlugin(Plugin):
    """The ``xrootd`` plugin."""

    name = "xrootd"
    schemes = SCHEMES
    option_group = "XROOTD PLUGIN"
    priority = 400
    event_domain = DOMAIN
    # gfal2 hands a copy to XrdCl whole: see copy().
    narrates_transfer = True
    copy_manages_destination = True
    copy_manages_checksums = True

    def __init__(self, context: Any) -> None:
        super().__init__(context)
        self._lock = threading.Lock()
        self._configs: dict[tuple[object, ...], Config] = {}
        self._combined: dict[tuple[str, str], str] = {}
        self._targets: dict[tuple[object, ...], tuple[XRootDURL, str]] = {}
        #: Idle filesystems by (endpoint, config), each with when it was put back.
        #: Never replaced, only emptied: :func:`_close_idle` holds it.
        self._idle: dict[tuple[str, int], list[tuple[float, FileSystem]]] = {}
        self._pid = os.getpid()
        # A context is a cycle (it holds its plugins, they hold it), so one
        # that is dropped is freed by the cycle collector - and a filesystem
        # freed that way takes its socket with it: the collector finalizes the
        # socket while xrdclient's Router.__del__ hands the session over it
        # back to xrdclient's process-wide pool, whose next taker (any
        # context's upload) then sends on a closed descriptor, EBADF. Held
        # from here, the idle filesystems are never part of that garbage; they
        # are closed properly, sockets intact, as soon as the plugin goes.
        weakref.finalize(self, _close_idle, self._idle, self._lock)

    @classmethod
    def available(cls) -> str | None:
        try:
            _import()
        except ImportError:
            return MISSING_HINT
        return None

    def close(self) -> None:
        """Forget cached settings and remove any combined credential files made."""
        with self._lock:
            self._configs.clear()
            self._targets.clear()
            combined, self._combined = self._combined, {}
        _close_idle(self._idle, self._lock)
        for path in combined.values():
            try:
                os.remove(path)
            except OSError:
                pass

    # -- configuration -------------------------------------------------------------

    def _proxy_for(self, cred: X509Credential) -> str:
        """A single PEM holding the certificate and its key, as xrdclient wants.

        A proxy already is one. A separate certificate and key (``usercert``
        plus ``userkey``) are concatenated into a private temporary file,
        once per pair, so that ``roots://`` can present them for TLS.
        """
        if cred.is_combined:
            return cred.cert
        key = (cred.cert, cred.key)
        with self._lock:
            found = self._combined.get(key)
            if found is not None:
                return found
            fd, path = tempfile.mkstemp(prefix="xgfal-x509-", suffix=".pem")
            try:
                with open(cred.cert, "rb") as cert, open(cred.key, "rb") as private:
                    body = cert.read().rstrip(b"\n") + b"\n" + private.read()
                os.write(fd, body)
            except OSError:
                os.close(fd)
                os.remove(path)
                raise
            os.close(fd)
            self._combined[key] = path
            return path

    def _config(self, url: str, timeout: float | None = None) -> Config:
        """The xrdclient settings for ``url``: this context's credentials and options.

        Built once per distinct set of inputs. ``prompt`` is always off: a
        library call has nobody to ask.
        """
        cred = self.context.x509(url)
        token = self.context.bearer_token(url)
        insecure = self.options.boolean(self.option_group, "INSECURE", False)
        wanted = self.options.string(self.option_group, "XRD.WANTPROT", "")
        request = float(timeout if timeout else self.option_timeout())
        ca_path = self.context.ca_path()
        # xrdclient reads it into Config.gsi_delegate, as XrdCl does at login;
        # gfal-copy exports it. Part of the key, so a change is picked up.
        delegate = os.environ.get("XrdSecGSIDELEGPROXY", "")  # noqa: SIM112 - XRootD spells it so
        key = (cred, token, insecure, wanted, request, ca_path, delegate)
        with self._lock:
            found = self._configs.get(key)
        if found is not None:
            return found
        changes: dict[str, Any] = {
            "prompt": False,
            "proxy": self._proxy_for(cred) if cred is not None else None,
            "token": token,
            "token_file": None,
            "ca_path": ca_path,
            "verify_tls": not insecure,
            "request_timeout": request,
            # A bound data sub-stream stalls writes against a stock xrootd
            # 5.9, so everything stays on the control link; downloads have
            # their own connections on the bulk plane regardless.
            "data_streams": 0,
        }
        order = tuple(part for part in wanted.replace(";", ",").split(",") if part.strip())
        if order:
            changes["auth_order"] = tuple(part.strip() for part in order)
        config: Config = _import().Config(**changes)
        with self._lock:
            self._configs[key] = config
        return config

    def _extra_cgi(self) -> dict[str, str]:
        """``[XROOTD PLUGIN] XRD.*`` options, as gfal2 appends them to every URL."""
        extra: dict[str, str] = {}
        try:
            keys = self.options.keys(self.option_group)
        except GError:  # no such group: nothing configured
            return extra
        for key in keys:
            if key.startswith("XRD."):
                value = self.options.string(self.option_group, key, "")
                extra[key.lower()] = value.replace(";", ",")
        return extra

    def _target(self, url: str, **extra: str) -> tuple[XRootDURL, str]:
        """``url`` as xrdclient's URL of the endpoint, and the decoded path.

        gfal2's ``prepare_url``: the path is URL-decoded (XRootD wants it
        raw) and the ``XRD.*`` options join whatever CGI the URL carried.
        The CGI stays on the endpoint so that every request made through it
        carries it, which is how an ``authz=`` token reaches the server.

        Remembered per URL and options, since a loop of ``stat`` asks for
        the same few again and again (the answer is immutable).
        """
        options = self._extra_cgi()
        key = (url, tuple(options.items()), tuple(extra.items()))
        found = self._targets.get(key)
        if found is not None:
            return found
        parsed = _import().parse(url)
        query = dict(parsed.query)
        query.update(options)
        query.update(extra)
        path = urllib.parse.unquote(parsed.path)
        found = parsed.evolve(path="/", query=query), path
        with self._lock:
            if len(self._targets) >= TARGET_CACHE:
                self._targets.clear()
            self._targets[key] = found
        return found

    def _file_url(self, url: str, **extra: str) -> XRootDURL:
        base, path = self._target(url, **extra)
        return base.with_path(path)

    @contextmanager
    def _fs(self, url: str, timeout: float | None = None) -> Iterator[tuple[FileSystem, str]]:
        """A filesystem on ``url``'s endpoint, kept for the next call when it worked.

        gfal2 keeps its connections in XrdCl's post master; here the
        filesystems stay open between calls, so a ``stat`` is one round trip
        and nothing else - no router to build, no trip through xrdclient's
        pool (which digests the credentials twice per use). One that failed
        other than by the server's answer is closed instead, which hands its
        connection to that pool, and the pool will not take a broken one.
        Nothing is kept where pooling is off (``XRD_POOLSIZE=0``).
        """
        base, path = self._target(url)
        config = self._config(url, timeout)
        key = (str(base), id(config)) if config.pool_size > 0 else None
        fs = self._checkout(key, config.pool_idle_ttl)
        if fs is None:
            fs = _import().FileSystem(base, config)
        try:
            yield fs, path
        except BaseException as exc:
            # The server's answer, or one of ours: the connection is fine.
            if isinstance(exc, (GError, _import().errors.ServerError)):
                self._checkin(key, fs)
            else:
                fs.close()
            raise
        self._checkin(key, fs)

    def _checkout(self, key: tuple[str, int] | None, ttl: float) -> FileSystem | None:
        if key is None:
            return None
        now = time.monotonic()
        stale: list[FileSystem] = []
        found = None
        with self._lock:
            if self._pid != os.getpid():
                # A forked child must not touch its parent's sockets: forget
                # them without closing, as xrdclient's own pool does.
                self._idle.clear()
                self._pid = os.getpid()
            entries = self._idle.get(key)
            while entries:
                when, fs = entries.pop()
                if now - when <= ttl:
                    found = fs
                    break
                stale.append(fs)
        for fs in stale:
            fs.close()
        return found

    def _checkin(self, key: tuple[str, int] | None, fs: FileSystem) -> None:
        with self._lock:
            entries = self._idle.get(key) if key is not None else None
            if entries is None and key is not None and len(self._idle) < IDLE_ENDPOINTS:
                entries = self._idle[key] = []
            if entries is not None and len(entries) < IDLE_PER_ENDPOINT:
                entries.append((time.monotonic(), fs))
                return
        fs.close()

    def _posix(self, url: str, description: str, action: Callable[[FileSystem, str], T]) -> T:
        """Run ``action`` and word any failure as the ``XrdPosix`` call would."""
        try:
            with self._fs(url) as (fs, path):
                return action(fs, path)
        except GError:
            raise
        except Exception as exc:
            raise posix_error(description, exc) from exc

    # -- namespace -----------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        return posix_stat(self._posix(url, "Failed to stat file", lambda fs, p: fs.stat(p)))

    lstat = stat

    def access(self, url: str, mode: int) -> None:
        info = self._posix(url, "Failed to access file or directory", lambda fs, p: fs.stat(p))
        bits = flags_to_mode(int(info.flags))
        allowed = not (
            (mode & os.R_OK and not bits & _stat.S_IRUSR)
            or (mode & os.W_OK and not bits & _stat.S_IWUSR)
            or (mode & os.X_OK and not bits & _stat.S_IXUSR)
        )
        if not allowed:
            code = errno.EACCES
            raise GError(f"Failed to access file or directory ({os.strerror(code)})", code)

    def chmod(self, url: str, mode: int) -> None:
        try:
            with self._fs(url) as (fs, path):
                fs.chmod(path, mode & 0o777)
        except Exception as exc:
            raise status_error("", exc) from exc

    def mkdir(self, url: str, mode: int) -> None:
        """Stat first: EOS says yes to an existing directory, so gfal2 asks."""
        description = f"Failed to create directory {url}"

        def create(fs: FileSystem, path: str) -> None:
            try:
                fs.stat(path)
            except Exception:
                pass  # absent, or unanswerable: the mkdir will say which
            else:
                raise GError(f"{description} ({os.strerror(errno.EEXIST)})", errno.EEXIST)
            try:
                # XrdPosix makes the whole path unless S_ISUID says not to.
                fs.mkdir(path, mode & 0o777, parents=not mode & _stat.S_ISUID)
            except Exception as exc:
                code = describe(exc).code
                raise posix_error(
                    description, exc, errno.EEXIST if code == errno.ECANCELED else code
                ) from exc

        self._posix(url, description, create)

    def mkdir_rec(self, url: str, mode: int) -> None:
        """gfal2's ``mkdir_rec`` is ``mkdir`` with parents, forgiving ``EEXIST``."""
        try:
            self.mkdir(url, mode)
        except GError as exc:
            if exc.code != errno.EEXIST:
                raise

    def rmdir(self, url: str) -> None:
        description = "Failed to delete directory"

        def remove(fs: FileSystem, path: str) -> None:
            try:
                fs.rmdir(path)
            except Exception as exc:
                raise posix_error(description, exc, _rmdir_errno(fs, path, exc)) from exc

        self._posix(url, description, remove)

    def unlink(self, url: str) -> None:
        self._posix(url, "Failed to delete file", lambda fs, p: fs.remove(p))

    def rename(self, old: str, new: str) -> None:
        description = "Failed to rename file or directory"

        def move(fs: FileSystem, path: str) -> None:
            _, target = self._target(new)
            try:
                fs.rename(path, target)
            except Exception as exc:
                error = posix_error(description, exc)
                # EOS says EEXIST when the target is a directory; gfal2 swaps
                # the code for EISDIR and keeps the message.
                if error.code == errno.EEXIST and _is_dir(fs, target):
                    error.code = errno.EISDIR
                    error.args = (error.message, error.code)
                raise error from exc

        self._posix(old, description, move)

    def readlink(self, url: str) -> str:
        """A vendor opcode; a stock server has none, and then neither does gfal2."""
        try:
            with self._fs(url) as (fs, path):
                return str(fs.readlink(path))
        except Exception as exc:
            raise _vendor_error(url, "Failed to read link", exc) from exc

    def symlink(self, target: str, link: str) -> None:
        destination = self._target(target)[1] if is_root(target) else target
        try:
            with self._fs(link) as (fs, path):
                fs.symlink(destination, path)
        except Exception as exc:
            raise _vendor_error(target, "Failed to create symlink", exc) from exc

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        """One ``kXR_dirlist`` with stat info, read in full; see :func:`_entries`."""

        def listing(fs: FileSystem, path: str) -> list[tuple[str, Stat | None]]:
            found = _entries(fs, path, brief=True)
            return [(name, _reduced(fields)) for name, fields in found]

        return iter(self._posix(url, "Failed to stat file", listing))

    def listdir(self, url: str) -> list[str]:
        """``opendir`` without building a stat per entry nobody will look at."""
        found = self._posix(url, "Failed to stat file", lambda fs, p: _entries(fs, p, brief=False))
        return [name for name, _ in found]

    # -- I/O -----------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o744, size: int | None = None) -> PluginFile:
        """``XrdPosixXrootd::Open``'s translation of POSIX flags.

        ``mode`` defaults to what ``gfal2_open`` passes, ``0744``.

        Anything but read-only is ``kXR_open_updt``; ``O_CREAT`` is
        ``kXR_delete`` (``kXR_new`` with ``O_EXCL``) and always makes the
        path; ``O_TRUNC`` without it truncates an existing file.
        """
        writable = bool(flags & O_ACCMODE_MASK)
        options = _UPDATE if writable else _READ
        access = 0
        if flags & O_CREAT:
            options |= (_NEW if flags & O_EXCL else _DELETE) | _MKPATH
            access = mode & 0o777
        elif flags & O_TRUNC and writable:
            options |= _DELETE
        try:
            target = self._file_url(url)
            handle = _import().File(target, self._config(url))
            handle.open(options, access)
        except Exception as exc:
            raise posix_error("Failed to open file", exc) from exc
        return XRootDFile(url, handle, writable=writable)

    # -- metadata ------------------------------------------------------------------

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        if offset or length:
            code = errno.ENOTSUP
            raise GError(f"XROOTD does not support partial checksums ({os.strerror(code)})", code)
        wanted = _checksum_name(algorithm)
        try:
            answer = self._checksum_answer(url, wanted)
        except Exception as exc:
            raise posix_error("Could not get the checksum", exc) from exc
        return _checksum_value(answer, wanted)

    def _checksum_answer(self, url: str, wanted: str) -> bytes:
        """The server's answer to ``kXR_Qcksum`` for ``url``, asked for ``wanted``."""
        argument = self._file_url(url, **{"cks.type": wanted}).path_with_cgi
        with self._fs(url) as (fs, _):
            return bytes(fs.query(3, argument))

    def getxattr(self, url: str, name: str) -> str:
        description = f'Failed to get the xattr "{name}"'
        if name == "spacetoken":
            return self._space(url)
        if name == "user.status":
            try:
                with self._fs(url) as (fs, path):
                    info = fs.stat(path)
            except Exception as exc:
                raise posix_error(description, exc, errno.ENOENT) from exc
            return status_word(int(info.flags))
        code = _XATTR_QUERY.get(name)
        if code is None:
            raise GError(f"{description} ({os.strerror(ENOATTR)})", ENOATTR)
        argument = self._file_url(url).path_with_cgi

        def query(fs: FileSystem, path: str) -> bytes:
            fs.stat(path)  # lands on the data server holding the file
            return bytes(fs.query(code, argument))

        answer = self._posix(url, description, query)
        return answer.split(b"\x00", 1)[0].decode("utf-8", "replace")

    def _space(self, url: str) -> str:
        try:
            with self._fs(url) as (fs, path):
                space = fs.query_space(path)
        except Exception as exc:
            message = describe(exc).message
            raise GError(f"Failed to get the space information: {message}", errno.EIO) from exc
        return space_json(space.total, space.free, space.used, space.largest_free)

    def listxattr(self, url: str) -> list[str]:
        return list(XATTRS)

    def setxattr(self, url: str, name: str, value: str, flags: int) -> None:
        code = errno.ENOSYS
        raise GError(f"Can not set extended attributes ({os.strerror(code)})", code)

    # -- tape ----------------------------------------------------------------------

    def _paths(self, urls: Sequence[str], *, cgi: bool) -> list[str]:
        """Each URL's path, with its CGI when the request carries one per file."""
        paths = []
        for url in urls:
            target = self._file_url(url)
            paths.append(target.path_with_cgi if cgi else target.path)
        return paths

    def bring_online(
        self,
        urls: Sequence[str],
        metadata: Sequence[str],
        pintime: int,
        timeout: int,
        is_async: bool,
    ) -> tuple[list[StagingResult], str]:
        """``kXR_prepare`` with ``kXR_stage``; the answer is the request id.

        gfal2 never reports a file online from here, only queued; the poll
        says when it is.
        """
        try:
            with self._fs(urls[0], timeout or None) as (fs, _):
                token = str(fs.prepare(self._paths(urls, cgi=True), stage=True))
        except Exception as exc:
            failure = describe(exc)
            message = (
                f"Bringonline request failed. One or more files failed with: {failure.to_string}"
            )
            return [GError(message, failure.code) for _ in urls], ""
        if not token:
            message = "Bringonline request failed: empty response from the server"
            return [GError(message, errno.ENOMSG) for _ in urls], ""
        return [False for _ in urls], token

    def bring_online_poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        return self._poll_prepare(urls, token, archive=False)

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        """A ``kXR_QPrep`` under a request id nobody made, asking only ``on_tape``."""
        return self._poll_prepare(urls, str(uuid.uuid4()), archive=True)

    def _poll_prepare(
        self, urls: Sequence[str], token: str, *, archive: bool
    ) -> list[StagingResult]:
        paths = [collapse_slashes(path) for path in self._paths(urls, cgi=False)]
        try:
            with self._fs(urls[0]) as (fs, _):
                answer = bytes(fs.query(2, "\n".join([token, *paths])))
        except Exception as exc:
            failure = describe(exc)
            code = ECOMM if failure.code in _NETWORK_ERRNOS else failure.code
            return [GError(failure.to_string, code) for _ in urls]
        return parse_prepare_status(
            answer.split(b"\x00", 1)[0].decode("utf-8", "replace"), token, paths, archive=archive
        )

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``kXR_prepare`` with ``kXR_evict``: no token needed over XRootD."""
        try:
            with self._fs(urls[0], 30) as (fs, _):
                fs.prepare(self._paths(urls, cgi=True), evict=True)
        except Exception as exc:
            return _each(urls, describe(exc))
        return [None for _ in urls]

    def abort_bring_online(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``kXR_prepare`` with ``kXR_cancel``: the request id, then the files to withdraw."""
        request = _requests().Prepare([token, *self._paths(urls, cgi=True)], _KXR_CANCEL)
        try:
            with self._fs(urls[0]) as (fs, _):
                fs._router.execute(request)
        except Exception as exc:
            return _each(urls, describe(exc))
        return [None for _ in urls]

    # -- copies --------------------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        """gfal2's ``gfal_xrootd_3rdcopy_check``: root to root, and root to or from file."""
        if is_root(source):
            return is_root(destination) or destination.startswith("file://")
        return is_root(destination) and source.startswith("file://")

    def copy(self, transfer: Transfer) -> None:
        """One job of XrdCl's copy process, as gfal2 sets it up and narrates it.

        gfal2 hands the whole copy to XrdCl, so the core does none of it:
        no existence check (``force`` decides, and the server answers
        ``EEXIST``), no parent creation (a pull and an upload make the path
        anyway, a download makes the local one), no ``CHECKSUM`` events (the
        job verifies, and a mismatch is ``EILSEQ``), and the clean-up after a
        failure is the plugin's own. ``TRANSFER:TYPE`` is ``3rd pull`` only
        for ``root`` to ``root``, where gfal2 asks for a third-party copy
        and nothing else; any other pair of XRootD schemes is a job XrdCl
        may run either way, which gfal2 announces as ``streamed``.
        """
        source, destination = transfer.source, transfer.destination
        params = transfer.params
        only = scheme_of(source) == "root" and scheme_of(destination) == "root"
        transfer.event(
            ev.TRANSFER_ENTER,
            f"{self._job_url(source, params.src_spacetoken)} => "
            f"{self._job_url(destination, params.dst_spacetoken)}",
        )
        transfer.event(ev.TRANSFER_TYPE, TYPE_PULL if only else TYPE_STREAMED)
        end = ""
        try:
            verify = _Verification(self, transfer)
            verify.before()
            if is_root(source) and is_root(destination):
                self._third_party(transfer, delegate=only and params.proxy_delegation)
            elif is_root(source):
                end = "source"
                self._download(transfer)
            else:
                end = "destination"
                self._upload(transfer)
            verify.after()
        except Exception as exc:
            if transfer.callback_error is not None:
                raise  # a callback's own exception: the core hands it back as it was
            self._copy_failed(transfer, exc, end)
        transfer.event(ev.TRANSFER_EXIT, "Job finished, [SUCCESS] ")
        if params.evict:
            # gfal2 asks for any source, and a file:// one always fails.
            failed = not is_root(source) or any(
                result is not None for result in self.release([source], "")
            )
            transfer.event(EVICT, str(-1 if failed else 0), side=ev.SOURCE)

    def _copy_failed(self, transfer: Transfer, exc: Exception, end: str) -> NoReturn:
        """End the job as XrdCl does, remove what it left, and raise gfal2's error."""
        if isinstance(exc, GError):
            code, text, error = exc.code, exc.message, exc
        else:
            status = status_error(
                "", exc, strerror=False, end=exc.end if isinstance(exc, _CopyError) else end
            )
            code, text = status.code, status.message
            error = GError(f"Error on XrdCl::CopyProcess::Run(): {text}", code)
        # gfal2's copy process ends every job with an EXIT; the core only
        # sends one for a copy that worked, so a failed one is said here.
        transfer.event(ev.TRANSFER_EXIT, f"Job finished, {text}")
        if transfer.params.transfer_cleanup and code != errno.EEXIST:
            self._clean(transfer)
        if error is exc:
            raise exc
        raise error from exc

    def _clean(self, transfer: Transfer) -> None:
        """``gfal_xrootd_copy_cleanup``: a destination already gone counts as removed.

        A local device or FIFO is a sink the copy wrote into, not a file it
        made, and is left alone (gfal2 would try to unlink ``/dev/null``).
        A ``root://`` destination is removed by this plugin itself, as gfal2
        calls ``gfal_xrootd_unlinkG`` - not through the context, which
        refuses new operations while a ``cancel()`` drains, and so would leave
        a cancelled copy's destination behind.
        """
        destination = transfer.destination
        remote = is_root(destination)
        if not remote and _is_sink(local_path(destination)):
            return
        try:
            (self.unlink if remote else self.context.unlink)(destination)
            status = 0
        except GError as exc:
            status = 0 if exc.code == errno.ENOENT else exc.code
        transfer.event(ev.CLEANUP, str(status), side=ev.DESTINATION)

    def _job_url(self, url: str, spacetoken: str) -> str:
        """``url`` as XrdCl's copy job prints it, after gfal2's ``prepare_url``.

        gfal2 gives the path three leading slashes and the ``XRD.*`` options,
        a space token replaces whatever CGI there was (``svcClass``), and
        XrdCl adds its intent, prints the port, and sorts the CGI; a local
        file is on ``localhost``.
        """
        parsed = urllib.parse.urlsplit(url)
        path = urllib.parse.unquote(parsed.path) or "///"
        if not path.startswith("///"):
            path = ("/" if path.startswith("//") else "//") + path
        cgi: dict[str, str] = {}
        if is_root(url):
            host = parsed.hostname or ""
            where = f"[{host}]" if ":" in host else host
            user = f"{parsed.username}@" if parsed.username else ""
            authority = f"{user}{where}:{parsed.port or 1094}"
            cgi.update(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            cgi.update(self._extra_cgi())
        else:
            authority = "localhost"
        if spacetoken:
            cgi = {"svcClass": spacetoken}
        cgi["xrdcl.intent"] = "tpc"
        query = "&".join(f"{key}={value}" for key, value in sorted(cgi.items()))
        return f"{scheme_of(url)}://{authority}{path}?{query}"

    def _copy_url(self, url: str, spacetoken: str) -> XRootDURL:
        """A copy's URL: gfal2 names the space token as ``svcClass``."""
        return self._file_url(url, **({"svcClass": spacetoken} if spacetoken else {}))

    def _third_party(self, transfer: Transfer, *, delegate: bool) -> None:
        """Destination pulls from source: XrdCl's ``ThirdPartyCopyJob``, step by step.

        See :class:`_Rendezvous` for the steps. The destination's path is
        made as the pull's open makes it, whatever ``create_parent`` says:
        when the open finds no parent, the parent is made and the job run
        once more.
        """
        params = transfer.params
        job = _Rendezvous(
            self._copy_url(transfer.source, params.src_spacetoken),
            self._copy_url(transfer.destination, params.dst_spacetoken),
            self._config(transfer.source),
            # XrdCl sets XrdSecGSIDELEGPROXY to match before this login.
            self._config(transfer.destination).evolve(gsi_delegate=delegate),
            delegate=delegate,
            overwrite=bool(params.overwrite),
        )
        try:
            size = self._pull(transfer, job)
        except _CopyError as exc:
            if not exc.no_parent:
                raise
            try:
                self.mkdir_rec(parent(transfer.destination), 0o755)
            except GError:
                raise exc from None
            size = self._pull(transfer, job)
        transfer.progress(size, always=True)  # XrdCl's last JobProgress, however short

    def _pull(self, transfer: Transfer, job: _Rendezvous) -> int:
        """The rendezvous, in a worker; this thread watches the clock.

        The rendezvous blocks until the destination has the file, so it runs
        in a worker while this thread keeps ``transfer.check()`` honest and,
        when someone is listening, reports progress from the size the
        destination has so far. A copy that must stop - cancelled, out of
        time, or a callback that raised - stops the destination's pull as
        XrdCl's progress handler does (see :class:`_Pull`), and fails the way
        gfal2's does: a cancelled pull with the destination's answer to the
        cancel (``ECANCELED``, "destination file prematurely closed"), one out
        of time as XrdCl's expired ``kXR_sync`` (``[ERROR] Operation
        expired``), and a callback's exception as it was.
        """
        params = transfer.params
        outcome: list[Any] = []
        timeout = transfer.remaining()
        stop = threading.Event()

        def pull() -> None:
            try:
                outcome.append(job.run(timeout, stop))
            except BaseException as exc:  # handed to the waiting thread
                outcome.append(exc)

        worker = threading.Thread(target=pull, name="xgfal-tpc", daemon=True)
        worker.start()
        watching = params.monitor_callback is not None
        asked = time.monotonic()
        while worker.is_alive():
            worker.join(TPC_POLL)
            try:
                transfer.check()
            except Exception as exc:
                stop.set()
                # The destination answers a cancel at once; one that does
                # not is left to it, as before XrdCl learned to cancel.
                worker.join(TPC_CANCEL_WAIT)
                raise _stopped(exc, outcome) from None
            if watching and worker.is_alive() and time.monotonic() - asked >= TPC_PROGRESS:
                asked = time.monotonic()
                self._tpc_progress(transfer)
        result = outcome.pop()
        if isinstance(result, BaseException):
            raise result
        return int(result)

    def _tpc_progress(self, transfer: Transfer) -> None:
        """How much the destination holds, as the progress of a pull."""
        try:
            with self._fs(transfer.destination) as (fs, path):
                transfer.progress(int(fs.stat(path).st_size))
        except Exception:
            pass  # not created yet, or busy: the next poll will know

    def _download(self, transfer: Transfer) -> None:
        """``root://`` to a local file over the bulk data plane.

        ``nbstreams`` connections each fetch their own span, pipelined and
        written at their own offsets; the progress callback is also where a
        cancelled or timed-out copy is noticed. The local path is made, as
        XrdCl makes it, and an existing file is replaced only with
        ``overwrite``. XrdCl opens the source first, so when the local file
        cannot be made, the source is opened to see whether that is the
        failure to report.
        """
        bulk = importlib.import_module("xrdclient.client.bulk")
        params = transfer.params
        source = self._copy_url(transfer.source, params.src_spacetoken)
        config = self._config(transfer.source)

        def progress(done: int, total: int | None) -> None:
            transfer.progress(done)
            transfer.check()

        workers = params.nbstreams if params.nbstreams > 0 else None
        try:
            fd = _local_create(local_path(transfer.destination), overwrite=bool(params.overwrite))
        except _CopyError:
            probe = _import().File(source, config)
            probe.open(_READ, 0)
            probe.close()
            raise
        try:
            try:
                bulk.download(source, fd, config=config, progress=progress, workers=workers)
            except bulk.BulkUnsupported:
                self._download_serially(transfer, source, config, fd)
        finally:
            os.close(fd)
        transfer.progress(transfer.transferred, always=True)  # XrdCl's last JobProgress

    def _download_serially(
        self, transfer: Transfer, source: XRootDURL, config: Config, fd: int
    ) -> None:
        """The same download one request at a time, for a server without the bulk plane."""
        from ..transfer import pump
        from .file import LocalFile

        handle = _import().File(source, config)
        handle.open(_READ, 0)
        reader = XRootDFile(str(source), handle, writable=False)
        os.ftruncate(fd, 0)
        writer = LocalFile(transfer.destination, local_path(transfer.destination), os.O_WRONLY, 0)
        try:
            pump(transfer, reader, writer, final_report=False)  # the caller reports
        finally:
            writer.close()
            reader.close()

    def _upload(self, transfer: Transfer) -> None:
        """A local file to ``root://`` on one handle, reads and writes overlapped.

        The destination is created exclusively unless ``overwrite`` is set,
        and its path is made. ``nbstreams`` does not apply: xrootd lets one
        writer at a time have a file open (``kXR_FileLocked``), so there is
        no second connection to spread an upload over.
        """
        params = transfer.params
        source = local_path(transfer.source)
        target = self._copy_url(transfer.destination, params.dst_spacetoken)
        config = self._config(transfer.destination)
        try:
            size = os.stat(source).st_size
        except OSError as exc:
            raise _CopyError(_local_failure(exc), "source") from exc
        # Persist on successful close, as XrdCl's upload asks.
        create = (_DELETE if params.overwrite else _NEW) | _MKPATH | _UPDATE | _POSC
        moved = self._upload_serially(transfer, source, target, config, create)
        if moved != size:
            raise GError(f"Short copy: {moved} bytes transferred, the source has {size}", errno.EIO)

    def _upload_serially(
        self, transfer: Transfer, source: str, target: XRootDURL, config: Config, create: int
    ) -> int:
        from ..transfer import pump
        from .file import LocalFile

        try:
            reader = LocalFile(transfer.source, source, os.O_RDONLY, 0)
        except OSError as exc:
            raise _CopyError(_local_failure(exc), "source") from exc
        try:
            handle = _import().File(target, config)
            handle.open(create, 0o644)
            writer = XRootDFile(str(target), handle, writable=True)
            try:
                if _Upload.usable(handle):
                    moved = _Upload(transfer, reader, writer, handle).run()
                else:
                    moved = pump(transfer, reader, writer, final_report=False)
                    transfer.progress(moved, always=True)
            except BaseException:
                # The failure is the news, not the close that follows it on
                # a connection it may have left unusable.
                try:
                    writer.close()
                except GError:
                    pass
                raise
            writer.close()
            return moved
        finally:
            reader.close()


class _CopyError(Exception):
    """A copy's failure worded as XrdCl words it, and the end it happened at.

    ``no_parent`` marks a pull's destination refusing its open for want of
    a parent directory, which :meth:`XRootDPlugin._third_party` repairs.
    """

    def __init__(self, failure: Failure, end: str, *, no_parent: bool = False) -> None:
        super().__init__(failure.to_str)
        self.failure = failure
        self.end = end
        self.no_parent = no_parent


def _unsupported(text: str) -> _CopyError:
    """XrdCl's ``errNotSupported`` with its own words, and no end named."""
    return _CopyError(Failure(errno.ENOTSUP, "[ERROR] Operation not supported", text), "")


class _Rendezvous:
    """XrdCl's ``ThirdPartyCopyJob`` (XRootD 5.9): ``CanDo``, then ``RunTPC`` or ``RunLite``.

    1. The source is opened with ``tpc.stage=placement`` and closed, which
       finds its data server (``tpcSource``) and size. Without delegation a
       failure here is the job's; with it the source is left to the
       destination to reach with the delegated proxy (TPC lite *only*).
    2. The destination is opened (``kXR_open_updt`` and ``kXR_new``, or
       ``kXR_delete`` for ``overwrite``) with ``cgiC2Dst``'s CGI: the key, the
       source, ``tpc.dlgon`` saying whether the client delegates, and, when
       it does, the source's CGI as ``tpc.scgi``. With delegation on the
       login delegates the proxy (XrdCl sets ``XrdSecGSIDELEGPROXY=1`` for
       it, ``0`` without), so a destination configured with
       ``ofs.tpc fcreds`` holds a proxy of its own to pull with.
    3. ``kXR_Qconfig`` ``tpc tpcdlg`` at the destination (``CheckTPCLite``):
       no TPC is "Destination does not support third-party-copy."; TPC and
       ``tpcdlg`` set, with delegation on, is TPC lite; anything else is the
       classic copy, which a source that could not be opened cannot have
       ("Destination does not support delegation.") and which needs the
       source to answer ``tpc`` (``CheckTPC``).
    4. Classic: ``kXR_sync`` arms the pull, the source is opened with the
       key and ``tpc.dst`` (``cgiC2Src``), and a second ``kXR_sync`` blocks
       until the destination has the file. Lite: the two syncs, and the
       source is not contacted at all.

    Failures carry XrdCl's side: ``(destination)`` for the destination's
    open, first sync and close, ``(source)`` for the source's keyed open and
    close, and nothing for the pull itself (the second sync).
    """

    def __init__(
        self,
        source: XRootDURL,
        target: XRootDURL,
        source_config: Config,
        target_config: Config,
        *,
        delegate: bool,
        overwrite: bool,
    ) -> None:
        self.source = source
        self.target = target
        self.source_config = source_config
        self.target_config = target_config
        self.delegate = delegate
        self.overwrite = overwrite

    def run(self, timeout: float | None, stop: threading.Event) -> int:
        """The whole job; the size of the source, as far as the job knew it.

        ``stop`` set calls the pull off once it is under way (see :class:`_Pull`).
        """
        xrd = _import()
        source, target = self.source, self.target
        source_config, target_config = self.source_config, self.target_config
        if timeout:
            source_config = source_config.evolve(request_timeout=timeout)
            target_config = target_config.evolve(request_timeout=timeout)
        size, where = self._place(source_config)
        origin = where or source  # tpcSource
        key = uuid.uuid4().hex[:24]
        fields = {
            "tpc.key": key,
            "tpc.src": _host_id(origin),
            "tpc.lfn": origin.path,
            **_streams(os.environ.get("XRD_SUBSTREAMSPERCHANNEL", "")),
            "tpc.dlg": _host_id(source),
            "tpc.spr": source.scheme,
            "tpc.tpr": target.scheme,
            "tpc.dlgon": "1" if self.delegate else "0",
        }
        if where is not None:
            fields["oss.asize"] = str(size)
        fields["tpc.stage"] = "copy"
        scgi = "\t".join(sorted(f for f in source.cgi.split("&") if not f.startswith("xrdcl.")))
        if scgi and self.delegate:
            fields["tpc.scgi"] = scgi
        pull = xrd.File(_opaque(target, fields), target_config)
        try:
            pull.open(_UPDATE | (_DELETE if self.overwrite else _NEW), 0o644)
        except Exception as exc:
            raise _refused(exc) from exc
        landed = _landed(target, pull.endpoint)
        lite = _tpc_lite(_ask_config(landed, "tpc tpcdlg", target_config))
        if lite is None:
            _quietly(pull.close)
            raise _unsupported("Destination does not support third-party-copy.")
        lite = lite and self.delegate
        if where is None and not lite:
            _quietly(pull.close)
            raise _unsupported("Destination does not support delegation.")
        if not lite and not _tpc(_ask_config(origin, "tpc", source_config)):
            _quietly(pull.close)
            raise _unsupported("Source does not support third-party-copy")
        _step(pull.sync, "destination", pull)
        ends = [(pull, "destination")]
        if not lite:
            keyed = xrd.File(
                _opaque(origin, {"tpc.key": key, "tpc.dst": landed.host, "tpc.stage": "copy"}),
                source_config,
            )
            _step(lambda: keyed.open(_READ), "source", pull)
            ends.insert(0, (keyed, "source"))
        _step(lambda: _Pull(pull, stop).run(), "", *(handle for handle, _ in ends))
        failures = [_closed(handle, end) for handle, end in ends]
        for failure in failures:
            if failure is not None:
                raise failure
        return max(size, 0)

    def _place(self, config: Config) -> tuple[int, XRootDURL | None]:
        """The size and landing place of the source, or ``None`` for one that cannot be opened."""
        placed = _import().File(_opaque(self.source, {"tpc.stage": "placement"}), config)
        try:
            placed.open(_READ)
            size = int(placed.size)
        except Exception as exc:
            if not self.delegate:
                raise _CopyError(describe(exc), "") from exc
            return -1, None
        _quietly(placed.close)
        return size, _landed(self.source, placed.endpoint)


class _Pull:
    """The pull itself - the destination's second ``kXR_sync`` - which can be called off.

    The destination defers its answer (``kXR_waitresp``) until it has the
    file, and xrdclient holds a connection's lock for as long as a request
    waits, so an ``Fcntl`` from another thread would wait for the very pull
    it means to stop. The handle's connection is borrowed instead, the way
    :class:`_Upload` borrows it: the sync is framed on a leased stream id,
    and the socket is watched a moment at a time. When ``stop`` is set,
    this sends what XrdCl's ``RunTPC``/``RunLite`` send when their progress
    handler's ``ShouldCancel`` says so (gfal2's says so once the context is
    cancelled): ``File::Fcntl("ofs.tpc cancel")``, a ``kXR_query`` of type
    ``kXR_Qopaqug`` on the pull's handle. ``XrdOfsFile::fctl`` then kills
    the pull and answers the waiting sync ``ECANCELED`` ("destination file
    prematurely closed"); XrdCl waits for that answer, and so does this,
    which is the pull's failure. The fctl's own answer is ignored, as XrdCl
    only logs it. Either way the rendezvous then closes the handles.

    Anything but those answers on the wire, or a connection that cannot be
    settled, marks the session broken so that nobody reuses it.
    """

    def __init__(self, handle: File, stop: threading.Event) -> None:
        self.handle = handle
        self.stop = stop
        self.session: Any = handle.session
        self.wire: Any = self.session.transport

    @staticmethod
    def usable(handle: File) -> bool:
        """Whether this connection can be borrowed so: the API is there."""
        session: Any = handle.session
        machine = getattr(session, "machine", None)
        return all(
            hasattr(machine, name) for name in ("lease_sids", "release_sids", "frame_for")
        ) and all(hasattr(session, name) for name in ("bulk", "transport", "mark_broken"))

    def run(self) -> None:
        if not _Pull.usable(self.handle):
            self.handle.sync()  # an older xrdclient: a pull that cannot be stopped
            return
        machine = self.session.machine
        with self.session.bulk(self.handle.handle, chunk=1, depth=1):
            leased = machine.lease_sids(2)
            try:
                failure = self._await(*leased)
            except BaseException:
                # A reply may still be in transit: keep the ids leased and the
                # connection out of anyone else's hands.
                self.session.mark_broken()
                raise
            machine.release_sids(leased)
        if failure is not None:
            raise failure

    def _await(self, sync: int, cancel: int) -> Exception | None:
        """Send the sync, and the cancel when asked; the sync's failure, if it failed."""
        requests = importlib.import_module("xrdclient.proto.requests")
        fhandle = self.handle.handle
        self._send(requests.Sync(fhandle), sync)
        owed = {sync}
        asked = False
        failure: Exception | None = None
        while owed:
            if self.stop.is_set() and not asked:
                asked = True
                owed.add(cancel)
                self._send(requests.Query(_KXR_QOPAQUG, TPC_CANCEL, fhandle=fhandle), cancel)
            answer = self._next()
            if answer is None:
                continue
            sid, status, body = answer
            if sid not in owed or status not in (_KXR_OK, _KXR_ERROR, _KXR_WAITRESP):
                raise _import().errors.ProtocolError(
                    f"unexpected reply to a third-party copy: stream {sid}, status {status}"
                )
            if status == _KXR_WAITRESP:
                continue  # the answer comes later, as a kXR_asynresp
            owed.discard(sid)
            if sid == sync and status == _KXR_ERROR:
                code = int.from_bytes(body[:4], "big")
                message = body[4:].rstrip(b"\x00").decode("utf-8", "replace")
                failure = _import().errors.ServerError(code, message, path=self.handle.url.path)
        return failure

    def _send(self, request: Any, sid: int) -> None:
        self.wire.send(self.session.machine.frame_for(request, sid))

    def _next(self) -> tuple[int, int, bytes] | None:
        """The next answer, a deferred one unwrapped; ``None`` if none began in ``TPC_POLL``."""
        header = bytearray(_RESPONSE_HEADER.size)
        self.wire.settimeout(TPC_POLL)
        try:
            got = self.wire.receive_into(memoryview(header))
        except _import().errors.TimeoutError:
            return None
        finally:
            self.wire.settimeout(self.session.config.request_timeout)
        if not got:
            raise _import().errors.ConnectionError("the server closed the connection")
        header[got:] = _receive(self.wire, len(header) - got)
        sid, status, length = _RESPONSE_HEADER.unpack(header)
        body = bytes(_receive(self.wire, length))
        if status != _KXR_ATTN:
            return sid, status, body
        if int.from_bytes(body[:4], "big") != _KXR_ASYNRESP:
            return None  # a notice, which nothing here waits for
        sid, status, _ = _RESPONSE_HEADER.unpack(body[8:16])
        return sid, status, body[16:]


def _stopped(exc: Exception, outcome: list[Any]) -> Exception:
    """The failure of a pull stopped by ``exc``, as gfal2 reports it (see ``_pull``)."""
    if not isinstance(exc, GError):
        return exc  # a callback's own exception
    if exc.code == errno.ETIMEDOUT:
        return _CopyError(Failure(errno.ETIMEDOUT, "[ERROR] Operation expired", ""), "")
    answered = outcome[-1] if outcome else None
    return answered if isinstance(answered, _CopyError) else exc


def _streams(value: str) -> dict[str, str]:
    """``tpc.str``: XrdCl's ``SubStreamsPerChannel`` less the control stream, when any are left.

    XrdCl reads it from ``XRD_SUBSTREAMSPERCHANNEL`` with ``strtol`` (base 0)
    and ignores a value that is not all number; gfal2's ``nbstreams`` goes
    to a job property the third-party job never reads.
    """
    try:
        count = int(value, 0)
    except ValueError:
        try:
            count = int(value, 8)  # strtol's octal "010"
        except ValueError:
            count = 1
    return {"tpc.str": str(count - 1)} if count > 1 else {}


def _opaque(url: XRootDURL, fields: dict[str, str]) -> XRootDURL:
    """``url`` with ``fields`` set in its CGI, as XrdCl writes them: verbatim.

    The fields already there keep their bytes; XrdCl merges its own over
    them, so the new values win.
    """
    kept = url.cgi_except(fields)
    added = "&".join(f"{name}={value}" for name, value in fields.items())
    parsed = _import().parse(f"root://h//?{kept}&{added}" if kept else f"root://h//?{added}")
    return url.evolve(query=parsed.query, _raw_query=parsed.cgi)


def _host_id(url: XRootDURL) -> str:
    """``XrdCl::URL::GetHostId``: ``[user@]host:port``, an IPv6 host bracketed."""
    user = f"{url.username}@" if url.username else ""
    host = f"[{url.host}]" if ":" in url.host else url.host
    return f"{user}{host}:{url.port}"


def _landed(url: XRootDURL, endpoint: str) -> XRootDURL:
    """``url`` on the server an open ended up at (XrdCl's ``LastURL``)."""
    host, _, port = endpoint.rpartition(":")
    return url.evolve(host=host.strip("[]"), port=int(port))


def _ask_config(url: XRootDURL, names: str, config: Config) -> str | None:
    """A ``kXR_Qconfig`` answer up to its first NUL, or ``None`` if the query failed."""
    fs = _import().FileSystem(url.without_query().with_path("/"), config)
    try:
        answer = bytes(fs.query(7, names))
    except Exception:
        return None
    finally:
        fs.close()
    return answer.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _atoi(text: str) -> int:
    """C's ``atoi`` after XrdCl's ``isdigit`` of the first character: leading digits, or 0."""
    count = len(text) - len(text.lstrip("0123456789"))
    return int(text[:count]) if count else 0


def _tpc_lite(answer: str | None) -> bool | None:
    """``XrdCl::Utils::CheckTPCLite``: no TPC (``None``), TPC (``False``), or TPC lite.

    The server answers each name on its line, echoing a name it has no value
    for; ``tpcdlg`` is set to the protocol whose credentials it forwards.
    """
    lines = [line for line in (answer or "").split("\n") if line]
    if not lines or not _atoi(lines[0]):
        return None
    return len(lines) > 1 and lines[1] != "tpcdlg"


def _tpc(answer: str | None) -> bool:
    """``XrdCl::Utils::CheckTPC``, including its refusal of a one-character answer."""
    return answer is not None and len(answer) != 1 and _atoi(answer) != 0


def _refused(exc: Exception) -> _CopyError:
    """The destination's open failing, as XrdCl reports it."""
    code, text = (
        (exc.code, exc.message) if isinstance(exc, _import().errors.ServerError) else (0, "")
    )
    if code == 3005 and "tpc not supported" in text:
        return _unsupported("Destination does not support third-party-copy.")
    return _CopyError(describe(exc), "destination", no_parent=code == 3011)


def _step(action: Callable[[], object], end: str, *handles: File) -> None:
    """One step of the rendezvous; on failure the open handles are closed, unheard."""
    try:
        action()
    except Exception as exc:
        for handle in handles:
            _quietly(handle.close)
        raise _CopyError(describe(exc), end) from exc


def _closed(handle: File, end: str) -> _CopyError | None:
    try:
        handle.close()
    except Exception as exc:
        return _CopyError(describe(exc), end)
    return None


def _quietly(action: Callable[[], object]) -> None:
    """A close whose outcome XrdCl ignores."""
    try:
        action()
    except Exception:
        pass


class _Verification:
    """The checksum part of XrdCl's copy job, as gfal2 configures it.

    ``source`` mode asks the source for its checksum, when no value was
    given, and compares it with nothing; ``target`` compares the
    destination's with the value given; ``both`` (``end2end``) compares it
    with the value given or, failing one, the source's. The value loses its
    leading zeros and its case first, and an algorithm left empty is
    ``[XROOTD PLUGIN] COPY_CHECKSUM_TYPE``. A mismatch is ``EILSEQ``, and no
    ``CHECKSUM`` event is sent.
    """

    def __init__(self, plugin: XRootDPlugin, transfer: Transfer) -> None:
        self.plugin = plugin
        self.transfer = transfer
        self.mode = transfer.checksum_mode
        self.algorithm = transfer.checksum_algorithm or plugin.checksum_type()
        self.expected = transfer.user_checksum.lstrip("0").lower()

    def before(self) -> None:
        if self.mode in (checksum_mode.source, checksum_mode.both) and not self.expected:
            self.expected = self._ask(self.transfer.source, "source")

    def after(self) -> None:
        if self.mode not in (checksum_mode.target, checksum_mode.both):
            return
        found = self._ask(self.transfer.destination, "destination")
        if self.expected and not checksums_match(self.expected, found):
            raise _CopyError(Failure(errno.EILSEQ, "[ERROR] CheckSum error", ""), "")

    def _ask(self, url: str, end: str) -> str:
        if not is_root(url):
            try:
                return str(self.plugin.context.checksum(url, self.algorithm))
            except GError as exc:
                raise _CopyError(
                    Failure(exc.code, "[ERROR] Local error", exc.message), end
                ) from exc
        wanted = _checksum_name(self.algorithm)
        try:
            answer = self.plugin._checksum_answer(url, wanted)
        except Exception as exc:
            failure = describe(exc)
            text = failure.to_str.rstrip("\n")
            newline = "\n" if failure.to_str.endswith("\n") else ""
            failure.to_str = f"{text} Got an error while querying the checksum!{newline}"
            raise _CopyError(failure, end) from exc
        try:
            return _checksum_value(answer, wanted)
        except GError as exc:
            raise _CopyError(
                Failure(exc.code, "[ERROR] Invalid response", exc.message), end
            ) from exc


#: ``kXR_write``'s request header: stream id, opcode, file handle, offset,
#: path id and three reserved bytes, then the payload length.
_WRITE_HEADER = struct.Struct(">HH4sqB3xI")
#: A response header: stream id, status, body length.
_RESPONSE_HEADER = struct.Struct(">HHI")
_KXR_WRITE, _KXR_OK, _KXR_ERROR, _KXR_WAIT = 3019, 0, 4003, 4005
_KXR_ATTN, _KXR_WAITRESP, _KXR_ASYNRESP, _KXR_QOPAQUG = 4001, 4006, 5008, 64


class _Upload:
    """A local file into an open ``root://`` handle, ``UPLOAD_DEPTH`` writes in flight.

    ``File.write`` is one request at a time, and copies each chunk four times
    on its way to the socket (a ``bytes`` of the slice, the frame, the send
    queue, the queue drained); for a large upload those copies and the wait
    per request are the whole cost. Here the handle's connection is borrowed
    the way xrdclient's own bulk reader borrows it - ``Session.bulk`` holds
    it idle and exclusive, stream ids are leased from its protocol machine -
    and each ``kXR_write`` goes out as a header and then the buffer itself,
    read straight from the file. One connection, one writer: what a stock
    xrootd admits. A second thread reads the file ahead of the sends, so
    the disk and the network are busy at once.

    The server answers each write ``kXR_ok``, ``kXR_error`` (the first one
    fails the upload, once every reply still owed is in) or ``kXR_wait``
    (that chunk is written again afterwards, the ordinary way, which knows
    how to wait). Anything else, or a connection that cannot be settled,
    marks the session broken so that nobody reuses it.
    """

    def __init__(
        self, transfer: Transfer, reader: PluginFile, writer: XRootDFile, handle: File
    ) -> None:
        self.transfer = transfer
        self.reader = reader
        self.writer = writer
        self.handle = handle
        self.session: Any = handle.session
        self.wire: Any = self.session.transport
        self.inflight: dict[int, tuple[int, int]] = {}
        self.free: list[int] = []
        self.again: list[tuple[int, int]] = []
        self.failure: Exception | None = None
        self.torn = False
        self.done = 0

    @staticmethod
    def usable(handle: File) -> bool:
        """Whether this connection can be borrowed so: unsigned, and the API is there."""
        session: Any = handle.session
        machine = getattr(session, "machine", None)
        return (
            getattr(machine, "signer", True) is None
            and all(hasattr(machine, name) for name in ("lease_sids", "release_sids"))
            and all(hasattr(session, name) for name in ("bulk", "transport", "mark_broken"))
            and len(handle.handle) == 4
        )

    def run(self) -> int:
        machine = self.session.machine
        with self.session.bulk(self.handle.handle, chunk=1, depth=1):
            leased = machine.lease_sids(UPLOAD_DEPTH)
            self.free = list(leased)
            try:
                self._stream()
            finally:
                if self._settle():
                    machine.release_sids(leased)
                else:
                    # A reply may still be in transit on these ids: keep them
                    # leased and the connection out of anyone else's hands.
                    self.session.mark_broken()
        if self.failure is not None:
            raise posix_error("Failed while writing to file", self.failure) from self.failure
        for offset, length in self.again:
            self.writer.pwrite(self.reader.pread(offset, length), offset)
            self._acked(length)
        self.transfer.progress(self.done, always=True)
        return self.done

    def _stream(self) -> None:
        """Send the file as it is read; a thread reads ahead while this one sends."""
        buffers: queue.Queue[bytearray] = queue.Queue()
        for _ in range(UPLOAD_BUFFERS):
            buffers.put(bytearray(UPLOAD_CHUNK))
        filled: queue.Queue[tuple[bytearray, int] | BaseException | None] = queue.Queue()
        stop = threading.Event()
        reader = threading.Thread(
            target=self._read, args=(buffers, filled, stop), name="xgfal-upload", daemon=True
        )
        reader.start()
        fhandle = self.handle.handle
        offset = 0
        try:
            while self.failure is None:
                if not self.free:
                    self._collect()
                    continue
                item = filled.get()
                if item is None:
                    break
                if isinstance(item, BaseException):
                    raise item
                buffer, count = item
                sid = self.free.pop()
                self.inflight[sid] = (offset, count)
                self.wire.send(_WRITE_HEADER.pack(sid, _KXR_WRITE, fhandle, offset, 0, count))
                self.wire.send(memoryview(buffer)[:count])
                buffers.put(buffer)  # sent is copied: the kernel has it now
                offset += count
                self.transfer.check()
            while self.inflight:
                self._collect()
        finally:
            stop.set()
            buffers.put(bytearray(0))  # a reader waiting for a buffer wakes to stop
            reader.join()

    def _read(
        self,
        buffers: queue.Queue[bytearray],
        filled: queue.Queue[tuple[bytearray, int] | BaseException | None],
        stop: threading.Event,
    ) -> None:
        try:
            while True:
                buffer = buffers.get()
                if stop.is_set():
                    return
                count = self.reader.readinto(buffer)
                if not count:
                    filled.put(None)
                    return
                filled.put((buffer, count))
        except BaseException as exc:  # handed to the sending thread to raise
            filled.put(exc)

    def _settle(self) -> bool:
        """Take every reply still owed off the wire; False if that cannot be done."""
        if self.torn:
            return False
        try:
            while self.inflight:
                self._collect()
        except Exception:
            return False
        return True

    def _collect(self) -> None:
        """One reply: its chunk is written, refused, or to be written again."""
        self.torn = True  # until a whole reply is in
        header = self._receive(_RESPONSE_HEADER.size)
        sid, status, length = _RESPONSE_HEADER.unpack(header)
        body = self._receive(length)
        self.torn = False
        span = self.inflight.pop(sid, None)
        if span is None or status not in (_KXR_OK, _KXR_ERROR, _KXR_WAIT):
            self.torn = True
            raise _import().errors.ProtocolError(
                f"unexpected reply to a write: stream {sid}, status {status}"
            )
        self.free.append(sid)
        if status == _KXR_OK:
            self._acked(span[1])
        elif status == _KXR_WAIT:
            self.again.append(span)
        elif self.failure is None:
            code = int.from_bytes(body[:4], "big")
            message = bytes(body[4:]).rstrip(b"\x00").decode("utf-8", "replace")
            try:
                _import().errors.raise_for_status(code, message, path=self.handle.url.path)
            except Exception as exc:
                self.failure = exc

    def _acked(self, count: int) -> None:
        self.done += count
        self.transfer.progress(self.done)

    def _receive(self, size: int) -> bytearray:
        return _receive(self.wire, size)


def _receive(wire: Any, size: int) -> bytearray:
    """Exactly ``size`` bytes off a borrowed connection."""
    buffer = bytearray(size)
    view = memoryview(buffer)
    got = 0
    while got < size:
        count = wire.receive_into(view[got:])
        if not count:
            raise _import().errors.ConnectionError("the server closed the connection")
        got += count
    return buffer


def _close_idle(
    idle: dict[tuple[str, int], list[tuple[float, FileSystem]]], lock: threading.Lock
) -> None:
    """Close every idle filesystem, which hands its connection to xrdclient's pool."""
    with lock:
        entries = [fs for kept in idle.values() for _, fs in kept]
        idle.clear()
    for fs in entries:
        fs.close()


def _checksum_name(algorithm: str) -> str:
    """gfal2's ``predefined_checksum_type_to_lower``: three names are lowered, others kept."""
    lower = algorithm.lower()
    return lower if lower in ("adler32", "crc32", "md5") else algorithm


def _checksum_value(answer: bytes, wanted: str) -> str:
    """The value in a ``kXR_Qcksum`` answer (``adler32 1a2b3c4d``), checked for its type."""
    text = answer.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
    kind, space, value = text.partition(" ")
    if not space:
        raise GError("Could not get the checksum (Wrong format)", errno.EIO)
    if kind.lower() != wanted.lower():
        raise GError(f"Got '{kind}' while expecting '{wanted}'", errno.EIO)
    return value.strip()


def _local_failure(exc: OSError) -> Failure:
    """A local file's ``OSError`` as XrdCl's ``errLocalError`` prints it."""
    code = exc.errno or errno.EIO
    return Failure(code, "[ERROR] Local error", "", f"[ERROR] Local error: {e2t(code)}: ")


def _is_sink(path: str) -> bool:
    """A device, FIFO or socket: written into, never created or removed."""
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return _stat.S_IFMT(mode) in (_stat.S_IFCHR, _stat.S_IFIFO, _stat.S_IFSOCK)


def _local_create(path: str, *, overwrite: bool) -> int:
    """A download's local file, its directory made; one already there needs ``overwrite``."""
    try:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except FileExistsError:
            pass  # a file where the directory should be: the open says ENOTDIR
        flags = os.O_WRONLY | os.O_CREAT
        if overwrite:
            return os.open(path, flags | os.O_TRUNC, 0o644)
        try:
            return os.open(path, flags | os.O_EXCL, 0o644)
        except FileExistsError:
            if not _is_sink(path):
                raise
            return os.open(path, os.O_WRONLY)
    except OSError as exc:
        raise _CopyError(_local_failure(exc), "destination") from exc


def _entries(fs: FileSystem, path: str, *, brief: bool) -> list[tuple[str, Brief]]:
    """Each entry's name and stat. One the server sent none for is stat'ed, as gfal2 does."""
    found = []
    for name, fields in _list(fs, path, brief=brief):
        if fields is None:
            try:
                info = fs.stat(f"{path.rstrip('/')}/{name}")
            except Exception as exc:
                raise status_error("Failed reading directory: ", exc, terse=True) from exc
            fields = (int(info.flags), info.st_size, info.st_mtime)
        found.append((name, fields))
    return found


def _list(fs: FileSystem, path: str, *, brief: bool) -> list[tuple[str, Brief | None]]:
    """A directory's entries, failing as gfal2's stat-then-list fails.

    gfal2 stats first, which is what turns a file into ``ENOTDIR`` rather
    than a listing error. The stat only matters when the listing does not
    already prove a directory, so it is made then and only then - after a
    refused listing, or an empty one - which saves a round trip per listing
    and says exactly what gfal2 says in every case.
    """
    refused: Exception | None = None
    entries: list[tuple[str, Brief | None]] = []
    try:
        entries = _dirlist(fs, path, brief=brief)
    except Exception as exc:
        refused = exc
    if entries:
        return entries
    info = fs.stat(path)
    if not int(info.flags) & _IS_DIR:
        code = errno.ENOTDIR
        raise GError(f"Not a directory ({os.strerror(code)})", code)
    if refused is not None:
        raise status_error("Failed to open dir: ", refused, terse=True) from refused
    return entries


def _dirlist(fs: FileSystem, path: str, *, brief: bool) -> list[tuple[str, Brief | None]]:
    """One ``kXR_dirlist`` with ``kXR_dstat``, sent and read as ``scandir`` would.

    The request goes through the filesystem's own router (redirects,
    retries, the CGI on the path) and only the parsing is done here; see
    :func:`parse_listing`. A filesystem without that router is asked
    through ``scandir``.
    """
    router = getattr(fs, "_router", None)
    if router is None:
        return [
            (entry.name, None if entry.stat is None else _brief(entry.stat))
            for entry in fs.scandir(path)
        ]
    target = fs.url.with_path(path).path_with_cgi
    request = _requests().Dirlist(target, _KXR_DSTAT)
    answer = router.execute(request, path=target)
    return parse_listing(bytes(answer.data), target, brief=brief)


def _brief(info: StatInfo) -> Brief:
    return int(info.flags), info.st_size, info.st_mtime


def _is_dir(fs: FileSystem, path: str) -> bool:
    try:
        return bool(int(fs.stat(path).flags) & _IS_DIR)
    except Exception:
        return False


def _rmdir_errno(fs: FileSystem, path: str, exc: BaseException) -> int:
    """gfal2's ``errno`` massaging after a failed ``rmdir``, for EOS's sake."""
    code = describe(exc).code
    if code == errno.EEXIST:
        return errno.ENOTEMPTY
    if code == errno.EIO:
        return errno.ENOTEMPTY if _is_dir(fs, path) else errno.ENOTDIR
    if code == errno.ENOENT:
        try:
            fs.stat(path)
        except Exception:
            return code
        return errno.ENOTDIR
    return code


def _vendor_error(url: str, description: str, exc: BaseException) -> GError:
    """A link operation's failure; no such opcode means no such operation, as in gfal2."""
    from xrdclient import errors as xe

    if isinstance(exc, xe.ServerError) and exc.code in _NO_SUCH_REQUEST:
        return not_supported_url(url)
    return posix_error(description, exc)


def _each(urls: Sequence[str], failure: Failure) -> list[GError | None]:
    return [GError(failure.to_string, failure.code) for _ in urls]


def _truth(value: object) -> bool:
    """``json_obj_to_bool``: only the string ``true``, in any case, is true."""
    if value is None:
        return False
    text = json.dumps(value) if not isinstance(value, str) else value
    return text.lower() == "true"


def parse_prepare_status(
    text: str, token: str, paths: Sequence[str], *, archive: bool
) -> list[StagingResult]:
    """One result per path from a ``kXR_QPrep`` answer, judged as gfal2 judges it.

    ``True`` is online (or, for ``archive``, safely on tape), ``False`` still
    waiting, and a ``GError`` whatever went wrong for that file. The checks,
    their order and their wording are gfal2's
    ``gfal_xrootd_bring_online_poll_list`` and ``..._archive_poll_list``.
    """
    count = len(paths)
    try:
        document = json.loads(text)
    except ValueError:
        document = None
    if not isinstance(document, dict):
        return _all(count, f"Response from server is an invalid JSON: {text}")
    if str(document.get("request_id") or "") != token:
        return _all(count, "Request ID mismatch.")
    responses = document.get("responses")
    if not isinstance(responses, list) or len(responses) != count:
        verb = "doest not" if archive else "does not"
        return _all(count, f"Number of files in the request {verb} match!")
    wanted = set(paths)
    return [_judge(entry, wanted, token, text, archive=archive) for entry in responses]


def _all(count: int, message: str) -> list[StagingResult]:
    return [GError(message, errno.ENOMSG) for _ in range(count)]


def _poll_error(code: int, message: str, reason: str) -> GError:
    """``gfal2_xrootd_poll_set_error``: the server's own text appended as the reason."""
    return GError(f"{message} (reason: {reason})" if reason else message, code)


def _judge(
    entry: object, wanted: set[str], token: str, text: str, *, archive: bool
) -> StagingResult:
    if not isinstance(entry, dict):
        return GError(f"Failed to parse responses JSON from server: {text}", errno.ENOMSG)
    if "error_text" not in entry:
        return GError("Error attribute missing.", errno.ENOMSG)
    reason = str(entry["error_text"] or "")
    path = collapse_slashes(str(entry.get("path") or ""))
    if not path or path not in wanted:
        return _poll_error(errno.ENOMSG, f"Wrong path: {path}", reason)
    exists = _truth(entry.get("path_exists")) or (
        not archive and _truth(entry.get("exists"))  # CTA's older spelling
    )
    if not exists:
        return _poll_error(errno.ENOENT, f"File does not exist: {path}", reason)
    if archive:
        if _truth(entry.get("on_tape")):
            return True
        return GError(reason, errno.ENOMSG) if reason else False
    if _truth(entry.get("online")):
        return True
    if not _truth(entry.get("requested")):
        return _poll_error(errno.ENOMSG, f"File is not being brought online: {path}", reason)
    if not _truth(entry.get("has_reqid")):
        return _poll_error(
            errno.ENOMSG,
            f"File ({path}) is not included in the bring online request: {token}",
            reason,
        )
    if not str(entry.get("req_time") or ""):
        return _poll_error(errno.ENOMSG, "Bring-online timestamp missing.", reason)
    if reason:
        return GError(reason, errno.ENOMSG)
    return False
