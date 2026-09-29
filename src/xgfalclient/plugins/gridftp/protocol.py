"""The GridFTP wire, minus the sockets: replies, addresses, facts and blocks.

Everything here is a pure function of bytes or text, so the control and
data channels, the plugin and the in-process test server share one reading
of the protocol:

* **replies** (RFC 959 §4.2): a three-digit code, optionally multi-line
  (``213-`` ... ``213 End``), and gfal2's translation of a failure into an
  ``errno``, which it makes from the reply *text* first and the code second
  because servers use 550 for everything;
* **addresses**: ``PASV``'s ``h1,h2,h3,h4,p1,p2``, ``EPSV``'s ``(|||port|)``,
  and ``SPAS``'s one-address-per-line striped form;
* **facts** (RFC 3659): the ``type=file;size=12;modify=...; name`` lines of
  ``MLST``/``MLSD``, turned into :class:`~xgfalclient.types.Stat`;
* **extended blocks** (GFD.020 ``MODE E``): a 17-byte header - descriptor,
  byte count, file offset - in front of every block. The end of a transfer
  is an ``EOF`` block whose *offset* field carries the number of ``EOD``
  blocks to expect, one per data connection; globus folds ``EOF`` and
  ``EOD`` into one ``0x48`` block on the last connection.
"""

from __future__ import annotations

import calendar
import errno
import ipaddress
import re
import stat as _stat
import struct
import time

from ...errors import ECOMM, GError
from ...types import Stat

__all__ = [
    "Reply",
    "errno_for_reply",
    "reply_error",
    "parse_pasv",
    "parse_epsv",
    "parse_spas",
    "format_port",
    "format_eprt",
    "parse_facts",
    "stat_from_facts",
    "format_mdtm",
    "parse_mdtm",
    "parse_perf_marker",
    "BLOCK_HEADER",
    "DESC_EOD",
    "DESC_EOF",
    "DESC_CLOSE",
    "check_path",
    "passive_address",
]

#: ``MODE E`` block header: descriptor, count, offset - all big-endian.
BLOCK_HEADER = struct.Struct(">BQQ")
DESC_EOF = 0x40
DESC_EOD = 0x08
DESC_CLOSE = 0x04


class Reply:
    """One (possibly multi-line) FTP reply."""

    __slots__ = ("code", "lines")

    def __init__(self, code: int, lines: list[str]) -> None:
        self.code = code
        self.lines = lines

    @property
    def kind(self) -> int:
        """The first digit: 1 preliminary, 2 done, 3 more needed, 4/5 failed."""
        return self.code // 100

    @property
    def text(self) -> str:
        """The reply with the code prefixes taken off, one line per line."""
        out = []
        for line in self.lines:
            if line[:3] == str(self.code) and line[3:4] in ("-", " ", ""):
                line = line[4:]
            out.append(line.strip())
        return "\n".join(part for part in out if part)

    def __str__(self) -> str:
        return f"{self.code} {self.text}"

    def __repr__(self) -> str:
        return f"Reply({self.code}, {self.lines!r})"


#: Reply text to ``errno``: gfal2's ``scan_errstring``, in its order and case.
_TEXT_ERRNO = (
    ("No such file", errno.ENOENT),
    ("not found", errno.ENOENT),
    ("error 3011", errno.ENOENT),
    ("Permission denied", errno.EACCES),
    ("credential", errno.EACCES),
    ("exists", errno.EEXIST),
    ("error 3006", errno.EEXIST),
    ("Not a direct", errno.ENOTDIR),
    ("Operation not supported", errno.ENOTSUP),
    ("Login incorrect", errno.EACCES),
    ("Could not get virtual id", errno.EACCES),
    ("the operation was aborted", errno.ECANCELED),
    ("Is a directory", errno.EISDIR),
    ("isk quota exceeded", errno.EDQUOT),
)


def errno_for_reply(text: str) -> int:
    """The ``errno`` a failure stands for, from its text alone; ``ECOMM`` otherwise.

    gfal2 ignores the reply code - servers answer 550 for everything, and
    globus even reports "Directory not empty" as 451 - so this does too.
    """
    for needle, value in _TEXT_ERRNO:
        if needle in text:
            return value
    return ECOMM


def reply_error(reply: Reply) -> GError:
    """A failure reply as gfal2 reports it, spacing included.

    globus_ftp_client quotes a one-line reply after its code and a
    multi-line one whole, with every CR and LF turned into a space::

        ... an error 550 550-GlobusError: v=1 c=PATH_NOT_FOUND  550-... 550 End.
    """
    lines = reply.lines if len(reply.lines) > 1 else [reply.lines[0][4:]]
    body = "".join(f"{line}  " for line in lines)
    return GError(
        f"globus_ftp_client: the server responded with an error {reply.code} {body} ",
        errno_for_reply(body),
    )


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

_PASV = re.compile(r"(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})")
_EPSV = re.compile(r"\((.)(\d?)\1([^|()]*)\1(\d+)\1\)")


def _protocol_error(what: str, text: str) -> GError:
    return GError(f"Could not parse the {what} reply: {text!r}", errno.EPROTO)


def parse_pasv(text: str) -> tuple[str, int]:
    """``227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`` to ``(host, port)``."""
    found = _PASV.search(text)
    if found is None:
        raise _protocol_error("PASV", text)
    parts = [int(value) for value in found.groups()]
    return ".".join(str(part) for part in parts[:4]), parts[4] * 256 + parts[5]


def parse_epsv(text: str) -> tuple[str, int]:
    """``229 ... (|||port|)`` or ``(|2|::1|port|)`` to ``(host or "", port)``."""
    found = _EPSV.search(text)
    if found is None:
        raise _protocol_error("EPSV", text)
    return found.group(3), int(found.group(4))


def parse_spas(lines: list[str]) -> list[tuple[str, int]]:
    """The stripes of a ``229-`` multi-line ``SPAS`` reply, in order."""
    found = [parse_pasv(line) for line in lines if _PASV.search(line)]
    if not found:
        raise _protocol_error("SPAS", "\n".join(lines))
    return found


_EVENT_27 = re.compile(
    r"[12]27 [^\[0-9]+\(?([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)\)?", re.IGNORECASE
)
_EVENT_29_V6 = re.compile(r"\|([0-9]*)\|([^|]*)\|([0-9]+)\|")
_EVENT_29_V4 = re.compile(r"([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)")


def _dotted(found: re.Match[str]) -> tuple[str, int]:
    parts = [int(value) for value in found.groups()]
    return ".".join(str(part) for part in parts[:4]), parts[4] * 256 + parts[5]


def passive_address(reply: Reply) -> tuple[str, int, bool] | None:
    """``(ip, port, is_ipv6)`` a passive reply announces, read as gfal2's PASV plugin reads it.

    ``1xx``/``2xx`` replies ending ``27`` (``PASV``, delayed ``127``) and
    ``29`` (``EPSV``, ``SPAS``) count; an ``EPSV`` reply names no address,
    so ``ip`` is ``""`` and the caller looks the host up. gfal2 misreads the
    ``h1,h2,...`` form of a ``229`` (it shifts the numbers by one); this
    reads it correctly.
    """
    if reply.kind not in (1, 2):
        return None
    text = "\r\n".join(reply.lines)
    if reply.code % 100 == 27:
        found = _EVENT_27.search(text)
        if found is None:
            return None
        return (*_dotted(found), False)
    if reply.code % 100 != 29:
        return None
    extended = _EVENT_29_V6.search(text)
    if extended is not None:
        ipv6 = extended.group(1) == "2"
        ip = extended.group(2)
        return (f"[{ip}]" if ipv6 and ip else ip), int(extended.group(3)), ipv6
    found = _EVENT_29_V4.search(text)
    return None if found is None else (*_dotted(found), False)


def format_port(host: str, port: int) -> str:
    """``PORT``'s argument: ``h1,h2,h3,h4,p1,p2``."""
    return ",".join([*host.split("."), str(port // 256), str(port % 256)])


def format_eprt(host: str, port: int) -> str:
    """``EPRT``'s argument: ``|1|host|port|`` or ``|2|host|port|``."""
    family = 2 if ipaddress.ip_address(host).version == 6 else 1
    return f"|{family}|{host}|{port}|"


# ---------------------------------------------------------------------------
# Facts
# ---------------------------------------------------------------------------


def parse_facts(line: str) -> tuple[dict[str, str], str]:
    """``type=file;size=3; name`` to ``({"type": "file", ...}, "name")``.

    Fact names are case-insensitive (RFC 3659 §7.5), so they are lowered.
    A line with no facts is just a name.
    """
    head, sep, name = line.partition(" ")
    if not sep or "=" not in head:
        return {}, line.strip()
    facts: dict[str, str] = {}
    for item in head.split(";"):
        key, eq, value = item.partition("=")
        if eq:
            facts[key.strip().lower()] = value
    return facts, name


def parse_mdtm(value: str) -> int:
    """``YYYYMMDDHHMMSS[.sss]`` (UTC) to a Unix time; 0 if unreadable."""
    digits = value.strip().split(".")[0]
    try:
        return calendar.timegm(time.strptime(digits, "%Y%m%d%H%M%S"))
    except ValueError:
        return 0


def format_mdtm(when: float) -> str:
    return time.strftime("%Y%m%d%H%M%S", time.gmtime(when))


def _integer(value: str, base: int = 10) -> int:
    try:
        return int(value, base)
    except ValueError:
        return 0


def stat_from_facts(facts: dict[str, str]) -> Stat:
    """What gfal2 fills from MLST facts: type, size, mtime, mode, owner.

    Like gfal2, ``atime``, ``ctime`` and ``ino`` stay zero and ``nlink`` is 1.
    """
    kind = facts.get("type", "").lower()
    if kind in ("dir", "cdir", "pdir"):
        mode = _stat.S_IFDIR
    elif kind.startswith("os.unix=slink") or kind.startswith("os.unix=symlink"):
        mode = _stat.S_IFLNK
    else:
        mode = _stat.S_IFREG
    mode |= _integer(facts.get("unix.mode", "0"), 8) & 0o7777
    return Stat(
        st_mode=mode,
        st_size=_integer(facts.get("size", "0")),
        st_uid=_integer(facts.get("unix.uid", "0")),
        st_gid=_integer(facts.get("unix.gid", "0")),
        st_nlink=1,
        st_mtime=parse_mdtm(facts.get("modify", "")),
    )


# ---------------------------------------------------------------------------
# Markers
# ---------------------------------------------------------------------------


def parse_perf_marker(reply: Reply) -> tuple[int, int] | None:
    """``(stripe index, bytes)`` from a ``112`` performance marker."""
    if reply.code != 112:
        return None
    index, count = 0, None
    for line in reply.text.splitlines():
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key == "stripe index":
            index = _integer(value.strip())
        elif key == "stripe bytes transferred":
            count = _integer(value.strip())
    return None if count is None else (index, count)


def check_path(path: str) -> str:
    """Refuse a path that would smuggle a second command onto the control line."""
    if "\r" in path or "\n" in path:
        raise GError(f"Invalid path {path!r}", errno.EINVAL)
    return path
