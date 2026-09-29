"""The dcap wire format: control lines, data-channel blocks, URLs and errors.

dcap is dCache's native protocol, as ``libdcap`` speaks it and gfal2's dcap
plugin drives it. Two channels:

* **control**, to the door (22125 plain, 22128 GSI, 22725 Kerberos): ASCII
  lines ``<session> <command-id> <partner> <verb> [args...]``. The client
  says ``0 0 client hello 0 0 2 47 14 "" -uid=... -pid=... -gid=...`` and the
  door answers ``0 0 server welcome 2 47``; after that every request gets a
  fresh session number and the door's answer carries it back
  (``7 0 client stat -st_size=12 -st_mode=-rw-r--r-- ...``,
  ``7 0 client ok``, ``7 0 client failed 10001 "No such file or directory"
  ENOENT``). Arguments are blank-separated and ``"``-quoted; options are
  ``-key=value``.
* **data**, to a pool mover: big-endian binary requests ``[length][command]
  [arguments]`` answered by ``[length][ACK][command][result]...``; a read's
  bytes follow as ``[DATA]`` then ``[n][n bytes]...`` blocks ended by ``-1``
  and a ``[FIN]``; a write sends its blocks the same way.

Everything here is pure: no sockets. The client (:mod:`.control`,
:mod:`.file`) and the in-process test server (``xgfalclient.testing.dcap``)
share it, so they cannot drift apart.

Sources: libdcap (``dcap.c``, ``dcap_interpreter.c``, ``dcap_command.c``,
``string2stat.c``, ``str2errno.c``, ``dcap_url.c``, ``dcap_read.c``,
``dcap_write.c``, ``dcap_close.c``) and dCache's door and mover
(``DCapDoorInterpreterV3``, ``DCapProtocol_3_nio``, ``DCapOutputByteBuffer``,
``DirectoryLookUpPool``).
"""

from __future__ import annotations

import errno
import re
import stat as _stat
import struct
from dataclasses import dataclass

from ..._compat import SLOTS
from ...errors import GError
from ...types import Stat
from ...url import parse as parse_url_parts

__all__ = [
    "DEFAULT_PORTS",
    "SCHEMES",
    "VERSION",
    "DcapURL",
    "Reply",
    "parse_url",
    "encode_path",
    "tokenize",
    "quote",
    "parse_reply",
    "options",
    "parse_stat",
    "stat_fields",
    "mode_string",
    "error_code",
    "IOCMD_WRITE",
    "IOCMD_READ",
    "IOCMD_SEEK",
    "IOCMD_CLOSE",
    "IOCMD_ACK",
    "IOCMD_FIN",
    "IOCMD_DATA",
    "IOCMD_LOCATE",
    "IOCMD_SEEK_READ",
    "IOCMD_SEEK_WRITE",
    "SEEK_SET",
    "SEEK_CURRENT",
    "SEEK_END",
    "DATA_SUM",
    "ADLER32",
    "INT",
    "HEADER",
]

#: The dcap schemes and their door ports (``dcap.net.port.*`` in dCache).
DEFAULT_PORTS = {"dcap": 22125, "gsidcap": 22128, "kdcap": 22725}
SCHEMES = tuple(DEFAULT_PORTS)

#: The libdcap release this client presents itself as in ``hello``:
#: protocol 2, library 47.14 (dcap 2.47.14, what EL9 ships).
VERSION = (2, 47, 14)

# Data-channel commands (dcap_protocol.h / DCapConstants).
IOCMD_WRITE = 1
IOCMD_READ = 2
IOCMD_SEEK = 3
IOCMD_CLOSE = 4
IOCMD_ACK = 6
IOCMD_FIN = 7
IOCMD_DATA = 8
IOCMD_LOCATE = 9
IOCMD_SEEK_READ = 11
IOCMD_SEEK_WRITE = 12

SEEK_SET = 0
SEEK_CURRENT = 1
SEEK_END = 2

#: A close block carrying a checksum, and the one checksum type libdcap sends.
DATA_SUM = 1
ADLER32 = 1

INT = struct.Struct(">i")
#: ``[length][command]`` - the start of every data-channel message.
HEADER = struct.Struct(">ii")


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------


@dataclass(frozen=True, **SLOTS)
class DcapURL:
    """A dcap URL in the parts the protocol needs."""

    scheme: str
    host: str
    port: int
    #: The path exactly as written (not percent-decoded), with its leading ``/``.
    path: str

    @property
    def prefix(self) -> str:
        """The tunnel prefix libdcap derives from the scheme: ``gsi``, ``k`` or none."""
        return self.scheme[: -len("dcap")]

    @property
    def netloc(self) -> str:
        return f"[{self.host}]" if ":" in self.host else self.host

    def wire(self) -> str:
        """The name the door is given, as libdcap's ``get_url_string`` builds it.

        The port is dropped (the door does not care), the path loses one
        leading ``/`` and is percent-encoded, and the scheme keeps its tunnel
        prefix: ``gsidcap://se.example.org:22128/pnfs/a b`` becomes
        ``gsidcap://se.example.org/pnfs/a%20b``. The door decodes it with
        ``java.net.URI``. libdcap writes an IPv6 host without brackets, which
        ``URI`` cannot parse; brackets are kept here.
        """
        return f"{self.scheme}://{self.netloc}/{encode_path(self.path[1:])}"

    def url(self, path: str) -> str:
        """Another path on the same door, as a URL."""
        return f"{self.scheme}://{self.netloc}:{self.port}{path}"


def parse_url(url: str) -> DcapURL:
    """Split a ``dcap``/``gsidcap``/``kdcap`` URL; ``EINVAL`` if it has no host or path.

    libdcap also accepts ``dcap:///pnfs/<domain>/...`` and turns the domain
    into a door called ``dcache.<domain>``; that convention predates DNS
    aliases and nobody passes such URLs to gfal2, so it is refused.
    """
    parts = parse_url_parts(url)
    scheme = parts.scheme
    if not url.startswith(scheme):
        # gfal2 claims DCAP:// (its check ignores case) and libdcap refuses it.
        raise GError(
            "Error reported by the external library dcap : Not valid DCAP url, number : 32",
            errno.EINVAL,
        )
    # Everything after the authority is the name, '?' and '#' included, as in libdcap.
    path = url[len(scheme) + 3 + len(parts.netloc) :]
    host = parts.host
    if scheme not in DEFAULT_PORTS or not host or not path.startswith("/"):
        raise GError(f"Invalid dcap URL: {url}", errno.EINVAL)
    if "\n" in path or '"' in path:
        # libdcap's name_invalid(): both would break the control line.
        raise GError(f"Invalid dcap URL (newline or quote in the path): {url}", errno.EINVAL)
    return DcapURL(scheme, host, parts.port or DEFAULT_PORTS[scheme], path)


_UNRESERVED = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~/")


def encode_path(path: str) -> str:
    """libdcap's ``url_encode``: ASCII letters, digits and ``-_.~/`` stay, the rest is ``%XX``."""
    data = path.encode("utf-8", "surrogateescape")
    if all(byte in _UNRESERVED for byte in data):
        return path
    return "".join(chr(byte) if byte in _UNRESERVED else f"%{byte:02X}" for byte in data)


# ---------------------------------------------------------------------------
# Control lines
# ---------------------------------------------------------------------------


_TOKEN = re.compile(r'(?:"[^"]*"?|[^\s"])+')


def tokenize(line: str) -> list[str]:
    """Split a control line on blanks, honouring (and removing) double quotes.

    This is dCache's ``Args`` and libdcap's ``inputParser``: a quote toggles
    quoting anywhere in a token, so ``-truncate="a b"`` is one token,
    ``-truncate=a b``. There is no escape character; nothing on either side
    sends one.
    """
    if '"' not in line:
        return line.split()
    return [token.replace('"', "") for token in _TOKEN.findall(line)]


def quote(value: str) -> str:
    """``value`` as one control-line argument."""
    return f'"{value}"'


@dataclass(frozen=True, **SLOTS)
class Reply:
    """One line from the door: ``<session> <id> <partner> <verb> <args...>``."""

    session: int
    command_id: int
    verb: str
    args: tuple[str, ...]

    def option(self, key: str) -> str | None:
        return options(self.args).get(key)


def parse_reply(line: str) -> Reply | None:
    """A reply, or ``None`` for a line libdcap would drop (too short, not numbered)."""
    tokens = tokenize(line)
    if len(tokens) < 4:
        return None
    try:
        session, command_id = int(tokens[0]), int(tokens[1])
    except ValueError:
        return None
    return Reply(session, command_id, tokens[3], tuple(tokens[4:]))


def options(args: tuple[str, ...] | list[str]) -> dict[str, str]:
    """The ``-key=value`` (and bare ``-key``) arguments of a line."""
    found: dict[str, str] = {}
    for arg in args:
        if arg.startswith("-") and len(arg) > 1:
            key, _, value = arg[1:].partition("=")
            found[key] = value
    return found


# ---------------------------------------------------------------------------
# stat
# ---------------------------------------------------------------------------

_TYPES = {"-": _stat.S_IFREG, "d": _stat.S_IFDIR, "l": _stat.S_IFLNK, "x": _stat.S_IFCHR}
_PERMISSIONS = (
    (_stat.S_IRUSR, "r"),
    (_stat.S_IWUSR, "w"),
    (_stat.S_IXUSR, "x"),
    (_stat.S_IRGRP, "r"),
    (_stat.S_IWGRP, "w"),
    (_stat.S_IXGRP, "x"),
    (_stat.S_IROTH, "r"),
    (_stat.S_IWOTH, "w"),
    (_stat.S_IXOTH, "x"),
)


def _parse_mode(text: str) -> int:
    """libdcap's ``string2mode``: ``drwxr-xr-x`` to ``st_mode``; 0 if too short."""
    if len(text) < 10:
        return 0
    mode = _TYPES.get(text[0], _stat.S_IFIFO)
    for index, (bit, letter) in enumerate(_PERMISSIONS, start=1):
        if text[index] == letter:
            mode |= bit
    return mode


def mode_string(mode: int) -> str:
    """The door's ``-st_mode`` value for ``mode`` (the inverse of :func:`_parse_mode`)."""
    if _stat.S_ISDIR(mode):
        kind = "d"
    elif _stat.S_ISLNK(mode):
        kind = "l"
    elif _stat.S_ISREG(mode):
        kind = "-"
    else:
        kind = "x"
    return kind + "".join(letter if mode & bit else "-" for bit, letter in _PERMISSIONS)


_STAT_KEYS = ("st_dev", "st_ino", "st_nlink", "st_uid", "st_gid", "st_size")
_TIME_KEYS = ("st_atime", "st_mtime", "st_ctime")


def parse_stat(args: tuple[str, ...]) -> Stat:
    """A ``stat`` reply's ``-st_*=`` options as a :class:`~xgfalclient.types.Stat`."""
    fields = options(args)
    values: dict[str, int] = {}
    for key in (*_STAT_KEYS, *_TIME_KEYS):
        if key in fields:
            try:
                values[key] = int(fields[key])
            except ValueError:
                values[key] = 0  # libdcap's atoi() makes nonsense zero
    if "st_mode" in fields:
        values["st_mode"] = _parse_mode(fields["st_mode"])
    return Stat(**values)


def stat_fields(info: Stat) -> str:
    """The door's ``stat`` reply arguments for ``info`` (the test server's side)."""
    return (
        f"-st_size={info.st_size} -st_uid={info.st_uid} -st_gid={info.st_gid} "
        f"-st_atime={info.st_atime} -st_mtime={info.st_mtime} -st_ctime={info.st_ctime} "
        f"-st_mode={mode_string(info.st_mode)} -st_ino={info.st_ino}"
    )


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def error_code(args: tuple[str, ...]) -> int:
    """The ``errno`` gfal2 reports for a door's ``failed <rc> "<message>" [ERRNO]``.

    libdcap sets ``errno`` from the POSIX name when the door sends one
    (``str2errno``; unknown names are ``EIO``) and to ``EIO`` when it does
    not. gfal2's dcap plugin then patches the common cases the door leaves
    vague (``dcap_errno_conversion``): an ``EIO`` whose text says "no such"
    is ``ENOENT``, and an ``EACCES`` about a non-empty directory is
    ``ENOTEMPTY``.
    """
    message = args[1] if len(args) > 1 else ""
    name = args[2] if len(args) > 2 else ""
    code = getattr(errno, name, errno.EIO) if name.startswith("E") else errno.EIO
    if code == errno.EIO and "o such" in message:
        return errno.ENOENT
    if code == errno.EACCES and "ectory not empty" in message:
        return errno.ENOTEMPTY
    return int(code)
