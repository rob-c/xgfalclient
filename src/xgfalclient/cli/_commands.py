"""The single-operation commands: mkdir, save, cat, xattr, sum, stat, rename, chmod, token.

Output formats and messages are gfal2-util 1.9.1's (Apache-2.0, (c) CERN),
reimplemented.

Each command is a function of the :class:`~._base.Command` (parsed options in
``cmd.params``, the context in ``cmd.context``) and a :class:`~._base.Spec`
in :data:`SPECS` holding its help text and arguments. The help strings,
gfal2-util's typos included (``mkdir -m``'s "display hidden files"), are
reproduced verbatim: they are the generated man pages' source too. A command
raises ``GError`` to fail; :func:`~._base.main` prints it and exits with
its errno.
"""

from __future__ import annotations

import contextlib
import stat
import sys
from datetime import datetime

from ..errors import GError
from ._base import Command, Spec, arg, out, output, stat_record, surl
from ._utils import file_mode_str, file_type_str

__all__ = ["SPECS"]

#: Bytes per read for ``gfal-cat`` and ``gfal-save``: large enough that a
#: remote protocol's per-request cost is amortised, small enough to stream.
CHUNK = 1 << 20


def mkdir(cmd: Command) -> None:
    """``gfal-mkdir [-p] [-m MODE] DIR...``: each directory in turn, the first failure ending it.

    ``-m`` is parsed by argparse as a *decimal* int (default 755) and then
    read back as octal digits, as gfal2-util does; that is why ``-m 0700``
    works and ``-m 8`` silently gives 0755.
    """
    mode = 0o755
    if cmd.params.mode:
        # -m 999: gfal2-util falls back to 0755 without a word
        with contextlib.suppress(ValueError):
            mode = int(str(cmd.params.mode), 8)
    for directory in cmd.params.directory:
        output.identify("mkdir", url=directory)
        if cmd.params.parents:
            cmd.context.mkdir_rec(directory, mode)
        else:
            cmd.context.mkdir(directory, mode)
        output.record(status="succeeded", mode=mode)


def save(cmd: Command) -> None:
    """``gfal-save URL``: stdin to a (new or truncated) remote file, in :data:`CHUNK` writes.

    The file is closed even on failure; for protocols that commit at close
    (HTTP), a failed upload is reported from there.
    """
    # Bytes from stdin untouched, as cat writes them: gfal2-util's text-mode
    # read dies on input that is not UTF-8 (UnicodeEncodeError, empty file).
    output.identify("save", url=cmd.params.file)
    handle = cmd.context.open(cmd.params.file, "w")
    received = 0
    try:
        while True:
            data = sys.stdin.buffer.read(CHUNK)
            if not data:
                break
            handle.write(data)
            received += len(data)
    finally:
        handle.close()
    output.record(status="succeeded", bytes_read=received)


def cat(cmd: Command) -> None:
    """``gfal-cat URL...``: each file's bytes to stdout, in order.

    Python's text stdout is flushed first so that earlier text output is
    not overtaken by bytes written to the buffer underneath.
    """
    # The bytes go to stdout untouched, with or without -b: gfal2-util's text
    # mode decodes each chunk on its own and chokes on binary data, or on a
    # character split across two reads.
    sys.stdout.flush()
    for name in cmd.params.file:
        output.identify("cat", url=name)
        handle = cmd.context.open(name, "r")
        try:
            while True:
                data = handle.read_bytes(CHUNK)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
        finally:
            handle.close()
        output.record(status="succeeded")


def xattr(cmd: Command) -> None:
    """``gfal-xattr URL [NAME | NAME=VALUE]``: list all, get one, or set one.

    Listing prints ``name = value`` per attribute and ``name FAILED: ...``
    for one that cannot be read, carrying on (gfal2-util's behaviour: one
    unreadable attribute must not hide the rest). A ``NAME=`` or ``=VALUE``
    with an empty side is silently ignored, as in gfal2-util.
    """
    path, attribute = cmd.params.file, cmd.params.attribute
    output.identify("xattr", url=path, attribute=attribute)
    if attribute is not None:
        if "=" in attribute:
            name, _, value = attribute.partition("=")
            if name and value:
                cmd.context.setxattr(path, name, value, 0)
                output.record(status="succeeded", name=name)
        else:
            value = cmd.context.getxattr(path, attribute)
            output.record(status="succeeded", name=attribute, value=value)
            out(value + "\n")
        return
    for name in cmd.context.listxattr(path):
        try:
            value = cmd.context.getxattr(path, name)
            output.record(status="succeeded", name=name, value=value)
            out(f"{name} = {value}\n")
        except GError as exc:
            output.error(exc, name=name)
            out(f"{name} FAILED: {exc}\n")


def checksum(cmd: Command) -> None:
    """``gfal-sum URL ALGORITHM``: prints ``URL VALUE`` (the URL as given, after ``surl``)."""
    output.identify("checksum", url=cmd.params.file)
    value = cmd.context.checksum(cmd.params.file, cmd.params.checksum_type)
    output.record(status="succeeded", algorithm=cmd.params.checksum_type, value=value)
    out(f"{cmd.params.file} {value}\n")


def _time(stamp: int) -> str:
    """A ``gfal-stat`` time: local time with microseconds, which are always ``.000000``.

    gfal2-util formats ``datetime.fromtimestamp`` of an integer, and scripts
    parse that exact shape.
    """
    return datetime.fromtimestamp(stamp).strftime("%Y-%m-%d %H:%M:%S.%f")


def stat_(cmd: Command) -> None:
    """``gfal-stat URL``: GNU ``stat``-like lines, in gfal2-util's exact layout.

    The tabs, the trailing tab after ``Gid``, the quoted file name and the
    mode as ``(0644/-rw-r--r--)`` are all gfal2-util's; scripts cut on them.
    """
    output.identify("stat", url=cmd.params.file)
    info = cmd.context.stat(cmd.params.file)
    output.record(status="succeeded", value=stat_record(info))
    mode = info.st_mode
    out(
        f"  File: '{cmd.params.file}'\n"
        f"  Size: {info.st_size}\t{file_type_str(stat.S_IFMT(mode))}\n"
        f"Access: ({stat.S_IMODE(mode):04o}/{file_mode_str(mode)})\t"
        f"Uid: {info.st_uid}\tGid: {info.st_gid}\t\n"
        f"Access: {_time(info.st_atime)}\n"
        f"Modify: {_time(info.st_mtime)}\n"
        f"Change: {_time(info.st_ctime)}\n"
    )


def rename(cmd: Command) -> None:
    """``gfal-rename SOURCE DESTINATION``: one ``rename``, nothing printed on success."""
    output.identify("rename", source=cmd.params.source, target=cmd.params.destination)
    cmd.context.rename(cmd.params.source, cmd.params.destination)
    output.record(status="succeeded")


def chmod(cmd: Command) -> None:
    """``gfal-chmod MODE URL``: ``MODE`` must be octal digits, else a usage error (status 2)."""
    output.identify("chmod", url=cmd.params.file)
    try:
        mode = int(cmd.params.mode, 8)
    except ValueError:
        cmd.parser.error("Mode must be an octal number (i.e. 0755)")
    cmd.context.chmod(cmd.params.file, mode)
    output.record(status="succeeded", mode=mode)


def token(cmd: Command) -> int:
    """``gfal-token URL [ACTIVITY...]``: print a storage-issued token (macaroon or SciToken).

    With activities, they are requested as given; otherwise ``-w`` picks
    the default write set and its absence the read set (the plugin decides
    what those are). A negative ``--validity`` is refused with gfal2-util's
    message and status 1 before anything is sent.
    """
    params = cmd.params
    output.identify("token", url=params.path)
    if params.validity < 0:
        output.error(ValueError("Token validity must be zero or greater"), code=1)
        output.message("Validity must be a number >= 0\n", stderr=True)
        return 1
    if params.verbose:
        if params.activities:
            out("Will use user-provided activities\n")
        else:
            kind = "write" if params.write_access else "read"
            out(f"Will use default activities for {kind} access\n")
    issuer = params.issuer if params.issuer is not None else ""
    access = params.activities if params.activities else params.write_access
    value = cmd.context.token_retrieve(params.path, issuer, params.validity, access)
    output.record(status="succeeded", value=value)
    out(value + "\n")
    return 0


SPECS = {
    "mkdir": Spec(
        "mkdir",
        "Makes directories. By default, it sets file mode 0755.",
        [
            arg("-m", "--mode", action="store", type=int, default=755, help="display hidden files"),
            arg(
                "-p",
                "--parents",
                action="store_true",
                help="no error if existing, make parent directories as needed",
            ),
            arg("directory", action="store", nargs="+", type=surl, help="Directory's uri"),
        ],
        mkdir,
    ),
    "save": Spec(
        "save",
        "Reads from stdin and writes to a file. If the file exists, it will be overwritten",
        [arg("file", action="store", type=surl, help="uri of the file to be written")],
        save,
    ),
    "cat": Spec(
        "cat",
        "Sends to stdout the contents of files",
        [
            arg(
                "-b",
                "--bytes",
                action="store_true",
                help="handle file contents as bytes (only in Python3)",
            ),
            arg(
                "file",
                action="store",
                nargs="+",
                type=surl,
                help="uri of the file to be displayed",
            ),
        ],
        cat,
    ),
    "xattr": Spec(
        "xattr",
        "Gets or set the extended attributes of files and directories",
        [
            arg("file", action="store", type=surl, help="file uri"),
            arg(
                "attribute",
                nargs="?",
                type=str,
                help="attribute to retrieve or set. To set, use key=value",
            ),
        ],
        xattr,
    ),
    "sum": Spec(
        "sum",
        "Calculates the checksum of a file",
        [
            arg(
                "file",
                action="store",
                type=surl,
                help="file uri to use for checksum calculation",
            ),
            arg(
                "checksum_type",
                action="store",
                type=str,
                help="checksum algorithm to use. For example: ADLER32, CRC32, MD5",
            ),
        ],
        checksum,
    ),
    "stat": Spec(
        "stat",
        "Stats a file",
        [arg("file", action="store", type=surl, help="uri of the file to be stat")],
        stat_,
    ),
    "rename": Spec(
        "rename",
        "Renames files or directories",
        [
            arg("source", action="store", type=surl, help="original file name"),
            arg("destination", action="store", type=surl, help="new file name"),
        ],
        rename,
    ),
    "chmod": Spec(
        "chmod",
        "Change the permissions of a file",
        [
            arg("mode", action="store", type=str, help="new mode, in octal"),
            arg(
                "file",
                action="store",
                type=surl,
                help="uri of the file to change permissions",
            ),
        ],
        chmod,
    ),
    "token": Spec(
        "token",
        "Retrieve a SE-issued token",
        [
            arg("--issuer", action="store", type=str, help="token issuer URL"),
            arg(
                "--validity",
                action="store",
                type=int,
                default=60,
                help="token validity in minutes",
            ),
            arg(
                "-w",
                "--write",
                dest="write_access",
                action="store_true",
                help="flag to request write access token",
            ),
            arg("path", action="store", type=surl, help="URI to request token for"),
            arg(
                "activities",
                action="store",
                nargs="*",
                type=str,
                help="activities for macaroon request",
            ),
        ],
        token,
    ),
}
