"""The single-operation commands: mkdir, save, cat, xattr, sum, stat, rename, chmod, token.

Output formats and messages are gfal2-util 1.9.1's (Apache-2.0, (c) CERN),
reimplemented.
"""

from __future__ import annotations

import stat
import sys
from datetime import datetime

from ..errors import GError
from ._base import Command, Spec, arg, out, surl
from ._utils import file_mode_str, file_type_str

__all__ = ["SPECS"]

#: Bytes per read for ``gfal-cat`` and ``gfal-save``.
CHUNK = 1 << 20


def mkdir(cmd: Command) -> None:
    mode = 0o755
    if cmd.params.mode:
        try:
            mode = int(str(cmd.params.mode), 8)
        except ValueError:
            pass  # -m 999: gfal2-util falls back to 0755 without a word
    for directory in cmd.params.directory:
        if cmd.params.parents:
            cmd.context.mkdir_rec(directory, mode)
        else:
            cmd.context.mkdir(directory, mode)


def save(cmd: Command) -> None:
    handle = cmd.context.open(cmd.params.file, "w")
    try:
        while True:
            data = sys.stdin.buffer.read(CHUNK)
            if not data:
                break
            handle.write(data)
    finally:
        handle.close()


def cat(cmd: Command) -> None:
    # The bytes go to stdout untouched, with or without -b: gfal2-util's text
    # mode decodes each chunk on its own and chokes on binary data, or on a
    # character split across two reads.
    sys.stdout.flush()
    for name in cmd.params.file:
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


def xattr(cmd: Command) -> None:
    path, attribute = cmd.params.file, cmd.params.attribute
    if attribute is not None:
        if "=" in attribute:
            name, _, value = attribute.partition("=")
            if name and value:
                cmd.context.setxattr(path, name, value, 0)
        else:
            out(cmd.context.getxattr(path, attribute) + "\n")
        return
    for name in cmd.context.listxattr(path):
        try:
            out(f"{name} = {cmd.context.getxattr(path, name)}\n")
        except GError as exc:
            out(f"{name} FAILED: {exc}\n")


def checksum(cmd: Command) -> None:
    value = cmd.context.checksum(cmd.params.file, cmd.params.checksum_type)
    out(f"{cmd.params.file} {value}\n")


def _time(stamp: int) -> str:
    return datetime.fromtimestamp(stamp).strftime("%Y-%m-%d %H:%M:%S.%f")


def stat_(cmd: Command) -> None:
    info = cmd.context.stat(cmd.params.file)
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
    cmd.context.rename(cmd.params.source, cmd.params.destination)


def chmod(cmd: Command) -> None:
    try:
        mode = int(cmd.params.mode, 8)
    except ValueError:
        cmd.parser.error("Mode must be an octal number (i.e. 0755)")
    cmd.context.chmod(cmd.params.file, mode)


def token(cmd: Command) -> int:
    params = cmd.params
    if params.validity < 0:
        sys.stderr.write("Validity must be a number >= 0\n")
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
    out(value + "\n")
    return 0


SPECS = {
    "mkdir": Spec(
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
        "Reads from stdin and writes to a file. If the file exists, it will be overwritten",
        [arg("file", action="store", type=surl, help="uri of the file to be written")],
        save,
    ),
    "cat": Spec(
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
        "Stats a file",
        [arg("file", action="store", type=surl, help="uri of the file to be stat")],
        stat_,
    ),
    "rename": Spec(
        "Renames files or directories",
        [
            arg("source", action="store", type=surl, help="original file name"),
            arg("destination", action="store", type=surl, help="new file name"),
        ],
        rename,
    ),
    "chmod": Spec(
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
