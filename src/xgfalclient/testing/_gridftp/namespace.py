"""The test GridFTP server's namespace verbs: listings, ``MLST``, ``SIZE`` and friends.

Listings (``NLST``, ``MLSD``, ``LIST``) are data transfers, always sent as a
plain ``MODE S`` stream, so this mixin builds on :class:`.data._DataChannel`;
the rest (``MLST``, ``SIZE``, ``MDTM``, ``CKSM``, ``MKD``, ``RMD``,
``DELE``, ``RNFR``/``RNTO``) answer on the control channel, failures worded
as globus's error block.

The ``MLST``/``MLSD`` facts are RFC 3659's (``Type``, ``Modify``, ``Size``,
``Perm``, ``Unique``) plus the ``UNIX.*`` facts globus adds; the plugin's
stat and directory listing are built from them, so they are what its stat
and listing tests actually exercise.
"""

from __future__ import annotations

import errno
import os
import stat as _stat
import time
from collections.abc import Callable
from typing import Any

from ...plugins.gridftp.data import Feed, send_stream
from ...plugins.gridftp.protocol import format_mdtm
from .common import _checksum, _Reply, _slice
from .data import _DataChannel


class _Namespace(_DataChannel):
    """Listings and the metadata and namespace verbs."""

    def listing(self, verb: str, arg: str, lines: Callable[[str], list[str]]) -> None:
        """Send a listing, always as a plain stream (``MODE S``), as clients read it.

        ``lines`` turns the local path into the listing's lines; an
        ``OSError`` from it fails the command before ``150`` (a missing path
        is ``550 ... PATH_NOT_FOUND``). The session's ``MODE`` is switched to
        ``S`` for the transfer and restored afterwards, so a client in
        ``MODE E`` can list without first switching back.
        """
        try:
            text = "".join(f"{line}\r\n" for line in lines(self.local(arg)))
        except OSError as exc:
            raise self.failure(exc, "stat") from None
        read = _slice(text.encode("utf-8", "surrogateescape"))
        mode, self.mode = self.mode, "S"
        try:
            self.transfer(
                verb, 1, lambda conn, i, moved: send_stream(conn, Feed(read, 65536, moved.add))
            )
        finally:
            self.mode = mode

    def entries(self, path: str) -> list[str]:
        """The names a listing of ``path`` shows: a directory's, with ``.`` and ``..``.

        A directory lists ``.``, ``..`` and its entries sorted (globus lists
        the dot entries too, and clients must skip them); any other existing
        path, a dangling symlink included, lists as itself. A missing path
        raises ``ENOENT``.
        """
        if os.path.isdir(path):
            return [".", "..", *sorted(os.listdir(path))]
        if os.path.lexists(path):
            return [os.path.basename(path)]
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT))

    def do_NLST(self, arg: str) -> None:
        """``NLST [path]``: names only, one per line (RFC 959)."""
        self.listing("NLST", arg, self.entries)

    def do_MLSD(self, arg: str) -> None:
        """``MLSD <dir>``: RFC 3659 machine listing, ``<facts> <name>`` per entry.

        A non-directory is ``ENOTDIR`` (RFC 3659 has ``MLSD`` list
        directories only; ``MLST`` is for a single object).
        """

        def lines(path: str) -> list[str]:
            """The facts line of every entry of the directory ``path``."""
            if not os.path.isdir(path):
                raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR))
            return [f"{self.facts(os.path.join(path, n), n)} {n}" for n in self.entries(path)]

        self.listing("MLSD", arg, lines)

    def do_LIST(self, arg: str) -> None:
        """``LIST [path]``: an ``ls -l`` style listing, for humans and old clients.

        The line is ``<mode> 1 <uid> <gid> <size> <Mon DD HH:MM> <name>``,
        numeric owners and UTC times; symlinks are shown, not followed.
        """

        def lines(path: str) -> list[str]:
            """One ``ls -l`` line per entry (``path`` itself if it is not a directory)."""
            base = path if os.path.isdir(path) else os.path.dirname(path)
            out = []
            for name in self.entries(path):
                info = os.lstat(os.path.join(base, name))
                when = time.strftime("%b %d %H:%M", time.gmtime(info.st_mtime))
                out.append(
                    f"{_stat.filemode(info.st_mode)} 1 {info.st_uid} {info.st_gid} "
                    f"{info.st_size} {when} {name}"
                )
            return out

        self.listing("LIST", arg, lines)

    def facts(self, path: str, name: str) -> str:
        """The ``MLST`` fact string of ``path``, ending in ``;`` (RFC 3659 section 7).

        ``name`` is only used to type ``.``/``..`` as ``cdir``/``pdir``.
        ``Perm`` is fixed rather than derived from the caller's access:
        ``cfmpel`` for directories (create, rename, mkdir, purge, enter,
        list) and ``adfrw`` for files (append, delete, rename, retrieve,
        store). ``Modify`` is ``YYYYMMDDHHMMSS`` UTC; ``Unique`` is
        ``<dev>-<inode>`` in hex. The path is ``stat``\\ ed, so a symlink
        shows its target and a dangling one raises ``ENOENT``.
        """
        info = os.stat(path)
        if _stat.S_ISDIR(info.st_mode):
            kind = {".": "cdir", "..": "pdir"}.get(name, "dir")
            perm = "cfmpel"
        else:
            kind, perm = "file", "adfrw"
        return (
            f"Type={kind};Modify={format_mdtm(info.st_mtime)};Size={info.st_size};Perm={perm};"
            f"UNIX.mode={_stat.S_IMODE(info.st_mode):04o};UNIX.owner={info.st_uid};"
            f"UNIX.uid={info.st_uid};UNIX.group={info.st_gid};UNIX.gid={info.st_gid};"
            f"Unique={info.st_dev:x}-{info.st_ino:x};"
        )

    # -- namespace --------------------------------------------------------------------------

    def do_MLST(self, arg: str) -> None:
        """``MLST <path>``: one object's facts on the control channel (RFC 3659 ``250-``).

        The reply is ``250-status of <path>``, the fact line indented by one
        space (as RFC 3659 requires), then ``250 End.``. This is gfal2's stat.
        """
        path = self.local(arg)
        try:
            facts = self.facts(path, os.path.basename(path))
        except OSError as exc:
            raise self.failure(exc, "stat") from None
        raise _Reply(f"250-status of {arg}\r\n {facts} {arg}\r\n250 End.")

    def do_SIZE(self, arg: str) -> None:
        """``SIZE <path>``: RFC 3659 ``213 <bytes>``; a directory is ``550`` (no size)."""
        try:
            info = os.stat(self.local(arg))
        except OSError as exc:
            raise self.failure(exc, "stat") from None
        if _stat.S_ISDIR(info.st_mode):
            raise _Reply(f"550 {arg}: not a plain file.")
        raise _Reply(f"213 {info.st_size}")

    def do_MDTM(self, arg: str) -> None:
        """``MDTM <path>``: RFC 3659 ``213 YYYYMMDDHHMMSS``, modification time in UTC."""
        try:
            info = os.stat(self.local(arg))
        except OSError as exc:
            raise self.failure(exc, "stat") from None
        raise _Reply(f"213 {format_mdtm(info.st_mtime)}")

    def do_CKSM(self, arg: str) -> None:
        """globus ``CKSM <algorithm> <offset> <length> <path>``: ``213 <hex>``.

        ``length`` ``-1`` covers the rest of the file. The algorithms are
        those :data:`~xgfalclient.testing.gridftp.FEATURES` advertises (and
        anything else :mod:`hashlib` knows); see :func:`~.common._checksum`.
        A ``delays["CKSM"]`` entry models a server that takes its time.
        """
        algorithm, offset, length, path = arg.split(" ", 3)
        try:
            value = _checksum(self.local(path), algorithm, int(offset), int(length))
        except OSError as exc:
            raise self.failure(exc, "open") from None
        raise _Reply(f"213 {value}")

    def simple(self, action: Callable[[str], Any], arg: str, operation: str, done: str) -> None:
        """Apply ``action`` to the local path of ``arg``; reply ``done``, or the error block.

        ``operation`` names the system call in the error block. An
        ``EEXIST`` is reported with ``553`` (RFC 959's "file name not
        allowed"), everything else with ``550`` - or ``451`` where globus
        has no name for the errno, such as ``ENOTEMPTY`` from ``RMD``.
        """
        try:
            action(self.local(arg))
        except OSError as exc:
            raise self.failure(
                exc, operation, "553" if exc.errno == errno.EEXIST else "550"
            ) from None
        raise _Reply(done)

    def do_MKD(self, arg: str) -> None:
        """``MKD <dir>``: RFC 959 ``257 "<dir>"``; one level, the parent must exist."""
        self.simple(os.mkdir, arg, "mkdir", f'257 "{arg}" directory created.')

    def do_RMD(self, arg: str) -> None:
        """``RMD <dir>``: remove an empty directory."""
        self.simple(os.rmdir, arg, "rmdir", "250 RMD command successful.")

    def do_DELE(self, arg: str) -> None:
        """``DELE <file>``: remove a file (a directory fails as ``unlink`` does)."""
        self.simple(os.unlink, arg, "unlink", "250 DELE command successful.")

    def do_RNFR(self, arg: str) -> None:
        """``RNFR <from>``: RFC 959's first half of a rename; ``350`` waits for ``RNTO``.

        A missing source fails here, as an error block with code ``500``
        rather than ``550``. Any earlier pending ``RNFR`` is dropped.
        """
        self.rename_from = None
        try:
            os.stat(self.local(arg))
        except OSError as exc:
            raise self.failure(exc, "stat", "500") from None
        self.rename_from = self.local(arg)
        raise _Reply("350 Waiting for RNTO.")

    def do_RNTO(self, arg: str) -> None:
        """``RNTO <to>``: complete the rename ``RNFR`` started; ``501`` without one.

        The pending source is consumed whether or not the rename succeeds,
        so a retry must send ``RNFR`` again. ``os.rename`` semantics apply:
        an existing file target is replaced.
        """
        source, self.rename_from = self.rename_from, None
        if source is None:
            raise _Reply("501 Invalid command arguments.")
        self.simple(lambda target: os.rename(source, target), arg, "rename", "250 RNTO successful.")
