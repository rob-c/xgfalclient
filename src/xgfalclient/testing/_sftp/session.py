"""One SFTP v3 session of the test server: framing, faults and the request handlers.

:class:`_Session` reads requests off whatever byte stream it was handed (a
socketpair, an SSH channel, a fake ``ssh``'s stdio), applies the server's
named faults and injected statuses, and dispatches through
:data:`_HANDLERS` - a plain table, so a test can swap one request type's
handler with ``monkeypatch.setitem`` on the facade's ``_HANDLERS``, which is
this same dict. The handlers behave like OpenSSH's ``sftp-server``,
including its ``errno`` to status mapping (:func:`portable_status`).

The wire format is draft-ietf-secsh-filexfer-02 (SFTP v3), the only
version OpenSSH speaks. Every packet is ``uint32 length``, ``byte type``
and, for everything but ``INIT``/``VERSION``, ``uint32 request-id``,
followed by the type's fields in SSH encoding (RFC 4251 section 5:
``uint32``/``uint64`` big-endian, ``string`` as a ``uint32`` length then the
bytes). The encoding helpers are the client's own (:mod:`~xgfalclient.crypto.sshkeys`
and :mod:`xgfalclient.plugins.sftp.protocol`), so a mistake in them shows up
on both sides at once; tests that pin the bytes themselves live in
``tests/test_sftp_protocol.py``.

How a handler reports failure: it raises. ``OSError`` from the local
filesystem becomes a ``STATUS`` through :func:`portable_status`, and a
malformed request (the reader running off the end, ``KeyError_``) becomes
``BAD_MESSAGE``; only answers that are not an errno - an unknown handle, an
unsupported extension - are sent by the handler itself. Requests are
handled strictly one at a time in arrival order, like ``sftp-server``; the
pipelining a client does is only visible here as several requests waiting
in the stream.

To support a new request type, add an ``op_<name>(self, rid, reader)``
method that reads its fields from ``reader`` and sends exactly one reply,
and list it in :data:`_HANDLERS`. A type missing from the table is answered
``OP_UNSUPPORTED``, which is how ``sftp-server`` answers too.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat as _stat
import struct
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from ...crypto.sshkeys import (
    KeyError_,
    Reader,
    string,
    uint32,
)
from ...plugins.sftp import protocol as fx
from ...plugins.sftp.protocol import Attrs

if TYPE_CHECKING:
    from .server import SFTPServer


def portable_status(code: int | None) -> int:
    """``errno_to_portable`` from OpenSSH's ``sftp-server.c``, verbatim in effect.

    SFTP v3 has only seven status codes, so most errnos collapse to the
    generic ``FAILURE``: ``EEXIST``, ``ENOTEMPTY``, ``EISDIR`` and ``ENOSPC``
    all look alike on the wire. That loss is the point of matching it
    exactly - the client's job of recovering a gfal2 errno from a bare
    ``FAILURE`` (by a follow-up ``STAT``, say) is only tested if the server
    is as unhelpful as the real one. ``None`` (an ``OSError`` without an
    errno) is also ``FAILURE``.
    """
    if code in (errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP):
        return fx.FX_NO_SUCH_FILE
    if code in (errno.EPERM, errno.EACCES, errno.EFAULT):
        return fx.FX_PERMISSION_DENIED
    if code in (errno.ENAMETOOLONG, errno.EINVAL):
        return fx.FX_BAD_MESSAGE
    if code == errno.ENOSYS:
        return fx.FX_OP_UNSUPPORTED
    return fx.FX_FAILURE


class _Drop(Exception):
    """Raised inside the server to end the session abruptly."""


class _Handle:
    """What a handle string stands for: an open file or a directory listing.

    ``path`` is the local path; ``FSETSTAT`` applies its changes by this name
    rather than through the descriptor. A file handle has an ``fd`` and
    ``entries`` ``None``; a directory handle has ``fd`` -1 and the names still
    to be returned by ``READDIR``, consumed batch by batch. Using a file
    handle for ``READDIR`` (or the reverse) is answered ``FAILURE``.
    """

    __slots__ = ("entries", "fd", "path")

    def __init__(self, path: str, fd: int = -1, entries: list[str] | None = None) -> None:
        """A file handle when given ``fd``, a directory handle when given ``entries``."""
        self.path = path
        self.fd = fd
        self.entries = entries


def _longname(name: str, info: os.stat_result) -> str:
    """The ``ls -l`` style ``longname`` of a ``READDIR`` entry, as sftp-server builds it.

    draft-02 leaves the format to the server and tells clients not to parse
    it; OpenSSH's ``ls_file`` writes mode, link count, owner, group, size,
    date and name. This one uses numeric owner and group and always the
    ``%b %d %H:%M`` date in UTC, which is enough for clients that display it.
    """
    mode = _stat.filemode(info.st_mode)
    when = time.strftime("%b %d %H:%M", time.gmtime(info.st_mtime))
    return (
        f"{mode} {info.st_nlink:3d} {info.st_uid:<8d} {info.st_gid:<8d} "
        f"{info.st_size:8d} {when} {name}"
    )


def _attrs(info: os.stat_result) -> Attrs:
    """The SFTP v3 ``ATTRS`` of a local stat: size, uid/gid, permissions, atime/mtime.

    All four v3 attribute groups are always present (``SIZE``, ``UIDGID``,
    ``PERMISSIONS``, ``ACMODTIME`` flags), as sftp-server sends them.
    ``permissions`` carries the full ``st_mode``, file type bits included,
    which clients rely on to tell a directory from a file. Times are whole
    seconds: v3 has no sub-second field.
    """
    return Attrs(
        size=info.st_size,
        uid=info.st_uid,
        gid=info.st_gid,
        permissions=info.st_mode,
        atime=int(info.st_atime),
        mtime=int(info.st_mtime),
    )


class _Session:
    """One client's SFTP session: the handshake, then a request loop until it ends.

    Created and run by :meth:`SFTPServer.serve` on one thread, which is the
    only thread that touches it, so it needs no locking of its own; what it
    shares with other sessions lives on the :class:`SFTPServer`. It owns its
    handles' file descriptors, and :meth:`close_all` releases them however
    the session ends.
    """

    def __init__(
        self, server: SFTPServer, read_exact: Callable[[int], bytes], write: Callable[[bytes], None]
    ) -> None:
        """Bind a session to ``server`` and the stream's two callables; :meth:`run` starts it."""
        self.server = server
        self.read_exact = read_exact
        # The stream's own write; replies go through write() so "reorder" can hold them.
        self.raw_write = write
        # Handle string -> what it names. Handles are never reused within a session.
        self.handles: dict[bytes, _Handle] = {}
        self.counter = 0
        # Replies held back by the "reorder" fault, and how many more to hold.
        self.held: list[bytes] = []
        self.reorder = 0

    # -- framing -------------------------------------------------------------------

    def write(self, data: bytes) -> None:
        """Send one complete reply packet, or hold it back while a reorder is pending.

        With the ``reorder`` fault armed, the next two replies are held and
        then written in reverse. Draft-02 lets a server answer requests in any
        order, so a client matching replies by request id must cope; OpenSSH
        never does it, which is why only a fault makes this server do it.
        """
        if self.reorder:
            self.held.append(data)
            self.reorder -= 1
            if not self.reorder:
                for packet in reversed(self.held):
                    self.raw_write(packet)
                self.held = []
            return
        self.raw_write(data)

    def send(self, ptype: int, rid: int, body: bytes) -> None:
        """Frame and send a reply: length (type + id + body), type, request id, body."""
        self.write(uint32(len(body) + 5) + bytes([ptype]) + uint32(rid) + body)

    def status(self, rid: int, code: int, message: str = "") -> None:
        """Send ``SSH_FXP_STATUS``: code, a message, and an empty language tag.

        Without a ``message`` the text is the code's name in sentence case
        ("No such file"), close to OpenSSH's own ``status_to_message``.
        """
        text = message or fx.STATUS_NAMES.get(code, "").replace("_", " ").capitalize()
        if code == fx.FX_OK:
            text = message or "Success"
        self.send(fx.STATUS, rid, uint32(code) + string(text) + string(""))

    def error(self, rid: int, exc: OSError) -> None:
        """Answer a failed filesystem call: the mapped status, with ``strerror`` as message.

        OpenSSH sends the status's generic text instead; the errno's text
        here only makes test failures easier to read, and the client must not
        (and does not) parse it.
        """
        self.status(rid, portable_status(exc.errno), os.strerror(exc.errno or errno.EIO))

    def run(self) -> None:
        """The handshake, then requests until the stream ends.

        ``SSH_FXP_INIT`` must come first (anything else ends the session, as
        sftp-server does); its client version and any extension data are read
        and ignored. The reply is ``SSH_FXP_VERSION`` with the configured
        version and the server's extension pairs (``string name, string
        data``). The ``banner`` fault writes a line of text ahead of it - what
        a login script printing to stdout does to a real ``ssh -s sftp`` - so
        the client sees a nonsense length and must fail cleanly.

        Never returns normally: the loop ends with ``EOFError``/``OSError``
        from the stream or :class:`_Drop` from a fault, which
        :meth:`SFTPServer.serve` treats as the end of the session.
        """
        length, ptype = struct.unpack(">IB", self.read_exact(5))
        body = self.read_exact(length - 1)
        if ptype != fx.INIT:
            raise _Drop
        if self.server._take_fault("banner"):
            self.raw_write(b"Welcome to the machine!\r\n")
        extensions = b"".join(string(k) + string(v) for k, v in self.server.extensions.items())
        payload = bytes([fx.VERSION_]) + uint32(self.server.version) + extensions
        self.raw_write(uint32(len(payload)) + payload)
        del body
        while True:
            length, ptype, rid = struct.unpack(">IBI", self.read_exact(9))
            reader = Reader(self.read_exact(length - 5))
            self.dispatch(ptype, rid, reader)

    def dispatch(self, ptype: int, rid: int, reader: Reader) -> None:
        """Log one request, apply any armed fault or injection, else run its handler.

        The log entry is ``(type, first field)`` - for most requests the
        path or handle - read without consuming it, so tests can assert
        which requests the client made without a parser of their own.

        Faults are checked in a fixed order and at most one stream-level
        fault fires per request: ``drop`` (hang up unanswered), ``hang``
        (never answer: the client's timeout path), ``garbage`` (a length
        of ~2 GiB, then hang up), ``wrong_type`` (a ``HANDLE`` - or ``NAME``
        for ``OPEN`` - where something else was due), then ``reorder``, which
        arms the reversal and lets the request through. An injected status
        comes after the faults, so a test can combine one of each.
        """
        server = self.server
        first = (
            reader.data[4 : 4 + struct.unpack(">I", reader.data[:4])[0]]
            if reader.remaining >= 4
            else b""
        )
        server.log.append((ptype, first))
        if server._take_fault("drop"):
            raise _Drop
        if server._take_fault("hang"):
            return
        if server._take_fault("garbage"):
            self.raw_write(b"\x7f\xff\xff\xff" + bytes([fx.STATUS]) + uint32(rid))
            raise _Drop
        if server._take_fault("wrong_type"):
            self.send(fx.HANDLE if ptype != fx.OPEN else fx.NAME, rid, string(b"x"))
            return
        if server._take_fault("reorder"):
            self.reorder = 2
        injected = server._take_injection(ptype)
        if injected is not None:
            self.status(rid, *injected)
            return
        handler = _HANDLERS.get(ptype)
        if handler is None:
            self.status(rid, fx.FX_OP_UNSUPPORTED, "Operation unsupported")
            return
        try:
            handler(self, rid, reader)
        except OSError as exc:
            self.error(rid, exc)
        except KeyError_:
            self.status(rid, fx.FX_BAD_MESSAGE, "Bad message")

    def close_all(self) -> None:
        """Close every file still open, as sftp-server does when its client goes away."""
        for handle in self.handles.values():
            if handle.fd >= 0:
                os.close(handle.fd)
        self.handles.clear()

    def new_handle(self, handle: _Handle) -> bytes:
        """Register ``handle`` and return its handle string (4 big-endian bytes).

        draft-02 makes handles opaque strings of at most 256 bytes; OpenSSH's
        are small integers too. Counting up means a stale handle from a
        closed file never names a newer one by accident.
        """
        self.counter += 1
        key = struct.pack(">I", self.counter)
        self.handles[key] = handle
        return key

    def handle(self, rid: int, reader: Reader) -> _Handle | None:
        """Read a handle string from ``reader`` and look it up.

        An unknown handle is answered here with ``FAILURE`` (sftp-server's
        answer, there being no errno for it) and ``None`` is returned: the
        caller must then send nothing more.
        """
        found = self.handles.get(reader.string())
        if found is None:
            self.status(rid, fx.FX_FAILURE, "Failure")
        return found

    # -- handlers --------------------------------------------------------------------

    def op_open(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_OPEN``: ``string filename, uint32 pflags, ATTRS`` -> ``HANDLE``.

        The ``SSH_FXF_*`` flags map onto ``open(2)`` flags as in sftp-server's
        ``flags_from_portable``: ``READ`` alone is ``O_RDONLY``, ``WRITE`` with
        or without ``READ`` picks ``O_WRONLY``/``O_RDWR``, and ``APPEND``,
        ``CREAT``, ``TRUNC``, ``EXCL`` add their ``O_*`` twins. The mode for a
        new file is the request's permissions, else 0666 (before umask).
        """
        path = self.server.local(reader.string())
        pflags = reader.uint32()
        attrs = Attrs.decode(reader)
        flags = 0
        if pflags & fx.FXF_READ and pflags & fx.FXF_WRITE:
            flags = os.O_RDWR
        elif pflags & fx.FXF_WRITE:
            flags = os.O_WRONLY
        for bit, value in (
            (fx.FXF_APPEND, os.O_APPEND),
            (fx.FXF_CREAT, os.O_CREAT),
            (fx.FXF_TRUNC, os.O_TRUNC),
            (fx.FXF_EXCL, os.O_EXCL),
        ):
            if pflags & bit:
                flags |= value
        mode = attrs.permissions & 0o7777 if attrs.permissions is not None else 0o666
        fd = os.open(path, flags, mode)
        if _stat.S_ISDIR(os.fstat(fd).st_mode):
            # Linux refuses O_WRONLY on a directory with EISDIR; reading one
            # "opens" and fails later. Report it now, as FAILURE, as sshd would.
            os.close(fd)
            raise IsADirectoryError(errno.EISDIR, "Is a directory")
        self.send(fx.HANDLE, rid, string(self.new_handle(_Handle(path, fd))))

    def op_close(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_CLOSE``: forget a file or directory handle; an unknown one is ``FAILURE``."""
        key = reader.string()
        handle = self.handles.pop(key, None)
        if handle is None:
            self.status(rid, fx.FX_FAILURE, "Failure")
            return
        if handle.fd >= 0:
            os.close(handle.fd)
        self.status(rid, fx.FX_OK)

    def op_read(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_READ``: ``string handle, uint64 offset, uint32 len`` -> ``DATA`` or ``EOF``.

        A read is capped at the max read length of ``limits@openssh.com``
        (1 MiB without it) and may legally return less than asked; the
        ``short_read`` fault halves it to prove the client asks again for the
        rest. ``EOF`` comes only when nothing at all is left at ``offset``.
        The ``oversize`` fault sends one byte more than the length field of
        the data string admits, a framing lie a client must not accept.
        """
        handle = self.handle(rid, reader)
        if handle is None:
            return
        offset = reader.uint64()
        size = min(reader.uint32(), self.server.limits[2] if self.server.limits else 1 << 20)
        if self.server._take_fault("short_read"):
            size = max(1, size // 2)
        data = os.pread(handle.fd, size, offset)
        if not data:
            self.status(rid, fx.FX_EOF, "End of file")
            return
        if self.server._take_fault("oversize"):
            data += b"!"
            self.write(
                uint32(len(data) + 9) + bytes([fx.DATA]) + uint32(rid) + string(data)[:4] + data
            )
            return
        self.send(fx.DATA, rid, string(data))

    def op_write(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_WRITE``: ``string handle, uint64 offset, string data`` -> ``STATUS``.

        Writes are positional (``pwrite``), so pipelined writes may land in
        any order. A short ``pwrite`` is not retried: on a local file it does
        not happen short of ``ENOSPC``, which raises instead.
        """
        handle = self.handle(rid, reader)
        if handle is None:
            return
        offset = reader.uint64()
        data = reader.string()
        os.pwrite(handle.fd, data, offset)
        self.status(rid, fx.FX_OK)

    def _stat_reply(self, rid: int, info: os.stat_result) -> None:
        """Answer a stat request with ``SSH_FXP_ATTRS``."""
        self.send(fx.ATTRS, rid, _attrs(info).encode())

    def op_stat(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_STAT``: attributes of a path, following symlinks."""
        self._stat_reply(rid, os.stat(self.server.local(reader.string())))

    def op_lstat(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_LSTAT``: attributes of a path itself, a symlink not followed."""
        self._stat_reply(rid, os.lstat(self.server.local(reader.string())))

    def op_fstat(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_FSTAT``: attributes of an open file handle.

        On a directory handle (``fd`` -1) ``fstat`` raises ``EBADF``, which
        maps to ``NO_SUCH_FILE`` - an oddity of this server, not of OpenSSH.
        """
        handle = self.handle(rid, reader)
        if handle is not None:
            self._stat_reply(rid, os.fstat(handle.fd))

    def _apply(self, path: str, attrs: Attrs) -> None:
        """Carry out ``SETSTAT``/``FSETSTAT``: truncate, chmod, then set times.

        The order is sftp-server's. Ownership (``UIDGID``) is accepted and
        ignored: the test runs unprivileged and no client test needs it. A
        failure part-way leaves the earlier changes made, as on a real server.
        """
        if attrs.size is not None:
            os.truncate(path, attrs.size)
        if attrs.permissions is not None:
            os.chmod(path, attrs.permissions & 0o7777)
        if attrs.atime is not None:
            # ATTR_ACMODTIME carries both times: decode never sets one alone.
            assert attrs.mtime is not None
            os.utime(path, (attrs.atime, attrs.mtime))

    def op_setstat(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_SETSTAT``: ``string path, ATTRS`` -> ``STATUS``; sets what is present."""
        path = self.server.local(reader.string())
        self._apply(path, Attrs.decode(reader))
        self.status(rid, fx.FX_OK)

    def op_fsetstat(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_FSETSTAT``: as ``SETSTAT``, on the path an open handle was opened by."""
        handle = self.handle(rid, reader)
        if handle is not None:
            self._apply(handle.path, Attrs.decode(reader))
            self.status(rid, fx.FX_OK)

    def op_opendir(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_OPENDIR``: snapshot a directory's names into a handle.

        The listing is taken now, sorted, with ``.`` and ``..`` first, as
        ``readdir(3)`` gives them to sftp-server; clients must filter those
        out themselves. Entries removed before ``READDIR`` reaches them are
        skipped then, not reported.
        """
        path = self.server.local(reader.string())
        names = [".", "..", *sorted(os.listdir(path))]
        self.send(fx.HANDLE, rid, string(self.new_handle(_Handle(path, entries=names))))

    def op_readdir(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_READDIR``: the next :attr:`SFTPServer.batch` names, or ``EOF``.

        Each ``NAME`` reply is ``uint32 count`` and per entry ``string
        filename, string longname, ATTRS``, attributes from ``lstat`` so a
        symlink is reported as a link. ``EOF`` comes as a separate reply once
        the names run out, never alongside the last batch - the client must
        keep asking until it sees it.
        """
        handle = self.handle(rid, reader)
        if handle is None:
            return
        if handle.entries is None:
            self.status(rid, fx.FX_FAILURE, "Failure")
            return
        batch, handle.entries = (
            handle.entries[: self.server.batch],
            handle.entries[self.server.batch :],
        )
        if not batch:
            self.status(rid, fx.FX_EOF, "End of file")
            return
        body = b""
        count = 0
        for name in batch:
            try:
                info = os.lstat(os.path.join(handle.path, name))
            except OSError:
                continue
            body += string(name.encode("utf-8", "surrogateescape"))
            body += string(_longname(name, info)) + _attrs(info).encode()
            count += 1
        self.send(fx.NAME, rid, uint32(count) + body)

    def op_remove(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_REMOVE``: unlink a file (or symlink); a directory is ``FAILURE``."""
        path = self.server.local(reader.string())
        if _stat.S_ISDIR(os.lstat(path).st_mode):
            # Linux says EISDIR (FAILURE from sshd); macOS says EPERM. Be Linux.
            raise IsADirectoryError(errno.EISDIR, "Is a directory")
        os.unlink(path)
        self.status(rid, fx.FX_OK)

    def op_mkdir(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_MKDIR``: ``string path, ATTRS``; mode from the permissions, else 0777.

        An existing path is ``EEXIST``, i.e. a bare ``FAILURE`` on the wire.
        """
        path = self.server.local(reader.string())
        attrs = Attrs.decode(reader)
        os.mkdir(path, attrs.permissions & 0o7777 if attrs.permissions is not None else 0o777)
        self.status(rid, fx.FX_OK)

    def op_rmdir(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_RMDIR``: a non-empty directory is ``ENOTEMPTY``, a bare ``FAILURE``."""
        os.rmdir(self.server.local(reader.string()))
        self.status(rid, fx.FX_OK)

    def op_realpath(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_REALPATH``: the canonical absolute path, as a one-entry ``NAME``.

        An empty path means ``.``, which is the root here. Like sftp-server,
        the name is also sent as the longname and the attributes are empty.
        A path that does not exist is canonicalised anyway rather than
        refused, since :func:`os.path.realpath` does not require it to exist.
        """
        raw = reader.string().decode("utf-8", "surrogateescape")
        name = self.server.remote(os.path.realpath(self.server.local(raw or ".")))
        self.send(fx.NAME, rid, uint32(1) + string(name) + string(name) + Attrs().encode())

    def op_rename(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_RENAME``: ``string oldpath, string newpath`` -> ``STATUS``.

        For an atomic replacing rename the client must use
        ``posix-rename@openssh.com`` (see :meth:`op_extended`).
        """
        old = self.server.local(reader.string())
        new = self.server.local(reader.string())
        # sftp-server's v3 rename refuses to replace an existing target.
        if os.path.lexists(new):
            self.status(rid, fx.FX_FAILURE, "Failure")
            return
        os.rename(old, new)
        self.status(rid, fx.FX_OK)

    def op_readlink(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_READLINK``: a symlink's target, unresolved, as a one-entry ``NAME``."""
        target = os.readlink(self.server.local(reader.string()))
        self.send(fx.NAME, rid, uint32(1) + string(target) + string(target) + Attrs().encode())

    def op_symlink(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_SYMLINK``, with OpenSSH's argument order: target first, then link path.

        draft-02 specifies ``linkpath, targetpath``; OpenSSH implemented them
        the other way round long ago and every client since follows OpenSSH
        (its ``PROTOCOL`` file documents the swap). The target is stored as
        sent, not mapped under the root, as ``symlink(2)`` would.
        """
        target = reader.string().decode("utf-8", "surrogateescape")
        link = self.server.local(reader.string())
        os.symlink(target, link)
        self.status(rid, fx.FX_OK)

    def op_extended(self, rid: int, reader: Reader) -> None:
        """``SSH_FXP_EXTENDED``: ``string request-name`` then that extension's fields.

        Only the extensions this server announced are honoured; the rest are
        ``OP_UNSUPPORTED``, which is what the client sees from a server
        without them. The ones carried out, in OpenSSH's ``PROTOCOL`` terms:

        * ``posix-rename@openssh.com`` - ``rename(2)``, replacing the target;
        * ``hardlink@openssh.com`` - ``link(2)``;
        * ``fsync@openssh.com`` - ``fsync(2)`` on an open handle;
        * ``limits@openssh.com`` - four ``uint64`` limits in an
          ``EXTENDED_REPLY`` (see :class:`~.server.SFTPServer`);
        * ``statvfs@openssh.com`` - eleven ``uint64`` in ``struct statvfs``
          order. ``f_fsid`` is sent as 0 and ``f_flag`` raw from the local
          ``statvfs``, where OpenSSH maps the flag to its own
          ``SSH2_FXE_STATVFS_ST_*`` bits (read-only 1, nosuid 2), which the
          Linux values happen to equal;
        * ``check-file-name`` - see :meth:`_check_file`.

        ``fstatvfs@openssh.com`` and ``lsetstat@openssh.com`` are announced
        (as OpenSSH does) but not implemented, so they fall through to
        ``OP_UNSUPPORTED``; the client never sends them.
        """
        name = reader.text()
        if name not in self.server.extensions:
            self.status(rid, fx.FX_OP_UNSUPPORTED, "Operation unsupported")
            return
        if name == "posix-rename@openssh.com":
            os.rename(self.server.local(reader.string()), self.server.local(reader.string()))
            self.status(rid, fx.FX_OK)
        elif name == "hardlink@openssh.com":
            os.link(self.server.local(reader.string()), self.server.local(reader.string()))
            self.status(rid, fx.FX_OK)
        elif name == "fsync@openssh.com":
            handle = self.handle(rid, reader)
            if handle is not None:
                os.fsync(handle.fd)
                self.status(rid, fx.FX_OK)
        elif name == "limits@openssh.com":
            assert self.server.limits is not None
            body = b"".join(struct.pack(">Q", value) for value in self.server.limits)
            self.send(fx.EXTENDED_REPLY, rid, body)
        elif name == "statvfs@openssh.com":
            info = os.statvfs(self.server.local(reader.string()))
            values = (
                info.f_bsize,
                info.f_frsize,
                info.f_blocks,
                info.f_bfree,
                info.f_bavail,
                info.f_files,
                info.f_ffree,
                info.f_favail,
                0,
                info.f_flag,
                info.f_namemax,
            )
            self.send(fx.EXTENDED_REPLY, rid, b"".join(struct.pack(">Q", v) for v in values))
        elif name == "check-file-name":
            self._check_file(rid, reader)
        else:
            self.status(rid, fx.FX_OP_UNSUPPORTED, "Operation unsupported")

    def _check_file(self, rid: int, reader: Reader) -> None:
        """``check-file-name``: one hash over a byte range, chosen from the client's list.

        From the later filexfer drafts' extensions (ProFTPD offers it;
        OpenSSH never has). The request is ``string path, string algorithm
        list, uint64 offset, uint64 length`` (0: to the end) and a ``uint32``
        block size, which is left unread because only a single whole-range
        hash is supported. The reply is ``string algorithm`` and then the raw
        digest. The algorithm is the client's first preference that is in
        :attr:`SFTPServer.check_file`; none in common is ``FAILURE``, the
        answer the client turns into "no server-side checksum".
        """
        path = self.server.local(reader.string())
        wanted = reader.text().split(",")
        offset = reader.uint64()
        length = reader.uint64()
        chosen = next((a for a in wanted if a in self.server.check_file), None)
        if chosen is None:
            self.status(rid, fx.FX_FAILURE, "No supported hash algorithm")
            return
        with open(path, "rb") as handle:
            handle.seek(offset)
            data = handle.read(length) if length else handle.read()
        digest = hashlib.new(chosen, data).digest()
        self.send(fx.EXTENDED_REPLY, rid, string(chosen) + digest)


#: Request type -> handler, the session's dispatch table. Tests swap entries
#: (through the facade, which re-exports this very dict) to model a server
#: that answers one request type differently; a type left out is
#: ``OP_UNSUPPORTED``.
_HANDLERS: dict[int, Callable[[_Session, int, Reader], None]] = {
    fx.OPEN: _Session.op_open,
    fx.CLOSE: _Session.op_close,
    fx.READ: _Session.op_read,
    fx.WRITE: _Session.op_write,
    fx.LSTAT: _Session.op_lstat,
    fx.FSTAT: _Session.op_fstat,
    fx.SETSTAT: _Session.op_setstat,
    fx.FSETSTAT: _Session.op_fsetstat,
    fx.OPENDIR: _Session.op_opendir,
    fx.READDIR: _Session.op_readdir,
    fx.REMOVE: _Session.op_remove,
    fx.MKDIR: _Session.op_mkdir,
    fx.RMDIR: _Session.op_rmdir,
    fx.REALPATH: _Session.op_realpath,
    fx.STAT: _Session.op_stat,
    fx.RENAME: _Session.op_rename,
    fx.READLINK: _Session.op_readlink,
    fx.SYMLINK: _Session.op_symlink,
    fx.EXTENDED: _Session.op_extended,
}
