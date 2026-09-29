"""``dcap://`` and ``gsidcap://``: dCache's native access protocol.

gfal2's dcap plugin is a thin layer over libdcap's POSIX-like calls
(``dc_stat``, ``dc_open``, ``dc_opendir``...). This is the same set of
operations spoken straight to the door - see :mod:`.protocol` for the wire
format, :mod:`.control` for connections, :mod:`.file` for data transfer and
:mod:`.tunnel` for authentication.

What gfal2 offers, and so what this offers: ``stat``/``lstat``, ``access``,
``mkdir``, ``chmod``, ``rmdir``, ``unlink``, ``opendir`` and ``open`` (read,
write, ``pread``/``pwrite``, ``lseek``), which is also what the core's
streamed copy needs. gfal2 has no dcap ``rename`` (libdcap has one); this
plugin implements it, since dCache's door does. There is no checksum query
and there are no extended attributes in dcap, so ``checksum`` and
``*xattr`` are left unsupported, as in gfal2.

``kdcap://`` (Kerberos) needs a GSS-API library the standard library does
not have. :class:`KdcapPlugin` asks :mod:`xgfalclient.crypto.krb5` for one
and, through :meth:`~xgfalclient.plugin.Plugin.available`, reports why not
when there is none; any other implementation can be installed with
:func:`.tunnel.register_tunnel`. gfal2 itself does not handle ``kdcap://``.

Knowingly different from gfal2 and libdcap: a door that cannot be reached
fails with the real ``errno`` - ``EHOSTUNREACH`` for a name that does not
resolve, ``ECONNREFUSED``, ``ETIMEDOUT`` - where libdcap says ``ENOENT``
("Can not create socket", "Unable to connect to server") or worse, and a
door that refuses ``hello`` is ``EIO`` for every call. ``dcap://`` is
matched without regard to case, as gfal2 matches it, and then refused
unless it is lower case, as libdcap refuses it, but always with ``EINVAL``
(gfal2's errno there is whatever was left over). Of libdcap's environment,
``DCACHE_REPLY`` (the host announced for call-backs) and ``DCACHE_CBPORT``
(``first[:last]``, the ports to listen on) are honoured; the rest tune
libdcap's own buffers, debugging, tunnel libraries or pnfs-path lookups,
none of which exist here. Writes are always libdcap's "unsafe" ones
(``DCACHE_USE_UNSAFE``).
"""

from __future__ import annotations

import errno
import os
import stat as _stat
import threading
from collections.abc import Iterator
from typing import Any, ClassVar

from ...errors import GError
from ...plugin import O_ACCMODE_MASK, O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY, Plugin, PluginFile
from ...types import Stat
from .control import UID, ControlConnection, Door
from .file import DataChannel, DcapFile, await_data, callback_listener, read_listing
from .protocol import DcapURL, Reply, error_code, parse_stat, parse_url, quote
from .tunnel import tunnel_factory, unavailable

__all__ = ["DcapPlugin", "KdcapPlugin", "GROUP", "parse_listing"]

GROUP = "DCAP PLUGIN"

#: libdcap's ``dc_errno`` for "the server sent an error message" (``DESRVMSG``).
_DESRVMSG = 30

_umask_lock = threading.Lock()
_umask: list[int] = []


def process_umask() -> int:
    """The process umask, read once (reading it means setting it, so not per call)."""
    with _umask_lock:
        if not _umask:
            mask = os.umask(0)
            os.umask(mask)
            _umask.append(mask)
        return _umask[0]


def parse_listing(data: bytes) -> list[str]:
    """Names from a directory lister's ``<pnfsid>:<d|f>:<size>:<name>`` lines.

    libdcap takes the text after the *last* colon as the name, which cuts
    names that contain one; the name here is everything after the third.
    """
    names = []
    for raw in data.split(b"\n"):
        fields = raw.rstrip(b"\r").split(b":", 3)
        if len(fields) == 4 and fields[3]:
            names.append(fields[3].decode("utf-8", "surrogateescape"))
    return names


class DcapPlugin(Plugin):
    """dCache's dcap protocol, plain and GSI."""

    name = "dcap"
    schemes: ClassVar[tuple[str, ...]] = ("dcap", "gsidcap")
    option_group = GROUP
    #: After ``file``: gfal2 2.23 lists its plugins as http, srm, mock,
    #: xrootd, gridftp, file, dcap.
    priority = 700
    event_domain = "dcap"

    def __init__(self, context: Any) -> None:
        super().__init__(context)
        self._doors: dict[tuple[object, ...], Door] = {}
        self._lock = threading.Lock()

    # -- connections -----------------------------------------------------------------

    def _door(self, url: DcapURL) -> Door:
        factory = tunnel_factory(url.scheme)
        credential = self.context.x509(url.url(url.path)) if factory is not None else None
        key = (url.scheme, url.host.lower(), url.port, credential)
        with self._lock:
            door = self._doors.get(key)
            if door is None:

                def connect() -> ControlConnection:
                    tunnel = factory(self, url) if factory is not None else None
                    return ControlConnection.open(url, tunnel, self.option_timeout())

                door = self._doors[key] = Door(url, connect)
            return door

    def close(self) -> None:
        with self._lock:
            doors, self._doors = list(self._doors.values()), {}
        for door in doors:
            door.close()

    @staticmethod
    def _failure(reply: Reply, code: int | None = None) -> GError:
        """gfal2's error for a door's ``failed`` line (verified against dCache 11.2)."""
        # libdcap keeps the quotes around the door's message, and so does gfal2's text.
        message = reply.args[1] if len(reply.args) > 1 else " ".join(reply.args)
        return GError(
            f'Error reported by the external library dcap : "{message}", number : {_DESRVMSG}',
            error_code(reply.args) if code is None else code,
        )

    def _request(self, url: str, verb: str, extra: str = "") -> Reply:
        """One namespace request; a ``failed`` answer is returned, not raised."""
        parsed = parse_url(url)
        target = quote(parsed.wire())

        def exchange(conn: ControlConnection, session: int) -> Reply:
            conn.send_line(f"{session} 0 client {verb} {target}{extra} -uid={UID}")
            return conn.wait(session)

        return self._door(parsed).call(exchange)

    def _simple(self, url: str, verb: str, extra: str = "") -> None:
        reply = self._request(url, verb, extra)
        if reply.verb == "failed":
            raise self._failure(reply)

    # -- namespace -------------------------------------------------------------------

    def _stat(self, operation: str, url: str) -> Stat:
        reply = self._request(url, operation)
        if reply.verb == "failed":
            # dc_stat() sets errno to ENOENT whatever the door said.
            raise self._failure(reply, errno.ENOENT)
        if reply.verb != "stat":
            raise GError(f"Unexpected answer to {operation}: {reply.verb}", errno.EPROTO)
        return parse_stat(reply.args)

    def stat(self, url: str) -> Stat:
        return self._stat("stat", url)

    def lstat(self, url: str) -> Stat:
        return self._stat("lstat", url)

    def access(self, url: str, mode: int) -> None:
        """libdcap's ``dc_access``: a ``stat`` judged against the local uid and gid.

        dCache has no access check of its own over dcap, so this is advisory,
        as it is in gfal2. (libdcap lets one granted permission satisfy the
        others; each is checked separately here.)
        """
        info = self.stat(url)
        if mode == os.F_OK:
            return
        uid = getattr(os, "geteuid", lambda: -1)()
        gid = getattr(os, "getegid", lambda: -1)()
        for wanted, bits in (
            (os.R_OK, (_stat.S_IRUSR, _stat.S_IRGRP, _stat.S_IROTH)),
            (os.W_OK, (_stat.S_IWUSR, _stat.S_IWGRP, _stat.S_IWOTH)),
            (os.X_OK, (_stat.S_IXUSR, _stat.S_IXGRP, _stat.S_IXOTH)),
        ):
            if not mode & wanted:
                continue
            owner, group, other = bits
            allowed = info.st_mode & other or (
                (info.st_uid == uid and info.st_mode & owner)
                or (info.st_gid == gid and info.st_mode & group)
            )
            if not allowed:
                raise GError(
                    f"Permission denied for {url} (mode {mode})",
                    errno.EACCES,
                )

    def mkdir(self, url: str, mode: int) -> None:
        # libdcap applies the process umask and sends the mode in decimal.
        self._simple(url, "mkdir", f" -mode={mode & ~process_umask() & 0o7777}")

    def chmod(self, url: str, mode: int) -> None:
        self._simple(url, "chmod", f" -mode={mode & 0o7777}")

    def rmdir(self, url: str) -> None:
        self._simple(url, "rmdir")

    def unlink(self, url: str) -> None:
        self._simple(url, "unlink")

    def rename(self, old: str, new: str) -> None:
        """``dc_rename``: the door moves the entry to a path on the same namespace."""
        source, target = parse_url(old), parse_url(new)
        if (source.scheme, source.host.lower(), source.port) != (
            target.scheme,
            target.host.lower(),
            target.port,
        ):
            raise GError(f"Cannot rename across dcap doors: {old} -> {new}", errno.EXDEV)
        self._simple(old, "rename", f" {quote(target.path)}")

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        """The directory's names, read in full from dCache's directory lister.

        The lister's lines say ``d`` or ``f`` and a size, but not the
        permissions, owner or times, so entries come without a ``Stat`` and
        ``readpp`` asks for one.
        """
        parsed = parse_url(url)
        target = quote(parsed.wire())
        timeout = float(self.option_timeout())

        def exchange(conn: ControlConnection, session: int) -> DataChannel:
            listener, host, port = callback_listener(conn)
            try:
                conn.send_line(f"{session} 0 client opendir {target} {host} {port} -uid={UID}")
                sock = await_data(conn, session, listener, timeout, self._failure)
            finally:
                listener.close()
            return DataChannel(sock, "directory lister")

        channel = self._door(parsed).call(exchange)
        try:
            listing = read_listing(channel)
        finally:
            channel.close()
        return iter([(name, None) for name in parse_listing(listing)])

    # -- file I/O ----------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        parsed = parse_url(url)
        target = quote(parsed.wire())
        access = flags & O_ACCMODE_MASK
        io = "r" if access == O_RDONLY else "w" if access == O_WRONLY else "rw"
        extra = ""
        if flags & O_CREAT:
            extra += f" -mode=0{mode & 0o7777:o}"
            if flags & O_TRUNC:
                extra += " -truncate"
        timeout = float(self.option_timeout())
        door = self._door(parsed)

        def exchange(conn: ControlConnection, session: int) -> DcapFile:
            listener, host, port = callback_listener(conn)
            try:
                conn.send_line(
                    f"{session} 0 client open {target} {io}{extra} {host} {port} "
                    f"-timeout=-1 -onerror=default -passive -uid={UID}"
                )
                sock = await_data(conn, session, listener, timeout, self._failure)
            finally:
                listener.close()
            channel = DataChannel(sock)
            return DcapFile(url, flags, door, conn, session, channel, self._failure)

        return door.call(exchange, keep=True)


class KdcapPlugin(DcapPlugin):
    """``kdcap://``: dcap through a Kerberos 5 tunnel, once one is registered."""

    name = "kdcap"
    schemes: ClassVar[tuple[str, ...]] = ("kdcap",)
    priority = 710

    @classmethod
    def available(cls) -> str | None:
        return unavailable("kdcap")
