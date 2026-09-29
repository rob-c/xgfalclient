"""``gsiftp://`` and ``ftp://`` - gfal2's GridFTP plugin, in Python.

What gfal2 does, verified against gfal2 2.23.5 and globus-gridftp-server 13
(the command sequences below are what gfal2 sends, read off the server's
log):

* **sessions**: ``AUTH GSSAPI``/``ADAT`` with delegation, ``USER
  :globus-mapping:``/``PASS dummy``, ``FEAT``, ``SITE CLIENTINFO``, ``TYPE
  I``, ``DCAU N`` (``[GRIDFTP PLUGIN] DCAU=false``, the default). Sessions
  are pooled per host, port and credential when ``SESSION_REUSE`` is on.
* **namespace**: ``MLST`` for stat, ``NLST`` (``TYPE A``) for listdir,
  ``MLSD`` for opendir, ``MKD``/``RMD``/``DELE``, ``RNFR``/``RNTO``,
  ``SITE CHMOD 0644 path``, ``CKSM ALG offset length path`` (``0 -1`` for
  the whole file); ``listxattr`` answers ``spacetoken`` and ``getxattr``
  of it asks ``SITE USAGE``.
* **errors**: the reply text decides the ``errno`` ("No such file" is
  ``ENOENT``, "exists" ``EEXIST``...) and anything else is ``ECOMM``,
  exactly as gfal2's ``scan_errstring``; messages read
  ``globus_ftp_client: the server responded with an error 550 ...``.
* **I/O**: reads are ``RETR`` in ``MODE S`` (``REST`` to resume after a
  seek), ``pread`` is ``ERET P offset length``, writes are ``STOR``, with
  gfal2's delayed passive (``OPTS PASV AllowDelayed=1;`` then a ``127``
  reply carrying the address).
* **third-party copies** (``3rd push``, domain ``GSIFTP``): ``MODE E`` on
  both ends, destination ``PASV`` + ``ALLO`` + ``STOR``, source ``PORT`` +
  ``RETR``, progress from ``112`` performance markers and the
  ``PERF_MARKER_TIMEOUT`` watchdog, sizes compared afterwards.

Where this deliberately does more than gfal2: gfal2 leaves ``file://`` <->
``gsiftp://`` copies to its core's streamed copy (one ``MODE S`` stream).
This plugin claims them and, with ``nbstreams`` (or ``RD_NB_STREAM``) above
zero, moves the file over that many ``MODE E`` connections with ``pwrite``
reassembly - globus-url-copy's ``-p N``. With zero streams the bytes move
exactly as gfal2 would move them. The events still say ``streamed``.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import socket
import ssl
import stat as _stat
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from ... import events as ev
from ..._compat import SLOTS
from ...crypto.der import DERError
from ...crypto.x509 import Credential, load_credential
from ...errors import GError
from ...plugin import O_ACCMODE_MASK, O_RDONLY, O_RDWR, Plugin, PluginFile
from ...types import Stat
from ...url import URL, parse, scheme_of
from ..file import local_path
from .control import Control, connect_error
from .data import (
    ChannelOptions,
    DataConn,
    DataSecurity,
    DataTransfer,
    EodCounter,
    Ranges,
    Reader,
    Writer,
    passive,
    perf_bytes,
    recv_blocks,
    recv_stream,
    routable,
    send_blocks,
    send_stream,
)
from .gsi import data_contexts
from .protocol import (
    Reply,
    check_path,
    format_eprt,
    format_port,
    parse_facts,
    parse_pasv,
    reply_error,
    stat_from_facts,
)

__all__ = ["GridFTPPlugin", "GROUP", "DOMAIN"]

GROUP = "GRIDFTP PLUGIN"
DOMAIN = "GSIFTP"
#: gfal2's ``ENOATTR`` is Linux's ``ENODATA``.
ENOATTR: int = getattr(errno, "ENOATTR", errno.ENODATA)
_SCHEMES = ("gsiftp", "ftp")


@dataclass(frozen=True, **SLOTS)
class _Profile:
    """Everything a session to one URL needs, worked out once per call."""

    key: tuple[object, ...]
    host: str
    port: int
    user: str
    password: str
    timeout: float
    #: The TLS context for GSI; ``None`` for cleartext ``ftp://``.
    tls: ssl.SSLContext | None = None
    delegate: Credential | None = None
    security: DataSecurity | None = None


class _Session:
    """A control connection lent out of the pool, with the profile it was made for."""

    __slots__ = ("control", "profile")

    def __init__(self, control: Control, profile: _Profile) -> None:
        self.control = control
        self.profile = profile


def _pwrite(fd: int, view: memoryview, offset: int) -> None:
    while view:
        written = os.pwrite(fd, view, offset)
        view = view[written:]
        offset += written


def _pread(fd: int) -> Reader:
    def read(view: memoryview, offset: int) -> int:
        return int(os.preadv(fd, [view], offset))

    return read


def _path(url: URL) -> str:
    return check_path(url.path or "/")


class GridFTPPlugin(Plugin):
    """GridFTP (``gsiftp://``) and plain FTP (``ftp://``)."""

    name = "gridftp"
    schemes = _SCHEMES
    option_group = GROUP
    priority = 500
    event_domain = DOMAIN

    def __init__(self, context: Any) -> None:
        super().__init__(context)
        self._lock = threading.Lock()
        self._idle: dict[tuple[object, ...], list[Control]] = {}
        self._credentials: dict[tuple[object, ...], Credential] = {}

    # -- sessions --------------------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            idle, self._idle = self._idle, {}
        for controls in idle.values():
            for control in controls:
                control.close()

    def _credential(self, cert: str, key: str) -> Credential:
        try:
            stamp = (cert, key, os.stat(cert).st_mtime)
            with self._lock:
                found = self._credentials.get(stamp)
            if found is None:
                found = load_credential(cert, key)
                with self._lock:
                    self._credentials[stamp] = found
        except (OSError, DERError, ValueError) as exc:
            raise GError(
                f"Could not load the X.509 credential {cert}: {exc}", errno.EACCES
            ) from exc
        return found

    def _profile(self, url: URL) -> _Profile:
        text = str(url)
        timeout = float(self.option_timeout())
        if url.scheme == "gsiftp":
            x509 = self.context.x509(text)
            if x509 is None:
                raise GError(
                    "globus_gsi_gssapi: Error with GSI credential: no proxy or certificate found",
                    errno.EACCES,
                )
            tls = self.context.ssl_context(text, group=GROUP, check_hostname=False)
            credential = self._credential(x509.cert, x509.key)
            security = None
            encrypt = self.options.boolean(GROUP, "ENCRYPTION", False)
            if self.options.boolean(GROUP, "DCAU", False) or encrypt:
                initiator, acceptor = data_contexts(x509.cert, x509.key, self.context.ca_path())
                person = next((c for c in credential.chain if not c.is_proxy), credential.chain[-1])
                security = DataSecurity(initiator, acceptor, person.subject.rdns, encrypt)
            delegate = credential if self.options.boolean(GROUP, "DELEGATION", True) else None
            return _Profile(
                key=(
                    "gsiftp",
                    url.host,
                    url.port,
                    x509.cert,
                    x509.key,
                    security is not None,
                    encrypt,
                    delegate is not None,
                ),
                host=url.host,
                port=url.port,
                tls=tls,
                delegate=delegate,
                user=":globus-mapping:",
                password="dummy",
                security=security,
                timeout=timeout,
            )
        user, _, password = url.userinfo.partition(":")
        if not user:
            user = self.context.credentials.get("USER", text)[0] or self.options.string(
                GROUP, "USER", "anonymous"
            )
            password = self.context.credentials.get("PASSWD", text)[0] or self.options.string(
                GROUP, "PASSWORD", "anonymous"
            )
        return _Profile(
            key=("ftp", url.host, url.port, user, password),
            host=url.host,
            port=url.port,
            user=user,
            password=password,
            timeout=timeout,
        )

    def _connect(self, profile: _Profile) -> Control:
        control = Control(profile.host, profile.port, timeout=profile.timeout)
        try:
            control.connect()
            if profile.tls is not None:
                control.authenticate(profile.tls, profile.delegate)
            control.login(profile.user, profile.password)
            name, version = self.context.get_user_agent()
            from ..._version import __version__

            control.command(
                f"SITE CLIENTINFO scheme={'ftp' if profile.tls is None else 'gsiftp'};"
                f'appname="{name or "xgfalclient"}";appver="{version or __version__}";',
                ok=(2, 4, 5),
            )
            control.setting("TYPE", "I")
            if profile.tls is not None:
                control.setting("DCAU", "N" if profile.security is None else "A")
                if profile.security is not None and profile.security.private:
                    control.setting("PBSZ", "1048576")
                    control.setting("PROT", "P")
        except BaseException:
            control.broken = True
            control.close()
            raise
        return control

    @contextlib.contextmanager
    def _session(self, url: URL) -> Iterator[_Session]:
        profile = self._profile(url)
        control = None
        with self._lock:
            idle = self._idle.get(profile.key, [])
            while idle and control is None:
                candidate = idle.pop()
                if candidate.healthy():
                    control = candidate
                else:
                    candidate.close()
        if control is None:
            control = self._connect(profile)
        try:
            yield _Session(control, profile)
        finally:
            self._release(profile, control)

    def _release(self, profile: _Profile, control: Control) -> None:
        if self.options.boolean(GROUP, "SESSION_REUSE", True) and control.healthy():
            with self._lock:
                self._idle.setdefault(profile.key, []).append(control)
        else:
            control.close()

    # -- shared pieces -----------------------------------------------------------------

    def _stat(self, control: Control, path: str) -> Stat:
        if control.supports("MLST"):
            reply = control.command(f"MLST {path}")
            for line in reply.lines[1:]:
                if line.startswith(" "):
                    facts, _ = parse_facts(line[1:])
                    return stat_from_facts(facts)
            raise GError(f"[{path}]: Bad MLST response", errno.EPROTO)
        try:
            size = int(control.command(f"SIZE {path}").text.split()[0])
        except GError as exc:
            try:
                control.command(f"CWD {path}")
            except GError:
                raise exc from None
            return Stat(st_mode=_stat.S_IFDIR | 0o755, st_nlink=1)
        return Stat(st_mode=_stat.S_IFREG | 0o644, st_size=size, st_nlink=1)

    def _data_options(self) -> ChannelOptions:
        return ChannelOptions(
            ipv6=self.options.boolean(GROUP, "IPV6", False),
            spas=self.options.boolean(GROUP, "SPAS", False),
            delayed=self.options.boolean(GROUP, "DELAY_PASSV", True),
        )

    def _buffer_size(self) -> int:
        return max(65536, int(self.options.integer("CORE", "COPY_BUFFERSIZE", 4194304)))

    def _fetch(self, session: _Session, command: str, kind: str = "I") -> bytes:
        """Run ``command`` over a ``MODE S`` data channel and collect what it sends.

        gfal2 lists names in ``TYPE A``; everything else moves in ``TYPE I``.
        """
        control = session.control
        control.setting("TYPE", kind)
        control.setting("MODE", "S")
        chunks = bytearray()

        def worker(conn: DataConn, index: int) -> None:
            recv_stream(conn, lambda view, _: chunks.extend(view), 65536, lambda n: None)

        DataTransfer(
            control,
            streams=1,
            worker=worker,
            security=session.profile.security,
            check=lambda: None,
            timeout=session.profile.timeout,
        ).run(command, self._data_options())
        return bytes(chunks)

    # -- namespace ------------------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        parsed = parse(url)
        with self._session(parsed) as session:
            return self._stat(session.control, _path(parsed))

    def access(self, url: str, mode: int) -> None:
        info = self.stat(url)
        wanted = [(os.R_OK, _stat.S_IRUSR), (os.W_OK, _stat.S_IWUSR), (os.X_OK, _stat.S_IXUSR)]
        for flag, bit in wanted:
            if mode & flag and not info.st_mode & bit:
                raise GError(f"Permission denied: {url}", errno.EACCES)

    def chmod(self, url: str, mode: int) -> None:
        parsed = parse(url)
        with self._session(parsed) as session:
            session.control.command(f"SITE CHMOD {mode & 0o7777:04o} {_path(parsed)}")

    def mkdir(self, url: str, mode: int) -> None:
        parsed = parse(url)
        with self._session(parsed) as session:
            session.control.command(f"MKD {_path(parsed)}")

    def rmdir(self, url: str) -> None:
        parsed = parse(url)
        with self._session(parsed) as session:
            session.control.command(f"RMD {_path(parsed)}")

    def unlink(self, url: str) -> None:
        parsed = parse(url)
        with self._session(parsed) as session:
            session.control.command(f"DELE {_path(parsed)}")

    def rename(self, old: str, new: str) -> None:
        source, target = parse(old), parse(new)
        with self._session(source) as session:
            control = session.control
            # globus_ftp_client sends RNTO whatever RNFR said, and gfal2 reports
            # the RNTO reply - "501 Invalid command arguments" for a missing source.
            first = control.command(f"RNFR {_path(source)}", ok=(2, 3, 4, 5))
            second = control.command(f"RNTO {_path(target)}", ok=(2, 3, 4, 5))
            for reply in (second, first):
                if reply.kind > 3:
                    raise reply_error(reply)

    def listdir(self, url: str) -> list[str]:
        parsed = parse(url)
        with self._session(parsed) as session:
            raw = self._fetch(session, f"NLST {_path(parsed)}", "A")
        return [
            line.rstrip("/").rsplit("/", 1)[-1]
            for line in raw.decode("utf-8", "replace").splitlines()
            if line
        ]

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        parsed = parse(url)
        with self._session(parsed) as session:
            if not session.control.supports("MLST"):
                return iter([(name, None) for name in self.listdir(url)])
            raw = self._fetch(session, f"MLSD {_path(parsed)}")
        entries: list[tuple[str, Stat | None]] = []
        for line in raw.decode("utf-8", "replace").splitlines():
            facts, name = parse_facts(line)
            entries.append((name, stat_from_facts(facts)))
        return iter(entries)

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        parsed = parse(url)
        limit = self.options.integer(
            GROUP, "CHECKSUM_CALC_TIMEOUT", self.options.integer("CORE", "CHECKSUM_TIMEOUT", 1800)
        )
        with self._session(parsed) as session:
            control = session.control
            control.timeout, saved = float(limit), control.timeout
            try:
                span = length if length > 0 else -1
                reply = control.command(f"CKSM {algorithm} {offset} {span} {_path(parsed)}")
            finally:
                control.timeout = saved
        return reply.text.strip()

    def listxattr(self, url: str) -> list[str]:
        return ["spacetoken"]

    def getxattr(self, url: str, name: str) -> str:
        if name != "spacetoken":
            raise GError(f"'{name}' extended attributed not supported by GridFTP plugin", ENOATTR)
        parsed = parse(url)
        token = parsed.query_dict().get("spacetoken", "")
        with self._session(parsed) as session:
            command = (
                f"SITE USAGE TOKEN {token} {_path(parsed)}"
                if token
                else f"SITE USAGE {_path(parsed)}"
            )
            reply = session.control.command(command)
        fields = reply.text.split()
        try:
            used, free, total = int(fields[1]), int(fields[3]), int(fields[5])
        except (IndexError, ValueError):
            raise GError("Invalid SITE USAGE response from server.", errno.EPROTO) from None
        return json.dumps(
            [{"spacetoken": token, "totalsize": total, "unusedsize": free, "usedsize": used}]
        )

    # -- files ----------------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        parsed = parse(url)
        access = flags & O_ACCMODE_MASK
        if access == O_RDWR:
            raise GError(
                f"gridftp open error : read-write access is not supported on url {url}",
                errno.ENOTSUP,
            )
        if access == O_RDONLY:
            return _ReadFile(self, url, parsed)
        return _WriteFile(self, url, parsed, size)

    # -- copies ---------------------------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        ends = (scheme_of(source), scheme_of(destination))
        remote = [end in _SCHEMES for end in ends]
        return all(remote) or (any(remote) and "file" in ends)

    def _streams(self, transfer: Any) -> int:
        count = int(transfer.params.nbstreams or 0)
        return count if count > 0 else self.options.integer(GROUP, "RD_NB_STREAM", 0)

    def copy(self, transfer: Any) -> None:
        if scheme_of(transfer.source) == "file":
            self._upload(transfer)
        elif scheme_of(transfer.destination) == "file":
            self._download(transfer)
        else:
            self._third_party(transfer)

    def _move(
        self,
        session: _Session,
        transfer: Any,
        command: str,
        streams: int,
        worker: Callable[[DataConn, int], object],
        **run: Any,
    ) -> None:
        session.control.setting("TYPE", "I")
        DataTransfer(
            session.control,
            streams=streams,
            worker=worker,
            security=session.profile.security,
            check=transfer.check,
            timeout=session.profile.timeout,
        ).run(command, self._data_options(), **run)

    def _download(self, transfer: Any) -> None:
        transfer.event(ev.TRANSFER_TYPE, "streamed")
        source = parse(transfer.source)
        path = _path(source)
        streams = self._streams(transfer)
        size = self._buffer_size()
        with self._session(source) as session:
            control = session.control
            info = self._stat(control, path)
            if info.is_dir():
                raise GError(f"{transfer.source} is a directory", errno.EISDIR)
            transfer.source_size = info.st_size
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(local_path(transfer.destination), flags, 0o644)
            try:
                write: Writer = lambda view, offset: _pwrite(fd, view, offset)  # noqa: E731
                if streams > 0:
                    control.setting("MODE", "E")
                    control.setting("OPTS RETR", f"Parallelism={streams},{streams},{streams};")
                    eods = EodCounter()
                    self._move(
                        session,
                        transfer,
                        f"RETR {path}",
                        streams,
                        lambda conn, _: recv_blocks(conn, write, size, transfer.add, eods),
                        active=True,
                        done=eods.done,
                    )
                else:
                    control.setting("MODE", "S")
                    self._move(
                        session,
                        transfer,
                        f"RETR {path}",
                        1,
                        lambda conn, _: recv_stream(conn, write, size, transfer.add),
                    )
                received = os.fstat(fd).st_size
            finally:
                os.close(fd)
        self._compare(info.st_size, received)
        transfer.progress(received, force=True)

    def _upload(self, transfer: Any) -> None:
        transfer.event(ev.TRANSFER_TYPE, "streamed")
        target = parse(transfer.destination)
        path = _path(target)
        streams = self._streams(transfer)
        size = self._buffer_size()
        try:
            fd = os.open(local_path(transfer.source), os.O_RDONLY)
        except OSError as exc:
            raise GError(f"Could not open source: {exc.strerror}", exc.errno or errno.EIO) from exc
        try:
            info = os.fstat(fd)
            if _stat.S_ISDIR(info.st_mode):
                raise GError(f"{transfer.source} is a directory", errno.EISDIR)
            transfer.source_size = info.st_size
            read = _pread(fd)
            with self._session(target) as session:
                control = session.control
                worker: Callable[[DataConn, int], object]
                if streams > 0:
                    control.setting("MODE", "E")
                    ranges = Ranges(0, info.st_size, size)
                    worker = lambda conn, index: send_blocks(  # noqa: E731
                        conn, read, ranges, transfer.add, size, streams if index == 0 else 0
                    )
                else:
                    control.setting("MODE", "S")
                    worker = lambda conn, _: send_stream(conn, read, size, transfer.add)  # noqa: E731
                control.command(f"ALLO {info.st_size}", ok=(2, 4, 5))
                self._move(session, transfer, f"STOR {path}", max(streams, 1), worker)
        finally:
            os.close(fd)
        transfer.progress(info.st_size, force=True)

    @staticmethod
    def _compare(expected: int, actual: int) -> None:
        if expected != actual:
            raise GError(
                f"Source and destination file sizes do not match: {expected} != {actual}", errno.EIO
            )

    def _third_party(self, transfer: Any) -> None:
        transfer.event(ev.TRANSFER_TYPE, "3rd push")
        source, target = parse(transfer.source), parse(transfer.destination)
        streams = self._streams(transfer)
        options = self._data_options()
        with self._session(source) as src, self._session(target) as dst:
            try:
                try:
                    info: Stat | None = self._stat(src.control, _path(source))
                except GError:
                    # gfal2 asks SIZE and carries on: RETR reports the real problem.
                    info = None
                if info is not None and info.is_dir():
                    raise GError(f"{transfer.source} is a directory", errno.EISDIR)
                size = None if info is None else info.st_size
                transfer.source_size = size
                _ThirdParty(self, transfer, src.control, dst.control, streams, options).run(
                    _path(source), _path(target), size
                )
                if size is not None:
                    self._compare(size, self._stat(dst.control, _path(target)).st_size)
                    transfer.progress(size, force=True)
            except GError as exc:
                raise GError(f"TRANSFER  {exc.message}", exc.code) from exc


class _ThirdParty:
    """Server-to-server: the destination listens, the source connects and sends."""

    POLL = 0.2

    def __init__(
        self,
        plugin: GridFTPPlugin,
        transfer: Any,
        source: Control,
        destination: Control,
        streams: int,
        options: ChannelOptions,
    ) -> None:
        self.plugin = plugin
        self.transfer = transfer
        self.source = source
        self.destination = destination
        self.streams = streams
        self.options = options
        self.markers: dict[int, int] = {}
        self.marker_timeout = plugin.options.integer(GROUP, "PERF_MARKER_TIMEOUT", 360)
        self.last_progress = time.monotonic()
        self.best = 0

    def run(self, source_path: str, target_path: str, size: int | None) -> None:
        src, dst = self.source, self.destination
        try:
            for control in (src, dst):
                control.setting("TYPE", "I")
                control.setting("MODE", "E")
            if self.streams > 1:
                n = self.streams
                src.setting("OPTS RETR", f"Parallelism={n},{n},{n};")
            addresses = passive(dst, self.options)
            if size is not None:
                dst.command(f"ALLO {size}", ok=(2, 4, 5))
            dst.send(f"STOR {target_path}")
            if not addresses:
                addresses = [self._delayed_address()]
            if self.options.spas:
                src.command("SPOR " + " ".join(format_port(h, p) for h, p in addresses))
            elif self.options.ipv6 or src.ipv6:
                src.command(f"EPRT {format_eprt(*addresses[0])}")
            else:
                src.command(f"PORT {format_port(*addresses[0])}")
            src.send(f"RETR {source_path}")
            self._await()
        except BaseException:
            src.broken = dst.broken = True
            raise

    def _delayed_address(self) -> tuple[str, int]:
        """The destination's ``127`` reply to ``STOR``: where the source must connect."""
        reply = self.destination.reply()
        if reply.code != 127:
            raise reply_error(reply)
        host, port = parse_pasv(reply.text)
        return routable(host, self.destination), port

    def _marker(self, reply: Reply) -> None:
        total = perf_bytes(self.markers, reply)
        if total is not None and total > self.best:
            self.best = total
            self.last_progress = time.monotonic()
            self.transfer.progress(total)

    def _watchdog(self) -> None:
        self.transfer.check()
        timeout = self.marker_timeout
        if timeout > 0 and time.monotonic() - self.last_progress > timeout:
            raise GError(
                f"Transfer canceled because the gsiftp performance marker timeout of {timeout} "
                "seconds has been exceeded, or all performance markers during that period "
                "indicated zero bytes transferred",
                errno.ETIMEDOUT,
            )

    def _await(self) -> None:
        pending = [self.source, self.destination]
        while pending:
            for control in list(pending):
                reply = control.poll(self.POLL / len(pending))
                if reply is None:
                    continue
                if reply.kind == 1:
                    self._marker(reply)
                elif reply.kind == 2:
                    pending.remove(control)
                else:
                    raise reply_error(reply)
            self._watchdog()


class _ReadFile(PluginFile):
    """A ``RETR`` stream read in order; ``REST`` restarts it after a seek."""

    def __init__(self, plugin: GridFTPPlugin, url: str, parsed: URL) -> None:
        super().__init__(url)
        self.plugin = plugin
        self.parsed = parsed
        self.path = _path(parsed)
        self._session_cm: Any = None
        self._session: _Session | None = None
        self._conn: DataConn | None = None
        self._stream_at = -1
        with plugin._session(parsed) as session:
            try:
                info = plugin._stat(session.control, self.path)
            except GError as exc:
                raise _open_error(exc, url) from exc
        if info.is_dir():
            raise GError(
                f" gridftp open error : {os.strerror(errno.EISDIR)} on url {url}", errno.EISDIR
            )
        self._size = info.st_size

    def size(self) -> int:
        return self._size

    def _start(self) -> None:
        self._stop()
        self._session_cm = self.plugin._session(self.parsed)
        self._session = session = self._session_cm.__enter__()
        control = session.control
        control.setting("MODE", "S")
        if self.position:
            control.command(f"REST {self.position}", ok=(3,))
        self._conn = _stream_open(self.plugin, session, f"RETR {self.path}", self.url)
        self._stream_at = self.position

    def _stop(self, clean: bool = False) -> None:
        if self._session_cm is None:
            return
        assert self._session is not None
        if self._conn is not None:
            self._conn.sock.close()
            self._conn = None
        if not clean:
            self._session.control.broken = True
        cm, self._session_cm, self._session = self._session_cm, None, None
        cm.__exit__(None, None, None)

    def readinto(self, buffer: memoryview | bytearray) -> int:
        view = memoryview(buffer).cast("B")
        if self.position >= self._size:
            return 0
        if self._conn is None or self._stream_at != self.position:
            self._start()
        assert self._conn is not None
        got = 0
        while got < len(view):
            count = self._conn.recv_into(view[got:])
            if count == 0:
                self._finish()
                break
            got += count
        self.position += got
        self._stream_at += got
        return got

    def _finish(self) -> None:
        assert self._session is not None
        try:
            self._session.control.final()
        except GError:
            self._stop()
            raise
        self._stop(clean=True)

    def read(self, size: int) -> bytes:
        buffer = bytearray(max(0, size))
        count = self.readinto(buffer)
        return bytes(buffer[:count])

    def pread(self, offset: int, size: int) -> bytes:
        if offset >= self._size or size <= 0:
            return b""
        size = min(size, self._size - offset)
        with self.plugin._session(self.parsed) as session:
            if session.control.supports("ERET"):
                return self.plugin._fetch(session, f"ERET P {offset} {size} {self.path}")
        saved = self.position
        try:
            self.position = offset
            return self.read(size)
        finally:
            self._stop()
            self.position = saved

    def close(self) -> None:
        self._stop()
        super().close()


class _WriteFile(PluginFile):
    """A ``STOR`` stream; the server's verdict arrives on :meth:`close`."""

    def __init__(self, plugin: GridFTPPlugin, url: str, parsed: URL, size: int | None) -> None:
        super().__init__(url)
        self._session_cm = plugin._session(parsed)
        self._session: _Session = self._session_cm.__enter__()
        try:
            control = self._session.control
            control.setting("MODE", "S")
            if size is not None:
                control.command(f"ALLO {size}", ok=(2, 4, 5))
            self._conn: DataConn | None = _stream_open(
                plugin, self._session, f"STOR {_path(parsed)}", url
            )
        except BaseException:
            self._session.control.broken = True
            self._session_cm.__exit__(None, None, None)
            raise

    def write(self, data: bytes | bytearray | memoryview) -> int:
        if self._conn is None:
            raise GError("I/O operation on a closed file", errno.EBADF)
        try:
            self._conn.sendall(data)
        except OSError as exc:
            self._session.control.broken = True
            raise GError(
                f"gridftp write error : {exc.strerror or exc} on url {self.url}", errno.EIO
            ) from exc
        count = len(memoryview(data).cast("B"))
        self.position += count
        return count

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        if offset != self.position:
            raise GError("Only sequential writes are supported over GridFTP", errno.ENOTSUP)
        return self.write(data)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        conn, self._conn = self._conn, None
        control = self._session.control
        try:
            assert conn is not None
            conn.finish()
            control.final()
        except GError:
            control.broken = True
            raise
        finally:
            self._session_cm.__exit__(None, None, None)


def _open_error(exc: GError, url: str) -> GError:
    return GError(f" gridftp open error : {os.strerror(exc.code)} on url {url}", exc.code)


class _Opener:
    """Connect (and, under ``DCAU A``, authenticate) one stream's data channel.

    globus says ``150`` only once the data channel is authenticated, so the
    handshake runs on a thread while the control channel is watched: waiting
    for ``150`` first would deadlock, and handshaking first would hang on a
    server that refused the command instead.
    """

    def __init__(self, session: _Session) -> None:
        self.session = session
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.result: list[DataConn | BaseException] = []

    def start(self, host: str, port: int) -> None:
        timeout = self.session.profile.timeout
        try:
            self.sock = socket.create_connection((host, port), timeout)
        except OSError as exc:
            raise connect_error(exc, host, port) from exc
        self.thread = threading.Thread(target=self._secure, name="xgfal-gridftp-open", daemon=True)
        self.thread.start()

    def _secure(self) -> None:
        assert self.sock is not None
        security = self.session.profile.security
        try:
            conn = DataConn(self.sock) if security is None else security.secure(self.sock, True)
            self.result.append(conn)
        except BaseException as exc:  # handed to the opening thread
            self.result.append(exc)

    def finish(self) -> DataConn:
        if self.thread is None:
            raise GError("The server started the transfer without a data channel", errno.EPROTO)
        self.thread.join()  # the handshake is bounded by the socket's own timeout
        found = self.result[0]
        if isinstance(found, BaseException):
            raise found
        return found

    def abandon(self) -> None:
        if self.sock is not None:
            self.sock.close()


def _stream_open(plugin: GridFTPPlugin, session: _Session, command: str, url: str) -> DataConn:
    """Start a ``MODE S`` stream for ``command``; the connection once the server is ready."""
    control = session.control
    opener = _Opener(session)
    try:
        control.setting("TYPE", "I")
        addresses = passive(control, plugin._data_options())
        if addresses:
            opener.start(*addresses[0])
        control.send(command)
        while True:
            reply = control.reply()
            if reply.code == 127 and opener.thread is None:
                host, port = parse_pasv(reply.text)
                opener.start(routable(host, control), port)
            elif reply.kind == 1:
                return opener.finish()
            else:
                raise reply_error(reply)
    except GError as exc:
        control.broken = True
        opener.abandon()
        raise _open_error(exc, url) from exc
