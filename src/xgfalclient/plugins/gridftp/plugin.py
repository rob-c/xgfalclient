"""``gsiftp://`` and ``ftp://`` - gfal2's GridFTP plugin, in Python.

What gfal2 does, verified against gfal2 2.23.5 and globus-gridftp-server 13
(the command sequences below are what gfal2 sends, read off the server's
log):

* **sessions**: ``AUTH GSSAPI``/``ADAT`` with delegation, ``USER
  :globus-mapping:``/``PASS dummy`` (``ftp://`` logs in as the credential's
  ``USER``/``PASSWD``, else ``[FTP] USER``/``PASSWORD``, else anonymous),
  ``FEAT``, ``SITE CLIENTINFO``, ``TYPE I``, ``DCAU N`` (``[GRIDFTP PLUGIN]
  DCAU=false``, the default). Sessions are pooled per host, port and
  credential when ``SESSION_REUSE`` is on.
* **paths**: as globus parses the URL - percent-decoded, and a ``?query``
  is part of the file name.
* **namespace**: ``MLST`` for stat, ``NLST`` (``TYPE A``) for listdir,
  ``MLSD`` for opendir (both after a stat: a file is ``EISDIR``, an
  unreadable directory ``EACCES``), ``MKD``/``RMD``/``DELE``,
  ``RNFR``/``RNTO``, ``SITE CHMOD 0644 path``, ``CKSM ALG offset length
  path`` (``0 -1`` for the whole file); ``access`` grants a permission any
  of user, group or other has. ``listxattr`` answers ``spacetoken`` and
  ``getxattr("spacetoken[?TOKEN]")`` asks ``SITE USAGE [TOKEN t] path``.
* **errors**: the reply text decides the ``errno`` ("No such file" is
  ``ENOENT``, "exists" ``EEXIST``...) and anything else is ``ECOMM``,
  exactly as gfal2's ``scan_errstring``; messages read
  ``globus_ftp_client: the server responded with an error 550 ...``.
* **I/O**: reads are ``RETR`` in ``MODE S`` after a stat (``STAT_ON_OPEN``;
  ``REST`` to resume after a seek), ``pread`` is ``ERET P offset length``,
  writes (``O_WRONLY`` or ``O_CREAT``, so Python's ``"rw"`` too) are
  ``STOR``, and ``O_RDWR`` alone reads with ``ERET`` and writes with
  ``ESTO``, as do writes after a seek. gfal2's delayed passive (``OPTS PASV
  AllowDelayed=1;`` then a ``127`` reply carrying the address), or, with
  ``GRIDFTP_V2`` and a server advertising ``GETPUT``, ``GET``/``PUT
  file=...;pasv;``.
* **third-party copies** (``3rd push``, domain ``GSIFTP``): gfal2's
  sequence - source checksum, ``TRANSFER:ENTER`` naming each end's
  ``(ip:port)``, ``TRANSFER:TYPE``, then the destination check
  (``OVERWRITE`` or ``DESTINATION EXISTS``) and parent directory, the move,
  ``TRANSFER:EXIT`` and the destination checksum, with gfal2's messages.
  ``MODE E`` on both ends (``MODE S`` and one stream when either end is
  ``ftp://``), ``SITE STORBUFSIZE``/``RETRBUFSIZE`` for ``tcp_buffersize``,
  destination ``PASV`` + ``ALLO`` + ``STOR``, source ``PORT`` + ``RETR``,
  progress from ``112`` performance markers and the ``PERF_MARKER_TIMEOUT``
  watchdog (not for ``ftp://``, which has no markers), sizes compared
  afterwards. ``RD_NB_STREAM``, when set, overrides ``nbstreams``;
  ``SKIP_SOURCE_CHECKSUM``, ``ENABLE_UDT`` (``SITE SETNETSTACK udt``, retried
  without it, events ``UDT:ENABLE``/``UDT:DISABLE``), ``ENABLE_PASV_PLUGIN``
  (events ``PASV`` and ``IPV4``/``IPV6``) and ``[CORE] RESOLVE_DNS`` are
  honoured. A bulk copy of GridFTP pairs is gfal2's: ``PREPARE`` (sources
  statted and checksummed, destinations prepared), the transfers over the
  pooled sessions, then ``CLOSE`` (sizes and destination checksums).

Where this deliberately differs from gfal2:

* gfal2 leaves ``file://`` <-> ``gsiftp://`` copies to its core's streamed
  copy (one ``MODE S`` stream). This plugin claims them and, with
  ``nbstreams`` (or ``RD_NB_STREAM``) above zero, moves the file over that
  many ``MODE E`` connections with ``pwrite`` reassembly - globus-url-copy's
  ``-p N``. With zero streams the bytes move exactly as gfal2 would move
  them. The events and the checks around the move are the core's, with the
  ``GSIFTP`` domain.
* A bulk copy runs its pairs one after another over pooled sessions rather
  than through globus' command pipeline, and a pair that fails in transfer
  fails alone; gfal2 aborts the whole pipeline with one error.
* A destination that fails its checksum is removed (``CLEANUP``), as the
  README says of every copy; gfal2 leaves it.
* A single third-party copy compares the two sizes afterwards (``EIO`` if
  they differ); gfal2 does that only for a bulk copy.
* A bulk copy between ``ftp://`` URLs works; gfal2's fails as a whole with
  ``ECOMM`` "No user supplied", its pipeline never logging in.
* ``BLOCK_SIZE`` sets the buffer this client's own data movers use; gfal2
  means to set globus' buffer but passes it 0.
* A seek while writing finishes the ``STOR`` cleanly before the ``ESTO``
  writes; gfal2 aborts it.
* A ``229`` reply's ``h1,h2,...`` form is read correctly for the PASV
  events; gfal2 shifts its numbers by one.
* ``GFAL2_GRIDFTP_DEBUG`` is not read: the control channel's commands and
  replies are logged at debug level to the ``gfal2`` logger instead of
  globus' debug output on stderr.
"""

from __future__ import annotations

import contextlib
import errno
import os
import random
import socket
import ssl
import stat as _stat
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from ... import events as ev
from ..._compat import SLOTS
from ..._version import GFAL2_VERSION
from ...checksum import checksums_match
from ...crypto.der import DERError
from ...crypto.x509 import Credential, load_credential
from ...errors import ECOMM, GError
from ...plugin import O_ACCMODE_MASK, O_CREAT, O_RDONLY, O_WRONLY, Plugin, PluginFile
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
    errno_for_reply,
    format_eprt,
    format_port,
    parse_facts,
    parse_pasv,
    passive_address,
    reply_error,
    stat_from_facts,
)

__all__ = ["GridFTPPlugin", "GROUP", "DOMAIN", "BULK_DOMAIN", "lookup_host"]

GROUP = "GRIDFTP PLUGIN"
DOMAIN = "GSIFTP"
#: The domain of gfal2's bulk-copy events.
BULK_DOMAIN = "GridFTP::Filecopy"
#: gfal2's ``ENOATTR`` is Linux's ``ENODATA``.
ENOATTR: int = getattr(errno, "ENOATTR", errno.ENODATA)
_SCHEMES = ("gsiftp", "ftp")
#: ``checksum_mode`` bits.
_SOURCE, _TARGET = 1, 2
#: The text a GridFTP server fails ``SITE SETNETSTACK udt`` with.
_NO_UDT = "udt driver not whitelisted"


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


class _TransferError(GError):
    """gfal2's ``TransferException``: reported as is, never cleaned up after.

    ``detail`` is the bare text; the message carries gfal2's ``SIDE NOTE``
    prefix.
    """

    def __init__(self, side: str, note: str, detail: str, code: int) -> None:
        super().__init__(f"{side} {note} {detail}", code)
        self.detail = detail


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
    """The path globus sends: percent-decoded, with any query as part of it."""
    raw = url.path or "/"
    if url.query:
        raw += "?" + url.query
    return check_path(urllib.parse.unquote(raw))


def _explicit_port(url: URL) -> int:
    """The port written in the URL, 0 without one (gfal2's ``gfal2_uri``)."""
    host = url.netloc.rpartition("@")[2]
    tail = host.rpartition("]")[2]
    text = tail.rpartition(":")[2] if ":" in tail else ""
    return int(text) if text.isdigit() else 0


def _check_url(url: URL) -> None:
    """``globus_url_parse``'s refusals, before any credential.

    No host, or a port that does not start with a digit (globus reads the
    leading number of ``h:0x``, as ``sscanf`` would).
    """
    tail = url.netloc.rpartition("@")[2].rpartition("]")[2]
    port = tail.rpartition(":")[2] if ":" in tail else "0"
    if not url.host or not port[:1].isdigit():
        raise GError("globus_ftp_client: an invalid value for url was used ", ECOMM)


def lookup_host(host: str, ipv6: bool) -> tuple[str, bool]:
    """gfal2's ``lookup_host``: an address of ``host`` and whether it has an IPv6 one.

    The last IPv4 and IPv6 addresses found are kept; the IPv6 one (in
    brackets) wins when ``ipv6`` is on.
    """
    try:
        found = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return "cant.be.resolved", False
    ip4 = ip6 = ""
    for family, _, _, _, address in found:
        if family == socket.AF_INET6:
            ip6 = str(address[0])
        else:
            ip4 = str(address[0])
    if ipv6 and ip6:
        return f"[{ip6}]", True
    return (ip4 or "cant.be.resolved"), bool(ip6)


def _host_and_port(url: str, ipv6: bool) -> str:
    parsed = parse(url)
    return f"{lookup_host(parsed.host, ipv6)[0]}:{_explicit_port(parsed)}"


def _pair_text(source: str, target: str, ipv6: bool) -> str:
    """``(ip:port) source => (ip:port) target``: gfal2's TRANSFER:ENTER/EXIT text."""
    return f"({_host_and_port(source, ipv6)}) {source} => ({_host_and_port(target, ipv6)}) {target}"


def _resolve_dns(url: str, what: str, log: Any) -> str:
    """``[CORE] RESOLVE_DNS``: the host replaced by the name of one of its addresses.

    As gfal2's ``resolve_dns_helper``: an address is picked at random and
    reverse-resolved; any failure leaves the URL as it was.
    """
    parsed = parse(url)
    host = parsed.host
    try:
        found = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        address = random.choice(found)[4][0]
        name = socket.gethostbyaddr(str(address))[0]
    except (OSError, UnicodeError):
        log.warning("Could not resolve DNS alias: %s", host)
        return url
    log.info("%s: %s => %s", what, host, name)
    userinfo, at, _ = parsed.netloc.rpartition("@")
    port = _explicit_port(parsed)
    netloc = f"{userinfo}{at}{name}" + (f":{port}" if port else "")
    return str(URL(parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


class GridFTPPlugin(Plugin):
    """GridFTP (``gsiftp://``) and plain FTP (``ftp://``)."""

    name = "gridftp"
    schemes = _SCHEMES
    option_group = GROUP
    priority = 500
    event_domain = DOMAIN
    #: gfal2's plugin emits TRANSFER:ENTER/EXIT itself (with ``(ip:port)``),
    #: and owns the destination and checksum checks around a copy.
    narrates_transfer = True
    copy_manages_destination = True
    copy_manages_checksums = True

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
        _check_url(url)
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
            # gfal2's gfal_gridftp_get_credentials: the credential, else [FTP].
            user = self.context.credentials.get("USER", text)[0] or self.options.string(
                "FTP", "USER", "anonymous"
            )
            password = self.context.credentials.get("PASSWD", text)[0] or self.options.string(
                "FTP", "PASSWORD", "anonymous"
            )
        return _Profile(
            key=("ftp", url.host, url.port, user, password),
            host=url.host,
            port=url.port,
            user=user,
            password=password,
            timeout=timeout,
        )

    def _client_info(self, scheme: str) -> str:
        """``SITE CLIENTINFO``'s argument, as globus writes gfal2's clientinfo."""
        name, version = self.context.get_user_agent()
        if name:
            application, release = name, f"{version} (gfal2 {GFAL2_VERSION})"
        else:
            application, release = "gfal2", GFAL2_VERSION
        extra = self.context.client_info_string()
        return f'scheme={scheme};appname="{application}";appver="{release}";{extra}'

    def _connect(self, profile: _Profile) -> Control:
        control = Control(profile.host, profile.port, timeout=profile.timeout)
        try:
            control.connect()
            if profile.tls is not None:
                control.authenticate(profile.tls, profile.delegate)
            control.login(profile.user, profile.password)
            scheme = "ftp" if profile.tls is None else "gsiftp"
            control.command(f"SITE CLIENTINFO {self._client_info(scheme)}", ok=(2, 4, 5))
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

    def _stat_facts(self, control: Control, path: str) -> tuple[Stat, bool]:
        """The stat of ``path``, and whether the server gave its permissions."""
        if control.supports("MLST"):
            reply = control.command(f"MLST {path}")
            for line in reply.lines[1:]:
                if line.startswith(" "):
                    facts, _ = parse_facts(line[1:])
                    return stat_from_facts(facts), "unix.mode" in facts
            raise GError(f"[{path}]: Bad MLST response", errno.EPROTO)
        try:
            size = int(control.command(f"SIZE {path}").text.split()[0])
        except GError as exc:
            try:
                control.command(f"CWD {path}")
            except GError:
                raise exc from None
            return Stat(st_mode=_stat.S_IFDIR | 0o755, st_nlink=1), True
        return Stat(st_mode=_stat.S_IFREG | 0o644, st_size=size, st_nlink=1), True

    def _stat(self, control: Control, path: str) -> Stat:
        return self._stat_facts(control, path)[0]

    def _data_options(self) -> ChannelOptions:
        return ChannelOptions(
            ipv6=self.options.boolean(GROUP, "IPV6", False),
            spas=self.options.boolean(GROUP, "SPAS", False),
            delayed=self.options.boolean(GROUP, "DELAY_PASSV", True),
        )

    def _getput(self, *controls: Control) -> bool:
        """GridFTP v2 ``GET``/``PUT``: ``GRIDFTP_V2`` and servers advertising ``GETPUT``."""
        wanted = self.options.boolean(GROUP, "GRIDFTP_V2", True)
        return wanted and all(control.supports("GETPUT") for control in controls)

    def _buffer_size(self) -> int:
        block = self.options.integer(GROUP, "BLOCK_SIZE", 0)
        if block > 0:
            return int(block)
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

    def _exists(self, url: str) -> bool:
        """gfal2's ``exists``: a stat, where only ``ENOENT`` means no."""
        try:
            self.stat(url)
        except GError as exc:
            if exc.code != errno.ENOENT:
                raise
            return False
        return True

    # -- namespace ------------------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        parsed = parse(url)
        with self._session(parsed) as session:
            return self._stat(session.control, _path(parsed))

    def access(self, url: str, mode: int) -> None:
        """Granted if user, group or other has the bit; a server hiding modes grants all."""
        parsed = parse(url)
        with self._session(parsed) as session:
            info, known = self._stat_facts(session.control, _path(parsed))
        if not known:
            self.log.info(
                "Access request is not managed by this server %s , "
                "return access authorized by default",
                url,
            )
            return
        wanted = ((os.R_OK, 0o444, "read"), (os.W_OK, 0o222, "write"), (os.X_OK, 0o111, "execute"))
        for flag, bits, what in wanted:
            if mode & flag and not info.st_mode & bits:
                raise GError(f"No {what} access", errno.EACCES)

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

    def _listing(self, url: str, command: str, kind: str) -> tuple[bytes, bool]:
        """gfal2's opendir: stat first (a file is ``EISDIR``), then list."""
        parsed = parse(url)
        path = _path(parsed)
        with self._session(parsed) as session:
            control = session.control
            info, known = self._stat_facts(control, path)
            if not info.is_dir():
                raise GError(f"{url} is not a directory", errno.EISDIR)
            if known and not info.st_mode & 0o444:
                raise GError(f"Can not read {url}", errno.EACCES)
            if command == "MLSD" and not control.supports("MLST"):
                command, kind = "NLST", "A"
            return self._fetch(session, f"{command} {path}", kind), command == "MLSD"

    def listdir(self, url: str) -> list[str]:
        return _names(self._listing(url, "NLST", "A")[0])

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        raw, facts = self._listing(url, "MLSD", "I")
        if not facts:
            return iter([(name, None) for name in _names(raw)])
        entries: list[tuple[str, Stat | None]] = []
        for line in raw.decode("utf-8", "replace").splitlines():
            found, name = parse_facts(line)
            entries.append((name, stat_from_facts(found)))
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
        value = reply.text.strip()
        # gfal2 replaces a reply that is not a plain checksum with zeros.
        return value if value.isalnum() else "0" * 16

    def listxattr(self, url: str) -> list[str]:
        return ["spacetoken"]

    def getxattr(self, url: str, name: str) -> str:
        """``spacetoken[?TOKEN]``: ``SITE USAGE``, as json-c prints gfal2's space report."""
        if not name.startswith("spacetoken"):
            raise GError(f"'{name}' extended attributed not supported by GridFTP plugin", ENOATTR)
        token = name.partition("?")[2] if "?" in name else ""
        parsed = parse(url)
        with self._session(parsed) as session:
            command = (
                f"SITE USAGE TOKEN {token} {_path(parsed)}"
                if token
                else f"SITE USAGE {_path(parsed)}"
            )
            reply = session.control.command(command, ok=(2, 3, 4, 5))
        if reply.code != 250:
            text = "".join(f"{line}  " for line in reply.lines) + " "
            raise GError(text, errno_for_reply(text))
        fields = reply.lines[0].split()
        try:
            if fields[1:6:2] != ["USAGE", "FREE", "TOTAL"]:
                raise ValueError(reply.lines[0])
            used, free, total = int(fields[2]), int(fields[4]), int(fields[6])
        except (IndexError, ValueError):
            text = "Invalid SITE USAGE response from server."
            raise GError(text, errno_for_reply(text)) from None
        if total < 0 and free >= 0 and used >= 0:
            total = free + used
        return f'{{ "totalsize": {total}, "unusedsize": {free}, "usedsize": {used} }}'

    # -- files ----------------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        """gfal2's modes: read-only is ``RETR``, ``O_WRONLY``/``O_CREAT`` is ``STOR``
        (so ``"rw"`` truncates), and ``O_RDWR`` alone is partial ``ERET``/``ESTO``."""
        parsed = parse(url)
        if flags & O_ACCMODE_MASK == O_RDONLY:
            return _ReadFile(self, url, parsed)
        if flags & (O_WRONLY | O_CREAT):
            return _WriteFile(self, url, parsed, size)
        return _PartialFile(self, url, parsed)

    def _partial_put(
        self, url: str, parsed: URL, data: bytes | bytearray | memoryview, offset: int
    ) -> int:
        """``ESTO A offset path`` on a session of its own: a write at ``offset``."""
        handle = _WriteFile(self, url, parsed, None, f"ESTO A {offset} {_path(parsed)}")
        try:
            return handle.write(data)
        finally:
            handle.close()

    def _partial_get(self, parsed: URL, offset: int, size: int) -> bytes:
        with self._session(parsed) as session:
            return self._fetch(session, f"ERET P {offset} {size} {_path(parsed)}")

    # -- copies ---------------------------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        ends = (scheme_of(source), scheme_of(destination))
        remote = [end in _SCHEMES for end in ends]
        return all(remote) or (any(remote) and "file" in ends)

    def _streams(self, transfer: Any) -> int:
        """``RD_NB_STREAM`` when set, else ``nbstreams`` (gfal2's precedence)."""
        configured = self.options.integer(GROUP, "RD_NB_STREAM", 0)
        return int(configured or transfer.params.nbstreams or 0)

    def copy(self, transfer: Any) -> None:
        if "file" in (scheme_of(transfer.source), scheme_of(transfer.destination)):
            self._local_copy(transfer)
        else:
            self._filecopy(transfer)

    # -- file:// <-> gridftp: the core's checks, this plugin's data movers --------------

    def _local_copy(self, transfer: Any) -> None:
        from ... import transfer as core

        strict = transfer.params.strict_copy
        algorithm = transfer.checksum_algorithm or self.checksum_type()
        if not strict:
            core._verify_source(transfer, algorithm)
            core._prepare_destination(transfer)
        transfer.event(ev.TRANSFER_ENTER, transfer.pair)
        transfer.owns_destination = not strict
        try:
            if scheme_of(transfer.source) == "file":
                self._upload(transfer)
            else:
                self._download(transfer)
            transfer.event(ev.TRANSFER_EXIT, transfer.pair)
            if not strict:
                core._verify_destination(transfer, algorithm)
        except Exception:
            core._cleanup(transfer, True)
            transfer.owns_destination = False  # cleaned: the core must not again
            raise

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
                    getput = self._getput(control)
                    self._move(
                        session,
                        transfer,
                        f"GET file={path};pasv;" if getput else f"RETR {path}",
                        1,
                        lambda conn, _: recv_stream(conn, write, size, transfer.add),
                        getput=getput,
                    )
                received = os.fstat(fd).st_size
            finally:
                os.close(fd)
        _compare(info.st_size, received)
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
                getput = False
                if streams > 0:
                    control.setting("MODE", "E")
                    ranges = Ranges(0, info.st_size, size)
                    worker = lambda conn, index: send_blocks(  # noqa: E731
                        conn, read, ranges, transfer.add, size, streams if index == 0 else 0
                    )
                else:
                    control.setting("MODE", "S")
                    getput = self._getput(control)
                    worker = lambda conn, _: send_stream(conn, read, size, transfer.add)  # noqa: E731
                control.command(f"ALLO {info.st_size}", ok=(2, 4, 5))
                command = f"PUT file={path};pasv;" if getput else f"STOR {path}"
                self._move(session, transfer, command, max(streams, 1), worker, getput=getput)
        finally:
            os.close(fd)
        transfer.progress(info.st_size, force=True)

    # -- gridftp <-> gridftp: gfal2's GridFTPModule::filecopy ----------------------------

    def _copy_checksum(self, url: str, algorithm: str) -> str:
        return self.checksum(url, algorithm, 0, 0)

    def _filecopy(self, transfer: Any) -> None:
        source, target = transfer.source, transfer.destination
        ipv6 = self.options.boolean(GROUP, "IPV6", False)
        if self.options.boolean("CORE", "RESOLVE_DNS", False):
            source = _resolve_dns(source, "Resolving source", self.log)
            target = _resolve_dns(target, "Resolving destination", self.log)
        mode = 0 if transfer.params.strict_copy else int(transfer.checksum_mode)
        if self.options.boolean(GROUP, "SKIP_SOURCE_CHECKSUM", False):
            mode &= ~_SOURCE
        algorithm = transfer.checksum_algorithm or self.checksum_type()
        user = transfer.user_checksum
        source_sum = ""
        if mode & _SOURCE:
            transfer.event(ev.CHECKSUM_ENTER, algorithm, ev.SOURCE)
            source_sum = self._copy_checksum(source, algorithm)
            transfer.event(ev.CHECKSUM_EXIT, f"{algorithm}={source_sum}", ev.SOURCE)
            if user and not checksums_match(user, source_sum):
                raise _TransferError(
                    "TRANSFER",
                    "CHECKSUM MISMATCH",
                    f"USER_DEFINE and SRC checksums are different. {user} != {source_sum}",
                    errno.EIO,
                )
        text = _pair_text(source, target, ipv6)
        transfer.event(ev.TRANSFER_ENTER, text)
        transfer.event(ev.TRANSFER_TYPE, "3rd push")
        try:
            self._copy_internal(transfer, source, target)
        except _TransferError:
            raise
        except GError as exc:
            if exc.code != errno.EEXIST:
                self._clean(target)
            raise GError(f"TRANSFER  {exc.message}", exc.code) from exc
        transfer.event(ev.TRANSFER_EXIT, text)
        if mode & _TARGET:
            transfer.event(ev.CHECKSUM_ENTER, algorithm, ev.DESTINATION)
            target_sum = self._copy_checksum(target, algorithm)
            transfer.event(ev.CHECKSUM_EXIT, algorithm, ev.DESTINATION)
            if mode & _SOURCE:
                good = checksums_match(source_sum, target_sum)
                detail = (
                    "SRC and DST checksum are different. "
                    f"Source: {source_sum} Destination: {target_sum}"
                )
            else:
                good = checksums_match(user, target_sum)
                detail = f"USER_DEFINE and DST checksums are different. {user} != {target_sum}"
            if not good:
                self._clean_after_mismatch(transfer, target)
                raise _TransferError("TRANSFER", "CHECKSUM MISMATCH", detail, errno.EIO)

    def _clean(self, url: str) -> None:
        """gfal2's ``autoCleanFileCopy``: remove a failed destination, quietly."""
        self.log.info("\t\tError in transfer, clean destination file %s ", url)
        try:
            self.unlink(url)
        except GError:
            self.log.debug("\t\tFailure in cleaning ...")

    def _clean_after_mismatch(self, transfer: Any, url: str) -> None:
        """Deliberately more than gfal2: a copy that fails its checksum is removed."""
        if not transfer.params.transfer_cleanup:
            return
        try:
            self.unlink(url)
            code = 0
        except GError as exc:
            # Already gone counts as cleaned, as gfal2's plugins report it.
            code = 0 if exc.code == errno.ENOENT else exc.code
        transfer.event(ev.CLEANUP, str(code), ev.DESTINATION)

    def _delete_existing(self, transfer: Any, url: str) -> bool:
        """``OVERWRITE`` an existing destination, or refuse it; True if deleted."""
        if not self._exists(url):
            return False
        if not transfer.params.overwrite:
            raise _TransferError(
                "DESTINATION", "EXISTS", f" Destination already exist {url}, Cancel", errno.EEXIST
            )
        self.unlink(url)
        transfer.event(ev.OVERWRITE, f"Deleted {url}", ev.DESTINATION)
        return True

    def _create_parent(self, transfer: Any, url: str) -> None:
        if not transfer.params.create_parent:
            return
        parent = url.rstrip("/").rpartition("/")[0]
        try:
            info = self.stat(parent)
        except GError as exc:
            if exc.code != errno.ENOENT:
                raise
        else:
            if not info.is_dir():
                raise _TransferError(
                    "DESTINATION",
                    "",
                    "The parent of the destination file exists, but it is not a directory",
                    errno.ENOTDIR,
                )
            return
        self.context.mkdir_rec(parent, 0o755)

    def _copy_internal(self, transfer: Any, source: str, target: str) -> None:
        if not transfer.params.strict_copy and not self._delete_existing(transfer, target):
            self._create_parent(transfer, target)
        streams = self._streams(transfer)
        udt = self.options.boolean(GROUP, "ENABLE_UDT", False)
        if udt:
            self.log.info("Trying UDT transfer")
            transfer.event("UDT:ENABLE", "Trying UDT")
        try:
            self._third_party(transfer, source, target, streams, udt)
        except GError as exc:
            if not udt or _NO_UDT not in exc.message:
                raise
            self.log.warning("UDT transfer failed! Disabling and retrying...")
            transfer.event("UDT:DISABLE", f"UDT failed. Falling back to default mode: {exc}")
            self._third_party(transfer, source, target, streams, False)

    def _third_party(
        self,
        transfer: Any,
        source_url: str,
        target_url: str,
        streams: int,
        udt: bool,
        compare: bool = True,
    ) -> None:
        """Move the bytes; with ``compare``, check the sizes (bulk copies do it at CLOSE)."""
        source, target = parse(source_url), parse(target_url)
        plain = "ftp" in (source.scheme, target.scheme)
        with self._session(source) as src, self._session(target) as dst:
            try:
                info: Stat | None = self._stat(src.control, _path(source))
            except GError:
                # gfal2 asks SIZE and carries on: RETR reports the real problem.
                info = None
            # A directory is RETR's to refuse, as it is for gfal2.
            size = None if info is None or info.is_dir() else info.st_size
            transfer.source_size = size
            copy = _ThirdParty(self, transfer, src.control, dst.control, streams, plain, udt)
            copy.run(_path(source), _path(target), size, target.host)
            if size is not None and compare:
                _compare(size, self._stat(dst.control, _path(target)).st_size)
            if size is not None:
                transfer.progress(size, force=True)

    # -- bulk -------------------------------------------------------------------------------

    def copy_bulk(self, params: Any, transfers: Sequence[Any]) -> list[GError | None]:
        """gfal2's ``gridftp_bulk_copy`` for GridFTP pairs; one copy at a time otherwise."""
        both = [
            scheme_of(item.source) in _SCHEMES and scheme_of(item.destination) in _SCHEMES
            for item in transfers
        ]
        if all(both):
            return _Bulk(self, params, list(transfers)).run()
        from ...transfer import run_copy

        results: list[GError | None] = []
        for item in transfers:
            try:
                user = (item.checksum_algorithm, item.user_checksum)
                run_copy(self.context, params, item.source, item.destination, user)
                results.append(None)
            except GError as exc:
                results.append(exc)
        return results


def _names(raw: bytes) -> list[str]:
    """The names of an ``NLST`` listing (some servers send paths, or blank lines)."""
    return [
        line.rstrip("/").rsplit("/", 1)[-1]
        for line in raw.decode("utf-8", "replace").splitlines()
        if line
    ]


def _compare(expected: int, actual: int) -> None:
    if expected != actual:
        raise GError(
            f"Source and destination file sizes do not match: {expected} != {actual}", errno.EIO
        )


class _Bulk:
    """``PREPARE`` every pair, move them, then ``CLOSE`` them: gfal2's bulk copy."""

    def __init__(self, plugin: GridFTPPlugin, params: Any, transfers: list[Any]) -> None:
        self.plugin = plugin
        self.params = params
        self.transfers = transfers
        self.errors: list[GError | None] = [None] * len(transfers)
        self.sizes = [0] * len(transfers)
        self.sums = [item.user_checksum for item in transfers]
        mode, algorithm, _ = params.get_checksum()
        self.mode = 0 if params.strict_copy else int(mode)
        self.algorithm = algorithm or plugin.checksum_type()

    def event(
        self, stage: str, text: str = "", side: int = ev.BOTH, domain: str = BULK_DOMAIN
    ) -> None:
        self.transfers[0].event(stage, text, side, domain)

    def pending(self) -> list[tuple[int, Any]]:
        return [(i, t) for i, t in enumerate(self.transfers) if self.errors[i] is None]

    def run(self) -> list[GError | None]:
        self.event(ev.PREPARE_ENTER)
        self._sources()
        self._destinations()
        self.event(ev.PREPARE_EXIT)
        started = self._transfer()
        for index in started:
            item = self.transfers[index]
            self.event(ev.TRANSFER_EXIT, f"Done {item.source} => {item.destination}")
        self._close()
        return self.errors

    def _sources(self) -> None:
        plugin = self.plugin
        for index, item in self.pending():
            try:
                item.check()
                info = plugin.stat(item.source)
                if info.is_dir():
                    raise GError("File is a directory", errno.EISDIR)
                self.sizes[index] = info.st_size
                if self.mode & _SOURCE:
                    item.event(ev.CHECKSUM_ENTER, item.source, ev.SOURCE, BULK_DOMAIN)
                    try:
                        value = plugin._copy_checksum(item.source, self.algorithm)
                        if not self.sums[index]:
                            self.sums[index] = value
                        elif not checksums_match(self.sums[index], value):
                            raise GError(
                                "SOURCE CHECKSUM MISMATCH User checksum and source checksum do "
                                f"not match: {self.sums[index]} != {value}",
                                errno.EIO,
                            )
                    finally:
                        item.event(ev.CHECKSUM_EXIT, item.source, ev.SOURCE, BULK_DOMAIN)
            except GError as exc:
                self.errors[index] = exc

    def _destinations(self) -> None:
        plugin = self.plugin
        parents: list[str] = []
        for index, item in self.pending():
            try:
                item.check()
                if self.params.strict_copy:
                    continue
                plugin._delete_existing(item, item.destination)
                parent = item.destination.rpartition("/")[0]
                if parent not in parents:
                    plugin._create_parent(item, item.destination)
                    parents.append(parent)
            except _TransferError as exc:
                self.errors[index] = GError(exc.detail, exc.code)
            except GError as exc:
                self.errors[index] = exc

    def _transfer(self) -> list[int]:
        plugin = self.plugin
        ipv6 = plugin.options.boolean(GROUP, "IPV6", False)
        started = []
        for index, item in self.pending():
            text = _pair_text(item.source, item.destination, ipv6)
            item.event(ev.TRANSFER_ENTER, text, domain=BULK_DOMAIN)
            item.event(ev.TRANSFER_TYPE, "3rd push")
            try:
                item.check()
                streams = plugin._streams(item)
                plugin._third_party(item, item.source, item.destination, streams, False, False)
                started.append(index)
            except GError as exc:
                self.errors[index] = exc
        return started

    def _close(self) -> None:
        plugin = self.plugin
        self.event("CLOSE:ENTER")
        for index, item in self.pending():
            try:
                size = plugin.stat(item.destination).st_size
                if size != self.sizes[index]:
                    raise GError(
                        "DESTINATION SIZE MISMATCH Source and destination file sizes do not "
                        f"match: {self.sizes[index]} != {size}",
                        errno.EIO,
                    )
                if self.mode & _TARGET:
                    item.event(ev.CHECKSUM_ENTER, item.destination, ev.DESTINATION, BULK_DOMAIN)
                    try:
                        value = plugin._copy_checksum(item.destination, self.algorithm)
                        if self.sums[index] and not checksums_match(self.sums[index], value):
                            raise GError(
                                "DESTINATION CHECKSUM MISMATCH Destination checksum do not "
                                f"match: {self.sums[index]} != {value}",
                                errno.EIO,
                            )
                    finally:
                        # gfal2 names the source in this event.
                        item.event(ev.CHECKSUM_EXIT, item.source, ev.DESTINATION, BULK_DOMAIN)
            except GError as exc:
                self.errors[index] = exc
        self.event("CLOSE:EXIT")


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
        plain: bool,
        udt: bool,
    ) -> None:
        self.plugin = plugin
        self.transfer = transfer
        self.source = source
        self.destination = destination
        #: ``ftp://`` at either end: stream mode, one connection, no markers.
        self.plain = plain
        self.streams = 0 if plain else streams
        self.udt = udt
        self.options = plugin._data_options()
        self.markers: dict[int, int] = {}
        self.marker_timeout = (
            0 if plain else plugin.options.integer(GROUP, "PERF_MARKER_TIMEOUT", 360)
        )
        self.last_progress = time.monotonic()
        self.best = 0

    def run(self, source_path: str, target_path: str, size: int | None, host: str) -> None:
        src, dst = self.source, self.destination
        options = self.plugin.options
        if options.boolean(GROUP, "ENABLE_PASV_PLUGIN", False):
            dst.observer = lambda reply: self._passive_event(reply, host)
        try:
            buffer = int(self.transfer.params.tcp_buffersize or 0)
            for control, verb in ((dst, "STORBUFSIZE"), (src, "RETRBUFSIZE")):
                control.setting("TYPE", "I")
                control.setting("MODE", "S" if self.plain else "E")
                if self.udt:
                    control.command("SITE SETNETSTACK udt")
                if buffer > 0:
                    control.command(f"SITE {verb} {buffer}", ok=(2, 4, 5))
            if self.streams > 1:
                n = self.streams
                src.setting("OPTS RETR", f"Parallelism={n},{n},{n};")
            getput = (
                self.plugin._getput(src, dst)
                and not self.options.spas
                and not self.options.ipv6
                and not src.ipv6
            )
            addresses = [] if getput else passive(dst, self.options)
            if size is not None:
                dst.command(f"ALLO {size}", ok=(2, 4, 5))
            dst.send(f"PUT file={target_path};pasv;" if getput else f"STOR {target_path}")
            if not addresses:
                addresses = [self._delayed_address()]
            if getput:
                src.send(f"GET file={source_path};port={format_port(*addresses[0])};")
            else:
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
        finally:
            dst.observer = None

    def _passive_event(self, reply: Reply, host: str) -> None:
        """gfal2's PASV plugin: where the destination listens, as events."""
        found = passive_address(reply)
        if found is None:
            return
        ip, port, ipv6 = found
        if not ip:
            ip, ipv6 = lookup_host(host, self.options.ipv6)
        self.transfer.event("PASV", f"{host}:{ip}:{port}", ev.DESTINATION)
        self.transfer.event("IPV6" if ipv6 else "IPV4", f"{ip}:{port}", ev.DESTINATION)

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
        #: Where the file ends, once known: from the stat, or the stream's end.
        self._size: int | None = None
        if plugin.options.boolean(GROUP, "STAT_ON_OPEN", True):
            with plugin._session(parsed) as session:
                try:
                    info = plugin._stat(session.control, self.path)
                except GError as exc:
                    if exc.code != errno.ENOENT:
                        raise
                    raise _open_error(exc, url) from exc
            # gfal2 opens a directory, and reading it gives nothing.
            self._size = 0 if info.is_dir() else info.st_size

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return _lseek(self, offset, whence)

    def _start(self) -> None:
        self._stop()
        self._session_cm = self.plugin._session(self.parsed)
        self._session = session = self._session_cm.__enter__()
        control = session.control
        control.setting("MODE", "S")
        if self.position:
            control.command(f"REST {self.position}", ok=(3,))
        getput = not self.position and self.plugin._getput(control)
        command = f"GET file={self.path};pasv;" if getput else f"RETR {self.path}"
        self._conn = _stream_open(self.plugin, session, command, self.url, getput)
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
        if self._size is not None and self.position >= self._size:
            return 0
        if self._conn is None or self._stream_at != self.position:
            self._start()
        assert self._conn is not None
        got = 0
        while got < len(view):
            count = self._conn.recv_into(view[got:])
            if count == 0:
                self._finish()
                self._size = self.position + got
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
        if size <= 0 or (self._size is not None and offset >= self._size):
            return b""
        if self._size is not None:
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
    """A ``STOR`` stream; the server's verdict arrives on :meth:`close`.

    A write anywhere but at the end of what the stream has sent - after a
    seek, which commits the stream, or a ``pwrite`` - is gfal2's partial
    put, an ``ESTO``.
    """

    def __init__(
        self,
        plugin: GridFTPPlugin,
        url: str,
        parsed: URL,
        size: int | None,
        command: str | None = None,
    ) -> None:
        super().__init__(url)
        self.plugin = plugin
        self.parsed = parsed
        self._stream_at = 0
        self._session_cm = plugin._session(parsed)
        self._session: _Session = self._session_cm.__enter__()
        try:
            control = self._session.control
            control.setting("MODE", "S")
            if size is not None:
                control.command(f"ALLO {size}", ok=(2, 4, 5))
            getput = command is None and plugin._getput(control)
            if command is None:
                path = _path(parsed)
                command = f"PUT file={path};pasv;" if getput else f"STOR {path}"
            self._conn: DataConn | None = _stream_open(plugin, self._session, command, url, getput)
        except BaseException:
            self._session.control.broken = True
            self._session_cm.__exit__(None, None, None)
            raise

    def write(self, data: bytes | bytearray | memoryview) -> int:
        if self.closed:
            raise GError("I/O operation on a closed file", errno.EBADF)
        if self._conn is None:  # committed by a seek: gfal2's partial put
            count = self.plugin._partial_put(self.url, self.parsed, data, self.position)
        else:
            try:
                self._conn.sendall(data)
            except OSError as exc:
                self._session.control.broken = True
                raise GError(
                    f"gridftp write error : {exc.strerror or exc} on url {self.url}", errno.EIO
                ) from exc
            count = len(memoryview(data).cast("B"))
            self._stream_at += count
        self.position += count
        return count

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        if self.closed:
            raise GError("I/O operation on a closed file", errno.EBADF)
        return self.plugin._partial_put(self.url, self.parsed, data, offset)

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        target = _lseek(self, offset, whence)
        if target != self._stream_at:
            self._commit()
        return target

    def _commit(self) -> None:
        """End the ``STOR`` stream; its reply decides whether the upload worked."""
        conn, self._conn = self._conn, None
        if conn is None:
            return
        control = self._session.control
        try:
            conn.finish()
            control.final()
        except GError:
            control.broken = True
            raise

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self._commit()
        finally:
            self._session_cm.__exit__(None, None, None)


class _PartialFile(PluginFile):
    """``O_RDWR`` without ``O_CREAT``: every read an ``ERET``, every write an ``ESTO``."""

    def __init__(self, plugin: GridFTPPlugin, url: str, parsed: URL) -> None:
        super().__init__(url)
        self.plugin = plugin
        self.parsed = parsed

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return _lseek(self, offset, whence)

    def pread(self, offset: int, size: int) -> bytes:
        return self.plugin._partial_get(self.parsed, offset, max(0, size))

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        return self.plugin._partial_put(self.url, self.parsed, data, offset)


def _lseek(handle: PluginFile, offset: int, whence: int) -> int:
    """gfal2's GridFTP seek: from the start or the cursor only."""
    if whence not in (os.SEEK_SET, os.SEEK_CUR):
        raise GError("Invalid whence", errno.EINVAL)
    return PluginFile.lseek(handle, offset, whence)


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


def _stream_open(
    plugin: GridFTPPlugin, session: _Session, command: str, url: str, getput: bool = False
) -> DataConn:
    """Start a ``MODE S`` stream for ``command``; the connection once the server is ready.

    A ``getput`` command (GridFTP v2 ``GET``/``PUT ...;pasv;``) asks for the
    passive address itself.
    """
    control = session.control
    opener = _Opener(session)
    try:
        control.setting("TYPE", "I")
        addresses = [] if getput else passive(control, plugin._data_options())
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
