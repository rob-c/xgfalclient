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

How the code is laid out (this module is the facade and the plugin class):

* :mod:`._base` - sessions: the option group and event domains, the per-URL
  profile (credential, TLS, data-channel security), the control-connection
  pool, globus' view of a URL, gfal2's host helpers, and
  ``_GridFTPBase``, the plugin's root class (connect, log in, pool, stat,
  ``MODE S`` fetch).
* :mod:`._copy` - ``copy_check``/``copy``/``copy_bulk`` as ``_CopyMixin``:
  local <-> GridFTP copies with the parallel data movers, gfal2's
  third-party ``filecopy`` and its checks, and the ``_ThirdParty`` and
  ``_Bulk`` engines.
* :mod:`._files` - ``open`` as ``_FilesMixin`` and the three handles it
  returns (``_ReadFile``, ``_WriteFile``, ``_PartialFile``), with the data
  connection opener.
* this module - :class:`GridFTPPlugin` itself (``_CopyMixin`` +
  ``_FilesMixin``, plus the class attributes the registry reads) and the
  namespace operations: ``stat``, ``access``, ``chmod``, ``mkdir``,
  ``rmdir``, ``unlink``, ``rename``, ``listdir``, ``opendir``,
  ``checksum``, ``listxattr``, ``getxattr``.

The names the single-module layout had - its helpers, private classes and
the names it imported, except the unused ``_stat``, ``urllib`` and ``ev`` -
are re-exported here, so
``from xgfalclient.plugins.gridftp.plugin import X`` keeps working. The split
modules do not look names up through this one at call time, because nothing
patches a module-level name they use: patch a class attribute (such as
``_ThirdParty.POLL``) on the class, or a helper in the module that defines it.
"""

from __future__ import annotations

# The stdlib names the single-module layout imported stay attributes of this
# module (tests reach ``os`` through it to patch ``os.pwrite``).
import contextlib as contextlib
import errno
import os
import random as random
import socket as socket
import ssl as ssl
import threading as threading
import time as time
from collections.abc import Callable as Callable
from collections.abc import Iterator
from collections.abc import Sequence as Sequence
from dataclasses import dataclass as dataclass
from typing import Any as Any

from xrdsec.der import DERError as DERError

# Everything below is re-exported with a redundant ``as`` so mypy's strict
# no-implicit-reexport and ruff both treat it as this module's API.
from ..._version import GFAL2_VERSION as GFAL2_VERSION
from ...checksum import checksums_match as checksums_match
from ...crypto.x509 import Credential as Credential
from ...crypto.x509 import load_credential as load_credential
from ...errors import ECOMM as ECOMM
from ...errors import GError
from ...plugin import O_ACCMODE_MASK as O_ACCMODE_MASK
from ...plugin import O_CREAT as O_CREAT
from ...plugin import O_RDONLY as O_RDONLY
from ...plugin import O_WRONLY as O_WRONLY
from ...plugin import Plugin as Plugin
from ...plugin import PluginFile as PluginFile
from ...plugin import shutdown_sockets as shutdown_sockets
from ...types import Stat
from ...url import URL as URL
from ...url import parse
from ...url import scheme_of as scheme_of
from ..file import local_path as local_path
from ._base import _NO_UDT as _NO_UDT
from ._base import _SCHEMES as _SCHEMES
from ._base import _SOURCE as _SOURCE
from ._base import _TARGET as _TARGET
from ._base import BULK_DOMAIN as BULK_DOMAIN
from ._base import DOMAIN as DOMAIN
from ._base import ENOATTR as ENOATTR
from ._base import GROUP as GROUP
from ._base import _check_url as _check_url
from ._base import _explicit_port as _explicit_port
from ._base import _GridFTPBase as _GridFTPBase
from ._base import _host_and_port as _host_and_port
from ._base import _pair_text as _pair_text
from ._base import _path as _path
from ._base import _Profile as _Profile
from ._base import _resolve_dns as _resolve_dns
from ._base import _Session as _Session
from ._base import lookup_host as lookup_host
from ._copy import _Bulk as _Bulk
from ._copy import _compare as _compare
from ._copy import _CopyMixin as _CopyMixin
from ._copy import _pread as _pread
from ._copy import _pwrite as _pwrite
from ._copy import _ThirdParty as _ThirdParty
from ._copy import _TransferError as _TransferError
from ._files import _FilesMixin as _FilesMixin
from ._files import _lseek as _lseek
from ._files import _open_error as _open_error
from ._files import _Opener as _Opener
from ._files import _PartialFile as _PartialFile
from ._files import _ReadFile as _ReadFile
from ._files import _stream_open as _stream_open
from ._files import _WriteFile as _WriteFile
from .control import Control as Control
from .control import connect_error as connect_error
from .data import ChannelOptions as ChannelOptions
from .data import DataConn as DataConn
from .data import DataSecurity as DataSecurity
from .data import DataTransfer as DataTransfer
from .data import EodCounter as EodCounter
from .data import Feed as Feed
from .data import Ranges as Ranges
from .data import Reader as Reader
from .data import Writer as Writer
from .data import passive as passive
from .data import perf_bytes as perf_bytes
from .data import recv_blocks as recv_blocks
from .data import recv_stream as recv_stream
from .data import routable as routable
from .data import send_blocks as send_blocks
from .data import send_stream as send_stream
from .gsi import data_contexts as data_contexts
from .protocol import Reply as Reply
from .protocol import check_path as check_path
from .protocol import errno_for_reply, parse_facts, reply_error, stat_from_facts
from .protocol import format_eprt as format_eprt
from .protocol import format_port as format_port
from .protocol import parse_pasv as parse_pasv
from .protocol import passive_address as passive_address

__all__ = ["BULK_DOMAIN", "DOMAIN", "GROUP", "GridFTPPlugin", "lookup_host"]


class GridFTPPlugin(_CopyMixin, _FilesMixin):
    """GridFTP (``gsiftp://``) and plain FTP (``ftp://``).

    One instance per context, created by the plugin registry. It is
    thread-safe: every method borrows its own session from the pool in
    :class:`~._base._GridFTPBase`, and errors are :class:`GError` with
    gfal2's ``errno`` and wording (see the module docstring).
    """

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

    # -- namespace ------------------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        """``MLST`` facts, or ``SIZE``/``CWD`` on a server without ``MLST``."""
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
        """``SITE CHMOD`` with a four-digit octal mode (the file-type bits dropped)."""
        parsed = parse(url)
        with self._session(parsed) as session:
            session.control.command(f"SITE CHMOD {mode & 0o7777:04o} {_path(parsed)}")

    def mkdir(self, url: str, mode: int) -> None:
        """``MKD``; FTP has no way to pass ``mode``, so the server's default applies."""
        parsed = parse(url)
        with self._session(parsed) as session:
            session.control.command(f"MKD {_path(parsed)}")

    def rmdir(self, url: str) -> None:
        """``RMD``; globus's ``451 Directory not empty`` maps to ``ECOMM``, as in gfal2."""
        parsed = parse(url)
        with self._session(parsed) as session:
            session.control.command(f"RMD {_path(parsed)}")

    def unlink(self, url: str) -> None:
        """``DELE``."""
        parsed = parse(url)
        with self._session(parsed) as session:
            session.control.command(f"DELE {_path(parsed)}")

    def rename(self, old: str, new: str) -> None:
        """``RNFR``/``RNTO`` (RFC 959) on the source's session; ``new``'s host is not checked.

        The ``RNTO`` reply is reported in preference to the ``RNFR`` one,
        which is what gfal2's message shows.
        """
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
        """The entry names, from ``NLST`` in ``TYPE A`` (gfal2's choice)."""
        return _names(self._listing(url, "NLST", "A")[0])

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        """Entries with their stats from ``MLSD``; names only (stat ``None``) without ``MLST``.

        The listing is read whole before iteration starts, so the session is
        back in the pool before the caller sees the first entry.
        """
        raw, facts = self._listing(url, "MLSD", "I")
        if not facts:
            return iter([(name, None) for name in _names(raw)])
        entries: list[tuple[str, Stat | None]] = []
        for line in raw.decode("utf-8", "replace").splitlines():
            found, name = parse_facts(line)
            entries.append((name, stat_from_facts(found)))
        return iter(entries)

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        """globus's ``CKSM algorithm offset length path``; ``length`` 0 means the whole file.

        Servers compute it on demand, which can take long for a big file, so
        the session's reply timeout is raised for this one command to
        ``CHECKSUM_CALC_TIMEOUT`` (else ``[CORE] CHECKSUM_TIMEOUT``, 1800 s)
        and restored after.
        """
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
        """Only ``spacetoken``, as gfal2's plugin lists, without asking the server."""
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


def _names(raw: bytes) -> list[str]:
    """The names of an ``NLST`` listing (some servers send paths, or blank lines)."""
    return [
        line.rstrip("/").rsplit("/", 1)[-1]
        for line in raw.decode("utf-8", "replace").splitlines()
        if line
    ]
