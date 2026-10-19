"""``lfc://``, ``lfn:`` and ``guid:``: the LCG File Catalog.

The LFC is a namespace of logical file names with, for each file, a GUID,
a size, an optional checksum, a comment and a list of *replicas* - the
storage URLs (SURLs) holding copies. gfal2 had a plugin for it until 2.22
(``src/plugins/lfc/`` there, removed with LFC's retirement); this one
follows it call for call, over :mod:`.client` instead of liblfc.

URLs, as gfal2's ``url_converter`` reads them:

``lfc://host[:port]/path``
    that catalogue and path, used as given;
``lfn:/path``
    the catalogue named by ``$LFC_HOST`` (else ``[LFC PLUGIN] LFC_HOST``),
    with doubled and trailing slashes removed;
``guid:<guid>``
    the file with that GUID in the ``$LFC_HOST`` catalogue - resolved to its
    path with ``Cns_getlinks``. Namespace changes (``rename``, ``mkdir``,
    ``rmdir``, ``opendir``, ``symlink``, ``readlink``) are refused for
    GUIDs, as in gfal2.

What each operation does is gfal2's: ``stat`` is ``Cns_statg``, ``unlink``
is ``Cns_delfilesbyname`` with ``force`` (the entry and its replica
records go together), extended attributes are ``user.guid``,
``user.replicas`` (newline-separated SURLs), ``user.comment``,
``user.chksumtype`` and ``user.checksum``, and ``setxattr user.replicas``
takes ``+<surl>`` to register a replica or ``-<surl>`` to drop one.
``open`` reads (or writes) the first replica that will open, through
whichever plugin handles its SURL. A copy *to* an LFC URL registers the
source as a replica: the entry is created with the source's size and
checksum if it does not exist, the replica added if it does; no data
moves.

Connection settings are liblfc's environment first, then gfal2's
``[LFC PLUGIN]`` options: ``LFC_HOST``, ``LFC_PORT`` (default 5010),
``LFC_CONNTIMEOUT``, ``LFC_CONRETRY``, ``LFC_CONRETRYINT``; ``CSEC_MECH``
chooses the authentication mechanisms (default ``GSI ID``).

Knowingly different from gfal2: the host in ``lfc://host/path`` always
wins (gfal2 lets an ``$LFC_HOST`` set at start-up override it); there is no
built-in ``LFC_HOST`` (gfal2's ``lfc_plugin.conf`` named the retired
``lfc-puppet01.cern.ch``), so a bare ``lfn:`` without one is ``EINVAL``;
``lstat`` always asks the server (gfal2 answers from a cache that
``readdirpp`` fills, possibly stale); and connection failures keep their
own ``errno`` (see :mod:`.wire`) where gfal2 says ``ECOMM``.

Layout: :mod:`.wire` is the byte format, :mod:`.csec` authentication,
:mod:`.client` the connection pool and one method per Cns call; this module
is only gfal2's semantics on top - URL parsing, which call each operation
makes, and gfal2's error wording (``"Error report from LFC : ..."``),
which the tests pin. Every :class:`~.client.CnsError`
is turned into a plain ``GError`` here; none should reach the caller.
"""

from __future__ import annotations

import errno
import os
import re
import stat as _stat
import threading
import uuid
from collections.abc import Iterator
from typing import Any, ClassVar, NamedTuple

from ...errors import ECOMM, GError
from ...plugin import Plugin, PluginFile
from ...types import Stat
from . import wire
from .client import CnsError, FileStat, Server, ServerOptions
from .csec import (
    GSIMechanism,
    IDMechanism,
    KRB5Mechanism,
    Mechanism,
    available_krb5,
    local_identity,
    mechanism_names,
)

__all__ = ["ENOATTR", "GROUP", "LFCURL", "LFCPlugin"]

#: The gfal2 configuration group for this plugin's options.
GROUP = "LFC PLUGIN"

#: "No such attribute": ``ENOATTR`` on macOS/BSD, ``ENODATA`` on Linux (its alias there).
ENOATTR: int = getattr(errno, "ENOATTR", errno.ENODATA)

# The extended attributes gfal2's LFC plugin defined; ``listxattr`` lists them in this order.
XATTR_GUID = "user.guid"
XATTR_REPLICAS = "user.replicas"
XATTR_COMMENT = "user.comment"
XATTR_CHKSUM_TYPE = "user.chksumtype"
XATTR_CHKSUM_VALUE = "user.checksum"
FILE_XATTRS = [XATTR_GUID, XATTR_REPLICAS, XATTR_COMMENT, XATTR_CHKSUM_TYPE, XATTR_CHKSUM_VALUE]

#: gfal2's own ``[LFC PLUGIN]`` defaults, from its ``lfc_plugin.conf``.
DEFAULT_CONNTIMEOUT = 15
DEFAULT_CONRETRY = 2
DEFAULT_CONRETRYINT = 1

#: The catalogue's two-letter checksum types (``Cns_srv_setfsizeg``).
CHECKSUM_NAMES = {"AD": "ADLER32", "MD": "MD5", "CS": "CS"}
# gfal2 algorithm name -> catalogue code; CRC32 is stored as the generic "CS".
_SHORT_CHECKSUM = {"ADLER32": "AD", "MD5": "MD", "CS": "CS", "CRC32": "CS"}

#: ``_get_host`` in ``lfc_register.c``: the host of a replica's URL.
_SURL_HOST = re.compile(r"(.+://([a-zA-Z0-9.-]+))(:[0-9]+)?/.+")

#: Operations gfal2 allows on ``guid:`` URLs (``gfal_lfc_check_lfn_url``).
_GUID_OPERATIONS = frozenset(
    [
        "access",
        "chmod",
        "stat",
        "lstat",
        "open",
        "getxattr",
        "listxattr",
        "setxattr",
        "unlink",
        "checksum",
    ]
)


class _ReplicaInfo(NamedTuple):
    """What registration learns about a replica: its size and one checksum.

    ``csumtype`` is a catalogue code (``AD``/``MD``/``CS``) or ``""``, with
    ``csumvalue`` then ``""`` too. A tuple, so it unpacks and compares like
    the ``(size, type, value)`` that gfal2's ``_get_replica_info`` fills.
    """

    size: int
    csumtype: str
    csumvalue: str


class LFCURL:
    """A parsed catalogue URL: which server, and which path (or GUID) on it.

    For a ``guid:`` URL, :attr:`path` is already the resolved name, so every
    operation works on paths alone; :attr:`guid` just remembers the input.
    """

    def __init__(self, url: str, host: str, path: str, guid: str = "") -> None:
        """``url`` as given (for credentials and messages), ``host`` maybe with ``:port``."""
        self.url = url
        #: ``host`` or ``host:port`` (``[v6]:port``), split by :func:`_split_host`.
        self.host = host
        #: The absolute catalogue path.
        self.path = path
        self.guid = guid


def _split_host(value: str, default_port: int) -> tuple[str, int]:
    """``send2nsd``'s ``host[:port]``: the last colon, unless it is inside IPv6.

    ``[v6]`` and ``[v6]:port`` are unwrapped; a bare IPv6 address (several
    colons, no brackets) is all host. A non-numeric port is ``EINVAL``.
    """
    if value.startswith("[") and "]" in value:
        host, _, rest = value[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif value.count(":") == 1:
        host, _, port = value.partition(":")
    else:
        host, port = value, ""
    if port and not port.isdigit():
        raise GError(f"Invalid LFC port in {value!r}", errno.EINVAL)
    return host, int(port) if port else default_port


def _lfn_path(url: str) -> str:
    """``lfc_urlconverter``: drop ``lfn:``, doubled slashes and a trailing one.

    ``lfn:/`` itself is the root, ``/``.
    """
    return re.sub(r"/+", "/", url[4:]).rstrip("/") or "/"


def to_stat(record: FileStat) -> Stat:
    """``gfal_lfc_convert_statg``: no inode, no device, as in gfal2.

    The record's file id could serve as an inode, but gfal2 leaves
    ``st_ino`` at ``0`` and so does this.
    """
    return Stat(
        st_mode=record.mode,
        st_nlink=record.nlink,
        st_uid=record.uid,
        st_gid=record.gid,
        st_size=record.size,
        st_atime=record.atime,
        st_mtime=record.mtime,
        st_ctime=record.ctime,
    )


class LFCPlugin(Plugin):
    """The LCG File Catalog: a namespace of logical names and their replicas.

    One instance per gfal2 context. It keeps a :class:`~.client.Server` -
    a connection pool - per (host, port, credential, ``$CSEC_MECH``), so
    different identities never share an authenticated connection; all of
    them are closed by :meth:`close`. Methods are safe to call from several
    threads at once.
    """

    name = "lfc"
    schemes: ClassVar[tuple[str, ...]] = ("lfc", "lfn", "guid")
    option_group = GROUP
    priority = 150
    event_domain = "lfc"
    #: gfal2 registers another replica on an existing name: the core must
    #: neither refuse it (EEXIST), delete it (overwrite) nor clean it up.
    copy_manages_destination = True

    def __init__(self, context: Any) -> None:
        """Bind to the gfal2 ``context``; no connection is made until first use."""
        super().__init__(context)
        self._servers: dict[tuple[object, ...], Server] = {}
        self._lock = threading.Lock()

    # -- dispatch ------------------------------------------------------------------

    def handles(self, url: str, operation: str) -> bool:
        """``gfal_lfc_check_lfn_url``: ``lfc://`` and ``lfn:/`` for all, ``guid:`` for some."""
        lowered = url[:6].lower()
        if lowered.startswith("lfc://") and len(url) > 6:
            return True
        if lowered.startswith("lfn:/") and len(url) > 5:
            return True
        return url.startswith("guid:") and len(url) > 5 and operation in _GUID_OPERATIONS

    def copy_check(self, source: str, destination: str) -> bool:
        """``gfal_lfc_register_check``: anything can be registered at an LFC name."""
        lowered = destination[:6].lower()
        return (lowered.startswith("lfc://") and len(destination) > 6) or (
            lowered.startswith("lfn:/") and len(destination) > 5
        )

    # -- configuration -------------------------------------------------------------------

    def _setting(self, name: str, default: int) -> int:
        """An ``LFC_*`` number: the environment, then ``[LFC PLUGIN]``, then gfal2's default."""
        value = os.environ.get(name, "").strip()
        if value.lstrip("-").isdigit():
            return int(value)
        return int(self.options.integer(GROUP, name, default))

    def default_host(self) -> str:
        """The catalogue for ``lfn:``/``guid:`` URLs: ``$LFC_HOST``, then the config.

        There is deliberately no built-in default (see the module
        docstring), so neither set is ``EINVAL`` with a message saying how
        to fix it.
        """
        host = os.environ.get("LFC_HOST") or self.options.string(GROUP, "LFC_HOST", "")
        if not host:
            raise GError(
                "No LFC host: set LFC_HOST, or [LFC PLUGIN] LFC_HOST, or use lfc://host/path",
                errno.EINVAL,
            )
        return host

    def _default_port(self) -> int:
        """``$LFC_PORT`` if numeric, else 5010; a port in the URL wins over both."""
        value = os.environ.get("LFC_PORT", "")
        return int(value) if value.isdigit() else wire.PORT

    # -- URLs ----------------------------------------------------------------------------

    def parse(self, url: str) -> LFCURL:
        """Which server and path ``url`` means; ``EINVAL`` for anything else.

        ``lfc://`` needs a host and a path (``lfc://host`` alone is
        ``EINVAL``); ``lfn:`` takes the default host. ``guid:`` costs a
        round trip - ``Cns_getlinks`` - and resolves to the file's own path
        (the first link); its errors keep gfal2's wording, odd spacing
        included.
        """
        lowered = url[:6].lower()
        if lowered.startswith("lfc://"):
            rest = url[6:].lstrip("/")
            host, slash, path = rest.partition("/")
            if not host or not slash:
                raise GError(f"Invalid lfc:// url: {url}", errno.EINVAL)
            return LFCURL(url, host, "/" + path)
        if lowered.startswith("lfn:"):
            return LFCURL(url, self.default_host(), _lfn_path(url))
        if url.startswith("guid:") and len(url) > 5:
            guid = url[5:]
            host = self.default_host()
            try:
                links = self.server(host, url).getlinks(None, guid)
            except CnsError as exc:
                raise GError(
                    f"Error while getlinks() with lfclib,  guid : {guid}, Error : {exc.message} ",
                    exc.code,
                ) from exc
            if not links:
                raise GError(
                    f"Error no links associated with this guid or corrupted one : {guid}",
                    errno.EINVAL,
                )
            return LFCURL(url, host, links[0], guid)
        raise GError(f"Not an LFC url: {url}", errno.EINVAL)

    def _same_server(self, first: LFCURL, url: str) -> LFCURL:
        """The second URL of a two-URL call, which gfal2 sends to the first's server."""
        second = self.parse(url)
        second.host = first.host
        return second

    # -- servers --------------------------------------------------------------------------

    def _mechanisms(self, url: str) -> list[Mechanism]:
        """The Csec offer for ``url``, in ``$CSEC_MECH`` order, built per connection.

        GSI is always offered when named, with ``None`` for TLS when no
        credential exists, so the failure is Csec's own "no credential"
        after negotiation (see :class:`~.csec.GSIMechanism`). The TLS
        context leaves host-name checking to GSI's rule. KRB5 is offered
        only when a Kerberos library loads; unknown names are dropped.
        """
        found: list[Mechanism] = []
        for name in mechanism_names(os.environ.get("CSEC_MECH")):
            if name == "GSI":
                tls = None
                if self.context.x509(url) is not None:
                    tls = self.context.ssl_context(url, group=GROUP, check_hostname=False)
                found.append(GSIMechanism(tls))
            elif name == "ID":
                found.append(IDMechanism(*local_identity()))
            elif name == "KRB5" and available_krb5():
                found.append(KRB5Mechanism())
            else:
                self.log.debug("Csec mechanism %s is not available; not offered", name)
        return found

    def server(self, hostport: str, url: str) -> Server:
        """The pooled :class:`~.client.Server` for ``hostport`` and ``url``'s identity.

        Keyed by lower-cased host, port, the X.509 credential ``url`` would
        use and ``$CSEC_MECH``, so a change of proxy or mechanism list gets
        new connections rather than ones authenticated as someone else.
        Settings are read when the server is first made: environment, then
        ``[LFC PLUGIN]``, then gfal2's defaults (negative retry values count
        as ``0``); the I/O timeout is the context's operation timeout.
        """
        host, port = _split_host(hostport, self._default_port())
        credential = self.context.x509(url)
        mechs = os.environ.get("CSEC_MECH", "")
        key = (host.lower(), port, credential, mechs)
        with self._lock:
            found = self._servers.get(key)
            if found is None:
                options = ServerOptions(
                    timeout=float(self.option_timeout()),
                    connect_timeout=float(self._setting("LFC_CONNTIMEOUT", DEFAULT_CONNTIMEOUT)),
                    retries=max(0, self._setting("LFC_CONRETRY", DEFAULT_CONRETRY)),
                    retry_interval=float(
                        max(0, self._setting("LFC_CONRETRYINT", DEFAULT_CONRETRYINT))
                    ),
                    sessions=self.options.boolean(GROUP, "SESSION_REUSE", True),
                )
                found = self._servers[key] = Server(
                    host, port, lambda: self._mechanisms(url), options
                )
            return found

    def _server(self, target: LFCURL) -> Server:
        """The server for a parsed URL."""
        return self.server(target.host, target.url)

    def close(self) -> None:
        """End every pooled session; later calls reconnect as needed."""
        with self._lock:
            servers, self._servers = list(self._servers.values()), {}
        for server in servers:
            server.close()

    @staticmethod
    def _error(exc: CnsError, text: str = "Error report from LFC : {}") -> GError:
        """``exc`` in gfal2's words: ``text`` with the message in ``{}``, the same ``errno``."""
        return GError(text.format(exc.message), exc.code)

    # -- namespace ----------------------------------------------------------------------

    def _statg(self, target: LFCURL) -> FileStat:
        """``Cns_statg`` by path, with gfal2's error text: the call behind most getters."""
        try:
            return self._server(target).statg(target.path)
        except CnsError as exc:
            raise self._error(exc) from exc

    def stat(self, url: str) -> Stat:
        """``gfal_lfc_statG``: ``Cns_statg``, following symlinks."""
        return to_stat(self._statg(self.parse(url)))

    def lstat(self, url: str) -> Stat:
        """``Cns_lstat``, always from the server (gfal2 might answer from a listing cache)."""
        target = self.parse(url)
        try:
            return to_stat(self._server(target).lstat(target.path))
        except CnsError as exc:
            raise self._error(exc) from exc

    def access(self, url: str, mode: int) -> None:
        """``Cns_access``; ``mode`` as for ``os.access``, errors in gfal2's wording."""
        target = self.parse(url)
        try:
            self._server(target).access(target.path, mode)
        except CnsError as exc:
            raise self._error(exc, f"lfc access error, file : {url}, error : {{}}") from exc

    def chmod(self, url: str, mode: int) -> None:
        """``Cns_chmod`` on the permission bits of ``mode``."""
        target = self.parse(url)
        try:
            self._server(target).chmod(target.path, mode)
        except CnsError as exc:
            raise self._error(exc, "Errno reported from lfc : {} ") from exc

    def _mkdir(self, server: Server, path: str, mode: int) -> None:
        """``gfal_lfc_mkdir``: ``Cns_mkdirg`` with a fresh GUID."""
        try:
            server.mkdir(path, str(uuid.uuid4()), mode)
        except CnsError as exc:
            raise GError(
                f"Error while mkdir call in the lfc {os.strerror(exc.code)}", exc.code
            ) from exc

    def mkdir(self, url: str, mode: int) -> None:
        """One directory, with a fresh GUID (:meth:`_mkdir`); ``EEXIST`` if it exists."""
        target = self.parse(url)
        self._mkdir(self._server(target), target.path, mode)

    def mkdir_rec(self, url: str, mode: int) -> None:
        """``gfal_lfc_ifce_mkdirpG`` with ``pflag``, and the core's "exists is fine"."""
        target = self.parse(url)
        self._mkdir_rec(self._server(target), target.path, mode)

    def _mkdir_rec(self, server: Server, path: str, mode: int) -> None:
        """``mkdir -p`` on ``server``: try the leaf, and only on ``ENOENT`` build the path.

        Ancestors that already exist (``EEXIST``) or that we may not create
        but can presumably traverse (``EACCES``, e.g. ``/grid``) are passed
        over; the final ``mkdir`` of the leaf reports any real problem.
        Also used by :meth:`_touch` for a new file's parents.
        """
        if self._try_mkdir(server, path, mode, (errno.EEXIST, errno.ENOENT)) != errno.ENOENT:
            return
        # gfal_lfc_mkdir_rec: every ancestor with owner rwx, then the leaf.
        parts = [part for part in path.split("/") if part]
        for depth in range(1, len(parts)):
            ancestor = "/" + "/".join(parts[:depth])
            self._try_mkdir(server, ancestor, mode | 0o700, (errno.EEXIST, errno.EACCES))
        self._try_mkdir(server, path, mode, (errno.EEXIST,))

    def _try_mkdir(self, server: Server, path: str, mode: int, tolerated: tuple[int, ...]) -> int:
        """:meth:`_mkdir`; 0 when made, the errno when it is one of ``tolerated``, else raise."""
        try:
            self._mkdir(server, path, mode)
        except GError as exc:
            if exc.code not in tolerated:
                raise
            return exc.code
        return 0

    def rmdir(self, url: str) -> None:
        """``Cns_rmdir``, with gfal2's ``ENOTEMPTY`` for a directory that has entries."""
        target = self.parse(url)
        try:
            self._server(target).rmdir(target.path)
        except CnsError as exc:
            # lfc_rmdirG: the server says EEXIST for a directory that is not empty.
            code = errno.ENOTEMPTY if exc.code == errno.EEXIST else exc.code
            raise GError(f"Error report from LFC {exc.message}", code) from exc

    def rename(self, old: str, new: str) -> None:
        """``Cns_rename`` on the first URL's server; the second URL's host is ignored."""
        source = self.parse(old)
        target = self._same_server(source, new)
        try:
            self._server(source).rename(source.path, target.path)
        except CnsError as exc:
            raise self._error(exc) from exc

    def symlink(self, target: str, link: str) -> None:
        """``Cns_symlink``: ``target`` may be an LFC URL or an absolute catalogue path.

        Anything else (a relative path, another protocol's URL) is
        ``EINVAL``: the link must name something in this catalogue.
        """
        pointed = self.parse(target) if self.handles(target, "symlink") else None
        where = self.parse(link)
        path = pointed.path if pointed is not None else target
        if not path.startswith("/"):
            raise GError(f"Invalid symlink target {target}: not an LFC path", errno.EINVAL)
        try:
            self._server(where).symlink(path, where.path)
        except CnsError as exc:
            raise self._error(exc) from exc

    def readlink(self, url: str) -> str:
        """``lfc_readlinkG``: the target, as an ``lfn:`` URL."""
        target = self.parse(url)
        try:
            return "lfn:" + self._server(target).readlink(target.path)
        except CnsError as exc:
            raise self._error(exc) from exc

    def unlink(self, url: str) -> None:
        """gfal2's unlink: ``Cns_delfilesbyname`` with ``force``, entry and replica records.

        The request can succeed while the file fails; that per-path status
        is raised the same way as a request error. The replicas' data on
        the storage elements is untouched, as in gfal2.
        """
        target = self.parse(url)
        try:
            statuses = self._server(target).delfiles([target.path], True)
        except CnsError as exc:
            raise self._error(exc) from exc
        if statuses and statuses[0]:
            failure = CnsError(statuses[0])
            raise self._error(failure)

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        """The whole listing, read up front (see :meth:`.client.Server.listdir`), with stats."""
        target = self.parse(url)
        try:
            entries = self._server(target).listdir(target.path)
        except CnsError as exc:
            raise GError(f"Error report from LFC {exc.message}", exc.code) from exc
        return iter([(entry.name, to_stat(entry.stat)) for entry in entries])

    # -- metadata ---------------------------------------------------------------------

    def getxattr(self, url: str, name: str) -> str:
        """One of the five LFC attributes (each one round trip); ``ENOATTR`` otherwise.

        The ``"axttr not found"`` typo is gfal2's and is kept for scripts
        that match on it.
        """
        target = self.parse(url)
        if name == XATTR_GUID:
            return self._statg(target).guid
        if name == XATTR_REPLICAS:
            return "\n".join(self.replicas(target))
        if name == XATTR_COMMENT:
            try:
                return self._server(target).getcomment(target.path)
            except CnsError as exc:
                if exc.code == errno.ENOENT:  # no comment (or no file): ambiguous, as in gfal2
                    return ""
                raise self._error(exc) from exc
        if name == XATTR_CHKSUM_TYPE:
            return self._statg(target).csumtype
        if name == XATTR_CHKSUM_VALUE:
            return self._statg(target).csumvalue
        raise GError("axttr not found", ENOATTR)

    def listxattr(self, url: str) -> list[str]:
        """``lfc_listxattrG``: the file attributes, or just the comment for a directory."""
        info = self.lstat(url)
        if _stat.S_ISDIR(info.st_mode):
            return [XATTR_COMMENT]
        return list(FILE_XATTRS)

    def setxattr(self, url: str, name: str, value: str, flags: int) -> None:
        """``user.comment`` (non-empty), or ``user.replicas`` with ``+surl``/``-surl``.

        ``flags`` (``XATTR_CREATE``...) are ignored. The other attributes
        are read-only (``ENOATTR``): GUID and checksum are set when a file
        is registered.
        """
        target = self.parse(url)
        if name == XATTR_COMMENT:
            if not value:
                raise GError("sizeof the buffer incorrect", errno.EINVAL)
            try:
                self._server(target).setcomment(target.path, value)
            except CnsError as exc:
                raise self._error(exc) from exc
            return
        if name == XATTR_REPLICAS:
            if not value:
                raise GError("Missing value", errno.EINVAL)
            if value[0] == "+":
                self.register(value[1:], target)
            elif value[0] == "-":
                self.unregister(target, value[1:])
            else:
                raise GError(
                    "user.replica only accepts additions (+) or deletions (-)", errno.EINVAL
                )
            return
        raise GError("unable to set this attribute on this file", ENOATTR)

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        """The checksum the catalogue holds for the file.

        gfal2 answered with the stored value whatever algorithm was asked
        for; here a different algorithm, a partial range, or no stored value
        at all is ``ENOTSUP``, so a copy that verifies checksums cannot be
        fooled into comparing an MD5 with an Adler-32.
        """
        record = self._statg(self.parse(url))
        wanted = _SHORT_CHECKSUM.get(algorithm.strip().upper())
        if offset or length:
            raise GError("The LFC holds whole-file checksums only", errno.ENOTSUP)
        if not record.csumvalue or wanted != record.csumtype:
            held = CHECKSUM_NAMES.get(record.csumtype, record.csumtype) or "none"
            raise GError(
                f"The LFC holds no {algorithm} checksum for {url} (it has {held})",
                errno.ENOTSUP,
            )
        return record.csumvalue

    # -- replicas ------------------------------------------------------------------------

    def replicas(self, target: LFCURL) -> list[str]:
        """``gfal_lfc_getSURL``: every replica's SURL."""
        try:
            found = self._server(target).getreplica(target.path)
        except CnsError as exc:
            raise self._error(exc, "error reported from lfc : {}") from exc
        return [replica.sfn for replica in found]

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        """``lfc_openG``: the first replica that opens, through its own plugin."""
        surls = self.replicas(self.parse(url))
        failure: GError | None = None
        for surl in surls:
            self.log.info("LFC resolution %s -> %s", url, surl)
            try:
                return self.context._open(surl, flags, size)
            except GError as exc:
                failure = exc
                # gfal2 moves on only for a communication error.
                if exc.code != ECOMM:
                    break
        if failure is not None:
            raise failure
        # gfal2's core reports a plugin that opened nothing as a bad handle.
        raise GError(f"No replica registered for {url}", errno.EBADF)

    def _replica_info(self, surl: str) -> _ReplicaInfo:
        """``_get_replica_info``: the replica's size and a checksum, if one comes.

        Asks the replica's own plugin, trying Adler-32, then MD5, then the
        generic type, and keeps the first that answers (cut to the
        catalogue's 32 characters). No checksum at all is fine: the entry
        is then registered without one. A failing ``stat`` propagates - a
        replica that cannot be seen is not registered.
        """
        size = self.context.stat(surl).st_size
        for short in ("AD", "MD", "CS"):
            try:
                value = self.context.checksum(surl, CHECKSUM_NAMES[short])
            except GError:
                continue
            return _ReplicaInfo(size, short, value[:32])
        return _ReplicaInfo(size, "", "")

    def register(self, surl: str, target: LFCURL) -> None:
        """``gfal_lfc_register``: add ``surl`` as a replica of ``target``, creating it if new.

        An existing entry must agree with the replica: same size, and the
        same checksum when both sides have one of the same type (else
        ``EINVAL``, nothing changed). A new entry gets a fresh GUID, its
        parents, the size and checksum (:meth:`_touch`), then the replica.
        Registering a replica that is already there succeeds. Not atomic:
        a failure after :meth:`_touch` leaves an entry with no replica.
        """
        found = _SURL_HOST.match(surl)
        if found is None:
            raise GError(f"The source is not a valid url: {surl} (No match)", errno.EINVAL)
        # gfal2 cut the last character off the host here (a g_strlcpy
        # off-by-one); the whole host name is registered instead.
        replica_host = found.group(2)
        info = self._replica_info(surl)
        server = self._server(target)
        try:
            record: FileStat | None = server.statg(target.path)
        except CnsError as exc:
            if exc.code != errno.ENOENT:
                raise GError(
                    f"Failed to stat the file: {exc.message} ({exc.code})", exc.code
                ) from exc
            record = None
        if record is not None:
            if info.size != record.size:
                raise GError(
                    f"Replica file size ({info.size}) and LFC file size ({record.size}) "
                    "do not match",
                    errno.EINVAL,
                )
            if (
                record.csumvalue
                and info.csumvalue
                and info.csumtype == record.csumtype
                and info.csumvalue != record.csumvalue
            ):
                raise GError(
                    f"Replica checksum ({info.csumvalue}) and LFC checksum ({record.csumvalue}) "
                    "do not match",
                    errno.EINVAL,
                )
            guid, fileid = record.guid, record.fileid
        else:
            guid, fileid = str(uuid.uuid4()), 0
            self._touch(server, target.path, guid, info)
        try:
            server.addreplica(guid, fileid, replica_host, surl)
        except CnsError as exc:
            if exc.code != errno.EEXIST:  # already registered: that is fine
                raise GError(f"Could not register the replica : {exc.message} ", exc.code) from exc

    def _touch(self, server: Server, path: str, guid: str, info: _ReplicaInfo) -> None:
        """``_lfc_touch``: the parent directories, the entry, its size and checksum.

        Parents are made only when ``Cns_access`` cannot see the parent;
        the entry is created ``0o644`` (less the umask) with ``guid``, and
        ``Cns_setfsizeg`` records ``info``'s size and checksum on it.
        """
        parent = path.rsplit("/", 1)[0] or "/"
        try:
            server.access(parent, os.F_OK)
        except CnsError:
            self._mkdir_rec(server, parent, 0o755)
        try:
            server.creat(path, guid, 0o644)
        except CnsError as exc:
            raise GError(f"Could not create the file: {exc.message}", exc.code) from exc
        try:
            server.setfsizeg(guid, info.size, info.csumtype, info.csumvalue)
        except CnsError as exc:
            raise GError(f"Could not set file size and checksum: {exc.message}", exc.code) from exc

    def unregister(self, target: LFCURL, surl: str) -> None:
        """``gfal_lfc_unregister``: drop one replica record.

        By file id (from ``Cns_statg``), so a ``guid:`` URL works too. The
        entry stays even when its last replica goes.
        """
        server = self._server(target)
        try:
            record = server.statg(target.path)
        except CnsError as exc:
            raise GError(f"Could not stat the file: {exc.message} ({exc.code})", exc.code) from exc
        try:
            server.delreplica(None, record.fileid, surl)
        except CnsError as exc:
            raise GError(
                f"Could not register the replica : {exc.message} ({exc.code}) ", exc.code
            ) from exc

    # -- copies ---------------------------------------------------------------------------

    def copy(self, transfer: Any) -> None:
        """Register the source as a replica of the destination name.

        No bytes move: the source must already be where it will be read
        from. The ``TRANSFER_TYPE`` event says so to monitoring, and
        ``transfer.check()`` honours a cancellation that arrived meanwhile.
        """
        from ... import events as ev

        transfer.event(ev.TRANSFER_TYPE, "register")
        self.register(transfer.source, self.parse(transfer.destination))
        transfer.check()
