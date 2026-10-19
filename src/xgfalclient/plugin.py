"""The plugin contract: one class per protocol family, as in gfal2.

gfal2 is a dispatcher. Every call names a URL; the core asks each loaded
plugin in priority order whether it handles that URL for that operation, and
the first that does gets the call. This module is that contract.

A plugin subclasses :class:`Plugin`, sets ``name`` and ``schemes``, and
overrides the operations it can perform. An operation left alone is one it
cannot do: the core notices that the method was not overridden and moves on
to the next plugin, ending in ``EPROTONOSUPPORT`` exactly as gfal2 does when
nobody claims a URL. There is no registration table to keep in step with the
code.

Every method takes URLs as strings and reports failure by raising
:class:`~xgfalclient.errors.GError` with an ``errno`` code. Return values are
Python values, not gfal2's ``0``: the context adds the C-shaped return codes.

A plugin that blocks on its own sockets registers them with the context
while it does (:meth:`~xgfalclient.Gfal2Context.abort_on_cancel`, or
:meth:`~xgfalclient.transfer.Transfer.abort_on_cancel` in a copy), so that
``cancel()`` wakes it at once instead of when the server next speaks;
:func:`shutdown_sockets` is the usual thing to register for several.

Each operation's docstring below names the gfal2 plugin-interface entry
(``gfal_plugin_interface``'s ``statG``, ``mkdirpG``...) it corresponds to,
which is where to look for the behaviour a plugin must reproduce. The base
methods raise ``NotImplementedError`` only as a guard: the core never calls
an operation a plugin did not override (see :meth:`Plugin.implements`).
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import socket
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING, Any, ClassVar, Self

from .errors import GError, from_oserror, unsupported
from .types import Stat
from .url import scheme_of

if TYPE_CHECKING:
    from .context import Gfal2Context
    from .transfer import Transfer, TransferParameters

__all__ = [
    "OPERATIONS",
    "O_ACCMODE_MASK",
    "O_APPEND",
    "O_CREAT",
    "O_EXCL",
    "O_RDONLY",
    "O_RDWR",
    "O_TRUNC",
    "O_WRONLY",
    "DirEntry",
    "Plugin",
    "PluginFile",
    "StagingResult",
    "shutdown_sockets",
]

# ``open`` flags are the platform's own ``os.O_*`` values: a plugin passes
# them to ``os.open`` unchanged, and the others test bits with them.
O_RDONLY = os.O_RDONLY
O_WRONLY = os.O_WRONLY
O_RDWR = os.O_RDWR
O_CREAT = os.O_CREAT
O_TRUNC = os.O_TRUNC
O_APPEND = os.O_APPEND
O_EXCL = os.O_EXCL
#: The access-mode bits of an ``open`` flag word; zero means read-only.
O_ACCMODE_MASK = os.O_WRONLY | os.O_RDWR


def shutdown_sockets(*sockets: socket.socket | None) -> None:
    """Shut each socket down both ways, waking any thread blocked on it; for ``cancel()``.

    The plain socket's ``shutdown`` even under TLS (``SSLSocket.shutdown``
    would tear the TLS state down under the reading thread); closing stays
    with the owner, which then sees an end of file or a reset. ``None`` (not
    connected yet) and sockets already gone are passed over: nothing is
    blocked on them.
    """
    for sock in sockets:
        if sock is None:
            continue
        with contextlib.suppress(OSError):
            socket.socket.shutdown(sock, socket.SHUT_RDWR)


#: A per-URL staging outcome: ``True`` is on disk now, ``False`` is still
#: queued, and a ``GError`` is a failure for that URL alone.
StagingResult = bool | GError

#: One ``opendir`` entry: ``(name, stat-or-None)``, or ``(name, stat-or-None,
#: d_type)`` when the listing knows the entry's own type - a symbolic link is
#: ``DT_LNK`` there, though its stat describes the target.
DirEntry = tuple[str, Stat | None] | tuple[str, Stat | None, int]

#: Every overridable operation, by method name. A new operation must be
#: added here and given a base method, or :meth:`Plugin.implements` cannot
#: see it.
OPERATIONS = (
    "access",
    "chmod",
    "rename",
    "stat",
    "lstat",
    "mkdir",
    "mkdir_rec",
    "rmdir",
    "opendir",
    "listdir",
    "open",
    "readlink",
    "symlink",
    "unlink",
    "unlink_bulk",
    "getxattr",
    "setxattr",
    "listxattr",
    "checksum",
    "bring_online",
    "bring_online_poll",
    "release",
    "abort_bring_online",
    "archive_poll",
    "check_file_qos",
    "check_available_qos_transitions",
    "check_target_qos",
    "change_object_qos",
    "qos_check_classes",
    "token_retrieve",
    "copy",
    "copy_bulk",
)


class PluginFile:
    """An open remote file, as :meth:`Plugin.open` returns it.

    Subclasses implement whichever primitives the protocol has. A protocol
    with positional reads (HTTP ranges, ``kXR_read``) implements
    :meth:`pread` and gets sequential :meth:`read` for free from the cursor
    kept here; a streaming protocol (GridFTP ``RETR``) implements
    :meth:`read` and leaves :meth:`pread` unsupported. Writes are the same
    with :meth:`pwrite`/:meth:`write`.
    """

    def __init__(self, url: str = "") -> None:
        """A handle for ``url`` with its cursor at 0; subclasses open the remote file first."""
        self.url = url
        self.position = 0
        self.closed = False

    # -- reading ---------------------------------------------------------------

    def read(self, size: int) -> bytes:
        """Up to ``size`` bytes from the cursor (``readG``); ``b""`` at end of file.

        The default is :meth:`pread` at the cursor. A short read is not end
        of file: callers loop until ``b""``.
        """
        data = self.pread(self.position, size)
        self.position += len(data)
        return data

    def readinto(self, buffer: memoryview | bytearray) -> int:
        """Fill ``buffer`` from the cursor; the copy engine's fast path."""
        view = memoryview(buffer)
        data = self.read(len(view))
        view[: len(data)] = data
        return len(data)

    def pread(self, offset: int, size: int) -> bytes:
        """Up to ``size`` bytes at ``offset``, cursor unmoved (``preadG``); else ``ENOSYS``."""
        raise unsupported("pread", self.url)

    # -- writing ---------------------------------------------------------------

    def write(self, data: bytes | bytearray | memoryview) -> int:
        """Write at the cursor (``writeG``); the count written, which may be short.

        The default is :meth:`pwrite` at the cursor. The core's pipeline
        treats a count of 0 (or a negative one) as the destination refusing
        data, never as "try again".
        """
        written = self.pwrite(data, self.position)
        self.position += written
        return written

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        """Write at ``offset``, cursor unmoved (``pwriteG``); ``ENOSYS`` by default."""
        raise unsupported("pwrite", self.url)

    # -- positioning -----------------------------------------------------------

    def size(self) -> int | None:
        """The file's length when the handle knows it, for ``SEEK_END``."""
        return None

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Move the cursor (``lseekG``) and answer the new position.

        Purely local: nothing is sent, so a streaming protocol that cannot
        seek finds out at its next read. ``SEEK_END`` needs :meth:`size`;
        a position before 0 is ``EINVAL`` in gfal2's file-plugin words.
        """
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self.position + offset
        elif whence == os.SEEK_END:
            end = self.size()
            if end is None:
                raise GError("Cannot seek relative to the end of this file", errno.ESPIPE)
            target = end + offset
        else:
            raise GError(f"Invalid whence {whence}", errno.EINVAL)
        if target < 0:  # worded as gfal2's file plugin reports lseek's EINVAL
            raise from_oserror(OSError(errno.EINVAL, "Invalid argument"))
        self.position = target
        return target

    def close(self) -> None:
        """Release the remote file (``closeG``); subclasses commit a write here, then call this.

        Must be idempotent, and must raise if a write could not be committed
        - for many protocols (HTTP ``PUT``, xrootd) close is where a failed
        upload is first reported.
        """
        self.closed = True

    def __enter__(self) -> Self:
        """The handle; the block's end closes it."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close, even when the block raised."""
        self.close()


class Plugin:
    """Base class for a protocol plugin.

    Class attributes a subclass sets:

    ``name``
        The short name gfal2 reports (``"http"``, ``"gridftp"``...).
    ``schemes``
        URL schemes claimed by the default :meth:`handles`.
    ``option_group``
        Its section in the configuration, e.g. ``"HTTP PLUGIN"``.
    ``priority``
        Lower is asked first. gfal2's order is http, srm, mock, xrootd,
        gridftp, file, and the built-ins keep it.
    """

    name: ClassVar[str] = "base"
    schemes: ClassVar[tuple[str, ...]] = ()
    option_group: ClassVar[str] = ""
    priority: ClassVar[int] = 1000
    #: The event domain for copies this plugin performs.
    event_domain: ClassVar[str] = ""
    #: True if :meth:`copy` emits its own ``TRANSFER:ENTER``/``EXIT`` (or, as
    #: gfal2's srm plugin does, none), so the core must not add them.
    narrates_transfer: ClassVar[bool] = False
    #: True if :meth:`copy` decides what an existing destination means (the
    #: LFC registers another replica), so the core neither refuses, deletes
    #: nor cleans up the destination.
    copy_manages_destination: ClassVar[bool] = False
    #: True if :meth:`copy` verifies source/destination checksums itself
    #: (gfal2's gridftp and srm plugins do), so the core must not.
    copy_manages_checksums: ClassVar[bool] = False

    def __init__(self, context: Gfal2Context) -> None:
        """Bind to ``context``, which owns the plugin; one instance per context.

        Keep this cheap and free of I/O: the context builds plugins lazily,
        mid-operation, and a constructor that connects or reads files would
        add that cost to whatever call first needed the scheme.
        """
        self.context = context
        self.log = logging.getLogger("gfal2")

    # -- identity and dispatch ---------------------------------------------------

    @classmethod
    def available(cls) -> str | None:
        """``None`` if usable, else why not (a missing optional package)."""
        return None

    @property
    def version(self) -> str:
        """The version reported in plugin labels: gfal2's own, as its built-in plugins report."""
        from ._version import GFAL2_VERSION

        return GFAL2_VERSION

    @property
    def label(self) -> str:
        """``name-version``, as ``get_plugin_names`` lists it."""
        return f"{self.name}-{self.version}"

    def handles(self, url: str, operation: str) -> bool:
        """Whether this plugin will take ``operation`` on ``url`` (``check_plugin_url``).

        The default claims every operation for the listed schemes; override
        to refuse some (a catalogue that only resolves names, say), and the
        core moves on to the next plugin.
        """
        return scheme_of(url) in self.schemes

    @classmethod
    def implements(cls, operation: str) -> bool:
        """True if the subclass overrides ``operation``.

        Compared by identity with :class:`Plugin`'s own method, so an
        override inherited from an intermediate base class counts too.
        """
        mine = getattr(cls, operation, None)
        return mine is not None and mine is not getattr(Plugin, operation, None)

    def close(self) -> None:
        """Release pooled connections; the context calls this on ``free()``."""

    # -- shared helpers ----------------------------------------------------------

    @property
    def options(self) -> Any:
        """The context's :class:`~xgfalclient.options.Options`; read at use, never copied.

        Reading it per operation is what makes ``set_opt_*`` between calls
        take effect, as it does in gfal2.
        """
        return self.context.options

    def option_timeout(self) -> int:
        """Seconds for one namespace operation: ``[<group>] OPERATION_TIMEOUT`` or the core's."""
        return int(self.context.options.timeout(self.option_group))

    def checksum_type(self) -> str:
        """``COPY_CHECKSUM_TYPE`` from this plugin's group, else ADLER32."""
        return str(self.context.options.string(self.option_group, "COPY_CHECKSUM_TYPE", "ADLER32"))

    # -- namespace ---------------------------------------------------------------

    def access(self, url: str, mode: int) -> int | None:
        """``None`` (or ``0``) for accessible; gfal2's mock answers ``1``, passed through."""
        raise NotImplementedError

    def chmod(self, url: str, mode: int) -> None:
        """``chmodG``: set permission bits (``mode`` is already range-checked)."""
        raise NotImplementedError

    def rename(self, old: str, new: str) -> None:
        """``renameG``: both URLs are this plugin's (the core checked)."""
        raise NotImplementedError

    def stat(self, url: str) -> Stat:
        """``statG``: the entry's metadata, links followed; ``ENOENT`` if absent."""
        raise NotImplementedError

    def lstat(self, url: str) -> Stat:
        """``lstatG``: as :meth:`stat` without following a final link; optional."""
        raise NotImplementedError

    def mkdir(self, url: str, mode: int) -> None:
        """``mkdirpG`` without parents: one directory; ``EEXIST`` if it is already there.

        ``ENOENT`` for a missing parent matters: it is what makes the core's
        ``mkdir_rec`` fallback climb.
        """
        raise NotImplementedError

    def mkdir_rec(self, url: str, mode: int) -> None:
        """``mkdirpG`` with parents, where the protocol can do it in one request.

        Optional: without it the core climbs with :meth:`mkdir`. ``EEXIST``
        is treated as success by the caller.
        """
        raise NotImplementedError

    def rmdir(self, url: str) -> None:
        """``rmdirG``: an empty directory; ``ENOTEMPTY``/``ENOTDIR`` as the server says."""
        raise NotImplementedError

    def opendir(self, url: str) -> Iterator[DirEntry]:
        """Entries as ``(name, stat-or-None[, d_type])``; ``None`` when a listing is names only."""
        raise NotImplementedError

    def listdir(self, url: str) -> list[str]:
        """Names only, for protocols where that is cheaper than :meth:`opendir`; optional."""
        raise NotImplementedError

    def readlink(self, url: str) -> str:
        """``readlinkG``: the link's stored target."""
        raise NotImplementedError

    def symlink(self, target: str, link: str) -> None:
        """``symlinkG``: create ``link`` pointing at ``target``."""
        raise NotImplementedError

    def unlink(self, url: str) -> None:
        """``unlinkG``: remove a file (not a directory: ``EISDIR``)."""
        raise NotImplementedError

    def unlink_bulk(self, urls: Sequence[str]) -> list[GError | None]:
        """``unlink_listG``: one result per URL, ``None`` for removed; must not raise per file."""
        raise NotImplementedError

    # -- file I/O ----------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        """``openG``: a :class:`PluginFile`; ``size`` hints the length to writers needing one.

        ``flags`` are ``O_*`` bits; ``mode`` applies to a file this creates.
        ``size`` is passed only by the core's streamed copy, so an override
        must accept being called without it.
        """
        raise NotImplementedError

    # -- metadata ----------------------------------------------------------------

    def getxattr(self, url: str, name: str) -> str:
        """``getxattrG``: one attribute as text (``user.replicas``, ``user.status``...).

        A failure for ``user.checksum.<alg>`` makes the core fall back to
        :meth:`checksum`, so there is no need to implement that one here.
        """
        raise NotImplementedError

    def setxattr(self, url: str, name: str, value: str, flags: int) -> None:
        """``setxattrG``: set one attribute."""
        raise NotImplementedError

    def listxattr(self, url: str) -> list[str]:
        """``listxattrG``: the attribute names this plugin can answer for ``url``."""
        raise NotImplementedError

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        """``checksum_calcG``: the checksum of a range; ``offset == length == 0`` is the file.

        Return what the server says; the core zero-pads ADLER32 when
        ``FORMAT_ADLER32_CHECKSUM`` asks, and comparisons ignore case and
        leading zeros.
        """
        raise NotImplementedError

    # -- tape --------------------------------------------------------------------

    def bring_online(
        self,
        urls: Sequence[str],
        metadata: Sequence[str],
        pintime: int,
        timeout: int,
        is_async: bool,
    ) -> tuple[list[StagingResult], str]:
        """``bring_online_list``: stage ``urls``; one result per URL, and the request token.

        Always called with lists, even for one URL; ``metadata`` has one
        entry per URL (``""`` for none). The context shapes the results into
        the bindings' single and list conventions.
        """
        raise NotImplementedError

    def bring_online_poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        """``bring_online_poll_list``: per URL, ``True`` online, ``False`` still queued."""
        raise NotImplementedError

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``release_file_list``: unpin; ``token`` may be empty."""
        raise NotImplementedError

    def abort_bring_online(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``abort_files``: cancel the staging request ``token`` for ``urls``."""
        raise NotImplementedError

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        """``archive_poll_list``: per URL, ``True`` once safely on tape."""
        raise NotImplementedError

    # -- QoS (CDMI) ----------------------------------------------------------------

    def check_file_qos(self, url: str) -> str:
        """gfal2's ``check_file_qos``: the object's current QoS class."""
        raise NotImplementedError

    def check_available_qos_transitions(self, url: str) -> list[str]:
        """The available QoS transitions: classes the object may move to."""
        raise NotImplementedError

    def check_target_qos(self, url: str) -> str:
        """gfal2's ``check_target_qos``: the class a transition in progress is heading for."""
        raise NotImplementedError

    def change_object_qos(self, url: str, target: str) -> None:
        """gfal2's ``change_object_qos``: start a transition to ``target``."""
        raise NotImplementedError

    def qos_check_classes(self, url: str, kind: str) -> list[str]:
        """gfal2's ``qos_check_classes``: the endpoint's classes of ``kind``."""
        raise NotImplementedError

    # -- tokens ------------------------------------------------------------------

    def token_retrieve(
        self, url: str, issuer: str, validity: int, write_access: bool, activities: list[str]
    ) -> str:
        """``token_retrieve``: a token for ``url`` valid ``validity`` minutes.

        ``activities`` (possibly empty) are the requested caveats or scopes;
        when empty, ``write_access`` picks a read-only or read-write default.
        """
        raise NotImplementedError

    # -- copies ------------------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        """Whether :meth:`copy` can move ``source`` to ``destination`` itself.

        gfal2's ``check_plugin_url_transfer``; the first plugin, in priority
        order, to answer True gets the copy.

        Answer ``True`` only for pairs the plugin moves better than the
        core's streamed copy: third-party transfers, or an upload the
        protocol has a single request for. Everything else is left to the
        core, which reads through one plugin and writes through another.
        """
        return False

    def copy(self, transfer: Transfer) -> None:
        """``copy_file``: move the bytes. The core has done overwrite, parent and checksum work.

        Unless the class says it manages them (``copy_manages_destination``,
        ``copy_manages_checksums``, ``narrates_transfer``). Call
        :meth:`Transfer.check` between steps, report bytes with
        :meth:`Transfer.progress`, and set ``transfer.third_party`` when the
        servers moved the data between themselves.
        """
        raise NotImplementedError

    def copy_bulk(
        self, params: TransferParameters, transfers: Sequence[Transfer]
    ) -> list[GError | None]:
        """``copy_bulk``: every pair at once (GridFTP pipelining); one result per transfer.

        Offered only when the first pair's plugin has it; the plugin then
        does every check itself, as the core does not run its sequence.
        A callback's exception must propagate rather than become a result.
        """
        raise NotImplementedError
