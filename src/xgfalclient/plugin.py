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
"""

from __future__ import annotations

import errno
import logging
import os
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING, Any, ClassVar, Union

from .errors import GError, unsupported
from .types import Stat
from .url import scheme_of

if TYPE_CHECKING:
    from .context import Gfal2Context
    from .transfer import Transfer, TransferParameters

__all__ = [
    "Plugin",
    "PluginFile",
    "StagingResult",
    "OPERATIONS",
    "O_RDONLY",
    "O_WRONLY",
    "O_RDWR",
    "O_CREAT",
    "O_TRUNC",
    "O_APPEND",
    "O_EXCL",
    "O_ACCMODE_MASK",
]

O_RDONLY = os.O_RDONLY
O_WRONLY = os.O_WRONLY
O_RDWR = os.O_RDWR
O_CREAT = os.O_CREAT
O_TRUNC = os.O_TRUNC
O_APPEND = os.O_APPEND
O_EXCL = os.O_EXCL
#: The access-mode bits of an ``open`` flag word; zero means read-only.
O_ACCMODE_MASK = os.O_WRONLY | os.O_RDWR

#: A per-URL staging outcome: ``True`` is on disk now, ``False`` is still
#: queued, and a ``GError`` is a failure for that URL alone.
StagingResult = Union[bool, GError]

#: Every overridable operation, by method name.
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
        self.url = url
        self.position = 0
        self.closed = False

    # -- reading ---------------------------------------------------------------

    def read(self, size: int) -> bytes:
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
        raise unsupported("pread", self.url)

    # -- writing ---------------------------------------------------------------

    def write(self, data: bytes | bytearray | memoryview) -> int:
        written = self.pwrite(data, self.position)
        self.position += written
        return written

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        raise unsupported("pwrite", self.url)

    # -- positioning -----------------------------------------------------------

    def size(self) -> int | None:
        """The file's length when the handle knows it, for ``SEEK_END``."""
        return None

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
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
        if target < 0:
            raise GError("Invalid argument", errno.EINVAL)
        self.position = target
        return target

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> PluginFile:
        return self

    def __exit__(self, *exc: object) -> None:
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

    def __init__(self, context: Gfal2Context) -> None:
        self.context = context
        self.log = logging.getLogger(f"xgfalclient.plugins.{self.name}")

    # -- identity and dispatch ---------------------------------------------------

    @classmethod
    def available(cls) -> str | None:
        """``None`` if usable, else why not (a missing optional package)."""
        return None

    @property
    def version(self) -> str:
        from ._version import __version__

        return __version__

    @property
    def label(self) -> str:
        """``name-version``, as ``get_plugin_names`` lists it."""
        return f"{self.name}-{self.version}"

    def handles(self, url: str, operation: str) -> bool:
        """Whether this plugin will take ``operation`` on ``url``."""
        return scheme_of(url) in self.schemes

    @classmethod
    def implements(cls, operation: str) -> bool:
        """True if the subclass overrides ``operation``."""
        mine = getattr(cls, operation, None)
        return mine is not None and mine is not getattr(Plugin, operation, None)

    def close(self) -> None:
        """Release pooled connections; the context calls this on ``free()``."""

    # -- shared helpers ----------------------------------------------------------

    @property
    def options(self) -> Any:
        return self.context.options

    def option_timeout(self) -> int:
        return int(self.context.options.timeout(self.option_group))

    def checksum_type(self) -> str:
        """``COPY_CHECKSUM_TYPE`` from this plugin's group, else ADLER32."""
        return str(self.context.options.string(self.option_group, "COPY_CHECKSUM_TYPE", "ADLER32"))

    # -- namespace ---------------------------------------------------------------

    def access(self, url: str, mode: int) -> None:
        raise NotImplementedError

    def chmod(self, url: str, mode: int) -> None:
        raise NotImplementedError

    def rename(self, old: str, new: str) -> None:
        raise NotImplementedError

    def stat(self, url: str) -> Stat:
        raise NotImplementedError

    def lstat(self, url: str) -> Stat:
        raise NotImplementedError

    def mkdir(self, url: str, mode: int) -> None:
        """Create one directory; ``EEXIST`` if it is already there."""
        raise NotImplementedError

    def mkdir_rec(self, url: str, mode: int) -> None:
        """Create a directory and its parents in one go, where the protocol can."""
        raise NotImplementedError

    def rmdir(self, url: str) -> None:
        raise NotImplementedError

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        """Entries as ``(name, stat-or-None)``; ``None`` when a listing is names only."""
        raise NotImplementedError

    def listdir(self, url: str) -> list[str]:
        raise NotImplementedError

    def readlink(self, url: str) -> str:
        raise NotImplementedError

    def symlink(self, target: str, link: str) -> None:
        raise NotImplementedError

    def unlink(self, url: str) -> None:
        raise NotImplementedError

    def unlink_bulk(self, urls: Sequence[str]) -> list[GError | None]:
        raise NotImplementedError

    # -- file I/O ----------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        """Open for I/O. ``size`` is a hint for writers that must declare a length."""
        raise NotImplementedError

    # -- metadata ----------------------------------------------------------------

    def getxattr(self, url: str, name: str) -> str:
        raise NotImplementedError

    def setxattr(self, url: str, name: str, value: str, flags: int) -> None:
        raise NotImplementedError

    def listxattr(self, url: str) -> list[str]:
        raise NotImplementedError

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        """Hex (or the server's) checksum; ``offset == length == 0`` is the whole file."""
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
        raise NotImplementedError

    def bring_online_poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        raise NotImplementedError

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        raise NotImplementedError

    def abort_bring_online(self, urls: Sequence[str], token: str) -> list[GError | None]:
        raise NotImplementedError

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        raise NotImplementedError

    # -- QoS (CDMI) ----------------------------------------------------------------

    def check_file_qos(self, url: str) -> str:
        raise NotImplementedError

    def check_available_qos_transitions(self, url: str) -> list[str]:
        raise NotImplementedError

    def check_target_qos(self, url: str) -> str:
        raise NotImplementedError

    def change_object_qos(self, url: str, target: str) -> None:
        raise NotImplementedError

    def qos_check_classes(self, url: str, kind: str) -> list[str]:
        raise NotImplementedError

    # -- tokens ------------------------------------------------------------------

    def token_retrieve(
        self, url: str, issuer: str, validity: int, write_access: bool, activities: list[str]
    ) -> str:
        raise NotImplementedError

    # -- copies ------------------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        """Whether :meth:`copy` can move ``source`` to ``destination`` itself.

        Answer ``True`` only for pairs the plugin moves better than the
        core's streamed copy: third-party transfers, or an upload the
        protocol has a single request for. Everything else is left to the
        core, which reads through one plugin and writes through another.
        """
        return False

    def copy(self, transfer: Transfer) -> None:
        """Move the bytes. The core has done overwrite, parent and checksum work."""
        raise NotImplementedError

    def copy_bulk(
        self, params: TransferParameters, transfers: Sequence[Transfer]
    ) -> list[GError | None]:
        raise NotImplementedError
