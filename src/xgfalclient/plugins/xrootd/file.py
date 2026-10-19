"""An open ``root://`` file, and how ``cancel()`` reaches a call blocked on one.

gfal2's ``cancel()`` must stop a call that is waiting on a silent server
now, not at its timeout. Every call the plugin makes is therefore made with
its xrdclient object - a :class:`~xrdclient.File` or a
:class:`~xrdclient.FileSystem` - registered with the context
(:meth:`~xgfalclient.Gfal2Context.abort_on_cancel`), and ``cancel()`` calls
that object's ``abort()``: xrdclient shuts the connection under it down,
which wakes the call at once with :class:`~xrdclient.errors.AbortedError`,
and refuses every call after. The core then reports the operation as
cancelled, whatever the plugin made of the error.

An abort costs the object's connection. That is why each operation has an
object of its own: the plugin's filesystems are checked out to one call at
a time (see :meth:`~.plugin.XRootDPlugin._fs`) and every file has its own
handle and connection, so one ``cancel()`` stops what that context had in
flight and nothing else that happens to share an endpoint.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from typing import TYPE_CHECKING, Any, TypeVar

from ...errors import GError
from ...plugin import PluginFile
from .errors import posix_error

if TYPE_CHECKING:
    from xrdclient.client.file import File

    from ...context import Gfal2Context

T = TypeVar("T")


class Abort:
    """``cancel()``'s hold on an xrdclient ``File`` or ``FileSystem`` while a call runs on it.

    Called, it aborts the object (see the module's account). ``fired`` says
    that this happened: the object's connection is then spent, and a
    filesystem is never kept for another call.
    """

    __slots__ = ("fired", "owner")

    def __init__(self, owner: Any) -> None:
        """Hold ``owner``, anything with an ``abort()``; nothing is registered yet."""
        self.owner = owner
        self.fired = False

    def __call__(self) -> None:
        """Abort the owner; may run on the cancelling thread while the call is blocked."""
        # Set first: the blocked call wakes as soon as abort() shuts the
        # socket, and its owner must already see that the connection is spent.
        self.fired = True
        self.owner.abort()


def aborting(context: Gfal2Context | None, abort: Abort) -> AbstractContextManager[None]:
    """While the ``with`` block runs, ``context``'s ``cancel()`` calls ``abort``."""
    if context is None:
        return nullcontext()
    return context.abort_on_cancel(abort)


class XRootDFile(PluginFile):
    """An open ``root://`` file: positional reads and writes on one handle.

    ``readinto`` hands the whole buffer to xrdclient, which fills a large one
    over its pipelined bulk path straight from the socket; that is what makes
    the core's streamed copy out of ``root://`` fast.
    """

    def __init__(self, url: str, handle: File, *, writable: bool, context: Any = None) -> None:
        """Take ownership of ``handle``, already opened by :meth:`~.plugin.XRootDPlugin.open`."""
        super().__init__(url)
        self._handle = handle
        self._writable = writable
        #: Whose ``cancel()`` aborts the handle mid-call.
        self._context = context

    def _io(self, description: str, action: Callable[[], T]) -> T:
        """One call on the handle, abortable by ``cancel()``, failing as ``XrdPosix`` words it."""
        try:
            with aborting(self._context, Abort(self._handle)):
                return action()
        except Exception as exc:
            raise posix_error(description, exc) from exc

    def read(self, size: int) -> bytes:
        """``kXR_read`` of up to ``size`` bytes at the cursor; short only at end of file."""
        data = self._read(self.position, size)
        self.position += len(data)
        return data

    def pread(self, offset: int, size: int) -> bytes:
        """Read at ``offset`` and leave the cursor after it.

        The plugin has no ``preadG``, so gfal2 emulates one with ``lseek``
        and ``read`` and the cursor stays where the read ended; code that
        mixes the two sees the same file here as there.
        """
        data = self._read(offset, size)
        self.position = offset + len(data)
        return data

    def _read(self, offset: int, size: int) -> bytes:
        """One positional read (:meth:`xrdclient.File.read`); the cursor is the caller's."""
        return self._io(
            "Failed while reading from file", lambda: bytes(self._handle.read(size, offset))
        )

    def readinto(self, buffer: memoryview | bytearray) -> int:
        """Fill ``buffer`` from the cursor (:meth:`xrdclient.File.readinto`); the count read."""
        count = self._io(
            "Failed while reading from file",
            lambda: int(self._handle.readinto(buffer, self.position)),
        )
        self.position += count
        return count

    def pwrite(self, data: bytes | bytearray | memoryview, offset: int) -> int:
        """``kXR_write`` at ``offset``; ``EBADF`` on a read-only handle, without a round trip.

        The server would refuse the write too, but with its own wording;
        gfal2's ``EBADF`` comes from ``XrdPosix``'s check of the open mode.
        """
        if not self._writable:
            code = errno.EBADF
            raise GError(f"Failed while writing to file ({os.strerror(code)})", code)
        view = memoryview(data).cast("B")
        return self._io(
            "Failed while writing to file",
            lambda: int(self._handle.write(view, offset)),
        )

    def size(self) -> int:
        """The file's length: xrdclient's cached size, else a ``kXR_stat`` on the open handle.

        What gfal2's ``lseek(SEEK_END)`` needs; a stat by handle rather than
        by path still answers after the file has been renamed or removed.
        """
        return self._io("Failed to seek within file", lambda: int(self._handle.size))

    def close(self) -> None:
        """``kXR_close``, once; a write's failure to persist surfaces here, so it is raised."""
        if self.closed:
            return
        self.closed = True
        self._io("Failed to close file", self._handle.close)
