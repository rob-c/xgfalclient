"""``Gfal2Context``: the object every gfal2 program is written against.

Method names, argument orders, overloads and return values are gfal2's, so
code written for the C-backed bindings runs unchanged::

    ctx = xgfalclient.creat_context()
    ctx.stat("davs://se.example.org/store/f").st_size
    ctx.filecopy(params, "file:///tmp/f", "root://se.example.org//store/f")

Each call is dispatched to the first plugin, in priority order, that both
claims the URL and implements the operation. Where gfal2's core fills a gap
itself - ``listdir`` from ``opendir``, ``mkdir_rec`` from ``mkdir``,
``lstat`` from ``stat``, bulk ``unlink`` from single ones, ``getxattr`` of
``user.checksum.<alg>`` from ``checksum`` - so does this.

Every failure is a ``GError``: a plugin that lets a ``ValueError`` or a
stray ``OSError`` escape is reported as ``EINVAL``/``EIO`` or the errno, as
gfal2 reports everything. A freed context refuses every call with
``EFAULT``, as the bindings do. The list forms of the tape calls answer one
result per URL and raise only for an empty list or mismatched metadata.

Knowingly different from gfal2: ``access`` falls back to ``stat`` for a
plugin without ``access``; a bulk ``unlink`` routes each URL to its own
plugin (gfal2 sends them all to the first URL's); ``rename`` across two
plugins is refused with ``EPROTONOSUPPORT`` where gfal2 silently does
nothing; client info is percent-encoded byte for byte, where gfal2 mangles
non-ASCII bytes to ``%FF``; ``read(0)`` and ``write("")`` succeed; and
``cancel()`` never waits for operations running on the calling thread (a
callback that cancels its own copy would deadlock gfal2); and a second
``free()`` does nothing rather than raise.
"""

from __future__ import annotations

import errno
import functools
import logging
import os
import threading
import urllib.parse
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING, Any, cast

from . import plugins as _registry
from .creds import (
    Credential,
    CredentialStore,
    TLSContexts,
    X509Credential,
    find_bearer_token,
    find_ca_path,
    find_x509,
    seed_options,
)
from .enums import event_side
from .errors import GError, from_oserror, not_supported_url
from .events import GfaltEvent
from .options import Options
from .plugin import (
    O_CREAT,
    O_RDONLY,
    O_RDWR,
    O_TRUNC,
    O_WRONLY,
    DirEntry,
    Plugin,
    PluginFile,
    StagingResult,
)
from .transfer import TransferParameters, run_bulk, run_copy
from .types import Dirent, Stat, dtype_for_mode
from .url import parent, scheme_of

if TYPE_CHECKING:
    import ssl

__all__ = ["Gfal2Context", "FileType", "DirectoryType", "creat_context"]

_log = logging.getLogger("gfal2")

#: ``gfal2_cred_get``'s fallback when no prefix matches: the configured value.
_CONFIGURED_CREDENTIAL = {
    "X509_CERT": ("X509", "CERT"),
    "X509_KEY": ("X509", "KEY"),
    "BEARER": ("BEARER", "TOKEN"),
}

_OPEN_FLAGS = {
    "r": O_RDONLY,
    "w": O_WRONLY | O_CREAT | O_TRUNC,
    "rw": O_RDWR | O_CREAT,
}


class FileType:
    """An open file (``ctx.open``). ``read`` returns ``str``; ``read_bytes`` bytes."""

    def __init__(self, context: Gfal2Context, path: str, flag: str) -> None:
        if flag not in _OPEN_FLAGS:
            raise RuntimeError("Invalid open flag, must be r, w, or rw")
        self._context = context
        self.path = path
        self._file = context._open(path, _OPEN_FLAGS[flag])

    def read(self, count: int) -> str:
        return self.read_bytes(count).decode("utf-8", "surrogateescape")

    def read_bytes(self, count: int) -> bytes:
        return cast(bytes, self._call(self._file.read, count))

    def readinto(self, buffer: bytearray | memoryview) -> int:
        return cast(int, self._call(self._file.readinto, buffer))

    def pread(self, offset: int, count: int) -> str:
        return self.pread_bytes(offset, count).decode("utf-8", "surrogateescape")

    def pread_bytes(self, offset: int, count: int) -> bytes:
        return cast(bytes, self._call(self._file.pread, offset, count))

    def write(self, data: str | bytes | bytearray | memoryview) -> int:
        return cast(int, self._call(self._file.write, _as_bytes(data)))

    def pwrite(self, data: str | bytes | bytearray | memoryview, offset: int) -> int:
        return cast(int, self._call(self._file.pwrite, _as_bytes(data), offset))

    def lseek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return cast(int, self._call(self._file.lseek, offset, whence))

    def close(self) -> None:
        if not self._file.closed:
            self._call(self._file.close)

    @property
    def closed(self) -> bool:
        return bool(self._file.closed)

    def _call(self, method: Any, *args: Any) -> Any:
        if self._file.closed:
            raise GError("I/O operation on a closed file", errno.EBADF)
        return self._context._guard(method, *args)

    def __enter__(self) -> FileType:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        file = getattr(self, "_file", None)
        if file is not None and not file.closed:
            try:
                file.close()
            except Exception:  # closing from a finaliser must never raise
                _log.debug("error closing %s from its finaliser", self.path, exc_info=True)

    def __repr__(self) -> str:
        return f"<xgfalclient.FileType {self.path!r}>"


def _as_bytes(data: str | bytes | bytearray | memoryview) -> bytes | bytearray | memoryview:
    return data.encode("utf-8", "surrogateescape") if isinstance(data, str) else data


class DirectoryType:
    """An open directory (``ctx.opendir``). ``read()`` returns an empty ``Dirent`` at the end."""

    def __init__(self, context: Gfal2Context, path: str) -> None:
        self._context = context
        self.path = path
        self._entries: Iterator[DirEntry] = context._opendir(path)
        self._offset = 0

    def _next(self) -> tuple[str, Stat | None, int | None] | None:
        """``(name, stat, d_type)``; ``d_type`` is ``None`` unless the plugin gave one."""
        try:
            entry: DirEntry = self._context._guard(next, self._entries)
        except StopIteration:
            return None
        return (entry[0], entry[1], entry[2] if len(entry) == 3 else None)

    def read(self) -> Dirent:
        entry = self._next()
        if entry is None:
            return Dirent()
        name, info, dtype = entry
        self._offset += 1
        if dtype is None:
            dtype = dtype_for_mode(info.st_mode) if info is not None else 0
        ino = info.st_ino if info is not None else 0
        return Dirent(name, dtype, ino, self._offset)

    def readpp(self) -> tuple[Dirent, Stat] | tuple[None, None]:
        entry = self._next()
        if entry is None:
            return None, None
        name, info, dtype = entry
        if info is None:
            info = self._context.stat(_child(self.path, name))
        self._offset += 1
        if dtype is None:
            dtype = dtype_for_mode(info.st_mode)
        return Dirent(name, dtype, info.st_ino, self._offset), info

    def __iter__(self) -> Iterator[Dirent]:
        while True:
            entry = self.read()
            if not entry.d_name:
                return
            yield entry

    def __repr__(self) -> str:
        return f"<xgfalclient.DirectoryType {self.path!r}>"


def _child(url: str, name: str) -> str:
    head, sep, query = url.partition("?")
    joined = head if head.endswith("/") else head + "/"
    return joined + name + (sep + query if sep else "")


class Gfal2Context:
    """A gfal2 context: options, credentials, and the loaded plugins."""

    def __init__(self, *, options: Options | None = None, load_plugins: bool = True) -> None:
        self.options = options if options is not None else Options()
        seed_options(self.options)
        self.credentials = CredentialStore()
        self.tls = TLSContexts()
        #: Ordered pairs, re-ordered as gfal2's ``GPtrArray`` is (see ``add_client_info``).
        self._client_info: list[tuple[str, str]] = []
        self._user_agent: tuple[str | None, str | None] = (None, None)
        self._cancel_generation = 0
        self._running = 0
        #: Running operations per thread, so ``cancel()`` never waits for its own.
        self._running_by_thread: dict[int, int] = {}
        self._cancelling = 0
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self._freed = False
        self._load_lock = threading.Lock()
        self.plugins: list[Plugin] = []
        #: Built-ins not imported yet; each is loaded when a URL first needs it.
        self._pending: list[_registry.Entry] = []
        #: Third-party entry points are only looked up for a scheme no built-in
        #: claims: ``importlib.metadata`` alone costs more than half a second.
        self._entry_points_pending = load_plugins
        if load_plugins:
            self._pending = sorted(_registry.BUILTIN, key=lambda entry: entry.priority)

    # -- plugins -----------------------------------------------------------------

    def add_plugin(self, cls: type[Plugin]) -> Plugin:
        """Load one more plugin (what gfal2 does per ``.so`` it finds)."""
        instance = cls(self)
        # Swap in a new list, so a thread iterating the old one never sees it change.
        self.plugins = sorted([*self.plugins, instance], key=lambda plugin: plugin.priority)
        # gfal2's words for a plugin it loads and for the order it then tries them in.
        _log.info("[gfal_module_load] plugin %s loaded with success ", cls.__module__)
        _log.debug(" gfal_plugin loaded successfully : %s", cls.__module__)
        order = "".join(f"{plugin.label} -> " for plugin in self.plugins)
        _log.debug(" plugin priority order: %s", order)
        return instance

    def _load_for(self, *schemes: str) -> None:
        """Import the pending built-ins that claim any of ``schemes``."""
        if not (self._pending or self._entry_points_pending):
            return
        with self._load_lock:  # held across the import: no half-loaded view
            wanted = [e for e in self._pending if any(s in e.schemes for s in schemes)]
            for entry in wanted:
                self._pending.remove(entry)
                cls = _registry.load(entry)
                if cls is not None:
                    self.add_plugin(cls)
            builtin = {scheme for entry in _registry.BUILTIN for scheme in entry.schemes}
            if self._entry_points_pending and not set(schemes) <= builtin:
                self._load_entry_points()

    def _load_entry_points(self) -> None:
        self._entry_points_pending = False
        for cls in _registry.entry_point_classes():
            self.add_plugin(cls)

    def _load_all(self) -> None:
        self._load_for(*(scheme for entry in self._pending for scheme in entry.schemes))
        with self._load_lock:
            if self._entry_points_pending:
                self._load_entry_points()

    def get_plugin_names(self) -> list[str]:
        self._load_all()
        return [plugin.label for plugin in self.plugins]

    def plugin(self, url: str, operation: str) -> Plugin:
        """The plugin that will perform ``operation`` on ``url``."""
        found = self._find(url, operation)
        if found is None:
            raise self._no_plugin(url)
        return found

    def _find(self, url: str, operation: str) -> Plugin | None:
        self._load_for(_load_key(url))
        for candidate in self.plugins:
            if candidate.implements(operation) and candidate.handles(url, operation):
                return candidate
        return None

    def _no_plugin(self, url: str) -> GError:
        error = not_supported_url(url)
        hint = _registry.missing_hint(scheme_of(url))
        if hint:
            error.message = f"{error.message} ({hint})"
            error.args = (error.message, error.code)
        return error

    def _copy_plugin(self, source: str, destination: str) -> Plugin | None:
        self._load_for(_load_key(source), _load_key(destination))
        for candidate in self.plugins:
            if candidate.implements("copy") and candidate.copy_check(source, destination):
                return candidate
        return None

    # -- plumbing ---------------------------------------------------------------

    def _enter(self) -> None:
        """Count one more running operation (refused while a ``cancel()`` drains)."""
        if self._freed:
            raise _freed()
        with self._lock:
            if self._cancelling:
                raise GError("[gfal2_cancel] operation canceled by user", errno.ECANCELED)
            self._running += 1
            me = threading.get_ident()
            self._running_by_thread[me] = self._running_by_thread.get(me, 0) + 1

    def _leave(self) -> None:
        with self._lock:
            self._running -= 1
            me = threading.get_ident()
            left = self._running_by_thread.pop(me) - 1
            if left:
                self._running_by_thread[me] = left
            self._idle.notify_all()

    def _guard(self, method: Any, *args: Any) -> Any:
        """Run a plugin call, counting it as running and making every failure a ``GError``."""
        self._enter()
        try:
            return method(*args)
        except (GError, StopIteration):
            raise
        except OSError as exc:
            # gfal2's file plugin words a local failure; so does any errno here.
            if exc.errno is not None:
                raise from_oserror(exc) from exc
            raise GError(str(exc), errno.EIO) from exc
        except Exception as exc:
            code = errno.EINVAL if isinstance(exc, ValueError) else errno.EIO
            raise GError(str(exc) or type(exc).__name__, code) from exc
        finally:
            self._leave()

    def _dispatch(self, operation: str, url: str, *args: Any) -> Any:
        plugin = self.plugin(url, operation)
        return self._guard(getattr(plugin, operation), url, *args)

    def _open(self, url: str, flags: int, size: int | None = None, mode: int = 0o744) -> PluginFile:
        """Open through the URL's plugin; ``mode`` for a file this creates is
        gfal2's (``gfal2_open`` passes 0744)."""
        plugin = self.plugin(url, "open")
        if size is None:
            return self._guard(plugin.open, url, flags, mode)  # type: ignore[no-any-return]
        return self._guard(plugin.open, url, flags, mode, size)  # type: ignore[no-any-return]

    def _opendir(self, url: str) -> Iterator[DirEntry]:
        plugin = self._find(url, "opendir")
        if plugin is not None:
            return self._guard(plugin.opendir, url)  # type: ignore[no-any-return]
        names = self._dispatch("listdir", url)
        return iter([(name, None) for name in names])

    # -- credentials helpers for plugins ------------------------------------------

    def x509(self, url: str = "") -> X509Credential | None:
        return find_x509(self.options, self.credentials, url)

    def bearer_token(self, url: str = "") -> str | None:
        return find_bearer_token(self.options, self.credentials, url)

    def ca_path(self) -> str | None:
        return find_ca_path()

    def ssl_context(
        self,
        url: str = "",
        *,
        group: str = "",
        check_hostname: bool = True,
        alpn: tuple[str, ...] = (),
    ) -> ssl.SSLContext:
        """The TLS client context for ``url``: its X.509 credential, the grid CAs,
        and ``[group] INSECURE`` honoured."""
        insecure = self.options.boolean(group, "INSECURE", False) if group else False
        return self.tls.get(
            self.x509(url),
            verify=not insecure,
            ca_path=self.ca_path(),
            check_hostname=check_hostname,
            alpn=alpn,
        )

    def user_agent_string(self) -> str:
        """What goes in a ``User-Agent`` header: ``<agent>/<version> gfal2/<v>``, as gfal2 sends."""
        from ._version import GFAL2_VERSION

        name, version = self._user_agent
        own = f"gfal2/{GFAL2_VERSION}"
        return f"{name}/{version} {own}" if name else own

    def client_info_string(self) -> str:
        """``key=value;key=value``, each side percent-encoded - gfal2's ``ClientInfo`` header.

        Empty when there is none, in which case gfal2 sends no header.
        """
        return ";".join(
            f"{_urlencode(key)}={_urlencode(value)}" for key, value in self._client_info
        )

    # -- namespace -----------------------------------------------------------------

    def access(self, path: str, mode: int) -> int:
        """``0``, or what the plugin answers (gfal2's mock answers 1)."""
        plugin = self._find(path, "access")
        if plugin is None:
            self._dispatch("stat", path)
            return 0
        answer = self._guard(plugin.access, path, mode)
        return answer if isinstance(answer, int) else 0

    def chmod(self, path: str, mode: int) -> int:
        self._dispatch("chmod", path, mode)
        return 0

    def rename(self, old: str, new: str) -> int:
        plugin = self.plugin(old, "rename")
        if self._find(new, "rename") is not plugin:
            raise not_supported_url(new)
        self._guard(plugin.rename, old, new)
        return 0

    def stat(self, path: str) -> Stat:
        return self._dispatch("stat", path)  # type: ignore[no-any-return]

    def lstat(self, path: str) -> Stat:
        if self._find(path, "lstat") is not None:
            return self._dispatch("lstat", path)  # type: ignore[no-any-return]
        return self.stat(path)

    def mkdir(self, path: str, mode: int = 0o755) -> int:
        self._dispatch("mkdir", path, mode)
        return 0

    def mkdir_rec(self, path: str, mode: int = 0o755) -> int:
        if self._find(path, "mkdir_rec") is not None:
            try:
                self._dispatch("mkdir_rec", path, mode)
            except GError as exc:
                if exc.code != errno.EEXIST:
                    raise
            return 0
        self._mkdir_parents(path, mode)
        return 0

    def _mkdir_parents(self, path: str, mode: int) -> None:
        """``gfal2_mkdir_rec``: try the leaf; on ``ENOENT`` climb until a mkdir works.

        Anything already at ``path`` - a file included - counts as done
        (``EEXIST``), exactly as in gfal2.
        """
        missing: list[str] = []  # deepest first
        current = path
        while True:
            try:
                self.mkdir(current, mode)
                break
            except GError as exc:
                if exc.code == errno.EEXIST:
                    break
                if exc.code != errno.ENOENT:
                    raise
            missing.append(current)
            up = parent(current)
            if up == current:
                break  # even the root is missing; creating it below reports why
            current = up
        for url in reversed(missing):
            try:
                self.mkdir(url, mode)
            except GError as exc:
                if exc.code != errno.EEXIST:  # made by someone else meanwhile
                    raise

    def rmdir(self, path: str) -> int:
        self._dispatch("rmdir", path)
        return 0

    def listdir(self, path: str) -> list[str]:
        plugin = self._find(path, "listdir")
        if plugin is not None:
            return self._guard(plugin.listdir, path)  # type: ignore[no-any-return]
        return [entry[0] for entry in self._opendir(path)]

    def opendir(self, path: str) -> DirectoryType:
        return DirectoryType(self, path)

    directory = opendir

    def open(self, path: str, flag: str) -> FileType:
        return FileType(self, path, flag)

    file = open

    def readlink(self, path: str) -> str:
        return self._dispatch("readlink", path)  # type: ignore[no-any-return]

    def symlink(self, target: str, link: str) -> int:
        plugin = self.plugin(link, "symlink")
        self._guard(plugin.symlink, target, link)
        return 0

    def unlink(self, path: str | Sequence[str]) -> int | list[GError | None]:
        if isinstance(path, str):
            self._dispatch("unlink", path)
            return 0
        paths = _non_empty(path)
        bulk = self._find(paths[0], "unlink_bulk")
        if bulk is not None:
            return self._guard(bulk.unlink_bulk, paths)  # type: ignore[no-any-return]
        results: list[GError | None] = []
        for item in paths:
            try:
                self._dispatch("unlink", item)
                results.append(None)
            except GError as exc:
                results.append(exc)
        return results

    # -- metadata -------------------------------------------------------------------

    def getxattr(self, path: str, name: str) -> str:
        """The attribute; for ``user.checksum.<alg>`` a failed lookup falls back to
        :meth:`checksum`, as gfal2's core does."""
        try:
            return self._dispatch("getxattr", path, name)  # type: ignore[no-any-return]
        except GError:
            if not name.startswith(_CHECKSUM_XATTR):
                raise
        return self.checksum(path, name[len(_CHECKSUM_XATTR) :])

    def setxattr(self, path: str, name: str, value: str, flags: int = 0) -> int:
        self._dispatch("setxattr", path, name, value, flags)
        return 0

    def listxattr(self, path: str) -> list[str]:
        return self._dispatch("listxattr", path)  # type: ignore[no-any-return]

    def checksum(self, path: str, algorithm: str, offset: int = 0, length: int = 0) -> str:
        value = self._dispatch("checksum", path, algorithm, offset, length)
        if algorithm.strip().lower() == "adler32" and self.options.boolean(
            "CORE", "FORMAT_ADLER32_CHECKSUM", True
        ):
            from .checksum import format_adler32

            value = format_adler32(value)
        return value  # type: ignore[no-any-return]

    # -- tape -----------------------------------------------------------------------

    def bring_online(self, path: str | Sequence[str], *args: Any) -> tuple[Any, str]:
        """``(path(s), [metadata(s)], pintime, timeout, async)``, as gfal2 overloads it."""
        if len(args) == 4:
            metadata_arg, pintime, timeout, is_async = args
        elif len(args) == 3:
            metadata_arg = None
            pintime, timeout, is_async = args
        else:
            raise TypeError("bring_online(path(s), [metadata], pintime, timeout, async)")
        call = (int(pintime), int(timeout), bool(is_async))
        if isinstance(path, str):
            metadata = [metadata_arg if metadata_arg is not None else ""]
            plugin = self.plugin(path, "bring_online")
            results, token = self._guard(plugin.bring_online, [path], metadata, *call)
            return _single_status(results[0]), token
        paths = _non_empty(path)
        metadata = list(metadata_arg) if metadata_arg is not None else [""] * len(paths)
        if len(metadata) != len(paths):
            raise GError("List of urls and list of metadata with different sizes", errno.EINVAL)
        found = self._bulk("bring_online", paths, metadata, *call)
        if isinstance(found, GError):
            return [found] * len(paths), ""
        results, token = found
        return [_list_error(r, u, None) for r, u in zip(results, paths)], token

    def bring_online_poll(self, path: str | Sequence[str], token: str) -> Any:
        if isinstance(path, str):
            return _single_status(self._one("bring_online_poll", path, token), pending=True)
        return self._bulk_list("bring_online_poll", path, "online", token)

    def release(self, path: str | Sequence[str], token: str = "") -> Any:
        if isinstance(path, str):
            return _single_done(self._one("release", path, token))
        return self._bulk_list("release", path, None, token)

    def abort_bring_online(self, path: str | Sequence[str], token: str) -> Any:
        if isinstance(path, str):
            return _single_done(self._one("abort_bring_online", path, token))
        return self._bulk_list("abort_bring_online", path, None, token)

    def archive_poll(self, path: str | Sequence[str]) -> Any:
        if isinstance(path, str):
            return _single_status(self._one("archive_poll", path), pending=True)
        return self._bulk_list("archive_poll", path, "archived")

    def _one(self, operation: str, path: str, *args: Any) -> Any:
        """A list-shaped plugin call made for one URL: its only result."""
        plugin = self.plugin(path, operation)
        return self._guard(getattr(plugin, operation), [path], *args)[0]

    def _bulk(self, operation: str, paths: list[str], *args: Any) -> Any:
        """Run a list-form call on the first URL's plugin, or the ``GError`` every file gets.

        gfal2 sends the whole list to the plugin of the first URL, and turns a
        failure to find one (or of the call as a whole) into the same error
        for each file rather than raising.
        """
        try:
            plugin = self.plugin(paths[0], operation)
            return self._guard(getattr(plugin, operation), paths, *args)
        except GError as exc:
            return exc

    def _bulk_list(
        self, operation: str, path: Sequence[str], pending: str | None, *args: Any
    ) -> list[GError | None]:
        paths = _non_empty(path)
        found = self._bulk(operation, paths, *args)
        if isinstance(found, GError):
            return [found] * len(paths)
        return [_list_error(r, u, pending) for r, u in zip(found, paths)]

    # -- QoS ----------------------------------------------------------------------

    def check_file_qos(self, path: str) -> str:
        return self._dispatch("check_file_qos", path)  # type: ignore[no-any-return]

    def check_available_qos_transitions(self, path: str) -> list[str]:
        return self._dispatch("check_available_qos_transitions", path)  # type: ignore[no-any-return]

    def check_target_qos(self, path: str) -> str:
        return self._dispatch("check_target_qos", path)  # type: ignore[no-any-return]

    def change_object_qos(self, path: str, target: str) -> int:
        self._dispatch("change_object_qos", path, target)
        return 0

    def qos_check_classes(self, path: str, kind: str) -> list[str]:
        return self._dispatch("qos_check_classes", path, kind)  # type: ignore[no-any-return]

    # -- tokens ---------------------------------------------------------------------

    def token_retrieve(self, path: str, issuer: str, validity: int, *access: Any) -> str:
        """``(url, issuer, validity, write_access | activities)`` or
        ``(url, issuer, validity, write_access, activities)``, as gfal2 overloads it.

        Given activities, the plugin asks for those; ``write_access`` only
        picks a default set, and is ``False`` for the activities-only form.
        """
        if len(access) == 2:
            write_access, activities = bool(access[0]), list(access[1])
        elif len(access) == 1 and isinstance(access[0], (list, tuple)):
            write_access, activities = False, list(access[0])
            if not activities:
                raise GError("Empty list of activities", errno.EINVAL)
        elif len(access) == 1:
            write_access, activities = bool(access[0]), []
        else:
            raise TypeError("token_retrieve(url, issuer, validity, write_access[, activities])")
        return self._dispatch(  # type: ignore[no-any-return]
            "token_retrieve", path, issuer, int(validity), write_access, activities
        )

    # -- copies -----------------------------------------------------------------------

    #: gfal2 binds the class itself here, so ``ctx.transfer_parameters()`` makes one
    #: and ``isinstance(p, ctx.transfer_parameters)`` holds.
    transfer_parameters = TransferParameters

    def filecopy(self, *args: Any) -> Any:
        """``filecopy([params,] src, dst)`` or ``filecopy([params,] srcs, dsts[, checksums])``."""
        if args and isinstance(args[0], TransferParameters):
            params, rest = args[0], args[1:]
        else:
            params, rest = TransferParameters(), args
        if len(rest) == 2 and isinstance(rest[0], str) and isinstance(rest[1], str):
            with self._running_op():
                run_copy(self, params, rest[0], rest[1])
            return 0
        if len(rest) in (2, 3) and not isinstance(rest[0], str):
            checksums = list(rest[2]) if len(rest) == 3 else []
            with self._running_op():
                return run_bulk(self, params, list(rest[0]), list(rest[1]), checksums)
        raise TypeError("filecopy([params,] src, dst) or filecopy([params,] srcs, dsts[, cks])")

    def _running_op(self) -> _Running:
        return _Running(self)

    # -- options ----------------------------------------------------------------------

    def get_opt_string(self, group: str, key: str) -> str:
        return self.options.get_string(group, key)

    def get_opt_integer(self, group: str, key: str) -> int:
        return self.options.get_integer(group, key)

    def get_opt_boolean(self, group: str, key: str) -> bool:
        return self.options.get_boolean(group, key)

    def get_opt_string_list(self, group: str, key: str) -> list[str]:
        return self.options.get_string_list(group, key)

    def set_opt_string(self, group: str, key: str, value: str) -> int:
        self.options.set_string(group, key, value)
        return 0

    def set_opt_integer(self, group: str, key: str, value: int) -> int:
        self.options.set_integer(group, key, value)
        return 0

    def set_opt_boolean(self, group: str, key: str, value: bool) -> int:
        self.options.set_boolean(group, key, value)
        return 0

    def set_opt_string_list(self, group: str, key: str, values: Sequence[str]) -> int:
        self.options.set_string_list(group, key, values)
        return 0

    def remove_opt(self, group: str, key: str) -> bool:
        return self.options.remove(group, key)

    def load_opts_from_file(self, path: str) -> int:
        self.options.load_file(path)
        return 0

    # -- credentials -------------------------------------------------------------------

    #: As in gfal2, the ``Credential`` class itself.
    cred_new = Credential

    def cred_set(self, prefix: str, credential: Credential) -> int:
        self.credentials.set(prefix, credential)
        self.tls.clear()
        return 0

    def cred_get(self, type: str, url: str) -> tuple[str, str]:
        """``(value, prefix)``; with no prefix matching, the configured
        ``[X509] CERT``/``KEY`` or ``[BEARER] TOKEN`` and an empty prefix."""
        found = self.credentials.get(type, url)
        if found[1] or type not in _CONFIGURED_CREDENTIAL:
            return found
        return self.options.string(*_CONFIGURED_CREDENTIAL[type]), ""

    def cred_del(self, type: str, prefix: str) -> int:
        """``0``, or ``-1`` if there was no credential of ``type`` at exactly ``prefix``."""
        removed = self.credentials.delete(type, prefix)
        self.tls.clear()
        return 0 if removed else -1

    def cred_clean(self) -> int:
        self.credentials.clean()
        self.tls.clear()
        return 0

    # -- client identity ------------------------------------------------------------------

    def set_user_agent(self, name: str, version: str) -> int:
        self._user_agent = (name, version)
        return 0

    def get_user_agent(self) -> tuple[str | None, str | None]:
        return self._user_agent

    def add_client_info(self, key: str, value: str) -> int:
        """Set ``key``; a key set again moves to the end, as in gfal2."""
        with self._lock:
            self._remove_client_info(key)
            self._client_info.append((key, value))
        return 0

    def remove_client_info(self, key: str) -> int:
        with self._lock:
            if not self._remove_client_info(key):
                raise GError(f"Key {key} not found", errno.EINVAL)
        return 0

    def _remove_client_info(self, key: str) -> bool:
        """``g_ptr_array_remove_index_fast``: the last entry takes the removed one's place."""
        for index, (name, _) in enumerate(self._client_info):
            if name == key:
                last = self._client_info.pop()
                if index < len(self._client_info):
                    self._client_info[index] = last
                return True
        return False

    def clear_client_info(self) -> int:
        with self._lock:
            self._client_info = []
        return 0

    def get_client_info(self) -> dict[str, str]:
        return dict(self._client_info)

    # -- lifecycle ----------------------------------------------------------------------

    def cancel(self) -> int:
        """Cancel what is in flight and wait for it to stop, as ``gfal2_cancel`` does.

        Answers how many operations were running. Copies notice between
        chunks; an operation starting meanwhile fails with ``ECANCELED``.
        Operations running on the calling thread (a callback cancelling its
        own copy) are not waited for.
        """
        with self._lock:
            self._cancel_generation += 1
            running = self._running
            self._cancelling += 1
            try:
                me = threading.get_ident()
                self._idle.wait_for(lambda: self._running == self._running_by_thread.get(me, 0))
            finally:
                self._cancelling -= 1
            return running

    def free(self) -> None:
        """Release the plugins; every later call raises ``EFAULT``.

        A second ``free()`` does nothing, where gfal2's raises: fixtures and
        ``with`` blocks free contexts that a test may already have freed.
        """
        if self._freed:
            return
        for plugin in self.plugins:
            try:
                plugin.close()
            except Exception:
                _log.debug("plugin %s failed to close", plugin.name, exc_info=True)
        self.tls.clear()
        self._freed = True

    def __enter__(self) -> Gfal2Context:
        return self

    def __exit__(self, *exc: object) -> None:
        self.free()

    def __repr__(self) -> str:
        loaded = [plugin.label for plugin in self.plugins]
        return f"<xgfalclient.Gfal2Context plugins={loaded} pending={len(self._pending)}>"


# gfal2 exposes its record types as attributes of the context class too, and
# (being defined inside the class's scope) its event enum and NullHandler.
for _alias in (Credential, DirectoryType, Dirent, FileType, GfaltEvent, Stat, TransferParameters):
    setattr(Gfal2Context, _alias.__name__, _alias)
Gfal2Context.event_side = event_side  # type: ignore[attr-defined]
Gfal2Context.gfalt_event = GfaltEvent  # type: ignore[attr-defined]
Gfal2Context.NullHandler = logging.NullHandler  # type: ignore[attr-defined]


def _freed() -> GError:
    return GError("gfal2 context has been freed", errno.EFAULT)


def _live(method: Any) -> Any:
    """Refuse the call once the context is freed, as every bindings method does."""

    @functools.wraps(method)
    def call(self: Gfal2Context, *args: Any, **kwargs: Any) -> Any:
        if self._freed:
            raise _freed()
        return method(self, *args, **kwargs)

    return call


#: The bindings' methods; each raises ``EFAULT`` on a freed context.
_API = (
    "cancel", "open", "file", "opendir", "directory", "access", "lstat", "stat",
    "chmod", "unlink", "mkdir", "mkdir_rec", "rmdir", "listdir", "rename", "readlink",
    "symlink", "checksum", "getxattr", "setxattr", "listxattr", "remove_opt",
    "get_opt_integer", "get_opt_boolean", "get_opt_string", "get_opt_string_list",
    "set_opt_string_list", "set_opt_string", "set_opt_boolean", "set_opt_integer",
    "load_opts_from_file", "set_user_agent", "get_user_agent", "add_client_info",
    "remove_client_info", "clear_client_info", "get_client_info", "filecopy",
    "bring_online", "bring_online_poll", "archive_poll", "release", "abort_bring_online",
    "get_plugin_names", "qos_check_classes", "check_file_qos",
    "check_available_qos_transitions", "check_target_qos", "change_object_qos",
    "token_retrieve", "cred_set", "cred_get", "cred_del", "cred_clean",
)  # fmt: skip
for _name in _API:
    setattr(Gfal2Context, _name, _live(getattr(Gfal2Context, _name)))


class _Running:
    """Counts a whole copy as one running operation, for ``cancel()``."""

    def __init__(self, context: Gfal2Context) -> None:
        self.context = context

    def __enter__(self) -> None:
        self.context._enter()

    def __exit__(self, *exc: object) -> None:
        self.context._leave()


def _single_status(result: StagingResult, pending: bool = False) -> int:
    """``1`` done, ``0`` not yet; a poll's ``EAGAIN`` is "not yet" too, as in the bindings."""
    if isinstance(result, GError):
        if pending and result.code == errno.EAGAIN:
            return 0
        raise result
    return 1 if result else 0


def _list_error(result: StagingResult, url: str, pending: str | None) -> GError | None:
    """``None`` for done; the error, or ``EAGAIN`` worded as gfal2 does, otherwise."""
    if isinstance(result, GError):
        return result
    if not result and pending is not None:
        return GError(f"File {url} is not yet {pending}", errno.EAGAIN)
    return None


def _single_done(result: GError | None) -> int:
    if result is not None:
        raise result
    return 0


def _load_key(url: str) -> str:
    """The scheme a lazily loaded plugin is filed under.

    ``scheme_of`` wants ``scheme://``; gfal2's mock plugin also takes
    ``mock:anything``, so a bare ``scheme:`` prefix names a plugin to load too.
    """
    return scheme_of(url) or url.partition(":")[0].lower()


def _non_empty(paths: Sequence[str]) -> list[str]:
    """A list-form argument as a list; gfal2 refuses an empty one."""
    found = list(paths)
    if not found:
        raise GError("Empty list of files", errno.EINVAL)
    return found


#: The attribute prefix gfal2's core answers with a checksum when a plugin cannot.
_CHECKSUM_XATTR = "user.checksum."


def _urlencode(text: str) -> str:
    """``gfal2_urlencode``: every byte but ``[A-Za-z0-9._-]`` as ``%XX``."""
    return urllib.parse.quote(text, safe="", encoding="utf-8", errors="surrogateescape").replace(
        "~", "%7E"
    )


def creat_context() -> Gfal2Context:
    """A new context with the default options and every available plugin."""
    return Gfal2Context()
