"""``Gfal2Context``: the object every gfal2 program is written against.

Method names, argument orders, overloads and return values are gfal2's, so
code written for the C-backed bindings runs unchanged::

    ctx = xgfalclient.creat_context()
    ctx.stat("davs://se.example.org/store/f").st_size
    ctx.filecopy(params, "file:///tmp/f", "root://se.example.org//store/f")

Each call is dispatched to the first plugin, in priority order, that both
claims the URL and implements the operation. Where gfal2's core fills a gap
itself - ``listdir`` from ``opendir``, ``mkdir_rec`` from ``mkdir``,
``lstat`` from ``stat``, bulk ``unlink`` from single ones - so does this.
"""

from __future__ import annotations

import errno
import logging
import os
import threading
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
)
from .errors import GError, not_supported_url
from .events import GfaltEvent
from .options import Options
from .plugin import O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, Plugin, PluginFile, StagingResult
from .transfer import TransferParameters, run_bulk, run_copy
from .types import Dirent, Stat, dtype_for_mode
from .url import parent, scheme_of

if TYPE_CHECKING:
    import ssl

__all__ = ["Gfal2Context", "FileType", "DirectoryType", "creat_context"]

_log = logging.getLogger("xgfalclient")

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
        self._entries: Iterator[tuple[str, Stat | None]] = context._opendir(path)
        self._offset = 0

    def _next(self) -> tuple[str, Stat | None] | None:
        try:
            return self._context._guard(next, self._entries)  # type: ignore[no-any-return]
        except StopIteration:
            return None

    def read(self) -> Dirent:
        entry = self._next()
        if entry is None:
            return Dirent()
        name, info = entry
        self._offset += 1
        dtype = dtype_for_mode(info.st_mode) if info is not None else 0
        ino = info.st_ino if info is not None else 0
        return Dirent(name, dtype, ino, self._offset)

    def readpp(self) -> tuple[Dirent, Stat] | tuple[None, None]:
        entry = self._next()
        if entry is None:
            return None, None
        name, info = entry
        if info is None:
            info = self._context.stat(_child(self.path, name))
        self._offset += 1
        return Dirent(name, dtype_for_mode(info.st_mode), info.st_ino, self._offset), info

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
        self.credentials = CredentialStore()
        self.tls = TLSContexts()
        self._client_info: dict[str, str] = {}
        self._user_agent: tuple[str | None, str | None] = (None, None)
        self._cancel_generation = 0
        self._running = 0
        self._lock = threading.Lock()
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
        self._load_for(scheme_of(url))
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
        self._load_for(scheme_of(source), scheme_of(destination))
        for candidate in self.plugins:
            if candidate.implements("copy") and candidate.copy_check(source, destination):
                return candidate
        return None

    # -- plumbing ---------------------------------------------------------------

    def _guard(self, method: Any, *args: Any) -> Any:
        """Run a plugin call, counting it as running and normalising failures."""
        if self._freed:
            raise GError("The context has been freed", errno.EBADF)
        with self._lock:
            self._running += 1
        try:
            return method(*args)
        except (GError, StopIteration):
            raise
        except OSError as exc:
            code = exc.errno if exc.errno is not None else errno.EIO
            raise GError(str(exc), code) from exc
        finally:
            with self._lock:
                self._running -= 1

    def _dispatch(self, operation: str, url: str, *args: Any) -> Any:
        plugin = self.plugin(url, operation)
        return self._guard(getattr(plugin, operation), url, *args)

    def _open(self, url: str, flags: int, size: int | None = None) -> PluginFile:
        plugin = self.plugin(url, "open")
        if size is None:
            return self._guard(plugin.open, url, flags)  # type: ignore[no-any-return]
        return self._guard(plugin.open, url, flags, 0o644, size)  # type: ignore[no-any-return]

    def _opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
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
        """What goes in a ``User-Agent`` header."""
        from ._version import __version__

        name, version = self._user_agent
        if name:
            return f"{name}/{version}" if version else name
        return f"xgfalclient/{__version__}"

    def client_info_string(self) -> str:
        """``key=value;key=value`` - the ``ClientInfo`` header gfal2 sends."""
        return ";".join(f"{key}={value}" for key, value in self._client_info.items())

    # -- namespace -----------------------------------------------------------------

    def access(self, path: str, mode: int) -> int:
        plugin = self._find(path, "access")
        if plugin is not None:
            self._guard(plugin.access, path, mode)
        else:
            self._dispatch("stat", path)
        return 0

    def chmod(self, path: str, mode: int) -> int:
        self._dispatch("chmod", path, mode)
        return 0

    def rename(self, old: str, new: str) -> int:
        self._dispatch("rename", old, new)
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
            self._dispatch("mkdir_rec", path, mode)
            return 0
        self._mkdir_parents(path, mode)
        return 0

    def _mkdir_parents(self, path: str, mode: int) -> None:
        try:
            if self.stat(path).is_dir():
                return
            raise GError(f"{path} exists and is not a directory", errno.ENOTDIR)
        except GError as exc:
            if exc.code != errno.ENOENT:
                raise
        up = parent(path)
        if up != path:
            self._mkdir_parents(up, mode)
        try:
            self.mkdir(path, mode)
        except GError as exc:
            if exc.code != errno.EEXIST:
                raise

    def rmdir(self, path: str) -> int:
        self._dispatch("rmdir", path)
        return 0

    def listdir(self, path: str) -> list[str]:
        plugin = self._find(path, "listdir")
        if plugin is not None:
            return self._guard(plugin.listdir, path)  # type: ignore[no-any-return]
        return [name for name, _ in self._opendir(path)]

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
        paths = list(path)
        if not paths:
            return []
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
        return self._dispatch("getxattr", path, name)  # type: ignore[no-any-return]

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
        single = isinstance(path, str)
        paths = [path] if isinstance(path, str) else list(path)
        if len(args) == 4:
            metadata_arg, pintime, timeout, is_async = args
            metadata = [metadata_arg] if single else list(metadata_arg)
        elif len(args) == 3:
            pintime, timeout, is_async = args
            metadata = [""] * len(paths)
        else:
            raise TypeError("bring_online(path(s), [metadata], pintime, timeout, async)")
        if len(metadata) != len(paths):
            raise GError("Number of metadata entries does not match the paths", errno.EINVAL)
        plugin = self.plugin(paths[0], "bring_online")
        results, token = self._guard(
            plugin.bring_online, paths, metadata, int(pintime), int(timeout), bool(is_async)
        )
        if single:
            return _single_status(results[0]), token
        return [_list_error(r, u, None) for r, u in zip(results, paths)], token

    def bring_online_poll(self, path: str | Sequence[str], token: str) -> Any:
        paths = [path] if isinstance(path, str) else list(path)
        plugin = self.plugin(paths[0], "bring_online_poll")
        results = self._guard(plugin.bring_online_poll, paths, token)
        if isinstance(path, str):
            return _single_status(results[0])
        return [_list_error(r, u, "online") for r, u in zip(results, paths)]

    def release(self, path: str | Sequence[str], token: str = "") -> Any:
        paths = [path] if isinstance(path, str) else list(path)
        plugin = self.plugin(paths[0], "release")
        results = self._guard(plugin.release, paths, token)
        return _single_or_list(path, results)

    def abort_bring_online(self, path: str | Sequence[str], token: str) -> Any:
        paths = [path] if isinstance(path, str) else list(path)
        plugin = self.plugin(paths[0], "abort_bring_online")
        results = self._guard(plugin.abort_bring_online, paths, token)
        return _single_or_list(path, results)

    def archive_poll(self, path: str | Sequence[str]) -> Any:
        paths = [path] if isinstance(path, str) else list(path)
        plugin = self.plugin(paths[0], "archive_poll")
        results = self._guard(plugin.archive_poll, paths)
        if isinstance(path, str):
            return _single_status(results[0])
        return [_list_error(r, u, "archived") for r, u in zip(results, paths)]

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

    def token_retrieve(
        self, path: str, issuer: str, validity: int, access: bool | Sequence[str]
    ) -> str:
        if isinstance(access, bool):
            write_access, activities = access, []
        else:
            activities = list(access)
            write_access = any(
                activity.upper() in ("UPLOAD", "MANAGE", "UPDATE", "DELETE")
                for activity in activities
            )
        return self._dispatch(  # type: ignore[no-any-return]
            "token_retrieve", path, issuer, int(validity), write_access, activities
        )

    # -- copies -----------------------------------------------------------------------

    def transfer_parameters(self) -> TransferParameters:
        return TransferParameters()

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

    def cred_new(self, type: str, value: str) -> Credential:
        return Credential(type, value)

    def cred_set(self, prefix: str, credential: Credential) -> int:
        self.credentials.set(prefix, credential)
        self.tls.clear()
        return 0

    def cred_get(self, type: str, url: str) -> tuple[str, str]:
        return self.credentials.get(type, url)

    def cred_del(self, type: str, prefix: str) -> int:
        self.credentials.delete(type, prefix)
        self.tls.clear()
        return 0

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
        self._client_info[key] = value
        return 0

    def remove_client_info(self, key: str) -> int:
        self._client_info.pop(key, None)
        return 0

    def clear_client_info(self) -> int:
        self._client_info.clear()
        return 0

    def get_client_info(self) -> dict[str, str]:
        return dict(self._client_info)

    # -- lifecycle ----------------------------------------------------------------------

    def cancel(self) -> int:
        """Cancel the copies in flight; answers how many operations were running."""
        with self._lock:
            self._cancel_generation += 1
            return self._running

    def free(self) -> None:
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


# gfal2 exposes its record types as attributes of the context class too.
for _alias in (Credential, DirectoryType, Dirent, FileType, GfaltEvent, Stat, TransferParameters):
    setattr(Gfal2Context, _alias.__name__, _alias)


class _Running:
    """Counts a whole copy as one running operation, for ``cancel()``."""

    def __init__(self, context: Gfal2Context) -> None:
        self.context = context

    def __enter__(self) -> None:
        with self.context._lock:
            self.context._running += 1

    def __exit__(self, *exc: object) -> None:
        with self.context._lock:
            self.context._running -= 1


def _single_status(result: StagingResult) -> int:
    if isinstance(result, GError):
        raise result
    return 1 if result else 0


def _list_error(result: StagingResult, url: str, pending: str | None) -> GError | None:
    """``None`` for done; the error, or ``EAGAIN`` worded as gfal2 does, otherwise."""
    if isinstance(result, GError):
        return result
    if not result and pending is not None:
        return GError(f"File {url} is not yet {pending}", errno.EAGAIN)
    return None


def _single_or_list(path: str | Sequence[str], results: list[GError | None]) -> Any:
    if isinstance(path, str):
        if results[0] is not None:
            raise results[0]
        return 0
    return results


def creat_context() -> Gfal2Context:
    """A new context with the default options and every available plugin."""
    return Gfal2Context()
