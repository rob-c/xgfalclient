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
non-ASCII bytes to ``%FF``; ``read(0)`` and ``write("")`` succeed;
``read``/``pread`` of bytes that are not UTF-8 return them surrogate-escaped
(gfal2 raises ``UnicodeDecodeError`` and the bytes are lost); and
``cancel()`` never waits for operations running on the calling thread (a
callback that cancels its own copy would deadlock gfal2), waits for the others
at most ``[CORE] CANCEL_TIMEOUT`` seconds (10; 0 waits as long as gfal2 does),
and wakes I/O blocked on a socket at once rather than when it next returns
(see :meth:`Gfal2Context.abort_on_cancel`); and a second ``free()`` does
nothing rather than raise.

Where to start reading: :meth:`Gfal2Context._find` (dispatch),
:meth:`Gfal2Context._guard` (the wrapper every plugin call goes through:
running-operation count, error translation, cancellation), then
:meth:`Gfal2Context.cancel`. The module tail wraps every bindings method in
:func:`_live` so a freed context refuses it; a new public method that
python3-gfal2 also has belongs in ``_API``.

Concurrency: one context may be used from many threads at once, as gfal2's
can. ``_lock`` guards the running-operation bookkeeping and client info;
``_load_lock`` serialises lazy plugin imports; ``self.plugins`` is replaced,
never mutated, so dispatch can iterate it without a lock.
"""

from __future__ import annotations

import errno
import functools
import itertools
import logging
import os
import socket
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Protocol, Self, TypeVar, cast

from . import plugins as _registry

# The open-file and open-directory handles, and the tape/QoS/token calls, are
# defined in private modules (see each one's docstring) and are this
# module's as much as ever: re-exported here, and on Gfal2Context itself.
from ._handles import DirectoryType as DirectoryType
from ._handles import FileType as FileType
from ._staging import StagingMixin, _non_empty
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
    DirEntry,
    Plugin,
    PluginFile,
)
from .transfer import TransferParameters, run_bulk, run_copy
from .types import Dirent, Stat
from .url import parent, scheme_of

if TYPE_CHECKING:
    import ssl

__all__ = ["DirectoryType", "FileType", "Gfal2Context", "creat_context"]

_log = logging.getLogger("gfal2")

#: The result type of the plugin method :meth:`Gfal2Context._guard` runs.
_T = TypeVar("_T")

#: What an operation refused, or cut short, by ``cancel()`` says (gfal2's words).
CANCELED_BY_USER = "[gfal2_cancel] operation canceled by user"

#: How long ``cancel()`` waits for running operations, unless ``[CORE]
#: CANCEL_TIMEOUT`` says otherwise. With blocked sockets shut down at once,
#: operations stop in milliseconds; this bounds the ones blocked somewhere no
#: plugin could register (a DNS lookup, a TCP connect).
CANCEL_TIMEOUT = 10

#: ``gfal2_cred_get``'s fallback when no prefix matches: the configured value.
_CONFIGURED_CREDENTIAL = {
    "X509_CERT": ("X509", "CERT"),
    "X509_KEY": ("X509", "KEY"),
    "BEARER": ("BEARER", "TOKEN"),
}


class Gfal2Context(StagingMixin):
    """A gfal2 context: options, credentials, and the loaded plugins.

    The tape (``bring_online`` and the rest), QoS and ``token_retrieve``
    methods are inherited from :class:`~xgfalclient._staging.StagingMixin`;
    everything else is defined here.

    python3-gfal2's ``gfal2.Gfal2Context`` (a ``gfal2_context_t`` and its
    ``gfal2_*`` calls). Each public method's docstring names the C call it
    stands for; return values are the bindings' (``0`` for success where the
    C call returns an int), never ``-1`` - failures raise ``GError``.
    """

    #: gfal2 defines its event enum and ``NullHandler`` inside the context
    #: class's scope, so they are attributes of the class too.
    event_side = event_side
    gfalt_event = GfaltEvent
    NullHandler = logging.NullHandler

    def __init__(self, *, options: Options | None = None, load_plugins: bool = True) -> None:
        """``gfal2_context_new``: options (the system configuration unless given), credentials.

        Plugins are not imported here: each built-in is loaded the first time
        a URL with one of its schemes is used, so ``creat_context()`` costs
        milliseconds however many protocols are installed. ``load_plugins=False``
        gives an empty context that tests fill with :meth:`add_plugin`.
        """
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
        #: Threads with a ``cancel()`` draining -> how many; see :meth:`_release_drained`.
        self._drains: dict[int, int] = {}
        #: What in-flight I/O is blocked on, by token; see :meth:`abort_on_cancel`.
        self._aborts: dict[int, object] = {}
        self._abort_tokens = itertools.count(1)
        #: Threads in :meth:`abort_exempt` -> how deep.
        self._exempt: dict[int, int] = {}
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
        """Load every third-party plugin (``xgfalclient.plugins`` entry points), once.

        Called with ``_load_lock`` held. The flag is cleared first so a
        plugin whose import fails is not retried on every call.
        """
        self._entry_points_pending = False
        for cls in _registry.entry_point_classes():
            self.add_plugin(cls)

    def _load_all(self) -> None:
        """Import every pending plugin; for calls that must see all of them."""
        self._load_for(*(scheme for entry in self._pending for scheme in entry.schemes))
        with self._load_lock:
            if self._entry_points_pending:
                self._load_entry_points()

    def get_plugin_names(self) -> list[str]:
        """``gfal2_get_plugin_names``: ``name-version`` of every plugin, in priority order.

        Forces every lazy plugin to load, since the answer must be complete.
        """
        self._load_all()
        return [plugin.label for plugin in self.plugins]

    def plugin(self, url: str, operation: str) -> Plugin:
        """The plugin that will perform ``operation`` on ``url``.

        Not in python3-gfal2; the core's streamed copy opens its destination
        through it, and tests use it to check dispatch. Raises gfal2's
        ``EPROTONOSUPPORT`` when nothing claims the URL, with a hint naming
        the missing optional package when there is one.
        """
        found = self._find(url, operation)
        if found is None:
            raise self._no_plugin(url)
        return found

    def _find(self, url: str, operation: str, checked: bool = True) -> Plugin | None:
        """The first plugin for ``operation`` on ``url``; ``checked`` applies gfal2's
        length limit, which its list forms apply to the first URL only."""
        if checked and len(url) >= _URL_MAX_LEN and operation in _LENGTH_CHECKED:
            raise GError("Invalid surl, surl too long or NULL", errno.EINVAL)
        self._load_for(_load_key(url))
        for candidate in self.plugins:
            if candidate.implements(operation) and candidate.handles(url, operation):
                return candidate
        return None

    def _no_plugin(self, url: str) -> GError:
        """gfal2's "Protocol not supported" error, plus an install hint where one helps."""
        error = not_supported_url(url)
        hint = _registry.missing_hint(scheme_of(url))
        if hint:
            error.message = f"{error.message} ({hint})"
            error.args = (error.message, error.code)
        return error

    def _copy_plugin(self, source: str, destination: str) -> Plugin | None:
        """The first plugin whose ``copy_check`` takes the pair, or None for the streamed copy.

        Both schemes' plugins are loaded first, since a third-party copy may
        be claimed by the destination's plugin (an HTTP pull) as well as the
        source's.
        """
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
            me = threading.get_ident()
            nested = self._running_by_thread.get(me, 0)
            # A call made from inside a running operation - a copy removing
            # the destination it wrote - is part of it, not a new one; the
            # drain is for operations that have not started.
            if self._cancelling and not nested:
                raise GError(CANCELED_BY_USER, errno.ECANCELED)
            self._running += 1
            self._running_by_thread[me] = nested + 1

    def _leave(self) -> None:
        """Count one operation finished; wake a ``cancel()`` waiting for the count to drop."""
        with self._lock:
            self._running -= 1
            me = threading.get_ident()
            left = self._running_by_thread.pop(me) - 1
            if left:
                self._running_by_thread[me] = left
            if self._cancelling:
                self._release_drained()
            self._idle.notify_all()

    def _release_drained(self) -> None:
        """End the ``cancel()`` calls whose wait is over, as the last operation leaves.

        gfal2's canceller clears its flag the moment the count reaches zero; left
        to the waiting thread (which needs the GIL back first), the thread whose
        operation was just cancelled would see its next call refused.
        """
        for thread, count in list(self._drains.items()):
            if self._running == self._running_by_thread.get(thread, 0):
                del self._drains[thread]
                self._cancelling -= count

    def _guard(self, method: Callable[..., _T], *args: Any) -> _T:
        """Run a plugin call, counting it as running and making every failure a ``GError``.

        A call that fails after a ``cancel()`` that began while it ran - its
        socket shut down under it, most likely - fails as cancelled
        (``ECANCELED``), whatever the broken connection made of it.
        """
        self._enter()
        generation = self._cancel_generation
        try:
            return method(*args)
        except StopIteration:
            raise
        except Exception as exc:
            error = _as_gerror(exc)
            if self._cancel_generation != generation and error.code != errno.ECANCELED:
                raise GError(CANCELED_BY_USER, errno.ECANCELED) from exc
            if error is exc:
                raise
            raise error from exc
        finally:
            self._leave()

    # -- cancellation of blocked I/O ------------------------------------------------

    def register_abort(self, resource: object) -> int:
        """Have ``cancel()`` abort ``resource`` until :meth:`unregister_abort`.

        ``resource`` is what an operation is blocked on: a socket (shut down
        both ways, which wakes a ``recv`` or ``send`` blocked on it in any
        thread at once; a TLS socket is shut down beneath its TLS layer), a
        callable taking no arguments (called), or anything with ``close()``
        (closed). The blocked call then fails, and the operation reports
        ``ECANCELED`` (see :meth:`_guard`, and :func:`~xgfalclient.transfer.run_copy`
        for copies).

        Registering while a ``cancel()`` is draining is refused with that
        ``ECANCELED`` straight away: a retry or reconnect after the abort must
        not block afresh. Answers the token :meth:`unregister_abort` takes.
        This, :meth:`unregister_abort` and :meth:`abort_on_cancel` are the
        hook for plugins, built in or not, that do their own I/O.
        """
        with self._lock:
            if threading.get_ident() in self._exempt:
                return 0  # never issued: unregistering it does nothing
            if self._cancelling:
                raise GError(CANCELED_BY_USER, errno.ECANCELED)
            token = next(self._abort_tokens)
            self._aborts[token] = resource
        return token

    def unregister_abort(self, token: int) -> None:
        """Forget a :meth:`register_abort`; an unknown or repeated token is fine."""
        with self._lock:
            self._aborts.pop(token, None)

    @contextmanager
    def abort_exempt(self) -> Iterator[None]:
        """Clean-up after a failed or cancelled operation: its I/O is not aborted.

        On this thread, inside the block, :meth:`register_abort` registers
        nothing and refuses nothing - so a copy cancelled mid-way can still
        remove the destination it wrote, while the ``cancel()`` that stopped
        it is draining. Such I/O is bounded by its own timeout instead.
        """
        me = threading.get_ident()
        with self._lock:
            self._exempt[me] = self._exempt.get(me, 0) + 1
        try:
            yield
        finally:
            with self._lock:
                left = self._exempt.pop(me) - 1
                if left:
                    self._exempt[me] = left

    @contextmanager
    def abort_on_cancel(self, resource: object) -> Iterator[None]:
        """:meth:`register_abort` ``resource`` for the duration of a ``with`` block."""
        token = self.register_abort(resource)
        try:
            yield
        finally:
            self.unregister_abort(token)

    def _dispatch(self, operation: str, url: str, *args: Any) -> Any:
        """Call ``operation`` on ``url``'s plugin through :meth:`_guard`; the common path."""
        plugin = self.plugin(url, operation)
        return self._guard(getattr(plugin, operation), url, *args)

    def _open(self, url: str, flags: int, size: int | None = None, mode: int = 0o744) -> PluginFile:
        """Open through the URL's plugin; ``mode`` for a file this creates is
        gfal2's (``gfal2_open`` passes 0744)."""
        plugin = self.plugin(url, "open")
        if size is None:
            return self._guard(plugin.open, url, flags, mode)
        return self._guard(plugin.open, url, flags, mode, size)

    def _opendir(self, url: str) -> Iterator[DirEntry]:
        """The plugin's ``opendir`` entries, or its ``listdir`` names with no stat.

        The fallback is gfal2's core filling the gap: a plugin that can only
        list names still supports ``opendir``/``readdir`` (with ``DT_UNKNOWN``).
        """
        plugin = self._find(url, "opendir")
        if plugin is not None:
            return self._guard(plugin.opendir, url)
        names = self._dispatch("listdir", url)
        return iter([(name, None) for name in names])

    # -- credentials helpers for plugins ------------------------------------------

    def x509(self, url: str = "") -> X509Credential | None:
        """The certificate and key to present to ``url``; see :func:`~.creds.find_x509`.

        Searched afresh on every call (cheap, and an environment change after
        the context was made still counts), not cached here.
        """
        return find_x509(self.options, self.credentials, url)

    def bearer_token(self, url: str = "") -> str | None:
        """The bearer token for ``url``, if any; see :func:`~.creds.find_bearer_token`.

        Raises ``EACCES`` for a token file that exists but is unsafe to read,
        rather than falling through to another identity.
        """
        return find_bearer_token(self.options, self.credentials, url)

    def ca_path(self) -> str | None:
        """The grid CA directory (``$X509_CERT_DIR``, then the usual places), or None."""
        return find_ca_path()

    def ssl_context(
        self,
        url: str = "",
        *,
        group: str = "",
        check_hostname: bool = True,
        alpn: tuple[str, ...] = (),
        x509: bool = True,
    ) -> ssl.SSLContext:
        """The TLS client context for ``url``: its X.509 credential (unless
        ``x509=False``), the grid CAs, and ``[group] INSECURE`` honoured."""
        insecure = self.options.boolean(group, "INSECURE", False) if group else False
        return self.tls.get(
            self.x509(url) if x509 else None,
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
        """``gfal2_access``: ``0``, or what the plugin answers (gfal2's mock answers 1).

        ``mode`` is ``os.F_OK``/``R_OK``/``W_OK``/``X_OK``. For a plugin with
        no ``access``, a successful ``stat`` stands for ``F_OK`` whatever
        ``mode`` asked (gfal2 would refuse with ``EPROTONOSUPPORT``).
        """
        plugin = self._find(path, "access")
        if plugin is None:
            self._dispatch("stat", path)
            return 0
        answer = self._guard(plugin.access, path, mode)
        return answer if isinstance(answer, int) else 0

    def chmod(self, path: str, mode: int) -> int:
        """``gfal2_chmod``; ``mode`` must fit an unsigned 32-bit ``mode_t``."""
        self._dispatch("chmod", path, _mode_t(mode))
        return 0

    def rename(self, old: str, new: str) -> int:
        """``gfal2_rename``; both URLs must belong to the same plugin.

        A rename is a namespace operation on one storage, so a cross-plugin
        pair (``file://`` to ``root://``) is ``EPROTONOSUPPORT`` here; gfal2
        returns success without doing anything, which hides the mistake.
        """
        plugin = self.plugin(old, "rename")
        if self._find(new, "rename") is not plugin:
            raise not_supported_url(new)
        self._guard(plugin.rename, old, new)
        return 0

    def stat(self, path: str) -> Stat:
        """``gfal2_stat``: the entry's :class:`~xgfalclient.types.Stat`, links followed."""
        return self._guard(self.plugin(path, "stat").stat, path)

    def lstat(self, path: str) -> Stat:
        """``gfal2_lstat``; a plugin with no notion of links answers its ``stat``, as in gfal2."""
        if self._find(path, "lstat") is not None:
            return self._guard(self.plugin(path, "lstat").lstat, path)
        return self.stat(path)

    def mkdir(self, path: str, mode: int = 0o755) -> int:
        """``gfal2_mkdir``: one directory; ``EEXIST`` if something is already there."""
        self._dispatch("mkdir", path, _mode_t(mode))
        return 0

    def mkdir_rec(self, path: str, mode: int = 0o755) -> int:
        """``gfal2_mkdir_rec`` (``mkdir -p``): an existing ``path`` is success.

        A plugin that can create parents in one request (``mkdir_rec``) is
        used; otherwise the core climbs with single ``mkdir`` calls, as
        gfal2's core does.
        """
        mode = _mode_t(mode)
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
        for url in reversed(self._missing_ancestry(path, mode)):
            try:
                self.mkdir(url, mode)
            except GError as exc:
                if exc.code != errno.EEXIST:  # made by someone else meanwhile
                    raise

    def _missing_ancestry(self, path: str, mode: int) -> list[str]:
        """``mkdir`` ``path``, then each parent, until one is made or exists.

        The answer is the directories found missing (``ENOENT``), deepest
        first, for the caller to make from the top down.
        """
        missing: list[str] = []
        current = path
        while not self._mkdir_unless_missing(current, mode):
            missing.append(current)
            up = parent(current)
            if up == current:
                break  # even the root is missing; creating it again reports why
            current = up
        return missing

    def _mkdir_unless_missing(self, url: str, mode: int) -> bool:
        """``mkdir`` ``url``: True if made or already there, False if its parent is missing."""
        try:
            self.mkdir(url, mode)
        except GError as exc:
            if exc.code == errno.EEXIST:
                return True
            if exc.code != errno.ENOENT:
                raise
            return False
        return True

    def rmdir(self, path: str) -> int:
        """``gfal2_rmdir``: an empty directory (``ENOTEMPTY`` otherwise, from the plugin)."""
        self._dispatch("rmdir", path)
        return 0

    def listdir(self, path: str) -> list[str]:
        """The bindings' ``listdir``: entry names, from ``listdir`` or else ``opendir``.

        The order is the server's (or ``readdir``'s), not sorted.
        """
        plugin = self._find(path, "listdir")
        if plugin is not None:
            return self._guard(plugin.listdir, path)
        return [entry[0] for entry in self._opendir(path)]

    def opendir(self, path: str) -> DirectoryType:
        """``gfal2_opendir``: a handle whose ``read``/``readpp`` step through the entries."""
        return DirectoryType(self, path)

    directory = opendir

    def open(self, path: str, flag: str) -> FileType:
        """``gfal2_open`` with the bindings' flags: ``"r"``, ``"w"`` (create, truncate), ``"rw"``.

        The file is opened before this returns, so a missing file or a
        refused write fails here rather than at the first read.
        """
        return FileType(self, path, flag)

    file = open

    def readlink(self, path: str) -> str:
        """``gfal2_readlink``: the link's target, as stored (not resolved)."""
        return self._guard(self.plugin(path, "readlink").readlink, path)

    def symlink(self, target: str, link: str) -> int:
        """``gfal2_symlink``: create ``link`` pointing at ``target`` (the order of ``ln -s``)."""
        plugin = self._find(link, "symlink")
        if plugin is None:
            # gfal2 looks the target up first, so its refusal names the target
            # unless that one could have been linked.
            raise self._no_plugin(link if self._find(target, "symlink") else target)
        self._guard(plugin.symlink, target, link)
        return 0

    def unlink(self, path: str | Sequence[str]) -> int | list[GError | None]:
        """``gfal2_unlink``, or with a list ``gfal2_unlink_list``: one result per URL.

        The list form never raises for a single URL's failure: each slot is
        ``None`` or that URL's ``GError``. If the first URL's plugin has a
        bulk delete (SRM's ``srmRm`` takes many SURLs) it gets the whole
        list; otherwise each URL goes to its own plugin.
        """
        if isinstance(path, str):
            self._dispatch("unlink", path)
            return 0
        paths = _non_empty(path)
        try:
            bulk = self._find(paths[0], "unlink_bulk")
        except GError as exc:
            return [exc] * len(paths)
        if bulk is not None:
            return self._guard(bulk.unlink_bulk, paths)
        results: list[GError | None] = []
        for item in paths:
            try:
                plugin = self._find(item, "unlink", checked=False)
                if plugin is None:
                    raise self._no_plugin(item)
                self._guard(plugin.unlink, item)
                results.append(None)
            except GError as exc:
                results.append(exc)
        return results

    # -- metadata -------------------------------------------------------------------

    def getxattr(self, path: str, name: str) -> str:
        """The attribute; for ``user.checksum.<alg>`` a failed lookup falls back to
        :meth:`checksum`, as gfal2's core does."""
        try:
            return self._guard(self.plugin(path, "getxattr").getxattr, path, name)
        except GError:
            if not name.startswith(_CHECKSUM_XATTR):
                raise
        return self.checksum(path, name[len(_CHECKSUM_XATTR) :])

    def setxattr(self, path: str, name: str, value: str, flags: int = 0) -> int:
        """``gfal2_setxattr``; ``flags`` is ``XATTR_CREATE``/``XATTR_REPLACE`` or 0."""
        self._dispatch("setxattr", path, name, value, flags)
        return 0

    def listxattr(self, path: str) -> list[str]:
        """``gfal2_listxattr``: the attribute names the plugin offers for ``path``."""
        return self._guard(self.plugin(path, "listxattr").listxattr, path)

    def checksum(self, path: str, algorithm: str, offset: int = 0, length: int = 0) -> str:
        """``gfal2_checksum``: the hex checksum of the whole file (``offset == length == 0``).

        With ``[CORE] FORMAT_ADLER32_CHECKSUM`` (on by default) an ADLER32 is
        zero-padded to eight digits, because servers disagree on whether to
        pad and an unpadded value would fail a string comparison.
        """
        value = self._guard(self.plugin(path, "checksum").checksum, path, algorithm, offset, length)
        if algorithm.strip().lower() == "adler32" and self.options.boolean(
            "CORE", "FORMAT_ADLER32_CHECKSUM", True
        ):
            from .checksum import format_adler32

            value = format_adler32(value)
        return value

    # -- tape, QoS, tokens: inherited from StagingMixin (xgfalclient/_staging.py) --

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
        """A context manager counting a whole copy as one running operation."""
        return _Running(self)

    # -- options ----------------------------------------------------------------------

    # Each ``*_opt_*`` method is the ``gfal2_*_opt_*`` call of the same name;
    # the semantics (GLib parsing, error codes) live in :mod:`.options`.
    # Changes apply to this context only, from its next operation on.

    def get_opt_string(self, group: str, key: str) -> str:
        """``gfal2_get_opt_string``: the raw value; ``GError`` 3/4 if the key/group is missing."""
        return self.options.get_string(group, key)

    def get_opt_integer(self, group: str, key: str) -> int:
        """``gfal2_get_opt_integer``; ``GError`` 5 for a value that is not a C ``int``."""
        return self.options.get_integer(group, key)

    def get_opt_boolean(self, group: str, key: str) -> bool:
        """``gfal2_get_opt_boolean``: ``true``/``false``/``1``/``0`` only."""
        return self.options.get_boolean(group, key)

    def get_opt_string_list(self, group: str, key: str) -> list[str]:
        """``gfal2_get_opt_string_list``: the value split on ``;``."""
        return self.options.get_string_list(group, key)

    def set_opt_string(self, group: str, key: str, value: str) -> int:
        """``gfal2_set_opt_string``."""
        self.options.set_string(group, key, value)
        return 0

    def set_opt_integer(self, group: str, key: str, value: int) -> int:
        """``gfal2_set_opt_integer``; outside the C ``int`` range is ``OverflowError``."""
        self.options.set_integer(group, key, value)
        return 0

    def set_opt_boolean(self, group: str, key: str, value: bool) -> int:
        """``gfal2_set_opt_boolean``."""
        self.options.set_boolean(group, key, value)
        return 0

    def set_opt_string_list(self, group: str, key: str, values: Sequence[str]) -> int:
        """``gfal2_set_opt_string_list``."""
        self.options.set_string_list(group, key, values)
        return 0

    def remove_opt(self, group: str, key: str) -> bool:
        """``gfal2_remove_opt``: True, or ``GError`` if the key was not set."""
        return self.options.remove(group, key)

    def load_opts_from_file(self, path: str) -> int:
        """``gfal2_load_opts_from_file``: merge one key file over the current options."""
        self.options.load_file(path)
        return 0

    # -- credentials -------------------------------------------------------------------

    #: As in gfal2, the ``Credential`` class itself.
    cred_new = Credential

    def cred_set(self, prefix: str, credential: Credential) -> int:
        """``gfal2_cred_set``: use ``credential`` for every URL starting with ``prefix``.

        Cached TLS contexts are dropped, so the next context built presents
        the new credential.
        """
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
        """``gfal2_cred_clean``: forget every credential set with :meth:`cred_set`."""
        self.credentials.clean()
        self.tls.clear()
        return 0

    # -- client identity ------------------------------------------------------------------

    def set_user_agent(self, name: str, version: str) -> int:
        """``gfal2_set_user_agent``: sent by the protocols that carry one (HTTP, SRM)."""
        self._user_agent = (name, version)
        return 0

    def get_user_agent(self) -> tuple[str | None, str | None]:
        """``gfal2_get_user_agent``: ``(name, version)``, both None until set."""
        return self._user_agent

    def add_client_info(self, key: str, value: str) -> int:
        """Set ``key``; a key set again moves to the end, as in gfal2."""
        with self._lock:
            self._remove_client_info(key)
            self._client_info.append((key, value))
        return 0

    def remove_client_info(self, key: str) -> int:
        """``gfal2_remove_client_info``; ``EINVAL`` for a key that was not set, as gfal2."""
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
        """``gfal2_clear_client_info``."""
        with self._lock:
            self._client_info = []
        return 0

    def get_client_info(self) -> dict[str, str]:
        """The bindings' ``get_client_info``: a dict (insertion order is the header's)."""
        return dict(self._client_info)

    # -- lifecycle ----------------------------------------------------------------------

    def cancel(self) -> int:
        """Cancel what is in flight and wait for it to stop, as ``gfal2_cancel`` does.

        Answers how many operations were running. Copies notice between
        chunks, and I/O blocked on a registered socket (see
        :meth:`register_abort`) is woken at once; an operation starting
        meanwhile fails with ``ECANCELED``. Operations running on the calling
        thread (a callback cancelling its own copy) are not waited for, and
        the others for at most ``[CORE] CANCEL_TIMEOUT`` seconds (0: without
        limit, as gfal2): an operation stuck somewhere nothing can wake it
        still fails with ``ECANCELED`` when it returns.
        """
        limit = self.options.integer("CORE", "CANCEL_TIMEOUT", CANCEL_TIMEOUT)
        deadline = time.monotonic() + limit if limit > 0 else None
        me = threading.get_ident()
        with self._lock:
            self._cancel_generation += 1
            running = self._running
            self._drains[me] = self._drains.get(me, 0) + 1
            self._cancelling += 1
            # Taken after ``_cancelling`` is set: anything registering from
            # now on is refused, so nothing escapes between this and the aborts.
            doomed = list(self._aborts.values())
        try:
            for resource in doomed:
                _abort(resource)
            with self._lock:
                drained = self._idle.wait_for(
                    lambda: (
                        me not in self._drains
                        or self._running == self._running_by_thread.get(me, 0)
                    ),
                    None if deadline is None else max(0.0, deadline - time.monotonic()),
                )
                if not drained:
                    _log.warning(
                        "cancel: %d operation(s) still running after %d s; not waiting longer",
                        self._running - self._running_by_thread.get(me, 0),
                        limit,
                    )
        finally:
            with self._lock:
                self._cancelling -= self._drains.pop(me, 0)
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

    def __enter__(self) -> Self:
        """The context itself; ``with creat_context() as ctx:`` frees it at the end."""
        return self

    def __exit__(self, *exc: object) -> None:
        """:meth:`free`, whatever ended the block (an extension: the bindings have no ``with``)."""
        self.free()

    def __repr__(self) -> str:
        """Loaded plugin labels and how many built-ins have not been needed yet."""
        loaded = [plugin.label for plugin in self.plugins]
        return f"<xgfalclient.Gfal2Context plugins={loaded} pending={len(self._pending)}>"


# gfal2 exposes its record types as attributes of the context class too.
# Set after the class body: inside it, the names would shadow the types the
# method annotations use.
for _alias in (Credential, DirectoryType, Dirent, FileType, GfaltEvent, Stat, TransferParameters):
    setattr(Gfal2Context, _alias.__name__, _alias)


def _freed() -> GError:
    """The bindings' error for any call on a freed context."""
    return GError("gfal2 context has been freed", errno.EFAULT)


def _as_gerror(exc: Exception) -> GError:
    """Any failure from a plugin as the ``GError`` gfal2 would have raised.

    ``ValueError`` (a malformed reply, typically) is ``EINVAL``; any other
    stray exception is ``EIO`` with its text, or its class name when it has
    none, so the message is never empty. ``KeyboardInterrupt`` and the other
    ``BaseException`` subclasses are not caught by the caller and pass through.
    """
    if isinstance(exc, GError):
        return exc
    if isinstance(exc, OSError):
        # gfal2's file plugin words a local failure; so does any errno here.
        if exc.errno is not None:
            return from_oserror(exc)
        return GError(str(exc), errno.EIO)
    code = errno.EINVAL if isinstance(exc, ValueError) else errno.EIO
    return GError(str(exc) or type(exc).__name__, code)


class _Closeable(Protocol):
    """What :func:`_abort` closes when it is neither a socket nor a callable."""

    def close(self) -> object:
        """Release the resource."""
        ...


def _abort(resource: object) -> None:
    """Wake whatever is blocked on ``resource``; see :meth:`Gfal2Context.register_abort`.

    A socket is shut down with :meth:`socket.socket.shutdown` called on the
    plain socket even for TLS - ``SSLSocket.shutdown`` would tear the TLS
    state down under the thread still reading it. Shutdown, not close: on
    Linux closing a descriptor does not wake a ``recv`` blocked on it, and
    the owner still closes it as it always does. A resource already gone
    (``ENOTCONN``, ``EBADF``) or failing to close is past waking anyway.
    """
    try:
        if isinstance(resource, socket.socket):
            socket.socket.shutdown(resource, socket.SHUT_RDWR)
        elif callable(resource):
            cast("Callable[[], object]", resource)()
        else:
            cast("_Closeable", resource).close()
    except Exception as exc:
        _log.debug("cancel: could not abort %r: %s", resource, exc)


def _live(method: Any) -> Any:
    """Refuse the call once the context is freed, as every bindings method does.

    A ``bytes`` argument is taken as the string it spells, as Boost.Python
    converts one for every ``std::string`` parameter (``ctx.stat(b"file:///f")``).
    """

    @functools.wraps(method)
    def call(self: Gfal2Context, *args: Any, **kwargs: Any) -> Any:
        """``method``, refused on a freed context and with ``bytes`` arguments decoded."""
        if self._freed:
            raise _freed()
        return method(self, *map(_text, args), **kwargs)

    return call


def _text(value: Any) -> Any:
    """``bytes`` as ``str`` (``os.fsdecode``, so undecodable bytes survive); anything else as is."""
    return os.fsdecode(value) if isinstance(value, bytes) else value


#: The bindings' methods; each raises ``EFAULT`` on a freed context.
_API = (
    "cancel",
    "open",
    "file",
    "opendir",
    "directory",
    "access",
    "lstat",
    "stat",
    "chmod",
    "unlink",
    "mkdir",
    "mkdir_rec",
    "rmdir",
    "listdir",
    "rename",
    "readlink",
    "symlink",
    "checksum",
    "getxattr",
    "setxattr",
    "listxattr",
    "remove_opt",
    "get_opt_integer",
    "get_opt_boolean",
    "get_opt_string",
    "get_opt_string_list",
    "set_opt_string_list",
    "set_opt_string",
    "set_opt_boolean",
    "set_opt_integer",
    "load_opts_from_file",
    "set_user_agent",
    "get_user_agent",
    "add_client_info",
    "remove_client_info",
    "clear_client_info",
    "get_client_info",
    "filecopy",
    "bring_online",
    "bring_online_poll",
    "archive_poll",
    "release",
    "abort_bring_online",
    "get_plugin_names",
    "qos_check_classes",
    "check_file_qos",
    "check_available_qos_transitions",
    "check_target_qos",
    "change_object_qos",
    "token_retrieve",
    "cred_set",
    "cred_get",
    "cred_del",
    "cred_clean",
)
for _name in _API:
    setattr(Gfal2Context, _name, _live(getattr(Gfal2Context, _name)))


class _Running:
    """Counts a whole copy as one running operation, for ``cancel()``.

    The plugin calls inside a copy are nested in it (see :meth:`Gfal2Context._enter`),
    so a ``cancel()`` waits for the copy as a whole and the copy's own
    clean-up calls are not refused mid-way.
    """

    def __init__(self, context: Gfal2Context) -> None:
        """Bind to ``context``; nothing is counted until ``__enter__``."""
        self.context = context

    def __enter__(self) -> None:
        """Count the copy as running; ``ECANCELED`` if a ``cancel()`` is draining."""
        self.context._enter()

    def __exit__(self, *exc: object) -> None:
        """Count it finished, however it ended."""
        self.context._leave()


def _load_key(url: str) -> str:
    """The scheme a lazily loaded plugin is filed under.

    ``scheme_of`` wants ``scheme://``; gfal2's mock plugin also takes
    ``mock:anything``, so a bare ``scheme:`` prefix names a plugin to load too.
    """
    return scheme_of(url) or url.partition(":")[0].lower()


def _mode_t(mode: int) -> int:
    """A ``mode_t`` argument, refused as Boost.Python refuses it outside 32 bits.

    Without this ``chmod(url, -1)`` reached ``os.chmod`` and set 7777.
    """
    if mode < 0:
        raise OverflowError("can't convert negative value to unsigned int")
    if mode >> 32:
        raise OverflowError("bad numeric conversion: positive overflow")
    return mode


#: gfal2's plugin lookup refuses a URL of ``GFAL_URL_MAX_LEN`` (2048) bytes or
#: more with ``EINVAL`` for these operations; readlink, setxattr, symlink,
#: token_retrieve and the QoS calls find their plugin another way, unchecked.
_URL_MAX_LEN = 2048
_LENGTH_CHECKED = frozenset(
    (
        "access",
        "stat",
        "lstat",
        "chmod",
        "rename",
        "mkdir",
        "mkdir_rec",
        "rmdir",
        "listdir",
        "opendir",
        "open",
        "unlink",
        "unlink_bulk",
        "getxattr",
        "listxattr",
        "checksum",
        "bring_online",
        "bring_online_poll",
        "release",
        "abort_bring_online",
        "archive_poll",
    )
)

#: The attribute prefix gfal2's core answers with a checksum when a plugin cannot
#: (``getxattr(url, "user.checksum.adler32")``).
_CHECKSUM_XATTR = "user.checksum."


def _urlencode(text: str) -> str:
    """``gfal2_urlencode``: every byte but ``[A-Za-z0-9._-]`` as ``%XX``.

    ``quote`` keeps ``~`` unescaped (RFC 3986 unreserved); gfal2 escapes it,
    hence the replace.
    """
    return urllib.parse.quote(text, safe="", encoding="utf-8", errors="surrogateescape").replace(
        "~", "%7E"
    )


def creat_context() -> Gfal2Context:
    """A new context with the default options and every available plugin.

    python3-gfal2's ``gfal2.creat_context()`` (the spelling is gfal2's).
    Each call makes an independent context; nothing is shared between them
    but imported modules.
    """
    return Gfal2Context()
