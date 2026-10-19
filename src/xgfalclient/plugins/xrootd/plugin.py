"""The ``xrootd`` plugin: gfal2's calls, each a few lines over xrdclient.

:class:`XRootDPlugin` holds what the calls share - the xrdclient settings
for a URL (:meth:`~XRootDPlugin._config`), the URL as xrdclient's endpoint
and decoded path (:meth:`~XRootDPlugin._target`), and the idle filesystems
kept between calls (:meth:`~XRootDPlugin._fs`) - and words every failure as
the gfal2 call it stands for would (:mod:`.errors`). Copies are
:class:`~.copy.CopyJob`'s and staging :mod:`.tape`'s; this module only
hands them over.

The filesystems are this plugin's own pool rather than xrdclient's, for
speed: a ``stat`` on a kept filesystem is one round trip and nothing else,
where a fresh one builds a router and digests the credentials on its way
through xrdclient's pool. A filesystem is checked out to one call at a time,
which is also what lets ``cancel()`` abort exactly that call's connection
(see :mod:`.file`).

Where to start reading: :meth:`XRootDPlugin._fs` (how a call gets its
filesystem), then any namespace method - each is the gfal2
``gfal_xrootd_*`` function of the same name, with the ``XrdPosix`` call it
makes replaced by the :class:`xrdclient.FileSystem` one that sends the same
request. What must not break: every failure leaves through
:func:`~.errors.posix_error`, :func:`~.errors.status_error` or a ready
:class:`~xgfalclient.GError`, never as a raw xrdclient exception, because
scripts match gfal2's wording and ``errno``; and a filesystem a
``cancel()`` aborted is never put back for another call.
"""

from __future__ import annotations

import errno
import os
import stat as _stat
import threading
import time
import urllib.parse
import weakref
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, TypeVar

import xrdclient
from xrdclient import errors as xe

from ...errors import GError
from ...plugin import O_ACCMODE_MASK, O_CREAT, O_EXCL, O_TRUNC, Plugin, PluginFile, StagingResult
from ...types import Stat
from .. import xrootd as package
from . import tape
from .copy import CopyJob, job_url
from .errors import ENOATTR, describe, posix_error, status_error, vendor_error
from .file import Abort, XRootDFile, aborting
from .stat import (
    checksum_name,
    checksum_value,
    entries,
    flags_to_mode,
    is_dir,
    posix_stat,
    reduced,
    rmdir_errno,
    space_json,
    status_word,
)
from .urls import SCHEMES, is_root

if TYPE_CHECKING:
    from xrdclient import Config, FileSystem, XRootDURL

    from ...creds import X509Credential
    from ...transfer import Transfer

T = TypeVar("T")

#: gfal2's event domain for this plugin (``g_quark_from_static_string("xroot")``).
DOMAIN = "xroot"

#: The attribute names gfal2's ``listxattr`` makes up, in its order.
XATTRS = ["xroot.cksum", "xroot.space", "xroot.xattr", "spacetoken"]
#: gfal2 ``xroot.*`` attribute to ``kXR_query`` code (``XrdPosixXrootd::Getxattr``):
#: ``kXR_Qcksum`` (3), ``kXR_Qspace`` (5) and ``kXR_Qxattr`` (4). The answer is
#: handed back as the server sent it, up to its first NUL.
_XATTR_QUERY = {"xroot.cksum": 3, "xroot.space": 5, "xroot.xattr": 4}

#: ``kXR_open`` options, spelled out so an open is one integer: ``kXR_open_read``,
#: ``kXR_open_updt``, ``kXR_new`` (fail if it exists), ``kXR_delete`` (create
#: or truncate) and ``kXR_mkpath`` (make missing parents), as ``XProtocol.hh``
#: numbers them.
_READ, _UPDATE, _NEW, _DELETE, _MKPATH = 0x0010, 0x0020, 0x0008, 0x0002, 0x0100

#: Idle filesystems by (endpoint, config), each with when it was put back.
#: The config is keyed by identity: :meth:`XRootDPlugin._config` hands out one
#: object per distinct set of settings, so equal settings share a pool entry
#: and a changed credential or timeout never reuses another's login.
Idle = dict[tuple[str, int], list[tuple[float, "FileSystem"]]]


class XRootDPlugin(Plugin):
    """The ``xrootd`` plugin: ``root``, ``roots``, ``xroot`` and ``xroots`` URLs.

    One instance per :class:`~xgfalclient.Gfal2Context`, shared by every
    thread using that context; the caches and the idle pool are guarded by
    one lock, held only for dictionary work, never across a request.
    """

    name = "xrootd"
    schemes = SCHEMES
    option_group = "XROOTD PLUGIN"
    priority = 400
    event_domain = DOMAIN
    # gfal2 hands a copy to XrdCl whole: see copy().
    narrates_transfer = True
    copy_manages_destination = True
    copy_manages_checksums = True

    def __init__(self, context: Any) -> None:
        """Empty caches; nothing is connected until the first call needs a server."""
        super().__init__(context)
        self._lock = threading.Lock()
        self._configs: dict[tuple[object, ...], Config] = {}
        self._targets: dict[tuple[object, ...], tuple[XRootDURL, str]] = {}
        #: Never replaced, only emptied: :func:`_close_idle` holds it.
        self._idle: Idle = {}
        #: The process the idle filesystems belong to; see :meth:`_checkout`.
        self._pid = os.getpid()
        # A context is a cycle (it holds its plugins, they hold it), so one
        # that is dropped is freed by the cycle collector. xrdclient (0.4)
        # copes with a Router collected unclosed - its weakref.finalize queues
        # the connection for the next pool operation or a reaper thread,
        # never touching it from inside the collector - but that is a
        # fallback with a delay. Held from here, the idle filesystems are
        # never part of that garbage: they are closed properly, and their
        # sessions handed back to the pool, as soon as the plugin goes.
        weakref.finalize(self, _close_idle, self._idle, self._lock)

    def close(self) -> None:
        """Forget cached settings and close the idle filesystems."""
        with self._lock:
            self._configs.clear()
            self._targets.clear()
        _close_idle(self._idle, self._lock)

    # -- configuration -------------------------------------------------------------

    def _config(self, url: str, timeout: float | None = None) -> Config:
        """The xrdclient settings for ``url``: this context's credentials and options.

        Built once per distinct set of inputs. ``prompt`` is always off: a
        library call has nobody to ask. An X.509 credential goes as it is:
        a proxy as the proxy, a separate certificate and key as
        ``usercert``/``userkey``, from which xrdclient makes what each
        protocol needs in memory - the key is never copied to disk. Every
        credential field is set, so the environment (``$X509_USER_PROXY``
        above all, which would otherwise win) has no say over what the
        context chose.
        """
        cred = self.context.x509(url)
        token = self.context.bearer_token(url)
        insecure = self.options.boolean(self.option_group, "INSECURE", False)
        wanted = self.options.string(self.option_group, "XRD.WANTPROT", "")
        request = float(timeout if timeout else self.option_timeout())
        ca_path = self.context.ca_path()
        # xrdclient reads it into Config.gsi_delegate, as XrdCl does at login;
        # gfal-copy exports it. Part of the key, so a change is picked up.
        delegate = os.environ.get("XrdSecGSIDELEGPROXY", "")  # noqa: SIM112 - XRootD spells it so
        key = (cred, token, insecure, wanted, request, ca_path, delegate)
        with self._lock:
            found = self._configs.get(key)
        if found is not None:
            return found
        changes: dict[str, Any] = {
            "prompt": False,
            **_x509(cred),
            "token": token,
            "token_file": None,
            "ca_path": ca_path,
            "verify_tls": not insecure,
            "request_timeout": request,
            # A bound data sub-stream stalls writes against a stock xrootd
            # 5.9, so everything stays on the control link; downloads have
            # their own connections on the bulk plane regardless.
            "data_streams": 0,
        }
        order = tuple(part for part in wanted.replace(";", ",").split(",") if part.strip())
        if order:
            changes["auth_order"] = tuple(part.strip() for part in order)
        config: Config = xrdclient.Config(**changes)
        with self._lock:
            self._configs[key] = config
        return config

    def _extra_cgi(self) -> dict[str, str]:
        """``[XROOTD PLUGIN] XRD.*`` options, as gfal2 appends them to every URL."""
        extra: dict[str, str] = {}
        try:
            keys = self.options.keys(self.option_group)
        except GError:  # no such group: nothing configured
            return extra
        for key in keys:
            if key.startswith("XRD."):
                # gfal2 lowers the name (XRD.WANTPROT -> xrd.wantprot) and turns
                # GKeyFile's ";" list separator into the "," XRootD expects.
                value = self.options.string(self.option_group, key, "")
                extra[key.lower()] = value.replace(";", ",")
        return extra

    def _target(self, url: str, **extra: str) -> tuple[XRootDURL, str]:
        """``url`` as xrdclient's URL of the endpoint, and the decoded path.

        gfal2's ``prepare_url``: the path is URL-decoded (XRootD wants it
        raw) and the ``XRD.*`` options join whatever CGI the URL carried.
        The CGI stays on the endpoint so that every request made through it
        carries it, which is how an ``authz=`` token reaches the server.

        Remembered per URL and options, since a loop of ``stat`` asks for
        the same few again and again (the answer is immutable).
        """
        options = self._extra_cgi()
        key = (url, tuple(options.items()), tuple(extra.items()))
        found = self._targets.get(key)
        if found is not None:
            return found
        parsed = xrdclient.parse(url)
        query = dict(parsed.query)
        query.update(options)
        query.update(extra)
        path = urllib.parse.unquote(parsed.path)
        found = parsed.evolve(path="/", query=query), path
        with self._lock:
            if len(self._targets) >= package.TARGET_CACHE:
                self._targets.clear()
            self._targets[key] = found
        return found

    def _file_url(self, url: str, **extra: str) -> XRootDURL:
        """``url`` as one xrdclient URL for a :class:`~xrdclient.File`: endpoint, path and CGI."""
        base, path = self._target(url, **extra)
        return base.with_path(path)

    def _copy_url(self, url: str, spacetoken: str) -> XRootDURL:
        """A copy's URL: gfal2 names the space token as ``svcClass``."""
        return self._file_url(url, **({"svcClass": spacetoken} if spacetoken else {}))

    def _job_url(self, url: str, spacetoken: str) -> str:
        """``url`` as XrdCl's copy job prints it; see :func:`~.copy.job_url`."""
        return job_url(url, spacetoken, self._extra_cgi() if is_root(url) else {})

    # -- the filesystems kept between calls ----------------------------------------

    @contextmanager
    def _fs(self, url: str, timeout: float | None = None) -> Iterator[tuple[FileSystem, str]]:
        """A filesystem on ``url``'s endpoint, kept for the next call when it worked.

        gfal2 keeps its connections in XrdCl's post master; here the
        filesystems stay open between calls, so a ``stat`` is one round trip
        and nothing else - no router to build, no trip through xrdclient's
        pool (which digests the credentials twice per use). One that failed
        other than by the server's answer is closed instead, which hands its
        connection to that pool, and the pool will not take a broken one.
        Nothing is kept where pooling is off (``XRD_POOLSIZE=0``), and
        nothing a ``cancel()`` aborted.
        """
        base, path = self._target(url)
        config = self._config(url, timeout)
        # The CGI is part of the key (str(base) keeps it): a filesystem's
        # CGI rides on every request it makes, so one opened with another
        # URL's ``authz=`` must not serve this one.
        key = (str(base), id(config)) if config.pool_size > 0 else None
        fs = self._checkout(key, config.pool_idle_ttl)
        if fs is None:
            fs = xrdclient.FileSystem(base, config)
        abort = Abort(fs)
        failure: BaseException | None = None
        try:
            with aborting(self.context, abort):
                yield fs, path
        except BaseException as exc:
            failure = exc
            raise
        finally:
            # The server's answer, or one of ours: the connection is fine -
            # unless a cancel() cut it.
            answered = failure is None or isinstance(failure, (GError, xe.ServerError))
            if answered and not abort.fired:
                self._checkin(key, fs)
            else:
                fs.close()

    def _checkout(self, key: tuple[str, int] | None, ttl: float) -> FileSystem | None:
        """The most recently kept filesystem for ``key`` still within ``ttl``, or ``None``.

        Most recent first (``pop`` from the end), so a burst of calls keeps
        reusing the warmest connection and the older ones age out. Those
        idle longer than ``ttl`` - xrdclient's ``pool_idle_ttl``, the time a
        server is likely to have kept its side open - are closed, outside
        the lock, since a close may write to the socket.
        """
        if key is None:
            return None
        now = time.monotonic()
        stale: list[FileSystem] = []
        found = None
        with self._lock:
            if self._pid != os.getpid():
                # A forked child must not touch its parent's sockets: forget
                # them without closing, as xrdclient's own pool does.
                self._idle.clear()
                self._pid = os.getpid()
            kept = self._idle.get(key)
            while kept:
                when, fs = kept.pop()
                if now - when <= ttl:
                    found = fs
                    break
                stale.append(fs)
        for fs in stale:
            fs.close()
        return found

    def _checkin(self, key: tuple[str, int] | None, fs: FileSystem) -> None:
        """Keep ``fs`` for the next call on its endpoint, or close it if there is no room.

        Bounded twice - :data:`~xgfalclient.plugins.xrootd.IDLE_ENDPOINTS`
        endpoints and :data:`~xgfalclient.plugins.xrootd.IDLE_PER_ENDPOINT`
        filesystems each - so a scan of many servers cannot hoard sockets;
        what does not fit is closed, which hands its session back to
        xrdclient's own pool.
        """
        with self._lock:
            kept = self._idle.get(key) if key is not None else None
            if kept is None and key is not None and len(self._idle) < package.IDLE_ENDPOINTS:
                kept = self._idle[key] = []
            if kept is not None and len(kept) < package.IDLE_PER_ENDPOINT:
                kept.append((time.monotonic(), fs))
                return
        fs.close()

    def _posix(self, url: str, description: str, action: Callable[[FileSystem, str], T]) -> T:
        """Run ``action`` and word any failure as the ``XrdPosix`` call would.

        ``description`` is the text gfal2 puts before ``(strerror)`` for this
        call. A :class:`~xgfalclient.GError` the action raised itself is
        already worded and passes through untouched.
        """
        try:
            with self._fs(url) as (fs, path):
                return action(fs, path)
        except GError:
            raise
        except Exception as exc:
            raise posix_error(description, exc) from exc

    # -- namespace -----------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        """``kXR_stat`` (:meth:`xrdclient.FileSystem.stat`), as ``XrdPosixXrootd::Stat`` fills it.

        XRootD has no symbolic-link stat a stock server answers, so ``lstat``
        is the same call, as it is in gfal2's plugin.
        """
        return posix_stat(self._posix(url, "Failed to stat file", lambda fs, p: fs.stat(p)))

    lstat = stat

    def access(self, url: str, mode: int) -> None:
        """``XrdPosixXrootd::Access``: a ``kXR_stat``, its flags read as the owner's bits.

        The server only says readable, writable or executable *for this
        client*, which ``Flags2Mode`` turns into owner bits; checking the
        wanted ``R_OK``/``W_OK``/``X_OK`` against those is all XrdPosix
        does. ``F_OK`` (0) passes once the stat succeeds.
        """
        info = self._posix(url, "Failed to access file or directory", lambda fs, p: fs.stat(p))
        bits = flags_to_mode(int(info.flags))
        allowed = not (
            (mode & os.R_OK and not bits & _stat.S_IRUSR)
            or (mode & os.W_OK and not bits & _stat.S_IWUSR)
            or (mode & os.X_OK and not bits & _stat.S_IXUSR)
        )
        if not allowed:
            code = errno.EACCES
            raise GError(f"Failed to access file or directory ({os.strerror(code)})", code)

    def chmod(self, url: str, mode: int) -> None:
        """``kXR_chmod``; gfal2 calls XrdCl directly here, so the failure is ``ToStr``-worded.

        Only the permission bits travel: XRootD's mode field has no room
        for set-id or sticky bits.
        """
        try:
            with self._fs(url) as (fs, path):
                fs.chmod(path, mode & 0o777)
        except Exception as exc:
            raise status_error("", exc) from exc

    def mkdir(self, url: str, mode: int) -> None:
        """Stat first: EOS says yes to an existing directory, so gfal2 asks."""
        description = f"Failed to create directory {url}"

        def create(fs: FileSystem, path: str) -> None:
            """``kXR_stat`` then ``kXR_mkdir`` on the one checked-out filesystem."""
            try:
                fs.stat(path)
            except Exception:
                pass  # absent, or unanswerable: the mkdir will say which
            else:
                raise GError(f"{description} ({os.strerror(errno.EEXIST)})", errno.EEXIST)
            try:
                # XrdPosix makes the whole path unless S_ISUID says not to.
                fs.mkdir(path, mode & 0o777, parents=not mode & _stat.S_ISUID)
            except Exception as exc:
                code = describe(exc).code
                # gfal2's mkdir turns ECANCELED into EEXIST: some servers answer
                # an existing directory with kXR_Cancelled rather than kXR_ItExists.
                raise posix_error(
                    description, exc, errno.EEXIST if code == errno.ECANCELED else code
                ) from exc

        self._posix(url, description, create)

    def mkdir_rec(self, url: str, mode: int) -> None:
        """gfal2's ``mkdir_rec`` is ``mkdir`` with parents, forgiving ``EEXIST``."""
        try:
            self.mkdir(url, mode)
        except GError as exc:
            if exc.code != errno.EEXIST:
                raise

    def rmdir(self, url: str) -> None:
        """``kXR_rmdir``, with gfal2's ``errno`` fixes for EOS (:func:`~.stat.rmdir_errno`)."""
        description = "Failed to delete directory"

        def remove(fs: FileSystem, path: str) -> None:
            """``kXR_rmdir``; on failure the errno is corrected with a further ``kXR_stat``."""
            try:
                fs.rmdir(path)
            except Exception as exc:
                raise posix_error(description, exc, rmdir_errno(fs, path, exc)) from exc

        self._posix(url, description, remove)

    def unlink(self, url: str) -> None:
        """``kXR_rm`` (:meth:`xrdclient.FileSystem.remove`)."""
        self._posix(url, "Failed to delete file", lambda fs, p: fs.remove(p))

    def rename(self, old: str, new: str) -> None:
        """``kXR_mv`` on ``old``'s endpoint; ``new`` contributes only its decoded path.

        As in gfal2, the destination's host is not checked: XRootD renames
        within one namespace, and a server asked to move a path elsewhere
        answers for itself.
        """
        description = "Failed to rename file or directory"

        def move(fs: FileSystem, path: str) -> None:
            """``kXR_mv`` from ``path`` to ``new``'s decoded path."""
            _, target = self._target(new)
            try:
                fs.rename(path, target)
            except Exception as exc:
                error = posix_error(description, exc)
                # EOS says EEXIST when the target is a directory; gfal2 swaps
                # the code for EISDIR and keeps the message.
                if error.code == errno.EEXIST and is_dir(fs, target):
                    error.code = errno.EISDIR
                    error.args = (error.message, error.code)
                raise error from exc

        self._posix(old, description, move)

    def readlink(self, url: str) -> str:
        """A vendor opcode; a stock server has none, and then neither does gfal2."""
        try:
            with self._fs(url) as (fs, path):
                return str(fs.readlink(path))
        except Exception as exc:
            raise vendor_error(url, "Failed to read link", exc) from exc

    def symlink(self, target: str, link: str) -> None:
        """A vendor ``kXR_symlink``; a ``root://`` target is reduced to its path.

        A non-XRootD ``target`` is passed through as written, so a link can
        point anywhere the server is willing to record.
        """
        destination = self._target(target)[1] if is_root(target) else target
        try:
            with self._fs(link) as (fs, path):
                fs.symlink(destination, path)
        except Exception as exc:
            raise vendor_error(target, "Failed to create symlink", exc) from exc

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        """One ``kXR_dirlist`` with stat info, read in full; see :func:`~.stat.entries`."""

        def listing(fs: FileSystem, path: str) -> list[tuple[str, Stat | None]]:
            """Every entry with its reduced stat, read before the filesystem is checked in."""
            return [(name, reduced(fields)) for name, fields in entries(fs, path, brief=True)]

        return iter(self._posix(url, "Failed to stat file", listing))

    def listdir(self, url: str) -> list[str]:
        """``opendir`` without building a stat per entry nobody will look at."""
        found = self._posix(url, "Failed to stat file", lambda fs, p: entries(fs, p, brief=False))
        return [name for name, _ in found]

    # -- I/O -----------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o744, size: int | None = None) -> PluginFile:
        """``XrdPosixXrootd::Open``'s translation of POSIX flags.

        ``mode`` defaults to what ``gfal2_open`` passes, ``0744``.

        Anything but read-only is ``kXR_open_updt``; ``O_CREAT`` is
        ``kXR_delete`` (``kXR_new`` with ``O_EXCL``) and always makes the
        path; ``O_TRUNC`` without it truncates an existing file.
        """
        writable = bool(flags & O_ACCMODE_MASK)
        options = _UPDATE if writable else _READ
        access = 0
        if flags & O_CREAT:
            options |= (_NEW if flags & O_EXCL else _DELETE) | _MKPATH
            access = mode & 0o777
        elif flags & O_TRUNC and writable:
            options |= _DELETE
        try:
            target = self._file_url(url)
            handle = xrdclient.File(target, self._config(url))
            handle.open(options, access)
        except Exception as exc:
            raise posix_error("Failed to open file", exc) from exc
        return XRootDFile(url, handle, writable=writable, context=self.context)

    # -- metadata ------------------------------------------------------------------

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        """``kXR_Qcksum`` with ``cks.type=<algorithm>``; whole files only, as in gfal2.

        The server computes (or reads a stored) checksum, so nothing is
        downloaded. The answer must name the algorithm asked for: a server
        that only knows its default answers with that one, and gfal2 calls
        the mismatch an error rather than hand back the wrong kind.
        """
        if offset or length:
            code = errno.ENOTSUP
            raise GError(f"XROOTD does not support partial checksums ({os.strerror(code)})", code)
        wanted = checksum_name(algorithm)
        try:
            answer = self._checksum_answer(url, wanted)
        except Exception as exc:
            raise posix_error("Could not get the checksum", exc) from exc
        return checksum_value(answer, wanted)

    def _checksum_answer(self, url: str, wanted: str) -> bytes:
        """The server's answer to ``kXR_Qcksum`` for ``url``, asked for ``wanted``."""
        argument = self._file_url(url, **{"cks.type": wanted}).path_with_cgi
        with self._fs(url) as (fs, _):
            return bytes(fs.query(3, argument))

    def getxattr(self, url: str, name: str) -> str:
        """gfal2's ``xroot.*`` attributes, ``user.status`` and ``spacetoken``.

        ``user.status`` comes from the stat flags (tape copy, offline);
        ``spacetoken`` is the ``kXR_Qspace`` summary as gfal2's JSON; the
        ``xroot.*`` names are raw ``kXR_query`` answers. Anything else is
        ``ENOATTR``, without a round trip.
        """
        description = f'Failed to get the xattr "{name}"'
        if name == "spacetoken":
            return self._space(url)
        if name == "user.status":
            try:
                with self._fs(url) as (fs, path):
                    info = fs.stat(path)
            except Exception as exc:
                raise posix_error(description, exc, errno.ENOENT) from exc
            return status_word(int(info.flags))
        code = _XATTR_QUERY.get(name)
        if code is None:
            raise GError(f"{description} ({os.strerror(ENOATTR)})", ENOATTR)
        argument = self._file_url(url).path_with_cgi

        def query(fs: FileSystem, path: str) -> bytes:
            """The ``kXR_query`` answer, asked of the server that holds the file."""
            # XrdPosix stats first, and so does gfal2 through it: a redirector
            # answers a query about a file it does not hold with an error, but
            # the stat leaves the filesystem on the data server that has it.
            fs.stat(path)
            return bytes(fs.query(code, argument))

        answer = self._posix(url, description, query)
        return answer.split(b"\x00", 1)[0].decode("utf-8", "replace")

    def _space(self, url: str) -> str:
        """``spacetoken``: ``kXR_Qspace`` as gfal2's JSON; any failure is ``EIO``, as there."""
        try:
            with self._fs(url) as (fs, path):
                space = fs.query_space(path)
        except Exception as exc:
            message = describe(exc).message
            raise GError(f"Failed to get the space information: {message}", errno.EIO) from exc
        return space_json(space.total, space.free, space.used, space.largest_free)

    def listxattr(self, url: str) -> list[str]:
        """gfal2's fixed list; the server is not asked, so a URL need not exist."""
        return list(XATTRS)

    def setxattr(self, url: str, name: str, value: str, flags: int) -> None:
        """Always ``ENOSYS``: gfal2's xrootd plugin has no ``setxattr``."""
        code = errno.ENOSYS
        raise GError(f"Can not set extended attributes ({os.strerror(code)})", code)

    # -- tape: see .tape -----------------------------------------------------------

    def bring_online(
        self,
        urls: Sequence[str],
        metadata: Sequence[str],
        pintime: int,
        timeout: int,
        is_async: bool,
    ) -> tuple[list[StagingResult], str]:
        """``kXR_prepare`` with ``kXR_stage``; the answer is the request id (see :mod:`.tape`).

        Only the URLs and the timeout reach the server: ``kXR_prepare`` has
        no field for a pin time or per-file metadata.
        """
        return tape.bring_online(self, urls, timeout)

    def bring_online_poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        """``kXR_QPrep`` under ``token``: which files are online yet."""
        return tape.poll(self, urls, token)

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        """A ``kXR_QPrep`` under a request id nobody made, asking only ``on_tape``."""
        return tape.poll(self, urls)

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``kXR_prepare`` with ``kXR_evict``; gfal2 sends no request id, so ``token`` is unused."""
        return tape.release(self, urls)

    def abort_bring_online(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``kXR_prepare`` with ``kXR_cancel`` under ``token``."""
        return tape.abort(self, urls, token)

    # -- copies: see .copy ---------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        """gfal2's ``gfal_xrootd_3rdcopy_check``: root to root, and root to or from file."""
        if is_root(source):
            return is_root(destination) or destination.startswith("file://")
        return is_root(destination) and source.startswith("file://")

    def copy(self, transfer: Transfer) -> None:
        """One job of XrdCl's copy process, as gfal2 sets it up and narrates it."""
        CopyJob(self, transfer).run()


def _x509(cred: X509Credential | None) -> dict[str, str | None]:
    """The credential fields of a :class:`~xrdclient.Config` for ``cred``, every one set."""
    if cred is None:
        return {"proxy": None, "usercert": None, "userkey": None}
    if cred.is_combined:
        return {"proxy": cred.cert, "usercert": None, "userkey": None}
    return {"proxy": None, "usercert": cred.cert, "userkey": cred.key}


def _close_idle(idle: Idle, lock: threading.Lock) -> None:
    """Close every idle filesystem, which hands its connection to xrdclient's pool."""
    with lock:
        kept = [fs for pairs in idle.values() for _, fs in pairs]
        idle.clear()
    for fs in kept:
        fs.close()
