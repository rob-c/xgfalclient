"""``mock://`` - a storage element described entirely by its URL.

gfal2 ships this plugin so that FTS and other callers can be tested without
a server: the query string says what the "file" is and how operations on it
should behave. The grammar is gfal2's:

========================  =====================================================
``size=N``                the file is ``N`` bytes (stat, and bytes read)
``errno=N``               ``stat`` fails with ``N``
``list=a:10,b:20``        the URL is a directory holding those entries
``checksum=HEX``          what ``checksum`` answers
``access_errno=N``        ``access``, ``unlink``, ``mkdir``... fail with ``N``
``open_errno=N``          ``open`` fails with ``N``
``read_errno=N``          ``read`` fails with ``N``
``rd_path=/local/file``   reads come from that local file instead of zeros
``size_pre=N``            destination exists with ``N`` bytes before a copy
``size_post=N``           destination has ``N`` bytes after a copy
``transfer_errno=N``      a copy to or from this URL fails with ``N``
``time=N``                a copy takes ``N`` seconds (else the configured range)
``staging_time=N``        staging completes ``N`` seconds after it is asked for
``staging_errno=N``       staging fails with ``N``
``release_errno=N``       ``release`` fails with ``N``
``archiving_time=N``      the file is archived ``N`` seconds after the first poll
``archiving_errno=N``     archiving fails with ``N``
========================  =====================================================

Everything is deterministic except where gfal2's is not (copy duration
between ``MIN_TRANSFER_TIME`` and ``MAX_TRANSFER_TIME``).
"""

from __future__ import annotations

import errno
import os
import random
import stat as _stat
import threading
import time
import uuid
from collections.abc import Iterator, Sequence

from ..errors import GError
from ..plugin import O_ACCMODE_MASK, Plugin, PluginFile, StagingResult
from ..transfer import Transfer
from ..types import Stat
from ..url import parse

__all__ = ["MockPlugin"]


def _params(url: str) -> dict[str, str]:
    return parse(url).query_dict()


def _int(params: dict[str, str], key: str, default: int = 0) -> int:
    try:
        return int(params.get(key, default))
    except ValueError:
        return default


def _fail(code: int) -> GError:
    return GError(os.strerror(code), code)


def _maybe_fail(params: dict[str, str], key: str) -> None:
    code = _int(params, key)
    if code:
        raise _fail(code)


class _MockFile(PluginFile):
    def __init__(self, url: str, params: dict[str, str]) -> None:
        super().__init__(url)
        self._params = params
        self._size = _int(params, "size")
        self._source = params.get("rd_path")

    def size(self) -> int:
        return self._size

    def pread(self, offset: int, size: int) -> bytes:
        _maybe_fail(self._params, "read_errno")
        if self._source:
            with open(self._source, "rb") as handle:
                handle.seek(offset)
                return handle.read(size)
        return bytes(max(0, min(size, self._size - offset)))


class MockPlugin(Plugin):
    """gfal2's ``mock`` plugin."""

    name = "mock"
    schemes = ("mock",)
    option_group = "MOCK PLUGIN"
    priority = 300
    event_domain = "GFAL2::PLUGINS::FILE"

    def __init__(self, context: object) -> None:
        super().__init__(context)  # type: ignore[arg-type]
        self._lock = threading.Lock()
        self._staging: dict[str, float] = {}
        self._archiving: dict[str, float] = {}
        self._copied: set[str] = set()

    # -- namespace ---------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        params = _params(url)
        _maybe_fail(params, "errno")
        if "list" in params:
            return Stat(st_mode=_stat.S_IFDIR | 0o755)
        return Stat(st_mode=_stat.S_IFREG | 0o755, st_size=self._size(url, params))

    def _size(self, url: str, params: dict[str, str]) -> int:
        """A destination is ``size_pre`` (else ``size_post``) bytes, then ``size_post``."""
        if "size" in params:
            return _int(params, "size")
        with self._lock:
            copied = url in self._copied
        if copied:
            return _int(params, "size_post")
        if "size_pre" in params:
            return _int(params, "size_pre")
        return _int(params, "size_post")  # gfal2: a size_post destination already exists

    def access(self, url: str, mode: int) -> None:
        _maybe_fail(_params(url), "access_errno")

    def mkdir(self, url: str, mode: int) -> None:
        _maybe_fail(_params(url), "access_errno")

    def mkdir_rec(self, url: str, mode: int) -> None:
        _maybe_fail(_params(url), "access_errno")

    def rmdir(self, url: str) -> None:
        _maybe_fail(_params(url), "access_errno")

    def unlink(self, url: str) -> None:
        _maybe_fail(_params(url), "access_errno")
        with self._lock:
            self._copied.discard(url)

    def rename(self, old: str, new: str) -> None:
        _maybe_fail(_params(old), "access_errno")

    def opendir(self, url: str) -> Iterator[tuple[str, Stat | None]]:
        params = _params(url)
        _maybe_fail(params, "errno")
        if "list" not in params:
            raise _fail(errno.ENOTDIR)
        entries = []
        for item in filter(None, params["list"].split(",")):
            name, _, size = item.partition(":")
            mode = _stat.S_IFDIR | 0o755 if name.endswith("/") else _stat.S_IFREG | 0o755
            entries.append((name.rstrip("/"), Stat(st_mode=mode, st_size=int(size or 0))))
        return iter(entries)

    # -- I/O ---------------------------------------------------------------------

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        params = _params(url)
        _maybe_fail(params, "open_errno")
        if flags & O_ACCMODE_MASK:
            raise GError("Mock plugin does not support read and write", errno.ENOSYS)
        return _MockFile(url, params)

    # -- metadata ------------------------------------------------------------------

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        params = _params(url)
        _maybe_fail(params, "errno")
        return params.get("checksum", "")

    def getxattr(self, url: str, name: str) -> str:
        params = _params(url)
        if name == "user.status":
            online = self._staged(url, params) is True
            return "ONLINE" if online or "staging_time" not in params else "NEARLINE"
        if name in ("user.replicas", "user.guid", "user.comment", "spacetoken"):
            return params.get(name.rpartition(".")[2], "")
        raise GError(f"Failed to retrieve xattr {name}", errno.ENODATA)

    def listxattr(self, url: str) -> list[str]:
        return ["user.status", "user.replicas", "user.guid", "user.comment", "spacetoken"]

    # -- tape --------------------------------------------------------------------

    def _staged(self, url: str, params: dict[str, str]) -> StagingResult:
        code = _int(params, "staging_errno")
        if code:
            return _fail(code)
        with self._lock:
            ready = self._staging.get(url)
        return ready is None or time.monotonic() >= ready

    def bring_online(
        self,
        urls: Sequence[str],
        metadata: Sequence[str],
        pintime: int,
        timeout: int,
        is_async: bool,
    ) -> tuple[list[StagingResult], str]:
        results: list[StagingResult] = []
        for url in urls:
            params = _params(url)
            with self._lock:
                self._staging[url] = time.monotonic() + _int(params, "staging_time")
            results.append(self._staged(url, params))
        return results, str(uuid.uuid4())

    def bring_online_poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        return [self._staged(url, _params(url)) for url in urls]

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        results: list[GError | None] = []
        for url in urls:
            code = _int(_params(url), "release_errno")
            results.append(_fail(code) if code else None)
        return results

    def abort_bring_online(self, urls: Sequence[str], token: str) -> list[GError | None]:
        with self._lock:
            for url in urls:
                self._staging.pop(url, None)
        return [None for _ in urls]

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        results: list[StagingResult] = []
        for url in urls:
            params = _params(url)
            code = _int(params, "archiving_errno")
            if code:
                results.append(_fail(code))
                continue
            with self._lock:
                ready = self._archiving.setdefault(
                    url, time.monotonic() + _int(params, "archiving_time")
                )
            results.append(time.monotonic() >= ready)
        return results

    def token_retrieve(
        self, url: str, issuer: str, validity: int, write_access: bool, activities: list[str]
    ) -> str:
        return "mock-token"

    # -- copies ------------------------------------------------------------------

    def copy_check(self, source: str, destination: str) -> bool:
        return source.startswith("mock://") and destination.startswith("mock://")

    def copy(self, transfer: Transfer) -> None:
        source, destination = _params(transfer.source), _params(transfer.destination)
        seconds = self._duration(source, destination)
        transfer.event("TRANSFER:TYPE", "mock")
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            transfer.check()
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        for params in (source, destination):
            _maybe_fail(params, "transfer_errno")
        with self._lock:
            self._copied.add(transfer.destination)
        transfer.progress(_int(destination, "size_post", _int(source, "size")), force=True)

    def _duration(self, source: dict[str, str], destination: dict[str, str]) -> float:
        for params in (destination, source):
            if "time" in params:
                return float(_int(params, "time"))
        low = self.options.integer(self.option_group, "MIN_TRANSFER_TIME", 5)
        high = self.options.integer(self.option_group, "MAX_TRANSFER_TIME", 5)
        return float(random.randint(min(low, high), max(low, high)))
