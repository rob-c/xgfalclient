"""The http plugin against xrdhttp's shared conformance suites.

The behaviour every HTTP storage client owes a user - stat, listings,
collections, renames, ranged reads, uploads, digests, redirects,
third-party copy, tape staging, macaroons, S3 - is checked once, in
:mod:`xrdhttp.testing.conformance`, and run here through :class:`GfalAdapter`:
the same operations through the gfal2 API a user calls (``ctx.stat``,
``ctx.filecopy``, ``ctx.bring_online``...), against this package's preset
of the fake (:class:`~xgfalclient.testing.webdav.WebDAVServer`, davix
style, over a real directory). xrdclient runs the same suites through its
own API. What only gfal2 promises - davix's errno and wording, gfal2's
options, events and copy modes - stays in the other ``test_http_*`` modules.
"""

from __future__ import annotations

import ssl
import urllib.parse
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from xrdhttp.testing import StorageServer
from xrdhttp.testing.conformance import (
    Adapter,
    ChecksumSuite,
    Conformance,
    ConnectionSuite,
    CopySuite,
    Kind,
    NamespaceSuite,
    Progress,
    ReadSuite,
    RedirectSuite,
    S3Suite,
    Stat,
    TapeSuite,
    TokenSuite,
    UploadSuite,
    kind_of_errno,
)

import xgfalclient
from xgfalclient import GError
from xgfalclient.plugin import O_CREAT, O_TRUNC, O_WRONLY
from xgfalclient.plugins.http import _s3
from xgfalclient.testing.pki import PKI
from xgfalclient.testing.webdav import WebDAVServer

#: The flags of an upload opened through the plugin, with its size declared.
WRITE = O_WRONLY | O_CREAT | O_TRUNC


def _raise_first(results: Sequence[GError | None]) -> None:
    """Raise the first error of a list-form call, which reports one per URL rather than raising."""
    for found in results:
        if found is not None:
            raise found


class GfalAdapter(Adapter):
    """The neutral operations, through one gfal2 context."""

    def __init__(self) -> None:
        """A fresh context, as a gfal2 program makes one."""
        self.context = xgfalclient.creat_context()

    def url(self, server: StorageServer, path: str) -> str:
        """``dav://`` (``davs://`` under TLS), the scheme grid users give gfal2."""
        scheme = "davs" if server.tls is not None else "dav"
        return f"{scheme}://{server.host}:{server.port}{urllib.parse.quote(path)}"

    def kind(self, error: BaseException) -> Kind:
        """A ``GError``'s ``code`` is its errno."""
        if isinstance(error, GError):
            return kind_of_errno(error.code)
        return super().kind(error)

    def close(self) -> None:
        """Free the context (and with it the plugin's pool)."""
        self.context.free()

    def authorise(self, token: str) -> None:
        """A ``BEARER`` credential for the host, as FTS sets one."""
        self.context.cred_set("127.0.0.1", self.context.cred_new("BEARER", token))

    def time_limit(self, seconds: float) -> None:
        """``HTTP PLUGIN`` ``OPERATION_TIMEOUT`` (whole seconds, as gfal2 reads it)."""
        self.context.set_opt_integer("HTTP PLUGIN", "OPERATION_TIMEOUT", round(seconds))

    # -- the namespace -----------------------------------------------------------------

    def stat(self, url: str) -> Stat:
        """``ctx.stat``."""
        info = self.context.stat(url)
        return Stat(info.st_size, info.is_dir(), info.st_mtime)

    def listdir(self, url: str) -> list[str]:
        """``ctx.listdir``."""
        return self.context.listdir(url)

    def mkdir(self, url: str) -> None:
        """``ctx.mkdir``."""
        self.context.mkdir(url, 0o755)

    def makedirs(self, url: str) -> None:
        """``ctx.mkdir_rec``."""
        self.context.mkdir_rec(url, 0o755)

    def rmdir(self, url: str) -> None:
        """``ctx.rmdir``."""
        self.context.rmdir(url)

    def unlink(self, url: str) -> None:
        """``ctx.unlink``."""
        self.context.unlink(url)

    def rename(self, source: str, destination: str) -> None:
        """``ctx.rename``."""
        self.context.rename(source, destination)

    # -- data ----------------------------------------------------------------------------

    def read(self, url: str) -> bytes:
        """``ctx.open(url, "r")`` read to the end."""
        handle = self.context.open(url, "r")
        try:
            return b"".join(iter(lambda: bytes(handle.read_bytes(1 << 20)), b""))
        finally:
            handle.close()

    def pread(self, url: str, offset: int, size: int) -> bytes:
        """``pread_bytes`` on a file opened for reading."""
        handle = self.context.open(url, "r")
        try:
            return bytes(handle.pread_bytes(offset, size))
        finally:
            handle.close()

    def write(self, url: str, data: bytes) -> None:
        """``ctx.open(url, "w")``: spooled, then one ``PUT`` with its length."""
        handle = self.context.open(url, "w")
        handle.write(data)
        handle.close()

    def stream(self, url: str, chunks: Sequence[bytes]) -> None:
        """The plugin's ``open`` with the size declared: each chunk goes out as written."""
        plugin: Any = self.context.plugin(url, "open")
        handle = plugin.open(url, WRITE, 0o644, sum(len(chunk) for chunk in chunks))
        for chunk in chunks:
            handle.write(chunk)
        handle.close()

    def checksum(self, url: str, algorithm: str) -> str:
        """``ctx.checksum``."""
        return self.context.checksum(url, algorithm)

    # -- third-party copy --------------------------------------------------------------

    def copy(
        self, source: str, destination: str, *, push: bool = False, progress: Progress | None = None
    ) -> None:
        """``ctx.filecopy`` with one ``COPY`` mode and no fallback."""
        mode = "3rd push" if push else "3rd pull"
        self.context.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", mode)
        self.context.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
        params = self.context.transfer_parameters()
        if progress is not None:
            params.monitor_callback = lambda src, dst, avg, inst, done, elapsed: progress(done)
        self.context.filecopy(params, source, destination)

    # -- the WLCG tape REST API -----------------------------------------------------

    def stage(self, urls: Sequence[str]) -> str:
        """``ctx.bring_online``, asynchronous."""
        found, token = self.context.bring_online(list(urls), 0, 0, True)
        _raise_first(found)
        return str(token)

    def poll(self, request: str, urls: Sequence[str]) -> list[bool]:
        """``ctx.bring_online_poll``, one URL at a time (``1`` is online)."""
        return [self.context.bring_online_poll(url, request) == 1 for url in urls]

    def release(self, request: str, urls: Sequence[str]) -> None:
        """``ctx.release``."""
        _raise_first(self.context.release(list(urls), request))

    def abort(self, request: str, urls: Sequence[str]) -> None:
        """``ctx.abort_bring_online``."""
        _raise_first(self.context.abort_bring_online(list(urls), request))

    def on_tape(self, urls: Sequence[str]) -> list[bool]:
        """The ``user.status`` xattr: ``NEARLINE`` is on tape."""
        return ["NEARLINE" in self.context.getxattr(url, "user.status") for url in urls]

    # -- tokens ---------------------------------------------------------------------------

    def macaroon(self, url: str, activities: Sequence[str]) -> str:
        """``ctx.token_retrieve`` with explicit activities and no issuer."""
        return self.context.token_retrieve(url, "", 10, list(activities))


class GfalS3Adapter(GfalAdapter):
    """The same context, given the fake's S3 keys, addressing buckets path-style."""

    def __init__(self, server: StorageServer) -> None:
        """``S3`` ``ACCESS_KEY``/``SECRET_KEY``, and ``ALTERNATE`` for path-style buckets."""
        super().__init__()
        assert server.s3 is not None
        self.context.set_opt_string("S3", "ACCESS_KEY", server.s3.access_key)
        self.context.set_opt_string("S3", "SECRET_KEY", server.s3.secret_key)
        self.context.set_opt_boolean("S3", "ALTERNATE", True)

    def url(self, server: StorageServer, path: str) -> str:
        """``s3://host:port/bucket/key``."""
        return f"s3://{server.host}:{server.port}{urllib.parse.quote(path)}"


class Gfal(Conformance):
    """xgfalclient's preset of the fake (davix style, over a directory) and its adapter."""

    def make_server(self, root: Path) -> StorageServer:
        """:class:`~xgfalclient.testing.webdav.WebDAVServer` rooted at ``root``."""
        return WebDAVServer(root)

    def make_adapter(self, server: StorageServer) -> Adapter:
        """:class:`GfalAdapter`."""
        return GfalAdapter()


class TestNamespace(Gfal, NamespaceSuite):
    """Stat, listings, collections, removal, renames."""


class TestRead(Gfal, ReadSuite):
    """Whole, ranged and resumed reads."""


class TestUpload(Gfal, UploadSuite):
    """Sized, streamed and redirected uploads."""


class TestChecksum(Gfal, ChecksumSuite):
    """Server-side digests."""


class TestRedirect(Gfal, RedirectSuite):
    """Redirects and the token across them."""


class TestConnection(Gfal, ConnectionSuite):
    """Keep-alive, stale connections, failures, tokens."""


class TestCopy(Gfal, CopySuite):
    """HTTP third-party copy."""


class TestTape(Gfal, TapeSuite):
    """The WLCG Tape REST API."""


class TestToken(Gfal, TokenSuite):
    """Macaroons: gfal2 asks for one only over HTTPS, so this fake has TLS."""

    @pytest.fixture
    def server(self, tmp_path: Path, grid_env: PKI) -> Iterator[StorageServer]:
        """A ``davs`` fake that takes the grid proxy as the client's identity."""
        tls = grid_env.server_context()
        tls.verify_mode = ssl.CERT_OPTIONAL
        with WebDAVServer(tmp_path / "tls", tls=tls) as started:
            yield started


class TestS3(Gfal, S3Suite):
    """A bucket as a filesystem, and multipart uploads."""

    @pytest.fixture(autouse=True)
    def _small_parts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Multipart past 1500 bytes, in kilobyte parts: the large object needs several."""
        monkeypatch.setattr(_s3, "MULTIPART_THRESHOLD", 1500)
        monkeypatch.setattr(_s3, "PART_SIZE", 1000)

    def make_adapter(self, server: StorageServer) -> Adapter:
        """:class:`GfalS3Adapter`."""
        return GfalS3Adapter(server)
