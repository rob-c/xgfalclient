# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""OpenStack Swift (``swift://``) and CS3/Reva (``cs3://``) through the http plugin."""

from __future__ import annotations

import errno
import stat as _stat
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from test_http_helpers import Events, dav, dav2, hctx, make_server, write  # noqa: F401
from xgfalclient import GError
from xgfalclient.plugins.http import _swift
from xgfalclient.plugins.http._client import Target
from xgfalclient.testing.webdav import Swift, WebDAVServer
from xgfalclient.url import parse

FILE = _stat.S_IFREG | 0o755
DIR = _stat.S_IFDIR | 0o755


@pytest.fixture
def swift(tmp_path: Path, hctx: xgfalclient.Gfal2Context) -> Iterator[WebDAVServer]:
    server = make_server(tmp_path / "swift")
    server.swift = Swift(token="TOK", account="AUTH_proj")
    (server.root / "cont").mkdir()
    hctx.set_opt_string("SWIFT", "OS_TOKEN", "TOK")
    hctx.set_opt_string("SWIFT", "OS_PROJECT_ID", "proj")
    yield server
    server.stop()


def url(server: WebDAVServer, path: str) -> str:
    return server.url(path, scheme="swift")


def _entries(context: xgfalclient.Gfal2Context, where: str) -> list[tuple[str, object]]:
    return list(context.plugin(where, "opendir").opendir(where))


def test_stat(hctx: xgfalclient.Gfal2Context, swift: WebDAVServer) -> None:
    write(swift, "/cont/dir/f", b"hello")
    info = hctx.stat(url(swift, "/cont/dir/f"))
    assert (info.st_mode, info.st_size) == (FILE, 5) and info.st_mtime > 0
    head = swift.requests[-1]
    assert (head.method, head.path) == ("HEAD", "/v1/AUTH_proj/cont/dir/f")
    assert head.header("X-Auth-Token") == "TOK"
    assert hctx.stat(url(swift, "/cont")).st_mode == DIR  # a container answers 204
    # Not an object: a directory if anything is listed under it.
    assert hctx.stat(url(swift, "/cont/dir")).st_mode == DIR
    listing = swift.requests[-1]
    assert listing.path == "/v1/AUTH_proj/cont/?prefix=dir%2F&delimiter=%2F"
    assert listing.header("Accept") == "application/xml"
    with pytest.raises(GError) as caught:
        hctx.stat(url(swift, "/cont/nope"))
    assert (caught.value.code, caught.value.message) == (
        errno.ENOENT,
        "Result Not a file or directory after 1 attempts",
    )
    swift.fault("HEAD", status=204)
    assert hctx.stat(url(swift, "/cont/odd")).st_mode == 0o755  # no file type, as davix has it
    swift.fault("HEAD", status=200, headers={"Content-Length": "0"})
    assert hctx.stat(url(swift, "/cont")).st_mode == DIR  # a container that answers 200
    swift.fault("HEAD", status=200, headers={"Content-Length": "2"}, body=b"ab")
    assert hctx.stat(url(swift, "/cont/x/")).st_mode == FILE  # "x/" with content: an object
    with pytest.raises(GError) as caught:
        hctx.stat(url(swift, "/nocont"))
    assert caught.value.code == errno.ENOENT
    swift.fault("HEAD", status=403)
    with pytest.raises(GError) as caught:
        hctx.stat(url(swift, "/cont/dir/f"))
    assert caught.value.code == errno.EPERM
    swift.fault("GET", status=500)
    with pytest.raises(GError) as caught:
        hctx.stat(url(swift, "/cont/dir"))
    assert caught.value.code == errno.EIO


def test_listing(hctx: xgfalclient.Gfal2Context, swift: WebDAVServer) -> None:
    write(swift, "/cont/dir/a", b"1")
    write(swift, "/cont/dir/sub/b", b"22")
    write(swift, "/cont/top", b"333")
    assert sorted(hctx.listdir(url(swift, "/cont/dir"))) == ["a", "sub"]
    assert sorted(hctx.listdir(url(swift, "/cont"))) == ["dir", "top"]
    entries = dict(_entries(hctx, url(swift, "/cont/dir/")))
    assert entries["a"].st_mode == FILE and entries["a"].st_size == 1
    assert entries["a"].st_mtime > 0 and entries["sub"].st_mode == DIR
    (swift.root / "cont" / "empty").mkdir()
    assert hctx.listdir(url(swift, "/cont/empty")) == []
    assert hctx.listdir(url(swift, "/cont/nothing")) == []  # an empty answer
    write(swift, "/cont/onlydirs/sub/f", b"x")
    assert hctx.listdir(url(swift, "/cont/onlydirs")) == ["sub"]
    odd = (
        b"<container><object><bytes>x</bytes></object><thing><name>dir/n</name></thing>"
        b"<object><name>dir/odd</name><bytes>many</bytes><hash/></object></container>"
    )
    swift.fault("GET", status=200, body=odd)
    ((name, info),) = _entries(hctx, url(swift, "/cont/dir"))
    assert (name, info.st_size) == ("odd", 0)
    with pytest.raises(GError) as caught:
        hctx.listdir(url(swift, "/nocont"))
    assert caught.value.code == errno.ENOENT


def test_namespace(hctx: xgfalclient.Gfal2Context, swift: WebDAVServer) -> None:
    hctx.mkdir(url(swift, "/cont/newdir"), 0o755)
    put = swift.requests[-1]
    assert (put.method, put.path) == ("PUT", "/v1/AUTH_proj/cont/newdir/")
    assert hctx.stat(url(swift, "/cont/newdir")).st_mode == DIR
    assert hctx.stat(url(swift, "/cont/newdir/")).st_mode == DIR  # the marker, 0 bytes
    hctx.mkdir(url(swift, "/cont/slash/"), 0o755)
    assert swift.requests[-1].path == "/v1/AUTH_proj/cont/slash/"
    hctx.mkdir(f"swift://127.0.0.1:{swift.port}", 0o755)
    assert swift.requests[-1].path == "/v1/AUTH_proj/"
    hctx.mkdir_rec(url(swift, "/cont/x/y"), 0o755)
    assert swift.local("/cont/x/y").is_dir()
    hctx.rmdir(url(swift, "/cont/x/y"))
    assert not swift.local("/cont/x/y").exists()
    write(swift, "/cont/f", b"data")
    hctx.rename(url(swift, "/cont/f"), url(swift, "/cont/g"))
    copy, delete = swift.requests[-2:]
    assert (copy.method, copy.header("X-Copy-From")) == ("PUT", "/cont/f")
    assert (delete.method, delete.path) == ("DELETE", "/v1/AUTH_proj/cont/f")
    assert swift.local("/cont/g").read_bytes() == b"data"
    with pytest.raises(GError) as caught:
        hctx.rename(url(swift, "/cont/f"), url(swift, "/cont/h"))
    assert caught.value.message == (
        "Received code 404 when trying to copy file - will not perform deletion"
    )
    with pytest.raises(GError) as caught:
        hctx.rename(url(swift, "/cont/g"), "swift://other.example/cont/h")
    assert "not using the same Swift provider" in caught.value.message
    hctx.unlink(url(swift, "/cont/g"))
    assert not swift.local("/cont/g").exists()
    with pytest.raises(GError) as caught:
        hctx.unlink(url(swift, "/cont/g"))
    assert caught.value.code == errno.ENOENT
    with pytest.raises(GError) as caught:
        hctx.stat(url(swift, "/cont/nodir/"))
    assert caught.value.code == errno.ENOENT
    http = hctx.plugin(url(swift, "/"), "stat")
    write(swift, "/cont/full/f", b"x")
    for method, path, status in (
        ("DELETE", "/cont/g", 404),
        ("DELETE", "/cont/full", 404),
        ("DELETE", "/cont/full/", 404),
        ("POST", "/cont/g", 405),
        ("GET", "/cont/?prefix=full/", 200),
    ):
        response = http._request(method, url(swift, path), body=b"")
        payload = response.body()
        assert response.status == status
    assert b"<name>full/f</name>" in payload  # no delimiter: everything under the prefix
    with hctx.open(url(swift, "/cont/deeper/still/f"), "w") as handle:
        handle.write(b"parents made")
    assert swift.local("/cont/deeper/still/f").read_bytes() == b"parents made"


def test_io_and_checksums(hctx: xgfalclient.Gfal2Context, swift: WebDAVServer) -> None:
    with hctx.open(url(swift, "/cont/new"), "w") as handle:
        handle.write(b"written")
    assert swift.local("/cont/new").read_bytes() == b"written"
    assert hctx.open(url(swift, "/cont/new"), "r").read(100) == "written"
    assert hctx.checksum(url(swift, "/cont/new"), "adler32") == "0c65030e"
    etag = '"' + "z" * 32 + '/5d41402abc4b2a76b9719d911017c592"'
    swift.fault("HEAD", status=200, headers={"ETag": etag})
    # No digest offered: the ETag's MD5 will do, as davix takes it.
    swift.digests = set()
    assert hctx.checksum(url(swift, "/cont/new"), "md5") == "5d41402abc4b2a76b9719d911017c592"


def test_credentials(hctx: xgfalclient.Gfal2Context, swift: WebDAVServer) -> None:
    write(swift, "/cont/f", b"x")
    hctx.set_opt_string("SWIFT", "OS_TOKEN", "WRONG")
    with pytest.raises(GError) as caught:
        hctx.stat(url(swift, "/cont/f"))
    assert caught.value.code == errno.EACCES
    hctx.set_opt_string("SWIFT:127.0.0.1", "OS_TOKEN", "TOK")  # the host's group comes first
    assert hctx.stat(url(swift, "/cont/f")).st_size == 1
    hctx.set_opt_string("SWIFT", "SWIFT_ACCOUNT", "AUTH_proj")  # an account beats a project
    hctx.set_opt_string("SWIFT", "OS_PROJECT_ID", "other")
    assert hctx.stat(url(swift, "/cont/f")).st_size == 1
    hctx.remove_opt("SWIFT", "SWIFT_ACCOUNT")
    hctx.remove_opt("SWIFT", "OS_PROJECT_ID")
    with pytest.raises(GError) as caught:  # outside the account: Swift has no such path
        hctx.stat(url(swift, "/cont/f"))
    assert caught.value.code == errno.ENOENT
    swift.swift = Swift()  # no token, no account
    hctx.remove_opt("SWIFT", "OS_TOKEN")
    hctx.remove_opt("SWIFT:127.0.0.1", "OS_TOKEN")
    assert hctx.stat(url(swift, "/cont/f")).st_size == 1
    request = swift.requests[-1]
    assert (request.path, request.header("X-Auth-Token")) == ("/cont/f", None)
    with pytest.raises(GError):
        hctx.stat(url(swift, "/v1/elsewhere/f"))


def test_signer_units() -> None:
    keys = _swift.SwiftKeys("SECRET", "p", "")
    assert "SECRET" not in repr(keys)
    signer = _swift.SwiftSigner(keys)
    target = signer.target("GET", Target.of("swift://h/c/o?x=1"))
    assert target.path == "/v1/AUTH_p/c/o?x=1"
    with pytest.raises(GError) as caught:
        signer.presign("GET", "swift://h/c/o")
    assert caught.value.code == errno.ENOSYS
    assert _swift.provider("swift://h/c") == ""
    assert _swift.provider("swift://a.example.org/c") == ".example.org"
    assert _swift._split("swift://h") == ("swift://h", "", "/")
    assert _swift._listing("swift://h", "", "/") == "swift://h/?prefix=&delimiter=%2F"
    assert parse("swift://h/c").host == "h"


def test_swift_in_a_copy(
    hctx: xgfalclient.Gfal2Context, swift: WebDAVServer, dav2: WebDAVServer
) -> None:
    """Swift takes part in copies as an HTTP endpoint (with no token for the far side)."""
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
    write(swift, "/cont/f", b"x")
    with pytest.raises(GError):
        hctx.filecopy(url(swift, "/cont/f"), dav2.url("/data/dst"))
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert copy_request.header("Source") == f"http://127.0.0.1:{swift.port}/cont/f"
    assert copy_request.header("TransferHeaderAuthorization") is None
    assert copy_request.header("Credential") == "none"
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "streamed")
    hctx.filecopy(url(swift, "/cont/f"), dav2.url("/data/dst"))
    assert dav2.local("/data/dst").read_bytes() == b"x"


# -- CS3 ------------------------------------------------------------------------------------


def test_cs3(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"reva")
    hctx.set_opt_string("BEARER", "TOKEN", "REVA")
    dav.tokens = {"REVA"}
    info = hctx.stat(dav.url("/data/f", scheme="cs3"))
    # davix's HEAD stat: a 0755 file of that size, and no times.
    assert (info.st_mode, info.st_size, info.st_mtime) == (FILE, 4, 0)
    head = dav.requests[-1]
    assert (head.method, head.header("Authorization")) == ("HEAD", "Bearer REVA")
    assert hctx.listdir(dav.url("/data", scheme="cs3")) == ["f"]
    hctx.cred_set(dav.url("/"), hctx.cred_new("BEARER", "NOT-FOR-CS3"))
    hctx.stat(dav.url("/data/f", scheme="cs3"))
    assert dav.requests[-1].header("Authorization") == "Bearer REVA"  # [BEARER] TOKEN only
    hctx.set_opt_string("BEARER", "TOKEN", "")
    dav.tokens = set()
    hctx.stat(dav.url("/data/f", scheme="cs3"))
    assert dav.requests[-1].header("Authorization") is None
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/data/nope", scheme="cs3"))
    assert caught.value.message == "Result HTTP 404 : File not found  after 1 attempts"
