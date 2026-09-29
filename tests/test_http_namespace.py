# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""The http plugin's namespace: stat, mkdir, rmdir, unlink, rename, listings, xattrs."""

from __future__ import annotations

import errno
import stat as _stat
from pathlib import Path

import pytest

import xgfalclient
from test_http_helpers import dav, dav2, hctx, write  # noqa: F401 - fixtures
from xgfalclient import GError
from xgfalclient.testing.webdav import WebDAVServer


def test_plugin_is_first_and_named(hctx: xgfalclient.Gfal2Context) -> None:
    assert hctx.get_plugin_names()[0].startswith("http-")
    assert hctx.plugin("davs://h/x", "stat").event_domain == "http_plugin"


def test_stat_file_and_directory(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f1", b"hello\n")
    info = hctx.stat(dav.url("/data/f1"))
    assert info.st_mode == _stat.S_IFREG | 0o777
    assert info.st_size == 6
    assert info.st_mtime > 0
    assert (info.st_uid, info.st_gid, info.st_nlink, info.st_ino, info.st_atime) == (0, 0, 0, 0, 0)
    folder = hctx.stat(dav.url("/data"))
    assert folder.st_mode == _stat.S_IFDIR | 0o777
    request = dav.requests[0]
    assert (request.method, request.header("Depth")) == ("PROPFIND", "0")
    assert request.header("User-Agent").startswith("xgfalclient/")


def test_stat_missing_is_worded_like_davix(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/data/nope"))
    assert caught.value.code == errno.ENOENT
    assert caught.value.message == "Result HTTP 404 : File not found  after 1 attempts"


def test_forbidden_is_eperm_as_in_gfal2(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    dav.fault("PROPFIND", status=403)
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/data/x"))
    assert (caught.value.code, caught.value.message) == (
        errno.EPERM,
        "HTTP 403 : Permission refused ",
    )


def test_unknown_status_uses_the_server_reason(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    dav.fault("PROPFIND", status=418)
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/data/x"))
    assert caught.value.message == "HTTP 418 : I'm a Teapot "


def test_connection_refused(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    port = dav.port
    dav.stop()
    with pytest.raises(GError) as caught:
        hctx.stat(f"dav://127.0.0.1:{port}/data/x")
    assert caught.value.code == errno.ECONNREFUSED
    assert caught.value.message == "Result Could not connect to server after 1 attempts"


def test_stat_over_plain_http_falls_back_to_head(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    write(dav, "/data/f", b"12345")
    dav.webdav = False
    info = hctx.stat(dav.url("/data/f", scheme="http"))
    assert (info.st_size, info.is_file()) == (5, True)
    assert info.st_mtime > 0
    assert dav.methods() == ["PROPFIND", "HEAD"]
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/data/missing", scheme="http"))
    assert caught.value.code == errno.ENOENT
    write(dav, "/data/empty", b"")
    assert hctx.stat(dav.url("/data/empty", scheme="http")).st_size == 0


def test_dav_scheme_does_not_fall_back(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    dav.webdav = False
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/data"))
    assert caught.value.code == errno.EPERM  # 405 -> EPERM, as davix maps it


def test_empty_multistatus_is_a_protocol_error(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    dav.fault(
        "PROPFIND",
        status=207,
        body=b'<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"></D:multistatus>',
    )
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/data"))
    assert caught.value.code == errno.EPROTO


def test_mkdir(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    hctx.mkdir(dav.url("/data/new"), 0o755)
    assert dav.local("/data/new").is_dir()
    with pytest.raises(GError) as caught:
        hctx.mkdir(dav.url("/data/new"), 0o755)
    assert caught.value.code == errno.EEXIST
    assert caught.value.message == (
        f"HTTP 405 : Method Not Allowed, File Exist  with url {dav.url('/data/new')}"
    )
    with pytest.raises(GError) as caught:
        hctx.mkdir(dav.url("/data/a/b"), 0o755)
    assert caught.value.code == errno.ENOENT
    assert caught.value.message.startswith("HTTP 409 : Conflict  with url")
    dav.fault("MKCOL", status=403)
    with pytest.raises(GError) as caught:
        hctx.mkdir(dav.url("/data/c"), 0o755)
    assert (caught.value.code, caught.value.message) == (
        errno.EPERM,
        "HTTP 403 : Permission refused ",
    )


def test_mkdir_rec(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    hctx.mkdir_rec(dav.url("/data/a/b/c"), 0o755)
    assert dav.local("/data/a/b/c").is_dir()
    hctx.mkdir_rec(dav.url("/data/a/b/c"), 0o755)  # already there
    write(dav, "/data/file", b"x")
    with pytest.raises(GError) as caught:
        hctx.mkdir_rec(dav.url("/data/file"), 0o755)
    assert caught.value.code == errno.ENOTDIR


def test_mkdir_rec_in_one_request_when_the_server_makes_parents(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    dav.mkcol_parents = True
    hctx.mkdir_rec(dav.url("/data/x/y/z"), 0o755)
    assert dav.methods() == ["MKCOL"]


def test_mkdir_rec_races_and_failures(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    # The parent appears between the 409 and the second MKCOL: EEXIST is fine.
    dav.fault("MKCOL", path="/data/p/q", status=409)
    dav.fault("MKCOL", path="/data/p/q", status=405)
    dav.local("/data/p").mkdir()
    hctx.mkdir_rec(dav.url("/data/p/q"), 0o755)
    # ...but any other failure on the second try is reported.
    dav.fault("MKCOL", path="/data/r/s", status=409)
    dav.fault("MKCOL", path="/data/r/s", status=403)
    dav.local("/data/r").mkdir()
    with pytest.raises(GError) as caught:
        hctx.mkdir_rec(dav.url("/data/r/s"), 0o755)
    assert caught.value.code == errno.EPERM
    # A refusal on the first try is not walked around.
    dav.fault("MKCOL", status=403)
    with pytest.raises(GError):
        hctx.mkdir_rec(dav.url("/data/t"), 0o755)
    # A 409 at the root has nowhere further up to go.
    dav.fault("MKCOL", status=409)
    with pytest.raises(GError) as caught:
        hctx.mkdir_rec(dav.url("/"), 0o755)
    assert caught.value.code == errno.ENOENT


def test_rmdir(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    dav.local("/data/d").mkdir()
    hctx.rmdir(dav.url("/data/d"))
    assert not dav.local("/data/d").exists()
    assert dav.requests[-1].path == "/data/d/"
    root = f"dav://127.0.0.1:{dav.port}"  # no path at all: the collection is "/"
    with pytest.raises(GError) as caught:
        hctx.rmdir(root)
    assert caught.value.code == errno.EEXIST and caught.value.message.endswith(f"{root}/")
    write(dav, "/data/f", b"x")
    with pytest.raises(GError) as caught:
        hctx.rmdir(dav.url("/data/f"))
    assert (caught.value.code, caught.value.message) == (errno.ENOTDIR, "Can not rmdir a file")
    with pytest.raises(GError) as caught:
        hctx.rmdir(dav.url("/data/nope"))
    assert caught.value.message == "Result HTTP 404 : File not found  after 1 attempts"
    write(dav, "/data/full/child", b"x")
    with pytest.raises(GError) as caught:
        hctx.rmdir(dav.url("/data/full/"))
    assert caught.value.code == errno.EEXIST
    assert caught.value.message == (
        f"DavPosix::rmdir  HTTP 409 : Conflict, File Exist  with url {dav.url('/data/full/')}"
    )
    dav.fault("DELETE", status=403)
    with pytest.raises(GError) as caught:
        hctx.rmdir(dav.url("/data/full"))
    assert caught.value.message == "DavPosix::rmdir  HTTP 403 : Permission refused "


def test_unlink(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"x")
    hctx.unlink(dav.url("/data/f"))
    assert not dav.local("/data/f").exists()
    assert dav.methods() == ["PROPFIND", "DELETE"]
    with pytest.raises(GError) as caught:
        hctx.unlink(dav.url("/data/f"))
    assert caught.value.message == (
        "DavPosix::unlink  Result HTTP 404 : File not found  after 1 attempts"
    )
    with pytest.raises(GError) as caught:
        hctx.unlink(dav.url("/data"))
    assert caught.value.code == errno.EISDIR
    assert caught.value.message == (
        f"DavPosix::unlink   {dav.url('/data')} is a directory, impossible to unlink"
    )
    dav.fault("PROPFIND", status=403)
    with pytest.raises(GError) as caught:
        hctx.unlink(dav.url("/data/x"))
    assert caught.value.message == "DavPosix::unlink  HTTP 403 : Permission refused "
    write(dav, "/data/g", b"x")
    dav.fault("DELETE", status=423)
    with pytest.raises(GError) as caught:
        hctx.unlink(dav.url("/data/g"))
    assert caught.value.code == errno.EBUSY


def test_bulk_unlink(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/a", b"x")
    results = hctx.unlink([dav.url("/data/a"), dav.url("/data/b")])
    assert results[0] is None and isinstance(results[1], GError)


def test_rename(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/old", b"x")
    hctx.rename(dav.url("/data/old"), dav.url("/data/new"))
    assert dav.local("/data/new").read_bytes() == b"x"
    move = dav.requests[-1]
    assert move.header("Destination") == f"http://127.0.0.1:{dav.port}/data/new"
    with pytest.raises(GError) as caught:
        hctx.rename(dav.url("/data/old"), dav.url("/data/x"))
    assert caught.value.message == (f"HTTP 404 : File not found  with url {dav.url('/data/old')}")


def test_listdir_and_opendir(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/dir/a", b"1")
    write(dav, "/data/dir/b c", b"22")
    dav.local("/data/dir/sub").mkdir()
    assert sorted(hctx.listdir(dav.url("/data/dir"))) == ["a", "b c", "sub"]
    listing = dav.requests[-1]
    assert listing.header("Depth") == "1" and b"propfind" in listing.body
    directory = hctx.opendir(dav.url("/data/dir/"))
    found = {}
    while True:
        entry, info = directory.readpp()
        if entry is None:
            break
        assert info is not None
        found[entry.d_name] = (entry.d_type, info.st_size)
    assert found == {"a": (8, 1), "b c": (8, 2), "sub": (4, 4096)}


def test_listing_errors(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"x")
    with pytest.raises(GError) as caught:
        hctx.listdir(dav.url("/data/f"))
    assert (caught.value.code, caught.value.message) == (
        errno.ENOTDIR,
        f"{dav.url('/data/f')} is not a collection, listing impossible",
    )
    with pytest.raises(GError) as caught:
        hctx.listdir(dav.url("/data/nope"))
    assert (caught.value.code, caught.value.message) == (errno.ENOENT, "HTTP 404 : File not found ")


def test_listing_without_a_self_entry_drops_the_first(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    body = (
        b'<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">'
        b"<D:response><D:href>/elsewhere/</D:href><D:propstat><D:prop><D:resourcetype>"
        b"<D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status>"
        b"</D:propstat></D:response>"
        b"<D:response><D:href>http://h/elsewhere/child</D:href><D:propstat><D:prop>"
        b"<D:getcontentlength>3</D:getcontentlength></D:prop></D:propstat></D:response>"
        b"<D:response><D:href>/</D:href></D:response>"
        b"<D:response><D:propstat/></D:response>"
        b"</D:multistatus>"
    )
    dav.fault("PROPFIND", status=207, body=body)
    assert hctx.listdir(dav.url("/data/whatever")) == ["child"]


def test_hostile_xml_is_refused(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    dav.fault(
        "PROPFIND",
        status=207,
        body=b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>',
    )
    with pytest.raises(GError) as caught:
        hctx.listdir(dav.url("/data"))
    assert caught.value.code == errno.EPROTO
    dav.fault("PROPFIND", status=207, body=b'<?xml version="1.0"?><!ENTITY a "aaaa"><x/>')
    with pytest.raises(GError) as caught:
        hctx.listdir(dav.url("/data"))  # an entity with no DOCTYPE around it is refused too
    assert caught.value.code == errno.EPROTO
    dav.fault("PROPFIND", status=207, body=b'<D:multistatus xmlns:D="DAV:"/>')
    assert hctx.listdir(dav.url("/data")) == []  # nothing, not even the collection itself
    dav.fault("PROPFIND", status=207, body=b"<not xml")
    with pytest.raises(GError) as caught:
        hctx.listdir(dav.url("/data"))
    assert "Malformed" in caught.value.message


def test_propstat_statuses(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    body = (
        b'<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>/data/f'
        b"</D:href><D:propstat><D:prop><D:getcontentlength>99</D:getcontentlength></D:prop>"
        b"<D:status>HTTP/1.1 404 Not Found</D:status></D:propstat><D:propstat><D:prop>"
        b"<D:getcontentlength>7</D:getcontentlength><D:getlastmodified>not a date"
        b"</D:getlastmodified><D:creationdate>2024-01-02T03:04:05Z</D:creationdate>"
        b"</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
        b"</D:multistatus>"
    )
    dav.fault("PROPFIND", status=207, body=body)
    info = hctx.stat(dav.url("/data/f"))
    assert (info.st_size, info.st_mtime, info.st_ctime) == (7, 0, 1704164645)
    body = (
        b'<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>/data/f'
        b"</D:href><D:propstat><D:prop><D:getcontentlength/></D:prop></D:propstat>"
        b"</D:response></D:multistatus>"
    )
    dav.fault("PROPFIND", status=207, body=body)
    assert hctx.stat(dav.url("/data/f")).st_size == 0  # an empty property is no value


def test_chmod_is_not_supported(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    with pytest.raises(GError) as caught:
        hctx.chmod(dav.url("/data"), 0o755)
    assert caught.value.code == errno.EPROTONOSUPPORT


def test_xattrs(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    url = dav.url("/data")
    assert hctx.listxattr(url) == [
        "taperestapi.version",
        "taperestapi.uri",
        "taperestapi.sitename",
    ]
    with pytest.raises(GError) as caught:
        hctx.getxattr(url, "user.foo")
    assert (caught.value.code, caught.value.message) == (
        errno.ENODATA,
        'Failed to get the xattr "user.foo" (No data available)',
    )
    with pytest.raises(GError) as caught:
        hctx.setxattr(url, "user.foo", "x", 0)
    assert (caught.value.code, caught.value.message) == (
        errno.ENOSYS,
        "Can not set extended attributes",
    )


def test_access_and_lstat(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"x")
    assert hctx.access(dav.url("/data/f"), 4) == 0
    assert hctx.lstat(dav.url("/data/f")).st_size == 1
    with pytest.raises(GError) as caught:
        hctx.access(dav.url("/data/nope"), 4)
    assert caught.value.code == errno.ENOENT


def test_urls_are_quoted_and_tokens_kept_out_of_them(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path
) -> None:
    write(dav, "/data/with space", b"x")
    assert hctx.stat(dav.url("/data/with space")).st_size == 1
    assert dav.requests[-1].path == "/data/with%20space"
    assert hctx.stat(dav.url("/data/with%20space?x=1&authz=secret")).st_size == 1
    request = dav.requests[-1]
    assert request.path == "/data/with%20space?x=1"
    assert request.header("Authorization") == "Bearer secret"


def test_invalid_url(hctx: xgfalclient.Gfal2Context) -> None:
    with pytest.raises(GError) as caught:
        hctx.stat("davs:///no/host")
    assert caught.value.code == errno.EINVAL


def test_two_servers_in_one_context(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/a", b"1")
    write(dav2, "/data/b", b"22")
    assert hctx.stat(dav.url("/data/a")).st_size == 1
    assert hctx.stat(dav2.url("/data/b")).st_size == 2
