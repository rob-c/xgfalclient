# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""Open HTTP files, and checksums."""

from __future__ import annotations

import base64
import errno
import hashlib
import os
import zlib

import pytest

import xgfalclient
from test_http_helpers import dav, dav2, hctx, write  # noqa: F401 - fixtures
from xgfalclient import GError
from xgfalclient.checksum import crc32c
from xgfalclient.plugin import O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY
from xgfalclient.plugins.http import _dav
from xgfalclient.testing.webdav import WebDAVServer

WRITE = O_WRONLY | O_CREAT | O_TRUNC


def plugin(context: xgfalclient.Gfal2Context):  # type: ignore[no-untyped-def]
    return context.plugin("davs://h/", "open")


# -- reading ------------------------------------------------------------------------------


def test_sequential_reads_share_one_get(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"hello world")
    handle = hctx.open(dav.url("/data/f"), "r")
    assert handle.read(4) == "hell"
    assert handle.read_bytes(3) == b"o w"
    buffer = bytearray(100)
    assert handle.readinto(buffer) == 4
    assert bytes(buffer[:4]) == b"orld"
    assert handle.read(10) == ""
    assert handle.readinto(bytearray(0)) == 0
    handle.close()
    assert dav.methods() == ["PROPFIND", "GET"]


def test_seek_reopens_with_a_range(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"0123456789")
    handle = hctx.open(dav.url("/data/f"), "r")
    assert handle.read(2) == "01"
    assert handle.lseek(-3, os.SEEK_END) == 7
    assert handle.read(10) == "789"
    assert dav.requests[-1].header("Range") == "bytes=7-"
    handle.lseek(5, os.SEEK_SET)
    dav.ignore_range = True  # the server now answers 200 with the whole file
    assert handle.read(2) == "56"
    handle.close()


def test_pread(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"hello\n")
    handle = hctx.open(dav.url("/data/f"), "r")
    assert handle.pread(2, 3) == "llo"
    assert dav.requests[-1].header("Range") == "bytes=2-4"
    assert handle.pread_bytes(100, 3) == b""  # 416
    assert handle.pread_bytes(0, 0) == b""
    dav.ignore_range = True
    assert handle.pread_bytes(4, 10) == b"o\n"
    assert handle.pread_bytes(50, 2) == b""  # the skip runs off the end
    handle.close()


def test_short_and_refused_reads(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"0123456789")
    handle = hctx.open(dav.url("/data/f"), "r")
    dav.fault("GET", status=200, body=b"01234")  # shorter than the stat said
    assert handle.read(10) == "01234"
    handle.close()
    handle = hctx.open(dav.url("/data/f"), "r")
    dav.fault("GET", status=416)
    assert handle.read(3) == ""
    handle.close()
    handle = hctx.open(dav.url("/data/f"), "r")
    dav.fault("GET", status=403)
    with pytest.raises(GError) as caught:
        handle.read(3)
    assert caught.value.code == errno.EPERM


def test_open_errors(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    with pytest.raises(GError) as caught:
        hctx.open(dav.url("/data/nope"), "r")
    assert caught.value.message == "Result HTTP 404 : File not found  after 1 attempts"
    with pytest.raises(GError) as caught:
        hctx.open(dav.url("/data"), "r")
    assert caught.value.code == errno.EISDIR
    with pytest.raises(GError) as caught:
        plugin(hctx).open(dav.url("/data/x"), O_RDWR | O_CREAT)
    assert caught.value.code == errno.ENOTSUP


def test_readinto_past_the_end(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"abc")
    handle = plugin(hctx).open(dav.url("/data/f"), O_RDONLY)
    handle.lseek(10)
    assert handle.readinto(bytearray(4)) == 0
    assert handle.size() == 3
    handle.close()


# -- writing ------------------------------------------------------------------------------


def test_write_spools_then_puts(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    handle = hctx.open(dav.url("/data/w"), "w")
    assert handle.write("hello ") == 6
    assert handle.pwrite(b"world", 6) == 5
    with pytest.raises(GError) as caught:
        handle.pwrite(b"x", 0)
    assert caught.value.code == errno.ESPIPE
    handle.close()
    handle.close()
    assert dav.local("/data/w").read_bytes() == b"hello world"
    put = dav.requests[-1]
    assert (put.method, put.header("Content-Length"), put.header("Expect")) == (
        "PUT",
        "11",
        "100-continue",
    )


def test_streamed_upload_with_a_size(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    handle = plugin(hctx).open(dav.url("/data/s"), WRITE, 0o644, 10)
    handle.write(b"01234")
    handle.write(memoryview(b"56789"))
    with pytest.raises(GError) as caught:
        handle.write(b"!")
    assert caught.value.code == errno.EFBIG
    handle.close()
    assert dav.local("/data/s").read_bytes() == b"0123456789"


def test_large_upload_to_webdav_is_one_put(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    from xgfalclient.plugins.http import _s3

    monkeypatch.setattr(_s3, "MULTIPART_THRESHOLD", 4)  # multipart is for S3 only
    handle = plugin(hctx).open(dav.url("/data/big"), WRITE, 0o644, 10)
    handle.write(b"0123456789")
    handle.close()
    assert dav.local("/data/big").read_bytes() == b"0123456789"
    assert dav.methods()[-1:] == ["PUT"]


def test_empty_upload(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    plugin(hctx).open(dav.url("/data/empty"), WRITE, 0o644, 0).close()
    assert dav.local("/data/empty").read_bytes() == b""
    assert dav.requests[-1].header("Expect") is None


def test_short_upload_is_an_error(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    handle = plugin(hctx).open(dav.url("/data/s"), WRITE, 0o644, 10)
    handle.write(b"0123")
    with pytest.raises(GError) as caught:
        handle.close()
    assert caught.value.code == errno.EIO
    assert "after 4 of 10 bytes" in caught.value.message


def test_close_during_an_exception_abandons_the_upload(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    streamed = plugin(hctx).open(dav.url("/data/a"), WRITE, 0o644, 10)
    spooled = plugin(hctx).open(dav.url("/data/b"), WRITE)
    unstarted = plugin(hctx).open(dav.url("/data/c"), WRITE, 0o644, 10)
    streamed.write(b"01")
    spooled.write(b"01")
    try:
        raise RuntimeError("the source broke")
    except RuntimeError:
        streamed.close()
        spooled.close()
        unstarted.close()
    assert not dav.local("/data/b").exists()
    assert not dav.local("/data/c").exists()


def test_refused_upload(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    dav.fault("PUT", status=403)
    handle = hctx.open(dav.url("/data/r"), "w")
    handle.write("abc")
    with pytest.raises(GError) as caught:
        handle.close()
    assert caught.value.code == errno.EPERM
    # Refused before the body with a known size: the writes are dropped, the
    # verdict arrives on close.
    dav.fault("PUT", status=507)
    handle = plugin(hctx).open(dav.url("/data/r"), WRITE, 0o644, 3)
    handle.write(b"abc")
    with pytest.raises(GError) as caught:
        handle.close()
    assert (caught.value.code, caught.value.message) == (
        errno.EIO,  # davix has no errno for 507
        "HTTP 507 : Insufficient Storage ",
    )


def test_upload_to_a_missing_parent(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    handle = hctx.open(dav.url("/data/no/such/f"), "w")
    handle.write("x")
    with pytest.raises(GError) as caught:
        handle.close()
    # davix's words, but a PUT's 409 is a missing parent: ENOENT, never the
    # "File exists" that callers matching on it would read as an existing target.
    assert (caught.value.code, caught.value.message) == (
        errno.ENOENT,
        "HTTP 409 : Conflict, File Exist ",
    )


def test_upload_follows_a_redirect_before_the_body(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    dav.redirects["/data/moved"] = dav2.base
    handle = plugin(hctx).open(dav.url("/data/moved"), WRITE, 0o644, 3)
    handle.write(b"abc")
    handle.close()
    assert dav2.local("/data/moved").read_bytes() == b"abc"
    handle = hctx.open(dav.url("/data/moved2"), "w")
    handle.write("xyz")
    handle.close()
    assert dav2.local("/data/moved2").read_bytes() == b"xyz"


def test_upload_redirect_loop(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    dav.redirects["/data/loop"] = dav.base
    with pytest.raises(GError) as caught:
        plugin(hctx).open(dav.url("/data/loop"), WRITE, 0o644, 3).write(b"abc")
    assert caught.value.code == errno.ELOOP


# -- checksums ----------------------------------------------------------------------------


def test_checksums(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    data = b"hello\n"
    write(dav, "/data/f", data)
    url = dav.url("/data/f")
    assert hctx.checksum(url, "adler32") == f"{zlib.adler32(data):08x}"
    assert dav.requests[-1].method == "HEAD"
    assert dav.requests[-1].header("Want-Digest") == "adler32"
    assert hctx.checksum(url, "ADLER32") == "084b021f"
    assert dav.requests[-1].header("Want-Digest") == "ADLER32"  # as given, as davix sends it
    assert hctx.checksum(url, "md5") == hashlib.md5(data).hexdigest()
    assert hctx.checksum(url, "sha256") == hashlib.sha256(data).hexdigest()
    assert hctx.checksum(url, "crc32c") == f"{crc32c(data, 0):08x}"


def test_checksum_errors(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"x")
    url = dav.url("/data/f")
    for offset, length in ((1, 2), (0, 2)):
        with pytest.raises(GError) as caught:
            hctx.checksum(url, "adler32", offset, length)
        assert (caught.value.code, caught.value.message) == (
            errno.ENOTSUP,
            "HTTP does not support partial checksums",
        )
    with pytest.raises(GError) as caught:
        hctx.checksum(dav.url("/data/nope"), "adler32")
    assert (caught.value.code, caught.value.message) == (errno.ENOENT, "HTTP 404 : File not found ")
    with pytest.raises(GError) as caught:
        hctx.checksum(url, "sha512")
    assert (caught.value.code, caught.value.message) == (
        errno.ENOSYS,
        f"checksum calculation for sha512 not supported for {url}",
    )
    assert [r.method for r in dav.requests[-2:]] == ["HEAD", "GET"]


def test_checksum_from_a_get_only_server(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"hello\n")
    dav.digest_on_head = False
    assert hctx.checksum(dav.url("/data/f"), "adler32") == "084b021f"
    assert dav.requests[-1].header("Range") == "bytes=0-0"
    dav.fault("GET", status=403)
    with pytest.raises(GError) as caught:
        hctx.checksum(dav.url("/data/f"), "adler32")
    assert caught.value.code == errno.ENOSYS


def test_checksum_from_content_md5(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    digest = hashlib.md5(b"abc").digest()
    dav.fault("HEAD", status=200, headers={"Content-MD5": base64.b64encode(digest).decode()})
    assert hctx.checksum(dav.url("/data/f"), "MD5") == digest.hex()
    write(dav, "/data/f", b"abc")
    dav.fault("HEAD", status=200, headers={"Content-MD5": "!!not base64!!"})
    assert hctx.checksum(dav.url("/data/f"), "md5") == digest.hex()  # from the GET


def test_digest_header_parsing() -> None:
    assert _dav.digest_value("ADLER32=0A0B0C0D, md5=zzz", "adler32") == "0a0b0c0d"
    assert _dav.digest_value("ADLER32=0A0B0C0D, md5=zzz", "md5") == "zzz"
    assert _dav.digest_value("sha=qZk+NkcGgWq6PiVxeFDCbJzQ2J0=", "SHA1") == (
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    )
    assert _dav.digest_value("sha-256=" + "ab" * 32, "sha256") == "ab" * 32
    assert _dav.digest_value("md5=%%%", "md5") == "%%%"
    assert _dav.digest_value("garbage, md5", "md5") == ""
    assert _dav.digest_value("foo=YWJj", "foo") == "616263"


def test_date_parsing() -> None:
    assert _dav.epoch("") == 0
    assert _dav.epoch("Thu, 01 Jan 1970 00:01:00 GMT") == 60
    assert _dav.epoch("1970-01-01T00:02:00Z") == 120
    assert _dav.epoch("yesterday") == 0
    assert _dav.href_path("https://h/a%20b/") == "/a b/"
    assert _dav.href_path("") == "/"
