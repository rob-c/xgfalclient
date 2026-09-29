# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""Object stores through the http plugin: S3 (SigV4) and Google Cloud Storage (signed URLs)."""

from __future__ import annotations

import errno
import hashlib
import json
import os
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest

import xgfalclient
from test_http_helpers import dav2, hctx, make_server, write  # noqa: F401 - fixtures
from xgfalclient import GError
from xgfalclient.crypto.rsa import private_key_pem
from xgfalclient.plugin import O_CREAT, O_TRUNC, O_WRONLY
from xgfalclient.plugins.http import _client, _gcloud, _s3
from xgfalclient.testing.pki import test_key
from xgfalclient.testing.webdav import S3, WebDAVServer
from xgfalclient.url import parse

WRITE = O_WRONLY | O_CREAT | O_TRUNC
EMAIL = "svc@project.iam.gserviceaccount.com"


@pytest.fixture
def s3(tmp_path: Path, hctx: xgfalclient.Gfal2Context) -> Iterator[WebDAVServer]:
    server = make_server(tmp_path / "s3")
    server.s3 = S3()
    (server.root / "bucket").mkdir()
    hctx.set_opt_string("S3", "ACCESS_KEY", "AKIDTEST")
    hctx.set_opt_string("S3", "SECRET_KEY", "SECRETTEST")
    hctx.set_opt_boolean("S3", "ALTERNATE", True)
    yield server
    server.stop()


@pytest.fixture
def gcs(tmp_path: Path, hctx: xgfalclient.Gfal2Context) -> Iterator[WebDAVServer]:
    server = make_server(tmp_path / "gcs")
    key = test_key(5)
    server.s3 = S3(gcs_key=key.public, gcs_email=EMAIL)
    (server.root / "bucket").mkdir()
    account = tmp_path / "account.json"
    account.write_text(
        json.dumps({"client_email": EMAIL, "private_key": private_key_pem(key).decode()})
    )
    hctx.set_opt_string("GCLOUD", "JSON_AUTH_FILE", str(account))
    yield server
    server.stop()


def s3url(server: WebDAVServer, path: str, scheme: str = "s3") -> str:
    return server.url(path, scheme=scheme)


def plugin(context: xgfalclient.Gfal2Context):  # type: ignore[no-untyped-def]
    return context.plugin("davs://h/", "open")


# -- S3 -------------------------------------------------------------------------------------


def test_s3_namespace(hctx: xgfalclient.Gfal2Context, s3: WebDAVServer) -> None:
    write(s3, "/bucket/dir/a", b"1")
    write(s3, "/bucket/dir/sub/b", b"22")
    write(s3, "/bucket/top", b"333")
    assert hctx.stat(s3url(s3, "/bucket/top")).st_size == 3
    head = s3.requests[-1]
    assert head.method == "HEAD" and head.header("Authorization").startswith("AWS4-HMAC-SHA256 ")
    assert hctx.stat(s3url(s3, "/bucket/dir")).is_dir()
    assert hctx.stat(s3url(s3, "/bucket")).is_dir()
    with pytest.raises(GError) as caught:
        hctx.stat(s3url(s3, "/bucket/nope"))
    assert caught.value.message == "Result HTTP 404 : File not found  after 1 attempts"
    assert sorted(hctx.listdir(s3url(s3, "/bucket/dir"))) == ["a", "sub"]
    assert sorted(hctx.listdir(s3url(s3, "/bucket/"))) == ["dir", "top"]
    with pytest.raises(GError) as caught:
        hctx.listdir(s3url(s3, "/bucket/top"))
    assert caught.value.code == errno.ENOTDIR
    with pytest.raises(GError) as caught:
        hctx.listdir(s3url(s3, "/bucket/empty"))
    assert caught.value.code == errno.ENOENT
    with pytest.raises(GError) as caught:
        hctx.listdir(s3url(s3, "/nobucket/"))
    assert caught.value.code == errno.ENOENT
    hctx.mkdir(s3url(s3, "/bucket/newdir"), 0o755)
    put = s3.requests[-1]
    assert (put.method, put.path, put.header("Content-Length")) == ("PUT", "/bucket/newdir/", "0")
    assert hctx.stat(s3url(s3, "/bucket/newdir")).st_mode == 0o40755  # davix's mode
    assert hctx.stat(s3url(s3, "/bucket/newdir/")).st_mode == 0o40755  # the marker itself
    assert hctx.listdir(s3url(s3, "/bucket/newdir")) == []
    hctx.mkdir_rec(s3url(s3, "/bucket/x/y"), 0o755)
    assert s3.requests[-1].path == "/bucket/x/y/"
    assert hctx.stat(s3url(s3, "/bucket/top")).st_mode == 0o100755
    s3.fault("HEAD", status=200, headers={"Content-Length": "3"}, body=b"abc")
    assert hctx.stat(s3url(s3, "/bucket/x/")).st_mode == 0o100755  # "key/" with content
    s3.fault("PUT", status=403)
    with pytest.raises(GError) as caught:
        hctx.mkdir(s3url(s3, "/bucket/refused"), 0o755)
    assert caught.value.message == "HTTP 403 : Permission refused bucket creation failure"
    hctx.rmdir(s3url(s3, "/bucket/dir/sub"))
    with pytest.raises(GError) as caught:
        hctx.rmdir(s3url(s3, "/bucket/top"))
    assert caught.value.code == errno.ENOTDIR
    hctx.unlink(s3url(s3, "/bucket/top"))
    assert not s3.local("/bucket/top").exists()
    write(s3, "/bucket/zero", b"")
    assert hctx.stat(s3url(s3, "/bucket/zero")).st_size == 0
    (s3.root / "void").mkdir()
    assert hctx.listdir(s3url(s3, "/void/")) == []  # an empty bucket is an empty listing
    # Keys appear under the prefix between the listing and the stat that follows
    # an empty one: a directory after all, and still (just) empty.
    empty = b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>"
    s3.fault("GET", path="/bucket?", status=200, body=empty)
    assert hctx.listdir(s3url(s3, "/bucket/dir")) == []


def test_s3_streamed_into_parts(
    hctx: xgfalclient.Gfal2Context,
    s3: WebDAVServer,
    dav2: WebDAVServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_s3, "MULTIPART_THRESHOLD", 1500)
    monkeypatch.setattr(_s3, "PART_SIZE", 1000)
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "streamed")
    data = os.urandom(2500)
    write(dav2, "/data/big", data)
    hctx.filecopy(dav2.url("/data/big"), s3url(s3, "/bucket/big"))
    assert s3.local("/bucket/big").read_bytes() == data
    assert [r for r in s3.requests if "partNumber" in r.path]


def test_s3_rename(hctx: xgfalclient.Gfal2Context, s3: WebDAVServer) -> None:
    """A server-side copy, then a delete: davix's S3 move."""
    write(s3, "/bucket/dir/a", b"1")
    hctx.rename(s3url(s3, "/bucket/dir/a"), s3url(s3, "/bucket/dir/b"))
    assert s3.local("/bucket/dir/b").read_bytes() == b"1"
    assert not s3.local("/bucket/dir/a").exists()
    copy, delete = s3.requests[-2:]
    assert (copy.method, copy.header("x-amz-copy-source")) == ("PUT", "/bucket/dir/a")
    assert (delete.method, delete.path) == ("DELETE", "/bucket/dir/a")
    with pytest.raises(GError) as caught:
        hctx.rename(s3url(s3, "/bucket/dir/nope"), s3url(s3, "/bucket/dir/c"))
    assert (caught.value.code, caught.value.message) == (
        errno.EIO,
        "Received code 404 when trying to copy file - will not perform deletion",
    )
    with pytest.raises(GError) as caught:
        hctx.rename(s3url(s3, "/bucket/dir/b"), "s3://other.example/bucket/c")
    assert caught.value.code == errno.ENOSYS
    s3.fault("DELETE", status=403)
    with pytest.raises(GError) as caught:
        hctx.rename(s3url(s3, "/bucket/dir/b"), s3url(s3, "/bucket/dir/c"))
    assert caught.value.code == errno.EPERM
    hctx.set_opt_boolean("S3", "ALTERNATE", False)  # virtual-host style: the bucket is the host
    assert _s3_copy_source(hctx, "s3://bkt.127.0.0.1:1/k") == "/bkt/k"


def _s3_copy_source(context: xgfalclient.Gfal2Context, url: str) -> str:
    seen: list[str] = []

    def fake(plugin: object, old: str, new: str, **kwargs: object) -> None:
        seen.append(str(kwargs["source"]))

    original = _s3._swift.rename
    _s3._swift.rename = fake  # type: ignore[assignment]
    try:
        _s3.rename(plugin(context), url, url)
    finally:
        _s3._swift.rename = original  # type: ignore[assignment]
    return seen[0]


def test_s3_listing_pages(hctx: xgfalclient.Gfal2Context, s3: WebDAVServer) -> None:
    s3.s3.page_size = 2  # type: ignore[union-attr]
    for name in "abcde":
        write(s3, f"/bucket/p/{name}", b"x")
    write(s3, "/bucket/p/deeper/f", b"x")
    assert sorted(hctx.listdir(s3url(s3, "/bucket/p"))) == ["a", "b", "c", "d", "deeper", "e"]
    tokens = [r.path for r in s3.requests if "continuation-token" in r.path]
    assert len(tokens) == 2


def test_s3_listing_skips_the_odd_entries(hctx: xgfalclient.Gfal2Context, s3: WebDAVServer) -> None:
    body = (
        b"<ListBucketResult><CommonPrefixes><Prefix>p/</Prefix></CommonPrefixes>"
        b"<Contents><Key>p/</Key><Size>0</Size></Contents>"
        b"<Contents><Key>p/f</Key><Size>big</Size></Contents>"
        b"<Contents><Key>p/deeper/g</Key><Size>1</Size></Contents>"
        b"<IsTruncated>true</IsTruncated></ListBucketResult>"
    )
    s3.fault("GET", status=200, body=body)
    assert hctx.listdir(s3url(s3, "/bucket/p")) == ["f"]


def test_s3_virtual_host_style(hctx: xgfalclient.Gfal2Context, s3: WebDAVServer) -> None:
    hctx.set_opt_boolean("S3", "ALTERNATE", False)
    write(s3, "/bucket/k/a", b"1")
    # The "bucket" is now part of the key, under the server's root.
    assert hctx.listdir(s3url(s3, "/bucket/k")) == ["a"]
    assert s3.requests[-1].path.startswith("/?")


def test_s3_io_and_checksums(
    hctx: xgfalclient.Gfal2Context, s3: WebDAVServer, tmp_path: Path
) -> None:
    handle = hctx.open(s3url(s3, "/bucket/obj"), "w")
    handle.write("object data")
    handle.close()
    assert s3.local("/bucket/obj").read_bytes() == b"object data"
    assert hctx.open(s3url(s3, "/bucket/obj"), "r").read(100) == "object data"
    assert hctx.checksum(s3url(s3, "/bucket/obj"), "MD5") == hashlib.md5(b"object data").hexdigest()
    with pytest.raises(GError) as caught:
        hctx.checksum(s3url(s3, "/bucket/obj"), "adler32")
    assert caught.value.code == errno.ENOSYS
    with pytest.raises(GError) as caught:
        hctx.checksum(s3url(s3, "/bucket/nope"), "md5")
    assert caught.value.code == errno.ENOENT
    s3.fault("HEAD", status=200, headers={"ETag": '"abc-2"'})
    with pytest.raises(GError):
        hctx.checksum(s3url(s3, "/bucket/obj"), "md5")
    s3.fault("HEAD", status=200)  # no ETag at all
    with pytest.raises(GError) as caught:
        hctx.checksum(s3url(s3, "/bucket/obj"), "md5")
    assert caught.value.code == errno.ENOSYS
    s3.fault("HEAD", status=200, headers={"x-goog-hash": "md5=", "ETag": '"ABC"'})
    assert hctx.checksum(s3url(s3, "/bucket/obj"), "md5") == "abc"  # an empty hash is no hash
    response = plugin(hctx)._request(
        "PUT", s3url(s3, "/bucket/meta"), headers={"x-amz-meta-owner": "me"}, body=b"m"
    )
    assert response.body() == b"" and response.status == 201  # the header is signed, and checks
    assert "x-amz-meta-owner" in s3.requests[-1].header("Authorization")
    source = tmp_path / "up"
    source.write_bytes(b"uploaded")
    hctx.filecopy("file://" + str(source), s3url(s3, "/bucket/new/up"))
    assert s3.local("/bucket/new/up").read_bytes() == b"uploaded"
    hctx.filecopy(s3url(s3, "/bucket/new/up"), "file://" + str(tmp_path / "down"))
    assert (tmp_path / "down").read_bytes() == b"uploaded"


def test_s3_bad_keys_and_tokens(hctx: xgfalclient.Gfal2Context, s3: WebDAVServer) -> None:
    write(s3, "/bucket/f", b"x")
    hctx.set_opt_string("S3", "SECRET_KEY", "wrong")
    with pytest.raises(GError) as caught:
        hctx.stat(s3url(s3, "/bucket/f"))
    assert caught.value.code == errno.EPERM
    hctx.set_opt_string("S3", "SECRET_KEY", "SECRETTEST")
    s3.s3.token = "SESSION"  # type: ignore[union-attr]
    with pytest.raises(GError):
        hctx.stat(s3url(s3, "/bucket/f"))
    hctx.set_opt_string("S3", "TOKEN", "SESSION")
    assert hctx.stat(s3url(s3, "/bucket/f")).st_size == 1
    hctx.set_opt_string("S3", "SECRET_KEY", "")
    with pytest.raises(GError) as caught:
        hctx.stat(s3url(s3, "/bucket/f"))  # half a key pair is none: unsigned
    assert caught.value.code == errno.EPERM
    assert s3.requests[-1].header("Authorization") is None
    hctx.set_opt_string("S3", "SECRET_KEY", "SECRETTEST")
    hctx.set_opt_string("S3", "ACCESS_KEY", "SOMEONEELSE")
    with pytest.raises(GError):
        hctx.stat(s3url(s3, "/bucket/f"))
    hctx.remove_opt("S3", "ACCESS_KEY")
    with pytest.raises(GError) as caught:
        hctx.stat(s3url(s3, "/bucket/f"))  # unsigned
    assert caught.value.code == errno.EPERM


def test_s3_keys_per_host(hctx: xgfalclient.Gfal2Context, s3: WebDAVServer) -> None:
    hctx.remove_opt("S3", "ACCESS_KEY")
    group = "S3:127.0.0.1"
    hctx.set_opt_string(group, "ACCESS_KEY", "AKIDTEST")
    hctx.set_opt_string(group, "SECRET_KEY", "SECRETTEST")
    hctx.set_opt_string(group, "REGION", "eu-west-1")
    s3.s3.region = "eu-west-1"  # type: ignore[union-attr]
    write(s3, "/bucket/f", b"xyz")
    assert hctx.stat(s3url(s3, "/bucket/f")).st_size == 3
    assert "eu-west-1" in s3.requests[-1].header("Authorization")
    hctx.remove_opt(group, "REGION")
    hctx.set_opt_string("S3", "REGION", "eu-west-1")  # the [S3] region, for want of the host's
    assert hctx.stat(s3url(s3, "/bucket/f")).st_size == 3
    assert "eu-west-1" in s3.requests[-1].header("Authorization")
    # Keys make no https:// URL an S3 one: gfal2 sends it unsigned, as WebDAV.
    with pytest.raises(GError):
        hctx.stat(s3.url("/bucket/f", scheme="http"))
    assert s3.requests[-1].header("Authorization") is None


def test_s3_key_lookup_units(hctx: xgfalclient.Gfal2Context) -> None:
    options = hctx.options
    host = parse("s3://bucket.s3.example:9000/k")
    assert _s3.s3_keys(options, host) is None
    options.set_string("S3:BUCKET.S3.EXAMPLE", "ACCESS_TOKEN", "LEGACY")  # half a legacy pair
    options.set_string("S3:BUCKET.S3.EXAMPLE", "TOKEN", "SESSION")
    assert _s3.s3_keys(options, host) is None
    options.set_string("S3:S3.EXAMPLE", "SECRET_KEY", "S")  # completes it on the next group
    options.set_string("S3:S3.EXAMPLE", "TOKEN", "IGNORED")
    keys = _s3.s3_keys(options, host)
    assert keys is not None
    assert (keys.access_key, keys.secret_key, keys.token) == ("LEGACY", "S", "SESSION")
    assert keys.region == "us-east-1"
    options.set_string("S3", "ACCESS_TOKEN", "HALF")  # half a legacy pair, last of all
    assert _s3.s3_keys(options, parse("s3://elsewhere/k")) is None


def test_s3_groups_and_legacy_names(hctx: xgfalclient.Gfal2Context, s3: WebDAVServer) -> None:
    """``[S3:<host less its first label>]`` - a virtual-host bucket's endpoint - and old names."""
    hctx.remove_opt("S3", "ACCESS_KEY")
    hctx.remove_opt("S3", "SECRET_KEY")
    hctx.remove_opt("S3", "ALTERNATE")
    write(s3, "/bucket/f", b"xyz")
    hctx.set_opt_string("S3:0.0.1", "ACCESS_TOKEN", "AKIDTEST")  # 127.0.0.1 less "127."
    hctx.set_opt_string("S3:0.0.1", "ACCESS_TOKEN_SECRET", "SECRETTEST")
    hctx.set_opt_boolean("S3:0.0.1", "ALTERNATE", True)
    hctx.set_opt_string("S3:127.0.0.1", "ALTERNATE", "neither")  # not a boolean: skipped
    assert hctx.stat(s3url(s3, "/bucket/f")).st_size == 3
    assert "Credential=AKIDTEST/" in s3.requests[-1].header("Authorization")
    # The session token may come from a broader group than the keys.
    s3.s3.token = "SESSION"  # type: ignore[union-attr]
    hctx.set_opt_string("S3", "TOKEN", "SESSION")
    assert hctx.stat(s3url(s3, "/bucket/f")).st_size == 3
    keys = _s3.s3_keys(hctx.options, parse("s3://h/b"))
    assert keys is None  # a host with no dot has no such group, and [S3] has no keys


def test_s3_multipart(
    hctx: xgfalclient.Gfal2Context,
    s3: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_s3, "MULTIPART_THRESHOLD", 1500)
    monkeypatch.setattr(_s3, "PART_SIZE", 1000)
    data = os.urandom(3500)
    source = tmp_path / "big"
    source.write_bytes(data)
    hctx.filecopy("file://" + str(source), s3url(s3, "/bucket/mp1"))
    assert s3.local("/bucket/mp1").read_bytes() == data
    parts = [r for r in s3.requests if "partNumber" in r.path]
    assert len(parts) == 4
    writer = plugin(hctx).open(s3url(s3, "/bucket/mp2"), WRITE, 0o644, len(data))
    writer.write(data[:1200])
    writer.pwrite(data[1200:], 1200)
    with pytest.raises(GError) as caught:
        writer.pwrite(b"x", 0)
    assert caught.value.code == errno.ESPIPE
    writer.close()
    writer.close()
    assert s3.local("/bucket/mp2").read_bytes() == data
    spooled = hctx.open(s3url(s3, "/bucket/mp3"), "w")
    spooled.write(data)
    spooled.close()
    assert s3.local("/bucket/mp3").read_bytes() == data
    empty = plugin(hctx).open(s3url(s3, "/bucket/mp4"), WRITE, 0o644, 2000)
    empty.close()
    assert s3.local("/bucket/mp4").read_bytes() == b""
    # A URL with a query of its own keeps it on every multipart call; a bare "?" adds nothing.
    for suffix in ("?versioning=x", "?"):
        s3.clear()
        writer = plugin(hctx).open(s3url(s3, "/bucket/mp5" + suffix), WRITE, 0o644, 2000)
        writer.write(data[:2000])
        writer.close()
        assert s3.local("/bucket/mp5").read_bytes() == data[:2000]
        paths = [r.path for r in s3.requests if r.method in ("POST", "PUT")]
        assert all(p.startswith("/bucket/mp5" + suffix.rstrip("?")) for p in paths)
        assert all(("versioning=x&" in p) == (suffix != "?") for p in paths)


def test_s3_multipart_failures(
    hctx: xgfalclient.Gfal2Context,
    s3: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_s3, "MULTIPART_THRESHOLD", 10)
    monkeypatch.setattr(_s3, "PART_SIZE", 10)
    source = tmp_path / "big"
    source.write_bytes(b"x" * 25)
    url = s3url(s3, "/bucket/mp")
    uploads = s3.s3.uploads  # type: ignore[union-attr]
    s3.fault("POST", status=500)
    with pytest.raises(GError):
        hctx.filecopy("file://" + str(source), url)
    for reply in (b"<InitiateMultipartUploadResult/>", b"<Result><UploadId/></Result>"):
        s3.fault("POST", status=200, body=reply)
        with pytest.raises(GError) as caught:
            hctx.filecopy("file://" + str(source), url)
        assert caught.value.code == errno.EPROTO
    s3.fault("PUT", path="/bucket/mp?partNumber", status=500)
    s3.fault("DELETE", status=500)  # the abort fails too, and that is ignored
    with pytest.raises(GError):
        hctx.filecopy("file://" + str(source), url)
    assert uploads
    uploads.clear()
    # Complete answers 200 with an <Error> inside, as S3 is allowed to.
    s3.fault("POST", path="/bucket/mp?uploadId", status=200, body=b"<Error>x</Error>")
    writer = plugin(hctx).open(url, WRITE, 0o644, 30)
    writer.write(b"y" * 30)
    with pytest.raises(GError):
        writer.close()
    assert not uploads
    s3.fault("POST", path="/bucket/mp?uploadId", status=503)
    writer = plugin(hctx).open(url, WRITE, 0o644, 30)
    writer.write(b"y" * 30)
    with pytest.raises(GError) as caught:
        writer.close()
    assert (caught.value.code, caught.value.message) == (
        errno.EIO,
        "HTTP 503 : Unexpected server error: 503 ",
    )
    uploads.clear()
    writer = plugin(hctx).open(url, WRITE, 0o644, 30)
    s3.fault("PUT", status=403)
    with pytest.raises(GError):
        writer.write(b"z" * 30)
    writer.close()  # already abandoned
    writer = plugin(hctx).open(url, WRITE, 0o644, 30)
    writer.write(b"z" * 5)
    try:
        raise RuntimeError("source failed")
    except RuntimeError:
        writer.close()
    assert not uploads


def test_s3_presigned_urls() -> None:
    keys = _s3.S3Keys(
        "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "us-east-1"
    )
    when = datetime(2013, 5, 24, tzinfo=timezone.utc)
    url = _s3.S3Signer(keys).presign(
        "GET", "s3s://examplebucket.s3.amazonaws.com/test.txt", 86400, when=when
    )
    # AWS's published example for query-string authentication.
    assert url.endswith(
        "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    )
    assert url.startswith("https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=")
    assert "secret" not in repr(keys).lower() or "redacted" in repr(keys)
    session = _s3.S3Keys("A", "B", "TOK", "us-east-1")
    assert "X-Amz-Security-Token=TOK" in _s3.S3Signer(session).presign("GET", "s3://h/b/k")


def test_s3_tpc_with_presigned_urls(
    hctx: xgfalclient.Gfal2Context, s3: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(s3, "/bucket/src", b"from s3")
    hctx.filecopy(s3url(s3, "/bucket/src"), dav2.url("/data/dst"))
    assert dav2.local("/data/dst").read_bytes() == b"from s3"
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert "X-Amz-Signature=" in copy_request.header("Source")
    assert copy_request.header("Credential") == "none"
    assert copy_request.header("Copy-Flags") == "NoHead"  # davix's hint for lcgdm-dav
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "3rd push")
    write(dav2, "/data/back", b"to s3")
    hctx.filecopy(dav2.url("/data/back"), s3url(s3, "/bucket/back"))
    assert s3.local("/bucket/back").read_bytes() == b"to s3"


def test_presigned_url_is_not_signed_again(
    hctx: xgfalclient.Gfal2Context, s3: WebDAVServer
) -> None:
    write(s3, "/bucket/f", b"abc")
    signer = hctx.plugin("davs://h/", "stat").presigner_for(s3url(s3, "/bucket/f"))
    presigned = signer.presign("GET", s3url(s3, "/bucket/f"))
    response = hctx.plugin("davs://h/", "stat")._request("GET", presigned)
    assert (response.status, response.body()) == (200, b"abc")
    assert s3.requests[-1].header("Authorization") is None


# -- Google Cloud Storage ---------------------------------------------------------------------


def test_gcs(hctx: xgfalclient.Gfal2Context, gcs: WebDAVServer, tmp_path: Path) -> None:
    gcs.s3.page_size = 2  # type: ignore[union-attr]
    for name in "abc":
        write(gcs, f"/bucket/d/{name}", name.encode() * 3)
    url = gcs.url("/bucket/d/a", scheme="gcloud")
    assert hctx.stat(url).st_size == 3
    assert "X-Goog-Signature=" in gcs.requests[-1].path
    assert sorted(hctx.listdir(gcs.url("/bucket/d", scheme="gcloud"))) == ["a", "b", "c"]
    assert any("marker=" in r.path for r in gcs.requests)
    assert not any("list-type" in r.path for r in gcs.requests)
    assert hctx.checksum(url, "md5") == hashlib.md5(b"aaa").hexdigest()
    crc = hctx.checksum(url, "crc32c")
    assert len(crc) == 8
    with pytest.raises(GError):
        hctx.checksum(url, "adler32")
    handle = hctx.open(gcs.url("/bucket/new", scheme="gcloud"), "w")
    handle.write("to gcs")
    handle.close()
    assert gcs.local("/bucket/new").read_bytes() == b"to gcs"
    hctx.unlink(gcs.url("/bucket/new", scheme="gcloud"))
    hctx.mkdir(gcs.url("/bucket/newdir", scheme="gcloud"), 0o755)
    hctx.rename(url, gcs.url("/bucket/d/moved", scheme="gcloud"))  # path-style, always
    assert gcs.local("/bucket/d/moved").read_bytes() == b"aaa"
    url = gcs.url("/bucket/d/moved", scheme="gcloud")
    gcs.fault("HEAD", status=200, headers={"x-goog-hash": "crc32c=!!!", "ETag": '"x-1"'})
    with pytest.raises(GError):
        hctx.checksum(url, "crc32c")


def test_gcs_large_uploads_are_single_puts(
    hctx: xgfalclient.Gfal2Context,
    gcs: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_s3, "MULTIPART_THRESHOLD", 10)
    source = tmp_path / "f"
    source.write_bytes(b"x" * 100)
    hctx.filecopy("file://" + str(source), gcs.url("/bucket/f", scheme="gcloud"))
    assert not [r for r in gcs.requests if "uploads" in r.path]
    writer = plugin(hctx).open(gcs.url("/bucket/g", scheme="gcloud"), WRITE, 0o644, 20)
    writer.write(b"y" * 20)
    writer.close()
    assert gcs.local("/bucket/g").read_bytes() == b"y" * 20


def test_gcs_tpc(hctx: xgfalclient.Gfal2Context, gcs: WebDAVServer, dav2: WebDAVServer) -> None:
    write(gcs, "/bucket/src", b"from gcs")
    hctx.filecopy(gcs.url("/bucket/src", scheme="gcloud"), dav2.url("/data/dst"))
    assert dav2.local("/data/dst").read_bytes() == b"from gcs"


def test_gcs_credentials(hctx: xgfalclient.Gfal2Context, gcs: WebDAVServer, tmp_path: Path) -> None:
    url = gcs.url("/bucket/f", scheme="gcloud")
    write(gcs, "/bucket/f", b"x")
    account = json.dumps(
        {"client_email": EMAIL, "private_key": private_key_pem(test_key(5)).decode()}
    )
    hctx.remove_opt("GCLOUD", "JSON_AUTH_FILE")
    hctx.set_opt_string("GCLOUD", "JSON_AUTH_STRING", account)
    assert hctx.stat(url).st_size == 1
    hctx.remove_opt("GCLOUD", "JSON_AUTH_STRING")
    with pytest.raises(GError) as caught:
        hctx.stat(url)  # unsigned: the bucket is not public
    assert caught.value.code == errno.EPERM
    stranger = json.loads(account) | {"client_email": "other@project.iam.gserviceaccount.com"}
    hctx.set_opt_string("GCLOUD", "JSON_AUTH_STRING", json.dumps(stranger))
    with pytest.raises(GError) as caught:
        hctx.stat(url)  # signed, by an account the bucket does not know
    assert caught.value.code == errno.EPERM
    cases = {
        "{nope": "Failed to load configured GCloud credentials",
        "[1]": "is not a JSON object",
        json.dumps({"client_email": EMAIL}): "Could not find private_key",
        json.dumps({"client_email": "", "private_key": "x"}): "Could not find client_email",
        json.dumps({"client_email": EMAIL, "private_key": "garbage"}): "Failed to load",
    }
    for text, words in cases.items():
        hctx.set_opt_string("GCLOUD", "JSON_AUTH_STRING", text)
        with pytest.raises(GError) as caught:
            hctx.stat(url)
        assert words in caught.value.message
        assert caught.value.code == errno.EINVAL
    hctx.remove_opt("GCLOUD", "JSON_AUTH_STRING")
    hctx.set_opt_string("GCLOUD", "JSON_AUTH_FILE", str(tmp_path / "missing.json"))
    with pytest.raises(GError) as caught:
        hctx.stat(url)
    assert caught.value.code == errno.ENOENT
    assert "Could not read gcloud credentials" in caught.value.message


def test_gcs_credentials_unreadable_without_an_errno(
    hctx: xgfalclient.Gfal2Context, gcs: WebDAVServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*args: object, **kwargs: object) -> object:
        raise OSError("refused")

    monkeypatch.setattr(_gcloud, "open", refuse, raising=False)
    with pytest.raises(GError) as caught:
        hctx.stat(gcs.url("/bucket/f", scheme="gcloud"))
    assert caught.value.code == errno.EIO
    assert "Could not read gcloud credentials" in caught.value.message


def test_gcloud_helpers() -> None:
    keys = _gcloud.load_keys(
        json.dumps({"client_email": EMAIL, "private_key": private_key_pem(test_key(5)).decode()}),
        "inline",
    )
    assert "redacted" in repr(keys)
    signer = _gcloud.GCloudSigner(keys)
    url = signer.presign("GET", "gclouds://storage.googleapis.com/b/k", expires=10**9)
    assert "X-Goog-Expires=604800" in url and url.startswith("https://storage.googleapis.com/b/k?")
    target = _client.Target.of("gcloud://h/b/k", s3=True)
    assert signer.sign("GET", target, {}, None) == {}
    when = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    signed = signer.signed_path("GET", target, when=when)
    assert "X-Goog-Date=20240102T030405Z" in signed
    assert "X-Goog-Credential=" + EMAIL.replace("@", "%40") + "%2F20240102%2F" in signed
    assert _gcloud.is_gcloud("gclouds") and not _gcloud.is_gcloud("s3")
