"""The HTTP transport: pooling, retries, redirects, credentials, 100-continue, errors."""

from __future__ import annotations

import errno
import socket
import ssl
from pathlib import Path

import pytest
from xrdhttp.connection import IncompleteRead, RemoteDisconnected
from xrdhttp.session import Failure, Route
from xrdhttp.wire import DIRECT_READ, ShortFileError

import xgfalclient
from test_http_helpers import dav as dav
from test_http_helpers import dav2 as dav2
from test_http_helpers import davs as davs
from test_http_helpers import davs_open as davs_open
from test_http_helpers import hctx as hctx
from test_http_helpers import write
from xgfalclient import GError
from xgfalclient.errors import ECOMM
from xgfalclient.plugins.http import _client
from xgfalclient.plugins.http._client import (
    FileBody,
    HTTPClient,
    Target,
    TransportError,
    Upload,
    config_group,
    davix_status,
    status_text,
    transport_error,
    wire_url,
)
from xgfalclient.plugins.http.plugin import HTTPPlugin
from xgfalclient.testing.pki import PKI
from xgfalclient.testing.webdav import WebDAVServer


def plugin(context: xgfalclient.Gfal2Context) -> HTTPPlugin:
    found = context.plugin("davs://h/", "stat")
    assert isinstance(found, HTTPPlugin)
    return found


# -- pooling --------------------------------------------------------------------------------


def test_keep_alive_off(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    hctx.set_opt_boolean("HTTP PLUGIN", "KEEP_ALIVE", False)
    write(dav, "/data/f", b"x")
    for _ in range(3):
        hctx.stat(dav.url("/data/f"))
    assert dav.connections == 3
    assert dav.requests[-1].header("Connection") == "close"


def test_idle_connections_are_capped(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_client, "MAX_IDLE", 2)
    write(dav, "/data/f", b"x")
    responses = [plugin(hctx)._request("GET", dav.url("/data/f")) for _ in range(3)]
    for response in responses:
        assert response.body() == b"x"
    assert plugin(hctx).client.idle_count() == 2


def test_a_server_that_keeps_hanging_up_is_an_error(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    """One replacement is the shared suite's; a server that keeps hanging up is an error."""
    write(dav, "/data/f", b"x")
    hctx.stat(dav.url("/data/f"))
    dav.fault("PROPFIND", drop=True, times=50)
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/data/f"))
    assert caught.value.code == errno.ECONNRESET or caught.value.message.startswith("Result")


def test_truncated_propfind_body_is_retried(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    write(dav, "/data/f", b"payload")
    dav.fault("PROPFIND", status=207, body=b"x" * 100, truncate=10)
    assert hctx.stat(dav.url("/data/f")).st_size == 7
    assert dav.methods().count("PROPFIND") == 2


def test_stale_connection_on_an_upload(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"x")
    hctx.stat(dav.url("/data/f"))
    dav.fault("PUT", drop=True)
    handle = plugin(hctx).open(dav.url("/data/up"), 0o1101, 0o644, 3)  # O_WRONLY|O_CREAT|O_TRUNC
    handle.write(b"abc")
    handle.close()
    assert dav.local("/data/up").read_bytes() == b"abc"
    dav.fault("PUT", drop=True, times=2)
    with pytest.raises(GError) as caught:
        plugin(hctx).client.upload(dav.url("/data/up2"), 3)
    assert "Connection terminated abruptly" in caught.value.message


def test_hang_up_on_a_fresh_upload_is_not_retried(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    dav.fault("PUT", drop=True)  # once: a retry would have succeeded
    with pytest.raises(GError) as caught:
        plugin(hctx).client.upload(dav.url("/data/up"), 3)
    assert "Connection terminated abruptly" in caught.value.message
    assert dav.connections == 1


def test_timeout(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    hctx.set_opt_integer("HTTP PLUGIN", "OPERATION_TIMEOUT", 1)
    dav.fault("PROPFIND", delay=1.5, status=207)
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/data"))
    assert (caught.value.code, caught.value.message) == (
        errno.ETIMEDOUT,
        "Result Connection timed out after 1 attempts",
    )


def test_truncated_bodies(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"0123456789")
    dav.fault("GET", status=200, body=b"0123456789", truncate=4)
    with pytest.raises(GError) as caught:
        plugin(hctx)._request("GET", dav.url("/data/f")).read()
    assert caught.value.code == ECOMM
    dav.fault("GET", status=200, body=b"0123456789", truncate=4)
    hctx.set_opt_integer("CORE", "CONN_RETRY", 0)  # with resume off, the drop surfaces
    handle = hctx.open(dav.url("/data/f"), "r")
    with pytest.raises(GError):
        handle.read(10)
    hctx.set_opt_integer("CORE", "CONN_RETRY", 3)
    # http.client reads a body cut short as a quiet end of file, and lets go of
    # its stream: a large readinto afterwards must not go looking for it.
    dav.fault("GET", body=b"0123456789", truncate=4)  # the status defaults to 200
    response = plugin(hctx)._request("GET", dav.url("/data/f"))
    assert response.read(100) == b"0123"
    with pytest.raises(GError) as caught:
        response.read(100)  # http.client lets go of its stream at the early end
    assert "6 bytes of the body never arrived" in caught.value.message
    with pytest.raises(GError) as caught:
        response.readinto(bytearray(DIRECT_READ))  # and a large read does not look for it
    assert "6 bytes of the body never arrived" in caught.value.message


def test_unread_bodies(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/small", b"s" * 100)
    write(dav, "/data/big", b"b" * 100_000)
    client = plugin(hctx).client
    plugin(hctx)._request("GET", dav.url("/data/small")).close()  # drained, kept
    assert client.idle_count() == 1
    plugin(hctx)._request("GET", dav.url("/data/big")).close()  # too much to drain
    assert client.idle_count() == 0
    dav.fault("GET", status=200, headers={"Connection": "close"}, body=b"abc")
    response = plugin(hctx)._request("GET", dav.url("/data/small"))
    assert response.readinto(bytearray()) == 0  # nothing asked for is not an end of file
    assert response.body() == b"abc"
    assert client.idle_count() == 0
    response.close()  # idempotent


# -- redirects ------------------------------------------------------------------------------


def test_redirects(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer) -> None:
    write(dav2, "/data/f", b"there")
    dav.redirect_prefixes["/data/f"] = dav2.base
    handle = hctx.open(dav.url("/data/f"), "r")
    assert handle.read(10) == "there"
    handle.close()
    write(dav, "/data/g", b"here")
    dav.fault("GET", path="/data/rel", status=302, headers={"Location": "/data/g"})
    assert plugin(hctx)._request("GET", dav.url("/data/rel")).body() == b"here"
    dav.fault("PUT", path="/data/see", status=303, headers={"Location": "/data/g"})
    response = plugin(hctx)._request("PUT", dav.url("/data/see"), body=b"xyz")
    assert (response.status, response.body()) == (200, b"here")
    assert dav.requests[-1].method == "GET"
    dav.fault("GET", path="/data/nowhere", status=302)  # no Location: the answer itself
    with plugin(hctx)._request("GET", dav.url("/data/nowhere")) as response:
        assert response.status == 302
    dav.fault("GET", path="/data/rel", status=302, headers={"Location": "/data/g"})
    response = plugin(hctx).client.request("GET", dav.url("/data/rel"), follow=False)
    assert (response.status, response.header("Location")) == (302, "/data/g")
    response.close()
    dav.redirect_prefixes["/data/loop"] = dav.base
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/data/loop"))
    assert caught.value.code == errno.ELOOP


def test_tokens_follow_redirects_but_not_into_clear_text(
    hctx: xgfalclient.Gfal2Context,
    davs_open: WebDAVServer,
    dav: WebDAVServer,
    dav2: WebDAVServer,
    grid_env: PKI,
) -> None:
    write(dav, "/data/f", b"x")
    hctx.cred_set("davs://", hctx.cred_new("BEARER", "SECRET"))
    davs_open.redirect_prefixes["/data/"] = f"http://localhost:{dav.port}"
    hctx.stat(davs_open.url("/data/f"))
    assert davs_open.requests[-1].header("Authorization") == "Bearer SECRET"
    assert dav.requests[-1].header("Authorization") is None
    write(davs_open, "/moved/data/f", b"x")
    moved = davs_open.base.replace("127.0.0.1", "localhost") + "/moved"
    davs_open.redirect_prefixes["/data/"] = moved
    hctx.stat(davs_open.url("/data/f"))
    assert davs_open.requests[-1].header("Authorization") == "Bearer SECRET"  # still TLS
    davs_open.redirect_prefixes["/data/"] = f"http://127.0.0.1:{dav.port}"
    hctx.stat(davs_open.url("/data/f"))
    assert dav.requests[-1].header("Authorization") == "Bearer SECRET"  # same host
    # From plain http, another host is no worse off than the first.
    hctx.cred_set("dav://", hctx.cred_new("BEARER", "CLEAR"))
    dav.redirect_prefixes["/data/"] = f"http://localhost:{dav2.port}"
    write(dav2, "/data/f", b"x")
    hctx.stat(dav.url("/data/f"))
    assert dav2.requests[-1].header("Authorization") == "Bearer CLEAR"


# -- credentials and headers --------------------------------------------------------------


def test_identity_headers(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    hctx.set_user_agent("fts", "3.14")
    hctx.add_client_info("job-id", "42")
    hctx.set_opt_string_list("HTTP PLUGIN", "HEADERS", ["X-Site: here", "nocolon", ": noname"])
    hctx.stat(dav.url("/data"))
    request = dav.requests[-1]
    assert request.header("User-Agent") == "fts/3.14 gfal2/2.23.5"
    assert request.header("ClientInfo") == "job-id=42"
    assert request.header("X-Site") == "here"
    assert request.header("nocolon") is None
    # The endpoint's own group replaces the plugin's list rather than adding to it.
    hctx.set_opt_string_list("DAV:127.0.0.1", "HEADERS", ["X-Host: yes"])
    hctx.stat(dav.url("/data"))
    request = dav.requests[-1]
    assert (request.header("X-Host"), request.header("X-Site")) == ("yes", None)


def test_header_groups_are_named_as_gfal2_names_them(
    hctx: xgfalclient.Gfal2Context, davs_open: WebDAVServer, grid_env: PKI
) -> None:
    hctx.set_opt_string_list("DAVS:127.0.0.1", "HEADERS", ["X-Wrong: davs"])
    hctx.set_opt_string_list("HTTP:127.0.0.1", "HEADERS", ["X-Right: http"])
    hctx.stat(davs_open.url("/data", scheme="https"))
    request = davs_open.requests[-1]
    assert (request.header("X-Right"), request.header("X-Wrong")) == ("http", None)
    hctx.stat(davs_open.url("/data"))  # davs is [DAV:HOST], which has none: the plugin's
    assert davs_open.requests[-1].header("X-Right") is None


def test_basic_auth(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    dav.basic = ("alice", "s3cret")
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/data"))
    assert caught.value.code == errno.EACCES
    hctx.cred_set(dav.url("/"), hctx.cred_new("USER", "alice"))
    hctx.cred_set(dav.url("/"), hctx.cred_new("PASSWD", "s3cret"))
    assert hctx.stat(dav.url("/data")).is_dir()
    hctx.cred_clean()
    url = f"dav://alice:s3cret@127.0.0.1:{dav.port}/data"
    assert hctx.stat(url).is_dir()


def test_bearer_token_keyed_by_host(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    """FTS sets tokens for a bare host name; a URL-prefix one still comes first."""
    dav.tokens = {"HOST", "PREFIX"}
    hctx.cred_set("127.0.0.1", hctx.cred_new("BEARER", "HOST"))
    assert hctx.stat(dav.url("/data")).is_dir()
    assert dav.requests[-1].header("Authorization") == "Bearer HOST"
    hctx.cred_set(dav.url("/data"), hctx.cred_new("BEARER", "PREFIX"))
    assert hctx.stat(dav.url("/data")).is_dir()
    assert dav.requests[-1].header("Authorization") == "Bearer PREFIX"


def test_tokens_in_the_url_stay_in_the_url(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    """davix sends the query as it is, and adds no Authorization for it."""
    write(dav, "/data/f", b"x")
    hctx.stat(dav.url("/data/f?authz=Bearer%20T&x=1"))
    request = dav.requests[-1]
    assert request.target == "/data/f?authz=Bearer%20T&x=1"
    assert request.header("Authorization") is None


def test_a_doubled_slash_is_folded_on_the_wire(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    """StoRM answers ``400`` to ``/store//file``; the request line is folded
    (the query, here with an escaped slash, rides along untouched)."""
    write(dav, "/data/f", b"x")
    assert hctx.stat(dav.url("/data//f?x=a%2F%2Fb")).st_size == 1
    assert dav.requests[-1].target == "/data/f?x=a%2F%2Fb"


def test_presigned_urls_carry_their_own_credentials(hctx: xgfalclient.Gfal2Context) -> None:
    hctx.cred_set("dav://", hctx.cred_new("BEARER", "UNUSED"))
    client = HTTPClient(hctx)
    for query in ("X-Amz-Signature=abc", "AWSAccessKeyId=AKID&Signature=x"):
        auth = client.auth(f"dav://h/b/k?{query}")
        assert not auth.headers and auth.signer is None
    assert client.auth("dav://h/b/k?X-Amz-Credential=AKID").headers  # not signed after all


def test_x509_only_requests_leave_tokens_out(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    dav.tokens = {"GOOD"}
    hctx.cred_set(dav.url("/"), hctx.cred_new("BEARER", "GOOD"))
    response = plugin(hctx)._request("GET", dav.url("/data"), x509_only=True)
    assert response.status == 401
    response.close()
    assert dav.requests[-1].header("Authorization") is None


def test_x509_and_tokens_over_tls(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI
) -> None:
    davs.tokens = {"GOOD"}
    assert hctx.stat(davs.url("/data")).is_dir()  # the proxy in the handshake
    hctx.cred_set(davs.url("/"), hctx.cred_new("BEARER", "BAD"))
    with pytest.raises(GError) as caught:
        hctx.stat(davs.url("/data"))  # the server goes by the token it was given
    assert caught.value.code == errno.EACCES
    request = davs.requests[-1]
    # As gfal2 does, the certificate is presented alongside the token.
    assert request.header("Authorization") == "Bearer BAD" and request.peer is not None


def test_tls_verification(
    hctx: xgfalclient.Gfal2Context,
    davs_open: WebDAVServer,
    grid_env: PKI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("X509_CERT_DIR")
    with pytest.raises(GError) as caught:
        hctx.stat(davs_open.url("/data"))
    assert caught.value.code == errno.EACCES and "SSL handshake failed" in caught.value.message
    hctx.set_opt_boolean("HTTP PLUGIN", "INSECURE", True)
    hctx.cred_set(davs_open.url("/"), hctx.cred_new("BEARER", "T"))
    assert hctx.stat(davs_open.url("/data")).is_dir()


# -- 100-continue --------------------------------------------------------------------------


def _finished(upload: Upload, status: int) -> None:
    """Finish ``upload``, check the answer's status, and close the answer (and its connection)."""
    response = upload.finish()
    assert response.status == status
    response.close()


def test_upload_redirects_and_extras(
    hctx: xgfalclient.Gfal2Context, davs_open: WebDAVServer, dav: WebDAVServer, grid_env: PKI
) -> None:
    client = plugin(hctx).client
    # Headers go along, and the credential is the one for cred_url.
    hctx.cred_set(dav.url("/cred"), hctx.cred_new("BEARER", "FROM-CRED-URL"))
    upload = client.upload(
        dav.url("/data/a"), 2, headers={"X-Extra": "1"}, cred_url=dav.url("/cred")
    )
    upload.write(b"ab")
    _finished(upload, 201)
    request = dav.requests[-1]
    assert (request.header("X-Extra"), request.header("Authorization")) == (
        "1",
        "Bearer FROM-CRED-URL",
    )
    # From TLS to plain http on another host, before the body: no token goes along.
    hctx.cred_set("davs://", hctx.cred_new("BEARER", "SECRET"))
    davs_open.redirect_prefixes["/data/"] = f"http://localhost:{dav.port}"
    upload = client.upload(davs_open.url("/data/b"), 2)
    upload.write(b"cd")
    _finished(upload, 201)
    assert dav.local("/data/b").read_bytes() == b"cd"
    assert dav.requests[-1].header("Authorization") is None
    # A redirect status with no Location is the answer.
    dav.fault("PUT", status=302)
    upload = client.upload(dav.url("/data/c"), 2)
    _finished(upload, 302)


def test_empty_spooled_upload(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    hctx.open(dav.url("/data/empty"), "w").close()
    assert dav.local("/data/empty").read_bytes() == b""


def test_upload_that_hangs_up_before_the_body(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    dav.fault("PUT", drop=True, times=2)
    handle = hctx.open(dav.url("/data/x"), "w")
    handle.write("abc")
    with pytest.raises(GError) as caught:
        handle.close()
    assert "Connection terminated abruptly" in caught.value.message


def test_file_shorter_than_declared(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path
) -> None:
    source = tmp_path / "f"
    source.write_bytes(b"abc")
    with open(source, "rb") as handle, pytest.raises(GError) as caught:
        plugin(hctx)._put_file(dav.url("/data/x"), FileBody(handle, 0, 10), 10)
    assert caught.value.code == errno.EIO


# -- units: helpers -------------------------------------------------------------------------


def test_targets() -> None:
    target = Target.of("davs://[::1]:8443/a b?authz=T&x=1")
    assert (target.scheme, target.host, target.port) == ("https", "::1", 8443)
    assert target.host_header == "[::1]:8443"
    assert target.path == "/a%20b?authz=T&x=1"
    assert Target.of("dav://h/p").host_header == "h"
    assert Target.of("davs+3rd://h").path == "/"
    assert Target.of("https://h:/").port == 443
    assert Target.of("http://u:p@h:81/").base == "http://h:81"
    # A doubled slash is a join artifact a WebDAV server folds; send it folded,
    # so a strict one (StoRM) does not 400 where others succeed.
    folded = Target.of("davs://h/store//sub///f.bin")
    assert folded.path == "/store/sub/f.bin"
    assert folded.url.path == "/store//sub///f.bin"  # the parsed URL is left as given
    assert Target.of("https://h//a/b").path == "/a/b"
    # ... but an escaped slash inside a name is a character, not a separator.
    assert Target.of("davs://h/store/a%2F%2Fb").path == "/store/a%2F%2Fb"
    # S3 keys are literal: their slashes, doubled or not, are left exactly.
    assert Target.of("s3://h/bucket/a//b", s3=True).path == "/bucket/a//b"
    # What neon's URI parser refuses, davix calls "not a valid HTTP or Webdav URL" (EIO)
    for bad in ("root://h/p", "https://h:x/", "https://[::1/x", "https://[::1]:bad/x"):
        with pytest.raises(GError) as caught:
            Target.of(bad)
        assert (caught.value.code, caught.value.message) == (
            errno.EIO,
            f" {bad} is not a valid HTTP or Webdav URL",
        )
    # ... but an empty host it takes, and fails to resolve.
    with pytest.raises(_client.TransportError) as refused:
        Target.of("davs:///x")
    assert (refused.value.code, refused.value.message) == (
        errno.EHOSTUNREACH,
        "Domain name resolution failed",
    )


def test_invalid_urls_through_the_context(hctx: xgfalclient.Gfal2Context) -> None:
    with pytest.raises(GError) as caught:
        hctx.stat("https://[::1/x")
    assert (caught.value.code, caught.value.message) == (
        errno.EIO,
        "Result  https://[::1/x is not a valid HTTP or Webdav URL after 1 attempts",
    )
    with pytest.raises(GError) as caught:
        hctx.open("davs://h:port/x", "r")
    assert (caught.value.code, caught.value.message) == (errno.EIO, " Uri invalid in Davix::Open")
    with pytest.raises(GError) as caught:
        hctx.stat("http://")
    assert (caught.value.code, caught.value.message) == (
        errno.EHOSTUNREACH,
        "Result Domain name resolution failed after 1 attempts",
    )
    with pytest.raises(GError) as caught:
        hctx.mkdir("s3://h:bad/b/x", 0o755)  # named as given, not as the marker object
    assert caught.value.message == " s3://h:bad/b/x is not a valid HTTP or Webdav URL"
    # unlink words everything in davix's DavPosix::unlink scope, even with no PROPFIND first
    with pytest.raises(GError) as caught:
        hctx.unlink("https://h:bad/x")
    assert caught.value.message == (
        "DavPosix::unlink  Result  https://h:bad/x is not a valid HTTP or Webdav URL"
        " after 1 attempts"
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(GError) as caught:
        hctx.unlink(f"http://127.0.0.1:{port}/x")
    assert (caught.value.code, caught.value.message) == (
        errno.ECONNREFUSED,
        "DavPosix::unlink  Could not connect to server",
    )


def test_url_helpers() -> None:
    assert wire_url("davs://h/f?authz=x") == "https://h/f?authz=x"
    assert wire_url("cs3s://h/f") == "https://h/f"
    assert wire_url("s3s://h") == "https://h/"
    assert config_group("davs://se.example:443/p") == "DAV:SE.EXAMPLE"
    assert config_group("https+3rd://h/p") == "HTTP:H"
    assert config_group("dav://h/p") == "DAV:H"


def test_status_words() -> None:
    """davix's reading of each status, and gfal2's errno for it."""
    assert status_text(404) == "HTTP 404 : File not found "
    assert status_text(599) == "HTTP 599 : Unexpected server error: 599 "
    assert davix_status(409) == (errno.EEXIST, "Conflict, File Exist")
    assert davix_status(409, "mkdir") == (errno.ENOENT, "Conflict, File not Found")
    assert davix_status(405) == (errno.EPERM, "Method Not Allowed, Permission refused")
    assert davix_status(405, "mkdir") == (errno.EEXIST, "Method Not Allowed, File Exist")
    assert davix_status(423) == (errno.EPERM, "Permission refused")
    assert davix_status(501)[1] == "Server Error"
    assert davix_status(504) == (errno.ETIMEDOUT, "Operation timeout")
    assert davix_status(507) == (errno.EIO, "Insufficient Storage")
    assert davix_status(302)[0] == errno.ENOSYS


def test_transport_errors() -> None:
    same = TransportError("x", 1)
    assert transport_error(same) is same
    cases: list[tuple[BaseException, int]] = [
        (TimeoutError(), errno.ETIMEDOUT),
        (ConnectionRefusedError(), errno.ECONNREFUSED),
        (socket.gaierror(8, "nodename"), errno.EHOSTUNREACH),
        (ssl.SSLError(1, "boom"), ECOMM),
        (RemoteDisconnected("gone"), ECOMM),
        (OSError(errno.ENETUNREACH, "unreachable"), errno.ENETUNREACH),
        (OSError("no errno"), ECOMM),
        (ValueError("odd"), ECOMM),
    ]
    for exc, code in cases:
        assert transport_error(exc).code == code
    alert = ssl.SSLError(1, "boom")
    alert.reason = "TLSV1_ALERT_UNKNOWN_CA"  # what OpenSSL names, when it names anything
    assert transport_error(alert).message == "SSL error: TLSV1_ALERT_UNKNOWN_CA"
    verify = ssl.SSLCertVerificationError(1, "bad")
    verify.verify_message = "unable to get local issuer certificate"
    assert transport_error(verify).code == errno.EACCES


def test_the_upload_words_misuse_as_gfal2_does(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    upload = plugin(hctx).client.upload(dav.url("/data/u"), 4)
    with pytest.raises(GError) as caught:
        upload.write(b"abcde")
    assert caught.value.code == errno.EFBIG
    upload.write(b"ab")
    with pytest.raises(GError) as caught:
        upload.finish()
    assert caught.value.code == errno.EIO and "after 2 of 4 bytes" in caught.value.message
    assert upload.done
    upload = plugin(hctx).client.upload(dav.url("/data/u"), 2)
    upload.abort()
    assert upload.done and upload.early is None


def test_session_failures_in_gfal2_words() -> None:
    errors = _client._ERRORS
    short = errors.transport(Failure("PUT", "dav://h/f", ShortFileError(3)))
    assert type(short) is GError and short.code == errno.EIO
    cut = errors.transport(Failure("GET", "dav://h/f", IncompleteRead(b"", 6)))
    assert isinstance(cut, TransportError) and "6 bytes of the body never arrived" in str(cut)
    reset = errors.transport(Failure("GET", "dav://h/f", ConnectionResetError()))
    assert isinstance(reset, TransportError) and reset.code == ECOMM
    loop = errors.redirect("GET", "dav://h/f", "more than 10 redirects")
    assert isinstance(loop, GError) and loop.code == errno.ELOOP
    with pytest.raises(ValueError) as refused:
        _client._route("davs://h:port/x")
    assert (
        errors.redirect("GET", "davs://h:port/x", "bad", refused.value) is refused.value.__cause__
    )
    other = errors.redirect("GET", "ftp://h/x", "bad", ValueError("not HTTP"))
    assert isinstance(other, GError) and other.code == errno.EIO


def test_routes_read_gfal_schemes_and_prepared_hops_alike() -> None:
    assert _client._route("s3s://bucket.host/k%20ey") == Route(
        "https", "bucket.host", 443, "/k%20ey"
    )
    assert _client._route("http://h:8080/a%2Fb?x=1") == Route("http", "h", 8080, "/a%2Fb?x=1")


def test_plugin_close_empties_the_pool(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    hctx.stat(dav.url("/data"))
    client = plugin(hctx).client
    assert client.idle_count() == 1
    hctx.free()
    assert client.idle_count() == 0
