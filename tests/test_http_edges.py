# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""Edges: delegation failures, odd server answers, and the test server's own corners."""

from __future__ import annotations

import base64
import errno
import http.client
import socket
from pathlib import Path

import pytest

import xgfalclient
from test_http_helpers import Events, dav, dav2, davs, hctx, make_server, write  # noqa: F401
from xgfalclient import GError
from xgfalclient.plugin import O_CREAT, O_TRUNC, O_WRONLY
from xgfalclient.plugins.http import _delegation
from xgfalclient.testing.pki import PKI
from xgfalclient.testing.webdav import S3, Tape, WebDAVServer

WRITE = O_WRONLY | O_CREAT | O_TRUNC
DELEGATION = "/gridsite-delegation"


def plugin(context: xgfalclient.Gfal2Context):  # type: ignore[no-untyped-def]
    return context.plugin("davs://h/", "stat")


def soap(inner: str) -> bytes:
    return (
        '<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV='
        '"http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>'
        f"{inner}</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    ).encode()


def pem_block(label: str, der: bytes) -> str:
    return f"-----BEGIN {label}-----\n{base64.b64encode(der).decode()}\n-----END {label}-----\n"


# -- delegation -------------------------------------------------------------------------------


def test_delegation_failures(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI, tmp_path: Path
) -> None:
    endpoint = davs.base + DELEGATION
    url = davs.url("/data/x")
    http_plugin = plugin(hctx)
    # A reply with no certificate request in it.
    cert_only = pem_block("CERTIFICATE", b"\x30\x00")
    davs.fault(
        "POST",
        path=DELEGATION,
        status=200,
        body=soap(f"<r><proxyRequest>{cert_only}</proxyRequest><delegationID>d</delegationID></r>"),
    )
    with pytest.raises(GError) as caught:
        _delegation.delegate(http_plugin, endpoint, url)
    assert caught.value.message == "The delegation service sent no certificate request"
    # A request that is not PKCS#10.
    junk = pem_block("CERTIFICATE REQUEST", b"\x30\x03\x02\x01\x00")
    davs.fault(
        "POST",
        path=DELEGATION,
        status=200,
        body=soap(f"<r><proxyRequest>{junk}</proxyRequest><delegationID>d</delegationID></r>"),
    )
    with pytest.raises(GError) as caught:
        _delegation.delegate(http_plugin, endpoint, url)
    assert caught.value.message.startswith("Could not sign the delegation request")
    # delegation-2 answers without a request, without an id, or with nothing at all:
    # delegation-1 is tried, and works.
    for reply in (
        soap("<r/>"),
        soap("<r><proxyRequest/><delegationID>d</delegationID></r>"),
        soap("<r><proxyRequest>x</proxyRequest></r>"),
        b"",
    ):
        davs.fault("POST", path=DELEGATION, status=200, body=reply)
        assert _delegation.delegate(http_plugin, endpoint, url)
    # Both versions fail.
    davs.fault("POST", path=DELEGATION, status=500, body=b"")
    davs.fault("POST", path=DELEGATION, status=200, body=soap("<r/>"))
    with pytest.raises(GError) as caught:
        _delegation.delegate(http_plugin, endpoint, url)
    assert caught.value.message.endswith("failed: no certificate request")
    davs.fault("POST", path=DELEGATION, status=500, body=b"")
    davs.fault(
        "POST",
        path=DELEGATION,
        status=200,
        body=soap("<SOAP-ENV:Fault><faultstring>go away</faultstring></SOAP-ENV:Fault>"),
    )
    with pytest.raises(GError) as caught:
        _delegation.delegate(http_plugin, endpoint, url)
    assert caught.value.message.endswith("failed: go away")
    # An unreadable credential.
    broken = tmp_path / "broken.pem"
    broken.write_text("not a proxy")
    hctx.cred_set(url, hctx.cred_new("X509_CERT", str(broken)))
    with pytest.raises(GError) as caught:
        _delegation.delegate(http_plugin, endpoint, url)
    assert caught.value.message.startswith("Could not load the user credentials")


def test_delegation_without_a_proxy(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    with pytest.raises(GError) as caught:
        _delegation.delegate(plugin(hctx), dav.base + DELEGATION, dav.url("/x"))
    assert caught.value.code == errno.EACCES


def test_delegation_that_never_arrives(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, davs: WebDAVServer, grid_env: PKI
) -> None:
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
    write(dav, "/data/src", b"x")
    davs.delegation = True
    davs.delegation_timeout = 0.2
    davs.fault("POST", path=DELEGATION, status=500, body=b"", times=2)
    with pytest.raises(GError):
        hctx.filecopy(dav.url("/data/src"), davs.url("/data/dst"))


def test_server_rejects_a_mismatched_proxy(davs: WebDAVServer, grid_env: PKI) -> None:
    connection = http.client.HTTPSConnection(
        "127.0.0.1", davs.port, context=grid_env.client_context()
    )

    def put_proxy(delegation_id: str, proxy: str) -> int:
        inner = f"<putProxy><delegationID>{delegation_id}</delegationID><proxy>{proxy}</proxy>"
        connection.request("POST", DELEGATION, body=soap(inner + "</putProxy>"))
        response = connection.getresponse()
        response.read()
        return response.status

    certificate = grid_env.user_cert_path.read_text()
    assert put_proxy("nope", "x") == 500  # no certificate at all
    assert put_proxy("nope", certificate) == 500  # a delegation nobody asked for
    connection.request("POST", DELEGATION, body=soap("<getNewProxyReq/>"))
    answer = connection.getresponse().read().decode()
    delegation_id = answer.split("<delegationID>")[1].split("</delegationID>")[0]
    assert put_proxy(delegation_id, certificate) == 500  # not the key that was asked to sign
    connection.close()


# -- the plugin on odd answers ----------------------------------------------------------------


def test_cleanup_that_removes_a_partial_file(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"x")
    dav2.tpc = "eof"
    events = Events()
    copy = xgfalclient.TransferParameters()
    copy.event_callback = events
    hctx.filecopy(copy, dav.url("/data/src"), dav2.url("/data/dst"))
    assert "CLEANUP 0" in events.stages()
    assert dav2.local("/data/dst").read_bytes() == b"x"


def test_markers_without_counts(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"x")
    body = b"Perf Marker\n\tStripe Index: x\n\tStripe Bytes Transferred: 5\nEnd\n"
    body += b"Perf Marker\n\tTimestamp: 1\nEnd\njunk line\nsuccess: Created\n"
    dav2.fault("COPY", status=202, body=body)
    hctx.filecopy(xgfalclient.TransferParameters(), dav.url("/data/src"), dav2.url("/data/dst"))


def test_write_handle_closed_twice(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    handle = plugin(hctx).open(dav.url("/data/w"), WRITE, 0o644, 1)
    handle.write(b"x")
    handle.close()
    handle.close()
    assert dav.local("/data/w").read_bytes() == b"x"


def test_md5_without_any_digest(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/f", b"x")
    dav.digests = {"adler32"}
    with pytest.raises(GError) as caught:
        hctx.checksum(dav.url("/data/f"), "md5")
    assert caught.value.code == errno.ENOSYS


def test_streamed_upload_with_a_token(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    dav.tokens = {"T"}
    hctx.cred_set(dav.url("/"), hctx.cred_new("BEARER", "T"))
    handle = plugin(hctx).open(dav.url("/data/t"), WRITE, 0o644, 2)
    handle.write(b"ok")
    handle.close()
    assert dav.requests[-1].header("Authorization") == "Bearer T"


def test_streamed_upload_to_nowhere(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    port = dav.port
    dav.stop()
    with pytest.raises(GError) as caught:
        plugin(hctx).client.upload(f"dav://127.0.0.1:{port}/data/x", 2)
    assert caught.value.code == errno.ECONNREFUSED


def test_s3_abort_that_cannot_reach_the_server(
    hctx: xgfalclient.Gfal2Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from xgfalclient.plugins.http import _s3

    monkeypatch.setattr(_s3, "PART_SIZE", 10)
    server = make_server(tmp_path / "s3")
    server.s3 = S3()
    (server.root / "bucket").mkdir()
    hctx.set_opt_string("S3", "ACCESS_KEY", "AKIDTEST")
    hctx.set_opt_string("S3", "SECRET_KEY", "SECRETTEST")
    hctx.set_opt_boolean("S3", "ALTERNATE", True)
    writer = _s3.S3PartWriter(plugin(hctx), server.url("/bucket/k", scheme="s3"))
    server.fault("PUT", status=500)
    server.fault("DELETE", drop=True, times=2)
    with pytest.raises(GError):
        writer.write(b"x" * 20)
    server.stop()


# -- the test server's own corners ------------------------------------------------------------


def test_server_corners(tmp_path: Path) -> None:
    with WebDAVServer(tmp_path / "root") as server:
        server.tape = Tape()
        (server.root / "d").mkdir()
        connection = http.client.HTTPConnection("127.0.0.1", server.port)

        def ask(method: str, path: str, body: bytes | None = None, **headers: str) -> int:
            connection = http.client.HTTPConnection("127.0.0.1", server.port)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            response.read()
            return response.status

        server.fault("GET", delay=0.01)  # a delay, then the real answer
        assert ask("GET", "/nope") == 404
        assert ask("POST", "/d", b"{}", **{"Content-Type": "text/plain"}) == 405
        assert ask("DELETE", "/missing") == 404
        assert ask("PUT", "/d", b"x") == 405
        assert ask("COPY", "/d") == 400
        connection.request("PUT", "/chunked", body=iter([b"ab", b"cd"]), encode_chunked=True)
        response = connection.getresponse()
        response.read()
        assert response.status == 201
        assert (server.root / "chunked").read_bytes() == b"abcd"
        assert ask("POST", "/api/v1/unknown", b"{}") == 404
        stage = b'{"files": [{"path": "/d"}]}'
        connection = http.client.HTTPConnection("127.0.0.1", server.port)
        connection.request("POST", "/api/v1/stage", body=stage)
        request_id = __import__("json").loads(connection.getresponse().read())["requestId"]
        assert ask("POST", f"/api/v1/stage/{request_id}/cancel", b'{"paths": ["/other"]}') == 200
        assert ask("POST", "/api/v1/stage/none/cancel", b'{"paths": []}') == 404
        # A chunked body whose sender hangs up mid-way ends where the data ends.
        with socket.create_connection(("127.0.0.1", server.port)) as raw:
            raw.sendall(
                b"PUT /cut HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n"
            )
            raw.shutdown(socket.SHUT_WR)
            assert raw.makefile("rb").readline().startswith(b"HTTP/1.1 201")
        assert (server.root / "cut").read_bytes() == b"ab"


def test_server_routing_corners(tmp_path: Path) -> None:
    with WebDAVServer(tmp_path / "root") as server:
        server.tape = Tape()
        (server.root / "d").mkdir()
        (server.root / "empty").write_bytes(b"")

        def ask(method: str, path: str, body: bytes | None = None, **headers: str) -> int:
            connection = http.client.HTTPConnection("127.0.0.1", server.port)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            response.read()
            connection.close()
            return response.status

        server.fault(path="/d", status=418)  # a fault for any method
        assert ask("PROPFIND", "/d") == 418
        # The token and delegation endpoints only take POST.
        assert ask("GET", "/token") == 404
        assert ask("GET", "/gridsite-delegation") == 404
        # A CDMI capabilities path is CDMI without the Accept header too.
        assert ask("GET", "/cdmi_capabilities/other") == 404
        assert ask("GET", "/d") == 403  # there, but not a file
        assert ask("GET", "/empty") == 200
        mac = {"Content-Type": "application/macaroon-request"}
        assert ask("POST", "/d", **mac) == 200  # no body: an empty request
        assert server.macaroons[-1]["path"] == "/d"
        # Tape REST calls that are not quite any call.
        assert ask("GET", "/api/v1/stage") == 404
        assert ask("POST", "/api/v1/stage/x") == 404
        assert ask("POST", "/api/v1/stage/x/other") == 404
        assert ask("POST", "/api/v1/release") == 404


def test_server_s3_corners(tmp_path: Path, hctx: xgfalclient.Gfal2Context) -> None:
    server = make_server(tmp_path / "s3")
    server.s3 = S3()
    (server.root / "bucket").mkdir()
    hctx.set_opt_string("S3", "ACCESS_KEY", "AKIDTEST")
    hctx.set_opt_string("S3", "SECRET_KEY", "SECRETTEST")
    hctx.set_opt_boolean("S3", "ALTERNATE", True)
    http_plugin = plugin(hctx)
    response = http_plugin._request("DELETE", server.url("/bucket/missing", scheme="s3"))
    assert response.status == 204
    response.close()
    response = http_plugin._request("MKCOL", server.url("/bucket/d", scheme="s3"))
    assert response.status == 405
    response.close()
    response = http_plugin._request("POST", server.url("/bucket/d", scheme="s3"), body=b"")
    assert response.status == 405  # a POST that is not a multipart upload
    response.close()
    server.stop()


def test_push_to_a_refusing_destination(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "3rd push")
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
    write(dav, "/data/src", b"x")
    dav2.fault("PUT", status=403)
    copy = xgfalclient.TransferParameters()
    copy.strict_copy = True
    with pytest.raises(GError) as caught:
        hctx.filecopy(copy, dav.url("/data/src"), dav2.url("/data/dst"))
    assert "destination answered HTTP 403" in caught.value.message
