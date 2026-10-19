"""Edges: delegation failures, odd server answers, and the test server's own corners."""

from __future__ import annotations

import base64
import errno
import logging
from pathlib import Path

import pytest
from xrdhttp.connection import HTTPSConnection

import xgfalclient
from test_http_helpers import Events, make_server, write
from test_http_helpers import dav as dav
from test_http_helpers import dav2 as dav2
from test_http_helpers import davs as davs
from test_http_helpers import davs_open as davs_open
from test_http_helpers import hctx as hctx
from xgfalclient import GError
from xgfalclient.plugin import O_CREAT, O_TRUNC, O_WRONLY
from xgfalclient.plugins.http import _delegation
from xgfalclient.plugins.http.plugin import HTTPPlugin
from xgfalclient.testing.pki import PKI
from xgfalclient.testing.webdav import S3, WebDAVServer

WRITE = O_WRONLY | O_CREAT | O_TRUNC
DELEGATION = "/gridsite-delegation"


def plugin(context: xgfalclient.Gfal2Context) -> HTTPPlugin:
    found = context.plugin("davs://h/", "stat")
    assert isinstance(found, HTTPPlugin)
    return found


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


def test_a_credential_that_will_not_load_is_left_out(
    hctx: xgfalclient.Gfal2Context,
    davs_open: WebDAVServer,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # gfal2 warns and goes on without it (upstream's own example does this):
    # a token, or a server that wants no certificate, still gets through.
    write(davs_open, "/data/f", b"hello")
    url = davs_open.url("/data/f")
    hctx.cred_set(url, hctx.cred_new("X509_CERT", str(tmp_path / "missing.pem")))
    with caplog.at_level(logging.WARNING, logger="gfal2"):
        assert hctx.stat(url).st_size == 5
        assert hctx.token_retrieve(url, "", 60, False) == davs_open.macaroons[0]["macaroon"]
    assert len(caplog.messages) == 2  # the stat, and the macaroon request (X.509 only)
    assert all(
        message.startswith("Could not load the user credentials: Could not load the X.509")
        for message in caplog.messages
    )


def test_delegation_that_never_arrives(
    hctx: xgfalclient.Gfal2Context, davs_open: WebDAVServer, davs: WebDAVServer, grid_env: PKI
) -> None:
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
    hctx.set_opt_boolean("HTTP PLUGIN", "RETRIEVE_BEARER_TOKEN", False)
    write(davs_open, "/data/src", b"x")
    davs.delegation = True
    davs.delegation_timeout = 0.2
    davs.fault("POST", path=DELEGATION, status=500, body=b"", times=2)
    with pytest.raises(GError) as caught:
        hctx.filecopy(davs_open.url("/data/src"), davs.url("/data/dst"))
    assert "Delegation" in caught.value.message or "delegat" in caught.value.message


def test_server_rejects_a_mismatched_proxy(davs: WebDAVServer, grid_env: PKI) -> None:
    connection = HTTPSConnection("127.0.0.1", davs.port, ssl_context=grid_env.client_context())

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
