# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""SE-issued tokens (``token_retrieve``) and CDMI QoS."""

from __future__ import annotations

import errno
import urllib.parse

import pytest

import xgfalclient
from test_http_helpers import dav, davs, hctx, write  # noqa: F401 - fixtures
from xgfalclient import GError
from xgfalclient.testing.pki import PKI
from xgfalclient.testing.webdav import WebDAVServer


def test_tokens_need_https(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    url = dav.url("/data/f")
    with pytest.raises(GError) as caught:
        hctx.token_retrieve(url, "", 60, False)
    assert (caught.value.code, caught.value.message) == (
        errno.ENODATA,
        f"Could not retrieve token for {url} [last failed attempt: "
        "Token request must be done over HTTPs]",
    )


def test_macaroons(hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI) -> None:
    url = davs.url("/data/f")
    token = hctx.token_retrieve(url, "", 60, False)
    assert token == davs.macaroons[-1]["macaroon"]
    assert davs.macaroons[-1]["caveats"] == ["activity:LIST,DOWNLOAD"]
    assert davs.macaroons[-1]["validity"] == "PT60M"
    # No issuer: straight to the file, nothing discovered first.
    assert [r.method for r in davs.requests] == ["POST"]
    request = davs.requests[-1]
    assert request.header("Content-Type") == "application/macaroon-request"
    assert request.header("Accept") is None
    assert request.body == b'{"caveats": ["activity:LIST,DOWNLOAD"], "validity": "PT60M"}'
    assert request.header("Authorization") is None  # authenticated by the proxy
    hctx.token_retrieve(url, "", 0, True)
    assert davs.macaroons[-1]["caveats"] == ["activity:LIST,DOWNLOAD,MANAGE,UPLOAD,DELETE"]
    assert davs.macaroons[-1]["validity"] == "PT0M"
    hctx.token_retrieve(url, "", 5, ["list", "Download"])  # as given, case and all
    assert davs.macaroons[-1]["caveats"] == ["activity:list,Download"]


@pytest.mark.parametrize(
    ("body", "why"),
    [
        (b"", "Response with no data"),
        (b"{nope", "Response was not valid JSON"),
        (b'["macaroon"]', "Response did not include 'macaroon' key"),
        (b'{"other": 1}', "Response did not include 'macaroon' key"),
        (b'{"macaroon": null}', "Key 'macaroon' was not a string"),
        (b'{"macaroon": ""}', "Extracted value for key 'macaroon' is empty"),
        (b"x" * (1 << 20), "Macaroon response exceeds maximum size: 1048576 bytes"),
    ],
)
def test_bad_macaroon_replies(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI, body: bytes, why: str
) -> None:
    davs.fault("POST", status=200, body=body)
    with pytest.raises(GError) as caught:
        hctx.token_retrieve(davs.url("/data/f"), "", 60, False)
    assert f"[last failed attempt: {why}" in caught.value.message


def test_a_non_string_token_is_taken_as_json_spells_it(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI
) -> None:
    davs.fault("POST", status=200, body=b'{"macaroon": 7}')
    assert hctx.token_retrieve(davs.url("/data/f"), "", 60, False) == "7"


def test_refused_and_unreachable(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI
) -> None:
    davs.fault("POST", status=201, body=b'{"macaroon": "X"}')  # only 200 will do
    with pytest.raises(GError) as caught:
        hctx.token_retrieve(davs.url("/data/f"), "", 60, False)
    assert caught.value.message.endswith(
        "[last failed attempt: Macaroon request failed with status code 201]"
    )
    davs.fault("POST", drop=True, times=2)
    with pytest.raises(GError) as caught:
        hctx.token_retrieve(davs.url("/data/f"), "", 60, False)
    assert "[last failed attempt: Macaroon request failed: Connection terminated" in (
        caught.value.message
    )


def test_issuer(hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI) -> None:
    """SciTokens, then a macaroon retriever for the issuer, then a macaroon for the file."""
    url = davs.url("/data/f")
    token = hctx.token_retrieve(url, davs.base.replace("https", "davs") + "/", 10, False)
    assert token.startswith("mac-")
    assert [(r.method, r.path) for r in davs.requests] == [
        ("GET", "/.well-known/oauth-authorization-server"),
        ("GET", "/.well-known/oauth-authorization-server"),
        ("POST", "/data/f"),
    ]
    with pytest.raises(GError) as caught:  # a plain-HTTP issuer is not asked at all
        davs.fault("POST", status=403)
        hctx.token_retrieve(url, "http://127.0.0.1:1/", 10, False)
    assert caught.value.message.endswith("Macaroon request failed with status code 403]")


def test_issuer_with_a_token_endpoint(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI
) -> None:
    davs.oauth = True
    davs.oauth_endpoint = f"{davs.base}/token"
    token = hctx.token_retrieve(davs.url("/data/f"), davs.base + "/realm", 10, True)
    assert token.startswith("oauth-")
    discovery, post = davs.requests
    assert discovery.path == "/.well-known/oauth-authorization-server/realm"
    # SciTokens asks for client credentials, and nothing else.
    assert post.body == b"grant_type=client_credentials"
    assert post.header("Accept") == "application/json"
    davs.clear()
    davs.fault("POST", path="/token", status=500)  # SciTokens refused: the macaroon one asks
    token = hctx.token_retrieve(davs.url("/data/f"), davs.base, 10, True)
    assert token.startswith("oauth-")
    form = davs.macaroons[-1]["form"]
    assert form["grant_type"] == ["client_credentials"]
    assert form["expire_in"] == ["600"]
    assert form["scopes"] == [
        "LIST:/data/f DOWNLOAD:/data/f MANAGE:/data/f UPLOAD:/data/f DELETE:/data/f"
    ]
    davs.fault("POST", path="/token", status=500, times=2)
    with pytest.raises(GError) as caught:
        hctx.token_retrieve(davs.url("/data/f"), davs.base, 10, True)
    assert caught.value.message.endswith("Token request failed with status code 500]")


def test_issuer_discovery_oddities(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI
) -> None:
    davs.oauth = True
    davs.fault("GET", path="/.well-known/", status=200, body=b"not json", times=2)
    assert hctx.token_retrieve(davs.url("/data/f"), davs.base, 10, False).startswith("mac-")
    davs.fault("GET", path="/.well-known/", status=404, times=2)
    with pytest.raises(GError) as caught:
        davs.fault("POST", status=500)
        hctx.token_retrieve(davs.url("/data/f"), davs.base, 10, False)
    assert caught.value.message.endswith("Macaroon request failed with status code 500]")
    # The discovery document names the server's own /token by default.
    assert hctx.token_retrieve(davs.url("/data/f"), davs.base, 10, False).startswith("oauth-")


# -- QoS ------------------------------------------------------------------------------------


@pytest.fixture
def qos(dav: WebDAVServer) -> WebDAVServer:
    dav.qos.update(
        {
            "/data/f": {
                "capabilitiesURI": "/cdmi_capabilities/dataobject/disk",
                "metadata": {"cdmi_capabilities_target": "/cdmi_capabilities/dataobject/tape"},
            },
            "/data/plain": {"metadata": "not a dict"},
            "/cdmi_capabilities/dataobject/disk": {
                "cdmi_capabilities_allowed": ["/cdmi_capabilities/dataobject/tape"]
            },
            "/cdmi_capabilities/dataobject/tape/": {},
            "/cdmi_capabilities/container/disk/": {},
        }
    )
    return dav


def test_qos(
    hctx: xgfalclient.Gfal2Context, qos: WebDAVServer, capsys: pytest.CaptureFixture[str]
) -> None:
    base = qos.base
    assert hctx.check_file_qos(qos.url("/data/f")) == "/cdmi_capabilities/dataobject/disk"
    assert qos.requests[-1].header("Accept") is None  # gfal2 sends none
    assert hctx.check_target_qos(qos.url("/data/f")) == "/cdmi_capabilities/dataobject/tape"
    assert hctx.check_target_qos(qos.url("/data/plain")) == ""
    assert hctx.check_file_qos(qos.url("/data/plain")) == ""
    assert hctx.check_available_qos_transitions(f"{base}/cdmi_capabilities/dataobject/disk") == [
        "/cdmi_capabilities/dataobject/tape"
    ]
    assert hctx.check_available_qos_transitions(qos.url("/data/f")) == []
    # The URL as given, and the classes with their prefix.
    assert hctx.qos_check_classes(base, "dataobject") == [
        "/cdmi_capabilities/dataobject/disk/",
        "/cdmi_capabilities/dataobject/tape/",
    ]
    assert qos.requests[-1].path == "/cdmi_capabilities/dataobject"
    assert hctx.qos_check_classes(base, "container") == ["/cdmi_capabilities/container/disk/"]
    hctx.change_object_qos(qos.url("/data/f"), "/cdmi_capabilities/dataobject/tape")
    put = qos.requests[-1]
    assert put.body == b'{"capabilitiesURI":"/cdmi_capabilities/dataobject/tape"}'
    assert put.method == "PUT" and put.header("Content-Type") == "application/cdmi-object"
    assert capsys.readouterr().err == ""


def test_qos_errors(
    hctx: xgfalclient.Gfal2Context, qos: WebDAVServer, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(GError) as caught:
        hctx.qos_check_classes(qos.url("/"), "files")
    assert (caught.value.code, caught.value.message) == (
        errno.EINVAL,
        "type argument should be either dataobject or container",
    )
    with pytest.raises(GError) as caught:
        hctx.qos_check_classes(qos.url("/data/f"), "dataobject")  # the path is kept: 404
    assert (caught.value.code, caught.value.message) == (errno.ENOENT, "HTTP 404 : File not found ")
    assert qos.requests[-1].path == "/data/f/cdmi_capabilities/dataobject"
    assert capsys.readouterr().err == (
        " error in request of getting available QoS classes: HTTP 404 : File not found \n"
    )
    with pytest.raises(GError) as caught:
        hctx.check_file_qos(qos.url("/data/nope"))
    assert caught.value.message == "HTTP 404 : File not found "
    qos.fault("PUT", status=403)
    with pytest.raises(GError) as caught:
        hctx.change_object_qos(qos.url("/data/f"), "x")
    assert caught.value.code == errno.EPERM
    qos.fault("PUT", status=207)
    with pytest.raises(GError) as caught:
        hctx.change_object_qos(qos.url("/data/f"), "x")
    assert caught.value.code == errno.EIO
    qos.fault("GET", status=200, body=b"[]")
    with pytest.raises(GError) as caught:
        hctx.check_file_qos(qos.url("/data/f"))
    assert caught.value.code == errno.EPROTO
    qos.fault("GET", status=200, body=b"{{{")
    with pytest.raises(GError):
        hctx.check_target_qos(qos.url("/data/f"))
    qos.fault("GET", status=200, body=b'{"children": "nope"}')
    assert hctx.qos_check_classes(qos.base, "container") == []
    qos.fault(
        "GET",
        status=200,
        body=b'{"capabilitiesURI": 5, "metadata": {"cdmi_capabilities_target": ["a b"]}}',
        times=2,
    )
    assert hctx.check_file_qos(qos.url("/data/f")) == "5"
    assert hctx.check_target_qos(qos.url("/data/f")) == "ab"
    with pytest.raises(GError):
        hctx.check_available_qos_transitions(f"{qos.base}/cdmi_capabilities/dataobject/gone")
    port = qos.port
    qos.stop()
    for call in (
        lambda: hctx.check_file_qos(f"dav://127.0.0.1:{port}/data/f"),
        lambda: hctx.change_object_qos(f"dav://127.0.0.1:{port}/data/f", "x"),
    ):
        with pytest.raises(GError) as caught:
            call()
        assert caught.value.code == errno.ECONNREFUSED


def test_unquoted_query_survives(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/q", b"x")
    query = urllib.parse.urlencode({"a": "b c"})
    assert hctx.stat(dav.url(f"/data/q?{query}")).st_size == 1
