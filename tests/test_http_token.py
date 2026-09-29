# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""SE-issued tokens (``token_retrieve``) and CDMI QoS."""

from __future__ import annotations

import errno
import json
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
    request = davs.requests[-1]
    assert request.header("Content-Type") == "application/macaroon-request"
    assert request.header("Authorization") is None  # authenticated by the proxy
    hctx.token_retrieve(url, "", 0, True)
    assert davs.macaroons[-1]["caveats"] == ["activity:LIST,MANAGE,UPLOAD,DELETE"]
    assert davs.macaroons[-1]["validity"] == "PT1M"
    hctx.token_retrieve(url, "", 5, ["download", " ", "Upload"])
    assert davs.macaroons[-1]["caveats"] == ["activity:DOWNLOAD,UPLOAD"]
    davs.fault("POST", status=201, body=b'{"macaroon": "CREATED"}')  # 201 is a success too
    assert hctx.token_retrieve(url, "", 60, False) == "CREATED"


@pytest.mark.parametrize(
    ("body", "why"),
    [
        (b"", "Response with no data"),
        (b"{nope", "Response was not valid JSON"),
        (b'["macaroon"]', "Response did not include 'macaroon' key"),
        (b'{"other": 1}', "Response did not include 'macaroon' key"),
        (b'{"macaroon": 7}', "Key 'macaroon' was not a string"),
        (b'{"macaroon": ""}', "Extracted value for key 'macaroon' is empty"),
    ],
)
def test_bad_macaroon_replies(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI, body: bytes, why: str
) -> None:
    davs.fault("POST", status=200, body=body)
    with pytest.raises(GError) as caught:
        hctx.token_retrieve(davs.url("/data/f"), "", 60, False)
    assert caught.value.message.endswith(f"[last failed attempt: {why}]")


def test_refused_and_unreachable(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI
) -> None:
    davs.fault("POST", status=403)
    with pytest.raises(GError) as caught:
        hctx.token_retrieve(davs.url("/data/f"), "", 60, False)
    assert caught.value.message.endswith(
        "[last failed attempt: Token request failed: HTTP 403 : Permission refused ]"
    )
    davs.fault("GET", drop=True, times=2)  # discovery hangs up: straight to the macaroon
    davs.fault("POST", drop=True, times=2)
    with pytest.raises(GError) as caught:
        hctx.token_retrieve(davs.url("/data/f"), "", 60, False)
    assert "Connection terminated abruptly" in caught.value.message


def test_oauth_token_endpoint(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI
) -> None:
    davs.oauth = True
    token = hctx.token_retrieve(davs.url("/data/f"), "", 10, True)
    assert token.startswith("oauth-")
    form = davs.macaroons[-1]["form"]
    assert form["grant_type"] == ["client_credentials"]
    assert form["expire_in"] == ["600"]
    assert form["scopes"] == ["list:/data/f manage:/data/f upload:/data/f delete:/data/f"]
    # The token endpoint refuses: the macaroon request still works.
    davs.fault("POST", path="/token", status=500)
    assert hctx.token_retrieve(davs.url("/data/f"), "", 10, False).startswith("mac-")


def test_oauth_discovery_oddities(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI
) -> None:
    davs.oauth = True
    davs.oauth_endpoint = "http://insecure.example/token"
    with pytest.raises(GError) as caught:
        hctx.token_retrieve(davs.url("/data/f"), "", 10, False)
    assert caught.value.message.endswith("Token request must be done over HTTPs]")
    davs.fault("GET", path="/.well-known/", status=200, body=b"not json")
    assert hctx.token_retrieve(davs.url("/data/f"), "", 10, False).startswith("mac-")


def test_issuer(hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, grid_env: PKI) -> None:
    with pytest.raises(GError) as caught:
        hctx.token_retrieve(davs.url("/data/f"), davs.base + "/", 10, False)
    assert caught.value.message.endswith("Invalid or empty token issuer endpoint]")
    davs.oauth = True
    assert hctx.token_retrieve(davs.url("/data/f"), davs.base, 10, False).startswith("oauth-")
    assert any(r.path == "/.well-known/openid-configuration" for r in davs.requests)


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


def test_qos(hctx: xgfalclient.Gfal2Context, qos: WebDAVServer) -> None:
    base = qos.base
    assert hctx.check_file_qos(qos.url("/data/f")) == "/cdmi_capabilities/dataobject/disk"
    assert qos.requests[-1].header("Accept") == "application/cdmi-object"
    assert hctx.check_target_qos(qos.url("/data/f")) == "/cdmi_capabilities/dataobject/tape"
    assert hctx.check_target_qos(qos.url("/data/plain")) == ""
    assert hctx.check_file_qos(qos.url("/data/plain")) == ""
    assert hctx.check_available_qos_transitions(f"{base}/cdmi_capabilities/dataobject/disk") == [
        "/cdmi_capabilities/dataobject/tape"
    ]
    assert hctx.check_available_qos_transitions(qos.url("/data/f")) == []
    assert hctx.qos_check_classes(qos.url("/"), "dataobject") == ["disk", "tape"]
    assert hctx.qos_check_classes(qos.url("/"), "container") == ["disk"]
    hctx.change_object_qos(qos.url("/data/f"), "/cdmi_capabilities/dataobject/tape")
    put = qos.requests[-1]
    assert json.loads(put.body) == {"capabilitiesURI": "/cdmi_capabilities/dataobject/tape"}
    assert put.method == "PUT" and put.header("Content-Type") == "application/cdmi-object"


def test_qos_errors(hctx: xgfalclient.Gfal2Context, qos: WebDAVServer) -> None:
    with pytest.raises(GError) as caught:
        hctx.qos_check_classes(qos.url("/"), "files")
    assert (caught.value.code, caught.value.message) == (
        errno.EINVAL,
        "type argument should be either dataobject or container",
    )
    with pytest.raises(GError) as caught:
        hctx.check_file_qos(qos.url("/data/nope"))
    assert (
        caught.value.message == " error in request of checking file QoS: HTTP 404 : File not found "
    )
    with pytest.raises(GError) as caught:
        hctx.change_object_qos(qos.url("/data/nope"), "x")
    assert caught.value.code == errno.ENOENT
    qos.fault("GET", status=200, body=b"[]")
    with pytest.raises(GError) as caught:
        hctx.check_file_qos(qos.url("/data/f"))
    assert caught.value.code == errno.EPROTO
    qos.fault("GET", status=200, body=b"{{{")
    with pytest.raises(GError):
        hctx.check_target_qos(qos.url("/data/f"))
    qos.fault("GET", status=200, body=b'{"children": "nope"}')
    assert hctx.qos_check_classes(qos.url("/"), "container") == []
    with pytest.raises(GError):
        hctx.check_available_qos_transitions(f"{qos.base}/cdmi_capabilities/dataobject/gone")


def test_unquoted_query_survives(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    write(dav, "/data/q", b"x")
    query = urllib.parse.urlencode({"a": "b c"})
    assert hctx.stat(dav.url(f"/data/q?{query}")).st_size == 1
