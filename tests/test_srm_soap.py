"""The srm plugin's building blocks: SOAP, SURLs, statuses, reply matching."""

from __future__ import annotations

import errno

import pytest

from xgfalclient.errors import ECOMM, GError
from xgfalclient.plugins.srm import soap
from xgfalclient.plugins.srm.client import FileStatus, Status, _same, match
from xgfalclient.plugins.srm.transport import ifce_error, normalise_path, parse_surl

# -- writing -------------------------------------------------------------------------


def test_request_envelope_is_what_srm_ifce_writes() -> None:
    body = soap.request(
        "srmLs",
        [
            ("arrayOfSURLs", [("urlArray", "srm://h/a&b")]),
            ("storageSystemInfo", soap.NIL),
            ("fullDetailedList", True),
            ("numOfLevels", 0),
            ("offset", None),
        ],
    ).decode()
    assert body.startswith('<?xml version="1.0" encoding="UTF-8"?>\n<SOAP-ENV:Envelope ')
    assert 'xmlns:srm2="http://srm.lbl.gov/StorageResourceManager"' in body
    assert (
        '<SOAP-ENV:Body SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<srm2:srmLs><srmLsRequest><arrayOfSURLs><urlArray>srm://h/a&amp;b</urlArray>"
        '</arrayOfSURLs><storageSystemInfo xsi:nil="true"/><fullDetailedList>true'
        "</fullDetailedList><numOfLevels>0</numOfLevels></srmLsRequest></srm2:srmLs>"
    ) in body
    assert repr(soap.NIL) == "NIL"


def test_false_renders() -> None:
    assert b"<recursive>false</recursive>" in soap.request("srmRmdir", [("recursive", False)])


def test_response_round_trips_plain_and_multiref() -> None:
    fields = [("returnStatus", [("statusCode", "SRM_SUCCESS")]), ("requestToken", "t1")]
    for multiref in (False, True):
        name, part = soap.parse(soap.response("srmPing", fields, multiref=multiref))
        assert name == "srmPingResponse"
        assert part.get("returnStatus", "statusCode") == "SRM_SUCCESS"
        assert part.get("requestToken") == "t1"


# -- reading -------------------------------------------------------------------------

ENV = (
    '<?xml version="1.0"?><e:Envelope xmlns:e="http://schemas.xmlsoap.org/soap/envelope/" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns="urn:x">'
    "<e:Body>{}</e:Body></e:Envelope>"
)


def parse(inner: str) -> tuple[str, soap.Node]:
    return soap.parse(ENV.format(inner).encode())


def test_hrefs_nils_and_missing_values() -> None:
    _, part = parse(
        '<ns:opResponse><r href="#a"/></ns:opResponse>'
        '<multiRef id="a"><x href="#b"/><n xsi:nil="true"/><gone href="#nowhere"/>'
        "<i>12</i><bad>x</bad><t>TRUE</t><f>0</f><u>maybe</u></multiRef>"
        '<multiRef id="b">  deep  </multiRef>'
    )
    assert part.get("x") == "deep"
    assert part.child("n") is None and part.child("gone") is None
    assert part.get("missing", default="d") == "d"
    assert part.integer("i") == 12 and part.integer("bad") is None
    assert part.boolean("t") is True and part.boolean("f") is False
    assert part.boolean("u") is None
    assert [node.text for node in part] == ["deep", "12", "x", "TRUE", "0", "maybe"]
    assert part.array("nothing", "item") == [] and part.strings("nothing", "item") == []


def test_href_cycles_are_cut() -> None:
    _, part = parse(
        '<ns:opResponse><r href="#a"/></ns:opResponse><multiRef id="a"><loop href="#b"/>'
        '</multiRef><multiRef id="b" href="#b"/>'
    )
    assert part.child("loop") is None


def test_header_and_leading_multirefs_are_skipped() -> None:
    data = ENV.format('<multiRef id="a">t1</multiRef><ns:opResponse><r href="#a"/></ns:opResponse>')
    data = data.replace("<e:Body>", "<e:Header><ns:session>1</ns:session></e:Header><e:Body>")
    name, part = soap.parse(data.encode())
    assert name == "opResponse" and part.text == "t1"


def test_response_without_a_part() -> None:
    name, part = parse("<ns:opResponse/>")
    assert name == "opResponse" and part.children() == []


@pytest.mark.parametrize(
    "data, message",
    [
        (b"not xml", "not XML"),
        (b"<html/>", "not a SOAP envelope"),
        (b'<e:Envelope xmlns:e="urn:e"/>', "no Body"),
        (ENV.format("").encode(), "Body is empty"),
        (b'<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>', "DTD"),
        (b"<x/><!ENTITY a 'b'>", "DTD"),
    ],
)
def test_unreadable_replies(data: bytes, message: str) -> None:
    with pytest.raises(soap.SOAPError, match=message):
        soap.parse(data)


def test_faults() -> None:
    with pytest.raises(soap.SOAPFault) as caught:
        soap.parse(soap.fault("SOAP-ENV:Server", "boom <here>"))
    assert (caught.value.code, caught.value.text) == ("SOAP-ENV:Server", "boom <here>")
    assert str(caught.value) == "SOAP-ENV:Server: boom <here>"
    assert str(soap.SOAPFault("", "bare")) == "bare"


# -- statuses and values -------------------------------------------------------------


def test_errno_for_status() -> None:
    assert soap.errno_for_status("SRM_SUCCESS") == 0
    assert soap.errno_for_status("SRM_RELEASED") == 0
    assert soap.errno_for_status("SRM_INVALID_PATH") == errno.ENOENT
    assert soap.errno_for_status("SRM_FAILURE") == errno.EIO
    assert soap.errno_for_status("SRM_INVALID_REQUEST") == soap.EBADR
    assert soap.errno_for_status("SRM_FILE_LOST") == errno.EIDRM
    assert soap.errno_for_status("SRM_INTERNAL_ERROR") == ECOMM
    assert soap.errno_for_status("SRM_DONE") == errno.EINVAL
    assert soap.errno_for_status("SRM_WHATEVER") == errno.EINVAL
    assert Status("SRM_REQUEST_QUEUED").pending and not Status("SRM_SUCCESS").pending


def test_permissions() -> None:
    assert [soap.permission(bits) for bits in (0, 5, 7, 0o755)] == ["NONE", "RX", "RWX", "RX"]
    assert soap.permission_bits(" rw ") == 6
    assert soap.permission_bits("6") == 6  # gfal2 sends ordinals
    assert soap.permission_bits("bogus") == 0 and soap.permission_bits("") == 0


@pytest.mark.parametrize(
    "text, seconds",
    [
        ("2020-01-02T03:04:05Z", 1577934245),
        ("2020-01-02T03:04:05.123Z", 1577934245),
        ("2020-01-02T03:04:05", 1577934245),
        ("2020-01-02T04:04:05+01:00", 1577934245),
        ("2020-01-02T02:04:05-0100", 1577934245),
        ("yesterday", 0),
        ("", 0),
    ],
)
def test_times(text: str, seconds: int) -> None:
    assert soap.parse_time(text) == seconds


def test_format_time() -> None:
    assert soap.format_time(1577934245.5) == "2020-01-02T03:04:05.000Z"


# -- SURLs ---------------------------------------------------------------------------


def test_short_surl() -> None:
    surl = parse_surl("srm://se.example.org:8446/pnfs/data/f")
    assert (surl.host, surl.port, surl.service, surl.path) == (
        "se.example.org",
        8446,
        "/srm/managerv2",
        "/pnfs/data/f",
    )
    assert surl.endpoint == "httpg://se.example.org:8446/srm/managerv2"
    assert surl.wire == "srm://se.example.org/pnfs/data/f"
    assert surl.parent().url == "srm://se.example.org:8446/pnfs/data"
    assert surl.parent().wire == "srm://se.example.org/pnfs/data"
    assert surl.join("g").url == "srm://se.example.org:8446/pnfs/data/f/g"
    assert parse_surl("srm://se/").parent().path == "/"
    assert parse_surl("srm://se/f").port == 8443


def test_full_surl() -> None:
    surl = parse_surl("srm://se:8443/srm/managerv2?SFN=/data/f&x=1")
    assert (surl.service, surl.path, surl.full) == ("/srm/managerv2", "/data/f", True)
    assert surl.wire == "srm://se/data/f"
    assert surl.parent().url == "srm://se:8443/srm/managerv2?SFN=/data"
    assert parse_surl("srm://se/other/service?SFN=/f").endpoint == "httpg://se:8443/other/service"
    bare = parse_surl("srm://se:8446?SFN=/f")
    assert (bare.host, bare.port, bare.path) == ("se", 8446, "/f")
    assert bare.endpoint == "httpg://se:8446/srm/managerv2"


def test_ipv6_surl() -> None:
    surl = parse_surl("srm://[::1]:9000/f")
    assert surl.wire == "srm://[::1]/f" and surl.endpoint == "httpg://::1:9000/srm/managerv2"


@pytest.mark.parametrize("url", ["srm:///f", "http://h/f", "srm://h", "srm://h?SFN=f"])
def test_bad_surls(url: str) -> None:
    with pytest.raises(GError) as caught:
        parse_surl(url)
    assert caught.value.code == errno.EINVAL


def test_normalise_and_ifce_error() -> None:
    assert normalise_path("/a//b/") == "/a/b" and normalise_path("") == "/"
    error = ifce_error(errno.ENOENT, "[SE][Ls][] x")
    assert error.message.startswith("srm-ifce err: ") and error.message.endswith(
        ", err: [SE][Ls][] x\n"
    )


# -- matching replies to requests ------------------------------------------------------


def test_match_follows_the_request_order() -> None:
    first, second = parse_surl("srm://h:1/a"), parse_surl("srm://h:1/b")
    found = [
        FileStatus("srm://h/b", Status("SRM_SUCCESS")),
        FileStatus("srm://h:1/srm/managerv2?SFN=/a/", Status("SRM_INVALID_PATH")),
    ]
    assert [item.status.code for item in match([first, second], found)] == [
        "SRM_INVALID_PATH",
        "SRM_SUCCESS",
    ]


def test_match_falls_back_on_position_then_failure() -> None:
    first, second = parse_surl("srm://h/a"), parse_surl("srm://h/b")
    matched = match([first, second], [FileStatus("", Status("SRM_SUCCESS"))])
    assert matched[0].status.ok
    assert matched[1].status.code == "SRM_FAILURE" and matched[1].surl == "srm://h/b"
    # a stray SURL at the right position does not stand in
    stray = match([first], [FileStatus("srm://h/c", Status("SRM_SUCCESS"))])
    assert stray[0].status.code == "SRM_FAILURE"
    assert not _same("not a surl", first)
    assert not _same("srm://other/a", first)
