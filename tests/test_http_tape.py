# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""The WLCG Tape REST API: bring_online, polls, release, abort, archive status, xattrs."""

from __future__ import annotations

import errno
import json

import pytest

import xgfalclient
from test_http_helpers import dav, hctx  # noqa: F401 - fixtures
from xgfalclient import GError
from xgfalclient.plugins.http import _tape
from xgfalclient.testing.webdav import Tape, WebDAVServer

WELL_KNOWN = "/.well-known/wlcg-tape-rest-api"


@pytest.fixture
def tape(dav: WebDAVServer) -> Tape:
    dav.tape = Tape(locality={"/data/a": "TAPE", "/data/b": "DISK", "/data/c": "DISK_AND_TAPE"})
    return dav.tape


def test_without_a_tape_api(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    # davix itself fails a 401 or 403, with its own words and errno...
    with pytest.raises(GError) as caught:
        hctx.getxattr(dav.url("/data/a"), "user.status")
    assert (caught.value.code, caught.value.message) == (
        errno.EPERM,
        "[Tape REST API] Failed to query /.well-known/wlcg-tape-rest-api: "
        "HTTP 403 : Permission refused ",
    )
    dav.fault("GET", WELL_KNOWN, status=401, body=b"who?")
    with pytest.raises(GError) as caught:
        hctx.getxattr(dav.url("/data/a"), "user.status")
    assert (caught.value.code, caught.value.message) == (
        errno.EACCES,
        "[Tape REST API] Failed to query /.well-known/wlcg-tape-rest-api: "
        "HTTP 401 : Authentication Error ",
    )
    # ...and gfal2 any other status but 200, with the body.
    dav.fault("GET", WELL_KNOWN, status=404, body=b"no tape here")
    with pytest.raises(GError) as caught:
        hctx.getxattr(dav.url("/data/a"), "user.status")
    assert (caught.value.code, caught.value.message) == (
        errno.EINVAL,
        "[Tape REST API] Failed to query /.well-known/wlcg-tape-rest-api: "
        "HTTP 404 : File not found : no tape here",
    )
    port = dav.port
    dav.stop()
    with pytest.raises(GError) as caught:
        hctx.getxattr(f"dav://127.0.0.1:{port}/x", "taperestapi.uri")
    assert caught.value.message.endswith("Could not connect to server")


def test_only_http_and_webdav_urls(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer) -> None:
    """gfal2's check_url: xattrs and tape calls are not for s3, gcloud, swift, cs3 or +3rd."""
    for url in ("s3://h/b/k", "dav+3rd://h/f", "swift://h/c/o", "cs3://h/f"):
        with pytest.raises(GError) as caught:
            hctx.listxattr(url)
        assert caught.value.code == errno.EPROTONOSUPPORT
        with pytest.raises(GError) as caught:
            hctx.bring_online(url, 0, 0, True)
        assert caught.value.code == errno.EPROTONOSUPPORT


def test_discovery_xattrs(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    url = dav.url("/data/a")
    assert hctx.getxattr(url, "taperestapi.version") == "v1"
    assert hctx.getxattr(url, "taperestapi.uri") == f"{dav.base}/api/v1/"  # as served
    assert hctx.getxattr(url, "taperestapi.sitename") == "XGFAL-TEST"
    assert [r.path for r in dav.requests].count(WELL_KNOWN) == 1  # cached


@pytest.mark.parametrize(
    ("document", "words"),
    [
        (b"not json", "Malformed served response"),
        ([1, 2], "Malformed served response"),
        ({"endpoints": []}, "No sitename"),
        ({"sitename": "X"}, "No endpoints"),
        ({"sitename": "X", "endpoints": []}, "v0 or v1"),
        ({"sitename": "X", "endpoints": "nope"}, "v0 or v1"),
        (
            {
                "sitename": "X",
                "endpoints": [
                    "x",
                    {"uri": "/v2", "version": "v2"},
                    {"uri": "/vx", "version": "vx"},
                    {"version": "v1"},
                    {"uri": "/nv"},
                ],
            },
            "v0 or v1",
        ),
        ({"sitename": "X", "endpoints": [{"uri": "", "version": "v1"}]}, "v0 or v1"),
    ],
)
def test_bad_discovery_documents(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape, document: object, words: str
) -> None:
    tape.discovery = document
    with pytest.raises(GError) as caught:
        hctx.getxattr(dav.url("/data/a"), "taperestapi.uri")
    assert words in caught.value.message
    assert caught.value.code == errno.ENOMSG


def test_discovery_takes_the_highest_version_leniently(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    tape.discovery = {
        "sitename": 7,
        "endpoints": [
            {"uri": f"{dav.base}/api/v0/", "version": "v0"},
            {"uri": f"{dav.base}/api/v1/", "version": "V1"},
            {"uri": f"{dav.base}/api/v0b/", "version": "v0"},
            {"uri": f"{dav.base}/api/v1", "version": 1},
        ],
    }
    url = dav.url("/data/a")
    assert hctx.getxattr(url, "taperestapi.uri") == f"{dav.base}/api/v1"  # the last v1 wins
    assert hctx.getxattr(url, "taperestapi.version") == "1"
    assert hctx.getxattr(url, "taperestapi.sitename") == "7"
    # A URI without its trailing slash still has calls made under it.
    assert hctx.getxattr(url, "user.status") == "NEARLINE"
    assert dav.requests[-1].path == "/api/v1/archiveinfo"
    assert [_tape._parse_version(v) for v in ("v", "v1.2", "", "x1")] == [0, 1, 0, -1]


def test_user_status(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    tape.locality.update({"/data/l": "LOST", "/data/n": "NONE", "/data/u": "UNAVAILABLE"})
    tape.locality["/data/w"] = "WEIRD"
    status = {
        path: hctx.getxattr(dav.url(path), "user.status")
        for path in ["/data/a", "/data/b", "/data/c"]
    }
    assert status == {
        "/data/a": "NEARLINE",
        "/data/b": "ONLINE",
        "/data/c": "ONLINE_AND_NEARLINE",
    }
    expected = {
        "/data/l": (errno.ENOENT, "[Tape REST API] File locality reported as LOST (path=/data/l)"),
        "/data/n": (errno.EPERM, "[Tape REST API] File locality reported as NONE (path=/data/n)"),
        "/data/u": (
            errno.EAGAIN,
            "[Tape REST API] File locality reported as UNAVAILABLE (path=/data/u)",
        ),
        "/data/w": (
            errno.ENOMSG,
            '[Tape REST API] File locality reported as "WEIRD" (path=/data/w)',
        ),
        # The server's "error" is ignored here: what is missing is the locality.
        "/data/missing": (errno.ENOMSG, "[Tape REST API] Locality attribute missing"),
    }
    for path, (code, message) in expected.items():
        with pytest.raises(GError) as caught:
            hctx.getxattr(dav.url(path), "user.status")
        assert (caught.value.code, caught.value.message) == (code, message)


def test_doubled_slashes_are_collapsed(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    """EOS and CTA URLs usually have ``//``; the API names files without them."""
    assert hctx.getxattr(dav.url("//data//a"), "user.status") == "NEARLINE"
    assert json.loads(dav.requests[-1].body) == {"paths": ["/data/a"]}
    _, token = hctx.bring_online(dav.url("//data/a"), 0, 0, True)
    assert tape.requests[token]["files"] == [{"path": "/data/a"}]
    assert hctx.bring_online_poll(dav.url("//data/a"), token) == 1


def test_bring_online_stages_and_returns(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    """One POST, whatever async and the timeout say: the file is queued."""
    for is_async in (True, False):
        dav.clear()
        status, token = hctx.bring_online(dav.url("/data/a"), 3600, 60, is_async)
        assert status == 0 and token in tape.requests
        assert [r.path for r in dav.requests if r.path.startswith("/api")] == ["/api/v1/stage"]
    stage = dav.requests[-1]
    assert json.loads(stage.body) == {"files": [{"path": "/data/a"}]}  # no pin time
    assert hctx.bring_online_poll(dav.url("/data/a"), token) == 1
    assert hctx.release(dav.url("/data/a"), token) == 0
    assert tape.released == [(token, ["/data/a"])]


def test_release_without_a_request_id(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    assert hctx.release(dav.url("/data/a")) == 0
    assert tape.released == [("gfal2-placeholder-id", ["/data/a"])]


def test_bring_online_lists_and_metadata(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    urls = [dav.url("/data/a"), dav.url("/data/b")]
    errors, token = hctx.bring_online(urls, ['{"activity": "x"}', "[1, 2]"], 3600, 60, True)
    assert errors == [None, None]
    stage = next(r for r in dav.requests if r.path == "/api/v1/stage")
    files = json.loads(stage.body)["files"]
    # Any JSON at all, inserted as it is.
    assert [f.get("targetedMetadata") for f in files] == [{"activity": "x"}, [1, 2]]
    failed, _ = hctx.bring_online(urls, ["{nope", ""], 3600, 60, True)
    assert [(e.code, e.message) for e in failed] == [
        (errno.EINVAL, "Invalid metadata format: {nope")
    ] * 2
    with pytest.raises(GError) as caught:
        hctx.bring_online(urls[0], "{nope", 3600, 60, True)
    assert caught.value.code == errno.EINVAL
    assert hctx.abort_bring_online(urls, token) == [None, None]
    assert tape.cancelled == [(token, ["/data/a", "/data/b"])]
    polled = hctx.bring_online_poll(urls, token)  # "onDisk": false outranks "CANCELLED"
    assert [e.code for e in polled] == [errno.EAGAIN, errno.EAGAIN]


def test_poll_outcomes(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    tape.locality["/data/lost"] = "LOST"
    urls = [dav.url("/data/a"), dav.url("/data/lost")]
    _, token = hctx.bring_online(urls, 3600, 60, True)
    tape.stage_polls = 5
    results = hctx.bring_online_poll(urls, token)
    assert (results[0].code, results[0].message) == (
        errno.EAGAIN,
        "[Tape REST API] File /data/a is not yet on disk",
    )
    assert hctx.bring_online_poll(urls[0], token) == 0
    assert (results[1].code, results[1].message) == (errno.ENOMSG, "[Tape REST API] file is LOST")
    assert [e.code for e in hctx.bring_online_poll(urls, "")] == [errno.EINVAL] * 2
    with pytest.raises(GError) as caught:
        hctx.bring_online_poll(urls[0], "no-such-request")
    assert (caught.value.code, caught.value.message) == (
        errno.EINVAL,
        "[Tape REST API] Stage call failed: HTTP 404 : File not found : no such request)",
    )


def _reply(dav: WebDAVServer, document: object, method: str = "GET", status: int = 200) -> None:
    body = document if isinstance(document, bytes) else json.dumps(document).encode()
    dav.fault(method, path="/api/v1/", status=status, body=body)


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        (b"<html>", "Malformed served response"),
        (b"", "Response with no data"),
        ([], "Request ID missing from polling response (expected id=id1)"),
        ({"id": ""}, "Request ID missing"),
        ({"files": []}, "Request ID missing"),
        ({"id": "other", "files": []}, "Request ID mismatch"),
        ({"id": "id1"}, "Files attribute missing"),
    ],
)
def test_malformed_polls(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape, document: object, expected: str
) -> None:
    hctx.getxattr(dav.url("/x"), "taperestapi.uri")
    _reply(dav, document)
    with pytest.raises(GError) as caught:
        hctx.bring_online_poll(dav.url("/data/a"), "id1")
    assert expected in caught.value.message
    assert caught.value.code == errno.ENOMSG


def test_file_states(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    hctx.getxattr(dav.url("/x"), "taperestapi.uri")
    names = ["done", "sub", "fail", "odd", "nostate", "offdisk", "ondisk", "canceled", "err"]
    urls = [dav.url(f"/data/{name}") for name in [*names, "missing"]]
    _reply(
        dav,
        {
            "id": "id1",
            "files": [
                {"path": "/data/done", "state": "COMPLETED"},
                {"path": "/data/sub", "state": "SUBMITTED"},
                {"path": "/data/fail", "state": "FAILED"},
                {"path": "/data/odd", "state": "CANCELLED"},
                {"path": "/data/nostate"},
                # onDisk wins over the state, either way.
                {"path": "/data/offdisk", "onDisk": False, "state": "COMPLETED"},
                {"path": "/data/ondisk", "onDisk": "TRUE", "state": "FAILED"},
                {"path": "/data/canceled", "state": "CANCELED"},
                {"path": "/data/err", "error": "gone", "state": "COMPLETED"},
                "not a dict",
                {"path": ""},
            ],
        },
    )
    results = hctx.bring_online_poll(urls, "id1")
    assert results[0] is None and results[6] is None
    assert [r.code for r in results[1:6]] == [
        errno.EAGAIN,
        errno.ENOENT,
        errno.ENOENT,
        errno.ENOMSG,
        errno.EAGAIN,
    ]
    assert [r.code for r in results[7:]] == [errno.ECANCELED, errno.ENOMSG, errno.ENOMSG]
    assert results[3].message == (
        "[Tape REST API] Unrecognized staging status. File=/data/odd status=CANCELLED"
    )
    assert results[9].message == "[Tape REST API] Missing response item for path=/data/missing"


def test_stage_failures(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    hctx.getxattr(dav.url("/x"), "taperestapi.uri")
    dav.fault("POST", path="/api/v1/stage", status=500, body=b"tape is on fire")
    with pytest.raises(GError) as caught:
        hctx.bring_online(dav.url("/data/a"), 3600, 60, True)
    assert (caught.value.code, caught.value.message) == (
        errno.EINVAL,
        "[Tape REST API] Stage call failed: HTTP 500 : Unexpected server error: 500 : "
        "tape is on fire",
    )
    _reply(dav, {"requestId": "x"}, "POST", 200)  # only 201 will do
    with pytest.raises(GError) as caught:
        hctx.bring_online(dav.url("/data/a"), 3600, 60, True)
    assert caught.value.code == errno.EINVAL
    for document, words in (
        ({"noRequestId": 1}, "[Tape REST API] requestID attribute missing"),
        ([1], "[Tape REST API] requestID attribute missing"),
        (b"", "[Tape REST API] Response with no data"),
        (b"<html>", "[Tape REST API] Malformed served response"),
    ):
        _reply(dav, document, "POST", 201)
        with pytest.raises(GError) as caught:
            hctx.bring_online(dav.url("/data/a"), 3600, 60, True)
        assert (caught.value.code, caught.value.message) == (errno.ENOMSG, words)


def test_release_and_abort_failures(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    url = dav.url("/data/a")
    with pytest.raises(GError) as caught:
        hctx.abort_bring_online(url, "")
    assert caught.value.code == errno.EINVAL
    dav.fault("POST", path="/api/v1/release", status=403)
    with pytest.raises(GError) as caught:
        hctx.release(url, "id")
    assert caught.value.code == errno.EINVAL
    assert caught.value.message.startswith("[Tape REST API] Release call failed: HTTP 403")
    (failed,) = hctx.abort_bring_online([url], "no-such-id")
    # gfal2 calls a refused cancel a failed "Stage" call.
    assert failed.message.startswith("[Tape REST API] Stage call failed: HTTP 404")


def test_archive_poll(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    tape.locality.update(
        {"/data/n": "NONE", "/data/l": "LOST", "/data/u": "UNAVAILABLE", "/data/f": "FOO"}
    )
    assert hctx.archive_poll(dav.url("/data/a")) == 1
    assert hctx.archive_poll(dav.url("/data/c")) == 1
    assert hctx.archive_poll(dav.url("/data/b")) == 0
    assert hctx.archive_poll(dav.url("/data/u")) == 0  # unavailable for now: pending
    names = ["a", "b", "n", "l", "u", "f", "missing"]
    results = hctx.archive_poll([dav.url(f"/data/{n}") for n in names])
    assert results[0] is None
    assert [r.code for r in results[1:]] == [
        errno.EAGAIN,
        errno.EPERM,
        errno.ENOENT,
        errno.EAGAIN,
        errno.ENOMSG,
        errno.ENOMSG,
    ]
    assert results[1].message == "[Tape REST API] File /data/b is not yet archived"
    assert results[3].message == "[Tape REST API] File locality reported as LOST (path=/data/l)"
    assert results[6].message == "[Tape REST API] USER ERROR: file not found"


def test_malformed_archive_info(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    hctx.getxattr(dav.url("/x"), "taperestapi.uri")
    _reply(dav, b"{not json", "POST")
    with pytest.raises(GError) as caught:
        hctx.archive_poll(dav.url("/data/a"))
    assert (caught.value.code, caught.value.message) == (
        errno.ENOMSG,
        "[Tape REST API] Malformed server response",
    )
    _reply(dav, {"not": "a list"}, "POST")
    assert hctx.archive_poll([dav.url("/data/a")])[0].code == errno.ENOMSG
    _reply(dav, [{"path": "/data/a"}, 7], "POST")
    urls = [dav.url(path) for path in ("/data/a", "/data/c")]
    results = hctx.archive_poll(urls)
    assert results[0].message == "[Tape REST API] Locality attribute missing"
    assert results[1].message == "[Tape REST API] Missing response item for path=/data/c"


def test_tape_call_transport_failure(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    hctx.getxattr(dav.url("/x"), "taperestapi.uri")
    dav.fault("POST", path="/api/v1/", drop=True, times=2)
    with pytest.raises(GError) as caught:
        hctx.archive_poll(dav.url("/data/a"))
    assert caught.value.message.startswith("[Tape REST API] Archive polling call failed:")
    dav.fault("GET", path="/api/v1/", drop=True, times=50)
    with pytest.raises(GError) as caught:
        hctx.bring_online_poll(dav.url("/data/a"), "id")
    assert caught.value.message.startswith("[Tape REST API] Stage pooling call failed:")
