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
    with pytest.raises(GError) as caught:
        hctx.getxattr(dav.url("/data/a"), "user.status")
    assert caught.value.code == errno.EPERM
    assert caught.value.message == (
        "[Tape REST API] Failed to query /.well-known/wlcg-tape-rest-api: "
        "HTTP 403 : Permission refused "
    )
    port = dav.port
    dav.stop()
    with pytest.raises(GError) as caught:
        hctx.getxattr(f"dav://127.0.0.1:{port}/x", "taperestapi.uri")
    assert caught.value.message.endswith("Could not connect to server")


def test_discovery_xattrs(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    url = dav.url("/data/a")
    assert hctx.getxattr(url, "taperestapi.version") == "v1"
    assert hctx.getxattr(url, "taperestapi.uri") == f"{dav.base}/api/v1"
    assert hctx.getxattr(url, "taperestapi.sitename") == "XGFAL-TEST"
    assert [r.path for r in dav.requests].count(WELL_KNOWN) == 1  # cached


@pytest.mark.parametrize(
    ("document", "words"),
    [
        (b"not json", "Malformed served response"),
        ([1, 2], "Malformed served response"),
        ({"endpoints": []}, "No sitename"),
        ({"sitename": "", "endpoints": []}, "No sitename"),
        ({"sitename": "X"}, "No endpoints"),
        ({"sitename": "X", "endpoints": []}, "No endpoints"),
        (
            {
                "sitename": "X",
                "endpoints": ["x", {"uri": "/v2", "version": "v2"}, {"version": "v1"}],
            },
            "v0 or v1",
        ),
    ],
)
def test_bad_discovery_documents(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape, document: object, words: str
) -> None:
    tape.discovery = document
    with pytest.raises(GError) as caught:
        hctx.getxattr(dav.url("/data/a"), "taperestapi.uri")
    assert words in caught.value.message
    assert caught.value.code == errno.EPROTO


def test_discovery_prefers_v1(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    tape.discovery = {
        "sitename": "X",
        "endpoints": [
            {"uri": f"{dav.base}/api/v0/", "version": "v0"},
            {"uri": f"{dav.base}/api/v1/", "version": "v1"},
            {"uri": f"{dav.base}/api/v0b/", "version": "v0"},
        ],
    }
    assert hctx.getxattr(dav.url("/x"), "taperestapi.uri") == f"{dav.base}/api/v1"


def test_user_status(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    tape.locality.update({"/data/l": "LOST", "/data/w": "WEIRD"})
    status = {path: hctx.getxattr(dav.url(path), "user.status") for path in tape.locality}
    assert status == {
        "/data/a": "NEARLINE",
        "/data/b": "ONLINE",
        "/data/c": "ONLINE_AND_NEARLINE",
        "/data/l": "LOST",
        "/data/w": "UNKNOWN",
    }
    with pytest.raises(GError) as caught:
        hctx.getxattr(dav.url("/data/missing"), "user.status")
    assert caught.value.code == errno.ENOENT
    assert caught.value.message == "[Tape REST API] USER ERROR: file not found"


def test_bring_online_async(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    tape.stage_polls = 1
    status, token = hctx.bring_online(dav.url("/data/a"), 3600, 60, True)
    assert status == 0 and token in tape.requests
    stage = next(r for r in dav.requests if r.path == "/api/v1/stage")
    assert json.loads(stage.body) == {"files": [{"path": "/data/a"}]}
    assert hctx.bring_online_poll(dav.url("/data/a"), token) == 1
    assert hctx.release(dav.url("/data/a"), token) == 0
    assert tape.released == [(token, ["/data/a"])]


def test_bring_online_waits_when_synchronous(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    tape: Tape,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_tape, "POLL_START", 0.01)
    tape.stage_polls = 2
    status, _ = hctx.bring_online(dav.url("/data/a"), 3600, 30, False)
    assert status == 1
    tape.stage_polls = 100
    status, _ = hctx.bring_online(dav.url("/data/a"), 3600, 0, False)
    assert status == 0


def test_bring_online_lists_and_metadata(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    urls = [dav.url("/data/a"), dav.url("/data/b")]
    errors, token = hctx.bring_online(urls, ['{"activity": "x"}', ""], 3600, 60, True)
    assert errors == [None, None]
    stage = next(r for r in dav.requests if r.path == "/api/v1/stage")
    assert json.loads(stage.body)["files"][0]["targetedMetadata"] == {"activity": "x"}
    with pytest.raises(GError) as caught:
        hctx.bring_online(urls, ["[1]", ""], 3600, 60, True)
    assert (caught.value.code, caught.value.message) == (
        errno.EINVAL,
        "Invalid metadata format: [1]",
    )
    with pytest.raises(GError):
        hctx.bring_online(urls, ["{nope", ""], 3600, 60, True)
    assert hctx.abort_bring_online(urls, token) == [None, None]
    polled = hctx.bring_online_poll(urls, token)
    assert [e.code for e in polled] == [errno.ECANCELED, errno.ECANCELED]


def test_poll_outcomes(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    tape.locality["/data/lost"] = "LOST"
    urls = [dav.url("/data/a"), dav.url("/data/lost")]
    _, token = hctx.bring_online(urls, 3600, 60, True)
    tape.stage_polls = 5
    results = hctx.bring_online_poll(urls, token)
    assert results[0].code == errno.EAGAIN
    assert (results[1].code, results[1].message) == (errno.EIO, "[Tape REST API] file is LOST")
    with pytest.raises(GError) as caught:
        hctx.bring_online_poll(urls, "")
    assert caught.value.code == errno.EINVAL
    with pytest.raises(GError) as caught:
        hctx.bring_online_poll(urls, "no-such-request")
    assert caught.value.code == errno.ENOENT
    assert caught.value.message.startswith("[Tape REST API] Stage polling call failed: HTTP 404")


def _reply(dav: WebDAVServer, document: object, method: str = "GET") -> None:
    dav.fault(method, path="/api/v1/", status=200, body=json.dumps(document).encode())


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ([], "Malformed server response"),
        ({"id": "other", "files": []}, "Request ID mismatch"),
        ({"files": "nope"}, "Files attribute missing"),
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


def test_file_states(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    hctx.getxattr(dav.url("/x"), "taperestapi.uri")
    names = ["done", "sub", "fail", "odd", "nostate", "offdisk", "canceled", "missing"]
    urls = [dav.url(f"/data/{name}") for name in names]
    _reply(
        dav,
        {
            "id": "id1",
            "files": [
                {"path": "/data/done", "state": "COMPLETED"},
                {"path": "/data/sub", "state": "SUBMITTED"},
                {"path": "/data/fail", "state": "FAILED"},
                {"path": "/data/odd", "state": "SIDEWAYS"},
                {"path": "/data/nostate"},
                {"path": "/data/offdisk", "onDisk": False},
                {"path": "/data/canceled", "state": "CANCELED"},
                "not a dict",
            ],
        },
    )
    results = hctx.bring_online_poll(urls, "id1")
    assert results[0] is None
    assert [r.code for r in results[1:]] == [
        errno.EAGAIN,
        errno.EIO,
        errno.EPROTO,
        errno.EPROTO,
        errno.EAGAIN,
        errno.ECANCELED,
        errno.ENOENT,
    ]


def test_stage_failures(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    hctx.getxattr(dav.url("/x"), "taperestapi.uri")
    dav.fault("POST", path="/api/v1/stage", status=500, body=b"tape is on fire")
    with pytest.raises(GError) as caught:
        hctx.bring_online(dav.url("/data/a"), 3600, 60, True)
    assert caught.value.message == (
        "[Tape REST API] Stage call failed: HTTP 500 : Internal Server Error : tape is on fire"
    )
    dav.fault("POST", path="/api/v1/stage", status=500)
    with pytest.raises(GError) as caught:
        hctx.bring_online(dav.url("/data/a"), 3600, 60, True)
    assert caught.value.message.endswith("Internal Server Error ")
    _reply(dav, {"noRequestId": 1}, "POST")
    with pytest.raises(GError) as caught:
        hctx.bring_online(dav.url("/data/a"), 3600, 60, True)
    assert caught.value.message == "[Tape REST API] requestID attribute missing"
    dav.fault("POST", path="/api/v1/stage", status=201, body=b"")
    with pytest.raises(GError):
        hctx.bring_online(dav.url("/data/a"), 3600, 60, True)
    dav.fault("POST", path="/api/v1/stage", status=201, body=b"<html>")
    with pytest.raises(GError) as caught:
        hctx.bring_online(dav.url("/data/a"), 3600, 60, True)
    assert caught.value.message == "[Tape REST API] Malformed server response"


def test_release_and_abort_failures(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    url = dav.url("/data/a")
    with pytest.raises(GError) as caught:
        hctx.release(url, "")
    assert caught.value.code == errno.EINVAL
    dav.fault("POST", path="/api/v1/release", status=403)
    with pytest.raises(GError) as caught:
        hctx.release(url, "id")
    assert caught.value.message.startswith("[Tape REST API] Release call failed: HTTP 403")
    (failed,) = hctx.abort_bring_online([url], "no-such-id")
    assert failed.message.startswith("[Tape REST API] Cancel call failed")


def test_archive_poll(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape) -> None:
    tape.locality.update({"/data/n": "NONE", "/data/l": "LOST", "/data/u": "UNAVAILABLE"})
    assert hctx.archive_poll(dav.url("/data/a")) == 1
    assert hctx.archive_poll(dav.url("/data/c")) == 1
    assert hctx.archive_poll(dav.url("/data/b")) == 0
    names = ["a", "b", "n", "l", "u", "missing"]
    results = hctx.archive_poll([dav.url(f"/data/{n}") for n in names])
    assert results[0] is None
    assert [r.code for r in results[1:]] == [
        errno.EAGAIN,
        errno.ENOENT,
        errno.EIO,
        errno.EIO,
        errno.ENOENT,
    ]
    assert results[3].message == "[Tape REST API] File locality reported as LOST (path=/data/l)"


def test_malformed_archive_info(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    hctx.getxattr(dav.url("/x"), "taperestapi.uri")
    _reply(dav, {"not": "a list"}, "POST")
    with pytest.raises(GError) as caught:
        hctx.archive_poll(dav.url("/data/a"))
    assert caught.value.code == errno.EPROTO
    _reply(
        dav,
        [
            {"path": "/data/a"},
            {"path": "/data/b", "error": "tape drive exploded"},
            {"path": "/data/d", "error": "not yet migrated"},
            7,
        ],
        "POST",
    )
    urls = [dav.url(path) for path in ("/data/a", "/data/b", "/data/c", "/data/d")]
    results = hctx.archive_poll(urls)
    assert results[0].message == "[Tape REST API] Locality attribute missing"
    assert (results[1].code, results[1].message) == (
        errno.EIO,
        "[Tape REST API] tape drive exploded",
    )
    assert results[2].message == "[Tape REST API] Missing response item for path=/data/c"
    assert results[3].code == errno.EIO  # "not", but not "not found"


def test_tape_call_transport_failure(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tape: Tape
) -> None:
    hctx.getxattr(dav.url("/x"), "taperestapi.uri")
    dav.fault("POST", path="/api/v1/", drop=True, times=2)
    with pytest.raises(GError) as caught:
        hctx.archive_poll(dav.url("/data/a"))
    assert caught.value.message.startswith("[Tape REST API] Archive polling call failed:")
