# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""Copies: uploads, parallel downloads, and HTTP third-party copy with gfal2's fallbacks."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

import xgfalclient
from test_http_helpers import Events, dav, dav2, davs, hctx, write  # noqa: F401 - fixtures
from xgfalclient import GError, checksum_mode
from xgfalclient import transfer as transfer_module
from xgfalclient.plugins.http import _copy
from xgfalclient.testing.pki import PKI
from xgfalclient.testing.webdav import WebDAVServer

MB = 1 << 20


def params(events: Events | None = None, **values: object) -> xgfalclient.TransferParameters:
    made = xgfalclient.TransferParameters()
    made.event_callback = events
    for name, value in values.items():
        setattr(made, name, value)
    return made


def file_url(path: Path) -> str:
    return "file://" + os.fspath(path)


@pytest.fixture(autouse=True)
def _report_every_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    """gfal2 reports progress once a second; these copies take milliseconds."""
    monkeypatch.setattr(transfer_module, "MONITOR_INTERVAL", 0.0)


def _cancel_on_type(context: xgfalclient.Gfal2Context) -> Events:
    """An event callback that cancels the copy as soon as its type is announced."""

    class Cancel(Events):
        def __call__(self, event: xgfalclient.GfaltEvent) -> None:
            super().__call__(event)
            if event.stage == "TRANSFER:TYPE":
                context.cancel()

    return Cancel()


# -- uploads ------------------------------------------------------------------------------


def test_upload(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path) -> None:
    source = tmp_path / "up"
    source.write_bytes(b"u" * 1000)
    events = Events()
    hctx.filecopy(params(events), file_url(source), dav.url("/data/up"))
    assert dav.local("/data/up").read_bytes() == b"u" * 1000
    assert "TRANSFER:TYPE streamed" in events.stages()
    put = dav.requests[-1]
    assert (put.method, put.header("Content-Length")) == ("PUT", "1000")
    hctx.filecopy(params(timeout=0, overwrite=True), file_url(source), dav.url("/data/up"))
    assert dav.requests[-1].method == "PUT"  # no deadline: the I/O timeout applies


def test_upload_errors(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path) -> None:
    with pytest.raises(GError) as caught:
        hctx.filecopy(file_url(tmp_path / "missing"), dav.url("/data/x"))
    assert caught.value.code == errno.ENOENT
    assert "Could not open source" in caught.value.message
    source = tmp_path / "up"
    source.write_bytes(b"x")
    dav.fault("PUT", status=403)
    with pytest.raises(GError) as caught:
        hctx.filecopy(file_url(source), dav.url("/data/x"))
    assert caught.value.code == errno.EPERM


def test_local_failures_without_an_errno(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ``OSError`` that names no errno is reported as EIO."""

    def refuse(*args: object, **kwargs: object) -> int:
        raise OSError("refused")

    source = tmp_path / "up"
    source.write_bytes(b"x")
    monkeypatch.setattr(_copy, "open", refuse, raising=False)
    with pytest.raises(GError) as caught:
        hctx.filecopy(file_url(source), dav.url("/data/x"))
    assert caught.value.code == errno.EIO and "Could not open source" in caught.value.message
    write(dav, "/data/f", b"x")
    monkeypatch.setattr(_copy.os, "open", refuse)
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/f"), file_url(tmp_path / "down"))
    assert caught.value.code == errno.EIO and "Could not open destination" in caught.value.message


def test_cancelled_upload(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path
) -> None:
    source = tmp_path / "up"
    source.write_bytes(b"x" * 100)
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(_cancel_on_type(hctx)), file_url(source), dav.url("/data/x"))
    assert caught.value.code == errno.ECANCELED


# -- downloads ----------------------------------------------------------------------------


def test_download_single_stream(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path
) -> None:
    write(dav, "/data/f", b"d" * 5000)
    events = Events()
    hctx.filecopy(params(events), dav.url("/data/f"), file_url(tmp_path / "down"))
    assert (tmp_path / "down").read_bytes() == b"d" * 5000
    assert "TRANSFER:TYPE streamed" in events.stages()


def test_parallel_download(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_copy, "PARALLEL_THRESHOLD", MB)
    data = os.urandom(3 * MB + 17)
    write(dav, "/data/big", data)
    seen: list[int] = []
    copy = params(nbstreams=3)
    copy.monitor_callback = lambda src, dst, avg, inst, done, elapsed: seen.append(done)
    hctx.filecopy(copy, dav.url("/data/big"), file_url(tmp_path / "big"))
    assert (tmp_path / "big").read_bytes() == data
    ranges = sorted(r.header("Range") or "" for r in dav.requests if r.method == "GET")
    assert len(ranges) == 3 and all(r.startswith("bytes=") for r in ranges)
    assert seen[-1] == len(data)
    dav.clear()
    hctx.filecopy(params(nbstreams=1), dav.url("/data/big"), file_url(tmp_path / "one"))
    assert (tmp_path / "one").read_bytes() == data
    assert [r.header("Range") for r in dav.requests if r.method == "GET"] == [None]


def test_parallel_download_without_ranges(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_copy, "PARALLEL_THRESHOLD", MB)
    data = os.urandom(2 * MB)
    write(dav, "/data/big", data)
    dav.ignore_range = True
    hctx.filecopy(dav.url("/data/big"), file_url(tmp_path / "big"))
    assert (tmp_path / "big").read_bytes() == data


def test_parallel_download_failures(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_copy, "PARALLEL_THRESHOLD", MB)
    write(dav, "/data/big", os.urandom(8 * MB))
    dav.fault("GET", status=403)
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(nbstreams=2), dav.url("/data/big"), file_url(tmp_path / "a"))
    assert caught.value.code == errno.EPERM
    dav.fault("GET", status=206, body=b"ab")
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(nbstreams=2), dav.url("/data/big"), file_url(tmp_path / "b"))
    assert caught.value.code == errno.EIO and "Short read" in caught.value.message


def test_download_errors(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path) -> None:
    write(dav, "/data/f", b"0123456789")
    dav.fault("GET", status=200, body=b"01234")
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/f"), file_url(tmp_path / "a"))
    assert caught.value.code == errno.EIO and "Short copy" in caught.value.message
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/f"), file_url(tmp_path / "no" / "dir"))
    assert "Could not open destination" in caught.value.message
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data"), file_url(tmp_path / "b"))
    assert caught.value.code == errno.EISDIR


# -- third-party copy ---------------------------------------------------------------------


def test_pull(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer) -> None:
    write(dav, "/data/src", b"s" * 3000)
    dav2.marker_every = 1000
    events = Events()
    seen: list[int] = []
    copy = params(events)
    copy.monitor_callback = lambda src, dst, avg, inst, done, elapsed: seen.append(done)
    hctx.filecopy(copy, dav.url("/data/src"), dav2.url("/data/dst"))
    assert dav2.local("/data/dst").read_bytes() == b"s" * 3000
    stages = events.stages()
    assert stages[stages.index("TRANSFER:TYPE 3rd pull") - 1].startswith("TRANSFER:ENTER")
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert copy_request.header("Source") == f"http://127.0.0.1:{dav.port}/data/src"
    assert copy_request.header("X-Number-Of-Streams") == "0"
    assert copy_request.header("Secure-Redirection") == "1"
    assert copy_request.header("Credential") == "none"
    assert copy_request.header("X-No-Delegate") == "true"
    assert copy_request.header("RequireChecksumVerification") == "false"
    assert copy_request.header("TransferHeaderAuthorization") is None
    assert copy_request.header("Overwrite") is None
    assert seen[-1] == 3000


def test_pull_with_everything(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"abc")
    write(dav2, "/data/dst", b"old")
    copy = params(overwrite=True, scitag=65, nbstreams=4)
    copy.set_checksum(checksum_mode.both, "adler32", "")
    hctx.filecopy(copy, dav.url("/data/src?authz=READTOKEN"), dav2.url("/data/dst"))
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert copy_request.header("Source") == f"http://127.0.0.1:{dav.port}/data/src"
    assert copy_request.header("TransferHeaderAuthorization") == "Bearer READTOKEN"
    assert copy_request.header("RequireChecksumVerification") == "true"
    assert copy_request.header("SciTag") == "65"
    assert copy_request.header("Overwrite") == "T"
    assert copy_request.header("X-Number-Of-Streams") == "4"
    assert dav2.local("/data/dst").read_bytes() == b"abc"


def test_fallback_to_push(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"push me")
    dav2.tpc = "xrootd"  # answers COPY with "OK" and hangs up, as XrdHttp without TPC does
    events = Events()
    hctx.filecopy(params(events), dav.url("/data/src"), dav2.url("/data/dst"))
    assert dav2.local("/data/dst").read_bytes() == b"push me"
    assert events.stages()[1:4] == [
        "TRANSFER:TYPE 3rd pull",
        "CLEANUP 0",
        "TRANSFER:TYPE 3rd push",
    ]
    assert [side for side, _, stage, _ in events.seen if stage == "CLEANUP"] == [1]
    push = next(r for r in dav.requests if r.method == "COPY")
    assert push.header("Destination") == f"http://127.0.0.1:{dav2.port}/data/dst"


def test_fallback_to_streamed(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"stream me")
    dav.tpc = dav2.tpc = "xrootd"
    events = Events()
    hctx.filecopy(params(events), dav.url("/data/src"), dav2.url("/data/dst"))
    assert dav2.local("/data/dst").read_bytes() == b"stream me"
    types = [s for s in events.stages() if s.startswith("TRANSFER:TYPE")]
    assert types == ["TRANSFER:TYPE 3rd pull", "TRANSFER:TYPE 3rd push", "TRANSFER:TYPE streamed"]


def test_every_mode_fails(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/nope"), dav2.url("/data/dst"))
    assert caught.value.code == errno.ENOENT
    assert caught.value.message == (
        "TRANSFER ERROR: Copy failed (3rd pull, 3rd push, streamed). "
        "Last attempt: Result HTTP 404 : File not found  after 1 attempts"
    )


def test_streamed_http_copy_of_a_directory(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "streamed")
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data"), dav2.url("/data/dst"))
    assert caught.value.code == errno.EISDIR


def test_streamed_short_copy(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "streamed")
    write(dav, "/data/src", b"0123456789")
    dav.fault("GET", status=200, body=b"012")
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    assert caught.value.code == errno.EIO


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({}, ["3rd pull", "3rd push", "streamed"]),
        ({"DEFAULT_COPY_MODE": "3rd push"}, ["3rd push", "streamed"]),
        ({"DEFAULT_COPY_MODE": "pull"}, ["3rd pull", "3rd push", "streamed"]),
        ({"DEFAULT_COPY_MODE": "streamed"}, ["streamed"]),
        ({"DEFAULT_COPY_MODE": "sideways"}, ["3rd pull", "3rd push", "streamed"]),
        ({"ENABLE_REMOTE_COPY": "false"}, ["streamed"]),
        ({"ENABLE_STREAM_COPY": "false"}, ["3rd pull", "3rd push"]),
        ({"ENABLE_FALLBACK_TPC_COPY": "false"}, ["3rd pull"]),
        ({"ENABLE_FALLBACK_TPC_COPY": "false", "DEFAULT_COPY_MODE": "push"}, ["3rd push"]),
    ],
)
def test_copy_modes(
    hctx: xgfalclient.Gfal2Context, options: dict[str, str], expected: list[str]
) -> None:
    for key, value in options.items():
        hctx.set_opt_string("HTTP PLUGIN", key, value)
    plugin = hctx.plugin("davs://h/", "copy")
    assert _copy.copy_modes(plugin, "davs://a/f", "davs://b/f") == expected  # type: ignore[arg-type]
    forced = _copy.copy_modes(plugin, "davs+3rd://a/f", "davs://b/f")  # type: ignore[arg-type]
    assert forced == [mode for mode in expected if mode != "streamed"]


def test_third_party_only_with_nothing_left(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_REMOTE_COPY", False)
    write(dav, "/data/src", b"x")
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/src", scheme="dav+3rd"), dav2.url("/data/dst"))
    assert caught.value.code == errno.EPERM
    assert "STREAMED DISABLED" in caught.value.message


def test_tpc_failures(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
    write(dav, "/data/src", b"x")
    dav2.tpc = "fail"
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    assert caught.value.message.endswith(
        "Last attempt: Transfer failure: HTTP 500 : the remote side refused"
    )
    dav2.tpc = "normal"
    dav2.fault("COPY", status=405)
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    assert caught.value.code == errno.EPERM
    dav2.fault("COPY", status=412)
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    assert caught.value.code == errno.EEXIST
    dav2.fault("COPY", status=202, body=b"failed\n")  # no detail: the line is the detail
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    assert caught.value.message.endswith("Transfer failure: failed")
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "3rd push")
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/nope"), dav2.url("/data/dst"))
    assert caught.value.code == errno.ENOENT  # quoted 404 in the failure line
    port = dav2.port
    dav2.stop()
    with pytest.raises(GError) as caught:
        hctx.filecopy(
            params(strict_copy=True), dav.url("/data/src"), f"dav://127.0.0.1:{port}/data/dst"
        )
    assert "Transfer failure: could not reach the destination" in caught.value.message


def test_pull_from_an_unreachable_source(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
    hctx.set_opt_boolean("CORE", "FORMAT_ADLER32_CHECKSUM", True)
    write(dav, "/data/src", b"x")
    port = dav.port
    dav.stop()
    with pytest.raises(GError) as caught:
        hctx.filecopy(f"dav://127.0.0.1:{port}/data/src", dav2.url("/data/dst"))
    assert caught.value.code != 0 and "could not reach the source" in caught.value.message


def test_tpc_that_never_reports(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
    write(dav, "/data/src", b"x")
    dav2.tpc = "eof"
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    assert "Connection terminated abruptly; Status of TPC request unknown" in caught.value.message


def test_no_fallback_after_eexist_or_cancel(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"x" * 4000)
    events = Events()
    dav2.fault("COPY", status=412)
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(events), dav.url("/data/src"), dav2.url("/data/dst"))
    assert caught.value.code == errno.EEXIST
    assert [s for s in events.stages() if s.startswith("TRANSFER:TYPE")] == [
        "TRANSFER:TYPE 3rd pull"
    ]
    dav2.marker_every = 1000
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(_cancel_on_type(hctx)), dav.url("/data/src"), dav2.url("/data/dst2"))
    assert caught.value.code == errno.ECANCELED
    assert caught.value.message == "Transfer canceled"


def test_no_fallback_once_out_of_time(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"x")
    dav2.fault("COPY", status=500, delay=1.1)
    events = Events()
    with pytest.raises(GError):
        hctx.filecopy(params(events, timeout=1), dav.url("/data/src"), dav2.url("/data/dst"))
    assert [s for s in events.stages() if s.startswith("TRANSFER:TYPE")] == [
        "TRANSFER:TYPE 3rd pull"
    ]


def test_cleanup_between_attempts(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"x")
    dav2.tpc = "eof"  # writes the file, then never says how it went
    dav2.fault("DELETE", status=403)
    events = Events()
    hctx.filecopy(params(events, overwrite=True), dav.url("/data/src"), dav2.url("/data/dst"))
    assert "CLEANUP 1" in events.stages()  # EPERM from the DELETE, reported, then push
    dav2.tpc = "eof"
    events = Events()
    hctx.filecopy(
        params(events, overwrite=True, transfer_cleanup=False),
        dav.url("/data/src"),
        dav2.url("/data/dst"),
    )
    assert not [s for s in events.stages() if s.startswith("CLEANUP")]


def test_copy_check(hctx: xgfalclient.Gfal2Context) -> None:
    plugin = hctx.plugin("davs://h/", "copy")
    assert plugin.copy_check("davs://a/f", "https://b/f")
    assert plugin.copy_check("file:///tmp/f", "davs://b/f")
    assert plugin.copy_check("davs://a/f", "file:///tmp/f")
    assert not plugin.copy_check("root://a/f", "davs://b/f")
    assert not plugin.copy_check("davs://a/f", "root://b/f")
    assert not plugin.copy_check("file:///a", "file:///b")


# -- credentials in a third-party copy ------------------------------------------------------


def test_far_token_from_the_context(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"x")
    dav.tokens = {"SRC"}
    dav2.tokens = {"SRC"}
    hctx.cred_set(dav.url("/"), hctx.cred_new("BEARER", "SRC"))
    hctx.cred_set(dav2.url("/"), hctx.cred_new("BEARER", "SRC"))
    hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert copy_request.header("TransferHeaderAuthorization") == "Bearer SRC"
    assert copy_request.header("Authorization") == "Bearer SRC"


def test_macaroon_for_the_far_side(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, dav2: WebDAVServer, grid_env: PKI
) -> None:
    write(davs, "/data/src", b"from tls")
    events = Events()
    hctx.filecopy(params(events), davs.url("/data/src"), dav2.url("/data/dst"))
    assert dav2.local("/data/dst").read_bytes() == b"from tls"
    issued = davs.macaroons[0]
    assert issued["caveats"] == ["activity:LIST,DOWNLOAD"]
    assert issued["validity"] == "PT61M"
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert copy_request.header("TransferHeaderAuthorization") == f"Bearer {issued['macaroon']}"
    assert copy_request.header("Source") == f"https://127.0.0.1:{davs.port}/data/src"


def test_macaroon_refused_then_no_token(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, dav2: WebDAVServer, grid_env: PKI
) -> None:
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
    write(davs, "/data/src", b"x")
    davs.fault("POST", status=403)
    with pytest.raises(GError):
        hctx.filecopy(davs.url("/data/src"), dav2.url("/data/dst"))
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert copy_request.header("TransferHeaderAuthorization") is None
    assert copy_request.header("Credential") == "none"
    hctx.set_opt_boolean("HTTP PLUGIN", "RETRIEVE_BEARER_TOKEN", False)
    dav2.clear()
    with pytest.raises(GError):
        hctx.filecopy(davs.url("/data/src"), dav2.url("/data/dst2"))
    assert not [r for r in davs.requests if r.method == "POST" and r.path.endswith("dst2")]


def test_push_asks_for_a_write_macaroon(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, davs: WebDAVServer, grid_env: PKI
) -> None:
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "3rd push")
    write(dav, "/data/src", b"pushed over tls")
    dav.client_tls = grid_env.client_context()
    davs.tokens = {"unused"}  # the pushed PUT must carry the macaroon (or the cert)
    hctx.filecopy(dav.url("/data/src"), davs.url("/data/dst"))
    assert davs.local("/data/dst").read_bytes() == b"pushed over tls"
    assert davs.macaroons[0]["caveats"] == ["activity:LIST,MANAGE,UPLOAD,DELETE"]


def test_delegation(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, davs: WebDAVServer, grid_env: PKI
) -> None:
    write(dav, "/data/src", b"delegated")
    davs.delegation = True
    hctx.filecopy(dav.url("/data/src"), davs.url("/data/dst"))
    assert davs.local("/data/dst").read_bytes() == b"delegated"
    copy_request = next(r for r in davs.requests if r.method == "COPY")
    assert copy_request.header("Credential") is None
    (chain,) = davs.delegated.values()
    assert chain[0].is_proxy
    davs.delegation_version = 1
    hctx.filecopy(params(overwrite=True), dav.url("/data/src"), davs.url("/data/dst"))
    assert len(davs.delegated) == 2
    davs.clear()
    hctx.filecopy(
        params(overwrite=True, proxy_delegation=False), dav.url("/data/src"), davs.url("/data/dst")
    )
    copy_request = next(r for r in davs.requests if r.method == "COPY")
    assert copy_request.header("Credential") == "none"
    assert len(davs.delegated) == 2
