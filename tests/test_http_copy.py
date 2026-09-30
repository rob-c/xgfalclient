# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""Copies: uploads, parallel downloads, and HTTP third-party copy with gfal2's fallbacks."""

from __future__ import annotations

import errno
import logging
import os
import socket
import threading
import types
from pathlib import Path

import pytest

import xgfalclient
from test_http_helpers import (  # noqa: F401 - fixtures
    Events,
    dav,
    dav2,
    davs,
    davs_open,
    hctx,
    write,
)
from xgfalclient import GError, checksum_mode
from xgfalclient import transfer as transfer_module
from xgfalclient.plugins.http import _copy
from xgfalclient.testing.pki import PKI
from xgfalclient.testing.webdav import Tape, WebDAVServer

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
    # gfal2 leaves this pair to its core: the core's events, in the core's domain.
    pair = f"{dav.url('/data/f')} => {file_url(tmp_path / 'down')}"
    assert events.stages(xgfalclient.events.DOMAIN_LOCAL) == [
        f"TRANSFER:ENTER {pair}",
        "TRANSFER:TYPE streamed",
        f"TRANSFER:EXIT {pair}",
    ]
    assert not events.stages()


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


def test_parallel_download_failure_stops_the_other_streams(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # One stream fails while the other is mid-segment; the other stops at its
    # next block rather than finishing its range.
    monkeypatch.setattr(_copy, "PARALLEL_THRESHOLD", MB)
    monkeypatch.setattr(_copy, "BLOCK", 64 << 10)
    write(dav, "/data/big", os.urandom(2 * MB))
    stopped = threading.Event()
    second = threading.Event()

    class Watched(threading.Event):
        def set(self) -> None:
            super().set()
            stopped.set()

    fake = types.SimpleNamespace(Lock=threading.Lock, Event=Watched, Thread=threading.Thread)
    monkeypatch.setattr(_copy, "threading", fake)
    original = _copy._pwrite_all
    lock = threading.Lock()
    writes: list[int] = []

    def pwrite(fd: int, view: memoryview, offset: int) -> None:
        with lock:
            writes.append(offset)
            first = len(writes) == 1
        if first:
            assert second.wait(10)
            raise GError("boom", errno.EIO)
        second.set()
        assert stopped.wait(10)
        original(fd, view, offset)

    monkeypatch.setattr(_copy, "_pwrite_all", pwrite)
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(nbstreams=2), dav.url("/data/big"), file_url(tmp_path / "a"))
    assert "boom" in caught.value.message
    assert len(writes) == 2


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
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/nope"), file_url(tmp_path / "c"))
    assert (caught.value.code, caught.value.message) == (
        errno.ENOENT,
        "Could not open source: Result HTTP 404 : File not found  after 1 attempts",
    )


# -- third-party copy ---------------------------------------------------------------------


def test_pull(hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer) -> None:
    write(dav, "/data/src", b"s" * 3000)
    dav2.marker_every = 1000
    events = Events()
    seen: list[int] = []
    copy = params(events)
    copy.monitor_callback = lambda src, dst, avg, inst, done, elapsed: seen.append(done)
    source, destination = dav.url("/data/src"), dav2.url("/data/dst")
    hctx.filecopy(copy, source, destination)
    assert dav2.local("/data/dst").read_bytes() == b"s" * 3000
    pair = f"{source} => {destination}"
    # gfal2's http plugin narrates the copy itself, event for event.
    assert events.stages() == [
        f"PREPARE:ENTER {pair}",
        f"PREPARE:EXIT {pair}",
        f"TRANSFER:ENTER {pair}",
        "TRANSFER:TYPE 3rd pull",
        f"TRANSFER:EXIT {pair}",
    ]
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert copy_request.header("Source") == f"http://127.0.0.1:{dav.port}/data/src"
    assert copy_request.header("X-Number-Of-Streams") == "0"
    assert copy_request.header("Secure-Redirection") == "1"
    assert copy_request.header("Credential") == "none"
    assert copy_request.header("X-No-Delegate") == "true"
    assert copy_request.header("RequireChecksumVerification") == "false"
    assert copy_request.header("TransferHeaderAuthorization") is None
    assert copy_request.header("Copy-Flags") is None
    assert seen[-1] == 3000


def test_every_performance_marker_is_reported(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    dav2: WebDAVServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # davix's performance callback reaches monitor_callback for each marker,
    # however quick the copy; the core's once-a-second clock does not apply.
    monkeypatch.setattr(transfer_module, "MONITOR_INTERVAL", 3600.0)
    write(dav, "/data/src", b"s" * 3000)
    dav2.marker_every = 1000
    seen: list[int] = []
    copy = params()
    copy.monitor_callback = lambda src, dst, avg, inst, done, elapsed: seen.append(done)
    hctx.filecopy(copy, dav.url("/data/src"), dav2.url("/data/dst"))
    assert seen == [1000, 2000, 3000]


def test_pull_with_everything(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"abc")
    write(dav2, "/data/dst", b"old")
    copy = params(overwrite=True, scitag=65, nbstreams=4)
    copy.set_checksum(checksum_mode.both, "adler32", "")
    hctx.filecopy(copy, dav.url("/data/src?authz=READTOKEN"), dav2.url("/data/dst"))
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    # The URL's token stays in its query, as davix leaves it.
    assert copy_request.header("Source") == (
        f"http://127.0.0.1:{dav.port}/data/src?authz=READTOKEN"
    )
    assert copy_request.header("TransferHeaderAuthorization") is None
    assert copy_request.header("RequireChecksumVerification") == "false"
    assert copy_request.header("SciTag") == "65"
    assert copy_request.header("Overwrite") is None  # gfal2 deleted it already
    assert copy_request.header("X-Number-Of-Streams") == "4"
    assert dav2.local("/data/dst").read_bytes() == b"abc"


@pytest.mark.parametrize(
    ("mode", "check", "expected"),
    [
        ("3rd pull", checksum_mode.none, "false"),
        ("3rd pull", checksum_mode.both, "false"),
        ("3rd pull", checksum_mode.source, None),
        ("3rd pull", checksum_mode.target, "false"),
        ("3rd push", checksum_mode.none, "false"),
        ("3rd push", checksum_mode.source, "false"),
        ("3rd push", checksum_mode.target, None),
    ],
)
def test_checksum_verification_header(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    dav2: WebDAVServer,
    mode: str,
    check: object,
    expected: str | None,
) -> None:
    """gfal2 only ever tells dCache not to verify, and only when it verifies that end itself."""
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", mode)
    write(dav, "/data/src", b"abc")
    copy = params()
    copy.set_checksum(check, "adler32", "024d0127")
    hctx.filecopy(copy, dav.url("/data/src"), dav2.url("/data/dst"))
    copy_request = next(r for r in dav.requests + dav2.requests if r.method == "COPY")
    assert copy_request.header("RequireChecksumVerification") == expected


def test_fallback_to_push(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"push me")
    dav2.tpc = "xrootd"  # answers COPY with "OK" and hangs up, as XrdHttp without TPC does
    events = Events()
    hctx.filecopy(params(events), dav.url("/data/src"), dav2.url("/data/dst"))
    assert dav2.local("/data/dst").read_bytes() == b"push me"
    assert events.stages()[3:6] == [
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
    events = Events()
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(events), dav.url("/data/nope"), dav2.url("/data/dst"))
    assert caught.value.code == errno.ENOENT
    last = (
        "ERROR: Copy failed (3rd pull, 3rd push, streamed). "
        "Last attempt: Result HTTP 404 : File not found  after 1 attempts"
    )
    assert caught.value.message == f"TRANSFER {last}"
    stages = events.stages()
    # Every failed attempt is cleaned up after, the last one too, and none by the core.
    assert stages[-2:] == ["CLEANUP 0", f"TRANSFER:EXIT {last}"]
    assert stages.count("CLEANUP 0") == 3


def test_streamed_http_copy_of_a_directory(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "streamed")
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data"), dav2.url("/data/dst"))
    assert caught.value.code == errno.EISDIR


def test_streamed_errors_name_their_side(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "streamed")
    write(dav, "/data/src", b"0123456789")
    dav.fault("GET", status=200, body=b"012")
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    assert caught.value.code == errno.EIO
    assert caught.value.message.endswith("the source has 10 (source)")
    dav.fault("GET", status=403)
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    assert caught.value.message.endswith("HTTP 403 : Permission refused  (source)")
    dav2.fault("PUT", status=507)
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    assert caught.value.message.endswith("HTTP 507 : Insufficient Storage  (destination)")


def test_content_md5_on_streamed_puts(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer, tmp_path: Path
) -> None:
    """The user's MD5, as typed, when the target is checked by MD5."""
    write(dav, "/data/src", b"abc")
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "streamed")
    good = "900150983cd24fb0d6963f7d28e17f72"
    for algorithm, value in (("md5", good), ("MD5", good.upper()), ("adler32", "024d0127")):
        copy = params(overwrite=True)
        copy.set_checksum(checksum_mode.target, algorithm, value)
        hctx.filecopy(copy, dav.url("/data/src"), dav2.url("/data/dst"))
        put = next(r for r in reversed(dav2.requests) if r.method == "PUT")
        assert put.header("Content-MD5") == (value if algorithm != "adler32" else None)
    source = tmp_path / "up"
    source.write_bytes(b"abc")
    copy = params(overwrite=True)
    copy.set_checksum(checksum_mode.both, "md5", good)
    hctx.filecopy(copy, file_url(source), dav2.url("/data/up"))
    put = next(r for r in reversed(dav2.requests) if r.method == "PUT")
    assert put.header("Content-MD5") == good
    copy = params(overwrite=True)
    copy.set_checksum(checksum_mode.both, "md5", "")
    hctx.filecopy(copy, file_url(source), dav2.url("/data/up"))
    assert (
        next(r for r in reversed(dav2.requests) if r.method == "PUT").header("Content-MD5") is None
    )


# -- preparing and verifying: gfal2's order and words -------------------------------------

ABC_ADLER32 = "024d0127"


def _checked(
    mode: object, value: str = "", algorithm: str = "ADLER32", **values: object
) -> tuple[xgfalclient.TransferParameters, Events]:
    """Parameters that check ``mode`` with the user's ``value``, and their events."""
    events = Events()
    made = params(events, **values)
    made.set_checksum(mode, algorithm, value)
    return made, events


def test_checksums_inside_prepare(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"abc")
    copy, events = _checked(checksum_mode.both)
    source, destination = dav.url("/data/src"), dav2.url("/data/dst")
    hctx.filecopy(copy, source, destination)
    pair = f"{source} => {destination}"
    assert events.stages() == [
        f"PREPARE:ENTER {pair}",
        "CHECKSUM:ENTER",
        "CHECKSUM:EXIT",
        f"PREPARE:EXIT {pair}",
        f"TRANSFER:ENTER {pair}",
        "TRANSFER:TYPE 3rd pull",
        f"TRANSFER:EXIT {pair}",
        "CHECKSUM:ENTER",
        "CHECKSUM:EXIT",
    ]
    assert [side for side, _, stage, _ in events.seen if stage.startswith("CHECKSUM")] == [
        0,
        0,
        1,
        1,
    ]
    for mode in (checksum_mode.source, checksum_mode.target, checksum_mode.both):
        copy, events = _checked(mode, ABC_ADLER32, overwrite=True)
        hctx.filecopy(copy, source, destination)  # the user's value agrees
        assert events.stages()[-1] == (
            "CHECKSUM:EXIT" if mode != checksum_mode.source else f"TRANSFER:EXIT {pair}"
        )


def test_source_checksum_failures(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"abc")
    source, destination = dav.url("/data/src"), dav2.url("/data/dst")
    copy, events = _checked(checksum_mode.source, "12345678")
    with pytest.raises(GError) as caught:
        hctx.filecopy(copy, source, destination)
    assert (caught.value.code, caught.value.message) == (
        errno.EIO,
        "SOURCE CHECKSUM MISMATCH Source and user-defined ADLER32 do not match "
        f"({ABC_ADLER32} != 12345678)",
    )
    assert events.stages() == [f"PREPARE:ENTER {source} => {destination}", "CHECKSUM:ENTER"]
    assert not dav2.local("/data/dst").exists()
    copy, events = _checked(checksum_mode.both)
    with pytest.raises(GError) as caught:
        hctx.filecopy(copy, dav.url("/data/nope"), destination)
    assert (caught.value.code, caught.value.message) == (
        errno.ENOENT,
        "SOURCE CHECKSUM HTTP 404 : File not found ",
    )


def test_source_that_cannot_checksum_is_skipped(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    dav2: WebDAVServer,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    write(dav, "/data/src", b"abc")
    source, destination = dav.url("/data/src"), dav2.url("/data/dst")
    real = transfer_module._checksum_value

    def value(context: xgfalclient.Gfal2Context, url: str, algorithm: str) -> str:
        if url == source:
            raise GError("checksum calculation not supported", errno.ENOSYS)
        return real(context, url, algorithm)

    monkeypatch.setattr(transfer_module, "_checksum_value", value)
    copy, events = _checked(checksum_mode.both)
    with caplog.at_level(logging.WARNING, logger="gfal2"):
        hctx.filecopy(copy, source, destination)  # nothing to compare the destination with
    assert "Checksum type ADLER32 not supported by source. Skip source check." in caplog.messages
    assert events.stages().count("CHECKSUM:EXIT") == 2
    copy, events = _checked(checksum_mode.both, "12345678", overwrite=True)
    with pytest.raises(GError) as caught:
        hctx.filecopy(copy, source, destination)  # but with the user's value
    assert caught.value.message == (
        "DESTINATION CHECKSUM MISMATCH User-defined and destination ADLER32 do not match "
        f"(12345678 != {ABC_ADLER32})"
    )


def test_destination_checksum_failures_clean_up(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"abc")
    source, destination = dav.url("/data/src"), dav2.url("/data/dst")
    copy, events = _checked(checksum_mode.target, "12345678")
    with pytest.raises(GError) as caught:
        hctx.filecopy(copy, source, destination)
    assert (caught.value.code, caught.value.message) == (
        errno.EIO,
        "DESTINATION CHECKSUM MISMATCH User-defined and destination ADLER32 do not match "
        f"(12345678 != {ABC_ADLER32})",
    )
    # No CHECKSUM:EXIT, as in gfal2; the bad copy goes, unlike in gfal2.
    assert events.stages()[-2:] == ["CHECKSUM:ENTER", "CLEANUP 0"]
    assert not dav2.local("/data/dst").exists()
    copy, events = _checked(checksum_mode.both)
    dav2.fault("HEAD", "/data/dst", status=200, headers={"Digest": "adler32=00000001"})
    with pytest.raises(GError) as caught:
        hctx.filecopy(copy, source, destination)
    assert caught.value.message == (
        "DESTINATION CHECKSUM MISMATCH Source and destination ADLER32 do not match "
        f"({ABC_ADLER32} != 00000001)"
    )
    copy, events = _checked(checksum_mode.target, ABC_ADLER32)
    dav2.fault("HEAD", "/data/dst", status=403)
    with pytest.raises(GError) as caught:
        hctx.filecopy(copy, source, destination)
    assert (caught.value.code, caught.value.message) == (
        errno.EPERM,
        "DESTINATION CHECKSUM HTTP 403 : Permission refused ",
    )
    assert events.stages()[-1] == "CLEANUP 0" and not dav2.local("/data/dst").exists()


def test_existing_destination(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"abc")
    write(dav2, "/data/dst", b"old")
    source, destination = dav.url("/data/src"), dav2.url("/data/dst")
    pair = f"{source} => {destination}"
    events = Events()
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(events), source, destination)
    assert (caught.value.code, caught.value.message) == (
        errno.EEXIST,
        "DESTINATION EXISTS The destination file exists and overwrite is not enabled",
    )
    assert events.stages() == [f"PREPARE:ENTER {pair}"]
    assert dav2.local("/data/dst").read_bytes() == b"old"
    dav2.fault("DELETE", "/data/dst", status=403)
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(overwrite=True), source, destination)
    assert (caught.value.code, caught.value.message) == (
        errno.EPERM,
        "DESTINATION OVERWRITE DavPosix::unlink  HTTP 403 : Permission refused ",
    )
    dav2.fault("PROPFIND", "/data/dst", status=500)
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(overwrite=True), source, destination)
    assert caught.value.message == (
        "DESTINATION OVERWRITE   Result HTTP 500 : Unexpected server error: 500  after 1 attempts"
    )
    events = Events()
    hctx.filecopy(params(events, overwrite=True), source, destination)
    assert events.stages()[:3] == [
        f"PREPARE:ENTER {pair}",
        f"OVERWRITE Deleted {destination}",
        f"PREPARE:EXIT {pair}",
    ]
    assert dav2.local("/data/dst").read_bytes() == b"abc"


def test_create_parent(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"abc")
    source = dav.url("/data/src")
    hctx.filecopy(params(create_parent=True), source, dav2.url("/data/sub/dst"))
    assert dav2.local("/data/sub/dst").read_bytes() == b"abc"
    assert "MKCOL" in dav2.methods()
    dav2.clear()
    hctx.filecopy(params(create_parent=True), source, dav2.url("/data/sub/two"))
    assert "MKCOL" not in dav2.methods()  # it is there already
    dav2.fault("MKCOL", status=403)
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(create_parent=True), source, dav2.url("/data/new/dst"))
    assert caught.value.message.startswith("DESTINATION MAKE_PARENT ")
    assert caught.value.code == errno.EPERM
    dav2.fault("PROPFIND", "/data/new/dst", status=404)
    dav2.fault("PROPFIND", "/data/new", status=403)
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(create_parent=True), source, dav2.url("/data/new/dst"))
    assert caught.value.message == "DESTINATION MAKE_PARENT   HTTP 403 : Permission refused "


def test_strict_copy_prepares_nothing(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer, tmp_path: Path
) -> None:
    write(dav, "/data/src", b"abc")
    write(dav2, "/data/dst", b"old")
    copy, events = _checked(checksum_mode.both, "900150983cd24fb0d6963f7d28e17f72", "md5")
    copy.strict_copy = True
    hctx.filecopy(copy, dav.url("/data/src"), dav2.url("/data/dst"))
    assert "PROPFIND" not in dav2.methods() and not dav.methods().count("HEAD")
    assert not [s for s in events.stages() if s.startswith(("CHECKSUM", "OVERWRITE"))]
    source = tmp_path / "up"
    source.write_bytes(b"abc")
    hctx.filecopy(copy, file_url(source), dav2.url("/data/dst"))
    assert dav2.requests[-1].header("Content-MD5") is None  # gfal2 checks nothing in strict mode


def test_evict_comes_after_the_destination_checksum(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"abc")
    copy, events = _checked(checksum_mode.both, evict=True)
    hctx.filecopy(copy, dav.url("/data/src"), dav2.url("/data/dst"))
    assert events.stages()[-3:] == ["CHECKSUM:ENTER", "CHECKSUM:EXIT", "EVICT -1"]


def test_download_is_the_cores_copy(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path
) -> None:
    write(dav, "/data/f", b"abc")
    target = tmp_path / "down"
    local = xgfalclient.events.DOMAIN_LOCAL
    copy, events = _checked(checksum_mode.both)
    hctx.filecopy(copy, dav.url("/data/f"), file_url(target))
    assert [s.split(" ")[0] for s in events.stages(local)] == [
        "CHECKSUM:ENTER",
        "CHECKSUM:EXIT",
        "TRANSFER:ENTER",
        "TRANSFER:TYPE",
        "TRANSFER:EXIT",
        "CHECKSUM:ENTER",
        "CHECKSUM:EXIT",
    ]
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/f"), file_url(target))
    assert caught.value.message == "The file exists and overwrite is not set"
    copy, events = _checked(checksum_mode.target, "12345678", overwrite=True)
    with pytest.raises(GError) as caught:
        hctx.filecopy(copy, dav.url("/data/f"), file_url(target))
    assert caught.value.message.startswith("DESTINATION CHECKSUM MISMATCH User defined")
    assert not target.exists()  # removed, quietly, as the core removes a streamed copy's
    assert not [s for s in events.stages(local) if s.startswith("CLEANUP")]
    copy, events = _checked(checksum_mode.target, "12345678")
    copy.strict_copy = True
    hctx.filecopy(copy, dav.url("/data/f"), file_url(target))  # strict: nothing checked
    assert target.read_bytes() == b"abc"
    assert not [s for s in events.stages(local) if s.startswith("CHECKSUM")]


def _plugin(context: xgfalclient.Gfal2Context):  # type: ignore[no-untyped-def]
    return context.plugin("davs://h/", "copy")


def _chain(plugin: object, source: str, destination: str) -> list[str]:
    modes = _copy.CopyMode(plugin, source, destination)  # type: ignore[arg-type]
    found: list[str] = []
    while modes.mode is not None and (not found or modes.fallback):
        found.append(modes.mode)
        modes.next()
    return found


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({}, ["3rd pull", "3rd push", "streamed"]),
        ({"DEFAULT_COPY_MODE": "3rd push"}, ["3rd push", "streamed"]),
        ({"DEFAULT_COPY_MODE": "push"}, ["3rd pull", "3rd push", "streamed"]),  # not a mode
        ({"DEFAULT_COPY_MODE": "streamed"}, ["streamed"]),
        ({"DEFAULT_COPY_MODE": "sideways"}, ["3rd pull", "3rd push", "streamed"]),
        ({"ENABLE_REMOTE_COPY": "false"}, ["streamed"]),
        ({"ENABLE_REMOTE_COPY": "false", "ENABLE_STREAM_COPY": "false"}, ["streamed"]),
        ({"ENABLE_STREAM_COPY": "false"}, ["3rd pull", "3rd push"]),
        ({"ENABLE_FALLBACK_TPC_COPY": "false"}, ["3rd pull"]),
        ({"ENABLE_FALLBACK_TPC_COPY": "false", "DEFAULT_COPY_MODE": "3rd push"}, ["3rd push"]),
    ],
)
def test_copy_modes(
    hctx: xgfalclient.Gfal2Context, options: dict[str, str], expected: list[str]
) -> None:
    for key, value in options.items():
        hctx.set_opt_string("HTTP PLUGIN", key, value)
    assert _chain(_plugin(hctx), "davs://a/f", "davs://b/f") == expected
    assert _chain(_plugin(hctx), "file:///a/f", "davs://b/f") == ["streamed"]


def test_copy_modes_per_storage_element(hctx: xgfalclient.Gfal2Context) -> None:
    """``[DAV:HOST]``/``[HTTP:HOST]`` groups, for either end, before ``[HTTP PLUGIN]``."""
    plugin = _plugin(hctx)
    hctx.set_opt_string("DAV:SRC.EXAMPLE", "DEFAULT_COPY_MODE", "3rd push")
    assert _chain(plugin, "davs://src.example/f", "davs://dst/f") == ["3rd push", "streamed"]
    hctx.set_opt_string("HTTP:DST", "DEFAULT_COPY_MODE", "streamed")
    assert _chain(plugin, "davs://a/f", "https://dst/f") == ["streamed"]
    assert _chain(plugin, "davs://src.example/f", "https://dst/f")[0] == "3rd push"  # source first
    hctx.set_opt_string("DAV:DST", "DEFAULT_COPY_MODE", "nonsense")
    assert _chain(plugin, "davs://a/f", "davs://dst/f")[0] == "3rd pull"
    # A boolean set on either end must hold for both.
    hctx.set_opt_boolean("DAV:NOREMOTE", "ENABLE_REMOTE_COPY", False)
    assert _chain(plugin, "davs://noremote/f", "davs://b/f") == ["streamed"]
    assert _chain(plugin, "davs://b/f", "davs://noremote/f") == ["streamed"]
    hctx.set_opt_boolean("DAV:YES", "ENABLE_REMOTE_COPY", True)
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_REMOTE_COPY", False)
    assert _chain(plugin, "davs://yes/f", "davs://b/f")[0] == "3rd pull"
    hctx.set_opt_string("DAV:BAD", "ENABLE_STREAM_COPY", "maybe")  # not a boolean: unset
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_REMOTE_COPY", True)
    assert _chain(plugin, "davs://bad/f", "davs://b/f")[-1] == "streamed"
    hctx.set_opt_boolean("DAV:NOSTREAM", "ENABLE_STREAM_COPY", False)
    assert _chain(plugin, "davs://nostream/f", "davs://b/f") == ["3rd pull", "3rd push"]
    hctx.set_opt_boolean("DAV:NOFALLBACK", "ENABLE_FALLBACK_TPC_COPY", False)
    assert _chain(plugin, "davs://b/f", "davs://nofallback/f") == ["3rd pull"]


def test_copy_mode_query_argument(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    plugin = _plugin(hctx)
    assert _chain(plugin, "davs://a/f?copy_mode=push", "davs://b/f") == ["3rd push"]
    assert _chain(plugin, "davs://a/f", "davs://b/f?x=1&copy_mode=pull") == ["3rd pull"]
    assert _chain(plugin, "davs://a/f?copy_mode=sideways", "davs://b/f")[0] == "3rd pull"
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_STREAM_COPY", False)
    assert _chain(plugin, "davs://a/f?copy_mode=push", "davs://b/f") == ["3rd push"]
    write(dav, "/data/src", b"q")
    hctx.filecopy(dav.url("/data/src?copy_mode=push"), dav2.url("/data/dst"))
    push = next(r for r in dav.requests if r.method == "COPY")
    assert push.path == "/data/src?copy_mode=push"
    assert push.header("Destination") == f"http://127.0.0.1:{dav2.port}/data/dst"


def test_streamed_disabled(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "streamed")
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_STREAM_COPY", False)
    write(dav, "/data/src", b"x")
    events = Events()
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(events), dav.url("/data/src"), dav2.url("/data/dst"))
    why = "STREAMED DISABLED Only streamed copy possible but streaming is disabled"
    assert (caught.value.code, caught.value.message) == (errno.EINVAL, f"TRANSFER {why}")
    assert events.stages()[-2:] == ["TRANSFER:TYPE streamed", f"TRANSFER:EXIT {why}"]
    # Remote copy off streams whatever ENABLE_STREAM_COPY says.
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_REMOTE_COPY", False)
    hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    assert dav2.local("/data/dst").read_bytes() == b"x"


def test_plus_3rd_urls_are_streamed_by_the_core(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"x")
    events = Events()
    source, destination = dav.url("/data/src", "dav+3rd"), dav2.url("/data/dst", "dav+3rd")
    hctx.filecopy(params(events), source, destination)
    assert dav2.local("/data/dst").read_bytes() == b"x"
    assert not [r for r in dav.requests + dav2.requests if r.method == "COPY"]
    assert ("TRANSFER:TYPE", "streamed") in [(stage, desc) for _, _, stage, desc in events.seen]


def test_tpc_failures(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
    write(dav, "/data/src", b"x")
    dav2.tpc = "fail"
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    assert caught.value.code == errno.EIO
    assert caught.value.message.endswith(
        "Last attempt: Transfer failure: HTTP 500 : the remote side refused"
    )
    dav2.tpc = "normal"
    # davix's words and errno for a COPY the active end turns down, as gfal2
    # 2.23.5 reports them (observed side by side against this server).
    refusals = [
        (400, errno.EHOSTDOWN, "copy HTTP 400 : Server Error "),
        (403, errno.EPERM, "copy HTTP 403 : Permission refused "),
        (404, errno.ENOENT, "copy HTTP 404 : File not found "),
        (405, errno.EPERM, "copy HTTP 405 : Method Not Allowed, Permission refused "),
        (300, errno.EIO, "Could not COPY. Unknown error code: 300"),
    ]
    for status, code, words in refusals:
        dav2.fault("COPY", status=status, body=b"bad copy")
        with pytest.raises(GError) as caught:
            hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
        assert (caught.value.code, caught.value.message) == (
            code,
            f"TRANSFER ERROR: Copy failed (3rd pull). Last attempt: {words}",
        )
    for line, code, words in (
        (b"failed\n", errno.EIO, "Transfer failed"),
        (b"Aborted: by the admin\n", errno.ECANCELED, "Transfer aborted in the remote end"),
    ):
        dav2.fault("COPY", status=202, body=line)
        with pytest.raises(GError) as caught:
            hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
        assert (caught.value.code, caught.value.message.rpartition(": ")[2]) == (code, words)
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "3rd push")
    with pytest.raises(GError) as caught:
        hctx.filecopy(dav.url("/data/nope"), dav2.url("/data/dst"))
    assert caught.value.code == errno.EIO  # the far end's words do not set the errno
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
    assert caught.value.code == errno.EIO
    assert "Connection terminated abruptly; Status of TPC request unknown" in caught.value.message


@pytest.mark.parametrize("status", [403, 404])
def test_no_fallback_after_a_refusal(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer, status: int
) -> None:
    write(dav, "/data/src", b"x" * 4000)
    events = Events()
    dav2.fault("COPY", status=status)
    with pytest.raises(GError):
        hctx.filecopy(params(events), dav.url("/data/src"), dav2.url("/data/dst"))
    assert [s for s in events.stages() if s.startswith("TRANSFER:TYPE")] == [
        "TRANSFER:TYPE 3rd pull"
    ]


def test_no_fallback_after_a_cancel(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"x" * 4000)
    dav2.marker_every = 1000
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(_cancel_on_type(hctx)), dav.url("/data/src"), dav2.url("/data/dst2"))
    assert caught.value.code == errno.ECANCELED
    assert caught.value.message == (
        "TRANSFER ERROR: Copy failed (3rd pull). Last attempt: Transfer canceled"
    )


def test_fallback_after_the_destination_exists(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    dav2: WebDAVServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EEXIST is tried again the next way, and its destination is not cleaned up."""
    write(dav, "/data/src", b"x")
    real = _copy.third_party

    def exists(plugin: object, transfer: object, mode: str) -> None:
        if mode == _copy.PULL:
            raise GError("there already", errno.EEXIST)
        real(plugin, transfer, mode)  # type: ignore[arg-type]

    monkeypatch.setattr(_copy, "third_party", exists)
    events = Events()
    hctx.filecopy(params(events), dav.url("/data/src"), dav2.url("/data/dst"))
    stages = events.stages()
    assert stages[3:5] == ["TRANSFER:TYPE 3rd pull", "TRANSFER:TYPE 3rd push"]


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
    assert plugin.copy_check("swift://a/c/f", "cs3s://b/f")
    assert not plugin.copy_check("davs+3rd://a/f", "davs://b/f")
    assert not plugin.copy_check("davs://a/f", "davs+3rd://b/f")
    assert not plugin.copy_check("root://a/f", "davs://b/f")
    assert not plugin.copy_check("davs://a/f", "root://b/f")
    assert not plugin.copy_check("file:///a", "file:///b")


def test_evict_after_a_copy(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"x")
    events = Events()
    hctx.filecopy(params(events, evict=True), dav.url("/data/src"), dav2.url("/data/dst"))
    assert (0, "http_plugin", "EVICT", "-1") in events.seen  # no tape API there
    dav.tape = Tape()
    events = Events()
    hctx.filecopy(
        params(events, evict=True, overwrite=True), dav.url("/data/src"), dav2.url("/data/dst")
    )
    assert (0, "http_plugin", "EVICT", "0") in events.seen
    assert dav.tape.released == [("gfal2-placeholder-id", ["/data/src"])]


def test_resolve_dns(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    dav2: WebDAVServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``[CORE] RESOLVE_DNS``: the copy goes to one address of the alias, by name."""
    write(dav, "/data/src", b"x")
    hctx.set_opt_boolean("CORE", "RESOLVE_DNS", True)
    monkeypatch.setattr(_copy.socket, "getnameinfo", lambda address, flags: ("localhost", ""))
    hctx.filecopy(dav.url("/data/src"), dav2.url("/data/dst"))
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert copy_request.header("Host") == f"localhost:{dav2.port}"
    assert copy_request.header("Source") == f"http://localhost:{dav.port}/data/src"

    def unknown(address: object, flags: int) -> tuple[str, str]:
        raise socket.gaierror(8, "no name")

    monkeypatch.setattr(_copy.socket, "getnameinfo", unknown)
    assert _copy.resolved(_plugin(hctx), "dav://u@127.0.0.1:1/f") == "dav://u@127.0.0.1:1/f"
    monkeypatch.setattr(_copy.socket, "getnameinfo", lambda address, flags: ("h.example", ""))
    assert _copy.resolved(_plugin(hctx), "dav://u@127.0.0.1:1/f") == "dav://u@h.example:1/f"


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
    # A token means Credential: none, and no X-No-Delegate.
    assert copy_request.header("Credential") == "none"


def test_cs3_far_side(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav, "/data/src", b"x")
    hctx.set_opt_string("BEARER", "TOKEN", "REVA")
    dav.tokens = dav2.tokens = {"REVA"}
    hctx.filecopy(dav.url("/data/src", "cs3"), dav2.url("/data/dst"))
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert copy_request.header("Source") == f"http://127.0.0.1:{dav.port}/data/src"
    assert copy_request.header("TransferHeaderAuthorization") == "Bearer REVA"
    assert copy_request.header("Credential") == "none"
    hctx.set_opt_string("BEARER", "TOKEN", "")
    dav.tokens = dav2.tokens = set()
    hctx.filecopy(params(overwrite=True), dav.url("/data/src", "cs3"), dav2.url("/data/dst"))
    copy_request = [r for r in dav2.requests if r.method == "COPY"][-1]
    assert copy_request.header("TransferHeaderAuthorization") is None


def test_macaroon_for_the_far_side(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, dav2: WebDAVServer, grid_env: PKI
) -> None:
    write(davs, "/data/src", b"from tls")
    events = Events()
    hctx.filecopy(params(events, timeout=1800), davs.url("/data/src"), dav2.url("/data/dst"))
    assert dav2.local("/data/dst").read_bytes() == b"from tls"
    issued = davs.macaroons[0]
    assert issued["caveats"] == ["activity:LIST,DOWNLOAD"]
    assert issued["validity"] == "PT70M"  # 2 * timeout / 60 + 10 minutes
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert copy_request.header("TransferHeaderAuthorization") == f"Bearer {issued['macaroon']}"
    assert copy_request.header("Source") == f"https://127.0.0.1:{davs.port}/data/src"
    assert copy_request.header("Credential") == "none"
    assert copy_request.header("X-No-Delegate") is None


def test_macaroon_refused_then_no_token(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, dav2: WebDAVServer, grid_env: PKI
) -> None:
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
    write(davs, "/data/src", b"x")
    davs.fault("POST", status=403, times=2)  # the file, then the SE as issuer
    with pytest.raises(GError):
        hctx.filecopy(davs.url("/data/src"), dav2.url("/data/dst"))
    assert [r.method for r in davs.requests][:3] == ["POST", "GET", "POST"]
    copy_request = next(r for r in dav2.requests if r.method == "COPY")
    assert copy_request.header("TransferHeaderAuthorization") is None
    # An HTTPS far side with no token: the active end should use gridsite delegation.
    assert copy_request.header("Credential") == "gridsite"
    assert copy_request.header("X-No-Delegate") is None
    hctx.set_opt_boolean("HTTP PLUGIN", "RETRIEVE_BEARER_TOKEN", False)
    davs.clear()
    with pytest.raises(GError):
        hctx.filecopy(davs.url("/data/src"), dav2.url("/data/dst2"))
    assert not [r for r in davs.requests if r.method == "POST"]
    hctx.set_opt_boolean("DAV:127.0.0.1", "RETRIEVE_BEARER_TOKEN", True)  # per endpoint
    with pytest.raises(GError):
        hctx.filecopy(davs.url("/data/src"), dav2.url("/data/dst3"))
    assert [r for r in davs.requests if r.method == "POST"]


def test_push_asks_for_a_write_macaroon(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, davs: WebDAVServer, grid_env: PKI
) -> None:
    hctx.set_opt_string("HTTP PLUGIN", "DEFAULT_COPY_MODE", "3rd push")
    write(dav, "/data/src", b"pushed over tls")
    dav.client_tls = grid_env.client_context()
    davs.tokens = {"unused"}  # the pushed PUT must carry the macaroon (or the cert)
    hctx.filecopy(dav.url("/data/src"), davs.url("/data/dst"))
    assert davs.local("/data/dst").read_bytes() == b"pushed over tls"
    assert davs.macaroons[0]["caveats"] == ["activity:LIST,DOWNLOAD,MANAGE,UPLOAD,DELETE"]


def test_presigned_far_side_gets_no_token(
    hctx: xgfalclient.Gfal2Context, davs: WebDAVServer, dav2: WebDAVServer, grid_env: PKI
) -> None:
    hctx.set_opt_boolean("HTTP PLUGIN", "ENABLE_FALLBACK_TPC_COPY", False)
    hctx.cred_set("davs://", hctx.cred_new("BEARER", "UNUSED"))
    for query in ("X-Amz-Signature=x", "AWSAccessKeyId=A&Signature=x"):
        dav2.clear()
        with pytest.raises(GError):
            hctx.filecopy(davs.url(f"/data/src?{query}"), dav2.url("/data/dst"))
        copy_request = next(r for r in dav2.requests if r.method == "COPY")
        assert copy_request.header("TransferHeaderAuthorization") is None


def test_delegation(
    hctx: xgfalclient.Gfal2Context, davs_open: WebDAVServer, davs: WebDAVServer, grid_env: PKI
) -> None:
    """An HTTPS far side and no token: ``Credential: gridsite``, and the proxy on request."""
    hctx.set_opt_boolean("HTTP PLUGIN", "RETRIEVE_BEARER_TOKEN", False)
    write(davs_open, "/data/src", b"delegated")
    davs.delegation = True
    davs.client_tls = grid_env.client_context()
    hctx.filecopy(davs_open.url("/data/src"), davs.url("/data/dst"))
    assert davs.local("/data/dst").read_bytes() == b"delegated"
    copy_request = next(r for r in davs.requests if r.method == "COPY")
    assert copy_request.header("Credential") == "gridsite"
    (chain,) = davs.delegated.values()
    assert chain[0].is_proxy
    davs.delegation_version = 1
    hctx.filecopy(params(overwrite=True), davs_open.url("/data/src"), davs.url("/data/dst"))
    assert len(davs.delegated) == 2


# -- transfers that survive a flaky link --------------------------------------------------
#
# A dropped GET is resumed from where it got to; a dropped PUT is restarted (a
# PUT replaces the whole resource, so nothing partial survives to resume). Both
# are bounded by CONN_RETRY. The WebDAV server's ``truncate`` fault declares a
# full length then cuts the body, which is exactly a dropped connection.


def test_a_single_stream_download_resumes_after_a_drop(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path
) -> None:
    data = os.urandom(200_000)
    write(dav, "/data/big", data)
    dav.fault("GET", body=data, truncate=50_000, times=1)  # first GET drops early
    hctx.filecopy(params(nbstreams=1), dav.url("/data/big"), file_url(tmp_path / "out"))
    assert (tmp_path / "out").read_bytes() == data


def test_a_parallel_download_resumes_a_dropped_segment(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_copy, "PARALLEL_THRESHOLD", MB)
    data = os.urandom(3 * MB + 17)
    write(dav, "/data/big", data)
    # One segment's ranged GET drops part way; its worker re-requests the rest.
    dav.fault("GET", body=data, truncate=40_000, times=1)
    hctx.filecopy(params(nbstreams=3), dav.url("/data/big"), file_url(tmp_path / "big"))
    assert (tmp_path / "big").read_bytes() == data


def test_a_download_gives_up_after_conn_retry(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path
) -> None:
    data = os.urandom(100_000)
    write(dav, "/data/big", data)
    hctx.set_opt_integer("CORE", "CONN_RETRY", 2)
    dav.fault("GET", body=data, truncate=1000, times=50)  # every GET drops
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(nbstreams=1), dav.url("/data/big"), file_url(tmp_path / "out"))
    assert caught.value.code in (errno.EIO, errno.ECOMM if hasattr(errno, "ECOMM") else errno.EIO)


def test_an_upload_restarts_after_a_dropped_put(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path
) -> None:
    data = os.urandom(200_000)
    source = tmp_path / "src"
    source.write_bytes(data)
    dav.fault("PUT", drop=True, times=1)  # the first PUT's connection drops
    hctx.filecopy(params(overwrite=True), file_url(source), dav.url("/data/up"))
    assert dav.local("/data/up").read_bytes() == data


def test_an_upload_gives_up_after_conn_retry(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path
) -> None:
    source = tmp_path / "src"
    source.write_bytes(os.urandom(50_000))
    hctx.set_opt_integer("CORE", "CONN_RETRY", 2)
    dav.fault("PUT", drop=True, times=50)  # every PUT drops
    with pytest.raises(GError):
        hctx.filecopy(params(overwrite=True), file_url(source), dav.url("/data/up"))


def test_a_parallel_segment_gives_up_after_conn_retry(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A segment whose stream keeps dropping is bounded by CONN_RETRY, then errors."""
    monkeypatch.setattr(_copy, "PARALLEL_THRESHOLD", MB)
    data = os.urandom(3 * MB + 17)
    write(dav, "/data/big", data)
    hctx.set_opt_integer("CORE", "CONN_RETRY", 2)
    hctx.set_opt_integer("CORE", "CONN_RETRY_INTERVAL", 1)  # exercise the pause path
    import xgfalclient.plugins.http.plugin as plugin_module

    monkeypatch.setattr(plugin_module.time, "sleep", lambda _s: None)
    # Every GET's connection is reset before a byte arrives, so no segment ever
    # makes progress and each one exhausts its retries.
    dav.fault("GET", drop=True, times=1000)
    with pytest.raises(GError) as caught:
        hctx.filecopy(params(nbstreams=2), dav.url("/data/big"), file_url(tmp_path / "a"))
    assert caught.value.code == errno.EIO
