"""The copy pipeline: parameters, events, overwrite/parent/checksum rules, streaming."""

from __future__ import annotations

import errno
import logging
import os
import stat as stat_module
import threading
import time
import zlib
from pathlib import Path
from typing import Any

import pytest

import xgfalclient
from conftest import file_url
from xgfalclient import GError, Gfal2Context, checksum_mode
from xgfalclient.plugin import Plugin, PluginFile
from xgfalclient.transfer import (
    Transfer,
    TransferParameters,
    _cleanup,
    _is_special,
    _split_checksum,
    emit,
    pump,
    run_bulk,
    run_copy,
)
from xgfalclient.types import Stat

# -- parameters ------------------------------------------------------------------------


def test_parameter_defaults_match_gfal2() -> None:
    params = TransferParameters()
    assert (params.timeout, params.nbstreams, params.tcp_buffersize) == (3600, 0, 0)
    assert not params.overwrite and not params.strict_copy and not params.create_parent
    assert params.local_transfers and params.proxy_delegation and params.transfer_cleanup
    assert (params.src_spacetoken, params.dst_spacetoken, params.scitag, params.evict) == (
        "",
        "",
        0,
        False,
    )
    assert params.get_checksum() == (checksum_mode.none, "", "")
    assert (
        repr(params)
        == "TransferParameters(timeout=3600, nbstreams=0, overwrite=False, checksum=none)"
    )


def test_parameters_copy_is_independent() -> None:
    params = TransferParameters()
    params.overwrite = True
    params.set_checksum(checksum_mode.both, "md5", "")
    clone = params.copy()
    clone.overwrite = False
    assert params.overwrite and clone.get_checksum() == (checksum_mode.both, "md5", "")


def test_set_checksum_validation() -> None:
    params = TransferParameters()
    with pytest.raises(GError) as caught:
        params.set_checksum(7, "adler32", "")
    assert caught.value.code == errno.EINVAL
    for mode in (checksum_mode.source, checksum_mode.target):
        with pytest.raises(GError) as caught:
            params.set_checksum(mode, "adler32", "")
        assert caught.value.message == "Checksum value required if mode is not end to end"
    params.set_checksum(1, "adler32", "abc")
    assert params.checksum_mode is checksum_mode.source
    assert (params.checksum_algorithm, params.checksum_value) == ("adler32", "abc")
    params.set_checksum(checksum_mode.none, None, None)  # type: ignore[arg-type]
    assert params.get_checksum() == (checksum_mode.none, "", "")


def test_deprecated_checksum_spellings() -> None:
    params = TransferParameters()
    with pytest.warns(DeprecationWarning):
        assert params.checksum_check is False
    with pytest.warns(DeprecationWarning):
        params.checksum_check = True
    assert params.get_checksum()[0] is checksum_mode.both
    with pytest.warns(DeprecationWarning):
        params.checksum_check = False
    assert params.get_checksum()[0] is checksum_mode.none
    with pytest.warns(DeprecationWarning):
        params.set_user_defined_checksum("md5", "x")
    with pytest.warns(DeprecationWarning):
        assert params.get_user_defined_checksum() == ("md5", "x")
    assert params.get_checksum() == (checksum_mode.none, "md5", "x")


# -- events and the Transfer handle ---------------------------------------------------------


def test_emit_logs_and_propagates(caplog: pytest.LogCaptureFixture) -> None:
    params = TransferParameters()
    with caplog.at_level(logging.INFO, logger="gfal2"):
        emit(params, "d", "s", "desc", side=1)  # no callback: logged all the same
    assert caplog.messages == ["Event triggered: DESTINATION d s desc"]

    def broken(event: Any) -> None:
        raise ValueError("boom")

    params.event_callback = broken
    with pytest.raises(ValueError, match="boom"):  # as in gfal2: it aborts the copy
        emit(params, "d", "s")


def test_transfer_checksum_selection(ctx: Gfal2Context) -> None:
    params = TransferParameters()
    transfer = Transfer(ctx, params, "a", "b", user_checksum=("md5", "x"))
    # A bulk entry replaces the algorithm and value, never the mode (gfal2's set_checksum).
    assert (transfer.checksum_mode, transfer.checksum_algorithm, transfer.user_checksum) == (
        checksum_mode.none,
        "md5",
        "x",
    )
    params.set_checksum(checksum_mode.source, "adler32", "1")
    transfer = Transfer(ctx, params, "a", "b", user_checksum=("md5", "x"))
    assert transfer.checksum_mode is checksum_mode.source
    assert transfer.pair == "a => b"


def test_transfer_events_domains(ctx: Gfal2Context) -> None:
    seen: list[xgfalclient.GfaltEvent] = []
    params = TransferParameters()
    params.event_callback = seen.append
    transfer = Transfer(ctx, params, "a", "b", domain="mine")
    transfer.event("X")
    transfer.event("Y", "desc", side=0, domain="other")
    assert [(e.domain, e.stage, e.side) for e in seen] == [("mine", "X", 2), ("other", "Y", 0)]


def test_transfer_limits(ctx: Gfal2Context, monkeypatch: pytest.MonkeyPatch) -> None:
    params = TransferParameters()
    params.timeout = 0
    transfer = Transfer(ctx, params, "a", "b")
    assert transfer.deadline is None and transfer.remaining() is None
    transfer.check()
    params.timeout = 10
    remaining = transfer.remaining()
    assert remaining is not None and 0 < remaining <= 10
    now = time.monotonic()
    monkeypatch.setattr("xgfalclient.transfer.time.monotonic", lambda: now + 20)
    with pytest.raises(GError) as caught:
        transfer.check()
    assert (caught.value.code, caught.value.message) == (
        errno.ETIMEDOUT,
        "Transfer canceled because the timeout expired",
    )
    assert transfer.remaining() == 0.0


def test_transfer_cancel(ctx: Gfal2Context) -> None:
    transfer = Transfer(ctx, TransferParameters(), "a", "b")
    assert ctx.cancel() == 0
    with pytest.raises(GError) as caught:
        transfer.check()
    assert caught.value.code == errno.ECANCELED


def test_progress_throttles_monitor(ctx: Gfal2Context, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr("xgfalclient.transfer.time.monotonic", lambda: clock[0])
    calls: list[tuple[Any, ...]] = []
    params = TransferParameters()
    transfer = Transfer(ctx, params, "a", "b")
    transfer.progress(10)  # no callback
    assert transfer.transferred == 10
    params.monitor_callback = lambda *args: calls.append(args)
    transfer.progress(50, force=True)  # under one interval: gfal2 never reports
    clock[0] += 2
    transfer.progress(100)
    clock[0] += 0.5
    transfer.progress(200)  # within the second: suppressed
    transfer.progress(300, force=True)
    assert [c[4] for c in calls] == [100, 300]
    assert calls[0] == ("a", "b", 50, 50, 100, 2)
    assert calls[1][3] == 400  # 200 bytes in the last half second

    def broken(*args: Any) -> None:
        raise RuntimeError("boom")

    params.monitor_callback = broken
    with pytest.raises(RuntimeError, match="boom") as caught:
        transfer.progress(400, force=True)
    with pytest.raises(RuntimeError):  # remembered: the next check() stops the copy
        transfer.check()
    assert transfer.callback_error is caught.value
    clock[0] += 2
    with pytest.raises(RuntimeError):
        transfer.add(1)
    assert transfer.callback_error is caught.value  # the first one is kept


def test_add_is_thread_safe(ctx: Gfal2Context) -> None:
    transfer = Transfer(ctx, TransferParameters(), "a", "b")

    def work() -> None:
        for _ in range(1000):
            transfer.add(1)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert transfer.transferred == 8000


# -- the pipeline, over file:// and mock:// ----------------------------------------------------


@pytest.fixture
def src(tmp_path: Path) -> Path:
    path = tmp_path / "src.bin"
    path.write_bytes(bytes(range(256)) * 4096 + b"tail")
    return path


def adler(path: Path) -> str:
    return f"{zlib.adler32(path.read_bytes()):08x}"


def stages(events: list[xgfalclient.GfaltEvent]) -> list[str]:
    return [f"{e.side}:{e.stage}" for e in events]


def test_local_copy_narrates_like_gfal2(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    events: list[xgfalclient.GfaltEvent] = []
    params = ctx.transfer_parameters()
    params.event_callback = events.append
    params.set_checksum(checksum_mode.both, "", "")
    dst = tmp_path / "dst.bin"
    assert ctx.filecopy(params, file_url(src), file_url(dst)) == 0
    assert dst.read_bytes() == src.read_bytes()
    assert stages(events) == [
        "2:LIST:ENTER",
        "2:LIST:ITEM",
        "2:LIST:EXIT",
        "0:CHECKSUM:ENTER",
        "0:CHECKSUM:EXIT",
        "2:TRANSFER:ENTER",
        "2:TRANSFER:TYPE",
        "2:TRANSFER:EXIT",
        "1:CHECKSUM:ENTER",
        "1:CHECKSUM:EXIT",
    ]
    assert {e.domain for e in events[3:]} == {"GFAL2:CORE:COPY:LOCAL"}
    assert events[6].description == "streamed"
    assert all(e.timestamp > 1_600_000_000_000 for e in events)  # ms since the epoch


def test_copy_onto_itself_is_refused(ctx: Gfal2Context, src: Path) -> None:
    params = ctx.transfer_parameters()
    params.overwrite = True
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, file_url(src), file_url(src))
    assert caught.value.code == errno.EINVAL
    assert src.exists()


def test_overwrite_rules(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    dst = tmp_path / "dst.bin"
    dst.write_bytes(b"old")
    params = ctx.transfer_parameters()
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, file_url(src), file_url(dst))
    assert (caught.value.code, caught.value.message) == (
        errno.EEXIST,
        "The file exists and overwrite is not set",
    )
    assert dst.read_bytes() == b"old"  # EEXIST never cleans up
    events: list[xgfalclient.GfaltEvent] = []
    params.overwrite = True
    params.event_callback = events.append
    ctx.filecopy(params, file_url(src), file_url(dst))
    assert dst.read_bytes() == src.read_bytes()
    overwrite = [e for e in events if e.stage == "OVERWRITE"]
    assert overwrite[0].description == f"Deleted {file_url(dst)}" and overwrite[0].side == 1


def test_destination_stat_errors_propagate(ctx: Gfal2Context, src: Path) -> None:
    with pytest.raises(GError) as caught:
        ctx.filecopy(file_url(src), "mock://h/dst?errno=13")
    assert caught.value.code == errno.EACCES


def test_create_parent(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    dst = tmp_path / "a" / "b" / "dst.bin"
    params = ctx.transfer_parameters()
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, file_url(src), file_url(dst))
    assert caught.value.code == errno.ENOENT
    assert caught.value.message.startswith("Could not open destination:")
    params.create_parent = True
    ctx.filecopy(params, file_url(src), file_url(dst))
    assert dst.read_bytes() == src.read_bytes()


def test_checksum_mismatches(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    params = ctx.transfer_parameters()
    params.set_checksum(checksum_mode.source, "adler32", "deadbeef")
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, file_url(src), file_url(tmp_path / "d1"))
    assert caught.value.code == errno.EIO
    assert caught.value.message == (
        "SOURCE CHECKSUM MISMATCH Source checksum and user-specified checksum do not match: "
        f"{adler(src)} != deadbeef"
    )
    assert not (tmp_path / "d1").exists()
    params.set_checksum(checksum_mode.target, "adler32", "deadbeef")
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, file_url(src), file_url(tmp_path / "d2"))
    assert caught.value.message == (
        "DESTINATION CHECKSUM MISMATCH User defined checksum and destination checksum do not "
        f"match: deadbeef != {adler(src)}"
    )
    assert not (tmp_path / "d2").exists()  # cleaned up
    params.set_checksum(checksum_mode.source, "adler32", adler(src).upper())
    ctx.filecopy(params, file_url(src), file_url(tmp_path / "d3"))
    params.set_checksum(checksum_mode.target, "adler32", adler(src))
    ctx.filecopy(params, file_url(src), file_url(tmp_path / "d4"))
    # A bulk entry replaces the parameters' value, and target mode needs one (as gfal2).
    results = ctx.filecopy(params, [file_url(src)], [file_url(tmp_path / "d5")], ["adler32:"])
    assert isinstance(results[0], GError)
    assert (results[0].code, results[0].message) == (
        errno.EINVAL,
        "Checksum value required if mode is not end to end",
    )
    assert params.get_checksum() == (checksum_mode.target, "adler32", adler(src))  # untouched
    assert not (tmp_path / "d5").exists()


def test_source_destination_mismatch(ctx: Gfal2Context, tmp_path: Path) -> None:
    params = ctx.transfer_parameters()
    params.set_checksum(checksum_mode.both, "adler32", "")
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, "mock://h/src?size=64&checksum=1", file_url(tmp_path / "dst"))
    message = caught.value.message
    assert message.startswith(  # mock:// reads random bytes, as gfal2's does
        "DESTINATION CHECKSUM MISMATCH Source checksum and destination checksum do not match: "
        "00000001 != "
    )
    assert len(message.rpartition(" != ")[2]) == 8


def test_strict_copy_skips_checks(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    dst = tmp_path / "dst.bin"
    dst.write_bytes(b"old")
    params = ctx.transfer_parameters()
    params.strict_copy = True
    params.set_checksum(checksum_mode.source, "adler32", "deadbeef")
    ctx.filecopy(params, file_url(src), file_url(dst))
    assert dst.read_bytes() == src.read_bytes()


def test_cleanup_policy(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    events: list[xgfalclient.GfaltEvent] = []
    params = ctx.transfer_parameters()
    params.event_callback = events.append
    params.set_checksum(checksum_mode.target, "adler32", "deadbeef")
    with pytest.raises(GError):
        ctx.filecopy(params, file_url(src), file_url(tmp_path / "gone"))
    assert not (tmp_path / "gone").exists()
    assert "CLEANUP" not in [e.stage for e in events]  # gfal2's local copy never narrates one
    params.transfer_cleanup = False
    with pytest.raises(GError):
        ctx.filecopy(params, file_url(src), file_url(tmp_path / "kept"))
    assert (tmp_path / "kept").exists()


class Copier(Plugin):
    """A plugin that claims cp:// pairs and misbehaves on request."""

    name = "copier"
    schemes = ("cp",)
    option_group = "COPIER PLUGIN"
    priority = 5

    def stat(self, url: str) -> Stat:
        raise GError("No such file", errno.ENOENT)

    def unlink(self, url: str) -> None:
        raise GError("cannot remove", errno.EBUSY)

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        return algorithm

    def copy_check(self, source: str, destination: str) -> bool:
        return source.startswith("cp://")

    def copy(self, transfer: Transfer) -> None:
        transfer.event("TRANSFER:TYPE", "custom")
        if "crash" in transfer.source:
            raise ValueError("plugin bug")
        if "fail" in transfer.source:
            raise GError("remote failure", errno.ECOMM if hasattr(errno, "ECOMM") else errno.EIO)


@pytest.fixture
def cctx(ctx: Gfal2Context) -> Gfal2Context:
    ctx.add_plugin(Copier)
    return ctx


def test_plugin_copies(cctx: Gfal2Context) -> None:
    events: list[xgfalclient.GfaltEvent] = []
    params = cctx.transfer_parameters()
    params.event_callback = events.append
    params.set_checksum(checksum_mode.both, "", "")
    cctx.filecopy(params, "cp://a/ok", "cp://b/ok")
    assert {e.domain for e in events[3:]} == {"copier"}
    cctx.set_opt_string("COPIER PLUGIN", "COPY_CHECKSUM_TYPE", "MD5")
    events.clear()
    cctx.filecopy(params, "cp://a/ok", "cp://b/ok")
    with pytest.raises(GError) as caught:
        cctx.filecopy(params, "cp://a/crash", "cp://b/x")
    assert caught.value.code == errno.EIO
    assert caught.value.message == "Transfer failed: plugin bug"
    cleanup = [e.description for e in events if e.stage == "CLEANUP"]
    assert cleanup == [str(errno.EBUSY)]


class Registrar(Copier):
    """Like the LFC: an existing destination is the plugin's business."""

    name = "registrar"
    schemes = ("reg",)
    copy_manages_destination = True

    def stat(self, url: str) -> Stat:
        return Stat(st_mode=0o100644, st_size=1)  # the destination "exists"

    def copy_check(self, source: str, destination: str) -> bool:
        return destination.startswith("reg://")


def test_plugin_that_manages_its_destination(ctx: Gfal2Context, src: Path) -> None:
    ctx.add_plugin(Registrar)
    events: list[xgfalclient.GfaltEvent] = []
    params = ctx.transfer_parameters()
    params.event_callback = events.append
    ctx.filecopy(params, file_url(src), "reg://h/name")  # no EEXIST, no delete
    assert "OVERWRITE" not in [e.stage for e in events]
    with pytest.raises(GError):
        ctx.filecopy(params, "cp://a/fail", "reg://h/name")  # Copier's source: fails
    with pytest.raises(GError, match="plugin bug"):
        ctx.filecopy(params, "cp://a/crash", "reg://h/name")
    assert "CLEANUP" not in [e.stage for e in events]


def test_no_route_without_local_transfers(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    params = ctx.transfer_parameters()
    params.local_transfers = False
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, file_url(src), file_url(tmp_path / "x"))
    assert caught.value.code == errno.EPROTONOSUPPORT


def test_bulk_copy(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    events: list[xgfalclient.GfaltEvent] = []
    params = ctx.transfer_parameters()
    params.event_callback = events.append
    results = ctx.filecopy(
        params,
        [file_url(src), file_url(tmp_path / "missing"), file_url(src)],
        [file_url(tmp_path / "b1"), file_url(tmp_path / "b2"), file_url(tmp_path / "b3")],
        [f"adler32:{adler(src)}", "", adler(src)],
    )
    assert results[0] is None and results[2] is None
    assert isinstance(results[1], GError) and results[1].code == errno.ENOENT
    assert results[1].message.startswith("Could not open source:")
    items = [e.description for e in events if e.stage == "LIST:ITEM"]
    assert items[:3] == [
        f"{file_url(src)} => {file_url(tmp_path / 'b1')}",
        f"{file_url(tmp_path / 'missing')} => {file_url(tmp_path / 'b2')}",
        f"{file_url(src)} => {file_url(tmp_path / 'b3')}",
    ]
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, [file_url(src)], [file_url(tmp_path / "x"), file_url(tmp_path / "y")])
    assert (caught.value.code, caught.value.message) == (
        errno.EINVAL,
        "Number of sources and destinations do not match",
    )
    with pytest.raises(GError):
        run_bulk(ctx, params, ["a"], ["b"], ["x", "y"])
    assert ctx.filecopy(params, [file_url(src)], [file_url(tmp_path / "b4")]) == [None]


def test_copy_into_a_device(ctx: Gfal2Context, src: Path) -> None:
    ctx.filecopy(file_url(src), "file:///dev/null")  # no overwrite needed, nothing deleted
    assert Path("/dev/null").exists()


def test_special_destinations() -> None:
    for kind in (stat_module.S_IFCHR, stat_module.S_IFIFO, stat_module.S_IFSOCK):
        assert _is_special(kind | 0o600)
    assert not _is_special(stat_module.S_IFREG | 0o600)


def test_copy_into_a_fifo(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    received: list[bytes] = []
    reader = threading.Thread(target=lambda: received.append(fifo.read_bytes()), daemon=True)
    reader.start()
    ctx.filecopy(file_url(src), file_url(fifo))  # a sink: no overwrite needed
    reader.join(10)
    assert received == [src.read_bytes()]


def test_checksum_failures_name_the_side(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    params = ctx.transfer_parameters()
    params.set_checksum(checksum_mode.both, "sha256", "")
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, file_url(src), file_url(tmp_path / "x"))
    assert caught.value.message == (
        "Could not get the source checksum: Checksum type sha256 not supported for local files"
    )
    params.set_checksum(checksum_mode.target, "sha256", "abc")
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, file_url(src), file_url(tmp_path / "y"))
    assert caught.value.message.startswith("Could not get the destination checksum:")


def test_split_checksum() -> None:
    assert _split_checksum("") == ("", "")
    assert _split_checksum("ADLER32:abc") == ("ADLER32", "abc")
    assert _split_checksum("abc") == ("", "abc")


# -- the streamed copy's failure modes -------------------------------------------------------


def test_stream_source_failures(ctx: Gfal2Context, tmp_path: Path) -> None:
    with pytest.raises(GError) as caught:
        run_copy(ctx, TransferParameters(), "mock://h/s?errno=13", file_url(tmp_path / "x"))
    assert caught.value.message == "Could not open source: Permission denied"
    with pytest.raises(GError) as caught:
        run_copy(ctx, TransferParameters(), file_url(tmp_path), file_url(tmp_path / "x"))
    assert (caught.value.code, caught.value.message) == (
        errno.EISDIR,
        "errno reported by local system call Is a directory",
    )
    with pytest.raises(GError) as caught:
        run_copy(
            ctx, TransferParameters(), "mock://h/s?size=3&open_errno=5", file_url(tmp_path / "x")
        )
    assert caught.value.message == "Could not open source: Input/output error"
    with pytest.raises(GError) as caught:
        run_copy(
            ctx, TransferParameters(), "mock://h/s?size=3&read_errno=5", file_url(tmp_path / "x")
        )
    assert caught.value.code == errno.EIO


def test_stream_destination_refuses_writes(ctx: Gfal2Context, src: Path) -> None:
    params = TransferParameters()
    params.overwrite = True
    with pytest.raises(GError) as caught:
        run_copy(ctx, params, file_url(src), "mock://h/dst?size_post=1")
    assert caught.value.code == errno.ENOSYS
    assert (
        caught.value.message
        == "Could not open destination: Mock plugin does not support read and write"
    )


class Short(PluginFile):
    def readinto(self, buffer: memoryview | bytearray) -> int:
        return 0


class Lying(Plugin):
    name = "lying"
    schemes = ("lie",)
    priority = 5

    def stat(self, url: str) -> Stat:
        return Stat(st_mode=0o100644, st_size=10)

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        return Short(url)


def test_short_stream_is_an_error(ctx: Gfal2Context, tmp_path: Path) -> None:
    ctx.add_plugin(Lying)
    with pytest.raises(GError) as caught:
        run_copy(ctx, TransferParameters(), "lie://h/f", file_url(tmp_path / "x"))
    assert caught.value.message == "Short copy: 0 bytes transferred, the source has 10"
    assert not (tmp_path / "x").exists()


class Chunks(PluginFile):
    def __init__(self, count: int, fail_at: int = -1) -> None:
        super().__init__("chunks")
        self.count = count
        self.fail_at = fail_at
        self.reads = 0

    def readinto(self, buffer: memoryview | bytearray) -> int:
        if self.reads == self.fail_at:
            raise GError("read failed", errno.EIO)
        if self.reads >= self.count or not len(buffer):
            return 0
        self.reads += 1
        buffer[:4] = b"data"
        return 4


class Sink(PluginFile):
    def __init__(self) -> None:
        super().__init__("sink")
        self.data = bytearray()

    def write(self, data: bytes | bytearray | memoryview) -> int:
        self.data += data
        return len(data)


def test_pump_moves_every_chunk(ctx: Gfal2Context) -> None:
    sink = Sink()
    transfer = Transfer(ctx, TransferParameters(), "a", "b")
    assert pump(transfer, Chunks(50), sink, buffer_size=16, depth=0) == 200
    assert bytes(sink.data) == b"data" * 50
    assert transfer.transferred == 200


def test_pump_reraises_reader_errors(ctx: Gfal2Context) -> None:
    transfer = Transfer(ctx, TransferParameters(), "a", "b")
    with pytest.raises(GError) as caught:
        pump(transfer, Chunks(50, fail_at=3), Sink(), buffer_size=16)
    assert caught.value.message == "read failed"


def test_pump_stops_on_cancel(ctx: Gfal2Context) -> None:
    transfer = Transfer(ctx, TransferParameters(), "a", "b")
    ctx.cancel()
    with pytest.raises(GError) as caught:
        pump(transfer, Chunks(10_000), Sink(), buffer_size=16)
    assert caught.value.code == errno.ECANCELED
    assert threading.active_count() >= 1  # the reader thread was joined, not leaked
    assert not [t for t in threading.enumerate() if t.name == "xgfal-reader"]


# -- gfal2 parity: modes, same file, clean-up, events, callbacks, bulk ---------------------------


def test_stream_creates_the_destination_0755(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    old = os.umask(0o022)
    try:
        ctx.filecopy(file_url(src), file_url(tmp_path / "d"))
    finally:
        os.umask(old)
    assert (tmp_path / "d").stat().st_mode & 0o777 == 0o755  # gfal2's streamed copy mode


def test_copy_onto_itself_without_overwrite_is_eexist(ctx: Gfal2Context, src: Path) -> None:
    with pytest.raises(GError) as caught:
        ctx.filecopy(file_url(src), file_url(src))
    assert (caught.value.code, caught.value.message) == (
        errno.EEXIST,
        "The file exists and overwrite is not set",
    )
    params = ctx.transfer_parameters()
    params.strict_copy = True  # would truncate the source before reading it
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, file_url(src), file_url(src))
    assert caught.value.code == errno.EINVAL
    assert src.stat().st_size == 256 * 4096 + 4


def test_failed_copy_leaves_an_untouched_destination(ctx: Gfal2Context, tmp_path: Path) -> None:
    precious = tmp_path / "precious"
    precious.write_bytes(b"keep me")
    events: list[xgfalclient.GfaltEvent] = []
    params = ctx.transfer_parameters()
    params.strict_copy = True
    params.event_callback = events.append
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, file_url(tmp_path / "missing"), file_url(precious))
    assert caught.value.message.startswith("Could not open source:")
    assert precious.read_bytes() == b"keep me"
    assert "CLEANUP" not in [e.stage for e in events]


def test_cleanup_spares_sinks_and_reports_failures(
    ctx: Gfal2Context, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    events: list[xgfalclient.GfaltEvent] = []
    params = TransferParameters()
    params.event_callback = events.append
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    transfer = Transfer(ctx, params, "a", file_url(fifo))
    transfer.owns_destination = True
    _cleanup(transfer, plugin_copy=False)
    assert fifo.exists() and not events
    transfer = Transfer(ctx, params, "a", file_url(tmp_path / "never"))
    transfer.owns_destination = True
    _cleanup(transfer, plugin_copy=False)  # nothing there: nothing to do
    assert not events
    _cleanup(transfer, plugin_copy=True)  # a plugin's is narrated; already gone is 0, as in gfal2
    assert [(e.stage, e.description) for e in events] == [("CLEANUP", "0")]
    (tmp_path / "full").mkdir()
    (tmp_path / "full" / "f").write_bytes(b"")
    with pytest.raises(GError) as caught:
        ctx.unlink(file_url(tmp_path / "full"))
    transfer = Transfer(ctx, params, "a", file_url(tmp_path / "full"))
    transfer.owns_destination = True
    with caplog.at_level(logging.WARNING, logger="gfal2"):
        _cleanup(transfer, plugin_copy=True)  # any other failure is its errno, and a warning
    assert (events[-1].stage, events[-1].description) == ("CLEANUP", str(caught.value.code))
    assert caplog.messages == [f"When trying to clean the destination: {caught.value.message}"]
    transfer.callback_error = ValueError("boom")  # the callback is broken: stay quiet
    _cleanup(transfer, plugin_copy=True)
    assert len(events) == 2


def test_list_items_are_markup_escaped(ctx: Gfal2Context, tmp_path: Path) -> None:
    events: list[xgfalclient.GfaltEvent] = []
    params = ctx.transfer_parameters()
    params.event_callback = events.append
    source, target = file_url(tmp_path / "a&b<c>"), file_url(tmp_path / "d&e")
    with pytest.raises(GError):
        ctx.filecopy(params, source, target)
    item = next(e.description for e in events if e.stage == "LIST:ITEM")
    assert "a&amp;b&lt;c&gt; => " in item and item.endswith("d&amp;e")
    enter = next(e.description for e in events if e.stage == "TRANSFER:ENTER")
    assert enter == f"{source} => {target}"  # not escaped, as in gfal2


def test_copy_events_are_logged(
    ctx: Gfal2Context, src: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="gfal2"):
        ctx.filecopy(file_url(src), file_url(tmp_path / "d"))
    triggered = [m for m in caplog.messages if m.startswith("Event triggered: ")]
    assert triggered[0] == "Event triggered: BOTH GFAL2:CORE:COPY LIST:ENTER "
    assert "Event triggered: BOTH GFAL2:CORE:COPY:LOCAL TRANSFER:TYPE streamed" in triggered


def test_an_event_callback_error_aborts_the_copy(
    ctx: Gfal2Context, src: Path, tmp_path: Path
) -> None:
    def early(event: Any) -> None:
        raise ValueError("boom")

    params = ctx.transfer_parameters()
    params.event_callback = early
    with pytest.raises(ValueError, match="boom"):
        ctx.filecopy(params, file_url(src), file_url(tmp_path / "e1"))
    assert not (tmp_path / "e1").exists()
    with pytest.raises(ValueError, match="boom"):  # a bulk copy stops, too
        ctx.filecopy(params, [file_url(src)] * 2, [file_url(tmp_path / "e2")] * 2)

    def late(event: Any) -> None:
        if event.stage == "TRANSFER:EXIT":
            raise KeyError("late")

    params.event_callback = late
    with pytest.raises(KeyError):
        ctx.filecopy(params, file_url(src), file_url(tmp_path / "e3"))
    assert not (tmp_path / "e3").exists()  # written, so cleaned up like any failed copy

    def gerror(event: Any) -> None:
        if event.stage == "TRANSFER:TYPE":
            raise GError("from the callback", errno.EPERM)

    params.event_callback = gerror
    with pytest.raises(GError, match="from the callback"):  # not a per-file result
        ctx.filecopy(params, [file_url(src)], [file_url(tmp_path / "e4")])


def test_a_monitor_callback_error_aborts_a_stream(
    ctx: Gfal2Context, src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("xgfalclient.transfer.STREAM_MONITOR_INTERVAL", 0.0)

    def broken(*args: Any) -> None:
        raise RuntimeError("stop")

    params = ctx.transfer_parameters()
    params.monitor_callback = broken
    with pytest.raises(RuntimeError, match="stop"):
        ctx.filecopy(params, file_url(src), file_url(tmp_path / "m"))
    assert not (tmp_path / "m").exists()


def test_stream_monitor_cadence(
    ctx: Gfal2Context, src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("xgfalclient.transfer.MONITOR_INTERVAL", 0.0)  # plugins' cadence only
    calls: list[int] = []
    params = ctx.transfer_parameters()
    params.monitor_callback = lambda *args: calls.append(args[4])
    ctx.set_opt_integer("CORE", "COPY_BUFFERSIZE", 4096)
    ctx.filecopy(params, file_url(src), file_url(tmp_path / "a"))
    assert calls == []  # under five seconds, and no final report
    monkeypatch.setattr("xgfalclient.transfer.STREAM_MONITOR_INTERVAL", 0.0)
    ctx.filecopy(params, file_url(src), file_url(tmp_path / "b"))
    assert calls and calls[-1] == src.stat().st_size


class Wrapper(Copier):
    """Plugin copies that mishandle a callback's exception, or nest a copy (as SRM does)."""

    name = "wrapper"
    schemes = ("wrap",)

    def copy_check(self, source: str, destination: str) -> bool:
        return source.startswith("wrap://")

    def copy(self, transfer: Transfer) -> None:
        try:
            transfer.event("TRANSFER:TYPE", "wrapped")
        except Exception as exc:
            if "wrap" in transfer.destination:
                raise GError(f"wrapped: {exc}", errno.EIO) from exc
            return  # swallowed
        run_copy(self.context, transfer.params, "cp://a/ok", "cp://b/inner")


def test_callback_errors_survive_plugins(cctx: Gfal2Context) -> None:
    cctx.add_plugin(Wrapper)

    def broken(event: Any) -> None:
        if event.description in ("wrapped", "custom"):
            raise ValueError("boom")

    params = cctx.transfer_parameters()
    params.event_callback = broken
    for destination in ("wrap://h/d", "cp://h/swallow"):
        with pytest.raises(ValueError, match="boom"):
            cctx.filecopy(params, "wrap://h/s", destination)

    def inner(event: Any) -> None:
        if event.description == "custom":  # raised by the nested copy's Transfer
            raise ValueError("inner")

    params.event_callback = inner
    with pytest.raises(ValueError, match="inner"):
        cctx.filecopy(params, "wrap://h/s", "cp://h/nested")


class SelfChecking(Copier):
    """Verifies checksums itself, as gfal2's plugins do."""

    name = "selfchecking"
    schemes = ("self",)
    copy_manages_checksums = True

    def copy_check(self, source: str, destination: str) -> bool:
        return source.startswith("self://")


def test_plugin_that_manages_its_checksums(cctx: Gfal2Context) -> None:
    cctx.add_plugin(SelfChecking)
    events: list[xgfalclient.GfaltEvent] = []
    params = cctx.transfer_parameters()
    params.event_callback = events.append
    params.set_checksum(checksum_mode.source, "adler32", "never-compared")
    cctx.filecopy(params, "self://a/ok", "self://b/ok")
    assert not [e for e in events if e.stage.startswith("CHECKSUM")]


def test_strict_plugin_copy_never_cleans_up(cctx: Gfal2Context) -> None:
    events: list[xgfalclient.GfaltEvent] = []
    params = cctx.transfer_parameters()
    params.strict_copy = True
    params.event_callback = events.append
    with pytest.raises(GError):
        cctx.filecopy(params, "cp://a/fail", "cp://b/x")
    assert "CLEANUP" not in [e.stage for e in events]


def test_no_route_message(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    params = ctx.transfer_parameters()
    params.local_transfers = False
    target = file_url(tmp_path / "x")
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, file_url(src), target)
    assert caught.value.message == (
        f"No plugin supports a transfer from {file_url(src)} to {target}, "
        "and local streaming is disabled"
    )


def test_bulk_checksums_keep_the_mode(ctx: Gfal2Context, src: Path, tmp_path: Path) -> None:
    params = ctx.transfer_parameters()
    wrong = ["ADLER32:00000000"]
    assert ctx.filecopy(params, [file_url(src)], [file_url(tmp_path / "n")], wrong) == [None]
    params.set_checksum(checksum_mode.both, "md5", "")
    results = ctx.filecopy(params, [file_url(src)], [file_url(tmp_path / "b")], wrong)
    assert isinstance(results[0], GError)
    assert results[0].message.startswith("SOURCE CHECKSUM MISMATCH")
    assert params.get_checksum() == (checksum_mode.both, "md5", "")
    params.set_checksum(checksum_mode.source, "adler32", adler(src))
    assert ctx.filecopy(params, [file_url(src)], [file_url(tmp_path / "s")]) == [None]
    right = [f"ADLER32:{adler(src)}"]
    assert ctx.filecopy(params, [file_url(src)], [file_url(tmp_path / "r")], right) == [None]
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, [file_url(src)], [file_url(tmp_path / "x")], ["a", "b"])
    assert caught.value.message == "Number of pairs and checksums do not match"


class Bulk(Copier):
    """A plugin with a bulk copy, handed the whole list."""

    name = "bulk"
    schemes = ("bulk",)
    handed: list[tuple[str, str, str, str]] = []

    def copy_check(self, source: str, destination: str) -> bool:
        return source.startswith("bulk://")

    def copy_bulk(self, params: TransferParameters, transfers: Any) -> list[GError | None]:
        for t in transfers:
            Bulk.handed.append((t.source, t.destination, t.checksum_algorithm, t.domain))
        return [None] * len(transfers)


def test_bulk_goes_to_a_plugin_copy_bulk(cctx: Gfal2Context) -> None:
    cctx.add_plugin(Bulk)
    params = cctx.transfer_parameters()
    sources, targets = ["bulk://a/1", "bulk://a/2"], ["bulk://b/1", "bulk://b/2"]
    assert cctx.filecopy(params, sources, targets, ["MD5:x", "y"]) == [None, None]
    assert Bulk.handed == [
        ("bulk://a/1", "bulk://b/1", "MD5", "bulk"),
        ("bulk://a/2", "bulk://b/2", "", "bulk"),
    ]
    Bulk.handed.clear()
    assert cctx.filecopy(params, sources[:1], targets[:1]) == [None]
    assert Bulk.handed[0][2] == ""
    assert cctx.filecopy(params, [], []) == []
    assert cctx.filecopy(params, ["cp://a/ok"], ["cp://b/ok"]) == [None]  # no copy_bulk: per pair


class Unsized(Plugin):
    """A regular file that stats as empty and is not (``/proc/self/status``)."""

    name = "unsized"
    schemes = ("proc",)
    priority = 5

    def stat(self, url: str) -> Stat:
        return Stat(st_mode=0o100444, st_size=0)

    def open(self, url: str, flags: int, mode: int = 0o644, size: int | None = None) -> PluginFile:
        return Chunks(3)


def test_stream_reads_to_eof(ctx: Gfal2Context, tmp_path: Path) -> None:
    ctx.add_plugin(Unsized)
    ctx.filecopy("proc://self/status", file_url(tmp_path / "status"))
    assert (tmp_path / "status").read_bytes() == b"data" * 3
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    writer = threading.Thread(target=lambda: fifo.write_bytes(b"x" * 1000), daemon=True)
    writer.start()
    ctx.filecopy(file_url(fifo), file_url(tmp_path / "fromfifo"))
    writer.join(10)
    assert (tmp_path / "fromfifo").read_bytes() == b"x" * 1000


class ThirdParty(Plugin):
    """Two servers copying between themselves; checksums as each end reports them."""

    name = "thirdparty"
    schemes = ("tpc",)
    option_group = "THIRDPARTY PLUGIN"
    priority = 5
    sums: dict[str, str] = {}
    removed: list[str] = []

    def stat(self, url: str) -> Stat:
        raise GError("No such file", errno.ENOENT)

    def unlink(self, url: str) -> None:
        self.removed.append(url)

    def checksum(self, url: str, algorithm: str, offset: int, length: int) -> str:
        if url not in self.sums:
            raise GError("no checksum here", errno.ENOTSUP)
        return self.sums[url]

    def copy_check(self, source: str, destination: str) -> bool:
        return source.startswith("tpc://")

    def copy(self, transfer: Transfer) -> None:
        transfer.third_party = True  # the destination says it is done


@pytest.fixture
def tctx(ctx: Gfal2Context) -> Gfal2Context:
    ThirdParty.sums, ThirdParty.removed = {}, []
    ctx.add_plugin(ThirdParty)
    return ctx


def test_a_third_party_copy_is_checked_even_when_no_checksum_was_asked_for(
    tctx: Gfal2Context,
) -> None:
    """RAL's Echo called a pull from EOS finished and held a full-size file of no data."""
    ThirdParty.sums = {"tpc://src/f": "262a6f28", "tpc://dst/f": "00000001"}
    params = tctx.transfer_parameters()
    with pytest.raises(GError) as caught:
        tctx.filecopy(params, "tpc://src/f", "tpc://dst/f")
    assert caught.value.code == errno.EIO
    assert "DESTINATION CHECKSUM MISMATCH after a third-party copy" in caught.value.message
    assert "262a6f28 != destination 00000001" in caught.value.message
    assert ThirdParty.removed == ["tpc://dst/f"]  # what it wrote is wrong, so it goes


def test_a_third_party_copy_whose_ends_agree_or_cannot_say_stands(tctx: Gfal2Context) -> None:
    params = tctx.transfer_parameters()
    ThirdParty.sums = {"tpc://src/f": "262a6f28", "tpc://dst/f": "262A6F28"}
    tctx.filecopy(params, "tpc://src/f", "tpc://dst/f")
    ThirdParty.sums = {"tpc://src/f": "262a6f28"}  # the destination has no checksum to give
    tctx.filecopy(params, "tpc://src/f", "tpc://dst/f")
    assert ThirdParty.removed == []


def test_the_third_party_check_can_be_turned_off(tctx: Gfal2Context) -> None:
    ThirdParty.sums = {"tpc://src/f": "262a6f28", "tpc://dst/f": "00000001"}
    tctx.set_opt_boolean("CORE", "VERIFY_THIRD_PARTY", False)
    tctx.filecopy(tctx.transfer_parameters(), "tpc://src/f", "tpc://dst/f")
    assert ThirdParty.removed == []
