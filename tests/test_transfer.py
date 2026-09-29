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
    params.checksum_check = True
    assert params.get_checksum()[0] is checksum_mode.both
    params.checksum_check = False
    assert params.get_checksum()[0] is checksum_mode.none
    with pytest.warns(DeprecationWarning):
        params.set_user_defined_checksum("md5", "x")
    with pytest.warns(DeprecationWarning):
        assert params.get_user_defined_checksum() == ("md5", "x")
    assert params.get_checksum() == (checksum_mode.none, "md5", "x")


# -- events and the Transfer handle ---------------------------------------------------------


def test_emit_survives_a_broken_callback(caplog: pytest.LogCaptureFixture) -> None:
    params = TransferParameters()
    emit(params, "d", "s")  # no callback: nothing happens

    def broken(event: Any) -> None:
        raise ValueError("boom")

    params.event_callback = broken
    with caplog.at_level(logging.ERROR, logger="xgfalclient.transfer"):
        emit(params, "d", "s")
    assert "event_callback raised" in caplog.text


def test_transfer_checksum_selection(ctx: Gfal2Context) -> None:
    params = TransferParameters()
    transfer = Transfer(ctx, params, "a", "b", user_checksum=("md5", "x"))
    assert (transfer.checksum_mode, transfer.checksum_algorithm, transfer.user_checksum) == (
        checksum_mode.both,
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
    params.timeout = -1  # negative is no limit too
    assert transfer.deadline is None
    params.timeout = 10
    remaining = transfer.remaining()
    assert remaining is not None and 0 < remaining <= 10
    now = time.monotonic()
    monkeypatch.setattr("xgfalclient.transfer.time.monotonic", lambda: now + 20)
    with pytest.raises(GError) as caught:
        transfer.check()
    assert caught.value.code == errno.ETIMEDOUT
    assert transfer.remaining() == 0.0


def test_transfer_cancel(ctx: Gfal2Context) -> None:
    transfer = Transfer(ctx, TransferParameters(), "a", "b")
    assert ctx.cancel() == 0
    with pytest.raises(GError) as caught:
        transfer.check()
    assert caught.value.code == errno.ECANCELED


def test_progress_throttles_monitor(
    ctx: Gfal2Context, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    with caplog.at_level(logging.ERROR, logger="xgfalclient.transfer"):
        transfer.progress(400, force=True)
    assert "monitor_callback raised" in caplog.text


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
    # A bulk entry with no value overrides the parameters' one: computed, not compared.
    assert ctx.filecopy(params, [file_url(src)], [file_url(tmp_path / "d5")], ["adler32:"]) == [
        None
    ]


def test_source_destination_mismatch(ctx: Gfal2Context, tmp_path: Path) -> None:
    params = ctx.transfer_parameters()
    params.set_checksum(checksum_mode.both, "adler32", "")
    with pytest.raises(GError) as caught:
        ctx.filecopy(params, "mock://h/src?size=64&checksum=1", file_url(tmp_path / "dst"))
    zeros = f"{zlib.adler32(bytes(64)):08x}"
    assert caught.value.message == (
        "DESTINATION CHECKSUM MISMATCH Source checksum and destination checksum do not match: "
        f"00000001 != {zeros}"
    )


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
    assert [(e.stage, e.description) for e in events if e.stage == "CLEANUP"] == [("CLEANUP", "0")]
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
    assert _split_checksum("") is None
    assert _split_checksum("ADLER32:abc") == ("ADLER32", "abc")
    assert _split_checksum("abc") == ("", "abc")


# -- the streamed copy's failure modes -------------------------------------------------------


def test_stream_source_failures(ctx: Gfal2Context, tmp_path: Path) -> None:
    with pytest.raises(GError) as caught:
        run_copy(ctx, TransferParameters(), "mock://h/s?errno=13", file_url(tmp_path / "x"))
    assert caught.value.message == "Could not open source: Permission denied"
    with pytest.raises(GError) as caught:
        run_copy(ctx, TransferParameters(), file_url(tmp_path), file_url(tmp_path / "x"))
    assert caught.value.code == errno.EISDIR
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
