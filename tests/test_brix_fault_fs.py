"""Local-copy behavior through the external BRIX FUSE fault filesystem."""

from __future__ import annotations

import errno
import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from _brix_fs import BrixFaultFS
from xgfalclient import GError


@pytest.fixture
def fault_fs(tmp_path: Path) -> Iterator[BrixFaultFS]:
    with BrixFaultFS(tmp_path) as filesystem:
        yield filesystem


def _url(path: Path) -> str:
    return f"file://{path}"


def _copy(source: Path, target: Path) -> None:
    context = xgfalclient.creat_context()
    try:
        context.filecopy(_url(source), _url(target))
    finally:
        context.free()


def test_local_copy_survives_short_fuse_reads_and_writes(fault_fs: BrixFaultFS) -> None:
    payload = os.urandom(2 << 20)
    (fault_fs.backing / "source.bin").write_bytes(payload)
    fault_fs.configure(
        {
            "trace": True,
            "rules": [
                {"path": "/source.bin", "op": "read", "action": "short", "bytes": 4096},
                {"path": "/target.bin", "op": "write", "action": "short", "bytes": 4096},
            ],
        }
    )

    _copy(fault_fs.mount / "source.bin", fault_fs.mount / "target.bin")

    assert (fault_fs.backing / "target.bin").read_bytes() == payload
    assert fault_fs.command("status")["faults"] > 0


def test_local_copy_preserves_enospc_and_finishes_promptly(fault_fs: BrixFaultFS) -> None:
    payload = os.urandom(1 << 20)
    source = fault_fs.backing.parent / "source.bin"
    source.write_bytes(payload)
    fault_fs.configure(
        {
            "trace": True,
            "rules": [
                {
                    "path": "/target.bin",
                    "op": "write",
                    "action": "error",
                    "errno": "ENOSPC",
                    "after_bytes": 64 << 10,
                }
            ],
        }
    )

    started = time.monotonic()
    with pytest.raises(GError) as caught:
        _copy(source, fault_fs.mount / "target.bin")

    assert caught.value.code == errno.ENOSPC
    assert time.monotonic() - started < 5


def test_local_copy_rejects_zero_progress_from_fuse(fault_fs: BrixFaultFS) -> None:
    source = fault_fs.backing.parent / "source.bin"
    source.write_bytes(b"x" * (128 << 10))
    fault_fs.configure(
        {"rules": [{"path": "/target.bin", "op": "write", "action": "short", "bytes": 0}]}
    )

    with pytest.raises(GError) as caught:
        _copy(source, fault_fs.mount / "target.bin")

    assert caught.value.code == errno.EIO


def test_success_means_local_bytes_reached_stable_storage(fault_fs: BrixFaultFS) -> None:
    payload = os.urandom(1 << 20)
    source = fault_fs.backing.parent / "source.bin"
    source.write_bytes(payload)
    fault_fs.configure({"writeback": True, "fsync": "commit", "flush_on_close": False})

    _copy(source, fault_fs.mount / "target.bin")

    assert (fault_fs.backing / "target.bin").read_bytes() == payload


def test_an_fsync_ack_without_publication_is_not_success(fault_fs: BrixFaultFS) -> None:
    payload = os.urandom(256 << 10)
    source = fault_fs.backing.parent / "source.bin"
    source.write_bytes(payload)
    fault_fs.configure({"writeback": True, "fsync": "ack", "flush_on_close": False})

    with pytest.raises(GError) as caught:
        _copy(source, fault_fs.mount / "target.bin")

    assert caught.value.code == errno.EIO
    assert not (fault_fs.backing / "target.bin").exists()


def test_bursty_stale_source_handles_are_reopened_at_the_same_offset(
    fault_fs: BrixFaultFS,
) -> None:
    payload = os.urandom(512 << 10)
    (fault_fs.backing / "source.bin").write_bytes(payload)
    target = fault_fs.backing.parent / "target.bin"
    fault_fs.configure(
        {
            "trace": True,
            "rules": [
                {
                    "path": "/source.bin",
                    "op": "read",
                    "action": "error",
                    "errno": "ESTALE",
                    "every": 4,
                    "burst": 2,
                }
            ],
        }
    )
    context = xgfalclient.creat_context()
    context.set_opt_integer("CORE", "CONN_RETRY", 3)
    context.set_opt_integer("CORE", "CONN_RETRY_INTERVAL", 0)
    try:
        context.filecopy(_url(fault_fs.mount / "source.bin"), _url(target))
    finally:
        context.free()

    assert target.read_bytes() == payload
    assert fault_fs.command("status")["faults"] >= 4


def test_a_burst_of_stale_read_only_opens_is_retried(fault_fs: BrixFaultFS) -> None:
    payload = os.urandom(256 << 10)
    (fault_fs.backing / "source.bin").write_bytes(payload)
    target = fault_fs.backing.parent / "target.bin"
    fault_fs.configure(
        {
            "rules": [
                {
                    "path": "/source.bin",
                    "op": "open",
                    "action": "error",
                    "errno": "ESTALE",
                    "count": 2,
                }
            ]
        }
    )
    context = xgfalclient.creat_context()
    context.set_opt_integer("CORE", "CONN_RETRY", 3)
    context.set_opt_integer("CORE", "CONN_RETRY_INTERVAL", 0)
    try:
        context.filecopy(_url(fault_fs.mount / "source.bin"), _url(target))
    finally:
        context.free()

    assert target.read_bytes() == payload


def test_stale_handle_recovery_refuses_to_splice_a_replacement_file(
    fault_fs: BrixFaultFS,
) -> None:
    original = b"A" * (512 << 10)
    replacement = b"B" * len(original)
    (fault_fs.backing / "source.bin").write_bytes(original)
    (fault_fs.backing / "replacement.bin").write_bytes(replacement)
    target = fault_fs.backing.parent / "target.bin"
    fault_fs.configure(
        {
            "rules": [
                {
                    "path": "/source.bin",
                    "op": "read",
                    "action": "error",
                    "errno": "ESTALE",
                    "count": 1,
                }
            ]
        }
    )
    context = xgfalclient.creat_context()
    context.set_opt_integer("CORE", "CONN_RETRY", 3)
    context.set_opt_integer("CORE", "CONN_RETRY_INTERVAL", 1)
    replace = threading.Timer(
        0.2,
        os.replace,
        args=(fault_fs.mount / "replacement.bin", fault_fs.mount / "source.bin"),
    )
    replace.start()
    try:
        with pytest.raises(GError) as caught:
            context.filecopy(_url(fault_fs.mount / "source.bin"), _url(target))
    finally:
        replace.join(timeout=5)
        context.free()

    assert caught.value.code == errno.ESTALE
    assert "changed while recovering" in caught.value.message
    assert not target.exists()


def test_a_silently_dropped_middle_write_is_caught_by_integrity_checking(
    fault_fs: BrixFaultFS,
) -> None:
    payload = os.urandom(512 << 10)
    source = fault_fs.backing.parent / "source.bin"
    source.write_bytes(payload)
    fault_fs.configure(
        {
            "trace": True,
            "rules": [
                {
                    "path": "/target.bin",
                    "op": "write",
                    "action": "drop",
                    "offset_min": 64 << 10,
                    "offset_max": (128 << 10) - 1,
                }
            ],
        }
    )
    context = xgfalclient.creat_context()
    params = context.transfer_parameters()
    params.set_checksum(xgfalclient.checksum_mode.both, "adler32", "")
    try:
        with pytest.raises(GError, match="DESTINATION CHECKSUM MISMATCH"):
            context.filecopy(params, _url(source), _url(fault_fs.mount / "target.bin"))
    finally:
        context.free()

    assert fault_fs.command("status")["faults"] > 0


def test_a_source_that_lies_about_its_size_is_not_a_success(fault_fs: BrixFaultFS) -> None:
    payload = os.urandom(256 << 10)
    (fault_fs.backing / "source.bin").write_bytes(payload)
    target = fault_fs.backing.parent / "target.bin"
    fault_fs.configure(
        {
            "rules": [
                {
                    "path": "/source.bin",
                    "op": "getattr",
                    "action": "metadata",
                    "size_delta": 64 << 10,
                }
            ]
        }
    )

    with pytest.raises(GError, match="Short copy"):
        _copy(fault_fs.mount / "source.bin", target)


def test_a_torn_write_fails_without_spinning_or_replaying(fault_fs: BrixFaultFS) -> None:
    source = fault_fs.backing.parent / "source.bin"
    source.write_bytes(os.urandom(256 << 10))
    fault_fs.configure(
        {
            "trace": True,
            "rules": [
                {
                    "path": "/target.bin",
                    "op": "write",
                    "action": "torn",
                    "bytes": 4096,
                    "errno": "EIO",
                    "count": 1,
                }
            ],
        }
    )

    started = time.monotonic()
    with pytest.raises(GError) as caught:
        _copy(source, fault_fs.mount / "target.bin")

    assert caught.value.code == errno.EIO
    assert time.monotonic() - started < 5
    assert fault_fs.command("status")["faults"] == 1


def test_an_fsync_that_commits_then_errors_is_not_replayed(fault_fs: BrixFaultFS) -> None:
    source = fault_fs.backing.parent / "source.bin"
    source.write_bytes(os.urandom(256 << 10))
    fault_fs.configure(
        {
            "writeback": True,
            "fsync": "commit",
            "flush_on_close": False,
            "trace": True,
            "rules": [
                {
                    "path": "/target.bin",
                    "op": "fsync",
                    "action": "after_error",
                    "errno": "EIO",
                }
            ],
        }
    )

    with pytest.raises(GError) as caught:
        _copy(source, fault_fs.mount / "target.bin")

    assert caught.value.code == errno.EIO
    trace = fault_fs.command("status")["trace"]
    assert [row["op"] for row in trace].count("fsync") == 1


def test_late_fsync_enospc_prevents_false_success(fault_fs: BrixFaultFS) -> None:
    source = fault_fs.backing.parent / "source.bin"
    source.write_bytes(os.urandom(256 << 10))
    fault_fs.configure(
        {
            "trace": True,
            "rules": [{"path": "/target.bin", "op": "fsync", "action": "error", "errno": "ENOSPC"}],
        }
    )

    with pytest.raises(GError) as caught:
        _copy(source, fault_fs.mount / "target.bin")

    assert caught.value.code == errno.ENOSPC
    assert any(row["op"] == "fsync" for row in fault_fs.command("status")["trace"])
