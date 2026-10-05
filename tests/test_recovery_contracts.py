"""Hermetic checks that transport rebasing preserves recovery and durability."""

from __future__ import annotations

import errno
import os
from types import SimpleNamespace

import pytest

from xgfalclient.errors import GError
from xgfalclient.plugins import file as local
from xgfalclient.plugins.http import _io
from xgfalclient.transfer import _sync_local_destination


def options(interval=None):
    return SimpleNamespace(
        integer=lambda group, key, default: default if interval is None else interval,
        has=lambda group, key: interval is not None,
    )


@pytest.mark.parametrize("interval,expected", [(None, 0.1), (0, None), (2, 2.0)])
def test_local_retry_pause_policy(monkeypatch, interval, expected):
    calls = []
    monkeypatch.setattr(local.time, "sleep", calls.append)
    local._retry_pause(options(interval), 2)
    assert calls == ([] if expected is None else [expected])


@pytest.mark.parametrize("method", ["pread", "readinto"])
def test_local_read_reopens_once_without_changing_source(tmp_path, monkeypatch, method):
    path = tmp_path / "data"
    path.write_bytes(b"a" * 5000)
    calls = []
    original = local._os

    def interrupted(function, *args):
        if function.__name__ == method and not calls:
            calls.append(function.__name__)
            raise GError("stale descriptor", errno.ESTALE)
        return original(function, *args)

    monkeypatch.setattr(local, "_os", interrupted)
    monkeypatch.setattr(local.time, "sleep", lambda _: None)
    handle = local.LocalFile(path.as_uri(), str(path), os.O_RDONLY, 0o600, options())
    try:
        if method == "pread":
            assert handle.pread(0, 5000) == b"a" * 4096
        else:
            buffer = bytearray(5000)
            assert handle.readinto(buffer) == 4096
            assert buffer[:4096] == b"a" * 4096
        assert calls == [method]
    finally:
        handle.close()


def test_local_read_without_recovery_options_preserves_error(tmp_path):
    path = tmp_path / "data"
    path.write_bytes(b"data")
    handle = local.LocalFile(path.as_uri(), str(path), os.O_RDONLY, 0o600)

    def failed():
        raise GError("stale descriptor", errno.ESTALE)

    try:
        with pytest.raises(GError, match="stale descriptor"):
            handle._recovering_read(failed)
    finally:
        handle.close()


@pytest.mark.parametrize("failure", ["open", "stat", "changed"])
def test_local_reopen_rejects_errors_and_changed_generation(tmp_path, monkeypatch, failure):
    path = tmp_path / "data"
    path.write_bytes(b"data")
    handle = local.LocalFile(path.as_uri(), str(path), os.O_RDONLY, 0o600, options(0))

    def failed(*args):
        raise OSError(errno.EIO, "unavailable")

    if failure == "changed":
        handle._identity = (0, 0, 0, 0, 0)
    else:
        monkeypatch.setattr(local.os, "open" if failure == "open" else "fstat", failed)
    try:
        with pytest.raises(GError) as caught:
            handle._reopen_read(1, GError("stale descriptor", errno.ESTALE))
        assert caught.value.code == (errno.ESTALE if failure == "changed" else errno.EIO)
    finally:
        handle.close()


def test_local_constructor_closes_descriptor_when_stat_fails(tmp_path, monkeypatch):
    path = tmp_path / "data"
    path.write_bytes(b"data")
    descriptor = []
    original = os.fstat

    def failed(fd):
        descriptor.append(fd)
        raise OSError(errno.EIO, "stat failed")

    monkeypatch.setattr(local.os, "fstat", failed)
    with pytest.raises(OSError, match="stat failed"):
        local.LocalFile(path.as_uri(), str(path), os.O_RDONLY, 0o600)
    with pytest.raises(OSError) as caught:
        original(descriptor[0])
    assert caught.value.errno == errno.EBADF


def test_plugin_open_retries_a_transient_read_failure(tmp_path, monkeypatch, ctx):
    path = tmp_path / "data"
    path.write_bytes(b"data")
    original = local.LocalFile
    calls = []

    def interrupted(*args):
        calls.append(args)
        if len(calls) == 1:
            raise OSError(errno.ESTALE, "stale mount")
        return original(*args)

    monkeypatch.setattr(local, "LocalFile", interrupted)
    monkeypatch.setattr(local.time, "sleep", lambda _: None)
    with ctx.open(path.as_uri(), "r") as handle:
        assert handle.read_bytes(4) == b"data"
    assert len(calls) == 2


@pytest.mark.parametrize("failure", ["size", "sync"])
def test_destination_sync_failure_is_not_reported_as_success(tmp_path, monkeypatch, failure):
    path = tmp_path / "data"
    path.write_bytes(b"data")
    transfer = SimpleNamespace(destination=path.as_uri(), transferred=3 if failure == "size" else 4)

    def failed(fd):
        raise OSError(errno.ENOSPC, "disk full")

    if failure == "sync":
        monkeypatch.setattr(os, "fsync", failed)
    with pytest.raises(GError, match="Could not sync destination") as caught:
        _sync_local_destination(transfer)
    assert caught.value.code == (errno.EIO if failure == "size" else errno.ENOSPC)


def test_skipping_an_ignored_range_stops_at_eof():
    calls = []

    def eof(view):
        calls.append(len(view))
        return 0

    _io._skip(SimpleNamespace(readinto=eof), 4)
    assert calls == [4]
