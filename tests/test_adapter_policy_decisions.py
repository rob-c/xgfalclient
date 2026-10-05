"""Offline decisions at transport, retry and dependency-adapter boundaries."""

from __future__ import annotations

import errno
import importlib
import os
from datetime import datetime, timezone
from email.message import Message
from functools import partial
from types import SimpleNamespace

import pytest

from xgfalclient._xml import fromstring
from xgfalclient.errors import GError
from xgfalclient.plugins import file as local
from xgfalclient.plugins.http import _client, _copy, _io, _metalink, _s3
from xgfalclient.plugins.http.plugin import HTTPPlugin
from xgfalclient.plugins.sftp import ssh


def _raise(error):
    raise error


def test_missing_optional_platform_errno_is_not_required(monkeypatch):
    original_namespace = dict(vars(local))
    try:
        with monkeypatch.context() as patcher:
            patcher.delattr(errno, "ESTALE")
            importlib.reload(local)
            assert errno.EAGAIN in local._TRANSIENT_READ_ERRORS
    finally:
        # Reloading replaces classes that other collected tests imported.
        # Restore their identities as well as the real platform errno set.
        vars(local).update(original_namespace)


@pytest.mark.parametrize("case", ["unseekable", "write_mode", "permanent"])
def test_local_read_recovery_rejects_unsafe_or_permanent_retries(tmp_path, ctx, case):
    path = tmp_path / "data"
    path.write_bytes(b"data")
    handle = local.LocalFile(path.as_uri(), str(path), os.O_RDONLY, 0o600, ctx.options)
    error = GError("read failed", errno.EACCES if case == "permanent" else errno.ESTALE)
    try:
        if case == "unseekable":
            handle._seekable = False
        if case == "write_mode":
            handle._flags = os.O_WRONLY
        assert not handle._can_recover_read(error, 1)
    finally:
        handle.close()


def test_local_open_stops_after_the_configured_retry_budget(monkeypatch, ctx):
    ctx.set_opt_integer("CORE", "CONN_RETRY", 0)
    monkeypatch.setattr(local, "LocalFile", lambda *args: _raise(OSError(errno.ESTALE, "stale")))
    with pytest.raises(GError) as error:
        local.FilePlugin(ctx).open("file:///unused-test-path", os.O_RDONLY)
    assert error.value.code == errno.ESTALE


def test_returning_a_connection_after_pool_shutdown_closes_it(ctx):
    client = _client.HTTPClient(ctx)
    calls = []
    exchange = SimpleNamespace(key=("http", "unused", 80, 0), close=lambda: calls.append("close"))
    client._checkin(exchange)
    assert calls == ["close"]


def test_destination_write_error_without_errno_has_a_plain_fallback(monkeypatch):
    monkeypatch.setattr(_copy.os, "pwrite", lambda *args: _raise(OSError("write failed")))
    with pytest.raises(GError, match="write failed") as error:
        _copy._pwrite_all(-1, memoryview(b"x"), 0)
    assert error.value.code == errno.EIO


@pytest.mark.parametrize("method", ["_retry_stream", "_failover_stream", "pread"])
def test_read_timeout_never_selects_another_replica(monkeypatch, method):
    plugin = SimpleNamespace(conn_retry=lambda: 0)
    handle = _io.HTTPReadFile(plugin, "https://unused.example/data", 1)
    monkeypatch.setattr(
        handle, "_next_replica", lambda: _raise(AssertionError("timeout must not fail over"))
    )
    timeout = _client.TransportError("timed out", errno.ETIMEDOUT)
    if method == "_retry_stream":
        call = partial(handle._retry_stream, timeout, 0)
    elif method == "_failover_stream":
        call = partial(handle._failover_stream, timeout)
    else:
        monkeypatch.setattr(handle, "_read_range", lambda *args: _raise(timeout))
        call = partial(handle.pread, 0, 1)
    with pytest.raises(GError) as error:
        call()
    assert error.value.code == (errno.EIO if method == "_retry_stream" else errno.ETIMEDOUT)


@pytest.mark.parametrize("operation", ["request", "stat"])
def test_http_timeout_preserves_code_and_does_not_attempt_recovery(ctx, monkeypatch, operation):
    plugin = HTTPPlugin(ctx)
    timeout = _client.TransportError("timed out", errno.ETIMEDOUT)
    if operation == "request":
        monkeypatch.setattr(plugin.client, "request", lambda *args, **kwargs: _raise(timeout))
        call = partial(plugin._request, "GET", "https://unused.example/data")
    else:
        monkeypatch.setattr(plugin, "_stat", lambda url: _raise(timeout))
        monkeypatch.setattr(plugin, "_metalink_enabled", lambda url: True)
        monkeypatch.setattr(
            plugin, "_metalink_stat", lambda *args: _raise(AssertionError("unexpected failover"))
        )
        call = partial(plugin.stat, "https://unused.example/data")
    with pytest.raises(GError) as error:
        call()
    assert error.value.code == errno.ETIMEDOUT


def _descriptor_response(relation):
    headers = Message()
    suffix = "" if relation is None else f'; rel="{relation}"'
    headers["Link"] = f'<https://unused.example/catalog>; type="application/metalink4+xml"{suffix}'
    return SimpleNamespace(headers=headers, header=lambda name: headers.get(name, ""))


@pytest.mark.parametrize("relation", [None, "alternate"])
def test_metalink_link_relation_may_be_missing_but_must_not_be_unrelated(relation):
    found = _metalink.descriptor_url(_descriptor_response(relation), "https://unused.example/data")
    assert found == ("https://unused.example/catalog" if relation is None else None)


def test_empty_metalink_size_does_not_invent_a_file_length():
    assert _metalink._size(fromstring(b"<metalink><size/></metalink>")) is None


class OfflineResponse:
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def header(self, name):
        return self.headers.get(name, "")

    def close(self):
        self.closed = True


def test_metalink_descriptor_with_informational_status_is_not_a_success(ctx, monkeypatch):
    plugin = HTTPPlugin(ctx)
    monkeypatch.setattr(plugin, "_metalink_enabled", lambda url: True)
    head = OfflineResponse(200, _descriptor_response("describedby").headers)
    descriptor = OfflineResponse(199, Message())
    monkeypatch.setattr(
        plugin.client,
        "request",
        lambda method, *args, **kwargs: head if method == "HEAD" else descriptor,
    )
    assert plugin._metalink_replicas("https://unused.example/data") == ()
    assert head.closed and descriptor.closed


def test_botocore_replaces_stale_signing_headers():
    signer = _s3.S3Signer(_s3.S3Keys("test-access", "test-secret", "test-token", "us-east-1"))
    target = _client.Target.of("https://unused.example/bucket/key", s3=True)
    signed = signer.sign(
        "GET",
        target,
        {
            "X-Amz-Date": "stale",
            "X-Amz-Content-Sha256": "stale",
            "X-Amz-Security-Token": "stale",
            "X-Amz-Meta-Name": "retained",
        },
        None,
        when=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    lowered = {name.lower(): value for name, value in signed.items()}
    assert lowered["x-amz-date"] == "20260101T000000Z"
    assert lowered["x-amz-security-token"] == "test-token"
    assert lowered["x-amz-meta-name"] == "retained"
    assert lowered["x-amz-content-sha256"] != "stale"


def test_ssh_preferences_keep_aes_ctr_when_optional_fast_modes_are_unavailable():
    backend = SimpleNamespace(has_gcm=False, fast_chacha=False)
    assert ssh._ciphers_preferred(backend) == (
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
        "chacha20-poly1305@openssh.com",
    )
