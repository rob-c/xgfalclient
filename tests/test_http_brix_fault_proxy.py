"""HTTP reads through the external BRIX network fault injector."""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

import pytest

import xgfalclient
from _brix import BrixProxy
from xgfalclient.testing.webdav import WebDAVServer


def test_stream_and_pread_survive_one_shot_brix_truncation(tmp_path: Path) -> None:
    payload = os.urandom(2 << 20)
    root = tmp_path / "dav"
    with WebDAVServer(root) as server:
        source = server.local("/data/payload.bin")
        source.parent.mkdir(parents=True)
        source.write_bytes(payload)
        with BrixProxy(server.port, seed=19) as proxy:
            context = xgfalclient.creat_context()
            context.set_opt_integer("CORE", "CONN_RETRY", 12)
            context.set_opt_integer("HTTP PLUGIN", "OPERATION_TIMEOUT", 2)
            url = f"dav://127.0.0.1:{proxy.listen_port}/data/payload.bin"
            try:
                streamed = context.open(url, "r")
                proxy.command("one-shot")
                proxy.command("truncate-at 65536 down")
                try:
                    assert streamed.read_bytes(len(payload)) == payload
                finally:
                    streamed.close()

                positioned = context.open(url, "r")
                proxy.command("one-shot")
                proxy.command("truncate-at 65536 down")
                try:
                    assert positioned.pread_bytes(0, len(payload)) == payload
                finally:
                    positioned.close()

                proxy.command("clear")
                proxy.command("block")
                proxy.command("drop")
                restore = threading.Timer(0.2, proxy.command, args=("unblock",))
                restore.start()
                try:
                    assert context.stat(url).st_size == len(payload)
                finally:
                    restore.join(timeout=5)
                status = proxy.command("status")
            finally:
                context.free()

    severed = re.search(r"severs=(\d+)", status)
    assert severed is not None and int(severed.group(1)) >= 2
    refused = re.search(r"refused=(\d+)", status)
    assert refused is not None and int(refused.group(1)) > 0


def test_http_put_replays_after_one_shot_brix_truncation(tmp_path: Path) -> None:
    payload = os.urandom(2 << 20)
    source = tmp_path / "upload.bin"
    source.write_bytes(payload)
    root = tmp_path / "dav"
    (root / "data").mkdir(parents=True)
    with WebDAVServer(root) as server:
        with BrixProxy(server.port, seed=29) as proxy:
            context = xgfalclient.creat_context()
            context.set_opt_integer("CORE", "CONN_RETRY", 12)
            context.set_opt_integer("HTTP PLUGIN", "OPERATION_TIMEOUT", 2)
            destination = f"dav://127.0.0.1:{proxy.listen_port}/data/upload.bin"
            proxy.command("one-shot")
            proxy.command("truncate-at 131072 up")
            try:
                context.filecopy(f"file://{source}", destination)
                status = proxy.command("status")
            finally:
                context.free()

        assert server.local("/data/upload.bin").read_bytes() == payload

    severed = re.search(r"severs=(\d+)", status)
    assert severed is not None and int(severed.group(1)) > 0


def test_download_outlasts_repeated_truncation_until_the_link_heals(tmp_path: Path) -> None:
    payload = os.urandom(2 << 20)
    root = tmp_path / "dav"
    with WebDAVServer(root) as server:
        source = server.local("/data/flapping.bin")
        source.parent.mkdir(parents=True)
        source.write_bytes(payload)
        with BrixProxy(server.port, seed=31) as proxy:
            context = xgfalclient.creat_context()
            context.set_opt_integer("CORE", "CONN_RETRY", 50)
            context.set_opt_integer("HTTP PLUGIN", "OPERATION_TIMEOUT", 1)
            url = f"dav://127.0.0.1:{proxy.listen_port}/data/flapping.bin"
            proxy.command("chunk 4096 down")
            proxy.command("truncate-at 32768 down")
            proxy.command("heal-after 300")
            started = time.monotonic()
            try:
                handle = context.open(url, "r")
                try:
                    received = handle.read_bytes(len(payload))
                finally:
                    handle.close()
                status = proxy.command("status")
            finally:
                context.free()

    assert received == payload
    assert time.monotonic() - started < 5
    severed = re.search(r"severs=(\d+)", status)
    assert severed is not None and int(severed.group(1)) >= 2


def test_http_put_replays_until_a_flapping_link_heals(tmp_path: Path) -> None:
    payload = os.urandom(2 << 20)
    source = tmp_path / "upload-flapping.bin"
    source.write_bytes(payload)
    root = tmp_path / "dav"
    (root / "data").mkdir(parents=True)
    with WebDAVServer(root) as server:
        with BrixProxy(server.port, seed=41) as proxy:
            context = xgfalclient.creat_context()
            context.set_opt_integer("CORE", "CONN_RETRY", 50)
            context.set_opt_integer("HTTP PLUGIN", "OPERATION_TIMEOUT", 1)
            destination = f"dav://127.0.0.1:{proxy.listen_port}/data/flapping-upload.bin"
            proxy.command("chunk 4096 up")
            proxy.command("truncate-at 65536 up")
            proxy.command("heal-after 300")
            try:
                context.filecopy(f"file://{source}", destination)
                status = proxy.command("status")
            finally:
                context.free()

        assert server.local("/data/flapping-upload.bin").read_bytes() == payload

    severed = re.search(r"severs=(\d+)", status)
    assert severed is not None and int(severed.group(1)) >= 2


def test_a_middlebox_stripping_range_cannot_shift_a_positioned_read(tmp_path: Path) -> None:
    payload = os.urandom(1 << 20)
    root = tmp_path / "dav"
    with WebDAVServer(root) as server:
        source = server.local("/data/range.bin")
        source.parent.mkdir(parents=True)
        source.write_bytes(payload)
        with BrixProxy(server.port, seed=43) as proxy:
            context = xgfalclient.creat_context()
            url = f"dav://127.0.0.1:{proxy.listen_port}/data/range.bin"
            proxy.command("http strip-header Range up")
            try:
                handle = context.open(url, "r")
                try:
                    received = handle.pread_bytes(192 << 10, 64 << 10)
                finally:
                    handle.close()
            finally:
                context.free()

    assert received == payload[192 << 10 : 256 << 10]


def test_body_corruption_is_rejected_and_cleaned_up(tmp_path: Path) -> None:
    payload = b"A" * (1 << 20)
    root = tmp_path / "dav"
    target = tmp_path / "corrupt-download.bin"
    with WebDAVServer(root) as server:
        source = server.local("/data/corrupt.bin")
        source.parent.mkdir(parents=True)
        source.write_bytes(payload)
        with BrixProxy(server.port, seed=47) as proxy:
            context = xgfalclient.creat_context()
            params = context.transfer_parameters()
            params.set_checksum(xgfalclient.checksum_mode.both, "adler32", "")
            url = f"dav://127.0.0.1:{proxy.listen_port}/data/corrupt.bin"
            proxy.command("replace str:AAAAAAAA str:BAAAAAAA down")
            try:
                with pytest.raises(xgfalclient.GError, match="DESTINATION CHECKSUM MISMATCH"):
                    context.filecopy(params, url, f"file://{target}")
            finally:
                context.free()

    assert not target.exists()


def test_read_survives_tiny_segments_jitter_and_a_silent_firewall_reap(
    tmp_path: Path,
) -> None:
    payload = os.urandom(2 << 20)
    root = tmp_path / "dav"
    with WebDAVServer(root) as server:
        source = server.local("/data/drunk-admin.bin")
        source.parent.mkdir(parents=True)
        source.write_bytes(payload)
        with BrixProxy(server.port, seed=59) as proxy:
            context = xgfalclient.creat_context()
            context.set_opt_integer("CORE", "CONN_RETRY", 20)
            context.set_opt_integer("HTTP PLUGIN", "OPERATION_TIMEOUT", 1)
            url = f"dav://127.0.0.1:{proxy.listen_port}/data/drunk-admin.bin"
            proxy.command("mss 128")
            proxy.command("chunk 97 both")
            proxy.command("jitter 2 both")
            proxy.command("one-shot")
            proxy.command("random-hangup 20 40 100")
            try:
                handle = context.open(url, "r")
                try:
                    received = handle.read_bytes(len(payload))
                finally:
                    handle.close()
                status = proxy.command("status")
            finally:
                context.free()

    assert received == payload
    hung = re.search(r"random_hangups=(\d+)", status)
    assert hung is not None and int(hung.group(1)) > 0
