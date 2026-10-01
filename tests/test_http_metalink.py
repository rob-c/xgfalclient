# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""Davix-compatible HTTP Metalink discovery and failover."""

from __future__ import annotations

import errno
import os
import shutil
import subprocess
from email.message import Message
from pathlib import Path

import pytest

import xgfalclient
from test_http_helpers import dav, dav2, hctx, write  # noqa: F401 - fixtures
from xgfalclient import GError
from xgfalclient.plugins.http import _copy, _metalink
from xgfalclient.testing.webdav import WebDAVServer


def enabled(context: xgfalclient.Gfal2Context) -> None:
    context.set_opt_boolean("HTTP PLUGIN", "METALINK", True)


def document(urls: list[tuple[int, str]], size: int, *, version: str = "4.0") -> bytes:
    if version.startswith("3"):
        resources = "".join(f'<url preference="{priority}">{url}</url>' for priority, url in urls)
        return (
            f'<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>'
            f'<file name="f"><size>{size}</size><resources>{resources}</resources>'
            "</file></files></metalink>"
        ).encode()
    resources = "".join(f'<url priority="{priority}">{url}</url>' for priority, url in urls)
    return (
        '<metalink xmlns="urn:ietf:params:xml:ns:metalink">'
        f'<file name="f"><size>{size}</size>{resources}</file></metalink>'
    ).encode()


def advertise(
    server: WebDAVServer,
    source: str,
    descriptor: str,
    *,
    times: int = 1,
) -> None:
    server.fault(
        "HEAD",
        source,
        status=200,
        headers={"Link": f'<{descriptor}>; rel="describedby"; type="application/metalink4+xml"'},
        times=times,
    )


def file_url(path: Path) -> str:
    return "file://" + os.fspath(path)


def test_filecopy_discovers_a_link_and_uses_the_first_working_replica(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    dav2: WebDAVServer,
    tmp_path: Path,
) -> None:
    enabled(hctx)
    body = b"replicated data"
    write(dav2, "/data/good", body)
    descriptor = dav.url("/catalog/f.meta4")
    write(
        dav,
        "/catalog/f.meta4",
        document([(1, dav2.url("/missing")), (2, dav2.url("/data/good"))], len(body)),
    )
    advertise(dav, "/logical", descriptor)

    hctx.filecopy(dav.url("/logical"), file_url(tmp_path / "out"))

    assert (tmp_path / "out").read_bytes() == body
    discovery = next(request for request in dav.requests if request.method == "HEAD")
    assert discovery.header("Accept") == _metalink.ACCEPT
    assert any(request.path == "/catalog/f.meta4" for request in dav.requests)
    assert any(
        request.method == "GET" and request.path == "/data/good" for request in dav2.requests
    )


@pytest.mark.skipif(shutil.which("davix-get") is None, reason="no official davix-get on PATH")
def test_official_davix_and_this_client_follow_the_same_metalink(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    dav2: WebDAVServer,
    tmp_path: Path,
) -> None:
    enabled(hctx)
    body = b"cross-implementation metalink"
    write(dav2, "/data/good", body)
    write(
        dav,
        "/official.meta4",
        document(
            [(1, dav2.url("/data/good").replace("dav://", "http://"))],
            len(body),
            version="3.0",
        ),
    )
    advertise(dav, "/logical", dav.url("/official.meta4"))
    ours = tmp_path / "ours"
    theirs = tmp_path / "theirs"
    hctx.filecopy(dav.url("/logical"), file_url(ours))
    # davix-get performs independent discovery for its stat and read stages.
    advertise(dav, "/logical", dav.url("/official.meta4"), times=2)
    completed = subprocess.run(
        [
            "davix-get",
            "--metalink",
            "failover",
            dav.url("/logical"),
            os.fspath(theirs),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    trace = [(request.method, request.path, request.header("Accept")) for request in dav.requests]
    assert completed.returncode == 0, f"{completed.stderr}\nrequests={trace!r}"
    assert ours.read_bytes() == theirs.read_bytes() == body


def test_open_recovers_when_get_fails_after_stat_succeeded(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    enabled(hctx)
    body = b"mirror"
    write(dav, "/data/original", body)
    write(dav2, "/data/mirror", body)
    write(dav, "/catalog.meta4", document([(1, dav2.url("/data/mirror"))], len(body)))
    dav.fault("GET", "/data/original", status=500)
    advertise(dav, "/data/original", dav.url("/catalog.meta4"))

    with hctx.open(dav.url("/data/original"), "r") as handle:
        assert handle.read(100) == "mirror"

    assert any(request.method == "GET" for request in dav2.requests)


def test_pread_fails_over_and_keeps_the_requested_range(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    enabled(hctx)
    body = b"0123456789"
    write(dav, "/data/original", body)
    write(dav2, "/data/mirror", body)
    write(dav, "/p.meta4", document([(1, dav2.url("/data/mirror"))], len(body)))
    dav.fault("GET", "/data/original", status=503)
    advertise(dav, "/data/original", dav.url("/p.meta4"))

    with hctx.open(dav.url("/data/original"), "r") as handle:
        assert handle.pread(3, 4) == "3456"

    assert dav2.requests[-1].header("Range") == "bytes=3-6"


def test_pread_keeps_progress_when_a_transport_failure_switches_replica(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    enabled(hctx)
    hctx.set_opt_integer("CORE", "CONN_RETRY", 0)
    body = b"transport failover"
    write(dav, "/data/original", body)
    write(dav2, "/data/mirror", body)
    write(dav, "/pread.meta4", document([(1, dav2.url("/data/mirror"))], len(body)))
    dav.fault("GET", "/data/original", body=body, truncate=3)
    advertise(dav, "/data/original", dav.url("/pread.meta4"))

    with hctx.open(dav.url("/data/original"), "r") as handle:
        assert handle.pread_bytes(0, len(body)) == body

    assert dav2.requests[-1].header("Range") == f"bytes=3-{len(body) - 1}"


def test_stream_switches_replica_after_transport_retry_budget(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    enabled(hctx)
    hctx.set_opt_integer("CORE", "CONN_RETRY", 0)
    body = b"transport failover"
    write(dav, "/data/original", body)
    write(dav2, "/data/mirror", body)
    write(dav, "/transport.meta4", document([(1, dav2.url("/data/mirror"))], len(body)))
    dav.fault("GET", "/data/original", body=body, truncate=3)
    advertise(dav, "/data/original", dav.url("/transport.meta4"))

    with hctx.open(dav.url("/data/original"), "r") as handle:
        assert handle.read_bytes(len(body)) == body


def test_pread_preserves_error_when_no_replica_or_discovery_fails(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    enabled(hctx)
    body = b"original"
    write(dav, "/data/no-other", body)
    write(dav, "/same.meta4", document([(1, dav.url("/data/no-other"))], len(body)))
    dav.fault("GET", "/data/no-other", status=500)
    advertise(dav, "/data/no-other", dav.url("/same.meta4"))
    with hctx.open(dav.url("/data/no-other"), "r") as handle, pytest.raises(GError):
        handle.pread_bytes(0, 2)

    write(dav, "/data/bad-catalog", body)
    write(dav, "/bad-catalog.meta4", b"<broken")
    dav.fault("GET", "/data/bad-catalog", status=500)
    advertise(dav, "/data/bad-catalog", dav.url("/bad-catalog.meta4"))
    with hctx.open(dav.url("/data/bad-catalog"), "r") as handle, pytest.raises(GError):
        handle.read_bytes(2)


def test_parallel_copy_restarts_on_a_metalink_replica_only_after_failure(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    dav2: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enabled(hctx)
    monkeypatch.setattr(_copy, "PARALLEL_THRESHOLD", 1)
    body = os.urandom((2 << 20) + 17)
    write(dav, "/data/original", body)
    write(dav2, "/data/mirror", body)
    write(dav, "/parallel.meta4", document([(1, dav2.url("/data/mirror"))], len(body)))
    dav.fault("GET", "/data/original", status=500, times=_copy.DEFAULT_STREAMS)
    advertise(dav, "/data/original", dav.url("/parallel.meta4"))
    params = hctx.transfer_parameters()
    params.nbstreams = 2

    hctx.filecopy(params, dav.url("/data/original"), file_url(tmp_path / "parallel"))

    assert (tmp_path / "parallel").read_bytes() == body


def test_parallel_copy_preserves_failure_when_metalink_discovery_errors(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enabled(hctx)
    monkeypatch.setattr(_copy, "PARALLEL_THRESHOLD", 1)
    body = os.urandom(10_000)
    write(dav, "/data/original", body)
    write(dav, "/invalid.meta4", b"<broken")
    dav.fault("GET", "/data/original", status=500, times=_copy.DEFAULT_STREAMS)
    advertise(dav, "/data/original", dav.url("/invalid.meta4"))
    params = hctx.transfer_parameters()
    params.nbstreams = 2

    with pytest.raises(GError):
        hctx.filecopy(params, dav.url("/data/original"), file_url(tmp_path / "out"))


@pytest.mark.parametrize("code", [errno.ECANCELED, errno.ETIMEDOUT])
def test_parallel_copy_does_not_fail_over_after_cancel_or_timeout(
    code: int,
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    dav2: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enabled(hctx)
    body = b"original"
    write(dav, "/data/original", body)
    write(dav2, "/data/mirror", body)
    write(dav, "/catalog.meta4", document([(1, dav2.url("/data/mirror"))], len(body)))
    advertise(dav, "/data/original", dav.url("/catalog.meta4"))
    monkeypatch.setattr(_copy, "PARALLEL_THRESHOLD", 1)

    def stopped(*args: object, **kwargs: object) -> None:
        raise GError("stop", code)

    monkeypatch.setattr(_copy, "_parallel", stopped)
    params = hctx.transfer_parameters()
    params.nbstreams = 2

    with pytest.raises(GError) as caught:
        hctx.filecopy(params, dav.url("/data/original"), file_url(tmp_path / "out"))
    assert caught.value.code == code
    assert not any(request.method == "HEAD" for request in dav.requests)


def test_content_type_can_make_the_original_url_the_descriptor(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    enabled(hctx)
    body = b"from self-described metadata"
    write(dav2, "/data/f", body)
    write(dav, "/logical", document([(1, dav2.url("/data/f"))], len(body)))
    dav.fault("PROPFIND", "/logical", status=500)
    dav.fault(
        "HEAD",
        "/logical",
        status=200,
        headers={"Content-Type": "application/metalink4+xml; charset=utf-8"},
    )

    assert hctx.stat(dav.url("/logical")).st_size == len(body)


def test_disabled_metalink_preserves_the_original_error(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    write(dav2, "/data/f", b"x")
    write(dav, "/catalog.meta4", document([(1, dav2.url("/data/f"))], 1))
    advertise(dav, "/missing", dav.url("/catalog.meta4"))

    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/missing"))

    assert caught.value.code == errno.ENOENT
    assert not any(request.method == "HEAD" for request in dav.requests)


def test_bad_descriptor_and_failed_replicas_preserve_the_primary_error(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    enabled(hctx)
    write(dav, "/bad.meta4", b"<broken")
    advertise(dav, "/missing", dav.url("/bad.meta4"))
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/missing"))
    assert caught.value.code == errno.ENOENT


def test_discovery_cache_and_absent_or_failed_descriptors(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, dav2: WebDAVServer
) -> None:
    enabled(hctx)
    source = dav.url("/cached")
    descriptor = dav.url("/cached.meta4")
    write(dav, "/cached.meta4", document([(1, dav2.url("/data/mirror"))], 1))
    advertise(dav, "/cached", descriptor)
    http = hctx.plugin(source, "stat")
    replicas = http._metalink_replicas(source)
    requests = len(dav.requests)
    assert http._metalink_replicas(source) == replicas
    assert len(dav.requests) == requests
    http._prefer_metalink(source, dav2.url("/not-listed"))
    assert http._metalink_replicas(source) == replicas

    write(dav, "/plain", b"plain")
    assert http._metalink_replicas(dav.url("/plain")) == ()

    advertise(dav, "/missing-descriptor", dav.url("/absent.meta4"))
    assert http._metalink_replicas(dav.url("/missing-descriptor")) == ()

    dav.clear()
    write(dav, "/none.meta4", document([(1, dav.url("/also-missing"))], 1))
    advertise(dav, "/missing2", dav.url("/none.meta4"))
    with pytest.raises(GError) as caught:
        hctx.stat(dav.url("/missing2"))
    assert caught.value.code == errno.ENOENT


def test_parser_orders_v3_resolves_relative_urls_and_deduplicates() -> None:
    parsed = _metalink.parse_metalink(
        document([(1, "../slow"), (100, "../fast"), (50, "../fast")], 9, version="3.0"),
        base_url="davs://host/catalog/f.meta4",
    )
    assert parsed.replicas == ("davs://host/fast", "davs://host/slow")
    assert parsed.size == 9


@pytest.mark.parametrize(
    "payload, message",
    [
        (b"<broken", "Malformed"),
        (b"<wrong/>", "root"),
        (b"<!DOCTYPE x><metalink/>", "DOCTYPE"),
        (b"<metalink><file><url>ftp://host/f</url></file></metalink>", "no usable"),
    ],
)
def test_parser_rejects_unsafe_or_unusable_documents(payload: bytes, message: str) -> None:
    with pytest.raises(GError, match=message):
        _metalink.parse_metalink(payload, base_url="https://host/f.meta4")


def test_parser_enforces_descriptor_url_and_replica_limits() -> None:
    with pytest.raises(GError, match="limit"):
        _metalink.parse_metalink(
            b" " * (_metalink.MAX_DESCRIPTOR_SIZE + 1), base_url="https://host/f.meta4"
        )
    too_long = "https://host/" + "x" * 4097
    parsed = _metalink.parse_metalink(
        document([(1, too_long), (2, "https://host/good")], 1),
        base_url="https://host/f.meta4",
    )
    assert parsed.replicas == ("https://host/good",)
    monkey = "".join(
        f"<url>https://host/{index}</url>" for index in range(_metalink.MAX_REPLICAS + 1)
    )
    with pytest.raises(GError, match="more than"):
        _metalink.parse_metalink(
            f"<metalink><file>{monkey}</file></metalink>".encode(),
            base_url="https://host/f.meta4",
        )


def test_discovery_link_parser_handles_multiple_and_malformed_fields() -> None:
    class Discovery:
        def __init__(self, links: list[str], content_type: str = "") -> None:
            self.headers = Message()
            for value in links:
                self.headers.add_header("Link", value)
            if content_type:
                self.headers["Content-Type"] = content_type

        def header(self, name: str) -> str:
            return str(self.headers.get(name, ""))

    response = Discovery(
        [
            "malformed link field",
            '<ignored>; rel="alternate"; type="text/plain", '
            "<//mirror.example/meta>; rel='describedby'; type='application/metalink4+xml'",
        ]
    )
    assert (
        _metalink.descriptor_url(response, "https://origin.example/data")  # type: ignore[arg-type]
        == "https://mirror.example/meta"
    )
    assert (
        _metalink.descriptor_url(  # type: ignore[arg-type]
            Discovery([], "application/metalink+xml"), "https://origin.example/data"
        )
        == "https://origin.example/data"
    )
    assert (
        _metalink.descriptor_url(  # type: ignore[arg-type]
            Discovery([]), "https://origin.example/data"
        )
        is None
    )
    assert _metalink._links("no angle brackets") == []
    assert _metalink._links("<unterminated") == []
    assert _metalink._parameter(_metalink._REL, "; title=x") == ""


def test_parser_tolerates_bad_metadata_and_resolves_network_paths() -> None:
    parsed = _metalink.parse_metalink(
        b"""
        <metalink><file><size>unknown</size>
          <url priority="not-a-number">//mirror.example/data</url>
          <url></url><url>file:///not-http</url>
        </file></metalink>
        """,
        base_url="davs://origin.example/catalog.meta4",
    )
    assert parsed.replicas == ("davs://mirror.example/data",)
    assert parsed.size is None


def test_parser_without_a_size_element_has_an_unknown_size() -> None:
    parsed = _metalink.parse_metalink(
        b"<metalink><file><url>/data</url></file></metalink>",
        base_url="https://origin.example/catalog.meta4",
    )
    assert parsed.size is None
