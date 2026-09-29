"""The ``srm://`` plugin's tape operations and copies."""

# The shared fixtures come from test_srm; ruff sees each use as a redefinition.
# ruff: noqa: F811

from __future__ import annotations

import errno
from pathlib import Path

import pytest

import xgfalclient
from test_srm import GROUP, _fast_polls, fails, root, sctx, srm  # noqa: F401
from xgfalclient.errors import GError
from xgfalclient.plugins.srm import plugin as srm_plugin
from xgfalclient.testing.srm import SRMServer

# -- tape --------------------------------------------------------------------------


def test_bring_online_sync(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    srm.set_locality("/data/f", "NEARLINE")
    status, token = sctx.bring_online(srm.url("/data/f"), 100, 200, False)
    assert status == 1 and token
    assert srm.locality("/data/f") == "ONLINE_AND_NEARLINE"
    assert srm.operations() == ["srmBringOnline", "srmStatusOfBringOnlineRequest"]
    body = srm.log[0][1].decode()
    assert "<desiredTotalRequestTime>200</desiredTotalRequestTime>" in body
    assert "<desiredLifeTime>100</desiredLifeTime>" in body
    assert "<arrayOfSourceSURLs>" in srm.log[1][1].decode()


def test_bring_online_async_poll_release_abort(
    sctx: xgfalclient.Gfal2Context, srm: SRMServer
) -> None:
    srm.set_locality("/data/f", "NEARLINE")
    urls = [srm.url("/data/f"), srm.url("/nope")]
    errors, token = sctx.bring_online(urls, 100, 200, True)
    assert errors[0] is None and errors[1].code == errno.ENOENT
    assert errors[1].message == (
        "error on the bring online request: [SE][BringOnline][SRM_INVALID_PATH] "
        "No such file or directory "
    )
    assert sctx.bring_online(srm.url("/data/f"), 1, 1, True)[0] == 0
    polled = sctx.bring_online_poll(urls, token)
    assert polled[0] is None and polled[1].code == errno.ENOENT
    assert sctx.bring_online_poll(srm.url("/data/f"), token) == 1
    error = fails(xgfalclient.plugins.srm.soap.EBADR, sctx.bring_online_poll, urls[0], "bogus")
    assert "[SE][StatusOfBringOnlineRequest][SRM_INVALID_REQUEST]" in error.message
    assert sctx.release(urls[0], token) == 0
    released = sctx.release(urls, token)
    assert released[0] is None and released[1].code == errno.ENOENT
    assert released[1].message.startswith("error on the release request : [SE][ReleaseFiles]")
    fails(errno.EINVAL, sctx.release, urls[0], "")
    assert sctx.abort_bring_online(urls, token) == [None, None]
    assert sctx.abort_bring_online(urls[0], token) == 0


def test_bring_online_queued_then_lost(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    srm.queue_polls = 3
    status, token = sctx.bring_online(srm.url("/data/f"), 1, 60, True)
    assert status == 0
    assert sctx.bring_online_poll([srm.url("/data/f")], token)[0].code == errno.EAGAIN
    srm.set_locality("/data/f", "LOST")
    error = fails(errno.EIDRM, sctx.bring_online, srm.url("/data/f"), 1, 60, True)
    assert "SRM_FILE_LOST" in error.message


def test_bring_online_status_without_files(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    srm.inject(
        "srmStatusOfBringOnlineRequest",
        srm.status_reply("srmStatusOfBringOnlineRequest", "SRM_REQUEST_INPROGRESS"),
    )
    queued = sctx.bring_online_poll([srm.url("/data/f")], "t")
    assert queued[0].code == errno.EAGAIN
    srm.inject("srmReleaseFiles", srm.status_reply("srmReleaseFiles", "SRM_SUCCESS"))
    assert sctx.release([srm.url("/data/f")], "tok") == [None]


def test_bring_online_sync_timeout(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    srm.queue_polls = 10**6
    error = fails(errno.ETIMEDOUT, sctx.bring_online, srm.url("/data/f"), 1, 1, False)
    assert error.message.endswith(
        f"[SE][StatusOfBringOnlineRequest][ETIMEDOUT] {srm.endpoint}: User timeout over\n"
    )
    assert srm.operations()[-1] == "srmAbortRequest"


def test_bring_online_with_spacetoken(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    sctx.set_opt_string(GROUP, "SPACETOKENDESC", "OTHER")
    assert sctx.bring_online(srm.url("/data/f"), 1, 60, True)[0] == 1
    assert "<targetSpaceToken>tok2</targetSpaceToken>" in srm.log[-1][1].decode()


def test_archive_poll(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    urls = [srm.url("/data/f"), srm.url("/nope"), srm.url("/data/sub"), "srm:///bad"]
    assert sctx.archive_poll(urls[0]) == 0
    results = sctx.archive_poll(urls)
    assert results[0].code == errno.EAGAIN and results[2].code == errno.EAGAIN
    assert results[1].code == errno.ENOENT and results[3].code == errno.EINVAL
    assert srm.operations() == ["srmLs", "srmLs"]
    srm.set_locality("/data/f", "ONLINE_AND_NEARLINE")
    assert sctx.archive_poll(urls[0]) == 1
    srm.inject("srmLs", srm.status_reply("srmLs", "SRM_AUTHORIZATION_FAILURE"))
    assert sctx.archive_poll([urls[0]])[0].code == errno.EACCES
    from xgfalclient.plugins.srm import soap

    other = soap.response(
        "srmLs",
        [
            ("returnStatus", [("statusCode", "SRM_SUCCESS")]),
            ("details", [("pathDetailArray", [("path", "/elsewhere")])]),
        ],
    )
    srm.inject("srmLs", other)
    error = sctx.archive_poll([urls[0]])[0]
    assert error.message.endswith("/data/f is not yet archived")


# -- copies ------------------------------------------------------------------------


class Events:
    def __init__(self) -> None:
        self.seen: list[tuple[str, str, str, str]] = []

    def __call__(self, event: xgfalclient.GfaltEvent) -> None:
        side = {0: "SOURCE", 1: "DEST"}.get(event.side, "BOTH")
        self.seen.append((side, event.domain, event.stage, event.description))

    def stages(self) -> list[str]:
        return [stage for _, _, stage, _ in self.seen]


def params(**changes: object) -> tuple[xgfalclient.TransferParameters, Events]:
    events = Events()
    transfer = xgfalclient.TransferParameters()
    transfer.event_callback = events
    for name, value in changes.items():
        setattr(transfer, name, value)
    return transfer, events


def test_copy_srm_to_srm(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    p, events = params()
    sctx.filecopy(p, srm.url("/data/f"), srm.url("/data/c"))
    assert (root / "data" / "c").read_bytes() == b"hello world\n"
    srm_events = [event for event in events.seen if event[1] in ("SRM", srm_plugin.EVENT_DOMAIN)]
    assert srm_events == [
        ("BOTH", "SRM", "PREPARE:ENTER", ""),
        (
            "SOURCE",
            srm_plugin.EVENT_DOMAIN,
            "SRM:GET",
            f"Got TURL {srm.url('/data/f')} => file://{root}/data/f",
        ),
        (
            "DEST",
            srm_plugin.EVENT_DOMAIN,
            "SRM:PUT",
            f"Got TURL {srm.url('/data/c')} => file://{root}/data/c",
        ),
        ("BOTH", "SRM", "PREPARE:EXIT", ""),
        ("DEST", "SRM", "CLOSE:ENTER", srm.url("/data/c")),
        ("DEST", "SRM", "CLOSE:EXIT", srm.url("/data/c")),
    ]
    assert "LIST:ITEM" in events.stages()[3:]  # the inner copy's own events come through
    put = next(body.decode() for op, body in srm.log if op == "srmPrepareToPut")
    assert "<expectedFileSize>12</expectedFileSize>" in put
    assert srm.operations()[-2:] == ["srmPutDone", "srmReleaseFiles"]


def test_copy_to_and_from_local(
    sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path, tmp_path: Path
) -> None:
    local = tmp_path / "local"
    sctx.filecopy(srm.url("/data/f"), f"file://{local}")
    assert local.read_bytes() == b"hello world\n"
    sctx.filecopy(f"file://{local}", srm.url("/data/back"))
    assert (root / "data" / "back").read_bytes() == b"hello world\n"


def test_copy_checksum_overwrite_parent_spacetokens(
    sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path
) -> None:
    p, events = params(overwrite=True, create_parent=True, src_spacetoken="OTHER")
    p.dst_spacetoken = "ATLASDATADISK"
    p.set_checksum(xgfalclient.checksum_mode.both, "ADLER32", "")
    (root / "data" / "sub" / "c").write_bytes(b"old")
    sctx.filecopy(p, srm.url("/data/f"), srm.url("/data/sub/c"))
    sctx.filecopy(p, srm.url("/data/f"), srm.url("/data/new/dir/c"))
    assert (root / "data" / "new" / "dir" / "c").read_bytes() == b"hello world\n"
    bodies = [body.decode() for op, body in srm.log if op.startswith("srmPrepareTo")]
    assert "<targetSpaceToken>tok2</targetSpaceToken>" in bodies[0]
    assert "<targetSpaceToken>tok1</targetSpaceToken>" in bodies[1]
    assert "OVERWRITE" in events.stages()


def test_copy_failures(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    error = fails(errno.ENOENT, sctx.filecopy, srm.url("/nope"), srm.url("/data/c"))
    assert error.message == (
        "SOURCE SRM_GET_TURL error on the turl  request : [SE][PrepareToGet][SRM_INVALID_PATH] "
        "No such file or directory "
    )
    error = fails(errno.ENOENT, sctx.filecopy, srm.url("/data/f"), srm.url("/no/dir/c"))
    assert error.message.startswith("DESTINATION SRM_PUT_TURL error on the turl  request : ")
    assert srm.operations()[-2:] == ["srmReleaseFiles", "srmRm"]  # released, cleaned up
    p, _ = params(dst_spacetoken="NOPE")
    error = fails(
        xgfalclient.plugins.srm.soap.EBADR, sctx.filecopy, p, srm.url("/data/f"), srm.url("/data/c")
    )
    assert error.message.startswith("DESTINATION SRM_PUT_TURL srm-ifce err: ")


def test_copy_fail_nearline(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    sctx.set_opt_boolean(GROUP, "COPY_FAIL_NEARLINE", True)
    srm.set_locality("/data/f", "NEARLINE")
    error = fails(errno.EINVAL, sctx.filecopy, srm.url("/data/f"), srm.url("/data/c"))
    assert error.message == "SOURCE SRM_GET_TURL The source file is not ONLINE"
    srm.set_locality("/data/f", "ONLINE")
    sctx.filecopy(srm.url("/data/f"), srm.url("/data/c"))


def test_copy_transfer_failure_aborts(
    sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path
) -> None:
    srm.protocols = {"file": f"file://{root}", "gsiftp": "gsiftp://localhost:1"}
    sctx.set_opt_string_list(GROUP, "TURL_3RD_PARTY_PROTOCOLS", ["gsiftp"])
    p, _ = params(timeout=5)
    with pytest.raises(GError):
        sctx.filecopy(p, srm.url("/data/f"), srm.url("/data/c"))
    ops = srm.operations()
    assert "srmAbortRequest" in ops and ops[-2:] == ["srmReleaseFiles", "srmRm"]


def test_copy_putdone_failure(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    srm.inject("srmPutDone", srm.status_reply("srmPutDone", "SRM_FAILURE", "no"))
    error = fails(errno.EIO, sctx.filecopy, srm.url("/data/f"), srm.url("/data/c"))
    assert error.message.startswith("DESTINATION SRM_PUTDONE srm-ifce err: ")
    assert "srmReleaseFiles" in srm.operations()


def test_copy_without_timeout_and_unstatable_source(
    sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path, tmp_path: Path
) -> None:
    p, _ = params(timeout=0)
    sctx.filecopy(p, srm.url("/data/f"), srm.url("/data/c"))
    # a source whose stat fails still gets a PUT, sized 0
    source = srm.url("/data/f")
    srm.inject("srmLs", srm.status_reply("srmLs", "SRM_FAILURE"))
    p, _ = params(strict_copy=True)
    sctx.filecopy(p, source, srm.url("/data/d"))
    put = [body.decode() for op, body in srm.log if op == "srmPrepareToPut"][-1]
    assert "<expectedFileSize>0</expectedFileSize>" in put


def test_copy_monitor(
    sctx: xgfalclient.Gfal2Context, srm: SRMServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("xgfalclient.transfer.MONITOR_INTERVAL", 0.0)
    reports: list[int] = []
    p, _ = params()
    p.monitor_callback = lambda src, dst, avg, inst, done, elapsed: reports.append(done)
    sctx.filecopy(p, srm.url("/data/f"), srm.url("/data/c"))
    assert reports and reports[-1] == 12


def test_copy_check(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    plugin = sctx.plugin(srm.url("/f"), "copy")
    assert plugin.copy_check("srm://a/f", "srm://b/f")
    assert plugin.copy_check("file:///f", "srm://b/f")
    assert not plugin.copy_check("srm://a/f", "davs://b/f")
    assert not plugin.copy_check("file:///a", "file:///b")


def test_https_goes_first_for_https_ends() -> None:
    order = srm_plugin._for_other_end
    assert order(["gsiftp", "root", "https"], "srm://a/f", "https://b/f") == [
        "https",
        "root",
        "gsiftp",
    ]
    assert order(["gsiftp", "https"], "davs://b/f", "srm://a/f") == ["https", "gsiftp"]
    assert order(["gsiftp", "root"], "srm://a/f", "https://b/f") == ["gsiftp", "root"]
    assert order(["gsiftp", "https"], "srm://a/f", "root://b/f") == ["gsiftp", "https"]
