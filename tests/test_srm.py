"""The ``srm://`` plugin against the in-process SRM server."""

from __future__ import annotations

import errno
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from xgfalclient.errors import GError
from xgfalclient.plugins.srm import client as srm_client
from xgfalclient.testing.pki import PKI
from xgfalclient.testing.srm import Space, SRMServer

GROUP = "SRM PLUGIN"


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(srm_client, "POLL_INITIAL", 0.001)


@pytest.fixture(autouse=True)
def _no_bdii() -> None:
    """A short SURL would have the BDII (lcg-bdii.cern.ch by default) asked for its
    service: switch it off, as a site without one does. test_bdii.py covers it."""
    Path(os.environ["GFAL_CONFIG_DIR"], "bdii.conf").write_text("[BDII]\nENABLED=false\n")


@pytest.fixture
def root(tmp_path: Path) -> Path:
    base = tmp_path / "root"
    (base / "data" / "sub").mkdir(parents=True)
    (base / "data" / "f").write_bytes(b"hello world\n")
    (base / "data" / "sub" / "a").write_bytes(b"a")
    return base


@pytest.fixture
def srm(grid_env: PKI, root: Path) -> Iterator[SRMServer]:
    server = SRMServer(grid_env.server_context(), root)
    server.spaces["tok1"] = Space("ATLASDATADISK")
    server.spaces["tok2"] = Space("OTHER", retention="CUSTODIAL", latency="NEARLINE")
    with server:
        yield server


@pytest.fixture
def sctx(ctx: xgfalclient.Gfal2Context) -> xgfalclient.Gfal2Context:
    ctx.set_opt_string_list(GROUP, "TURL_PROTOCOLS", ["file"])
    ctx.set_opt_string_list(GROUP, "TURL_3RD_PARTY_PROTOCOLS", ["file"])
    return ctx


def fails(code: int, function: object, *args: object) -> GError:
    with pytest.raises(GError) as caught:
        function(*args)  # type: ignore[operator]
    assert caught.value.code == code, caught.value
    return caught.value


# -- namespace -----------------------------------------------------------------------


def test_stat(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    info = sctx.stat(srm.url("/data/f"))
    assert info.st_size == 12 and info.is_file() and info.st_mode & 0o777 == 0o644
    assert info.st_nlink == 1 and info.st_atime == 0 and info.st_mtime > 0
    assert sctx.stat(srm.full_url("/data/sub")).is_dir()
    body = srm.log[0][1].decode()
    assert "<urlArray>srm://localhost/data/f</urlArray>" in body
    assert '<storageSystemInfo xsi:nil="true"/>' in body
    headers = srm.headers[0]
    assert headers["SOAPAction"] == '"Ls"' and headers["Connection"] == "keep-alive"
    assert srm.connections == 1  # the session is reused


def test_stat_missing(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    error = fails(errno.ENOENT, sctx.stat, srm.url("/nope"))
    assert error.message == (
        "Error reported from srm_ifce : 2 [SE][Ls][SRM_INVALID_PATH] No such file or directory"
    )


def test_bare_scheme_is_nobodys(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    plugin = sctx.plugin(srm.url("/f"), "stat")
    assert plugin.handles("SRM://h/f", "stat")
    assert not plugin.handles("srm://", "stat") and not plugin.handles("file:///f", "stat")
    fails(errno.EPROTONOSUPPORT, sctx.stat, "srm://")


def test_listdir_and_opendir(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    assert sctx.listdir(srm.url("/data")) == ["f", "sub"]
    entries = [(entry.d_name, info.st_size) for entry, info in _readpp(sctx, srm.url("/data"))]
    assert entries == [("f", 12), ("sub", 0)]
    error = fails(errno.ENOTDIR, sctx.listdir, srm.url("/data/f"))
    assert error.message == (
        "srm-plugin: srm://localhost/data/f is not a directory, impossible to list content"
    )
    fails(errno.ENOENT, sctx.listdir, srm.url("/nope"))


def _readpp(ctx: xgfalclient.Gfal2Context, url: str) -> list[tuple[object, object]]:
    handle = ctx.opendir(url)
    return list(iter(handle.readpp, (None, None)))


def test_listing_in_chunks(
    sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from xgfalclient.plugins.srm import plugin

    for name in "abcde":
        (root / "data" / "sub" / name).write_bytes(b"x")
    monkeypatch.setattr(plugin, "LS_CHUNK", 2)
    srm.max_ls = 2
    assert sctx.listdir(srm.url("/data/sub")) == ["a", "b", "c", "d", "e"]
    bodies = [body.decode() for op, body in srm.log if op == "srmLs"]
    assert "<count>2</count>" in bodies[1] and "<offset>" not in bodies[1]
    assert "<offset>4</offset>" in bodies[-1]
    (root / "data" / "sub" / "f").write_bytes(b"x")
    assert len(sctx.listdir(srm.url("/data/sub"))) == 6  # the last page is short
    srm.max_ls = 1
    error = fails(errno.EFBIG, sctx.listdir, srm.url("/data/sub"))
    assert error.message.startswith("Failed when attempting chunk listingError reported")


def test_queued_ls(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    srm.ls_queue_polls = 2
    assert sctx.stat(srm.url("/data/f")).st_size == 12
    assert srm.operations() == ["srmLs", "srmStatusOfLsRequest", "srmStatusOfLsRequest"]
    assert srm.status_reply("srmLs", "SRM_SUCCESS")  # helper is usable directly


def test_mkdir(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    error = fails(errno.EEXIST, sctx.mkdir, srm.url("/data"), 0o755)
    assert error.message == "directory already exist"
    sctx.mkdir(srm.url("/data/x/y"), 0o755)  # gfal2's srm mkdir makes parents
    assert (root / "data" / "x" / "y").is_dir()
    assert srm.operations()[-3:] == ["srmMkdir", "srmMkdir", "srmMkdir"]
    sctx.mkdir_rec(srm.url("/data/a/b/c"), 0o755)
    assert (root / "data" / "a" / "b" / "c").is_dir()
    sctx.mkdir_rec(srm.url("/data/a/b/c"), 0o755)
    error = fails(errno.ENOTDIR, sctx.mkdir_rec, srm.url("/data/f"), 0o755)
    assert error.message.endswith("/data/f it is a file")


def test_mkdir_failures(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    srm.inject("srmMkdir", srm.status_reply("srmMkdir", "SRM_AUTHORIZATION_FAILURE", "no"))
    error = fails(errno.EACCES, sctx.mkdir, srm.url("/data/new"), 0o755)
    assert error.message.endswith(f"[SE][Mkdir][SRM_AUTHORIZATION_FAILURE] {srm.endpoint}: no\n")
    srm.inject("srmMkdir", srm.status_reply("srmMkdir", "SRM_INVALID_PATH"), times=5)
    fails(errno.ENOENT, sctx.mkdir, srm.url("/q"), 0o755)  # up to a missing root: give up
    srm.inject("srmLs", srm.status_reply("srmLs", "SRM_AUTHORIZATION_FAILURE", "no"))
    fails(errno.EACCES, sctx.mkdir, srm.url("/data/new"), 0o755)


def test_rmdir(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    error = fails(errno.ENOTEMPTY, sctx.rmdir, srm.url("/data/sub"))
    assert error.message == "Error report from the srm_ifce Directory not empty "
    error = fails(errno.ENOTDIR, sctx.rmdir, srm.url("/data/f"))
    assert error.message == "This file is not a directory, impossible to use rmdir on it"
    (root / "data" / "empty").mkdir()
    sctx.rmdir(srm.url("/data/empty"))
    assert not (root / "data" / "empty").exists()
    srm.inject("srmRmdir", srm.status_reply("srmRmdir", "SRM_CUSTOM_STATUS"))
    fails(errno.EINVAL, sctx.rmdir, srm.url("/data/sub"))


def test_unlink(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    sctx.unlink(srm.url("/data/f"))
    assert not (root / "data" / "f").exists()
    error = fails(errno.ENOENT, sctx.unlink, srm.url("/nope"))
    assert error.message == (
        "error reported from srm_ifce, [SE][srmRm][SRM_INVALID_PATH] No such file or directory"
    )
    fails(errno.ENOENT, sctx.unlink, srm.url("/data/sub"))  # "Not a file"


def test_unlink_bestman_einval(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    from xgfalclient.plugins.srm import soap

    reply = soap.response(
        "srmRm",
        [
            ("returnStatus", [("statusCode", "SRM_FAILURE")]),
            (
                "arrayOfFileStatuses",
                [
                    (
                        "statusArray",
                        [
                            ("surl", "srm://localhost/x"),
                            ("status", [("statusCode", "SRM_FAILURE_X")]),
                        ],
                    )
                ],
            ),
        ],
    )
    srm.inject("srmRm", reply)
    fails(errno.ENOENT, sctx.unlink, srm.url("/x"))


def test_unlink_bulk(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    (root / "data" / "g").write_bytes(b"g")
    results = sctx.unlink([srm.url("/data/g"), srm.url("/nope"), "srm:///bad", srm.url("/data/f")])
    assert isinstance(results, list)
    assert results[0] is None and results[3] is None
    assert results[1] is not None and results[1].code == errno.ENOENT
    assert results[2] is not None and results[2].code == errno.EINVAL
    assert srm.operations() == ["srmRm"]  # one request for the endpoint
    srm.inject("srmRm", srm.status_reply("srmRm", "SRM_AUTHORIZATION_FAILURE"))
    results = sctx.unlink([srm.url("/a"), srm.url("/b")])
    assert [result.code for result in results if result is not None] == [errno.EACCES] * 2
    srm.inject("srmRm", srm.status_reply("srmRm", "SRM_SUCCESS"))
    assert sctx.unlink([srm.url("/data/sub/a")]) == [None]


def test_rename_and_chmod(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    sctx.rename(srm.url("/data/f"), srm.url("/data/g"))
    assert (root / "data" / "g").exists()
    error = fails(errno.ENOENT, sctx.rename, srm.url("/data/f"), srm.url("/data/h"))
    assert error.message == (
        "srm-ifce err: No such file or directory, err: [SE][Mv][SRM_INVALID_PATH] "
        f"{srm.endpoint}: No such file or directory\n"
    )
    fails(errno.EEXIST, sctx.rename, srm.url("/data/g"), srm.url("/data/sub"))
    fails(errno.ENOENT, sctx.rename, srm.url("/data/g"), srm.url("/no/where"))
    sctx.chmod(srm.url("/data/g"), 0o640)
    assert (root / "data" / "g").stat().st_mode & 0o777 == 0o640
    body = srm.log[-1][1].decode()
    assert "<ownerPermission>RW</ownerPermission><otherPermission>NONE</otherPermission>" in body
    fails(errno.ENOENT, sctx.chmod, srm.url("/nope"), 0o600)


def test_simple_calls_with_odd_statuses(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    from xgfalclient.errors import ECOMM

    srm.inject("srmMv", srm.status_reply("srmMv", "SRM_PARTIAL_SUCCESS"))
    error = fails(ECOMM, sctx.rename, srm.url("/a"), srm.url("/b"))
    assert error.message.endswith(
        f"[SE][Mv][SRM_PARTIAL_SUCCESS] {srm.endpoint}: <empty response>\n"
    )
    srm.inject("srmMv", srm.status_reply("srmMv", "SRM_FILE_LOST"))
    fails(errno.EIDRM, sctx.rename, srm.url("/a"), srm.url("/b"))


def test_access(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    sctx.access(srm.url("/data/f"), os.R_OK | os.W_OK)
    error = fails(errno.EACCES, sctx.access, srm.url("/data/f"), os.X_OK)
    assert error.message == (
        "Error 13 : Permission denied , file srm://localhost/data/f: "
        "[SE][CheckPermission][SRM_SUCCESS] <none>"
    )
    error = fails(errno.ENOENT, sctx.access, srm.url("/nope"), os.F_OK)
    assert error.message.startswith("Error 2 : ") and "SRM_INVALID_PATH" in error.message
    srm.inject("srmCheckPermission", srm.status_reply("srmCheckPermission", "SRM_SUCCESS"))
    fails(xgfalclient.errors.ECOMM, sctx.access, srm.url("/data/f"), os.F_OK)
    srm.inject("srmCheckPermission", srm.status_reply("srmCheckPermission", "SRM_FAILURE"))
    fails(errno.EIO, sctx.access, srm.url("/data/f"), os.F_OK)


# -- metadata ------------------------------------------------------------------------


def test_checksum(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    assert sctx.checksum(srm.url("/data/f"), "ADLER32") == "1e720467"
    assert srm.operations() == ["srmLs"]
    assert sctx.checksum(srm.url("/data/f"), "md5") == "6f5902ac237024bdd0c176cb93063dc4"
    assert srm.operations()[1:] == ["srmLs", "srmPrepareToGet", "srmReleaseFiles"]
    assert sctx.checksum(srm.url("/data/f"), "adler32", 0, 5)
    assert sctx.checksum(srm.url("/data/f"), "md5", 6, 0) == "591785b794601e212b260e25925636fd"
    fails(errno.ENOENT, sctx.checksum, srm.url("/nope"), "adler32")


def test_checksum_the_server_does_not_keep(
    sctx: xgfalclient.Gfal2Context, grid_env: PKI, root: Path
) -> None:
    with SRMServer(grid_env.server_context(), root, checksum_type=None) as server:
        assert sctx.checksum(server.url("/data/f"), "adler32") == "1e720467"
        assert server.operations() == ["srmLs", "srmPrepareToGet", "srmReleaseFiles"]


def test_xattrs(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    url = srm.url("/data/f")
    assert sctx.listxattr(url) == ["user.replicas", "user.status", "srm.type", "spacetoken"]
    assert sctx.getxattr(url, "user.replicas") == f"file://{root}/data/f"
    assert sctx.getxattr(url, "user.status") == "ONLINE"
    assert sctx.getxattr(srm.url("/data"), "user.status") == "NONE"
    srm.set_locality("/data/f", "WEIRD")
    assert sctx.getxattr(url, "user.status") == "UNKNOWN"
    assert sctx.getxattr(url, "srm.type") == "xgfal"
    srm.backend = ""
    error = fails(errno.ENODATA, sctx.getxattr, url, "srm.type")
    assert error.message == "Could not get the storage type"
    error = fails(errno.ENODATA, sctx.getxattr, url, "user.foo")
    assert error.message == "not an existing extended attribute"


def test_space_xattrs(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    url = srm.url("/data/f")
    assert sctx.getxattr(url, "spacetoken") == '["tok1","tok2"]'
    one = (
        '{ "spacetoken": "tok2", "owner": "xgfal", "totalsize": 1099511627776, '
        '"unusedsize": 549755813888, "usedsize": 0, "guaranteedsize": 1099511627776, '
        '"lifetimeassigned": -1, "lifetimeleft": -1, "retention": "CUSTODIAL", '
        '"accesslatency": "NEARLINE" }'
    )
    assert sctx.getxattr(url, "spacetoken.token?tok2") == one
    srm.spaces["tok3"] = Space("OTHER")
    listed = sctx.getxattr(url, "spacetoken.description?OTHER")
    assert listed.startswith("[" + one + ",{ ") and listed.endswith("}]")
    error = fails(
        xgfalclient.plugins.srm.soap.EBADR, sctx.getxattr, url, "spacetoken.description?NO"
    )
    assert "No such space token descriptor" in error.message
    fails(errno.EIO, sctx.getxattr, url, "spacetoken.token?nope")
    error = fails(errno.ENODATA, sctx.getxattr, url, "spacetoken.bogus")
    assert error.message == "Unknown space token attribute bogus"
    error = fails(errno.ENODATA, sctx.getxattr, url, "spacetoken.bogus?tok1")
    assert error.message == "Unknown space token attribute bogus?tok1"
    # gfal2 sends every "spacetoken..." name to its space code, and words it so.
    for name in ("spacetoken?x", "spacetokenX"):
        error = fails(errno.ENODATA, sctx.getxattr, url, name)
        assert error.message == f"Unknown space token attribute {name}"
    assert sctx.getxattr(url, "spacetoken.") == '["tok1","tok2","tok3"]'


def test_space_without_sizes(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    from xgfalclient.plugins.srm import soap

    bare = [("spaceToken", "tok1"), ("status", [("statusCode", "SRM_SUCCESS")])]
    reply = soap.response(
        "srmGetSpaceMetaData",
        [
            ("returnStatus", [("statusCode", "SRM_SUCCESS")]),
            ("arrayOfSpaceDetails", [("spaceDataArray", bare)]),
        ],
    )
    srm.inject("srmGetSpaceMetaData", reply)
    got = sctx.getxattr(srm.url("/data/f"), "spacetoken.token?tok1")
    assert '"totalsize": 0, "unusedsize": 0, "usedsize": 0, "guaranteedsize": 0' in got
    assert '"lifetimeassigned": 0, "lifetimeleft": 0' in got


def test_xattr_fail_nearline(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    sctx.set_opt_boolean(GROUP, "XATTR_FAIL_NEARLINE", True)
    srm.set_locality("/data/f", "NEARLINE")
    error = fails(errno.EINVAL, sctx.getxattr, srm.url("/data/f"), "user.replicas")
    assert error.message == "The source file is not ONLINE"
    srm.set_locality("/data/f", "ONLINE_AND_NEARLINE")
    assert sctx.getxattr(srm.url("/data/f"), "user.replicas").startswith("file://")
    # Only NEARLINE is refused: gfal2 compares with it exactly.
    srm.set_locality("/data/f", "NONE")
    assert sctx.getxattr(srm.url("/data/f"), "user.replicas").startswith("file://")
    srm.set_locality("/data/f", "LOST")
    error = fails(errno.EIDRM, sctx.getxattr, srm.url("/data/f"), "user.replicas")
    assert "[PrepareToGet][SRM_FILE_LOST]" in error.message
    fails(errno.ENOENT, sctx.getxattr, srm.url("/nope"), "user.replicas")


def test_percent_encoded_surls(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    (root / "data" / "sp ace").write_bytes(b"12")
    assert sctx.stat(srm.url("/data/sp%20ace")).st_size == 2
    assert "<urlArray>srm://localhost/data/sp ace</urlArray>" in srm.log[-1][1].decode()
    assert sctx.stat(srm.full_url("/data/sp%20ace")).st_size == 2


def test_spacetokendesc_for_every_request(
    sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path
) -> None:
    """gfal2 asks for ``SPACETOKENDESC``'s space on opens, replicas and checksum TURLs."""
    sctx.set_opt_string(GROUP, "SPACETOKENDESC", "ATLASDATADISK")
    with sctx.open(srm.url("/data/w"), "w") as handle:
        handle.write("x")
    with sctx.open(srm.url("/data/f"), "r") as handle:
        handle.read(1)
    sctx.getxattr(srm.url("/data/f"), "user.replicas")
    srm.checksum_type = None  # the checksum comes from a TURL
    sctx.checksum(srm.url("/data/f"), "ADLER32")
    bodies = [body.decode() for op, body in srm.log if op.startswith("srmPrepareTo")]
    assert len(bodies) == 4
    assert all("<targetSpaceToken>tok1</targetSpaceToken>" in body for body in bodies)


def test_identity_headers(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    sctx.stat(srm.url("/data/f"))
    assert srm.headers[-1]["User-Agent"].endswith(" srm-ifce/1.24.8 gSOAP/2.8")
    assert "ClientInfo" not in srm.headers[-1]
    sctx.set_user_agent("myagent", "9.9")
    sctx.add_client_info("job", "42")
    sctx.stat(srm.url("/data/f"))
    agent = srm.headers[-1]["User-Agent"]
    assert agent.startswith("myagent/9.9 ") and agent.endswith(" srm-ifce/1.24.8 gSOAP/2.8")
    assert srm.headers[-1]["ClientInfo"] == "job=42"


# -- I/O -----------------------------------------------------------------------------


def test_read(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    with sctx.open(srm.url("/data/f"), "r") as handle:
        assert handle.read(5) == "hello"
        assert handle.pread_bytes(6, 5) == b"world"
        buffer = bytearray(3)
        assert handle.readinto(buffer) == 3 and buffer == b" wo"
        assert handle.lseek(0, os.SEEK_END) == 12
    assert srm.operations() == ["srmPrepareToGet", "srmReleaseFiles"]
    assert srm.released == ["/data/f"]
    body = srm.log[0][1].decode()
    assert "<desiredFileStorageType>PERMANENT</desiredFileStorageType>" in body
    assert "<desiredTotalRequestTime>3600</desiredTotalRequestTime>" in body
    assert "<stringArray>file</stringArray>" in body


def test_read_failures(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    error = fails(errno.ENOENT, sctx.open, srm.url("/data/nope"), "r")
    assert error.message == (
        "error on the turl request : [SE][PrepareToGet][SRM_INVALID_PATH] "
        "No such file or directory "
    )
    srm.set_locality("/data/f", "LOST")
    fails(errno.EIDRM, sctx.open, srm.url("/data/f"), "r")
    srm.set_locality("/data/f", "UNAVAILABLE")
    fails(errno.EBUSY, sctx.open, srm.url("/data/f"), "r")
    srm.set_locality("/data/f", "ONLINE")
    sctx.set_opt_string_list(GROUP, "TURL_PROTOCOLS", ["gsiftp"])
    error = fails(errno.EOPNOTSUPP, sctx.open, srm.url("/data/f"), "r")
    assert "SRM_NOT_SUPPORTED" in error.message


def test_read_turl_that_cannot_open(
    sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path
) -> None:
    srm.protocols = {"file": "file:///no/such/dir"}
    fails(errno.ENOENT, sctx.open, srm.url("/data/f"), "r")
    assert srm.operations()[-1] == "srmReleaseFiles"


def test_unrequested_protocol(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    srm.protocols = {"file": "gsiftp://elsewhere"}
    error = fails(errno.EPROTONOSUPPORT, sctx.open, srm.url("/data/f"), "r")
    assert error.message.startswith("The SRM endpoint returned a protocol that wasn't requested")


def test_write(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    with sctx.open(srm.url("/data/new"), "w") as handle:
        handle.write("abc")
        handle.pwrite(b"d", 3)
    assert (root / "data" / "new").read_bytes() == b"abcd"
    assert srm.operations() == ["srmPrepareToPut", "srmPutDone"]
    assert "<expectedFileSize>0</expectedFileSize>" in srm.log[0][1].decode()
    error = fails(errno.EEXIST, sctx.open, srm.url("/data/f"), "w")
    assert error.message == (
        "error on the turl request : [SE][PrepareToPut][SRM_DUPLICATION_ERROR] The file exists "
    )


def test_write_with_a_size(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    plugin = sctx.plugin(srm.url("/data/new"), "open")
    handle = plugin.open(srm.url("/data/new"), os.O_WRONLY | os.O_CREAT, 0o644, 3)
    handle.write(b"abc")
    handle.close()
    assert "<expectedFileSize>3</expectedFileSize>" in srm.log[0][1].decode()
    assert (root / "data" / "new").read_bytes() == b"abc"


def test_write_failures(sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path) -> None:
    handle = sctx.open(srm.url("/data/new"), "w")
    inner = handle._file.inner  # type: ignore[attr-defined]
    inner.close()  # the TURL goes away under us
    fails(errno.EINVAL, handle.write, "x")  # the file plugin's ValueError, as the context maps it
    handle.close()
    assert srm.operations()[-1] == "srmAbortRequest"
    # putdone refused
    handle = sctx.open(srm.url("/data/new2"), "w")
    srm.inject("srmPutDone", srm.status_reply("srmPutDone", "SRM_FAILURE", "nope"))
    error = fails(errno.EIO, handle.close)
    assert error.message.startswith("srm-ifce err")


def test_write_close_error_and_putdone_file_error(
    sctx: xgfalclient.Gfal2Context, srm: SRMServer, root: Path
) -> None:
    handle = sctx.open(srm.url("/data/new"), "w")
    (root / "data" / "new").unlink()  # the upload vanished before PutDone
    error = fails(errno.ENOENT, handle.close)
    assert error.message.startswith("Error on the surl srm://localhost/data/new while putdone : ")
    srm.protocols = {"file": "file:///no/such/dir"}
    fails(errno.ENOENT, sctx.open, srm.url("/data/new3"), "w")
    assert srm.operations()[-1] == "srmAbortRequest"


# -- odd replies ---------------------------------------------------------------------


def test_queued_without_a_token(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    srm.inject("srmPrepareToGet", srm.status_reply("srmPrepareToGet", "SRM_REQUEST_QUEUED"))
    fails(errno.EAGAIN, sctx.open, srm.url("/data/f"), "r")


def test_timeout_with_failing_abort(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    sctx.set_opt_integer(GROUP, "OPERATION_TIMEOUT", 1)
    srm.queue_polls = 10**6
    srm.inject("srmAbortRequest", srm.status_reply("srmAbortRequest", "SRM_FAILURE"))
    fails(errno.ETIMEDOUT, sctx.open, srm.url("/data/f"), "r")


def test_request_status_missing(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    from xgfalclient.plugins.srm import soap

    srm.inject("srmMkdir", soap.response("srmMkdir", []))
    error = fails(errno.EIO, sctx.mkdir, srm.url("/data/d"))
    assert error.message.endswith(
        f"[SE][Mkdir][SRM_FAILURE] {srm.endpoint}: the server returned no status\n"
    )
    # a status without a code is a failure too
    no_code = soap.response("srmMkdir", [("returnStatus", [("explanation", "who knows")])])
    srm.inject("srmMkdir", no_code)
    error = fails(errno.EIO, sctx.mkdir, srm.url("/data/d"))
    assert error.message.endswith(f"[SE][Mkdir][SRM_FAILURE] {srm.endpoint}: who knows\n")


def test_ls_success_without_details(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    srm.inject("srmLs", srm.status_reply("srmLs", "SRM_SUCCESS"))
    error = fails(xgfalclient.errors.ECOMM, sctx.stat, srm.url("/data/f"))
    assert error.message.endswith(f"[SE][Ls][SRM_SUCCESS] {srm.endpoint}: <empty response>\n")


def test_space_description_without_tokens(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    srm.inject("srmGetSpaceTokens", srm.status_reply("srmGetSpaceTokens", "SRM_SUCCESS"))
    params = sctx.transfer_parameters()
    params.dst_spacetoken = "ATLASDATADISK"
    error = fails(errno.EINVAL, sctx.filecopy, params, srm.url("/data/f"), srm.url("/data/c"))
    assert error.message.endswith("no valid space tokens\n")


def test_ready_without_a_turl(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    from xgfalclient.plugins.srm import soap

    reply = soap.response(
        "srmPrepareToGet",
        [
            ("returnStatus", [("statusCode", "SRM_SUCCESS")]),
            ("requestToken", "t"),
            (
                "arrayOfFileStatuses",
                [
                    (
                        "statusArray",
                        [
                            ("sourceSURL", "srm://localhost/data/f"),
                            ("status", [("statusCode", "SRM_FILE_PINNED")]),
                        ],
                    )
                ],
            ),
        ],
    )
    srm.inject("srmPrepareToGet", reply)
    error = fails(errno.EIO, sctx.open, srm.url("/data/f"), "r")
    assert "the server returned no transfer URL" in error.message


def test_file_handle_extras(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    plugin = sctx.plugin(srm.url("/data/f"), "open")
    handle = plugin.open(srm.url("/data/f"), os.O_RDONLY)
    assert handle.size() == 12
    srm.inject("srmReleaseFiles", srm.status_reply("srmReleaseFiles", "SRM_FAILURE"))
    handle.close()  # a failed release is only logged
    handle.close()
