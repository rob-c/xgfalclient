"""The in-process SRM server's own edges, driven with raw requests."""

# The shared fixtures come from test_srm; ruff sees each use as a redefinition.
# ruff: noqa: F811

from __future__ import annotations

import socket
import ssl
from collections.abc import Iterator
from pathlib import Path

import pytest

from test_srm import root  # noqa: F401
from xgfalclient.plugins.srm import soap
from xgfalclient.testing.pki import PKI
from xgfalclient.testing.srm import SRMServer


@pytest.fixture
def server(pki: PKI, root: Path) -> Iterator[SRMServer]:
    srm = SRMServer(pki.server_context(), root)
    yield srm
    srm._server.server_close()


def call(srm: SRMServer, operation: str, fields: soap.Fields) -> soap.Node:
    return soap.parse(srm.dispatch(soap.request(operation, fields)).body)[1]


def code(node: soap.Node) -> str:
    return node.get("returnStatus", "statusCode")


def surls(*urls: str) -> soap.Fields:
    return [("arrayOfSURLs", [("urlArray", url) for url in urls])]


def files(key: str, *urls: str) -> soap.Fields:
    return [("arrayOfFileRequests", [("requestArray", [(key, url)]) for url in urls])]


PROTO: soap.Fields = [
    ("transferParameters", [("arrayOfTransferProtocols", [("stringArray", "file")])])
]


def test_bad_requests(server: SRMServer) -> None:
    reply = server.dispatch(b"junk")
    assert reply.status == 500 and b"Fault" in reply.body
    reply = server.dispatch(soap.request("srmCopy", []))
    assert reply.status == 500 and b"not implemented" in reply.body


def test_bad_surls_everywhere(server: SRMServer) -> None:
    bad = "http://x/y"
    assert (
        call(server, "srmLs", surls(bad)).get("details", "pathDetailArray", "status", "statusCode")
        == "SRM_INVALID_PATH"
    )
    assert code(call(server, "srmMkdir", [("SURL", bad)])) == "SRM_INVALID_PATH"
    assert code(call(server, "srmRmdir", [("SURL", bad)])) == "SRM_INVALID_PATH"
    assert code(call(server, "srmMv", [("fromSURL", bad), ("toSURL", bad)])) == "SRM_INVALID_PATH"
    assert code(call(server, "srmReleaseFiles", surls(bad))) == "SRM_FAILURE"
    got = call(server, "srmPrepareToGet", files("sourceSURL", bad) + PROTO)
    assert (
        got.get("arrayOfFileStatuses", "statusArray", "status", "statusCode") == "SRM_INVALID_PATH"
    )


def test_namespace_edges(server: SRMServer, root: Path) -> None:
    url = server.url
    assert code(call(server, "srmMkdir", [("SURL", url("/no/parent"))])) == "SRM_INVALID_PATH"
    assert code(call(server, "srmRmdir", [("SURL", url("/nope"))])) == "SRM_INVALID_PATH"
    assert code(call(server, "srmRmdir", [("SURL", url("/data/f"))])) == "SRM_INVALID_PATH"
    assert code(call(server, "srmMkdir", [("SURL", url("/data"))])) == "SRM_DUPLICATION_ERROR"
    assert (
        code(call(server, "srmRmdir", [("SURL", url("/data/sub")), ("recursive", True)]))
        == "SRM_SUCCESS"
    )
    assert not (root / "data" / "sub").exists()
    assert (
        code(call(server, "srmMv", [("fromSURL", url("/nope")), ("toSURL", url("/x"))]))
        == "SRM_INVALID_PATH"
    )
    listing = call(server, "srmLs", [*surls(url("/data")), ("offset", 0), ("count", 5000)])
    assert code(listing) == "SRM_TOO_MANY_RESULTS"
    no_levels = soap.request("srmLs", surls(url("/data")))
    assert soap.parse(server.dispatch(no_levels).body)[1].child(
        "details", "pathDetailArray", "arrayOfSubPaths"
    )
    assert (
        code(call(server, "srmStatusOfLsRequest", [("requestToken", "nope")]))
        == "SRM_INVALID_REQUEST"
    )
    perms = call(server, "srmSetPermission", [("SURL", url("/data/f"))])  # nothing to change
    assert code(perms) == "SRM_SUCCESS"


def test_checksums_can_be_left_out(pki: PKI, root: Path) -> None:
    srm = SRMServer(pki.server_context(), root, checksum_type=None)
    try:
        detail = call(srm, "srmLs", surls(srm.url("/data/f"))).child("details", "pathDetailArray")
        assert detail is not None and detail.child("checkSumType") is None
    finally:
        srm._server.server_close()


def test_transfer_edges(server: SRMServer, root: Path) -> None:
    url = server.url
    got = call(server, "srmPrepareToGet", files("sourceSURL", url("/data/sub")) + PROTO)
    assert (
        got.get("arrayOfFileStatuses", "statusArray", "status", "explanation") == "Is a directory"
    )
    bad_space = [*files("sourceSURL", url("/data/f")), ("targetSpaceToken", "nope"), *PROTO]
    assert code(call(server, "srmPrepareToGet", bad_space)) == "SRM_INVALID_REQUEST"
    assert (
        code(call(server, "srmPrepareToPut", files("targetSURL", url("/data/n"))))
        == "SRM_NOT_SUPPORTED"
    )
    assert (
        code(call(server, "srmBringOnline", [("targetSpaceToken", "nope")]))
        == "SRM_INVALID_REQUEST"
    )
    # a second put of a file being written is refused
    first = call(server, "srmPrepareToPut", files("targetSURL", url("/data/n")) + PROTO)
    token = first.get("requestToken")
    busy = call(server, "srmPrepareToPut", files("targetSURL", url("/data/n")) + PROTO)
    assert busy.get("arrayOfFileStatuses", "statusArray", "status", "statusCode") == "SRM_FILE_BUSY"
    get = call(server, "srmPrepareToGet", files("sourceSURL", url("/data/f")) + PROTO)
    other = call(server, "srmPrepareToPut", files("targetSURL", url("/data/m")) + PROTO)
    assert other.get("requestToken")
    # put-done oddities
    get_token = get.get("requestToken")
    pd = call(server, "srmPutDone", [("requestToken", get_token), *surls(url("/data/f"))])
    assert (
        pd.get("arrayOfFileStatuses", "statusArray", "status", "statusCode") == "SRM_INVALID_PATH"
    )
    (root / "data" / "n").write_bytes(b"x")
    assert (
        code(call(server, "srmPutDone", [("requestToken", token), *surls(url("/data/n"))]))
        == "SRM_SUCCESS"
    )
    again = call(server, "srmPutDone", [("requestToken", token), *surls(url("/data/n"))])
    assert "state SRM_SUCCESS" in again.get(
        "arrayOfFileStatuses", "statusArray", "status", "explanation"
    )
    assert (
        code(call(server, "srmPutDone", [("requestToken", "nope"), *surls(url("/data/n"))]))
        == "SRM_INVALID_REQUEST"
    )
    # release and abort oddities
    rel = call(server, "srmReleaseFiles", [("requestToken", get_token), *surls(url("/data/sub/a"))])
    assert "not part" in rel.get("arrayOfFileStatuses", "statusArray", "status", "explanation")
    assert code(call(server, "srmReleaseFiles", surls(url("/data/f")))) == "SRM_SUCCESS"
    ab = call(server, "srmAbortFiles", surls(url("/data/f")))
    assert code(ab) == "SRM_FAILURE"
    written = call(server, "srmPrepareToPut", files("targetSURL", url("/data/w")) + PROTO)
    (root / "data" / "w").write_bytes(b"partial")
    wtoken = written.get("requestToken")
    assert (
        code(call(server, "srmAbortFiles", [("requestToken", wtoken), *surls(url("/data/w"))]))
        == "SRM_SUCCESS"
    )
    assert not (root / "data" / "w").exists()
    unwritten = call(server, "srmPrepareToPut", files("targetSURL", url("/data/v")) + PROTO)
    utoken = unwritten.get("requestToken")
    assert (
        code(call(server, "srmAbortFiles", [("requestToken", utoken), *surls(url("/data/v"))]))
        == "SRM_SUCCESS"
    )
    assert (
        code(call(server, "srmAbortRequest", [("requestToken", "nope")])) == "SRM_INVALID_REQUEST"
    )
    assert (
        code(call(server, "srmStatusOfPutRequest", [("requestToken", get_token)]))
        == "SRM_INVALID_REQUEST"
    )


def test_queued_requests(pki: PKI, root: Path) -> None:
    srm = SRMServer(pki.server_context(), root, queue_polls=2)
    try:
        put = call(srm, "srmPrepareToPut", files("targetSURL", srm.url("/data/q")) + PROTO)
        assert code(put) == "SRM_REQUEST_QUEUED"
        token = put.get("requestToken")
        assert (
            code(call(srm, "srmStatusOfPutRequest", [("requestToken", token)]))
            == "SRM_REQUEST_INPROGRESS"
        )
        assert code(call(srm, "srmAbortRequest", [("requestToken", token)])) == "SRM_SUCCESS"
        after = call(srm, "srmStatusOfPutRequest", [("requestToken", token)])
        assert (
            after.get("arrayOfFileStatuses", "statusArray", "status", "statusCode") == "SRM_ABORTED"
        )
        # an aborted request leaves settled files alone
        assert code(call(srm, "srmAbortRequest", [("requestToken", token)])) == "SRM_SUCCESS"
        srm.queue_polls = 1
        get = call(srm, "srmPrepareToGet", files("sourceSURL", srm.url("/data/f")) + PROTO)
        ready = call(srm, "srmStatusOfGetRequest", [("requestToken", get.get("requestToken"))])
        assert code(ready) == "SRM_SUCCESS"
    finally:
        srm._server.server_close()


def test_space_edges(server: SRMServer) -> None:
    from xgfalclient.testing.srm import Space

    server.spaces["t"] = Space("D")
    got = call(
        server,
        "srmGetSpaceMetaData",
        [("arrayOfSpaceTokens", [("stringArray", "t"), ("stringArray", "x")])],
    )
    assert code(got) == "SRM_PARTIAL_SUCCESS"


# -- the wire ----------------------------------------------------------------------


def _open(srm: SRMServer, pki: PKI, flag: bytes) -> ssl.SSLSocket:
    tls = pki.client_context()
    tls.check_hostname = False
    sock = tls.wrap_socket(socket.create_connection(("localhost", srm.port)))
    sock.sendall(flag)
    return sock


def test_chunked_request_and_bad_flag(server: SRMServer, pki: PKI) -> None:
    with server:
        body = soap.request("srmPing", [])
        sock = _open(server, pki, b"0")
        head = b"POST /srm/managerv2 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        chunks = b"%x;ext\r\n%s\r\n0\r\n\r\n" % (len(body), body)
        sock.sendall(head + chunks)
        reply = sock.recv(65536)
        assert reply.startswith(b"HTTP/1.1 200") and b"versionInfo" in reply + sock.recv(65536)
        sock.close()
        bad = _open(server, pki, b"D")
        assert bad.recv(1) == b""
        bad.close()
        assert server.connections == 1


def test_other_protocols(pki: PKI, root: Path) -> None:
    srm = SRMServer(pki.server_context(), root, protocols={"gsiftp": "gsiftp://mover:2811"})
    try:
        wanted = [
            ("transferParameters", [("arrayOfTransferProtocols", [("stringArray", "gsiftp")])])
        ]
        got = call(srm, "srmPrepareToGet", files("sourceSURL", srm.url("/data/f")) + wanted)
        turl = got.get("arrayOfFileStatuses", "statusArray", "transferURL")
        assert turl == "gsiftp://mover:2811/data/f"
        # file:// is no longer served
        assert code(
            call(srm, "srmPrepareToGet", files("sourceSURL", srm.url("/data/f")) + PROTO)
        ) == ("SRM_NOT_SUPPORTED")
    finally:
        srm._server.server_close()


def test_tokens_of_the_wrong_request(server: SRMServer, root: Path) -> None:
    url = server.url
    get = call(server, "srmPrepareToGet", files("sourceSURL", url("/data/f")) + PROTO)
    get_token = get.get("requestToken")
    # an srmLs status poll for a get request
    assert (
        code(call(server, "srmStatusOfLsRequest", [("requestToken", get_token)]))
        == "SRM_INVALID_REQUEST"
    )
    put = call(server, "srmPrepareToPut", files("targetSURL", url("/data/n")) + PROTO)
    token = put.get("requestToken")
    # put-done without a token, and with a SURL the request does not hold
    pd = call(server, "srmPutDone", surls(url("/data/n")))
    assert "not part" in pd.get("arrayOfFileStatuses", "statusArray", "status", "explanation")
    pd = call(server, "srmPutDone", [("requestToken", token), *surls(url("/data/f"))])
    assert "not part" in pd.get("arrayOfFileStatuses", "statusArray", "status", "explanation")
    # abort a SURL the request does not hold, then the file twice
    ab = call(server, "srmAbortFiles", [("requestToken", token), *surls(url("/data/f"))])
    assert "not part" in ab.get("arrayOfFileStatuses", "statusArray", "status", "explanation")
    for _ in range(2):
        abort = [("requestToken", token), *surls(url("/data/n"))]
        assert code(call(server, "srmAbortFiles", abort)) == "SRM_SUCCESS"
    (root / "data" / "n").write_bytes(b"not the put's")
    abort = [("requestToken", token), *surls(url("/data/n"))]
    assert code(call(server, "srmAbortFiles", abort)) == "SRM_SUCCESS"
    assert (root / "data" / "n").exists()  # an aborted put no longer owns the file
    # an aborted put does not keep the path busy
    (root / "data" / "n").unlink()
    again = call(server, "srmPrepareToPut", files("targetSURL", url("/data/n")) + PROTO)
    assert code(again) == "SRM_SUCCESS"
    # a move to a bad SURL
    move = [("fromSURL", url("/data/f")), ("toSURL", "http://x/y")]
    assert code(call(server, "srmMv", move)) == "SRM_INVALID_PATH"


def test_globus_turn_under_tls12_and_bodyless_requests(pki: PKI, root: Path) -> None:
    srm = SRMServer(pki.server_context(), root, globus_turn=True)
    tls = pki.client_context()
    tls.check_hostname = False
    tls.maximum_version = ssl.TLSVersion.TLSv1_2
    heads = [
        # neither a Content-Length nor chunks: an empty body
        b"POST /srm/managerv2 HTTP/1.1\r\nHost: x\r\n\r\n",
        # a chunk-size line left blank ends the body
        b"POST /srm/managerv2 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\r\n\r\n",
    ]
    with srm:
        for head in heads:
            sock = tls.wrap_socket(socket.create_connection(("localhost", srm.port)))
            sock.sendall(b"0" + head)  # no turn byte comes first under TLS 1.2
            assert sock.recv(65536).startswith(b"HTTP/1.1 500")
            sock.close()
