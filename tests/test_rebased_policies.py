"""Exercise native and compatibility policies in the newly shared engines."""

from __future__ import annotations

import struct
import time
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest
from xrdclient.errors import ProtocolError, ServerError
from xrdclient.errors import TimeoutError as XrdTimeoutError
from xrdclient.proto import constants as c
from xrdclient.proto import requests as r
from xrdclient.session.bulk import BulkReader, BulkUnsupported, _refuse, _WriteReplies
from xrdclient.session.deadline import OperationExpiredError, deadline
from xrdhttp.s3 import codec as _codec
from xrdhttp.s3.sigv4 import Credentials, hash_payload, sign
from xrdsec import der, x509

from test_xrootd import _upload_channel
from xgfalclient.plugins.http import _s3


class Wire:
    def __init__(self) -> None:
        self.answers = bytearray()

    def send_buffers(self, parts: Iterable[bytes | memoryview]) -> None:
        # xrdclient 0.4 sends one request's frame as a vector: the header
        # (with any short body) first, a long write's payload as a view.
        for part in parts:
            self.send(part)

    def send(self, header: bytes | memoryview) -> None:
        if not isinstance(header, memoryview):
            sid = int.from_bytes(header[:2], "big")
            self.answers.extend(struct.pack(">HHI", sid, c.kXR_ok, 0))

    def receive_into(self, view: memoryview) -> int:
        count = min(len(view), len(self.answers))
        view[:count] = self.answers[:count]
        del self.answers[:count]
        return count


def test_bulk_read_and_gather_share_safe_stream_lifetimes() -> None:
    wire = Wire()
    channel, session = _upload_channel(wire.receive_into)
    session.transport.send_buffers = wire.send_buffers
    assert list(channel.stream(0, 8192)) == []
    assert channel.gather([]) == []
    assert channel.gather([(r.Ping(), 0), (r.Ping(), 0)]) == [memoryview(b"")] * 2
    assert not session.broken and not channel._leased


def test_bulk_without_a_stall_budget_still_discards_a_torn_connection() -> None:
    channel, session = _upload_channel(lambda view: 0)
    session.config = session.config.evolve(stall_deadline=0)
    channel._begin()
    channel._check_clocks(0)
    channel._torn = True
    channel.settle()
    assert session.broken


@pytest.mark.parametrize("chunk", [0, c.MAX_RESPONSE_BODY + 1])
def test_bulk_bounds_are_checked_before_a_session_is_borrowed(chunk: int) -> None:
    _, session = _upload_channel(lambda view: 0)
    with pytest.raises(ValueError, match="chunk must be"):
        BulkReader(session, bytes(4), chunk=chunk, depth=1)


@pytest.mark.parametrize("stall", [False, True])
def test_bulk_deadlines_retire_ids_but_stalls_break_connections(stall: bool) -> None:
    channel, session = _upload_channel(lambda view: 0)
    session.config = session.config.evolve(stall_deadline=0)
    with deadline(0 if not stall else 3600):
        channel._begin()
        channel._owed.add(channel._leased[0])
        if stall:
            channel._expires = time.monotonic() - 1
        expected = XrdTimeoutError if stall else OperationExpiredError
        with pytest.raises(expected):
            channel._check_clocks(8)
        if stall:
            channel._torn = True
        channel.settle()
    assert session.broken == stall


def test_a_cancelled_bulk_read_finishes_its_frame_then_retires_its_ids() -> None:
    # The plugin stops a transfer by aborting its handles (a hook xrdclient
    # watches); a cancel *scope* is xrdclient.aio's way, which no plugin call
    # installs. It is the same reader underneath, so its policy is held here,
    # beside the deadline's: part-way through a frame a cancelled reader
    # finishes it within the grace, between frames it stops, and what is
    # still owed is left to the machine to drop - the connection is kept.
    from xrdcore import cancel as _cancel

    channel, session = _upload_channel(lambda view: 0)
    scope = _cancel.CancelScope()
    scope.cancel()

    def cancelled_read() -> None:
        channel._begin()
        channel._owed.add(channel._leased[0])
        channel._torn = True
        channel._check_clocks(8)  # inside the grace: the frame is finished
        channel._torn = False
        with pytest.raises(_cancel.Cancelled):
            channel._check_clocks(8)
        channel.settle()

    _cancel.within(scope, cancelled_read)
    assert not session.broken and not channel._leased


def test_default_wait_policy_and_short_server_errors_are_not_successes() -> None:
    channel, _ = _upload_channel(lambda view: 0)
    reply = SimpleNamespace(status=c.kXR_wait)
    count, error = channel._write_answer(reply, bytearray(), (0, 1), _WriteReplies())
    assert count == 0 and isinstance(error, BulkUnsupported)
    # A kXR_error too short to carry its code is a malformed reply, and one
    # whose code is 0 is still a refusal: neither may read as a success.
    # (xrdclient 0.4 parses bulk errors exactly as the event path does.)
    with pytest.raises(ProtocolError, match="truncated"):
        _refuse(c.kXR_error, bytearray())
    with pytest.raises(ServerError, match="XRootD error 0"):
        _refuse(c.kXR_error, bytearray(4))


def test_empty_legacy_extensions_are_skipped() -> None:
    extension = der.parse_one(der.explicit(3, der.sequence(der.sequence())))
    assert x509.tbs_extensions([extension]) == {}


def test_s3_modeled_empty_fields_and_headers_keep_both_facade_policies() -> None:
    body = b"<ListBucketResult><Contents><Size/></Contents></ListBucketResult>"
    for lenient in (False, True):
        answer = _codec.decode("ListObjectsV2", body, lenient=lenient)
        assert answer["Contents"][0]["Size"] == 0
    with pytest.raises(ET.ParseError):
        _codec.decode("ListObjectsV2", b"")
    assert (
        _codec.decode("CopyObject", b"", headers={"x-amz-request-id": "test"})["ResponseMetadata"][
            "RequestId"
        ]
        == "test"
    )


def test_compatibility_listing_adapter_does_not_return_empty_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_s3, "listing_items", lambda *args: iter([("/", None)]))
    assert list(_s3._entries({}, "")) == []


@pytest.mark.parametrize("access,secret", [("", ""), ("id", ""), ("id", "secret")])
def test_shared_s3_credentials_keep_environment_precedence(
    monkeypatch: pytest.MonkeyPatch, access: str, secret: str
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", access)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", secret)
    monkeypatch.setenv("AWS_SESSION_TOKEN", "token")
    fallback = Credentials("file-id", "file-secret")
    monkeypatch.setattr(Credentials, "from_file", classmethod(lambda cls: fallback))
    found = Credentials.from_env()
    assert found == (Credentials(access, secret, "token") if access and secret else None)
    assert Credentials.discover() == (found or fallback)
    assert "secret_key=<redacted>" in repr(fallback)
    assert "session_token=<redacted>" in repr(Credentials("id", "secret", "token"))


@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize(
    "fields", ["", "aws_access_key_id=id", "aws_access_key_id=id\naws_secret_access_key=secret"]
)
def test_shared_s3_file_profiles_ignore_incomplete_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, explicit: bool, fields: str
) -> None:
    path = tmp_path / "credentials"
    path.write_text(f"[test]\n{fields}\n")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(path))
    monkeypatch.setenv("AWS_PROFILE", "test")
    found = Credentials.from_file(str(path), "test") if explicit else Credentials.from_file()
    assert found == (Credentials("id", "secret") if "aws_secret_access_key" in fields else None)


@pytest.mark.parametrize("token", ["", "temporary-token"])
@pytest.mark.parametrize("target", ["", "/data"])
def test_native_signing_preserves_empty_target_and_session_tokens(token: str, target: str) -> None:
    signed = sign(
        "GET",
        target,
        "example.test",
        {},
        hash_payload(None),
        credentials=Credentials("id", "secret", token),
        region="us-east-1",
    )
    assert signed["Authorization"].startswith("AWS4-HMAC-SHA256 ")
    assert signed.get("x-amz-security-token", "") == token
