"""Exercise native and compatibility policies in the newly shared engines."""

from __future__ import annotations

import struct
import time
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest
from xrdclient.crypto import der, x509
from xrdclient.errors import TimeoutError as XrdTimeoutError
from xrdclient.proto import constants as c
from xrdclient.proto import requests as r
from xrdclient.s3 import _codec
from xrdclient.s3.sigv4 import Credentials, hash_payload, sign
from xrdclient.session.bulk import BulkReader, BulkUnsupported, _refuse
from xrdclient.session.deadline import OperationExpiredError, deadline

from test_xrootd import _upload_channel
from xgfalclient.plugins.http import _s3


class Wire:
    def __init__(self):
        self.answers = bytearray()

    def send(self, header):
        if not isinstance(header, memoryview):
            sid = int.from_bytes(header[:2], "big")
            self.answers.extend(struct.pack(">HHI", sid, c.kXR_ok, 0))

    def receive_into(self, view):
        count = min(len(view), len(self.answers))
        view[:count] = self.answers[:count]
        del self.answers[:count]
        return count


def test_bulk_read_and_gather_share_safe_stream_lifetimes():
    wire = Wire()
    channel, session = _upload_channel(wire.receive_into)
    session.transport.send = wire.send
    assert list(channel.stream(0, 8192)) == []
    assert channel.gather([]) == []
    assert channel.gather([(r.Ping(), 0), (r.Ping(), 0)]) == [memoryview(b"")] * 2
    assert not session.broken and not channel._leased


def test_bulk_without_a_stall_budget_still_discards_a_torn_connection():
    channel, session = _upload_channel(lambda view: 0)
    session.config = session.config.evolve(stall_deadline=0)
    channel._begin()
    channel._check_clocks(0)
    channel._torn = True
    channel.settle()
    assert session.broken


@pytest.mark.parametrize("chunk", [0, c.MAX_RESPONSE_BODY + 1])
def test_bulk_bounds_are_checked_before_a_session_is_borrowed(chunk):
    _, session = _upload_channel(lambda view: 0)
    with pytest.raises(ValueError, match="chunk must be"):
        BulkReader(session, bytes(4), chunk=chunk, depth=1)


@pytest.mark.parametrize("stall", [False, True])
def test_bulk_deadlines_retire_ids_but_stalls_break_connections(stall):
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


def test_default_wait_policy_and_short_server_errors_are_not_successes():
    channel, _ = _upload_channel(lambda view: 0)
    reply = SimpleNamespace(status=c.kXR_wait)
    count, error = channel._write_answer(reply, bytearray(), (0, 1), None, None, False)
    assert count == 0 and isinstance(error, BulkUnsupported)
    with pytest.raises(Exception, match="error code 0"):
        _refuse(c.kXR_error, bytearray())


def test_empty_legacy_extensions_are_skipped():
    extension = der.parse_one(der.explicit(3, der.sequence(der.sequence())))
    assert x509._extensions([extension]) == {}


def test_s3_modeled_empty_fields_and_headers_keep_both_facade_policies():
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


def test_compatibility_listing_adapter_does_not_return_empty_names(monkeypatch):
    monkeypatch.setattr(_s3, "listing_items", lambda *args: iter([("/", None)]))
    assert list(_s3._entries({}, "")) == []


@pytest.mark.parametrize("access,secret", [("", ""), ("id", ""), ("id", "secret")])
def test_shared_s3_credentials_keep_environment_precedence(monkeypatch, access, secret):
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
    tmp_path, monkeypatch, explicit, fields
):
    path = tmp_path / "credentials"
    path.write_text(f"[test]\n{fields}\n")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(path))
    monkeypatch.setenv("AWS_PROFILE", "test")
    found = Credentials.from_file(str(path), "test") if explicit else Credentials.from_file()
    assert found == (Credentials("id", "secret") if "aws_secret_access_key" in fields else None)


@pytest.mark.parametrize("token", ["", "temporary-token"])
@pytest.mark.parametrize("target", ["", "/data"])
def test_native_signing_preserves_empty_target_and_session_tokens(token, target):
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
