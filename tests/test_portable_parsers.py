"""xgfal's XML readers on the shared guard, and bounded local LFC record readers.

The guard itself - every encoding, both ElementTree parsers, every kind of
declaration - is :mod:`xrdcore.safexml` and is tested there; this file tests
how each xgfal protocol turns its refusal into that protocol's error.
"""

from __future__ import annotations

import errno
from pathlib import Path
from typing import Any

import pytest

from xgfalclient.errors import GError
from xgfalclient.plugins.http._dav import parse_xml
from xgfalclient.plugins.http._metalink import parse_metalink
from xgfalclient.plugins.lfc import client
from xgfalclient.plugins.lfc.wire import Packer, Unpacker, WireError
from xgfalclient.plugins.srm import bdii, soap


def test_protocols_translate_unsafe_xml_rejections_and_preserve_codes() -> None:
    with pytest.raises(GError, match="document type") as error:
        parse_xml(b"<!DOCTYPE doc><doc/>")
    assert error.value.code == errno.EIO
    with pytest.raises(GError, match="DOCTYPE") as error:
        parse_metalink(b"<!DOCTYPE metalink><metalink/>", base_url="https://host")
    assert error.value.code == 0
    with pytest.raises(soap.SOAPError, match="DTD"):
        soap.parse(b"<!DOCTYPE doc><doc/>")


def test_bdii_discards_a_cache_with_entity_declarations(tmp_path: Path) -> None:
    path = tmp_path / "cache"
    path.write_text("<!DOCTYPE doc><entry/>")
    assert bdii.read_cache(str(path), "host") == []


def _stat_fields() -> dict[str, Any]:
    return {
        "fileid": 1,
        "guid": "id",
        "mode": 0o644,
        "nlink": 1,
        "uid": 1000,
        "gid": 1000,
        "size": 42,
        "atime": -1,
        "mtime": 2,
        "ctime": 3,
        "fileclass": 0,
        "status": "-",
        "csumtype": "AD",
        "csumvalue": "1234",
    }


def _stat_payload(fields: dict[str, Any], with_guid: bool) -> bytes:
    record = Packer().hyper(fields["fileid"])
    if with_guid:
        record.string(fields["guid"])
    record.word(fields["mode"]).long(fields["nlink"]).long(fields["uid"]).long(fields["gid"])
    record.hyper(fields["size"]).hyper(fields["atime"]).hyper(fields["mtime"])
    record.hyper(fields["ctime"]).word(fields["fileclass"]).byte(fields["status"])
    if with_guid:
        record.string(fields["csumtype"]).string(fields["csumvalue"])
    return record.bytes()


@pytest.mark.parametrize("with_guid", [False, True])
def test_stat_keeps_cursor_and_optional_fields(with_guid: bool) -> None:
    body = _stat_payload(_stat_fields(), with_guid)
    reader = Unpacker(body + b"tail")
    record = client._stat(reader, with_guid)
    assert record.size == 42
    assert record.atime == -1
    assert record.guid == ("id" if with_guid else "")
    assert record.csumtype == ("AD" if with_guid else "")
    assert reader.remaining == 4


@pytest.mark.parametrize("fraction", range(24))
def test_truncated_stat_remains_a_protocol_error(fraction: int) -> None:
    body = _stat_payload(_stat_fields(), True)
    with pytest.raises(WireError) as error:
        client._stat(Unpacker(body[: len(body) * fraction // 24]), True)
    assert error.value.code == errno.EPROTO


@pytest.mark.parametrize("field,limit", [("guid", 36), ("csumtype", 2), ("csumvalue", 32)])
def test_record_still_bounds_strings(field: str, limit: int) -> None:
    fields = _stat_fields()
    fields[field] = "x" * (limit + 1)
    with pytest.raises(WireError, match="string too long") as error:
        client._stat(Unpacker(_stat_payload(fields, True)), True)
    assert error.value.code == errno.EPROTO


def test_replica_keeps_surrogate_escaped_names() -> None:
    fields: dict[str, Any] = {
        "fileid": 1,
        "nbaccesses": 2,
        "atime": 3,
        "ptime": 4,
        "status": "-",
        "f_type": "P",
        "poolname": "pool",
        "host": "host",
        "fs": "/fs",
        "sfn": "/file\udcff",
    }
    record = Packer().hyper(fields["fileid"]).hyper(fields["nbaccesses"])
    record.hyper(fields["atime"]).hyper(fields["ptime"]).byte(fields["status"]).byte(
        fields["f_type"]
    )
    record.string(fields["poolname"]).string(fields["host"]).string(fields["fs"]).string(
        fields["sfn"]
    )
    assert client._replicas([record.bytes()])[0] == client.Replica(**fields)
