"""Portable XML loading and bounded local LFC record readers."""

from __future__ import annotations

import errno
from xml.etree import ElementTree as ET

import pytest

from xgfalclient._xml import UnsafeXML, fromstring
from xgfalclient.errors import GError
from xgfalclient.plugins.http._dav import parse_xml
from xgfalclient.plugins.http._metalink import parse_metalink
from xgfalclient.plugins.lfc import client
from xgfalclient.plugins.lfc.wire import Packer, Unpacker, WireError
from xgfalclient.plugins.srm import bdii, soap


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("padding", [0, 20_000])
@pytest.mark.parametrize(
    "declaration", ["<!DOCTYPE doc>", '<!DOCTYPE doc SYSTEM "urn:test:unused">']
)
def test_parser_rejects_dtds_in_every_encoding(encoding, padding, declaration):
    with pytest.raises(UnsafeXML):
        fromstring((" " * padding + declaration + "<doc/>").encode(encoding))


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
def test_normal_xml_keeps_stdlib_elements_and_namespaces(encoding):
    root = fromstring('<doc xmlns="urn:test"><item>hello</item></doc>'.encode(encoding))
    assert isinstance(root, ET.Element)
    assert root.findtext("{urn:test}item") == "hello"


def test_comment_text_is_not_mistaken_for_a_declaration():
    assert fromstring(b"<!-- <!DOCTYPE doc> --><doc/>").tag == "doc"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
def test_internal_declarations_are_rejected_before_tree_construction(monkeypatch, encoding):
    from xgfalclient import _xml as local_xml

    def unexpected_tree(*args):
        raise AssertionError("a rejected document must not reach tree construction")

    monkeypatch.setattr(local_xml.ET, "fromstring", unexpected_tree)
    document = '<!DOCTYPE doc [<!ENTITY content "hello">]><doc/>'
    with pytest.raises(UnsafeXML):
        fromstring(document.encode(encoding))


@pytest.mark.parametrize(
    "handler", ["StartDoctypeDeclHandler", "EntityDeclHandler", "ExternalEntityRefHandler"]
)
def test_each_expat_declaration_callback_rejects_the_input(monkeypatch, handler):
    from xgfalclient import _xml as local_xml

    class DeclarationProbe:
        def Parse(self, data, final):
            getattr(self, handler)()

    monkeypatch.setattr(local_xml.expat, "ParserCreate", DeclarationProbe)
    with pytest.raises(UnsafeXML, match="not allowed"):
        fromstring(b"<doc/>")


def test_predefined_entities_and_literal_declaration_text_are_harmless():
    assert fromstring(b"<doc>A&amp;B</doc>").text == "A&B"
    assert fromstring(b"<doc><![CDATA[<!DOCTYPE doc>]]></doc>").text == "<!DOCTYPE doc>"


def test_malformed_xml_preserves_stdlib_exception_details():
    with pytest.raises(ET.ParseError) as error:
        fromstring(b"<doc>")
    assert error.value.code == 3
    assert error.value.position == (1, 5)


def test_namespace_errors_remain_stdlib_parse_errors():
    with pytest.raises(ET.ParseError, match="unbound prefix"):
        fromstring(b"<unknown:doc/>")


def test_protocols_translate_unsafe_xml_rejections_and_preserve_codes():
    with pytest.raises(GError, match="document type") as error:
        parse_xml(b"<!DOCTYPE doc><doc/>")
    assert error.value.code == errno.EIO
    with pytest.raises(GError, match="DOCTYPE") as error:
        parse_metalink(b"<!DOCTYPE metalink><metalink/>", base_url="https://host")
    assert error.value.code == 0
    with pytest.raises(soap.SOAPError, match="DTD"):
        soap.parse(b"<!DOCTYPE doc><doc/>")


def test_bdii_discards_a_cache_with_entity_declarations(tmp_path):
    path = tmp_path / "cache"
    path.write_text("<!DOCTYPE doc><entry/>")
    assert bdii.read_cache(str(path), "host") == []


def _stat_fields():
    return dict(
        fileid=1,
        guid="id",
        mode=0o644,
        nlink=1,
        uid=1000,
        gid=1000,
        size=42,
        atime=-1,
        mtime=2,
        ctime=3,
        fileclass=0,
        status="-",
        csumtype="AD",
        csumvalue="1234",
    )


def _stat_payload(fields, with_guid):
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
def test_stat_keeps_cursor_and_optional_fields(with_guid):
    body = _stat_payload(_stat_fields(), with_guid)
    reader = Unpacker(body + b"tail")
    record = client._stat(reader, with_guid)
    assert record.size == 42
    assert record.atime == -1
    assert record.guid == ("id" if with_guid else "")
    assert record.csumtype == ("AD" if with_guid else "")
    assert reader.remaining == 4


@pytest.mark.parametrize("fraction", range(24))
def test_truncated_stat_remains_a_protocol_error(fraction):
    body = _stat_payload(_stat_fields(), True)
    with pytest.raises(WireError) as error:
        client._stat(Unpacker(body[: len(body) * fraction // 24]), True)
    assert error.value.code == errno.EPROTO


@pytest.mark.parametrize("field,limit", [("guid", 36), ("csumtype", 2), ("csumvalue", 32)])
def test_record_still_bounds_strings(field, limit):
    fields = _stat_fields()
    fields[field] = "x" * (limit + 1)
    with pytest.raises(WireError, match="string too long") as error:
        client._stat(Unpacker(_stat_payload(fields, True)), True)
    assert error.value.code == errno.EPROTO


def test_replica_keeps_surrogate_escaped_names():
    fields = dict(
        fileid=1,
        nbaccesses=2,
        atime=3,
        ptime=4,
        status="-",
        f_type="P",
        poolname="pool",
        host="host",
        fs="/fs",
        sfn="/file\udcff",
    )
    record = Packer().hyper(fields["fileid"]).hyper(fields["nbaccesses"])
    record.hyper(fields["atime"]).hyper(fields["ptime"]).byte(fields["status"]).byte(
        fields["f_type"]
    )
    record.string(fields["poolname"]).string(fields["host"]).string(fields["fs"]).string(
        fields["sfn"]
    )
    assert client._replicas([record.bytes()])[0] == client.Replica(**fields)
