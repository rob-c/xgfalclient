"""Errors, enums, events, records and URLs: the small shared pieces."""

from __future__ import annotations

import errno
import os
import pickle
import stat as stat_module

import pytest

import xgfalclient
from xgfalclient import errors
from xgfalclient._compat import dataclass_slots, peer_chain_der
from xgfalclient.enums import checksum_mode, event_side, verbose_level
from xgfalclient.events import BOTH, DESTINATION, SOURCE, GfaltEvent
from xgfalclient.types import DT_DIR, DT_LNK, DT_REG, DT_UNKNOWN, Dirent, Stat, dtype_for_mode
from xgfalclient.url import URL, basename, join, parent, parse, scheme_of

# -- errors ---------------------------------------------------------------------


def test_gerror_has_the_bindings_shape() -> None:
    error = xgfalclient.GError("No such file", errno.ENOENT)
    assert error.code == errno.ENOENT
    assert error.message == "No such file"
    assert error.args == ("No such file", errno.ENOENT)
    assert str(error) == "No such file"
    assert repr(error) == "GError('No such file', 2)"
    assert not isinstance(error, OSError)


def test_gerror_pickles() -> None:
    error = pickle.loads(pickle.dumps(xgfalclient.GError("boom", 5)))
    assert (error.message, error.code) == ("boom", 5)


def test_gerror_prefixes_scopes() -> None:
    assert errors.gerror(2, "gone").message == "gone"
    assert errors.gerror(2, "gone", "gfal2_stat", "http").message == "[gfal2_stat][http] gone"
    with pytest.raises(xgfalclient.GError) as caught:
        errors.raise_gerror(13, "denied", "x")
    assert caught.value.code == 13


def test_from_oserror_words_like_the_file_plugin() -> None:
    error = errors.from_oserror(OSError(errno.ENOENT, "whatever"))
    assert error.code == errno.ENOENT
    assert error.message == f"errno reported by local system call {os.strerror(errno.ENOENT)}"
    assert errors.from_oserror(OSError("no errno")).code == errno.EIO


def test_unsupported_and_not_supported_url() -> None:
    assert errors.unsupported("pread").code == errno.ENOSYS
    assert "for u" in errors.unsupported("pread", "u").message
    missing = errors.not_supported_url("foo://x")
    assert missing.code == errno.EPROTONOSUPPORT
    assert missing.message == "Protocol not supported or path/url invalid: foo://x"


@pytest.mark.parametrize(
    ("status", "code"),
    [(404, errno.ENOENT), (403, errno.EACCES), (599, errors.ECOMM), (418, errno.EIO)],
)
def test_http_status_to_errno(status: int, code: int) -> None:
    assert errors.errno_for_http(status) == code


# -- enums ----------------------------------------------------------------------


def test_checksum_mode_matches_boost_enum_surface() -> None:
    assert int(checksum_mode.both) == 3
    assert checksum_mode.both.name == "both"
    assert checksum_mode.names["source"] is checksum_mode.source
    assert checksum_mode.values[2] is checksum_mode.target
    assert repr(checksum_mode.none) == "gfal2.checksum_mode.none"
    assert str(checksum_mode.none) == "gfal2.checksum_mode.none"
    assert isinstance(checksum_mode.both, int)


def test_duplicate_values_keep_the_first_member() -> None:
    assert verbose_level.values[128] is verbose_level.debug
    assert verbose_level.trace == verbose_level.debug
    assert verbose_level.trace.name == "trace"


def test_enums_pickle_to_the_same_member() -> None:
    assert pickle.loads(pickle.dumps(event_side.event_destination)) is event_side.event_destination
    assert pickle.loads(pickle.dumps(checksum_mode.both)) is checksum_mode.both


# -- events ---------------------------------------------------------------------


def test_event_str_matches_gfal2() -> None:
    event = GfaltEvent(BOTH, "GFAL2:CORE:COPY", "LIST:ITEM", "a => b", timestamp=42)
    assert str(event) == "[42] BOTH   GFAL2:CORE:COPY\tLIST:ITEM\ta => b"
    assert repr(event) == str(event)
    assert str(GfaltEvent(SOURCE, "d", "s", timestamp=1)) == "[1] SOURCE d\ts\t"
    assert str(GfaltEvent(DESTINATION, "d", "s", timestamp=1)) == "[1] DEST   d\ts\t"
    assert str(GfaltEvent(9, "d", "s", timestamp=1)).startswith("[1] BOTH")


def test_event_defaults_to_now() -> None:
    event = GfaltEvent()
    assert event.side == 2
    assert event.timestamp > 1_600_000_000_000


# -- Stat and Dirent -------------------------------------------------------------


def test_stat_prints_like_gfal2() -> None:
    info = Stat(st_mode=0o100644, st_size=12, st_nlink=1, st_ino=7, st_mtime=3)
    assert str(info) == (
        "uid: 0\ngid: 0\nmode: 100644\nsize: 12\nnlink: 1\nino: 7\nctime: 0\natime: 0\nmtime: 3\n"
    )
    assert repr(info) == str(info)
    assert info.is_file() and not info.is_dir() and not info.is_link()
    assert info.as_dict()["st_size"] == 12


def test_stat_rejects_unknown_fields_and_compares() -> None:
    with pytest.raises(TypeError, match="st_bogus"):
        Stat(st_bogus=1)
    assert Stat(st_size=1) == Stat(st_size=1)
    assert Stat(st_size=1) != Stat(st_size=2)
    assert Stat() != "stat"


def test_stat_from_os(tmp_path: object) -> None:
    info = Stat.from_os(os.stat(os.fspath(tmp_path)))  # type: ignore[arg-type]
    assert info.is_dir()


@pytest.mark.parametrize(
    ("mode", "dtype"),
    [
        (stat_module.S_IFDIR, DT_DIR),
        (stat_module.S_IFREG, DT_REG),
        (stat_module.S_IFLNK, DT_LNK),
        (stat_module.S_IFIFO, DT_UNKNOWN),
    ],
)
def test_dtype_for_mode(mode: int, dtype: int) -> None:
    assert dtype_for_mode(mode) == dtype


def test_dirent_fields() -> None:
    entry = Dirent("f.txt", DT_REG, 5, 1)
    assert (entry.d_name, entry.d_type, entry.d_ino, entry.d_off) == ("f.txt", DT_REG, 5, 1)
    assert entry.d_reclen == 32
    assert Dirent("a", DT_DIR).d_reclen == 24
    assert Dirent().d_reclen == 0
    assert repr(entry) == "Dirent(d_name='f.txt', d_type=8)"
    assert entry == Dirent("f.txt", DT_REG, 5, 9)
    assert entry != Dirent("g", DT_REG, 5)
    assert entry != "f.txt"


# -- URLs -----------------------------------------------------------------------


def test_parse_keeps_everything() -> None:
    url = "root://user@host.example:1095//store/f?authz=x#frag"
    parsed = parse(url)
    assert parsed == URL("root", "user@host.example:1095", "//store/f", "authz=x", "frag")
    assert str(parsed) == url
    assert parsed.host == "host.example"
    assert parsed.port == 1095
    assert parsed.userinfo == "user"
    assert parsed.base == "root://user@host.example:1095"
    assert parsed.query_dict() == {"authz": "x"}


def test_parse_ipv6_and_default_ports() -> None:
    parsed = parse("davs://[::1]:8443/data")
    assert parsed.host == "::1" and parsed.port == 8443
    assert parse("davs://[::1]/data").port == 443
    assert parse("gsiftp://h/x").port == 2811
    assert parse("mock://h/x").port == 0
    assert parse("https://h:notaport/x").port == 443
    assert parse("file:///tmp/x").host == ""


def test_parse_srm_query_path_and_mutators() -> None:
    parsed = parse("srm://se:8443/srm/managerv2?SFN=/pnfs/f")
    assert parsed.query_items() == [("SFN", "/pnfs/f")]
    assert str(parsed.with_path("/x")) == "srm://se:8443/x?SFN=/pnfs/f"
    assert str(parsed.with_scheme("httpg")).startswith("httpg://")
    assert str(parsed.with_query("")) == "srm://se:8443/srm/managerv2"


@pytest.mark.parametrize(
    ("url", "netloc", "path", "query", "fragment"),
    [
        ("srm://se:8446?SFN=/f", "se:8446", "", "SFN=/f", ""),
        ("https://h#frag", "h", "", "", "frag"),
        ("https://h", "h", "", "", ""),
        ("https://h/a?b#c", "h", "/a", "b", "c"),
    ],
)
def test_parse_authority_ends_at_path_query_or_fragment(
    url: str, netloc: str, path: str, query: str, fragment: str
) -> None:
    parsed = parse(url)
    assert (parsed.netloc, parsed.path, parsed.query, parsed.fragment) == (
        netloc,
        path,
        query,
        fragment,
    )
    assert str(parsed) == url


@pytest.mark.parametrize(
    ("url", "scheme"),
    [
        ("DAVS://h/x", "davs"),
        ("/tmp/x", ""),
        ("://x", ""),
        ("a b://x", ""),
        ("s3s://b/k", "s3s"),
        ("lfn:/grid/vo/f", "lfn"),
        ("GUID:1234-abcd", "guid"),
    ],
)
def test_scheme_of(url: str, scheme: str) -> None:
    assert scheme_of(url) == scheme


def test_parse_rejects_schemeless() -> None:
    with pytest.raises(xgfalclient.GError) as caught:
        parse("/tmp/x")
    assert caught.value.code == errno.EPROTONOSUPPORT


def test_join_parent_basename() -> None:
    assert join("davs://h/a", "b") == "davs://h/a/b"
    assert join("davs://h/a/", "/b") == "davs://h/a/b"
    assert parent("davs://h/a/b?x=1") == "davs://h/a"
    assert parent("davs://h/a/") == "davs://h/"
    assert parent("davs://h/") == "davs://h/"
    assert parent("root://h//a") == "root://h//"
    assert parent("root://h//a/b") == "root://h//a"
    assert parent("file:///") == "file:///"
    assert basename("davs://h/a/b/") == "b"


# -- the version shims -------------------------------------------------------------


def test_dataclass_slots_only_from_3_10() -> None:
    assert dataclass_slots((3, 9, 18)) == {}
    assert dataclass_slots((3, 10, 0)) == {"slots": True}


class _Link:
    """An ``_ssl.Certificate`` before 3.13: no ``public_bytes``, but buffer-convertible."""

    def __init__(self, der: bytes) -> None:
        self.der = der

    def __bytes__(self) -> bytes:
        return self.der


class _PublicLink(_Link):
    """A 3.13 ``ssl.Certificate``: ``public_bytes(2)`` is the DER form."""

    def public_bytes(self, encoding: int) -> bytes:
        assert encoding == 2
        return self.der


class _Tls:
    """Just enough of an ``SSLSocket``: the leaf via ``getpeercert``, nothing else."""

    def __init__(self, leaf: bytes | None) -> None:
        self.leaf = leaf

    def getpeercert(self, binary_form: bool = False) -> bytes | None:
        assert binary_form
        return self.leaf


def test_peer_chain_der_public_method() -> None:
    tls = _Tls(b"unused")
    tls.get_unverified_chain = lambda: [_PublicLink(b"leaf"), _PublicLink(b"ca")]  # type: ignore[attr-defined]
    assert peer_chain_der(tls) == [b"leaf", b"ca"]


def test_peer_chain_der_private_method_before_3_13() -> None:
    tls = _Tls(b"unused")
    tls._sslobj = type("SSLObject", (), {"get_unverified_chain": lambda self: [_Link(b"leaf")]})()  # type: ignore[attr-defined]
    assert peer_chain_der(tls) == [b"leaf"]


def test_peer_chain_der_leaf_only_on_3_9() -> None:
    assert peer_chain_der(_Tls(b"leaf")) == [b"leaf"]
    assert peer_chain_der(_Tls(None)) == []
