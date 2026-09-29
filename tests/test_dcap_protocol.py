"""The dcap wire format: URLs, control lines, stat records and error codes."""

from __future__ import annotations

import errno
import stat

import pytest

from xgfalclient.errors import GError
from xgfalclient.plugins.dcap import protocol
from xgfalclient.plugins.dcap.protocol import (
    DcapURL,
    encode_path,
    error_code,
    mode_string,
    options,
    parse_reply,
    parse_stat,
    parse_url,
    stat_fields,
    tokenize,
)
from xgfalclient.types import Stat


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("dcap://door/pnfs/f", DcapURL("dcap", "door", 22125, "/pnfs/f")),
        ("gsidcap://door/pnfs/f", DcapURL("gsidcap", "door", 22128, "/pnfs/f")),
        ("kdcap://door/pnfs/f", DcapURL("kdcap", "door", 22725, "/pnfs/f")),
        ("dcap://door:1234/pnfs/f", DcapURL("dcap", "door", 1234, "/pnfs/f")),
        ("dcap://[::1]:1/a?b#c", DcapURL("dcap", "::1", 1, "/a?b#c")),
        ("dcap://door//double", DcapURL("dcap", "door", 22125, "//double")),
    ],
)
def test_parse_url(url: str, expected: DcapURL) -> None:
    assert parse_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "dcap:///pnfs/f",
        "dcap://door",
        "root://door/f",
        'dcap://door/a"b',
        "dcap://door/a\nb",
        "DCAP://door/f",
        "Gsidcap://door/f",
    ],
)
def test_parse_url_rejects(url: str) -> None:
    with pytest.raises(GError) as info:
        parse_url(url)
    assert info.value.code == errno.EINVAL


def test_wire_name_is_libdcaps() -> None:
    url = parse_url("gsidcap://door:22128/pnfs/a b/ü")
    assert url.prefix == "gsi"
    assert url.wire() == "gsidcap://door/pnfs/a%20b/%C3%BC"
    assert parse_url("dcap://door/x").prefix == ""
    ipv6 = parse_url("dcap://[::1]:7/x")
    assert ipv6.wire() == "dcap://[::1]/x"
    assert ipv6.url("/y") == "dcap://[::1]:7/y"


def test_encode_path() -> None:
    assert encode_path("a/b-c_d.e~f") == "a/b-c_d.e~f"
    assert encode_path("a:b%c") == "a%3Ab%25c"


def test_tokenize() -> None:
    assert tokenize(' 1 0 client stat "a b" -x="c d"e ""\r\n') == [
        "1",
        "0",
        "client",
        "stat",
        "a b",
        "-x=c de",
        "",
    ]
    assert tokenize('"open to the end') == ["open to the end"]
    assert tokenize("a\tb") == ["a", "b"]


def test_parse_reply() -> None:
    reply = parse_reply('3 7 client failed 1 "why" EIO -k=v')
    assert reply is not None
    assert (reply.session, reply.command_id, reply.verb) == (3, 7, "failed")
    assert reply.args == ("1", "why", "EIO", "-k=v")
    assert reply.option("k") == "v"
    assert reply.option("missing") is None
    assert parse_reply("1 2 client") is None
    assert parse_reply("x 2 client ok") is None


def test_options() -> None:
    assert options(["-a=1", "-b", "-", "c", "-d=x=y"]) == {"a": "1", "b": "", "d": "x=y"}


def test_parse_stat() -> None:
    info = parse_stat(
        (
            "-st_size=12",
            "-st_uid=1",
            "-st_gid=2",
            "-st_atime=3",
            "-st_mtime=4",
            "-st_ctime=5",
            "-st_mode=-rw-r--r--",
            "-st_ino=bogus",
            "stray",
        )
    )
    assert (info.st_size, info.st_uid, info.st_gid) == (12, 1, 2)
    assert (info.st_atime, info.st_mtime, info.st_ctime) == (3, 4, 5)
    assert info.st_mode == stat.S_IFREG | 0o644
    assert info.st_ino == 0
    assert info.st_nlink == 0


@pytest.mark.parametrize(
    ("text", "mode"),
    [
        ("drwxr-x--x", stat.S_IFDIR | 0o751),
        ("lrwxrwxrwx", stat.S_IFLNK | 0o777),
        ("x---------", stat.S_IFCHR),
        ("?rw-------", stat.S_IFIFO | 0o600),
        ("drwx", 0),
    ],
)
def test_parse_mode(text: str, mode: int) -> None:
    assert parse_stat((f"-st_mode={text}",)).st_mode == mode


@pytest.mark.parametrize(
    ("mode", "text"),
    [
        (stat.S_IFDIR | 0o755, "drwxr-xr-x"),
        (stat.S_IFLNK | 0o777, "lrwxrwxrwx"),
        (stat.S_IFREG | 0o640, "-rw-r-----"),
        (stat.S_IFIFO | 0o600, "xrw-------"),
    ],
)
def test_mode_string(mode: int, text: str) -> None:
    assert mode_string(mode) == text


def test_stat_fields_round_trip() -> None:
    info = Stat(st_size=5, st_uid=1, st_gid=2, st_mode=stat.S_IFREG | 0o600, st_ino=9, st_mtime=7)
    assert parse_stat(tuple(stat_fields(info).split())) == info


@pytest.mark.parametrize(
    ("args", "code"),
    [
        (("10001", "No such file or directory", "ENOENT"), errno.ENOENT),
        (("20", "Directory exists", "EEXIST"), errno.EEXIST),
        (("17", "Path is a Directory", "EISDIR"), errno.EISDIR),
        (("2", "No such file or directory", ""), errno.ENOENT),
        (("1", "File is readOnly"), errno.EIO),
        (("23", "Directory not empty", "EACCES"), errno.ENOTEMPTY),
        (("19", "Permission denied", "EACCES"), errno.EACCES),
        (("1", "whatever", "EBOGUS"), errno.EIO),
        (("1", "whatever", "NOTANERRNO"), errno.EIO),
        ((), errno.EIO),
    ],
)
def test_error_code(args: tuple[str, ...], code: int) -> None:
    assert error_code(args) == code


def test_constants() -> None:
    assert protocol.SCHEMES == ("dcap", "gsidcap", "kdcap")
    assert protocol.HEADER.size == 8
