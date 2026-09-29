"""GridFTP wire details that need no socket."""

from __future__ import annotations

import errno
import stat

import pytest

from xgfalclient.errors import ECOMM, GError
from xgfalclient.plugins.gridftp import protocol as p


def test_reply_text_and_kind() -> None:
    reply = p.Reply(250, ["250-status of /f", " Type=file; /f", "250 End."])
    assert reply.kind == 2
    assert reply.text == "status of /f\nType=file; /f\nEnd."
    assert str(reply) == "250 status of /f\nType=file; /f\nEnd."
    assert repr(reply) == "Reply(250, ['250-status of /f', ' Type=file; /f', '250 End.'])"
    assert p.Reply(200, ["200"]).text == ""
    # A continuation line that merely starts with the code's digits keeps them.
    assert p.Reply(250, ["250-sizes", "2500 bytes", "250 End."]).text == "sizes\n2500 bytes\nEnd."


def test_reply_error_matches_gfal2_wording() -> None:
    # Byte for byte what gfal2 2.23.5 reports for these globus replies.
    multi = p.Reply(
        550,
        [
            "550-GlobusError: v=1 c=PATH_NOT_FOUND",
            "550-GridFTP-Errno: 2",
            "550-GridFTP-Reason: System error in stat",
            "550-GridFTP-Error-String: No such file or directory",
            "550 End.",
        ],
    )
    error = p.reply_error(multi)
    assert error.code == errno.ENOENT
    assert error.message == (
        "globus_ftp_client: the server responded with an error 550 550-GlobusError: v=1 "
        "c=PATH_NOT_FOUND  550-GridFTP-Errno: 2  550-GridFTP-Reason: System error in stat  "
        "550-GridFTP-Error-String: No such file or directory  550 End.   "
    )
    single = p.reply_error(p.Reply(501, ["501 Invalid command arguments."]))
    assert single.code == ECOMM
    assert single.message == (
        "globus_ftp_client: the server responded with an error 501 Invalid command arguments.   "
    )


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("No such file or directory", errno.ENOENT),
        ("path not found", errno.ENOENT),
        ("error 3011 at door", errno.ENOENT),
        ("Permission denied", errno.EACCES),
        ("bad credential", errno.EACCES),
        ("File exists", errno.EEXIST),
        ("error 3006", errno.EEXIST),
        ("Not a directory", errno.ENOTDIR),
        ("Operation not supported", errno.ENOTSUP),
        ("Login incorrect.", errno.EACCES),
        ("Could not get virtual id", errno.EACCES),
        ("the operation was aborted", errno.ECANCELED),
        ("Is a directory", errno.EISDIR),
        ("Disk quota exceeded", errno.EDQUOT),
        ("Directory not empty", ECOMM),  # gfal2 has no rule for it
        ("no such file", ECOMM),  # gfal2's match is case-sensitive
    ],
)
def test_errno_for_reply(text: str, code: int) -> None:
    assert p.errno_for_reply(text) == code


def test_addresses() -> None:
    assert p.parse_pasv("227 Entering Passive Mode (172,20,0,2,195,124)") == ("172.20.0.2", 50044)
    assert p.parse_epsv("229 Entering Extended Passive Mode (|||50000|)") == ("", 50000)
    assert p.parse_epsv("229 x (|2|::1|2811|)") == ("::1", 2811)
    assert p.parse_spas(
        ["229-Entering Striped Passive Mode", " 1,2,3,4,0,5", " 1,2,3,5,0,6", "229 End"]
    ) == [
        ("1.2.3.4", 5),
        ("1.2.3.5", 6),
    ]
    assert p.format_port("10.0.0.1", 50044) == "10,0,0,1,195,124"
    assert p.format_eprt("10.0.0.1", 5) == "|1|10.0.0.1|5|"
    assert p.format_eprt("::1", 5) == "|2|::1|5|"
    for call in (
        lambda: p.parse_pasv("227 nothing"),
        lambda: p.parse_epsv("229 nothing"),
        lambda: p.parse_spas(["229-x", "229 End"]),
    ):
        with pytest.raises(GError) as caught:
            call()
        assert caught.value.code == errno.EPROTO


def test_facts() -> None:
    facts, name = p.parse_facts("Type=file;Size=12;UNIX.mode=0644;odd; my file")
    assert facts == {"type": "file", "size": "12", "unix.mode": "0644"}
    assert name == "my file"
    assert p.parse_facts("plain-name") == ({}, "plain-name")
    assert p.parse_facts("two words") == ({}, "two words")


def test_stat_from_facts() -> None:
    info = p.stat_from_facts(
        {
            "type": "file",
            "size": "12",
            "modify": "20260928152358",
            "unix.mode": "0644",
            "unix.uid": "1000",
            "unix.gid": "7",
        }
    )
    assert info.st_mode == stat.S_IFREG | 0o644
    assert (info.st_size, info.st_uid, info.st_gid, info.st_nlink) == (12, 1000, 7, 1)
    assert info.st_mtime == 1790609038
    assert info.st_atime == info.st_ctime == info.st_ino == 0
    for kind in ("dir", "cdir", "pdir"):
        assert p.stat_from_facts({"type": kind}).is_dir()
    assert p.stat_from_facts({"type": "OS.unix=slink:/x"}).is_link()
    assert p.stat_from_facts({"type": "OS.unix=symlink"}).is_link()
    odd = p.stat_from_facts({"size": "big", "modify": "yesterday", "unix.mode": "rw"})
    assert (odd.st_size, odd.st_mtime, odd.st_mode) == (0, 0, stat.S_IFREG)


def test_mdtm() -> None:
    assert p.parse_mdtm("20260928152358.123") == 1790609038
    assert p.format_mdtm(1790609038) == "20260928152358"


def test_perf_marker() -> None:
    marker = p.Reply(
        112,
        [
            "112-Perf Marker",
            " Timestamp:  1790609083.9",
            " Stripe Index: 2",
            " Stripe Bytes Transferred: 1234",
            " Total Stripe Count: 3",
            "112 End.",
        ],
    )
    assert p.parse_perf_marker(marker) == (2, 1234)
    assert p.parse_perf_marker(p.Reply(111, ["111 Range Marker 0-12"])) is None
    assert p.parse_perf_marker(p.Reply(112, ["112-Perf Marker", "112 End."])) is None


def test_check_path() -> None:
    assert p.check_path("/a b") == "/a b"
    with pytest.raises(GError) as caught:
        p.check_path("/a\r\nDELE /b")
    assert caught.value.code == errno.EINVAL
    with pytest.raises(GError):
        p.check_path("/a\nDELE /b")  # a bare line feed ends the line too


def test_passive_address() -> None:
    """What gfal2's PASV plugin reads from a passive reply."""
    from xgfalclient.plugins.gridftp.protocol import passive_address

    def of(code: int, *lines: str) -> object:
        return passive_address(p.Reply(code, list(lines)))

    assert of(227, "227 Entering Passive Mode (10,0,0,1,1,2)") == ("10.0.0.1", 258, False)
    assert of(127, "127 PORT 10,0,0,1,1,2") == ("10.0.0.1", 258, False)
    assert of(227, "227 no address") is None
    assert of(229, "229 Entering Extended Passive Mode (|||5000|)") == ("", 5000, False)
    assert of(229, "229 EPSV (|2|::1|5000|)") == ("[::1]", 5000, True)
    assert of(229, "229 EPSV (|2||5000|)") == ("", 5000, True)
    assert of(229, "229 EPSV (|1|10.0.0.1|5000|)") == ("10.0.0.1", 5000, False)
    assert of(229, "229-Striped", " 10,0,0,1,1,2", "229 End") == ("10.0.0.1", 258, False)
    assert of(229, "229 nothing") is None
    assert of(200, "200 Passive delayed.") is None
    assert of(500, "527 x") is None
