"""The ``root://`` plugin, end to end against xrdclient's in-process server.

Every behaviour asserted here was read off gfal2 2.23.5's xrootd plugin and
checked against it with a real ``xrootd`` (see ``test_xrootd_interop.py``):
the wording of each message, the ``errno`` each ``kXR_*`` code becomes, how a
stat is filled in, and the quirks - ``mkdir`` answering ``EEXIST`` itself,
``rmdir`` massaging its ``errno``, ``pread`` moving the cursor.
"""

from __future__ import annotations

import errno
import json
import os
import socket
import stat as _stat
import threading
import time
import urllib.parse
import zlib
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

xrdclient = pytest.importorskip("xrdclient")

from xrdclient import errors as xe  # noqa: E402
from xrdclient.proto import constants as c  # noqa: E402
from xrdclient.testing import FakeServer, error, frame  # noqa: E402

import xgfalclient  # noqa: E402
from xgfalclient import GError, checksum_mode  # noqa: E402
from xgfalclient import plugins as registry  # noqa: E402
from xgfalclient.creds import X509Credential  # noqa: E402
from xgfalclient.plugins import xrootd  # noqa: E402
from xgfalclient.plugins.xrootd import (  # noqa: E402
    XRootDPlugin,
    collapse_slashes,
    describe,
    flags_to_mode,
    listing_stat,
    local_path,
    parse_prepare_status,
    posix_stat,
    space_json,
    status_error,
    status_word,
)
from xgfalclient.testing.pki import PKI  # noqa: E402

HELLO = b"hello world\n"
ADLER_HELLO = f"{zlib.adler32(HELLO):08x}"


@pytest.fixture
def server() -> Iterator[FakeServer]:
    with FakeServer(files={"/data/a.txt": HELLO}, dirs=["/data/sub"]) as srv:
        yield srv


@pytest.fixture
def base(server: FakeServer) -> str:
    host, port = server.address
    return f"root://{host}:{port}/"


@pytest.fixture
def plugin(ctx: xgfalclient.Gfal2Context) -> XRootDPlugin:
    found = ctx.plugin("root://h//f", "stat")
    assert isinstance(found, XRootDPlugin)
    return found


def _reply(server: FakeServer, opcode: int, code: int, message: str = "nope") -> None:
    """Answer every ``opcode`` with ``kXR_error``/``code`` from now on."""
    server.handlers[opcode] = lambda conn, sid, params, body: iter([error(sid, code, message)])


def _ok(server: FakeServer, opcode: int, body: bytes = b"") -> None:
    server.handlers[opcode] = lambda conn, sid, params, body_: iter([frame(sid, c.kXR_ok, body)])


def _gerror(call: Any, *args: Any) -> GError:
    with pytest.raises(GError) as caught:
        call(*args)
    return caught.value


# -- loading ---------------------------------------------------------------------------


def test_the_plugin_is_registered_under_gfal2s_name(ctx: xgfalclient.Gfal2Context) -> None:
    assert any(name.startswith("xrootd-") for name in ctx.get_plugin_names())
    for scheme in ("root", "roots", "xroot", "xroots"):
        assert isinstance(ctx.plugin(f"{scheme}://h//f", "stat"), XRootDPlugin)


def test_without_xrdclient_root_urls_say_how_to_fix_it(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str = "xrdclient") -> Any:
        raise ImportError("No module named 'xrdclient'")

    monkeypatch.setattr(xrootd, "_import", missing)
    monkeypatch.setattr(registry, "_MISSING", {})
    assert XRootDPlugin.available() == xrootd.MISSING_HINT
    with xgfalclient.creat_context() as context:
        assert not any(name.startswith("xrootd") for name in context.get_plugin_names())
        failure = _gerror(context.stat, "root://host//f")
    assert failure.code == errno.EPROTONOSUPPORT
    assert "pip install 'xgfalclient[xrootd]'" in failure.message


def test_available_when_xrdclient_imports() -> None:
    assert XRootDPlugin.available() is None


# -- errors ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kxr", "code"),
    [
        (3011, errno.ENOENT),
        (3010, errno.EACCES),
        (3018, errno.EEXIST),
        (3005, errno.ENODEV),
        (3012, errno.EFAULT),
        (3013, errno.ENOTSUP),
        (3016, errno.EISDIR),
        (3034, errno.ETIMEDOUT),
        (3027, xrootd.ENOATTR),
        (3999, errno.ENOMSG),
    ],
)
def test_server_codes_map_as_xprotocol_to_errno(kxr: int, code: int) -> None:
    with pytest.raises(xe.XRootDError) as caught:
        xe.raise_for_status(kxr, "why", path="/p")
    failure = describe(caught.value)
    assert failure.code == code
    assert failure.to_str == f"[ERROR] Server responded with an error: [{kxr}] why\n"
    assert failure.to_string == f"[ERROR] Error response: {xrootd.e2t(code)}"
    assert failure.message == "why"


def _raised_from(exc: BaseException, cause: BaseException) -> BaseException:
    try:
        try:
            raise cause
        except BaseException as inner:
            raise exc from inner
    except BaseException as outer:
        return outer


@pytest.mark.parametrize(
    ("exc", "code", "text"),
    [
        (xe.ChecksumMismatchError("adler32", "a", "b"), errno.EILSEQ, "[ERROR] Checksum error"),
        (xe.AuthenticationError("no proxy"), xrootd.EAUTH, "[FATAL] Auth failed"),
        (xe.NoMechanismError(["gsi"]), xrootd.EAUTH, "[FATAL] Auth failed"),
        (xe.RedirectLimitError("loop"), errno.ELOOP, "[FATAL] Redirect limit has been reached"),
        (xe.TooLargeError(10, 5), errno.EFBIG, "[ERROR] Invalid operation"),
        (xe.ProtocolError("garbage"), errno.EPROTO, "[FATAL] Invalid message"),
        (xe.WaitLimitError("busy"), errno.EAGAIN, "[ERROR] Retry"),
        (xe.TimeoutError("slow"), errno.ETIMEDOUT, "[ERROR] Operation expired"),
        (socket.timeout("slow"), errno.ETIMEDOUT, "[ERROR] Operation expired"),
        (ValueError("bad port"), errno.EINVAL, "[ERROR] Invalid arguments"),
        (RuntimeError("odd"), errno.EIO, "[ERROR] Unknown error"),
        (xe.ConnectionError("closed"), errno.ECONNRESET, "[FATAL] Connection error"),
    ],
)
def test_client_failures_map_as_xrdposix_maps_them(
    exc: BaseException, code: int, text: str
) -> None:
    failure = describe(exc)
    assert (failure.code, failure.to_string) == (code, text)
    assert failure.to_str == f"{text}: {exc}"


def test_socket_failures_are_found_down_the_cause_chain() -> None:
    refused = describe(_raised_from(xe.TransientError("x"), ConnectionRefusedError(61, "no")))
    assert (refused.code, refused.to_str) == (61, "[FATAL] Connection error")
    unknown = describe(_raised_from(xe.TransientError("x"), socket.gaierror(8, "who")))
    assert (unknown.code, unknown.to_str) == (errno.EHOSTUNREACH, "[FATAL] Invalid address")
    reset = describe(_raised_from(xe.TransientError("x"), ConnectionResetError(54, "gone")))
    assert (reset.code, reset.to_string) == (54, "[FATAL] Socket error")
    # An OSError without an errno says nothing; the outer error decides.
    bare = describe(_raised_from(xe.ConnectionError("x"), OSError("no errno")))
    assert bare.code == errno.ECONNRESET


def test_a_cause_chain_that_loops_is_walked_once() -> None:
    looped = xe.ConnectionError("x")
    looped.__cause__ = looped
    assert describe(looped).code == errno.ECONNRESET


def test_status_errors_can_name_the_side_of_a_copy() -> None:
    with pytest.raises(xe.XRootDError) as caught:
        xe.raise_for_status(3011, "gone")
    server_side = status_error("P: ", caught.value, strerror=False, end="source")
    assert server_side.message == (
        "P: [ERROR] Server responded with an error: [3011] gone (source)\n"
    )
    local = status_error("P: ", RuntimeError("x"), end="destination", terse=True)
    assert local.message == "P: [ERROR] Unknown error (destination) (Input/output error)"


# -- small pieces ----------------------------------------------------------------------


def test_flags_become_owner_bits_and_a_type_as_xrdposix_has_it() -> None:
    assert flags_to_mode(0x10 | 0x20) == _stat.S_IFREG | 0o600
    assert flags_to_mode(0x02 | 0x10 | 0x20 | 0x01) == _stat.S_IFDIR | 0o700
    assert flags_to_mode(0x04) == _stat.S_IFBLK
    assert flags_to_mode(0x40) == _stat.S_IFREG | _stat.S_ISUID


def test_a_listing_entry_gets_the_reduced_stat() -> None:
    entry = xrdclient.StatInfo(st_size=5, flags=xrdclient.StatInfoFlags(0x10 | 0x20), st_mtime=9)
    assert listing_stat(entry).as_dict() == {
        **xgfalclient.Stat().as_dict(),
        "st_mode": _stat.S_IFREG | 0o666,
        "st_size": 5,
        "st_mtime": 9,
    }
    folder = xrdclient.StatInfo(flags=xrdclient.StatInfoFlags(0x02 | 0x01))
    assert listing_stat(folder).st_mode == _stat.S_IFDIR | 0o111


def test_posix_stat_uses_the_extended_times_when_there_are_some() -> None:
    old = xrdclient.StatInfo(id="12x", st_size=3, st_mtime=100, st_ctime=100, st_atime=100)
    info = posix_stat(old)
    assert (info.st_ino, info.st_nlink, info.st_ctime, info.st_mtime) == (12, 1, 100, 100)
    assert info.st_atime >= int(time.time()) - 5  # XrdPosix: atime is now
    assert (info.st_uid, info.st_gid) == (os.getuid(), os.getgid())
    new = xrdclient.StatInfo(id="x", st_mtime=100, st_ctime=50, st_atime=70, mode_str="0640")
    assert (posix_stat(new).st_ino, posix_stat(new).st_ctime, posix_stat(new).st_atime) == (
        0,
        50,
        70,
    )


def test_uid_and_gid_are_zero_where_the_platform_has_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "getuid")
    monkeypatch.delattr(os, "getgid")
    assert xrootd._ids() == (0, 0)


def test_status_words() -> None:
    assert status_word(0x10) == "ONLINE"
    assert status_word(0x08) == "UNKNOWN"
    assert status_word(0x08 | 0x80) == "NEARLINE"
    assert status_word(0x80) == "ONLINE_AND_NEARLINE"


def test_small_helpers() -> None:
    assert collapse_slashes("//a///b/") == "/a/b/"
    assert local_path("file:///tmp/x") == "/tmp/x"
    assert local_path("file://localhost/tmp/x") == "/tmp/x"
    assert local_path("file://localhost") == "/"
    assert space_json(1, 2, 3, 4) == (
        '{ "totalsize": 1, "unusedsize": 2, "usedsize": 3, "guaranteedsize": 4 }'
    )
    assert xrootd.e2t(errno.ENOENT) == "no such file or directory"


# -- configuration ---------------------------------------------------------------------


def test_the_config_carries_this_contexts_credentials(
    ctx: xgfalclient.Gfal2Context, plugin: XRootDPlugin, grid_env: PKI
) -> None:
    ctx.cred_set("root://h", xgfalclient.cred_new("BEARER", "tok"))
    config = plugin._config("root://h//f")
    assert config.proxy == str(grid_env.proxy_path)
    assert config.token == "tok" and config.token_file is None
    assert config.ca_path == str(grid_env.ca_dir)
    assert config.prompt is False and config.verify_tls and config.data_streams == 0
    assert config.request_timeout == 300.0
    assert plugin._config("root://h//f") is config  # built once per set of inputs


def test_insecure_timeouts_and_wantprot_reach_the_config(
    ctx: xgfalclient.Gfal2Context, plugin: XRootDPlugin
) -> None:
    ctx.set_opt_boolean("XROOTD PLUGIN", "INSECURE", True)
    ctx.set_opt_integer("XROOTD PLUGIN", "OPERATION_TIMEOUT", 7)
    ctx.set_opt_string("XROOTD PLUGIN", "XRD.WANTPROT", "ztn;unix")
    config = plugin._config("root://h//f")
    assert not config.verify_tls and config.request_timeout == 7.0 and config.proxy is None
    assert tuple(config.auth_order) == ("ztn", "unix")
    assert plugin._config("root://h//f", timeout=3).request_timeout == 3.0


def test_gsi_delegation_follows_the_environment(
    plugin: XRootDPlugin, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``XrdSecGSIDELEGPROXY`` (which gfal-copy exports) turns xrdclient's delegation on."""
    assert plugin._config("root://h//f").gsi_delegate is False
    monkeypatch.setenv("XrdSecGSIDELEGPROXY", "1")
    assert plugin._config("root://h//f").gsi_delegate is True


def test_a_separate_certificate_and_key_are_combined_once(
    ctx: xgfalclient.Gfal2Context, plugin: XRootDPlugin, pki: PKI
) -> None:
    cred = X509Credential(str(pki.user_cert_path), str(pki.user_key_path))
    combined = plugin._proxy_for(cred)
    assert plugin._proxy_for(cred) == combined
    body = Path(combined).read_bytes()
    assert b"BEGIN CERTIFICATE" in body and b"PRIVATE KEY" in body
    assert _stat.S_IMODE(os.stat(combined).st_mode) == 0o600
    os.remove(combined)  # closing copes with a file that has already gone
    plugin.close()
    assert plugin._combined == {}


def test_closing_removes_combined_credentials(plugin: XRootDPlugin, pki: PKI) -> None:
    combined = plugin._proxy_for(X509Credential(str(pki.user_cert_path), str(pki.user_key_path)))
    plugin.close()
    assert not os.path.exists(combined)


def test_an_unreadable_key_leaves_no_file_behind(
    plugin: XRootDPlugin, pki: PKI, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(xrootd.tempfile, "tempdir", str(tmp_path))
    with pytest.raises(OSError):
        plugin._proxy_for(X509Credential(str(pki.user_cert_path), str(tmp_path / "missing")))
    assert list(tmp_path.iterdir()) == []


def test_xrd_options_and_url_cgi_reach_every_request(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    ctx.set_opt_string_list("XROOTD PLUGIN", "XRD.APPNAME", ["a", "b"])
    ctx.stat(base + "/data/a%2Etxt?authz=secret")
    # gfal2 turns the raw "a;b;" into "a,b," - trailing separator and all.
    # xrdclient may or may not percent-encode the commas; both mean the same.
    decoded = [(code, urllib.parse.unquote(argument)) for code, argument in server.arguments]
    assert (c.kXR_stat, "/data/a.txt?authz=secret&xrd.appname=a,b,") in decoded


def test_a_missing_option_group_means_no_extra_cgi(
    plugin: XRootDPlugin, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_group(group: str) -> list[str]:
        raise GError("no group", 4)

    monkeypatch.setattr(plugin.options, "keys", no_group)
    assert plugin._extra_cgi() == {}


# -- namespace -------------------------------------------------------------------------


def test_stat_a_file_and_a_directory(ctx: xgfalclient.Gfal2Context, base: str) -> None:
    info = ctx.stat(base + "/data/a.txt")
    assert (info.st_size, info.st_mode, info.st_nlink) == (12, _stat.S_IFREG | 0o600, 1)
    assert info.st_mtime == 1700000000
    assert ctx.lstat(base + "//data/sub").st_mode == _stat.S_IFDIR | 0o600


def test_stat_of_a_missing_file(ctx: xgfalclient.Gfal2Context, base: str) -> None:
    failure = _gerror(ctx.stat, base + "/nothing")
    assert (failure.code, failure.message) == (
        errno.ENOENT,
        "Failed to stat file (No such file or directory)",
    )


def test_a_bad_url_is_einval(ctx: xgfalclient.Gfal2Context) -> None:
    failure = _gerror(ctx.stat, "root://host:notaport//f")
    assert failure.code == errno.EINVAL and failure.message.startswith("Failed to stat file")


def test_an_unreachable_server_is_econnrefused(ctx: xgfalclient.Gfal2Context) -> None:
    ctx.set_opt_integer("XROOTD PLUGIN", "OPERATION_TIMEOUT", 2)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    failure = _gerror(ctx.stat, f"root://127.0.0.1:{port}//f")
    assert failure.code == errno.ECONNREFUSED
    assert failure.message == f"Failed to stat file ({os.strerror(errno.ECONNREFUSED)})"


def test_access_checks_the_owner_bits(ctx: xgfalclient.Gfal2Context, base: str) -> None:
    assert ctx.access(base + "/data/a.txt", os.R_OK | os.W_OK) == 0
    failure = _gerror(ctx.access, base + "/data/a.txt", os.X_OK)
    assert (failure.code, failure.message) == (
        errno.EACCES,
        "Failed to access file or directory (Permission denied)",
    )
    missing = _gerror(ctx.access, base + "/nothing", os.F_OK)
    assert missing.message == "Failed to access file or directory (No such file or directory)"


def test_access_refuses_reading_or_writing_what_the_flags_forbid(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    line = b"1 3 0 1700000000\x00"  # no flags at all
    _ok(server, c.kXR_stat, line)
    assert _gerror(ctx.access, base + "/f", os.R_OK).code == errno.EACCES
    assert _gerror(ctx.access, base + "/f", os.W_OK).code == errno.EACCES
    assert ctx.access(base + "/f", os.F_OK) == 0
    _ok(server, c.kXR_stat, b"1 3 49 1700000000\x00")  # readable, writable, executable
    assert ctx.access(base + "/f", os.R_OK | os.W_OK | os.X_OK) == 0


def test_chmod(ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str) -> None:
    assert ctx.chmod(base + "/data/a.txt", 0o4640) == 0
    assert server.modes["/data/a.txt"] == 0o640
    failure = _gerror(ctx.chmod, base + "/nothing", 0o600)
    assert failure.code == errno.ENOENT
    assert failure.message == (
        "[ERROR] Server responded with an error: [3011] no such file or directory: "
        "/nothing\n (No such file or directory)"
    )


def test_mkdir_makes_parents_and_refuses_what_exists(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    assert ctx.mkdir(base + "/new/deeper", 0o755) == 0
    assert "/new/deeper" in server.dirs
    failure = _gerror(ctx.mkdir, base + "/new/deeper", 0o755)
    assert (failure.code, failure.message) == (
        errno.EEXIST,
        f"Failed to create directory {base}/new/deeper (File exists)",
    )
    assert _gerror(ctx.mkdir, base + "/data/a.txt", 0o755).code == errno.EEXIST


def test_mkdir_with_setuid_does_not_make_parents(ctx: xgfalclient.Gfal2Context, base: str) -> None:
    failure = _gerror(ctx.mkdir, base + "/none/x", 0o4755)
    assert failure.code == errno.ENOENT
    assert (
        failure.message == f"Failed to create directory {base}/none/x (No such file or directory)"
    )


def test_mkdir_reads_cancelled_as_exists(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    _reply(server, c.kXR_mkdir, 3017)
    assert _gerror(ctx.mkdir, base + "/raced", 0o755).code == errno.EEXIST


def test_mkdir_rec_forgives_only_eexist(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    assert ctx.mkdir_rec(base + "/r/s/t", 0o755) == 0
    assert ctx.mkdir_rec(base + "/r/s/t", 0o755) == 0
    assert ctx.mkdir_rec(base + "/data/a.txt", 0o755) == 0  # gfal2 forgives a file too
    _reply(server, c.kXR_mkdir, 3010)
    assert _gerror(ctx.mkdir_rec, base + "/denied", 0o755).code == errno.EACCES


def test_rmdir(ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str) -> None:
    ctx.mkdir(base + "/empty", 0o755)
    assert ctx.rmdir(base + "/empty") == 0
    missing = _gerror(ctx.rmdir, base + "/nothing")
    assert (missing.code, missing.message) == (
        errno.ENOENT,
        "Failed to delete directory (No such file or directory)",
    )
    # The fake answers kXR_NotFound for a file; gfal2 then stats and says ENOTDIR.
    assert _gerror(ctx.rmdir, base + "/data/a.txt").code == errno.ENOTDIR
    # kXR_ItExists, as xrootd says it for "not empty", becomes ENOTEMPTY.
    assert _gerror(ctx.rmdir, base + "/data").code == errno.ENOTEMPTY


@pytest.mark.parametrize(
    ("kxr", "path", "code"),
    [
        (3018, "/data", errno.ENOTEMPTY),
        (3007, "/data", errno.ENOTEMPTY),
        (3007, "/data/a.txt", errno.ENOTDIR),
        (3010, "/data", errno.EACCES),
    ],
)
def test_rmdir_massages_errno_as_gfal2_does(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str, kxr: int, path: str, code: int
) -> None:
    _reply(server, c.kXR_rmdir, kxr)
    failure = _gerror(ctx.rmdir, base + path)
    assert (failure.code, failure.message) == (
        code,
        f"Failed to delete directory ({os.strerror(code)})",
    )


def test_unlink(ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str) -> None:
    assert ctx.unlink(base + "/data/a.txt") == 0
    assert "/data/a.txt" not in server.files
    failure = _gerror(ctx.unlink, base + "/data/a.txt")
    assert failure.message == "Failed to delete file (No such file or directory)"
    (bulk,) = ctx.unlink([base + "/nothing"])
    assert bulk.code == errno.ENOENT


def test_rename(ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str) -> None:
    assert ctx.rename(base + "/data/a.txt", base + "/data/b.txt") == 0
    assert server.contents("/data/b.txt") == HELLO
    failure = _gerror(ctx.rename, base + "/data/a.txt", base + "/data/c.txt")
    assert failure.message == "Failed to rename file or directory (No such file or directory)"


def test_rename_onto_a_directory_is_eisdir(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    _reply(server, c.kXR_mv, 3018)
    failure = _gerror(ctx.rename, base + "/data/a.txt", base + "/data/sub")
    assert (failure.code, failure.message) == (
        errno.EISDIR,
        "Failed to rename file or directory (File exists)",
    )
    assert failure.args == (failure.message, errno.EISDIR)
    other = _gerror(ctx.rename, base + "/data/a.txt", base + "/nowhere")
    assert other.code == errno.EEXIST


def test_links_where_the_server_has_them(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    assert ctx.symlink(base + "/data/a.txt", base + "/data/l1") == 0
    assert ctx.symlink("/data/a.txt", base + "/data/l2") == 0
    assert server.links == {"/data/l1": "/data/a.txt", "/data/l2": "/data/a.txt"}
    assert ctx.readlink(base + "/data/l1") == "/data/a.txt"


@pytest.mark.parametrize("kxr", [3006, 3013])
def test_links_where_the_server_has_not_are_unsupported_as_in_gfal2(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str, kxr: int
) -> None:
    _reply(server, c.kXR_readlink, kxr)
    _reply(server, c.kXR_symlink, kxr)
    failure = _gerror(ctx.readlink, base + "/data/a.txt")
    assert failure.code == errno.EPROTONOSUPPORT
    assert failure.message.startswith("Protocol not supported or path/url invalid")
    assert _gerror(ctx.symlink, "/x", base + "/l").code == errno.EPROTONOSUPPORT


def test_link_errors_are_worded_like_the_rest(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    assert _gerror(ctx.readlink, base + "/nothing").message == (
        "Failed to read link (No such file or directory)"
    )
    _reply(server, c.kXR_symlink, 3010)
    assert _gerror(ctx.symlink, "/x", base + "/l").message == (
        "Failed to create symlink (Permission denied)"
    )


def test_link_operations_on_an_unreachable_server(ctx: xgfalclient.Gfal2Context) -> None:
    ctx.set_opt_integer("XROOTD PLUGIN", "OPERATION_TIMEOUT", 2)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    failure = _gerror(ctx.readlink, f"root://127.0.0.1:{port}//l")
    assert failure.code == errno.ECONNREFUSED
    assert failure.message.startswith("Failed to read link")


# -- listings --------------------------------------------------------------------------


def test_listdir_and_readpp(ctx: xgfalclient.Gfal2Context, base: str) -> None:
    assert sorted(ctx.listdir(base + "/data")) == ["a.txt", "sub"]
    directory = ctx.opendir(base + "/data")
    seen = {}
    while True:
        entry, info = directory.readpp()
        if entry is None:
            break
        seen[entry.d_name] = (entry.d_type, info.st_mode, info.st_size, info.st_nlink)
    assert seen == {
        "a.txt": (8, _stat.S_IFREG | 0o666, 12, 0),
        "sub": (4, _stat.S_IFDIR | 0o666, 4096, 0),
    }


def test_listing_a_file_or_nothing(ctx: xgfalclient.Gfal2Context, base: str) -> None:
    not_dir = _gerror(ctx.listdir, base + "/data/a.txt")
    assert (not_dir.code, not_dir.message) == (errno.ENOTDIR, "Not a directory (Not a directory)")
    missing = _gerror(ctx.listdir, base + "/nothing")
    assert missing.message == "Failed to stat file (No such file or directory)"


def test_a_listing_the_server_refuses(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    _reply(server, c.kXR_dirlist, 3010)
    failure = _gerror(ctx.listdir, base + "/data")
    assert (failure.code, failure.message) == (
        errno.EACCES,
        "Failed to open dir: [ERROR] Error response: permission denied (Permission denied)",
    )


def test_entries_without_stat_are_stat_ed_one_by_one(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    _ok(server, c.kXR_dirlist, b"a.txt\nsub\x00")  # a server that ignores kXR_dstat
    directory = ctx.opendir(base + "/data")
    first, info = directory.readpp()
    assert (first.d_name, info.st_size) == ("a.txt", 12)
    _ok(server, c.kXR_dirlist, b"gone\x00")
    failure = _gerror(ctx.listdir, base + "/data")
    assert failure.message == (
        "Failed reading directory: [ERROR] Error response: no such file or directory "
        "(No such file or directory)"
    )


def test_a_listing_with_entries_is_one_round_trip(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    ctx.stat(base + "/data")
    server.seen.clear()
    assert sorted(ctx.listdir(base + "/data")) == ["a.txt", "sub"]
    assert server.seen == [c.kXR_dirlist]  # no stat first, and the connection is kept


def test_an_empty_directory_is_stat_ed_to_prove_it_is_one(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    server.add_dir("/data/empty")
    assert ctx.listdir(base + "/data/empty") == []
    assert ctx.opendir(base + "/data/empty").readpp() == (None, None)
    assert server.seen[-2:] == [c.kXR_dirlist, c.kXR_stat]


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        (b".\n0 0 0 0\nbad/name\n1 2 3 4\x00", "kXR_dirlist entry 'bad/name'"),
        (b".\n0 0 0 0\nshort\n1 2\x00", "kXR_stat returned 2 fields"),
        (b"../up\x00", "kXR_dirlist entry '../up'"),
        (b"..\x00", "kXR_dirlist entry '..'"),
    ],
)
def test_a_listing_that_makes_no_sense_is_refused(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str, body: bytes, detail: str
) -> None:
    _ok(server, c.kXR_dirlist, body)
    for call in (ctx.listdir, lambda url: ctx.opendir(url).readpp()):
        failure = _gerror(call, base + "/data")
        assert failure.code == errno.EPROTO
        assert failure.message == "Failed to open dir: [FATAL] Invalid message (Protocol error)"
        assert detail in str(failure.__cause__)


def test_listings_are_read_as_xrdclient_reads_them() -> None:
    from xrdclient.proto import responses

    body = (
        b".\n0 0 0 0\nf1\n123 42 16 1700000000 1700000001 1700000002 0644 u g\n"
        b"d\n77 4096 50 1600000000\n.\n0 0 0 0\n\x00junk"
    )
    theirs = [
        (entry.name, xrootd._brief(entry.stat))
        for entry in responses.parse_dirlist(body, "/p")
        if entry.stat is not None
    ]
    assert [name for name, _ in theirs] == ["f1", "d"]
    assert xrootd.parse_listing(body, "/p") == theirs
    assert xrootd.parse_listing(body, "/p", brief=False) == [
        (name, xrootd._UNREAD) for name, _ in theirs
    ]
    assert xrootd.parse_listing(b"a\nb\n\x00", "/p") == [("a", None), ("b", None)]


def test_a_filesystem_without_a_router_is_listed_through_scandir() -> None:
    info = SimpleNamespace(flags=0x10, st_size=5, st_mtime=7)
    entries = [SimpleNamespace(name="a", stat=info), SimpleNamespace(name="b", stat=None)]
    fs: Any = SimpleNamespace(scandir=lambda path: entries)
    assert xrootd._dirlist(fs, "/d", brief=True) == [("a", (0x10, 5, 7)), ("b", None)]


# -- connections -----------------------------------------------------------------------


def test_filesystems_are_kept_between_calls(
    ctx: xgfalclient.Gfal2Context, plugin: XRootDPlugin, server: FakeServer, base: str
) -> None:
    ctx.stat(base + "/data/a.txt")
    server.seen.clear()
    ctx.stat(base + "/data/a.txt")
    ctx.stat(base + "/data/a.txt")
    assert server.seen == [c.kXR_stat, c.kXR_stat]
    assert [len(kept) for kept in plugin._idle.values()] == [1]
    assert _gerror(ctx.stat, base + "/nothing").code == errno.ENOENT
    assert [len(kept) for kept in plugin._idle.values()] == [1]  # an answer is no failure


def test_only_so_many_filesystems_are_kept(
    ctx: xgfalclient.Gfal2Context,
    plugin: XRootDPlugin,
    base: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(xrootd, "IDLE_ENDPOINTS", 0)
    assert ctx.stat(base + "/data/a.txt").st_size == 12
    assert plugin._idle == {}
    monkeypatch.setattr(xrootd, "IDLE_ENDPOINTS", 1)
    monkeypatch.setattr(xrootd, "IDLE_PER_ENDPOINT", 0)
    assert ctx.stat(base + "/data/a.txt").st_size == 12
    assert [len(kept) for kept in plugin._idle.values()] == [0]


def test_nothing_is_kept_where_pooling_is_off(
    ctx: xgfalclient.Gfal2Context,
    plugin: XRootDPlugin,
    base: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XRD_POOLSIZE", "0")
    assert ctx.stat(base + "/data/a.txt").st_size == 12
    assert ctx.stat(base + "/data/a.txt").st_size == 12
    assert plugin._idle == {}


def test_an_idle_filesystem_goes_stale(
    ctx: xgfalclient.Gfal2Context, plugin: XRootDPlugin, base: str
) -> None:
    ctx.stat(base + "/data/a.txt")
    [(key, kept)] = plugin._idle.items()
    old = kept[0][1]
    kept[:] = [(float("-inf"), old)]
    assert ctx.stat(base + "/data/a.txt").st_size == 12
    assert plugin._idle[key][0][1] is not old


def test_a_forked_child_forgets_its_parents_filesystems(
    ctx: xgfalclient.Gfal2Context, plugin: XRootDPlugin, base: str
) -> None:
    ctx.stat(base + "/data/a.txt")
    [kept] = plugin._idle.values()
    parents = kept[0][1]
    plugin._pid = -1  # as if this were the child
    assert ctx.stat(base + "/data/a.txt").st_size == 12
    assert plugin._pid == os.getpid()
    [kept] = plugin._idle.values()
    assert kept[0][1] is not parents
    parents.close()


def test_parsed_urls_are_remembered_but_not_forever(
    ctx: xgfalclient.Gfal2Context,
    plugin: XRootDPlugin,
    base: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx.stat(base + "/data/a.txt")
    assert len(plugin._targets) == 1
    monkeypatch.setattr(xrootd, "TARGET_CACHE", 1)
    ctx.stat(base + "/data/sub")
    assert len(plugin._targets) == 1


# -- files -----------------------------------------------------------------------------


def test_reading_as_gfal2_does(ctx: xgfalclient.Gfal2Context, base: str) -> None:
    handle = ctx.open(base + "/data/a.txt", "r")
    assert handle.read_bytes(4) == b"hell"
    assert handle.read_bytes(100) == b"o world\n"
    assert handle.read_bytes(10) == b""
    assert handle.lseek(2, os.SEEK_SET) == 2
    assert handle.pread_bytes(6, 3) == b"wor"
    assert handle.read_bytes(2) == b"ld"  # pread left the cursor after itself
    assert handle.lseek(-2, os.SEEK_END) == 10
    buffer = bytearray(8)
    assert handle.readinto(buffer) == 2 and buffer[:2] == b"d\n"
    failure = _gerror(handle.write, "x")
    assert (failure.code, failure.message) == (
        errno.EBADF,
        "Failed while writing to file (Bad file descriptor)",
    )
    handle.close()
    handle.close()


def test_writing_creates_parents_and_truncates(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    with ctx.open(base + "/deep/er/f", "w") as handle:
        assert handle.write(b"0123456789") == 10
        assert handle.pwrite(b"AB", 4) == 2
    assert server.contents("/deep/er/f") == b"0123AB6789"
    with ctx.open(base + "/deep/er/f", "rw") as handle:
        assert handle.read_bytes(3) == b""  # O_CREAT without O_EXCL is kXR_delete
        handle.write(b"xy")
    assert server.contents("/deep/er/f") == b"xy"


def test_open_flags_as_xrdposix_translates_them(
    plugin: XRootDPlugin, server: FakeServer, base: str
) -> None:
    exclusive = _gerror(plugin.open, base + "/data/a.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    assert (exclusive.code, exclusive.message) == (
        errno.EEXIST,
        "Failed to open file (File exists)",
    )
    truncating = plugin.open(base + "/data/a.txt", os.O_WRONLY | os.O_TRUNC)
    truncating.close()
    assert server.contents("/data/a.txt") == b""
    appending = plugin.open(base + "/data/a.txt", os.O_WRONLY)
    appending.write(b"abc")
    appending.close()
    reading = plugin.open(base + "/data/a.txt", os.O_RDONLY | os.O_TRUNC)  # O_TRUNC is ignored
    reading.close()
    assert server.contents("/data/a.txt") == b"abc"
    missing = _gerror(plugin.open, base + "/nothing", os.O_RDONLY)
    assert missing.message == "Failed to open file (No such file or directory)"


def test_io_failures_are_worded_per_call(
    plugin: XRootDPlugin, server: FakeServer, base: str
) -> None:
    reader = plugin.open(base + "/data/a.txt", os.O_RDONLY)
    writer = plugin.open(base + "/data/w", os.O_WRONLY | os.O_CREAT)
    writer.write(b"ok")  # the handle now has to ask for its size
    _reply(server, c.kXR_read, 3007)
    _reply(server, c.kXR_write, 3009)
    _reply(server, c.kXR_stat, 3007)
    _reply(server, c.kXR_close, 3007)
    assert _gerror(reader.read, 3).message == "Failed while reading from file (Input/output error)"
    assert _gerror(reader.readinto, bytearray(3)).code == errno.EIO
    assert _gerror(writer.write, b"x").message == (
        "Failed while writing to file (No space left on device)"
    )
    assert _gerror(writer.lseek, 0, os.SEEK_END).message == (
        "Failed to seek within file (Input/output error)"
    )
    assert _gerror(writer.close).message == "Failed to close file (Input/output error)"
    assert writer.closed
    server.handlers.clear()
    reader.close()
    reader.close()  # closing twice is closing once


# -- checksums and attributes ----------------------------------------------------------


def test_checksums(ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str) -> None:
    url = base + "/data/a.txt"
    assert ctx.checksum(url, "ADLER32") == ADLER_HELLO
    assert ctx.checksum(url, "md5") == "6f5902ac237024bdd0c176cb93063dc4"
    assert (c.kXR_query, "/data/a.txt?cks.type=adler32") in server.arguments
    ctx.checksum(url, "CRC32C")
    assert (c.kXR_query, "/data/a.txt?cks.type=CRC32C") in server.arguments


def test_checksum_failures(ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str) -> None:
    url = base + "/data/a.txt"
    partial = _gerror(ctx.checksum, url, "adler32", 1, 2)
    assert (partial.code, partial.message) == (
        errno.ENOTSUP,
        f"XROOTD does not support partial checksums ({os.strerror(errno.ENOTSUP)})",
    )
    assert _gerror(ctx.checksum, url, "adler32", 0, 5).code == errno.ENOTSUP  # a prefix, too
    assert _gerror(ctx.checksum, base + "/nothing", "adler32").message == (
        "Could not get the checksum (No such file or directory)"
    )
    _ok(server, c.kXR_query, b"adler32\x00")
    assert _gerror(ctx.checksum, url, "adler32").message == (
        "Could not get the checksum (Wrong format)"
    )
    _ok(server, c.kXR_query, b"md5 abc\x00")
    assert _gerror(ctx.checksum, url, "adler32").message == "Got 'md5' while expecting 'adler32'"


def test_listxattr_is_gfal2s_fixed_list(ctx: xgfalclient.Gfal2Context, base: str) -> None:
    assert ctx.listxattr(base + "/anything") == [
        "xroot.cksum",
        "xroot.space",
        "xroot.xattr",
        "spacetoken",
    ]


def test_setxattr_is_not_implemented(ctx: xgfalclient.Gfal2Context, base: str) -> None:
    failure = _gerror(ctx.setxattr, base + "/data/a.txt", "user.x", "1", 0)
    assert (failure.code, failure.message) == (
        errno.ENOSYS,
        "Can not set extended attributes (Function not implemented)",
    )


def test_getxattr(ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str) -> None:
    url = base + "/data/a.txt"
    assert ctx.getxattr(url, "xroot.cksum") == f"adler32 {ADLER_HELLO}"
    assert ctx.getxattr(url, "xroot.space") == server.space
    assert json.loads(ctx.getxattr(url, "spacetoken")) == {
        "totalsize": 2000000,
        "unusedsize": 1500000,
        "usedsize": 500000,
        "guaranteedsize": 1400000,
    }
    assert ctx.getxattr(url, "user.status") == "ONLINE"
    server.nearline.add("/data/a.txt")
    assert ctx.getxattr(url, "user.status") == "UNKNOWN"


def test_getxattr_failures(ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str) -> None:
    url = base + "/data/a.txt"
    unknown = _gerror(ctx.getxattr, url, "user.foo")
    assert (unknown.code, unknown.message) == (
        xrootd.ENOATTR,
        f'Failed to get the xattr "user.foo" ({os.strerror(xrootd.ENOATTR)})',
    )
    # The fake has no kXR_Qxattr, and says so.
    assert _gerror(ctx.getxattr, url, "xroot.xattr").code == errno.ENOTSUP
    assert _gerror(ctx.getxattr, base + "/nothing", "xroot.cksum").message == (
        'Failed to get the xattr "xroot.cksum" (No such file or directory)'
    )
    _reply(server, c.kXR_stat, 3010)
    status = _gerror(ctx.getxattr, url, "user.status")
    assert (status.code, status.message) == (
        errno.ENOENT,
        'Failed to get the xattr "user.status" (No such file or directory)',
    )
    _reply(server, c.kXR_query, 3010, "go away")
    space = _gerror(ctx.getxattr, url, "spacetoken")
    assert (space.code, space.message) == (
        errno.EIO,
        "Failed to get the space information: go away",
    )


# -- tape ------------------------------------------------------------------------------


def test_bring_online_queues_and_the_poll_answers(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    status, token = ctx.bring_online(base + "/data/a.txt?x=1", 60, 30, True)
    assert (status, token) == (0, "prep-0001")
    assert server.prepared == {"prep-0001": ["/data/a.txt"]}
    assert ctx.bring_online_poll(base + "/data/a.txt", token) == 1
    results = ctx.bring_online_poll([base + "/data/a.txt", base + "/data/zz"], token)
    assert results[0] is None
    assert (results[1].code, results[1].message) == (
        errno.ENOENT,
        "File does not exist: /data/zz (reason: no such file)",
    )
    listing, token = ctx.bring_online([base + "/data/a.txt"], ["{}"], 60, 30, True)
    assert listing == [None]


def test_bring_online_failures(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    _reply(server, c.kXR_prepare, 3011)
    failure = _gerror(ctx.bring_online, base + "/nothing", 60, 30, True)
    assert (failure.code, failure.message) == (
        errno.ENOENT,
        "Bringonline request failed. One or more files failed with: "
        "[ERROR] Error response: no such file or directory",
    )
    _ok(server, c.kXR_prepare, b"\x00")
    empty = _gerror(ctx.bring_online, base + "/data/a.txt", 60, 0, True)
    assert empty.code == errno.ENOMSG


def test_a_poll_the_server_refuses(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str
) -> None:
    failure = _gerror(ctx.bring_online_poll, base + "/data/a.txt", "unknown")
    assert (failure.code, failure.message) == (
        errno.EINVAL,
        "[ERROR] Error response: invalid argument",
    )


def test_a_poll_that_cannot_connect_is_ecomm(ctx: xgfalclient.Gfal2Context) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    results = ctx.archive_poll([f"root://127.0.0.1:{port}//f"])
    assert results[0].code == xgfalclient.errors.ECOMM


def test_archive_poll(ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str) -> None:
    def answer(conn: Any, sid: int, params: bytes, body: bytes) -> Iterator[bytes]:
        token, *paths = body.split(b"\x00", 1)[0].decode().split("\n")
        responses = [
            {"path": p, "path_exists": True, "on_tape": p == "/data/t", "error_text": ""}
            for p in paths
        ]
        doc = {"request_id": token, "responses": responses}
        yield frame(sid, c.kXR_ok, json.dumps(doc).encode() + b"\x00")

    server.handlers[c.kXR_query] = answer
    assert ctx.archive_poll(base + "//data/t") == 1
    waiting = ctx.archive_poll([base + "/data/t", base + "/data/a.txt"])
    assert waiting[0] is None and waiting[1].code == errno.EAGAIN


def test_release_and_abort(ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str) -> None:
    assert ctx.release(base + "/data/a.txt") == 0
    assert server.evicted == ["/data/a.txt"]
    assert ctx.abort_bring_online([base + "/data/a.txt"], "prep-0001") == [None]
    # gfal2 names the files after the request id: withdraw these, not the lot.
    assert server.cancelled_prepares == ["prep-0001\n/data/a.txt"]
    _reply(server, c.kXR_prepare, 3010)
    assert ctx.release([base + "/data/a.txt"], "")[0].message == (
        "[ERROR] Error response: permission denied"
    )
    assert ctx.abort_bring_online([base + "/data/a.txt"], "t")[0].code == errno.EACCES


def _doc(*responses: dict[str, Any], request_id: str = "tok") -> str:
    return json.dumps({"request_id": request_id, "responses": list(responses)})


def test_poll_documents_are_judged_as_gfal2_judges_them() -> None:
    paths = ["/f"]
    judged = parse_prepare_status("No information found.", "tok", paths, archive=False)
    assert judged[0].message == "Response from server is an invalid JSON: No information found."
    assert parse_prepare_status("[]", "tok", paths, archive=False)[0].code == errno.ENOMSG
    assert parse_prepare_status(_doc(request_id="x"), "tok", paths, archive=False)[0].message == (
        "Request ID mismatch."
    )
    no_id = json.dumps({"responses": []})
    assert parse_prepare_status(no_id, "tok", paths, archive=False)[0].message == (
        "Request ID mismatch."
    )
    not_a_list = json.dumps({"request_id": "tok", "responses": {"/f": {}}})
    assert parse_prepare_status(not_a_list, "tok", paths, archive=False)[0].message == (
        "Number of files in the request does not match!"
    )
    assert parse_prepare_status(_doc(), "tok", paths, archive=False)[0].message == (
        "Number of files in the request does not match!"
    )
    assert parse_prepare_status(_doc(), "tok", paths, archive=True)[0].message == (
        "Number of files in the request doest not match!"
    )


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (7, "Failed to parse responses JSON from server"),
        ({"path": "/f"}, "Error attribute missing."),
        ({"path": "/g", "error_text": "why"}, "Wrong path: /g (reason: why)"),
        ({"error_text": "why"}, "Wrong path:  (reason: why)"),
        ({"path": "//f", "error_text": ""}, "File does not exist: /f"),
        ({"path": "/f", "exists": True, "error_text": "", "online": True}, True),
        ({"path": "/f", "path_exists": "TRUE", "error_text": ""}, "File is not being brought"),
        (
            {"path": "/f", "path_exists": True, "error_text": "", "requested": True},
            "File (/f) is not included in the bring online request: tok",
        ),
        (
            {
                "path": "/f",
                "path_exists": 1,
                "exists": True,
                "error_text": "",
                "requested": True,
                "has_reqid": True,
            },
            "Bring-online timestamp missing.",
        ),
        (
            {
                "path": "/f",
                "path_exists": True,
                "error_text": "tape on fire",
                "requested": True,
                "has_reqid": True,
                "req_time": "now",
            },
            "tape on fire",
        ),
        (
            {
                "path": "/f",
                "path_exists": True,
                "error_text": None,
                "requested": True,
                "has_reqid": True,
                "req_time": "now",
            },
            False,
        ),
    ],
)
def test_one_staging_entry(entry: Any, expected: Any) -> None:
    (result,) = parse_prepare_status(_doc(entry), "tok", ["/f"], archive=False)
    if isinstance(expected, bool):
        assert result is expected
    else:
        assert isinstance(result, GError) and result.message.startswith(expected)


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ({"path": "/f", "exists": True, "error_text": ""}, "File does not exist: /f"),
        ({"path": "/f", "path_exists": True, "on_tape": True, "error_text": "x"}, True),
        ({"path": "/f", "path_exists": True, "error_text": "not yet"}, "not yet"),
        ({"path": "/f", "path_exists": True, "error_text": ""}, False),
    ],
)
def test_one_archive_entry(entry: Any, expected: Any) -> None:
    (result,) = parse_prepare_status(_doc(entry), "tok", ["/f"], archive=True)
    if isinstance(expected, bool):
        assert result is expected
    else:
        assert isinstance(result, GError) and result.message.startswith(expected)


# -- copies ----------------------------------------------------------------------------


def test_copy_check_claims_what_gfal2s_does(plugin: XRootDPlugin) -> None:
    assert plugin.copy_check("root://a//f", "roots://b//f")
    assert plugin.copy_check("xroot://a//f", "file:///tmp/f")
    assert plugin.copy_check("file:///tmp/f", "xroots://b//f")
    assert not plugin.copy_check("root://a//f", "davs://b/f")
    assert not plugin.copy_check("davs://a/f", "root://b//f")
    assert not plugin.copy_check("file:///a", "file:///b")


def _events(params: Any) -> list[tuple[int, str, str, str]]:
    seen: list[tuple[int, str, str, str]] = []
    params.event_callback = lambda e: seen.append((e.side, e.domain, e.stage, e.description))
    return seen


def test_upload_and_download(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str, tmp_path: Path
) -> None:
    payload = os.urandom(3 << 20)
    (tmp_path / "src").write_bytes(payload)
    params = ctx.transfer_parameters()
    seen = _events(params)
    params.set_checksum(checksum_mode.both, "adler32", "")
    ctx.filecopy(params, f"file://{tmp_path}/src", base + "/up/loaded")
    assert server.contents("/up/loaded") == payload
    assert (2, "xroot", "TRANSFER:TYPE", "streamed") in seen
    params = ctx.transfer_parameters()
    params.nbstreams = 3
    ctx.filecopy(params, base + "/up/loaded", f"file://{tmp_path}/back")
    assert (tmp_path / "back").read_bytes() == payload


def _small_chunks(monkeypatch: pytest.MonkeyPatch) -> bytes:
    monkeypatch.setattr(xrootd, "UPLOAD_CHUNK", 4096)
    return os.urandom(10 * 4096 + 123)


def test_an_upload_keeps_several_writes_in_flight(
    ctx: xgfalclient.Gfal2Context,
    server: FakeServer,
    base: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _small_chunks(monkeypatch)
    (tmp_path / "src").write_bytes(payload)
    ctx.filecopy(ctx.transfer_parameters(), f"file://{tmp_path}/src", base + "/up/many")
    assert server.contents("/up/many") == payload
    assert server.seen.count(c.kXR_write) == 11
    assert ctx.stat(base + "/up/many").st_size == len(payload)  # the connection is fine


def test_writes_the_server_asks_to_wait_for_are_made_again(
    ctx: xgfalclient.Gfal2Context,
    server: FakeServer,
    base: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _small_chunks(monkeypatch)
    (tmp_path / "src").write_bytes(payload)
    server.waits[c.kXR_write] = 2
    ctx.filecopy(ctx.transfer_parameters(), f"file://{tmp_path}/src", base + "/up/waited")
    assert server.contents("/up/waited") == payload
    assert server.seen.count(c.kXR_write) == 13


def test_a_write_the_server_refuses_fails_the_upload(
    ctx: xgfalclient.Gfal2Context,
    server: FakeServer,
    base: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(xrootd, "UPLOAD_CHUNK", 4096)
    (tmp_path / "src").write_bytes(os.urandom(64 * 4096))  # more than the reader reads ahead
    _reply(server, c.kXR_write, 3009, "no room")
    failure = _gerror(
        ctx.filecopy, ctx.transfer_parameters(), f"file://{tmp_path}/src", base + "/up/full"
    )
    assert (failure.code, failure.message) == (
        errno.ENOSPC,
        "Failed while writing to file (No space left on device)",
    )
    assert server.seen.count(c.kXR_write) == 4  # what was in flight, and no more
    assert ctx.stat(base + "/data/a.txt").st_size == 12


def test_a_source_that_cannot_be_read_fails_the_upload(
    ctx: xgfalclient.Gfal2Context,
    server: FakeServer,
    base: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _small_chunks(monkeypatch)
    (tmp_path / "src").write_bytes(payload)
    from xgfalclient.plugins import file as local

    real = local.LocalFile.readinto
    calls: list[int] = []

    def flaky(self: Any, buffer: Any) -> int:
        calls.append(1)
        if len(calls) > 2:
            raise OSError(errno.EIO, "bad sector")
        return real(self, buffer)

    monkeypatch.setattr(local.LocalFile, "readinto", flaky)
    failure = _gerror(
        ctx.filecopy, ctx.transfer_parameters(), f"file://{tmp_path}/src", base + "/up/bad"
    )
    assert failure.code == errno.EIO
    assert "bad sector" in failure.message
    assert ctx.stat(base + "/data/a.txt").st_size == 12


def test_a_reply_no_write_expects_breaks_the_connection(
    ctx: xgfalclient.Gfal2Context,
    server: FakeServer,
    base: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _small_chunks(monkeypatch)
    (tmp_path / "src").write_bytes(payload)
    server.redirects[c.kXR_write] = ("127.0.0.1", 1, "")
    failure = _gerror(
        ctx.filecopy, ctx.transfer_parameters(), f"file://{tmp_path}/src", base + "/up/odd"
    )
    assert failure.code == errno.EPROTO
    assert "unexpected reply to a write" in failure.message
    assert ctx.stat(base + "/data/a.txt").st_size == 12  # on a connection of its own


def test_an_upload_goes_one_write_at_a_time_where_it_cannot_borrow_the_wire(
    ctx: xgfalclient.Gfal2Context,
    server: FakeServer,
    base: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = os.urandom(5000)
    (tmp_path / "src").write_bytes(payload)
    monkeypatch.setattr(xrootd._Upload, "usable", staticmethod(lambda handle: False))
    ctx.filecopy(ctx.transfer_parameters(), f"file://{tmp_path}/src", base + "/up/plain")
    assert server.contents("/up/plain") == payload


def test_a_signing_session_is_not_borrowed() -> None:
    def handle(signer: object) -> Any:
        session = SimpleNamespace(
            machine=SimpleNamespace(signer=signer, lease_sids=1, release_sids=1),
            bulk=1,
            transport=1,
            mark_broken=1,
        )
        return SimpleNamespace(session=session, handle=b"\x00" * 4)

    assert xrootd._Upload.usable(handle(None))
    assert not xrootd._Upload.usable(handle(object()))


def test_a_session_without_the_bulk_api_is_not_borrowed() -> None:
    machine = SimpleNamespace(signer=None, lease_sids=1, release_sids=1)
    older = SimpleNamespace(machine=SimpleNamespace(signer=None), bulk=1, transport=1)
    assert not xrootd._Upload.usable(SimpleNamespace(session=older, handle=b"\x00" * 4))
    no_bulk = SimpleNamespace(machine=machine, transport=1, mark_broken=1)
    assert not xrootd._Upload.usable(SimpleNamespace(session=no_bulk, handle=b"\x00" * 4))


def test_an_upload_that_cannot_settle_its_connection_says_so() -> None:
    upload: Any = object.__new__(xrootd._Upload)
    upload.torn, upload.inflight = False, {1: (0, 1)}

    def lost() -> None:
        raise ConnectionError("gone")

    upload._collect = lost
    assert upload._settle() is False
    upload.wire = SimpleNamespace(receive_into=lambda view: 0)
    with pytest.raises(xe.ConnectionError):
        upload._receive(8)


def test_an_upload_refuses_a_reply_to_a_write_it_did_not_send() -> None:
    upload: Any = object.__new__(xrootd._Upload)
    upload.inflight = {1: (0, 1)}
    pending = bytearray(xrootd._RESPONSE_HEADER.pack(7, 0, 0))  # stream 7: never used

    def receive_into(view: memoryview) -> int:
        count = min(len(view), len(pending))
        view[:count] = pending[:count]
        del pending[:count]
        return count

    upload.wire = SimpleNamespace(receive_into=receive_into)
    with pytest.raises(xe.ProtocolError, match="stream 7"):
        upload._collect()
    assert upload.torn and upload.inflight == {1: (0, 1)}


def test_an_upload_that_comes_up_short_fails(
    ctx: xgfalclient.Gfal2Context, base: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "src").write_bytes(b"abc")
    monkeypatch.setattr(XRootDPlugin, "_upload_serially", lambda *args: 1)
    failure = _gerror(
        ctx.filecopy, ctx.transfer_parameters(), f"file://{tmp_path}/src", base + "/s"
    )
    assert (failure.code, failure.message) == (
        errno.EIO,
        "Short copy: 1 bytes transferred, the source has 3",
    )


def test_a_download_of_a_missing_file(
    ctx: xgfalclient.Gfal2Context, base: str, tmp_path: Path
) -> None:
    params = ctx.transfer_parameters()
    seen = _events(params)
    failure = _gerror(ctx.filecopy, params, base + "/nothing", f"file://{tmp_path}/x")
    assert failure.code == errno.ENOENT
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Server responded with an error: [3011] "
        "no such file or directory: /nothing (source)\n"
    )
    assert (1, "xroot", "CLEANUP", "0") in seen
    assert (
        2,
        "xroot",
        "TRANSFER:EXIT",
        "Job finished, [ERROR] Server responded with an error: [3011] "
        "no such file or directory: /nothing (source)\n",
    ) in seen


def test_a_download_makes_its_local_directory(
    ctx: xgfalclient.Gfal2Context, base: str, tmp_path: Path
) -> None:
    ctx.filecopy(ctx.transfer_parameters(), base + "/data/a.txt", f"file://{tmp_path}/no/x")
    assert (tmp_path / "no" / "x").read_bytes() == HELLO  # as XrdCl makes it, unasked


def test_a_local_destination_that_cannot_be_made(
    ctx: xgfalclient.Gfal2Context, base: str, tmp_path: Path
) -> None:
    (tmp_path / "file").write_bytes(b"")
    params = ctx.transfer_parameters()
    seen = _events(params)
    failure = _gerror(ctx.filecopy, params, base + "/data/a.txt", f"file://{tmp_path}/file/x")
    assert failure.code == errno.ENOTDIR
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Local error: not a directory:  (destination)"
    )
    assert (1, "xroot", "CLEANUP", str(errno.ENOTDIR)) in seen
    # XrdCl opens the source first: when both are wrong, the source is the news.
    failure = _gerror(ctx.filecopy, params, base + "/nothing", f"file://{tmp_path}/file/x")
    assert failure.code == errno.ENOENT
    assert failure.message.endswith("no such file or directory: /nothing (source)\n")


def test_a_download_onto_an_existing_file_needs_overwrite(
    ctx: xgfalclient.Gfal2Context, base: str, tmp_path: Path
) -> None:
    (tmp_path / "x").write_bytes(b"keep me")
    params = ctx.transfer_parameters()
    seen = _events(params)
    failure = _gerror(ctx.filecopy, params, base + "/data/a.txt", f"file://{tmp_path}/x")
    assert failure.code == errno.EEXIST
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Local error: file exists:  (destination)"
    )
    # gfal2 reports 3018 here, fails to recognise it as EEXIST and deletes the
    # file it refused to overwrite; the file is kept, and nothing is cleaned.
    assert (tmp_path / "x").read_bytes() == b"keep me"
    assert not [event for event in seen if event[2] == "CLEANUP"]


def test_a_download_into_a_sink(ctx: xgfalclient.Gfal2Context, base: str) -> None:
    ctx.filecopy(ctx.transfer_parameters(), base + "/data/a.txt", "file:///dev/null")
    params = ctx.transfer_parameters()
    seen = _events(params)
    assert _gerror(ctx.filecopy, params, base + "/nothing", "file:///dev/null").code == 2
    assert not [event for event in seen if event[2] == "CLEANUP"]  # never unlinked


def test_a_destination_error_without_an_errno(
    ctx: xgfalclient.Gfal2Context, base: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = str(tmp_path / "x")
    real_open = os.open

    def fake_open(path: str, *args: Any, **kwargs: Any) -> int:
        if path == target:
            raise OSError("the disk said no")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", fake_open)
    params = ctx.transfer_parameters()
    params.transfer_cleanup = False
    failure = _gerror(ctx.filecopy, params, base + "/data/a.txt", "file://" + target)
    assert failure.code == errno.EIO
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Local error: input/output error:  "
        "(destination)"
    )


def test_a_download_without_the_bulk_plane_goes_one_request_at_a_time(
    ctx: xgfalclient.Gfal2Context, base: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from xrdclient.client import bulk

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise bulk.BulkUnsupported("not here")

    monkeypatch.setattr(bulk, "download", refuse)
    (tmp_path / "x").write_bytes(b"stale bytes that must go away")
    params = ctx.transfer_parameters()
    params.overwrite = True
    ctx.filecopy(params, base + "/data/a.txt", f"file://{tmp_path}/x")
    assert (tmp_path / "x").read_bytes() == HELLO


def test_a_cancelled_download_stops(
    ctx: xgfalclient.Gfal2Context,
    server: FakeServer,
    base: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server.add_file("/big", os.urandom(8 << 20))
    monkeypatch.setattr("xgfalclient.transfer.MONITOR_INTERVAL", 0.0)  # report at once
    params = ctx.transfer_parameters()
    params.monitor_callback = lambda *args: ctx.cancel()
    params.nbstreams = 1
    failure = _gerror(ctx.filecopy, params, base + "/big", f"file://{tmp_path}/big")
    assert failure.code == errno.ECANCELED


def test_spacetokens_travel_as_svcclass(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str, tmp_path: Path
) -> None:
    (tmp_path / "src").write_bytes(b"abc")
    params = ctx.transfer_parameters()
    params.dst_spacetoken = "T0"
    ctx.filecopy(params, f"file://{tmp_path}/src", base + "/st")
    assert "/st?svcClass=T0" in server.opened


def test_evicting_the_source_after_a_copy(
    ctx: xgfalclient.Gfal2Context,
    plugin: XRootDPlugin,
    server: FakeServer,
    base: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    params = ctx.transfer_parameters()
    params.evict = True
    seen = _events(params)
    ctx.filecopy(params, base + "/data/a.txt", f"file://{tmp_path}/a")
    assert server.evicted == ["/data/a.txt"]
    assert (0, "xroot", "EVICT", "0") in seen
    monkeypatch.setattr(XRootDPlugin, "release", lambda self, urls, token: [GError("x", 1)])
    params.overwrite = True
    ctx.filecopy(params, base + "/data/a.txt", f"file://{tmp_path}/a")
    assert (0, "xroot", "EVICT", "-1") in seen
    (tmp_path / "up").write_bytes(b"u")
    ctx.filecopy(params, f"file://{tmp_path}/up", base + "/up")
    assert seen.count((0, "xroot", "EVICT", "-1")) == 2  # gfal2 tries a local one, and fails


# -- third-party copies ----------------------------------------------------------------


class Puller:
    """Make a :class:`FakeServer` act on the ``XrdOucTPC`` rendezvous.

    The destination's second ``kXR_sync`` on a handle opened with ``tpc.src``
    is the moment a real server pulls; this one copies the bytes out of the
    source fake instead, optionally slowly, and optionally not at all.
    """

    def __init__(self, source: FakeServer, target: FakeServer, delay: float = 0.0) -> None:
        self.source = source
        self.delay = delay
        self.syncs: dict[bytes, int] = {}
        target.handlers[c.kXR_sync] = self.sync

    def sync(self, conn: Any, sid: int, params: bytes, body: bytes) -> Iterator[bytes]:
        handle = params[:4]
        self.syncs[handle] = self.syncs.get(handle, 0) + 1
        path = conn.handles[handle]
        if self.syncs[handle] == 2:
            opened = [raw for raw in conn.s.opened if raw.startswith(path + "?tpc.key")][-1]
            lfn = opened.split("tpc.lfn=")[1].split("&")[0]
            data = self.source.contents(lfn)
            half = len(data) // 2
            conn.s.files[path] = bytearray(data[:half])
            time.sleep(self.delay)
            conn.s.files[path] = bytearray(data)
        yield frame(sid, c.kXR_ok)


@pytest.fixture
def target() -> Iterator[FakeServer]:
    with FakeServer() as srv:
        yield srv


def _url(server: FakeServer) -> str:
    host, port = server.address
    return f"root://{host}:{port}/"


def test_a_third_party_copy_is_a_pull(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, target: FakeServer
) -> None:
    Puller(server, target)
    params = ctx.transfer_parameters()
    seen = _events(params)
    params.set_checksum(checksum_mode.both, "", "")
    ctx.filecopy(params, _url(server) + "/data/a.txt", _url(target) + "/pulled")
    assert target.contents("/pulled") == HELLO
    assert (2, "xroot", "TRANSFER:TYPE", "3rd pull") in seen
    assert any("tpc.lfn=/data/a.txt" in raw for raw in target.opened)


def test_a_slow_pull_reports_progress(
    ctx: xgfalclient.Gfal2Context,
    server: FakeServer,
    target: FakeServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(xrootd, "TPC_PROGRESS", 0.0)
    monkeypatch.setattr(xgfalclient.transfer, "MONITOR_INTERVAL", 0.0)
    Puller(server, target, delay=0.5)
    params = ctx.transfer_parameters()
    done: list[int] = []
    params.monitor_callback = lambda s, d, avg, inst, moved, elapsed: done.append(moved)
    ctx.filecopy(params, _url(server) + "/data/a.txt", _url(target) + "/pulled")
    assert 6 in done and done[-1] == 12


def test_a_pull_without_a_timeout_between_progress_reports(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, target: FakeServer
) -> None:
    Puller(server, target, delay=0.3)  # shorter than TPC_PROGRESS: nobody is asked
    params = ctx.transfer_parameters()
    params.timeout = 0
    done: list[int] = []
    params.monitor_callback = lambda s, d, avg, inst, moved, elapsed: done.append(moved)
    ctx.filecopy(params, _url(server) + "/data/a.txt", _url(target) + "/pulled")
    assert target.contents("/pulled") == HELLO
    assert 6 not in done


def test_progress_is_quiet_until_the_destination_exists(
    ctx: xgfalclient.Gfal2Context, plugin: XRootDPlugin, target: FakeServer
) -> None:
    transfer = xgfalclient.transfer.Transfer(
        ctx, ctx.transfer_parameters(), "root://h//a", _url(target) + "/none"
    )
    plugin._tpc_progress(transfer)
    assert transfer.transferred == 0


def test_a_pull_from_a_missing_source(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, target: FakeServer
) -> None:
    params = ctx.transfer_parameters()
    seen = _events(params)
    failure = _gerror(ctx.filecopy, params, _url(server) + "/nothing", _url(target) + "/x")
    # With delegation on, XrdCl leaves the source to a destination that can
    # pull with the delegated proxy; a stock one cannot, and that is the news.
    assert failure.code == errno.ENOTSUP
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Operation not supported: "
        "Destination does not support delegation."
    )
    assert (1, "xroot", "CLEANUP", "0") in seen
    params.proxy_delegation = False
    failure = _gerror(ctx.filecopy, params, _url(server) + "/nothing", _url(target) + "/x")
    assert failure.code == errno.ENOENT
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Server responded with an error: [3011] "
        "no such file or directory: /nothing\n"
    )


@pytest.mark.parametrize(
    ("answer", "delegates"),
    [("1\n1", True), ("1\ntpcdlg", False), ("1\n0", False), ("1\n", False), ("1", False)],
)
def test_whether_a_destination_takes_a_delegated_pull(
    plugin: XRootDPlugin, target: FakeServer, answer: str, delegates: bool
) -> None:
    target.config_values["tpc tpcdlg"] = answer
    assert plugin._delegates(_url(target) + "/x") is delegates
    _reply(target, c.kXR_query, 3000)
    assert plugin._delegates(_url(target) + "/x") is False


def test_a_pull_the_destination_fails_is_its_answer(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, target: FakeServer
) -> None:
    _reply(target, c.kXR_sync, 3007, "pull failed")
    failure = _gerror(
        ctx.filecopy, ctx.transfer_parameters(), _url(server) + "/data/a.txt", _url(target) + "/x"
    )
    assert failure.code == errno.EIO
    assert failure.message.endswith("[3007] pull failed\n")  # no side named, as in XrdCl


def test_a_destination_that_delegates_hears_about_the_source(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, target: FakeServer
) -> None:
    target.config_values["tpc tpcdlg"] = "1\ngsi"
    failure = _gerror(
        ctx.filecopy, ctx.transfer_parameters(), _url(server) + "/nothing", _url(target) + "/x"
    )
    assert failure.code == errno.ENOENT  # this client cannot delegate: the source is the news


def test_a_pull_can_be_cancelled(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, target: FakeServer
) -> None:
    Puller(server, target, delay=2.0)
    params = ctx.transfer_parameters()
    params.transfer_cleanup = False
    timer = threading.Timer(0.3, ctx.cancel)
    timer.start()
    started = time.monotonic()
    seen = _events(params)
    failure = _gerror(ctx.filecopy, params, _url(server) + "/data/a.txt", _url(target) + "/p")
    timer.join()
    assert failure.code == errno.ECANCELED
    assert (2, "xroot", "TRANSFER:EXIT", "Job finished, Transfer canceled") in seen
    assert time.monotonic() - started < 1.5


def test_a_pull_is_narrated_as_xrdcls_copy_job(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, target: FakeServer
) -> None:
    Puller(server, target)
    params = ctx.transfer_parameters()
    params.evict = True
    seen = _events(params)
    ctx.filecopy(params, _url(server) + "/data/a.txt", _url(target) + "/pulled")
    source, destination = _url(server).rstrip("/"), _url(target).rstrip("/")
    assert [event[2:] for event in seen if event[1] == "xroot"] == [
        (
            "TRANSFER:ENTER",
            f"{source}///data/a.txt?xrdcl.intent=tpc => {destination}///pulled?xrdcl.intent=tpc",
        ),
        ("TRANSFER:TYPE", "3rd pull"),
        ("TRANSFER:EXIT", "Job finished, [SUCCESS] "),
        ("EVICT", "0"),
    ]
    assert not [event for event in seen if event[2].startswith("CHECKSUM")]


def test_a_copy_jobs_urls(ctx: xgfalclient.Gfal2Context, plugin: XRootDPlugin) -> None:
    job = plugin._job_url
    assert job("root://h//p", "") == "root://h:1094///p?xrdcl.intent=tpc"
    assert job("root://u@h:1095/p?b=2&a=1", "") == ("root://u@h:1095///p?a=1&b=2&xrdcl.intent=tpc")
    assert job("xroot://[::1]:1094////p%20q", "") == "xroot://[::1]:1094////p q?xrdcl.intent=tpc"
    assert job("root://h", "") == "root://h:1094///?xrdcl.intent=tpc"
    assert job("root:///p", "") == "root://:1094///p?xrdcl.intent=tpc"
    # A space token replaces the CGI there was, as XrdCl's SetParams does.
    assert job("root://h//p?authz=x", "T0") == "root://h:1094///p?svcClass=T0&xrdcl.intent=tpc"
    assert job("file:///tmp/f", "") == "file://localhost///tmp/f?xrdcl.intent=tpc"
    ctx.set_opt_string("XROOTD PLUGIN", "XRD.WANTPROT", "gsi;unix")
    assert job("roots://h//p", "") == "roots://h:1094///p?xrd.wantprot=gsi,unix&xrdcl.intent=tpc"


def test_a_copy_between_other_xrootd_schemes_is_announced_as_streamed(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, target: FakeServer
) -> None:
    Puller(server, target)
    params = ctx.transfer_parameters()
    seen = _events(params)
    source = "xroot" + _url(server)[4:]
    ctx.filecopy(params, source + "/data/a.txt", _url(target) + "/pulled")
    assert target.contents("/pulled") == HELLO
    assert (2, "xroot", "TRANSFER:TYPE", "streamed") in seen


def test_a_pull_makes_the_destinations_path(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, target: FakeServer
) -> None:
    Puller(server, target)
    ctx.filecopy(ctx.transfer_parameters(), _url(server) + "/data/a.txt", _url(target) + "/n/d/x")
    assert target.contents("/n/d/x") == HELLO  # create_parent unset, as XrdCl ignores it
    _reply(target, c.kXR_mkdir, 3010)
    params = ctx.transfer_parameters()
    params.transfer_cleanup = False
    failure = _gerror(ctx.filecopy, params, _url(server) + "/data/a.txt", _url(target) + "/m/x")
    assert failure.code == errno.ENOENT  # the open's own answer, not the mkdir's
    assert failure.message.endswith("no such file or directory: /m (destination)\n")


def test_a_pull_onto_an_existing_file_is_the_destinations_answer(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, target: FakeServer
) -> None:
    target.add_file("/there", b"old")
    params = ctx.transfer_parameters()
    seen = _events(params)
    failure = _gerror(ctx.filecopy, params, _url(server) + "/data/a.txt", _url(target) + "/there")
    assert failure.code == errno.EEXIST
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Server responded with an error: [3018] "
        "already exists: /there (destination)\n"
    )
    assert target.contents("/there") == b"old"
    assert not [event for event in seen if event[2] == "CLEANUP"]


def test_an_upload_onto_an_existing_file(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str, tmp_path: Path
) -> None:
    (tmp_path / "src").write_bytes(b"new")
    failure = _gerror(
        ctx.filecopy, ctx.transfer_parameters(), f"file://{tmp_path}/src", base + "/data/a.txt"
    )
    assert failure.code == errno.EEXIST
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Server responded with an error: [3018] "
        "already exists: /data/a.txt (destination)\n"
    )
    assert server.contents("/data/a.txt") == HELLO


def test_an_upload_of_a_local_file_that_is_not_there(
    ctx: xgfalclient.Gfal2Context, base: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    params = ctx.transfer_parameters()
    seen = _events(params)
    failure = _gerror(ctx.filecopy, params, f"file://{tmp_path}/none", base + "/up")
    assert failure.code == errno.ENOENT
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Local error: no such file or directory:  "
        "(source)"
    )
    assert (1, "xroot", "CLEANUP", "0") in seen  # removing what is not there is no failure
    (tmp_path / "src").write_bytes(b"x")
    from xgfalclient.plugins import file as local

    def refused(*args: Any) -> None:
        raise PermissionError(errno.EACCES, "no")

    monkeypatch.setattr(local.LocalFile, "__init__", refused)
    failure = _gerror(ctx.filecopy, params, f"file://{tmp_path}/src", base + "/up")
    assert failure.code == errno.EACCES
    assert failure.message.endswith("Local error: permission denied:  (source)")


def test_a_clean_up_that_fails_says_why(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str, tmp_path: Path
) -> None:
    params = ctx.transfer_parameters()
    params.set_checksum(checksum_mode.target, "adler32", "1")
    seen = _events(params)
    (tmp_path / "src").write_bytes(b"abc")
    _reply(server, c.kXR_rm, 3010)
    failure = _gerror(ctx.filecopy, params, f"file://{tmp_path}/src", base + "/up")
    assert failure.code == errno.EILSEQ
    assert (1, "xroot", "CLEANUP", str(errno.EACCES)) in seen


def test_a_copy_verifies_checksums_as_xrdcl_does(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str, tmp_path: Path
) -> None:
    (tmp_path / "src").write_bytes(HELLO)
    up = f"file://{tmp_path}/src"
    params = ctx.transfer_parameters()
    params.overwrite = True
    seen = _events(params)
    params.set_checksum(checksum_mode.both, "ADLER32", "00" + ADLER_HELLO.upper())
    ctx.filecopy(params, up, base + "/c")
    params.set_checksum(checksum_mode.source, "adler32", "deadbeef")
    ctx.filecopy(params, up, base + "/c")  # only the target is ever compared
    params.set_checksum(checksum_mode.target, "adler32", "0")  # nothing left to compare
    ctx.filecopy(params, up, base + "/c")
    params.set_checksum(checksum_mode.both, "", "")  # COPY_CHECKSUM_TYPE
    ctx.filecopy(params, base + "/c", f"file://{tmp_path}/back")
    assert not [event for event in seen if event[2].startswith("CHECKSUM")]
    for mode in (checksum_mode.target, checksum_mode.both):
        params.set_checksum(mode, "adler32", "deadbeef")
        failure = _gerror(ctx.filecopy, params, up, base + "/c")
        assert (failure.code, failure.message) == (
            errno.EILSEQ,
            "Error on XrdCl::CopyProcess::Run(): [ERROR] CheckSum error",
        )
        assert seen[-2:] == [
            (2, "xroot", "TRANSFER:EXIT", "Job finished, [ERROR] CheckSum error"),
            (1, "xroot", "CLEANUP", "0"),
        ]


def test_a_source_checksum_that_cannot_be_asked_for(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str, tmp_path: Path
) -> None:
    params = ctx.transfer_parameters()
    params.set_checksum(checksum_mode.both, "sha256", "")
    _reply(server, c.kXR_query, 3012, "sha256 checksum not supported.")
    failure = _gerror(ctx.filecopy, params, base + "/data/a.txt", f"file://{tmp_path}/b")
    assert failure.code == errno.EFAULT
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Server responded with an error: [3012] "
        "sha256 checksum not supported. Got an error while querying the checksum! (source)\n"
    )


def test_a_checksum_query_that_times_out(
    ctx: xgfalclient.Gfal2Context, base: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def slow(*args: Any) -> bytes:
        raise TimeoutError("too slow")

    monkeypatch.setattr(XRootDPlugin, "_checksum_answer", slow)
    params = ctx.transfer_parameters()
    params.set_checksum(checksum_mode.both, "adler32", "")
    failure = _gerror(ctx.filecopy, params, base + "/data/a.txt", f"file://{tmp_path}/x")
    assert (failure.code, failure.message) == (
        errno.ETIMEDOUT,
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Operation expired: too slow "
        "Got an error while querying the checksum! (source)",
    )


def test_checksums_the_local_end_cannot_make(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str, tmp_path: Path
) -> None:
    params = ctx.transfer_parameters()
    params.set_checksum(checksum_mode.both, "sha256", "")
    failure = _gerror(ctx.filecopy, params, base + "/data/a.txt", f"file://{tmp_path}/x")
    assert failure.code == errno.ENOSYS
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Local error: Checksum type sha256 not "
        "supported for local files (destination)"
    )


def test_a_checksum_answer_that_makes_no_sense(
    ctx: xgfalclient.Gfal2Context, server: FakeServer, base: str, tmp_path: Path
) -> None:
    _ok(server, c.kXR_query, b"garbage\x00")
    params = ctx.transfer_parameters()
    params.set_checksum(checksum_mode.both, "adler32", "")
    failure = _gerror(ctx.filecopy, params, base + "/data/a.txt", f"file://{tmp_path}/x")
    assert failure.code == errno.EIO
    assert failure.message == (
        "Error on XrdCl::CopyProcess::Run(): [ERROR] Invalid response: "
        "Could not get the checksum (Wrong format) (source)"
    )


def test_a_callback_that_raises_ends_the_copy_as_it_was_raised(
    ctx: xgfalclient.Gfal2Context,
    server: FakeServer,
    base: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("xgfalclient.transfer.MONITOR_INTERVAL", 0.0)
    server.add_file("/big", os.urandom(1 << 20))
    params = ctx.transfer_parameters()

    def refuse(*args: Any) -> None:
        raise KeyError("stop")

    params.monitor_callback = refuse
    seen = _events(params)
    with pytest.raises(KeyError):
        ctx.filecopy(params, base + "/big", f"file://{tmp_path}/big")
    assert not [event for event in seen if event[2] == "TRANSFER:EXIT"]


def test_a_dropped_context_closes_its_idle_filesystems(server: FakeServer, base: str) -> None:
    """Not the cycle collector: it would finalize the socket under a pooled session (EBADF)."""
    import gc

    context = xgfalclient.creat_context()
    context.stat(base + "/data/a.txt")
    found = context.plugin(base + "/data/a.txt", "stat")
    assert isinstance(found, XRootDPlugin)
    [(_, fs)] = [entry for kept in found._idle.values() for entry in kept]
    router: Any = fs._router
    assert router._session is not None
    del found, context, fs
    gc.collect()
    assert router._session is None  # handed back to xrdclient's pool, socket and all
