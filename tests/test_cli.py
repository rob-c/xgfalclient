"""The ``gfal-*`` commands: common machinery, and every command but ``gfal-copy``.

Everything goes through the entry points (``xgfalclient.cli.ls([...])``) with
stdout and stderr captured, against ``file://`` in ``tmp_path`` and ``mock://``.
Expected outputs are gfal2-util 1.9.1's; ``test_cli_parity.py`` checks them
against the real thing.
"""

from __future__ import annotations

import errno
import io
import logging
import os
import runpy
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

import xgfalclient
from xgfalclient import cli
from xgfalclient.cli import _base as base
from xgfalclient.cli import _ls as ls_module
from xgfalclient.cli import _tape as tape
from xgfalclient.cli import _utils as utils
from xgfalclient.cli.__main__ import main as module_main
from xgfalclient.context import Gfal2Context
from xgfalclient.errors import GError
from xgfalclient.plugins.mock import MockPlugin
from xgfalclient.testing.lfc import USER_DN, LFCServer
from xgfalclient.testing.pki import PKI
from xgfalclient.types import Stat

Run = Callable[..., tuple[int, str, str]]

OLD = 1577934245  # 2020-01-02 03:04:05 UTC


@pytest.fixture(autouse=True)
def _ls_colors(monkeypatch: pytest.MonkeyPatch) -> None:
    """No ``LS_COLORS`` from the environment, and none read yet."""
    monkeypatch.delenv("LS_COLORS", raising=False)
    monkeypatch.setattr(utils, "_colors", None)


@pytest.fixture
def run(capsys: pytest.CaptureFixture[str]) -> Run:
    def _run(command: str, *args: str) -> tuple[int, str, str]:
        code = getattr(cli, command)(list(args))
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return _run


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """``a.txt`` (6 bytes), ``sub/b``, ``.hidden``, all with an old mtime."""
    (tmp_path / "a.txt").write_text("hello\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b").write_text("x\n")
    (tmp_path / ".hidden").write_text("")
    for path in (
        tmp_path / "a.txt",
        tmp_path / "sub",
        tmp_path / "sub" / "b",
        tmp_path / ".hidden",
    ):
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
        os.utime(path, (OLD, OLD))
    return tmp_path


def url(path: Path | str) -> str:
    return "file://" + os.fspath(path)


def local(stamp: float, fmt: str) -> str:
    return datetime.fromtimestamp(stamp).strftime(fmt)


# ---------------------------------------------------------------------------
# Common options and machinery
# ---------------------------------------------------------------------------


def test_help_has_gfal2_util_layout(run: Run) -> None:
    code, out, _ = run("copy", "--help")
    assert code == 0
    assert out.startswith("usage: gfal-copy [-h] [-V] [-v] [-D DEFINITION]")
    assert "Gfal util COPY command. Copy a file or set of files.\n" in out
    assert "\noptional arguments:\n" in out
    assert "  -D DEFINITION, --definition DEFINITION\n" in out
    assert "  -f, --force " in out
    assert "  src                   source file\n" in out


def test_description_gets_a_full_stop(run: Run) -> None:
    _, out, _ = run("save", "--help")
    assert "overwritten.\n" in out
    _code, out, _ = run("mkdir", "--help")
    assert "mode\n0755.\n" in out and "0755..\n" not in out


def test_version(run: Run) -> None:
    code, out, _ = run("ls", "-V")
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == "gfal2-util version 1.9.1 (gfal2 2.23.5)"
    assert "\tfile-2.23.5" in lines
    assert "\tmock-2.23.5" in lines


def test_usage_error(run: Run) -> None:
    code, out, err = run("stat")
    assert code == 2
    assert out == ""
    assert err.endswith("gfal-stat: error: the following arguments are required: file\n")


def test_argv_defaults_to_sys_argv(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tree: Path
) -> None:
    monkeypatch.setattr(sys, "argv", ["gfal-ls", url(tree / "a.txt")])
    assert cli.ls() == 0
    assert capsys.readouterr().out == url(tree / "a.txt") + "\n"


def test_surl() -> None:
    assert base.surl("-") == "-"
    assert base.surl("mock://h/x") == "mock://h/x"
    assert base.surl("/a;b?c#d") == "file:///a;b?c#d"
    assert base.surl("rel") == "file://" + os.path.abspath("rel")


def test_relative_path(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tree)
    assert run("ls", "sub") == (0, "b\n", "")


def test_parse_definition() -> None:
    assert base.parse_definition("CORE:A:B=1,true,no,x") == ("CORE:A", "B", [1, True, False, "x"])
    with pytest.raises(ValueError, match="doesn't include value"):
        base.parse_definition("CORE:X")
    with pytest.raises(ValueError, match="doesn't include group name"):
        base.parse_definition("X=1")


def test_definitions_client_info_and_flags(
    run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    original = Gfal2Context.set_user_agent

    def spy(self: Gfal2Context, name: str, version: str) -> int:
        seen["options"] = self.options.snapshot()
        seen["info"] = self.get_client_info()
        seen["agent"] = (name, version)
        return original(self, name, version)

    monkeypatch.setattr(Gfal2Context, "set_user_agent", spy)
    code, _, _ = run(
        "ls",
        "-D", "G:INT=5",
        "-D", "G:BOOL=yes",
        "-D", "G:STR=hello",
        "-D", "G:LIST=a,b",
        "-C", "k=v",
        "-C", "bare",
        "-C", "x=y=z",
        "-6",
        "-t", "0",
        url(tree / "a.txt"),
    )  # fmt: skip
    assert code == 0
    group = seen["options"]["G"]
    assert group == {"INT": "5", "BOOL": "true", "STR": "hello", "LIST": "a;b;"}
    assert seen["options"]["GRIDFTP PLUGIN"]["IPV6"] == "true"
    assert seen["options"].get("CORE", {}).get("NAMESPACE_TIMEOUT") != "0"
    assert seen["info"] == {"k": "v", "bare": "", "x=y=z": ""}
    assert seen["agent"] == ("gfal2-util", "1.9.1")

    run("ls", "-4", "-t", "77", url(tree / "a.txt"))
    assert seen["options"]["GRIDFTP PLUGIN"]["IPV6"] == "false"
    assert seen["options"]["CORE"]["NAMESPACE_TIMEOUT"] == "77"
    assert seen["options"]["CORE"]["CHECKSUM_TIMEOUT"] == "77"


def test_bad_definition_is_a_traceback(run: Run, tree: Path) -> None:
    code, out, err = run("ls", "-D", "CORE:X", url(tree))
    assert code == 1
    assert out == ""
    assert err.startswith("Traceback (most recent call last):\n")
    assert err.endswith(
        "ValueError: parameter 'CORE:X' doesn't include value, use 'group:option=value'\n"
    )


def test_cert_sets_environment(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("X509_USER_CERT", "X509_USER_KEY"):
        monkeypatch.setenv(name, "unset")
    monkeypatch.setenv("X509_USER_PROXY", "/proxy")
    run("stat", "-E", "/cert.pem", url(tree))
    assert os.environ["X509_USER_CERT"] == "/cert.pem"
    assert os.environ["X509_USER_KEY"] == "/cert.pem"
    assert "X509_USER_PROXY" not in os.environ
    run("stat", "-E", "/c.pem", "--key", "/k.pem", url(tree))
    assert os.environ["X509_USER_KEY"] == "/k.pem"


def test_verbose_logging_to_stdout_and_file(run: Run, tree: Path) -> None:
    root = logging.getLogger()
    before = (list(root.handlers), root.level, xgfalclient._log.threshold())
    code, _out, _ = run("stat", "-vvvv", url(tree / "nope"))
    assert code == errno.ENOENT
    after = (list(root.handlers), root.level, xgfalclient._log.threshold())
    assert after == before
    log = tree / "gfal.log"
    code, _, _ = run("ls", "-vv", "--log-file", str(log), url(tree / "a.txt"))
    assert code == 0 and log.exists()


def test_log_file_in_missing_directory(run: Run, tree: Path) -> None:
    code, _out, err = run("ls", "--log-file", str(tree / "no" / "log"), url(tree))
    assert code == 1
    assert "FileNotFoundError" in err


def test_log_formatter() -> None:
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "hi %s", ("there",), None)
    assert base._Formatter(False).format(record) == "INFO hi there"
    assert base._Formatter(True).format(record) == "\033[1;34mINFO    \033[1;m hi there"
    record.levelno, record.levelname = 55, "LOUD"
    assert base._Formatter(True).format(record) == "LOUD hi there"


def test_log_handler_goes_through_root(
    run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def noisy(self: Gfal2Context, path: str) -> Stat:
        logging.getLogger("xgfalclient.test").warning("careful with %s", "that")
        return Stat(st_mode=stat.S_IFREG | 0o644)

    monkeypatch.setattr(Gfal2Context, "stat", noisy)
    _code, out, _ = run("ls", "-v", url(tree))
    assert out == f"WARNING careful with that\n{url(tree)}\n"


def test_isatty() -> None:
    assert base._isatty(object()) is False
    closed = io.StringIO()
    closed.close()
    assert base._isatty(closed) is False

    class TTY:
        def isatty(self) -> bool:
            return True

    assert base._isatty(TTY()) is True


def test_gerror_out_of_range_exits_255(run: Run) -> None:
    code, _, err = run("stat", "mock://h/f?errno=300")
    assert code == 255
    assert err.startswith(f"gfal-stat error: 300 ({os.strerror(300)}) - ")


def test_unexpected_exception_in_command(run: Run, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(path: str) -> list[str]:
        raise ValueError("unreadable list")

    monkeypatch.setattr(tape, "read_list", broken)
    code, _out, err = run("bringonline", "--from-file", "list")
    assert code == 255
    assert err.startswith("Exception in thread Thread-1:\nTraceback (most recent call last):")
    assert err.endswith("ValueError: unreadable list\n")


def test_oserror_in_command(run: Run, tree: Path) -> None:
    code, _, err = run("archivepoll", "--from-file", str(tree / "missing.list"))
    assert code == 255
    assert "FileNotFoundError" in err


def test_broken_pipe_is_quiet(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken(io.BytesIO):
        def write(self, data: Any) -> int:
            raise BrokenPipeError(errno.EPIPE, "Broken pipe")

    class Stdout(io.StringIO):
        buffer = Broken()

    monkeypatch.setattr(sys, "stdout", Stdout())
    code = cli.cat([url(tree / "a.txt")])
    assert code == 255


class _PipeStdout(io.StringIO):
    """A stdout on a real descriptor whose reader has gone."""

    def __init__(self, fd: int) -> None:
        super().__init__()
        self.fd = fd

    def write(self, text: str) -> int:
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")

    def fileno(self) -> int:
        return self.fd


def test_broken_pipe_points_stdout_at_devnull(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """So the interpreter's last flush cannot fail again; ``gfal-rm`` still exits 0."""
    read_end, write_end = os.pipe()
    try:
        monkeypatch.setattr(sys, "stdout", _PipeStdout(write_end))
        assert cli.ls([url(tree)]) == 255
        assert stat.S_ISCHR(os.fstat(write_end).st_mode)
        assert cli.rm([url(tree / "a.txt")]) == 0
    finally:
        os.close(read_end)
        os.close(write_end)


@pytest.mark.parametrize(("command", "status"), [("ls", 255), ("rm", 0)])
def test_broken_pipe_in_a_real_process(tmp_path: Path, command: str, status: int) -> None:
    """``gfal-ls dir | head -1``: gfal2-util's status, and nothing on stderr."""
    import subprocess

    for index in range(3000):  # well past a pipe's buffer
        (tmp_path / f"a-rather-long-file-name-to-fill-the-pipe-{index}").write_bytes(b"")
    args = [command, "-r", url(tmp_path)] if command == "rm" else [command, url(tmp_path)]
    process = subprocess.Popen(
        [sys.executable, "-m", "xgfalclient.cli", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None and process.stderr is not None
    process.stdout.readline()
    process.stdout.close()
    assert process.wait(60) == status
    assert process.stderr.read() == b""
    process.stderr.close()


def test_ls_colors_warning_from_every_command(
    run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LS_COLORS", "di=1:a=b=c")
    code, out, err = run("stat", "--help")
    assert code == 0 and out.startswith("usage: gfal-stat")
    assert err == "unparsable value for LS_COLORS environment variable: a=b=c\n"
    assert run("rm", url(tree / "a.txt"))[2] == ""  # once per process, as gfal2-util


def test_exit_status() -> None:
    assert [base.exit_status(code) for code in (None, 0, 2, -1, 256)] == [0, 0, 2, 255, 0]


def test_timeout(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()

    def slow(self: Gfal2Context, path: str) -> Stat:
        release.wait(10)
        return Stat()

    monkeypatch.setattr(Gfal2Context, "stat", slow)
    monkeypatch.setattr(base, "TIMEOUT_GRACE", 0)
    code, _out, err = run("stat", "-t", "1", url(tree))
    assert code == errno.ETIMEDOUT
    assert err == "Command timed out after 1 seconds!\n"
    release.set()
    for thread in threading.enumerate():
        if thread.name == "Thread-1":
            thread.join(10)


def test_keyboard_interrupt(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted(worker: threading.Thread, timeout: float | None) -> None:
        worker.join()
        raise KeyboardInterrupt

    monkeypatch.setattr(base, "_wait", interrupted)
    code, _, err = run("stat", url(tree))
    assert code == errno.EINTR
    assert err.endswith("Caught keyboard interrupt. Canceling...")


def test_keyboard_interrupt_cancel_hangs(
    run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(worker: threading.Thread, timeout: float | None) -> None:
        worker.join()
        raise KeyboardInterrupt

    release = threading.Event()

    def stuck(self: Gfal2Context) -> int:
        release.wait(10)
        return 0

    monkeypatch.setattr(base, "_wait", interrupted)
    monkeypatch.setattr(base, "CANCEL_WAIT", 0.05)
    monkeypatch.setattr(Gfal2Context, "cancel", stuck)
    code, _, err = run("stat", url(tree))
    release.set()
    assert code == errno.EINTR
    assert err.endswith("Canceling...failed to cancel after waiting some time\n")


def test_python_dash_m(capsys: pytest.CaptureFixture[str], tree: Path) -> None:
    assert module_main(["gfal2_version", "--ignored"]) == 0
    assert module_main(["gfal_srm_ifce_version"]) == 0
    assert capsys.readouterr().out == "GFAL-client-2.23.5\ngfal-srm-ifce--1.24.8\n"
    assert module_main(["gfal-ls", url(tree / "a.txt")]) == 0
    assert module_main(["ls", url(tree / "a.txt")]) == 0
    assert capsys.readouterr().out == url(tree / "a.txt") + "\n" + url(tree / "a.txt") + "\n"
    assert module_main([]) == 2
    assert module_main(["nope"]) == 2
    assert capsys.readouterr().err.startswith("usage: python -m xgfalclient.cli {archivepoll,")


def test_python_dash_m_runs_main(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tree: Path
) -> None:
    monkeypatch.setattr(sys, "argv", ["xgfalclient.cli", "stat", url(tree / "nope")])
    monkeypatch.delitem(sys.modules, "xgfalclient.cli.__main__", raising=False)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("xgfalclient.cli", run_name="__main__")
    assert exit_info.value.code == errno.ENOENT


# ---------------------------------------------------------------------------
# Mode strings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "text", "kind"),
    [
        (stat.S_IFDIR | 0o755, "drwxr-xr-x", "directory"),
        (stat.S_IFBLK | 0o640, "brw-r-----", "block device"),
        (stat.S_IFCHR | 0o666, "crw-rw-rw-", "character device"),
        (stat.S_IFIFO | 0o600, "frw-------", "fifo"),
        (stat.S_IFSOCK | 0o777, "srwxrwxrwx", "socket"),
        (stat.S_IFLNK | 0o777, "-rwxrwxrwx", "symbolic link"),
        (stat.S_IFREG | 0o4751, "-rwxr-x--x", "regular file"),
        (0o644, "-rw-r--r--", "unknown"),
    ],
)
def test_mode_strings(mode: int, text: str, kind: str) -> None:
    assert utils.file_mode_str(mode) == text
    assert utils.file_type_str(stat.S_IFMT(mode)) == kind


# ---------------------------------------------------------------------------
# stat, sum, cat, save, xattr, mkdir, rename, chmod, token
# ---------------------------------------------------------------------------


def test_stat(run: Run, tree: Path) -> None:
    info = os.stat(tree / "a.txt")
    code, out, err = run("stat", url(tree / "a.txt"))
    assert (code, err) == (0, "")
    fmt = "%Y-%m-%d %H:%M:%S.%f"
    assert out == (
        f"  File: '{url(tree / 'a.txt')}'\n"
        "  Size: 6\tregular file\n"
        f"Access: (0644/-rw-r--r--)\tUid: {info.st_uid}\tGid: {info.st_gid}\t\n"
        f"Access: {local(int(info.st_atime), fmt)}\n"
        f"Modify: {local(OLD, fmt)}\n"
        f"Change: {local(int(info.st_ctime), fmt)}\n"
    )


def test_stat_mock_and_errors(run: Run) -> None:
    code, out, _ = run("stat", "mock://h/f?size=10")
    assert code == 0
    assert "  Size: 10\tregular file\nAccess: (0755/-rwxr-xr-x)\tUid: 0\tGid: 0\t\n" in out
    assert run("stat", "mock://h/f?errno=13") == (
        13,
        "",
        "gfal-stat error: 13 (Permission denied) - Permission denied\n",
    )


def test_sum(run: Run, tree: Path) -> None:
    assert run("sum", url(tree / "a.txt"), "ADLER32") == (
        0,
        f"{url(tree / 'a.txt')} 084b021f\n",
        "",
    )
    assert run("sum", "mock://h/f?checksum=abc", "MD5") == (0, "mock://h/f?checksum=abc abc\n", "")


def test_cat(tree: Path, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
    (tree / "empty").write_bytes(b"")
    (tree / "bin").write_bytes(b"\xff\x00\xfe")
    assert cli.cat([url(tree / "a.txt"), url(tree / "empty"), url(tree / "sub/b")]) == 0
    assert cli.cat(["-b", url(tree / "bin")]) == 0
    assert capsysbinary.readouterr().out == b"hello\nx\n\xff\x00\xfe"


def test_cat_missing(run: Run, tree: Path) -> None:
    code, _, err = run("cat", url(tree / "nope"))
    assert code == 2
    assert err == (
        "gfal-cat error: 2 (No such file or directory) - "
        "errno reported by local system call No such file or directory\n"
    )


def test_save(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"saved\n\xff")))
    assert run("save", url(tree / "s")) == (0, "", "")
    assert (tree / "s").read_bytes() == b"saved\n\xff"


def test_save_failure(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"x")))
    code, _, _err = run("save", url(tree / "no" / "s"))
    assert code == errno.ENOENT


def test_save_write_failure_closes(run: Run, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"x")))
    code, _, _err = run("save", "mock://h/f")
    assert code == errno.ENOSYS  # the mock plugin opens nothing for writing


def test_xattr(run: Run, monkeypatch: pytest.MonkeyPatch) -> None:
    assert run("xattr", "mock://h/f?user.status=ONLINE", "user.status") == (0, "ONLINE\n", "")
    code, _, err = run("xattr", "mock://h/f", "user.nope")
    assert (code, err) == (
        errno.ENODATA,
        f"gfal-xattr error: {errno.ENODATA} ({os.strerror(errno.ENODATA)}) - "
        "Failed to retrieve xattr user.nope\n",
    )
    original = MockPlugin.getxattr

    def flaky(self: MockPlugin, path: str, name: str) -> str:
        if name == "user.guid":
            raise GError("no guid here", errno.ENODATA)
        return original(self, path, name)

    monkeypatch.setattr(MockPlugin, "getxattr", flaky)
    names = ["user.status", "user.replicas", "user.guid", "user.comment", "spacetoken"]
    # gfal2's mock has no listxattr
    monkeypatch.setattr(MockPlugin, "listxattr", lambda self, path: names, raising=False)
    code, out, _ = run("xattr", "mock://h/f?user.status=ONLINE&user.replicas=r1&spacetoken=T")
    assert code == 0
    assert out == (
        "user.status = ONLINE\n"
        "user.replicas = r1\n"
        "user.guid FAILED: no guid here\n"
        "user.comment FAILED: Failed to retrieve xattr user.comment\n"
        "spacetoken = T\n"
    )


def test_xattr_set(run: Run, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def setxattr(self: MockPlugin, path: str, name: str, value: str, flags: int) -> None:
        calls.append((path, name, value))

    monkeypatch.setattr(MockPlugin, "setxattr", setxattr, raising=False)
    assert run("xattr", "mock://h/f", "user.a=b=c") == (0, "", "")
    assert run("xattr", "mock://h/f", "user.a=") == (0, "", "")
    assert run("xattr", "mock://h/f", "=x") == (0, "", "")
    assert calls == [("mock://h/f", "user.a", "b=c")]


def test_mkdir(run: Run, tree: Path) -> None:
    assert run("mkdir", url(tree / "m1"), url(tree / "m2")) == (0, "", "")
    assert (tree / "m1").is_dir() and (tree / "m2").is_dir()
    assert stat.S_IMODE(os.stat(tree / "m1").st_mode) == 0o755 & ~_umask()
    assert run("mkdir", "-m", "700", url(tree / "m3"))[0] == 0
    assert stat.S_IMODE(os.stat(tree / "m3").st_mode) == 0o700
    assert run("mkdir", "-m", "0", url(tree / "m4"))[0] == 0
    assert stat.S_IMODE(os.stat(tree / "m4").st_mode) == 0o755 & ~_umask()
    assert run("mkdir", "-m", "999", url(tree / "m5"))[0] == 0
    assert stat.S_IMODE(os.stat(tree / "m5").st_mode) == 0o755 & ~_umask()
    assert run("mkdir", "-p", url(tree / "p" / "q" / "r"))[0] == 0
    assert (tree / "p" / "q" / "r").is_dir()
    code, _, err = run("mkdir", url(tree / "m1"))
    assert code == errno.EEXIST
    assert err == (
        f"gfal-mkdir error: {errno.EEXIST} (File exists) - "
        "errno reported by local system call File exists\n"
    )


def _umask() -> int:
    mask = os.umask(0)
    os.umask(mask)
    return mask


def test_rename(run: Run, tree: Path) -> None:
    assert run("rename", url(tree / "a.txt"), url(tree / "z")) == (0, "", "")
    assert (tree / "z").exists()


def test_chmod(run: Run, tree: Path) -> None:
    assert run("chmod", "600", url(tree / "a.txt")) == (0, "", "")
    assert stat.S_IMODE(os.stat(tree / "a.txt").st_mode) == 0o600
    code, _out, err = run("chmod", "xyz", url(tree / "a.txt"))
    assert code == 255
    assert err.endswith("gfal-chmod: error: Mode must be an octal number (i.e. 0755)\n")


def test_token(run: Run, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, ...]] = []
    original = Gfal2Context.token_retrieve

    def spy(self: Gfal2Context, *args: Any) -> str:
        calls.append(args)
        return original(self, *args)

    monkeypatch.setattr(Gfal2Context, "token_retrieve", spy)
    # gfal2's mock has no token_retrieve
    token = lambda self, *args: "mock-token"  # noqa: E731
    monkeypatch.setattr(MockPlugin, "token_retrieve", token, raising=False)
    assert run("token", "mock://h/f") == (0, "mock-token\n", "")
    assert run("token", "-v", "-w", "--issuer", "https://i", "mock://h/f") == (
        0,
        "Will use default activities for write access\nmock-token\n",
        "",
    )
    assert run("token", "-v", "mock://h/f")[1].startswith(
        "Will use default activities for read access\n"
    )
    assert run("token", "-v", "--validity", "5", "mock://h/f", "DOWNLOAD", "LIST")[1] == (
        "Will use user-provided activities\nmock-token\n"
    )
    assert calls == [
        ("mock://h/f", "", 60, False),
        ("mock://h/f", "https://i", 60, True),
        ("mock://h/f", "", 60, False),
        ("mock://h/f", "", 5, ["DOWNLOAD", "LIST"]),
    ]
    assert run("token", "--validity=-1", "mock://h/f") == (
        1,
        "",
        "Validity must be a number >= 0\n",
    )


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------


def test_ls(run: Run, tree: Path) -> None:
    code, out, _ = run("ls", url(tree))
    assert code == 0
    assert sorted(out.splitlines()) == ["a.txt", "sub"]
    code, out, _ = run("ls", "-a", url(tree))
    assert sorted(out.splitlines()) == [".", "..", ".hidden", "a.txt", "sub"]
    assert run("ls", url(tree / "a.txt")) == (0, url(tree / "a.txt") + "\n", "")
    assert run("ls", "-d", url(tree)) == (0, url(tree) + "\n", "")


def test_ls_long(run: Run, tree: Path) -> None:
    info = os.stat(tree / "a.txt")
    _, out, _ = run("ls", "-l", url(tree))
    lines = sorted(out.splitlines())
    assert len(lines) == 2
    when = datetime.fromtimestamp(OLD)
    date = when.strftime("%b ") + when.strftime("%d").lstrip("0").rjust(2) + when.strftime("  %Y")
    assert (
        f"-rw-r--r--   1 {str(info.st_uid).ljust(5)} {str(info.st_gid).ljust(5)}         6 "
        f"{date} a.txt\t"
    ) in lines
    _code, out, _ = run("ls", "-ld", url(tree / "sub"))
    assert out.startswith("drwx")
    assert out.endswith(f" {url(tree / 'sub')}\t\n")


def test_ls_time_styles(run: Run, tree: Path) -> None:
    now = int(time.time())
    os.utime(tree / "sub" / "b", (now, now))
    target = url(tree / "sub" / "b")
    old = url(tree / "a.txt")

    def date(*args: str) -> str:
        return run("ls", "-l", *args)[1].split(None, 5)[5].rsplit(" ", 1)[0].strip()

    assert date("--time-style=full-iso", old) == local(OLD, "%Y-%m-%d %H:%M:%S.%f +0000")
    assert date("--time-style=long-iso", old) == local(OLD, "%Y-%m-%d %H:%M")
    assert date("--full-time", old) == local(OLD, "%Y-%m-%d %H:%M")
    assert date("--time-style=iso", old) == local(OLD, "%Y-%m-%d")
    assert date("--time-style=iso", target) == local(now, "%m-%d %H:%M")
    recent = datetime.fromtimestamp(now)
    assert date(target) == recent.strftime("%b ") + recent.strftime("%d").lstrip("0").rjust(
        2
    ) + recent.strftime(" %H:%M")


def test_ls_human(run: Run, tree: Path) -> None:
    (tree / "big").write_bytes(b"\0" * 1536)
    assert " 1.5K " in run("ls", "-lH", url(tree / "big"))[1]


@pytest.mark.parametrize(
    ("size", "text"),
    [
        (0, "0.0"),
        (1023, "1023"),
        (1024, "1.0K"),
        (1025, "1.1K"),
        (15 * 1024 + 1, "16K"),
        (1024**5 * 2000, "2000P"),
    ],
)
def test_size_to_human(size: int, text: str) -> None:
    assert ls_module.size_to_human(size) == text


def test_ls_color(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tree / "exe").write_text("")
    os.chmod(tree / "exe", 0o755)
    monkeypatch.setenv("LS_COLORS", "di=01;34:ln=01;36:ex=01;32:no=00:junk:a=b=c")
    code, out, err = run("ls", "-l", "--color", "always", url(tree))
    assert code == 0
    assert err == "unparsable value for LS_COLORS environment variable: a=b=c\n"
    assert "\033[01;34msub\033[0m\t" in out
    assert "\033[01;32mexe\033[0m\t" in out
    assert "\033[037ma.txt\033[0m\t" in out
    code, out, err = run("ls", "--color=always", url(tree / "a.txt"))
    assert out == f"\033[00m{url(tree / 'a.txt')}\033[0m\n"
    assert err == ""  # read, and warned about, once per process
    monkeypatch.delenv("LS_COLORS")
    monkeypatch.setattr(utils, "_colors", None)
    code, out, _ = run("ls", "--color=always", url(tree / "a.txt"))
    assert out == f"\033[037m{url(tree / 'a.txt')}\033[0m\n"
    monkeypatch.setenv("LS_COLORS", "ln=01;36")
    monkeypatch.setattr(utils, "_colors", None)
    monkeypatch.setattr(Gfal2Context, "stat", lambda self, path: Stat(st_mode=stat.S_IFLNK | 0o777))
    code, out, _ = run("ls", "-l", "--color=always", "mock://h/link")
    assert "\033[01;36mmock://h/link\033[0m\t" in out
    monkeypatch.setattr(ls_module, "stdout_isatty", lambda: True)
    assert run("ls", url(tree / "a.txt"))[1].startswith("\033[037m")
    assert run("ls", "--color=never", url(tree / "a.txt"))[1] == url(tree / "a.txt") + "\n"


def test_ls_xattr(run: Run) -> None:
    target = "mock://h/f?user.status=ONLINE&user.guid=g"
    _, out, _ = run("ls", "-l", "--xattr", "user.status", "--xattr", "user.guid", target)
    assert out.endswith(f" {target}\tONLINE\tg\n")
    listing = "mock://h/d?list=a:1&user.status=ONLINE"
    _code, out, _ = run("ls", "-l", "--xattr", "user.status", listing)
    assert out.endswith(" a\tONLINE/a\n")  # gfal2's too: the child is "<listing>/a"
    assert run("ls", "--xattr", "user.status", "mock://h/d?list=a:1") == (0, "a\n", "")


def test_ls_errors(run: Run, tree: Path) -> None:
    code, _, err = run("ls", url(tree / "nope"))
    assert code == 2
    assert err == (
        "gfal-ls error: 2 (No such file or directory) - "
        "errno reported by local system call No such file or directory\n"
    )
    code, _, err = run("ls", "nope://h/x")
    assert code == errno.EPROTONOSUPPORT
    assert err.endswith("Protocol not supported or path/url invalid: nope://h/x\n")


# ---------------------------------------------------------------------------
# rm
# ---------------------------------------------------------------------------


def test_rm(run: Run, tree: Path) -> None:
    target = url(tree / "a.txt")
    assert run("rm", target) == (0, f"{target}\tDELETED\n", "")
    assert run("rm", target) == (2, f"{target}\tMISSING\n", "")


def test_rm_directory(run: Run, tree: Path) -> None:
    code, out, err = run("rm", url(tree / "sub"))
    assert code == errno.EISDIR
    assert err == (
        f"gfal-rm error: 21 (Is a directory) - Can not remove {url(tree / 'sub')}, is a directory\n"
    )
    code, out, _ = run("rm", "-r", "--dry-run", url(tree / "sub"))
    assert out == f"{url(tree / 'sub/b')}\tSKIP\n{url(tree / 'sub')}\tSKIP DIR\n"
    code, out, _ = run("rm", "-R", url(tree / "sub") + "/")
    assert out == f"{url(tree / 'sub/b')}\tDELETED\n{url(tree / 'sub')}/\tRMDIR\n"
    assert not (tree / "sub").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_rm_recursive_rmdir_failure(run: Run, tree: Path) -> None:
    (tree / "p" / "d").mkdir(parents=True)
    os.chmod(tree / "p", 0o555)
    try:
        code, out, err = run("rm", "-r", url(tree / "p" / "d"))
    finally:
        os.chmod(tree / "p", 0o755)
    assert (code, out) == (errno.EACCES, f"{url(tree / 'p' / 'd')}\tFAILED\n")
    assert err.startswith("gfal-rm error: 13 (Permission denied) - ")


def test_rm_recursive_rmdir_missing(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def gone(self: Gfal2Context, path: str) -> int:
        raise GError("gone", errno.ENOENT)

    monkeypatch.setattr(Gfal2Context, "rmdir", gone)
    code, out, _ = run("rm", "-r", url(tree / "sub"))
    assert (code, out) == (
        errno.ENOENT,
        f"{url(tree / 'sub/b')}\tDELETED\n{url(tree / 'sub')}\tMISSING\n",
    )


def test_rm_failures(run: Run) -> None:
    code, out, err = run("rm", "mock://h/f?errno=13", "mock://h/g")
    assert (code, out) == (13, "mock://h/f?errno=13\tFAILED\n")
    assert err == "gfal-rm error: 13 (Permission denied) - Permission denied\n"
    code, out, _ = run("rm", "--just-delete", "mock://h/f?errno=2", "mock://h/g")
    assert (code, out) == (2, "mock://h/f?errno=2\tMISSING\nmock://h/g\tDELETED\n")
    code, out, _ = run("rm", "-r", "mock://h/d?list=&errno=2")
    assert (code, out) == (2, "mock://h/d?list=&errno=2\tMISSING\n")
    code, out, _ = run("rm", "-r", "mock://h/d?list=&errno=5")
    assert (code, out) == (5, "mock://h/d?list=&errno=5\tFAILED\n")


def test_rm_just_delete_dry_run(run: Run, tree: Path) -> None:
    assert run("rm", "--just-delete", "--dry-run", "mock://h/f") == (0, "mock://h/f\tSKIP\n", "")


def test_rm_arguments(run: Run, tree: Path) -> None:
    listing = tree / "list"
    listing.write_text(f"{url(tree / 'a.txt')}\n\n  {url(tree / 'nope')}  \n")
    assert run("rm", "--from-file", str(listing), url(tree)) == (
        22,
        "",
        "--from-file and positional arguments can not be used at the same time\n",
    )
    assert run("rm", "--bulk", "-r", url(tree)) == (
        22,
        "",
        "--bulk and --recursive can not be used at the same time\n",
    )
    assert run("rm") == (22, "", "Missing surl\n")
    assert run("rm", "--from-file", str(listing)) == (
        2,
        f"{url(tree / 'a.txt')}\tDELETED\n{url(tree / 'nope')}\tMISSING\n",
        "",
    )


def test_rm_bulk(run: Run, tree: Path) -> None:
    assert run("rm", "--bulk", "--dry-run", url(tree / "a.txt")) == (0, "\tBULK DELETION\n", "")
    code, out, _ = run("rm", "--bulk", url(tree / "a.txt"), url(tree / "nope"), "mock://h/x")
    assert code == 2
    assert out == (
        f"{url(tree / 'a.txt')}\tDELETED\n"
        f"{url(tree / 'nope')}\tFAILED: errno reported by local system call "
        "No such file or directory\n"
        "mock://h/x\tDELETED\n"
    )
    code, out, _ = run("rm", "--just-delete", url(tree / "nope"), "mock://h/x?errno=5")
    assert code == 5  # the failure that stops the command wins


def test_rm_unexpected_error_exits_zero(run: Run, tree: Path) -> None:
    code, _, err = run("rm", "--from-file", str(tree / "missing"))
    assert code == 0  # gfal-rm starts from 0, as gfal2-util's does
    assert "FileNotFoundError" in err


# ---------------------------------------------------------------------------
# Tape
# ---------------------------------------------------------------------------


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    slept: list[float] = []
    monkeypatch.setattr(tape, "sleep", slept.append)
    return slept


def _ready_after(monkeypatch: pytest.MonkeyPatch, method: str, polls: int) -> None:
    """Make ``MockPlugin.<method>`` answer "queued" ``polls`` times, then "ready"."""
    calls = [0]

    def answer(self: MockPlugin, urls: Any, *args: Any) -> list[bool]:
        calls[0] += 1
        return [calls[0] > polls for _ in urls]

    monkeypatch.setattr(MockPlugin, method, answer)


def test_bringonline(run: Run, no_sleep: list[float]) -> None:
    code, out, _ = run("bringonline", "mock://h/f")
    lines = out.splitlines()
    assert code == 0
    assert lines[0].startswith("Bringonline token: ")
    assert lines[1:] == ["mock://h/f QUEUED"]
    code, out, _ = run("bringonline", "mock://h/f?staging_errno=22")
    assert out.splitlines()[1:] == ["mock://h/f?staging_errno=22 => FAILED: Invalid argument"]
    assert no_sleep == []


def test_bringonline_polls(
    run: Run, no_sleep: list[float], monkeypatch: pytest.MonkeyPatch
) -> None:
    _ready_after(monkeypatch, "bring_online_poll", 1)
    _code, out, _ = run("bringonline", "--polling-timeout", "1000", "mock://h/f?staging_time=100")
    assert out.splitlines()[1:] == [
        "mock://h/f?staging_time=100 QUEUED",
        "Request queued, sleep 1 seconds...",
        "mock://h/f?staging_time=100 QUEUED",
        "Request queued, sleep 2 seconds...",
        "mock://h/f?staging_time=100 READY",
    ]
    assert no_sleep == [1, 2]


def test_bringonline_poll_backoff(run: Run, no_sleep: list[float]) -> None:
    code, out, _ = run("bringonline", "--polling-timeout", "600", "mock://h/f?staging_time=100")
    assert code == 0
    assert no_sleep == [1, 2, 4, 8, 16, 32, 64, 128, 256, 300]
    assert out.count("mock://h/f?staging_time=100 QUEUED") == 11


def test_bringonline_from_file(run: Run, tree: Path, no_sleep: list[float]) -> None:
    listing = tree / "list"
    listing.write_text("mock://h/a\n\nmock://h/b?staging_errno=2\n")
    _code, out, _ = run(
        "bringonline",
        "--from-file",
        str(listing),
        "--pin-lifetime",
        "10",
        "--desired-request-time",
        "20",
        "--staging-metadata",
        "meta",
    )
    assert out.splitlines()[1:] == [
        "mock://h/a QUEUED",
        "mock://h/b?staging_errno=2 => FAILED: No such file or directory",
    ]
    assert run("bringonline", "--from-file", str(listing), "mock://h/a") == (
        1,
        "",
        "Could not combine --from-file with a surl in the positional arguments\n",
    )
    assert run("bringonline") == (1, "", "Missing surl\n")


def test_bringonline_without_token(run: Run, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_token(self: MockPlugin, urls: Any, *args: Any) -> tuple[list[Any], str]:
        return [True for _ in urls], ""

    monkeypatch.setattr(MockPlugin, "bring_online", no_token)
    assert run("bringonline", "mock://h/f") == (0, "mock://h/f QUEUED\n", "")


def test_archivepoll(run: Run, no_sleep: list[float], monkeypatch: pytest.MonkeyPatch) -> None:
    assert run("archivepoll", "mock://h/f") == (0, "mock://h/f READY\n", "")
    assert run("archivepoll", "mock://h/f?archiving_errno=22") == (
        0,
        "mock://h/f?archiving_errno=22 => FAILED: Invalid argument\n",
        "",
    )
    assert run("archivepoll") == (1, "", "Missing surl\n")
    _ready_after(monkeypatch, "archive_poll", 1)
    _code, out, _ = run("archivepoll", "--polling-timeout", "3", "mock://h/f")
    assert out == ("mock://h/f QUEUED\nArchiving ongoing, sleep 1 seconds...\nmock://h/f READY\n")


def test_evict(run: Run) -> None:
    assert run("evict", "mock://h/f") == (0, "", "")
    assert run("evict", "mock://h/f?release_errno=22", "token") == (
        22,
        "",
        "gfal-evict error: 22 (Invalid argument) - Invalid argument\n",
    )


# ---------------------------------------------------------------------------
# Version tools and the legacy commands
# ---------------------------------------------------------------------------


def test_version_tools(run: Run) -> None:
    assert run("gfal2_version") == (0, "GFAL-client-2.23.5\n", "")
    assert run("gfal_srm_ifce_version", "-x") == (0, "gfal-srm-ifce--1.24.8\n", "")


def test_legacy_help(run: Run) -> None:
    code, out, _ = run("legacy_register", "--help")
    assert code == 0
    assert out.startswith("usage: gfal-legacy-register [-h] [-V]")
    assert "\nGfal util REGISTER command. Register a replica.\n" in out
    assert "  lfc                   LFC entry (lfc:// or guid:)\n" in out
    assert "  surl                  Site URL to be unregistered\n" in out
    _, out, _ = run("legacy_unregister", "--help")
    assert "\nGfal util UNREGISTER command. Unregister a replica.\n" in out
    _, out, _ = run("legacy_replicas", "--help")
    assert "\nGfal util REPLICAS command. List replicas.\n" in out
    assert run("legacy_replicas")[0] == 2


def test_legacy_bringonline(run: Run, no_sleep: list[float]) -> None:
    notice = "This command is deprecated. Please use gfal-bringonline instead.\n"
    code, out, _ = run("legacy_bringonline", "--help")
    assert code == 0
    assert out.startswith(notice + "usage: gfal-legacy-bringonline [-h]")
    assert "\nGfal util BRINGONLINE command. Execute bring online.\n" in out
    code, out, _ = run("legacy_bringonline", "mock://h/f")
    assert code == 0
    assert out.startswith(notice + "Bringonline token: ")


def test_legacy_replicas_without_catalogue(run: Run, tree: Path) -> None:
    code, out, err = run("legacy_replicas", url(tree / "a.txt"))
    assert (code, out) == (errno.ENODATA, "")
    assert err.startswith(f"gfal-legacy-replicas error: {errno.ENODATA} (")


@pytest.fixture
def lfc(grid_env: PKI, monkeypatch: pytest.MonkeyPatch) -> Iterator[LFCServer]:
    for name in ("LFC_HOST", "LFC_PORT", "CSEC_MECH", "LFC_CONNTIMEOUT", "LFC_CONRETRYINT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LFC_CONRETRY", "0")
    with LFCServer(gsi=grid_env.server_context(), mapfile={USER_DN: "xgfal"}) as server:
        server.mkdir("/grid", 0o777)
        yield server


def test_legacy_register_replicas_unregister(run: Run, lfc: LFCServer) -> None:
    entry = lfc.url("/grid/f")
    first = "mock://se.example.org/f?size=12&checksum=0000abcd"
    second = "mock://se.example.org/g?size=12&checksum=0000abcd"
    assert run("legacy_register", entry, first) == (0, "", "")
    assert run("legacy_register", entry, second) == (0, "", "")
    assert [replica.sfn for replica in lfc.lookup("/grid/f").replicas] == [first, second]
    assert run("legacy_replicas", entry) == (0, f"{first}\n{second}\n", "")
    assert run("legacy_unregister", entry, first) == (0, "", "")
    assert run("legacy_replicas", entry) == (0, f"{second}\n", "")
    code, _, err = run("legacy_unregister", entry, first)
    assert code == errno.ENOENT
    assert err.startswith("gfal-legacy-unregister error: 2 (No such file or directory) - ")
    code, _, err = run("legacy_register", entry, "file:///no/host")
    assert code == errno.EINVAL
    assert err.startswith("gfal-legacy-register error: 22 (Invalid argument) - ")
