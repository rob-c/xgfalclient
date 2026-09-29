"""``gfal-copy`` and its progress bar, against ``file://`` and ``mock://``.

Expected outputs are gfal2-util 1.9.1's; ``test_cli_parity.py`` checks them
against the real thing.
"""

from __future__ import annotations

import errno
import io
import os
import stat
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from xgfalclient import cli
from xgfalclient.cli import _base as base
from xgfalclient.cli import _copy as copy_module
from xgfalclient.cli import _progress as progress
from xgfalclient.context import Gfal2Context
from xgfalclient.errors import GError
from xgfalclient.events import GfaltEvent
from xgfalclient.transfer import TransferParameters
from xgfalclient.types import Stat

Run = Callable[..., tuple[int, str, str]]


@pytest.fixture
def run(capsys: pytest.CaptureFixture[str]) -> Run:
    def _run(*args: str) -> tuple[int, str, str]:
        code = cli.copy(list(args))
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return _run


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "a.txt").write_text("hello\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b").write_text("x\n")
    (tmp_path / "sub" / "deep").mkdir()
    (tmp_path / "sub" / "deep" / "c").write_text("y\n")
    return tmp_path


def url(path: Path | str) -> str:
    return "file://" + os.fspath(path)


@pytest.fixture
def params(monkeypatch: pytest.MonkeyPatch) -> list[TransferParameters]:
    """Every ``TransferParameters`` handed to ``filecopy``."""
    seen: list[TransferParameters] = []
    original = Gfal2Context.filecopy

    def spy(self: Gfal2Context, *args: Any) -> Any:
        seen.append(args[0])
        return original(self, *args)

    monkeypatch.setattr(Gfal2Context, "filecopy", spy)
    return seen


# ---------------------------------------------------------------------------
# Single files
# ---------------------------------------------------------------------------


def test_copy(run: Run, tree: Path) -> None:
    source, target = url(tree / "a.txt"), url(tree / "o")
    assert run(source, target) == (0, f"Copying 6 bytes {source} => {target}\n", "")
    assert (tree / "o").read_text() == "hello\n"
    assert run(source, target) == (
        17,
        "",
        "gfal-copy error: 17 (File exists) - "
        f"Destination {target} exists and overwrite is not set\n",
    )
    (tree / "a.txt").write_text("again\n")
    assert run("-f", source, target)[0] == 0
    assert (tree / "o").read_text() == "again\n"


def test_copy_local_paths(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tree)
    _code, out, _ = run("a.txt", "o")
    assert (
        out == f"Copying 6 bytes {url(os.path.abspath('a.txt'))} => {url(os.path.abspath('o'))}\n"
    )


def test_copy_into_directory(run: Run, tree: Path) -> None:
    source = url(tree / "a.txt")
    assert run(source, url(tree / "sub"))[1] == (
        f"Copying 6 bytes {source} => {url(tree / 'sub' / 'a.txt')}\n"
    )
    code, out, err = run(source, url(tree / "sub") + "/")
    assert out == f"Copying 6 bytes {source} => {url(tree / 'sub' / 'a.txt')}\n"
    assert (code, err) == (
        17,
        "gfal-copy error: 17 (File exists) - The file exists and overwrite is not set\n",
    )


def test_copy_missing_source(run: Run, tree: Path) -> None:
    assert run(url(tree / "nope"), url(tree / "o")) == (
        2,
        "",
        "gfal-copy error: 2 (No such file or directory) - Could not stat the source: "
        "errno reported by local system call No such file or directory\n",
    )


def test_copy_parent(run: Run, tree: Path) -> None:
    assert run("-p", url(tree / "a.txt"), url(tree / "x" / "y"))[0] == 0
    assert (tree / "x" / "y").read_text() == "hello\n"
    code, _, err = run(url(tree / "a.txt"), url(tree / "q" / "y"))
    assert code == 2
    assert "Could not open destination" in err


def test_copy_dry_run(run: Run, tree: Path) -> None:
    assert run("--dry-run", url(tree / "a.txt"), url(tree / "o"))[0] == 0
    assert not (tree / "o").exists()


def test_copy_checksums(run: Run, tree: Path, params: list[TransferParameters]) -> None:
    source = url(tree / "a.txt")
    assert run("-K", "ADLER32", source, url(tree / "o1"))[0] == 0
    assert params[-1].get_checksum() == (3, "ADLER32", "")
    assert (
        run("-K", "adler32:084b021f", "--checksum-mode", "source", source, url(tree / "o2"))[0] == 0
    )
    assert params[-1].get_checksum() == (1, "adler32", "084b021f")
    code, _, err = run("-K", "ADLER32:deadbeef", source, url(tree / "o3"))
    assert code == errno.EIO
    assert err == (
        "gfal-copy error: 5 (Input/output error) - SOURCE CHECKSUM MISMATCH Source checksum "
        "and user-specified checksum do not match: 084b021f != deadbeef\n"
    )
    code, _, err = run("-K", "MD5", "--checksum-mode", "target", source, url(tree / "o4"))
    assert code == errno.EINVAL
    assert "Checksum value required if mode is not end to end" in err


def test_copy_knobs(
    run: Run, tree: Path, params: list[TransferParameters], monkeypatch: pytest.MonkeyPatch
) -> None:
    options: list[dict[str, dict[str, str]]] = []
    original = Gfal2Context.free

    def spy(self: Gfal2Context) -> None:
        options.append(self.options.snapshot())
        original(self)

    monkeypatch.setattr(Gfal2Context, "free", spy)
    code, _, _ = run(
        "-n", "4", "--tcp-buffersize", "65536", "-s", "SRC", "-S", "DST", "-T", "60",
        "--disable-cleanup", "--no-delegation", "--evict", "--scitag", "65",
        "--copy-mode", "push", url(tree / "a.txt"), url(tree / "o"),
    )  # fmt: skip
    assert code == 0
    transfer = params[-1]
    assert (transfer.nbstreams, transfer.tcp_buffersize, transfer.timeout) == (4, 65536, 60)
    assert (transfer.src_spacetoken, transfer.dst_spacetoken) == ("SRC", "DST")
    assert transfer.transfer_cleanup is False
    assert transfer.proxy_delegation is False
    assert transfer.evict is True
    assert transfer.scitag == 65
    http = options[-1]["HTTP PLUGIN"]
    assert (http["ENABLE_REMOTE_COPY"], http["ENABLE_FALLBACK_TPC_COPY"]) == ("true", "false")
    assert http["DEFAULT_COPY_MODE"] == "3rd push"

    run("--copy-mode", "pull", url(tree / "a.txt"), url(tree / "o2"))
    assert options[-1]["HTTP PLUGIN"]["DEFAULT_COPY_MODE"] == "3rd pull"
    run("--copy-mode", "streamed", url(tree / "a.txt"), url(tree / "o3"))
    http = options[-1]["HTTP PLUGIN"]
    assert (http["ENABLE_REMOTE_COPY"], http["DEFAULT_COPY_MODE"]) == ("false", "streamed")
    assert "ENABLE_FALLBACK_TPC_COPY" not in http or http["ENABLE_FALLBACK_TPC_COPY"] != "false"


def test_copy_defaults(run: Run, tree: Path, params: list[TransferParameters]) -> None:
    assert run(url(tree / "a.txt"), url(tree / "o"))[0] == 0
    transfer = params[-1]
    assert (transfer.nbstreams, transfer.timeout, transfer.overwrite) == (0, 3600, False)
    assert (transfer.create_parent, transfer.strict_copy, transfer.scitag) == (False, False, 0)


def test_copy_verbose(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("xgfalclient.transfer.MONITOR_INTERVAL", 3600.0)  # load-proof
    source, target = url(tree / "a.txt"), url(tree / "o")
    _code, out, _ = run("-v", source, target)
    lines = out.splitlines()
    assert lines[0] == f"Copying 6 bytes {source} => {target}"
    events = [line for line in lines if line.startswith("event: ")]
    assert events[0].endswith("GFAL2:CORE:COPY\tLIST:ENTER\t")
    assert any(line.endswith(f"TRANSFER:ENTER\t{source} => {target}") for line in events)
    # A sub-second copy is never reported to monitor_callback, as in gfal2.
    assert not [line for line in lines if line.startswith("monitor: ")]


def test_copy_verbose_monitor_lines(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("xgfalclient.transfer.MONITOR_INTERVAL", 0.0)  # report every chunk
    source, target = url(tree / "a.txt"), url(tree / "o")
    _code, out, _ = run("-v", source, target)
    monitors = [line for line in out.splitlines() if line.startswith("monitor: ")]
    assert monitors and monitors[-1].split()[1:3] == [source, target]
    assert monitors[-1].split()[5] == "6"


def test_copy_mock(run: Run) -> None:
    source, target = "mock://h/src?size=10&time=0", "mock://h/dst?size_post=10&time=0"
    assert run(source, target)[0] == errno.EEXIST  # gfal2: a size_post destination exists
    assert run("-f", source, target) == (0, f"Copying 10 bytes {source} => {target}\n", "")
    failing = target + "&transfer_errno=5"
    assert run("-f", source, failing) == (
        5,
        f"Copying 10 bytes {source} => {failing}\n",
        "gfal-copy error: 5 (Input/output error) - Input/output error\n",
    )


def test_copy_force_retries_after_eexist(
    run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    original = Gfal2Context.filecopy

    def once(self: Gfal2Context, *args: Any) -> Any:
        calls.append(args[2])
        if len(calls) == 1:
            raise GError("The file exists and overwrite is not set", errno.EEXIST)
        return original(self, *args)

    monkeypatch.setattr(Gfal2Context, "filecopy", once)
    (tree / "o").write_text("old")
    source, target = url(tree / "a.txt"), url(tree / "o")
    assert run("-f", source, target) == (
        0,
        f"Copying 6 bytes {source} => {target}\nCopying 6 bytes {source} => {target}\n",
        "",
    )
    assert calls == [target, target]


def test_copy_lfc_destination_warns(run: Run, tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original = Gfal2Context.stat

    def lfc_stat(self: Gfal2Context, path: str) -> Stat:
        if path.startswith("lfc://"):
            return Stat(st_mode=stat.S_IFREG | 0o644, st_size=1)
        return original(self, path)

    monkeypatch.setattr(Gfal2Context, "stat", lfc_stat)
    code, out, _err = run("-v", url(tree / "a.txt"), "lfc://h/f")
    assert out.startswith(
        "WARNING Destination exists, but it is an LFC, so try to add a new replica\n"
        f"Copying 6 bytes {url(tree / 'a.txt')} => lfc://h/f\n"
    )
    # The LFC plugin takes the copy and, like gfal2, cannot register a local
    # file as a replica.
    assert code == errno.EINVAL


# ---------------------------------------------------------------------------
# Special destinations
# ---------------------------------------------------------------------------


def test_copy_to_stdout(tree: Path, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
    source = url(tree / "a.txt")
    assert cli.copy([source, "-"]) == 0
    assert capsysbinary.readouterr().out == (
        f"Copying 6 bytes {source} => file:///dev/stdout\nhello\n".encode()
    )
    assert cli.copy(["--just-copy", source, "-"]) == 0
    assert capsysbinary.readouterr().out == (
        f"Copying 0 bytes {source} => file:///dev/stdout\nhello\n".encode()
    )


def test_copy_to_dev_null(run: Run, tree: Path) -> None:
    assert run("-f", url(tree / "a.txt"), "file:///dev/null")[0] == 0
    assert os.path.exists("/dev/null")


def test_copy_to_fifo(run: Run, tree: Path) -> None:
    fifo = tree / "fifo"
    os.mkfifo(fifo)
    received: list[bytes] = []
    reader = threading.Thread(target=lambda: received.append(fifo.read_bytes()))
    reader.start()
    assert run(url(tree / "a.txt"), url(fifo))[0] == 0
    reader.join(10)
    assert received == [b"hello\n"]


def test_stream_to_unopenable_special(tree: Path, capsys: pytest.CaptureFixture[str]) -> None:
    command = base.Command("gfal-copy", copy_module.SPECS["copy"])
    command.parse([url(tree / "a.txt"), url(tree / "o")])
    command.context = Gfal2Context()
    copier = copy_module._Copier(command)
    with pytest.raises(GError) as error:
        copier.stream(url(tree / "a.txt"), url(tree / "no" / "dev"))
    assert error.value.code == errno.ENOENT
    command.context.free()


def test_copy_stream_read_failure(run: Run, tree: Path) -> None:
    code, _, _err = run("mock://h/f?size=10&read_errno=5", "-")
    assert code == 5


def test_just_copy(run: Run, tree: Path, params: list[TransferParameters]) -> None:
    source, target = url(tree / "a.txt"), url(tree / "o")
    assert run("--just-copy", source, target) == (0, f"Copying 0 bytes {source} => {target}\n", "")
    assert params[-1].strict_copy is True
    assert (tree / "o").read_text() == "hello\n"


# ---------------------------------------------------------------------------
# Chains and lists
# ---------------------------------------------------------------------------


def test_chain(run: Run, tree: Path) -> None:
    a, c1, sub, c3 = url(tree / "a.txt"), url(tree / "c1"), url(tree / "sub"), url(tree / "c3")
    code, out, _ = run(a, c1, sub, c3)
    assert code == 0
    assert out == (
        f"Copying 6 bytes {a} => {c1}\n"
        f"Copying 6 bytes {c1} => {sub}/c1\n"
        f"Copying 6 bytes {sub}/c1 => {c3}\n"
    )


def test_chain_just_copy_does_not_stat(run: Run, tree: Path) -> None:
    a, sub2 = url(tree / "a.txt"), url(tree / "s2")
    _code, out, _ = run("--just-copy", a, url(tree / "c1"), sub2)
    assert out.splitlines()[1] == f"Copying 0 bytes {url(tree / 'c1')} => {sub2}"


def test_missing_source(run: Run, tree: Path) -> None:
    assert run(url(tree / "a.txt")) == (1, "", "Missing source\n")
    code, _, err = run()
    assert code == 2
    assert err.endswith("gfal-copy: error: the following arguments are required: dst\n")


def test_from_file(run: Run, tree: Path) -> None:
    listing = tree / "list"
    listing.write_text(f"{url(tree / 'a.txt')}\n\n  {url(tree / 'sub' / 'b')}\n")
    code, out, _ = run("--from-file", str(listing), url(tree / "sub" / "deep"))
    assert code == 0
    assert out == (
        f"Copying 6 bytes {url(tree / 'a.txt')} => {url(tree / 'sub/deep/a.txt')}\n"
        f"Copying 2 bytes {url(tree / 'sub/b')} => {url(tree / 'sub/deep/b')}\n"
    )
    assert run("--from-file", str(listing), url(tree / "a.txt"), url(tree / "o")) == (
        1,
        "",
        "Cannot combine '--from-file' with a source in the positional arguments\n",
    )


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------


def test_directory_to_new_directory(run: Run, tree: Path) -> None:
    code, out, _ = run(url(tree / "sub"), url(tree / "copy"))
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == f"Mkdir {url(tree / 'copy')}"
    assert f"Mkdir {url(tree / 'copy/deep')}" in lines
    assert f"Copying 2 bytes {url(tree / 'sub/b')} => {url(tree / 'copy/b')}" in lines
    assert (tree / "copy" / "deep" / "c").read_text() == "y\n"


def test_directory_dry_run(run: Run, tree: Path) -> None:
    _code, out, _ = run("--dry-run", url(tree / "sub") + "/", url(tree / "copy") + "/")
    assert f"Mkdir {url(tree / 'copy')}/" in out
    assert f"Copying 2 bytes {url(tree / 'sub/b')} => {url(tree / 'copy/b')}" in out
    assert not (tree / "copy").exists()


def test_directory_onto_existing_directory(run: Run, tree: Path) -> None:
    (tree / "copy").mkdir()
    assert run(url(tree / "sub"), url(tree / "copy")) == (0, f"Skipping {url(tree / 'sub')}\n", "")
    code, out, _ = run("-r", url(tree / "sub"), url(tree / "copy"))
    assert code == 0
    assert (tree / "copy" / "b").exists()
    code, out, _ = run("-r", url(tree / "sub"), url(tree / "copy"))
    assert code == 0
    assert f"ERROR (17): Destination {url(tree / 'copy/b')} exists and overwrite is not set" in out
    code, out, err = run("-r", "--abort-on-failure", url(tree / "sub"), url(tree / "copy"))
    assert code == 17
    assert "exists and overwrite is not set" in err


def test_directory_over_file(run: Run, tree: Path) -> None:
    assert run("-f", url(tree / "sub"), url(tree / "a.txt")) == (
        21,
        "",
        "gfal-copy error: 21 (Is a directory) - Can not copy a directory over a file\n",
    )
    assert run("-r", "-f", url(tree / "sub"), url(tree / "a.txt")) == (
        0,
        "ERROR (21): Can not copy a directory over a file\n",
        "",
    )


def test_directory_mkdir_failure(run: Run, tree: Path) -> None:
    code, out, err = run(url(tree / "sub"), url(tree / "a.txt" / "x"))
    assert out == f"Mkdir {url(tree / 'a.txt/x')}\n"
    assert code == errno.ENOTDIR
    assert "Could not create the directory: " in err
    code, out, err = run("-r", url(tree / "sub"), url(tree / "a.txt" / "x"))
    assert code == 0
    assert out.splitlines()[1].startswith(
        f"ERROR ({errno.ENOTDIR}): Could not create the directory: "
    )


def test_recursive_failures_carry_on(run: Run, tree: Path) -> None:
    code, out, _ = run("-r", url(tree / "nope"), url(tree / "o"))
    assert code == 0
    assert out.startswith("ERROR (2): Could not stat the source: ")


# ---------------------------------------------------------------------------
# The progress bar
# ---------------------------------------------------------------------------


@pytest.fixture
def tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base, "stdout_isatty", lambda: True)
    monkeypatch.setattr(progress, "INTERVAL", 0.01)


def test_progress_bar_on_a_tty(run: Run, tree: Path, tty: None) -> None:
    source = "mock://h/src?size=1048576&time=0"
    code, out, _ = run("-f", source, "mock://h/dst?size_post=1048576&time=0")
    assert code == 0
    assert f"\rCopying {source}   [DONE]  after 0s" in out
    assert out.endswith("\n")


def test_progress_bar_failure(run: Run, tree: Path, tty: None) -> None:
    code, out, _ = run(
        "-f", "mock://h/s?size=1&time=0", "mock://h/d?size_post=1&time=0&transfer_errno=5"
    )
    assert code == 5
    assert "[FAILED]" in out


def test_progress_bar_timeout(
    run: Run, tree: Path, tty: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(base, "TIMEOUT_GRACE", 0)
    code, out, err = run(
        "-t", "1", "-f", "mock://h/s?size=1&time=2", "mock://h/d?size_post=1&time=2"
    )
    assert code == errno.ETIMEDOUT
    assert err == "Command timed out after 1 seconds!\n"
    assert "[FAILED]  after 1s" in out
    for thread in threading.enumerate():
        if thread.name == "gfal-command":
            thread.join(10)


def _bar(status: dict[str, Any] | None, width: int = 80) -> str:
    bar = progress.Progress("Copying x")
    bar.status = status
    out = io.StringIO()
    original = sys.stdout
    sys.stdout = out
    original_width = progress._width
    progress._width = lambda: width  # type: ignore[assignment]
    try:
        bar._update()
    finally:
        sys.stdout = original
        progress._width = original_width  # type: ignore[assignment]
    return out.getvalue()


def test_progress_rendering() -> None:
    assert _bar(None) == "\rCopying x     0s "
    assert _bar({}) == "\rCopying x     0s "
    assert _bar({"rate": 5}) == "\rCopying x     0s " + " " * 63
    assert _bar({"total_size": 2048}) == "\rCopying x     0s  File size: 2.00KB" + " " * 45
    assert _bar({"curr_size": 10}) == "\rCopying x     0s " + " " * 59 + "10B "
    assert _bar({"curr_size": 10, "rate": 5}) == "\rCopying x     0s " + " " * 55 + "10B 5B/s"
    status = {"curr_size": 512, "total_size": 1024, "rate": 512.0, "percentage": 50.0}
    line = _bar(status)
    assert line.startswith("\rCopying x     0s 50% [")
    assert line.endswith("] 512B 512B/s")
    assert len(line) == 81
    narrow = _bar(status, width=30)
    assert "50% [=>" in narrow
    tiny = {"curr_size": 1, "total_size": 10000, "rate": 1.0, "percentage": 0.01}
    assert "[>" in _bar(tiny)


@pytest.mark.parametrize(
    ("value", "rate", "size"),
    [
        (0, "0B/s", "0B"),
        (1023, "1023B/s", "1023B"),
        (1024, "1.00K/s", "1.00KB"),
        (10 * 1024, "10.0K/s", "10.0KB"),
        (500 * 1024, "500K/s", "500KB"),
        (3 * 1024**2, "3.00M/s", "3.00MB"),
        (2000 * 1024**5, "2000P/s", "2000PB"),
    ],
)
def test_rate_and_size(value: int, rate: str, size: str) -> None:
    assert progress.rate_str(value) == rate
    assert progress.size_str(value) == size


def test_progress_update() -> None:
    bar = progress.Progress("x")
    bar.update(total_size=100)
    assert bar.status == {"total_size": 100}
    bar.update(50, 100, 10, 5)
    assert bar.status == {"curr_size": 50, "total_size": 100, "rate": 10.0, "percentage": 50.0}
    bar.update(50, rate=7)
    assert bar.status == {"curr_size": 50, "rate": 7}
    bar.update(50, rate=7, time_elapsed=5)  # no total: no percentage, the given rate
    assert bar.status == {"curr_size": 50, "rate": 7}
    bar.update()
    assert bar.status == {}


def test_progress_lifecycle(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(progress, "INTERVAL", 0.01)
    bar = progress.Progress("Copying x")
    bar.stop(True)  # not started: nothing
    bar.start()
    with pytest.raises(RuntimeError):
        bar.start()
    bar.stop(True)
    bar.stop(False)  # already stopped: nothing
    assert bar.thread is not None
    bar.thread.join(5)
    out = capsys.readouterr().out
    assert out.endswith("\rCopying x   [DONE]  after 0s" + " " * 52)
    assert out.count("[DONE]") == 1


def test_width(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO())
    assert progress._width() == 80
    monkeypatch.setattr(os, "get_terminal_size", lambda fd: os.terminal_size((132, 40)))
    monkeypatch.setattr(sys, "stdin", sys.__stdin__)
    assert progress._width() == 132


def test_event_callback_quiet(tree: Path) -> None:
    command = base.Command("gfal-copy", copy_module.SPECS["copy"])
    command.parse([url(tree / "a.txt"), url(tree / "o")])
    command.context = Gfal2Context()
    transfer = copy_module._Copier(command).parameters(6)
    assert transfer.event_callback is not None
    transfer.event_callback(GfaltEvent())
    command.context.free()
