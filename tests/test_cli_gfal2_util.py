"""The ``gfal2_util`` package: gfal2-util's modules and names, driving ``xgfalclient.cli``.

Callers use it as gfal2-util's scripts do - ``Gfal2Shell().main(sys.argv)``
- or subclass ``base.CommandBase`` with ``@base.arg``-decorated
``execute_<name>`` methods of their own.
"""

from __future__ import annotations

import argparse
import errno
import logging
import os
import time
from pathlib import Path
from typing import Any

import pytest

import xgfalclient
from gfal2_util import (
    base,
    commands,
    copy,
    gfal2_utils_parameters,
    legacy,
    ls,
    progress,
    rm,
    shell,
    tape,
    utils,
)
from xgfalclient.cli import _progress
from xgfalclient.cli import _utils as cli_utils


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LS_COLORS", raising=False)
    monkeypatch.setattr(cli_utils, "_colors", None)


def url(path: Path) -> str:
    return "file://" + os.fspath(path)


def test_public_names() -> None:
    assert base.VERSION == "1.9.1"
    assert base.surl("/x") == "file:///x"
    assert base.Gfal2VersionAction is not None
    assert progress.Progress is _progress.Progress
    assert utils.file_mode_str(0o40755) == "drwxr-xr-x"
    assert utils.file_type_str(0o100000) == "regular file"
    assert ls.CommandLs._size_to_human(1024) == "1.0K"
    assert sorted(ls.time_formats) == ["full-iso", "iso", "locale", "long-iso"]
    assert ls.full_iso(0).endswith(" +0000") and len(ls.long_iso(0)) == 16
    assert ls.time_iso(0) and ls.time_locale(0)
    assert isinstance(ls.color_dict, dict)
    classes = base.CommandBase.get_subclasses()
    for clasz in (
        commands.GfalCommands,
        ls.CommandLs,
        legacy.CommandLegacy,
        copy.CommandCopy,
        rm.CommandRm,
        tape.CommandTape,
    ):
        assert clasz in classes
    assert commands.GfalCommands.execute_stat.__doc__ == "Stats a file"
    assert [flags for flags, _ in legacy.CommandLegacy.execute_register.arguments] == [  # type: ignore[attr-defined]
        ("lfc",),
        ("surl",),
    ]


def test_command_factory() -> None:
    assert shell.CommandFactory.get_command("ls") == (ls.CommandLs, ls.CommandLs.execute_ls)
    assert shell.CommandFactory.get_command("register")[0] is legacy.CommandLegacy
    assert shell.CommandFactory.get_command("bringonline")[0] is tape.CommandTape
    with pytest.raises(ValueError, match="Invalid command"):
        shell.CommandFactory.get_command("nope")
    assert rm.CommandRm().return_code == 0
    assert commands.GfalCommands().return_code == -1


def test_shell_runs_the_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "a").write_text("hello\n")
    assert shell.Gfal2Shell().main(["/usr/bin/gfal-ls", url(tmp_path)]) == 0
    assert shell.Gfal2Shell().main(["gfal-cat", url(tmp_path / "a")]) is None
    assert capsys.readouterr().out == "a\nhello\n"
    assert shell.Gfal2Shell().main(["gfal-STAT", url(tmp_path / "nope")]) == errno.ENOENT
    assert capsys.readouterr().err.startswith("gfal-STAT error: 2 (No such file or directory)")
    assert shell.Gfal2Shell().main(["gfal-rm", url(tmp_path / "nope")]) == errno.ENOENT
    assert shell.Gfal2Shell().main(["gfal-legacy-bringonline", "mock://h/f"]) is None
    assert "Bringonline token: " in capsys.readouterr().out


def test_shell_lets_exits_and_bad_definitions_escape(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as help_exit:
        shell.Gfal2Shell().main(["gfal-copy", "--help"])
    assert help_exit.value.code == 0
    assert "Gfal util COPY command. Copy a file or set of files." in capsys.readouterr().out
    root = logging.getLogger()
    handlers = list(root.handlers)
    with pytest.raises(ValueError, match="doesn't include value"):
        shell.Gfal2Shell().main(["gfal-ls", "-D", "CORE:X", url(tmp_path)])
    assert root.handlers == handlers


def test_user_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "a").write_text("hello\n")
    duplicate = base.arg("-x", action="store_true", help="shout")

    class CommandHello(base.CommandBase):
        @base.arg("file", type=base.surl, help="file's uri")
        @duplicate
        @duplicate
        def execute_hello(self) -> int:
            """
            Say hello

            More text that is not the description.
            """
            size = self.context.stat(self.params.file).st_size
            print(("HELLO" if self.params.x else "hello"), size)
            return 7

        def execute_bare(self) -> None:
            raise xgfalclient.GError("bare failure", errno.EIO)

    assert [flags for flags, _ in CommandHello.execute_hello.arguments] == [("file",), ("-x",)]  # type: ignore[attr-defined]
    assert shell.Gfal2Shell().main(["gfal-hello", "-x", url(tmp_path / "a")]) == 7
    assert capsys.readouterr().out == "HELLO 6\n"
    with pytest.raises(SystemExit):
        shell.Gfal2Shell().main(["gfal-hello", "--help"])
    assert "\nGfal util HELLO command. Say hello.\n" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        shell.Gfal2Shell().main(["gfal-bare", "--help"])
    assert "\nGfal util BARE command. .\n" in capsys.readouterr().out
    assert shell.Gfal2Shell().main(["gfal-bare"]) == errno.EIO
    assert capsys.readouterr().err == "gfal-bare error: 5 (Input/output error) - bare failure\n"


def test_parameters() -> None:
    assert gfal2_utils_parameters.parse_parameter("G:K=1,yes,x") == ("G", "K", [1, True, "x"])
    assert gfal2_utils_parameters.get_parameter_from_str("no") is False
    assert gfal2_utils_parameters.get_parameter_from_str_list("7,y") == [7, True]
    context = xgfalclient.creat_context()
    gfal2_utils_parameters.set_gfal_tool_parameter(context, ("G", "K", [5]))
    assert context.get_opt_integer("G", "K") == 5
    params: dict[str, Any] = {
        "definition": [["G:S=text"]],
        "client_info": ["k=v"],
        "ipv4": True,
        "ipv6": False,
        "timeout": 9,
    }
    gfal2_utils_parameters.apply_option(context, argparse.Namespace(**params))
    assert context.get_opt_string("G", "S") == "text"
    assert context.get_opt_integer("CORE", "NAMESPACE_TIMEOUT") == 9
    assert context.get_client_info() == {"k": "v"}
    context.free()


def test_timeout() -> None:
    with utils.Timeout(5):
        pass
    with pytest.raises(utils.Timeout.Timeout), utils.Timeout(1):
        time.sleep(5)
