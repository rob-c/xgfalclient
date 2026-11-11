"""A mis-typed option in the ``gfal-*`` commands.

The suggestion itself lives in :mod:`xrdcore.suggest` and is tested there;
these are the twenty-one commands answering through the entry points a user
runs, whichever of gfal2-util's tools they typed first. gfal2-util's exit code
for a usage error is argparse's ``2``, so the command returns it rather than
letting ``SystemExit`` out.
"""

from __future__ import annotations

from typing import Any

import pytest

from xgfalclient import cli


@pytest.mark.parametrize(
    ("command", "argv", "expected"),
    [
        ("ls", ["--longg", "."], "'--long'"),
        ("stat", ["--timeoot", "1", "file:///tmp"], "'--timeout'"),
        ("xattr", ["--timetout", "1", "file:///tmp"], "'--timeout'"),
        ("sum", ["--verboze", "ADLER32", "file:///tmp"], "'--verbose'"),
        # a transposition, not an abbreviation: gfal-* accept those
        ("rm", ["--recusrive", "file:///tmp"], "'--recursive'"),
        ("chmod", ["--verboze", "0755", "file:///tmp"], "'--verbose'"),
    ],
)
def test_a_gfal_command_names_the_option_that_was_meant(
    capsys: pytest.CaptureFixture[str], command: str, argv: list[str], expected: str
) -> None:
    tool: Any = getattr(cli, command)
    assert tool(argv) == 2
    assert f"did you mean {expected}?" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("command", "argv"),
    [
        ("ls", ["."]),
        ("stat", ["file:///tmp"]),
        ("cat", ["file:///tmp"]),
        ("mkdir", ["file:///tmp/x"]),
        ("rm", ["file:///tmp"]),
        ("sum", ["ADLER32", "file:///tmp"]),
        ("chmod", ["0755", "file:///tmp"]),
    ],
)
def test_every_command_answers_a_mis_typed_option(
    capsys: pytest.CaptureFixture[str], command: str, argv: list[str]
) -> None:
    """The parser every command builds is the one that answers (xrdcore.report.Parser)."""
    tool: Any = getattr(cli, command)
    assert tool(["--no-such-option", *argv]) == 2
    assert "unrecognized arguments" in capsys.readouterr().err
