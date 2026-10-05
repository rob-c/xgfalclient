"""``gfal2_util.shell``: ``Gfal2Shell().main(argv)`` runs the command ``argv[0]`` names.

Every gfal2-util script is ``sys.exit(Gfal2Shell().main(sys.argv))``: the
part of the program name after its last ``-`` picks the ``execute_<name>``
method among the subclasses of :class:`gfal2_util.base.CommandBase`,
including any the caller defined. ``main`` returns what the command did
(``None`` for success, as gfal2-util's does) and lets ``--help``'s
``SystemExit`` and a malformed ``-D``'s ``ValueError`` escape.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Callable

from xgfalclient.cli._base import exit_status, output

from . import base
from . import commands as commands
from . import copy as copy
from . import legacy as legacy
from . import ls as ls
from . import rm as rm
from . import tape as tape

__all__ = ["CommandFactory", "Gfal2Shell"]


class CommandFactory:
    @staticmethod
    def get_command(cmd: str) -> tuple[type[base.CommandBase], Callable[..., Any]]:
        """The class and ``execute_<cmd>`` method for ``cmd``; ``ValueError`` if none has it."""
        for clasz in base.CommandBase.get_subclasses():
            func = getattr(clasz, "execute_" + cmd, None)
            if func is not None:
                return clasz, func
        raise ValueError("Invalid command")


class Gfal2Shell:
    def main(self, args: Sequence[str]) -> int | None:
        """Entry point"""
        if output.requested(args[1:]):
            return output.run_cli(args[0], args[1:], lambda: exit_status(self._main(args)))
        return self._main(args)

    def _main(self, args: Sequence[str]) -> int | None:
        cmd = args[0].rsplit("-", 1)[1].lower()
        command_class, command_func = CommandFactory.get_command(cmd)
        inst = command_class()
        inst.parse(command_func, args)
        return inst.execute(command_func)
