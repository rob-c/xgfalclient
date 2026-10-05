"""``python -m xgfalclient.cli <command> [args...]``: any ``gfal-*`` command.

The command may be spelled ``ls`` or ``gfal-ls``; ``gfal2_version`` and
``gfal_srm_ifce_version`` run too.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from . import COMMANDS, TOOLS, run
from ._base import output


def main(argv: Sequence[str] | None = None) -> int:
    return output.run_cli("xgfalclient", argv, lambda: _main(argv))


def _main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    command = args[0].rpartition("gfal-")[2] if args else ""
    if command in TOOLS:
        return TOOLS[command](args[1:])
    if command not in COMMANDS:
        sys.stderr.write(
            "usage: python -m xgfalclient.cli {" + ",".join(COMMANDS) + "} [arguments...]\n"
        )
        return 2
    return run(command, args[1:])


if __name__ == "__main__":
    sys.exit(main())
