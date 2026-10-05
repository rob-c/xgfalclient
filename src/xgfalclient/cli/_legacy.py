"""``gfal-legacy-register``, ``-unregister`` and ``-replicas``: an LFC entry's replicas.

gfal2-util's ``legacy`` commands, which drive the catalogue through the
``user.replicas`` extended attribute of an ``lfc://`` or ``guid:`` entry:
``setxattr`` with ``+surl`` registers a replica, ``-surl`` unregisters one,
and ``getxattr`` lists them, one per line. The help text is gfal2-util's,
including ``surl``'s "to be unregistered" for register too.

(``gfal-legacy-bringonline`` is ``gfal-bringonline`` under another name,
after a deprecation notice; see :func:`xgfalclient.cli.run`.)
"""

from __future__ import annotations

from ._base import Command, Spec, arg, out, output, surl

__all__ = ["SPECS", "REPLICAS"]

#: The extended attribute that holds an LFC entry's replicas.
REPLICAS = "user.replicas"


def _set(cmd: Command, sign: str) -> None:
    output.identify(
        "register" if sign == "+" else "unregister", url=cmd.params.lfc, replica=cmd.params.surl
    )
    value = sign + cmd.params.surl
    cmd.context.setxattr(cmd.params.lfc, REPLICAS, value, len(value))
    output.record(status="succeeded")


def register(cmd: Command) -> None:
    _set(cmd, "+")


def unregister(cmd: Command) -> None:
    _set(cmd, "-")


def replicas(cmd: Command) -> None:
    output.identify("replicas", url=cmd.params.lfc)
    for replica in cmd.context.getxattr(cmd.params.lfc, REPLICAS).split("\n"):
        output.record(status="succeeded", replica=replica)
        out(replica + "\n")


_LFC = arg("lfc", action="store", type=surl, help="LFC entry (lfc:// or guid:)")
_SURL = arg("surl", action="store", type=surl, help="Site URL to be unregistered")

SPECS = {
    "legacy-register": Spec("register", "Register a replica.", [_LFC, _SURL], register),
    "legacy-unregister": Spec("unregister", "Unregister a replica.", [_LFC, _SURL], unregister),
    "legacy-replicas": Spec("replicas", "List replicas.", [_LFC], replicas),
}
