"""``gfal2_util.base``: ``CommandBase``, the ``@arg`` decorator, ``surl`` and ``VERSION``.

A subclass of :class:`CommandBase` declares commands as ``execute_<name>``
methods, their options with :func:`arg`, and :class:`gfal2_util.shell.Gfal2Shell`
finds them by the program name. ``self.params``, ``self.context``,
``self.return_code`` and ``self.progress_bar`` are gfal2-util's.

``CommandBase`` *is* :class:`xgfalclient.cli._base.Command`, so a user's
``execute_<name>`` method receives the same object the built-in commands
do; the built-in ``execute_*`` methods are made by :func:`_method` from the
shared ``Spec`` objects.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from xgfalclient.cli._base import VERSION, Command, _VersionAction, surl

__all__ = ["VERSION", "CommandBase", "Gfal2VersionAction", "arg", "surl"]

#: The decorated method's type, preserved by :func:`arg`.
F = TypeVar("F", bound=Callable[..., Any])

#: ``-V``: the gfal2-util version, gfal2's, then the plugins.
Gfal2VersionAction = _VersionAction


def arg(*args: Any, **kwargs: Any) -> Callable[[F], F]:
    """Decorator for CLI args: ``add_argument(*args, **kwargs)`` for the method.

    Decorators apply bottom-up and each inserts at the front, so the
    arguments end up in the order they are written.
    """

    def _decorator(func: F) -> F:
        """Prepend this argument to ``func.arguments`` (once, however often applied)."""
        arguments: list[tuple[Any, Any]] = vars(func).setdefault("arguments", [])
        if (args, kwargs) not in arguments:
            arguments.insert(0, (args, kwargs))
        return func

    return _decorator


class CommandBase(Command):
    """What every command class derives from; ``parse(func, argv)``, ``execute(func)``.

    gfal2-util's ``gfal2_util.base.CommandBase``. Behaviour (threading,
    ``-t``, ``Ctrl-C``, error printing, exit statuses) is inherited
    unchanged from :class:`~xgfalclient.cli._base.Command`.
    """

    @staticmethod
    def get_subclasses() -> list[type[CommandBase]]:
        """Direct subclasses only, as gfal2-util looks them up (``__subclasses__``).

        A user command class must therefore derive from ``CommandBase``
        itself, not from one of the built-in command classes, to be found by
        :class:`~gfal2_util.shell.Gfal2Shell`.
        """
        return CommandBase.__subclasses__()


def _method(spec: Any) -> Callable[[CommandBase], Any]:
    """An ``execute_<name>`` method running one of :mod:`xgfalclient.cli`'s commands."""

    def execute(self: CommandBase) -> Any:
        """Replaced below by the command's own help line (``spec.doc``)."""
        return spec(self)

    execute.__name__ = spec.__name__
    execute.__qualname__ = spec.__name__
    # The parser's description comes from the first line of __doc__, as for a
    # hand-written execute_<name>, so the help text is the Spec's.
    execute.__doc__ = spec.doc
    vars(execute)["arguments"] = list(spec.arguments)
    return execute
