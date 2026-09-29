"""``gfal2_util.base``: ``CommandBase``, the ``@arg`` decorator, ``surl`` and ``VERSION``.

A subclass of :class:`CommandBase` declares commands as ``execute_<name>``
methods, their options with :func:`arg`, and :class:`gfal2_util.shell.Gfal2Shell`
finds them by the program name. ``self.params``, ``self.context``,
``self.return_code`` and ``self.progress_bar`` are gfal2-util's.
"""

from __future__ import annotations

from typing import Any, Callable, TypeVar

from xgfalclient.cli._base import VERSION, Command, _VersionAction, surl

__all__ = ["VERSION", "CommandBase", "Gfal2VersionAction", "arg", "surl"]

F = TypeVar("F", bound=Callable[..., Any])

#: ``-V``: the gfal2-util version, gfal2's, then the plugins.
Gfal2VersionAction = _VersionAction


def arg(*args: Any, **kwargs: Any) -> Callable[[F], F]:
    """Decorator for CLI args: ``add_argument(*args, **kwargs)`` for the method.

    Decorators apply bottom-up and each inserts at the front, so the
    arguments end up in the order they are written.
    """

    def _decorator(func: F) -> F:
        arguments: list[tuple[Any, Any]] = vars(func).setdefault("arguments", [])
        if (args, kwargs) not in arguments:
            arguments.insert(0, (args, kwargs))
        return func

    return _decorator


class CommandBase(Command):
    """What every command class derives from; ``parse(func, argv)``, ``execute(func)``."""

    @staticmethod
    def get_subclasses() -> list[type[CommandBase]]:
        return CommandBase.__subclasses__()


def _method(spec: Any) -> Callable[[CommandBase], Any]:
    """An ``execute_<name>`` method running one of :mod:`xgfalclient.cli`'s commands."""

    def execute(self: CommandBase) -> Any:
        return spec(self)

    execute.__name__ = spec.__name__
    execute.__qualname__ = spec.__name__
    execute.__doc__ = spec.doc
    vars(execute)["arguments"] = list(spec.arguments)
    return execute
