"""The machinery every ``gfal-*`` command shares, as gfal2-util 1.9.1 has it.

A command is a :class:`Spec` - its one-line description, its arguments and a
function taking a :class:`Command` - and :func:`main` runs one the way
gfal2-util's ``CommandBase`` does:

* the same ``argparse`` parser, with the same common options and help text;
* ``--cert``/``--key`` exported as ``X509_USER_CERT``/``X509_USER_KEY``;
* ``-v`` counted into a root ``logging`` handler on stdout (or ``--log-file``);
* ``-D GROUP:KEY=VALUE``, ``-C key=value``, ``-4``/``-6`` and ``-t`` applied
  to a fresh context, whose user agent is ``gfal2-util/1.9.1``;
* the command run in a daemon thread, so that ``Ctrl-C`` cancels it and
  ``-t`` bounds it, with a ``GError`` reported as
  ``gfal-ls error: 2 (No such file or directory) - <message>`` and its errno
  becoming the exit status.

The exit statuses follow from that: whatever the command returns (``None``
is 0), the ``GError`` code (255 if out of range), 255 when the command died
of anything else, ``ETIMEDOUT`` on ``-t`` and ``EINTR`` on ``Ctrl-C``.

Behaviour, wording and layout are gfal2-util's (Apache-2.0, (c) CERN); the
code is a reimplementation.
"""

from __future__ import annotations

import argparse
import errno
import logging
import os
import signal
import sys
import threading
import traceback
from collections.abc import Sequence
from typing import IO, TYPE_CHECKING, Any, Callable, Optional, Union

from ..errors import GError

if TYPE_CHECKING:
    from ..context import Gfal2Context
    from ._progress import Progress

__all__ = [
    "VERSION",
    "Argument",
    "Command",
    "Spec",
    "arg",
    "main",
    "out",
    "surl",
]

#: The gfal2-util release whose behaviour the commands reproduce.
VERSION = "1.9.1"

#: Seconds added to ``-t`` before the command thread is abandoned, so that the
#: plugins get the chance to time out on their own first.
TIMEOUT_GRACE = 30
#: Seconds to wait for ``cancel()`` after ``Ctrl-C``.
CANCEL_WAIT = 4.0

Argument = tuple[tuple[str, ...], dict[str, Any]]
Runner = Callable[["Command"], Optional[int]]


def arg(*flags: str, **options: Any) -> Argument:
    """One ``add_argument`` call, as data."""
    return flags, options


class Spec:
    """A command: what ``--help`` says, what it accepts, what it does."""

    def __init__(
        self, doc: str, arguments: Sequence[Argument], run: Runner, return_code: int = -1
    ) -> None:
        self.doc = doc
        self.arguments = list(arguments)
        self.run = run
        #: Where the exit status starts: ``gfal-rm`` starts at 0, so that an
        #: unexpected exception still exits 0 there, as it does in gfal2-util.
        self.return_code = return_code


def out(text: str) -> None:
    """Write to stdout and flush: gfal2-util runs under ``python -u``."""
    sys.stdout.write(text)
    sys.stdout.flush()


def surl(value: str) -> str:
    """An argument that may be a local path: ``/p`` and ``p`` become ``file:///abs/p``.

    gfal2-util rebuilds the URL from ``urlparse``'s path alone, which drops
    anything after a ``;``, ``?`` or ``#`` in a local file name; the whole
    path is kept here.
    """
    if value == "-":
        return value
    from urllib.parse import urlparse

    if urlparse(value).scheme:
        return value
    return "file://" + os.path.abspath(value)


# ---------------------------------------------------------------------------
# The parser
# ---------------------------------------------------------------------------


class _HelpFormatter(argparse.HelpFormatter):
    """``-D DEFINITION, --definition DEFINITION``, as Python 3.9 prints it.

    Python 3.13 shortened the option list to ``-D, --definition DEFINITION``;
    the help of gfal2-util, and of this, is the older form on every version.
    """

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            (metavar,) = self._metavar_formatter(action, action.dest)(1)
            return str(metavar)
        if action.nargs == 0:
            return ", ".join(action.option_strings)
        args = self._format_args(action, self._get_default_metavar_for_optional(action))
        return ", ".join(f"{option} {args}" for option in action.option_strings)


class _VersionAction(argparse.Action):
    """``-V``: the version, then the loaded plugins, one per line."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["nargs"] = 0
        super().__init__(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        from .. import creat_context, get_version

        text = f"gfal2-util version {VERSION} (gfal2 {get_version()})"
        context = creat_context()
        for plugin in sorted(context.get_plugin_names()):
            text += "\n\t" + plugin
        context.free()
        out(text + "\n")
        sys.exit(0)


def build_parser(prog: str, spec: Spec) -> argparse.ArgumentParser:
    command = prog.rsplit("-", 1)[-1]
    description = f"Gfal util {command.upper()} command. {spec.doc}"
    if not description.endswith("."):
        description += "."
    parser = argparse.ArgumentParser(
        prog=prog, description=description, add_help=True, formatter_class=_HelpFormatter
    )
    parser._optionals.title = "optional arguments"  # Python 3.10+ says "options"
    parser.color = False  # type: ignore[attr-defined]  # Python 3.14 colours help on a TTY
    parser.add_argument(
        "-V", "--version", action=_VersionAction, help="output version information and exit"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="enable the verbose mode, -v for warning, -vv for info, -vvv for debug",
    )
    parser.add_argument(
        "-D",
        "--definition",
        nargs=1,
        type=str,
        help="override a gfal parameter",
        action="append",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=1800,
        help="maximum time for the operation to terminate - default is 1800 seconds",
    )
    parser.add_argument("-E", "--cert", type=str, default=None, help="user certificate")
    parser.add_argument("--key", type=str, default=None, help="user private key")
    parser.add_argument(
        "-4",
        dest="ipv4",
        action="store_true",
        help="forces gfal2-util to use IPv4 addresses only. N.B. this is valid only for gridftp",
    )
    parser.add_argument(
        "-6",
        dest="ipv6",
        action="store_true",
        help="forces gfal2-util to use IPv6 addresses only. N.B. this is valid only for gridftp",
    )
    parser.add_argument(
        "-C",
        "--client-info",
        type=str,
        help="provide custom client-side information",
        action="append",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="write Gfal2 library logs to the given file location",
    )
    for flags, options in spec.arguments:
        parser.add_argument(*flags, **options)
    return parser


# ---------------------------------------------------------------------------
# -D and friends
# ---------------------------------------------------------------------------

Value = Union[int, bool, str]


def _value(text: str) -> Value:
    """An option value: an integer, else a boolean, else the string."""
    try:
        return int(text)
    except ValueError:
        pass
    lowered = text.lower()
    if lowered in ("true", "yes", "y", "1"):
        return True
    if lowered in ("false", "no", "n", "0"):
        return False
    return text


def parse_definition(text: str) -> tuple[str, str, list[Value]]:
    """``GROUP:KEY=VALUE[,VALUE...]`` into its parts; ``ValueError`` if malformed."""
    equals = text.find("=")
    if equals == -1:
        raise ValueError(f"parameter '{text}' doesn't include value, use 'group:option=value'")
    colon = text[:equals].rfind(":")
    if colon == -1:
        raise ValueError(f"parameter '{text}' doesn't include group name, use 'group:option=value'")
    values = [_value(part) for part in text[equals + 1 :].split(",")]
    return text[:colon], text[colon + 1 : equals], values


def _set_definition(context: Gfal2Context, group: str, key: str, values: list[Value]) -> None:
    if len(values) > 1:
        context.set_opt_string_list(group, key, [str(value) for value in values])
        return
    value = values[0]
    if isinstance(value, bool):
        context.set_opt_boolean(group, key, value)
    elif isinstance(value, int):
        context.set_opt_integer(group, key, value)
    else:
        context.set_opt_string(group, key, value)


def apply_options(context: Gfal2Context, params: argparse.Namespace) -> None:
    """What the common options do to the context."""
    if params.definition:
        parsed = [parse_definition(item[0]) for item in params.definition]
        for group, key, values in parsed:
            _set_definition(context, group, key, values)
    for info in params.client_info or ():
        parts = info.split("=", 2)
        if len(parts) == 2:
            context.add_client_info(parts[0], parts[1])
        else:
            context.add_client_info(info, "")
    if params.ipv6:
        context.set_opt_boolean("GRIDFTP PLUGIN", "IPV6", True)
    elif params.ipv4:
        context.set_opt_boolean("GRIDFTP PLUGIN", "IPV6", False)
    if params.timeout:
        context.set_opt_integer("CORE", "NAMESPACE_TIMEOUT", params.timeout)
        context.set_opt_integer("CORE", "CHECKSUM_TIMEOUT", params.timeout)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

#: Level names on a terminal: bold dim, blue, yellow, red.
_TTY_LEVELS = {
    logging.DEBUG: "\033[1;2mDEBUG   \033[1;m",
    logging.INFO: "\033[1;34mINFO    \033[1;m",
    logging.WARNING: "\033[1;33mWARNING \033[1;m",
    logging.ERROR: "\033[1;31mERROR   \033[1;m",
}


class _Formatter(logging.Formatter):
    """``LEVEL message``; the level coloured on a terminal.

    gfal2-util renames the levels process-wide with ``addLevelName``; a
    formatter does the same for this handler alone.
    """

    def __init__(self, tty: bool) -> None:
        super().__init__("%(levelname)s %(message)s")
        self.tty = tty

    def formatMessage(self, record: logging.LogRecord) -> str:
        if not self.tty:
            return super().formatMessage(record)
        return f"{_TTY_LEVELS.get(record.levelno, record.levelname)} {record.getMessage()}"


class _Logging:
    """The root handler for ``-v``, removed again afterwards.

    A command normally owns its process, but ``main()`` may be called more
    than once in one (tests, wrappers), so everything touched is put back.
    """

    def __init__(self, verbose: int, log_file: str | None) -> None:
        from .. import set_verbose, verbose_level

        level = min(3, max(0, verbose))
        self.value = logging.ERROR - level * 10
        self.library = logging.getLogger("xgfalclient")
        self.library_level = self.library.level
        set_verbose(verbose_level.verbose if level < 3 else verbose_level.debug)
        self.file: IO[str] | None = open(log_file, "w+") if log_file else None  # noqa: SIM115
        stream = self.file if self.file is not None else sys.stdout
        self.handler = logging.StreamHandler(stream)
        self.handler.setLevel(self.value)
        self.handler.setFormatter(_Formatter(_isatty(stream)))
        self.root = logging.getLogger()
        self.root_level = self.root.level
        self.root.setLevel(self.value)
        self.root.addHandler(self.handler)

    def close(self) -> None:
        self.root.removeHandler(self.handler)
        self.root.setLevel(self.root_level)
        self.library.setLevel(self.library_level)
        if self.file is not None:
            self.file.close()


def _isatty(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def stdout_isatty() -> bool:
    return _isatty(sys.stdout)


# ---------------------------------------------------------------------------
# Running a command
# ---------------------------------------------------------------------------


class Command:
    """One invocation: the parsed arguments, the context, and the outcome."""

    def __init__(self, prog: str, spec: Spec) -> None:
        self.prog = prog
        self.spec = spec
        self.parser = build_parser(prog, spec)
        self.params = argparse.Namespace()
        self.context: Gfal2Context
        self.progress_bar: Progress | None = None
        self.return_code: int | None = spec.return_code

    def parse(self, argv: Sequence[str]) -> None:
        self.params = self.parser.parse_args(list(argv))

    def execute(self) -> int:
        params = self.params
        if params.cert:
            if not params.key:
                params.key = params.cert
            os.environ["X509_USER_CERT"] = params.cert
            os.environ["X509_USER_KEY"] = params.key
            os.environ.pop("X509_USER_PROXY", None)
        log = _Logging(params.verbose, params.log_file)
        try:
            from .. import creat_context

            self.context = creat_context()
            try:
                apply_options(self.context, params)
            except ValueError:
                # gfal2-util lets this escape its main(): a traceback and status 1.
                traceback.print_exc()
                return 1
            self.context.set_user_agent("gfal2-util", VERSION)
            return self._run_threaded()
        finally:
            log.close()

    def _run_threaded(self) -> int:
        """Run the command in a daemon thread, which ``Ctrl-C`` and ``-t`` can abandon."""
        worker = threading.Thread(target=self._executor, name="gfal-command", daemon=True)
        try:
            worker.start()
            timeout = self.params.timeout
            _wait(worker, timeout + TIMEOUT_GRACE if timeout > 0 else None)
            if worker.is_alive():
                if self.progress_bar is not None:
                    self.progress_bar.stop(False)
                sys.stderr.write(f"Command timed out after {timeout} seconds!\n")
                return errno.ETIMEDOUT
            self.context.free()
            code = self.return_code
            return 0 if code is None else code & 0xFF
        except KeyboardInterrupt:
            return self._interrupted()

    def _interrupted(self) -> int:
        sys.stderr.write("Caught keyboard interrupt. Canceling...")
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            canceller = threading.Thread(target=self.context.cancel, daemon=True)
            canceller.start()
            canceller.join(CANCEL_WAIT)
            if canceller.is_alive():
                sys.stderr.write("failed to cancel after waiting some time\n")
        finally:
            signal.signal(signal.SIGINT, previous)
        return errno.EINTR

    def _executor(self) -> None:
        try:
            self.return_code = self.spec.run(self)
        except GError as exc:
            sys.stdout.flush()
            sys.stderr.write(
                f"{self.prog} error: {exc.code} ({os.strerror(exc.code)}) - {exc.message}\n"
            )
            self.return_code = exc.code if 0 <= exc.code <= 255 else 255
        except OSError as exc:
            if exc.errno != errno.EPIPE:
                _thread_traceback()
        except SystemExit:
            pass  # parser.error() inside the command: argparse has printed why
        except Exception:
            _thread_traceback()


def _wait(worker: threading.Thread, timeout: float | None) -> None:
    worker.join(timeout)


def _thread_traceback() -> None:
    """What ``threading`` prints for an exception that ends a thread."""
    sys.stdout.flush()
    sys.stderr.write(f"Exception in thread {threading.current_thread().name}:\n")
    sys.stderr.write(traceback.format_exc())


def main(command: str, spec: Spec, argv: Sequence[str] | None = None) -> int:
    """Run ``gfal-<command>`` with ``argv`` (default ``sys.argv[1:]``); the exit status."""
    args = list(sys.argv[1:] if argv is None else argv)
    runner = Command(f"gfal-{command}", spec)
    try:
        runner.parse(args)
        return runner.execute()
    except SystemExit as exc:  # --help, --version, a usage error
        return int(exc.code or 0)
    except Exception:  # what escapes gfal2-util's main(): a traceback and status 1
        traceback.print_exc()
        return 1
