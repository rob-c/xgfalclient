"""``gfal-bringonline``, ``gfal-archivepoll`` and ``gfal-evict``.

Polling backs off 1, 2, 4... seconds (capped at 300) until every file is in
a terminal state or ``--polling-timeout`` is spent. A failed file is
reported, not fatal: both staging commands exit 0, as in gfal2-util 1.9.1
(Apache-2.0, (c) CERN), whose behaviour this reimplements.
"""

from __future__ import annotations

import errno
import sys
import time
from collections.abc import Callable, Sequence

from ..errors import GError
from ._base import Command, Spec, arg, out, surl
from ._rm import read_list

__all__ = ["SPECS"]

#: ``time.sleep``, replaceable in tests.
sleep = time.sleep


def _evaluate(errors: Sequence[GError | None], urls: Sequence[str], polling: bool) -> int:
    """Print each file's state; the number of files that are done (ready or failed)."""
    terminal = 0
    for url, error in zip(urls, errors):
        if error is not None:
            if error.code != errno.EAGAIN:
                out(f"{url} => FAILED: {error.message}\n")
                terminal += 1
            else:
                out(f"{url} QUEUED\n")
        elif not polling:
            out(f"{url} QUEUED\n")
        else:
            terminal += 1
            out(f"{url} READY\n")
    return terminal


def _urls(cmd: Command) -> list[str] | None:
    params = cmd.params
    if params.from_file and params.surl:
        sys.stderr.write("Could not combine --from-file with a surl in the positional arguments\n")
        return None
    if params.from_file:
        return read_list(params.from_file)
    if params.surl:
        return [params.surl]
    sys.stderr.write("Missing surl\n")
    return None


def _poll(
    cmd: Command,
    urls: list[str],
    terminal: int,
    message: str,
    poll: Callable[[], Sequence[GError | None]],
) -> None:
    wait = cmd.params.polling_timeout
    delay = 1
    while terminal != len(urls) and wait > 0:
        out(f"{message}, sleep {delay} seconds...\n")
        wait -= delay
        sleep(delay)
        errors = poll()
        terminal = _evaluate(errors, urls, polling=True)
        delay = min(delay * 2, 300)


def bringonline(cmd: Command) -> int | None:
    urls = _urls(cmd)
    if urls is None:
        return 1
    params = cmd.params
    errors, token = cmd.context.bring_online(
        urls,
        [params.staging_metadata] * len(urls),
        params.pin_lifetime,
        params.desired_request_time,
        True,
    )
    if token:
        out(f"Bringonline token: {token}\n")
    terminal = _evaluate(errors, urls, polling=False)
    _poll(
        cmd,
        urls,
        terminal,
        "Request queued",
        lambda: cmd.context.bring_online_poll(urls, token),
    )
    return None


def archivepoll(cmd: Command) -> int | None:
    urls = _urls(cmd)
    if urls is None:
        return 1
    terminal = _evaluate(cmd.context.archive_poll(urls), urls, polling=True)
    _poll(cmd, urls, terminal, "Archiving ongoing", lambda: cmd.context.archive_poll(urls))
    return None


def evict(cmd: Command) -> None:
    cmd.context.release(cmd.params.file, cmd.params.token)


_POLLING = arg(
    "--polling-timeout",
    action="store",
    type=int,
    default=0,
    help="Timeout for the polling operation",
)
_FROM_FILE = arg("--from-file", type=str, default=None, help="read surls from a file")
_SURL = arg("surl", action="store", type=surl, nargs="?", help="Site URL")

SPECS = {
    "bringonline": Spec(
        "bringonline",
        "Execute bring online",
        [
            arg(
                "--pin-lifetime",
                action="store",
                type=int,
                default=0,
                help="Desired pin lifetime",
            ),
            arg(
                "--desired-request-time",
                action="store",
                type=int,
                default=28800,
                help="Desired total request time",
            ),
            arg(
                "--staging-metadata",
                action="store",
                type=str,
                default="",
                help="Metadata for the bringonline operation",
            ),
            _POLLING,
            _FROM_FILE,
            _SURL,
        ],
        bringonline,
    ),
    # "Execute bring online" is gfal2-util's (copied) description of archivepoll too.
    "archivepoll": Spec(
        "archivepoll", "Execute bring online", [_POLLING, _FROM_FILE, _SURL], archivepoll
    ),
    "evict": Spec(
        "evict",
        "Evict file from a disk buffer",
        [
            arg("file", action="store", type=surl, help="URI to the file to be evicted"),
            arg(
                "token",
                type=str,
                nargs="?",
                default="",
                help="The token from the bring online request",
            ),
        ],
        evict,
    ),
}
#: gfal2-util's deprecated name for bringonline; run() prints the notice first.
SPECS["legacy-bringonline"] = SPECS["bringonline"]
