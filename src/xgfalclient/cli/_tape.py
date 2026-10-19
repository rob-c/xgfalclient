"""``gfal-bringonline``, ``gfal-archivepoll`` and ``gfal-evict``.

Polling backs off 1, 2, 4... seconds (capped at 300) until every file is in
a terminal state or ``--polling-timeout`` is spent. A failed file is
reported, not fatal: both staging commands exit 0, as in gfal2-util 1.9.1
(Apache-2.0, (c) CERN), whose behaviour this reimplements.

With the default ``--polling-timeout`` of 0 there is no polling at all:
``gfal-bringonline`` submits asynchronously, prints the token and each
file's first state, and exits - the token is what a later
``gfal-bringonline``/``gfal-evict`` (or FTS) uses.
"""

from __future__ import annotations

import errno
import time
from collections.abc import Callable, Sequence

from ..errors import GError
from ._base import Command, Spec, arg, out, output, surl
from ._rm import read_list

__all__ = ["SPECS"]

#: ``time.sleep``, replaceable in tests.
sleep = time.sleep


def _evaluate(errors: Sequence[GError | None], urls: Sequence[str], polling: bool) -> int:
    """Print each file's state; the number of files that are done (ready or failed).

    The list form's convention (see ``Gfal2Context.bring_online``): ``None``
    is done, ``EAGAIN`` is still queued, any other error is final. The
    first answer to an asynchronous request (``polling=False``) says
    nothing yet, so even a ``None`` is printed ``QUEUED`` then, as
    gfal2-util prints it.
    """
    terminal = 0
    for url, error in zip(urls, errors, strict=False):
        if error is not None:
            if error.code != errno.EAGAIN:
                output.error(error, url=url)
                output.record(url=url, status="failed", code=error.code)
                out(f"{url} => FAILED: {error.user_message}\n")
                terminal += 1
            else:
                output.record(url=url, status="queued", code=error.code)
                out(f"{url} QUEUED\n")
        elif not polling:
            output.record(url=url, status="queued")
            out(f"{url} QUEUED\n")
        else:
            output.record(url=url, status="ready")
            terminal += 1
            out(f"{url} READY\n")
    return terminal


def _urls(cmd: Command) -> list[str] | None:
    """The files to act on (one positional URL or ``--from-file``), or None after an error.

    The caller then exits 1, as gfal2-util does for these usage mistakes.
    """
    params = cmd.params
    if params.from_file and params.surl:
        output.error(ValueError("Use either --from-file or a positional URL, not both"), code=1)
        output.message(
            "Could not combine --from-file with a surl in the positional arguments\n", stderr=True
        )
        return None
    if params.from_file:
        return read_list(params.from_file)
    if params.surl:
        return [params.surl]
    output.error(ValueError("Provide a file URL or use --from-file"), code=1)
    output.message("Missing surl\n", stderr=True)
    return None


def _poll(
    cmd: Command,
    urls: list[str],
    terminal: int,
    message: str,
    poll: Callable[[], Sequence[GError | None]],
) -> None:
    """Poll with exponential back-off until every file is terminal or the budget is gone.

    The budget is charged with the planned sleep, not the time the poll
    took, so ``--polling-timeout`` bounds the sleeping (as in gfal2-util),
    and a final poll always follows the last sleep.
    """
    wait = cmd.params.polling_timeout
    delay = 1
    while terminal != len(urls) and wait > 0:
        output.record("wait", seconds=delay, remaining_budget=wait)
        out(f"{message}, sleep {delay} seconds...\n")
        wait -= delay
        sleep(delay)
        errors = poll()
        terminal = _evaluate(errors, urls, polling=True)
        delay = min(delay * 2, 300)


def bringonline(cmd: Command) -> int | None:
    """``gfal-bringonline``: one asynchronous request for every file, then optional polling.

    ``--pin-lifetime`` and ``--desired-request-time`` are seconds, passed
    as gfal2's ``pintime`` and ``timeout``; the same ``--staging-metadata``
    goes with every file.
    """
    urls = _urls(cmd)
    if urls is None:
        return 1
    output.identify("bringonline", urls=urls)
    params = cmd.params
    errors, token = cmd.context.bring_online(
        urls,
        [params.staging_metadata] * len(urls),
        params.pin_lifetime,
        params.desired_request_time,
        True,
    )
    if token:
        output.record("request", request_id=token, urls=urls)
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
    """``gfal-archivepoll``: whether each file has reached tape, polling if asked."""
    urls = _urls(cmd)
    if urls is None:
        return 1
    output.identify("archivepoll", urls=urls)
    terminal = _evaluate(cmd.context.archive_poll(urls), urls, polling=True)
    _poll(cmd, urls, terminal, "Archiving ongoing", lambda: cmd.context.archive_poll(urls))
    return None


def evict(cmd: Command) -> None:
    """``gfal-evict URL [TOKEN]``: release the file's disk copy (gfal2's ``release``)."""
    output.identify("evict", url=cmd.params.file, request_id=cmd.params.token)
    cmd.context.release(cmd.params.file, cmd.params.token)
    output.record(status="succeeded")


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
