"""Staging: bring-online, its polls, release and abort, as gfal2 does them over XRootD.

Each call is one request to the first URL's endpoint for all the files:
``kXR_prepare`` with ``kXR_stage`` (the answer is the request id),
``kXR_evict`` or ``kXR_cancel``, or a ``kXR_QPrep`` query whose JSON answer
:func:`parse_prepare_status` judges file by file with gfal2's checks, in
gfal2's order and wording (``gfal_xrootd_bring_online_poll_list`` and
``..._archive_poll_list``). A failure of the request itself is every file's,
in XrdCl's terse ``ToString`` spelling; a poll that could not reach the
server is ``ECOMM``, which gfal2 reads as "try again".

The requests go through xrdclient's public :class:`~xrdclient.FileSystem`
(``prepare``, ``cancel_prepare`` and the raw ``query``), on the plugin's
pooled filesystem for the first URL. Batches are not split per endpoint:
gfal2 sends every file to ``urls[0]``'s server, which for a tape site is
the redirector that knows them all, and so does this.

The ``kXR_QPrep`` answer is read here rather than through
:meth:`xrdclient.FileSystem.query_prepare`: that method gives xrdclient's
own reading of each file, and gfal2's users depend on gfal2's - which keys
it checks, in which order, with which messages (one of them misspelt;
see :func:`parse_prepare_status`). The JSON is what a tape-backed XRootD
(CTA, or a server with a prepare plug-in) answers.
"""

from __future__ import annotations

import errno
import json
import uuid
from collections.abc import Sequence
from typing import TYPE_CHECKING

from ...errors import ECOMM, GError
from ...plugin import StagingResult
from .errors import NETWORK_ERRNOS, describe, each
from .urls import collapse_slashes

if TYPE_CHECKING:
    from .plugin import XRootDPlugin


def _paths(plugin: XRootDPlugin, urls: Sequence[str], *, cgi: bool) -> list[str]:
    """Each URL's path, with its CGI when the request carries one per file.

    ``kXR_prepare`` names each file with its opaque CGI (a space token, an
    ``authz=``), as gfal2 passes the URLs on; a ``kXR_QPrep`` query does not,
    because the server matches the paths in its answer against the ones it
    was asked about, and a path with CGI attached would never match.
    """
    paths = []
    for url in urls:
        target = plugin._file_url(url)
        paths.append(target.path_with_cgi if cgi else target.path)
    return paths


def bring_online(
    plugin: XRootDPlugin, urls: Sequence[str], timeout: int
) -> tuple[list[StagingResult], str]:
    """``kXR_prepare`` with ``kXR_stage``; the answer is the request id.

    gfal2 never reports a file online from here, only queued; the poll
    says when it is.
    """
    try:
        # A timeout of 0 is gfal2's "no timeout given": the plugin's default applies.
        with plugin._fs(urls[0], timeout or None) as (fs, _):
            token = str(fs.prepare(_paths(plugin, urls, cgi=True), stage=True))
    except Exception as exc:
        failure = describe(exc)
        message = f"Bringonline request failed. One or more files failed with: {failure.to_string}"
        return [GError(message, failure.code) for _ in urls], ""
    if not token:
        message = "Bringonline request failed: empty response from the server"
        return [GError(message, errno.ENOMSG) for _ in urls], ""
    return [False for _ in urls], token


def poll(
    plugin: XRootDPlugin, urls: Sequence[str], token: str | None = None
) -> list[StagingResult]:
    """A ``kXR_QPrep`` for ``token``; with none, an archive poll under a request id nobody made.

    The archive poll asks only whether each file is safely on tape. It still
    needs a request id on the wire, and the server checks that its answer
    echoes it, so a fresh UUID stands in for one. A failure to ask is every file's, with a
    network failure turned into ``ECOMM`` so gfal2's poll loop retries
    rather than giving up on a flaky link.
    """
    archive = token is None
    token = str(uuid.uuid4()) if token is None else token
    paths = [collapse_slashes(path) for path in _paths(plugin, urls, cgi=False)]
    try:
        with plugin._fs(urls[0]) as (fs, _):
            # 2 is kXR_QPrep: the request id, then one path per line.
            answer = bytes(fs.query(2, "\n".join([token, *paths])))
    except Exception as exc:
        failure = describe(exc)
        code = ECOMM if failure.code in NETWORK_ERRNOS else failure.code
        return [GError(failure.to_string, code) for _ in urls]
    # The answer is a C string; anything past its NUL is padding.
    text = answer.split(b"\x00", 1)[0].decode("utf-8", "replace")
    return parse_prepare_status(text, token, paths, archive=archive)


def release(plugin: XRootDPlugin, urls: Sequence[str]) -> list[GError | None]:
    """``kXR_prepare`` with ``kXR_evict``: no token needed over XRootD.

    The server drops its disk copy of each file; nothing waits for that to
    happen. ``release`` takes no timeout from its caller, so the request is
    bounded at 30 seconds here rather than at the plugin's default. A
    failure is every file's, worded by :func:`~.errors.each`.
    """
    try:
        with plugin._fs(urls[0], 30) as (fs, _):
            fs.prepare(_paths(plugin, urls, cgi=True), evict=True)
    except Exception as exc:
        return each(urls, describe(exc))
    return [None for _ in urls]


def abort(plugin: XRootDPlugin, urls: Sequence[str], token: str) -> list[GError | None]:
    """``kXR_prepare`` with ``kXR_cancel``: the request id, then the files to withdraw.

    gfal2 names the files, so only these leave the request, not the lot
    (an empty list would cancel the whole request, which is not what
    ``abort_bring_online`` for some files means).
    """
    try:
        with plugin._fs(urls[0]) as (fs, _):
            fs.cancel_prepare(token, _paths(plugin, urls, cgi=True))
    except Exception as exc:
        return each(urls, describe(exc))
    return [None for _ in urls]


# -- judging a poll's answer -----------------------------------------------------------


def _truth(value: object) -> bool:
    """``json_obj_to_bool``: only the string ``true``, in any case, is true.

    gfal2 reads every flag through json-c's string form, so a JSON ``true``
    (serialised ``true``) counts and so does ``"TRUE"``, while ``1`` and
    ``"yes"`` do not.
    """
    if value is None:
        return False
    text = json.dumps(value) if not isinstance(value, str) else value
    return text.lower() == "true"


def parse_prepare_status(
    text: str, token: str, paths: Sequence[str], *, archive: bool
) -> list[StagingResult]:
    """One result per path from a ``kXR_QPrep`` answer, judged as gfal2 judges it.

    ``True`` is online (or, for ``archive``, safely on tape), ``False`` still
    waiting, and a ``GError`` whatever went wrong for that file. The checks,
    their order and their wording are gfal2's
    ``gfal_xrootd_bring_online_poll_list`` and ``..._archive_poll_list``.
    """
    count = len(paths)
    try:
        document = json.loads(text)
    except ValueError:
        document = None
    # Whole-answer failures first, each failing every file alike, in gfal2's
    # order: not JSON, someone else's request, a different number of files.
    if not isinstance(document, dict):
        return _all(count, f"Response from server is an invalid JSON: {text}")
    if str(document.get("request_id") or "") != token:
        return _all(count, "Request ID mismatch.")
    responses = document.get("responses")
    if not isinstance(responses, list) or len(responses) != count:
        # gfal2's archive poll misspells its message, and tests pin the misspelling.
        verb = "doest not" if archive else "does not"
        return _all(count, f"Number of files in the request {verb} match!")
    # Entries are judged in the server's order, which is the order asked
    # (gfal2 assumes so too); a path nobody asked about is that entry's error.
    wanted = set(paths)
    return [_judge(entry, wanted, token, text, archive=archive) for entry in responses]


def _all(count: int, message: str) -> list[StagingResult]:
    """The same malformed-answer error (``ENOMSG``) for every one of ``count`` files."""
    return [GError(message, errno.ENOMSG) for _ in range(count)]


def _poll_error(code: int, message: str, reason: str) -> GError:
    """``gfal2_xrootd_poll_set_error``: the server's own text appended as the reason."""
    return GError(f"{message} (reason: {reason})" if reason else message, code)


def _judge(
    entry: object, wanted: set[str], token: str, text: str, *, archive: bool
) -> StagingResult:
    """One file's entry: the checks every poll makes, then the archive's or the staging's."""
    if not isinstance(entry, dict):
        return GError(f"Failed to parse responses JSON from server: {text}", errno.ENOMSG)
    if "error_text" not in entry:
        return GError("Error attribute missing.", errno.ENOMSG)
    reason = str(entry["error_text"] or "")
    path = collapse_slashes(str(entry.get("path") or ""))
    if not path or path not in wanted:
        return _poll_error(errno.ENOMSG, f"Wrong path: {path}", reason)
    # Every entry must carry ``error_text`` (possibly empty), the reason
    # appended to whatever is wrong with it.
    exists = _truth(entry.get("path_exists")) or (
        not archive and _truth(entry.get("exists"))  # CTA's older spelling
    )
    if not exists:
        return _poll_error(errno.ENOENT, f"File does not exist: {path}", reason)
    if archive:
        # Safely archived, or not yet: an error text without ``on_tape`` is
        # the archiving's failure, its absence just "keep waiting".
        if _truth(entry.get("on_tape")):
            return True
        return GError(reason, errno.ENOMSG) if reason else False
    return _staging(entry, path, token, reason)


def _staging(entry: dict[str, object], path: str, token: str, reason: str) -> StagingResult:
    """A file that exists, in a bring-online poll: online, waiting, or why not.

    Online wins over everything, even an error text. A file that is not
    online must be part of *this* request (``requested``, ``has_reqid``)
    and carry the time it was asked for; anything missing is the server
    contradicting itself, ``ENOMSG``. Only then does an ``error_text`` mean
    the staging failed; without one the file is simply still on its way.
    """
    if _truth(entry.get("online")):
        return True
    if not _truth(entry.get("requested")):
        return _poll_error(errno.ENOMSG, f"File is not being brought online: {path}", reason)
    if not _truth(entry.get("has_reqid")):
        return _poll_error(
            errno.ENOMSG,
            f"File ({path}) is not included in the bring online request: {token}",
            reason,
        )
    if not str(entry.get("req_time") or ""):
        return _poll_error(errno.ENOMSG, "Bring-online timestamp missing.", reason)
    if reason:
        return GError(reason, errno.ENOMSG)
    return False
