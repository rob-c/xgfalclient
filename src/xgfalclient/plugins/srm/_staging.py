"""SRM staging: bring-online, its poll, release, abort, and the archive poll.

Part of the :mod:`xgfalclient.plugins.srm.plugin` split. :class:`_StagingMixin`
is gfal2's tape interface for ``srm://`` - ``srmBringOnline`` and
``srmStatusOfBringOnlineRequest``, ``srmReleaseFiles``, ``srmAbortFiles``,
and an ``srmLs`` per endpoint for ``archive_poll`` - with each file's answer
turned into a :data:`~xgfalclient.plugin.StagingResult` in gfal2's words.

Nothing here is looked up through the facade: no test patches a
module-level name these methods use.

Each method answers per URL, never raising for one file's failure: a
:data:`~xgfalclient.plugin.StagingResult` is ``True`` (online/done),
``False`` (still queued) or the file's ``GError``. Only a failure of the
whole request (network, SOAP, request status) raises.
"""

from __future__ import annotations

import errno
from collections.abc import Sequence

from ...errors import GError
from ...plugin import StagingResult
from ._base import _by_endpoint, _SRMBase, _stat_error
from .client import Detail, Staging, Status, file_error
from .transport import SURL, normalise_path


class _StagingMixin(_SRMBase):
    """Bring-online, its poll, release and abort, and the archive poll."""

    def bring_online(
        self,
        urls: Sequence[str],
        metadata: Sequence[str],
        pintime: int,
        timeout: int,
        is_async: bool,
    ) -> tuple[list[StagingResult], str]:
        """``srmBringOnline`` of ``urls``; per-file results and the request token.

        ``pintime`` and ``timeout`` are gfal2's, in seconds (see
        :class:`~.client.Staging`). Asynchronously, the first answer is
        returned and the token is for :meth:`bring_online_poll`; otherwise
        the request is polled for up to ``timeout`` seconds, then aborted.
        ``metadata`` (staging metadata for the HTTP tape REST API) is
        ignored: an SRM request has nowhere to carry it.
        """
        surls = [self._surl(url) for url in urls]
        token, statuses = self.client.bring_online(
            surls,
            self._turl_protocols(),
            Staging(pintime, timeout, None if is_async else float(timeout)),
            spacetoken=self._spacetoken(),
        )
        return [_staging(found.status, "BringOnline") for found in statuses], token

    def bring_online_poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        """One ``srmStatusOfBringOnlineRequest`` of a request :meth:`bring_online` started."""
        surls = [self._surl(url) for url in urls]
        statuses = self.client.bring_online_status(token, surls)
        return [_staging(found.status, "StatusOfBringOnlineRequest") for found in statuses]

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``srmReleaseFiles``: unpin staged files; ``None`` per file released.

        Without a token every URL fails ``EINVAL`` and nothing is sent.
        """
        if not token:
            # gfal2 will not release without the request's token either.
            error = GError("Invalid value handle, surl or token", errno.EINVAL)
            return [error for _ in urls]
        statuses = self.client.release(token, [self._surl(url) for url in urls])
        return [_file_failure(found.status, "ReleaseFiles", "release") for found in statuses]

    def abort_bring_online(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``srmAbortFiles``; as in gfal2, only a failure of the request itself counts."""
        self.client.abort_files(token, [self._surl(url) for url in urls])
        return [None for _ in urls]

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        """Archived means on tape: ``NEARLINE`` or ``ONLINE_AND_NEARLINE``."""
        results: list[StagingResult] = [False] * len(urls)
        for indices, surls in _by_endpoint(urls, results, self._surl):
            try:
                details = self.client.ls(surls, timeout=self._timeout())
            except GError as exc:
                for index in indices:
                    results[index] = exc
                continue
            for index, surl in zip(indices, surls, strict=False):
                results[index] = _archived(surl, details)
        return results


def _file_failure(status: Status, short: str, what: str) -> GError | None:
    """``None`` for success, else ``error on the <what> request : ...`` (gfal2's words)."""
    if status.ok:
        return None
    error = file_error(short, status)
    return GError(f"error on the {what} request : {error.message} ", error.code)


def _staging(status: Status, short: str) -> StagingResult:
    """A file's bring-online status: ``True`` pinned, ``False`` pending, else its error."""
    if status.ok:
        return True
    if status.pending:
        return False
    error = file_error(short, status)
    return GError(f"error on the bring online request: {error.message} ", error.code)


def _archived(surl: SURL, details: list[Detail]) -> StagingResult:
    """One SURL's archive state from a bulk ``srmLs``.

    The entry is found by normalised path, since servers echo paths in
    their own spelling. No entry is ``EAGAIN`` (ask again later), as gfal2
    reports a file not yet on tape; ``NEARLINE`` anywhere in the locality
    (``NEARLINE``, ``ONLINE_AND_NEARLINE``) means a tape copy exists.
    """
    wanted = normalise_path(surl.path)
    found = [item for item in details if normalise_path(item.path) == wanted]
    if not found:
        return GError(f"File {surl.url} is not yet archived", errno.EAGAIN)
    if not found[0].status.ok:
        return _stat_error(found[0].status)
    return "NEARLINE" in found[0].locality
