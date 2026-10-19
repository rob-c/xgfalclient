"""SRM copies: gfal2's ``srm_plugin_filecopy`` (``gfal_srm_copy.c``).

Part of the :mod:`xgfalclient.plugins.srm.plugin` split (that module's
docstring walks through the sequence of a copy). :class:`_CopyMixin` holds
``copy_check`` and ``copy``: the ``PREPARE`` stage (source checksum and
size, ``COPY_FAIL_NEARLINE``, the source and destination TURLs with the
other end's scheme first - :func:`_reorder`), the TURL-to-TURL copy through
the core with :func:`_inner`'s parameters, the ``CLOSE`` stage
(``srmPutDone``, the destination checksum, ``srmReleaseFiles``), and the
rollback when anything fails.

Nothing here is looked up through the facade at call time: no test patches
a module-level name these methods use (tests patch ``_checksum_of`` on a
plugin instance, which reaches it as any method does).

What :meth:`_CopyMixin.copy` must keep, whatever is changed: the source's
get request is released on every path (``finally``); a destination put
request ends in ``srmPutDone`` or, failing that, an abort, never left
open; the events come in gfal2's order; and the rollback removes only
what this copy wrote - a destination that refused with ``EEXIST`` is
someone else's file.
"""

from __future__ import annotations

import errno

from ... import events as ev
from ...checksum import checksums_match, normalise_name
from ...errors import GError
from ...transfer import Transfer, TransferParameters, run_copy
from ...url import scheme_of
from ._base import (
    _SOURCE,
    _TARGET,
    CLOSE_ENTER,
    CLOSE_EXIT,
    EVENT_DOMAIN,
    GET_EVENT,
    GROUP,
    PUT_EVENT,
    _SRMBase,
    _TURLRequest,
)
from .transport import SURL


def _prefixed(prefix: str, exc: GError) -> GError:
    """``exc`` with gfal2's stage prefix (``SOURCE SRM_GET_TURL``...), ``errno`` kept."""
    return GError(f"{prefix} {exc.message}", exc.code)


class _CopyMixin(_SRMBase):
    """gfal2's ``srm_plugin_filecopy``, with the checks and clean-up around it."""

    def copy_check(self, source: str, destination: str) -> bool:
        """An SRM end, and at the other anything that looks like a URL (gfal2's check)."""
        if scheme_of(source) == "srm":
            return ":" in destination
        return scheme_of(destination) == "srm" and ":" in source

    def copy(self, transfer: Transfer) -> None:
        """gfal2's ``srm_plugin_filecopy``.

        The sequence is the module docstring's (and :mod:`.plugin`'s). The
        state it tracks for the rollback: ``get``/``put`` are the open
        requests, ``(token, SURL)``; ``moved`` turns true just before the
        bytes start moving, ``finished`` once the destination is complete
        (committed with ``srmPutDone`` when it is an SRM). A source stat failure only loses the
        expected size (0 goes in ``srmPrepareToPut``), as in gfal2.
        """
        source, destination = transfer.source, transfer.destination
        params = transfer.params
        get: tuple[str, SURL] | None = None
        put: tuple[str, SURL] | None = None
        moved = finished = False
        transfer.event(ev.PREPARE_ENTER)
        try:
            # ``checksum_mode`` bits: _SOURCE verifies the source, _TARGET the
            # destination; with only _TARGET the source's value is still
            # fetched (cheaply) to compare against.
            mode = int(transfer.checksum_mode)
            if self.options.boolean(GROUP, "ALLOW_EMPTY_SOURCE_CHECKSUM", False):
                mode &= ~_SOURCE
            algorithm = transfer.checksum_algorithm or self.checksum_type()
            source_sum = self._source_checksum(transfer, mode, algorithm) if mode else ""
            # The size only feeds ``expectedFileSize`` and the final progress
            # report, so failing to learn it is no reason to fail the copy.
            size = 0
            try:
                size = self.context.stat(source).st_size
            except GError as exc:
                self.log.debug(
                    "Fail to stat src SRM url %s to determine file size, %s", source, exc
                )
            protocols = self._third_party_protocols()
            # A non-SRM end is its own TURL: the core copies to or from it.
            source_turl, destination_turl = source, destination
            if scheme_of(source) == "srm":
                surl = self._surl(source)
                if self.options.boolean(GROUP, "COPY_FAIL_NEARLINE", False):
                    self._require_online(surl, "SOURCE SRM_GET_TURL ")
                # Each end gets its own copy of the list to reorder.
                wanted = _reorder(list(protocols), destination)
                token, source_turl = self._copy_turl(
                    transfer, surl, wanted, params.src_spacetoken, None
                )
                get = (token, surl)  # from here on, ``finally`` releases it
                text = f"Got TURL {source} => {source_turl}"
                transfer.event(GET_EVENT, text, ev.SOURCE, EVENT_DOMAIN)
            if scheme_of(destination) == "srm":
                surl = self._surl(destination)
                self._prepare_destination(transfer, surl)
                wanted = _reorder(list(protocols), source)
                token, destination_turl = self._copy_turl(
                    transfer, surl, wanted, params.dst_spacetoken, size
                )
                put = (token, surl)  # from here on, the rollback aborts it
                text = f"Got TURL {destination} => {destination_turl}"
                transfer.event(PUT_EVENT, text, ev.DESTINATION, EVENT_DOMAIN)
            transfer.event(ev.PREPARE_EXIT)
            # Cancellation, a spent timeout or a callback's failure stops
            # the copy here, before any bytes move, so the rollback has only
            # the requests to undo.
            transfer.check()
            inner = _inner(transfer, put is not None)
            moved = True
            run_copy(self.context, inner, source_turl, destination_turl)
            # Report the full count even if the TURL copy's last progress
            # callback fell short of it.
            transfer.progress(max(size, transfer.transferred), force=True)
            transfer.event(CLOSE_ENTER, destination, ev.DESTINATION)
            try:
                if put is not None:
                    self._put_done(*put)
            except GError as exc:
                raise _prefixed("DESTINATION SRM_PUTDONE", exc) from exc
            finally:
                transfer.event(CLOSE_EXIT, destination, ev.DESTINATION)
            finished = True
            # After the commit: a mismatch now rolls back by removing the
            # destination, which ``finished`` tells the rollback to do.
            if mode & _TARGET:
                self._destination_checksum(transfer, algorithm, source_sum)
        except BaseException as exc:
            # BaseException: a KeyboardInterrupt mid-copy must not leave a
            # put request open on the server either.
            self._rollback(transfer, exc, put, moved, finished)
            raise
        finally:
            if get is not None:
                self._release_quietly(*get)

    def _copy_turl(
        self,
        transfer: Transfer,
        surl: SURL,
        protocols: list[str],
        spacetoken: str,
        size: int | None,
    ) -> tuple[str, str]:
        """The TURL of one end of a copy (``size`` for a put), prefixed as gfal2 prefixes it.

        The polling time is what is left of the copy's own timeout, so the
        TURL requests count against it; without one, the operation timeout.
        """
        remaining = transfer.remaining()
        timeout = remaining if remaining is not None else self._timeout()
        request = _TURLRequest(protocols, timeout, spacetoken, " ")
        try:
            if size is None:
                return self._get_turl(surl, request)
            return self._put_turl(surl, size, request)
        except GError as exc:
            prefix = "SOURCE SRM_GET_TURL" if size is None else "DESTINATION SRM_PUT_TURL"
            raise _prefixed(prefix, exc) from exc

    def _prepare_destination(self, transfer: Transfer, surl: SURL) -> None:
        """``srmRm`` for ``overwrite`` (a missing file is fine) and the parent directory.

        Without ``overwrite`` nothing is checked: ``srmPrepareToPut`` refuses
        an existing file itself.
        """
        destination = transfer.destination
        if transfer.params.overwrite:
            try:
                self.unlink(destination)
                transfer.event(ev.OVERWRITE, f"Deleted {destination}", ev.DESTINATION)
            except GError as exc:
                if exc.code not in (errno.ENOENT, errno.EINVAL):
                    raise _prefixed("DESTINATION OVERWRITE", exc) from exc
                self.log.info("%s doesn't exist, carry on", destination)
        if transfer.params.create_parent:
            trimmed = destination.rstrip("/")
            cut = trimmed.rfind("/")
            try:
                if cut <= len("srm://"):
                    raise GError(f"Invalid srm url {destination}", errno.EINVAL)
                self.mkdir_rec(trimmed[:cut], 0o755)
            except GError as exc:
                raise _prefixed("DESTINATION MAKE_PARENT", exc) from exc

    def _checksum_of(self, url: str, algorithm: str, fallback: bool) -> str:
        """gfal2's ``gfal_srm_checksumG_fallback``: ``srmLs``'s, then the TURL's.

        Without ``fallback`` only ``srmLs`` is asked, and any failure is "".
        """
        if fallback:
            # The full lookups: the SRM plugin's own checksum (srmLs, then a
            # TURL), or the other end's plugin through the context.
            if scheme_of(url) == "srm":
                return self.checksum(url, algorithm, 0, 0)
            return str(self.context.checksum(url, algorithm))
        # The cheap lookup: only what srmLs already knows, no TURL.
        if scheme_of(url) != "srm":
            return ""
        try:
            detail = self._detail(self._surl(url))
        except GError:
            return ""
        if normalise_name(detail.checksum_type) != normalise_name(algorithm):
            return ""
        return detail.checksum_value

    def _source_checksum(self, transfer: Transfer, mode: int, algorithm: str) -> str:
        """The source checksum, checked against the user's; "" when there is none.

        With the source bit of ``mode`` set the checksum is required (TURL
        fallback, failures raise) and compared with a user-given value
        (``EIO`` on mismatch). With only the target bit, it is fetched
        from ``srmLs`` if cheaply available, to compare with the
        destination's later.
        """
        transfer.event(ev.CHECKSUM_ENTER, "", ev.SOURCE)
        try:
            try:
                value = self._checksum_of(transfer.source, algorithm, bool(mode & _SOURCE))
            except GError as exc:
                raise _prefixed("SOURCE CHECKSUM", exc) from exc
            user = transfer.user_checksum
            if mode & _SOURCE and user and not checksums_match(value, user):
                raise GError(
                    "SOURCE CHECKSUM MISMATCH User defined checksum and source checksum do not "
                    f"match {user} != {value}",
                    errno.EIO,
                )
            return value
        finally:
            transfer.event(ev.CHECKSUM_EXIT, "", ev.SOURCE)

    def _destination_checksum(self, transfer: Transfer, algorithm: str, source: str) -> None:
        """Check the committed destination's checksum against the source's and the user's.

        An empty destination checksum is ``EINVAL`` (it cannot be
        verified); a mismatch with either is ``EIO``. A failure here rolls
        back the copy like any other.
        """
        transfer.event(ev.CHECKSUM_ENTER, "", ev.DESTINATION)
        try:
            try:
                value = self._checksum_of(transfer.destination, algorithm, True)
            except GError as exc:
                raise _prefixed("DESTINATION CHECKSUM", exc) from exc
            user = transfer.user_checksum
            if not value:
                raise GError("DESTINATION CHECKSUM Empty destination checksum", errno.EINVAL)
            if source and not checksums_match(source, value):
                raise GError(
                    "TRANSFER CHECKSUM MISMATCH Source and destination checksums do not match "
                    f"{source} != {value}",
                    errno.EIO,
                )
            if user and not checksums_match(user, value):
                raise GError(
                    "TRANSFER CHECKSUM MISMATCH User defined checksum and destination checksums "
                    f"do not match {user} != {value}",
                    errno.EIO,
                )
        finally:
            transfer.event(ev.CHECKSUM_EXIT, "", ev.DESTINATION)

    def _rollback(
        self,
        transfer: Transfer,
        exc: BaseException,
        put: tuple[str, SURL] | None,
        moved: bool,
        finished: bool,
    ) -> None:
        """gfal2's ``srm_rollback_put``: remove a written destination, or abort the PUT.

        gfal2 also removes a destination that is not an SRM when the copy
        failed before it began - someone else's file; this does not.
        """
        destination = transfer.destination
        # EEXIST: the destination was there before this copy (refused by
        # ``srmPrepareToPut`` or the core's strict check) and is not ours.
        refused = isinstance(exc, GError) and exc.code == errno.EEXIST
        cleanup = transfer.params.transfer_cleanup
        # A complete file exists to remove: committed, or - for a non-SRM
        # destination, which has no put request - the bytes started moving.
        written = finished or (moved and put is None)
        if not refused and written and cleanup:
            status = 0
            try:
                self.context.unlink(destination)
            except GError as error:
                if error.code != errno.ENOENT:
                    self.log.warning("When trying to clean the destination: %s", error.message)
                    status = error.code
            transfer.event(ev.CLEANUP, str(status), ev.DESTINATION)
        elif not finished and put is not None:
            # Deliberately even without transfer_cleanup: no request is left pending.
            self.client.abort_request(put[1], put[0])
            if cleanup:  # some SRMs keep the file after an abort (gfal2's LCGUTIL-358)
                self.unlink_bulk([destination])


def _reorder(protocols: list[str], other: str) -> list[str]:
    """gfal2's ``reorder_rd3_sup_protocols``: the other end's scheme to the front.

    It swaps places with the head of the list (``gsiftp;root;https`` for a
    ``davs://`` end - ``davs`` counts as ``https`` - becomes
    ``https;root;gsiftp``), so that an SRM can hand out a TURL the other end
    can copy with directly.
    """
    scheme = other.partition(":")[0] if ":" in other else ""
    if scheme == "davs":
        scheme = "https"
    if scheme in protocols:
        index = protocols.index(scheme)
        protocols[0], protocols[index] = protocols[index], protocols[0]
    return protocols


def _inner(transfer: Transfer, srm_destination: bool) -> TransferParameters:
    """Parameters for the TURL-to-TURL copy: no checksums, no clean-up, events forwarded.

    The SRM plugin does the checksums and the clean-up, and, for an SRM
    destination, the overwrite and the parent directories, so that copy is
    strict; to anything else the core checks the destination, as in gfal2.
    The inner copy reports its progress as the outer copy's.
    """
    params = transfer.params.copy()
    if srm_destination:
        params.strict_copy = True
        params.overwrite = False
    params.transfer_cleanup = False
    params.set_checksum(0, "", "")
    left = transfer.remaining()
    params.timeout = max(1, int(left)) if left is not None else 0
    params.monitor_callback = lambda _s, _d, _a, _i, done, _e: transfer.progress(done)
    return params
