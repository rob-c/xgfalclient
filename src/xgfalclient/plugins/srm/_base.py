"""What every SRM operation shares: options, SURL resolution and TURL requests.

Part of the :mod:`xgfalclient.plugins.srm.plugin` split (that module's
docstring has gfal2's behaviour and the layout). :class:`_SRMBase` is the
plugin class's root: it owns the SOAP :class:`~.transport.Transport`, the
:class:`~.client.Client` and the BDII :class:`~.bdii.Resolver`, reads the
plugin's options, resolves a short SURL's web service, and makes the
requests both I/O and copies are built on - ``srmPrepareToGet`` and
``srmPrepareToPut`` for a TURL, ``srmReleaseFiles``, ``srmPutDone`` - plus
the ``srmLs`` of one SURL that stat, the nearline checks and copies start
from. The module-level helpers here (``_turl``, ``_by_endpoint``,
``_stat_error``, ``_locality``) are the ones more than one of the split
modules uses.

Nothing here is looked up through the facade at call time: no test or
caller patches a module-level name these functions use. ``LS_CHUNK``, which
a test does patch, stays in :mod:`.plugin` with the listing that reads it.

The TURL life cycle, which every caller must keep balanced: a get's token
is released (``srmReleaseFiles``) once the TURL is read, even on failure;
a put's token is committed (``srmPutDone``) after a good write and aborted
(``srmAbortRequest``) after a bad one. A request left open pins disk space
on the server until its lifetime runs out. The one deliberate exception is
``user.replicas``, whose TURL gfal2 leaves pinned so it stays usable.
"""

from __future__ import annotations

import errno
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from ...errors import GError
from ...plugin import Plugin
from ...url import scheme_of
from .bdii import Resolver
from .client import Client, Detail, FileStatus, Status, file_error
from .transport import SURL, Transport, parse_surl

#: The plugin's option group in gfal2's configuration.
GROUP = "SRM PLUGIN"
#: gfal2's ``TURL_PROTOCOLS`` default: the schemes asked for to open a file
#: or bring one online, most wanted first.
DEFAULT_TURL_PROTOCOLS = ["gsiftp", "rfio", "gsidcap", "dcap", "kdcap"]
#: gfal2's ``TURL_3RD_PARTY_PROTOCOLS`` default, for copies and checksums.
DEFAULT_3RD_PARTY_PROTOCOLS = ["gsiftp", "https", "root"]

#: The domain of the ``SRM:GET``/``SRM:PUT`` events; the others are ``SRM``.
EVENT_DOMAIN = "GFAL2::PLUGINS::SRM"
GET_EVENT = "SRM:GET"
PUT_EVENT = "SRM:PUT"
CLOSE_ENTER = "CLOSE:ENTER"
CLOSE_EXIT = "CLOSE:EXIT"
#: ``checksum_mode`` bits.
_SOURCE, _TARGET = 1, 2
#: The tail of gfal2's warning when a short SURL's service had to be guessed
#: (the missing space after the full stop is gfal2's, kept so logs match).
_ADVICE = (
    "fallback on the default service path.This can lead to wrong service path, you should "
    "use FULL SURL format or register your endpoint into the BDII"
)

#: The ``TFileLocality`` values; anything else a server sends is ``UNKNOWN``.
_LOCALITIES = ("ONLINE", "NEARLINE", "ONLINE_AND_NEARLINE", "LOST", "NONE", "UNAVAILABLE")


def _locality(detail: Detail) -> str:
    """The ``user.status`` answer: the file's locality, or ``UNKNOWN``."""
    return detail.locality if detail.locality in _LOCALITIES else "UNKNOWN"


def _stat_error(status: Status) -> GError:
    """A failed ``srmLs`` entry, worded as gfal2's stat words it (same ``errno``)."""
    error = file_error("Ls", status)
    return GError(f"Error reported from srm_ifce : {error.code} {error.message}", error.code)


def _by_endpoint(
    urls: Sequence[str], results: list[Any], parse: Callable[[str], SURL]
) -> list[tuple[list[int], list[SURL]]]:
    """SURLs grouped by endpoint, keeping their indices; bad ones fail in place.

    The bulk operations (``unlink_bulk``, ``archive_poll``) send one request
    per web service, since a request can only go to one. ``results`` is the
    caller's per-URL answer list: an unparseable URL's ``GError`` goes in
    its slot and it joins no group. Groups keep first-seen order, and
    within a group the URLs keep theirs, so answers map back by index.
    """
    groups: dict[tuple[str, int, str], tuple[list[int], list[SURL]]] = {}
    for index, url in enumerate(urls):
        try:
            surl = parse(url)
        except GError as exc:
            results[index] = exc
            continue
        indices, surls = groups.setdefault(surl.key, ([], []))
        indices.append(index)
        surls.append(surl)
    return list(groups.values())


def _turl(found: FileStatus, short: str, protocols: list[str], space: str) -> str:
    """The TURL of a get or put, or its failure in gfal2's words.

    gfal2 words a copy's failure ``error on the turl  request`` (an empty
    ``%s`` between the spaces) and an open's ``error on the turl request``;
    ``space`` carries that difference.

    A success without a TURL is the server's fault and fails as
    ``SRM_FAILURE`` (``EIO``). A TURL on a scheme that was not asked for is
    refused with ``EPROTONOSUPPORT``, as gfal2 refuses it: the caller asked
    only for schemes it knows how to use.
    """
    if not found.status.ok or not found.turl:
        status = found.status
        if status.ok:
            status = Status("SRM_FAILURE", "the server returned no transfer URL")
        error = file_error(short, status)
        raise GError(f"error on the turl {space}request : {error.message} ", error.code)
    if scheme_of(found.turl) not in protocols:
        raise GError(
            f"The SRM endpoint returned a protocol that wasn't requested: {found.turl}",
            errno.EPROTONOSUPPORT,
        )
    return found.turl


@dataclass(frozen=True, slots=True)
class _TURLRequest:
    """How one ``srmPrepareToGet``/``srmPrepareToPut`` asks for its TURL.

    ``protocols`` are the acceptable TURL schemes, most wanted first;
    ``timeout`` is how long to poll, in seconds; ``spacetoken`` a space
    token *description* ("" for none); ``space`` the filler gfal2 puts in
    its failure message (see :func:`_turl`): " " for a copy, "" otherwise.
    """

    protocols: list[str]
    timeout: float
    spacetoken: str = ""
    space: str = ""


class _SRMBase(Plugin):
    """Options, SURL resolution and the TURL requests: see the module docstring.

    One instance per context, shared by every thread using it: the
    transport's pool and the resolver's cache are locked, and nothing else
    here is mutable.
    """

    def __init__(self, context: Any) -> None:
        """The SOAP transport, its client, and the BDII resolver of ``context``."""
        super().__init__(context)
        self.transport = Transport(self)
        self.client = Client(self.transport)
        self.bdii = Resolver(context.options)

    def close(self) -> None:
        """Close the pooled httpg connections (the context's ``free()``)."""
        self.transport.close()

    def handles(self, url: str, operation: str) -> bool:
        """gfal2's ``^srm://.+$``, case-blind: a bare ``srm://`` is nobody's (93)."""
        return super().handles(url, operation) and len(url) > len("srm://")

    # -- options -------------------------------------------------------------------

    def _timeout(self) -> float:
        """``OPERATION_TIMEOUT`` (else the core's), in seconds, for polls and lookups."""
        return float(self.option_timeout())

    def _request_time(self) -> int:
        """``REQUEST_LIFETIME``: the ``desiredTotalRequestTime`` of gets and puts."""
        return int(self.options.integer(GROUP, "REQUEST_LIFETIME", 3600))

    def _turl_protocols(self) -> list[str]:
        """``TURL_PROTOCOLS``: what local I/O and bring-online ask for (a fresh list)."""
        return list(self.options.string_list(GROUP, "TURL_PROTOCOLS", DEFAULT_TURL_PROTOCOLS))

    def _third_party_protocols(self) -> list[str]:
        """``TURL_3RD_PARTY_PROTOCOLS``: what copies and checksums ask for (a fresh list)."""
        return list(
            self.options.string_list(GROUP, "TURL_3RD_PARTY_PROTOCOLS", DEFAULT_3RD_PARTY_PROTOCOLS)
        )

    def _spacetoken(self) -> str:
        """``SPACETOKENDESC``: the space every request but a copy's asks for."""
        return str(self.options.string(GROUP, "SPACETOKENDESC", ""))

    def _surl(self, url: str) -> SURL:
        """``url`` parsed, and its web service found as gfal2 finds it.

        A full SURL names its service and is used as written. A short one
        asks the BDII (when ``[BDII] ENABLED``); a BDII failure, an empty
        answer or a disabled BDII all fall back to the guessed
        ``/srm/managerv2`` service with gfal2's warning, never to an error.
        Only an unparseable URL raises (``EINVAL``).
        """
        surl = parse_surl(url)
        if surl.full:
            return surl
        found = None
        if self.bdii.enabled():
            try:
                found = self.bdii.endpoint(surl.host, self._timeout())
            except GError as exc:
                self.log.warning(
                    "Error while bdii SRM service resolution : %s, %s", exc.message, _ADVICE
                )
                return surl
        if found is None:  # gfal2 says this too when the BDII had nothing, and no error
            self.log.warning("BDII usage disabled, %s", _ADVICE)
            return surl
        self.log.debug("Service endpoint resolution, resolved from BDII %s -> %s", url, found)
        return surl.with_endpoint(found)

    # -- the srmLs every check starts from ---------------------------------------

    def _detail(self, surl: SURL) -> Detail:
        """``srmLs`` of one SURL, failing as gfal2's stat fails.

        ``ENOENT`` for a missing file comes from the entry's
        ``SRM_INVALID_PATH``; callers that want "does it exist" catch that.
        """
        detail = self.client.ls([surl], timeout=self._timeout())[0]
        if not detail.status.ok:
            raise _stat_error(detail.status)
        return detail

    def _require_online(self, surl: SURL, prefix: str) -> None:
        """``COPY_FAIL_NEARLINE``/``XATTR_FAIL_NEARLINE``: refuse a file only on tape.

        As gfal2: exactly ``NEARLINE``; ``NONE``, ``LOST`` and the rest go on
        to ask for a TURL.
        """
        if _locality(self._detail(surl)) == "NEARLINE":
            raise GError(f"{prefix}The source file is not ONLINE", errno.EINVAL)

    # -- TURLs -----------------------------------------------------------------------

    def _local_request(self, protocols: list[str]) -> _TURLRequest:
        """A TURL request outside a copy: the operation timeout and ``SPACETOKENDESC``."""
        return _TURLRequest(protocols, self._timeout(), self._spacetoken())

    def _get_turl(self, surl: SURL, request: _TURLRequest) -> tuple[str, str]:
        """``(token, TURL)`` of an ``srmPrepareToGet``; the token must be released."""
        token, statuses = self.client.prepare_get(
            [surl],
            request.protocols,
            request_time=self._request_time(),
            timeout=request.timeout,
            spacetoken=request.spacetoken,
        )
        return token, _turl(statuses[0], "PrepareToGet", request.protocols, request.space)

    def _put_turl(self, surl: SURL, size: int, request: _TURLRequest) -> tuple[str, str]:
        """``(token, TURL)`` of an ``srmPrepareToPut`` of ``size`` bytes.

        The token must end in :meth:`_put_done` or an ``srmAbortRequest``.
        """
        token, statuses = self.client.prepare_put(
            [(surl, size)],
            request.protocols,
            request_time=self._request_time(),
            timeout=request.timeout,
            spacetoken=request.spacetoken,
        )
        return token, _turl(statuses[0], "PrepareToPut", request.protocols, request.space)

    def _release_quietly(self, token: str, surl: SURL) -> None:
        """``srmReleaseFiles`` of a get's TURL, logging rather than raising.

        It runs on close and clean-up paths, where the read's own result (or
        error) is what the caller must see; a pin left behind expires with
        the request's lifetime.
        """
        try:
            self.client.release(token, [surl])
        except GError as exc:
            self.log.debug("error on the release request : %s", exc)

    def _put_done(self, token: str, surl: SURL) -> None:
        """``srmPutDone`` of one upload; its per-file failure raises in gfal2's words."""
        found = self.client.put_done(token, [surl])[0]
        if not found.status.ok:
            error = file_error("PutDone", found.status)
            raise GError(
                f"Error on the surl {surl.wire} while putdone : {error.message}", error.code
            )
