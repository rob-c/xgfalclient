"""The WLCG Tape REST API: staging, archive status and ``user.status`` over HTTP.

The API is found, per endpoint, at ``/.well-known/wlcg-tape-rest-api``, a
JSON document naming the site and one or more versioned API roots; gfal2
takes the highest of ``v0`` and ``v1`` (``V1``, ``1`` and ``v1.x`` count)
and caches it, and so does this. Files are named by their paths, with
doubled slashes collapsed, in the request bodies, not in the URL.

=============================  ==============================================
gfal2 call                     request
=============================  ==============================================
``bring_online``               ``POST {api}/stage`` - and nothing else: the
                               files are reported queued, sync or not
``bring_online_poll``          ``GET {api}/stage/{id}``
``abort_bring_online``         ``POST {api}/stage/{id}/cancel``
``release``                    ``POST {api}/release/{id}`` (``gfal2-placeholder-id``
                               when there is no id)
``archive_poll``, xattr        ``POST {api}/archiveinfo``
=============================  ==============================================

Messages, and errno values, are gfal2's ``[Tape REST API] ...`` ones: a
malformed answer is ``ENOMSG``, a status other than the one expected
``EINVAL`` (but a 401 or 403 to the discovery request is davix's own
``HTTP 403 : Permission refused``), a file reported ``LOST`` ``ENOENT``, ``NONE`` ``EPERM``, and
one not there yet (not on disk, not archived, ``UNAVAILABLE`` for now)
``EAGAIN``, which a single-file poll reports as ``0``.

The API's vocabulary is xrdhttp's (:mod:`xrdhttp.tape`), shared with
xrdclient's XrdClHttp-compatible client: the well-known path, reading the
discovery document (:func:`~xrdhttp.tape.listed_endpoints`, picking with
:func:`~xrdhttp.tape.newest_endpoint` by gfal2's ``parseVersion``), JSON
values as json-c spells them, slash collapsing, and finding a reply's entry
for a path. What stays here is gfal2's: the requests' shapes and statuses,
every message and errno, and the endpoint discovered. That is also why
:class:`xrdhttp.tape.TapeClient` is not used: it roots every request at
``/api/v1`` and accepts a set of statuses per verb, as XrdClHttp does,
where gfal2 roots them at the URI the discovery document names, expects one
exact status per call (``201`` for a stage) and words each failure with that
call's own name, which a ``send`` callback is never told.

The protocol is the WLCG Tape REST API (v1 specification, as implemented by
dCache, StoRM and CTA/EOS): staging is asynchronous - a ``POST /stage``
returns a request id at once, the client polls ``GET /stage/{id}`` for
per-file ``state``/``onDisk``, and ``/release/{id}`` lets the system evict
the disk copy again. ``archiveinfo`` is synchronous and reports each file's
``locality`` (``DISK``, ``TAPE``, ``DISK_AND_TAPE``, ``LOST``, ``NONE``,
``UNAVAILABLE``), which is how "is it on tape yet?" is asked after a write.
Every body is JSON, every request carries the same credentials as the file
itself (the ``cred_url``), and per-file problems arrive as an ``error``
field on that file's entry, not as an HTTP status.

Concurrency: one :class:`TapeREST` per plugin, shared by its threads; the
endpoint cache is locked, the requests are not (each is independent).
"""

from __future__ import annotations

import errno
import json
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from xrdhttp.tape import WELL_KNOWN as WELL_KNOWN
from xrdhttp.tape import TapeEndpoint as TapeEndpoint
from xrdhttp.tape import collapse as collapse
from xrdhttp.tape import entry_for, listed_endpoints, newest_endpoint
from xrdhttp.tape import json_text as _text

from ...errors import GError
from ...plugin import StagingResult
from ...url import parse
from ._client import Target, davix_status, status_text

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["TAPE_XATTRS", "TapeEndpoint", "TapeREST"]

#: The xattrs ``listxattr`` offers, and what they answer from the discovery document.
TAPE_XATTRS = ("taperestapi.version", "taperestapi.uri", "taperestapi.sitename")
#: What ``archiveinfo`` localities mean as gfal2 ``user.status`` values.
_STATUS = {"DISK": "ONLINE", "TAPE": "NEARLINE", "DISK_AND_TAPE": "ONLINE_AND_NEARLINE"}
#: Localities gfal2 turns into errors, with their errno.
_BAD_LOCALITY = {"LOST": errno.ENOENT, "NONE": errno.EPERM, "UNAVAILABLE": errno.EAGAIN}
#: The request id ``release`` uses when it was given none.
PLACEHOLDER_ID = "gfal2-placeholder-id"


def _not_yet(path: str, where: str) -> GError:
    """The ``EAGAIN`` gfal2 reports for a file still on its way (``where``: on disk, archived)."""
    return GError(f"[Tape REST API] File {path} is not yet {where}", errno.EAGAIN)


def _loads(payload: bytes) -> Any:
    """``payload`` as JSON, or ``None`` - which every caller turns into gfal2's ``ENOMSG``."""
    try:
        return json.loads(payload.decode("utf-8", "replace"))
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class _Call:
    """One Tape REST request, and how gfal2 words its failures.

    gfal2 names its calls inconsistently - a poll or a cancel fails as a
    "Stage" call, a poll that cannot be sent as "Stage pooling", and one
    message ends in a stray ``)`` - and those words are pinned by tests, so
    each call carries its own rather than deriving them from ``what``.
    """

    method: str
    #: The path under the API root (``/stage``, ``/archiveinfo``, ...).
    suffix: str
    #: How gfal2 names the call in its messages.
    what: str
    #: The JSON request body, or ``None`` for a bodiless ``GET``.
    document: Any = None
    #: The status a successful answer has (``201 Created`` for a stage).
    expect: int = 200
    #: The name used when the status is wrong, if not ``what``.
    failed: str = ""
    #: The name used when the request could not be made at all, if not ``what``.
    unreachable: str = ""
    #: Appended to the wrong-status message, as gfal2 appends it.
    tail: str = ""
    #: Whether an empty answer is an error (``release`` and ``cancel`` have none).
    answer: bool = True


class TapeREST:
    """The tape API of every endpoint this plugin has asked, discovered once each.

    A batch of URLs is sent to the API of the *first* URL's endpoint, as
    gfal2 does: a bring-online call is one request id at one site.
    """

    def __init__(self, plugin: HTTPPlugin) -> None:
        """Requests go through ``plugin`` (its credentials, retries and timeouts)."""
        self.plugin = plugin
        self._lock = threading.Lock()
        self._endpoints: dict[str, TapeEndpoint] = {}

    # -- discovery ---------------------------------------------------------------

    def endpoint(self, url: str) -> TapeEndpoint:
        """The API ``url``'s endpoint (scheme, host and port) offers, discovered on first use.

        Only successes are cached: a failed discovery is tried again on the
        next call, so a door that was briefly down does not stay "no tape
        API" for the life of the context. Two threads may both discover the
        same endpoint at once; the lock is not held across the request, and
        the answers are the same.
        """
        base = Target.of(url).base
        with self._lock:
            found = self._endpoints.get(base)
        if found is not None:
            return found
        found = self._discover(url, base)
        with self._lock:
            self._endpoints[base] = found
        return found

    def _discover(self, url: str, base: str) -> TapeEndpoint:
        """``GET`` the well-known document at ``base`` and pick the newest v0/v1 API in it.

        Each malformation has its own gfal2 message (``ENOMSG``): not JSON,
        no ``sitename``, no ``endpoints``, no usable version.
        """
        where = f"[Tape REST API] Failed to query {WELL_KNOWN}"
        try:
            response = self.plugin._request("GET", base + WELL_KNOWN, cred_url=url)
        except GError as exc:
            raise GError(f"{where}: {exc.message}", exc.code) from exc
        payload = response.body()
        if response.status in (401, 403):
            # davix fails the request itself on these, before gfal2 sees the answer.
            code = davix_status(response.status)[0]
            raise GError(f"{where}: {status_text(response.status)}", code)
        if response.status != 200:
            detail = payload.decode("utf-8", "replace")
            raise GError(f"{where}: {status_text(response.status)}: {detail}", errno.EINVAL)
        document = _loads(payload)
        if not isinstance(document, dict):
            raise GError(
                f"[Tape REST API] Malformed served response from {WELL_KNOWN}", errno.ENOMSG
            )
        if "sitename" not in document:
            raise GError(f"[Tape REST API] No sitename in response from {WELL_KNOWN}", errno.ENOMSG)
        if "endpoints" not in document:
            raise GError(
                f"[Tape REST API] No endpoints in response from {WELL_KNOWN}", errno.ENOMSG
            )
        chosen = newest_endpoint(listed_endpoints(document))
        if chosen is None:
            raise GError(
                f"[Tape REST API] Failed to find v0 or v1 metadata endpoint in response "
                f"from {WELL_KNOWN}",
                errno.ENOMSG,
            )
        return chosen

    def xattr(self, url: str, name: str) -> str:
        """One of :data:`TAPE_XATTRS`, read from the discovery document (cached)."""
        found = self.endpoint(url)
        return {
            "taperestapi.version": found.version,
            "taperestapi.uri": found.uri,
            "taperestapi.sitename": found.sitename,
        }[name]

    # -- requests ----------------------------------------------------------------

    def _call(self, url: str, call: _Call) -> bytes:
        """One API call; the body of an answer with the expected status, else gfal2's error.

        ``url`` is the first file's: it picks the endpoint (and so the API
        root) and the credentials, as gfal2 uses ``urls[0]`` for a batch.
        """
        uri = self.endpoint(url).uri
        # Normalised to exactly one slash between the root and the suffix,
        # whether or not the discovery document ended the URI with one.
        api = uri if uri.endswith("/") else uri + "/"
        body = None if call.document is None else json.dumps(call.document).encode()
        headers = {"Content-Type": "application/json"} if body is not None else {}
        try:
            response = self.plugin._request(
                call.method, api[:-1] + call.suffix, body=body, headers=headers, cred_url=url
            )
        except GError as exc:
            raise GError(
                f"[Tape REST API] {call.unreachable or call.what} call failed: {exc.message}",
                exc.code,
            ) from exc
        payload = response.body()
        if response.status != call.expect:
            text = payload.decode("utf-8", "replace")
            raise GError(
                f"[Tape REST API] {call.failed or call.what} call failed: "
                f"{status_text(response.status)}: {text}{call.tail}",
                errno.EINVAL,
            )
        if call.answer and not payload:
            raise GError("[Tape REST API] Response with no data", errno.ENOMSG)
        return payload

    @staticmethod
    def _paths(urls: Sequence[str]) -> list[str]:
        """The files' paths: the API names files by path, the endpoint being implied."""
        return [parse(url).path for url in urls]

    # -- staging -----------------------------------------------------------------

    def bring_online(
        self, urls: Sequence[str], metadata: Sequence[str]
    ) -> tuple[list[StagingResult], str]:
        """``POST /stage`` once; every file is then queued, as gfal2 reports it."""
        files: list[dict[str, Any]] = []
        # ``metadata`` may be shorter than ``urls`` - files past its end get
        # none - hence ``strict=False``; each non-empty entry must be JSON
        # and is passed through untouched as the file's ``targetedMetadata``.
        for path, extra in zip(self._paths(urls), metadata, strict=False):
            entry: dict[str, Any] = {"path": collapse(path)}
            if extra:
                try:
                    entry["targetedMetadata"] = json.loads(extra)
                except ValueError:
                    raise GError(f"Invalid metadata format: {extra}", errno.EINVAL) from None
            files.append(entry)
        payload = self._call(urls[0], _Call("POST", "/stage", "Stage", {"files": files}, 201))
        reply = _loads(payload)
        if reply is None:
            raise GError("[Tape REST API] Malformed served response", errno.ENOMSG)
        if not isinstance(reply, dict) or "requestId" not in reply:
            raise GError("[Tape REST API] requestID attribute missing", errno.ENOMSG)
        # ``False`` is "queued": a stage request is accepted, never completed,
        # in the answer to the POST, even for a file already on disk. Callers
        # learn otherwise from :meth:`poll`, as with gfal2.
        return [False for _ in urls], _text(reply["requestId"])

    def poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        """``GET /stage/{token}``: per file, ``True`` (on disk), ``EAGAIN`` (not yet) or an error.

        The reply must echo ``token`` as its ``id``; a different id would mean
        reading someone else's request, so it is ``ENOMSG``.
        """
        if not token:
            raise GError("The request ID was not provided", errno.EINVAL)
        stage = _Call("GET", f"/stage/{token}", "Stage", unreachable="Stage pooling", tail=")")
        payload = self._call(urls[0], stage)
        reply = _loads(payload)
        if reply is None:
            raise GError("[Tape REST API] Malformed served response", errno.ENOMSG)
        answered = _text(reply["id"]) if isinstance(reply, dict) and "id" in reply else ""
        if not answered:
            raise GError(
                f"[Tape REST API] Request ID missing from polling response (expected id={token})",
                errno.ENOMSG,
            )
        if answered != token:
            raise GError(
                f"[Tape REST API] Request ID mismatch. Expected id={token} but received "
                f"id={answered}",
                errno.ENOMSG,
            )
        if "files" not in reply:
            raise GError(
                "[Tape REST API] Files attribute missing from server poll response", errno.ENOMSG
            )
        return [self._staged(path, entry_for(reply["files"], path)) for path in self._paths(urls)]

    @staticmethod
    def _staged(path: str, entry: dict[str, Any] | None) -> StagingResult:
        """One file's polling entry as gfal2 reads it.

        ``onDisk``, where the server reports it, wins over ``state``; an
        ``error`` wins over both. ``STARTED``/``SUBMITTED`` are still pending; any
        state the spec does not define is an error, not a silent wait.
        """
        if entry is None:
            return GError(f"[Tape REST API] Missing response item for path={path}", errno.ENOMSG)
        if "error" in entry:
            return GError(f"[Tape REST API] {_text(entry['error'])}", errno.ENOMSG)
        if "onDisk" in entry:
            return _text(entry["onDisk"]).lower() == "true" or _not_yet(path, "on disk")
        if "state" not in entry:
            return GError("[Tape REST API] State and onDisk attributes missing", errno.ENOMSG)
        state = _text(entry["state"])
        if state == "COMPLETED":
            return True
        if state in ("STARTED", "SUBMITTED"):
            return _not_yet(path, "on disk")
        if state == "CANCELED":
            return GError(
                f"[Tape REST API] Staging operation cancelled. File={path}", errno.ECANCELED
            )
        if state == "FAILED":
            return GError(f"[Tape REST API] Staging operation failed for file={path}", errno.ENOENT)
        return GError(
            f"[Tape REST API] Unrecognized staging status. File={path} status={state}", errno.ENOENT
        )

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``POST /release/{token}``: the disk copies may go; one failure fails every file.

        The request id goes in the path; with none given, gfal2 sends
        :data:`PLACEHOLDER_ID` there, and the body still names the files.
        """
        return self._bulk(urls, f"/release/{token or PLACEHOLDER_ID}", "Release")

    def abort(self, urls: Sequence[str], token: str) -> list[GError | None]:
        """``POST /stage/{token}/cancel`` for these files; ``EINVAL`` without a token."""
        if not token:
            raise GError("The request ID was not provided", errno.EINVAL)
        return self._bulk(urls, f"/stage/{token}/cancel", "Cancel", failed="Stage")

    def _bulk(
        self, urls: Sequence[str], suffix: str, what: str, failed: str = ""
    ) -> list[GError | None]:
        """One ``{"paths": [...]}`` call whose outcome is every file's: the error, or ``None``.

        The API answers these calls for the batch as a whole, so a failure
        is reported against each file rather than raised, as gfal2's
        per-file error array does.
        """
        paths = [collapse(path) for path in self._paths(urls)]
        try:
            call = _Call("POST", suffix, what, {"paths": paths}, failed=failed, answer=False)
            self._call(urls[0], call)
        except GError as exc:
            return [exc for _ in urls]
        return [None for _ in urls]

    # -- archive -----------------------------------------------------------------

    def _archive_info(self, urls: Sequence[str]) -> Any:
        """``POST /archiveinfo`` for the files: the decoded list of per-path entries."""
        paths = [collapse(path) for path in self._paths(urls)]
        call = _Call("POST", "/archiveinfo", "Archive polling", {"paths": paths})
        payload = self._call(urls[0], call)
        reply = _loads(payload)
        if reply is None:
            raise GError("[Tape REST API] Malformed server response", errno.ENOMSG)
        return reply

    def _locality(self, entry: dict[str, Any] | None, path: str, bypass: bool) -> str:
        """gfal2's ``get_file_locality``: ``DISK``, ``TAPE`` or ``DISK_AND_TAPE``, else raises."""
        if entry is None:
            raise GError(f"[Tape REST API] Missing response item for path={path}", errno.ENOMSG)
        if "error" in entry and not bypass:
            raise GError(f"[Tape REST API] {_text(entry['error'])}", errno.ENOMSG)
        if "locality" not in entry:
            raise GError("[Tape REST API] Locality attribute missing", errno.ENOMSG)
        locality = _text(entry["locality"])
        if locality in _STATUS:
            return locality
        if locality in _BAD_LOCALITY:
            raise GError(
                f"[Tape REST API] File locality reported as {locality} (path={path})",
                _BAD_LOCALITY[locality],
            )
        raise GError(
            f'[Tape REST API] File locality reported as "{locality}" (path={path})', errno.ENOMSG
        )

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        """Per file: ``True`` once a tape copy exists, ``EAGAIN`` until then, or an error.

        One ``archiveinfo`` request for the batch; a file's own bad locality
        (``LOST``, ``NONE``) is its result, not the batch's.
        """
        reply = self._archive_info(urls)
        results: list[StagingResult] = []
        for path in self._paths(urls):
            try:
                # ``TAPE`` and ``DISK_AND_TAPE`` both mean a tape copy exists.
                archived = "TAPE" in self._locality(entry_for(reply, path), path, False)
            except GError as exc:
                results.append(exc)
                continue
            results.append(archived or _not_yet(path, "archived"))
        return results

    def status(self, url: str) -> str:
        """``user.status``: where the file is, in gfal2's words (an ``error`` field ignored)."""
        path = self._paths([url])[0]
        entry = entry_for(self._archive_info([url]), path)
        # ``bypass``: gfal2's ``user.status`` reads the locality even when the
        # entry also carries an ``error``, which archive polling would raise.
        return _STATUS[self._locality(entry, path, True)]
