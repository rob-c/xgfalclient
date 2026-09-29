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
``EINVAL``, a file reported ``LOST`` ``ENOENT``, ``NONE`` ``EPERM``, and
one not there yet (not on disk, not archived, ``UNAVAILABLE`` for now)
``EAGAIN``, which a single-file poll reports as ``0``.
"""

from __future__ import annotations

import errno
import itertools
import json
import re
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from ...errors import GError
from ...plugin import StagingResult
from ...url import parse
from ._client import Target, status_text

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["TapeREST", "TapeEndpoint", "TAPE_XATTRS"]

WELL_KNOWN = "/.well-known/wlcg-tape-rest-api"
#: The xattrs ``listxattr`` offers, and what they answer from the discovery document.
TAPE_XATTRS = ("taperestapi.version", "taperestapi.uri", "taperestapi.sitename")
#: What ``archiveinfo`` localities mean as gfal2 ``user.status`` values.
_STATUS = {"DISK": "ONLINE", "TAPE": "NEARLINE", "DISK_AND_TAPE": "ONLINE_AND_NEARLINE"}
#: Localities gfal2 turns into errors, with their errno.
_BAD_LOCALITY = {"LOST": errno.ENOENT, "NONE": errno.EPERM, "UNAVAILABLE": errno.EAGAIN}
#: The request id ``release`` uses when it was given none.
PLACEHOLDER_ID = "gfal2-placeholder-id"
_SLASHES = re.compile("/{2,}")


@dataclass(frozen=True)
class TapeEndpoint:
    uri: str
    version: str
    sitename: str


def _text(value: Any) -> str:
    """A JSON value as json-c's ``json_object_get_string`` spells it."""
    return value if isinstance(value, str) else json.dumps(value)


def _parse_version(version: str) -> int:
    """gfal2's ``parseVersion``: ``v1``, ``V1``, ``1`` and ``v1.2`` are 1; ``vX`` is -1."""
    text = version.lower()
    text = text[1:] if text.startswith("v") else text
    if text and not text[0].isdigit():
        return -1
    digits = "".join(itertools.takewhile(str.isdigit, text))
    return int(digits) if digits else 0


def _not_yet(path: str, where: str) -> GError:
    return GError(f"[Tape REST API] File {path} is not yet {where}", errno.EAGAIN)


def collapse(path: str) -> str:
    """``//a//b`` as ``/a/b``: how gfal2 names a file to the tape API."""
    return _SLASHES.sub("/", path)


def _loads(payload: bytes) -> Any:
    try:
        return json.loads(payload.decode("utf-8", "replace"))
    except ValueError:
        return None


class TapeREST:
    """The tape API of every endpoint this plugin has asked, discovered once each."""

    def __init__(self, plugin: HTTPPlugin) -> None:
        self.plugin = plugin
        self._lock = threading.Lock()
        self._endpoints: dict[str, TapeEndpoint] = {}

    # -- discovery ---------------------------------------------------------------

    def endpoint(self, url: str) -> TapeEndpoint:
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
        where = f"[Tape REST API] Failed to query {WELL_KNOWN}"
        try:
            response = self.plugin._request("GET", base + WELL_KNOWN, cred_url=url)
        except GError as exc:
            raise GError(f"{where}: {exc.message}", exc.code) from exc
        payload = response.body()
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
        endpoints = document["endpoints"]
        best = 0
        chosen: TapeEndpoint | None = None
        for entry in endpoints if isinstance(endpoints, list) else []:
            if not isinstance(entry, dict) or "version" not in entry or "uri" not in entry:
                continue
            version = _text(entry["version"])
            number = _parse_version(version)
            if best <= number <= 1:
                chosen = TapeEndpoint(_text(entry["uri"]), version, _text(document["sitename"]))
                best = number
        if chosen is None or not chosen.uri:
            raise GError(
                f"[Tape REST API] Failed to find v0 or v1 metadata endpoint in response "
                f"from {WELL_KNOWN}",
                errno.ENOMSG,
            )
        return chosen

    def xattr(self, url: str, name: str) -> str:
        found = self.endpoint(url)
        return {
            "taperestapi.version": found.version,
            "taperestapi.uri": found.uri,
            "taperestapi.sitename": found.sitename,
        }[name]

    # -- requests ----------------------------------------------------------------

    def _call(
        self,
        url: str,
        method: str,
        suffix: str,
        document: Any,
        what: str,
        *,
        expect: int = 200,
        failed: str = "",
        unreachable: str = "",
        tail: str = "",
        answer: bool = True,
    ) -> bytes:
        """One API call; the body of an answer with ``expect``'s status, else gfal2's error.

        ``failed`` is how gfal2 names the call when the status is wrong (it
        says "Stage" for polls and cancels too, and adds a ``tail`` to one),
        ``unreachable`` when the request could not be made at all; an
        ``answer`` must not be empty.
        """
        uri = self.endpoint(url).uri
        api = uri if uri.endswith("/") else uri + "/"
        body = None if document is None else json.dumps(document).encode()
        headers = {"Content-Type": "application/json"} if body is not None else {}
        try:
            response = self.plugin._request(
                method, api[:-1] + suffix, body=body, headers=headers, cred_url=url
            )
        except GError as exc:
            raise GError(
                f"[Tape REST API] {unreachable or what} call failed: {exc.message}", exc.code
            ) from exc
        payload = response.body()
        if response.status != expect:
            text = payload.decode("utf-8", "replace")
            raise GError(
                f"[Tape REST API] {failed or what} call failed: "
                f"{status_text(response.status)}: {text}{tail}",
                errno.EINVAL,
            )
        if answer and not payload:
            raise GError("[Tape REST API] Response with no data", errno.ENOMSG)
        return payload

    @staticmethod
    def _paths(urls: Sequence[str]) -> list[str]:
        return [parse(url).path for url in urls]

    @staticmethod
    def _by_path(items: Any, path: str) -> dict[str, Any] | None:
        """The item of a JSON list whose ``path`` names ``path`` (slashes collapsed)."""
        for item in items if isinstance(items, list) else []:
            named = isinstance(item, dict) and item.get("path")
            if named and collapse(_text(item["path"])) == collapse(path):
                return cast("dict[str, Any]", item)
        return None

    # -- staging -----------------------------------------------------------------

    def bring_online(
        self, urls: Sequence[str], metadata: Sequence[str]
    ) -> tuple[list[StagingResult], str]:
        """``POST /stage`` once; every file is then queued, as gfal2 reports it."""
        files: list[dict[str, Any]] = []
        for path, extra in zip(self._paths(urls), metadata):
            entry: dict[str, Any] = {"path": collapse(path)}
            if extra:
                try:
                    entry["targetedMetadata"] = json.loads(extra)
                except ValueError:
                    raise GError(f"Invalid metadata format: {extra}", errno.EINVAL) from None
            files.append(entry)
        payload = self._call(urls[0], "POST", "/stage", {"files": files}, "Stage", expect=201)
        reply = _loads(payload)
        if reply is None:
            raise GError("[Tape REST API] Malformed served response", errno.ENOMSG)
        if not isinstance(reply, dict) or "requestId" not in reply:
            raise GError("[Tape REST API] requestID attribute missing", errno.ENOMSG)
        return [False for _ in urls], _text(reply["requestId"])

    def poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        if not token:
            raise GError("The request ID was not provided", errno.EINVAL)
        payload = self._call(
            urls[0], "GET", f"/stage/{token}", None, "Stage", unreachable="Stage pooling", tail=")"
        )
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
        return [
            self._staged(path, self._by_path(reply["files"], path)) for path in self._paths(urls)
        ]

    @staticmethod
    def _staged(path: str, entry: dict[str, Any] | None) -> StagingResult:
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
        return self._bulk(urls, f"/release/{token or PLACEHOLDER_ID}", "Release")

    def abort(self, urls: Sequence[str], token: str) -> list[GError | None]:
        if not token:
            raise GError("The request ID was not provided", errno.EINVAL)
        return self._bulk(urls, f"/stage/{token}/cancel", "Cancel", failed="Stage")

    def _bulk(
        self, urls: Sequence[str], suffix: str, what: str, failed: str = ""
    ) -> list[GError | None]:
        paths = [collapse(path) for path in self._paths(urls)]
        try:
            self._call(urls[0], "POST", suffix, {"paths": paths}, what, failed=failed, answer=False)
        except GError as exc:
            return [exc for _ in urls]
        return [None for _ in urls]

    # -- archive -----------------------------------------------------------------

    def _archive_info(self, urls: Sequence[str]) -> Any:
        paths = [collapse(path) for path in self._paths(urls)]
        payload = self._call(urls[0], "POST", "/archiveinfo", {"paths": paths}, "Archive polling")
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
        reply = self._archive_info(urls)
        results: list[StagingResult] = []
        for path in self._paths(urls):
            try:
                archived = "TAPE" in self._locality(self._by_path(reply, path), path, False)
            except GError as exc:
                results.append(exc)
                continue
            results.append(archived or _not_yet(path, "archived"))
        return results

    def status(self, url: str) -> str:
        """``user.status``: where the file is, in gfal2's words (an ``error`` field ignored)."""
        path = self._paths([url])[0]
        entry = self._by_path(self._archive_info([url]), path)
        return _STATUS[self._locality(entry, path, True)]
