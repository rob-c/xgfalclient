"""The WLCG Tape REST API: staging, archive status and ``user.status`` over HTTP.

The API is found, per endpoint, at ``/.well-known/wlcg-tape-rest-api``, a
JSON document naming the site and one or more versioned API roots; gfal2
takes ``v1`` (or ``v0``) and caches it, and so does this. Files are named by
their paths in the request bodies, not in the URL.

=============================  ==============================================
gfal2 call                     request
=============================  ==============================================
``bring_online``               ``POST {api}/stage``
``bring_online_poll``          ``GET {api}/stage/{id}``
``abort_bring_online``         ``POST {api}/stage/{id}/cancel``
``release``                    ``POST {api}/release/{id}``
``archive_poll``, xattr        ``POST {api}/archiveinfo``
=============================  ==============================================

Messages are worded as gfal2's ``[Tape REST API] ...`` ones.
"""

from __future__ import annotations

import errno
import json
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ...errors import GError
from ...plugin import StagingResult
from ...url import parse
from ._client import Target, http_errno, status_text

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["TapeREST", "TapeEndpoint", "TAPE_XATTRS"]

WELL_KNOWN = "/.well-known/wlcg-tape-rest-api"
#: The xattrs ``listxattr`` offers, and what they answer from the discovery document.
TAPE_XATTRS = ("taperestapi.version", "taperestapi.uri", "taperestapi.sitename")
#: What ``archiveinfo`` localities mean as gfal2 ``user.status`` values.
_STATUS = {
    "DISK": "ONLINE",
    "TAPE": "NEARLINE",
    "DISK_AND_TAPE": "ONLINE_AND_NEARLINE",
    "LOST": "LOST",
    "NONE": "NONE",
    "UNAVAILABLE": "UNAVAILABLE",
}
#: Polling cadence for a synchronous ``bring_online``.
POLL_START = 1.0
POLL_MAX = 30.0


@dataclass(frozen=True)
class TapeEndpoint:
    uri: str
    version: str
    sitename: str


def _json(payload: bytes) -> Any:
    return json.loads(payload.decode("utf-8", "replace"))


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
            raise GError(
                f"{where}: {status_text(response.status, response.reason)}",
                http_errno(response.status),
            )
        try:
            document = _json(payload)
        except ValueError:
            document = None
        if not isinstance(document, dict):
            raise GError(
                f"[Tape REST API] Malformed served response from {WELL_KNOWN}", errno.EPROTO
            )
        sitename = document.get("sitename")
        if not isinstance(sitename, str) or not sitename:
            raise GError(f"[Tape REST API] No sitename in response from {WELL_KNOWN}", errno.EPROTO)
        endpoints = document.get("endpoints")
        if not isinstance(endpoints, list) or not endpoints:
            raise GError(
                f"[Tape REST API] No endpoints in response from {WELL_KNOWN}", errno.EPROTO
            )
        chosen: TapeEndpoint | None = None
        for entry in endpoints:
            if not isinstance(entry, dict):
                continue
            version, uri = str(entry.get("version", "")), str(entry.get("uri", ""))
            if version in ("v0", "v1") and uri and (chosen is None or version > chosen.version):
                chosen = TapeEndpoint(uri.rstrip("/"), version, sitename)
        if chosen is None:
            raise GError(
                f"[Tape REST API] Failed to find v0 or v1 metadata endpoint in response "
                f"from {WELL_KNOWN}",
                errno.EPROTO,
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

    def _call(self, url: str, method: str, suffix: str, document: Any, what: str) -> Any:
        api = self.endpoint(url).uri
        body = None if document is None else json.dumps(document).encode()
        headers = {"Content-Type": "application/json"} if body is not None else {}
        try:
            response = self.plugin._request(
                method, api + suffix, body=body, headers=headers, cred_url=url
            )
        except GError as exc:
            raise GError(f"[Tape REST API] {what} call failed: {exc.message}", exc.code) from exc
        payload = response.body()
        if response.status >= 300:
            detail = status_text(response.status, response.reason)
            text = payload.decode("utf-8", "replace").strip()
            message = f"[Tape REST API] {what} call failed: {detail}"
            raise GError(f"{message}: {text}" if text else message, http_errno(response.status))
        if not payload.strip():
            return None
        try:
            return _json(payload)
        except ValueError as exc:
            raise GError("[Tape REST API] Malformed server response", errno.EPROTO) from exc

    @staticmethod
    def _paths(urls: Sequence[str]) -> list[str]:
        return [parse(url).path for url in urls]

    # -- staging -----------------------------------------------------------------

    def stage(self, urls: Sequence[str], metadata: Sequence[str]) -> str:
        files: list[dict[str, Any]] = []
        for path, extra in zip(self._paths(urls), metadata):
            entry: dict[str, Any] = {"path": path}
            if extra:
                try:
                    targeted = json.loads(extra)
                except ValueError:
                    targeted = None
                if not isinstance(targeted, dict):
                    raise GError(f"Invalid metadata format: {extra}", errno.EINVAL)
                entry["targetedMetadata"] = targeted
            files.append(entry)
        reply = self._call(urls[0], "POST", "/stage", {"files": files}, "Stage")
        request_id = reply.get("requestId") if isinstance(reply, dict) else None
        if not request_id:
            raise GError("[Tape REST API] requestID attribute missing", errno.EPROTO)
        return str(request_id)

    def poll(self, urls: Sequence[str], token: str) -> list[StagingResult]:
        if not token:
            raise GError("The request ID was not provided", errno.EINVAL)
        reply = self._call(urls[0], "GET", f"/stage/{token}", None, "Stage polling")
        if not isinstance(reply, dict):
            raise GError("[Tape REST API] Malformed server response", errno.EPROTO)
        answered = reply.get("id")
        if answered is not None and str(answered) != token:
            raise GError(
                f"[Tape REST API] Request ID mismatch. Expected id={token} but received "
                f"id={answered}",
                errno.EPROTO,
            )
        files = reply.get("files")
        if not isinstance(files, list):
            raise GError(
                "[Tape REST API] Files attribute missing from server poll response", errno.EPROTO
            )
        by_path = {str(entry.get("path")): entry for entry in files if isinstance(entry, dict)}
        return [self._staged(path, by_path.get(path)) for path in self._paths(urls)]

    @staticmethod
    def _staged(path: str, entry: dict[str, Any] | None) -> StagingResult:
        if entry is None:
            return GError(f"[Tape REST API] Missing response item for path={path}", errno.ENOENT)
        error = entry.get("error")
        if error:
            return GError(f"[Tape REST API] {error}", errno.EIO)
        if entry.get("onDisk") is True:
            return True
        state = str(entry.get("state", "")).upper()
        if state == "COMPLETED":
            return True
        if state in ("SUBMITTED", "STARTED"):
            return False
        if state == "CANCELLED" or state == "CANCELED":
            return GError(
                f"[Tape REST API] Staging operation cancelled. File={path}", errno.ECANCELED
            )
        if state == "FAILED":
            return GError(f"[Tape REST API] Staging operation failed for file={path}", errno.EIO)
        if not state and "onDisk" in entry:
            return False
        if not state:
            return GError("[Tape REST API] State and onDisk attributes missing", errno.EPROTO)
        return GError(
            f"[Tape REST API] Unrecognized staging status. File={path} status={state}", errno.EPROTO
        )

    def bring_online(
        self, urls: Sequence[str], metadata: Sequence[str], timeout: int, is_async: bool
    ) -> tuple[list[StagingResult], str]:
        token = self.stage(urls, metadata)
        results = self.poll(urls, token)
        deadline = time.monotonic() + max(timeout, 0)
        delay = POLL_START
        while not is_async and any(result is False for result in results):
            left = deadline - time.monotonic()
            if left <= 0:
                break
            time.sleep(min(delay, left))
            delay = min(delay * 2, POLL_MAX)
            results = self.poll(urls, token)
        return results, token

    def release(self, urls: Sequence[str], token: str) -> list[GError | None]:
        return self._bulk(urls, f"/release/{token}", "Release", token)

    def abort(self, urls: Sequence[str], token: str) -> list[GError | None]:
        return self._bulk(urls, f"/stage/{token}/cancel", "Cancel", token)

    def _bulk(self, urls: Sequence[str], suffix: str, what: str, token: str) -> list[GError | None]:
        if not token:
            raise GError("The request ID was not provided", errno.EINVAL)
        try:
            self._call(urls[0], "POST", suffix, {"paths": self._paths(urls)}, what)
        except GError as exc:
            return [exc for _ in urls]
        return [None for _ in urls]

    # -- archive -----------------------------------------------------------------

    def archive_info(self, urls: Sequence[str]) -> list[dict[str, Any] | GError]:
        reply = self._call(
            urls[0], "POST", "/archiveinfo", {"paths": self._paths(urls)}, "Archive polling"
        )
        entries = reply if isinstance(reply, list) else None
        if entries is None:
            raise GError("[Tape REST API] Malformed server response", errno.EPROTO)
        by_path = {str(entry.get("path")): entry for entry in entries if isinstance(entry, dict)}
        found: list[dict[str, Any] | GError] = []
        for path in self._paths(urls):
            entry = by_path.get(path)
            if entry is None:
                found.append(
                    GError(f"[Tape REST API] Missing response item for path={path}", errno.ENOENT)
                )
            elif entry.get("error"):
                message = str(entry["error"])
                code = (
                    errno.ENOENT
                    if "not" in message.lower() and "found" in message.lower()
                    else errno.EIO
                )
                found.append(GError(f"[Tape REST API] {message}", code))
            elif not entry.get("locality"):
                found.append(GError("[Tape REST API] Locality attribute missing", errno.EPROTO))
            else:
                found.append(entry)
        return found

    def archive_poll(self, urls: Sequence[str]) -> list[StagingResult]:
        results: list[StagingResult] = []
        for url, entry in zip(urls, self.archive_info(urls)):
            if isinstance(entry, GError):
                results.append(entry)
                continue
            locality = str(entry["locality"]).upper()
            if "TAPE" in locality:
                results.append(True)
            elif locality in ("LOST", "NONE", "UNAVAILABLE"):
                results.append(
                    GError(
                        f"[Tape REST API] File locality reported as {locality} "
                        f"(path={parse(url).path})",
                        errno.ENOENT if locality == "NONE" else errno.EIO,
                    )
                )
            else:
                results.append(False)
        return results

    def status(self, url: str) -> str:
        """``user.status``: where the file is, in gfal2's words."""
        entry = self.archive_info([url])[0]
        if isinstance(entry, GError):
            raise entry
        return _STATUS.get(str(entry["locality"]).upper(), "UNKNOWN")
