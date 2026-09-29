"""The SRM v2.2 operations, as srm-ifce performs them for gfal2.

Each method builds the request srm-ifce builds - element for element, as
captured from gfal2 2.23.5 - sends it through the
:class:`~.transport.Transport`, and reads the reply into plain records.
Asynchronous requests (``srmPrepareToGet``, ``srmPrepareToPut``,
``srmBringOnline``, and ``srmLs`` on servers that queue it) are polled with
their ``srmStatusOf*Request`` twin, backing off exponentially, while they
are ``SRM_REQUEST_QUEUED`` or ``SRM_REQUEST_INPROGRESS``; when the caller's
time runs out the request is aborted, as srm-ifce aborts it.

Failures read as srm-ifce writes them: ``[SE][<Op>][<TStatusCode>] <endpoint>:
<explanation>`` for a request (inside gfal2's ``srm-ifce err: ...`` wrapper),
``[SE][<Op>][<TStatusCode>] <explanation>`` for one file of a request, with
the ``errno`` of :func:`~.soap.errno_for_status`.
"""

from __future__ import annotations

import errno
import os
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ..._compat import SLOTS
from ...errors import ECOMM, GError
from . import soap
from .transport import SURL, Transport, ifce_error, normalise_path, parse_surl

__all__ = [
    "Client",
    "Status",
    "Detail",
    "FileStatus",
    "Space",
    "request_error",
    "empty_response",
    "file_error",
    "match",
    "POLL_INITIAL",
    "POLL_MAX",
]

#: First wait between polls of an asynchronous request, in seconds; doubles
#: each time up to :data:`POLL_MAX`.
POLL_INITIAL = 0.05
POLL_MAX = 10.0

#: What srm-ifce asks for on every get, put and bring-online.
STORAGE_TYPE = "PERMANENT"

#: Request-level codes a single-answer call reports as ``<empty response>``.
_EMPTY = frozenset({"SRM_TOO_MANY_RESULTS", "SRM_DONE", "SRM_PARTIAL_SUCCESS"})


@dataclass(**SLOTS)
class Status:
    """A ``TReturnStatus``."""

    code: str
    explanation: str = ""

    @property
    def ok(self) -> bool:
        return self.code in soap.SUCCESS

    @property
    def pending(self) -> bool:
        return self.code in soap.PENDING

    @property
    def errno(self) -> int:
        return soap.errno_for_status(self.code)


def _status(node: soap.Node | None, missing: str = "SRM_FAILURE") -> Status:
    """A ``TReturnStatus``; an absent one is ``missing`` (srm-ifce reads an
    absent file status as success, an absent request status as failure)."""
    if node is None:
        return Status(missing, "" if missing in soap.SUCCESS else "the server returned no status")
    return Status(node.get("statusCode") or "SRM_FAILURE", node.get("explanation"))


def request_error(surl: SURL, short: str, status: Status) -> GError:
    """A failed request, worded as srm-ifce words it.

    ``status`` is never a success, so its ``errno`` is never ``0``.
    """
    explanation = status.explanation or "<none>"
    return ifce_error(status.errno, f"[SE][{short}][{status.code}] {surl.endpoint}: {explanation}")


def empty_response(surl: SURL, short: str, code: str = "") -> GError:
    """srm-ifce's complaint about a reply that lacks what it came for."""
    return ifce_error(ECOMM, f"[SE][{short}][{code}] {surl.endpoint}: <empty response>")


def file_error(short: str, status: Status) -> GError:
    """One file's failure within a request."""
    code = status.errno or errno.EINVAL
    return GError(f"[SE][{short}][{status.code}] {status.explanation or '<none>'}", code)


@dataclass(**SLOTS)
class Detail:
    """A ``TMetaDataPathDetail``: one entry of an ``srmLs`` reply."""

    path: str
    status: Status
    size: int = 0
    kind: str = ""
    created: int = 0
    modified: int = 0
    locality: str = ""
    owner: int = 0
    group: int = 0
    other: int = 0
    checksum_type: str = ""
    checksum_value: str = ""
    subpaths: list[Detail] = field(default_factory=list)

    @property
    def name(self) -> str:
        return os.path.basename(self.path.rstrip("/"))


def _detail(node: soap.Node) -> Detail:
    return Detail(
        path=node.get("path"),
        status=_status(node.child("status"), "SRM_SUCCESS"),
        size=node.integer("size") or 0,
        kind=node.get("type").upper(),
        created=soap.parse_time(node.get("createdAtTime")),
        modified=soap.parse_time(node.get("lastModificationTime")),
        locality=node.get("fileLocality").upper(),
        owner=soap.permission_bits(node.get("ownerPermission", "mode")),
        group=soap.permission_bits(node.get("groupPermission", "mode")),
        other=soap.permission_bits(node.get("otherPermission")),
        checksum_type=node.get("checkSumType"),
        checksum_value=node.get("checkSumValue"),
        subpaths=[_detail(child) for child in node.array("arrayOfSubPaths", "pathDetailArray")],
    )


@dataclass(**SLOTS)
class FileStatus:
    """One file of a request: its SURL, status, and TURL when there is one."""

    surl: str
    status: Status
    turl: str = ""


@dataclass(**SLOTS)
class Space:
    """A ``TMetaDataSpace`` from ``srmGetSpaceMetaData``."""

    token: str
    status: Status
    owner: str = ""
    total: int = 0
    guaranteed: int = 0
    unused: int = 0
    assigned: int = 0
    left: int = 0
    retention: str = ""
    latency: str = ""


def _surls(surls: Sequence[SURL]) -> soap.Fields:
    return [("urlArray", surl.wire) for surl in surls]


def _protocols(protocols: Sequence[str]) -> soap.Fields:
    return [("arrayOfTransferProtocols", [("stringArray", name) for name in protocols])]


def _same(first: str, second: SURL) -> bool:
    """Whether a SURL in a reply names ``second``, however it is written."""
    if first in (second.wire, second.url):
        return True
    try:
        found = parse_surl(first)
    except GError:
        return False
    same_path = normalise_path(found.path) == normalise_path(second.path)
    return found.host == second.host and same_path


def match(surls: Sequence[SURL], found: Sequence[FileStatus]) -> list[FileStatus]:
    """``found`` in the order of ``surls``; servers need not keep it.

    A reply entry is matched by its SURL; one without a SURL stands in for
    the request at its own position.
    """
    result = []
    for index, surl in enumerate(surls):
        hit = next((item for item in found if _same(item.surl, surl)), None)
        if hit is None and index < len(found) and not found[index].surl:
            hit = found[index]
        if hit is None:
            hit = FileStatus(surl.url, Status("SRM_FAILURE", "the server returned no status"))
        result.append(hit)
    return result


class Client:
    """SRM v2.2 requests over a :class:`Transport`."""

    def __init__(
        self, transport: Transport, *, sleep: Callable[[float], None] = time.sleep
    ) -> None:
        self.transport = transport
        self.sleep = sleep

    def call(self, surl: SURL, operation: str, fields: soap.Fields) -> soap.Node:
        return self.transport.call(surl, operation, fields)

    def simple(self, surl: SURL, operation: str, fields: soap.Fields) -> Status:
        """A call whose only answer is its ``returnStatus``, which must be success."""
        status = _status(self.call(surl, operation, fields).child("returnStatus"))
        if status.code in _EMPTY:
            raise empty_response(surl, operation[3:], status.code)
        if not status.ok:
            raise request_error(surl, operation[3:], status)
        return status

    # -- asynchronous requests -------------------------------------------------------

    def wait(
        self,
        surl: SURL,
        reply: soap.Node,
        status_operation: str,
        status_fields: Callable[[str], soap.Fields],
        timeout: float,
    ) -> tuple[soap.Node, str]:
        """Poll an asynchronous request until it is no longer pending."""
        token = reply.get("requestToken")
        deadline = time.monotonic() + timeout
        attempt = 0
        while True:
            status = _status(reply.child("returnStatus"))
            if not status.pending:
                return reply, token
            if not token:
                raise request_error(surl, status_operation[3:], status)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.abort_request(surl, token)
                raise ifce_error(
                    errno.ETIMEDOUT,
                    f"[SE][{status_operation[3:]}][ETIMEDOUT] {surl.endpoint}: User timeout over",
                )
            self.sleep(min(POLL_INITIAL * (2**attempt), POLL_MAX, remaining))
            attempt += 1
            reply = self.call(surl, status_operation, status_fields(token))

    def abort_request(self, surl: SURL, token: str) -> None:
        """``srmAbortRequest``, best effort: a request given up on should not linger."""
        try:
            self.simple(surl, "srmAbortRequest", [("requestToken", token)])
        except GError:
            pass

    def _file_statuses(
        self, surl: SURL, short: str, reply: soap.Node, key: str, surls: Sequence[SURL]
    ) -> list[FileStatus]:
        """Per-file results; a request-level failure only when there are none."""
        found = [
            FileStatus(node.get(key), _status(node.child("status")), node.get("transferURL"))
            for node in reply.array("arrayOfFileStatuses", "statusArray")
        ]
        if found:
            return match(surls, found)
        status = _status(reply.child("returnStatus"))
        if status.ok:
            return [FileStatus(item.url, status) for item in surls]
        raise request_error(surl, short, status)

    # -- namespace -------------------------------------------------------------------

    def ping(self, surl: SURL) -> tuple[str, dict[str, str]]:
        """``srmPing``: the version and the ``otherInfo`` pairs (``backend_type``...)."""
        reply = self.call(surl, "srmPing", [])
        extra = {
            node.get("key"): node.get("value")
            for node in reply.array("otherInfo", "extraInfoArray")
        }
        return reply.get("versionInfo"), extra

    def ls(
        self,
        surls: Sequence[SURL],
        *,
        levels: int = 0,
        offset: int | None = None,
        count: int | None = None,
        timeout: float,
    ) -> list[Detail]:
        """``srmLs`` with ``fullDetailedList``; a queued listing is polled."""
        surl = surls[0]
        fields: soap.Fields = [
            ("arrayOfSURLs", _surls(surls)),
            ("storageSystemInfo", soap.NIL),
            ("fullDetailedList", True),
            ("numOfLevels", levels),
            ("offset", offset),
            ("count", count),
        ]
        reply, _ = self.wait(
            surl,
            self.call(surl, "srmLs", fields),
            "srmStatusOfLsRequest",
            lambda token: [("requestToken", token)],
            timeout,
        )
        details = [_detail(node) for node in reply.array("details", "pathDetailArray")]
        if details:
            return details
        status = _status(reply.child("returnStatus"))
        if status.ok:
            raise empty_response(surl, "Ls", status.code)
        raise request_error(surl, "Ls", status)

    def check_permission(self, surl: SURL) -> tuple[Status, int]:
        """``srmCheckPermission``: the file's status and the caller's ``rwx`` bits."""
        reply = self.call(surl, "srmCheckPermission", [("arrayOfSURLs", _surls([surl]))])
        found = reply.array("arrayOfPermissions", "surlPermissionArray")
        if found:
            entry = found[0]
            return _status(entry.child("status")), soap.permission_bits(entry.get("permission"))
        status = _status(reply.child("returnStatus"))
        if status.ok:
            raise empty_response(surl, "CheckPermission", status.code)
        raise request_error(surl, "CheckPermission", status)

    def mkdir(self, surl: SURL) -> None:
        self.simple(surl, "srmMkdir", [("SURL", surl.wire)])

    def rmdir(self, surl: SURL) -> Status:
        """``srmRmdir``; the status is the caller's to report, as srm-ifce leaves it."""
        reply = self.call(surl, "srmRmdir", [("SURL", surl.wire)])
        return _status(reply.child("returnStatus"))

    def mv(self, source: SURL, destination: SURL) -> None:
        self.simple(source, "srmMv", [("fromSURL", source.wire), ("toSURL", destination.wire)])

    def set_permission(self, surl: SURL, mode: int) -> None:
        """``srmSetPermission`` ``CHANGE`` of the owner and other bits.

        gfal2 sends these two and no group permission (a ``TGroupPermission``
        needs a group name it does not have). It writes the modes as
        ordinals (``6``), which the WSDL's enumeration does not allow; this
        writes their names (``RW``).
        """
        self.simple(
            surl,
            "srmSetPermission",
            [
                ("SURL", surl.wire),
                ("permissionType", "CHANGE"),
                ("ownerPermission", soap.permission(mode >> 6)),
                ("otherPermission", soap.permission(mode)),
            ],
        )

    def rm(self, surls: Sequence[SURL]) -> list[FileStatus]:
        surl = surls[0]
        reply = self.call(surl, "srmRm", [("arrayOfSURLs", _surls(surls))])
        return self._file_statuses(surl, "srmRm", reply, "surl", surls)

    # -- transfers -------------------------------------------------------------------

    def space_token(self, surl: SURL, description: str) -> str | None:
        """srm-ifce's lookup: a space token *description* to the token itself."""
        if not description:
            return None
        tokens = self.space_tokens(surl, description)
        if not tokens:
            text = f"[SE][GetSpaceTokens][] {surl.endpoint}: no valid space tokens"
            raise ifce_error(errno.EINVAL, text)
        return tokens[0]

    def prepare_get(
        self,
        surls: Sequence[SURL],
        protocols: Sequence[str],
        *,
        request_time: int,
        timeout: float,
        spacetoken: str = "",
    ) -> tuple[str, list[FileStatus]]:
        """``srmPrepareToGet``, polled until every TURL is ready or has failed."""
        surl = surls[0]
        fields: soap.Fields = [
            (
                "arrayOfFileRequests",
                [("requestArray", [("sourceSURL", item.wire)]) for item in surls],
            ),
            ("desiredFileStorageType", STORAGE_TYPE),
            ("desiredTotalRequestTime", request_time),
            ("targetSpaceToken", self.space_token(surl, spacetoken)),
            ("transferParameters", _protocols(protocols)),
        ]
        reply, token = self.wait(
            surl,
            self.call(surl, "srmPrepareToGet", fields),
            "srmStatusOfGetRequest",
            lambda token: [("requestToken", token)],
            timeout,
        )
        return token, self._file_statuses(surl, "PrepareToGet", reply, "sourceSURL", surls)

    def prepare_put(
        self,
        surls: Sequence[SURL],
        sizes: Sequence[int],
        protocols: Sequence[str],
        *,
        request_time: int,
        timeout: float,
        spacetoken: str = "",
    ) -> tuple[str, list[FileStatus]]:
        """``srmPrepareToPut``, polled until every TURL is ready or has failed."""
        surl = surls[0]
        fields: soap.Fields = [
            (
                "arrayOfFileRequests",
                [
                    ("requestArray", [("targetSURL", item.wire), ("expectedFileSize", size)])
                    for item, size in zip(surls, sizes)
                ],
            ),
            ("desiredTotalRequestTime", request_time),
            ("desiredFileStorageType", STORAGE_TYPE),
            ("targetSpaceToken", self.space_token(surl, spacetoken)),
            ("transferParameters", _protocols(protocols)),
        ]
        reply, token = self.wait(
            surl,
            self.call(surl, "srmPrepareToPut", fields),
            "srmStatusOfPutRequest",
            lambda token: [("requestToken", token)],
            timeout,
        )
        return token, self._file_statuses(surl, "PrepareToPut", reply, "SURL", surls)

    def _token_call(self, operation: str, token: str, surls: Sequence[SURL]) -> list[FileStatus]:
        surl = surls[0]
        fields: soap.Fields = [("requestToken", token), ("arrayOfSURLs", _surls(surls))]
        reply = self.call(surl, operation, fields)
        return self._file_statuses(surl, operation[3:], reply, "surl", surls)

    def put_done(self, token: str, surls: Sequence[SURL]) -> list[FileStatus]:
        return self._token_call("srmPutDone", token, surls)

    def release(self, token: str, surls: Sequence[SURL]) -> list[FileStatus]:
        return self._token_call("srmReleaseFiles", token, surls)

    def abort_files(self, token: str, surls: Sequence[SURL]) -> list[FileStatus]:
        return self._token_call("srmAbortFiles", token, surls)

    # -- tape ------------------------------------------------------------------------

    def bring_online(
        self,
        surls: Sequence[SURL],
        protocols: Sequence[str],
        *,
        pintime: int,
        timeout: int,
        wait: float | None,
        spacetoken: str = "",
    ) -> tuple[str, list[FileStatus]]:
        """``srmBringOnline``; given ``wait`` seconds, polled until nothing is queued."""
        surl = surls[0]
        fields: soap.Fields = [
            (
                "arrayOfFileRequests",
                [("requestArray", [("sourceSURL", item.wire)]) for item in surls],
            ),
            ("desiredFileStorageType", STORAGE_TYPE),
            ("desiredTotalRequestTime", timeout),
            ("desiredLifeTime", pintime),
            ("targetSpaceToken", self.space_token(surl, spacetoken)),
            ("transferParameters", _protocols(protocols)),
        ]
        reply = self.call(surl, "srmBringOnline", fields)
        token = reply.get("requestToken")
        if wait is not None:
            reply, token = self.wait(
                surl,
                reply,
                "srmStatusOfBringOnlineRequest",
                lambda token: [("requestToken", token), ("arrayOfSourceSURLs", _surls(surls))],
                wait,
            )
        return token, self._pending_or_files(surl, "BringOnline", reply, surls)

    def bring_online_status(self, token: str, surls: Sequence[SURL]) -> list[FileStatus]:
        surl = surls[0]
        reply = self.call(
            surl,
            "srmStatusOfBringOnlineRequest",
            [("requestToken", token), ("arrayOfSourceSURLs", _surls(surls))],
        )
        return self._pending_or_files(surl, "StatusOfBringOnlineRequest", reply, surls)

    def _pending_or_files(
        self, surl: SURL, short: str, reply: soap.Node, surls: Sequence[SURL]
    ) -> list[FileStatus]:
        """File statuses; a still-queued request without them queues every file."""
        status = _status(reply.child("returnStatus"))
        if status.pending and reply.child("arrayOfFileStatuses") is None:
            return [FileStatus(item.url, status) for item in surls]
        return self._file_statuses(surl, short, reply, "sourceSURL", surls)

    # -- space -------------------------------------------------------------------------

    def space_tokens(self, surl: SURL, description: str = "") -> list[str]:
        fields: soap.Fields = [("userSpaceTokenDescription", description or None)]
        reply = self.call(surl, "srmGetSpaceTokens", fields)
        status = _status(reply.child("returnStatus"))
        if not status.ok:
            raise request_error(surl, "GetSpaceTokens", status)
        return reply.strings("arrayOfSpaceTokens", "stringArray")

    def space_metadata(self, surl: SURL, tokens: Sequence[str]) -> list[Space]:
        fields: soap.Fields = [("arrayOfSpaceTokens", [("stringArray", token) for token in tokens])]
        reply = self.call(surl, "srmGetSpaceMetaData", fields)
        status = _status(reply.child("returnStatus"))
        if not status.ok:
            raise request_error(surl, "GetSpaceMetaData", status)
        return [
            Space(
                token=node.get("spaceToken"),
                status=_status(node.child("status")),
                owner=node.get("owner"),
                total=node.integer("totalSize") or 0,
                guaranteed=node.integer("guaranteedSize") or 0,
                unused=node.integer("unusedSize") or 0,
                assigned=node.integer("lifetimeAssigned") or 0,
                left=node.integer("lifetimeLeft") or 0,
                retention=node.get("retentionPolicyInfo", "retentionPolicy"),
                latency=node.get("retentionPolicyInfo", "accessLatency"),
            )
            for node in reply.array("arrayOfSpaceDetails", "spaceDataArray")
        ]
