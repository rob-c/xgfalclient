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

SRM v2.2 (OGF GFD.129) answers on two levels, and the code keeps them
apart. Every reply carries a request-level ``returnStatus``; the bulk
operations also carry one ``TReturnStatus`` per file. A request can be
``SRM_PARTIAL_SUCCESS`` with some files failed, or ``SRM_FAILURE`` with
the per-file statuses saying why, so the per-file answers win whenever
there are any (:meth:`Client._file_statuses`) and the request status is
only the fallback. Servers need not answer files in the order asked, nor
write the SURL back the way it was sent, so :func:`match` pairs them up.

Where to start reading: :meth:`Client.wait` (the polling every
asynchronous request goes through) and :meth:`Client._file_statuses`; the
operations themselves are mostly the request's fields in wire order. That
order, and the element names, are what gfal2 sends and what the capture
tests compare; keep them when editing a request.

:class:`Client` keeps no state of its own beyond the transport and the
sleep function, so it is as thread-safe as :class:`~.transport.Transport`
(whose connection pool is locked): the plugin shares one per context.
Nothing here caches answers.
"""

from __future__ import annotations

import contextlib
import errno
import os
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ...errors import ECOMM, GError
from . import soap
from .transport import SURL, Transport, ifce_error, normalise_path, parse_surl

__all__ = [
    "POLL_INITIAL",
    "POLL_MAX",
    "Client",
    "Detail",
    "FileStatus",
    "Space",
    "Staging",
    "Status",
    "empty_response",
    "file_error",
    "match",
    "request_error",
]

#: First wait between polls of an asynchronous request, in seconds; doubles
#: each time up to :data:`POLL_MAX`.
POLL_INITIAL = 0.05
#: The longest wait between two polls, in seconds; the remaining time caps
#: it further, so a poll never sleeps past the caller's deadline.
POLL_MAX = 10.0

#: What srm-ifce asks for on every get, put and bring-online: the
#: ``TFileStorageType`` (``VOLATILE``, ``DURABLE`` or ``PERMANENT``) of the
#: copy the request makes. ``PERMANENT`` means no expiry is requested.
STORAGE_TYPE = "PERMANENT"

#: Request-level codes a single-answer call reports as ``<empty response>``.
#: They are not failures by :data:`~.soap.SUCCESS`'s reckoning, but neither
#: are they an answer to a call that should have one plain success.
_EMPTY = frozenset({"SRM_TOO_MANY_RESULTS", "SRM_DONE", "SRM_PARTIAL_SUCCESS"})


@dataclass(slots=True)
class Status:
    """A ``TReturnStatus``: a ``TStatusCode`` and the server's explanation.

    The explanation is free text from the server, often empty; the error
    messages put ``<none>`` in its place, as srm-ifce does.
    """

    #: The ``TStatusCode`` name, e.g. ``SRM_SUCCESS`` or ``SRM_INVALID_PATH``.
    code: str
    explanation: str = ""

    @property
    def ok(self) -> bool:
        """Whether srm-ifce counts the code as success (:data:`~.soap.SUCCESS`)."""
        return self.code in soap.SUCCESS

    @property
    def pending(self) -> bool:
        """Whether the request is still queued or in progress, so worth polling."""
        return self.code in soap.PENDING

    @property
    def errno(self) -> int:
        """srm-ifce's ``errno`` for the code; ``0`` exactly when :attr:`ok`."""
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
    """srm-ifce's complaint about a reply that lacks what it came for.

    Used when the request status says success (or one of :data:`_EMPTY`)
    but the details, permissions or TURLs the call exists for are missing:
    ``ECOMM``, since the server broke the protocol rather than refused.
    ``code`` is the request's ``TStatusCode`` and may be empty.
    """
    return ifce_error(ECOMM, f"[SE][{short}][{code}] {surl.endpoint}: <empty response>")


def file_error(short: str, status: Status) -> GError:
    """One file's failure within a request.

    There is no endpoint in the text: srm-ifce words per-file failures
    without one, and callers wrap this in their own gfal2 prefix
    (``error on the turl request : ...``). A success-coded ``status`` (one
    that carried no TURL, say) still yields a usable error: ``EINVAL``
    rather than an ``errno`` of 0.
    """
    code = status.errno or errno.EINVAL
    return GError(f"[SE][{short}][{status.code}] {status.explanation or '<none>'}", code)


@dataclass(slots=True)
class Detail:
    """A ``TMetaDataPathDetail``: one entry of an ``srmLs`` reply.

    Absent fields keep their defaults: servers leave out whatever they do
    not track (Castor has no checksums, a short listing has no times), and
    srm-ifce reads an absent field as zero or empty, so this does too.
    """

    #: The SFN path as the server wrote it (it may differ in slashes from
    #: the one asked for; compare with :func:`~.transport.normalise_path`).
    path: str
    #: This entry's own status; absent means success.
    status: Status
    #: Bytes.
    size: int = 0
    #: The ``TFileType``, upper-cased: ``FILE``, ``DIRECTORY``, ``LINK`` or "".
    kind: str = ""
    #: ``createdAtTime`` and ``lastModificationTime``, Unix seconds; 0 if absent.
    created: int = 0
    modified: int = 0
    #: The ``TFileLocality``, upper-cased (``ONLINE``, ``NEARLINE``,
    #: ``ONLINE_AND_NEARLINE``, ``LOST``, ``NONE``, ``UNAVAILABLE``) or "".
    locality: str = ""
    #: The owner, group and other ``TPermissionMode`` as ``rwx`` bits (0-7).
    owner: int = 0
    group: int = 0
    other: int = 0
    #: The server's checksum, if it keeps one: algorithm name as the server
    #: spells it (``adler32``, ``ADLER32``...) and the value as text.
    checksum_type: str = ""
    checksum_value: str = ""
    #: A directory's entries, when the listing asked for ``numOfLevels`` >= 1.
    subpaths: list[Detail] = field(default_factory=list)

    @property
    def name(self) -> str:
        """The last path component, which is what a directory listing shows."""
        return os.path.basename(self.path.rstrip("/"))


def _detail(node: soap.Node) -> Detail:
    """A ``TMetaDataPathDetail`` element read into a :class:`Detail`, recursively.

    ``ownerPermission`` and ``groupPermission`` are structures (a user or
    group ID plus a ``mode``); ``otherPermission`` is the bare mode, hence
    the different paths. An entry without its own status is a success,
    as srm-ifce reads it.
    """
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


@dataclass(slots=True)
class FileStatus:
    """One file of a request: its SURL, status, and TURL when there is one.

    The common shape of ``TGetRequestFileStatus``, ``TPutRequestFileStatus``,
    ``TBringOnlineRequestFileStatus`` and ``TSURLReturnStatus``.
    """

    #: The SURL as the reply wrote it, or as this client wrote it when the
    #: reply named none (see :func:`match`).
    surl: str
    status: Status
    #: The ``transferURL`` of a ready get or put; "" for everything else.
    turl: str = ""


@dataclass(slots=True)
class Space:
    """A ``TMetaDataSpace`` from ``srmGetSpaceMetaData``.

    This is what the ``spacetoken.*`` extended attributes print (as gfal2's
    JSON; see ``_space_json`` in :mod:`.plugin`).
    """

    token: str
    status: Status
    owner: str = ""
    #: ``totalSize``, ``guaranteedSize`` and ``unusedSize``, in bytes.
    total: int = 0
    guaranteed: int = 0
    unused: int = 0
    #: ``lifetimeAssigned`` and ``lifetimeLeft``, in seconds (SRM writes -1
    #: for no limit; passed through as given).
    assigned: int = 0
    left: int = 0
    #: ``retentionPolicyInfo``: ``REPLICA``/``OUTPUT``/``CUSTODIAL`` and
    #: ``ONLINE``/``NEARLINE``.
    retention: str = ""
    latency: str = ""


@dataclass(frozen=True, slots=True)
class Staging:
    """The times of an ``srmBringOnline``, in seconds.

    ``pintime`` is ``desiredLifeTime``: how long the server should keep the
    recalled copy pinned on disk. ``timeout`` is ``desiredTotalRequestTime``:
    how long the server may spend on the recall. ``wait`` is this side's
    patience: how long :meth:`Client.bring_online` polls before aborting
    the request, or ``None`` to return after the first answer (gfal2's
    asynchronous bring-online, polled later with the request token).
    """

    pintime: int
    timeout: int
    wait: float | None = None


def _surls(surls: Sequence[SURL]) -> soap.Fields:
    """An ``ArrayOfAnyURI``'s items, the SURLs in their short wire form."""
    return [("urlArray", surl.wire) for surl in surls]


def _protocols(protocols: Sequence[str]) -> soap.Fields:
    """``TTransferParameters`` naming only the TURL schemes, most wanted first."""
    return [("arrayOfTransferProtocols", [("stringArray", name) for name in protocols])]


def _same(first: str, second: SURL) -> bool:
    """Whether a SURL in a reply names ``second``, however it is written.

    Servers echo SURLs back in their own spelling: the full form with the
    port and ``?SFN=``, a doubled slash, a trailing one. Host and
    normalised path decide; an unparseable echo matches nothing.
    """
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
    the request at its own position. A SURL the reply does not mention at
    all gets an ``SRM_FAILURE`` of its own, so the result always has one
    entry per SURL asked for and callers can index it.
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
    """SRM v2.2 requests over a :class:`Transport`.

    Every method takes the SURL(s) it acts on and sends to the first one's
    endpoint: callers group SURLs by endpoint first (``_by_endpoint`` in
    :mod:`._base`). ``short`` names, used in messages, are the operation
    without its ``srm`` prefix (``PrepareToGet``), as srm-ifce prints them.
    Failures are :class:`~xgfalclient.errors.GError` throughout, worded by
    :func:`request_error`, :func:`empty_response`, :func:`file_error` or
    the transport's :func:`~.transport.ifce_error`.
    """

    def __init__(
        self, transport: Transport, *, sleep: Callable[[float], None] = time.sleep
    ) -> None:
        """Send through ``transport``; ``sleep`` is the poll wait (tests pass a fake)."""
        self.transport = transport
        self.sleep = sleep

    def call(self, surl: SURL, operation: str, fields: soap.Fields) -> soap.Node:
        """One SOAP round trip to ``surl``'s endpoint; the reply's part.

        Network, TLS and SOAP-fault failures come back from the transport as
        srm-ifce's ``GError`` (``ECOMM``, ``ETIMEDOUT``, ...); the reply is
        not checked here.
        """
        return self.transport.call(surl, operation, fields)

    def simple(self, surl: SURL, operation: str, fields: soap.Fields) -> Status:
        """A call whose only answer is its ``returnStatus``, which must be success.

        Raises the request's error, or ``<empty response>`` for a code in
        :data:`_EMPTY`, which srm-ifce does not take for this kind of answer.
        """
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
        """Poll an asynchronous request until it is no longer pending.

        ``reply`` is the first answer; while its ``returnStatus`` is
        :data:`~.soap.PENDING`, ``status_operation`` is sent with the fields
        ``status_fields`` builds from the request token, waiting
        :data:`POLL_INITIAL`, doubling up to :data:`POLL_MAX`, between polls.
        Returns the first non-pending reply and the token (empty for a
        request that finished at once).

        A pending reply without a token cannot be polled and fails as a
        request error. When ``timeout`` seconds have passed the request is
        aborted (``srmAbortRequest``, so the server stops working on it) and
        ``ETIMEDOUT`` is raised in srm-ifce's ``User timeout over`` words.
        The deadline is on the monotonic clock and caps every sleep, so the
        last poll happens no later than the deadline.
        """
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
        """``srmAbortRequest``, best effort: a request given up on should not linger.

        Any failure is swallowed: this runs on paths that are already
        failing, and the original error is the one worth reporting.
        """
        with contextlib.suppress(GError):
            self.simple(surl, "srmAbortRequest", [("requestToken", token)])

    def _file_statuses(
        self, surl: SURL, short: str, reply: soap.Node, key: str, surls: Sequence[SURL]
    ) -> list[FileStatus]:
        """Per-file results; a request-level failure only when there are none.

        ``key`` is the element that holds the SURL in this operation's file
        status (``sourceSURL``, ``SURL`` or ``surl``: the WSDL is not
        consistent). With no file statuses at all, a successful request
        stands for every file and a failed one raises.
        """
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
        """``srmPing``: the version and the ``otherInfo`` pairs (``backend_type``...).

        The version is the server's ``versionInfo`` (``v2.2``); ``otherInfo``
        is free-form, and ``backend_type`` (``dCache``, ``StoRM``...) is the
        one pair the plugin reads, for ``srm.type``.
        """
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
        """``srmLs`` with ``fullDetailedList``; a queued listing is polled.

        ``levels`` is ``numOfLevels``: 0 describes each SURL itself, 1 also
        lists a directory's entries in :attr:`Detail.subpaths`. ``offset`` and
        ``count`` page a large directory and are left out when ``None``. A
        server that refuses to list a directory in one go answers
        ``SRM_TOO_MANY_RESULTS``, whose ``errno`` is ``EFBIG``: the plugin's
        cue to list in pages.

        A server that queues listings answers with a token; that is polled with
        ``srmStatusOfLsRequest`` within ``timeout`` seconds. The details
        come back in the server's order. A successful reply without any is
        ``<empty response>``.
        """
        surl = surls[0]
        fields: soap.Fields = [
            ("arrayOfSURLs", _surls(surls)),
            ("storageSystemInfo", soap.NIL),  # gSOAP sends the absent struct as nil
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
        """``srmCheckPermission``: the file's status and the caller's ``rwx`` bits.

        The status is the file's (``SRM_INVALID_PATH`` for a missing one) and
        is returned rather than raised: :meth:`~.plugin.SRMPlugin.access`
        words the failure. Only a reply with no per-file answer raises.
        """
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
        """``srmMkdir`` of one directory; a missing parent fails ``ENOENT``.

        The parents are the plugin's business (``_makedirs``); an existing
        directory fails ``EEXIST`` (``SRM_DUPLICATION_ERROR``).
        """
        self.simple(surl, "srmMkdir", [("SURL", surl.wire)])

    def rmdir(self, surl: SURL) -> Status:
        """``srmRmdir``; the status is the caller's to report, as srm-ifce leaves it."""
        reply = self.call(surl, "srmRmdir", [("SURL", surl.wire)])
        return _status(reply.child("returnStatus"))

    def mv(self, source: SURL, destination: SURL) -> None:
        """``srmMv``, sent to the source's endpoint: a rename within one SRM."""
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
        """``srmRm`` of several files at one endpoint; one status per SURL.

        The ``short`` name stays ``srmRm`` here, prefix and all: that is how
        srm-ifce words this one operation, and a test pins it.
        """
        surl = surls[0]
        reply = self.call(surl, "srmRm", [("arrayOfSURLs", _surls(surls))])
        return self._file_statuses(surl, "srmRm", reply, "surl", surls)

    # -- transfers -------------------------------------------------------------------

    def space_token(self, surl: SURL, description: str) -> str | None:
        """srm-ifce's lookup: a space token *description* to the token itself.

        gfal2's ``SPACETOKENDESC`` and ``src_spacetoken``/``dst_spacetoken``
        are descriptions (``ATLASDATADISK``); requests need the token. An
        empty description is ``None``, which leaves ``targetSpaceToken`` out
        of the request. Several matches take the first, as srm-ifce does;
        none is ``EINVAL``. One ``srmGetSpaceTokens`` per request: nothing
        is cached.
        """
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
        """``srmPrepareToGet``, polled until every TURL is ready or has failed.

        ``protocols`` are the TURL schemes acceptable, in order of
        preference; the server picks one. ``request_time`` is
        ``desiredTotalRequestTime`` (how long the server may take); ``timeout``
        is how long this side polls. Returns the request token, which
        :meth:`release` needs once the TURL has been read, and one
        :class:`FileStatus` per SURL in ``surls``' order.
        """
        surl = surls[0]
        fields: soap.Fields = [
            (
                "arrayOfFileRequests",
                [("requestArray", [("sourceSURL", item.wire)]) for item in surls],
            ),
            # srm-ifce's field order, which differs from its put's.
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
        files: Sequence[tuple[SURL, int]],
        protocols: Sequence[str],
        *,
        request_time: int,
        timeout: float,
        spacetoken: str = "",
    ) -> tuple[str, list[FileStatus]]:
        """``srmPrepareToPut``, polled until every TURL is ready or has failed.

        ``files`` pairs each target SURL with its ``expectedFileSize`` in
        bytes (0 when unknown; servers may use it to reserve room). The
        rest is as :meth:`prepare_get`. The token is the one
        :meth:`put_done` commits, or :meth:`abort_request` gives up. An
        existing file is refused by the server (``SRM_DUPLICATION_ERROR``,
        ``EEXIST``), which is how gfal2's non-overwriting copy refuses it.
        """
        surls = [item for item, _ in files]
        surl = surls[0]
        fields: soap.Fields = [
            (
                "arrayOfFileRequests",
                [
                    ("requestArray", [("targetSURL", item.wire), ("expectedFileSize", size)])
                    for item, size in files
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
        """A request token plus its SURLs, answered per file: the shape of the next three."""
        surl = surls[0]
        fields: soap.Fields = [("requestToken", token), ("arrayOfSURLs", _surls(surls))]
        reply = self.call(surl, operation, fields)
        return self._file_statuses(surl, operation[3:], reply, "surl", surls)

    def put_done(self, token: str, surls: Sequence[SURL]) -> list[FileStatus]:
        """``srmPutDone``: the bytes are written; the server makes the file visible.

        Until this the SRM treats the upload as still in progress; a put
        request that expires without it may take the file with it.
        """
        return self._token_call("srmPutDone", token, surls)

    def release(self, token: str, surls: Sequence[SURL]) -> list[FileStatus]:
        """``srmReleaseFiles``: unpin what a get or bring-online pinned."""
        return self._token_call("srmReleaseFiles", token, surls)

    def abort_files(self, token: str, surls: Sequence[SURL]) -> list[FileStatus]:
        """``srmAbortFiles``: stop some files of a request, the rest carry on."""
        return self._token_call("srmAbortFiles", token, surls)

    # -- tape ------------------------------------------------------------------------

    def bring_online(
        self,
        surls: Sequence[SURL],
        protocols: Sequence[str],
        staging: Staging,
        *,
        spacetoken: str = "",
    ) -> tuple[str, list[FileStatus]]:
        """``srmBringOnline``; given ``staging.wait`` seconds, polled until nothing is queued.

        Asks for files on tape to be recalled to disk and pinned there
        (:class:`Staging` has the times). ``protocols`` is sent as srm-ifce
        sends it, although a recall hands out no TURL. Without ``wait`` the
        first answer is returned, typically every file
        ``SRM_REQUEST_QUEUED``, with the token :meth:`bring_online_status`
        polls with.
        """
        surl = surls[0]
        fields: soap.Fields = [
            (
                "arrayOfFileRequests",
                [("requestArray", [("sourceSURL", item.wire)]) for item in surls],
            ),
            ("desiredFileStorageType", STORAGE_TYPE),
            ("desiredTotalRequestTime", staging.timeout),
            ("desiredLifeTime", staging.pintime),
            ("targetSpaceToken", self.space_token(surl, spacetoken)),
            ("transferParameters", _protocols(protocols)),
        ]
        reply = self.call(surl, "srmBringOnline", fields)
        token = reply.get("requestToken")
        if staging.wait is not None:
            reply, token = self.wait(
                surl,
                reply,
                "srmStatusOfBringOnlineRequest",
                lambda token: [("requestToken", token), ("arrayOfSourceSURLs", _surls(surls))],
                staging.wait,
            )
        return token, self._pending_or_files(surl, "BringOnline", reply, surls)

    def bring_online_status(self, token: str, surls: Sequence[SURL]) -> list[FileStatus]:
        """One ``srmStatusOfBringOnlineRequest``: where each file's recall stands.

        A single poll, not a loop: gfal2's ``bring_online_poll`` leaves the
        waiting to its caller. A file still queued reads as pending.
        """
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
        """File statuses; a still-queued request without them queues every file.

        Some servers answer a queued ``srmBringOnline`` with only the request
        status. :meth:`_file_statuses` would take that pending status for a
        failure (pending is not :attr:`Status.ok`) and raise; a recall that
        has merely not started yet is reported per file as pending instead.
        """
        status = _status(reply.child("returnStatus"))
        if status.pending and reply.child("arrayOfFileStatuses") is None:
            return [FileStatus(item.url, status) for item in surls]
        return self._file_statuses(surl, short, reply, "sourceSURL", surls)

    # -- space -------------------------------------------------------------------------

    def space_tokens(self, surl: SURL, description: str = "") -> list[str]:
        """``srmGetSpaceTokens``: the tokens of ``description``, or all the user's.

        An empty description leaves ``userSpaceTokenDescription`` out, which
        servers read as "every space this user may use".
        """
        fields: soap.Fields = [("userSpaceTokenDescription", description or None)]
        reply = self.call(surl, "srmGetSpaceTokens", fields)
        status = _status(reply.child("returnStatus"))
        if not status.ok:
            raise request_error(surl, "GetSpaceTokens", status)
        return reply.strings("arrayOfSpaceTokens", "stringArray")

    def space_metadata(self, surl: SURL, tokens: Sequence[str]) -> list[Space]:
        """``srmGetSpaceMetaData`` of ``tokens``, in the server's order.

        A failed request raises; a token the server does not know comes back
        as a :class:`Space` with a failed status, for the caller to judge.
        """
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
