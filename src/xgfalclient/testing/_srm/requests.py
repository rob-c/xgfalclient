"""The test SRM server's asynchronous requests: get, put, bring-online, and their ends.

``srmPrepareToGet``, ``srmPrepareToPut`` and ``srmBringOnline`` create a
:class:`~.model.Request` that stays queued for ``queue_polls`` status calls
(and a ``NEARLINE`` file for ``stage_polls``), each ``srmStatusOf...Request``
advancing it one poll; ``srmPutDone``, ``srmReleaseFiles``,
``srmAbortFiles`` and ``srmAbortRequest`` end it. Space tokens named in a
request are checked against the server's :attr:`spaces`.

A file's life, as SRM v2.2 describes it and the plugin's tests drive it:

* get: ``SRM_REQUEST_QUEUED`` -> ``SRM_FILE_PINNED`` (with a TURL) ->
  ``SRM_RELEASED`` after ``srmReleaseFiles``;
* put: ``SRM_REQUEST_QUEUED`` -> ``SRM_SPACE_AVAILABLE`` (with a TURL; the
  client now writes the file) -> ``SRM_SUCCESS`` after ``srmPutDone``;
* bring-online: ``SRM_REQUEST_QUEUED`` -> ``SRM_SUCCESS``, no TURL;
* any of them -> ``SRM_ABORTED`` by ``srmAbortFiles``/``srmAbortRequest``.

Time is counted in polls, not seconds: each status call advances every
waiting file of that request by one, so a test controls exactly when a file
becomes ready. Validation failures (missing file, existing put target,
``LOST`` file...) are per-file statuses in an otherwise accepted request;
the request's own status folds them (``SRM_FAILURE`` when every file failed).
"""

from __future__ import annotations

from collections.abc import Callable

from ...plugins.srm import soap
from .base import _OperationsBase
from .model import _OPEN_PUT, Fields, File, Request, _aggregate, _only, _status


class _RequestOps(_OperationsBase):
    """Asynchronous transfer and staging requests."""

    def _file_status(self, file: File, key: str) -> Fields:
        """One file's status entry; ``key`` names its SURL field.

        The field is ``sourceSURL`` in get and bring-online replies and
        ``SURL`` in put replies, per the SRM v2.2 WSDL. Size and TURL are
        omitted until known.
        """
        return [
            (key, file.surl),
            ("status", _status(file.code, file.explanation)),
            ("fileSize", file.size),
            ("transferURL", file.turl or None),
        ]

    def _request_reply(self, request: Request, key: str) -> Fields:
        """The reply to a prepare or status call: overall status, token, file statuses.

        A pending request reports ``SRM_REQUEST_QUEUED`` until it has been
        polled once and ``SRM_REQUEST_INPROGRESS`` after, so a client sees
        both states.
        """
        code = _aggregate(file.code for file in request.files)
        if code in soap.PENDING and not request.started:
            code = "SRM_REQUEST_QUEUED"
        return [
            ("returnStatus", _status(code)),
            ("requestToken", request.token),
            (
                "arrayOfFileStatuses",
                [("statusArray", self._file_status(file, key)) for file in request.files],
            ),
        ]

    def _advance(self, request: Request) -> None:
        """One status poll's worth of progress."""
        request.started = True
        for file in request.files:
            if file.wait > 0:
                file.wait -= 1
                if file.wait == 0:
                    if file.stage:
                        self.set_locality(file.path, "ONLINE_AND_NEARLINE")
                    self._ready(request, file)

    def _ready(self, request: Request, file: File) -> None:
        """Make ``file`` ready: pinned (get), space available (put) or online (bring-online).

        Gets and puts get a TURL: the chosen protocol's prefix plus the SRM
        path, so with the default ``file://`` mapping it points straight at
        the file under the root.
        """
        if request.kind == "bol":
            file.code = "SRM_SUCCESS"
            return
        file.code = "SRM_FILE_PINNED" if request.kind == "get" else "SRM_SPACE_AVAILABLE"
        file.turl = self.protocols[request.protocol] + file.path

    def _new_request(
        self, kind: str, part: soap.Node, key: str, check: Callable[[str], tuple[str, str]]
    ) -> Request | Fields:
        """Create and register a request from a prepare/bring-online call.

        Returns the :class:`~.model.Request`, or a whole failure reply when
        the request itself is unacceptable: an unknown ``targetSpaceToken``
        (``SRM_INVALID_REQUEST``) or, for get and put, none of the client's
        transfer protocols served (``SRM_NOT_SUPPORTED``; the first one
        offered that the server's ``protocols`` map has is chosen). Each file
        request names its SURL under ``key``; ``check`` validates its path
        and returns ``("", "")`` or a failure code. A valid file waits
        ``queue_polls`` polls - or ``stage_polls`` if it must be staged from
        ``NEARLINE``, whichever is longer - and is ready at once if both are 0.
        """
        holder = part.child("transferParameters", "arrayOfTransferProtocols")
        protocols = [node.text for node in holder.children("stringArray")] if holder else []
        spacetoken = part.get("targetSpaceToken")
        if spacetoken and spacetoken not in self.spaces:
            return _only("SRM_INVALID_REQUEST", f"Unknown space token {spacetoken}")
        chosen = next((name for name in protocols if name in self.protocols), "")
        if kind != "bol" and not chosen:
            return _only("SRM_NOT_SUPPORTED", "No requested transfer protocol is supported")
        request = Request(self._token(), kind, protocol=chosen, spacetoken=spacetoken)
        self.requests[request.token] = request
        for node in part.array("arrayOfFileRequests", "requestArray"):
            request.files.append(self._file_request(request, node, key, check))
        return request

    def _file_request(
        self, request: Request, node: soap.Node, key: str, check: Callable[[str], tuple[str, str]]
    ) -> File:
        """One file of a new ``request``: failed by ``check``, or queued (or ready) to move.

        See :meth:`_new_request` for how long a valid file waits.
        """
        kind = request.kind
        surl = node.get(key)
        path = self._path(surl)
        file = File(surl, path or "", "SRM_REQUEST_QUEUED")
        if kind == "put":
            file.size = node.integer("expectedFileSize")
        code, explanation = ("SRM_INVALID_PATH", "Invalid SURL") if path is None else check(path)
        if code:
            file.code, file.explanation = code, explanation
        else:
            file.stage = kind != "put" and self.locality(file.path) == "NEARLINE"
            file.wait = max(self.queue_polls, self.stage_polls if file.stage else 0)
            if file.wait == 0:
                self._ready(request, file)
        return file

    # -- transfers -------------------------------------------------------------------

    def _check_get(self, path: str) -> tuple[str, str]:
        """Can ``path`` be read? A regular file that is not ``LOST`` or ``UNAVAILABLE``."""
        local = self.local(path)
        if not local.exists():
            return "SRM_INVALID_PATH", "No such file or directory"
        if local.is_dir():
            return "SRM_INVALID_PATH", "Is a directory"
        locality = self.locality(path)
        if locality == "LOST":
            return "SRM_FILE_LOST", "The file is lost"
        if locality == "UNAVAILABLE":
            return "SRM_FILE_UNAVAILABLE", "The file is unavailable"
        return "", ""

    def _check_put(self, path: str) -> tuple[str, str]:
        """Can ``path`` be written? It must not exist, its parent must, and no open put has it.

        There is no overwrite flag: a put over an existing file is
        ``SRM_DUPLICATION_ERROR``, so a client that wants to overwrite must
        ``srmRm`` first. A second put of a path still being
        written is ``SRM_FILE_BUSY``.
        """
        local = self.local(path)
        if local.exists():
            return "SRM_DUPLICATION_ERROR", "The file exists"
        if not local.parent.is_dir():
            return "SRM_INVALID_PATH", "Parent directory does not exist"
        for request in self.requests.values():
            for file in request.files:
                if request.kind == "put" and file.path == path and file.code in _OPEN_PUT:
                    return "SRM_FILE_BUSY", "The file is being written"
        return "", ""

    def _srmPrepareToGet(self, part: soap.Node) -> Fields:
        """``srmPrepareToGet``: pin each file for reading and return its TURL when ready."""
        request = self._new_request("get", part, "sourceSURL", self._check_get)
        if isinstance(request, Request):
            return self._request_reply(request, "sourceSURL")
        return request

    def _srmPrepareToPut(self, part: soap.Node) -> Fields:
        """``srmPrepareToPut``: reserve each target and return the TURL to write to."""
        request = self._new_request("put", part, "targetSURL", self._check_put)
        if isinstance(request, Request):
            return self._request_reply(request, "SURL")
        return request

    def _srmBringOnline(self, part: soap.Node) -> Fields:
        """``srmBringOnline``: stage each file to disk; no protocol or TURL is involved."""
        request = self._new_request("bol", part, "sourceSURL", self._check_get)
        if isinstance(request, Request):
            return self._request_reply(request, "sourceSURL")
        return request

    def _poll(self, part: soap.Node, kind: str, key: str) -> Fields:
        """A ``srmStatusOf...Request``: advance the request one poll, then report it.

        The token must name a request of ``kind``; otherwise
        ``SRM_INVALID_REQUEST``. The optional SURL array that narrows a
        status call is ignored: every file of the request is reported.
        """
        request = self.requests.get(part.get("requestToken"))
        if request is None or request.kind != kind:
            return _only("SRM_INVALID_REQUEST", "Unknown request token")
        self._advance(request)
        return self._request_reply(request, key)

    def _srmStatusOfGetRequest(self, part: soap.Node) -> Fields:
        """``srmStatusOfGetRequest``: poll a get."""
        return self._poll(part, "get", "sourceSURL")

    def _srmStatusOfPutRequest(self, part: soap.Node) -> Fields:
        """``srmStatusOfPutRequest``: poll a put."""
        return self._poll(part, "put", "SURL")

    def _srmStatusOfBringOnlineRequest(self, part: soap.Node) -> Fields:
        """``srmStatusOfBringOnlineRequest``: poll a bring-online."""
        return self._poll(part, "bol", "sourceSURL")

    def _in_request(
        self, part: soap.Node, action: Callable[[Request | None, str, File | None], tuple[str, str]]
    ) -> Fields:
        """Apply ``action`` to each SURL of a (possibly token-less) request.

        ``action(request, path, file)`` gets the request (``None`` when no
        token was sent - ``srmReleaseFiles`` allows that) and the file of
        that request with the SURL's path (``None`` if it has none). A token
        that names no request fails the whole call.
        """
        token = part.get("requestToken")
        request = self.requests.get(token) if token else None
        if token and request is None:
            return _only("SRM_INVALID_REQUEST", "Unknown request token")

        def each(surl: str) -> tuple[str, str]:
            """Resolve one SURL to its file in the request and apply ``action``."""
            path = self._path(surl)
            if path is None:
                return "SRM_INVALID_PATH", "Invalid SURL"
            files = request.files if request is not None else []
            return action(request, path, next((f for f in files if f.path == path), None))

        return self._surl_statuses(part, each)

    def _put_done(self, request: Request | None, path: str, file: File | None) -> tuple[str, str]:
        """``srmPutDone`` for one file: commit it if it was written.

        The file must belong to a put request and be ``SRM_SPACE_AVAILABLE``;
        if nothing was written to the TURL the put fails for good
        (``SRM_FAILURE``).
        """
        if request is None or request.kind != "put" or file is None:
            return "SRM_INVALID_PATH", "The SURL is not part of this request"
        if file.code != "SRM_SPACE_AVAILABLE":
            return "SRM_FAILURE", f"The file is in state {file.code}"
        if not self.local(path).is_file():
            file.code = "SRM_FAILURE"
            return "SRM_INVALID_PATH", "The file was never written"
        file.code = "SRM_SUCCESS"
        return "SRM_SUCCESS", ""

    def _release(self, request: Request | None, path: str, file: File | None) -> tuple[str, str]:
        """``srmReleaseFiles`` for one file: unpin it, recording the path in ``released``.

        Without a token any existing path may be released (the client
        may release by SURL alone in SRM v2.2); with one it must be part of
        that request, whose file becomes ``SRM_RELEASED``.
        """
        if not self.local(path).exists():
            return "SRM_INVALID_PATH", "No such file or directory"
        if request is not None:
            if file is None:
                return "SRM_INVALID_PATH", "The SURL is not part of this request"
            file.code = "SRM_RELEASED"
        self.released.append(path)
        return "SRM_SUCCESS", ""

    def _abort(self, request: Request | None, path: str, file: File | None) -> tuple[str, str]:
        """``srmAbortFiles`` for one file: abort it, deleting a partially written put.

        A put that was still open (queued or space available) loses whatever
        was written to its TURL; a committed one keeps its file.
        """
        if request is None or file is None:
            return "SRM_INVALID_PATH", "The SURL is not part of this request"
        if request.kind == "put" and file.code in _OPEN_PUT:
            local = self.local(path)
            if local.is_file():
                local.unlink()
        file.code, file.wait, file.turl = "SRM_ABORTED", 0, ""
        return "SRM_SUCCESS", ""

    def _srmPutDone(self, part: soap.Node) -> Fields:
        """``srmPutDone``: commit the named files of a put."""
        return self._in_request(part, self._put_done)

    def _srmReleaseFiles(self, part: soap.Node) -> Fields:
        """``srmReleaseFiles``: unpin the named files, of a request or by SURL alone."""
        return self._in_request(part, self._release)

    def _srmAbortFiles(self, part: soap.Node) -> Fields:
        """``srmAbortFiles``: abort the named files of a request."""
        return self._in_request(part, self._abort)

    def _srmAbortRequest(self, part: soap.Node) -> Fields:
        """``srmAbortRequest``: abort every file of the request that is still waiting.

        Files already ready (pinned, space available, done) keep their state
        and, unlike :meth:`_abort`, no partially written put is deleted.
        """
        request = self.requests.get(part.get("requestToken"))
        if request is None:
            return _only("SRM_INVALID_REQUEST", "Unknown request token")
        for file in request.files:
            if file.wait:
                file.code, file.wait = "SRM_ABORTED", 0
        return _only("SRM_SUCCESS")
