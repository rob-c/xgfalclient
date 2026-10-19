"""The test SRM server's namespace operations.

``srmPing``, ``srmLs`` (levels, ``offset``/``count`` paging,
``SRM_TOO_MANY_RESULTS``, and the queued form polled with
``srmStatusOfLsRequest``), ``srmMkdir``, ``srmRmdir``, ``srmRm``,
``srmMv``, ``srmSetPermission`` and ``srmCheckPermission``, each a method
named ``_<operation>`` that the server's dispatch table finds by name.

Everything acts on the real directory under the server's root, so a test
can set up or check state with ordinary file operations. Owners and groups
are always ``xgfal``; permissions are the file's real mode bits, mapped to
``TPermissionMode`` names. Failures are ``TStatusCode`` values the client
maps to errnos: ``SRM_INVALID_PATH`` for missing paths and wrong types,
``SRM_DUPLICATION_ERROR`` for existing targets.
"""

from __future__ import annotations

import os
import posixpath
import shutil
import stat as _stat

from ...plugins.srm import soap
from .base import _OperationsBase
from .model import Fields, File, Request, _adler32, _aggregate, _only, _status


class _NamespaceOps(_OperationsBase):
    """Namespace operations, and the ``srmLs`` detail they are built on."""

    def _detail(self, path: str, levels: int, offset: int, count: int) -> tuple[Fields, str]:
        """``srmLs``'s ``TMetaDataPathDetail`` for ``path``, and its status code.

        A missing path is a detail holding only ``SRM_INVALID_PATH``. The
        retention policy and access latency follow the locality (anything
        ``NEARLINE`` is on tape, so ``CUSTODIAL``). A file gets the server's
        checksum, computed now. A directory listed with ``levels`` > 0
        gets ``arrayOfSubPaths``: its sorted entries, ``offset`` and
        ``count`` applied (``count`` 0 means all), each at one level only -
        recursion is never deeper than one, which is all clients ask for.
        Asking for more than ``max_ls`` entries, or for all of a directory
        that has more, replaces the status with ``SRM_TOO_MANY_RESULTS``
        so the client must page.
        """
        local = self.local(path)
        try:
            info = local.stat()
        except OSError:
            missing = _status("SRM_INVALID_PATH", "No such file or directory")
            return [("path", path), ("status", missing)], "SRM_INVALID_PATH"
        is_dir = _stat.S_ISDIR(info.st_mode)
        mode = info.st_mode
        locality = self.locality(path)
        fields: Fields = [
            ("path", path),
            ("status", _status("SRM_SUCCESS")),
            ("size", 0 if is_dir else info.st_size),
            ("createdAtTime", soap.format_time(info.st_ctime)),
            ("lastModificationTime", soap.format_time(info.st_mtime)),
            ("fileStorageType", "PERMANENT"),
            (
                "retentionPolicyInfo",
                [
                    ("retentionPolicy", "CUSTODIAL" if "NEARLINE" in locality else "REPLICA"),
                    ("accessLatency", "NEARLINE" if locality == "NEARLINE" else "ONLINE"),
                ],
            ),
            ("fileLocality", locality),
            ("type", "DIRECTORY" if is_dir else "FILE"),
            # TPermissionMode per rwx triplet: owner bits 8-6, group 5-3, other 2-0.
            ("ownerPermission", [("userID", "xgfal"), ("mode", soap.permission(mode >> 6))]),
            ("groupPermission", [("groupID", "xgfal"), ("mode", soap.permission(mode >> 3))]),
            ("otherPermission", soap.permission(mode)),
        ]
        if not is_dir and self.checksum_type:
            fields.append(("checkSumType", self.checksum_type))
            fields.append(("checkSumValue", _adler32(local)))
        # A file, or a directory asked about itself only (numOfLevels 0).
        if not (is_dir and levels > 0):
            return fields, "SRM_SUCCESS"
        names = sorted(os.listdir(local))
        if count > self.max_ls or (not count and len(names) > self.max_ls):
            # The directory's own detail stays, but its status says to page.
            fields[1] = ("status", _status("SRM_TOO_MANY_RESULTS", "Too many results"))
            return fields, "SRM_TOO_MANY_RESULTS"
        window = names[offset : offset + count] if count else names[offset:]
        # Children are listed at level 0: their own detail, never their entries.
        children = [
            ("pathDetailArray", self._detail(posixpath.join(path, name), 0, 0, 0)[0])
            for name in window
        ]
        fields.append(("arrayOfSubPaths", children))
        return fields, "SRM_SUCCESS"

    # -- namespace operations --------------------------------------------------------

    def _srmPing(self, part: soap.Node) -> Fields:
        """``srmPing``: version ``v2.2`` and the ``backend_type``/``backend_version`` pairs.

        No ``returnStatus``: ``srmPingResponse`` has none in SRM v2.2.
        """
        return [
            ("versionInfo", "v2.2"),
            (
                "otherInfo",
                [
                    ("extraInfoArray", [("key", "backend_type"), ("value", self.backend)]),
                    ("extraInfoArray", [("key", "backend_version"), ("value", "1.0")]),
                ],
            ),
        ]

    def _srmLs(self, part: soap.Node) -> Fields:
        """``srmLs``: a detail per SURL, synchronously or as a queued request.

        ``numOfLevels`` defaults to 1, as in SRM v2.2. The request's status
        folds the per-path codes, except that ``SRM_TOO_MANY_RESULTS``
        anywhere wins, since that is what tells the client to page. With
        ``ls_queue_polls`` the full answer is computed now but held back:
        the reply is ``SRM_REQUEST_QUEUED`` with a token, and
        :meth:`_srmStatusOfLsRequest` releases it - so changes made to the
        directory in between do not show, a simplification.
        """
        levels = part.integer("numOfLevels")
        levels = 1 if levels is None else levels
        offset = part.integer("offset") or 0
        count = part.integer("count") or 0
        details: Fields = []
        codes = []
        for surl in part.strings("arrayOfSURLs", "urlArray"):
            path = self._path(surl)
            if path is None:
                detail = [("path", surl), ("status", _status("SRM_INVALID_PATH", "Invalid SURL"))]
                code = "SRM_INVALID_PATH"
            else:
                detail, code = self._detail(path, levels, offset, count)
            details.append(("pathDetailArray", detail))
            codes.append(code)
        code = _aggregate(codes)
        if "SRM_TOO_MANY_RESULTS" in codes:
            code = "SRM_TOO_MANY_RESULTS"
        reply = [("returnStatus", _status(code)), ("details", details)]
        if not self.ls_queue_polls:
            return reply
        request = Request(self._token(), "ls", listing=reply)
        request.files.append(File("", "", "SRM_REQUEST_QUEUED", wait=self.ls_queue_polls))
        self.requests[request.token] = request
        return [("returnStatus", _status("SRM_REQUEST_QUEUED")), ("requestToken", request.token)]

    def _srmStatusOfLsRequest(self, part: soap.Node) -> Fields:
        """Poll a queued ``srmLs``: ``INPROGRESS`` until its polls run out, then the listing.

        The request stays in the table afterwards, so later polls keep
        returning the listing. An unknown token, or a token for another
        kind of request, is ``SRM_INVALID_REQUEST``.
        """
        request = self.requests.get(part.get("requestToken"))
        if request is None or request.kind != "ls":
            return _only("SRM_INVALID_REQUEST", "Unknown request token")
        # A queued ls is a request with one placeholder file counting the polls.
        pending = request.files[0]
        pending.wait -= 1
        if pending.wait > 0:
            return _only("SRM_REQUEST_INPROGRESS")
        return request.listing

    def _srmMkdir(self, part: soap.Node) -> Fields:
        """``srmMkdir``: one level; the parent must exist (``mkdir -p`` is the client's job)."""
        path = self._path(part.get("SURL"))
        local = self.local(path or "/")
        if path is None or not local.parent.is_dir():
            return _only("SRM_INVALID_PATH", "Parent directory does not exist")
        if local.exists():
            return _only("SRM_DUPLICATION_ERROR", "Path exists")
        local.mkdir()
        return _only("SRM_SUCCESS")

    def _srmRmdir(self, part: soap.Node) -> Fields:
        """``srmRmdir``: an empty directory, or any directory with ``recursive`` true.

        A non-empty directory without ``recursive`` is
        ``SRM_NON_EMPTY_DIRECTORY``; a file is ``SRM_INVALID_PATH``.
        """
        path, local = self._existing(part.get("SURL"))
        if path is None:
            return _only("SRM_INVALID_PATH", "No such file or directory")
        if not local.is_dir():
            return _only("SRM_INVALID_PATH", "Not a directory")
        if part.boolean("recursive"):
            shutil.rmtree(local)
        elif any(local.iterdir()):
            return _only("SRM_NON_EMPTY_DIRECTORY", "Directory is not empty")
        else:
            local.rmdir()
        return _only("SRM_SUCCESS")

    def _rm(self, surl: str) -> tuple[str, str]:
        """Delete one file for ``srmRm``; a directory is refused (that is ``srmRmdir``)."""
        path, local = self._existing(surl)
        if path is None:
            return "SRM_INVALID_PATH", "No such file or directory"
        if local.is_dir():
            return "SRM_INVALID_PATH", "Not a file"
        local.unlink()
        return "SRM_SUCCESS", ""

    def _srmRm(self, part: soap.Node) -> Fields:
        """``srmRm``: delete each SURL, a status per SURL."""
        return self._surl_statuses(part, self._rm)

    def _srmMv(self, part: soap.Node) -> Fields:
        """``srmMv``: rename ``fromSURL`` to ``toSURL``, never over an existing target.

        Unlike POSIX ``rename``, an existing destination is
        ``SRM_DUPLICATION_ERROR`` rather than replaced.
        """
        source, local = self._existing(part.get("fromSURL"))
        target = self._path(part.get("toSURL"))
        if source is None or target is None:
            return _only("SRM_INVALID_PATH", "No such file or directory")
        destination = self.local(target)
        if destination.exists():
            return _only("SRM_DUPLICATION_ERROR", "Destination exists")
        if not destination.parent.is_dir():
            return _only("SRM_INVALID_PATH", "Destination parent does not exist")
        os.rename(local, destination)
        return _only("SRM_SUCCESS")

    def _srmSetPermission(self, part: soap.Node) -> Fields:
        """``srmSetPermission``: set owner, (first) group and other bits; absent ones are kept.

        Only the ``CHANGE``-like effect is modelled: each of the three modes
        the request names replaces those bits, whatever ``permissionType``
        says, and the group mode is read from the first group entry only.
        A mode may be a name (``RW``) or, as gfal2 sends it, an ordinal.
        """
        path, local = self._existing(part.get("SURL"))
        if path is None:
            return _only("SRM_INVALID_PATH", "No such file or directory")
        current = local.stat().st_mode
        wanted = (
            part.get("ownerPermission"),
            part.get("arrayOfGroupPermissions", "groupPermissionArray", "mode"),
            part.get("otherPermission"),
        )
        # Rebuild the mode triplet by triplet; only the rwx bits are kept, so
        # setuid/setgid/sticky are cleared by any srmSetPermission.
        mode = 0
        for shift, text in zip((6, 3, 0), wanted, strict=False):
            bits = soap.permission_bits(text) if text else (current >> shift) & 7
            mode |= bits << shift
        os.chmod(local, mode)
        return _only("SRM_SUCCESS")

    def _srmCheckPermission(self, part: soap.Node) -> Fields:
        """``srmCheckPermission``: the caller's rights on each SURL.

        Every caller is the owner here, so the answer is the owner bits.
        """
        results: Fields = []
        codes = []
        for surl in part.strings("arrayOfSURLs", "urlArray"):
            path, local = self._existing(surl)
            if path is None:
                missing = _status("SRM_INVALID_PATH", "No such file or directory")
                codes.append("SRM_INVALID_PATH")
                results.append(("surlPermissionArray", [("surl", surl), ("status", missing)]))
                continue
            bits = (local.stat().st_mode >> 6) & 7
            codes.append("SRM_SUCCESS")
            entry = [
                ("surl", surl),
                ("status", _status("SRM_SUCCESS")),
                ("permission", soap.permission(bits)),
            ]
            results.append(("surlPermissionArray", entry))
        return [("returnStatus", _status(_aggregate(codes))), ("arrayOfPermissions", results)]
