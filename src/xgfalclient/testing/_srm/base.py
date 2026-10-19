"""What every group of the test SRM server's operations shares.

:class:`_OperationsBase` is the base of the operation mixins
(:mod:`.namespace`, :mod:`.requests`, :mod:`.space`). It declares the
server state they read - set by :class:`~xgfalclient.testing.srm.SRMServer`'s
constructor, which is where each attribute is documented - and holds the
helpers more than one group uses: SURL to path, request tokens, and a
per-SURL status array.

Each operation is a method ``_<srmOperation>(part) -> Fields``: ``part``
is the parsed ``<operation>Request`` element, the return value is the
content of ``<operation>Response`` as ``(name, value)`` pairs (a ``None``
value is omitted from the XML). Operations run under the server's lock, so
they read and change state freely. Failures are answered, never raised:
an SRM error is a ``TStatusCode`` in ``returnStatus`` with HTTP 200, as
SRM v2.2 has it; SOAP faults are for requests that cannot be understood.
"""

from __future__ import annotations

import itertools
import posixpath
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from ...errors import GError
from ...plugins.srm import soap
from ...plugins.srm.transport import parse_surl
from .model import Fields, Request, Space, _aggregate, _status


class _OperationsBase:
    """The server state and helpers the operation mixins share; see ``SRMServer``."""

    protocols: dict[str, str]
    queue_polls: int
    stage_polls: int
    ls_queue_polls: int
    max_ls: int
    checksum_type: str | None
    backend: str
    requests: dict[str, Request]
    spaces: dict[str, Space]
    released: list[str]
    _tokens: itertools.count[int]

    if TYPE_CHECKING:  # defined by SRMServer, beside the rest of its public API

        def local(self, path: str) -> Path:
            """:meth:`SRMServer.local <xgfalclient.testing.srm.SRMServer.local>`."""

        def locality(self, path: str) -> str:
            """:meth:`SRMServer.locality <xgfalclient.testing.srm.SRMServer.locality>`."""

        def set_locality(self, path: str, locality: str) -> None:
            """:meth:`SRMServer.set_locality <xgfalclient.testing.srm.SRMServer.set_locality>`."""

    @staticmethod
    def _path(surl: str) -> str | None:
        """The normalised SRM path of a SURL (short or ``?SFN=``); ``None`` if it is not one.

        Uses the client's own SURL parser, so the two agree on what a SURL is.
        """
        try:
            return posixpath.normpath(parse_surl(surl).path)
        except GError:
            return None

    def _existing(self, surl: str) -> tuple[str | None, Path]:
        """``(path, local)`` of a SURL; ``path`` is ``None`` if it does not exist."""
        path = self._path(surl)
        local = self.local(path or "/")
        return (path if path is not None and local.exists() else None), local

    def _token(self) -> str:
        """A new request token, unique for this server's lifetime."""
        return f"xgfal-{next(self._tokens)}"

    def _surl_statuses(self, part: soap.Node, action: Callable[[str], tuple[str, str]]) -> Fields:
        """Apply ``action`` to each SURL of ``arrayOfSURLs``; a TSURLReturnStatus each.

        ``action`` returns ``(code, explanation)``. The request's
        ``returnStatus`` folds the per-SURL codes (see
        :func:`~.model._aggregate`), so one bad SURL out of several makes it
        ``SRM_PARTIAL_SUCCESS`` - the shape ``srmRm``, ``srmPutDone``,
        ``srmReleaseFiles`` and ``srmAbortFiles`` all answer with.
        """
        statuses: Fields = []
        codes = []
        for surl in part.strings("arrayOfSURLs", "urlArray"):
            code, explanation = action(surl)
            codes.append(code)
            statuses.append(
                ("statusArray", [("surl", surl), ("status", _status(code, explanation))])
            )
        return [("returnStatus", _status(_aggregate(codes))), ("arrayOfFileStatuses", statuses)]
