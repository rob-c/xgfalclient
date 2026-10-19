"""The test SRM server's data model: injected replies, spaces and asynchronous requests.

:class:`Reply` (and :data:`DROP`) are what a test injects; :class:`Space`,
:class:`File` and :class:`Request` are the state the operations keep and a
test inspects (``srm.requests``, ``srm.spaces``). The functions build the
``TReturnStatus`` shapes every operation answers with and fold per-file codes
into a request's code.

``TStatusCode`` values are passed around as their SRM v2.2 names
(``"SRM_SUCCESS"``, ``"SRM_FILE_PINNED"``...); :mod:`xgfalclient.plugins.srm.soap`
groups them (``SUCCESS``, ``PENDING``) and maps them to errnos on the client side.
"""

from __future__ import annotations

import zlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from ...plugins.srm import soap

#: An element's content as ordered ``(name, value)`` pairs; a value is text,
#: a number, a bool, nested ``Fields``, or ``None`` (left out).
Fields = soap.Fields


@dataclass
class Reply:
    """An injected answer: ``body`` with HTTP ``status``; ``close`` drops the line."""

    body: bytes = b""
    status: int = 200
    close: bool = False


#: Inject this to have the server hang up instead of answering.
DROP = Reply(close=True)

#: What :meth:`~xgfalclient.testing.srm.SRMServer.inject` takes: a SOAP body
#: (sent with HTTP 200), a :class:`Reply`, or a callable that sees the
#: request part and returns one of those or ``None`` for the normal answer.
Injection = bytes | Reply | Callable[[soap.Node], bytes | Reply | None]


@dataclass
class Space:
    """A space reservation, as ``srmGetSpaceMetaData`` describes it.

    Sizes are bytes (1 TiB total and guaranteed, half of it unused by
    default); ``lifetime`` is seconds, ``-1`` meaning infinite as in SRM.
    ``retention`` and ``latency`` are ``TRetentionPolicy`` and
    ``TAccessLatency`` names. ``description`` is what
    ``srmGetSpaceTokens`` matches a user's token description against.
    """

    description: str
    total: int = 1 << 40
    guaranteed: int = 1 << 40
    unused: int = 1 << 39
    lifetime: int = -1
    retention: str = "REPLICA"
    latency: str = "ONLINE"
    owner: str = "xgfal"


@dataclass
class File:
    """One file of an asynchronous request.

    ``surl`` is as the client sent it, ``path`` the SRM path it names
    (empty if it did not parse). ``code``/``explanation`` are its current
    ``TStatusCode``; ``turl`` is set once it is ready (pinned or space
    available). ``size`` is the put's ``expectedFileSize``. ``wait`` counts
    the status polls still to go before it is ready, and ``stage`` marks a
    ``NEARLINE`` file that becomes ``ONLINE_AND_NEARLINE`` when it is.
    """

    surl: str
    path: str
    code: str
    explanation: str = ""
    turl: str = ""
    size: int | None = None
    wait: int = 0
    stage: bool = False


@dataclass
class Request:
    """An asynchronous request, by token; tests inspect these.

    ``kind`` is ``get``, ``put``, ``bol`` (bring-online) or ``ls``.
    ``protocol`` is the TURL protocol chosen from the client's list,
    ``spacetoken`` the ``targetSpaceToken`` it named. ``started`` turns true
    at the first status poll: before it, a pending request reports
    ``SRM_REQUEST_QUEUED``, after it ``SRM_REQUEST_INPROGRESS``.
    """

    token: str
    kind: str
    files: list[File] = field(default_factory=list)
    protocol: str = ""
    spacetoken: str = ""
    started: bool = False
    #: For a queued ``srmLs``: the reply it will give once it is done.
    listing: Fields = field(default_factory=list)


def _status(code: str, explanation: str = "") -> Fields:
    """A ``TReturnStatus``; an empty explanation is left out, as servers do."""
    return [("statusCode", code), ("explanation", explanation or None)]


def _only(code: str, explanation: str = "") -> Fields:
    """A response holding just ``returnStatus``: every request-level failure."""
    return [("returnStatus", _status(code, explanation))]


def _aggregate(codes: Iterable[str]) -> str:
    """A request's status from its files': all good, some good, or none.

    Any file still pending makes the request ``SRM_REQUEST_INPROGRESS``
    (the caller turns that into ``QUEUED`` before the first poll). An empty
    request counts as all good.
    """
    codes = list(codes)
    if any(code in soap.PENDING for code in codes):
        return "SRM_REQUEST_INPROGRESS"
    good = sum(code in soap.SUCCESS for code in codes)
    if good == len(codes):
        return "SRM_SUCCESS"
    return "SRM_PARTIAL_SUCCESS" if good else "SRM_FAILURE"


def _adler32(path: Path) -> str:
    """The file's ADLER32 as eight hex digits, read in 1 MiB chunks."""
    value = 1
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value = zlib.adler32(chunk, value)
    return f"{value:08x}"


#: Put states in which a file is still being written: a second put of the
#: same path is ``SRM_FILE_BUSY`` and an abort deletes the partial file.
_OPEN_PUT = frozenset({"SRM_SPACE_AVAILABLE", "SRM_REQUEST_QUEUED"})
