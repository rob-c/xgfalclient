"""SOAP 1.1 for SRM v2.2: envelopes out, trees in, ``TStatusCode`` to ``errno``.

SRM v2.2 is an rpc/encoded web service. A call is an element named after
the operation in the ``http://srm.lbl.gov/StorageResourceManager`` namespace
holding a single, unqualified part named ``<operation>Request``; the reply
mirrors it with ``<operation>Response``. Everything below the part is
unqualified too. That is what gSOAP generates for srm-ifce (gfal2's client)
and for StoRM, and what dCache's Axis accepts and answers.

Axis may answer with SOAP-encoding multi-references (``<x href="#id0"/>``
pointing at a ``<multiRef id="id0">`` elsewhere in the body) and with
``xsi:nil`` for absent values, so the reader follows both. Documents carrying
a DTD are refused outright: SOAP forbids them, and refusing them rules out
entity-expansion attacks from a hostile endpoint.

This module is shared by both ends: the client (:mod:`.client`) writes
requests with :func:`request` and reads replies with :func:`parse`, and the
test server (:mod:`xgfalclient.testing.srm`) does the reverse with
:func:`response` and :func:`fault`. It knows nothing of particular
operations; the element names of each request live with the operation in
:mod:`.client`. What a maintainer must not break: the envelope head is
compared byte for byte with gfal2's captures, and the reader must keep
tolerating both gSOAP's plain trees and Axis's multi-references.
"""

from __future__ import annotations

import calendar
import errno
import re
import time
from collections.abc import Iterator
from typing import Any
from xml.etree import ElementTree
from xml.sax.saxutils import escape

from xrdcore.safexml import UnsafeXML, fromstring

from ...errors import ECOMM

__all__ = [
    "EBADR",
    "ETIME",
    "NIL",
    "PENDING",
    "PERMISSION_MODES",
    "SOAP_ENV_NS",
    "SRM_NS",
    "SUCCESS",
    "Fields",
    "Node",
    "SOAPError",
    "SOAPFault",
    "errno_for_status",
    "fault",
    "format_time",
    "parse",
    "parse_time",
    "permission",
    "permission_bits",
    "request",
    "response",
]

#: The SRM v2.2 WSDL's target namespace (the operation elements only).
SRM_NS = "http://srm.lbl.gov/StorageResourceManager"
SOAP_ENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
SOAP_ENC_NS = "http://schemas.xmlsoap.org/soap/encoding/"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
XSD_NS = "http://www.w3.org/2001/XMLSchema"

#: A structure to serialise: ``[(element name, value), ...]`` where a value
#: is text, a number, a boolean, ``None`` (left out) or another such list.
Fields = list[tuple[str, Any]]

#: The head of every envelope, byte for byte what srm-ifce's gSOAP writes.
_HEAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    f'<SOAP-ENV:Envelope xmlns:SOAP-ENV="{SOAP_ENV_NS}" xmlns:SOAP-ENC="{SOAP_ENC_NS}" '
    f'xmlns:xsi="{XSI_NS}" xmlns:xsd="{XSD_NS}" xmlns:srm2="{SRM_NS}">'
    f'<SOAP-ENV:Body SOAP-ENV:encodingStyle="{SOAP_ENC_NS}">'
)
#: gSOAP ends every envelope with CRLF, and so does this.
_TAIL = "</SOAP-ENV:Body></SOAP-ENV:Envelope>\r\n"


class _Nil:
    """The value of an element sent as ``xsi:nil``, as gSOAP sends absent structs."""

    def __repr__(self) -> str:
        """``NIL``, so field lists read cleanly in test failures."""
        return "NIL"


#: Render the element as ``<name xsi:nil="true"/>``.
NIL = _Nil()


class SOAPError(Exception):
    """The reply is not a SOAP envelope we can read."""


class SOAPFault(Exception):
    """The server answered with a ``<SOAP-ENV:Fault>``.

    Servers fault for what their SRM layer never sees, such as a request
    they cannot parse or a caller their authorisation layer refuses. The
    transport turns it into ``ECOMM`` with the fault string.
    """

    def __init__(self, code: str, text: str) -> None:
        """``code`` is the ``faultcode`` (may be ""), ``text`` the ``faultstring``."""
        super().__init__(f"{code}: {text}" if code else text)
        self.code = code
        self.text = text


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _render(name: str, value: Any, out: list[str]) -> None:
    """Append element ``name`` holding ``value`` (see :data:`Fields`) to ``out``.

    ``bool`` is tested before ``int`` because it is one, and must be
    written ``true``/``false``, not ``True``/``1``. Text is XML-escaped; element names are
    trusted, as they come from this package.
    """
    if value is None:
        return
    if value is NIL:
        out.append(f'<{name} xsi:nil="true"/>')
    elif isinstance(value, bool):
        out.append(f"<{name}>{'true' if value else 'false'}</{name}>")
    elif isinstance(value, (int, str)):
        out.append(f"<{name}>{escape(str(value))}</{name}>")
    else:
        out.append(f"<{name}>")
        for child, inner in value:
            _render(child, inner, out)
        out.append(f"</{name}>")


def _envelope(element: str, part: str, fields: Fields, multiref: bool = False) -> bytes:
    """The whole envelope: ``<srm2:element><part>fields</part></srm2:element>``.

    With ``multiref`` the part is written as Axis writes it, a reference to
    a ``multiRef`` sibling in the Body, so the test server can exercise the
    reader's href following.
    """
    out = [_HEAD, f"<srm2:{element}>"]
    if multiref:
        # Axis style: the part is a reference to a sibling multiRef.
        out.append(f'<{part} href="#id0"/></srm2:{element}><multiRef id="id0">')
        for child, inner in fields:
            _render(child, inner, out)
        out.append("</multiRef>")
    else:
        _render(part, fields, out)
        out.append(f"</srm2:{element}>")
    out.append(_TAIL)
    return "".join(out).encode("utf-8")


def request(operation: str, fields: Fields) -> bytes:
    """The envelope for a call to ``operation`` (``"srmLs"``...)."""
    return _envelope(operation, f"{operation}Request", fields)


def response(operation: str, fields: Fields, *, multiref: bool = False) -> bytes:
    """The envelope answering ``operation``; ``multiref`` writes it Axis-style."""
    name = f"{operation}Response"
    return _envelope(name, name, fields, multiref)


def fault(code: str, text: str) -> bytes:
    """A ``SOAP-ENV:Fault`` envelope, as the test server answers a bad request."""
    return (
        f"{_HEAD}<SOAP-ENV:Fault><faultcode>{escape(code)}</faultcode>"
        f"<faultstring>{escape(text)}</faultstring></SOAP-ENV:Fault>{_TAIL}"
    ).encode()


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _local(tag: str) -> str:
    """An ElementTree tag without its ``{namespace}``: replies are read by local name.

    Namespaces are ignored on purpose: servers disagree on which elements
    are qualified, and the local names are unambiguous within a reply.
    """
    return tag.rpartition("}")[2]


_NIL = f"{{{XSI_NS}}}nil"


class Node:
    """An element of a reply, addressed by local names, with hrefs followed.

    Lookups never raise for a missing element: :meth:`get` gives "",
    :meth:`child` ``None``, :meth:`array` ``[]``, so callers read optional
    fields without guards and supply their own defaults. That matches
    gSOAP, which leaves an absent field zero or NULL. A nil element counts
    as absent.
    """

    __slots__ = ("_ids", "element")

    def __init__(self, element: ElementTree.Element, ids: dict[str, ElementTree.Element]) -> None:
        """Wrap ``element``; ``ids`` maps the Body's ``id`` attributes to elements."""
        self.element = element
        self._ids = ids

    @property
    def text(self) -> str:
        """The element's own text, stripped; "" when it has none."""
        return (self.element.text or "").strip()

    def _resolve(self, element: ElementTree.Element) -> ElementTree.Element | None:
        """``element``, or what its ``href="#id"`` chain points at; ``None`` if nil.

        A dangling reference, or a chain longer than 32 (a loop, from a
        broken or hostile server), reads as absent rather than failing.
        """
        seen = 0
        while True:
            href = element.get("href", "")
            if not href.startswith("#"):
                break
            target = self._ids.get(href[1:])
            seen += 1
            if target is None or seen > 32:
                return None
            element = target
        if element.get(_NIL, "") in ("true", "1"):
            return None
        return element

    def children(self, name: str | None = None) -> list[Node]:
        """Child elements called ``name`` (all when ``None``), nil ones left out."""
        found = []
        for child in self.element:
            if name is not None and _local(child.tag) != name:
                continue
            resolved = self._resolve(child)
            if resolved is not None:
                found.append(Node(resolved, self._ids))
        return found

    def child(self, *names: str) -> Node | None:
        """The first descendant along ``names``, or ``None``."""
        node = self
        for name in names:
            matches = node.children(name)
            if not matches:
                return None
            node = matches[0]
        return node

    def get(self, *names: str, default: str = "") -> str:
        """The text at the path ``names``, or ``default`` when it is absent."""
        node = self.child(*names)
        return node.text if node is not None else default

    def integer(self, *names: str) -> int | None:
        """The integer at the path ``names``; ``None`` when absent or not a number."""
        text = self.get(*names)
        try:
            return int(text)
        except ValueError:
            return None

    def boolean(self, *names: str) -> bool | None:
        """An ``xsd:boolean`` (``true``/``false``/``1``/``0``); ``None`` otherwise."""
        text = self.get(*names).lower()
        if text in ("true", "1"):
            return True
        if text in ("false", "0"):
            return False
        return None

    def array(self, container: str, item: str) -> list[Node]:
        """``<container><item/>...</container>``, the ArrayOf* shape."""
        holder = self.child(container)
        return holder.children(item) if holder is not None else []

    def strings(self, container: str, item: str) -> list[str]:
        """The texts of an ``ArrayOfString``-shaped :meth:`array`."""
        return [node.text for node in self.array(container, item)]

    def __iter__(self) -> Iterator[Node]:
        """Every non-nil child, in document order."""
        return iter(self.children())


def parse(data: bytes) -> tuple[str, Node]:
    """``(operation element name, the part)`` from an envelope.

    Raises :class:`SOAPFault` for a fault and :class:`SOAPError` for anything
    that is not a well-formed SOAP envelope.

    The operation element is the Body's first child that is not a
    ``multiRef``; its first child is the part. A reply whose operation
    element is empty yields an empty part, whose lookups all come back
    absent, so the client reports a missing status rather than crashing.
    ``ids`` is collected over the whole Body because Axis puts the
    referenced ``multiRef`` elements beside the operation, not in it.
    """
    try:
        root = fromstring(data)
    except UnsafeXML as exc:
        raise SOAPError("the reply carries a DTD, which SOAP forbids") from exc
    except ElementTree.ParseError as exc:
        raise SOAPError(f"the reply is not XML: {exc}") from None
    if _local(root.tag) != "Envelope":
        raise SOAPError(f"the reply is not a SOAP envelope but <{_local(root.tag)}>")
    body = next((child for child in root if _local(child.tag) == "Body"), None)
    if body is None:
        raise SOAPError("the SOAP envelope has no Body")
    ids = {element.get("id", ""): element for element in body.iter() if element.get("id")}
    operation = next((child for child in body if _local(child.tag) != "multiRef"), None)
    if operation is None:
        raise SOAPError("the SOAP Body is empty")
    wrapper = Node(operation, ids)
    if _local(operation.tag) == "Fault":
        raise SOAPFault(wrapper.get("faultcode"), wrapper.get("faultstring"))
    parts = wrapper.children()
    return _local(operation.tag), parts[0] if parts else Node(ElementTree.Element("empty"), ids)


# ---------------------------------------------------------------------------
# Status codes
# ---------------------------------------------------------------------------

#: Codes srm-ifce counts as success, at request and at file level alike.
SUCCESS = frozenset({"SRM_SUCCESS", "SRM_FILE_PINNED", "SRM_SPACE_AVAILABLE", "SRM_RELEASED"})
#: Codes that mean "ask again later"; srm-ifce polls while it sees these.
PENDING = frozenset({"SRM_REQUEST_QUEUED", "SRM_REQUEST_INPROGRESS"})

#: Linux ``errno`` values srm-ifce uses that other systems lack (macOS has
#: no ``EBADR``; it has ``ETIME``), with the nearest portable stand-in.
EBADR: int = getattr(errno, "EBADR", errno.EINVAL)
ETIME: int = getattr(errno, "ETIME", errno.ETIMEDOUT)

#: ``TStatusCode`` to ``errno`` exactly as srm-ifce 1.24 maps them (probed
#: code by code against gfal2 2.23.5); anything else is ``EINVAL``.
_ERRNO: dict[str, int] = {
    "SRM_FAILURE": errno.EIO,
    "SRM_AUTHENTICATION_FAILURE": errno.EACCES,
    "SRM_AUTHORIZATION_FAILURE": errno.EACCES,
    "SRM_INVALID_REQUEST": EBADR,
    "SRM_INVALID_PATH": errno.ENOENT,
    "SRM_FILE_LIFETIME_EXPIRED": ETIME,
    "SRM_EXCEED_ALLOCATION": errno.EDQUOT,
    "SRM_NO_USER_SPACE": EBADR,
    "SRM_NO_FREE_SPACE": errno.ENOSPC,
    "SRM_DUPLICATION_ERROR": errno.EEXIST,
    "SRM_NON_EMPTY_DIRECTORY": errno.ENOTEMPTY,
    "SRM_TOO_MANY_RESULTS": errno.EFBIG,
    "SRM_INTERNAL_ERROR": ECOMM,
    "SRM_NOT_SUPPORTED": errno.EOPNOTSUPP,
    "SRM_REQUEST_QUEUED": errno.EAGAIN,
    "SRM_REQUEST_INPROGRESS": errno.EAGAIN,
    "SRM_ABORTED": errno.ECANCELED,
    "SRM_FILE_BUSY": errno.EBUSY,
    "SRM_FILE_LOST": errno.EIDRM,
    "SRM_FILE_UNAVAILABLE": errno.EBUSY,
}


def errno_for_status(code: str) -> int:
    """The ``errno`` srm-ifce reports for a ``TStatusCode``; ``0`` for success."""
    if code in SUCCESS:
        return 0
    return _ERRNO.get(code, errno.EINVAL)


# ---------------------------------------------------------------------------
# Value formats
# ---------------------------------------------------------------------------

#: ``TPermissionMode`` indexed by the three ``rwx`` bits (``r`` = 4, ``w`` = 2,
#: ``x`` = 1), so ``PERMISSION_MODES[6]`` is ``RW``.
PERMISSION_MODES = ("NONE", "X", "W", "WX", "R", "RX", "RW", "RWX")


def permission(bits: int) -> str:
    """Three ``rwx`` bits as a ``TPermissionMode``."""
    return PERMISSION_MODES[bits & 7]


def permission_bits(mode: str) -> int:
    """A ``TPermissionMode`` as three ``rwx`` bits (0 for anything unknown).

    gfal2 sends the enumeration's ordinal (``6``) rather than its name
    (``RW``), so a digit is read as the bits too.
    """
    text = mode.strip().upper()
    if len(text) == 1 and text in "01234567":
        return int(text)
    try:
        return PERMISSION_MODES.index(text)
    except ValueError:
        return 0


#: ``xsd:dateTime``: fractional seconds ignored, the zone optional (absent
#: is read as UTC).
_TIME = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)?$")


def parse_time(text: str) -> int:
    """An ``xsd:dateTime`` as Unix seconds; 0 when absent or unreadable."""
    found = _TIME.match(text.strip())
    if found is None:
        return 0
    fields = [int(part) for part in found.groups()[:6]]
    seconds = calendar.timegm((*fields, 0, 0, 0))
    zone = found.group(7)
    if zone and zone != "Z":
        sign = -1 if zone[0] == "-" else 1
        digits = zone[1:].replace(":", "")
        seconds -= sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
    return seconds


def format_time(epoch: float) -> str:
    """Unix seconds as an ``xsd:dateTime`` in UTC, as the test server writes times."""
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(epoch))
