"""BDII endpoint discovery: which SRM web service serves a host.

A short SURL (``srm://host/path``) names a storage element, not the web
service that answers for it. gfal2 asks the BDII - the grid's LDAP
information system - and this does what it does (``utils/mds`` in gfal2
2.23.5):

1. ``[BDII] CACHE_FILE`` (FTS3's XML dump) first: every top-level
   ``<entry>`` whose ``<endpoint>``, after ``://``, starts with the host
   (case-insensitively) counts. A file that is missing or does not parse is
   skipped.
2. Otherwise LDAP: the servers in ``$LCG_GFAL_INFOSYS``, else ``[BDII]
   LCG_GFAL_INFOSYS`` (comma-separated ``host:port``, tried in turn until
   one accepts the connection), an anonymous simple bind, and one subtree
   search under ``o=grid`` for ``(|(GlueSEUniqueID=*<host>*)(&(GlueServiceType=
   srm*)(GlueServiceEndpoint=*://<host>*)))``, asking for the service's
   type, version and endpoint. ``[BDII] TIMEOUT`` bounds the connection and
   the answer.
3. The first SRM v2 endpoint found is the service, used as it is.

Any failure is gfal2's: the SRM plugin logs "Error while bdii SRM service
resolution" and guesses ``httpg://host[:port]/srm/managerv2``.

The LDAP needed is a sliver of LDAPv3 (RFC 4511): BER-encoded bind,
search and unbind requests and their responses, and the RFC 4515 filter
syntax. It is written out here rather than taken from a library, because the
package depends on nothing. :mod:`xgfalclient.testing.ldap` serves the same
sliver for the tests.

Where this differs from gfal2: an answer (or a failure) is kept for the
life of the context, one lookup per host, where gfal2 asks the BDII again
on every SRM operation; and a ``TIMEOUT`` of zero or less is bounded by the
caller's timeout rather than by nothing.
"""

from __future__ import annotations

import errno
import logging
import os
import socket
import threading
import xml.etree.ElementTree as ElementTree
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Union

from ..._compat import SLOTS
from ...errors import ECOMM, GError

__all__ = [
    "Resolver",
    "Endpoint",
    "LDAPError",
    "LDAPClient",
    "encode",
    "decode",
    "parse_filter",
    "encode_filter",
    "match_filter",
    "SRM_FILTER",
    "ATTRIBUTES",
    "BASE",
    "GROUP",
    "RESULT_TEXT",
]

_log = logging.getLogger("gfal2")

GROUP = "BDII"
BASE = "o=grid"
SRM_FILTER = (
    "(|(GlueSEUniqueID=*{host}*)(&(GlueServiceType=srm*)(GlueServiceEndpoint=*://{host}*)))"
)
ATTRIBUTES = ("GlueServiceVersion", "GlueServiceEndpoint", "GlueServiceType")
#: gfal2 keeps at most this many endpoints per host.
MAX_ENDPOINTS = 100
LDAP_PORT = 389

# ---------------------------------------------------------------------------
# BER (X.690), as much as LDAP needs
# ---------------------------------------------------------------------------

#: A decoded element: its tag byte and its content, which is the raw bytes
#: of a primitive and the list of elements of a constructed one.
Element = tuple[int, Union[bytes, list[Any]]]

INTEGER, OCTETS, ENUMERATED, BOOLEAN, SEQUENCE, SET = 0x02, 0x04, 0x0A, 0x01, 0x30, 0x31


class BERError(ValueError):
    """Bytes that are not the BER this module reads."""


def _length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    body = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def encode(tag: int, content: bytes | Sequence[bytes]) -> bytes:
    """One element: ``content`` is the value, or the encoded children."""
    body = content if isinstance(content, bytes) else b"".join(content)
    return bytes([tag]) + _length(len(body)) + body


def integer(value: int, tag: int = INTEGER) -> bytes:
    size = max(1, (value.bit_length() + 8) // 8)
    return encode(tag, value.to_bytes(size, "big", signed=True))


def octets(value: str, tag: int = OCTETS) -> bytes:
    return encode(tag, value.encode("utf-8"))


def _read(data: bytes, offset: int) -> tuple[int, int, int]:
    """``(tag, content start, content end)`` of the element at ``offset``."""
    if offset + 2 > len(data):
        raise BERError("truncated element")
    tag, first = data[offset], data[offset + 1]
    start = offset + 2
    if first & 0x80:
        count = first & 0x7F
        if not count or start + count > len(data):
            raise BERError("bad length")
        size = int.from_bytes(data[start : start + count], "big")
        start += count
    else:
        size = first
    if tag & 0x1F == 0x1F:
        raise BERError("multi-byte tags are not LDAP's")
    if start + size > len(data):
        raise BERError("truncated element")
    return tag, start, start + size


def element_size(data: bytes) -> int | None:
    """How many bytes the first element of ``data`` takes; ``None`` until its header is in."""
    if len(data) < 2:
        return None
    first = data[1]
    if not first & 0x80:
        return 2 + first
    count = first & 0x7F
    if len(data) < 2 + count:
        return None
    return 2 + count + int.from_bytes(data[2 : 2 + count], "big")


def decode(data: bytes) -> Element:
    """The one element ``data`` holds, children decoded for constructed tags."""
    tag, start, end = _read(data, 0)
    if end != len(data):
        raise BERError("trailing bytes")
    return _decode(data, tag, start, end)


def _decode(data: bytes, tag: int, start: int, end: int) -> Element:
    if not tag & 0x20:
        return tag, data[start:end]
    children: list[Any] = []
    offset = start
    while offset < end:
        child, child_start, child_end = _read(data, offset)
        if child_end > end:
            raise BERError("child overruns its parent")
        children.append(_decode(data, child, child_start, child_end))
        offset = child_end
    return tag, children


def as_int(item: Element) -> int:
    value = item[1]
    if not isinstance(value, bytes):
        raise BERError("expected a primitive")
    return int.from_bytes(value, "big", signed=True)


def as_text(item: Element) -> str:
    value = item[1]
    if not isinstance(value, bytes):
        raise BERError("expected a primitive")
    return value.decode("utf-8", "replace")


def children(item: Element) -> list[Element]:
    value = item[1]
    if not isinstance(value, list):
        raise BERError("expected a constructed element")
    return value


# ---------------------------------------------------------------------------
# Filters (RFC 4515)
# ---------------------------------------------------------------------------

#: A parsed filter: ``("&"|"|", [filters])``, ``("!", filter)``,
#: ``("=", attr, value)``, ``("present", attr)`` or
#: ``("substrings", attr, initial, [any...], final)``.
Filter = tuple[Any, ...]


def _unescape(text: str) -> str:
    out = bytearray()
    index = 0
    raw = text.encode("utf-8")
    while index < len(raw):
        if raw[index : index + 1] == b"\\" and index + 3 <= len(raw):
            try:
                out.append(int(raw[index + 1 : index + 3], 16))
                index += 3
                continue
            except ValueError:
                pass
        out.append(raw[index])
        index += 1
    return out.decode("utf-8", "replace")


def parse_filter(text: str) -> Filter:
    """An RFC 4515 filter string; ``ValueError`` for one that is not."""
    found, end = _parse(text, 0)
    if end != len(text):
        raise ValueError(f"Bad search filter: {text}")
    return found


def _parse(text: str, index: int) -> tuple[Filter, int]:
    if text[index : index + 1] != "(":
        raise ValueError(f"Bad search filter: {text}")
    index += 1
    kind = text[index : index + 1]
    if kind in ("&", "|"):
        items = []
        index += 1
        while text[index : index + 1] == "(":
            item, index = _parse(text, index)
            items.append(item)
        found: Filter = (kind, items)
    elif kind == "!":
        item, index = _parse(text, index + 1)
        found = ("!", item)
    else:
        close = text.find(")", index)
        if close < 0:
            raise ValueError(f"Bad search filter: {text}")
        attribute, sep, value = text[index:close].partition("=")
        if not sep or not attribute:
            raise ValueError(f"Bad search filter: {text}")
        index = close
        if value == "*":
            found = ("present", attribute)
        elif "*" in value:
            parts = [_unescape(part) for part in value.split("*")]
            found = ("substrings", attribute, parts[0], [p for p in parts[1:-1] if p], parts[-1])
        else:
            found = ("=", attribute, _unescape(value))
    if text[index : index + 1] != ")":
        raise ValueError(f"Bad search filter: {text}")
    return found, index + 1


def encode_filter(found: Filter) -> bytes:
    kind = found[0]
    if kind in ("&", "|"):
        return encode(0xA0 if kind == "&" else 0xA1, [encode_filter(f) for f in found[1]])
    if kind == "!":
        return encode(0xA2, [encode_filter(found[1])])
    if kind == "present":
        return octets(found[1], 0x87)
    if kind == "=":
        return encode(0xA3, [octets(found[1]), octets(found[2])])
    _, attribute, initial, middle, final = found
    parts = [octets(initial, 0x80)] if initial else []
    parts += [octets(part, 0x81) for part in middle]
    parts += [octets(final, 0x82)] if final else []
    return encode(0xA4, [octets(attribute), encode(SEQUENCE, parts)])


def decode_filter(item: Element) -> Filter:
    """The filter a search request carries (for the test server)."""
    tag = item[0]
    if tag in (0xA0, 0xA1):
        return ("&" if tag == 0xA0 else "|", [decode_filter(f) for f in children(item)])
    if tag == 0xA2:
        return ("!", decode_filter(children(item)[0]))
    if tag == 0x87:
        return ("present", as_text(item))
    if tag == 0xA3:
        attribute, value = children(item)
        return ("=", as_text(attribute), as_text(value))
    if tag == 0xA4:
        attribute, parts = children(item)
        initial, middle, final = "", [], ""
        for part in children(parts):
            if part[0] == 0x80:
                initial = as_text(part)
            elif part[0] == 0x81:
                middle.append(as_text(part))
            else:
                final = as_text(part)
        return ("substrings", as_text(attribute), initial, middle, final)
    raise BERError(f"unsupported filter choice {tag:#x}")


def match_filter(found: Filter, entry: dict[str, list[str]]) -> bool:
    """Whether ``entry`` (attribute names matched case-insensitively) passes."""
    values = {name.lower(): items for name, items in entry.items()}
    kind = found[0]
    if kind == "&":
        return all(match_filter(f, entry) for f in found[1])
    if kind == "|":
        return any(match_filter(f, entry) for f in found[1])
    if kind == "!":
        return not match_filter(found[1], entry)
    present = values.get(found[1].lower(), [])
    if kind == "present":
        return bool(present)
    if kind == "=":
        return any(value.lower() == found[2].lower() for value in present)
    _, _, initial, middle, final = found
    return any(
        _substrings(value.lower(), initial.lower(), middle, final.lower()) for value in present
    )


def _substrings(value: str, initial: str, middle: list[str], final: str) -> bool:
    if not value.startswith(initial):
        return False
    position = len(initial)
    for part in middle:
        found = value.find(part.lower(), position)
        if found < 0:
            return False
        position = found + len(part)
    return len(value) - position >= len(final) and value.endswith(final)


# ---------------------------------------------------------------------------
# LDAP
# ---------------------------------------------------------------------------

#: ``ldap_err2string`` for the result codes a BDII can produce.
RESULT_TEXT = {
    -1: "Can't contact LDAP server",
    -5: "Timed out",
    -7: "Bad search filter",
    0: "Success",
    1: "Operations error",
    2: "Protocol error",
    3: "Time limit exceeded",
    4: "Size limit exceeded",
    32: "No such object",
    48: "Inappropriate authentication",
    49: "Invalid credentials",
    50: "Insufficient access",
    51: "Server is busy",
    52: "Server is unavailable",
    53: "Server is unwilling to perform",
    80: "Internal (implementation specific) error",
}

SERVER_DOWN, TIMEOUT, FILTER_ERROR = -1, -5, -7

#: Protocol operation tags (RFC 4511 section 4.2 onwards).
BIND_REQUEST, BIND_RESPONSE, UNBIND_REQUEST = 0x60, 0x61, 0x42
SEARCH_REQUEST, SEARCH_ENTRY, SEARCH_DONE, SEARCH_REFERENCE = 0x63, 0x64, 0x65, 0x73


class LDAPError(Exception):
    """An LDAP failure: ``code`` is libldap's result code."""

    def __init__(self, code: int) -> None:
        super().__init__(RESULT_TEXT.get(code, "Unknown error"))
        self.code = code


@dataclass(frozen=True, **SLOTS)
class Server:
    host: str
    port: int


def parse_servers(text: str) -> list[Server]:
    """``host[:port]`` items, comma-separated, as ``LCG_GFAL_INFOSYS`` lists them."""
    found = []
    for token in text.split(","):
        token = token.strip().rpartition("://")[2]
        if not token:
            continue
        if token.startswith("["):
            host, _, rest = token[1:].partition("]")
            port = rest[1:]
        else:
            host, _, port = token.partition(":")
        found.append(Server(host, int(port) if port.isdigit() else LDAP_PORT))
    return found


class LDAPClient:
    """One connection to the first of ``servers`` that accepts one."""

    def __init__(self, servers: Sequence[Server], timeout: float | None) -> None:
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self._buffer = b""
        self._id = 0
        for server in servers:
            try:
                self.sock = socket.create_connection((server.host, server.port), timeout)
            except (OSError, UnicodeError):
                continue
            break
        if self.sock is None:
            raise LDAPError(SERVER_DOWN)

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self._send(encode(UNBIND_REQUEST, b""))
        except LDAPError:
            pass
        self.sock.close()
        self.sock = None

    def _send(self, operation: bytes) -> int:
        assert self.sock is not None
        self._id += 1
        try:
            self.sock.sendall(encode(SEQUENCE, [integer(self._id), operation]))
        except OSError as exc:
            raise LDAPError(TIMEOUT if isinstance(exc, socket.timeout) else SERVER_DOWN) from exc
        return self._id

    def _message(self) -> Element:
        """The next protocol operation addressed to us."""
        assert self.sock is not None
        while True:
            size = element_size(self._buffer)
            if size is not None and len(self._buffer) >= size:
                raw, self._buffer = self._buffer[:size], self._buffer[size:]
                try:
                    message = children(decode(raw))
                    return message[1]
                except (BERError, IndexError) as exc:
                    raise LDAPError(2) from exc
            try:
                chunk = self.sock.recv(65536)
            except OSError as exc:
                raise LDAPError(
                    TIMEOUT if isinstance(exc, socket.timeout) else SERVER_DOWN
                ) from exc
            if not chunk:
                raise LDAPError(SERVER_DOWN)
            self._buffer += chunk

    @staticmethod
    def _result(operation: Element) -> None:
        code = as_int(children(operation)[0])
        if code:
            raise LDAPError(code)

    def bind(self) -> None:
        """An anonymous simple bind, LDAPv3."""
        self._send(encode(BIND_REQUEST, [integer(3), octets(""), octets("", 0x80)]))
        reply = self._message()
        if reply[0] != BIND_RESPONSE:
            raise LDAPError(2)
        self._result(reply)

    def search(
        self, base: str, found: Filter, attributes: Sequence[str], time_limit: int = 0
    ) -> list[dict[str, list[str]]]:
        """A subtree search; each entry's attributes, in the order the server sent them."""
        request = [
            octets(base),
            integer(2, ENUMERATED),  # wholeSubtree
            integer(0, ENUMERATED),  # neverDerefAliases
            integer(0),  # no size limit
            integer(max(0, time_limit)),
            encode(BOOLEAN, b"\x00"),
            encode_filter(found),
            encode(SEQUENCE, [octets(name) for name in attributes]),
        ]
        self._send(encode(SEARCH_REQUEST, request))
        entries: list[dict[str, list[str]]] = []
        while True:
            reply = self._message()
            if reply[0] == SEARCH_DONE:
                self._result(reply)
                return entries
            if reply[0] == SEARCH_ENTRY:
                _, pairs = children(reply)
                entry: dict[str, list[str]] = {}
                for pair in children(pairs):
                    name, values = children(pair)
                    entry[as_text(name)] = [as_text(value) for value in children(values)]
                entries.append(entry)
            elif reply[0] != SEARCH_REFERENCE:
                raise LDAPError(2)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True, **SLOTS)
class Endpoint:
    """One service the BDII (or its cache) lists: its URL and SRM version."""

    url: str
    #: ``"srm_v2"``, ``"srm_v1"``, or ``""`` for anything else.
    kind: str


def _failure(code: int, message: str, *scope: str) -> GError:
    """A GError with gfal2's ``[function]`` prefixes, outermost first."""
    return GError("".join(f"[{name}]" for name in scope) + message, code)


_OUTER = ("gfal_mds_get_se_types_and_endpoints", "gfal_mds_bdii_get_srm_endpoint")


def _entry_endpoint(entry: dict[str, list[str]]) -> Endpoint | None:
    """gfal2's ``gfal_mds_convert_entry_to_srm_information`` of one entry."""
    scope: tuple[str, ...] = (
        *_OUTER,
        "gfal_mds_get_srm_types_endpoint",
        "gfal_mds_convert_entry_to_srm_information",
    )
    fields = {"GlueServiceVersion": "", "GlueServiceEndpoint": "", "GlueServiceType": ""}
    counted = 0
    for name, values in entry.items():
        if not values:
            continue
        if name not in fields:
            raise _failure(errno.EINVAL, " Bad attribute retrieved from bdii ", *scope)
        fields[name] = values[0]
        counted += 1
    if not counted:
        return None
    name = fields["GlueServiceType"]
    version = fields["GlueServiceVersion"]
    url = fields["GlueServiceEndpoint"]
    scope = (*scope, "gfal_mds_srm_endpoint_struct_builder")
    if not name.upper().startswith("SRM"):
        text = f"bad value of srm endpoint returned by bdii : {name}, excepted : SRM "
        raise _failure(errno.EINVAL, text, *scope)
    if version[:2] not in ("1.", "2."):
        text = f"bad value of srm version returned by bdii : {version}, excepted 1.x or 2.x "
        raise _failure(errno.EINVAL, text, *scope)
    if ":/" not in url:
        text = (
            f"bad value of srm endpoint returned by bdii : {url}, excepted a correct endpoint "
            "url ( httpg://, https://, ... ) "
        )
        raise _failure(errno.EINVAL, text, *scope)
    return Endpoint(url, "srm_v2" if version.startswith("2.") else "srm_v1")


def read_cache(path: str, host: str) -> list[Endpoint]:
    """The endpoints an FTS3 BDII cache file lists for ``host``; none if it is unreadable."""
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        if text.lstrip().startswith("<?xml"):
            text = text.split("?>", 1)[1]
        root = ElementTree.fromstring(f"<cache>{text}</cache>")
    except (OSError, UnicodeError, ElementTree.ParseError) as exc:
        _log.debug("Could not load BDII CACHE_FILE: %s", exc)
        return []
    found = []
    for entry in root.findall("entry"):
        url = (entry.findtext("endpoint") or "").strip()
        hostname = url.partition("://")[2] if "://" in url else url
        if not hostname.lower().startswith(host.lower()):
            continue
        kind = (entry.findtext("type") or "").strip().lower()
        version = (entry.findtext("version") or "").strip()
        if kind == "srm" and version.startswith("2."):
            found.append(Endpoint(url, "srm_v2"))
        else:  # SRM v1, WebDAV, or unknown: counted, never chosen
            found.append(Endpoint(url, "srm_v1" if kind == "srm" else ""))
        if len(found) >= MAX_ENDPOINTS:
            break
    return found


class Resolver:
    """A context's BDII lookups: one per host, remembered."""

    def __init__(self, options: Any) -> None:
        self.options = options
        self._lock = threading.Lock()
        self._cache: dict[str, str | GError | None] = {}

    def enabled(self) -> bool:
        return bool(self.options.boolean(GROUP, "ENABLED", True))

    def endpoint(self, host: str, timeout: float | None = None) -> str | None:
        """The SRM v2 endpoint of ``host``; ``None`` when there is nothing to say.

        ``timeout`` bounds the LDAP exchange when ``[BDII] TIMEOUT`` does not.

        ``None`` is gfal2's odd case of a lookup that found no usable entry
        and no error either. A failure raises ``GError`` with gfal2's words.
        """
        with self._lock:
            if host not in self._cache:
                try:
                    self._cache[host] = self._select(self._lookup(host, timeout))
                except GError as exc:
                    self._cache[host] = exc
            found = self._cache[host]
        if isinstance(found, GError):
            raise found
        return found

    @staticmethod
    def _select(found: list[Endpoint]) -> str | None:
        if not found:
            return None
        for item in found:
            if item.kind == "srm_v2":
                return item.url
        raise GError(
            "cannot obtain a valid protocol from the bdii response, fatal error", errno.EINVAL
        )

    def _lookup(self, host: str, timeout: float | None) -> list[Endpoint]:
        path = self.options.string(GROUP, "CACHE_FILE", "")
        if path:
            _log.debug("BDII CACHE_FILE set to %s", path)
            cached = read_cache(path, host)
            if cached:
                _log.debug("%s found in the cache!", host)
                for item in cached:
                    _log.debug("\tFound %s", item.url)
                return cached
        return self._ldap(host, timeout)

    def _servers(self) -> list[Server]:
        text = os.environ.get("LCG_GFAL_INFOSYS")
        if text is None:
            text = self.options.string(GROUP, "LCG_GFAL_INFOSYS", "")
        servers = parse_servers(text)
        if not servers:
            raise _failure(
                errno.EINVAL,
                " no valid value for BDII found: please, configure the plugin properly, "
                "or try setting in the environment LCG_GFAL_INFOSYS",
                *_OUTER,
            )
        _log.debug(" use LCG_GFAL_INFOSYS : %s", text)
        return servers

    def _ldap(self, host: str, fallback: float | None) -> list[Endpoint]:
        servers = self._servers()
        uri = ",".join(f"ldap://{server.host}:{server.port}" for server in servers)
        configured = int(self.options.integer(GROUP, "TIMEOUT", -1))
        timeout = float(configured) if configured > 0 else fallback
        _log.debug(" use BDII TIMEOUT : %d", configured)
        _log.debug("  Try to bind with the bdii %s", uri)
        try:
            client = LDAPClient(servers, timeout)
        except LDAPError as exc:
            raise _failure(ECOMM, f"Error while bind to bdii with {uri} : {exc}", *_OUTER) from exc
        try:
            try:
                client.bind()
            except LDAPError as exc:
                text = f"Error while bind to bdii with {uri} : {exc}"
                raise _failure(ECOMM, text, *_OUTER) from exc
            query = SRM_FILTER.format(host=host)
            try:
                entries = client.search(BASE, parse_filter(query), ATTRIBUTES, max(0, configured))
            except (LDAPError, ValueError) as exc:
                reason = exc if isinstance(exc, LDAPError) else LDAPError(FILTER_ERROR)
                text = f"Error while request {query} to bdii : {reason}"
                raise _failure(ECOMM, text, *_OUTER, "gfal_mds_ldap_search") from exc
        finally:
            client.close()
        if not entries:
            text = " no entries for the endpoint returned by the bdii : 0 "
            raise _failure(errno.ENXIO, text, *_OUTER, "gfal_mds_get_srm_types_endpoint")
        return list(_endpoints(entries))


def _endpoints(entries: list[dict[str, list[str]]]) -> Iterator[Endpoint]:
    count = 0
    for entry in entries:
        found = _entry_endpoint(entry)
        if found is not None and count < MAX_ENDPOINTS:
            count += 1
            yield found
