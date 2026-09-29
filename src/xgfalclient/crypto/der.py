"""DER: read and write the handful of ASN.1 types X.509 and PKCS use.

GSI delegation means signing a certificate - the remote end sends a
certificate request, and the client answers with a proxy certificate it has
built and signed itself. That needs a DER *writer* as well as a reader. Both
are here, small and strict: the reader rejects indefinite lengths,
multi-byte tags and trailing garbage, because it parses structures that
arrive from the network.
"""

from __future__ import annotations

import calendar
import time
from dataclasses import dataclass

from .._compat import SLOTS

__all__ = [
    "DERError",
    "Element",
    "parse",
    "parse_one",
    "parse_all",
    "read_integer",
    "oid_string",
    "tlv",
    "integer",
    "oid",
    "sequence",
    "set_of",
    "octet_string",
    "bit_string",
    "boolean",
    "null",
    "utf8_string",
    "printable_string",
    "utc_time",
    "generalized_time",
    "validity_time",
    "explicit",
    "TAG_BOOLEAN",
    "TAG_INTEGER",
    "TAG_BIT_STRING",
    "TAG_OCTET_STRING",
    "TAG_NULL",
    "TAG_OID",
    "TAG_UTF8_STRING",
    "TAG_SEQUENCE",
    "TAG_SET",
    "TAG_PRINTABLE_STRING",
    "TAG_IA5_STRING",
    "TAG_UTC_TIME",
    "TAG_GENERALIZED_TIME",
]

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_PRINTABLE_STRING = 0x13
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18


class DERError(ValueError):
    """The bytes given are not the DER structure they claim to be."""


@dataclass(frozen=True, **SLOTS)
class Element:
    """One tag-length-value triple; ``encoded`` re-emits it byte for byte."""

    tag: int
    value: bytes

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def encoded(self) -> bytes:
        return tlv(self.tag, self.value)

    def children(self) -> list[Element]:
        if not self.constructed:
            raise DERError(f"tag 0x{self.tag:02x} is primitive and has no children")
        return parse_all(self.value)

    def __getitem__(self, index: int) -> Element:
        return self.children()[index]

    def __repr__(self) -> str:
        return f"Element(tag=0x{self.tag:02x}, len={len(self.value)})"


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise DERError("truncated: no length byte")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0:
        raise DERError("indefinite lengths are not valid DER")
    if count > 4:
        raise DERError(f"length of length {count} is implausible")
    if pos + count > len(data):
        raise DERError("truncated: long-form length runs past the end")
    return int.from_bytes(data[pos : pos + count], "big"), pos + count


def parse(data: bytes, pos: int = 0) -> tuple[Element, int]:
    """Read one element at ``pos``; returns it and the offset after it."""
    if pos >= len(data):
        raise DERError("truncated: no tag byte")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise DERError("multi-byte tags are not supported")
    length, pos = _read_length(data, pos + 1)
    end = pos + length
    if end > len(data):
        raise DERError(f"truncated: element claims {length} bytes, {len(data) - pos} available")
    return Element(tag, bytes(data[pos:end])), end


def parse_one(data: bytes) -> Element:
    """Exactly one element, with nothing after it."""
    element, end = parse(data)
    if end != len(data):
        raise DERError(f"{len(data) - end} trailing bytes after the element")
    return element


def parse_all(data: bytes) -> list[Element]:
    out: list[Element] = []
    pos = 0
    while pos < len(data):
        element, pos = parse(data, pos)
        out.append(element)
    return out


def read_integer(element: Element) -> int:
    if element.tag != TAG_INTEGER:
        raise DERError(f"expected INTEGER, got tag 0x{element.tag:02x}")
    if not element.value:
        raise DERError("INTEGER with no content")
    return int.from_bytes(element.value, "big", signed=True)


def oid_string(element: Element) -> str:
    if element.tag != TAG_OID:
        raise DERError(f"expected OBJECT IDENTIFIER, got tag 0x{element.tag:02x}")
    if not element.value:
        raise DERError("OBJECT IDENTIFIER with no content")
    arcs: list[int] = []
    value = 0
    for byte in element.value:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    if element.value[-1] & 0x80:
        raise DERError("OBJECT IDENTIFIER ends mid-arc")
    # The first sub-identifier packs two arcs: 40 * first + second, where
    # only the arc 2 may have a second arc of 40 or more.
    first = min(arcs[0] // 40, 2)
    return ".".join(str(arc) for arc in (first, arcs[0] - 40 * first, *arcs[1:]))


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _length(count: int) -> bytes:
    if count < 0x80:
        return bytes([count])
    body = count.to_bytes((count.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def integer(value: int) -> bytes:
    width = (value.bit_length() + 8) // 8  # at least 1, even for 0
    return tlv(TAG_INTEGER, value.to_bytes(width, "big", signed=True))


def oid(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.split(".")]
    body = bytearray()
    for arc in (40 * arcs[0] + arcs[1], *arcs[2:]):
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body.extend(reversed(chunk))
    return tlv(TAG_OID, bytes(body))


def sequence(*parts: bytes) -> bytes:
    return tlv(TAG_SEQUENCE, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    """A SET OF, members sorted as DER requires."""
    return tlv(TAG_SET, b"".join(sorted(parts)))


def octet_string(data: bytes) -> bytes:
    return tlv(TAG_OCTET_STRING, data)


def bit_string(data: bytes) -> bytes:
    return tlv(TAG_BIT_STRING, b"\x00" + data)


def boolean(value: bool) -> bytes:
    return tlv(TAG_BOOLEAN, b"\xff" if value else b"\x00")


def null() -> bytes:
    return tlv(TAG_NULL, b"")


def utf8_string(text: str) -> bytes:
    return tlv(TAG_UTF8_STRING, text.encode("utf-8"))


def printable_string(text: str) -> bytes:
    return tlv(TAG_PRINTABLE_STRING, text.encode("ascii"))


def utc_time(when: float) -> bytes:
    return tlv(TAG_UTC_TIME, time.strftime("%y%m%d%H%M%SZ", time.gmtime(when)).encode())


def generalized_time(when: float) -> bytes:
    return tlv(TAG_GENERALIZED_TIME, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(when)).encode())


def validity_time(when: float) -> bytes:
    """RFC 5280: UTCTime through 2049, GeneralizedTime from 2050."""
    year = time.gmtime(when).tm_year
    return utc_time(when) if year < 2050 else generalized_time(when)


def explicit(number: int, inner: bytes) -> bytes:
    """A context-specific constructed tag ``[number] EXPLICIT``."""
    return tlv(0xA0 | number, inner)


def decode_time(element: Element) -> float:
    """``UTCTime``/``GeneralizedTime`` as a UNIX timestamp."""
    text = element.value.decode("ascii", "replace").strip()
    if text.endswith("Z"):
        text = text[:-1]
    if element.tag == TAG_UTC_TIME:
        if len(text) < 10:
            raise DERError(f"malformed UTCTime {text!r}")
        year = int(text[:2])
        text = f"{2000 + year if year < 50 else 1900 + year}{text[2:]}"
    elif element.tag != TAG_GENERALIZED_TIME:
        raise DERError(f"tag 0x{element.tag:02x} is not a certificate time")
    text = (text + "000000")[:14]
    try:
        parsed = time.strptime(text, "%Y%m%d%H%M%S")
    except ValueError as exc:
        raise DERError(f"malformed time {text!r}") from exc
    return float(calendar.timegm(parsed))
