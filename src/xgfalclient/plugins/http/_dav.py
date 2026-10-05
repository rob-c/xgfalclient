"""WebDAV and RFC 3230 parsing: ``PROPFIND`` multistatus bodies and ``Digest`` headers.

A multistatus is loaded through the local standard-library XML wrapper,
which refuses DTDs, entities and external resources. A body that does not parse
is ``EIO`` ``XML Parsing Error: ...``
as in davix, but the rest of the message is expat's diagnosis, not
libxml2's (``XML parse error at line 1: Document is empty``).

The ``stat`` a ``<D:response>`` becomes is davix's: WebDAV has no owner and
no permissions, so the mode is ``0777`` plus the file type, uid, gid, nlink
and inode are zero, ``mtime`` comes from ``getlastmodified`` and ``ctime``
from ``creationdate`` when the server sends one.
"""

from __future__ import annotations

import base64
import binascii
import email.utils
import errno
import hashlib
import posixpath
import stat as _stat
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime

from ..._xml import UnsafeXML, fromstring
from ...errors import GError
from ...types import Stat

__all__ = [
    "PROPFIND_BODY",
    "digest_value",
    "epoch",
    "href_path",
    "parse_multistatus",
    "parse_xml",
    "stat_for",
]

_DAV = "{DAV:}"

#: The properties a listing asks for: what ``Stat`` needs and nothing else.
PROPFIND_BODY = (
    b'<?xml version="1.0" encoding="utf-8" ?>\n'
    b'<D:propfind xmlns:D="DAV:"><D:prop>'
    b"<D:resourcetype/><D:getcontentlength/><D:getlastmodified/><D:creationdate/>"
    b"</D:prop></D:propfind>"
)

#: A file's and a directory's mode as davix reports them.
FILE_MODE = _stat.S_IFREG | 0o777
DIR_MODE = _stat.S_IFDIR | 0o777


def parse_xml(payload: bytes, what: str = "WebDAV response") -> ET.Element:
    """Parse an XML body, refusing any document that carries a DTD."""
    try:
        return fromstring(payload)
    except UnsafeXML as exc:
        raise GError(f"Refusing a {what} with a document type declaration", errno.EIO) from exc
    except ET.ParseError as exc:
        # davix's WebDavPropertiesParsingError, which gfal2 reports as EIO.
        raise GError(f"XML Parsing Error: {what}: {exc}", errno.EIO) from exc


def epoch(stamp: str) -> int:
    """Seconds since the epoch from an HTTP date or an ISO 8601 one."""
    text = stamp.strip()
    if not text:
        return 0
    try:
        return int(email.utils.parsedate_to_datetime(text).timestamp())
    except (TypeError, ValueError, IndexError):
        pass
    try:
        return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


def href_path(href: str) -> str:
    """The unquoted server path an ``<D:href>`` names, absolute or not."""
    raw = urllib.parse.urlsplit(href).path if "://" in href else href
    return urllib.parse.unquote(raw) or "/"


def _text(element: ET.Element | None, name: str) -> str:
    if element is None:
        return ""
    found = element.find(_DAV + name)
    return (found.text or "").strip() if found is not None else ""


def stat_for(response: ET.Element) -> Stat:
    """One ``<D:response>`` as the ``Stat`` davix makes of it."""
    prop = None
    for propstat in response.findall(_DAV + "propstat"):
        status = _text(propstat, "status")
        if not status or " 200 " in f"{status} ":
            prop = propstat.find(_DAV + "prop")
            break
    kind = prop.find(_DAV + "resourcetype") if prop is not None else None
    is_dir = kind is not None and kind.find(_DAV + "collection") is not None
    size = _text(prop, "getcontentlength")
    return Stat(
        st_mode=DIR_MODE if is_dir else FILE_MODE,
        st_size=int(size) if size.isdigit() else 0,
        st_mtime=epoch(_text(prop, "getlastmodified")),
        st_ctime=epoch(_text(prop, "creationdate")),
    )


def parse_multistatus(payload: bytes) -> list[tuple[str, Stat]]:
    """``(path, stat)`` for every ``<D:response>``, in document order."""
    root = parse_xml(payload)
    found = []
    for entry in root.iter(_DAV + "response"):
        href = _text(entry, "href")
        if href:
            found.append((href_path(href), stat_for(entry)))
    return found


def same_path(left: str, right: str) -> bool:
    """Equal as collection paths: trailing slashes and ``//`` do not count."""
    return posixpath.normpath("/" + left.strip("/")) == posixpath.normpath("/" + right.strip("/"))


# ---------------------------------------------------------------------------
# RFC 3230 digests
# ---------------------------------------------------------------------------

#: Digests storage sends in hex; every other algorithm arrives base64-encoded.
_HEX = frozenset({"adler32", "crc32", "crc32c", "unixcksum", "cksum"})
#: The RFC 3230 names that differ from the names users type.
_ALIASES = {"sha": "sha1", "sha-1": "sha1", "sha-256": "sha256", "sha-512": "sha512"}


def _canonical(name: str) -> str:
    key = name.strip().lower()
    return _ALIASES.get(key, key)


def digest_value(header: str, algorithm: str) -> str:
    """``algorithm``'s value out of a ``Digest`` header, as lower-case hex ('' if absent)."""
    wanted = _canonical(algorithm)
    for item in header.split(","):
        name, sep, raw = item.strip().partition("=")
        if not sep or _canonical(name) != wanted:
            continue
        return _as_hex(raw.strip(), wanted)
    return ""


def _as_hex(value: str, algorithm: str) -> str:
    """RFC 3230 base64 for hashes; hex for the checksums storage speaks natively."""
    if algorithm in _HEX or _looks_hex(value, algorithm):
        return value.lower()
    try:
        return base64.b64decode(value, validate=True).hex()
    except (binascii.Error, ValueError):
        return value.lower()


def _looks_hex(value: str, algorithm: str) -> bool:
    try:
        width = 2 * hashlib.new(algorithm).digest_size
    except ValueError:
        return False
    return len(value) == width and all(char in "0123456789abcdefABCDEF" for char in value)
