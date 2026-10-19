"""WebDAV and RFC 3230 parsing: ``PROPFIND`` multistatus bodies and ``Digest`` headers.

The parsing itself is xrdhttp's (:mod:`xrdhttp.webdav`; xrdclient's
``http._webdav`` until 0.4.0), shared by every client: what a
``<D:response>`` says, which path an ``<D:href>`` names, HTTP and ISO 8601
dates, and which ``Digest`` value is the checksum asked for. What this
module adds is davix's reading of the result.

A multistatus is loaded through :mod:`xrdcore.safexml`, which refuses DTDs,
entities and external resources. A body that does not parse is ``EIO``
``XML Parsing Error: ...`` as in davix, but the rest of the message is
expat's diagnosis, not libxml2's (``XML parse error at line 1: Document is
empty``).

The ``stat`` a ``<D:response>`` becomes is davix's: WebDAV has no owner and
no permissions, so the mode is ``0777`` plus the file type, uid, gid, nlink
and inode are zero, ``mtime`` comes from ``getlastmodified`` and ``ctime``
from ``creationdate`` when the server sends one. Unlike xrdclient, which
refuses one, a ``<D:response>`` with no ``href`` is skipped, and responses
nested anywhere in the document count, as davix's parser finds them.

Per RFC 4918 (section 14.16) a multistatus holds one ``<D:response>`` per
resource, each with an ``<D:href>`` and ``<D:propstat>`` blocks; a ``404``
propstat for a property the server lacks (say ``creationdate``) is normal
and just leaves that field at zero.
"""

from __future__ import annotations

import errno
import posixpath
import stat as _stat
import xml.etree.ElementTree as ET

from xrdcore.safexml import UnsafeXML, fromstring
from xrdhttp.webdav import DAV as _DAV
from xrdhttp.webdav import epoch as epoch
from xrdhttp.webdav import href_path as href_path
from xrdhttp.webdav import pick_digest, resource
from xrdhttp.webdav import text as _text

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


def stat_for(response: ET.Element) -> Stat:
    """One ``<D:response>`` as the ``Stat`` davix makes of it."""
    found = resource(response)
    return Stat(
        st_mode=DIR_MODE if found.is_dir else FILE_MODE,
        st_size=found.size,
        st_mtime=found.mtime,
        st_ctime=found.ctime,
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
    """Equal as collection paths: trailing slashes and ``//`` do not count.

    Used to find a listing's own entry: servers answer ``/dir`` asked as
    ``/dir/`` and the reverse, and some double a slash at a mount point.
    """
    return posixpath.normpath("/" + left.strip("/")) == posixpath.normpath("/" + right.strip("/"))


def digest_value(header: str, algorithm: str) -> str:
    """``algorithm``'s value out of a ``Digest`` header, as lower-case hex ('' if absent).

    RFC 3230 base64 for hashes, hex for the checksums storage speaks natively
    (ADLER32, the CRCs): xrdhttp's
    :func:`~xrdhttp.webdav.pick_digest`, which compares names in
    canonical form (``sha``, ``SHA-1`` and ``sha1`` are one algorithm).
    """
    return pick_digest(header, algorithm)
