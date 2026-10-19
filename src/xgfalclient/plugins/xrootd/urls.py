"""URL spellings the plugin needs: its schemes, local paths, and opaque CGI.

Small and pure, and shared by everything else in the package. The opaque
helpers are XrdCl's: a third-party copy names hosts as ``GetHostId`` does
and writes its CGI fields verbatim, merged over whatever the URL carried,
because a stock server reads them byte for byte.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import xrdclient

from ...url import scheme_of

if TYPE_CHECKING:
    from xrdclient import XRootDURL

#: The schemes gfal2's xrootd plugin claims; the ``s`` forms ask for TLS
#: (``roots`` is XRootD 5's, ``xroots`` its alias), which xrdclient negotiates.
SCHEMES = ("root", "roots", "xroot", "xroots")


def is_root(url: str) -> bool:
    """Whether ``url`` is this plugin's: one of the four XRootD schemes."""
    return scheme_of(url) in SCHEMES


def collapse_slashes(path: str) -> str:
    """gfal2's ``collapse_slashes``: ``//a///b`` is ``/a/b``."""
    while "//" in path:
        path = path.replace("//", "/")
    return path


def local_path(url: str) -> str:
    """The path in a ``file://`` URL, with or without a host part."""
    rest = url[len("file://") :]
    if rest.startswith("/"):
        return rest
    slash = rest.find("/")
    return rest[slash:] if slash >= 0 else "/"


def opaque(url: XRootDURL, fields: dict[str, str]) -> XRootDURL:
    """``url`` with ``fields`` set in its CGI, as XrdCl writes them: verbatim.

    The fields already there keep their bytes; XrdCl merges its own over
    them, so the new values win. The URL is spelled out and parsed again
    because a parsed URL's CGI is kept exactly as written, where one built
    field by field is re-encoded (a tab in ``tpc.scgi`` would become
    ``%09``, which a stock server does not read back).
    """
    kept = url.cgi_except(fields)
    added = "&".join(f"{name}={value}" for name, value in fields.items())
    cgi = f"{kept}&{added}" if kept else added
    return xrdclient.parse(f"{url.without_query()}?{cgi}")


def host_id(url: XRootDURL) -> str:
    """``XrdCl::URL::GetHostId``: ``[user@]host:port``, an IPv6 host bracketed."""
    user = f"{url.username}@" if url.username else ""
    host = f"[{url.host}]" if ":" in url.host else url.host
    return f"{user}{host}:{url.port}"


def landed(url: XRootDURL, endpoint: str) -> XRootDURL:
    """``url`` on the server an open ended up at (XrdCl's ``LastURL``)."""
    host, _, port = endpoint.rpartition(":")
    return url.evolve(host=host.strip("[]"), port=int(port))
