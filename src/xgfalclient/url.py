"""URLs, parsed without being normalised.

A storage URL's path is not always a path: ``root://host//store/f`` means
something different from ``root://host/store/f`` to some servers, and
``srm://host:8443/srm/managerv2?SFN=/pnfs/f`` keeps its real path in the
query. :func:`urllib.parse.urlsplit` is used for the split, and nothing is
collapsed, unquoted or reordered on the way back out, so ``str(parse(u))``
is ``u``.
"""

from __future__ import annotations

import posixpath
import urllib.parse
from dataclasses import dataclass, replace

from ._compat import SLOTS
from .errors import not_supported_url

__all__ = ["URL", "parse", "scheme_of", "join", "parent", "basename"]

#: Default ports, so a plugin never has to spell them.
DEFAULT_PORTS = {
    "http": 80,
    "dav": 80,
    "https": 443,
    "davs": 443,
    "s3": 80,
    "s3s": 443,
    "root": 1094,
    "roots": 1094,
    "xroot": 1094,
    "xroots": 1094,
    "gsiftp": 2811,
    "ftp": 21,
    "srm": 8443,
    "httpg": 8443,
}


@dataclass(frozen=True, **SLOTS)
class URL:
    """A URL in parts. ``path`` keeps any doubled leading slash."""

    scheme: str
    netloc: str
    path: str
    query: str = ""
    fragment: str = ""

    @property
    def host(self) -> str:
        host = self.netloc.rpartition("@")[2]
        if host.startswith("["):
            return host[1 : host.index("]")]
        return host.rpartition(":")[0] if ":" in host else host

    @property
    def port(self) -> int:
        """The explicit port, else the scheme's default (0 if it has none)."""
        host = self.netloc.rpartition("@")[2]
        tail = host.rpartition("]")[2] if host.startswith("[") else host
        if ":" in tail:
            text = tail.rpartition(":")[2]
            if text.isdigit():
                return int(text)
        return DEFAULT_PORTS.get(self.scheme, 0)

    @property
    def userinfo(self) -> str:
        return self.netloc.rpartition("@")[0]

    @property
    def base(self) -> str:
        """``scheme://netloc``, with no path."""
        return f"{self.scheme}://{self.netloc}"

    def query_items(self) -> list[tuple[str, str]]:
        return urllib.parse.parse_qsl(self.query, keep_blank_values=True)

    def query_dict(self) -> dict[str, str]:
        return dict(self.query_items())

    def with_path(self, path: str) -> URL:
        return replace(self, path=path)

    def with_scheme(self, scheme: str) -> URL:
        return replace(self, scheme=scheme)

    def with_query(self, query: str) -> URL:
        return replace(self, query=query)

    def __str__(self) -> str:
        text = f"{self.scheme}://{self.netloc}{self.path}"
        if self.query:
            text += f"?{self.query}"
        if self.fragment:
            text += f"#{self.fragment}"
        return text


#: Schemes written without ``//``: the LFC's logical names and GUIDs.
OPAQUE_SCHEMES = ("lfn", "guid")


def scheme_of(url: str) -> str:
    """The lower-cased scheme, or ``""`` when ``url`` has none."""
    prefix = url.partition(":")[0].lower()
    if prefix in OPAQUE_SCHEMES:
        return prefix
    head, sep, _ = url.partition("://")
    if not sep or not head or not head.replace("+", "").replace("-", "").isalnum():
        return ""
    return head.lower()


def parse(url: str) -> URL:
    """Split ``url``; a string with no scheme is not a gfal URL."""
    scheme = scheme_of(url)
    if not scheme:
        raise not_supported_url(url)
    rest = url[len(scheme) + 3 :]
    # The authority ends at the first "/", "?" or "#" (RFC 3986 section 3.2).
    end = next((i for i, char in enumerate(rest) if char in "/?#"), len(rest))
    netloc, remainder = rest[:end], rest[end:]
    path, _, fragment = remainder.partition("#")
    path, _, query = path.partition("?")
    return URL(scheme, netloc, path, query, fragment)


def join(url: str, name: str) -> str:
    """``url`` with ``name`` appended as one more path component."""
    parsed = parse(url)
    path = parsed.path
    if not path.endswith("/"):
        path += "/"
    return str(parsed.with_path(path + name.lstrip("/")))


def parent(url: str) -> str:
    """The URL of the directory holding ``url``'s last component."""
    parsed = parse(url)
    trimmed = parsed.path.rstrip("/")
    # A parsed path is empty or starts with "/", so dirname never comes back
    # empty; dirname("//f") is "//", so root://host//f keeps its double-slash root.
    head = posixpath.dirname(trimmed) if trimmed else "/"
    return str(replace(parsed, path=head, query="", fragment=""))


def basename(url: str) -> str:
    return posixpath.basename(parse(url).path.rstrip("/"))
