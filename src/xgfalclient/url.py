"""URLs, parsed without being normalised.

A storage URL's path is not always a path: ``root://host//store/f`` means
something different from ``root://host/store/f`` to some servers, and
``srm://host:8443/srm/managerv2?SFN=/pnfs/f`` keeps its real path in the
query. The split is done by hand (RFC 3986's authority rule) rather than
with :func:`urllib.parse.urlsplit`, which silently deletes tabs and newlines
from its input (bpo-43882) and so would not round-trip; nothing is collapsed,
unquoted or reordered on the way back out, so ``str(parse(u))`` is ``u``.

The opaque LFC forms (``lfn:/grid/...``, ``guid:...``) - a scheme not followed
by ``//`` - parse with an empty netloc, the whole remainder as the path and
``URL.opaque`` set, and print back the same way; ``lfn:///grid/...`` is an
ordinary hierarchical URL with an empty authority. :func:`parent` climbs an
``lfn:`` path like any other and leaves a ``guid:`` (which has no directory)
unchanged, so a ``mkdir_rec`` climb stops there.
"""

from __future__ import annotations

import posixpath
import urllib.parse
from dataclasses import dataclass, replace

from .errors import not_supported_url

__all__ = ["URL", "basename", "join", "parent", "parse", "scheme_of"]

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


@dataclass(frozen=True, slots=True)
class URL:
    """A URL in parts. ``path`` keeps any doubled leading slash.

    Frozen so that plugins can cache by URL and pass parts between threads.
    ``path`` is still percent-encoded exactly as given: unquoting, if any,
    is each plugin's business.
    """

    scheme: str
    netloc: str
    path: str
    query: str = ""
    fragment: str = ""
    #: Written ``scheme:path``, with no ``//`` authority (``lfn:/grid/f``, ``guid:...``).
    opaque: bool = False

    @property
    def host(self) -> str:
        """The host, without user info, port or IPv6 brackets (``[::1]`` gives ``::1``)."""
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
        """``user[:password]`` before the ``@``, still encoded; ``""`` without one."""
        return self.netloc.rpartition("@")[0]

    @property
    def base(self) -> str:
        """``scheme://netloc``, with no path."""
        return f"{self.scheme}://{self.netloc}"

    def query_items(self) -> list[tuple[str, str]]:
        """The query's ``key=value`` pairs, decoded, in order; blank values kept.

        Blank values are kept because a key's presence can matter even when
        it has no value.
        """
        return urllib.parse.parse_qsl(self.query, keep_blank_values=True)

    def query_dict(self) -> dict[str, str]:
        """:meth:`query_items` as a dict; for a repeated key the last value wins."""
        return dict(self.query_items())

    def with_path(self, path: str) -> URL:
        """A copy with ``path`` replaced (given encoded, as stored)."""
        return replace(self, path=path)

    def with_scheme(self, scheme: str) -> URL:
        """A copy with another scheme (``davs`` to ``https`` before a request, say)."""
        return replace(self, scheme=scheme)

    def with_query(self, query: str) -> URL:
        """A copy with the raw query string replaced (without the ``?``)."""
        return replace(self, query=query)

    def __str__(self) -> str:
        """The URL text again; exactly the input for anything :func:`parse` made."""
        if self.opaque:
            text = f"{self.scheme}:{self.path}"
        else:
            text = f"{self.scheme}://{self.netloc}{self.path}"
        if self.query:
            text += f"?{self.query}"
        if self.fragment:
            text += f"#{self.fragment}"
        return text


#: Schemes written without ``//``: the LFC's logical names and GUIDs.
OPAQUE_SCHEMES = ("lfn", "guid")


def scheme_of(url: str) -> str:
    """The lower-cased scheme, or ``""`` when ``url`` has none.

    Cheaper than :func:`parse` and never raises, because plugin dispatch
    calls it for every operation. A ``scheme://`` prefix must be RFC 3986
    scheme characters (letters, digits, ``+``, ``-``; ``.`` is not
    accepted), so a local path containing ``://`` is not mistaken for one.
    """
    prefix = url.partition(":")[0].lower()
    if prefix in OPAQUE_SCHEMES:
        return prefix
    head, sep, _ = url.partition("://")
    if not sep or not head or not head.replace("+", "").replace("-", "").isalnum():
        return ""
    return head.lower()


def parse(url: str) -> URL:
    """Split ``url``; a string with no scheme is not a gfal URL.

    Raises the ``EPROTONOSUPPORT`` ``GError`` gfal2 gives for a bare path,
    so a caller passing ``/tmp/f`` instead of ``file:///tmp/f`` gets
    gfal2's message.
    """
    scheme = scheme_of(url)
    if not scheme:
        raise not_supported_url(url)
    rest = url[len(scheme) + 1 :]
    if not rest.startswith("//"):
        # An opaque LFC name (lfn:/grid/f, guid:...): no authority, all path.
        path, _, fragment = rest.partition("#")
        path, _, query = path.partition("?")
        return URL(scheme, "", path, query, fragment, opaque=True)
    rest = rest[2:]
    # The authority ends at the first "/", "?" or "#" (RFC 3986 section 3.2).
    end = next((i for i, char in enumerate(rest) if char in "/?#"), len(rest))
    netloc, remainder = rest[:end], rest[end:]
    path, _, fragment = remainder.partition("#")
    path, _, query = path.partition("?")
    return URL(scheme, netloc, path, query, fragment)


def join(url: str, name: str) -> str:
    """``url`` with ``name`` appended as one more path component.

    Exactly one ``/`` separates them, whatever either side has; the query
    and fragment are kept.
    """
    parsed = parse(url)
    path = parsed.path
    if not path.endswith("/"):
        path += "/"
    return str(parsed.with_path(path + name.lstrip("/")))


def parent(url: str) -> str:
    """The URL of the directory holding ``url``'s last component.

    The query and fragment are dropped: they belong to the object, not its
    directory. At the root the root comes back (``parent("root://h/")`` is
    ``root://h/``), which is how ``mkdir_rec`` knows to stop climbing.
    """
    parsed = parse(url)
    trimmed = parsed.path.rstrip("/")
    # A hierarchical URL's path is empty or starts with "/", so dirname never
    # comes back empty for one; dirname("//f") is "//", so root://host//f
    # keeps its double-slash root.
    head = posixpath.dirname(trimmed) if trimmed else "/"
    if not head:
        return url  # an opaque path with no "/" (a guid:) has no directory
    return str(replace(parsed, path=head, query="", fragment=""))


def basename(url: str) -> str:
    """The last path component (still percent-encoded), ignoring a trailing slash."""
    return posixpath.basename(parse(url).path.rstrip("/"))
