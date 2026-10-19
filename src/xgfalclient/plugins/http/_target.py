"""Where an HTTP request goes: gfal schemes on the wire, request targets, config groups.

gfal2 names one storage element by many schemes - ``dav``, ``davs``, ``s3s``,
``swift``, ``cs3`` and the ``+3rd`` forms - and every one of them is plain
``http`` or ``https`` once it leaves the client. This module is that mapping
(:func:`wire_scheme`, :func:`wire_url`), the per-endpoint option group gfal2
reads settings from (:func:`config_group`), and :class:`Target`: one request's
endpoint and origin-form request target, quoted the way davix quotes it -
existing ``%XX`` escapes are kept, which is deliberately not xrdclient's
encode-exactly-once rule.

Split out of :mod:`._client`, which re-exports every name here; the client,
the copy modules and the object-store signers all address requests with it.
Following a redirect is :mod:`xrdhttp.redirects`' since 0.4.0 (both pieces
moved there from here): :func:`~xrdhttp.redirects.resolve_location` keeps the
gfal scheme of a relative hop, so ``davs://`` stays ``davs://`` and ``s3s://``
keeps its signing, and :func:`~xrdhttp.redirects.davix_carries_credentials`
decides whether the ``Authorization`` goes along - davix's rule, not
xrdclient's same-origin one - over :attr:`Target.base`.
"""

from __future__ import annotations

import errno
import re
import urllib.parse
from dataclasses import dataclass

from ...errors import GError
from ...url import URL, parse
from ._status import TransportError

__all__ = [
    "OBJECT_STORES",
    "Target",
    "config_group",
    "valid_authority",
    "wire_scheme",
    "wire_url",
]

#: Schemes whose requests are signed (or carry a Swift token) instead of a bearer token.
OBJECT_STORES = frozenset({"s3", "s3s", "gcloud", "gclouds", "swift", "swifts"})
#: gfal scheme -> wire scheme. The trailing ``s`` is TLS for every family;
#: ``cs3`` (CERNBox/Reva) is WebDAV with a configured bearer token. A scheme
#: missing here maps to ``""``, which :meth:`Target.of` refuses.
_WIRE = {
    "http": "http",
    "dav": "http",
    "s3": "http",
    "gcloud": "http",
    "swift": "http",
    "cs3": "http",
    "https": "https",
    "davs": "https",
    "s3s": "https",
    "gclouds": "https",
    "swifts": "https",
    "cs3s": "https",
}


def wire_scheme(scheme: str) -> str:
    """``http`` or ``https`` for a gfal scheme (``davs+3rd`` -> ``https``)."""
    return _WIRE.get(scheme.partition("+")[0], "")


def wire_url(url: str) -> str:
    """``url`` as another server must see it: ``http(s)://``, query and all.

    What goes in a ``Destination`` or ``Source`` header is read by a server,
    not by gfal2, and ``davs://`` means nothing to it.
    """
    parsed = parse(url)
    text = f"{wire_scheme(parsed.scheme)}://{parsed.netloc}{parsed.path or '/'}"
    return f"{text}?{parsed.query}" if parsed.query else text


def config_group(url: str) -> str:
    """gfal2's per-endpoint group for ``url``: ``DAV:HOST`` for ``davs://host/...``.

    The protocol (``+3rd`` dropped) loses one trailing ``s``, and the whole
    name is upper-cased: ``https`` and ``http`` share ``[HTTP:HOST]``.
    """
    parsed = parse(url)
    scheme = parsed.scheme.partition("+")[0]
    scheme = scheme[:-1] if scheme.endswith("s") else scheme
    return f"{scheme}:{parsed.host}".upper()


#: An existing percent-escape, which :func:`_quote_path` must not re-escape.
_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
#: RFC 3986 ``pchar`` sub-delimiters plus ``/``: legal in a path as they are.
_PATH_SAFE = "/:@!$&'()*+,;=~"
#: A run of two or more literal path separators (never an escaped ``%2F``).
_SLASHES = re.compile(r"/{2,}")


def _collapse_slashes(path: str) -> str:
    """Fold runs of ``/`` into one, as a POSIX-backed WebDAV server does.

    A doubled slash (``/store//file``) is a join artifact, not meaning: most
    servers normalise it, but StoRM answers ``400`` where the others
    succeed, so the request goes out with it folded. Only literal separators
    are folded - a ``%2F`` standing for a slash inside a name is an escape,
    not a separator, and is left alone. S3 keeps its slashes (an S3 key is
    literal, and SigV4 signs it as spelled), which is why only the non-S3
    branch of :meth:`Target.of` calls this. The parsed URL kept in
    :attr:`Target.url` is untouched: this is about the request line only.
    """
    return _SLASHES.sub("/", path)


def _quote_path(path: str) -> str:
    """Percent-encode a path, leaving escapes that are already there alone.

    davix's (neon's) behaviour: ``a%20b c`` goes out as ``a%20b%20c``. A
    file whose name really contains ``%41`` therefore cannot be named
    without encoding the ``%`` first - gfal2 users already live with that,
    whereas decoding first would turn an escaped ``%2F`` into a path
    separator and so name a different file.
    """
    parts: list[str] = []
    end = 0
    for match in _ESCAPE.finditer(path):
        parts.append(urllib.parse.quote(path[end : match.start()], safe=_PATH_SAFE))
        parts.append(match.group())
        end = match.end()
    parts.append(urllib.parse.quote(path[end:], safe=_PATH_SAFE))
    return "".join(parts)


@dataclass(frozen=True)
class Target:
    """Where one request goes: the endpoint and the origin-form request target.

    ``path`` is the RFC 9112 origin-form - path and query, already quoted -
    exactly as it goes on the request line; ``url`` is the parsed URL it was
    made from, gfal scheme and all, for whatever needs the original.
    """

    #: ``http`` or ``https``, never a gfal scheme.
    scheme: str
    #: The host, without IPv6 brackets.
    host: str
    #: The port, the scheme's default when the URL names none.
    port: int
    path: str
    url: URL

    @classmethod
    def of(cls, url: str, *, s3: bool = False) -> Target:
        """The target for ``url``; ``s3`` quotes the path as SigV4's canonical request does.

        Refuses, in davix's words, what davix refuses: a scheme with no wire
        form or an authority neon cannot parse (``EIO``, the message's
        leading space included), and an empty host (``EHOSTUNREACH``, as the
        name lookup davix attempts would fail).
        """
        parsed = parse(url)
        scheme = wire_scheme(parsed.scheme)
        if not scheme or not valid_authority(parsed.netloc):
            raise GError(f" {url} is not a valid HTTP or Webdav URL", errno.EIO)
        if not parsed.host:
            # davix takes an empty host and fails to resolve it.
            raise TransportError("Domain name resolution failed", errno.EHOSTUNREACH)
        explicit = _explicit_port(parsed.netloc)
        port = explicit or (443 if scheme == "https" else 80)
        raw = parsed.path or "/"
        # S3 signs the path exactly as its canonical form spells it, so the
        # wire must use that spelling too - and an S3 key's slashes are
        # literal. Elsewhere a doubled slash is a join artifact a WebDAV
        # server folds, so it is folded here rather than left for a strict
        # one (StoRM) to refuse.
        quoted = (
            urllib.parse.quote(urllib.parse.unquote(raw), safe="/")
            if s3
            else _quote_path(_collapse_slashes(raw))
        )
        query = parsed.query
        return cls(scheme, parsed.host, port, f"{quoted}?{query}" if query else quoted, parsed)

    @property
    def host_header(self) -> str:
        """The ``Host`` value (RFC 9110 section 7.2): the port only when not the default.

        An IPv6 literal gets its brackets back, and a default port is left
        out as curl and browsers leave it out: some servers (and virtual-host
        S3 endpoints) compare ``Host`` with their configured name verbatim.
        """
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return host if self.port == default else f"{host}:{self.port}"

    @property
    def base(self) -> str:
        """``scheme://host:port`` - where server-rooted APIs live."""
        return f"{self.scheme}://{self.host_header}"


def valid_authority(netloc: str) -> bool:
    """Whether davix (neon's URI parser) takes ``netloc``: a closed ``[...]``, a numeric port."""
    host = netloc.rpartition("@")[2]
    if host.startswith("["):
        if "]" not in host:
            return False
        host = host.rpartition("]")[2]
    port = host.partition(":")[2]
    return not port or port.isdigit()


def _explicit_port(netloc: str) -> int:
    """The port written in ``netloc``, or ``0`` when there is none.

    Userinfo is dropped first (a password may contain ``:``), and the
    colons inside an IPv6 literal's brackets are not a port separator.
    """
    host = netloc.rpartition("@")[2]
    tail = host.rpartition("]")[2] if host.startswith("[") else host
    text = tail.rpartition(":")[2] if ":" in tail else ""
    return int(text) if text.isdigit() else 0
