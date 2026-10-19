"""Bounded Metalink discovery and parsing for Davix-compatible failover.

Davix does not treat a ``.meta4`` filename as the requested data. After an
HTTP read or stat fails, it sends ``HEAD`` with an
``Accept: application/metalink4+xml`` header. A ``Link`` response header can
point at the descriptor, or the response itself can carry a Metalink content
type. The listed replicas are then tried in order.

Discovery - reading the ``Link`` field - is davix's alone and lives here. The
descriptor itself is parsed by xrdhttp (:func:`xrdhttp.metalink.parse_metalink`)
under davix's :data:`POLICY`: every ``<url>`` of the document counts, not just
those of a single ``<file>``, and only HTTP-family replicas are kept. The
bounds, ranking and URL resolution are the ones XrdCl's reading uses; an
error is xrdhttp's message as a :class:`~xgfalclient.GError`.

The plugin drives it (:meth:`~.plugin.HTTPPlugin._metalink_replicas`) and
caches the result per URL; this module never makes a request itself, so it
can be tested on header values and documents alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from xrdhttp.metalink import MAX_DESCRIPTOR_SIZE as MAX_DESCRIPTOR_SIZE
from xrdhttp.metalink import MAX_REPLICAS as MAX_REPLICAS
from xrdhttp.metalink import MAX_URL_SIZE as MAX_URL_SIZE
from xrdhttp.metalink import MetalinkError, MetalinkPolicy, resolve
from xrdhttp.metalink import parse_metalink as _parse

from ...errors import GError
from ...url import scheme_of
from ._client import Response, wire_scheme

__all__ = ["ACCEPT", "MAX_DESCRIPTOR_SIZE", "Metalink", "descriptor_url", "parse_metalink"]

#: The media type RFC 5854 registers for Metalink 4, asked for in ``Accept``.
ACCEPT = "application/metalink4+xml"
# ``type=`` and ``rel=`` parameters of one Link value (RFC 8288), each quoted
# with ``"`` or ``'`` or bare; the three groups are those three spellings.
_TYPE = re.compile(r"(?:^|;)\s*type\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^;\s]+))", re.I)
_REL = re.compile(r"(?:^|;)\s*rel\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^;\s]+))", re.I)


def _http_replica(url: str) -> bool:
    """Whether davix can read ``url``: an ``http(s)``, ``dav(s)`` or object-store URL."""
    return bool(wire_scheme(scheme_of(url)))


#: davix's reading of a descriptor; see the module docstring.
POLICY = MetalinkPolicy(single_file=False, accepts=_http_replica)


@dataclass(frozen=True, slots=True)
class Metalink:
    """The replicas a descriptor lists, best first, and the size it declares."""

    replicas: tuple[str, ...]
    size: int | None = None


def descriptor_url(response: Response, origin: str) -> str | None:
    """The descriptor advertised by one discovery ``HEAD`` response, or ``None``.

    RFC 6249's way first: a ``Link`` with a Metalink media type whose
    ``rel`` is ``describedby`` - or that has no ``rel`` at all, accepted
    from servers that leave it out. Failing that, a response
    that *is* a Metalink document (its ``Content-Type`` says so) makes the
    URL its own descriptor. A relative link is resolved against ``origin``.
    """
    for value in response.headers.get_all("Link", []):
        for target, parameters in _links(value):
            media = _parameter(_TYPE, parameters).lower()
            relations = _parameter(_REL, parameters).lower().split()
            if media.startswith("application/metalink") and (
                not relations or "describedby" in relations
            ):
                return resolve(origin, target)
    content_type = response.header("Content-Type").lower().split(";", 1)[0].strip()
    if content_type.startswith("application/metalink"):
        return origin
    return None


def parse_metalink(document: bytes, *, base_url: str) -> Metalink:
    """Parse Metalink 3 or 4 URLs with strict resource limits.

    xrdhttp bounds the document (:data:`MAX_DESCRIPTOR_SIZE`), the number
    of replicas (:data:`MAX_REPLICAS`) and each URL's length, and refuses a
    DTD, so a hostile descriptor costs bounded memory. Its message becomes
    the ``GError``'s (with no errno: callers fall back to the original error).
    """
    try:
        parsed = _parse(document, base_url=base_url, policy=POLICY)
    except MetalinkError as exc:
        raise GError(str(exc)) from None
    return Metalink(parsed.replicas, parsed.size)


def _links(value: str) -> list[tuple[str, str]]:
    """Split a Link field without treating commas inside ``<...>`` as separators.

    Each link is ``(target, parameters)``. A URI may itself contain commas,
    so a link's parameters end at the last comma before the next ``<``, not
    at the first. An unterminated ``<`` ends the field: what follows cannot
    be read reliably, and the links already found are still good.
    """
    links: list[tuple[str, str]] = []
    at = 0
    while True:
        left = value.find("<", at)
        if left < 0:
            return links
        right = value.find(">", left + 1)
        if right < 0:
            return links
        next_left = value.find("<", right + 1)
        comma = value.rfind(",", right + 1, next_left if next_left >= 0 else len(value))
        end = comma if comma >= 0 else len(value)
        links.append((value[left + 1 : right].strip(), value[right + 1 : end]))
        if next_left < 0:
            return links
        at = next_left


def _parameter(pattern: re.Pattern[str], value: str) -> str:
    """The first value ``pattern`` finds in a parameter list, unquoted; ``""`` if absent."""
    found = pattern.search(value)
    if found is None:
        return ""
    return next((part for part in found.groups() if part is not None), "")
