"""Bounded Metalink discovery and parsing for Davix-compatible failover.

Davix does not treat a ``.meta4`` filename as the requested data. After an
HTTP read or stat fails, it sends ``HEAD`` with an
``Accept: application/metalink4+xml`` header. A ``Link`` response header can
point at the descriptor, or the response itself can carry a Metalink content
type. The listed replicas are then tried in order.
"""

from __future__ import annotations

import posixpath
import re
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from ..._compat import SLOTS
from ..._xml import UnsafeXML, fromstring
from ...errors import GError
from ...url import parse, scheme_of
from ._client import Response, wire_scheme

__all__ = ["ACCEPT", "MAX_DESCRIPTOR_SIZE", "Metalink", "descriptor_url", "parse_metalink"]

ACCEPT = "application/metalink4+xml"
MAX_DESCRIPTOR_SIZE = 8 << 20
MAX_URL_SIZE = 4096
MAX_REPLICAS = 10_000
_TYPE = re.compile(r"(?:^|;)\s*type\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^;\s]+))", re.I)
_REL = re.compile(r"(?:^|;)\s*rel\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^;\s]+))", re.I)


@dataclass(frozen=True, **SLOTS)
class Metalink:
    replicas: tuple[str, ...]
    size: int | None = None


def descriptor_url(response: Response, origin: str) -> str | None:
    """The descriptor advertised by one discovery ``HEAD`` response."""
    for value in response.headers.get_all("Link", []):
        for target, parameters in _links(value):
            media = _parameter(_TYPE, parameters).lower()
            relations = _parameter(_REL, parameters).lower().split()
            if media.startswith("application/metalink") and (
                not relations or "describedby" in relations
            ):
                return _absolute(origin, target)
    content_type = response.header("Content-Type").lower().split(";", 1)[0].strip()
    if content_type.startswith("application/metalink"):
        return origin
    return None


def parse_metalink(document: bytes, *, base_url: str) -> Metalink:
    """Parse Metalink 3 or 4 URLs with strict resource limits."""
    root = _parse_root(document)
    replicas = _replicas(root, base_url)
    if not replicas:
        raise GError("Metalink descriptor contains no usable HTTP replica")
    return Metalink(replicas, _size(root))


def _parse_root(document: bytes) -> ET.Element:
    """Parse a bounded, entity-free Metalink document."""
    if len(document) > MAX_DESCRIPTOR_SIZE:
        raise GError(
            f"Metalink descriptor is {len(document)} bytes; limit is {MAX_DESCRIPTOR_SIZE}"
        )
    try:
        root = fromstring(document)
    except UnsafeXML as exc:
        raise GError("Metalink descriptors may not declare a DOCTYPE or XML entities") from exc
    except ET.ParseError as exc:
        raise GError(f"Malformed Metalink descriptor: {exc}") from None
    if _local_name(root.tag) != "metalink":
        raise GError("Metalink document root must be <metalink>")
    return root


def _replicas(root: ET.Element, base_url: str) -> tuple[str, ...]:
    """Return usable replica URLs in Metalink preference order."""
    version = (root.get("version") or "4").strip()
    v3 = version.startswith("3")
    ranked: list[tuple[int, int, str]] = []
    for order, node in enumerate(root.iter()):
        candidate = _ranked_replica(node, base_url, v3, order)
        if candidate is not None:
            ranked.append(candidate)
        if len(ranked) > MAX_REPLICAS:
            raise GError(f"Metalink contains more than {MAX_REPLICAS} replica URLs")
    ranked.sort()
    return tuple(dict.fromkeys(value for _, _, value in ranked))


def _ranked_replica(
    node: ET.Element, base_url: str, v3: bool, order: int
) -> tuple[int, int, str] | None:
    if _local_name(node.tag) != "url":
        return None
    value = (node.text or "").strip()
    if not value or len(value.encode()) > MAX_URL_SIZE:
        return None
    value = _absolute(base_url, value)
    if not wire_scheme(scheme_of(value)):
        return None
    attribute, default = ("preference", 0) if v3 else ("priority", 999_999)
    rank = _integer(node.get(attribute), default)
    return (-rank if v3 else rank, order, value)


def _links(value: str) -> list[tuple[str, str]]:
    """Split a Link field without treating commas inside ``<...>`` as separators."""
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
    found = pattern.search(value)
    if found is None:
        return ""
    return next((part for part in found.groups() if part is not None), "")


def _local_name(tag: str) -> str:
    return tag.rpartition("}")[2].lower()


def _size(root: ET.Element) -> int | None:
    for node in root.iter():
        if _local_name(node.tag) == "size":
            text = (node.text or "").strip()
            return int(text) if text.isdigit() else None
    return None


def _integer(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def _absolute(base: str, reference: str) -> str:
    if scheme_of(reference):
        return reference
    original = parse(base)
    if reference.startswith("//"):
        return f"{original.scheme}:{reference}"
    path = (
        reference
        if reference.startswith("/")
        else posixpath.join(posixpath.dirname(original.path), reference)
    )
    path = posixpath.normpath(path)
    joined = urllib.parse.urlunsplit((wire_scheme(original.scheme), original.netloc, path, "", ""))
    return original.scheme + joined[joined.index("://") :]
