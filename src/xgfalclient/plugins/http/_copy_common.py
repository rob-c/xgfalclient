"""What the HTTP copy modules share: the mode names, the schemes, and a few helpers.

A leaf: :mod:`._copy`, :mod:`._tpc`, :mod:`._streamed` and :mod:`._ranged`
import it, and it imports none of them. ``[CORE] RESOLVE_DNS`` (gfal2's
DMC-1348 workaround, :func:`resolved`) lives here because both a
third-party and a streamed copy address the endpoints through it.
"""

from __future__ import annotations

import logging
import random
import socket
from dataclasses import replace
from typing import TYPE_CHECKING

from ...errors import GError
from ...transfer import Transfer
from ...url import parse, scheme_of
from ._client import config_group

if TYPE_CHECKING:
    from ...options import Options
    from .plugin import HTTPPlugin

__all__ = ["HTTP_SCHEMES", "PULL", "PUSH", "STREAMED", "is_http_scheme", "local_path", "resolved"]

_log = logging.getLogger("gfal2")

# The copy modes, spelled as gfal2 spells them in ``DEFAULT_COPY_MODE`` and in
# the ``TRANSFER_TYPE`` event: a pull has the destination fetch the source
# (WebDAV ``COPY`` with ``Source:``), a push has the source send it
# (``Destination:``), and streamed moves the bytes through this process.
PULL = "3rd pull"
PUSH = "3rd push"
STREAMED = "streamed"
#: Every mode name ``DEFAULT_COPY_MODE`` may set; anything else is ignored.
_MODES = (PULL, PUSH, STREAMED)
#: What ``is_http_scheme`` accepts in gfal2: no ``+3rd``.
HTTP_SCHEMES = frozenset(
    {"http", "https", "dav", "davs", "s3", "s3s", "gcloud", "gclouds"}
    | {"swift", "swifts", "cs3", "cs3s"}
)
#: ``checksum_mode`` bits: check the source, check the target (gfal2's
#: ``GFALT_CHECKSUM_SOURCE`` and ``GFALT_CHECKSUM_TARGET``).
_CHECKSUM_SOURCE = 1
_CHECKSUM_TARGET = 2


def is_http_scheme(url: str) -> bool:
    """gfal2's ``is_http_scheme``: the plugin's schemes, less the ``+3rd`` ones."""
    return scheme_of(url) in HTTP_SCHEMES


def local_path(url: str) -> str:
    """The path of a ``file://`` URL, as gfal2 takes it: everything after the scheme.

    Not :func:`urllib.parse.unquote`-d and no host allowed for, because gfal2
    passes the path of ``file:///path`` straight to the system calls.
    """
    return url[len("file://") :]


def _deadline_timeout(transfer: Transfer, fallback: float) -> float:
    """The socket timeout for a copy's one long request: the time it has left.

    A TPC ``COPY`` or a streamed ``PUT`` waits on one request for the whole
    transfer, so the per-operation timeout would cut it short; the copy's own
    deadline bounds it instead, or ``fallback`` when the copy has none. At
    least a second, so a copy at its deadline still gets an answer to fail on
    rather than a zero timeout (which would make the socket non-blocking).
    """
    left = transfer.remaining()
    return fallback if left is None else max(left, 1.0)


def _se_boolean(options: Options, url: str, key: str) -> bool | None:
    """``key`` from ``url``'s own group, or ``None`` when that group does not set it.

    gfal2 lets a storage element override the plugin's copy settings in a
    group named after its host (:func:`~._client.config_group`); ``None``
    leaves the decision to the plugin-wide option. A value that is not a
    boolean is treated as unset rather than failing the copy.
    """
    group = config_group(url)
    if not options.has(group, key):
        return None
    try:
        return bool(options.get_boolean(group, key))
    except GError:
        return None


def resolved(plugin: HTTPPlugin, url: str) -> str:
    """``url`` on one of its host's addresses, by name, when ``[CORE] RESOLVE_DNS`` is on.

    gfal2's DMC-1348: a DNS alias in front of several doors is resolved
    once, one address picked at random, and that address's reverse name used,
    so that both sides of a TPC - and every request of a streamed copy -
    reach the same door, and TLS still sees a host name its certificate can
    match. Any resolver failure leaves the URL as it was, with a warning.
    """
    if not plugin.options.boolean("CORE", "RESOLVE_DNS", False):
        return url
    parsed = parse(url)
    host = parsed.host
    try:
        found = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        address = random.choice(found)[4]
        name = socket.getnameinfo(address, socket.NI_NAMEREQD)[0]
    except OSError as exc:
        _log.warning("Could not resolve DNS alias %s: %s", host, exc)
        return url
    _log.info("Resolved url: %s => %s", host, name)
    # Replace the host only, keeping any user info and the port.
    userinfo, at, place = parsed.netloc.rpartition("@")
    return str(replace(parsed, netloc=userinfo + at + place.replace(host, name, 1)))
