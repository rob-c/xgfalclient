"""OpenStack Swift: ``swift://`` and ``swifts://``, as davix speaks it.

davix does not talk to Keystone: the token is configured, not fetched. It
comes from ``OS_TOKEN`` in ``[SWIFT:<HOST>]`` or ``[SWIFT]``, and so do
``OS_PROJECT_ID`` and ``SWIFT_ACCOUNT`` - each found on its own, the host's
group first. Every request carries the token as ``X-Auth-Token``, and its
path is moved under the account: ``/v1/<SWIFT_ACCOUNT>/<container>/<object>``
when an account is named, else ``/v1/AUTH_<OS_PROJECT_ID>/...``, else left
as it is. A URL is ``swift://host/<container>/<object path>``.

=============  ================================================================
``stat``       ``HEAD``; a ``404`` is a directory if a listing under it has
               anything in it. Modes are ``0755``, as davix makes them.
``listdir``    ``GET <container>/?prefix=<path>/&delimiter=/``, XML
``mkdir``      ``PUT <path>/`` with no body (a marker object)
``rename``     ``PUT <new>`` with ``X-Copy-From``, then ``DELETE <old>``
=============  ================================================================

Where this differs from davix: an object in a listing is a regular file
(davix leaves the file-type bits out), and an empty listing is an empty
directory rather than davix's "not a Swift listing or the directory is
empty" error. Uploads are single ``PUT`` requests, without davix's segmented
upload for very large objects - so Swift's own object size cap (5 GiB by
default) applies.

A Swift token is a bearer credential with no signature over the request,
so :class:`SwiftSigner` cannot pre-sign a URL for a third-party copy
(``ENOSYS``); TempURL keys are not part of gfal2's Swift support. The
server-side copy-then-delete :func:`rename` lives here and is shared with
:mod:`._s3`, whose copy differs only in the header, source and status
(:class:`ServerCopy`).
"""

from __future__ import annotations

import errno
import stat as _stat
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from ...errors import GError
from ...types import Stat
from ...url import URL, parse
from ._client import Body, Target, status_error
from ._dav import epoch, parse_xml

if TYPE_CHECKING:
    from ...options import Options
    from .plugin import HTTPPlugin

__all__ = ["SwiftKeys", "SwiftSigner", "is_swift", "swift_keys"]

#: A Swift object's and "directory"'s mode, as davix reports them.
FILE_MODE = _stat.S_IFREG | 0o755
DIR_MODE = _stat.S_IFDIR | 0o755


def is_swift(scheme: str) -> bool:
    """Whether ``scheme`` is Swift (``swift``/``swifts``, any ``+3rd`` suffix ignored)."""
    return scheme.partition("+")[0] in ("swift", "swifts")


@dataclass(frozen=True)
class SwiftKeys:
    """A configured Swift identity: the Keystone token and where it points.

    ``account`` (``SWIFT_ACCOUNT``) wins over ``project``
    (``OS_PROJECT_ID``, made into ``AUTH_<id>``); with neither, the URL's
    path is taken to name the account already. Any of them may be ``""``.
    """

    token: str
    project: str
    account: str

    def __repr__(self) -> str:
        """Project and account; the token redacted, as it grants the account's rights."""
        return f"SwiftKeys(token=<redacted>, project={self.project!r}, account={self.account!r})"


def swift_keys(options: Options, url: URL) -> SwiftKeys:
    """``OS_TOKEN``, ``OS_PROJECT_ID`` and ``SWIFT_ACCOUNT``, each from the first group with it."""
    groups = (f"SWIFT:{url.host}".upper(), "SWIFT")
    found = {
        key: next((value for value in (options.string(g, key) for g in groups) if value), "")
        for key in ("OS_TOKEN", "OS_PROJECT_ID", "SWIFT_ACCOUNT")
    }
    return SwiftKeys(found["OS_TOKEN"], found["OS_PROJECT_ID"], found["SWIFT_ACCOUNT"])


class SwiftSigner:
    """Puts the token on a request and its path under the account.

    It fills the :class:`~._client.Signer` role so the transport treats
    Swift like the signed stores: :meth:`target` rewrites the path once per
    hop, :meth:`sign` adds the header. Being a signer, it is applied on
    every hop of a redirect, as an S3 signature is.
    """

    def __init__(self, keys: SwiftKeys) -> None:
        """Use ``keys`` for every request; the signer holds nothing else."""
        self.keys = keys

    def target(self, method: str, target: Target) -> Target:
        """``target`` with its path moved under ``/v1/<account>``, when an account is known."""
        if self.keys.account:
            root = f"/v1/{self.keys.account}"
        elif self.keys.project:
            root = f"/v1/AUTH_{self.keys.project}"
        else:
            return target
        return replace(target, path=root + target.path)

    def sign(
        self, method: str, target: Target, headers: Mapping[str, str], body: Body | None
    ) -> dict[str, str]:
        """``X-Auth-Token``, or nothing for an unconfigured token (a public container)."""
        return {"X-Auth-Token": self.keys.token} if self.keys.token else {}

    def presign(self, method: str, url: str, expires: int = 3600) -> str:
        """Always ``ENOSYS``: a token cannot be scoped to one URL, and is not to be handed out."""
        raise GError("Swift URLs cannot be pre-signed", errno.ENOSYS)


def _split(url: str) -> tuple[str, str, str]:
    """``(scheme://host:port, container, path in it)``; the path is ``/`` for a container."""
    parsed = parse(url)
    path = parsed.path or "/"
    container, sep, rest = path[1:].partition("/")
    return f"{parsed.scheme}://{parsed.netloc}", container, f"/{rest}" if sep else "/"


def _listing(base: str, container: str, path: str) -> str:
    """The ``GET`` that lists under ``path``, as davix's ``swiftUriTransformer`` builds it."""
    prefix = path if path.endswith("/") else path + "/"
    # The prefix is relative to the container (no leading slash) and fully
    # percent-encoded, ``/`` included, as one query value.
    escaped = urllib.parse.quote(prefix[1:], safe="")
    head = f"{base}/{container}/" if container else f"{base}/"
    return f"{head}?prefix={escaped}&delimiter=%2F"


def _list_body(plugin: HTTPPlugin, url: str) -> bytes:
    """The XML listing under ``url``; empty when Swift answers ``204`` (nothing there).

    ``Accept: application/xml`` because Swift's default is a plain-text
    list of names, which carries no sizes or times.
    """
    base, container, path = _split(url)
    response = plugin._request(
        "GET", _listing(base, container, path), headers={"Accept": "application/xml"}, cred_url=url
    )
    payload = response.body()
    if response.status not in (200, 204):
        raise status_error(response.status)
    return payload


def stat(plugin: HTTPPlugin, url: str) -> Stat:
    """``HEAD`` the object; a missing one is a directory if anything is listed under it.

    Swift has no directories either: a ``404`` key is a "directory" exactly
    when it is a prefix of some object (``ENOENT`` otherwise), and a
    ``<path>/`` marker of length zero is one too.
    """
    response = plugin._request("HEAD", url)
    response.close()
    path = _split(url)[2]
    if response.status == 404:
        if not _list_body(plugin, url).strip():
            raise GError("Not a file or directory", errno.ENOENT)
        return Stat(st_mode=DIR_MODE)
    if response.status == 204:
        # A container answers a HEAD with 204; anything else gets no file type.
        return Stat(st_mode=DIR_MODE if path == "/" else 0o755)
    if response.status != 200:
        raise status_error(response.status)
    size = response.length or 0
    if path == "/" or (path.endswith("/") and not size):
        return Stat(st_mode=DIR_MODE)
    return Stat(st_mode=FILE_MODE, st_size=size, st_mtime=epoch(response.header("Last-Modified")))


def _local(tag: str) -> str:
    """An XML tag without its ``{namespace}``, lower-cased, so any server's dialect reads."""
    return tag.rpartition("}")[2].lower()


def list_objects(plugin: HTTPPlugin, url: str) -> list[tuple[str, Stat | None]]:
    """What a Swift listing says is directly under ``url``."""
    path = _split(url)[2]
    strip = "" if path == "/" else path[1:].rstrip("/") + "/"
    root = parse_xml(_list_body(plugin, url) or b"<container/>", "Swift listing")
    found: list[tuple[str, Stat | None]] = []
    # ``<subdir name="p/"/>`` is a common prefix (the delimiter at work);
    # ``<object>`` carries ``name``, ``bytes`` and ``last_modified``.
    for entry in root:
        kind = _local(entry.tag)
        fields = {_local(child.tag): (child.text or "").strip() for child in entry}
        name = fields.get("name", "")[len(strip) :].strip("/")
        if not name:
            continue
        if kind == "subdir":
            found.append((name, Stat(st_mode=DIR_MODE)))
        elif kind == "object":
            size = fields.get("bytes", "")
            modified = epoch(fields.get("last_modified", ""))
            found.append(
                (
                    name,
                    Stat(
                        st_mode=FILE_MODE,
                        st_size=int(size) if size.isdigit() else 0,
                        st_mtime=modified,
                        st_ctime=modified,
                    ),
                )
            )
    return found


def mkdir(plugin: HTTPPlugin, url: str) -> None:
    """A zero-length object named ``<path>/``: what davix makes for a directory (S3 too)."""
    Target.of(url)  # a URL davix refuses is refused by the name it was given
    parsed = parse(url)
    path = parsed.path or "/"
    marker = str(parsed.with_path(path if path.endswith("/") else path + "/"))
    response = plugin._request("PUT", marker, body=b"")
    response.body()
    if response.status >= 300:
        raise status_error(response.status, suffix="bucket creation failure")


def provider(url: str) -> str:
    """davix's ``extract_s3_provider``: the host from its first dot on."""
    host = parse(url).host
    return host[host.index(".") :] if "." in host else ""


@dataclass(frozen=True, slots=True)
class ServerCopy:
    """How one object store spells a server-side copy, for :func:`rename`.

    ``header`` names the source - ``X-Copy-From`` for Swift,
    ``x-amz-copy-source`` for S3 and GCS - as ``source``, a
    ``/<container-or-bucket>/<key>`` path; ``ok`` is the status that means
    the copy is there (Swift's ``201 Created``, S3's ``200``); ``verify``
    reads the body of that answer, for S3, which can say ``200`` and still
    report an ``<Error>`` inside it.
    """

    header: str
    source: str
    ok: int
    verify: Callable[[bytes], None] | None = None


def rename(plugin: HTTPPlugin, old: str, new: str, how: ServerCopy) -> None:
    """Copy on the server, then delete the original - how object stores rename.

    As davix moves an object: refused outright across providers
    (``ENOSYS``, in davix's words), since a server-side copy cannot cross
    them; the original is deleted only once the copy is known to exist, so
    a failure leaves the source in place (``EIO``). Not atomic: a crash
    between the two steps leaves both names, never neither.
    """
    copy_header = how.header
    what = "Swift" if copy_header == "X-Copy-From" else "S3"
    if provider(old) != provider(new):
        raise GError(
            f"It looks that the two URLs are not using the same {what} provider. "
            "Unable to perform the move operation.",
            errno.ENOSYS,
        )
    response = plugin._request("PUT", new, headers={copy_header: how.source}, body=b"")
    payload = response.body()
    if response.status != how.ok:
        raise GError(
            f"Received code {response.status} when trying to copy file - will not perform deletion",
            errno.EIO,
        )
    if how.verify is not None:
        how.verify(payload)
    removal = plugin._request("DELETE", old)
    removal.body()
    if removal.status >= 300:
        raise status_error(removal.status)


def rename_swift(plugin: HTTPPlugin, old: str, new: str) -> None:
    """A Swift rename: ``X-Copy-From: /<container>/<object>``, ``201 Created``, then delete."""
    _, container, path = _split(old)
    rename(plugin, old, new, ServerCopy("X-Copy-From", f"/{container}{path}", 201))
