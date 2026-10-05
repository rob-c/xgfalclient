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
upload for very large objects.
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
    return scheme.partition("+")[0] in ("swift", "swifts")


@dataclass(frozen=True)
class SwiftKeys:
    token: str
    project: str
    account: str

    def __repr__(self) -> str:
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
    """Puts the token on a request and its path under the account."""

    def __init__(self, keys: SwiftKeys) -> None:
        self.keys = keys

    def target(self, method: str, target: Target) -> Target:
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
        return {"X-Auth-Token": self.keys.token} if self.keys.token else {}

    def presign(self, method: str, url: str, expires: int = 3600) -> str:
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
    escaped = urllib.parse.quote(prefix[1:], safe="")
    head = f"{base}/{container}/" if container else f"{base}/"
    return f"{head}?prefix={escaped}&delimiter=%2F"


def _list_body(plugin: HTTPPlugin, url: str) -> bytes:
    base, container, path = _split(url)
    response = plugin._request(
        "GET", _listing(base, container, path), headers={"Accept": "application/xml"}, cred_url=url
    )
    payload = response.body()
    if response.status not in (200, 204):
        raise status_error(response.status)
    return payload


def stat(plugin: HTTPPlugin, url: str) -> Stat:
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
    return tag.rpartition("}")[2].lower()


def list_objects(plugin: HTTPPlugin, url: str) -> list[tuple[str, Stat | None]]:
    """What a Swift listing says is directly under ``url``."""
    path = _split(url)[2]
    strip = "" if path == "/" else path[1:].rstrip("/") + "/"
    root = parse_xml(_list_body(plugin, url) or b"<container/>", "Swift listing")
    found: list[tuple[str, Stat | None]] = []
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


def rename(
    plugin: HTTPPlugin,
    old: str,
    new: str,
    *,
    copy_header: str,
    source: str,
    ok: int,
    verify: Callable[[bytes], None] | None = None,
) -> None:
    """Copy on the server, then delete the original - how object stores rename.

    ``copy_header`` names the source (``X-Copy-From`` for Swift,
    ``x-amz-copy-source`` for S3) as ``source``; ``ok`` is the status that
    means the copy is there.
    """
    what = "Swift" if copy_header == "X-Copy-From" else "S3"
    if provider(old) != provider(new):
        raise GError(
            f"It looks that the two URLs are not using the same {what} provider. "
            "Unable to perform the move operation.",
            errno.ENOSYS,
        )
    response = plugin._request("PUT", new, headers={copy_header: source}, body=b"")
    payload = response.body()
    if response.status != ok:
        raise GError(
            f"Received code {response.status} when trying to copy file - will not perform deletion",
            errno.EIO,
        )
    if verify is not None:
        verify(payload)
    removal = plugin._request("DELETE", old)
    removal.body()
    if removal.status >= 300:
        raise status_error(removal.status)


def rename_swift(plugin: HTTPPlugin, old: str, new: str) -> None:
    _, container, path = _split(old)
    rename(plugin, old, new, copy_header="X-Copy-From", source=f"/{container}{path}", ok=201)
