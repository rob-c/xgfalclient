"""The one exception gfal2 raises, and the helpers that build it.

gfal2 reports every failure as a ``GError``: an ``errno`` value in ``code``
and a human sentence in ``message``. Code written against the C-backed
bindings catches ``gfal2.GError`` and switches on ``e.code``, so that is
exactly the shape here - ``args`` is ``(message, code)``. ``message`` retains
the compatibility payload; ``str()`` and ``user_message`` provide plain display
text and remove internal scope prefixes.

It deliberately does not subclass :class:`OSError`: a ``GError`` is a plain
``Exception``, as in gfal2, so an ``except OSError`` in caller code does not
start swallowing grid failures it never used to see.

The class carries the bindings' class-level ``code = 0`` and ``message = ""``.
Its constructor stays lenient (both arguments optional, keywords accepted)
where gfal2's insists on exactly ``(str, int)``: nothing that works there
breaks here. Imported as ``gfal2`` (the shim, or :func:`install_as_gfal2`),
the class reports ``__module__ == "gfal2"``, so an uncaught one prints as
``gfal2.GError: ...`` and still pickles by that name.
"""

from __future__ import annotations

import errno
import os
import re
from typing import NoReturn

__all__ = [
    "GError",
    "gerror",
    "raise_gerror",
    "from_oserror",
    "unsupported",
    "not_supported_url",
    "HTTP_ERRNO",
    "errno_for_http",
    "ECOMM",
]


class GError(Exception):
    """A gfal2 error: ``code`` is an ``errno`` value, ``message`` the text."""

    code: int = 0
    message: str = ""

    def __init__(self, message: str = "", code: int = 0) -> None:
        super().__init__(message, code)
        self.message = message
        self.code = code

    def __str__(self) -> str:
        return self.user_message

    @property
    def user_message(self) -> str:
        """Plain text for people; ``message``, ``args`` and ``code`` stay compatible."""
        message = re.sub(r"^(?:\[[^\]\n]+\])+\s*", "", self.message).strip()
        generic = {
            "",
            os.strerror(self.code),
            f"errno reported by local system call {os.strerror(self.code)}",
        }
        if message in generic:
            return _USER_ERRORS.get(
                self.code, "The request failed. Check the command and service configuration."
            )
        return message

    def __repr__(self) -> str:
        return f"GError({self.message!r}, {self.code})"

    def __reduce__(self) -> tuple[type[GError], tuple[str, int]]:
        return (GError, (self.message, self.code))


def gerror(code: int, message: str, *scope: str) -> GError:
    """A ``GError`` whose message carries gfal2's ``[scope][scope]`` prefix.

    gfal2 prefixes messages with the chain of functions the error passed
    through, e.g. ``[gfal2_stat][gfal_http_stat] Result HTTP 404``. Callers
    that parse messages look for the text after the brackets, so a prefix is
    added only when a scope is named.
    """
    prefix = "".join(f"[{part}]" for part in scope)
    return GError(f"{prefix} {message}" if prefix else message, code)


def raise_gerror(code: int, message: str, *scope: str) -> NoReturn:
    """Raise :func:`gerror` - a statement form for the common case."""
    raise gerror(code, message, *scope)


def from_oserror(exc: OSError, prefix: str = "errno reported by local system call") -> GError:
    """Translate a local ``OSError`` the way gfal2's file plugin words it."""
    code = exc.errno if exc.errno is not None else errno.EIO
    return GError(f"{prefix} {os.strerror(code)}", code)


def unsupported(operation: str, url: str = "") -> GError:
    """``ENOSYS``: the plugin exists but cannot do this operation."""
    where = f" for {url}" if url else ""
    return GError(f"Operation {operation} is not supported{where}", errno.ENOSYS)


def not_supported_url(url: str) -> GError:
    """``EPROTONOSUPPORT``: no plugin claims this URL for this operation."""
    return GError(f"Protocol not supported or path/url invalid: {url}", errno.EPROTONOSUPPORT)


#: ``ECOMM`` ("communication error on send") is what davix reports for a 5xx;
#: it is Linux-only, and ``EIO`` is the nearest thing elsewhere.
ECOMM: int = getattr(errno, "ECOMM", errno.EIO)

#: HTTP status to ``errno``, as davix and gfal2's http plugin map them.
HTTP_ERRNO: dict[int, int] = {
    400: errno.EINVAL,
    401: errno.EACCES,
    403: errno.EACCES,
    404: errno.ENOENT,
    405: errno.EPERM,
    406: errno.EINVAL,
    408: errno.ETIMEDOUT,
    409: errno.ENOENT,
    410: errno.ENOENT,
    412: errno.EEXIST,
    413: errno.EFBIG,
    414: errno.ENAMETOOLONG,
    416: errno.EINVAL,
    423: errno.EBUSY,
    429: errno.EAGAIN,
    500: ECOMM,
    501: errno.ENOSYS,
    502: ECOMM,
    503: errno.EAGAIN,
    504: errno.ETIMEDOUT,
    507: errno.ENOSPC,
}


def errno_for_http(status: int) -> int:
    """The ``errno`` an HTTP failure status stands for (``EIO`` if unknown)."""
    if status in HTTP_ERRNO:
        return HTTP_ERRNO[status]
    return ECOMM if status >= 500 else errno.EIO


# Display wording is deliberately separate from protocol payloads and numeric codes.
_USER_ERRORS: dict[int, str] = {
    errno.ENOENT: "File or folder not found. Check the path and try again.",
    errno.EACCES: "Permission denied. Check that your account can access this file or service.",
    errno.EPERM: "Permission denied. Check that your account can perform this operation.",
    errno.EEXIST: "This path already exists. Choose another path or explicitly enable overwrite.",
    errno.ENOTDIR: "Part of this path is a file, not a folder. Check the path.",
    errno.EISDIR: "This path names a folder, not a file. Choose a file path.",
    errno.ENOTEMPTY: "The folder is not empty. Check its contents before removing it.",
    errno.ENOSPC: "Storage is full. Free space or choose another destination.",
    errno.EDQUOT: "Your storage quota is full. Free space or ask for a larger quota.",
    errno.ENODATA: (
        "The requested file metadata is not available. "
        "Check the attribute name or service configuration."
    ),
    errno.EROFS: "This storage is read-only. Choose a writable destination.",
    errno.EIO: (
        "The file or service could not be read or written. Check the connection and storage."
    ),
    errno.EINVAL: "A setting or path is invalid. Check the command and configuration.",
    errno.ETIMEDOUT: (
        "The request timed out. Check your connection and whether the service is available."
    ),
    errno.ECONNREFUSED: (
        "Connection refused. Check the server name, port and whether it is running."
    ),
    errno.ECONNRESET: (
        "The connection was interrupted. Check whether the transfer completed before retrying."
    ),
    errno.EHOSTUNREACH: "Cannot reach the server. Check the server name and your network or VPN.",
    errno.ENETUNREACH: "The network is unavailable. Check your network or VPN connection.",
    errno.EBUSY: "The file or service is busy. Try again later.",
    errno.EAGAIN: "The service is temporarily unavailable. Try again later.",
    errno.ENOSYS: "This operation is not supported. Check the URL and available client features.",
    errno.ECANCELED: "The operation was canceled.",
}
