"""The one exception gfal2 raises, and the helpers that build it.

gfal2 reports every failure as a ``GError``: an ``errno`` value in ``code``
and a human sentence in ``message``. Code written against the C-backed
bindings catches ``gfal2.GError`` and switches on ``e.code``, so that is
exactly the shape here - ``args`` is ``(message, code)`` and ``str()`` is the
message alone, as it is there.

It deliberately does not subclass :class:`OSError`: a ``GError`` is a plain
``Exception``, as in gfal2, so an ``except OSError`` in caller code does not
start swallowing grid failures it never used to see.
"""

from __future__ import annotations

import errno
import os
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

    def __init__(self, message: str = "", code: int = 0) -> None:
        super().__init__(message, code)
        self.message = message
        self.code = code

    def __str__(self) -> str:
        return self.message

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
