"""HTTP failures as gfal2 reports them: davix's status words and errno, and network errors.

HTTP statuses are *not* raised by the client: every caller words its own
errors the way gfal2 does for that operation, with :func:`status_error`, which
reads a status as davix's ``httpcodeToDavixError`` and gfal2's
``davix2errno`` do. A failure below HTTP - a refused connection, a TLS alert,
a body cut short - is a :class:`TransportError` from :func:`transport_error`.

Split out of :mod:`._client`, which re-exports every name here.
"""

from __future__ import annotations

import errno
import os
import socket
import ssl

from xrdhttp.connection import HTTPException

from ...errors import ECOMM, GError

__all__ = [
    "MKDIR",
    "PUT",
    "HTTPStatusError",
    "TransportError",
    "davix_status",
    "status_error",
    "status_text",
    "transport_error",
]


class HTTPStatusError(GError):
    """A GError that came from an HTTP status; ``status`` says which.

    Several statuses share an errno (``ENOENT`` is ``303``, ``404`` and
    ``410``), so ``status`` keeps the one that was actually answered for
    anything that needs more than the errno - a caller, a log, a test.
    """

    def __init__(self, message: str, code: int, status: int) -> None:
        """``message`` and ``code`` as for any GError; ``status`` the HTTP status behind them."""
        super().__init__(message, code)
        self.status = status


class TransportError(GError):
    """A GError that came from the network, not from the server's answer.

    Its own class because the retry rules hinge on it: a transport failure
    of an idempotent request may be retried (``CONN_RETRY``), a server's
    answer never is.
    """


#: The scope in which davix reads 405 and 409 as a directory question.
MKDIR = "mkdir"
#: An upload: a 409 there means the parent collection is missing (RFC 4918).
PUT = "put"

#: The errno gfal2 gives davix's "Server Error" statuses (see :data:`_DAVIX`);
#: a platform without ``EHOSTDOWN`` falls back to ``EIO``.
_EHOSTDOWN = getattr(errno, "EHOSTDOWN", errno.EIO)

#: davix's ``httpcodeToDavixError`` for everything that is not a success,
#: with gfal2's ``davix2errno`` already applied: status -> (errno, phrase).
_DAVIX: dict[int, tuple[int, str]] = {
    **dict.fromkeys((401, 402, 407), (errno.EACCES, "Authentication Error")),
    **dict.fromkeys((303, 404, 410), (errno.ENOENT, "File not found")),
    **dict.fromkeys((408, 504), (errno.ETIMEDOUT, "Operation timeout")),
    **dict.fromkeys((403, 423), (errno.EPERM, "Permission refused")),
    **dict.fromkeys((400, 411, 412, 413, 414, 415, 424, 501), (_EHOSTDOWN, "Server Error")),
    507: (errno.EIO, "Insufficient Storage"),
    **dict.fromkeys(
        (300, 301, 302),
        (errno.ENOSYS, "Redirection requested, transparent redirection disabled"),
    ),
}


def davix_status(status: int, scope: str = "") -> tuple[int, str]:
    """``(errno, phrase)`` for a failed ``status``, as gfal2 reports it through davix.

    Only ``mkdir`` reads 405 and 409 differently: there they mean the
    directory exists and its parent does not, elsewhere a refusal and an
    existing file. Anything davix has no words for is ``EIO``.
    """
    if status == 405:
        if scope == MKDIR:
            return errno.EEXIST, "Method Not Allowed, File Exist"
        return errno.EPERM, "Method Not Allowed, Permission refused"
    if status == 409:
        if scope == MKDIR:
            return errno.ENOENT, "Conflict, File not Found"
        if scope == PUT:
            # davix's words, but not its EEXIST: a PUT's 409 is a missing
            # parent, and "File exists" would read as an existing target to
            # anything matching on it (the ATLAS pilot does). gfal2 itself
            # reports a stale errno here.
            return errno.ENOENT, "Conflict, File Exist"
        return errno.EEXIST, "Conflict, File Exist"
    return _DAVIX.get(status, (errno.EIO, f"Unexpected server error: {status}"))


def status_text(status: int, scope: str = "") -> str:
    """davix's wording: ``HTTP 404 : File not found `` (trailing space and all)."""
    return f"HTTP {status} : {davix_status(status, scope)[1]} "


def status_error(
    status: int, *, prefix: str = "", suffix: str = "", scope: str = ""
) -> HTTPStatusError:
    """The GError gfal2 raises for a failed ``status``: ``<prefix>HTTP <n> : <phrase> <suffix>``.

    ``prefix`` and ``suffix`` are the operation's own words around davix's
    (gfal2's ``"Failed to delete: "``, a ``bucket creation failure``);
    ``scope`` selects the 405/409 reading (see :func:`davix_status`). The
    space before ``suffix`` is always there, as in gfal2's messages.
    """
    code, phrase = davix_status(status, scope)
    return HTTPStatusError(f"{prefix}HTTP {status} : {phrase} {suffix}", code, status)


def transport_error(exc: BaseException) -> TransportError:
    """A network failure as the GError gfal2 would raise for it.

    The errno is what gfal2 reports for the same failure through davix:
    ``ETIMEDOUT``,
    ``ECONNREFUSED``, ``EHOSTUNREACH`` for a name that does not resolve,
    ``EACCES`` for a certificate that does not verify, and ``ECOMM`` for a
    connection cut off. The order of the checks matters: the specific
    ``OSError`` subclasses come before the generic errno fallback, and
    ``SSLCertVerificationError`` before the ``SSLError`` it subclasses.
    """
    if isinstance(exc, TransportError):
        return exc
    if isinstance(exc, TimeoutError):
        return TransportError("Connection timed out", errno.ETIMEDOUT)
    if isinstance(exc, ConnectionRefusedError):
        return TransportError("Could not connect to server", errno.ECONNREFUSED)
    if isinstance(exc, socket.gaierror):
        return TransportError("Domain name resolution failed", errno.EHOSTUNREACH)
    if isinstance(exc, ssl.SSLCertVerificationError):
        return TransportError(f"SSL handshake failed: {exc.verify_message}", errno.EACCES)
    if isinstance(exc, ssl.SSLError):
        return TransportError(f"SSL error: {getattr(exc, 'reason', None) or exc}", ECOMM)
    if isinstance(exc, (HTTPException, ConnectionResetError, BrokenPipeError)):
        return TransportError(f"Connection terminated abruptly: {exc}", ECOMM)
    if isinstance(exc, OSError) and exc.errno:
        return TransportError(os.strerror(exc.errno), exc.errno)
    return TransportError(f"Connection error: {exc}", ECOMM)
