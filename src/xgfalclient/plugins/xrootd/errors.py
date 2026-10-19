"""How a failure from below looks to gfal2: its ``errno`` and its wording.

gfal2's xrootd plugin words a failure in one of three ways, depending on
the call: ``XrdPosix``'s ``description (strerror)`` for most of the
namespace, XrdCl's ``ToStr`` for the calls it makes on XrdCl directly
(``chmod``, copies), and the terser ``ToString`` for staging. Scripts match
on all three, so :class:`Failure` carries each, and :func:`describe` is the
one place an xrdclient exception (or the socket error under it) is
classified the way XrdCl classifies the corresponding status.

The ``kXR_*`` to ``errno`` table is ``XProtocol::toErrno``, which xrdclient
publishes as :data:`xrdclient.errors.KXR_ERRNO`; it is re-exported here
under the name this module has always offered it by.

Callers pick the spelling, not this module: :func:`posix_error` for the
``XrdPosix``-backed namespace and I/O calls, :func:`status_error` for the
XrdCl-backed ones, :func:`each` for staging, :class:`CopyError` inside a
copy (which :mod:`.copy` turns into gfal2's copy messages). Changing a
string here changes what users' scripts see; the tests pin each one.
"""

from __future__ import annotations

import errno
import os
import socket
from collections.abc import Iterator, Sequence

from xrdclient import errors as xe
from xrdclient.errors import KXR_ERRNO as KXR_ERRNO  # re-exported: this name has always been here
from xrdclient.errors import errno_for

from ...errors import GError, not_supported_url

#: ``errno`` numbers a platform may lack, as ``XProtocol.hh`` falls back
#: for them - read off the table rather than worked out again.
EAUTH = errno_for(xe.kXR_AuthFailed)
EBADRQC = errno_for(xe.kXR_InvalidRequest)
ENOATTR = errno_for(xe.kXR_AttrNotFound)
ETIME = errno_for(xe.kXR_TimerExpired)

#: What a vendor opcode sounds like on a server that does not have it.
NO_SUCH_REQUEST = (xe.kXR_InvalidRequest, xe.kXR_Unsupported)

#: gfal2 masks these as ``ECOMM`` when a staging poll fails, so that a
#: network hiccup reads as "try again" rather than as the file's fault.
NETWORK_ERRNOS = frozenset(
    {
        errno.EHOSTUNREACH,
        errno.ENOTSOCK,
        errno.ETIMEDOUT,
        errno.ENOTCONN,
        errno.ECONNRESET,
        errno.ECONNREFUSED,
        errno.ENETRESET,
        errno.ECONNABORTED,
    }
)

#: Client-side failures XrdCl gives a status of their own, most specific
#: first: the ``errno`` ``XrdPosix`` maps that status to, and ``ToString``.
_CLIENT_FAILURES: tuple[tuple[type[BaseException], int, str], ...] = (
    (xe.ChecksumMismatchError, errno.EILSEQ, "[ERROR] Checksum error"),
    (xe.AuthenticationError, EAUTH, "[FATAL] Auth failed"),
    (xe.RedirectLimitError, errno.ELOOP, "[FATAL] Redirect limit has been reached"),
    (xe.TooLargeError, errno.EFBIG, "[ERROR] Invalid operation"),
    (xe.ProtocolError, errno.EPROTO, "[FATAL] Invalid message"),
    (xe.WaitLimitError, errno.EAGAIN, "[ERROR] Retry"),
    (TimeoutError, errno.ETIMEDOUT, "[ERROR] Operation expired"),
)
# Consulted before describe()'s ConnectionError fallback, which matters:
# xrdclient's WaitLimitError and TimeoutError are transient ConnectionErrors
# too, and would otherwise read as a reset connection.


def _chain(exc: BaseException) -> Iterator[BaseException]:
    """``exc`` and everything it was raised from, without looping.

    ``__cause__`` first (an explicit ``raise ... from``), else the implicit
    ``__context__``; a set of ids guards against the cycle a handler that
    re-raises its own context can leave behind.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def e2t(code: int) -> str:
    """``XrdSysE2T``: ``strerror`` with its first letter lowered.

    XRootD lowers it so the text reads as the tail of a sentence
    (``Error response: no such file or directory``); gfal2's messages carry
    that spelling, and so do these.
    """
    text = os.strerror(code)
    return text[:1].lower() + text[1:]


class Failure:
    """What a failure from below looks like to gfal2, in each of its spellings.

    ``code`` is the ``errno``. ``to_str`` is ``XrdCl::XRootDStatus::ToStr``,
    which gfal2 puts in the messages of the calls it makes on XrdCl directly
    (``chmod``, copies) and which scripts match on: ``[ERROR] Server
    responded with an error: [3011] ...``. ``to_string`` is ``ToString``, the
    terser ``[ERROR] Error response: no such file or directory`` the staging
    calls use, and ``message`` is the server's bare text.
    """

    __slots__ = ("code", "message", "to_str", "to_string")

    def __init__(self, code: int, to_string: str, message: str, to_str: str = "") -> None:
        """``to_str`` defaults to ``ToStr``'s usual ``"<ToString>: <message>"`` joining."""
        self.code = code
        self.to_string = to_string
        self.message = message
        self.to_str = to_str or (f"{to_string}: {message}" if message else to_string)


class CopyError(Exception):
    """A copy's failure worded as XrdCl words it, and the end it happened at.

    ``no_parent`` marks a pull's destination refusing its open for want of
    a parent directory, which the copy repairs (see :mod:`.copy`).
    """

    def __init__(self, failure: Failure, end: str, *, no_parent: bool = False) -> None:
        """``end`` is ``"source"``, ``"destination"`` or ``""`` (XrdCl names no end)."""
        super().__init__(failure.to_str)
        self.failure = failure
        self.end = end
        self.no_parent = no_parent


def unsupported(text: str) -> CopyError:
    """XrdCl's ``errNotSupported`` with its own words, and no end named."""
    return CopyError(Failure(errno.ENOTSUP, "[ERROR] Operation not supported", text), "")


def local_failure(exc: OSError) -> Failure:
    """A local file's ``OSError`` as XrdCl's ``errLocalError`` prints it."""
    code = exc.errno or errno.EIO
    return Failure(code, "[ERROR] Local error", "", f"[ERROR] Local error: {e2t(code)}: ")


def describe(exc: BaseException) -> Failure:
    """Classify a failure from xrdclient (or the socket under it) as XrdCl would.

    Total: every exception gets a :class:`Failure`, ``EIO`` and
    ``[ERROR] Unknown error`` when nothing more specific fits, so callers
    never need a fallback of their own.

    A server's answer is its code through ``XProtocol::toErrno``; a failure
    of the client's own is the status XrdCl would have, found first by type
    and then down the cause chain, where the socket error that started it
    says more than whatever xrdclient wrapped it in.
    """
    if isinstance(exc, CopyError):
        return exc.failure
    if isinstance(exc, xe.ServerError):
        code = errno_for(exc.code)
        return Failure(
            code,
            f"[ERROR] Error response: {e2t(code)}",
            exc.message,
            # ToStr ends a server's answer with a newline, and gfal2 keeps it.
            f"[ERROR] Server responded with an error: [{exc.code}] {exc.message}\n",
        )
    detail = str(exc)
    for kind, code, text in _CLIENT_FAILURES:
        if isinstance(exc, kind):
            return Failure(code, text, detail)
    found = _socket_failure(exc, detail)
    if found is not None:
        return found
    if isinstance(exc, ConnectionError):
        return Failure(errno.ECONNRESET, "[FATAL] Connection error", detail)
    if isinstance(exc, (ValueError, TypeError)):
        return Failure(errno.EINVAL, "[ERROR] Invalid arguments", detail)
    return Failure(errno.EIO, "[ERROR] Unknown error", detail)


def _socket_failure(exc: BaseException, detail: str) -> Failure | None:
    """The socket's own failure somewhere down ``exc``'s cause chain, if there is one.

    A name that does not resolve is XrdCl's ``errInvalidAddr`` with
    ``EHOSTUNREACH``; a refused connection keeps its own ``errno``. The
    xrdclient errors are excluded although they are ``OSError`` subclasses: their
    ``errno`` is the server's or xrdclient's verdict, already classified.
    """
    for link in _chain(exc):
        if isinstance(link, socket.gaierror):
            return Failure(errno.EHOSTUNREACH, "[FATAL] Invalid address", "")
        if isinstance(link, OSError) and not isinstance(link, xe.XRootDError) and link.errno:
            if isinstance(link, ConnectionRefusedError):
                return Failure(link.errno, "[FATAL] Connection error", "")
            return Failure(link.errno, "[FATAL] Socket error", detail)
    return None


def posix_error(description: str, exc: BaseException, code: int | None = None) -> GError:
    """``description (strerror)``: how every ``XrdPosix``-backed call words a failure."""
    found = describe(exc).code if code is None else code
    return GError(f"{description} ({os.strerror(found)})", found)


def status_error(
    prefix: str,
    exc: BaseException,
    *,
    strerror: bool = True,
    terse: bool = False,
    end: str = "",
) -> GError:
    """``prefix`` and the XrdCl status (``ToStr``, or ``ToString`` if ``terse``).

    ``end`` names the side of a copy that failed, which XrdCl's copy process
    appends to the server's text: ``... no such file or directory (source)``.
    """
    failure = describe(exc)
    text = failure.to_string if terse else failure.to_str
    if end:
        newline = "\n" if text.endswith("\n") else ""
        text = f"{text.rstrip(chr(10))} ({end}){newline}"
    tail = f" ({os.strerror(failure.code)})" if strerror else ""
    return GError(f"{prefix}{text}{tail}", failure.code)


def vendor_error(url: str, description: str, exc: BaseException) -> GError:
    """A link operation's failure; no such opcode means no such operation, as in gfal2.

    ``kXR_symlink`` and ``kXR_readlink`` are vendor extensions: a stock
    ``xrootd`` answers them ``kXR_InvalidRequest`` or ``kXR_Unsupported``,
    which gfal2 reports as the URL's protocol not supporting the call
    (``EPROTONOSUPPORT``) rather than as a failure of this file.
    """
    if isinstance(exc, xe.ServerError) and exc.code in NO_SUCH_REQUEST:
        return not_supported_url(url)
    return posix_error(description, exc)


def each(urls: Sequence[str], failure: Failure) -> list[GError | None]:
    """One staging call's failure, once per file it was asked about."""
    return [GError(failure.to_string, failure.code) for _ in urls]
