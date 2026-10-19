"""The HTTP transport under the http plugin: gfal2's policy over xrdhttp's shared session.

davix is what gfal2 speaks HTTP with. The machinery davix and every other
client need - connections pooled per endpoint and credential, a stale pooled
connection replaced once, the redirect loop, ``Expect: 100-continue``, bodies
read straight off the socket and file bodies sent with ``sendfile`` - is
:class:`xrdhttp.session.Session`, the one session xrdclient and xrdarc use
too. What is gfal2's, and lives here, is the policy it is configured with:

* **credentials** are gfal2's (``get_credentials``): the X.509 proxy is
  presented in every TLS handshake, whatever else is sent, and on top of it
  ``s3``/``gcloud`` requests are signed, ``swift`` ones carry the
  ``X-Auth-Token``, ``cs3`` ones ``[BEARER] TOKEN``, and HTTP/WebDAV ones the
  bearer token found for the URL - a URL-prefix credential, then one keyed
  by the bare host name (FTS sets those), then ``[BEARER] TOKEN`` - or else
  ``USER``/``PASSWD`` Basic auth. A token in the URL's query (``authz=``)
  is left where it is, as davix leaves it;
* the ``Authorization`` follows a redirect as davix sends it along
  (:func:`xrdhttp.redirects.davix_carries_credentials`): the data server is
  part of the same storage element and needs the same token, except over a
  hop from ``https`` down to plain ``http`` on another host. The caller's
  own headers (a TPC's ``TransferHeader*``) go everywhere, as davix's do;
* every hop carries gfal2's standing headers - ``Host`` by davix's port
  rule, the user agent, ``ClientInfo``, ``[HTTP PLUGIN] HEADERS`` - and is
  quoted and, for an object store, signed here (:meth:`HTTPClient._prepare`);
* only a non-empty ``PUT`` asks ``Expect: 100-continue``; a stale reused
  connection is replaced whatever the method (no byte of an answer had
  arrived), and ``[HTTP PLUGIN] KEEP_ALIVE`` is read on every check-in;
* a ``cancel()`` on the context wakes a request blocked on its connection
  (the session's ``watch`` hook registers each checked-out connection).

HTTP statuses are *not* raised here: every caller words its own errors the
way gfal2 does for that operation, with :func:`status_error`, which reads a
status as davix's ``httpcodeToDavixError`` and gfal2's ``davix2errno`` do.
Network failures are :class:`TransportError` (:func:`transport_error`).

The transport is three modules; this one re-exports the other two's names:
:mod:`._target` (where a request goes: wire schemes, :class:`Target`, option
groups), :mod:`._status` (davix's status words and errno,
:class:`TransportError`), and this one (credentials, hops, requests,
uploads). Where to start reading: :meth:`HTTPClient.request`, then
:meth:`HTTPClient._prepare` (one hop's headers and signature).
"""

from __future__ import annotations

import base64
import errno
import functools
import logging
import ssl
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, TypedDict, Unpack

from xrdhttp import session as _http
from xrdhttp.connection import IncompleteRead
from xrdhttp.redirects import davix_carries_credentials
from xrdhttp.session import FileBody as FileBody
from xrdhttp.session import Response as Response
from xrdhttp.wire import ShortFileError

from ...creds import BEARER, check_bearer_token
from ...errors import ECOMM, GError
from ...url import URL, parse
from ._status import MKDIR as MKDIR
from ._status import PUT as PUT
from ._status import HTTPStatusError as HTTPStatusError
from ._status import TransportError as TransportError
from ._status import davix_status as davix_status
from ._status import status_error as status_error
from ._status import status_text as status_text
from ._status import transport_error as transport_error
from ._target import OBJECT_STORES as OBJECT_STORES
from ._target import Target as Target
from ._target import config_group as config_group
from ._target import valid_authority as valid_authority
from ._target import wire_scheme as wire_scheme
from ._target import wire_url as wire_url

if TYPE_CHECKING:
    from ...context import Gfal2Context

__all__ = [
    "BLOCK",
    "OBJECT_STORES",
    "Auth",
    "Body",
    "FileBody",
    "HTTPClient",
    "HTTPStatusError",
    "Response",
    "Signer",
    "Streamed",
    "Target",
    "TransportError",
    "Upload",
    "config_group",
    "davix_status",
    "status_error",
    "status_text",
    "transport_error",
    "wire_scheme",
    "wire_url",
]

_log = logging.getLogger("gfal2")

#: Socket I/O size for bodies: gfal2's ``COPY_BUFFERSIZE``.
BLOCK = 4 << 20
#: How long an upload waits for ``100 Continue`` before sending anyway, as curl does.
#: RFC 9110 section 10.1.1 lets a client go ahead without the interim answer,
#: because HTTP/1.0 servers and some proxies never send one.
CONTINUE_WAIT = 1.0
#: How many redirect hops are followed before giving up (``ELOOP``); a dCache
#: door handing over to a pool node is one or two.
MAX_REDIRECTS = 10
#: Idle connections kept per endpoint and credential.
MAX_IDLE = 16


@dataclass(frozen=True, slots=True)
class Streamed:
    """The body of an upload the caller writes piece by piece, as a signer sees it.

    Its bytes are not known when the head is signed, so an S3 signature
    covers ``UNSIGNED-PAYLOAD`` rather than a hash of them (the hash of an
    empty body, which a real S3 refuses once the bytes arrive).
    """

    length: int


#: Every body a signer may be shown: one in memory, a slice of a file, or a
#: body still to be streamed.
Body = bytes | bytearray | memoryview | FileBody | Streamed


class Signer(Protocol):
    """What signs object-store requests (S3 SigV4 headers, GCS signed URLs).

    Implemented by :mod:`._s3`, :mod:`._gcloud` and :mod:`._swift`; the
    client calls :meth:`target` and then :meth:`sign` for every hop of a
    request, redirects included, because a signature covers the host it is
    sent to.
    """

    def target(self, method: str, target: Target) -> Target:
        """Where the request really goes (a virtual-host bucket, a signed GCS query)."""
        ...

    def sign(
        self, method: str, target: Target, headers: Mapping[str, str], body: Body | None
    ) -> dict[str, str]:
        """Headers to add (``Authorization``, ``x-amz-date``, ...) for this exact request."""
        ...

    def presign(self, method: str, url: str, expires: int = 3600) -> str:
        """A URL anyone can use for ``expires`` seconds: gfal2's ``SIGNED_URL`` xattrs and TPC."""
        ...


@dataclass
class Auth:
    """How requests for one URL are authorised.

    ``headers`` (a bearer token, Basic auth, a Swift token) are sent only
    where davix would forward them (see :func:`xrdhttp.redirects.davix_carries_credentials`);
    ``tls`` carries the X.509 proxy, presented in every handshake; ``signer``
    signs each hop of an object-store request.
    """

    headers: dict[str, str] = field(default_factory=dict)
    tls: ssl.SSLContext | None = None
    signer: Signer | None = None


class RequestOptions(TypedDict, total=False):
    """The keyword options of :meth:`HTTPClient.request`; every one may be left out.

    A ``TypedDict`` rather than six keyword parameters so the one place that
    says what a request can carry is also where each option is explained;
    mypy checks every caller's keywords against it all the same.
    """

    #: Sent on top of the standing headers (``[HTTP PLUGIN] HEADERS``, auth).
    headers: Mapping[str, str] | None
    #: The request body; a :class:`FileBody` goes out with ``sendfile``.
    body: _http.Body | None
    #: Per-socket-operation timeout in seconds (default 300, gfal2's own).
    timeout: float
    #: Follow 3xx redirects (default ``True``); ``False`` hands the 3xx back.
    follow: bool
    #: The URL credentials are looked up for, when not the request's own
    #: (a TPC's far side, a tape API root under the file's endpoint).
    cred_url: str | None
    #: Credentials to use as they are, bypassing the lookup altogether.
    auth: Auth | None


class _Refused(ValueError):
    """A URL davix refuses, in the session's vocabulary; the ``GError`` is its cause."""


def _route(url: str) -> _http.Route:
    """Where ``url`` goes on the wire, for any gfal scheme.

    A hop the client prepared is already ``http(s)://`` and quoted
    (:meth:`HTTPClient._prepare`), and goes as written; a ``Location`` still
    in a gfal scheme (``davs://``, ``s3s://``) is read by :class:`Target`, so
    one davix refuses is refused in davix's words.
    """
    if url.partition("://")[0].lower() in ("http", "https"):
        return _http.Route.of(url)
    try:
        target = Target.of(url)
    except GError as exc:
        raise _Refused(exc.message) from exc
    return _http.Route(target.scheme, target.host, target.port, target.path)


def _carries(origin: str, target: str) -> bool:
    """davix's rule for the ``Authorization`` on a redirect, over gfal URLs."""
    return davix_carries_credentials(Target.of(origin).base, Target.of(target).base)


def _expects(method: str, length: int | None) -> bool:
    """Only a non-empty ``PUT`` waits for the go-ahead: that is where a redirect costs a body."""
    return method == "PUT" and bool(length)


class _Errors(_http.Errors):
    """gfal2's words for what the session reports; statuses stay the callers' to word."""

    def transport(self, failure: _http.Failure) -> Exception:
        """A :class:`TransportError` (davix's network errors), or ``EIO`` for a short local file.

        A file that shrank under an upload is the source's failure, not the
        network's, so it is a plain ``GError`` that no retry repeats.
        """
        error = failure.error
        if isinstance(error, ShortFileError):
            return GError(str(error.strerror), errno.EIO)
        if isinstance(error, IncompleteRead):
            # A body cut short: say how much never came, as the ranged
            # download's resume logic and gfal2's message both put it.
            message = (
                f"Connection terminated abruptly: {error.expected} bytes of the body never arrived"
            )
            return TransportError(message, ECOMM)
        return transport_error(error)

    def redirect(
        self, method: str, url: str, problem: str, error: Exception | None = None
    ) -> Exception:
        """``ELOOP`` for a chain too long; a refused ``Location`` as davix words it."""
        if error is not None and isinstance(error.__cause__, GError):
            return error.__cause__
        if error is not None:
            return GError(f" {url} is not a valid HTTP or Webdav URL", errno.EIO)
        return GError(f"Too many redirections for {url}", errno.ELOOP)


_ERRORS = _Errors()


class HTTPClient:
    """Thread-safe pooled HTTP for one plugin instance, over one shared session.

    Requests run on the caller's thread; the pool and its lock are the
    session's. Parallel download streams each get a connection of their own
    (checkouts are not limited, only idle ones).
    """

    def __init__(self, context: Gfal2Context, group: str = "HTTP PLUGIN") -> None:
        """A client reading its options from ``group`` of ``context``.

        ``group`` is ``HTTP PLUGIN`` for gfal2's davix plugin; the context
        supplies credentials, TLS contexts, the user agent and ``cancel()``.
        """
        self.context = context
        self.group = group
        #: S3 credentials for a URL, when there are any; set by the plugin.
        self.signer_for: Callable[[URL], Signer | None] = lambda url: None
        policy = _http.Policy(
            connect_timeout=None,  # gfal2 bounds the handshake by the request's timeout
            keep_alive=lambda: self.keep_alive,
            expects=_expects,
            continue_wait=CONTINUE_WAIT,
            route=_route,
            max_idle=MAX_IDLE,
            retry=_http.RetryPolicy(replay_unanswered=True),
            redirects=_http.RedirectPolicy(MAX_REDIRECTS, _carries),
            # ``[HTTP PLUGIN] INSECURE`` is a setting davix obeys silently.
            warn_unverified=False,
        )
        self._session = _http.Session(policy=policy, errors=_ERRORS, watch=self._watch)

    # -- pool --------------------------------------------------------------------

    @property
    def keep_alive(self) -> bool:
        """``[HTTP PLUGIN] KEEP_ALIVE`` (default on); off, every request gets a new connection.

        Read on every check-in rather than once, so a change made with
        ``set_opt_boolean`` applies from the next request on.
        """
        return bool(self.context.options.boolean(self.group, "KEEP_ALIVE", True))

    def _watch(self, abort: Callable[[], None]) -> Callable[[], None]:
        """Register a checked-out connection's abort for the context's ``cancel()``.

        Raises the context's ``ECANCELED`` while a ``cancel()`` is under way:
        the session then puts the connection back, nothing having been sent.
        """
        token = self.context.register_abort(abort)
        return functools.partial(self.context.unregister_abort, token)

    def close(self) -> None:
        """Close every idle connection; those checked out are closed by their owners.

        The client stays usable: a request made afterwards opens a new
        connection, as a context reused after ``free()`` expects.
        """
        self._session.clear()

    def idle_count(self) -> int:
        """How many connections wait in the pools (tests pin keep-alive with it)."""
        return self._session.idle_count()

    # -- credentials ---------------------------------------------------------------

    def tls(self, url: str) -> ssl.SSLContext:
        """The TLS context for ``url``, with its X.509 credential when that loads.

        One that does not (a missing or unreadable file) is left out with a
        warning, as gfal2's ``get_certificate`` does: the request goes ahead
        without it, so a token or a server that asks for no certificate
        still works.
        """
        try:
            return self.context.ssl_context(url, group=self.group)
        except GError as exc:
            _log.warning("Could not load the user credentials: %s", exc.message)
            return self.context.ssl_context(url, group=self.group, x509=False)

    def auth(self, url: str) -> Auth:
        """How to authorise requests for ``url``, as gfal2's ``get_credentials`` does.

        The TLS context always carries the X.509 credential, if there is one:
        gfal2 presents it whatever else it sends.
        """
        Target.of(url)  # a URL davix refuses fails as such, before any lookup
        parsed = parse(url)
        tls = self.tls(url)
        scheme = parsed.scheme.partition("+")[0]
        if scheme in ("cs3", "cs3s"):
            configured = self.context.options.string("BEARER", "TOKEN")
            check_bearer_token(configured)
            return Auth({"Authorization": f"Bearer {configured}"} if configured else {}, tls)
        query = parsed.query_dict()
        if "X-Amz-Signature" in query or "AWSAccessKeyId" in query:
            return Auth(tls=tls)  # a pre-signed URL carries its own credential
        if scheme in OBJECT_STORES:
            return Auth(tls=tls, signer=self.signer_for(parsed))
        token = self.bearer(url, parsed)
        if token:
            check_bearer_token(token)
            return Auth({"Authorization": f"Bearer {token}"}, tls)
        user, password = _basic(self.context, url, parsed)
        if user:
            secret = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
            return Auth({"Authorization": f"Basic {secret}"}, tls)
        return Auth(tls=tls)

    def bearer(self, url: str, parsed: URL) -> str | None:
        """The bearer token for ``url``: by URL prefix, then by bare host, then configured."""
        value, _ = self.context.credentials.get(BEARER, url)
        if not value:
            value, _ = self.context.credentials.get(BEARER, parsed.host)
        return value or self.context.bearer_token(url) or None

    # -- headers -------------------------------------------------------------------

    def standing_headers(self, target: Target, origin: URL) -> dict[str, str]:
        """What every request carries: identity, ClientInfo, configured extras.

        The extras are ``HEADERS`` from the endpoint's own group (``[DAV:HOST]``
        for the URL the caller named, not a redirect's), and only when it has
        none, from ``[HTTP PLUGIN]``.
        """
        headers = {"Host": target.host_header, "User-Agent": self.context.user_agent_string()}
        info = self.context.client_info_string()
        if info:
            headers["ClientInfo"] = info
        if not self.keep_alive:
            headers["Connection"] = "close"
        options = self.context.options
        group = config_group(str(origin))
        if not options.has(group, "HEADERS"):
            group = self.group
        for item in options.string_list(group, "HEADERS"):
            name, sep, value = item.partition(":")
            if sep and name.strip():
                headers[name.strip()] = value.strip()
        return headers

    def _prepare(
        self, auth: Auth, caller: Mapping[str, str] | None, length: int | None
    ) -> Callable[[_http.Hop], None]:
        """The session's per-hop hook: gfal2's headers, the davix quoting, the signature.

        Each hop - redirects included - gets the standing headers for the
        URL the caller named, then what the session decided (the
        ``Authorization`` where davix carries it, ``Content-Length``,
        ``Expect``), then the caller's own headers, which go everywhere as
        davix's do. The hop's URL becomes the target as it goes on the wire,
        quoted as davix quotes it (or as SigV4 does, for S3), and an object
        store's signer signs last, so the signature covers every header
        sent. ``length`` is a streamed upload's: its body is signed as
        :class:`Streamed`, never as the empty body the hop has.
        """
        signer = auth.signer
        first: list[Target] = []

        def prepare(hop: _http.Hop) -> None:
            """Rewrite ``hop`` in place; see :meth:`_prepare`."""
            target = Target.of(hop.url, s3=signer is not None)
            if not first:
                first.append(Target.of(hop.origin, s3=signer is not None))
            headers = self.standing_headers(target, first[0].url)
            headers.update(hop.headers)
            headers.update(caller or {})
            if signer is not None:
                body = hop.body if length is None else Streamed(length)
                target = signer.target(hop.method, target)
                headers.update(signer.sign(hop.method, target, headers, body))
            hop.headers = headers
            hop.url = f"{target.base}{target.path}"

        return prepare

    # -- requests ------------------------------------------------------------------

    def request(self, method: str, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Send one request (following redirects) and return the unread response.

        The redirect loop is the session's, which also turns a ``303`` into
        a bodiless ``GET`` as RFC 9110 section 15.4.4 says; each hop is
        re-targeted, re-headed and re-signed by :meth:`_prepare`.
        Credentials are looked up once, for the first URL (or ``cred_url``):
        a redirect to a data server does not change whose request it is.
        Statuses are not checked - the caller words them - and the caller
        must read or :meth:`~xrdhttp.session.Response.close` what comes back.
        """
        auth = options.get("auth")
        auth = auth if auth is not None else self.auth(options.get("cred_url") or url)
        return self._session.request(
            method,
            url,
            body=options.get("body"),
            auth=_http.Auth(
                auth.headers, auth.tls, self._prepare(auth, options.get("headers"), None)
            ),
            timeout=options.get("timeout", 300.0),
            follow=options.get("follow", True),
        )

    # -- streamed uploads ------------------------------------------------------------

    def upload(
        self,
        url: str,
        length: int,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float = 300.0,
        cred_url: str | None = None,
    ) -> Upload:
        """Start a ``PUT`` of ``length`` bytes that the caller then writes piecemeal.

        Redirects and refusals are dealt with by the session before any of
        the body is sent, courtesy of ``Expect: 100-continue``.
        """
        auth = self.auth(cred_url or url)
        prepare = self._prepare(auth, headers, length)
        upload = self._session.upload(
            "PUT", url, length, auth=_http.Auth(auth.headers, auth.tls, prepare), timeout=timeout
        )
        return Upload(upload, length)


class Upload:
    """A ``PUT`` in flight: :meth:`write` the body, then :meth:`finish`.

    This is what gfal2's ``open(O_WRONLY)`` on an HTTP URL streams through:
    the ``PUT`` carries a ``Content-Length`` and is never chunked, so the
    length is declared up front and writing past it is ``EFBIG``. The
    session's :class:`xrdhttp.session.Upload` does the sending; this wrapper
    words its refusals as gfal2 does. Not thread-safe; one writer at a time,
    as with any file handle.
    """

    def __init__(self, upload: _http.Upload, length: int) -> None:
        """Wrap the session's upload of ``length`` bytes, its head already sent."""
        self._upload = upload
        self._length = length

    @property
    def early(self) -> Response | None:
        """The server's answer, if it gave one before the whole body went."""
        return self._upload.early

    @property
    def done(self) -> bool:
        """Whether the upload was answered, finished or abandoned."""
        return self._upload.done

    def write(self, data: bytes | bytearray | memoryview) -> None:
        """Send the next part of the body; past the declared size is ``EFBIG``.

        A server that hangs up mid-body usually said why first (a quota, a
        permission): that answer is kept for :meth:`finish` and later writes
        are dropped, so the caller sees the server's status rather than
        ``EPIPE``.
        """
        upload = self._upload
        if upload.early is None and upload.sent + memoryview(data).nbytes > self._length:
            raise GError(
                f"Writing past the declared size of {upload.url} ({self._length} bytes)",
                errno.EFBIG,
            )
        upload.write(data)

    def finish(self) -> Response:
        """The server's answer, once the whole body has gone; a short body is ``EIO``."""
        upload = self._upload
        if upload.early is None and upload.sent != self._length:
            upload.abort()
            raise GError(
                f"Upload of {upload.url} closed after {upload.sent} of {self._length} bytes",
                errno.EIO,
            )
        return upload.finish()

    def abort(self) -> None:
        """Drop the connection, which is how an HTTP upload is abandoned."""
        self._upload.abort()


def _basic(context: Gfal2Context, url: str, parsed: URL) -> tuple[str, str]:
    """``USER``/``PASSWD`` from the credential store, else the URL's userinfo.

    gfal2's order: a credential set for the URL (``cred_set``) wins over a
    ``user:password@`` in the URL itself, which is percent-decoded as
    RFC 3986 section 3.2.1 encodes it.
    """
    user, _ = context.credentials.get("USER", url)
    if user:
        password, _ = context.credentials.get("PASSWD", url)
        return user, password
    info = parsed.userinfo
    if info:
        name, _, secret = info.partition(":")
        return urllib.parse.unquote(name), urllib.parse.unquote(secret)
    return "", ""
