"""The third-party copy modes, ``3rd pull`` and ``3rd push``: an HTTP ``COPY``.

A third-party ``COPY`` carries what davix sends: ``Source`` or
``Destination``, ``X-Number-Of-Streams``, ``Secure-Redirection``, a
``RequireChecksumVerification: false`` where gfal2 sends one (it never
sends ``true``), ``SciTag``, and the far side's credential: a bearer token
in ``TransferHeaderAuthorization`` with ``Credential: none`` - a
macaroon the far SE mints when ``RETRIEVE_BEARER_TOKEN`` is on (by default
whenever we hold an ambient token, which an SE may refuse on this leg), or
the user-set token itself when no mint is possible - else ``Credential:
gridsite`` when the far side is HTTPS (the active end may then ask for a
delegated proxy, ``X-Delegate-To``), else ``Credential: none`` and
``X-No-Delegate: true``. An S3 or GCS far side gets a
pre-signed URL and ``Copy-Flags: NoHead``. The response streams
performance markers, which become ``transfer.progress``, and ends
``success``, ``failure``/``failed`` or ``aborted``; errors are worded and
numbered as davix words them.

``[CORE] RESOLVE_DNS`` makes the copy use one address of each endpoint's
DNS alias, by its reverse-resolved name, as gfal2 does (DMC-1348).

The performance-marker stream is read by xrdhttp
(:func:`xrdhttp.tpc.follow_markers`), which xrdclient's ``COPY`` uses too;
what each marker and outcome means to gfal2 is decided in :func:`_follow`.
The far side's token rules - how long a minted macaroon lives
(:func:`~xrdhttp.tpc.token_minutes`), how a token and a stream count are
spelt (:func:`~xrdhttp.tpc.add_token`, :func:`~xrdhttp.tpc.add_streams`) -
are xrdhttp's too; the choice of credential, the checksum header and the
davix-only headers stay here, because they are gfal2's policy, not the
protocol's (xrdhttp's :func:`~xrdhttp.tpc.copy_headers` spells a request
with ``Overwrite`` and no ``Secure-Redirection``, which davix never sends).

The protocol is the WLCG HTTP-TPC one (the "HTTP Third Party Copy"
technical note of the DOMA TPC working group, as dCache, StoRM, XRootD's
XrdTpc and EOS implement it): the client sends ``COPY`` to the *active*
end - the destination for a pull, the source for a push - naming the
*passive* end in ``Source``/``Destination``. Every ``TransferHeader<X>``
header is forwarded by the active end as ``<X>`` on its own request to the
passive end, which is how a bearer token for the far side travels without
the client ever talking to it. ``Credential: gridsite`` asks the active end
to obtain a delegated X.509 proxy for the far side (it names its gridsite
delegation service in ``X-Delegate-To``, answered by :mod:`._delegation`);
``Credential: none`` says it needs none. The ``COPY`` answers ``202`` at
once and then streams text: ``Perf Marker`` blocks every few seconds
(``Timestamp``, ``Stripe Index``, ``Stripe Bytes Transferred``,
``Total Stripe Count``, ``End``) and a final ``success`` or
``failure: <reason>`` line - so the copy's success is in the *body*, not
the status. A connection that closes before that line leaves the outcome
unknown, which is an error: the far side may or may not have the file.

Nothing here owns state between copies; one call is one ``COPY`` on one
pooled connection, run on the copy's own thread.
"""

from __future__ import annotations

import errno
from typing import TYPE_CHECKING

from xrdhttp.tpc import MAX_LINE, add_streams, add_token, token_minutes

from ...errors import GError
from ...transfer import Transfer
from ...url import parse, scheme_of
from ._client import Response, status_error, wire_url
from ._copy_common import (
    _CHECKSUM_SOURCE,
    _CHECKSUM_TARGET,
    HTTP_SCHEMES,
    PULL,
    PUSH,
    _deadline_timeout,
    _se_boolean,
    resolved,
)
from ._token import se_token

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["third_party"]

#: The longest line believed to be a performance marker
#: (:data:`xrdhttp.tpc.MAX_LINE`). A server that streams something else (a
#: misrouted ``GET``'s body) is cut off here rather than buffered whole.
MAX_MARKER_LINE = MAX_LINE


def _passive_credential(
    plugin: HTTPPlugin, far: str, write: bool, transfer: Transfer
) -> dict[str, str]:
    """The headers that let the active end reach ``far`` (gfal2's ``get_tpc_params``).

    ``write`` is whether the far side is written (a push): it decides the
    activities of a token minted for it. The precedence is gfal2's:

    * ``cs3`` (CERNBox/Reva): the configured ``[BEARER] TOKEN``, forwarded;
    * WebDAV/HTTP: a token from :func:`_far_token`, which also says
      ``Credential: none`` - with a token, no proxy needs delegating;
    * object stores (S3, GCS, Swift) get no token: their far URL is
      pre-signed instead (see :func:`third_party`);
    * then an HTTPS far side with no credential decision yet gets
      ``Credential: gridsite`` (delegate a proxy), and a plain-HTTP one
      ``Credential: none`` plus ``X-No-Delegate``, since a proxy must never
      be handed to an endpoint reached in clear.
    """
    headers: dict[str, str] = {}
    scheme = scheme_of(far)
    if scheme in ("cs3", "cs3s"):
        add_token(headers, plugin.options.string("BEARER", "TOKEN"))
    elif scheme in HTTP_SCHEMES - {"s3", "s3s", "gcloud", "gclouds", "swift", "swifts"}:
        token = _far_token(plugin, far, write, transfer)
        if token:
            add_token(headers, token)
            headers["Credential"] = "none"
    if scheme in ("https", "davs"):
        # ``setdefault``: a token chosen above already said ``none``.
        headers.setdefault("Credential", "gridsite")
    else:
        headers["Credential"] = "none"
        headers["X-No-Delegate"] = "true"
    return headers


def _far_token(plugin: HTTPPlugin, far: str, write: bool, transfer: Transfer) -> str | None:
    """What goes in ``TransferHeaderAuthorization`` so the active end can reach ``far``.

    ``None`` means "delegate instead" (or, for plain HTTP, "no credential").
    A token written into the far URL itself (``authz=``) stays in its query,
    as davix leaves it, and is not repeated here. What remains is the
    *ambient* token - ours, from the context or the environment - and that
    is the catch fixed in 0.3.2: an SE accepts an identity-mapped token (a
    DiracX token) for a direct read or write, and to mint a macaroon, but
    refuses it on the delegated server-to-server leg. So where an ambient
    token would be forwarded to an HTTPS far end, the far SE is asked
    (:func:`._token.se_token`) for a macaroon scoped to this one file
    instead, and only if it cannot mint one is the ambient token forwarded
    after all. Hence ``RETRIEVE_BEARER_TOKEN`` defaults to "yes, when there
    is an ambient token to replace" (the shipped ``http_plugin.conf`` turns
    it on regardless). With no token at all - a proxy copy - nothing
    changes: a mint only when the option asks, else the gridsite delegation
    :func:`_passive_credential` falls back to.
    """
    parsed = parse(far)
    query = parsed.query_dict()
    # Already pre-signed (by the user, or an FTS that signed it): the
    # signature is the credential, and an Authorization header would make
    # S3 reject the request as carrying two.
    if "X-Amz-Signature" in query or "AWSAccessKeyId" in query:
        return None
    ambient = plugin.client.bearer(far, parsed)
    retrieve = _se_boolean(plugin.options, far, "RETRIEVE_BEARER_TOKEN")
    if retrieve is None:
        group = plugin.option_group
        retrieve = plugin.options.boolean(group, "RETRIEVE_BEARER_TOKEN", bool(ambient))
    # Minting is HTTPS-only: a token must never be fetched or sent in clear.
    if retrieve and parsed.scheme in ("https", "davs"):
        # gfal2's lifetime: twice the copy's timeout, plus ten minutes of
        # slack for queueing at the active end, so the token outlives the
        # transfer.
        minted = se_token(plugin, far, write, token_minutes(transfer.params.timeout))
        if minted:
            return minted
    return ambient


def _checksum_header(mode: str, checks: int) -> dict[str, str]:
    """``RequireChecksumVerification: false`` exactly where gfal2 sends it (for dCache).

    dCache verifies a TPC's checksum itself unless told not to; gfal2 tells
    it not to when gfal2 will check the active end's side anyway, or when no
    checks were asked for at all. It never sends ``true``, so neither does
    this - the header's absence leaves dCache's own default.
    """
    side = _CHECKSUM_SOURCE if mode == PUSH else _CHECKSUM_TARGET
    if checks & side or not checks:
        return {"RequireChecksumVerification": "false"}
    return {}


def third_party(plugin: HTTPPlugin, transfer: Transfer, mode: str) -> None:
    """One ``3rd pull`` or ``3rd push`` attempt: send the ``COPY`` and follow it to the end.

    ``near`` is the active end (the one the ``COPY`` goes to, with the
    client's own credentials) and ``far`` the passive one. Raises
    :class:`GError` for a refused ``COPY`` (davix's status words), a
    ``failure`` outcome (``EIO``), an ``aborted`` one (``ECANCELED``), a
    stream that ends with no outcome (``EIO``), or the transfer's own
    cancel/timeout noticed between markers. The caller (:func:`._copy.run_modes`)
    decides whether another mode follows.
    """
    near, far = (
        (transfer.destination, transfer.source)
        if mode == PULL
        else (transfer.source, transfer.destination)
    )
    params = transfer.params
    # Tells the core's progress reporting the bytes are not flowing through
    # this process (no local rate to measure; markers are the only source).
    transfer.third_party = True
    headers = _passive_credential(plugin, far, mode == PUSH, transfer)
    signer = plugin.presigner_for(far)
    if signer is not None:
        # An S3 or GCS endpoint joins a TPC through a pre-signed URL.
        far_url = signer.presign("GET" if mode == PULL else "PUT", resolved(plugin, far))
        headers["Copy-Flags"] = "NoHead"
    else:
        far_url = wire_url(resolved(plugin, far))
    headers["Source" if mode == PULL else "Destination"] = far_url
    # davix's fixed headers: the stream count is advisory (XrdTpc honours
    # it), and ``Secure-Redirection`` lets a dCache door redirect the
    # active transfer to an HTTPS pool without downgrading.
    add_streams(headers, params.nbstreams)
    headers["Secure-Redirection"] = "1"
    headers.update(_checksum_header(mode, int(transfer.checksum_mode)))
    if params.scitag:
        headers["SciTag"] = str(params.scitag)
    # The read timeout covers the gap between markers, not the whole copy;
    # with no deadline, an hour of silence is davix's limit for a dead TPC.
    timeout = _deadline_timeout(transfer, 3600.0)
    active = resolved(plugin, near)
    with plugin._request(
        "COPY", active, headers=headers, timeout=timeout, cred_url=near
    ) as response:
        if response.status >= 300:
            raise _copy_refused(response)
        endpoint = response.header("X-Delegate-To").split()
        if endpoint:
            # The gridsite delegation client needs the X.509/RSA stack; only
            # a server that asks for a proxy here makes a copy pay for it.
            from ._delegation import delegate

            delegate(plugin, endpoint[0], near)
        _follow(response, transfer)


def _copy_refused(response: Response) -> GError:
    """davix's error for a ``COPY`` the active endpoint turned down.

    davix's request layer fails any status from 400 on before its copy
    module looks at the code, so what gfal2 shows is the generic
    ``copy HTTP <status> : <phrase> `` with davix's errno for it; the copy
    module's own "Could not COPY" words are only reached by a 3xx that
    carries no ``Location``.
    """
    status = response.status
    if status >= 400:
        return status_error(status, prefix="copy ")
    return GError(f"Could not COPY. Unknown error code: {status}", errno.EIO)


def _follow(response: Response, transfer: Transfer) -> None:
    """Read performance markers until the outcome line, as davix does.

    The reading is xrdhttp's (:func:`xrdhttp.tpc.follow_markers`);
    what each marker and outcome means to gfal2 is decided here. Every marker
    is reported, as davix's performance callback is, and every block - one
    without a byte count too - is a moment to notice a cancel or a deadline.
    """
    from xrdhttp.tpc import Marker, follow_markers

    def on_marker(total: int, marker: Marker | None) -> None:
        """A marker block ended: report bytes (if it had any), then honour a cancel."""
        if marker is not None:
            transfer.progress(total, always=True)
        transfer.check()

    outcome = follow_markers(response.readline, on_marker, limit=MAX_MARKER_LINE)
    # ``failed`` lines are folded into ``failure`` by xrdhttp; ``closed``
    # (the body ended without a verdict) is the last, catch-all case.
    if outcome.kind == "success":
        transfer.progress(outcome.transferred, force=True)
        return
    if outcome.kind == "aborted":
        raise GError("Transfer aborted in the remote end", errno.ECANCELED)
    if outcome.kind == "failure":
        raise GError(f"Transfer {outcome.line}", errno.EIO)
    raise GError("Connection terminated abruptly; Status of TPC request unknown", errno.EIO)
