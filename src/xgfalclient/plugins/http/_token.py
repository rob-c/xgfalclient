"""SE-issued tokens: ``token_retrieve``, and the TPC credential for the far side.

A storage element can mint a token for its own files, authenticated by the
X.509 proxy the client already has; that token then goes wherever the
proxy cannot - into a third-party copy's ``TransferHeaderAuthorization``.
This is gfal2's chain of retrievers, request for request:

* **no issuer**: a macaroon request - a ``POST`` of
  ``application/macaroon-request`` to the file itself, with a caveat naming
  the activities and an ISO 8601 validity - what dCache and XRootD answer;
* **an issuer**: first *SciTokens*, which discovers the issuer's token
  endpoint in ``<issuer host>/.well-known/oauth-authorization-server<issuer
  path>`` and asks it for ``grant_type=client_credentials`` and nothing
  more; then a *macaroon retriever* for that issuer, which does the same
  discovery and, if an endpoint is found, sends it an OAuth request with
  ``scopes=<ACTIVITY>:<path> ...``, and otherwise falls back to the
  macaroon request to the file.

The TPC far side uses a macaroon request to the file, then a macaroon
retriever with the storage element itself as issuer.

Activities are the caller's, as given, or gfal2's sets: ``LIST,DOWNLOAD``
to read and ``LIST,DOWNLOAD,MANAGE,UPLOAD,DELETE`` to write. Tokens are only
requested over HTTPS (``davs`` counts). Every failure is reported as gfal2
reports it, ``ENODATA`` naming the last attempt.

gfal2's retrievers also look in ``.well-known/openid-configuration`` when
the first discovery document yields nothing; since a document that yields
nothing is an error there, that second look never happens, and it is not
made here either.
"""

from __future__ import annotations

import errno
import json
import logging
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ...errors import GError
from ...url import URL, parse

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["activities", "retrieve", "se_token"]

_log = logging.getLogger("gfal2")

READ_ACTIVITIES = ("LIST", "DOWNLOAD")
WRITE_ACTIVITIES = ("LIST", "DOWNLOAD", "MANAGE", "UPLOAD", "DELETE")
#: The most of a macaroon response gfal2 reads (StoRM answers the POST with the file).
RESPONSE_MAX_SIZE = 1024 * 1024


def activities(write_access: bool, requested: Sequence[str] = ()) -> list[str]:
    if requested:
        return list(requested)
    return list(WRITE_ACTIVITIES if write_access else READ_ACTIVITIES)


class _Failed(Exception):
    """One way of getting a token did not work; the message says why."""


def _json(payload: bytes, key: str) -> str:
    if not payload:
        raise _Failed("Response with no data")
    try:
        document: Any = json.loads(payload.decode("utf-8", "replace"))
    except ValueError as exc:
        raise _Failed("Response was not valid JSON") from exc
    if not isinstance(document, dict) or key not in document:
        raise _Failed(f"Response did not include '{key}' key")
    value = document[key]
    if value is None:
        raise _Failed(f"Key '{key}' was not a string")
    text = value if isinstance(value, str) else json.dumps(value)
    if not text:
        raise _Failed(f"Extracted value for key '{key}' is empty")
    return text


def _https(url: str) -> URL:
    """``url`` as HTTPS (``davs`` becomes ``https``); anything else is refused."""
    parsed = parse(url)
    scheme = "https" if parsed.scheme == "davs" else parsed.scheme
    if scheme != "https":
        raise _Failed("Token request must be done over HTTPs")
    return parsed.with_scheme(scheme)


@dataclass
class _Retriever:
    """One of gfal2's ``TokenRetriever``: SciTokens or macaroon, with or without an issuer."""

    plugin: HTTPPlugin
    issuer: str = ""
    scitokens: bool = False

    def _endpoint(self, cred_url: str) -> str:
        """The issuer's ``token_endpoint``, or ``""`` if there is none to be had."""
        if not self.issuer:
            return ""
        try:
            issuer = _https(self.issuer)
            path = issuer.path if issuer.path not in ("", "/") else ""
            discovery = f"{issuer.base}/.well-known/oauth-authorization-server{path}"
            payload = self._send("GET", discovery, cred_url, "Token endpoint discovery")
            return _json(payload, "token_endpoint")
        except _Failed as exc:
            _log.debug("(SEToken) Error during issuer endpoint discovery: %s", exc)
            return ""

    def _send(
        self,
        method: str,
        url: str,
        cred_url: str,
        what: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        colon: str = ":",
    ) -> bytes:
        try:
            response = self.plugin._request(
                method, url, body=body, headers=headers, cred_url=cred_url, x509_only=True
            )
        except GError as exc:
            raise _Failed(f"{what} request failed: {exc.message}") from exc
        payload = response.body(RESPONSE_MAX_SIZE)
        if response.status != 200:
            raise _Failed(f"{what} request failed with status code{colon} {response.status}")
        if len(payload) >= RESPONSE_MAX_SIZE:
            raise _Failed(
                f"{what} response exceeds maximum size: {len(payload)} bytes "
                f"(max size = {RESPONSE_MAX_SIZE})"
            )
        return payload

    def retrieve(
        self, url: str, write_access: bool, validity: int, requested: Sequence[str]
    ) -> str:
        target = _https(url)
        endpoint = self._endpoint(url)
        acts = activities(write_access, requested)
        form = "application/x-www-form-urlencoded"
        if self.scitokens:
            if not endpoint:
                raise _Failed("Invalid or empty token issuer endpoint")
            headers = {"Accept": "application/json", "Content-Type": form}
            payload = self._send(
                "POST", endpoint, url, "SciTokens", b"grant_type=client_credentials", headers
            )
            return _json(payload, "access_token")
        if endpoint:
            scopes = " ".join(f"{act}:{target.path}" for act in acts)
            body = (
                f"grant_type=client_credentials&expire_in={validity * 60}"
                f"&scopes={urllib.parse.quote(scopes, safe='')}"
            )
            headers = {"Content-Type": form, "Accept": "application/json"}
            payload = self._send("POST", endpoint, url, "Token", body.encode(), headers, "")
            return _json(payload, "access_token")
        request = {"caveats": [f"activity:{','.join(acts)}"], "validity": f"PT{validity}M"}
        payload = self._send(
            "POST",
            str(target),
            url,
            "Macaroon",
            json.dumps(request).encode(),
            {"Content-Type": "application/macaroon-request"},
            "",
        )
        return _json(payload, "macaroon")


def _chain(
    chain: Sequence[_Retriever],
    url: str,
    write_access: bool,
    validity: int,
    requested: Sequence[str],
) -> tuple[str, str]:
    """``(token, "")`` from the first retriever that works, else ``("", last error)``."""
    last = ""
    for retriever in chain:
        try:
            return retriever.retrieve(url, write_access, validity, requested), ""
        except _Failed as exc:
            _log.info("(SEToken) Error during token retrieval: %s", exc)
            last = str(exc)
    return "", last


def retrieve(
    plugin: HTTPPlugin,
    url: str,
    issuer: str,
    validity: int,
    write_access: bool,
    requested: Sequence[str] = (),
) -> str:
    """``token_retrieve``: a token for ``url`` from its storage element (or ``issuer``)."""
    if issuer:
        chain = [_Retriever(plugin, issuer, scitokens=True), _Retriever(plugin, issuer)]
    else:
        chain = [_Retriever(plugin)]
    token, last = _chain(chain, url, write_access, int(validity), requested)
    if not token:
        raise GError(
            f"Could not retrieve token for {url} [last failed attempt: {last}]", errno.ENODATA
        )
    return token


def se_token(plugin: HTTPPlugin, url: str, write_access: bool, validity: int) -> str | None:
    """A token the storage element behind ``url`` mints for it, or ``None``.

    gfal2's ``retrieve_and_store_se_token``: a macaroon request to the file,
    then the same with the storage element itself as the issuer.
    """
    parsed = parse(url)
    storage = f"{parsed.scheme}://{parsed.netloc.rpartition('@')[2]}"
    chain = [_Retriever(plugin), _Retriever(plugin, storage)]
    token, _ = _chain(chain, url, write_access, validity, ())
    if not token:
        _log.warning("(SEToken) Could not retrieve any token for %s", url)
        return None
    return token
