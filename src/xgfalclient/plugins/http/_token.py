"""SE-issued tokens: ``token_retrieve``, and the TPC credential for the far side.

A storage element can mint a token for its own files, authenticated by the
X.509 proxy the client already has; that token then goes wherever the
proxy cannot - into a third-party copy's ``TransferHeaderAuthorization``.
gfal2 asks in two ways, and so does this:

* **OAuth2 client credentials**, when the SE advertises a token endpoint -
  in ``/.well-known/oauth-authorization-server`` on its own host, or, when
  an issuer is named, in the issuer's ``.well-known/openid-configuration``;
* **a macaroon request**: a ``POST`` of ``application/macaroon-request`` to
  the file itself, with caveats naming the activities and an ISO 8601
  validity - what dCache and XRootD's macaroon plugin answer.

Activities default to gfal2's sets: ``LIST,DOWNLOAD`` to read and
``LIST,MANAGE,UPLOAD,DELETE`` to write. Tokens are only ever requested over
HTTPS - a token minted over plain HTTP would have been visible to anyone
on the path - and every failure is reported as gfal2 reports it,
``ENODATA`` naming the last attempt.
"""

from __future__ import annotations

import errno
import json
import urllib.parse
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from ...errors import GError
from ...url import parse
from ._client import Target, status_text, wire_scheme

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = ["activities", "retrieve"]

READ_ACTIVITIES = ("LIST", "DOWNLOAD")
WRITE_ACTIVITIES = ("LIST", "MANAGE", "UPLOAD", "DELETE")


def activities(write_access: bool, requested: Sequence[str] = ()) -> list[str]:
    if requested:
        return [item.strip().upper() for item in requested if item.strip()]
    return list(WRITE_ACTIVITIES if write_access else READ_ACTIVITIES)


class _Failed(Exception):
    """One way of getting a token did not work; the message says why."""


def _json(payload: bytes, key: str) -> str:
    if not payload.strip():
        raise _Failed("Response with no data")
    try:
        document: Any = json.loads(payload.decode("utf-8", "replace"))
    except ValueError as exc:
        raise _Failed("Response was not valid JSON") from exc
    if not isinstance(document, dict) or key not in document:
        raise _Failed(f"Response did not include '{key}' key")
    value = document[key]
    if not isinstance(value, str):
        raise _Failed(f"Key '{key}' was not a string")
    if not value:
        raise _Failed(f"Extracted value for key '{key}' is empty")
    return value


def _post(plugin: HTTPPlugin, url: str, body: bytes, content_type: str, cred_url: str) -> bytes:
    try:
        response = plugin._request(
            "POST",
            url,
            body=body,
            headers={"Content-Type": content_type, "Accept": "application/json"},
            cred_url=cred_url,
            x509_only=True,
        )
    except GError as exc:
        raise _Failed(exc.message) from exc
    payload = response.body()
    if response.status != 200 and response.status != 201:
        raise _Failed(f"Token request failed: {status_text(response.status, response.reason)}")
    return payload


def _endpoint(plugin: HTTPPlugin, discovery: str, cred_url: str) -> str | None:
    """The ``token_endpoint`` a discovery document names, if there is one."""
    try:
        response = plugin._request("GET", discovery, cred_url=cred_url, x509_only=True)
    except GError:
        return None
    payload = response.body()
    if response.status != 200:
        return None
    try:
        endpoint = _json(payload, "token_endpoint")
    except _Failed:
        return None
    if not endpoint.lower().startswith("https://"):
        raise _Failed("Token request must be done over HTTPs")
    return endpoint


def _oauth(plugin: HTTPPlugin, endpoint: str, url: str, validity: int, acts: list[str]) -> str:
    path = parse(url).path
    scopes = " ".join(f"{act.lower()}:{path}" for act in acts)
    form = urllib.parse.urlencode(
        {"grant_type": "client_credentials", "expire_in": str(validity * 60), "scopes": scopes}
    )
    payload = _post(plugin, endpoint, form.encode(), "application/x-www-form-urlencoded", url)
    return _json(payload, "access_token")


def _macaroon(plugin: HTTPPlugin, url: str, validity: int, acts: list[str]) -> str:
    request = {"caveats": [f"activity:{','.join(acts)}"], "validity": f"PT{validity}M"}
    payload = _post(plugin, url, json.dumps(request).encode(), "application/macaroon-request", url)
    return _json(payload, "macaroon")


def retrieve(
    plugin: HTTPPlugin,
    url: str,
    issuer: str,
    validity: int,
    write_access: bool,
    requested: Sequence[str] = (),
) -> str:
    """A token for ``url`` from its storage element (or ``issuer``)."""
    acts = activities(write_access, requested)
    minutes = max(int(validity), 1)
    try:
        if wire_scheme(parse(url).scheme) != "https":
            raise _Failed("Token request must be done over HTTPs")
        if issuer:
            discovery = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
        else:
            discovery = f"{Target.of(url).base}/.well-known/oauth-authorization-server"
        endpoint = _endpoint(plugin, discovery, url)
        if endpoint is not None:
            try:
                return _oauth(plugin, endpoint, url, minutes, acts)
            except _Failed:
                pass  # the SE may still answer a macaroon request
        elif issuer:
            raise _Failed("Invalid or empty token issuer endpoint")
        return _macaroon(plugin, url, minutes, acts)
    except _Failed as exc:
        last = str(exc)
    raise GError(f"Could not retrieve token for {url} [last failed attempt: {last}]", errno.ENODATA)
