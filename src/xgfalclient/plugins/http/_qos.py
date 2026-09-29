"""QoS over CDMI, as dCache exposes it and gfal2's http plugin drives it.

A CDMI object's ``capabilitiesURI`` names its current QoS class; the class
document lists the classes it may move to (``cdmi_capabilities_allowed``);
while a transition is under way the object's metadata carries
``cdmi_capabilities_target``; and a transition is requested by ``PUT``-ting
a new ``capabilitiesURI``. The classes an endpoint offers are the children
of ``<url>/cdmi_capabilities/dataobject`` or ``.../container``, returned as
``/cdmi_capabilities/<type>/<child>``.

Requests are plain ``GET``\\ s, with no ``Accept`` header, as gfal2 sends
them. A failure is davix's error (``HTTP 404 : File not found ``), and gfal2
also prints `` error in request of <what>: <error>`` on standard error,
which this does too. Where gfal2 would crash on a reply that is not a CDMI
object, or has no ``capabilitiesURI``, this reports ``EPROTO`` or an empty
class; and json-c's escaping of ``/`` as ``\\/`` in a class list is not
reproduced. gfal2's http plugin claims the QoS calls for any URL at all, so
there a ``root://`` or ``file://`` one is sent to davix as HTTP and fails
with whatever the far end makes of that (``ECOMM`` from an XRootD port);
here the calls belong to the HTTP schemes, and any other URL is
``EPROTONOSUPPORT``.
"""

from __future__ import annotations

import errno
import json
import sys
from typing import TYPE_CHECKING, Any

from ...errors import GError
from ._client import status_error

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = [
    "change_object_qos",
    "check_available_qos_transitions",
    "check_file_qos",
    "check_target_qos",
    "qos_check_classes",
]

#: What gfal2 strips out of a value it read with ``json_object_get_string``.
_JUNK = str.maketrans("", "", '[] "\\')


def _complain(what: str, error: GError) -> GError:
    sys.stderr.write(f" error in request of {what}: {error.message}\n")
    return error


def _get(plugin: HTTPPlugin, url: str, what: str, cred_url: str | None = None) -> dict[str, Any]:
    try:
        response = plugin._request("GET", url, cred_url=cred_url or url)
    except GError as exc:
        raise _complain(what, exc) from None
    payload = response.body()
    if response.status >= 300:
        raise _complain(what, status_error(response.status))
    try:
        document = json.loads(payload.decode("utf-8", "replace"))
    except ValueError:
        document = None
    if not isinstance(document, dict):
        raise GError(f" error in request of {what}: the reply is not a CDMI object", errno.EPROTO)
    return document


def _metadata(document: dict[str, Any], key: str) -> Any:
    metadata = document.get("metadata")
    return metadata.get(key) if isinstance(metadata, dict) else None


def _clean(value: Any) -> str:
    return (value if isinstance(value, str) else json.dumps(value)).translate(_JUNK)


def qos_check_classes(plugin: HTTPPlugin, url: str, kind: str) -> list[str]:
    if kind not in ("dataobject", "container"):
        raise GError("type argument should be either dataobject or container", errno.EINVAL)
    document = _get(plugin, f"{url}/cdmi_capabilities/{kind}", "getting available QoS classes", url)
    children = document.get("children")
    found = children if isinstance(children, list) else []
    return [f"/cdmi_capabilities/{kind}/{_clean(child)}" for child in found]


def check_file_qos(plugin: HTTPPlugin, url: str) -> str:
    found = _get(plugin, url, "checking file QoS").get("capabilitiesURI")
    return "" if found is None else _clean(found)


def check_available_qos_transitions(plugin: HTTPPlugin, url: str) -> list[str]:
    allowed = _metadata(_get(plugin, url, "checking file QoS"), "cdmi_capabilities_allowed")
    return [_clean(item) for item in allowed] if isinstance(allowed, list) else []


def check_target_qos(plugin: HTTPPlugin, url: str) -> str:
    target = _metadata(_get(plugin, url, "checking file QoS"), "cdmi_capabilities_target")
    return "" if target is None else _clean(target)


def change_object_qos(plugin: HTTPPlugin, url: str, target: str) -> None:
    what = "changing file QoS"
    body = f'{{"capabilitiesURI":"{target}"}}'.encode()
    try:
        response = plugin._request(
            "PUT", url, body=body, headers={"Content-Type": "application/cdmi-object"}
        )
    except GError as exc:
        raise _complain(what, exc) from None
    response.body()
    if response.status >= 400:
        raise _complain(what, status_error(response.status))
    if response.status not in (200, 201, 202, 204):
        sys.stderr.write(f" error in request of {what} \n")
        raise GError(f"Unexpected answer to the QoS change: HTTP {response.status}", errno.EIO)
