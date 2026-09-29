"""QoS over CDMI, as dCache exposes it and gfal2's http plugin drives it.

A CDMI object's ``capabilitiesURI`` names its current QoS class; the class
document lists the classes it may move to (``cdmi_capabilities_allowed``);
while a transition is under way the object's metadata carries
``cdmi_capabilities_target``; and a transition is requested by ``PUT``-ting
a new ``capabilitiesURI``. The classes an endpoint offers are the children
of ``/cdmi_capabilities/dataobject/`` or ``/cdmi_capabilities/container/``.
"""

from __future__ import annotations

import errno
import json
from typing import TYPE_CHECKING, Any

from ...errors import GError
from ._client import Target, http_errno, status_text

if TYPE_CHECKING:
    from .plugin import HTTPPlugin

__all__ = [
    "change_object_qos",
    "check_available_qos_transitions",
    "check_file_qos",
    "check_target_qos",
    "qos_check_classes",
]

_CDMI = {"Accept": "application/cdmi-object"}


def _get(plugin: HTTPPlugin, url: str, what: str, cred_url: str | None = None) -> dict[str, Any]:
    response = plugin._request("GET", url, headers=_CDMI, cred_url=cred_url or url)
    payload = response.body()
    if response.status != 200:
        raise GError(
            f" error in request of {what}: {status_text(response.status, response.reason)}",
            http_errno(response.status),
        )
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


def qos_check_classes(plugin: HTTPPlugin, url: str, kind: str) -> list[str]:
    if kind not in ("dataobject", "container"):
        raise GError("type argument should be either dataobject or container", errno.EINVAL)
    base = Target.of(url).base
    document = _get(
        plugin, f"{base}/cdmi_capabilities/{kind}/", "getting available QoS classes", url
    )
    children = document.get("children")
    return [str(child).strip("/") for child in children] if isinstance(children, list) else []


def check_file_qos(plugin: HTTPPlugin, url: str) -> str:
    return str(_get(plugin, url, "checking file QoS").get("capabilitiesURI") or "")


def check_available_qos_transitions(plugin: HTTPPlugin, url: str) -> list[str]:
    allowed = _metadata(_get(plugin, url, "checking QoS transitions"), "cdmi_capabilities_allowed")
    return [str(item) for item in allowed] if isinstance(allowed, list) else []


def check_target_qos(plugin: HTTPPlugin, url: str) -> str:
    target = _metadata(_get(plugin, url, "checking target QoS"), "cdmi_capabilities_target")
    return "" if target is None else str(target)


def change_object_qos(plugin: HTTPPlugin, url: str, target: str) -> None:
    body = json.dumps({"capabilitiesURI": target}).encode()
    response = plugin._request(
        "PUT", url, body=body, headers={"Content-Type": "application/cdmi-object", **_CDMI}
    )
    response.body()
    if response.status not in (200, 202, 204):
        raise GError(
            " error in request of changing file QoS: "
            + status_text(response.status, response.reason),
            http_errno(response.status),
        )
