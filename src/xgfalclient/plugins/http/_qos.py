"""QoS over CDMI, as dCache exposes it and gfal2's http plugin drives it.

CDMI is SNIA's Cloud Data Management Interface (ISO/IEC 17826); dCache
uses its *capabilities* to name storage QoS classes (``disk``, ``tape``,
``disk+tape``). A CDMI object's ``capabilitiesURI`` names its current QoS
class; its metadata lists the classes it may move to
(``cdmi_capabilities_allowed``) and, while a transition is under way, the
one it is moving to (``cdmi_capabilities_target``); and a transition is
requested by ``PUT``-ting a new ``capabilitiesURI``. The classes an endpoint offers are the children
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
    """Print gfal2's stderr line for a failed QoS request, and hand ``error`` back to raise.

    gfal2 writes this line itself, outside any logger, and scripts that
    scrape gfal2's output see it; so it goes to ``stderr`` here too.
    """
    sys.stderr.write(f" error in request of {what}: {error.message}\n")
    return error


def _get(plugin: HTTPPlugin, url: str, what: str, cred_url: str | None = None) -> dict[str, Any]:
    """``GET`` a CDMI document as a JSON object; ``what`` names the call in errors.

    A transport failure or an error status is davix's error, announced on
    stderr (:func:`_complain`); a reply that is not a JSON object is
    ``EPROTO``, where gfal2 would dereference a null and crash.
    """
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
    """``document["metadata"][key]``, or ``None`` when either level is missing."""
    metadata = document.get("metadata")
    return metadata.get(key) if isinstance(metadata, dict) else None


def _clean(value: Any) -> str:
    """A JSON value as gfal2 prints it: its text with brackets, quotes and spaces removed.

    gfal2 takes ``json_object_get_string`` of the value (which serialises a
    non-string) and strips :data:`_JUNK` characters from it; the odd result
    for a list (``a,b``) is what gfal2 users see, so it is kept.
    """
    return (value if isinstance(value, str) else json.dumps(value)).translate(_JUNK)


def qos_check_classes(plugin: HTTPPlugin, url: str, kind: str) -> list[str]:
    """Every QoS class the endpoint at ``url`` offers for ``kind`` (a file or a directory).

    ``kind`` is ``dataobject`` or ``container`` (``EINVAL`` otherwise, in
    gfal2's words); the classes are the ``children`` of that capability
    document, as absolute ``/cdmi_capabilities/<kind>/<name>`` paths.
    """
    if kind not in ("dataobject", "container"):
        raise GError("type argument should be either dataobject or container", errno.EINVAL)
    document = _get(plugin, f"{url}/cdmi_capabilities/{kind}", "getting available QoS classes", url)
    children = document.get("children")
    found = children if isinstance(children, list) else []
    return [f"/cdmi_capabilities/{kind}/{_clean(child)}" for child in found]


def check_file_qos(plugin: HTTPPlugin, url: str) -> str:
    """The object's current class (``capabilitiesURI``), or ``""`` if it names none."""
    found = _get(plugin, url, "checking file QoS").get("capabilitiesURI")
    return "" if found is None else _clean(found)


def check_available_qos_transitions(plugin: HTTPPlugin, url: str) -> list[str]:
    """The classes the object may move to; empty if the server lists none."""
    allowed = _metadata(_get(plugin, url, "checking file QoS"), "cdmi_capabilities_allowed")
    return [_clean(item) for item in allowed] if isinstance(allowed, list) else []


def check_target_qos(plugin: HTTPPlugin, url: str) -> str:
    """The class a transition under way is moving the object to, or ``""`` if none is."""
    target = _metadata(_get(plugin, url, "checking file QoS"), "cdmi_capabilities_target")
    return "" if target is None else _clean(target)


def change_object_qos(plugin: HTTPPlugin, url: str, target: str) -> None:
    """Ask for the object to move to class ``target``; returns once the request is accepted.

    The transition itself is asynchronous (tape writes take hours): a
    ``202 Accepted`` is success, and :func:`check_target_qos` follows it.
    Any other status below 400 (a redirect left unfollowed, say) is neither
    success nor davix's error, so it gets gfal2's bare stderr line and
    ``EIO``.
    """
    what = "changing file QoS"
    # Built as text, not with json.dumps: ``target`` goes in unescaped,
    # byte for byte as the caller gave it, as gfal2 formats it.
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
