"""Copy events: what ``params.event_callback`` receives.

FTS and gfal2-util read these to log what a transfer is doing, so both the
object and its ``str()`` match gfal2's::

    [1790606713232] BOTH   GFAL2:CORE:COPY:LOCAL	TRANSFER:ENTER	file:///a => file:///b

The side is printed left-justified in six columns, followed by a space;
domain, stage and description are separated by tabs.

As in gfal2, a description is cut to 511 bytes (its fixed 512-byte buffer),
and every event is also logged to the ``gfal2`` logger at INFO as
``Event triggered: <SIDE> <domain> <stage> <description>`` - the copy engine
calls :func:`log_event` for each one, whether or not a callback is set.
"""

from __future__ import annotations

import time

from . import _log
from .enums import event_side

__all__ = [
    "GfaltEvent",
    "SOURCE",
    "DESTINATION",
    "BOTH",
    "DOMAIN_COPY",
    "DOMAIN_LOCAL",
    "LIST_ENTER",
    "LIST_ITEM",
    "LIST_EXIT",
    "PREPARE_ENTER",
    "PREPARE_EXIT",
    "TRANSFER_ENTER",
    "TRANSFER_TYPE",
    "TRANSFER_EXIT",
    "CHECKSUM_ENTER",
    "CHECKSUM_EXIT",
    "OVERWRITE",
    "CLEANUP",
    "now_ms",
    "log_event",
    "markup_escape",
    "MAX_DESCRIPTION",
]

SOURCE = event_side.event_source
DESTINATION = event_side.event_destination
BOTH = event_side.event_none

DOMAIN_COPY = "GFAL2:CORE:COPY"
DOMAIN_LOCAL = "GFAL2:CORE:COPY:LOCAL"

LIST_ENTER = "LIST:ENTER"
LIST_ITEM = "LIST:ITEM"
LIST_EXIT = "LIST:EXIT"
PREPARE_ENTER = "PREPARE:ENTER"
PREPARE_EXIT = "PREPARE:EXIT"
TRANSFER_ENTER = "TRANSFER:ENTER"
TRANSFER_TYPE = "TRANSFER:TYPE"
TRANSFER_EXIT = "TRANSFER:EXIT"
CHECKSUM_ENTER = "CHECKSUM:ENTER"
CHECKSUM_EXIT = "CHECKSUM:EXIT"
OVERWRITE = "OVERWRITE"
CLEANUP = "CLEANUP"

_SIDE_LABELS = {0: "SOURCE", 1: "DEST", 2: "BOTH"}
#: How the log line names a side (``plugin_trigger_event`` spells DESTINATION out).
_LOG_SIDES = {0: "SOURCE", 1: "DESTINATION"}

#: The longest description, in UTF-8 bytes, gfal2's event buffer holds.
MAX_DESCRIPTION = 511

#: What ``g_markup_escape_text`` replaces, which gfal2 applies to LIST:ITEM URLs:
#: the five markup characters, and C0/C1 controls (not tab, newline, CR or NEL)
#: as ``&#x..;``.
_MARKUP = str.maketrans(
    {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "'": "&apos;",
        '"': "&quot;",
        **{
            chr(code): f"&#x{code:x};"
            for code in (*range(0x01, 0x20), *range(0x7F, 0xA0))
            if code not in (0x09, 0x0A, 0x0D, 0x85)
        },
    }
)


def now_ms() -> int:
    return int(time.time() * 1000)


def markup_escape(text: str) -> str:
    """``text`` escaped as ``g_markup_escape_text`` does (``&`` to ``&amp;``...)."""
    return text.translate(_MARKUP)


def _truncate(description: str) -> str:
    raw = description.encode("utf-8", "surrogateescape")
    if len(raw) <= MAX_DESCRIPTION:
        return description
    # A character cut in half is dropped rather than left malformed.
    return raw[:MAX_DESCRIPTION].decode("utf-8", "ignore")


class GfaltEvent:
    """One event: ``side`` (an int), ``timestamp`` (ms), ``domain``, ``stage``, ``description``.

    Built bare it is the bindings' zeroed record: ``SOURCE`` side, timestamp 0.
    """

    __slots__ = ("description", "domain", "side", "stage", "timestamp")

    def __init__(
        self,
        side: int = SOURCE,
        domain: str = "",
        stage: str = "",
        description: str = "",
        timestamp: int = 0,
    ) -> None:
        self.side = int(side)
        self.domain = domain
        self.stage = stage
        self.description = _truncate(description)
        self.timestamp = timestamp

    def __str__(self) -> str:
        label = _SIDE_LABELS.get(self.side, "BOTH")
        return f"[{self.timestamp}] {label:<6} {self.domain}\t{self.stage}\t{self.description}"

    __repr__ = __str__


def log_event(event: GfaltEvent) -> None:
    """Log ``event`` at INFO on ``gfal2``, as gfal2 logs every event it triggers."""
    _log.LOGGER.info(
        "Event triggered: %s %s %s %s",
        _LOG_SIDES.get(event.side, "BOTH"),
        event.domain,
        event.stage,
        event.description,
    )
