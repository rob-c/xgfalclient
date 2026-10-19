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

The stage strings are gfal2's ``GFAL_EVENT_*`` quarks (``gfal2/transfer/
gfal_transfer_types.h``) and the domains its ``GFAL2:CORE:COPY`` family;
plugins add their own domains (``GFAL2:HTTP``...) and stages. FTS greps for
these exact strings, so they are constants here and must never be reworded.
"""

from __future__ import annotations

import time

from . import _log
from .enums import event_side

__all__ = [
    "BOTH",
    "CHECKSUM_ENTER",
    "CHECKSUM_EXIT",
    "CLEANUP",
    "DESTINATION",
    "DOMAIN_COPY",
    "DOMAIN_LOCAL",
    "LIST_ENTER",
    "LIST_EXIT",
    "LIST_ITEM",
    "MAX_DESCRIPTION",
    "OVERWRITE",
    "PREPARE_ENTER",
    "PREPARE_EXIT",
    "SOURCE",
    "TRANSFER_ENTER",
    "TRANSFER_EXIT",
    "TRANSFER_TYPE",
    "GfaltEvent",
    "log_event",
    "markup_escape",
    "now_ms",
]

SOURCE = event_side.event_source
DESTINATION = event_side.event_destination
#: gfal2 calls it ``GFAL_EVENT_NONE``; it prints as ``BOTH`` and means both ends.
BOTH = event_side.event_none

#: The core copy engine's domain (bulk and third-party orchestration).
DOMAIN_COPY = "GFAL2:CORE:COPY"
#: The streamed copy's domain: bytes passed through this process.
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

#: How ``str(event)`` names a side; anything unknown prints as ``BOTH``, as in gfal2.
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
    """Wall-clock milliseconds since the epoch: an event's ``timestamp``.

    Wall time, not monotonic, because consumers (FTS logs) correlate it with
    other machines' clocks.
    """
    return int(time.time() * 1000)


def markup_escape(text: str) -> str:
    """``text`` escaped as ``g_markup_escape_text`` does (``&`` to ``&amp;``...).

    gfal2 escapes the URLs in a bulk copy's ``LIST:ITEM`` descriptions, so
    consumers that split on ``=>`` or parse them as markup see the same text
    here; nothing else is escaped.
    """
    return text.translate(_MARKUP)


def _truncate(description: str) -> str:
    """``description`` cut to :data:`MAX_DESCRIPTION` UTF-8 bytes, as gfal2's buffer cuts it.

    ``surrogateescape`` keeps undecodable file names (bytes smuggled through
    ``os.fsdecode``) countable byte for byte instead of raising.
    """
    raw = description.encode("utf-8", "surrogateescape")
    if len(raw) <= MAX_DESCRIPTION:
        return description
    # A character cut in half is dropped rather than left malformed.
    return raw[:MAX_DESCRIPTION].decode("utf-8", "ignore")


class GfaltEvent:
    """One event: ``side`` (an int), ``timestamp`` (ms), ``domain``, ``stage``, ``description``.

    Built bare it is the bindings' zeroed record: ``SOURCE`` side, timestamp 0.

    Maps to python3-gfal2's ``gfal2.GfaltEvent`` (gfal2's ``gfalt_event``).
    Slotted, so it has exactly the bindings' five attributes and no others.
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
        """Build an event; ``description`` is truncated as gfal2's buffer would cut it."""
        self.side = int(side)
        self.domain = domain
        self.stage = stage
        self.description = _truncate(description)
        self.timestamp = timestamp

    def __str__(self) -> str:
        """The bindings' one-line form, byte for byte (see the module docstring)."""
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
