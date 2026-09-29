"""Copy events: what ``params.event_callback`` receives.

FTS and gfal2-util read these to log what a transfer is doing, so both the
object and its ``str()`` match gfal2's::

    [1790606713232] BOTH   GFAL2:CORE:COPY:LOCAL	TRANSFER:ENTER	file:///a => file:///b

The side is printed left-justified in six columns, followed by a space;
domain, stage and description are separated by tabs.
"""

from __future__ import annotations

import time

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


def now_ms() -> int:
    return int(time.time() * 1000)


class GfaltEvent:
    """One event: ``side`` (an int), ``timestamp`` (ms), ``domain``, ``stage``, ``description``."""

    __slots__ = ("description", "domain", "side", "stage", "timestamp")

    def __init__(
        self,
        side: int = BOTH,
        domain: str = "",
        stage: str = "",
        description: str = "",
        timestamp: int | None = None,
    ) -> None:
        self.side = int(side)
        self.domain = domain
        self.stage = stage
        self.description = description
        self.timestamp = now_ms() if timestamp is None else timestamp

    def __str__(self) -> str:
        label = _SIDE_LABELS.get(self.side, "BOTH")
        return f"[{self.timestamp}] {label:<6} {self.domain}\t{self.stage}\t{self.description}"

    __repr__ = __str__
