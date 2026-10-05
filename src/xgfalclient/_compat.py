"""What the oldest supported Python lacks, in one place.

The code is kept to 3.9 syntax because that is what RHEL 9 and AlmaLinux 9
ship as ``python3``, although the declared floor is 3.10 (the dependencies
cannot be resolved on 3.9). Nothing else in the
package may test ``sys.version_info``; if a module needs something newer, the
fallback lives here.
"""

from __future__ import annotations

import socket
import sys
from typing import Any

__all__ = ["SLOTS", "TIMEOUTS", "peer_chain_der"]


def dataclass_slots(version: tuple[Any, ...]) -> dict[str, bool]:
    """``slots=True`` for a dataclass if interpreter ``version`` accepts it."""
    return {"slots": True} if version >= (3, 10) else {}


#: ``slots=True`` for a dataclass where the running interpreter accepts it.
SLOTS: dict[str, bool] = dataclass_slots(sys.version_info)

#: What a socket raises when the far end goes quiet. On 3.9 these are two
#: distinct classes, so every ``except`` that means "timed out" names both.
TIMEOUTS: tuple[type[BaseException], ...] = (socket.timeout, TimeoutError)


def peer_chain_der(tls: Any) -> list[bytes]:
    """The certificates a TLS peer sent (DER, leaf first).

    ``get_unverified_chain`` is public from 3.13 and a private method of the
    underlying object from 3.10; 3.9 offers only the leaf.
    """
    whole = getattr(tls, "get_unverified_chain", None) or getattr(
        getattr(tls, "_sslobj", None), "get_unverified_chain", None
    )
    return (
        [_der(link) for link in whole()]
        if whole is not None
        else [der for der in [tls.getpeercert(binary_form=True)] if der]
    )


def _der(link: Any) -> bytes:
    """One chain entry as DER: bytes from 3.13, an ``_ssl.Certificate`` before."""
    public_bytes = getattr(link, "public_bytes", None)
    return bytes(public_bytes(2)) if public_bytes is not None else bytes(link)  # 2 = DER
