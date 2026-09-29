"""The shape every backend fills in: one GSS context, driven by tokens."""

from __future__ import annotations

from dataclasses import dataclass

from ..._compat import SLOTS

__all__ = ["Target", "Mechanism", "Backend", "HOSTBASED", "PRINCIPAL", "INITIATE", "ACCEPT"]

#: ``GSS_C_NT_HOSTBASED_SERVICE`` - ``service@host``, the realm from the host.
HOSTBASED = "hostbased"
#: ``GSS_KRB5_NT_PRINCIPAL_NAME`` - a full ``primary/instance@REALM``.
PRINCIPAL = "principal"

# ``gss_cred_usage_t``.
INITIATE = 1
ACCEPT = 2


@dataclass(frozen=True, **SLOTS)
class Target:
    """A name to import: the text and which GSS name type it is."""

    name: str
    kind: str = HOSTBASED


class Mechanism:
    """One GSS security context in a backend's own terms.

    Callers serialise access (:class:`~xgfalclient.crypto.krb5.ClientContext`
    holds a lock); a mechanism need not be thread-safe itself.
    """

    #: True once the library says the context is established.
    complete: bool = False

    def step(self, token: bytes) -> bytes:
        """Feed the peer's token (empty to start); return the one to send."""
        raise NotImplementedError

    def wrap(self, data: bytes, confidential: bool) -> tuple[bytes, bool]:
        """``gss_wrap``: the token, and whether it was actually encrypted."""
        raise NotImplementedError

    def unwrap(self, token: bytes) -> tuple[bytes, bool]:
        """``gss_unwrap``: the data, and whether it had been encrypted."""
        raise NotImplementedError

    def get_mic(self, data: bytes) -> bytes:
        raise NotImplementedError

    def verify_mic(self, data: bytes, mic: bytes) -> None:
        raise NotImplementedError

    def inquire(self) -> tuple[str, str, int]:
        """The initiator's name, the target's name and the negotiated flags."""
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class Backend:
    """A GSS-API implementation able to build :class:`Mechanism` objects."""

    #: ``ctypes-mit``, ``ctypes-heimdal`` or ``gssapi``.
    name: str = ""

    def initiator(self, target: Target, flags: int, ccache: str | None) -> Mechanism:
        raise NotImplementedError

    def acceptor(self, name: Target | None, keytab: str | None) -> Mechanism:
        raise NotImplementedError
