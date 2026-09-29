"""Where to connect and as whom: everything a transport tier needs, in one record.

The plugin resolves URL, credential store and ``[SFTP PLUGIN]`` options
into an :class:`Endpoint`; the tiers only read it. It is hashable (the
connection pool's key) and its ``repr`` hides the secrets.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..._compat import SLOTS

__all__ = ["Endpoint"]


@dataclass(frozen=True, **SLOTS)
class Endpoint:
    host: str
    port: int = 22
    user: str = ""
    password: str = field(default="", repr=False)
    key_file: str = ""
    passphrase: str = field(default="", repr=False)
    timeout: int = 60
    known_hosts: str = ""
    strict_host_keys: str = "accept-new"
    ssh_options: tuple[str, ...] = ()
    #: Whether the URL named the port (ssh's own config decides otherwise).
    explicit_port: bool = False

    @property
    def label(self) -> str:
        who = f"{self.user}@" if self.user else ""
        return f"{who}{self.host}:{self.port}"
