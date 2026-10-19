"""Where to connect and as whom: everything a transport tier needs, in one record.

The plugin resolves URL, credential store and ``[SFTP PLUGIN]`` options
into an :class:`Endpoint` (``SFTPPlugin._endpoint``); the tiers only read
it. It is frozen, so one endpoint can be shared by threads and pooled
connections, and its ``repr`` hides the secrets. The connection pool keys
on a subset of it (tier, user, host, port, key file - see
``SFTPPlugin._pool_key``), not on the whole record.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Endpoint"]


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One SFTP server and the identity to use there, as every tier needs it.

    Empty strings mean "not configured" throughout. The password and the
    passphrase never leave the process: the OpenSSH tier does not use them
    (see :mod:`.openssh`), and the plugin routes a password connection to
    an in-process tier instead.
    """

    #: Host name or address, from the URL.
    host: str
    #: TCP port; 22 unless the URL named one (see :attr:`explicit_port`).
    port: int = 22
    #: Login name: URL userinfo, then credential store, ``USER``, local user.
    user: str = ""
    #: From the URL, the credential store's ``PASSWD`` or ``PASSWORD``.
    password: str = field(default="", repr=False)
    #: Private key path (``PRIVKEY``; default ``~/.ssh/id_rsa``, may not exist).
    key_file: str = ""
    #: Decrypts :attr:`key_file` for the in-process tiers (``PASSPHRASE``).
    passphrase: str = field(default="", repr=False)
    #: Seconds for connect and every socket read/write; 0 means no timeout.
    timeout: int = 60
    #: ``KNOWN_HOSTS``: replaces the default ``known_hosts`` files when set.
    known_hosts: str = ""
    #: OpenSSH ``StrictHostKeyChecking`` value: ``accept-new`` records a
    #: first key; ``yes`` refuses unknown keys; ``no``/``off``/``accept-all``
    #: accept them. The in-process tiers refuse a changed or revoked key
    #: whatever the value; the OpenSSH tier passes it to ``ssh`` as is.
    strict_host_keys: str = "accept-new"
    #: Extra ``-o`` options for the OpenSSH tier only (``SSH_OPTIONS``).
    ssh_options: tuple[str, ...] = ()
    #: Whether the URL named the port (ssh's own config decides otherwise).
    explicit_port: bool = False

    @property
    def label(self) -> str:
        """``user@host:port`` for error messages; never includes a secret."""
        who = f"{self.user}@" if self.user else ""
        return f"{who}{self.host}:{self.port}"
