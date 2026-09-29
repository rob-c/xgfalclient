"""Transport tier 2: borrow paramiko's SSH transport, keep our SFTP client.

paramiko, when it happens to be installed, is a mature SSH-2 implementation
with C-accelerated ciphers. This tier uses only its *transport* - the
handshake, key exchange and channel - and runs *our* :class:`SFTPClient` on
top of the resulting subsystem channel, so the SFTP behaviour (errno mapping,
pipelining, listings) is identical across all three tiers. paramiko is never a
dependency: this module is imported only when :func:`plugin._has_paramiko`
already found it.

The channel paramiko returns is adapted to the byte-stream the SFTP client
wants. Host keys are checked against ``known_hosts`` with our own
:class:`KnownHosts`, so the ``StrictHostKeyChecking`` policy is the same too.
"""

from __future__ import annotations

import errno
import os
from typing import Any

from ...crypto.sshkeys import KeyError_, KnownHosts, parse_public_blob
from ...errors import GError
from .endpoint import Endpoint

__all__ = ["ParamikoStream", "connect"]


class ParamikoStream:
    """A :class:`~.client.Stream` over a paramiko subsystem channel."""

    def __init__(self, transport: Any, channel: Any) -> None:
        self._transport = transport
        self._channel = channel

    def send(self, *parts: Any) -> None:
        for part in parts:
            if len(part):
                self._channel.sendall(bytes(part))

    def recv_into(self, view: memoryview) -> int:
        data = self._channel.recv(len(view))
        if not data:
            return 0
        view[: len(data)] = data
        return len(data)

    def close(self) -> None:
        try:
            self._channel.close()
        finally:
            self._transport.close()


def _check_host_key(endpoint: Endpoint, transport: Any) -> None:
    from .ssh import _known_hosts_paths, _record_host_key

    try:
        key = parse_public_blob(transport.get_remote_server_key().asbytes())
    except KeyError_ as exc:
        raise GError(f"Unreadable host key from {endpoint.label}: {exc}", errno.EACCES) from exc
    paths = _known_hosts_paths(endpoint)
    result = KnownHosts.load(paths).check(endpoint.host, endpoint.port, key)
    if result.status == "match":
        return
    if result.status in ("revoked", "changed"):
        raise GError(
            f"Host key verification failed for {endpoint.label}: {result.detail}", errno.EACCES
        )
    if endpoint.strict_host_keys in ("no", "off", "accept-all"):
        return
    if endpoint.strict_host_keys == "accept-new":
        _record_host_key(paths, endpoint, key)
        return
    raise GError(f"Host key for {endpoint.label} is not known", errno.EACCES)


def _authenticate(paramiko: Any, endpoint: Endpoint, transport: Any) -> None:
    tried: list[str] = []
    if endpoint.key_file and os.path.isfile(endpoint.key_file):
        tried.append("publickey")
        try:
            pkey = paramiko.PKey.from_path(endpoint.key_file, endpoint.passphrase or None)
            transport.auth_publickey(endpoint.user, pkey)
        except paramiko.SSHException:
            pass
    if not transport.is_authenticated() and endpoint.password:
        tried.append("password")
        try:
            transport.auth_password(endpoint.user, endpoint.password)
        except paramiko.SSHException:
            pass
    if not transport.is_authenticated():
        raise GError(
            f"All supported authentication methods failed for {endpoint.label} "
            f"(tried {', '.join(tried) or 'none'})",
            errno.EACCES,
        )


def connect(endpoint: Endpoint, key_files: Any = ()) -> ParamikoStream:
    """Open a paramiko transport to ``endpoint`` and start the ``sftp`` subsystem."""
    import socket

    import paramiko  # type: ignore[import-untyped,import-not-found]

    del key_files  # paramiko loads keys from the file itself
    timeout = float(endpoint.timeout) if endpoint.timeout > 0 else None
    try:
        sock = socket.create_connection((endpoint.host, endpoint.port), timeout=timeout)
    except socket.gaierror as exc:
        raise GError(f"Could not resolve host {endpoint.host}: {exc}", errno.EREMOTE) from exc
    except OSError as exc:
        raise GError(
            f"Could not connect to {endpoint.label}: {exc.strerror or exc}",
            exc.errno or errno.ECONNREFUSED,
        ) from exc
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        _check_host_key(endpoint, transport)
        _authenticate(paramiko, endpoint, transport)
        channel = transport.open_session(timeout=timeout)
        channel.invoke_subsystem("sftp")
    except paramiko.SSHException as exc:
        transport.close()
        raise GError(f"SSH error talking to {endpoint.label}: {exc}", errno.ECONNRESET) from exc
    except BaseException:
        transport.close()
        raise
    return ParamikoStream(transport, channel)
