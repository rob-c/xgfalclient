"""Transport tier 2: borrow paramiko's SSH transport, keep our SFTP client.

paramiko (the ``sftp`` extra: ``pip install xgfalclient[sftp]``) is a mature
SSH-2 implementation with native ciphers and, from 3.4, strict KEX - the
Terrapin countermeasure. It is the in-process tier ``auto`` prefers and the
one ahead of the python tier (:mod:`.ssh`). This tier uses only
its *transport* - the handshake, key exchange and channel - and runs *our*
:class:`~.client.SFTPClient` on top of the resulting subsystem channel, so the SFTP
behaviour (errno mapping, pipelining, listings) is identical across all three
tiers. paramiko is never a base dependency: it is imported only when the tier
is chosen - by ``auto`` once :func:`plugin._has_paramiko` found a new enough
release, or by an explicit ``TRANSPORT=paramiko``.

The channel paramiko returns is adapted to the byte-stream the SFTP client
wants. Host keys are checked against ``known_hosts`` with our own
:class:`KnownHosts`, so the ``StrictHostKeyChecking`` policy is the same too.
"""

from __future__ import annotations

import contextlib
import errno
import os
from typing import Any

from ...crypto.sshkeys import KeyError_, KnownHosts, parse_public_blob
from ...errors import GError
from ...plugin import shutdown_sockets
from .endpoint import Endpoint

__all__ = ["ParamikoStream", "connect"]


class ParamikoStream:
    """A :class:`~.client.Stream` over a paramiko subsystem channel.

    paramiko runs its own reader thread and flow control, so this adapter
    is thin. It owns both objects: closing the stream closes the transport
    and with it the TCP connection.
    """

    def __init__(self, transport: Any, channel: Any) -> None:
        """``transport`` is a connected ``paramiko.Transport``, ``channel`` its sftp channel."""
        self._transport = transport
        self._channel = channel

    def send(self, *parts: Any) -> None:
        """``sendall`` each non-empty part; paramiko blocks while the window is full.

        Each part is copied to ``bytes`` before paramiko sees it (one copy
        per part, on top of paramiko's own). A dead connection raises from
        paramiko, typically ``OSError``.
        """
        for part in parts:
            if len(part):
                self._channel.sendall(bytes(part))

    def recv_into(self, view: memoryview) -> int:
        """Up to ``len(view)`` bytes of channel data; 0 once the channel is closed.

        paramiko's channel has no ``recv_into``, so this costs one copy.
        """
        data = self._channel.recv(len(view))
        if not data:
            return 0
        view[: len(data)] = data
        return len(data)

    def abort(self) -> None:
        """Shut paramiko's socket down; for ``cancel()``.

        paramiko's transport thread reads the end of the stream, closes every
        channel, and the ``recv`` blocked on ours returns at once. ``close``
        stays the owner's.
        """
        shutdown_sockets(getattr(self._transport, "sock", None))

    def close(self) -> None:
        """Close the channel, then the transport; best-effort, as closing must be.

        paramiko's channel close writes ``CHANNEL_EOF`` and then
        ``CHANNEL_CLOSE``; a server that hangs up on the EOF (the test server
        does, and so may any) makes the second write raise ``EOFError`` or
        an ``OSError``. The connection is going away either way, so that is
        not a failure of the caller's operation.
        """
        try:
            self._channel.close()
        except (EOFError, OSError):
            pass
        finally:
            self._transport.close()


def _check_host_key(endpoint: Endpoint, transport: Any) -> None:
    """The python tier's ``known_hosts`` policy, applied to paramiko's server key.

    paramiko has already verified the key's signature over the exchange
    hash during ``start_client``; what remains is whether the key is the
    expected one. We do that with our :class:`KnownHosts` rather than
    paramiko's ``HostKeys`` so ``@revoked``, hashed hosts and the
    ``StrictHostKeyChecking`` values behave exactly as in the other tiers.
    Every refusal is ``EACCES``.
    """
    # Imported here: the python tier module is only loaded when a tier needs it.
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
    """The configured key file, then the password - the python tier's order.

    ``paramiko`` is the imported module, passed in so this module never
    imports it at load time. No agent and no ``~/.ssh`` key search: the
    in-process tiers use only what the ``[SFTP PLUGIN]`` configuration
    names. Failure is ``EACCES``, listing the methods tried.
    """
    tried: list[str] = []
    if endpoint.key_file and os.path.isfile(endpoint.key_file):
        tried.append("publickey")
        # paramiko hands the passphrase to cryptography's key loader, which
        # takes bytes only (a str raises TypeError). The plugin has already
        # parsed the file with our own loader, so a missing or wrong
        # passphrase was reported there; a key paramiko still cannot use
        # (ValueError/TypeError from that loader) falls through to the
        # password, as a rejected key does.
        passphrase = endpoint.passphrase.encode("utf-8") if endpoint.passphrase else None
        try:
            pkey = paramiko.PKey.from_path(endpoint.key_file, passphrase)
            transport.auth_publickey(endpoint.user, pkey)
        except (paramiko.SSHException, ValueError, TypeError):
            pass
    if not transport.is_authenticated() and endpoint.password:
        tried.append("password")
        with contextlib.suppress(paramiko.SSHException):
            transport.auth_password(endpoint.user, endpoint.password)
    if not transport.is_authenticated():
        raise GError(
            f"All supported authentication methods failed for {endpoint.label} "
            f"(tried {', '.join(tried) or 'none'})",
            errno.EACCES,
        )


def connect(endpoint: Endpoint, key_files: Any = ()) -> ParamikoStream:
    """Open a paramiko transport to ``endpoint`` and start the ``sftp`` subsystem.

    ``key_files`` (the keys the plugin already parsed) is accepted for
    signature parity with the python tier and ignored. Connect failures map
    as in :func:`.ssh._open_socket`; any paramiko ``SSHException`` during the
    handshake becomes ``ECONNRESET``, and once the transport exists it (with
    its socket) is closed on every failure path. The endpoint timeout bounds the
    handshake and the channel open, not later reads.
    """
    import socket

    # paramiko ships no type information (no py.typed, and typeshed's stubs
    # are not a dependency), so mypy cannot check calls into it.
    import paramiko

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
