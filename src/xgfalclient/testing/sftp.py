"""In-process SFTP and SSH-2 servers, and a fake ``ssh``, for testing the sftp plugin.

Three layers, each usable alone:

:class:`SFTPServer`
    An SFTP v3 server over a local directory, behaving like OpenSSH's
    ``sftp-server``: the same extensions, the same ``errno`` to status
    mapping (so ``EEXIST`` arrives as a bare ``FAILURE``, exactly the
    ambiguity a client has to resolve), ``.`` and ``..`` in listings.
    :meth:`SFTPServer.pair` connects a client stream to it over a
    socketpair. Faults: :meth:`~SFTPServer.inject` a status for the next
    request of a type, :attr:`~SFTPServer.faults` for short reads,
    reordered replies, dropped connections and garbage.

:class:`SSHServer`
    An SSH-2 server over a socketpair speaking the same algorithms as the
    client transport (curve25519 and DH group KEX; ed25519, RSA and ECDSA
    host keys; AES-GCM, ChaCha20-Poly1305 and AES-CTR+HMAC; OpenSSH's strict
    KEX, the Terrapin countermeasure), with password and public-key
    authentication, the ``sftp`` subsystem wired to an :class:`SFTPServer`,
    forced rekeying and handshake faults.

:func:`fake_ssh_main`
    What a test configures as the plugin's ``ssh`` command: it reads the
    host from OpenSSH's command line, fails the way ``ssh`` fails (stderr
    text and exit status 255) for the magic host names of
    :data:`FAKE_HOSTS`, and otherwise serves SFTP on stdin/stdout.
    :func:`write_fake_ssh` writes the executable.

Which to use: :meth:`SFTPServer.pair` for anything about SFTP itself (the
client's requests, pipelining, status mapping), :class:`SSHServer` for the
SSH transport, and the fake ``ssh`` for the OpenSSH tier's process
handling and error classification. None of them listens on a port; the
interop tests run against a real sshd instead.

How this module is organised: it is the public facade, and defines nothing
itself. Each layer lives in the private :mod:`xgfalclient.testing._sftp`
package - the SFTP session and its handlers, the :class:`SFTPServer` object,
the SSH-2 transport, the SSH server and its channel, the fake ``ssh`` - and
every name the single-module layout had, private helpers and the imported
names tests reach through it (``string``, ``Reader``, ``struct``)
included, is re-exported here. ``_HANDLERS`` is the very dict the sessions
dispatch through, so ``monkeypatch.setitem(sftp._HANDLERS, ...)`` reaches
them; nothing in the package reads any other name through this module, so
patch a private helper in its own ``_sftp`` module.
"""

from __future__ import annotations

# Every name the single-module layout had is re-exported with a redundant
# ``as`` (so mypy's strict no-implicit-reexport and ruff treat it as this
# module's API): what it defined, now defined in ``_sftp``, and what it
# imported, which tests reach through it (``sftp.string``, ``sftp.Reader``,
# ``sftp.struct``). Modules the layout imported under a private alias are not
# re-exported: reach them under their own names.
import contextlib as contextlib
import errno as errno
import hashlib as hashlib
import os as os
import posixpath as posixpath
import socket as socket
import struct as struct
import sys as sys
import threading as threading
import time as time
from collections.abc import Callable as Callable
from typing import Any as Any
from typing import BinaryIO as BinaryIO

from ..crypto.sshkeys import KeyError_ as KeyError_
from ..crypto.sshkeys import PrivateKey as PrivateKey
from ..crypto.sshkeys import PublicKey as PublicKey
from ..crypto.sshkeys import Reader as Reader
from ..crypto.sshkeys import mpint as mpint
from ..crypto.sshkeys import parse_public_blob as parse_public_blob
from ..crypto.sshkeys import string as string
from ..crypto.sshkeys import uint32 as uint32
from ..plugins.sftp.protocol import Attrs as Attrs
from ._sftp.fake_ssh import FAKE_HOSTS as FAKE_HOSTS
from ._sftp.fake_ssh import _fake_ssh_host as _fake_ssh_host
from ._sftp.fake_ssh import _read_stdio as _read_stdio
from ._sftp.fake_ssh import fake_ssh_main as fake_ssh_main
from ._sftp.fake_ssh import write_fake_ssh as write_fake_ssh
from ._sftp.server import OPENSSH_EXTENSIONS as OPENSSH_EXTENSIONS
from ._sftp.server import SFTPServer as SFTPServer
from ._sftp.server import SocketStream as SocketStream
from ._sftp.server import _SocketIO as _SocketIO
from ._sftp.session import _HANDLERS as _HANDLERS
from ._sftp.session import _attrs as _attrs
from ._sftp.session import _Drop as _Drop
from ._sftp.session import _Handle as _Handle
from ._sftp.session import _longname as _longname
from ._sftp.session import _Session as _Session
from ._sftp.session import portable_status as portable_status
from ._sftp.ssh import _SERVER_MAXPACKET as _SERVER_MAXPACKET
from ._sftp.ssh import _SERVER_WINDOW as _SERVER_WINDOW
from ._sftp.ssh import SSHServer as SSHServer
from ._sftp.ssh import _SSHServerConn as _SSHServerConn
from ._sftp.transport import _read_exact_from as _read_exact_from
from ._sftp.transport import _SSHTransport as _SSHTransport

__all__ = [
    "FAKE_HOSTS",
    "SFTPServer",
    "SSHServer",
    "SocketStream",
    "fake_ssh_main",
    "portable_status",
    "write_fake_ssh",
]
