"""Transport tier 1: the system OpenSSH client, speaking SFTP over its pipes.

``ssh -s host sftp`` starts the server's ``sftp`` subsystem and connects it
to ssh's stdin and stdout, which is exactly how OpenSSH's own ``sftp``
works. Everything hard - host keys and ``known_hosts``, the agent, every
key format, Kerberos, ``~/.ssh/config`` (``ProxyJump``, ``Match``...),
AES-GCM at C speed on another core - is then OpenSSH's, and this module
only has to start it well:

* **no password ever reaches ssh.** This tier runs with ``BatchMode=yes``
  so ssh never prompts, and it authenticates only the ways ssh can without a
  secret from us: a key file (``[SFTP PLUGIN] PRIVKEY`` via ``-i``, or one
  named in ``~/.ssh/config``), ``ssh-agent``, and Kerberos/GSSAPI. An
  ``ssh`` subprocess cannot be handed a password safely - it calls
  ``closefrom(3)`` at startup, so an inherited file descriptor never reaches
  an ``SSH_ASKPASS`` helper, and argv or the environment would expose it -
  so a *configured* password (URL userinfo, ``PASSWORD``, or the credential
  store's ``PASSWD``) is not used here at all: the plugin's tier selection
  sends that connection to the in-process Python transport (or paramiko),
  which does RFC 4252 password authentication itself, the secret never
  leaving the process. Key passphrases are the same: an encrypted key used
  through this tier must be loaded into ``ssh-agent``.
* **host keys** default to ``StrictHostKeyChecking=accept-new``: a first
  contact is recorded, a changed key is refused. gfal2 (libssh2) checks no
  host key at all; refusing a changed one is the deliberate difference.
* **failures** are read from ssh's stderr and exit status and mapped to
  gfal2's errors: ``Permission denied`` is ``EACCES``, ``Connection
  refused`` ``ECONNREFUSED``, an unknown host ``EREMOTE`` as in gfal2, and
  so on.
"""

from __future__ import annotations

import errno
import os
import select
import shlex
import shutil
import subprocess
import threading
import time
from collections.abc import Sequence
from typing import Any

from ...errors import GError
from .endpoint import Endpoint

__all__ = ["PipeStream", "command", "environment", "ssh_error", "find_ssh", "connect"]


def find_ssh(configured: str = "") -> list[str] | None:
    """The ``ssh`` command: ``SSH_COMMAND`` (shell-split) or ``ssh`` on ``PATH``."""
    if configured:
        argv = shlex.split(configured)
        if argv and (os.path.isabs(argv[0]) or shutil.which(argv[0])):
            return argv
        return None
    found = shutil.which("ssh")
    return [found] if found else None


def command(ssh: Sequence[str], endpoint: Endpoint) -> list[str]:
    """The ``ssh`` argument vector for ``endpoint`` - never carrying a secret."""
    # BatchMode=yes always: this tier never has a password to type, so ssh
    # must fail rather than block on a prompt. NumberOfPasswordPrompts=0
    # skips even the keyboard-interactive round trips.
    argv = list(ssh)
    argv += ["-s", "-T", "-x", "-a", "-oLogLevel=ERROR", "-oClearAllForwardings=yes"]
    argv += ["-oBatchMode=yes", "-oNumberOfPasswordPrompts=0"]
    argv.append(f"-oStrictHostKeyChecking={endpoint.strict_host_keys}")
    if endpoint.known_hosts:
        argv.append(f"-oUserKnownHostsFile={endpoint.known_hosts}")
    if endpoint.timeout > 0:
        argv.append(f"-oConnectTimeout={endpoint.timeout}")
    argv += ["-oServerAliveInterval=15", "-oServerAliveCountMax=4"]
    if endpoint.key_file:
        argv += ["-i", endpoint.key_file]
    for option in endpoint.ssh_options:
        argv.append(f"-o{option}")
    if endpoint.explicit_port:
        argv += ["-p", str(endpoint.port)]
    if endpoint.user:
        argv += ["-l", endpoint.user]
    argv += ["--", endpoint.host, "sftp"]
    return argv


def environment(endpoint: Endpoint, base: dict[str, str] | None = None) -> dict[str, str]:
    """ssh's environment: the caller's, with any askpass override neutralised.

    The endpoint carries no secret into ssh (see the module docstring), so
    this only makes sure a hostile ``SSH_ASKPASS`` inherited from the caller
    cannot run: with ``BatchMode=yes`` ssh will not invoke it, and clearing
    ``SSH_ASKPASS_REQUIRE`` keeps that true on every version.
    """
    env = dict(os.environ if base is None else base)
    env.pop("SSH_ASKPASS_REQUIRE", None)
    return env


#: stderr fragment -> (errno, gfal2-style message). First match wins.
_FAILURES: tuple[tuple[str, int, str], ...] = (
    ("host key verification failed", errno.EACCES, "Host key verification failed"),
    ("remote host identification has changed", errno.EACCES, "Host key verification failed"),
    ("permission denied", errno.EACCES, "All supported authentication methods failed"),
    (
        "too many authentication failures",
        errno.EACCES,
        "All supported authentication methods failed",
    ),
    ("could not resolve hostname", errno.EREMOTE, "Could not resolve host"),
    ("name or service not known", errno.EREMOTE, "Could not resolve host"),
    ("nodename nor servname", errno.EREMOTE, "Could not resolve host"),
    ("connection refused", errno.ECONNREFUSED, "Could not connect"),
    ("timed out", errno.ETIMEDOUT, "Connection timed out"),
    ("no route to host", errno.EHOSTUNREACH, "Could not connect"),
    ("network is unreachable", errno.ENETUNREACH, "Could not connect"),
    ("subsystem request failed", errno.EPROTONOSUPPORT, "The server has no sftp subsystem"),
    ("connection reset", errno.ECONNRESET, "Connection reset"),
    ("connection closed", errno.ECONNRESET, "Connection closed by the server"),
    ("broken pipe", errno.ECONNRESET, "Connection closed by the server"),
)


def ssh_error(stderr: str, status: int | None, endpoint: Endpoint) -> GError:
    """The ``GError`` for an ssh that died: its stderr says why."""
    text = " ".join(stderr.split())
    lowered = text.lower()
    where = f"{endpoint.host}:{endpoint.port}"
    for fragment, code, message in _FAILURES:
        if fragment in lowered:
            return GError(f"{message} ({where}): {text}", code)
    detail = text or "no diagnostic output"
    return GError(f"ssh to {where} exited with status {status}: {detail}", errno.ECONNRESET)


class PipeStream:
    """The SFTP byte stream of a running ``ssh -s ... sftp``."""

    def __init__(
        self, process: subprocess.Popen[bytes], endpoint: Endpoint, timeout: float
    ) -> None:
        self.process = process
        self.endpoint = endpoint
        self.timeout = timeout
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        self._write_fd = process.stdin.fileno()
        self._read_fd = process.stdout.fileno()
        self._stderr: list[bytes] = []
        self._stderr_size = 0
        self._closed = False
        self._drain = threading.Thread(
            target=self._collect, args=(process.stderr,), name="xgfal-ssh-stderr", daemon=True
        )
        self._drain.start()

    def _collect(self, pipe: Any) -> None:
        # Keep the head of stderr; ssh says why it failed first.
        for line in iter(pipe.readline, b""):
            if self._stderr_size < 65536:
                self._stderr.append(line)
                self._stderr_size += len(line)
        pipe.close()

    def stderr(self) -> str:
        self._drain.join(timeout=2)
        return b"".join(self._stderr).decode("utf-8", "replace")

    def failure(self) -> GError:
        """What went wrong, once ssh has gone away."""
        try:
            status = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            status = self.process.wait()
        return ssh_error(self.stderr(), status, self.endpoint)

    def send(self, *parts: Any) -> None:
        views = [memoryview(part).cast("B") for part in parts if len(part)]
        try:
            while views:
                written = os.writev(self._write_fd, views)
                while views and written >= len(views[0]):
                    written -= len(views[0])
                    views.pop(0)
                if views and written:
                    views[0] = views[0][written:]
        except (BrokenPipeError, ValueError, OSError):
            raise self.failure() from None

    def recv_into(self, view: memoryview) -> int:
        if self.timeout > 0:
            ready, _, _ = select.select([self._read_fd], [], [], self.timeout)
            if not ready:
                raise GError(
                    f"Timed out after {self.timeout:g}s waiting for the SFTP server "
                    f"({self.endpoint.host}:{self.endpoint.port})",
                    errno.ETIMEDOUT,
                )
        try:
            got = os.readv(self._read_fd, [view])
        except OSError:
            got = 0
        if not got:
            raise self.failure()
        return got

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for pipe in (self.process.stdin, self.process.stdout):
            try:
                pipe.close()  # type: ignore[union-attr]
            except OSError:
                pass
        deadline = time.monotonic() + 2
        while self.process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


def connect(ssh: Sequence[str], endpoint: Endpoint) -> PipeStream:
    """Start ssh for ``endpoint``; the SFTP handshake is the caller's first read."""
    argv = command(ssh, endpoint)
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment(endpoint),
            start_new_session=True,
            bufsize=0,
        )
    except OSError as exc:
        raise GError(
            f"Could not start {argv[0]}: {exc.strerror or exc}", exc.errno or errno.ENOENT
        ) from exc
    return PipeStream(process, endpoint, float(endpoint.timeout))
