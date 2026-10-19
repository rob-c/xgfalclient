"""A fake ``ssh`` executable for the sftp plugin's OpenSSH transport tier.

:func:`write_fake_ssh` writes a script that runs :func:`fake_ssh_main`
(imported from the facade, :mod:`xgfalclient.testing.sftp`), which parses
OpenSSH's command line, fails like ``ssh`` for the magic host names in
:data:`FAKE_HOSTS`, and otherwise serves SFTP on stdin/stdout with an
:class:`~.server.SFTPServer`.

It stands in for the OpenSSH tier of the sftp plugin
(:mod:`xgfalclient.plugins.sftp.openssh`), which runs ``ssh ... -s -- host
sftp`` as a child process and speaks SFTP over its pipes. There is no SSH
at all here: the fake goes straight to SFTP, which is exactly what the
plugin sees of a real ``ssh`` once it has logged in. What it reproduces is
the part the plugin interprets - the exit status and the stderr text of a
failed connection - so the plugin's mapping of those to gfal2 errors is
tested without a network or an sshd.

It runs in a separate process, so it is configured through the
environment rather than arguments the plugin would not pass:
``XGFAL_FAKE_ROOT`` and ``XGFAL_FAKE_CHECKFILE``. The test sets them with
``monkeypatch.setenv``; the child inherits them.
"""

from __future__ import annotations

import os
import sys
from typing import BinaryIO

from .server import SFTPServer

#: Magic host names a test can target to make the fake ssh fail like the real
#: one: ``name -> (stderr line, exit status)``. The texts are OpenSSH's own
#: (255 is the status ``ssh`` exits with for any error of its own), because
#: the plugin classifies failures by matching them. ``.invalid`` (RFC 6761)
#: guarantees no test could ever reach a real host by these names.
FAKE_HOSTS: dict[str, tuple[str, int]] = {
    "refused.invalid": ("ssh: connect to host refused.invalid port 22: Connection refused", 255),
    "unknownhost.invalid": (
        "ssh: Could not resolve hostname unknownhost.invalid: Name or service not known",
        255,
    ),
    "badauth.invalid": ("badauth.invalid: Permission denied (publickey,password).", 255),
    "changedkey.invalid": (
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
        "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n"
        "Host key verification failed.",
        255,
    ),
    "nosubsystem.invalid": ("subsystem request failed on channel 0", 255),
    "timeout.invalid": ("ssh: connect to host timeout.invalid port 22: Operation timed out", 255),
}


def _fake_ssh_host(argv: list[str]) -> str:
    """The host name out of an ``ssh ... -- host sftp`` command line.

    The plugin always ends its options with ``--``, so the host is the word
    after it. The fallback keeps the fake usable by hand (``ssh host``), but
    it does not know which options take a value, so ``-p 2222 host`` would
    give ``2222``.
    """
    if "--" in argv:
        rest = argv[argv.index("--") + 1 :]
        return rest[0] if rest else ""
    # Fallback: the last non-option token before "sftp".
    tokens = [a for a in argv[1:] if not a.startswith("-")]
    return tokens[0] if tokens else ""


def fake_ssh_main(argv: list[str], stdin: BinaryIO, stdout: BinaryIO, stderr: BinaryIO) -> int:
    """Behave like ``ssh -s host sftp``: fail for a magic host, else serve SFTP on stdio.

    The SFTP root is ``$XGFAL_FAKE_ROOT``; ``$XGFAL_FAKE_CHECKFILE`` (comma
    separated) turns on ``check-file-name``. A test puts this on ``PATH`` as
    ``ssh`` through :func:`write_fake_ssh`.
    """
    host = _fake_ssh_host(argv)
    if host in FAKE_HOSTS:
        message, status = FAKE_HOSTS[host]
        stderr.write(message.encode() + b"\n")
        stderr.flush()
        return status
    root = os.environ.get("XGFAL_FAKE_ROOT", ".")
    check = tuple(a for a in os.environ.get("XGFAL_FAKE_CHECKFILE", "").split(",") if a)
    server = SFTPServer(root, check_file=check)

    def write(data: bytes) -> None:
        """Write a reply and flush it: a pipe is buffered and the plugin waits for it."""
        stdout.write(data)
        stdout.flush()

    # serve() swallows the end-of-stream that a client disconnect raises.
    server.serve(lambda n: _read_stdio(stdin, n), write)
    return 0


def _read_stdio(stdin: BinaryIO, count: int) -> bytes:
    """Exactly ``count`` bytes from stdin; ``EOFError`` when the plugin closes the pipe.

    A buffered pipe's ``read`` may return less than asked, hence the loop.
    """
    chunks = bytearray()
    while len(chunks) < count:
        got = stdin.read(count - len(chunks))
        if not got:
            raise EOFError
        chunks += got
    return bytes(chunks)


def write_fake_ssh(path: str | os.PathLike[str]) -> str:
    """Write an executable ``ssh`` stand-in at ``path`` and return its path.

    The script's shebang is this interpreter, so the child runs in the same
    virtualenv and imports the same ``xgfalclient``; the test must still make
    that importable in the child (via ``PYTHONPATH`` when running from a
    source tree). Tests hand the returned path to the plugin as its
    ``SFTP PLUGIN`` / ``SSH_COMMAND`` option.
    """
    target = os.fspath(path)
    script = (
        f"#!{sys.executable}\n"
        "import sys\n"
        "from xgfalclient.testing.sftp import fake_ssh_main\n"
        "sys.exit(\n"
        "    fake_ssh_main(sys.argv, sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer)\n"
        ")\n"
    )
    with open(target, "w", encoding="ascii") as handle:
        handle.write(script)
    os.chmod(target, 0o755)
    return target
