"""The OpenSSH subprocess transport tier."""

from __future__ import annotations

import errno
import os
import subprocess
from pathlib import Path

import pytest

from xgfalclient.errors import GError
from xgfalclient.plugins.sftp import openssh
from xgfalclient.plugins.sftp.client import SFTPClient
from xgfalclient.plugins.sftp.endpoint import Endpoint
from xgfalclient.testing.sftp import write_fake_ssh


@pytest.fixture
def fake_ssh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    root = tmp_path / "root"
    root.mkdir()
    (root / "hello.txt").write_bytes(b"hello world\n")
    monkeypatch.setenv("XGFAL_FAKE_ROOT", str(root))
    return write_fake_ssh(tmp_path / "ssh")


def _endpoint(**kw: object) -> Endpoint:
    defaults: dict[str, object] = dict(host="example.org", port=22, user="alice")
    defaults.update(kw)
    return Endpoint(**defaults)  # type: ignore[arg-type]


# -- command line and environment --------------------------------------------


def test_command_line_shape() -> None:
    endpoint = _endpoint(
        port=2222,
        explicit_port=True,
        key_file="/k/id",
        user="bob",
        known_hosts="/kh",
        strict_host_keys="yes",
        ssh_options=("Compression=no",),
        timeout=30,
    )
    argv = openssh.command(["ssh"], endpoint)
    assert argv[0] == "ssh"
    assert "-oBatchMode=yes" in argv and "-oNumberOfPasswordPrompts=0" in argv
    assert "-oStrictHostKeyChecking=yes" in argv
    assert "-oUserKnownHostsFile=/kh" in argv
    assert "-oConnectTimeout=30" in argv
    assert "-i" in argv and "/k/id" in argv
    assert "-oCompression=no" in argv
    assert argv[-3:] == ["--", "example.org", "sftp"]
    assert "-p" in argv and "2222" in argv
    assert "-l" in argv and "bob" in argv
    # No password machinery ever appears.
    assert not any("askpass" in a.lower() or "BatchMode=no" in a for a in argv)


def test_command_line_minimal() -> None:
    endpoint = _endpoint(user="", timeout=0)
    argv = openssh.command(["ssh"], endpoint)
    assert "-l" not in argv  # no user
    assert not any(a.startswith("-oConnectTimeout") for a in argv)  # no timeout


def test_environment_neutralises_askpass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_ASKPASS_REQUIRE", "force")
    env = openssh.environment(_endpoint())
    assert "SSH_ASKPASS_REQUIRE" not in env
    # An explicit base environment is copied, not os.environ.
    base = {"SSH_ASKPASS_REQUIRE": "force", "HOME": "/home/alice"}
    assert openssh.environment(_endpoint(), base) == {"HOME": "/home/alice"}
    assert "SSH_ASKPASS_REQUIRE" in base


def test_find_ssh() -> None:
    assert openssh.find_ssh("/bin/sh -x") == ["/bin/sh", "-x"]
    assert openssh.find_ssh("definitely-not-a-real-command-xyz") is None
    found = openssh.find_ssh("")
    assert found is None or (len(found) == 1 and found[0].endswith("ssh"))
    # A blank SSH_COMMAND names nothing.
    assert openssh.find_ssh("   ") is None


def test_find_ssh_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(openssh.shutil, "which", lambda name: f"/opt/bin/{name}")
    # A bare name found on PATH is kept as given; ssh itself resolves to its path.
    assert openssh.find_ssh("gsissh -v") == ["gsissh", "-v"]
    assert openssh.find_ssh("") == ["/opt/bin/ssh"]
    monkeypatch.setattr(openssh.shutil, "which", lambda name: None)
    assert openssh.find_ssh("") is None


# -- ssh_error mapping --------------------------------------------------------


@pytest.mark.parametrize(
    ("stderr", "code"),
    [
        ("Host key verification failed.", errno.EACCES),
        ("REMOTE HOST IDENTIFICATION HAS CHANGED", errno.EACCES),
        ("alice@h: Permission denied (publickey).", errno.EACCES),
        ("Too many authentication failures", errno.EACCES),
        ("ssh: Could not resolve hostname h", errno.EREMOTE),
        ("Name or service not known", errno.EREMOTE),
        ("nodename nor servname provided", errno.EREMOTE),
        ("connect to host h port 22: Connection refused", errno.ECONNREFUSED),
        ("Operation timed out", errno.ETIMEDOUT),
        ("No route to host", errno.EHOSTUNREACH),
        ("Network is unreachable", errno.ENETUNREACH),
        ("subsystem request failed on channel 0", errno.EPROTONOSUPPORT),
        ("Connection reset by peer", errno.ECONNRESET),
        ("Connection closed by remote host", errno.ECONNRESET),
        ("client_loop: Broken pipe", errno.ECONNRESET),
    ],
)
def test_ssh_error_mapping(stderr: str, code: int) -> None:
    err = openssh.ssh_error(stderr, 255, _endpoint())
    assert err.code == code


def test_ssh_error_unknown() -> None:
    err = openssh.ssh_error("something weird happened", 3, _endpoint())
    assert err.code == errno.ECONNRESET and "status 3" in err.message
    # Empty stderr still yields a diagnostic.
    assert "no diagnostic" in openssh.ssh_error("", None, _endpoint()).message


# -- live subprocess (the fake ssh) ------------------------------------------


def test_connect_and_transfer(fake_ssh: str) -> None:
    endpoint = _endpoint(host="server.example")
    stream = openssh.connect([fake_ssh], endpoint)
    client = SFTPClient(stream)
    client.handshake()
    assert client.stat(b"/hello.txt").size == 12
    client.close()


def test_connect_bulk_upload(fake_ssh: str, tmp_path: Path) -> None:
    # A large write exercises the writev loop across a filling pipe.
    from xgfalclient.plugins.sftp import protocol as fx
    from xgfalclient.plugins.sftp.client import WriteBehind

    payload = os.urandom(500_000)
    endpoint = _endpoint(host="server.example")
    stream = openssh.connect([fake_ssh], endpoint)
    client = SFTPClient(stream)
    client.handshake()
    handle = client.open(b"/up.bin", fx.FXF_WRITE | fx.FXF_CREAT | fx.FXF_TRUNC)
    writer = WriteBehind(client, handle)
    writer.write(0, payload)
    writer.flush()
    client.close_handle(handle)
    client.close()
    assert (Path(os.environ["XGFAL_FAKE_ROOT"]) / "up.bin").read_bytes() == payload


@pytest.mark.parametrize(
    ("host", "code"),
    [
        ("refused.invalid", errno.ECONNREFUSED),
        ("unknownhost.invalid", errno.EREMOTE),
        ("badauth.invalid", errno.EACCES),
        ("nosubsystem.invalid", errno.EPROTONOSUPPORT),
    ],
)
def test_magic_host_failures(fake_ssh: str, host: str, code: int) -> None:
    endpoint = _endpoint(host=host)
    stream = openssh.connect([fake_ssh], endpoint)
    client = SFTPClient(stream)
    with pytest.raises(GError) as caught:
        client.handshake()
    assert caught.value.code == code
    client.close()


def test_connect_missing_binary() -> None:
    endpoint = _endpoint()
    with pytest.raises(GError) as caught:
        openssh.connect(["/no/such/ssh/binary"], endpoint)
    assert caught.value.code in (errno.ENOENT, errno.EACCES)


def test_connect_start_failure_without_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise OSError("cannot start")

    monkeypatch.setattr(openssh.subprocess, "Popen", refuse)
    with pytest.raises(GError, match="Could not start ssh: cannot start") as caught:
        openssh.connect(["ssh"], _endpoint())
    assert caught.value.code == errno.ENOENT


# -- PipeStream internals via a controllable process --------------------------


class FakePopen:
    """A stand-in for ``subprocess.Popen`` backed by real pipes."""

    def __init__(
        self, stdout_data: bytes = b"", stderr_data: bytes = b"", alive: bool = False
    ) -> None:
        r_in, w_in = os.pipe()  # our stdin -> process (we write here)
        r_out, w_out = os.pipe()  # process stdout -> us (we read here)
        r_err, w_err = os.pipe()
        self.stdin = os.fdopen(w_in, "wb", 0)
        self._stdin_r = r_in
        self.stdout = os.fdopen(r_out, "rb", 0)
        if stdout_data:
            os.write(w_out, stdout_data)
        self._w_out = w_out
        self._alive = alive
        if not alive:
            os.close(w_out)  # EOF on stdout
        self.stderr = os.fdopen(r_err, "rb", 0)
        # Write stderr from a thread so a payload larger than the pipe buffer
        # does not block construction before the reader drains it.
        import threading

        def pump() -> None:
            try:
                os.write(w_err, stderr_data)
            finally:
                os.close(w_err)

        threading.Thread(target=pump, daemon=True).start()
        self._returncode = 255
        self.killed = False

    def poll(self) -> int | None:
        return None if self._alive else self._returncode

    def wait(self, timeout: float | None = None) -> int:
        if self._alive and timeout is not None:
            raise subprocess.TimeoutExpired("ssh", timeout)
        return self._returncode

    def kill(self) -> None:
        self.killed = True
        self._alive = False
        if self._w_out >= 0:
            try:
                os.close(self._w_out)
            except OSError:
                pass
            self._w_out = -1


def test_pipestream_recv_timeout() -> None:
    process = FakePopen(alive=True)  # stays open, never sends
    stream = openssh.PipeStream(process, _endpoint(), timeout=0.2)
    with pytest.raises(GError) as caught:
        stream.recv_into(memoryview(bytearray(16)))
    assert caught.value.code == errno.ETIMEDOUT
    process.kill()
    stream.close()


def test_pipestream_failure_kills_hung_process() -> None:
    process = FakePopen(stderr_data=b"Connection refused\n", alive=True)
    stream = openssh.PipeStream(process, _endpoint(), timeout=0)
    # No timeout: recv sees EOF only after the process is torn down, so drive
    # failure() directly (the process is hung, so it is killed).
    err = stream.failure()
    assert err.code == errno.ECONNREFUSED
    assert process.killed
    stream.close()


def test_pipestream_send_after_exit_raises() -> None:
    process = FakePopen(stderr_data=b"Permission denied\n", alive=False)
    stream = openssh.PipeStream(process, _endpoint(), timeout=0)
    os.close(process._stdin_r)  # closing the read end makes writes fail
    with pytest.raises(GError) as caught:
        stream.send(b"x" * 100000)
    assert caught.value.code == errno.EACCES
    stream.close()


def test_pipestream_stderr_is_capped() -> None:
    process = FakePopen(stderr_data=b"line\n" * 20000, alive=False)
    stream = openssh.PipeStream(process, _endpoint(), timeout=0)
    text = stream.stderr()
    assert 65536 <= len(text) <= 70000  # only the head is kept
    stream.close()


def test_pipestream_recv_without_timeout_reads_data() -> None:
    process = FakePopen(stdout_data=b"payload-bytes", alive=False)
    stream = openssh.PipeStream(process, _endpoint(), timeout=0)  # no select
    view = memoryview(bytearray(32))
    got = stream.recv_into(view)
    assert bytes(view[:got]) == b"payload-bytes"
    stream.close()


def test_pipestream_recv_readv_oserror() -> None:
    process = FakePopen(stderr_data=b"Connection reset\n", alive=False)
    stream = openssh.PipeStream(process, _endpoint(), timeout=0)
    stream.process.stdout.close()  # a closed fd makes readv raise OSError
    with pytest.raises(GError):
        stream.recv_into(memoryview(bytearray(16)))
    stream.close()


def test_pipestream_send_partial_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakePopen(alive=False)
    stream = openssh.PipeStream(process, _endpoint(), timeout=0)
    written_out = bytearray()
    # Return a short count first (a partial write of the first view), then one
    # that ends exactly on the view boundary, then the rest. The empty part is
    # never handed to writev at all.
    counts = iter([3, 2])

    def fake_writev(fd: int, views: list[memoryview]) -> int:
        data = b"".join(bytes(v) for v in views)
        n = next(counts, len(data))
        written_out.extend(data[:n])
        return n

    monkeypatch.setattr(openssh.os, "writev", fake_writev)
    stream.send(b"hello", b"", b"world")
    assert bytes(written_out) == b"helloworld"
    stream.close()


class _RaisingClose:
    def __init__(self, fd: int) -> None:
        self._fd = fd

    def fileno(self) -> int:
        return self._fd

    def close(self) -> None:
        raise OSError("close failed")


def test_pipestream_close_idempotent_and_tolerant(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakePopen(alive=True)
    stream = openssh.PipeStream(process, _endpoint(), timeout=0)
    # Replace the pipes with ones whose close() raises, to cover the guard.
    stream.process.stdin = _RaisingClose(process.stdin.fileno())  # type: ignore[assignment]
    stream.process.stdout = _RaisingClose(process.stdout.fileno())  # type: ignore[assignment]

    # Make the kill-wait loop finish instantly, then require a kill.
    values = iter([0.0, 100.0, 100.0])
    monkeypatch.setattr(openssh.time, "monotonic", lambda: next(values, 100.0))
    stream.close()
    assert process.killed
    stream.close()  # idempotent second call returns immediately
