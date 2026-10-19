"""``cancel()`` against a server that has stopped sending: blocked I/O wakes at once.

A copy checks for a cancel between chunks, and a namespace call not at all;
blocked in a ``recv`` on a server that went silent, either used to hold
``cancel()`` (and the caller) for the whole operation timeout - five minutes
by default. Plugins now register what they block on with the context
(:meth:`~xgfalclient.Gfal2Context.register_abort`), and ``cancel()`` shuts it
down: the operation fails with ``ECANCELED`` within moments, and ``cancel()``
returns as soon as it has. Each test here stalls one of the in-tree servers
and measures both.
"""

from __future__ import annotations

import contextlib
import errno
import os
import socket
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import xgfalclient
from test_gridftp_helpers import ftp as ftp
from test_http_helpers import dav as dav
from test_http_helpers import hctx as hctx
from test_http_helpers import write
from xgfalclient import GError
from xgfalclient.context import CANCELED_BY_USER
from xgfalclient.crypto.sshkeys import PrivateKey
from xgfalclient.plugins.dcap.plugin import DcapPlugin
from xgfalclient.plugins.gridftp.plugin import GROUP as GRIDFTP
from xgfalclient.plugins.http import _ranged
from xgfalclient.testing.dcap import DcapServer
from xgfalclient.testing.gridftp import GridFTPServer
from xgfalclient.testing.sftp import SFTPServer, SSHServer
from xgfalclient.testing.webdav import WebDAVServer

MB = 1 << 20
#: How long the server stays silent: far past every bound asserted below.
STALL = 60.0
#: How quickly a cancelled operation must fail, and cancel() return.
PROMPT = 2.0


class Canceller:
    """Cancels ``context`` once ``ready()`` says the operation is blocked; times both ends."""

    def __init__(self, context: xgfalclient.Gfal2Context, ready: Callable[[], bool]) -> None:
        self.context = context
        self.ready = ready
        self.started = 0.0
        self.returned = 0.0
        self.answer: int | None = None
        self.thread = threading.Thread(target=self._run, name="test-canceller")

    def _run(self) -> None:
        deadline = time.monotonic() + 30
        while not self.ready() and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.2)  # let the operation get into its blocking recv
        self.started = time.monotonic()
        self.answer = self.context.cancel()
        self.returned = time.monotonic()

    def __enter__(self) -> Canceller:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.thread.join(STALL)


def assert_cancelled_promptly(
    context: xgfalclient.Gfal2Context, ready: Callable[[], bool], call: Callable[[], Any]
) -> GError:
    """Run ``call`` (which stalls), cancel it once ``ready()``; it must stop at once."""
    with Canceller(context, ready) as canceller, pytest.raises(GError) as caught:
        call()
    failed = time.monotonic()
    assert canceller.started, "the cancel never happened"
    assert caught.value.code == errno.ECANCELED, caught.value
    assert failed - canceller.started < PROMPT
    assert canceller.returned - canceller.started < PROMPT
    assert canceller.answer == 1
    return caught.value


def _consumed(server: WebDAVServer) -> Callable[[], bool]:
    return lambda: not server.faults


# -- HTTP ----------------------------------------------------------------------------------


def test_a_download_from_a_silent_server_is_cancelled_at_once(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer, tmp_path: Path
) -> None:
    data = os.urandom(MB)
    write(dav, "/data/f", data)
    dav.fault("GET", body=data, truncate=64 << 10, hold=STALL)
    target = tmp_path / "f"
    error = assert_cancelled_promptly(
        hctx, _consumed(dav), lambda: hctx.filecopy(dav.url("/data/f"), target.as_uri())
    )
    assert error.message == "Transfer canceled"
    assert not target.exists()  # the failed copy's destination is removed, as ever


def test_a_parallel_download_with_one_silent_stream_is_cancelled_at_once(
    hctx: xgfalclient.Gfal2Context,
    dav: WebDAVServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_ranged, "PARALLEL_THRESHOLD", MB)
    data = os.urandom(4 * MB)
    write(dav, "/data/f", data)
    dav.fault("GET", body=data[:MB], truncate=1000, status=206, hold=STALL)
    params = hctx.transfer_parameters()
    params.nbstreams = 2
    assert_cancelled_promptly(
        hctx,
        _consumed(dav),
        lambda: hctx.filecopy(params, dav.url("/data/f"), (tmp_path / "f").as_uri()),
    )


def test_a_stat_answered_by_silence_is_cancelled_at_once(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    write(dav, "/data/f", b"x")
    dav.fault("PROPFIND", hold=STALL)
    error = assert_cancelled_promptly(hctx, _consumed(dav), lambda: hctx.stat(dav.url("/data/f")))
    assert CANCELED_BY_USER in error.message  # in davix's "Result ... after 1 attempts"
    # The drain is over: the next call is not refused, and the pool recovers.
    assert hctx.stat(dav.url("/data/f")).st_size == 1


# -- GridFTP -------------------------------------------------------------------------------


@pytest.fixture
def gctx() -> Iterator[xgfalclient.Gfal2Context]:
    context = xgfalclient.creat_context()
    context.set_opt_integer(GRIDFTP, "OPERATION_TIMEOUT", 300)  # never what ends the wait
    yield context
    context.free()


def _logged(server: GridFTPServer, verb: str) -> Callable[[], bool]:
    return lambda: any(line.startswith(verb) for line in server.log)


def test_a_gridftp_command_never_answered_is_cancelled_at_once(
    gctx: xgfalclient.Gfal2Context, ftp: GridFTPServer
) -> None:
    (Path(ftp.root) / "f").write_bytes(b"x")
    ftp.faults["MLST"] = "hang"
    assert_cancelled_promptly(gctx, _logged(ftp, "MLST"), lambda: gctx.stat(ftp.url("/f")))
    del ftp.faults["MLST"]
    assert gctx.stat(ftp.url("/f")).st_size == 1  # a fresh session, not the aborted one


def test_a_gridftp_stream_gone_silent_is_cancelled_at_once(
    gctx: xgfalclient.Gfal2Context, ftp: GridFTPServer, tmp_path: Path
) -> None:
    (Path(ftp.root) / "f").write_bytes(os.urandom(MB))
    ftp.data_faults["RETR"] = "stall"
    with gctx.open(ftp.url("/f"), "r") as handle:
        assert_cancelled_promptly(gctx, _logged(ftp, "RETR"), lambda: handle.read_bytes(MB))


def test_a_gridftp_download_gone_silent_is_cancelled_at_once(
    gctx: xgfalclient.Gfal2Context, ftp: GridFTPServer, tmp_path: Path
) -> None:
    (Path(ftp.root) / "f").write_bytes(os.urandom(MB))
    ftp.data_faults["RETR"] = "stall"
    target = tmp_path / "f"
    assert_cancelled_promptly(
        gctx, _logged(ftp, "RETR"), lambda: gctx.filecopy(ftp.url("/f"), target.as_uri())
    )


# -- dCap ----------------------------------------------------------------------------------


@pytest.fixture
def door(tmp_path: Path) -> Iterator[DcapServer]:
    root = tmp_path / "ns"
    (root / "data").mkdir(parents=True)
    (root / "data" / "f").write_bytes(b"hello world\n")
    with DcapServer(root) as server:
        yield server


@pytest.fixture
def dctx() -> Iterator[xgfalclient.Gfal2Context]:
    context = xgfalclient.creat_context()
    if not any(type(plugin) is DcapPlugin for plugin in context.plugins):
        context.add_plugin(DcapPlugin)
    context.set_opt_integer("DCAP PLUGIN", "OPERATION_TIMEOUT", 300)
    yield context
    context.free()


def test_a_dcap_mover_gone_silent_is_cancelled_at_once(
    dctx: xgfalclient.Gfal2Context, door: DcapServer
) -> None:
    with dctx.open(door.url("/data/f"), "r") as handle:
        door.fault("stall")
        assert_cancelled_promptly(dctx, lambda: not door._faults, lambda: handle.read_bytes(5))


def test_a_dcap_door_gone_silent_is_cancelled_at_once(
    dctx: xgfalclient.Gfal2Context, door: DcapServer
) -> None:
    asked, release = threading.Event(), threading.Event()

    def silent(session: int, args: list[str]) -> None:
        asked.set()
        release.wait(STALL)  # the door thinks forever; answering normally after

    door.inject("stat", silent)
    try:
        assert_cancelled_promptly(dctx, asked.is_set, lambda: dctx.stat(door.url("/data/f")))
    finally:
        release.set()


# -- XRootD ---------------------------------------------------------------------------------


@pytest.fixture
def xserver() -> Iterator[Any]:
    from xrdclient.testing import FakeServer

    with FakeServer(files={"/data/f": os.urandom(MB)}) as server:
        yield server


def _silent(server: Any, opcode: int) -> tuple[threading.Event, threading.Event]:
    """Make ``server`` take requests of ``opcode`` and never answer them (until released)."""
    asked, release = threading.Event(), threading.Event()

    def handler(conn: Any, sid: int, params: bytes, body: bytes) -> Iterator[bytes]:
        asked.set()
        release.wait(STALL)
        return iter(())

    server.handlers[opcode] = handler
    return asked, release


def test_an_xrootd_request_never_answered_is_cancelled_at_once(
    ctx: xgfalclient.Gfal2Context, xserver: Any
) -> None:
    from xrdclient.proto import constants

    host, port = xserver.address
    ctx.set_opt_string("XROOTD PLUGIN", "XRD_REQUESTTIMEOUT", "300")
    asked, release = _silent(xserver, constants.kXR_stat)
    try:
        assert_cancelled_promptly(
            ctx, asked.is_set, lambda: ctx.stat(f"root://{host}:{port}//data/f")
        )
    finally:
        release.set()


def test_an_xrootd_read_never_answered_is_cancelled_at_once(
    ctx: xgfalclient.Gfal2Context, xserver: Any
) -> None:
    from xrdclient.proto import constants

    host, port = xserver.address
    with ctx.open(f"root://{host}:{port}//data/f", "r") as handle:
        asked, release = _silent(xserver, constants.kXR_read)
        try:
            assert_cancelled_promptly(ctx, asked.is_set, lambda: handle.read_bytes(MB))
        finally:
            release.set()


def test_an_xrootd_download_never_answered_is_cancelled_at_once(
    ctx: xgfalclient.Gfal2Context, xserver: Any, tmp_path: Path
) -> None:
    """The bulk download's workers are woken by the cancel, not at their next piece."""
    from xrdclient.proto import constants

    host, port = xserver.address
    target = tmp_path / "f"
    asked, release = _silent(xserver, constants.kXR_read)
    try:
        error = assert_cancelled_promptly(
            ctx,
            asked.is_set,
            lambda: ctx.filecopy(f"root://{host}:{port}//data/f", target.as_uri()),
        )
    finally:
        release.set()
    assert error.message == "Transfer canceled"


def test_an_xrootd_upload_never_answered_is_cancelled_at_once(
    ctx: xgfalclient.Gfal2Context, xserver: Any, tmp_path: Path
) -> None:
    from xrdclient.proto import constants

    host, port = xserver.address
    source = tmp_path / "f"
    source.write_bytes(os.urandom(MB))
    asked, release = _silent(xserver, constants.kXR_write)
    try:
        assert_cancelled_promptly(
            ctx,
            asked.is_set,
            lambda: ctx.filecopy(source.as_uri(), f"root://{host}:{port}//data/up"),
        )
    finally:
        release.set()


# -- SFTP ----------------------------------------------------------------------------------


@pytest.fixture(params=["python", "paramiko"])
def sftp(
    request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[xgfalclient.Gfal2Context, SFTPServer]]:
    """A context whose SFTP sessions (python or paramiko tier) reach an in-process server.

    One session is opened and pooled first, so a stall injected afterwards
    hits the operation under test and not the SSH handshake (which has only
    its connect timeout to bound it).
    """
    from xgfalclient.plugins.sftp import ssh

    if request.param == "paramiko":
        pytest.importorskip("paramiko", minversion="3.4")
    root = tmp_path / "root"
    root.mkdir()
    (root / "f").write_bytes(os.urandom(MB))
    files = SFTPServer(root)
    server = SSHServer(
        files, PrivateKey.from_ed25519_seed(os.urandom(32)), username="alice", password="pw"
    )
    real_connect = ssh.connect
    monkeypatch.setattr(
        ssh,
        "connect",
        lambda endpoint, auth, **kw: real_connect(endpoint, auth, sock=server.pair()),
    )
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kw: server.pair())
    context = xgfalclient.creat_context()
    for key, value in (
        ("USER", "alice"),
        ("PASSWORD", "pw"),
        ("KNOWN_HOSTS", str(tmp_path / "known_hosts")),
        ("TRANSPORT", request.param),
        ("TIMEOUT", "300"),
    ):
        context.set_opt_string("SFTP PLUGIN", key, value)
    context.stat(f"{SFTP}/f")  # the pooled session the operations below reuse
    yield context, files
    context.free()


SFTP = "sftp://server.example"


def _silent_sftp(
    monkeypatch: pytest.MonkeyPatch, server: SFTPServer, ptype: int
) -> threading.Event:
    """Make ``server`` swallow its next request of ``ptype`` unanswered."""
    asked = threading.Event()
    real = server._take_fault

    def take(name: str) -> bool:
        if name == "hang" and not asked.is_set() and server.log[-1][0] == ptype:
            asked.set()
            return True
        return bool(real(name))

    monkeypatch.setattr(server, "_take_fault", take)
    return asked


def test_an_sftp_request_never_answered_is_cancelled_at_once(
    sftp: tuple[xgfalclient.Gfal2Context, SFTPServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    from xgfalclient.plugins.sftp import protocol as fx

    context, server = sftp
    asked = _silent_sftp(monkeypatch, server, fx.STAT)
    assert_cancelled_promptly(context, asked.is_set, lambda: context.stat(f"{SFTP}/f"))
    assert context.stat(f"{SFTP}/f").st_size == MB  # the broken session was not pooled


def test_an_sftp_download_gone_silent_is_cancelled_at_once(
    sftp: tuple[xgfalclient.Gfal2Context, SFTPServer],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from xgfalclient.plugins.sftp import protocol as fx

    context, server = sftp
    asked = _silent_sftp(monkeypatch, server, fx.READ)
    target = tmp_path / "copy"
    error = assert_cancelled_promptly(
        context, asked.is_set, lambda: context.filecopy(f"{SFTP}/f", target.as_uri())
    )
    assert error.message == "Transfer canceled"
    assert not target.exists()  # the failed copy's destination is removed, as ever


def test_an_sftp_read_never_answered_is_cancelled_at_once(
    sftp: tuple[xgfalclient.Gfal2Context, SFTPServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    from xgfalclient.plugins.sftp import protocol as fx

    context, server = sftp
    with context.open(f"{SFTP}/f", "r") as handle:
        asked = _silent_sftp(monkeypatch, server, fx.READ)
        assert_cancelled_promptly(context, asked.is_set, lambda: handle.read_bytes(4096))


def test_an_ssh_process_is_ended_under_a_blocked_read() -> None:
    """The openssh tier's abort: ``ssh`` is killed, and the blocked read fails."""
    from xgfalclient.plugins.sftp.endpoint import Endpoint
    from xgfalclient.plugins.sftp.openssh import PipeStream

    with contextlib.ExitStack() as stack:
        process = stack.enter_context(
            __import__("subprocess").Popen(
                ["sleep", "60"],
                stdin=-1,
                stdout=-1,
                stderr=-1,  # never writes
            )
        )
        stream = PipeStream(process, Endpoint(host="h", port=22, user="u"), timeout=0)
        stack.callback(stream.close)
        threading.Timer(0.2, stream.abort).start()
        started = time.monotonic()
        with pytest.raises(GError):
            stream.recv_into(memoryview(bytearray(16)))
        assert time.monotonic() - started < PROMPT
        stream.abort()  # a process already gone is passed over


# -- the registry itself ----------------------------------------------------------------


@pytest.fixture
def ctx() -> Iterator[xgfalclient.Gfal2Context]:
    context = xgfalclient.creat_context()
    yield context
    context.free()


def test_every_kind_of_resource_is_aborted(ctx: xgfalclient.Gfal2Context) -> None:
    left, right = socket.socketpair()
    closed: list[str] = []
    called: list[str] = []

    class Handle:
        def close(self) -> None:
            closed.append("closed")

    class Broken:
        def close(self) -> None:
            raise OSError(errno.EBADF, "gone")

    gone, _ = socket.socketpair()
    gone.close()  # shutting down a closed socket fails; cancel() carries on
    tokens = [
        ctx.register_abort(resource)
        for resource in (left, Handle(), lambda: called.append("called"), Broken(), gone)
    ]
    try:
        assert ctx.cancel() == 0
        assert left.recv(1) == b""  # shut down: an end of file, not a wait
        assert closed == ["closed"] and called == ["called"]
    finally:
        for token in tokens:
            ctx.unregister_abort(token)
        left.close()
        right.close()
        _.close()


def test_unregistered_resources_are_left_alone(ctx: xgfalclient.Gfal2Context) -> None:
    left, right = socket.socketpair()
    try:
        with ctx.abort_on_cancel(left):
            pass
        ctx.unregister_abort(12345)  # unknown: nothing to do
        ctx.cancel()
        right.sendall(b"y")
        assert left.recv(1) == b"y"
    finally:
        left.close()
        right.close()


def test_registering_while_a_cancel_drains_is_refused(ctx: xgfalclient.Gfal2Context) -> None:
    started, release = threading.Event(), threading.Event()
    refused: list[GError] = []

    def blocked() -> None:
        started.set()
        release.wait(10)

    def late() -> None:
        try:
            ctx.register_abort(lambda: None)
        except GError as exc:
            refused.append(exc)

    worker = threading.Thread(target=ctx._guard, args=(blocked,))
    worker.start()
    started.wait(10)
    canceller = threading.Thread(target=ctx.cancel)
    canceller.start()
    while not ctx._cancelling:
        time.sleep(0.001)
    late()
    release.set()
    worker.join(10)
    canceller.join(10)
    assert [(e.code, e.message) for e in refused] == [(errno.ECANCELED, CANCELED_BY_USER)]


def test_cancel_waits_only_so_long_for_an_operation_nothing_can_wake(
    ctx: xgfalclient.Gfal2Context, caplog: pytest.LogCaptureFixture
) -> None:
    ctx.set_opt_integer("CORE", "CANCEL_TIMEOUT", 1)
    started, release = threading.Event(), threading.Event()

    def deaf() -> None:
        started.set()
        release.wait(10)
        raise OSError(errno.ECONNRESET, "reset")  # how it ends, once it does

    failures: list[GError] = []

    def run() -> None:
        try:
            ctx._guard(deaf)
        except GError as exc:
            failures.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    started.wait(10)
    began = time.monotonic()
    assert ctx.cancel() == 1
    assert 0.9 < time.monotonic() - began < 5
    assert "still running after 1 s" in caplog.text
    assert not ctx._cancelling  # and nothing is refused any more
    release.set()
    worker.join(10)
    # Woken at last, the operation reports the cancel, not what woke it.
    assert [(e.code, e.message) for e in failures] == [(errno.ECANCELED, CANCELED_BY_USER)]


def test_a_failure_of_an_operation_nobody_cancelled_is_its_own(
    ctx: xgfalclient.Gfal2Context,
) -> None:
    def fails() -> None:
        raise OSError(errno.ECONNRESET, "reset")

    with pytest.raises(GError) as caught:
        ctx._guard(fails)
    assert caught.value.code == errno.ECONNRESET


def test_clean_up_is_exempt_from_a_draining_cancel(ctx: xgfalclient.Gfal2Context) -> None:
    started, release = threading.Event(), threading.Event()

    def blocked() -> None:
        started.set()
        release.wait(10)

    worker = threading.Thread(target=ctx._guard, args=(blocked,))
    worker.start()
    started.wait(10)
    canceller = threading.Thread(target=ctx.cancel)
    canceller.start()
    while not ctx._cancelling:
        time.sleep(0.001)
    try:
        with ctx.abort_exempt(), ctx.abort_exempt():  # nested, as clean-ups call each other
            assert ctx.register_abort(lambda: None) == 0  # neither refused nor registered
        assert not ctx._exempt and not ctx._aborts
        with pytest.raises(GError):  # outside the block, the drain refuses again
            ctx.register_abort(lambda: None)
    finally:
        release.set()
        worker.join(10)
        canceller.join(10)


def test_a_cancel_timeout_of_zero_waits_as_long_as_it_takes(
    ctx: xgfalclient.Gfal2Context,
) -> None:
    ctx.set_opt_integer("CORE", "CANCEL_TIMEOUT", 0)
    started = threading.Event()

    def slow() -> None:
        started.set()
        time.sleep(1.2)  # past nothing: there is no limit to pass

    worker = threading.Thread(target=ctx._guard, args=(slow,))
    worker.start()
    started.wait(10)
    began = time.monotonic()
    assert ctx.cancel() == 1
    assert time.monotonic() - began > 0.9
    worker.join(10)


def test_shutdown_sockets_passes_over_what_is_not_there() -> None:
    from xgfalclient.plugin import shutdown_sockets

    live, peer = socket.socketpair()
    gone, other = socket.socketpair()
    gone.close()
    try:
        shutdown_sockets(None, gone, live)
        assert live.recv(1) == b""
    finally:
        for sock in (live, peer, other):
            sock.close()


def test_a_copy_can_register_what_it_blocks_on(ctx: xgfalclient.Gfal2Context) -> None:
    from xgfalclient.transfer import Transfer, TransferParameters

    transfer = Transfer(ctx, TransferParameters(), "a", "b")
    left, right = socket.socketpair()
    try:
        with transfer.abort_on_cancel(left):
            assert not transfer.cancelled
            ctx.cancel()
            assert transfer.cancelled
            assert left.recv(1) == b""
    finally:
        left.close()
        right.close()


def test_a_stall_the_client_outlasts_ends_on_its_own(
    hctx: xgfalclient.Gfal2Context, dav: WebDAVServer
) -> None:
    write(dav, "/data/f", b"x")
    dav.fault("PROPFIND", hold=0.2)
    with contextlib.suppress(GError):  # the hang-up may or may not be retried
        hctx.stat(dav.url("/data/f"))
    assert [r.method for r in dav.requests].count("PROPFIND") >= 1
