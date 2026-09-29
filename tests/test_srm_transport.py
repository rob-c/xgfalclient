"""httpg transport: sessions, timeouts, TLS and GSI failures, unreadable replies."""

# The shared fixtures come from test_srm; ruff sees each use as a redefinition.
# ruff: noqa: F811

from __future__ import annotations

import errno
import http.client
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from test_srm import GROUP, _fast_polls, fails, root, sctx, srm  # noqa: F401
from xgfalclient.crypto.gsi import GSIError
from xgfalclient.errors import ECOMM
from xgfalclient.plugins.srm import soap
from xgfalclient.plugins.srm.transport import HTTPGConnection, _network_error, parse_surl
from xgfalclient.testing.pki import PKI, create_pki
from xgfalclient.testing.srm import DROP, Reply, SRMServer

FAULT_NO_STRING = (
    b'<?xml version="1.0"?><e:Envelope xmlns:e="http://schemas.xmlsoap.org/soap/envelope/">'
    b"<e:Body><e:Fault><faultcode>e:Server</faultcode></e:Fault></e:Body></e:Envelope>"
)


@pytest.mark.parametrize(
    "reply, text",
    [
        (Reply(soap.fault("SOAP-ENV:Server", "boom"), 500), "boom"),
        (Reply(FAULT_NO_STRING, 500), "Unknown SOAP error (e:Server)"),
        (Reply(b"<html>no</html>", 500), "Error 500: HTTP 500 Internal Server Error"),
        (Reply(b"garbage", 200), "Unknown SOAP error (the reply is not XML"),
        (Reply(b"", 404), "Error 404: HTTP 404 Not Found"),
        (DROP, "Remote end closed connection"),
    ],
)
def test_unreadable_replies(
    sctx: xgfalclient.Gfal2Context, srm: SRMServer, reply: Reply, text: str
) -> None:
    srm.inject("srmLs", reply)
    error = fails(ECOMM, sctx.stat, srm.url("/data/f"))
    assert (
        error.message.startswith("srm-ifce err: ")
        and f"[SE][Ls][] {srm.endpoint}: " in error.message
    )
    assert text in error.message


def test_multiref_replies(grid_env: PKI, root: Path, sctx: xgfalclient.Gfal2Context) -> None:
    with SRMServer(grid_env.server_context(), root, multiref=True) as server:
        assert sctx.stat(server.url("/data/f")).st_size == 12
        assert sctx.listdir(server.url("/data")) == ["f", "sub"]


def test_no_keep_alive(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    sctx.set_opt_boolean(GROUP, "KEEP_ALIVE", False)
    sctx.stat(srm.url("/data/f"))
    sctx.stat(srm.url("/data/f"))
    assert srm.connections == 2 and srm.headers[0]["Connection"] == "close"


def test_server_that_closes(grid_env: PKI, root: Path, sctx: xgfalclient.Gfal2Context) -> None:
    with SRMServer(grid_env.server_context(), root, keep_alive=False) as server:
        sctx.stat(server.url("/data/f"))
        sctx.stat(server.url("/data/f"))
        assert server.connections == 2


def test_stale_session_is_retried(
    grid_env: PKI, root: Path, sctx: xgfalclient.Gfal2Context
) -> None:
    with SRMServer(grid_env.server_context(), root, io_timeout=0.2) as server:
        sctx.stat(server.url("/data/f"))
        time.sleep(0.5)  # the server drops the idle session
        assert sctx.stat(server.url("/data/f")).st_size == 12
        assert server.connections == 2


def test_free_closes_sessions(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    sctx.stat(srm.url("/data/f"))
    sctx.free()


def test_connection_refused(sctx: xgfalclient.Gfal2Context, grid_env: PKI) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    error = fails(errno.ECONNREFUSED, sctx.stat, f"srm://localhost:{port}/f")
    assert error.message.endswith("Connection refused\n")


@pytest.fixture
def silent() -> Iterator[int]:
    """A listener that accepts and never speaks."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    held: list[socket.socket] = []
    stop = threading.Event()

    def accept() -> None:
        listener.settimeout(0.1)
        while not stop.is_set():
            try:
                held.append(listener.accept()[0])
            except OSError:
                pass

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield listener.getsockname()[1]
    stop.set()
    thread.join()
    for conn in held:
        conn.close()
    listener.close()


def test_connect_timeout(sctx: xgfalclient.Gfal2Context, grid_env: PKI, silent: int) -> None:
    sctx.set_opt_integer(GROUP, "CONN_TIMEOUT", 1)
    error = fails(errno.ETIMEDOUT, sctx.stat, f"srm://localhost:{silent}/f")
    assert error.message.endswith("Connection fails or timeout\n")


def test_host_name_is_checked(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    url = f"srm://127.0.0.1:{srm.port}/data/f"
    error = fails(ECOMM, sctx.stat, url)
    assert "Error during the GSI handshake" in error.message
    sctx.set_opt_boolean(GROUP, "INSECURE", True)
    assert sctx.stat(url).st_size == 12


def test_untrusted_server(
    sctx: xgfalclient.Gfal2Context, grid_env: PKI, root: Path, tmp_path: Path
) -> None:
    other = create_pki(tmp_path / "other", key_slots=(5, 6, 7))
    with SRMServer(other.server_context(require_client=False), root) as server:
        error = fails(ECOMM, sctx.stat, server.url("/data/f"))
        assert "CERTIFICATE_VERIFY_FAILED" in error.message


def test_network_error_wording() -> None:
    surl = parse_surl("srm://h:1/f")
    assert _network_error(surl, "Ls", OSError(errno.EHOSTUNREACH, "x")).code == errno.EHOSTUNREACH
    assert _network_error(surl, "Ls", GSIError("bad name")).code == ECOMM
    assert _network_error(surl, "Ls", ssl.SSLError("x")).code == ECOMM
    assert "OSError" in _network_error(surl, "Ls", OSError()).message
    garbled = _network_error(surl, "Ls", http.client.BadStatusLine("junk"))
    assert garbled.code == ECOMM and garbled.message.endswith(": junk\n")


class _Anonymous:
    """A TLS context whose peer (on an anonymous cipher suite) shows no certificate."""

    def wrap_socket(self, raw: socket.socket, server_hostname: str) -> _Anonymous:
        return self

    def getpeercert(self, binary_form: bool) -> None:
        return None


def test_peer_without_a_certificate(silent: int) -> None:
    connection = HTTPGConnection(
        "localhost",
        silent,
        _Anonymous(),  # type: ignore[arg-type]
        connect_timeout=1,
        timeout=1,
        check_name=True,
    )
    with pytest.raises(GSIError, match="no certificate"):
        connection.connect()


def test_operation_timeout(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    sctx.set_opt_integer(GROUP, "OPERATION_TIMEOUT", 1)

    def slow(part: soap.Node) -> None:
        time.sleep(1.5)

    sctx.stat(srm.url("/data/f"))  # so that the slow call rides a reused session
    srm.inject("srmLs", slow)
    fails(errno.ETIMEDOUT, sctx.stat, srm.url("/data/f"))
    assert srm.operations().count("srmLs") == 2  # a timeout is not retried


def test_zero_timeouts_mean_none(sctx: xgfalclient.Gfal2Context, srm: SRMServer) -> None:
    sctx.set_opt_integer(GROUP, "CONN_TIMEOUT", 0)
    sctx.set_opt_integer(GROUP, "OPERATION_TIMEOUT", 0)
    assert sctx.stat(srm.url("/data/f")).st_size == 12


def test_globus_tls13_turn_byte(grid_env: PKI, root: Path, sctx: xgfalclient.Gfal2Context) -> None:
    """A globus acceptor under TLS 1.3 sends a NUL turn token; it is skipped."""
    with SRMServer(grid_env.server_context(), root, globus_turn=True) as server:
        assert sctx.stat(server.url("/data/f")).st_size == 12
        assert sctx.stat(server.url("/data/f")).st_size == 12
        assert server.connections == 1
