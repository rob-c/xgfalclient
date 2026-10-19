"""The test SRM server's transport: httpg (HTTPS with GSI's delegation byte) over TLS.

:class:`_Handler` completes the GSI handshake details a gSOAP/CGSI client
expects (the globus TLS 1.3 "turn" byte, the delegation flag - xrdsec's
:func:`~xrdsec.testing.gsi.accept_httpg`), reads a
plain or chunked SOAP body and hands it to
:meth:`~xgfalclient.testing.srm.SRMServer.dispatch`; :class:`_TCPServer`
is the threading socket server it runs in.

httpg is what SRM clients (srm-ifce over CGSI-gSOAP) speak: TLS with a GSI
proxy as the client certificate, then one byte from the client saying
whether it will delegate (``"0"`` no, ``"D"`` yes, followed by a delegation
exchange), then plain HTTP/1.1. SRM operations never need delegation, so
this server accepts only ``"0"``; a client that tries to delegate is cut off.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer, ThreadingMixIn
from typing import TYPE_CHECKING, Any

from xrdsec.testing.gsi import accept_httpg

if TYPE_CHECKING:
    from ..srm import SRMServer


class _Handler(BaseHTTPRequestHandler):
    """One httpg connection: GSI preamble, then keep-alive SOAP POSTs.

    HTTP/1.1, so a connection serves requests until the client closes it,
    the server's ``keep_alive`` is off, or an injected :data:`DROP`.
    """

    protocol_version = "HTTP/1.1"
    server: _TCPServer

    def setup(self) -> None:
        """Do the TLS handshake and the GSI preamble before HTTP starts.

        Runs on the connection's own thread, so a slow or broken handshake
        holds up no one else. A wrong delegation byte, a TLS failure or a
        timeout raises, which :meth:`_TCPServer.handle_error` swallows.
        """
        srm = self.server.srm
        self.request.settimeout(srm.io_timeout)
        tls = srm.tls.wrap_socket(self.request, server_side=True)
        try:
            # The globus TLS 1.3 turn byte (when configured), then the delegation flag.
            accept_httpg(tls, turn=srm.globus_turn)
        except BaseException:
            # The server closes only the socket it accepted, which TLS took
            # over (detached), so the TLS socket is this handler's to close.
            tls.close()
            raise
        with srm.lock:
            srm.connections += 1
        self.request = self.connection = tls
        super().setup()

    def finish(self) -> None:
        """Flush and close the streams, then the TLS socket itself (see :meth:`setup`)."""
        try:
            super().finish()
        finally:
            self.request.close()

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the per-request stderr line; :attr:`SRMServer.log` records requests."""
        pass

    def _body(self) -> bytes:
        """The request body: ``Content-Length`` bytes, or a chunked body reassembled.

        gSOAP and this package's plugin send ``Content-Length``; chunked is
        accepted because any HTTP/1.1 client may use it (a test pins this).
        Chunk extensions are ignored and trailers are not supported - the
        line after the last chunk is read as the terminating blank line.
        A missing length means an empty body.
        """
        if self.headers.get("Transfer-Encoding", "").lower() != "chunked":
            return self.rfile.read(int(self.headers.get("Content-Length") or 0))
        chunks: list[bytes] = []
        while True:
            size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
            if size == 0:
                self.rfile.readline()
                return b"".join(chunks)
            chunks.append(self.rfile.read(size))
            self.rfile.readline()

    def do_POST(self) -> None:
        """Dispatch the SOAP body and send the reply, or hang up for :data:`DROP`.

        Every reply is ``text/xml`` with its length, whatever status the
        operation or injection chose (``500`` for faults).
        """
        srm = self.server.srm
        reply = srm.dispatch(self._body(), dict(self.headers.items()))
        if reply.close:
            self.close_connection = True
            return
        self.send_response(reply.status)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(reply.body)))
        if not srm.keep_alive:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(reply.body)


class _TCPServer(ThreadingMixIn, TCPServer):
    """A thread per connection, daemon so a stuck client cannot block exit."""

    daemon_threads = True
    allow_reuse_address = True
    srm: SRMServer

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Ignore the error rather than print a traceback to stderr."""
        pass  # a client that hangs up mid-handshake is not a server failure
