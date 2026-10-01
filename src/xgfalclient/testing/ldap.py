"""An in-process BDII: the sliver of LDAPv3 gfal2's endpoint discovery uses.

It answers anonymous simple binds and searches over a list of entries,
evaluating the request's filter the way an OpenLDAP BDII would (attribute
names and values case-insensitively), and returning the requested
attributes under the entry's own spelling of their names::

    with BDIIServer() as bdii:
        bdii.add_srm("se.example.org", "httpg://se.example.org:8446/srm/managerv2")
        ctx.set_opt_string("BDII", "LCG_GFAL_INFOSYS", bdii.address)

Faults are injected by name: ``bind_result``/``search_result`` answer with
that LDAP result code, ``hang`` accepts and never answers, ``close`` hangs up
on the first request, and ``garbage`` answers with bytes that are not BER.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Sequence
from typing import Any

from ..plugins.srm.bdii import (
    BIND_REQUEST,
    BIND_RESPONSE,
    ENUMERATED,
    SEARCH_DONE,
    SEARCH_ENTRY,
    SEARCH_REFERENCE,
    SEARCH_REQUEST,
    SEQUENCE,
    SET,
    BERError,
    as_text,
    children,
    decode,
    decode_filter,
    element_size,
    encode,
    integer,
    match_filter,
    octets,
)

__all__ = ["BDIIServer"]

Entry = tuple[str, dict[str, list[str]]]


class BDIIServer:
    """A threaded LDAP server holding ``entries`` (``(dn, attributes)`` pairs)."""

    def __init__(self, entries: Sequence[Entry] = (), *, host: str = "127.0.0.1") -> None:
        self.entries: list[Entry] = list(entries)
        self.host = host
        #: Every request: ``("bind", name)`` or ``("search", base, filter, attributes)``.
        self.log: list[tuple[Any, ...]] = []
        self.faults: dict[str, Any] = {}
        #: Send a search reference before the entries, as a referring server would.
        self.reference = False
        self._listener = socket.create_server((host, 0))
        self.port = int(self._listener.getsockname()[1])
        self._stop = threading.Event()
        self._sockets: list[socket.socket] = []
        self._lock = threading.Lock()

    @property
    def address(self) -> str:
        """``host:port``, as ``LCG_GFAL_INFOSYS`` lists a BDII."""
        return f"{self.host}:{self.port}"

    def add_srm(self, host: str, endpoint: str, version: str = "2.2.0", kind: str = "SRM") -> None:
        """A GLUE 1.3 SRM service entry for ``host``."""
        self.entries.append(
            (
                f"GlueServiceUniqueID={endpoint},Mds-Vo-name=resource,o=grid",
                {
                    "objectClass": ["GlueService"],
                    "GlueServiceUniqueID": [endpoint],
                    "GlueServiceType": [kind],
                    "GlueServiceVersion": [version],
                    "GlueServiceEndpoint": [endpoint],
                    "GlueSEUniqueID": [host],
                },
            )
        )

    # -- lifecycle -----------------------------------------------------------------

    def start(self) -> BDIIServer:
        threading.Thread(target=self._serve, name="xgfal-bdii", daemon=True).start()
        return self

    def stop(self) -> None:
        self._stop.set()
        # Linux does not wake a thread blocked in accept() when the listener is
        # merely closed (macOS does); a shutdown does.
        try:
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._listener.close()
        with self._lock:
            sockets = list(self._sockets)
        for sock in sockets:
            sock.close()

    def __enter__(self) -> BDIIServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _serve(self) -> None:
        while True:
            try:
                sock, _ = self._listener.accept()
            except OSError:
                return
            with self._lock:
                self._sockets.append(sock)
            threading.Thread(target=self._session, args=(sock,), daemon=True).start()

    # -- one connection --------------------------------------------------------------

    def _session(self, sock: socket.socket) -> None:
        buffer = b""
        try:
            while True:
                size = element_size(buffer)
                if size is None or len(buffer) < size:
                    chunk = sock.recv(65536)
                    if not chunk:
                        return
                    buffer += chunk
                    continue
                raw, buffer = buffer[:size], buffer[size:]
                if not self._handle(sock, raw):
                    return
        except (OSError, BERError, ValueError, IndexError):
            return
        finally:
            sock.close()

    def _handle(self, sock: socket.socket, raw: bytes) -> bool:
        """Answer one request; ``False`` to hang up."""
        message_id, operation = children(decode(raw))[:2]
        number = int.from_bytes(message_id[1], "big")
        if "hang" in self.faults:
            self._stop.wait()
            return False
        if "close" in self.faults:
            return False
        if "garbage" in self.faults:
            sock.sendall(b"\x30\x03\x02\x01")  # a truncated message, then EOF
            return False

        def send(*ops: bytes) -> None:
            sock.sendall(b"".join(encode(SEQUENCE, [integer(number), op]) for op in ops))

        tag = operation[0]
        if tag == BIND_REQUEST:
            _, name, _ = children(operation)
            self.log.append(("bind", as_text(name)))
            send(_result(BIND_RESPONSE, int(self.faults.get("bind_result", 0))))
            return True
        if tag != SEARCH_REQUEST:  # unbind, or anything else: the end
            return False
        base, _, _, _, _, _, found, wanted = children(operation)
        names = [as_text(item) for item in children(wanted)]
        query = decode_filter(found)
        self.log.append(("search", as_text(base), query, names))
        replies = []
        if self.reference:
            replies.append(encode(SEARCH_REFERENCE, [octets("ldap://elsewhere/o=grid")]))
        for dn, attributes in self.entries:
            if not match_filter(query, attributes):
                continue
            pairs = [
                encode(SEQUENCE, [octets(key), encode(SET, [octets(v) for v in values])])
                for key, values in attributes.items()
                if key.lower() in (name.lower() for name in names)
            ]
            replies.append(encode(SEARCH_ENTRY, [octets(dn), encode(SEQUENCE, pairs)]))
        replies.append(_result(SEARCH_DONE, int(self.faults.get("search_result", 0))))
        send(*replies)
        return True


def _result(tag: int, code: int) -> bytes:
    """An ``LDAPResult``: the code, no matched DN, no message."""
    return encode(tag, [integer(code, ENUMERATED), octets(""), octets("")])
