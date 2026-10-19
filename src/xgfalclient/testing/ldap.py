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

What it does not do, deliberately - gfal2 never asks for it: the search
base, scope, deref, size and time limits and ``typesOnly`` are read but ignored (every entry
is searched, as if the base were the root and the scope the subtree), and
an empty attribute list returns entries with no attributes rather than all
of them, as RFC 4511 would. There is no TLS and no SASL. Messages are
LDAPv3 BER (RFC 4511) using the client's own BER codec
(:mod:`xgfalclient.plugins.srm.bdii`), plus :func:`decode_filter` - the one
piece only a server needs.

The entries are GLUE schema objects; :meth:`BDIIServer.add_srm` writes the
GLUE 1.3 ``GlueService`` shape gfal2 queries for SRM endpoints. Tests that
need GLUE 2.0 or other objects append ``(dn, attributes)`` to
:attr:`BDIIServer.entries` directly.
"""

from __future__ import annotations

import contextlib
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
    Element,
    Filter,
    as_text,
    children,
    decode,
    element_size,
    encode,
    integer,
    octets,
)

__all__ = ["BDIIServer", "decode_filter", "match_filter"]

#: One directory entry: its DN and attribute name to values, as written.
Entry = tuple[str, dict[str, list[str]]]


def decode_filter(item: Element) -> Filter:
    """The filter a search request carries, in the shape ``bdii.parse_filter`` builds.

    The inverse of the client's ``encode_filter``: only a server reads a
    filter off the wire, so this lives with the test server.
    """
    # RFC 4511 Filter is a CHOICE of context tags: [0] and, [1] or, [2] not
    # (constructed, 0xA0-0xA2), [3] equalityMatch and [4] substrings
    # (constructed), [7] present (primitive, 0x87: just the attribute name).
    # The ordering, approxMatch and extensibleMatch choices raise BERError.
    tag = item[0]
    if tag in (0xA0, 0xA1):
        return ("&" if tag == 0xA0 else "|", [decode_filter(f) for f in children(item)])
    if tag == 0xA2:
        return ("!", decode_filter(children(item)[0]))
    if tag == 0x87:
        return ("present", as_text(item))
    if tag == 0xA3:
        attribute, value = children(item)
        return ("=", as_text(attribute), as_text(value))
    if tag == 0xA4:
        return _decode_substrings(item)
    raise BERError(f"unsupported filter choice {tag:#x}")


def _decode_substrings(item: Element) -> Filter:
    """A ``substrings`` choice: attribute, then initial/any.../final parts by context tag."""
    attribute, parts = children(item)
    initial, middle, final = "", [], ""
    # SubstringFilter parts: [0] initial, [1] any (repeatable), [2] final.
    for part in children(parts):
        if part[0] == 0x80:
            initial = as_text(part)
        elif part[0] == 0x81:
            middle.append(as_text(part))
        else:
            final = as_text(part)
    return ("substrings", as_text(attribute), initial, middle, final)


def match_filter(found: Filter, entry: dict[str, list[str]]) -> bool:
    """Whether ``entry`` passes ``found``, the way an OpenLDAP BDII decides.

    Attribute names and values compare case-insensitively (the Glue schema's
    ``caseIgnoreMatch``); a missing attribute is absent, not an error.
    """
    values = {name.lower(): items for name, items in entry.items()}
    kind = found[0]
    if kind == "&":
        return all(match_filter(f, entry) for f in found[1])
    if kind == "|":
        return any(match_filter(f, entry) for f in found[1])
    if kind == "!":
        return not match_filter(found[1], entry)
    present = values.get(found[1].lower(), [])
    if kind == "present":
        return bool(present)
    if kind == "=":
        return any(value.lower() == found[2].lower() for value in present)
    _, _, initial, middle, final = found
    return any(
        _substrings(value.lower(), initial.lower(), middle, final.lower()) for value in present
    )


def _substrings(value: str, initial: str, middle: list[str], final: str) -> bool:
    """RFC 4515 substring match: ``initial*middle...*final``, in order, without overlap.

    ``value``, ``initial`` and ``final`` arrive lower-cased; each middle part
    is lowered here. The final length check stops the last middle part and
    ``final`` from claiming the same characters.
    """
    if not value.startswith(initial):
        return False
    position = len(initial)
    for part in middle:
        found = value.find(part.lower(), position)
        if found < 0:
            return False
        position = found + len(part)
    return len(value) - position >= len(final) and value.endswith(final)


class BDIIServer:
    """A threaded LDAP server holding ``entries`` (``(dn, attributes)`` pairs).

    One daemon thread accepts and one serves each connection; requests on a
    connection are answered in order. :attr:`entries`, :attr:`faults` and
    :attr:`reference` may be changed between requests; :attr:`log` records
    every bind and search, for tests that check the query gfal2 built.
    Fault keys: ``bind_result``/``search_result`` (an LDAP result code to
    answer with, e.g. ``49`` invalidCredentials), ``hang``, ``close`` and
    ``garbage`` (presence is enough); they apply to every later request.
    """

    def __init__(self, entries: Sequence[Entry] = (), *, host: str = "127.0.0.1") -> None:
        """Bind the listener now (ephemeral port, see :attr:`address`); serving starts later."""
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
        """Accept connections on a daemon thread; returns ``self`` for chaining."""
        threading.Thread(target=self._serve, name="xgfal-bdii", daemon=True).start()
        return self

    def stop(self) -> None:
        """Stop accepting, release ``hang`` faults and close every open connection."""
        self._stop.set()
        # Linux does not wake a thread blocked in accept() when the listener is
        # merely closed (macOS does); a shutdown does.
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()
        with self._lock:
            sockets = list(self._sockets)
        for sock in sockets:
            sock.close()

    def __enter__(self) -> BDIIServer:
        """:meth:`start` the server for a ``with`` block."""
        return self.start()

    def __exit__(self, *exc: object) -> None:
        """:meth:`stop` the server; exceptions propagate."""
        self.stop()

    def _serve(self) -> None:
        """The accept loop; ends when :meth:`stop` closes the listener."""
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
        """Split the stream into BER messages and answer each until one says stop.

        LDAP has no framing of its own: a message is one BER element, so
        bytes are buffered until :func:`element_size` says a whole element
        is there. A malformed message just ends the connection, as a real
        server's protocol error would from the client's point of view.
        """
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
        """Answer one request; ``False`` to hang up.

        A request is ``LDAPMessage { messageID, protocolOp }``; each reply
        carries the same ID. A bind is answered with a ``BindResponse`` (any
        name and password are accepted - BDIIs are anonymous); a search with
        an optional ``SearchResultReference``, a ``SearchResultEntry`` per
        matching entry - only the requested attributes, compared
        case-insensitively but returned under the entry's own spelling - and
        a ``SearchResultDone``. An unbind, or any other operation, ends the
        connection. Faults are checked after the message is decoded, so a
        garbled request still just ends the connection.
        """
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
            """Send each protocol op wrapped in an ``LDAPMessage`` with the request's ID."""
            sock.sendall(b"".join(encode(SEQUENCE, [integer(number), op]) for op in ops))

        tag = operation[0]
        if tag == BIND_REQUEST:
            # BindRequest: version, name, authentication (simple password).
            _, name, _ = children(operation)
            self.log.append(("bind", as_text(name)))
            send(_result(BIND_RESPONSE, int(self.faults.get("bind_result", 0))))
            return True
        if tag != SEARCH_REQUEST:  # unbind, or anything else: the end
            return False
        send(*self._search(operation))
        return True

    def _search(self, operation: Element) -> list[bytes]:
        """The protocol ops answering a ``SearchRequest``: reference, entries, then done."""
        # SearchRequest: baseObject, scope, derefAliases, sizeLimit, timeLimit,
        # typesOnly, filter, attributes (RFC 4511 section 4.5.1).
        base, _, _, _, _, _, found, wanted = children(operation)
        names = [as_text(item) for item in children(wanted)]
        query = decode_filter(found)
        self.log.append(("search", as_text(base), query, names))
        replies = []
        if self.reference:
            replies.append(encode(SEARCH_REFERENCE, [octets("ldap://elsewhere/o=grid")]))
        for dn, attributes in self.entries:
            if match_filter(query, attributes):
                replies.append(_search_entry(dn, attributes, names))
        replies.append(_result(SEARCH_DONE, int(self.faults.get("search_result", 0))))
        return replies


def _search_entry(dn: str, attributes: dict[str, list[str]], names: list[str]) -> bytes:
    """A ``SearchResultEntry`` with those of ``attributes`` named in ``names``.

    The names are compared case-insensitively, and the attributes returned
    under the entry's own spelling.
    """
    pairs = [
        encode(SEQUENCE, [octets(key), encode(SET, [octets(v) for v in values])])
        for key, values in attributes.items()
        if key.lower() in (name.lower() for name in names)
    ]
    return encode(SEARCH_ENTRY, [octets(dn), encode(SEQUENCE, pairs)])


def _result(tag: int, code: int) -> bytes:
    """An ``LDAPResult``: the code, no matched DN, no message."""
    return encode(tag, [integer(code, ENUMERATED), octets(""), octets("")])
