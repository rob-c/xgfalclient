"""The Cns marshalling and Csec negotiation, byte by byte."""

from __future__ import annotations

import errno
import socket
import struct
import sys
import threading
from collections.abc import Callable, Iterator

import pytest

from xgfalclient.errors import ECOMM, GError
from xgfalclient.plugins.lfc import csec, wire
from xgfalclient.plugins.lfc.csec import (
    GSIMechanism,
    IDMechanism,
    KRB5Mechanism,
    TokenLink,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)
from xgfalclient.plugins.lfc.wire import Packer, Unpacker, WireError
from xgfalclient.testing.pki import PKI

# -- marshalling -----------------------------------------------------------------------


def test_packer_round_trip() -> None:
    data = (
        Packer()
        .long(-1)
        .word(0x8180)
        .byte("x")
        .byte(0x1FF)
        .hyper(-2)
        .string("é")
        .raw(b"\x01")
        .bytes()
    )
    reader = Unpacker(data)
    assert reader.ulong() == 0xFFFFFFFF
    assert reader.word() == 0x8180
    assert reader.char() == "x"
    assert reader.byte() == 0xFF
    assert reader.hyper() == 2**64 - 2
    assert reader.string() == "é"
    assert reader.remaining == 1
    assert not reader.at_end()
    assert reader.byte() == 1
    assert reader.at_end()


def test_unpacker_errors() -> None:
    assert Unpacker(struct.pack(">q", -5)).time() == -5
    assert Unpacker(struct.pack(">i", -5)).long() == -5
    with pytest.raises(WireError) as info:
        Unpacker(b"\0\0").long()
    assert info.value.code == errno.EPROTO
    with pytest.raises(WireError, match="unterminated"):
        Unpacker(b"abc").string()
    with pytest.raises(WireError, match="too long"):
        Unpacker(b"abcd\0").string(3)
    with pytest.raises(GError) as nul:
        Packer().string("a\0b")
    assert nul.value.code == errno.EINVAL


def test_request_header() -> None:
    assert (
        wire.request(wire.MAGIC, wire.STAT, b"xy")
        == struct.pack(">iii", wire.MAGIC, wire.STAT, 14) + b"xy"
    )


def test_serrno() -> None:
    assert wire.serrno_text(errno.ENOENT) == "No such file or directory"
    assert wire.serrno_text(wire.SENOMAPFND) == "No user mapping"
    assert wire.serrno_text(wire.SELOOP) == "Too many symbolic links encountered"
    assert wire.serrno_text(wire.ESEC_BAD_CREDENTIALS) == "Bad credentials"
    assert wire.serrno_text(wire.ENSNACT) == "Name server not active"
    assert wire.serrno_text(1399) == "Unknown error 1399"
    assert wire.errno_for(errno.EEXIST) == errno.EEXIST
    assert wire.errno_for(wire.ESEC_BAD_CREDENTIALS) == errno.EPERM
    assert wire.errno_for(wire.SENAMETOOLONG) == errno.ENAMETOOLONG
    assert wire.errno_for(wire.SEINTERNAL) == ECOMM
    assert wire.errno_for(0) == ECOMM


# -- Csec negotiation --------------------------------------------------------------------


def test_request_encoding() -> None:
    body = encode_request(["GSI", "ID"])
    version, authorization, mechs, flags = decode_request(body)
    assert (version, authorization, mechs) == (2, None, ["GSI", "ID"])
    assert flags == [0, csec.NODELEG]
    assert decode_request(encode_request(["GSI"]))[3] == [0]
    assert decode_request(encode_request([]))[2:] == ([], [])
    with_id = decode_request(encode_request(["ID"], ("GSI", "/CN=someone")))
    assert with_id[1] == ("GSI", "/CN=someone")


def test_response_encoding() -> None:
    assert decode_response(encode_response(3, 1, csec.NODELEG, ["GSI"])) == (
        2,
        1,
        csec.NODELEG,
        [],
    )
    assert decode_response(encode_response(2, None, 0, ["GSI", "ID"])) == (
        2,
        None,
        0,
        ["GSI", "ID"],
    )
    assert decode_response(encode_response(2, None, 0, [])) == (2, None, 0, [])


def test_bounded_lists() -> None:
    huge = Packer().long(2).long(0).long(5000).bytes()
    with pytest.raises(WireError, match="protocols"):
        decode_request(huge)
    flags = Packer().long(2).long(0).long(1).string("ID").long(5000).bytes()
    with pytest.raises(WireError, match="sets"):
        decode_request(flags)
    indexes = Packer().long(2).long(0).long(1).string("ID").long(1).long(2).long(5000).bytes()
    with pytest.raises(WireError, match="indexes"):
        decode_request(indexes)
    out_of_range = Packer().long(2).long(0).long(1).string("ID").long(1).long(2).long(1).long(9)
    assert decode_request(out_of_range.long(0).bytes())[3] == [0]


def test_mechanism_names() -> None:
    assert csec.mechanism_names(None) == ["GSI", "ID"]
    assert csec.mechanism_names("  KRB5\tGSI ") == ["KRB5", "GSI"]
    assert csec.mechanism_names(" ") == ["GSI", "ID"]


def test_local_identity() -> None:
    uid, gid, name = csec.local_identity()
    assert isinstance(uid, int) and isinstance(gid, int) and name


def test_local_identity_of_an_unnamed_uid(monkeypatch: pytest.MonkeyPatch) -> None:
    import pwd

    def nobody(uid: int) -> pwd.struct_passwd:
        raise KeyError(uid)

    monkeypatch.setattr(pwd, "getpwuid", nobody)
    uid, _, name = csec.local_identity()
    assert name == str(uid)


def test_local_identity_without_pwd(monkeypatch: pytest.MonkeyPatch) -> None:
    """As on Windows: no ``pwd``, no ``geteuid``, so uid and gid are 0."""
    monkeypatch.setitem(sys.modules, "pwd", None)
    monkeypatch.delattr(csec.os, "geteuid", raising=False)
    monkeypatch.delattr(csec.os, "getegid", raising=False)
    assert csec.local_identity() == (0, 0, "0")


# -- tokens over a socket pair --------------------------------------------------------------


@pytest.fixture
def pair() -> Iterator[tuple[socket.socket, socket.socket]]:
    left, right = socket.socketpair()
    yield left, right
    left.close()
    right.close()


def token(kind: int, data: bytes, magic: int = csec.TOKEN_MAGIC) -> bytes:
    return struct.pack(">III", magic, kind, len(data)) + data


def serve(sock: socket.socket, script: Callable[[TokenLink], None]) -> threading.Thread:
    thread = threading.Thread(target=script, args=(TokenLink(sock, "client"),), daemon=True)
    thread.start()
    return thread


def test_token_errors(pair: tuple[socket.socket, socket.socket]) -> None:
    left, right = pair
    link = TokenLink(left, "peer")
    right.sendall(token(1, b"", magic=0x1234))
    with pytest.raises(csec.CsecError, match="bad Csec token") as info:
        link.recv_token()
    assert info.value.code == errno.EPROTO
    right.sendall(token(1, b""))
    with pytest.raises(csec.CsecError, match="0 bytes"):
        link.recv_token()
    right.sendall(b"\0\0")
    right.shutdown(socket.SHUT_WR)
    with pytest.raises(GError, match="closed the connection") as closed:
        link.recv_token()
    assert closed.value.code == errno.ECONNRESET


def test_token_timeout_and_reset(pair: tuple[socket.socket, socket.socket]) -> None:
    left, right = pair
    left.settimeout(0.05)
    link = TokenLink(left, "peer")
    with pytest.raises(GError) as info:
        link.recv_token()
    assert info.value.code == errno.ETIMEDOUT
    right.close()
    left.settimeout(None)
    with pytest.raises(GError):
        for _ in range(100):  # the first sends may still land in the buffer
            link.send_token(1, b"x" * 65536)


def test_socket_error_without_errno() -> None:
    error = csec._socket_error(OSError("gone"), "peer")
    assert error.code == errno.ECONNRESET and error.message.endswith("authenticating: gone")


def test_negotiate(pair: tuple[socket.socket, socket.socket]) -> None:
    left, right = pair
    link = TokenLink(left, "peer")

    def answer(kind: int, body: bytes) -> Callable[[TokenLink], None]:
        def script(server: TokenLink) -> None:
            server.recv_token()
            server.send_token(kind, body)

        return script

    serve(right, answer(csec.PROTOCOL_RESP, encode_response(2, 0, csec.NODELEG, [])))
    assert csec.negotiate(link, ["ID"]) == "ID"
    serve(right, answer(csec.HANDSHAKE, b"x"))
    with pytest.raises(csec.CsecError, match="token type"):
        csec.negotiate(link, ["ID"])
    serve(right, answer(csec.PROTOCOL_RESP, encode_response(2, None, 0, ["KRB5"])))
    with pytest.raises(csec.CsecError, match="allows KRB5") as refused:
        csec.negotiate(link, ["ID"])
    assert refused.value.code == errno.EACCES
    serve(right, answer(csec.PROTOCOL_RESP, encode_response(2, None, 0, [])))
    with pytest.raises(csec.CsecError, match="allows none"):
        csec.negotiate(link, [])
    for chosen, flags in ((5, csec.NODELEG), (0, 0), (0, csec.DELEG)):
        serve(right, answer(csec.PROTOCOL_RESP, encode_response(2, chosen, flags, [])))
        with pytest.raises(csec.CsecError, match="impossible") as bad:
            csec.negotiate(link, ["ID"])
        assert bad.value.code == errno.EPROTO


def test_id_mechanism(pair: tuple[socket.socket, socket.socket]) -> None:
    left, right = pair
    IDMechanism(7, 8, "alice").authenticate(TokenLink(left, "peer"), "host")
    assert TokenLink(right, "c").recv_token() == (csec.HANDSHAKE, b"7 8 alice")


def test_gsi_without_credential(pair: tuple[socket.socket, socket.socket]) -> None:
    left, right = pair
    with pytest.raises(csec.CsecError, match=r"No X\.509") as info:
        GSIMechanism(None).authenticate(TokenLink(left, "peer"), "host")
    assert info.value.code == errno.EACCES
    kind, data = TokenLink(right, "c").recv_token()
    assert (kind, struct.unpack(">I", data)[0]) == (
        csec.HANDSHAKE_ERROR,
        csec.REASON_ACQUIRE_FAILED,
    )


def test_gsi_server_refuses(pair: tuple[socket.socket, socket.socket], pki: PKI) -> None:
    left, right = pair

    def refuse(server: TokenLink) -> None:
        server.recv_token()  # the ClientHello
        server.send_token(csec.HANDSHAKE_ERROR, struct.pack(">I", 0))

    serve(right, refuse)
    with pytest.raises(csec.CsecError, match="had a problem"):
        GSIMechanism(pki.client_context()).authenticate(TokenLink(left, "peer"), "localhost")


def test_gsi_garbage_is_aborted(pair: tuple[socket.socket, socket.socket], pki: PKI) -> None:
    left, right = pair
    seen: list[int] = []

    def garbage(server: TokenLink) -> None:
        server.recv_token()
        server.send_token(csec.HANDSHAKE, b"not TLS at all" * 10)
        seen.append(server.recv_token()[0])

    thread = serve(right, garbage)
    with pytest.raises(csec.CsecError, match="GSI authentication") as info:
        GSIMechanism(pki.client_context()).authenticate(TokenLink(left, "peer"), "localhost")
    assert info.value.code == errno.EACCES
    thread.join(5)
    assert seen == [csec.HANDSHAKE_ERROR]


def test_abort_on_dead_link(pair: tuple[socket.socket, socket.socket]) -> None:
    left, right = pair
    right.close()
    left.close()
    csec._abort(TokenLink(left, "peer"), 0)  # nothing raised


class FakeKerberos:
    """A two-leg GSS exchange, standing in for the platform library."""

    def __init__(self, service: str, host: str, **flags: object) -> None:
        self.target = f"{service}@{host}"
        self.flags = flags
        self.complete = False
        self.fail = False

    def step(self, token: bytes = b"") -> bytes:
        if token == b"AP-REP":
            self.complete = True
            return b""
        if token:
            raise GError("replayed", errno.EPROTO)
        return b"AP-REQ"


def test_krb5_mechanism(
    pair: tuple[socket.socket, socket.socket], monkeypatch: pytest.MonkeyPatch
) -> None:
    from xgfalclient.crypto import krb5

    monkeypatch.setattr(krb5, "ClientContext", FakeKerberos)
    left, right = pair
    mech = KRB5Mechanism()
    assert mech.context("lfc.example").target == "host@lfc.example"

    def accept(server: TokenLink) -> None:
        assert server.recv_token() == (csec.HANDSHAKE, b"AP-REQ")
        server.send_token(csec.HANDSHAKE_FINAL, b"AP-REP")

    serve(right, accept)
    mech.authenticate(TokenLink(left, "peer"), "lfc.example")

    def corrupt(server: TokenLink) -> None:
        server.recv_token()
        server.send_token(csec.HANDSHAKE, b"junk")

    serve(right, corrupt)
    with pytest.raises(csec.CsecError, match="KRB5 authentication") as info:
        mech.authenticate(TokenLink(left, "peer"), "lfc.example")
    assert info.value.code == errno.EPROTO


def test_available_krb5(monkeypatch: pytest.MonkeyPatch) -> None:
    from xgfalclient.crypto import krb5

    monkeypatch.setattr(krb5, "available", lambda name=None: None)
    assert csec.available_krb5()
    monkeypatch.setattr(krb5, "available", lambda name=None: "no library")
    assert not csec.available_krb5()


def test_base_mechanism() -> None:
    with pytest.raises(NotImplementedError):
        csec.Mechanism().authenticate(None, "h")  # type: ignore[arg-type]
    with pytest.raises(NotImplementedError):
        csec._TokenMechanism().context("h")
