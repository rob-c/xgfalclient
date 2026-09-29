# ruff: noqa: F811 - pytest fixtures are imported by name, then requested by name
"""BDII endpoint discovery: the LDAP sliver, the FTS cache file, and the SRM plugin's use.

Everything runs against :class:`xgfalclient.testing.ldap.BDIIServer` or a
closed port; no test reaches a real BDII.
"""

from __future__ import annotations

import errno
import logging
import socket
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

import xgfalclient
from test_srm import root, srm  # noqa: F401 - fixtures
from xgfalclient.errors import ECOMM, GError
from xgfalclient.plugins.srm import bdii
from xgfalclient.plugins.srm import transport as srm_transport
from xgfalclient.plugins.srm.bdii import (
    Endpoint,
    LDAPClient,
    LDAPError,
    Resolver,
    Server,
    parse_filter,
    parse_servers,
)
from xgfalclient.testing.ldap import BDIIServer
from xgfalclient.testing.srm import SRMServer

SE = "se.example.org"
SERVICE = f"httpg://{SE}:8446/srm/managerv2"


@pytest.fixture
def server() -> Iterator[BDIIServer]:
    with BDIIServer([("o=grid", {"objectClass": ["top"]})]) as found:
        yield found


@pytest.fixture
def bctx(ctx: xgfalclient.Gfal2Context, server: BDIIServer) -> xgfalclient.Gfal2Context:
    """A context whose BDII is the test server, with no cache file."""
    ctx.set_opt_string("BDII", "LCG_GFAL_INFOSYS", server.address)
    ctx.set_opt_string("BDII", "CACHE_FILE", "")
    ctx.set_opt_integer("BDII", "TIMEOUT", 5)
    return ctx


def resolver(ctx: xgfalclient.Gfal2Context) -> Resolver:
    return Resolver(ctx.options)


def closed_port() -> int:
    probe = socket.create_server(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


# -- BER ---------------------------------------------------------------------------


def test_ber_round_trip() -> None:
    long = bdii.octets("x" * 300)
    assert long[:4] == b"\x04\x82\x01\x2c"
    tag, value = bdii.decode(bdii.encode(bdii.SEQUENCE, [bdii.integer(-2), long]))
    assert tag == bdii.SEQUENCE and isinstance(value, list)
    assert bdii.as_int(value[0]) == -2 and bdii.as_text(value[1]) == "x" * 300
    assert bdii.element_size(b"\x04") is None
    assert bdii.element_size(b"\x04\x82\x01") is None
    assert bdii.element_size(long[:4]) == 304
    assert bdii.element_size(b"\x04\x03") == 5


@pytest.mark.parametrize(
    "data",
    [
        b"\x04",  # no length
        b"\x04\x80",  # indefinite
        b"\x04\x82\x01",  # a long length cut short
        b"\x04\x05ab",  # short
        b"\x04\x01ab",  # trailing
        b"\x1f\x01a",  # a multi-byte tag
        b"\x30\x03\x04\x05a",  # a child longer than its parent, and the data
        b"\x30\x07\x30\x02\x04\x03abc",  # a child longer than its parent
    ],
)
def test_ber_errors(data: bytes) -> None:
    with pytest.raises(bdii.BERError):
        bdii.decode(data)


def test_ber_accessors_refuse_the_wrong_kind() -> None:
    constructed = bdii.decode(bdii.encode(bdii.SEQUENCE, [bdii.integer(1)]))
    primitive = bdii.decode(bdii.integer(1))
    for call in (bdii.as_int, bdii.as_text):
        with pytest.raises(bdii.BERError):
            call(constructed)
    with pytest.raises(bdii.BERError):
        bdii.children(primitive)


# -- filters -------------------------------------------------------------------------


def test_filters() -> None:
    query = parse_filter(bdii.SRM_FILTER.format(host=SE))
    assert query == (
        "|",
        [
            ("substrings", "GlueSEUniqueID", "", [SE], ""),
            (
                "&",
                [
                    ("substrings", "GlueServiceType", "srm", [], ""),
                    ("substrings", "GlueServiceEndpoint", "", [f"://{SE}"], ""),
                ],
            ),
        ],
    )
    for text in ("(!(a=b))", "(a=*)", "(a=x\\2ay)", "(a=b*c*d)", "(&(a=1)(|(b=2)(c=3)))"):
        found = parse_filter(text)
        assert bdii.decode_filter(bdii.decode(bdii.encode_filter(found))) == found
    assert parse_filter("(a=x\\2ay)") == ("=", "a", "x*y")
    assert parse_filter("(a=x\\zz)") == ("=", "a", "x\\zz")  # not an escape: as it is
    assert parse_filter("(a=x\\a)") == ("=", "a", "x\\a")  # too short to be one
    assert parse_filter("(a=b**c)") == ("substrings", "a", "b", [], "c")


@pytest.mark.parametrize("text", ["a=b", "(a=b", "(=b)", "(ab)", "(a=b))", "(&(a=b)", "(!(a=b)"])
def test_bad_filters(text: str) -> None:
    with pytest.raises(ValueError):
        parse_filter(text)


def test_unknown_filter_choice() -> None:
    with pytest.raises(bdii.BERError):
        bdii.decode_filter(bdii.decode(bdii.octets("x", 0x85)))


def test_filter_matching() -> None:
    entry = {"GlueServiceType": ["SRM"], "GlueSEUniqueID": ["se.example.org"], "x": []}
    match = bdii.match_filter
    assert match(parse_filter("(glueservicetype=srm)"), entry)
    assert match(parse_filter("(GlueSEUniqueID=se*org)"), entry)
    assert match(parse_filter("(GlueSEUniqueID=*xam*le*)"), entry)
    assert not match(parse_filter("(GlueSEUniqueID=*nope*)"), entry)
    assert not match(parse_filter("(GlueSEUniqueID=x*)"), entry)
    assert not match(parse_filter("(GlueSEUniqueID=*.orgx)"), entry)
    assert not match(parse_filter("(GlueSEUniqueID=se*example.org*.org)"), entry)
    assert match(parse_filter("(!(x=*))"), entry) and not match(parse_filter("(y=*)"), entry)
    assert match(parse_filter("(&(x=*)(y=*))"), {"x": ["1"], "y": ["2"]})
    assert not match(parse_filter("(|(x=2)(y=1))"), {"x": ["1"], "y": ["2"]})


def test_servers() -> None:
    assert parse_servers("a:2170, b ,,[::1]:99,ldap://c:1,[::2]") == [
        Server("a", 2170),
        Server("b", 389),
        Server("::1", 99),
        Server("c", 1),
        Server("::2", 389),
    ]


# -- the LDAP client -----------------------------------------------------------------


def test_bind_and_search(server: BDIIServer) -> None:
    server.add_srm(SE, SERVICE)
    server.entries.append(("cn=other,o=grid", {"GlueSEUniqueID": ["elsewhere"]}))
    server.reference = True
    client = LDAPClient([Server("127.0.0.1", closed_port()), Server(server.host, server.port)], 5)
    client.bind()
    found = client.search(bdii.BASE, parse_filter(bdii.SRM_FILTER.format(host=SE)), bdii.ATTRIBUTES)
    client.close()
    client.close()
    assert found == [
        {
            "GlueServiceType": ["SRM"],
            "GlueServiceVersion": ["2.2.0"],
            "GlueServiceEndpoint": [SERVICE],
        }
    ]
    assert server.log[0] == ("bind", "")
    _, base, _, names = server.log[1]
    assert base == "o=grid" and names == list(bdii.ATTRIBUTES)


def test_client_failures(server: BDIIServer) -> None:
    with pytest.raises(LDAPError) as down:
        LDAPClient([Server("127.0.0.1", closed_port()), Server("nowhere.invalid", 1)], 1)
    assert (down.value.code, str(down.value)) == (-1, "Can't contact LDAP server")
    assert str(LDAPError(12345)) == "Unknown error"

    def attempt(**faults: object) -> LDAPError:
        server.faults = dict(faults)
        client = LDAPClient([Server(server.host, server.port)], 0.3)
        try:
            with pytest.raises(LDAPError) as caught:
                client.bind()
                client.search("o=grid", ("present", "x"), [])
        finally:
            client.close()
        return caught.value

    assert attempt(bind_result=49).code == 49
    assert attempt(search_result=32).code == 32
    assert attempt(hang=True).code == bdii.TIMEOUT
    assert attempt(close=True).code == bdii.SERVER_DOWN
    assert attempt(garbage=True).code == bdii.SERVER_DOWN


def test_client_protocol_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replies a BDII never sends: the wrong operation, and bytes that are not BER."""
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    replies = [
        bdii.encode(bdii.SEQUENCE, [bdii.integer(1), bdii.octets("x")]),  # not a BindResponse
        b"\x30\x03\x02\x01\x01" + b"\x30\x02\x05\x00",  # malformed, then no operation at all
        bdii.encode(bdii.SEQUENCE, [bdii.integer(1), bdii.encode(0x78, [])]),  # an odd operation
    ]

    def serve() -> None:
        for reply in replies:
            sock, _ = listener.accept()
            sock.recv(4096)
            sock.sendall(reply)
            sock.recv(4096)
            sock.close()

    import threading

    threading.Thread(target=serve, daemon=True).start()
    for step in range(3):
        client = LDAPClient([Server("127.0.0.1", port)], 5)
        with pytest.raises(LDAPError) as caught:
            if step < 2:
                client.bind()
            else:
                client.search("o=grid", ("present", "x"), [])
        assert caught.value.code == 2
        client.close()
    listener.close()


def test_server_hangs_up_on_nonsense(server: BDIIServer) -> None:
    with socket.create_connection((server.host, server.port), 5) as sock:
        bind = bdii.encode(
            bdii.SEQUENCE,
            [
                bdii.integer(1),
                bdii.encode(
                    bdii.BIND_REQUEST, [bdii.integer(3), bdii.octets(""), bdii.octets("", 0x80)]
                ),
            ],
        )
        sock.sendall(bind[:4])  # a request in pieces
        time.sleep(0.05)
        sock.sendall(bind[4:])
        assert sock.recv(100)[-7:] == b"\x0a\x01\x00\x04\x00\x04\x00"  # success
        sock.sendall(b"\x30\x02\x05\x00")  # a message with no operation
        assert sock.recv(10) == b""


def test_send_failures(server: BDIIServer, monkeypatch: pytest.MonkeyPatch) -> None:
    client = LDAPClient([Server(server.host, server.port)], 5)
    assert client.sock is not None

    class Broken:
        def __init__(self, error: OSError) -> None:
            self.error = error

        def sendall(self, data: bytes) -> None:
            raise self.error

        def close(self) -> None:
            pass

    real = client.sock
    for error, code in ((socket.timeout(), bdii.TIMEOUT), (OSError("reset"), bdii.SERVER_DOWN)):
        client.sock = Broken(error)  # type: ignore[assignment]
        with pytest.raises(LDAPError) as caught:
            client.bind()
        assert caught.value.code == code

    class Deaf(Broken):
        def sendall(self, data: bytes) -> None:
            pass

        def recv(self, size: int) -> bytes:
            raise self.error

    for error, code in ((socket.timeout(), bdii.TIMEOUT), (OSError("reset"), bdii.SERVER_DOWN)):
        client.sock = Deaf(error)  # type: ignore[assignment]
        with pytest.raises(LDAPError) as caught:
            client.bind()
        assert caught.value.code == code
    client.sock = Broken(OSError("reset"))  # type: ignore[assignment]
    client.close()  # the unbind fails too, quietly
    real.close()


# -- the cache file --------------------------------------------------------------------


def test_cache_file(tmp_path: Path) -> None:
    cache = tmp_path / "bdii_cache.xml"
    cache.write_text(
        '<?xml version="1.0"?>\n'
        "<entry><endpoint>https://SE.example.org/dav</endpoint><type>webdav</type></entry>\n"
        f"<entry><endpoint>{SERVICE}</endpoint><type>SRM</type>"
        "<version>2.2.0</version></entry>\n"
        "<entry><endpoint>httpg://se.example.org.old:1/srm</endpoint><type>srm</type>"
        "<version>1.1</version></entry>\n"
        "<entry><endpoint>httpg://other.org:1/srm</endpoint><type>srm</type>"
        "<version>2.2</version></entry>\n"
        "<entry><type>srm</type></entry>\n"
        "<other><endpoint>httpg://se.example.org:9/x</endpoint></other>\n"
    )
    assert bdii.read_cache(str(cache), SE) == [
        Endpoint("https://SE.example.org/dav", ""),
        Endpoint(SERVICE, "srm_v2"),
        Endpoint("httpg://se.example.org.old:1/srm", "srm_v1"),
    ]
    assert bdii.read_cache(str(cache), "nowhere") == []
    assert bdii.read_cache(str(tmp_path / "missing.xml"), SE) == []
    cache.write_text("<entry><endpoint>")
    assert bdii.read_cache(str(cache), SE) == []
    cache.write_text(
        "".join(f"<entry><endpoint>{SERVICE}{i}</endpoint></entry>" for i in range(150))
    )
    assert len(bdii.read_cache(str(cache), SE)) == bdii.MAX_ENDPOINTS


# -- the resolver ------------------------------------------------------------------------


def test_resolver_from_the_cache_file(ctx: xgfalclient.Gfal2Context, tmp_path: Path) -> None:
    cache = tmp_path / "cache.xml"
    cache.write_text(
        f"<entry><endpoint>{SERVICE}</endpoint><type>srm</type><version>2.2</version></entry>"
        "<entry><endpoint>httpg://old.org/srm</endpoint><type>srm</type><version>1.1</version>"
        "</entry>"
    )
    ctx.set_opt_string("BDII", "CACHE_FILE", str(cache))
    ctx.set_opt_string("BDII", "LCG_GFAL_INFOSYS", "")  # never asked
    found = resolver(ctx)
    assert found.endpoint(SE) == SERVICE
    with pytest.raises(GError) as caught:
        found.endpoint("old.org")
    assert (caught.value.code, caught.value.message) == (
        errno.EINVAL,
        "cannot obtain a valid protocol from the bdii response, fatal error",
    )


def test_resolver_over_ldap(bctx: xgfalclient.Gfal2Context, server: BDIIServer) -> None:
    server.add_srm(SE, "httpg://se.example.org:8443/v1", version="1.1.0")
    server.add_srm(SE, SERVICE)
    found = resolver(bctx)
    assert found.endpoint(SE) == SERVICE
    assert found.endpoint(SE) == SERVICE  # remembered: one search
    assert [entry[0] for entry in server.log] == ["bind", "search"]
    _, _, query, _ = server.log[1]
    # A cache file with nothing for the host sends the question to the BDII.
    bctx.set_opt_string("BDII", "CACHE_FILE", "/no/such/cache.xml")
    assert resolver(bctx).endpoint(SE) == SERVICE
    assert query == parse_filter(bdii.SRM_FILTER.format(host=SE))


def test_resolver_environment_first(
    bctx: xgfalclient.Gfal2Context, server: BDIIServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.add_srm(SE, SERVICE)
    bctx.set_opt_string("BDII", "LCG_GFAL_INFOSYS", "127.0.0.1:1")
    monkeypatch.setenv("LCG_GFAL_INFOSYS", f"127.0.0.1:{closed_port()},{server.address}")
    assert resolver(bctx).endpoint(SE) == SERVICE


def failure(ctx: xgfalclient.Gfal2Context, host: str = SE) -> GError:
    with pytest.raises(GError) as caught:
        resolver(ctx).endpoint(host, 5.0)
    return caught.value


OUTER = "[gfal_mds_get_se_types_and_endpoints][gfal_mds_bdii_get_srm_endpoint]"
ENTRY = OUTER + "[gfal_mds_get_srm_types_endpoint][gfal_mds_convert_entry_to_srm_information]"


def test_resolver_failures(
    bctx: xgfalclient.Gfal2Context, server: BDIIServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = failure(bctx)
    assert (error.code, error.message) == (
        errno.ENXIO,
        OUTER + "[gfal_mds_get_srm_types_endpoint] no entries for the endpoint returned by "
        "the bdii : 0 ",
    )
    server.faults["bind_result"] = 49
    error = failure(bctx)
    assert (error.code, error.message) == (
        ECOMM,
        OUTER + f"Error while bind to bdii with ldap://{server.address} : Invalid credentials",
    )
    server.faults = {"search_result": 1}
    error = failure(bctx)
    query = bdii.SRM_FILTER.format(host=SE)
    assert error.message == (
        OUTER + f"[gfal_mds_ldap_search]Error while request {query} to bdii : Operations error"
    )
    server.faults = {}
    error = failure(bctx, "bad)host")
    assert error.message.endswith("to bdii : Bad search filter")
    bctx.set_opt_string("BDII", "LCG_GFAL_INFOSYS", f"127.0.0.1:{closed_port()}")
    error = failure(bctx)
    assert error.code == ECOMM and error.message.endswith(": Can't contact LDAP server")
    bctx.set_opt_string("BDII", "LCG_GFAL_INFOSYS", " , ")
    error = failure(bctx)
    assert (error.code, error.message) == (
        errno.EINVAL,
        OUTER + " no valid value for BDII found: please, configure the plugin properly, "
        "or try setting in the environment LCG_GFAL_INFOSYS",
    )


@pytest.mark.parametrize(
    ("attributes", "message"),
    [
        (
            {"GlueServiceType": ["https"], "GlueServiceVersion": ["2.2"]},
            "[gfal_mds_srm_endpoint_struct_builder]bad value of srm endpoint returned by bdii : "
            "https, excepted : SRM ",
        ),
        (
            {"GlueServiceType": ["SRM"], "GlueServiceVersion": ["3.0"]},
            "[gfal_mds_srm_endpoint_struct_builder]bad value of srm version returned by bdii : "
            "3.0, excepted 1.x or 2.x ",
        ),
        (
            {
                "GlueServiceType": ["srm"],
                "GlueServiceVersion": ["2.2"],
                "GlueServiceEndpoint": ["x"],
            },
            "[gfal_mds_srm_endpoint_struct_builder]bad value of srm endpoint returned by bdii : "
            "x, excepted a correct endpoint url ( httpg://, https://, ... ) ",
        ),
        ({"glueServiceType": ["SRM"]}, " Bad attribute retrieved from bdii "),
    ],
)
def test_bad_entries(
    bctx: xgfalclient.Gfal2Context,
    server: BDIIServer,
    attributes: dict[str, list[str]],
    message: str,
) -> None:
    server.entries.append(("cn=x,o=grid", {"GlueSEUniqueID": [SE], **attributes}))
    error = failure(bctx)
    assert (error.code, error.message) == (errno.EINVAL, ENTRY + message)


def test_entries_without_attributes(bctx: xgfalclient.Gfal2Context, server: BDIIServer) -> None:
    """gfal2 counts no endpoint and no error: the caller says "BDII usage disabled"."""
    server.entries.append(("cn=x,o=grid", {"GlueSEUniqueID": [SE], "GlueServiceType": []}))
    assert resolver(bctx).endpoint(SE) is None


def test_many_entries(bctx: xgfalclient.Gfal2Context, server: BDIIServer) -> None:
    for index in range(bdii.MAX_ENDPOINTS + 5):
        server.add_srm(SE, f"httpg://{SE}:{index}/srm/managerv2", version="1.1")
    with pytest.raises(GError):
        resolver(bctx).endpoint(SE)


def test_unreachable_bdii_costs_the_timeout(
    ctx: xgfalclient.Gfal2Context, server: BDIIServer
) -> None:
    server.faults["hang"] = True
    ctx.set_opt_string("BDII", "LCG_GFAL_INFOSYS", server.address)
    ctx.set_opt_string("BDII", "CACHE_FILE", "")
    ctx.set_opt_integer("BDII", "TIMEOUT", 1)
    started = time.monotonic()
    error = failure(ctx)
    assert "Timed out" in error.message and time.monotonic() - started < 3
    # With no TIMEOUT, the caller's bounds it.
    ctx.set_opt_integer("BDII", "TIMEOUT", -1)
    started = time.monotonic()
    with pytest.raises(GError):
        resolver(ctx).endpoint(SE, 0.5)
    assert time.monotonic() - started < 3


# -- through the SRM plugin ----------------------------------------------------------------


def test_short_surl_found_in_the_bdii(
    bctx: xgfalclient.Gfal2Context, server: BDIIServer, srm: SRMServer
) -> None:
    """``srm://se.example.org/...`` served by whatever endpoint the BDII names."""
    server.add_srm(SE, srm.endpoint)
    bctx.set_opt_string_list("SRM PLUGIN", "TURL_PROTOCOLS", ["file"])
    assert bctx.stat(f"srm://{SE}/data/f").st_size == 12
    assert bctx.stat(f"srm://{SE}:1234/data/f").st_size == 12  # its own port is ignored
    assert "<urlArray>srm://se.example.org/data/f</urlArray>" in srm.log[-1][1].decode()
    assert [entry[0] for entry in server.log] == ["bind", "search"]
    # A full SURL never asks.
    bctx.stat(srm.full_url("/data/f"))
    assert len(server.log) == 2


def test_fallback_to_the_default_path(
    bctx: xgfalclient.Gfal2Context,
    server: BDIIServer,
    srm: SRMServer,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bctx.set_opt_string_list("SRM PLUGIN", "TURL_PROTOCOLS", ["file"])
    with caplog.at_level(logging.WARNING, logger="gfal2"):
        assert bctx.stat(srm.url("/data/f")).st_size == 12
    assert "Error while bdii SRM service resolution : " in caplog.text
    assert "no entries for the endpoint" in caplog.text
    assert "fallback on the default service path.This can lead to wrong service path" in caplog.text
    # With no port, the guess has none, and the connection goes to port 80, as gSOAP's.
    attempts: list[tuple[str, int]] = []

    def connect(address: tuple[str, int], timeout: float | None = None) -> socket.socket:
        attempts.append(address)
        raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

    monkeypatch.setattr(srm_transport.socket, "create_connection", connect)
    with pytest.raises(GError) as caught:
        bctx.stat("srm://127.0.0.1/x")
    assert attempts[-1] == ("127.0.0.1", 80)  # after the BDII's own attempt
    assert "httpg://127.0.0.1/srm/managerv2" in caught.value.message


def test_bdii_disabled(
    ctx: xgfalclient.Gfal2Context,
    server: BDIIServer,
    srm: SRMServer,
    caplog: pytest.LogCaptureFixture,
) -> None:
    ctx.set_opt_boolean("BDII", "ENABLED", False)
    ctx.set_opt_string("BDII", "LCG_GFAL_INFOSYS", server.address)
    ctx.set_opt_string_list("SRM PLUGIN", "TURL_PROTOCOLS", ["file"])
    with caplog.at_level(logging.WARNING, logger="gfal2"):
        assert ctx.stat(srm.url("/data/f")).st_size == 12
    assert "BDII usage disabled, fallback on the default service path." in caplog.text
    assert server.log == []


def test_bdii_with_nothing_to_say(
    bctx: xgfalclient.Gfal2Context,
    server: BDIIServer,
    srm: SRMServer,
    caplog: pytest.LogCaptureFixture,
) -> None:
    host = srm.host
    server.entries.append(("cn=x,o=grid", {"GlueSEUniqueID": [host], "GlueServiceType": []}))
    bctx.set_opt_string_list("SRM PLUGIN", "TURL_PROTOCOLS", ["file"])
    with caplog.at_level(logging.WARNING, logger="gfal2"):
        assert bctx.stat(srm.url("/data/f")).st_size == 12
    assert "BDII usage disabled" in caplog.text
