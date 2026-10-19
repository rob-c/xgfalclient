"""The decisions of the shared library modules that gfal2's own paths never take.

``tests/condcov.py`` holds a few library modules to xgfalclient's condition
coverage rule (see its ``SHARED_MODULES``): the ones that *are* gfal2's
behaviour - :mod:`xrdsec.discovery` (gfal2's X.509 search orders) and
:mod:`xrdhttp.redirects` (davix's credential-forwarding rule and the
scheme-keeping ``Location`` resolution) - and the HTTP engine pieces every
plugin request goes through. gfal2's own use takes most of their decisions
both ways; the few it cannot reach (a tool's own proxy setting, ARC's
``~/.arc``, xrdclient's stricter same-origin rule, a response replayed
from bytes rather than read off a socket) are taken here, through
the public API, so that the gate sees both outcomes and a change to a
neighbouring path that could leak into gfal2's is noticed. The behaviour
itself is the libraries' and is tested in their suites; these cases only
check that each call answers what its documentation says.
"""

from __future__ import annotations

import io
import socket
from pathlib import Path
from typing import cast

import pytest
from xrdhttp import connection, redirects, wire
from xrdsec import discovery


def _pair(directory: Path) -> tuple[str, str]:
    """``usercert.pem`` and ``userkey.pem`` in ``directory`` (contents never read here)."""
    directory.mkdir(parents=True, exist_ok=True)
    cert, key = directory / "usercert.pem", directory / "userkey.pem"
    cert.write_text("x")
    key.write_text("x")
    return str(cert), str(key)


def test_a_tools_own_settings_stand_in_for_the_variables(tmp_path: Path) -> None:
    """``proxy=``, ``cert=``/``key=`` and ``configured=`` replace ``$X509_*`` (gfal2 sets none)."""
    proxy = tmp_path / "proxy"
    proxy.write_text("x")
    found = discovery.discover_x509(discovery.GFAL2, proxy=str(proxy), environ={})
    assert found is not None and (found.cert, found.source) == (str(proxy), "X509_USER_PROXY")
    cert, key = _pair(tmp_path / "pair")
    found = discovery.discover_x509(discovery.GFAL2, cert=cert, key=key, environ={})
    assert found is not None and (found.cert, found.key) == (cert, key)
    assert discovery.discover_ca_dir(discovery.GFAL2, configured="/named", environ={}) == "/named"


def test_a_pair_is_judged_by_both_halves(tmp_path: Path) -> None:
    """A missing certificate fails ``user-pair`` as a missing key does; ``~/.globus`` is next."""
    cert, key = _pair(tmp_path / "pair")
    Path(cert).unlink()
    home = tmp_path / "home"
    env = {"X509_USER_CERT": cert, "X509_USER_KEY": key, "HOME": str(home)}
    assert discovery.discover_x509(discovery.GFAL2, environ=env) is None
    globus = _pair(home / ".globus")
    found = discovery.discover_x509(discovery.GFAL2, environ=env)
    assert found is not None and (found.cert, found.key) == globus


def test_the_home_directory_and_the_process_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``%USERPROFILE%`` with no ``$HOME``; ARC's ``~/.arc``; ``os.environ`` by default."""
    profile = tmp_path / "profile"
    globus = _pair(profile / ".globus")
    found = discovery.discover_x509(discovery.GFAL2, environ={"USERPROFILE": str(profile)})
    assert found is not None and (found.cert, found.key) == globus
    arc = _pair(profile / ".arc")
    found = discovery.discover_x509(discovery.ARC, environ={"HOME": str(profile)})
    assert found is not None and (found.cert, found.key) == arc
    monkeypatch.setenv("X509_USER_CERT", globus[0])
    monkeypatch.setenv("X509_USER_KEY", globus[1])
    found = discovery.discover_x509(discovery.GFAL2)
    assert found is not None and found.source == "X509_USER_CERT and X509_USER_KEY"


def test_xrdclients_same_origin_rule_beside_davixs() -> None:
    """The strict rule refuses what davix's allows; trusted domains and downgrades."""
    assert redirects.endpoint("https://SE.example/x") == ("https", "se.example", 443)
    assert redirects.endpoint("http:///x") == ("http", "", 80)
    assert redirects.davix_carries_credentials("https://a.example/x", "https://b.example/y")
    assert not redirects.carries_credentials("https://a.example/x", "https://b.example/y")
    assert not redirects.carries_credentials("https://a.example/x", "http://a.example/y")
    assert redirects.carries_credentials("http://a.example/x", "http://a.example:80/y")
    assert redirects.carries_credentials("https://a.cern.ch/", "https://b.cern.ch/", ["*"])
    assert redirects.carries_credentials("https://a.cern.ch/", "https://b.cern.ch/", ["cern.ch"])
    assert not redirects.carries_credentials(
        "https://a.cern.ch/", "https://evilcern.ch/", ["cern.ch"]
    )
    assert redirects.carries_credentials("https://a.cern.ch/", "https://cern.ch/", [".cern.ch"])


def test_transfer_headers_stay_within_the_site() -> None:
    """A ``COPY``'s far-side token follows to the origin's site, never to a registry."""
    assert redirects.relays_transfer_headers("https://eos.cern.ch/", "http://st-1.cern.ch:8443/")
    assert not redirects.relays_transfer_headers("https://eos.cern.ch/", "https://other.org/")
    assert not redirects.relays_transfer_headers("https://se.ac.uk/", "https://x.ac.uk/")
    assert redirects.relays_transfer_headers("https://cern.ch/", "https://cern.ch/")
    assert not redirects.relays_transfer_headers("https://10.0.0.1/", "https://10.0.0.2/")
    assert redirects.public_suffix("ac.uk") and redirects.public_suffix("edu.xx")
    assert not redirects.public_suffix("cern.ch") and not redirects.public_suffix("a.b.ch")
    headers = {"Authorization": "a", "TransferHeaderAuthorization": "t", "Accept": "*/*"}
    assert redirects.without_credentials(headers) == {"Accept": "*/*"}
    kept = redirects.without_credentials(headers, keep_transfer=True)
    assert kept == {"TransferHeaderAuthorization": "t", "Accept": "*/*"}


@pytest.mark.parametrize("current", ["no-scheme/x", "://h/x"])
def test_a_location_needs_an_absolute_url_to_resolve_against(current: str) -> None:
    with pytest.raises(ValueError, match="not an absolute URL"):
        redirects.resolve_location(current, "y")


@pytest.mark.parametrize("headers", [None, {"User-Agent": "decisions"}])
def test_a_request_may_carry_no_headers_at_all(headers: dict[str, str] | None) -> None:
    """``request(..., headers=None)`` - the plugin uses ``putrequest`` - frames as the stdlib's."""
    sent: list[bytes] = []

    class Connection(connection.HTTPConnection):
        def send(self, data: object) -> None:  # record the framing without a socket
            assert isinstance(data, bytes | bytearray | memoryview)
            sent.append(bytes(data))

    probe = Connection("localhost")
    probe.request("GET", "/", headers=headers)
    probe.close()
    assert sent[0].startswith(b"GET / HTTP/1.1\r\n")
    # Still the stdlib's connection underneath (xrdhttp subclasses it, adding no framing).
    assert any(
        (base.__module__, base.__name__) == ("http.client", "HTTPConnection")
        for base in type(probe).__mro__
    )


class _Replay:
    """A socket stand-in whose stream is bytes already read, as :mod:`xrdhttp.expect` replays."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def makefile(self, mode: str) -> io.BufferedReader:
        return io.BufferedReader(io.BytesIO(self._data))


def test_a_replayed_response_is_read_through_http_client() -> None:
    """With no socket under it, even a large read of a sized body stays on http.client's path."""
    raw = connection.HTTPResponse(
        cast("socket.socket", _Replay(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
    )
    raw.begin()
    buffer = bytearray(wire.DIRECT_READ)
    assert wire.DirectReader(raw, None).readinto(buffer) == 5
    assert bytes(buffer[:5]) == b"hello"
    raw.close()
