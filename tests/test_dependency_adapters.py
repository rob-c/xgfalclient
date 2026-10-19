"""Security/compatibility contracts at the general-purpose library boundaries."""

from __future__ import annotations

import base64
import errno
import json
import time
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from xrdhttp import connection as _connection
from xrdhttp.wire import IdlePool  # the pool the HTTP plugin keeps its connections in

import xgfalclient
from xgfalclient.creds import check_bearer_token, token_claims
from xgfalclient.crypto import der, ed25519, p256
from xgfalclient.errors import GError
from xgfalclient.plugins.http import _client

ROOT = Path(__file__).resolve().parents[1]


def _segment(raw: bytes) -> str:
    """``raw`` as an unpadded base64url JWS segment."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unsigned(claims: object, header: object = None) -> str:
    """An ``alg: none`` JWT, as an identity provider's test mode would mint it."""
    head = {"alg": "none", "typ": "JWT"} if header is None else header
    return f"{_segment(json.dumps(head).encode())}.{_segment(json.dumps(claims).encode())}."


def _requirements() -> list[Requirement]:
    """The checkout's own declared requirements (pyproject is the source of truth).

    The installed distribution's metadata can be stale in an editable or
    shared environment, so the contracts below read what will be built.
    """
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    extras = project["optional-dependencies"]
    return [Requirement(value) for value in project["dependencies"]] + [
        Requirement(f"{value}; extra == '{extra}'")
        for extra, values in extras.items()
        for value in values
    ]


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"exp": time.time() + 3600},
        {"exp": "invalid"},
        {"exp": []},
        {"exp": None},
    ],
)
def test_token_inspection_does_not_authenticate(claims: dict[str, object]) -> None:
    token = _unsigned(claims)
    assert token_claims(token) == claims
    check_bearer_token(token)


@pytest.mark.parametrize("expiry", [1, 1.5, "1"])
def test_expired_jwt_error_never_leaks_token(expiry: object) -> None:
    token = _unsigned({"exp": expiry, "sub": "private-identity"})
    with pytest.raises(GError, match="Get a new token") as caught:
        check_bearer_token(token)
    assert caught.value.code == errno.EACCES
    assert "private-identity" not in str(caught.value)
    assert token not in str(caught.value)


@pytest.mark.parametrize("token", ["", "opaque-macaroon", "a.b", "a.b.c", "a.b.c.d"])
def test_opaque_credentials_remain_supported(token: str) -> None:
    assert token_claims(token) == {}
    check_bearer_token(token)


_HEAD = _segment(b'{"alg":"none"}')
_EXPIRED = _segment(b'{"exp":1}')


@pytest.mark.parametrize(
    "token",
    [
        f"{_HEAD}.{_EXPIRED}=.",  # padding is not part of a JWS segment
        f"{_HEAD}.{_EXPIRED[:-1]}+.",  # standard, not URL-safe, alphabet
        f"{_HEAD}.{_EXPIRED} .",  # whitespace a lenient decoder would skip
        f"{_HEAD}.{_EXPIRED}A.",  # one character past a multiple of four
        f"{_HEAD}.{_segment(bytes([0xFF, 0xFE]))}.",  # not UTF-8
        f"{_HEAD}.{_segment(b'{exp: 1}')}.",  # not JSON
        f"{_HEAD}.{_segment(b'[1]')}.",  # JSON, but not an object
        f"{_segment(b'[]')}.{_EXPIRED}.",  # the header must be an object too
        f"{_segment(b'not json')}.{_EXPIRED}.",
        f".{_EXPIRED}.",  # an empty header encodes nothing
    ],
)
def test_malformed_jwts_have_no_claims(token: str) -> None:
    assert token_claims(token) == {}
    check_bearer_token(token)  # nothing trustworthy says it expired


def test_url_safe_alphabet_is_decoded() -> None:
    claims = {"exp": time.time() + 3600, "sub": "???>>>"}
    token = _unsigned(claims, header={"alg": "none", "kid": "~~~"})
    assert "-" in token or "_" in token
    assert token_claims(token) == claims


def test_a_connection_failure_keeps_the_errno_contract() -> None:
    cause = ConnectionRefusedError(errno.ECONNREFUSED, "refused")

    def connect() -> None:
        raise cause

    with pytest.raises(ConnectionRefusedError):
        _connection._connect(connect)


class _Conn:
    """A stand-in connection: whether it is still usable, and whether it was closed."""

    def __init__(self, connected: bool = True) -> None:
        self.is_connected = connected
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_the_pool_reuses_the_newest_live_connection_and_drops_the_rest() -> None:
    made: list[_Conn] = []

    def factory() -> _Conn:
        made.append(_Conn())
        return made[-1]

    pool = IdlePool(factory, _client.MAX_IDLE)
    old, dead, new = _Conn(), _Conn(connected=False), _Conn()
    for conn in (old, dead, new):
        pool.put(conn)
    assert pool.get() is new  # newest first
    assert pool.get() is old and dead.closed  # a dropped one is closed on the way
    assert pool.get() is made[0] and pool.idle_count() == 0  # then a fresh one


def test_the_pool_is_bounded_and_closes_what_comes_back_after_close() -> None:
    pool = IdlePool(_Conn, _client.MAX_IDLE)
    kept = [_Conn() for _ in range(_client.MAX_IDLE)]
    for conn in kept:
        pool.put(conn)
    extra = _Conn()
    pool.put(extra)
    assert extra.closed and pool.idle_count() == _client.MAX_IDLE
    pool.close()
    assert all(conn.closed for conn in kept) and pool.idle_count() == 0
    late = _Conn()
    pool.put(late)
    assert late.closed and pool.idle_count() == 0


def test_dependency_rejection_boundaries() -> None:
    assert not ed25519.verify(b"short", b"", bytes(64))
    assert not p256.verify((0, 0), b"message", 1, 1)
    with pytest.raises(der.DERError):
        der.parse(b"\x02\x01\x01", -1)


def test_required_dependencies_are_portable() -> None:
    runtime = {
        requirement.name.lower()
        for requirement in _requirements()
        if requirement.marker is None or requirement.marker.evaluate({"extra": ""})
    }
    # Only what this package imports itself; asn1crypto, for one, still
    # arrives transitively through xrdsec, and botocore through xrdhttp (S3
    # signing and parsing are xrdhttp's, so nothing here imports botocore).
    # urllib3 is gone: the HTTP plugin pools standard-library connections itself
    # (it still arrives, through botocore, but nothing here imports it).
    assert runtime == {
        "xrdclient",
        "xrdcore",
        "xrdsec",
        "xrdhttp",
        "bcrypt",
        "cryptography",
    }


def test_the_libraries_are_pinned_to_their_minor_release() -> None:
    """xrdcore, xrdsec and xrdhttp follow semantic versioning: any 0.4.x, never 0.5."""
    libraries = {
        requirement.name: str(requirement.specifier)
        for requirement in _requirements()
        if requirement.name in ("xrdcore", "xrdsec", "xrdhttp")
    }
    assert libraries == dict.fromkeys(("xrdcore", "xrdsec", "xrdhttp"), "<0.5,>=0.4.0")


def test_shared_client_dependency_is_exactly_pinned() -> None:
    dependency = next(
        requirement for requirement in _requirements() if requirement.name == "xrdclient"
    )
    # The two projects are released together under one version number, so
    # the pin names this package's own release.
    assert str(dependency.specifier) == f"=={xgfalclient.__version__}"
    assert dependency.marker is None


def test_native_kerberos_bindings_are_in_the_optional_extra() -> None:
    """The extra is xrdsec's: python-gssapi through it, and no pykrb5 (dropped in 0.4.0)."""
    optional = [
        requirement
        for requirement in _requirements()
        if requirement.marker is not None and requirement.marker.evaluate({"extra": "krb5"})
    ]
    assert [(r.name.lower(), sorted(r.extras)) for r in optional] == [("xrdsec", ["krb5"])]


def test_additional_cipher_adapter_boundaries() -> None:
    from xgfalclient.crypto import aes, chacha, ciphers

    with pytest.raises(ValueError, match="16 bytes"):
        aes.AES(bytes(16)).encrypt_block(b"short")
    with pytest.raises(ValueError, match="32 bytes"):
        ciphers.get().chacha20(b"short")
    assert ciphers.get("  ") is ciphers.PURE
    block = chacha.chacha20_block(
        bytes(range(32)), chacha.rfc_iv(1, bytes.fromhex("000000090000004a00000000"))
    )
    assert block.hex() == (
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    )
