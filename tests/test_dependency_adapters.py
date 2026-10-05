"""Security/compatibility contracts at the general-purpose library boundaries."""

from __future__ import annotations

import errno
import time
from importlib.metadata import requires

import jwt
import pytest
import xrdclient
from packaging.requirements import Requirement
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.exceptions import ConnectTimeoutError, HTTPError, NewConnectionError

from xgfalclient.creds import check_bearer_token, token_claims
from xgfalclient.crypto import der, ed25519, p256
from xgfalclient.errors import GError
from xgfalclient.plugins.http import _client, _connection


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
def test_token_inspection_does_not_authenticate(claims):
    token = jwt.encode(claims, key="", algorithm="none")
    assert token_claims(token) == claims
    check_bearer_token(token)


@pytest.mark.parametrize("expiry", [1, 1.5, "1"])
def test_expired_jwt_error_never_leaks_token(expiry):
    token = jwt.encode({"exp": expiry, "sub": "private-identity"}, key="", algorithm="none")
    with pytest.raises(GError, match="Get a new token") as caught:
        check_bearer_token(token)
    assert caught.value.code == errno.EACCES
    assert "private-identity" not in str(caught.value)
    assert token not in str(caught.value)


@pytest.mark.parametrize("token", ["", "opaque-macaroon", "a.b", "a.b.c", "a.b.c.d"])
def test_opaque_credentials_remain_supported(token):
    assert token_claims(token) == {}
    check_bearer_token(token)


@pytest.mark.parametrize(
    "error",
    [
        ConnectTimeoutError("timed out"),
        HTTPError("unclassified transport error"),
    ],
)
def test_urllib3_errors_keep_the_errno_contract(error):
    def connect():
        raise error

    with pytest.raises(OSError):
        _connection._connect(connect)


def test_refusal_is_not_misreported_as_timeout():
    cause = ConnectionRefusedError(errno.ECONNREFUSED, "refused")
    error = NewConnectionError(None, "refused")

    def connect():
        raise error from cause

    with pytest.raises(ConnectionRefusedError):
        _connection._connect(connect)


def test_closed_library_pool_has_no_idle_connections():
    pool = HTTPConnectionPool("localhost")
    pool.close()
    assert _client._idle_count(pool) == 0


def test_dependency_rejection_boundaries():
    assert not ed25519.verify(b"short", b"", bytes(64))
    assert not p256.verify((0, 0), b"message", 1, 1)
    with pytest.raises(der.DERError):
        der.parse(b"\x02\x01\x01", -1)


def test_required_dependencies_are_portable():
    runtime = {
        Requirement(value).name.lower()
        for value in requires("xgfalclient") or []
        if Requirement(value).marker is None or Requirement(value).marker.evaluate({"extra": ""})
    }
    assert runtime == {
        "xrdclient",
        "asn1crypto",
        "botocore",
        "cryptography",
        "pyjwt",
        "urllib3",
    }


def test_shared_client_dependency_is_exactly_pinned():
    dependency = next(
        Requirement(value)
        for value in requires("xgfalclient") or []
        if Requirement(value).name == "xrdclient"
    )
    assert str(dependency.specifier) == f"=={xrdclient.__version__}"
    assert dependency.marker is None


def test_native_kerberos_bindings_are_in_the_optional_extra():
    optional = {
        Requirement(value).name.lower()
        for value in requires("xgfalclient") or []
        if Requirement(value).marker is not None
        and Requirement(value).marker.evaluate({"extra": "krb5"})
    }
    assert optional == {"gssapi", "krb5"}


def test_additional_cipher_adapter_boundaries():
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
