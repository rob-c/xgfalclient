"""Kerberos: gfal2's side of the GSS-API contexts xrdsec provides.

The contexts, the python-gssapi binding and the status mapping are tested in
xrdsec's suite (``tests/test_krb5_gss.py``); the real KDC runs in
``test_krb5_interop.py``. What is tested here is what
:mod:`xgfalclient.crypto.krb5` adds: every failure is a ``GError`` carrying
the library's ``errno``, statuses and token; ``$XGFAL_KRB5_BACKEND`` with
its ``ctypes`` alias; and this package's install hint.
"""

from __future__ import annotations

import errno
import pickle
import sys
from collections.abc import Callable, Iterator

import pytest
from xrdsec.krb5 import gss
from xrdsec.testing.krb5 import FAKE_USER, FakeGssapi, fake_gssapi_module

from xgfalclient.crypto import krb5
from xgfalclient.errors import GError


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("KRB5CCNAME", "KRB5_KTNAME", krb5.BACKEND_ENV):
        monkeypatch.delenv(name, raising=False)
    krb5.reset()
    yield
    krb5.reset()


@pytest.fixture
def gssapi(monkeypatch: pytest.MonkeyPatch) -> FakeGssapi:
    module = fake_gssapi_module()
    monkeypatch.setitem(sys.modules, "gssapi", module)
    return module


def no_gssapi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "gssapi", None)  # import raises ImportError


def test_the_public_names_are_the_librarys() -> None:
    assert krb5.reset is gss.reset
    for name in ("CONF_FLAG", "DELEG_FLAG", "INTEG_FLAG", "MUTUAL_FLAG", "REPLAY_FLAG"):
        assert getattr(krb5, name) is getattr(gss, name)
    assert krb5.SEQUENCE_FLAG is gss.SEQUENCE_FLAG


def test_kerberos_error_is_a_gerror_and_a_library_error() -> None:
    error = krb5.KerberosError("nope", errno.EACCES, 1, 2, b"tok")
    assert isinstance(error, GError) and isinstance(error, gss.KerberosError)
    assert (error.code, error.major, error.minor, error.token) == (errno.EACCES, 1, 2, b"tok")
    assert error.args == ("nope", errno.EACCES)
    copy = pickle.loads(pickle.dumps(error))
    assert type(copy) is krb5.KerberosError
    assert (copy.message, copy.code, copy.token) == ("nope", errno.EACCES, b"")


def test_gssapi_is_found_and_cached(gssapi: FakeGssapi) -> None:
    assert krb5.backend() == "gssapi"
    assert krb5.available() is None
    assert krb5.load_backend() is krb5.load_backend()


def test_no_binding_names_this_packages_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    no_gssapi(monkeypatch)
    reason = krb5.available()
    assert reason is not None and "gssapi" in reason and krb5.HINT in reason
    assert krb5.backend() is None
    with pytest.raises(krb5.KerberosError) as info:
        krb5.ClientContext("host", "door")
    assert info.value.code == errno.EPROTONOSUPPORT and krb5.HINT in info.value.message
    with pytest.raises(krb5.KerberosError):
        krb5.AcceptorContext()


def test_the_environment_and_the_ctypes_alias(
    monkeypatch: pytest.MonkeyPatch, gssapi: FakeGssapi
) -> None:
    assert krb5.backend("gssapi") == "gssapi"
    assert krb5.available("ctypes") is None
    monkeypatch.setenv(krb5.BACKEND_ENV, "ctypes")
    assert krb5.backend() == "gssapi"
    no_gssapi(monkeypatch)
    krb5.reset()
    monkeypatch.setenv(krb5.BACKEND_ENV, "gssapi")
    assert "gssapi" in str(krb5.available())
    with pytest.raises(krb5.KerberosError, match="unknown Kerberos backend") as info:
        krb5.load_backend("heimdal")
    assert info.value.code == errno.EINVAL
    monkeypatch.setenv(krb5.BACKEND_ENV, "heimdal")
    with pytest.raises(krb5.KerberosError, match="'heimdal'"):
        krb5.ClientContext("host", "door")


def test_a_handshake_through_the_adapter(gssapi: FakeGssapi) -> None:
    with (
        krb5.ClientContext("host", "door.example", delegate=True, backend="ctypes") as client,
        krb5.AcceptorContext(keytab="/tmp/kt") as server,
    ):
        assert client.step(server.step(client.step())) == b""
        assert client.complete and server.complete
        assert server.initiator_name == FAKE_USER
        assert client.flags & krb5.DELEG_FLAG
        assert server.unwrap(client.wrap(b"hi"), require_confidential=True) == b"hi"
        server.verify_mic(b"m", client.get_mic(b"m"))


def test_construction_errors_are_gerrors(gssapi: FakeGssapi) -> None:
    errors = gssapi.exceptions
    gssapi.fail["SecurityContext"] = errors.GSSError(7 << 16, 0, "No credentials were supplied")
    with pytest.raises(krb5.KerberosError, match="run kinit") as info:
        krb5.ClientContext("host", "door")
    assert info.value.code == errno.EACCES and info.value.major == 7 << 16
    gssapi.fail["Credentials"] = errors.GeneralError("bad keytab")
    with pytest.raises(krb5.KerberosError, match="preparing a Kerberos acceptor"):
        krb5.AcceptorContext(keytab="/x")


def test_step_errors_keep_the_token(gssapi: FakeGssapi) -> None:
    client = krb5.ClientContext("host", "door")
    with pytest.raises(krb5.KerberosError, match="Invalid token") as info:
        krb5.AcceptorContext().step(b"bad")
    assert info.value.token == b"KRB-ERROR"
    client.step()
    with pytest.raises(krb5.KerberosError, match="Invalid token"):
        client.step(b"bad")


@pytest.mark.parametrize("call", ["wrap", "unwrap", "get_mic", "verify_mic"])
def test_message_protection_errors_are_gerrors(gssapi: FakeGssapi, call: str) -> None:
    client = krb5.ClientContext("host", "door")
    server = krb5.AcceptorContext()
    calls: dict[str, Callable[[], object]] = {
        "wrap": lambda: client.wrap(b"x"),
        "unwrap": lambda: server.unwrap(b"junk"),
        "get_mic": lambda: client.get_mic(b"x"),
        "verify_mic": lambda: server.verify_mic(b"x", b"bad"),
    }
    with pytest.raises(krb5.KerberosError, match="not yet established") as info:
        calls[call]()
    assert info.value.code == errno.EPROTO
    client.step(server.step(client.step()))
    gssapi.fail.update(
        wrap=gssapi.exceptions.GSSError(2, 0, "The token was a duplicate"),
        get_signature=gssapi.exceptions.GSSError(2, 0, "The token was a duplicate"),
    )
    with pytest.raises(krb5.KerberosError) as info:
        calls[call]()
    assert info.value.code == errno.EPROTO
