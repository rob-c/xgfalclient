"""Kerberos: status mapping, backend selection, and the ``gssapi``-package backend.

The real KDC runs in ``test_krb5_interop.py``. Native handle management and
ABI behavior belong to the optional python-gssapi dependency.
"""

from __future__ import annotations

import errno
import pickle
import sys
import threading
from collections.abc import Iterator
from typing import Any

import pytest

from krb5_fakes import USER, fake_gssapi_module
from xgfalclient.crypto import krb5
from xgfalclient.crypto.krb5 import _status
from xgfalclient.crypto.krb5._base import Backend, Mechanism, Target
from xgfalclient.errors import GError


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("KRB5CCNAME", "KRB5_KTNAME", krb5.BACKEND_ENV, "XGFAL_GSSAPI_LIBRARY"):
        monkeypatch.delenv(name, raising=False)
    krb5.reset()
    yield
    krb5.reset()


@pytest.fixture
def gssapi(monkeypatch: pytest.MonkeyPatch) -> Any:
    module = fake_gssapi_module()
    monkeypatch.setitem(sys.modules, "gssapi", module)
    return module


def no_gssapi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "gssapi", None)  # import raises ImportError


def test_signed_and_is_error() -> None:
    assert _status.signed(_status.KDC_UNREACH & 0xFFFFFFFF) == _status.KDC_UNREACH
    assert _status.signed(5) == 5
    assert _status.is_error(7 << 16) and _status.is_error(1 << 24)
    assert not _status.is_error(_status.CONTINUE_NEEDED)


def test_routine_text() -> None:
    assert "argument" in _status.routine_text(1 << 24)
    assert "credentials" in _status.routine_text(_status.NO_CRED << 16)
    assert _status.routine_text(99 << 16) == f"GSS major status 0x{99 << 16:08x}"
    assert "duplicate" in _status.routine_text(2)


@pytest.mark.parametrize(
    ("major", "minor", "protection", "code"),
    [
        (_status.FAILURE << 16, _status.KDC_UNREACH & 0xFFFFFFFF, False, errno.ETIMEDOUT),
        (_status.FAILURE << 16, errno.ETIMEDOUT, False, errno.ETIMEDOUT),
        (_status.FAILURE << 16, errno.ECONNREFUSED, False, errno.ECONNREFUSED),
        (1 << 24, 0, False, errno.EINVAL),
        (2, 0, True, errno.EPROTO),
        (2, 0, False, errno.EPROTO),
        (_status.BAD_MIC << 16, 0, True, errno.EPROTO),
        (_status.BAD_MIC << 16, 0, False, errno.EACCES),
        (_status.NO_CRED << 16, 0, False, errno.EACCES),
        (_status.NO_CRED << 16, 0, True, errno.EACCES),
        (_status.BAD_MECH << 16, 0, False, errno.EPROTONOSUPPORT),
        (_status.UNAVAILABLE << 16, 0, False, errno.EOPNOTSUPP),
        (_status.FAILURE << 16, 0, False, errno.EACCES),
    ],
)
def test_errno_for(major: int, minor: int, protection: bool, code: int) -> None:
    assert _status.errno_for(major, minor, protection=protection) == code


def test_hints() -> None:
    failure = _status.FAILURE << 16
    assert "kinit" in _status.hint_for(_status.NO_CRED << 16, 0)
    assert "kinit" in _status.hint_for(failure, _status.KG_EMPTY_CCACHE)
    assert "service principal" in _status.hint_for(
        failure, _status.KDC_ERR_S_PRINCIPAL_UNKNOWN & 0xFFFFFFFF
    )
    assert "clocks" in _status.hint_for(failure, _status.AP_ERR_SKEW)
    assert "no KDC" in _status.hint_for(failure, _status.KDC_UNREACH)
    assert _status.hint_for(failure, 0) == ""


def test_kerberos_error_is_a_gerror() -> None:
    error = krb5.KerberosError("nope", errno.EACCES, 1, 2, b"tok")
    assert isinstance(error, GError)
    assert (error.code, error.major, error.minor, error.token) == (errno.EACCES, 1, 2, b"tok")
    copy = pickle.loads(pickle.dumps(error))
    assert type(copy) is krb5.KerberosError
    assert (copy.message, copy.code) == ("nope", errno.EACCES)


# -- backend selection ---------------------------------------------------------------------------


def test_gssapi_is_preferred(gssapi: Any) -> None:
    assert krb5.backend() == "gssapi"
    assert krb5.available() is None
    assert krb5.load_backend() is krb5.load_backend()  # cached


def test_context_lifecycle_and_protection_policy(gssapi: Any) -> None:
    with krb5.ClientContext("host", "door") as client, krb5.AcceptorContext() as server:
        with pytest.raises(krb5.KerberosError, match="not yet established"):
            client.wrap(b"not ready")
        with pytest.raises(krb5.KerberosError, match="needs the client's token"):
            server.step(b"")
        client.step(server.step(client.step()))
        with pytest.raises(krb5.KerberosError, match="already established"):
            client.step(b"again")
        token = client.wrap(b"message", confidential=False)
        with pytest.raises(krb5.KerberosError, match="unencrypted"):
            server.unwrap(token, require_confidential=True)
    with pytest.raises(krb5.KerberosError, match="closed"):
        client.step(b"again")
    with pytest.raises(krb5.KerberosError, match="closed"):
        client.get_mic(b"message")


def test_neither_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    no_gssapi(monkeypatch)
    reason = krb5.available()
    assert reason is not None
    assert "gssapi" in reason
    assert krb5.HINT in reason
    assert krb5.backend() is None
    with pytest.raises(krb5.KerberosError) as info:
        krb5.ClientContext("host", "door")
    assert info.value.code == errno.EPROTONOSUPPORT


def test_forced_backends(monkeypatch: pytest.MonkeyPatch, gssapi: Any) -> None:
    assert krb5.backend("gssapi") == "gssapi"
    assert krb5.available("ctypes") is None
    monkeypatch.setenv(krb5.BACKEND_ENV, "ctypes")
    assert krb5.backend() == "gssapi"
    monkeypatch.setitem(sys.modules, "gssapi", None)
    krb5.reset()
    monkeypatch.setenv(krb5.BACKEND_ENV, "gssapi")
    assert "gssapi" in str(krb5.available())
    with pytest.raises(krb5.KerberosError, match="unknown Kerberos backend") as info:
        krb5.load_backend("heimdal")
    assert info.value.code == errno.EINVAL


def test_gssapi_handshake_and_protection(gssapi: Any) -> None:
    client = krb5.ClientContext("host", "door.example", delegate=True)
    server = krb5.AcceptorContext()
    assert client.backend == server.backend == "gssapi"
    reply = server.step(client.step())
    assert server.complete and not client.complete
    assert client.step(reply) == b""
    assert client.complete
    assert client.initiator_name == server.initiator_name == USER
    assert client.target_name == "host/door.example@XGFAL.TEST"
    assert client.flags & krb5.MUTUAL_FLAG and client.flags & krb5.DELEG_FLAG
    assert server.unwrap(client.wrap(b"hi"), require_confidential=True) == b"hi"
    assert client.unwrap(server.wrap(b"yo", confidential=False)) == b"yo"
    server.verify_mic(b"m", client.get_mic(b"m"))
    with pytest.raises(krb5.KerberosError) as info:
        server.verify_mic(b"m", b"bad")
    assert info.value.code == errno.EPROTO
    assert "Message Integrity Check" in info.value.message  # the fallback text
    with pytest.raises(krb5.KerberosError, match="invalid Message Integrity") as info:
        server.unwrap(b"junk")
    assert info.value.code == errno.EPROTO
    gssapi.no_conf = True
    with pytest.raises(krb5.KerberosError, match="confidentiality"):
        client.wrap(b"x")
    client.close()
    server.close()


def test_gssapi_one_step_and_names(gssapi: Any) -> None:
    client = krb5.ClientContext("", "", principal="xrootd/h@XGFAL.TEST", mutual=False)
    token = client.step()
    assert client.complete and client.target_name == "xrootd/h@XGFAL.TEST"
    server = krb5.AcceptorContext(principal="xrootd/h@XGFAL.TEST", keytab="/tmp/kt")
    assert gssapi.last_credentials["store"] == {"keytab": "/tmp/kt"}
    assert gssapi.last_credentials["name"].text == "xrootd/h@XGFAL.TEST"
    assert server.step(token) == b""
    krb5.AcceptorContext(keytab="/tmp/kt")
    assert gssapi.last_credentials["name"] is None
    krb5.AcceptorContext("host", "door")
    assert gssapi.last_credentials["store"] is None
    krb5.ClientContext("host", "door", ccache="FILE:/tmp/cc")
    assert gssapi.last_credentials["store"] == {"ccache": "FILE:/tmp/cc"}


def test_unestablished_names_and_optional_requested_flags(gssapi: Any) -> None:
    with krb5.ClientContext(
        "host",
        "",
        mutual=False,
        replay=False,
        sequence=False,
        confidentiality=False,
        integrity=False,
    ) as client:
        assert client.initiator_name is None
        assert client.target_name is None
        assert client.flags == 0 and client.requested == 0
        assert client.target.name == "host"
    with krb5.AcceptorContext("host", ""):
        assert gssapi.last_credentials["name"].text == "host/localhost@XGFAL.TEST"


def test_supplementary_status_does_not_display_success_as_a_failure() -> None:
    error = _status.describe("checking token", 2, 1, ["duplicate"], ["Success"])
    assert "duplicate" in error.message
    assert "Success" not in error.message


def test_gssapi_errors(gssapi: Any) -> None:
    errors = gssapi.exceptions
    no_cred = errors.GSSError(7 << 16, 0x96C73A8D, "No credentials were supplied")
    gssapi.fail["SecurityContext"] = no_cred
    with pytest.raises(krb5.KerberosError, match="preparing Kerberos") as info:
        krb5.ClientContext("host", "door")
    assert info.value.code == errno.EACCES and "run kinit" in info.value.message
    assert f"No credentials were supplied: minor text {0x96C73A8D}" in info.value.message

    gssapi.fail["SecurityContext"] = errors.GSSError(13 << 16, 1, "Unspecified GSS failure")
    with pytest.raises(krb5.KerberosError) as info:
        krb5.ClientContext("host", "door")
    assert info.value.message.endswith("Unspecified GSS failure: minor code 1")

    gssapi.fail["SecurityContext"] = errors.GSSError(13 << 16, 5, "Unspecified GSS failure")
    with pytest.raises(krb5.KerberosError) as info:
        krb5.ClientContext("host", "door")
    assert info.value.message.endswith("failed: minor text 5")  # MIT's filler is dropped

    gssapi.fail["Credentials"] = NotImplementedError("no credential store extension")
    with pytest.raises(krb5.KerberosError, match="store extension") as info:
        krb5.ClientContext("host", "door", ccache="FILE:/x")
    assert info.value.code == errno.EOPNOTSUPP

    gssapi.fail["Credentials"] = errors.GeneralError("bad keytab")
    with pytest.raises(krb5.KerberosError, match="preparing a Kerberos acceptor") as info:
        krb5.AcceptorContext(keytab="/x")
    assert info.value.code == errno.EACCES

    client = krb5.ClientContext("host", "door")
    gssapi.fail["step"] = errors.GSSError(13 << 16, _status.KDC_UNREACH & 0xFFFFFFFF)
    with pytest.raises(krb5.KerberosError) as info:
        client.step()
    assert info.value.code == errno.ETIMEDOUT
    assert info.value.token == b""
    token = client.step()
    with pytest.raises(krb5.KerberosError, match="Invalid token"):
        client.step(b"bad")

    server = krb5.AcceptorContext()
    with pytest.raises(krb5.KerberosError) as info:
        server.step(b"bad")
    assert info.value.token == b"KRB-ERROR"
    server = krb5.AcceptorContext()
    client.close()

    client = krb5.ClientContext("host", "door")
    token = client.step()
    gssapi.fail["actual_flags"] = errors.GSSError(8 << 16, 0, "")
    with pytest.raises(krb5.KerberosError, match="gss_inquire_context"):
        client.step(server.step(token))

    client = krb5.ClientContext("host", "door")
    server = krb5.AcceptorContext()
    client.step(server.step(client.step()))
    for name, call in (
        ("wrap", lambda: client.wrap(b"x")),
        ("unwrap", lambda: server.unwrap(b"WC:x")),
        ("get_signature", lambda: client.get_mic(b"x")),
        ("verify_signature", lambda: server.verify_mic(b"x", b"MIC:x")),
    ):
        gssapi.fail[name] = errors.GSSError(2, 0, "The token was a duplicate")
        with pytest.raises(krb5.KerberosError, match="duplicate") as info:
            call()
        assert info.value.code == errno.EPROTO


def test_mutual_is_enforced_with_gssapi(gssapi: Any) -> None:
    client = krb5.ClientContext("host", "door")
    server = krb5.AcceptorContext()
    reply = server.step(client.step())
    gssapi.flags_override = 0
    with pytest.raises(krb5.KerberosError, match="mutual"):
        client.step(reply)


def test_contexts_are_locked(gssapi: Any) -> None:
    """Wrapping from many threads at once goes through one context safely."""
    client = krb5.ClientContext("host", "door")
    server = krb5.AcceptorContext()
    client.step(server.step(client.step()))
    results: list[bytes] = []

    def worker(index: int) -> None:
        for _ in range(50):
            results.append(server.unwrap(client.wrap(b"%d" % index)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 400


def test_failed_constructor_is_safe_to_collect(monkeypatch: pytest.MonkeyPatch) -> None:
    no_gssapi(monkeypatch)
    with pytest.raises(krb5.KerberosError):
        krb5.AcceptorContext()
    # __del__ ran on a half-built object; closing one by hand is also harmless.
    context = krb5.ClientContext.__new__(krb5.ClientContext)
    context.close()


def test_base_interfaces_are_unimplemented() -> None:
    """Every backend overrides these; the base class only states the shape."""
    mech = Mechanism()
    assert mech.complete is False
    calls: list[Any] = [
        lambda: mech.step(b""),
        lambda: mech.wrap(b"x", True),
        lambda: mech.unwrap(b"x"),
        lambda: mech.get_mic(b"x"),
        lambda: mech.verify_mic(b"x", b"m"),
        mech.inquire,
        mech.close,
        lambda: Backend().initiator(Target("host@example.org"), 0, None),
        lambda: Backend().acceptor(None, None),
    ]
    for call in calls:
        with pytest.raises(NotImplementedError):
            call()
