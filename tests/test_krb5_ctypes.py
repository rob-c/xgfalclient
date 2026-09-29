"""The ctypes GSS-API binding, against a fake library (and the real one, locally).

:class:`~krb5_fakes.FakeGSS` receives exactly what the binding would hand a
real ``CDLL``, so these tests pin the call sequence, the buffer and handle
ownership (nothing may leak), and every error path - statuses a real KDC
cannot be made to produce on demand.
"""

from __future__ import annotations

import ctypes
import errno
import sys
from collections.abc import Iterator
from typing import Any

import pytest

from krb5_fakes import (
    BAD_MIC,
    BAD_NAME,
    FAILURE,
    NO_CRED,
    USER,
    FakeGSS,
)
from xgfalclient.crypto import krb5
from xgfalclient.crypto.krb5 import _ctypes, _status
from xgfalclient.crypto.krb5._base import ACCEPT, INITIATE, PRINCIPAL, Target

KDC_UNREACH_UNSIGNED = _status.KDC_UNREACH & 0xFFFFFFFF


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("KRB5CCNAME", "KRB5_KTNAME", krb5.BACKEND_ENV, _ctypes.LIBRARY_ENV):
        monkeypatch.delenv(name, raising=False)
    krb5.reset()
    yield
    krb5.reset()


def backend(flavour: str = "mit", **kwargs: Any) -> tuple[_ctypes.CtypesBackend, FakeGSS]:
    fake = FakeGSS(flavour, **kwargs)
    return _ctypes.CtypesBackend(_ctypes.Library(fake, "fake")), fake


def install(monkeypatch: pytest.MonkeyPatch, flavour: str = "mit", **kwargs: Any) -> FakeGSS:
    """Make the fake the process's ctypes backend."""
    found, fake = backend(flavour, **kwargs)
    monkeypatch.setattr(_ctypes, "load", lambda: found)
    monkeypatch.setenv(krb5.BACKEND_ENV, "ctypes")
    return fake


def handshake(
    client: krb5.ClientContext, server: krb5.AcceptorContext
) -> tuple[krb5.ClientContext, krb5.AcceptorContext]:
    reply = server.step(client.step())
    if not client.complete:
        assert client.step(reply) == b""
    return client, server


# -- layout and discovery -----------------------------------------------------------------------


def test_packing_matches_the_headers() -> None:
    assert _ctypes.packing("darwin", "x86_64") == {"_pack_": 2, "_layout_": "ms"}
    assert _ctypes.packing("darwin", "arm64") == {}
    assert _ctypes.packing("linux", "x86_64") == {}
    expected = 4 if _ctypes.packing(sys.platform, _ctypes.platform.machine()) else 8
    assert _ctypes.OID.elements.offset == expected


def test_candidates_order_and_dedup(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []

    def find(stem: str) -> str | None:
        asked.append(stem)
        return {"gssapi_krb5": "libgssapi_krb5.so.2"}.get(stem)

    found = _ctypes.candidates("linux", find)
    assert next(found) == "libgssapi_krb5.so.2"
    assert asked == []  # find_library is only asked once the fixed names fail
    assert list(found) == ["libgssapi.so.3"]
    assert asked == ["gssapi_krb5", "gssapi"]

    monkeypatch.setenv(_ctypes.LIBRARY_ENV, "/opt/gss.so")
    darwin = list(_ctypes.candidates("darwin", lambda stem: None))
    assert darwin[0] == "/opt/gss.so"
    assert darwin[1] == "/System/Library/Frameworks/GSS.framework/GSS"
    assert "/usr/lib/libgssapi_krb5.dylib" in darwin


def test_load_reports_every_failure() -> None:
    def loader(path: str) -> Any:
        if path == "missing":
            raise OSError("no such file")
        if path == "libc":
            return object()  # loads, but has no gss_* symbols
        return FakeGSS("heimdal")

    with pytest.raises(OSError) as info:
        _ctypes.load(["missing", "libc"], loader)
    assert "missing: no such file" in str(info.value)
    assert "libc: not a GSS-API library" in str(info.value)
    with pytest.raises(OSError, match="nothing to try"):
        _ctypes.load([], loader)
    found = _ctypes.load(["missing", "good"], loader)
    assert found.name == "ctypes-heimdal"
    assert found.library.path == "good"
    # With no paths, the platform's candidates are tried.
    assert _ctypes.load(None, lambda path: FakeGSS()).name == "ctypes-mit"


def test_library_declares_signatures() -> None:
    fake = FakeGSS("mit")
    library = _ctypes.Library(fake, "fake")
    assert library.flavour == "mit"
    assert fake.gss_wrap.restype is ctypes.c_uint32
    assert fake.gss_wrap.argtypes == _ctypes.SIGNATURES["gss_wrap"]
    assert set(library.optional) == {
        "gss_acquire_cred_from",
        "gss_krb5_ccache_name",
        "krb5_gss_register_acceptor_identity",
    }


# -- statuses --------------------------------------------------------------------------------------


def test_display_status_chain_and_fallbacks() -> None:
    found, fake = backend()
    library = found.library
    assert library.display(NO_CRED, 1) == [
        f"major {NO_CRED:#x} part 0",
        f"major {NO_CRED:#x} part 1",
    ]
    fake.display_loops = True
    assert len(library.display(5, 2)) == 8  # capped
    fake.display_loops = False
    fake.display_empty = True
    error = library.error("thing", NO_CRED, 5)
    assert error.message.startswith("thing failed: " + _status.routine_text(NO_CRED))
    assert "minor code 5" in error.message
    assert "run kinit" in error.message
    assert error.code == errno.EACCES
    assert (error.major, error.minor) == (NO_CRED, 5)
    fake.display_empty = False
    fake.display_fails = True
    assert library.display(NO_CRED, 1) == []
    assert fake.live() == {}


def test_error_texts_and_codes() -> None:
    found, _fake = backend()
    library = found.library
    timeout = library.error("auth", FAILURE, KDC_UNREACH_UNSIGNED)
    assert timeout.code == errno.ETIMEDOUT
    assert "minor 0x" in timeout.message and "no KDC answered" in timeout.message
    replay = library.error("gss_unwrap", 2, 100001, protection=True)
    assert replay.code == errno.EPROTO
    assert "minor" not in replay.message  # MIT's "Success" is left out
    plain = library.error("auth", FAILURE, 0)
    assert plain.code == errno.EACCES and "minor" not in plain.message


# -- names and credentials ----------------------------------------------------------------------


def test_import_and_display_names() -> None:
    found, fake = backend()
    library = found.library
    name = library.import_name(Target("host@door.example"))
    assert library.display_name(name) == "host/door.example@XGFAL.TEST"
    library.release_name(name)
    library.release_name(name)  # already released: nothing to do
    principal = library.import_name(Target("xrootd/h@XGFAL.TEST", PRINCIPAL))
    fake.fail["gss_display_name"] = (BAD_NAME, 0)
    with pytest.raises(krb5.KerberosError) as info:
        library.display_name(principal)
    assert info.value.code == errno.EINVAL
    library.release_name(principal)
    fake.fail["gss_import_name"] = (BAD_NAME, 0)
    with pytest.raises(krb5.KerberosError, match="importing the Kerberos name 'bad'"):
        library.import_name(Target("bad"))
    assert fake.live() == {}


def test_acquire_from_store_and_default() -> None:
    found, fake = backend("mit")
    library = found.library
    cred = library.acquire(None, INITIATE, {"ccache": "FILE:/tmp/cc"})
    assert fake.objects[cred.value] == ("cred", INITIATE, None, {"ccache": "FILE:/tmp/cc"})
    library.release_cred(cred)
    library.release_cred(cred)
    cred = library.acquire(None, ACCEPT, {})
    assert "gss_acquire_cred" in fake.calls
    library.release_cred(cred)
    fake.fail["gss_acquire_cred_from"] = (NO_CRED, 0)
    with pytest.raises(krb5.KerberosError, match="acquiring Kerberos credentials"):
        library.acquire(None, INITIATE, {"ccache": "FILE:/nope"})
    assert fake.live() == {}


def test_acquire_legacy_ccache_restores_the_previous_name() -> None:
    found, fake = backend("heimdal")
    library = found.library
    fake.ccache_name = b"API:original"
    cred = library.acquire(None, INITIATE, {"ccache": "FILE:/tmp/other"})
    assert fake.objects[cred.value][3] == {"ccache": "FILE:/tmp/other"}
    assert fake.ccache_name == b"API:original"
    library.release_cred(cred)
    fake.fail["gss_krb5_ccache_name"] = (FAILURE, 0)
    with pytest.raises(krb5.KerberosError, match="selecting the credential cache"):
        library.acquire(None, INITIATE, {"ccache": "FILE:/x"})
    fake.fail["gss_acquire_cred"] = (NO_CRED, 0)
    with pytest.raises(krb5.KerberosError):
        library.acquire(None, INITIATE, {"ccache": "FILE:/x"})
    assert fake.ccache_name == b"API:original"
    assert fake.live() == {}


def test_acquire_legacy_keytab() -> None:
    found, fake = backend("heimdal")
    library = found.library
    cred = library.acquire(None, ACCEPT, {"keytab": "/tmp/kt"})
    assert fake.acceptor_identity == b"/tmp/kt"
    assert fake.objects[cred.value][3] == {"keytab": "/tmp/kt"}
    library.release_cred(cred)
    # Old MIT: the krb5_ spelling only.
    found, fake = backend("old-mit")
    cred = found.library.acquire(None, ACCEPT, {"keytab": "/tmp/kt2"})
    assert fake.acceptor_identity == b"/tmp/kt2"
    found.library.release_cred(cred)


def test_acquire_legacy_without_the_extensions() -> None:
    found, _fake = backend("bare")
    with pytest.raises(krb5.KerberosError, match="set KRB5_KTNAME") as info:
        found.library.acquire(None, ACCEPT, {"keytab": "/tmp/kt"})
    assert info.value.code == errno.EOPNOTSUPP
    with pytest.raises(krb5.KerberosError, match="set KRB5CCNAME"):
        found.library.acquire(None, INITIATE, {"ccache": "FILE:/x"})


# -- contexts through the public API ------------------------------------------------------------


@pytest.mark.parametrize("flavour", ["mit", "heimdal"])
def test_mutual_handshake_and_protection(monkeypatch: pytest.MonkeyPatch, flavour: str) -> None:
    fake = install(monkeypatch, flavour)
    client = krb5.ClientContext("host", "door.example")
    server = krb5.AcceptorContext()
    assert client.backend == f"ctypes-{flavour}"
    assert client.initiator_name is None and client.target_name is None and client.flags == 0
    handshake(client, server)
    assert client.complete and server.complete
    assert client.initiator_name == server.initiator_name == USER
    assert client.target_name == "host/door.example@XGFAL.TEST"
    assert client.flags & krb5.MUTUAL_FLAG and client.flags & krb5.CONF_FLAG
    assert server.unwrap(client.wrap(b"hello"), require_confidential=True) == b"hello"
    assert client.unwrap(server.wrap(b"back", confidential=False)) == b"back"
    server.verify_mic(b"data", client.get_mic(b"data"))
    with pytest.raises(krb5.KerberosError) as info:
        server.verify_mic(b"data", b"forged")
    assert info.value.code == errno.EPROTO
    with pytest.raises(krb5.KerberosError) as info:
        server.unwrap(b"garbage")
    assert info.value.code == errno.EPROTO
    with pytest.raises(krb5.KerberosError, match="already established"):
        client.step(b"more")
    client.close()
    server.close()
    client.close()
    assert fake.live() == {}


def test_no_mutual_completes_in_one_step(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = install(monkeypatch)
    with krb5.ClientContext("host", "", mutual=False, replay=False, sequence=False) as client:
        token = client.step()
        assert client.complete
        with krb5.AcceptorContext("host", "door") as server:
            assert server.step(token) == b""
            assert server.complete
    assert fake.live() == {}


def test_mutual_authentication_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = install(monkeypatch)
    client = krb5.ClientContext("host", "door")
    server = krb5.AcceptorContext(principal="host/door@XGFAL.TEST", keytab="/tmp/kt")
    reply = server.step(client.step())
    fake.inquire_flags = 0
    with pytest.raises(krb5.KerberosError, match="did not authenticate itself") as info:
        client.step(reply)
    assert info.value.code == errno.EACCES
    assert not client.complete
    client.close()
    server.close()
    assert fake.live() == {}


def test_wrap_without_confidentiality_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = install(monkeypatch)
    client, server = handshake(krb5.ClientContext("host", "door"), krb5.AcceptorContext())
    fake.no_conf = True
    with pytest.raises(krb5.KerberosError, match="confidentiality"):
        client.wrap(b"secret")
    with pytest.raises(krb5.KerberosError, match="unencrypted"):
        server.unwrap(client.wrap(b"x", confidential=False), require_confidential=True)
    for name, call in (
        ("gss_wrap", lambda: client.wrap(b"x")),
        ("gss_unwrap", lambda: server.unwrap(b"WC:x")),
        ("gss_get_mic", lambda: client.get_mic(b"x")),
        ("gss_verify_mic", lambda: server.verify_mic(b"x", b"MIC:x")),
    ):
        fake.fail[name] = (BAD_MIC, 0)
        with pytest.raises(krb5.KerberosError, match=name) as info:
            call()
        assert info.value.code == errno.EPROTO
    fake.fail["gss_unwrap"] = (4, 0)  # GSS_S_OLD_TOKEN, supplementary only
    with pytest.raises(krb5.KerberosError):
        server.unwrap(b"WC:x")
    client.close()
    server.close()
    assert fake.live() == {}


def test_handshake_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = install(monkeypatch)
    client = krb5.ClientContext("host", "door")
    fake.fail["gss_init_sec_context"] = (FAILURE, KDC_UNREACH_UNSIGNED)
    with pytest.raises(krb5.KerberosError) as info:
        client.step()
    assert info.value.code == errno.ETIMEDOUT
    assert "gss_init_sec_context" in info.value.message
    client.step()
    with pytest.raises(krb5.KerberosError) as info:
        client.step(b"not an AP-REP")
    assert info.value.code == errno.EPROTO
    assert info.value.minor == 0x96C73A1F
    client.close()

    server = krb5.AcceptorContext()
    with pytest.raises(krb5.KerberosError) as info:
        server.step(b"junk")
    assert info.value.token == b"KRB-ERROR"  # for the protocol to forward
    with pytest.raises(krb5.KerberosError, match="needs the client's token"):
        server.step(b"")
    server.close()
    assert fake.live() == {}


def test_inquire_failure_releases_names(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = install(monkeypatch)
    client = krb5.ClientContext("host", "door", mutual=False)
    fake.fail["gss_inquire_context"] = (FAILURE, 0)
    with pytest.raises(krb5.KerberosError, match="gss_inquire_context"):
        client.step()
    client.close()
    assert fake.live() == {}


def test_closed_and_unestablished_contexts(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch)
    client = krb5.ClientContext("host", "door")
    with pytest.raises(krb5.KerberosError, match="not yet established") as info:
        client.wrap(b"x")
    assert info.value.code == errno.EPROTO
    client.close()
    with pytest.raises(krb5.KerberosError, match="closed") as info:
        client.step()
    assert info.value.code == errno.EBADF
    with pytest.raises(krb5.KerberosError, match="closed"):
        client.unwrap(b"x")


def test_client_ccache_and_its_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = install(monkeypatch)
    client = krb5.ClientContext("host", "door", ccache="FILE:/tmp/cc", delegate=True)
    assert client.requested & krb5.DELEG_FLAG
    client.close()
    bare = krb5.ClientContext("host", "door", integrity=False, confidentiality=False)
    assert not bare.requested & (krb5.CONF_FLAG | krb5.INTEG_FLAG)
    bare.close()
    fake.fail["gss_acquire_cred_from"] = (NO_CRED, _status.FCC_NOFILE & 0xFFFFFFFF)
    with pytest.raises(krb5.KerberosError, match="run kinit"):
        krb5.ClientContext("host", "door", ccache="FILE:/nope")
    assert fake.live() == {}


def test_acceptor_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = install(monkeypatch)
    krb5.AcceptorContext(keytab="/tmp/kt").close()  # keytab, any principal in it
    krb5.AcceptorContext("host").close()  # a name, the default keytab
    fake.fail["gss_acquire_cred"] = (NO_CRED, 0)
    with pytest.raises(krb5.KerberosError):
        krb5.AcceptorContext("host", "door")
    fake.fail["gss_acquire_cred_from"] = (NO_CRED, 0)
    with pytest.raises(krb5.KerberosError):
        krb5.AcceptorContext(keytab="/tmp/kt")
    assert fake.live() == {}


# -- the real library, where there is one ------------------------------------------------------


def test_real_library_names_and_statuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Names and messages only: no credential cache, no KDC, no network."""
    try:
        found = _ctypes.load()
    except OSError as exc:
        pytest.skip(str(exc))
    monkeypatch.setenv("KRB5CCNAME", "MEMORY:xgfal-test")
    library = found.library
    name = library.import_name(Target("host@door.example.org"))
    assert "door.example.org" in library.display_name(name)
    library.release_name(name)
    error = library.error("auth", NO_CRED, _status.CC_NOTFOUND & 0xFFFFFFFF)
    assert "credentials" in error.message.lower()
    assert error.code == errno.EACCES
