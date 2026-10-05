"""Read-only native cache diagnostics, without ambient credentials or a KDC."""

from __future__ import annotations

import errno
import sys
from types import SimpleNamespace

import pytest

from xgfalclient.crypto import krb5


class NativeError(Exception):
    err_code = -1765328189


@pytest.fixture
def binding(monkeypatch):
    calls = []
    credentials = [SimpleNamespace(times=SimpleNamespace(endtime=123))]
    module = SimpleNamespace(
        init_context=lambda: object(),
        cc_default_name=lambda context: b"API:default",
        cc_resolve=lambda context, name: calls.append(name) or credentials,
        cc_get_principal=lambda context, cache: SimpleNamespace(name=b"alice@EXAMPLE"),
        Krb5Error=NativeError,
    )
    monkeypatch.setitem(sys.modules, "krb5", module)
    return module, calls


@pytest.mark.parametrize("name", [None, "FILE:/tmp/test-cache", "API:user", "KCM:user"])
def test_preflight_returns_metadata_not_keys(binding, name):
    _module, calls = binding
    expected = name or "API:default"
    assert krb5.inspect_cache(name) == {
        "name": expected,
        "principal": "alice@EXAMPLE",
        "expires_at": 123,
    }
    assert calls == [expected.encode()]


def test_empty_cache_has_no_expiry(binding):
    module, _calls = binding
    module.cc_resolve = lambda context, name: []
    module.cc_get_principal = lambda context, cache: SimpleNamespace(name=None)
    assert krb5.inspect_cache()["expires_at"] == 0
    assert krb5.inspect_cache()["principal"] == ""


@pytest.mark.parametrize("name", [None, "API:user"])
def test_preflight_keeps_native_error_code(binding, name):
    module, _calls = binding

    def fail():
        raise NativeError("test cache unavailable")

    module.init_context = fail
    with pytest.raises(krb5.KerberosError, match=r"Check KRB5CCNAME.*kinit") as error:
        krb5.inspect_cache(name)
    assert error.value.code == errno.EACCES
    assert error.value.minor == NativeError.err_code


def test_missing_binding_explains_optional_install(monkeypatch):
    monkeypatch.setitem(sys.modules, "krb5", None)
    with pytest.raises(krb5.KerberosError, match=r"pip install 'xgfalclient\[krb5\]'") as error:
        krb5.inspect_cache()
    assert error.value.code == errno.EPROTONOSUPPORT


def test_real_native_cache_is_read_without_changes(tmp_path):
    native = pytest.importorskip("krb5")
    path = tmp_path / "cache"
    context = native.init_context()
    cache = native.cc_resolve(context, ("FILE:" + str(path)).encode())
    native.cc_initialize(context, cache, native.parse_name_flags(context, b"alice@EXAMPLE"))
    before = path.read_bytes()
    metadata = krb5.inspect_cache("FILE:" + str(path))
    assert metadata["principal"] == "alice@EXAMPLE"
    assert metadata["expires_at"] == 0
    assert path.read_bytes() == before
