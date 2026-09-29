"""``import gfal2``: the top-level package that stands in for python3-gfal2."""

from __future__ import annotations

import importlib
import pickle
import sys
import traceback

import pytest

import xgfalclient

#: python3-gfal2's module-level names (``dir(gfal2)`` less the dunders).
UPSTREAM = {
    "GError",
    "Gfal2Context",
    "NullHandler",
    "checksum_mode",
    "creat_context",
    "cred_clean",
    "cred_new",
    "cred_set",
    "get_version",
    "set_verbose",
    "verbose_level",
}


def test_import_gfal2_is_this_api() -> None:
    import gfal2

    assert gfal2.__name__ == "gfal2"
    assert gfal2.__version__ == "1.13.1" and gfal2.get_version() == "2.23.5"
    assert gfal2.Gfal2Context is xgfalclient.Gfal2Context
    assert gfal2.GError is xgfalclient.GError
    public = {name for name in dir(gfal2) if not name.startswith("_")}
    assert public >= UPSTREAM
    assert public <= set(xgfalclient.__all__)  # nothing leaked: no sys, no helpers
    assert "install_as_gfal2" not in public and "VERSION" not in public
    assert xgfalclient.VERSION == xgfalclient.__version__ != gfal2.__version__


def test_from_gfal2_import_names() -> None:
    from gfal2 import GError, Gfal2Context, checksum_mode, creat_context  # noqa: F401

    assert isinstance(creat_context(), Gfal2Context)
    assert str(checksum_mode.both) == "both"


def test_install_as_gfal2_installs_the_same_module(monkeypatch: pytest.MonkeyPatch) -> None:
    import gfal2

    monkeypatch.delitem(sys.modules, "gfal2")
    assert xgfalclient.install_as_gfal2() is gfal2
    assert sys.modules["gfal2"] is gfal2
    # A fresh import of the package answers with that same object too.
    monkeypatch.delitem(sys.modules, "gfal2")
    assert importlib.import_module("gfal2") is gfal2


def test_gerror_reports_as_gfal2() -> None:
    import gfal2

    assert gfal2.GError.__module__ == "gfal2"
    assert (gfal2.GError.code, gfal2.GError.message) == (0, "")
    error = pickle.loads(pickle.dumps(gfal2.GError("boom", 5)))
    assert (type(error), error.args) == (gfal2.GError, ("boom", 5))
    try:
        raise gfal2.GError("boom", 5)
    except gfal2.GError as exc:
        printed = traceback.format_exception_only(type(exc), exc)
    assert printed == ["gfal2.GError: boom\n"]


def test_install_before_any_import_makes_the_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xgfalclient, "_GFAL2", None)
    monkeypatch.delitem(sys.modules, "gfal2", raising=False)
    made = xgfalclient.install_as_gfal2()
    assert not hasattr(made, "__file__") and made.__version__ == "1.13.1"
    assert importlib.import_module("gfal2") is made
    assert made.Gfal2Context is xgfalclient.Gfal2Context


def test_module_credential_helpers_print_their_deprecation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    import gfal2

    context = gfal2.creat_context()
    credential = gfal2.cred_new("BEARER", "t")
    assert gfal2.cred_set(context, "https://se/", credential) == 0
    assert gfal2.cred_clean(context) == 0
    assert capsys.readouterr().err.splitlines() == [
        f"Deprecated: Please use context.{name}() instead!"
        for name in ("cred_new", "cred_set", "cred_clean")
    ]
