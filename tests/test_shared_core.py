"""Old import paths are true aliases of the one shared implementation in the libraries.

The code itself is tested where it lives: xrdsec's suite covers the
cryptography and VOMS (its ``tests/test_shared_core.py`` is this file's former
body, run against xrdsec), xrdcore's the XML guard. What stays here is
xgfalclient's promise that its semi-public module paths keep working, as the
same module objects, and that both certificate views read one file alike.
"""

from __future__ import annotations

import importlib

import pytest
from xrdsec.x509 import Name, load_proxy

from xgfalclient.crypto import x509
from xgfalclient.testing.pki import PKI


@pytest.mark.parametrize("name", ["aes", "der", "ed25519", "p256", "rsa", "voms"])
def test_crypto_compatibility_modules_are_xrdsecs(name: str) -> None:
    previous = importlib.import_module(f"xgfalclient.crypto.{name}")
    canonical = importlib.import_module(f"xrdsec.{name}")
    assert previous is canonical
    assert previous.__file__ == canonical.__file__


def test_the_gsi_module_is_xrdsecs() -> None:
    """GSI moved to ``xrdsec.gsi.gss`` in 0.4.0; the old path is that module."""
    assert importlib.import_module("xgfalclient.crypto.gsi") is importlib.import_module(
        "xrdsec.gsi.gss"
    )


def test_xml_guard_is_xrdcores() -> None:
    previous = importlib.import_module("xgfalclient._xml")
    assert previous is importlib.import_module("xrdcore.safexml")


def test_the_http_connection_alias_is_gone() -> None:
    """The plug-in no longer builds connections itself: xrdhttp's session does."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("xgfalclient.plugins.http._connection")


def test_both_certificate_models_share_names_and_key_types(pki: PKI) -> None:
    previous = x509.load_credential(str(pki.proxy_path))
    canonical = load_proxy(str(pki.proxy_path))
    assert previous.certificate.subject == canonical.certificate.subject
    assert previous.certificate.issuer == canonical.certificate.issuer
    assert previous.certificate.public_key == canonical.certificate.public_key
    assert x509.Name is Name
