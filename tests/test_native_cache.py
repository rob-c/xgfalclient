"""Read-only Kerberos cache diagnostics, without ambient credentials or a KDC.

:func:`xgfalclient.crypto.krb5.inspect_cache` reads the cache with
xrdsec's pure-Python reader (tested in xrdsec's suite); what is pinned here
is gfal2's shape of the answer - the dictionary, and a ``GError`` whose
``errno`` tells "no cache" (``ENOENT``) from "cannot read it" (``EACCES``).
"""

from __future__ import annotations

import errno
from pathlib import Path

import pytest
from xrdsec.krb5.model import Principal
from xrdsec.testing.krb5 import make_ticket, write_ccache

from xgfalclient.crypto import krb5

JANE = Principal(("jane",), "EXAMPLE.ORG", 1)
TGT = Principal(("krbtgt", "EXAMPLE.ORG"), "EXAMPLE.ORG", 2)


def test_a_cache_is_described_without_its_keys_and_left_unchanged(tmp_path: Path) -> None:
    ticket = make_ticket(JANE, TGT, lifetime=600)
    path = Path(write_ccache(tmp_path / "cache", [ticket]))
    before = path.read_bytes()
    assert krb5.inspect_cache(f"FILE:{path}") == {
        "name": f"FILE:{path}",
        "principal": "jane@EXAMPLE.ORG",
        "expires_at": ticket.end_time,
    }
    assert path.read_bytes() == before


def test_the_default_cache_comes_from_krb5ccname(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_ccache(tmp_path / "cache", [], default=JANE)
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{path}")
    info = krb5.inspect_cache()
    assert info == {"name": f"FILE:{path}", "principal": "jane@EXAMPLE.ORG", "expires_at": 0}


def test_no_cache_is_enoent(tmp_path: Path) -> None:
    with pytest.raises(krb5.KerberosError, match=r"Check KRB5CCNAME.*kinit") as error:
        krb5.inspect_cache(f"FILE:{tmp_path / 'absent'}")
    assert error.value.code == errno.ENOENT


@pytest.mark.parametrize("kind", ["garbage", "directory", "api"])
def test_an_unreadable_cache_is_eacces(tmp_path: Path, kind: str) -> None:
    target = tmp_path / "bad"
    if kind == "garbage":
        target.write_bytes(b"\x09\x09garbage")
    elif kind == "directory":
        target.mkdir()
    name = "API:user" if kind == "api" else f"FILE:{target}"
    with pytest.raises(krb5.KerberosError, match=r"Check KRB5CCNAME and your file") as error:
        krb5.inspect_cache(name)
    assert error.value.code == errno.EACCES
