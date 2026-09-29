"""Kerberos against a real MIT KDC: both backends, three kinds of credential cache.

A throwaway AlmaLinux 9 container (``tests/krb5_interop/Dockerfile``: MIT
krb5 1.21, sssd's KCM, python3-gssapi, Python 3.9) creates realm
``XGFAL.TEST`` with ``user@XGFAL.TEST`` and ``host/kdc.xgfal.test`` in
``/etc/krb5.keytab``, runs ``kinit`` into a ``FILE:``, ``KCM:`` or ``DIR:``
default cache, and then ``driver.py`` - with this checkout's ``src``
bind-mounted - performs handshakes through the ctypes backend and the
``gssapi`` package and across the two, wrap/unwrap/MIC round trips, replay
and tamper detection, ``ccache=``/``keytab=`` selection, and the failures:
no ticket, unknown service, wrong keytab, KDC down.

On macOS a second test points the system Heimdal (``GSS.framework`` and the
``libgssapi_krb5.dylib`` shim) at the same KDC through a published port, so
the Heimdal paths - packed structs, the process-wide ccache and keytab
fallbacks - run for real too.

Skipped unless ``XGFAL_INTEROP=1``. Run as a script for a report::

    python tests/test_krb5_interop.py
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

pytestmark = [
    pytest.mark.interop,
    pytest.mark.skipif(os.environ.get("XGFAL_INTEROP") != "1", reason="XGFAL_INTEROP=1 not set"),
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available"),
]

IMAGE = "xgfal-krb5:latest"
ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "tests" / "krb5_interop"
HOST = "kdc.xgfal.test"
CCACHES = ("file", "kcm", "dir")


def build_image() -> None:
    subprocess.run(
        ["docker", "build", "-q", "-t", IMAGE, str(HERE)], check=True, capture_output=True
    )


def run_driver(ccache: str) -> dict[str, Any]:
    done = subprocess.run(
        [
            "docker", "run", "--rm", "-h", HOST,
            "-v", f"{ROOT / 'src'}:/src:ro", "-v", f"{HERE}:/k:ro",
            IMAGE, "/k/run.sh", ccache,
        ],
        capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    lines = done.stdout.strip().splitlines()
    assert done.returncode == 0 and lines, done.stderr
    return json.loads(lines[-1])  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def image() -> None:
    build_image()


@pytest.mark.parametrize("ccache", CCACHES)
def test_mit_kdc(image: None, ccache: str) -> None:
    results = run_driver(ccache)
    assert results["_python"].startswith("3.9")
    assert results["_ccache"].split(": ", 1)[1].split(":")[0] == ccache.upper()
    assert results["_backend"] == "gssapi"  # installed, so preferred
    failed = {name: r["detail"] for name, r in results.items() if name[0] != "_" and not r["ok"]}
    assert not failed, "\n".join(f"{name}:\n{detail}" for name, detail in failed.items())
    assert len(results) == 20 + 3  # 20 checks, 3 facts


MAC_SCRIPT = r"""
import os, sys
from xgfalclient.crypto import krb5
mode, cc, kt = sys.argv[1:]
if mode == "env":
    os.environ["KRB5CCNAME"], os.environ["KRB5_KTNAME"] = cc, kt
    client_options, acceptor_options = {}, {}
else:
    os.environ["KRB5CCNAME"] = "FILE:/nonexistent"
    client_options, acceptor_options = {"ccache": cc}, {"keytab": kt}
client = krb5.ClientContext("host", "kdc.xgfal.test", **client_options)
server = krb5.AcceptorContext(**acceptor_options)
client.step(server.step(client.step()))
assert client.complete and server.complete
assert client.initiator_name == server.initiator_name == "user@XGFAL.TEST"
assert server.unwrap(client.wrap(b"hello"), require_confidential=True) == b"hello"
assert client.unwrap(server.wrap(b"x" * 70000)) == b"x" * 70000
server.verify_mic(b"m", client.get_mic(b"m"))
token = client.wrap(b"once")
server.unwrap(token)
try:
    server.unwrap(token)
    raise SystemExit("replay accepted")
except krb5.KerberosError:
    pass
print(client.backend)
"""

MAC_KRB5_CONF = """\
[libdefaults]
    default_realm = XGFAL.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
    dns_canonicalize_hostname = false
    rdns = false
[realms]
    XGFAL.TEST = {{
        kdc = tcp/127.0.0.1:{port}
    }}
[domain_realm]
    kdc.xgfal.test = XGFAL.TEST
"""


@pytest.mark.skipif(sys.platform != "darwin", reason="the system Heimdal is macOS's")
@pytest.mark.parametrize(
    "library", ["/System/Library/Frameworks/GSS.framework/GSS", "/usr/lib/libgssapi_krb5.dylib"]
)
@pytest.mark.parametrize("mode", ["env", "explicit"])
def test_macos_heimdal(image: None, library: str, mode: str, tmp_path: Path) -> None:
    name = f"xgfal-kdc-{os.getpid()}-{mode}-{Path(library).name}"
    with socket.socket() as probe:  # a port nothing else is using
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    out = Path(tempfile.mkdtemp(dir=tmp_path))
    subprocess.run(
        [
            "docker", "run", "-d", "--rm", "--name", name, "-h", HOST,
            "-p", f"{port}:88/tcp", "-v", f"{HERE}:/k:ro", "-v", f"{out}:/out",
            IMAGE, "sh", "-c",
            "CCACHE_LINE= /k/kdc.sh && cp /etc/krb5.keytab /out/host.keytab"
            " && chmod 644 /out/host.keytab && sleep 300",
        ],
        check=True, capture_output=True,
    )  # fmt: skip
    try:
        for _ in range(100):
            if (out / "host.keytab").exists():
                break
            time.sleep(0.2)
        conf = tmp_path / "krb5.conf"
        conf.write_text(MAC_KRB5_CONF.format(port=port))
        cache = f"FILE:{tmp_path / 'cc'}"
        env = dict(os.environ, KRB5_CONFIG=str(conf), KRB5CCNAME=cache)
        env["XGFAL_GSSAPI_LIBRARY"] = library
        env["PYTHONPATH"] = str(ROOT / "src")
        for _ in range(20):  # the KDC may still be starting
            kinit = subprocess.run(
                ["kinit", "--password-file=STDIN", "user@XGFAL.TEST"],
                input="userpw\n", env=env, capture_output=True, text=True, check=False,
            )  # fmt: skip
            if kinit.returncode == 0:
                break
            time.sleep(0.5)
        assert kinit.returncode == 0, kinit.stderr
        done = subprocess.run(
            [sys.executable, "-c", MAC_SCRIPT, mode, cache, f"FILE:{out / 'host.keytab'}"],
            env=env, capture_output=True, text=True, timeout=120, check=False,
        )  # fmt: skip
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == "ctypes-heimdal"
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


if __name__ == "__main__":
    build_image()
    for kind in CCACHES:
        for check, result in run_driver(kind).items():
            if check.startswith("_"):
                print(f"{kind:4} {check}: {result}")
            else:
                status = "ok  " if result["ok"] else "FAIL"
                print(f"{kind:4} {status} {check}  {result['detail'].strip()[:160]}")
