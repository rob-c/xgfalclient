"""Run inside the ``xgfal-krb5`` container by ``run.sh`` (after ``kdc.sh`` and ``kinit``).

Exercises :mod:`xgfalclient.crypto.krb5` against the real MIT KDC and
library with each backend (and across them), and prints one JSON object:
``{check: {"ok": bool, "detail": text}}`` plus ``_``-prefixed facts, which
``test_krb5_interop.py`` asserts on.
"""

from __future__ import annotations

import errno
import json
import os
import socket
import subprocess
import sys
import traceback
from typing import Any, Callable

from xgfalclient.crypto import krb5

HOST = socket.getfqdn()
BACKENDS = ("ctypes", "gssapi")
results: dict[str, Any] = {}


def check(name: str) -> Callable[[Callable[[], Any]], None]:
    def run(body: Callable[[], Any]) -> None:
        try:
            outcome = body()
            results[name] = {"ok": True, "detail": outcome or ""}
        except Exception:  # report, never stop: every check is independent
            results[name] = {"ok": False, "detail": traceback.format_exc()}

    return run


def handshake(client: krb5.ClientContext, server: krb5.AcceptorContext) -> None:
    token = client.step()
    while True:
        reply = server.step(token) if token else b""
        if client.complete:
            assert not reply, reply
            break
        token = client.step(reply)
        if client.complete:
            break
    assert client.complete and server.complete


def expect_error(code: int, call: Callable[[], Any], text: str = "") -> str:
    try:
        call()
    except krb5.KerberosError as exc:
        assert exc.code == code, (exc.code, str(exc))
        assert text in exc.message, exc.message
        return exc.message
    raise AssertionError("no error raised")


def full_round(client_backend: str, server_backend: str, **client_options: Any) -> None:
    client = krb5.ClientContext("host", HOST, backend=client_backend, **client_options)
    server = krb5.AcceptorContext(backend=server_backend)
    handshake(client, server)
    assert client.backend.startswith(client_backend), client.backend
    assert client.initiator_name == server.initiator_name == "user@XGFAL.TEST"
    assert client.target_name == f"host/{HOST}@XGFAL.TEST", client.target_name
    assert client.flags & krb5.MUTUAL_FLAG and client.flags & krb5.CONF_FLAG
    for size in (0, 1, 1000, 65536):
        data = os.urandom(size)
        assert server.unwrap(client.wrap(data), require_confidential=True) == data
        assert client.unwrap(server.wrap(data, confidential=False)) == data
    server.verify_mic(b"message", client.get_mic(b"message"))
    token = client.wrap(b"once")
    server.unwrap(token)
    expect_error(errno.EPROTO, lambda: server.unwrap(token), "duplicate")
    # A signature over other data fails; it also leaves a hole in the
    # sequence, which the next token then reports.
    expect_error(errno.EPROTO, lambda: server.verify_mic(b"other", client.get_mic(b"message")))
    expect_error(errno.EPROTO, lambda: server.unwrap(client.wrap(b"after")), "not received")
    tampered = bytearray(server.wrap(b"tamper me"))
    tampered[-1] ^= 1
    expect_error(errno.EPROTO, lambda: client.unwrap(bytes(tampered)))
    client.close()
    server.close()


for c in BACKENDS:
    for s in BACKENDS:
        check(f"round {c}->{s}")(lambda c=c, s=s: full_round(c, s))

for b in BACKENDS:
    check(f"delegate {b}")(lambda b=b: full_round(b, b, delegate=True))


def _one_step(b: str) -> None:
    client = krb5.ClientContext("host", HOST, mutual=False, backend=b)
    token = client.step()
    assert client.complete
    server = krb5.AcceptorContext(backend=b)
    assert server.step(token) == b""
    assert server.complete
    assert server.unwrap(client.wrap(b"x")) == b"x"


def _principal_and_keytab(b: str) -> None:
    client = krb5.ClientContext("", "", principal=f"host/{HOST}@XGFAL.TEST", backend=b)
    server = krb5.AcceptorContext("host", HOST, keytab="/etc/krb5.keytab", backend=b)
    handshake(client, server)


def _explicit_ccache(b: str) -> None:
    """``ccache=``: a second cache holding the same user, the default one emptied."""
    path = f"FILE:/tmp/explicit-{b}"
    subprocess.run(
        ["kinit", "-c", path, "user"], input=b"userpw\n", check=True, stdout=subprocess.DEVNULL
    )
    saved = os.environ.get("KRB5CCNAME")
    os.environ["KRB5CCNAME"] = "FILE:/tmp/does-not-exist"
    try:
        client = krb5.ClientContext("host", HOST, ccache=path, backend=b)
        handshake(client, krb5.AcceptorContext(backend=b))
    finally:
        if saved is None:
            del os.environ["KRB5CCNAME"]
        else:
            os.environ["KRB5CCNAME"] = saved


def _no_ticket(b: str) -> str:
    saved = os.environ.get("KRB5CCNAME")
    os.environ["KRB5CCNAME"] = "FILE:/tmp/does-not-exist"
    try:
        return expect_error(
            errno.EACCES, lambda: krb5.ClientContext("host", HOST, backend=b).step(), "kinit"
        )
    finally:
        if saved is None:
            del os.environ["KRB5CCNAME"]
        else:
            os.environ["KRB5CCNAME"] = saved


def _unknown_service(b: str) -> str:
    return expect_error(
        errno.EACCES,
        lambda: krb5.ClientContext("nosuch", HOST, backend=b).step(),
        "service principal",
    )


def _wrong_key(b: str) -> str:
    """An acceptor whose keytab lacks the key: the client's token is refused."""
    client = krb5.ClientContext("host", HOST, backend=b)
    token = client.step()
    server = krb5.AcceptorContext(keytab="/tmp/empty.keytab", backend=b)
    try:
        server.step(token)
    except krb5.KerberosError as exc:
        assert exc.code == errno.EACCES, exc.code
        assert exc.token, "no KRB-ERROR token for the client"
        return exc.message + f" [error token: {len(exc.token)} bytes]"
    raise AssertionError("accepted without the key")


for b in BACKENDS:
    check(f"one step {b}")(lambda b=b: _one_step(b))
    check(f"principal+keytab {b}")(lambda b=b: _principal_and_keytab(b))
    check(f"explicit ccache {b}")(lambda b=b: _explicit_ccache(b))
    check(f"no ticket {b}")(lambda b=b: _no_ticket(b))
    check(f"unknown service {b}")(lambda b=b: _unknown_service(b))


def _make_other_keytab() -> None:
    env = dict(os.environ, KRB5CCNAME="MEMORY:setup")
    subprocess.run(
        ["kadmin.local", "-q", "addprinc -randkey other/elsewhere@XGFAL.TEST"],
        check=True,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["kadmin.local", "-q", "ktadd -k /tmp/empty.keytab other/elsewhere@XGFAL.TEST"],
        check=True,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


_make_other_keytab()
for b in BACKENDS:
    check(f"wrong key {b}")(lambda b=b: _wrong_key(b))


def _kdc_down(b: str) -> str:
    """A service ticket that is not cached yet, with the KDC gone: ETIMEDOUT."""
    return expect_error(
        errno.ETIMEDOUT,
        lambda: krb5.ClientContext("ftp", HOST, backend=b).step(),
    )


subprocess.run(
    ["kadmin.local", "-q", f"addprinc -randkey ftp/{HOST}@XGFAL.TEST"],
    check=True,
    env=dict(os.environ, KRB5CCNAME="MEMORY:setup"),
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
subprocess.run(["pkill", "krb5kdc"], check=False)
subprocess.run(["sh", "-c", "while pgrep krb5kdc >/dev/null; do sleep 0.1; done"], check=True)
for b in BACKENDS:
    check(f"kdc down {b}")(lambda b=b: _kdc_down(b))

results["_backend"] = krb5.backend()
results["_ccache"] = subprocess.run(["klist"], capture_output=True, text=True).stdout.splitlines()[
    0
]
results["_python"] = sys.version.split()[0]
print(json.dumps(results))
