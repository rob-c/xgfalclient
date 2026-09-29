# ruff: noqa: E501 - the driver embedded below is a script, kept readable as one
"""The sftp plugin against a real OpenSSH sshd, side by side with real gfal2.

The already-running ``xgfal-sftp-ref`` container (``gfal-ref:latest``:
AlmaLinux 9, OpenSSH 9.9, gfal2 2.23.5 with ``gfal2-plugin-sftp``, Python 3.9)
runs sshd with user ``alice`` (password ``secret``, an ed25519 and an RSA
key). A second container on the same docker network (``xgfal-sftp-net``) runs
a driver that performs the same operations through ``gfal2`` and through
``xgfalclient`` (bind-mounted), for every transport tier, and reports both.

Each answer is compared; the deliberate differences are in :data:`KNOWN`
(proper errno instead of the raw SFTP status gfal2 leaks, ``.``/``..`` left
out of listings, a real ``lstat``, a working checksum, ``access`` via
``stat``). The three xgfalclient tiers - ``openssh`` (key/agent only),
``python`` and (if importable) ``paramiko`` - are all exercised: openssh with
key auth, python/paramiko with password and key.

Skipped unless ``XGFAL_INTEROP=1``. Run as a script for a report::

    XGFAL_INTEROP=1 python tests/test_sftp_interop.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.interop,
    pytest.mark.skipif(os.environ.get("XGFAL_INTEROP") != "1", reason="XGFAL_INTEROP=1 not set"),
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available"),
]

# A snapshot of xgfal-sftp-ref (gfal-ref plus gfal2-plugin-sftp, which the base
# image lacks); made with ``docker commit xgfal-sftp-ref gfal-sftp-ref:latest``.
IMAGE = "gfal-sftp-ref:latest"
NETWORK = "xgfal-sftp-net"
REF = "xgfal-sftp-ref"
HOST = "sftpref"  # resolvable on xgfal-sftp-net
ROOT = Path(__file__).resolve().parent.parent

#: Deliberate differences from gfal2's sftp plugin, and why.
KNOWN = {
    "listdir": "gfal2 includes '.' and '..'; this plugin omits them",
    "stat missing": "gfal2 leaks the raw SFTP status as errno; this plugin maps ENOENT",
    "mkdir exists": "gfal2 leaks the raw status; this plugin maps EEXIST",
    "rmdir missing": "errno mapping differs (raw status vs ENOENT)",
    "rmdir not empty": "errno mapping differs (raw status vs ENOTEMPTY)",
    "rename missing": "errno mapping differs (raw status vs ENOENT)",
    "chmod missing": "errno mapping differs (raw status vs ENOENT)",
    "unlink missing": "errno mapping differs (raw status vs ENOENT)",
    "open missing": "errno mapping differs (raw status vs ENOENT)",
    "checksum md5": "gfal2 answers EPROTONOSUPPORT; this plugin reads the file",
    "checksum missing": "gfal2 answers EPROTONOSUPPORT; this plugin reads (then ENOENT)",
    "access": "gfal2 answers EPROTONOSUPPORT; this plugin falls back to stat",
    "access missing": "gfal2 answers EPROTONOSUPPORT; this plugin falls back to stat (ENOENT)",
    "readlink notlink": "errno mapping differs (raw status vs EINVAL)",
    "symlink": "errno/behaviour differs; this plugin performs a real symlink",
    "lstat link": "gfal2 aliases lstat to stat; this plugin does a real lstat",
}

DRIVER = r"""
import importlib, json, os, sys
sys.path.insert(0, "/src/src")
import xgfalclient
real = importlib.import_module("gfal2")
HOST = os.environ["IHOST"]

def run(fn):
    try:
        return ["ok", fn()]
    except (real.GError, xgfalclient.GError) as exc:
        return ["err", exc.code]

def configure(ctx, tier):
    ctx.set_opt_string("SFTP PLUGIN", "USER", "alice")
    if tier in ("password-py", "password-pmk"):
        ctx.set_opt_string("SFTP PLUGIN", "PASSWORD", "secret")
        ctx.set_opt_string("SFTP PLUGIN", "PRIVKEY", "/nonexistent")
    else:
        ctx.set_opt_string("SFTP PLUGIN", "PRIVKEY", "/keys/id_ed25519")
    return ctx

def configure_xgfal(ctx, tier):
    configure(ctx, tier)
    ctx.set_opt_string("SFTP PLUGIN", "KNOWN_HOSTS", "/tmp/kh_" + tier)
    ctx.set_opt_string("SFTP PLUGIN", "STRICT_HOST_KEY_CHECKING", "accept-new")
    transport = {"openssh": "openssh", "password-py": "python", "key-py": "python",
                 "password-pmk": "paramiko", "key-pmk": "paramiko"}[tier]
    ctx.set_opt_string("SFTP PLUGIN", "TRANSPORT", transport)
    return ctx

def ops(mod, ctx, base, home):
    local = "/tmp/loc_" + base.rsplit("/", 1)[-1]
    with open(local + ".src", "w") as fh:
        fh.write("local sftp payload\n")
    def write():
        f = ctx.open(base + "/written.txt", "w"); f.write("some data\n"); f = None
        return ctx.stat(base + "/written.txt").st_size
    def copy(src, dst):
        p = ctx.transfer_parameters(); p.overwrite = True
        ctx.filecopy(p, src, dst); return True
    table = [
        ("stat file", lambda: [ctx.stat(base + "/hello.txt").st_size]),
        ("stat missing", lambda: ctx.stat(base + "/missing")),
        ("listdir", lambda: sorted(ctx.listdir(base))),
        ("mkdir", lambda: ctx.mkdir(base + "/newdir", 0o755)),
        ("mkdir exists", lambda: ctx.mkdir(base + "/newdir", 0o755)),
        ("rmdir", lambda: ctx.rmdir(base + "/newdir")),
        ("rmdir missing", lambda: ctx.rmdir(base + "/newdir")),
        ("mkdir_rec", lambda: ctx.mkdir_rec(base + "/a/b/c", 0o755)),
        ("rmdir not empty", lambda: ctx.rmdir(base + "/a")),
        ("unlink missing", lambda: ctx.unlink(base + "/missing")),
        ("chmod missing", lambda: ctx.chmod(base + "/missing", 0o600)),
        ("read", lambda: [ctx.open(base + "/hello.txt", "r").read(5)]),
        ("open missing", lambda: ctx.open(base + "/missing", "r").read(1)),
        ("write", write),
        ("unlink", lambda: ctx.unlink(base + "/written.txt")),
        ("checksum md5", lambda: ctx.checksum(base + "/hello.txt", "md5")),
        ("access", lambda: ctx.access(base + "/hello.txt", os.R_OK)),
        ("access missing", lambda: ctx.access(base + "/missing", os.F_OK)),
        ("upload", lambda: copy("file://" + local + ".src", base + "/up.txt")),
        ("download", lambda: copy(base + "/up.txt", "file://" + local + ".back") and open(local + ".back").read()),
        ("roundtrip size", lambda: [ctx.stat(base + "/up.txt").st_size]),
    ]
    out = {}
    for label, fn in table:
        res = run(fn)
        if res[0] == "err":
            pass
        out[label] = res
    return out

report = {"tiers": {}}
home = "/home/alice"
# gfal2 reference (its single sftp implementation), in its own subdirectory.
# No userinfo in the URL: both stacks take the user from the USER option.
gctx = configure(real.creat_context(), "password-py")
gctx.set_opt_string("SFTP PLUGIN", "PASSWORD", "secret")
report["gfal2"] = ops(real, gctx, "sftp://%s%s/real" % (HOST, home), home)

tiers = ["openssh", "password-py", "key-py"]
try:
    import paramiko  # noqa: F401
    tiers += ["password-pmk", "key-pmk"]
    report["paramiko"] = True
except Exception:
    report["paramiko"] = False

for tier in tiers:
    ctx = configure_xgfal(xgfalclient.creat_context(), tier)
    sub = tier.replace("-", "_")
    d = "sftp://%s%s/%s" % (HOST, home, sub)
    report["tiers"][tier] = ops(xgfalclient, ctx, d, home)

print("XGFALJSON" + json.dumps(report))
"""

SETUP = r"""
set -e
# Prepare per-tier working directories under alice's home on the server.
for d in real openssh password_py key_py password_pmk key_pmk; do
  install -d -o alice -g alice /home/alice/$d
  echo 'hello world' > /home/alice/$d/hello.txt
  chown alice:alice /home/alice/$d/hello.txt
done
"""


def _run_setup_on_ref() -> None:
    subprocess.run(["docker", "exec", REF, "bash", "-c", SETUP], check=True, capture_output=True)


def _copy_key(tmp: Path) -> Path:
    keydir = tmp / "keys"
    keydir.mkdir()
    subprocess.run(
        ["docker", "cp", f"{REF}:/home/alice/.ssh/id_ed25519", str(keydir / "id_ed25519")],
        check=True,
        capture_output=True,
    )
    (keydir / "id_ed25519").chmod(0o600)
    return keydir


def _drive(tmp_path: Path) -> dict:
    _run_setup_on_ref()
    keydir = _copy_key(tmp_path)
    proc = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            NETWORK,
            "-e",
            f"IHOST={HOST}",
            "-v",
            f"{ROOT}:/src:ro",
            "-v",
            f"{keydir}:/keys:ro",
            IMAGE,
            "python3",
            "-c",
            DRIVER,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if "XGFALJSON" not in proc.stdout:
        raise AssertionError(f"driver failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return json.loads(proc.stdout.split("XGFALJSON", 1)[1])


def test_sftp_interop(tmp_path: Path) -> None:
    report = _drive(tmp_path)
    gfal2 = report["gfal2"]
    assert report["tiers"], "no tiers ran"
    problems = []
    for tier, results in report["tiers"].items():
        for label, ours in results.items():
            theirs = gfal2.get(label)
            if theirs is None:
                continue
            if ours != theirs and label not in KNOWN:
                problems.append(f"{tier}/{label}: xgfal={ours} gfal2={theirs}")
    assert not problems, "unexpected differences from gfal2:\n" + "\n".join(problems)
    # Every tier must at least stat, read and copy successfully.
    for tier, results in report["tiers"].items():
        assert results["stat file"][0] == "ok", f"{tier} stat failed: {results['stat file']}"
        assert results["read"] == ["ok", ["hello"]], f"{tier} read: {results['read']}"
        assert results["upload"][0] == "ok", f"{tier} upload: {results['upload']}"
        assert results["download"][0] == "ok", f"{tier} download: {results['download']}"


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        rep = _drive(Path(tmp))
    print(json.dumps(rep, indent=2, sort_keys=True))
    sys.exit(0)
