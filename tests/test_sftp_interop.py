"""The sftp plugin against a real OpenSSH sshd, side by side with real gfal2.

The already-running ``xgfal-sftp-ref`` container (``gfal-ref:latest``:
AlmaLinux 9, OpenSSH 9.9, gfal2 2.23.5 with ``gfal2-plugin-sftp``, Python 3.9)
runs sshd with user ``alice`` (password ``secret``, an ed25519 and an RSA
key). Two more containers on the same docker network (``xgfal-sftp-net``) run
a driver that performs the same operations through ``gfal2`` (on the system
Python 3.9) and through ``xgfalclient`` (bind-mounted with the host's
``xrdclient``, on AppStream Python 3.11 in an image derived for it, see
:mod:`_interop_image`), for every transport tier, and report both.

Each answer is compared; the deliberate differences are in :data:`KNOWN`
(proper errno instead of the raw SFTP status gfal2 leaks, ``.``/``..`` left
out of listings, a real ``lstat``, a working checksum). The three
xgfalclient tiers - ``openssh`` (key/agent only), ``python`` and (if
importable) ``paramiko`` - are all exercised: openssh with key auth,
python/paramiko with password and key.

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
from typing import Any

import pytest

from _interop_image import GFAL2_PYTHON, XGFAL_PYTHON, library_mounts, xgfal_image, xrdclient_src

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
    "rename missing": "errno mapping differs (raw status vs ENOENT)",
    "checksum md5": "gfal2 answers EPROTONOSUPPORT; this plugin reads the file",
    "checksum adler32": "gfal2 answers EPROTONOSUPPORT; this plugin reads the file",
    "unlink dir": "gfal2 leaks the raw SFTP status (4); this plugin says EISDIR",
    "checksum missing": "gfal2 answers EPROTONOSUPPORT; this plugin reads (then ENOENT)",
    "readlink notlink": "errno mapping differs (raw status vs EINVAL)",
    "symlink": "errno/behaviour differs; this plugin performs a real symlink",
    "lstat link": "gfal2 aliases lstat to stat; this plugin does a real lstat",
}

#: One side per run: ``gfal2`` on the system python3 (keep to 3.9 syntax), or
#: ``xgfal``'s tiers on python3.11, so that each imports only what it can.
DRIVER = r"""
import json, os, sys
SIDE = sys.argv[1]
if SIDE == "xgfal":
    sys.path[:0] = ["/src/src", "/src/xrd"]
    import xgfalclient as lib
else:
    import gfal2 as lib
HOST = os.environ["IHOST"]

def run(fn):
    try:
        return ["ok", fn()]
    except lib.GError as exc:
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
        ("rmdir file", lambda: ctx.rmdir(base + "/hello.txt")),
        ("unlink dir", lambda: ctx.unlink(base + "/a")),
        ("checksum adler32", lambda: ctx.checksum(base + "/hello.txt", "ADLER32")),
        ("checksum bogus", lambda: ctx.checksum(base + "/hello.txt", "bogus")),
        ("stat upper", lambda: ctx.stat(base.replace("sftp://", "SFTP://") + "/hello.txt")),
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
        ("download", lambda: (
            copy(base + "/up.txt", "file://" + local + ".back") and open(local + ".back").read()
        )),
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
if SIDE != "xgfal":
    gctx = configure(lib.creat_context(), "password-py")
    gctx.set_opt_string("SFTP PLUGIN", "PASSWORD", "secret")
    url = "sftp://%s%s/real" % (HOST, home)
    print("XGFALJSON" + json.dumps({"gfal2": ops(lib, gctx, url, home)}))
    sys.exit(0)

tiers = ["openssh", "password-py", "key-py"]
try:
    import paramiko
    tiers += ["password-pmk", "key-pmk"]
    report["paramiko"] = True
except Exception:
    report["paramiko"] = False

for tier in tiers:
    ctx = configure_xgfal(lib.creat_context(), tier)
    sub = tier.replace("-", "_")
    d = "sftp://%s%s/%s" % (HOST, home, sub)
    report["tiers"][tier] = ops(lib, ctx, d, home)

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


def _run_side(side: str, keydir: Path) -> dict[str, Any]:
    """One side of the driver in a client container of its own: its report."""
    if side == "xgfal":
        # paramiko is the optional third tier; the derived image carries it.
        image, python = xgfal_image(IMAGE, ("paramiko>=3.4",)), XGFAL_PYTHON
    else:
        image, python = IMAGE, GFAL2_PYTHON
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
            # The package alone: src/ also holds the gfal2 shim, which
            # would shadow the real gfal2 and compare this package with itself.
            f"{ROOT / 'src' / 'xgfalclient'}:/src/src/xgfalclient:ro",
            "-v",
            f"{xrdclient_src()}:/src/xrd:ro",
            *library_mounts(),
            "-v",
            f"{keydir}:/keys:ro",
            image,
            python,
            "-c",
            DRIVER,
            side,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if "XGFALJSON" not in proc.stdout:
        raise AssertionError(
            f"{side} driver failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    report: dict[str, Any] = json.loads(proc.stdout.split("XGFALJSON", 1)[1])
    return report


def _drive(tmp_path: Path) -> dict[str, Any]:
    _run_setup_on_ref()
    keydir = _copy_key(tmp_path)
    return {**_run_side("gfal2", keydir), **_run_side("xgfal", keydir)}


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
