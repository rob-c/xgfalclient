# ruff: noqa: E501
"""A 256 MiB upload/download benchmark for the sftp plugin, inside the Docker VM.

Run from the host; it launches a client container on ``xgfal-sftp-net`` (the
``gfal-sftp-ref`` snapshot, which carries ``gfal2-plugin-sftp``) that transfers
a 256 MiB file to and from the sshd in ``xgfal-sftp-ref`` through each
xgfalclient transport tier and through real gfal2, and prints MB/s.

    python tests/bench_sftp.py

Local timings on the Mac are meaningless (the box is loaded and Docker
Desktop's port-forward throttles); this runs entirely inside the VM.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

IMAGE = "gfal-sftp-ref:latest"
NETWORK = "xgfal-sftp-net"
REF = "xgfal-sftp-ref"
HOST = "sftpref"
ROOT = Path(__file__).resolve().parent.parent
SIZE = 256 * 1024 * 1024

DRIVER = r"""
import importlib, json, os, sys, time
sys.path.insert(0, "/src/src")
import xgfalclient
real = importlib.import_module("gfal2")
HOST = os.environ["IHOST"]
SIZE = int(os.environ["SIZE"])
home = "/home/alice"

src = "/tmp/src.bin"
with open(src, "wb") as fh:
    fh.write(os.urandom(1 << 20))
    fh.truncate(SIZE)

def timed(fn):
    best = None
    for _ in range(2):
        t = time.monotonic()
        fn()
        dt = time.monotonic() - t
        best = dt if best is None else min(best, dt)
    return SIZE / best / 1e6  # MB/s

def bench(mod, ctx, base, tier):
    up = base + "/bench_up_%s.bin" % tier
    down = "/tmp/down_%s.bin" % tier
    p = ctx.transfer_parameters(); p.overwrite = True
    def upload():
        ctx.filecopy(p, "file://" + src, up)
    def download():
        ctx.filecopy(p, up, "file://" + down)
    ctx.filecopy(p, "file://" + src, up)  # warm
    return {"upload_MBps": round(timed(upload), 1), "download_MBps": round(timed(download), 1)}

def cfg(ctx, tier, passwd):
    ctx.set_opt_string("SFTP PLUGIN", "USER", "alice")
    if passwd:
        ctx.set_opt_string("SFTP PLUGIN", "PASSWORD", "secret")
        ctx.set_opt_string("SFTP PLUGIN", "PRIVKEY", "/nonexistent")
    else:
        ctx.set_opt_string("SFTP PLUGIN", "PRIVKEY", "/keys/id_ed25519")
    return ctx

report = {}
gctx = cfg(real.creat_context(), "gfal2", True)
report["gfal2 (libssh2)"] = bench(real, gctx, "sftp://%s%s/real" % (HOST, home), "gfal2")

for tier, transport, passwd in [
    ("openssh", "openssh", False),
    ("python", "python", True),
]:
    ctx = cfg(xgfalclient.creat_context(), tier, passwd)
    ctx.set_opt_string("SFTP PLUGIN", "KNOWN_HOSTS", "/tmp/kh_" + tier)
    ctx.set_opt_string("SFTP PLUGIN", "STRICT_HOST_KEY_CHECKING", "accept-new")
    ctx.set_opt_string("SFTP PLUGIN", "TRANSPORT", transport)
    label = "xgfal %s (%s)" % (tier, xgfalclient.__name__)
    from xgfalclient.crypto import ciphers
    report["xgfal " + tier + " [" + ciphers.get().name + "]"] = bench(xgfalclient, ctx, "sftp://%s%s/%s" % (HOST, home, tier), tier)

print("BENCHJSON" + json.dumps(report))
"""


def main() -> int:
    if shutil.which("docker") is None:
        print("docker not available")
        return 1
    subprocess.run(
        [
            "docker",
            "exec",
            REF,
            "bash",
            "-c",
            "install -d -o alice -g alice /home/alice/real /home/alice/openssh /home/alice/python",
        ],
        check=True,
        capture_output=True,
    )
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            ["docker", "cp", f"{REF}:/home/alice/.ssh/id_ed25519", f"{tmp}/id_ed25519"],
            check=True,
            capture_output=True,
        )
        Path(f"{tmp}/id_ed25519").chmod(0o600)
        proc = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                NETWORK,
                "-e",
                f"IHOST={HOST}",
                "-e",
                f"SIZE={SIZE}",
                "-v",
                f"{ROOT}:/src:ro",
                "-v",
                f"{tmp}:/keys:ro",
                IMAGE,
                "python3",
                "-c",
                DRIVER,
            ],
            capture_output=True,
            text=True,
            timeout=1200,
        )
    if "BENCHJSON" not in proc.stdout:
        print("STDOUT:\n" + proc.stdout)
        print("STDERR:\n" + proc.stderr)
        return 1
    report = json.loads(proc.stdout.split("BENCHJSON", 1)[1])
    print(f"\n256 MiB transfers to/from {HOST} (inside the Docker VM):\n")
    print(f"{'stack':<34} {'upload MB/s':>12} {'download MB/s':>14}")
    for label, r in report.items():
        print(f"{label:<34} {r['upload_MBps']:>12} {r['download_MBps']:>14}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
