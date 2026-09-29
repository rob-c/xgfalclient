# ruff: noqa: E501 - the driver embedded below is a script, kept readable as one
"""The gridftp plugin against a real globus-gridftp-server, side by side with real gfal2.

A throwaway container from ``gfal-ref:latest`` (AlmaLinux 9: globus-gridftp-server
13.28, gfal2 2.23.5 with its gridftp plugin, Python 3.9) serves ``gsiftp://``
with a host certificate from a fresh test PKI (port 2811) and anonymous
``ftp://`` (port 2812). A second container on the same docker network runs a
driver that performs the same operations through ``gfal2`` and through
``xgfalclient`` (bind-mounted) - each in its own directory of the same
export - and reports both. Every answer must match, errno and message,
except the differences in :data:`KNOWN`. Then ``xgfalclient`` alone runs what
gfal2 has no API for or does differently: ``MODE E`` with parallel streams,
``DCAU A``, ``PROT P``, third-party copies in every combination.

Running the driver in a container (not from the host) matters: ``MODE E``
downloads have the server connect back to the client, and passive
addresses are the container's own.

Skipped unless ``XGFAL_INTEROP=1``. Run as a script for a report::

    python tests/test_gridftp_interop.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = [
    pytest.mark.interop,
    pytest.mark.skipif(os.environ.get("XGFAL_INTEROP") != "1", reason="XGFAL_INTEROP=1 not set"),
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available"),
]

IMAGE = "gfal-ref:latest"
ROOT = Path(__file__).resolve().parent.parent
HOST = "gridftp.xgfal.test"

#: Differences from gfal2 that are deliberate, and why.
KNOWN = {
    # gfal2 streams file:// <-> gsiftp:// copies through its core
    # (GFAL2:CORE:COPY:LOCAL); this plugin moves them itself, domain GSIFTP.
    "upload events": "the copy is the plugin's own, so its events carry the GSIFTP domain",
    "download events": "the copy is the plugin's own, so its events carry the GSIFTP domain",
}

SETUP = r"""
set -e
mkdir -p /etc/grid-security/certificates
cp /pki/certificates/* /etc/grid-security/certificates/
cp /pki/hostcert.pem /etc/grid-security/hostcert.pem
cp /pki/hostkey.pem /etc/grid-security/hostkey.pem
chmod 600 /etc/grid-security/hostkey.pem
useradd -m griduser 2>/dev/null || true
echo '"/DC=org/DC=xgfal/OU=People/CN=Test User" griduser' > /etc/grid-security/grid-mapfile
for d in real ours extra; do
  mkdir -p /data/$d
  echo 'hello world' > /data/$d/hello.txt
done
head -c 12345678 /dev/urandom > /data/extra/big.bin
chown -R griduser /data
export GLOBUS_TCP_PORT_RANGE=50000,60000
ip=$(hostname -i)
globus-gridftp-server -p 2811 -data-interface $ip -l /tmp/gsi.log &
globus-gridftp-server -p 2812 -aa -anonymous-user griduser -data-interface $ip -l /tmp/anon.log &
wait
"""

DRIVER = r"""
import importlib, json, os, sys, time, zlib
sys.path.insert(0, "/src/src")
import xgfalclient
real = importlib.import_module("gfal2")
HOST = sys.argv[1]

def run(fn):
    try:
        return ["ok", fn()]
    except (real.GError, xgfalclient.GError) as exc:
        return ["err", exc.code, exc.message]

def stat_tuple(s):
    return [s.st_mode, s.st_size, s.st_uid, s.st_gid, s.st_nlink, s.st_mtime, s.st_atime, s.st_ctime, s.st_ino]

def ops(g, ctx, scheme, port, name):
    base = f"{scheme}://{HOST}:{port}/data/{name}"
    def readpp():
        d = ctx.opendir(base)
        out = []
        while True:
            e, s = d.readpp()
            if e is None:
                return sorted(out)
            out.append([e.d_name, e.d_type, s.st_mode, s.st_size])
    def write():
        f = ctx.open(base + "/written.txt", "w")
        f.write("some data\n")
        f = None
        return ctx.stat(base + "/written.txt").st_size
    def copy(src, dst):
        events = []
        p = ctx.transfer_parameters()
        p.overwrite = True
        p.event_callback = lambda e: events.append([e.domain, e.stage])
        ctx.filecopy(p, src, dst)
        return [e for e in events if e[1] in ("TRANSFER:TYPE",)]
    local = f"/tmp/{name}-{scheme}"
    with open(local + ".src", "w") as fh:
        fh.write("local file\n")
    table = [
        ("stat file", lambda: stat_tuple(ctx.stat(base + "/hello.txt"))),
        ("stat dir", lambda: stat_tuple(ctx.stat(base))[:2]),
        ("stat missing", lambda: ctx.stat(base + "/missing")),
        ("listdir", lambda: sorted(ctx.listdir(base))),
        ("readpp", readpp),
        ("mkdir", lambda: ctx.mkdir(base + "/newdir", 0o755)),
        ("mkdir exists", lambda: ctx.mkdir(base + "/newdir", 0o755)),
        ("rmdir", lambda: ctx.rmdir(base + "/newdir")),
        ("rmdir missing", lambda: ctx.rmdir(base + "/newdir")),
        ("mkdir_rec", lambda: ctx.mkdir_rec(base + "/a/b/c", 0o755)),
        ("rmdir not empty", lambda: ctx.rmdir(base + "/a")),
        ("unlink missing", lambda: ctx.unlink(base + "/missing")),
        ("rename", lambda: (ctx.rename(base + "/hello.txt", base + "/hello2.txt"), ctx.rename(base + "/hello2.txt", base + "/hello.txt"))),
        ("rename missing", lambda: ctx.rename(base + "/missing", base + "/other")),
        ("chmod", lambda: (ctx.chmod(base + "/hello.txt", 0o600), oct(ctx.stat(base + "/hello.txt").st_mode), ctx.chmod(base + "/hello.txt", 0o644))[1]),
        ("chmod missing", lambda: ctx.chmod(base + "/missing", 0o600)),
        ("checksum adler32", lambda: ctx.checksum(base + "/hello.txt", "ADLER32")),
        ("checksum md5", lambda: ctx.checksum(base + "/hello.txt", "MD5")),
        ("checksum partial", lambda: ctx.checksum(base + "/hello.txt", "md5", 1, 4)),
        ("checksum bad", lambda: ctx.checksum(base + "/hello.txt", "FOO")),
        ("checksum missing", lambda: ctx.checksum(base + "/missing", "ADLER32")),
        ("access", lambda: ctx.access(base + "/hello.txt", os.R_OK)),
        ("access missing", lambda: ctx.access(base + "/missing", os.F_OK)),
        ("read", lambda: [ctx.open(base + "/hello.txt", "r").read(5)]),
        ("pread", lambda: ctx.open(base + "/hello.txt", "r").pread(3, 4)),
        ("open missing", lambda: ctx.open(base + "/missing", "r").read(1)),
        ("write", write),
        ("unlink", lambda: ctx.unlink(base + "/written.txt")),
        ("listxattr", lambda: ctx.listxattr(base + "/hello.txt")),
        ("getxattr bad", lambda: ctx.getxattr(base + "/hello.txt", "user.status")),
        ("upload", lambda: copy("file://" + local + ".src", base + "/up.txt") and None),
        ("upload events", lambda: copy("file://" + local + ".src", base + "/up.txt")),
        ("download", lambda: copy(base + "/up.txt", "file://" + local + ".back") and open(local + ".back").read()),
        ("download events", lambda: copy(base + "/up.txt", "file://" + local + ".back")),
        ("third party", lambda: copy(base + "/up.txt", base + "/tpc.txt")),
        ("third party missing", lambda: copy(base + "/missing", base + "/tpc2.txt")),
        ("third party result", lambda: ctx.checksum(base + "/tpc.txt", "ADLER32")),
    ]
    out = {}
    for label, fn in table:
        result = run(fn)
        if result[0] == "err":
            result[2] = result[2].replace(f"/data/{name}", "/data/X").replace(f"/tmp/{name}-", "/tmp/X-").replace(base, "URL")
        out[label] = result
    return out

report = {}
for scheme, port in (("gsiftp", 2811), ("ftp", 2812)):
    report[scheme] = {
        "gfal2": ops(real, real.creat_context(), scheme, port, "real"),
        "xgfal": ops(xgfalclient, xgfalclient.creat_context(), scheme, port, "ours"),
    }

# xgfalclient alone: parallel streams, data-channel security, big third-party copies.
def adler(path):
    value = 1
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            value = zlib.adler32(chunk, value)
    return f"{value:08x}"

extra = {}
with open("/tmp/big.src", "wb") as fh:
    fh.write(os.urandom(50 << 20))
want = adler("/tmp/big.src")
for scheme, port in (("gsiftp", 2811), ("ftp", 2812)):
    for option in ("", "DCAU", "ENCRYPTION"):
        if scheme == "ftp" and option:
            continue
        for streams in (0, 4):
            ctx = xgfalclient.creat_context()
            if option:
                ctx.set_opt_boolean("GRIDFTP PLUGIN", option, True)
            base = f"{scheme}://{HOST}:{port}/data/extra"
            p = ctx.transfer_parameters()
            p.overwrite = True
            p.nbstreams = streams
            label = f"{scheme} {option or 'plain'} x{streams}"
            def flow():
                t = time.time()
                ctx.filecopy(p, "file:///tmp/big.src", base + "/big-up.bin")
                up = time.time() - t
                t = time.time()
                ctx.filecopy(p, base + "/big-up.bin", "file:///tmp/big.back")
                down = time.time() - t
                ctx.filecopy(p, base + "/big-up.bin", base + "/big-tpc.bin")
                return {
                    "up MiB/s": round(50 / up, 1),
                    "down MiB/s": round(50 / down, 1),
                    "same": adler("/tmp/big.back") == want == ctx.checksum(base + "/big-tpc.bin", "ADLER32"),
                }
            extra[label] = run(flow)
            ctx.free()
report["extra"] = extra
print("REPORT" + json.dumps(report))
"""

SIGNING_POLICY = """access_id_CA      X509         '/DC=org/DC=xgfal/CN=xgfal Test CA'
pos_rights        globus        CA:sign
cond_subjects     globus       '"/DC=org/DC=xgfal/*"'
"""


def _docker(
    *args: str, check: bool = True, timeout: float = 600
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=timeout
    )


def collect() -> dict[str, Any]:
    """Boot the server and driver containers, run the driver, return its report."""
    sys.path.insert(0, str(ROOT / "src"))
    from xgfalclient.testing.pki import create_pki, subject_hash

    tag = f"{os.getpid()}"
    network = f"xgfal-gridftp-net-{tag}"
    server = f"xgfal-gridftp-srv-{tag}"
    driver = f"xgfal-gridftp-cli-{tag}"
    work = Path(tempfile.mkdtemp(prefix="xgfal-gridftp-interop-"))
    try:
        pki = create_pki(work / "pki", hosts=(HOST, "localhost"), host_cn=f"host/{HOST}")
        name = subject_hash(pki.ca.subject.encoded())
        (pki.ca_dir / f"{name}.signing_policy").write_text(SIGNING_POLICY)
        (work / "setup.sh").write_text(SETUP)
        (work / "driver.py").write_text(DRIVER)
        os.chmod(work, 0o755)
        _docker("network", "create", network)
        _docker(
            "run", "-d", "--name", server, "--hostname", HOST, "--network", network,
            "--network-alias", HOST, "-v", f"{work / 'pki'}:/pki:ro",
            "-v", f"{work}:/work:ro", IMAGE, "bash", "/work/setup.sh",
        )  # fmt: skip
        _docker(
            "run", "-d", "--name", driver, "--network", network,
            # The package alone: src/ also holds the gfal2 shim, which would
            # shadow the real gfal2 and compare this package with itself.
            "-v", f"{work}:/work:ro",
            "-v", f"{ROOT / 'src' / 'xgfalclient'}:/src/src/xgfalclient:ro",
            "-e", "X509_USER_PROXY=/tmp/x509up", "-e", "X509_CERT_DIR=/work/pki/certificates",
            IMAGE, "sleep", "infinity",
        )  # fmt: skip
        _docker(
            "exec",
            driver,
            "bash",
            "-c",
            "cp /work/pki/x509up_rfc /tmp/x509up && chmod 600 /tmp/x509up",
        )
        for _ in range(60):
            probe = _docker(
                "exec",
                server,
                "bash",
                "-c",
                "grep -c 'Server started' /tmp/gsi.log /tmp/anon.log",
                check=False,
            )
            if probe.stdout.count(":1") == 2:
                break
            subprocess.run(["sleep", "0.5"], check=True)
        done = _docker("exec", driver, "python3", "/work/driver.py", HOST, timeout=900)
        line = next(x for x in done.stdout.splitlines() if x.startswith("REPORT"))
        return json.loads(line[len("REPORT") :])  # type: ignore[no-any-return]
    finally:
        _docker("rm", "-f", server, driver, check=False)
        _docker("network", "rm", network, check=False)
        shutil.rmtree(work, ignore_errors=True)


@pytest.fixture(scope="module")
def report() -> Iterator[dict[str, Any]]:
    yield collect()


OPERATIONS = [
    "stat file", "stat dir", "stat missing", "listdir", "readpp", "mkdir", "mkdir exists",
    "rmdir", "rmdir missing", "mkdir_rec", "rmdir not empty", "unlink missing", "rename",
    "rename missing", "chmod", "chmod missing", "checksum adler32", "checksum md5",
    "checksum partial", "checksum bad", "checksum missing", "access", "access missing",
    "read", "pread", "open missing", "write", "unlink", "listxattr", "getxattr bad",
    "upload", "upload events", "download", "download events", "third party",
    "third party missing", "third party result",
]  # fmt: skip


@pytest.mark.parametrize("scheme", ["gsiftp", "ftp"])
@pytest.mark.parametrize("operation", OPERATIONS)
def test_same_as_gfal2(report: dict[str, Any], scheme: str, operation: str) -> None:
    theirs = report[scheme]["gfal2"][operation]
    ours = report[scheme]["xgfal"][operation]
    if operation in KNOWN:
        assert ours[0] == theirs[0] == "ok", (theirs, ours)
    else:
        assert ours == theirs


@pytest.mark.parametrize(
    "label",
    [
        "gsiftp plain x0", "gsiftp plain x4", "gsiftp DCAU x0", "gsiftp DCAU x4",
        "gsiftp ENCRYPTION x0", "gsiftp ENCRYPTION x4", "ftp plain x0", "ftp plain x4",
    ],
)  # fmt: skip
def test_xgfal_only_flows(report: dict[str, Any], label: str) -> None:
    result = report["extra"][label]
    assert result[0] == "ok", result
    assert result[1]["same"], result


if __name__ == "__main__":  # pragma: no cover - a manual report
    found = collect()
    for scheme in ("gsiftp", "ftp"):
        for operation in OPERATIONS:
            theirs = found[scheme]["gfal2"][operation]
            ours = found[scheme]["xgfal"][operation]
            mark = "same" if ours == theirs else ("KNOWN" if operation in KNOWN else "DIFF")
            print(f"{mark:5} {scheme:6} {operation:22} gfal2={theirs} xgfal={ours}")
    for label, result in found["extra"].items():
        print(f"xgfal {label:24} {result}")
