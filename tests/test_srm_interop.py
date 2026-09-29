"""The ``srm://`` plugin side by side with real gfal2, and against a real dCache.

**gfal2 parity.** A throwaway ``gfal-ref:latest`` container (gfal2 2.23.5,
srm-ifce 1.24.8, CGSI-gSOAP, Python 3.9) runs :mod:`xgfalclient.testing.srm`
and a driver that performs the same operations through ``gfal2`` and
through ``xgfalclient`` (bind-mounted), recording each answer and every
SOAP request body the server received. Answers and request bodies must be
identical except where :data:`KNOWN` says why not.

**dCache.** With ``XGFAL_SRM_URL`` (e.g. ``srm://xgfal-srm-dcache:8443/data``)
plus ``XGFAL_SRM_PROXY`` and ``XGFAL_SRM_CERTDIR``, the plugin is exercised
against that SRM door directly.

Skipped unless ``XGFAL_INTEROP=1``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

import xgfalclient

pytestmark = [
    pytest.mark.interop,
    pytest.mark.skipif(os.environ.get("XGFAL_INTEROP") != "1", reason="XGFAL_INTEROP=1 not set"),
]

IMAGE = "gfal-ref:latest"
ROOT = Path(__file__).resolve().parent.parent

#: Differences from gfal2 that are deliberate, and why.
KNOWN = {
    "stat": "srm-ifce invents uid/gid from a counter of user names; 0 is reported",
    "chmod-wire": "gfal2 sends TPermissionMode ordinals, which the WSDL forbids; names are sent",
    "release-notoken": "gfal2 returns 22 instead of raising; EINVAL is raised",
    "release-list": "srm-ifce prints the request status for a file's failure; the file's is used",
    "archive-list": "the core words a not-yet-archived file generically",
    "cks-md5": "gfal2's gridftp plugin wording differs from this package's",
}

DRIVER = r"""
import json, os, sys, pathlib, shutil, errno
sys.path.insert(0, "/xgfal/src")
from xgfalclient.testing.pki import create_pki, subject_hash
from xgfalclient.testing.srm import SRMServer, Space
impl = sys.argv[1]
if impl == "x":
    import xgfalclient as gfal2
else:
    import gfal2
d = pathlib.Path("/tmp/run-" + impl); shutil.rmtree(d, ignore_errors=True)
pki = create_pki(d / "pki")
h = subject_hash(pki.ca.subject.encoded())
(pki.ca_dir / f"{h}.signing_policy").write_text(
    "access_id_CA X509 '/DC=org/DC=xgfal/CN=xgfal Test CA'\npos_rights globus CA:sign\n"
    "cond_subjects globus '\"/DC=org/DC=xgfal/*\"'\n")
os.environ.update(pki.environment())
root = d / "root"; (root / "data" / "sub").mkdir(parents=True)
(root / "data" / "f").write_bytes(b"hello world\n"); (root / "data" / "sub" / "a").write_bytes(b"a")
srm = SRMServer(pki.server_context(), root, queue_polls=1).start()
srm.spaces["tok1"] = Space("ATLASDATADISK")
u = srm.url("")
ctx = gfal2.creat_context()
ctx.set_opt_boolean("BDII", "ENABLED", False)
ctx.set_opt_string_list("SRM PLUGIN", "TURL_PROTOCOLS", ["file"])
ctx.set_opt_string_list("SRM PLUGIN", "TURL_3RD_PARTY_PROTOCOLS", ["file"])
out = {}
def run(name, fn):
    try:
        value = fn()
        if isinstance(value, list):
            value = [[e.code, e.message] if isinstance(e, gfal2.GError) else e for e in value]
        out[name] = ["ok", repr(value)]
    except gfal2.GError as e:
        out[name] = ["error", e.code, e.message]
run("stat", lambda: str(ctx.stat(u + "/data/f")).split("mode")[1].split("ctime")[0])
run("stat-missing", lambda: ctx.stat(u + "/nope"))
run("listdir", lambda: ctx.listdir(u + "/data"))
run("listdir-file", lambda: ctx.listdir(u + "/data/f"))
run("mkdir-exists", lambda: ctx.mkdir(u + "/data", 0o755))
run("mkdir-parents", lambda: ctx.mkdir(u + "/data/x/y", 0o755))
run("rmdir-nonempty", lambda: ctx.rmdir(u + "/data/sub"))
run("rmdir-file", lambda: ctx.rmdir(u + "/data/f"))
run("unlink-missing", lambda: ctx.unlink(u + "/nope"))
run("rename-missing", lambda: ctx.rename(u + "/nope", u + "/data/z"))
run("access-x", lambda: ctx.access(u + "/data/f", os.X_OK))
run("cks", lambda: ctx.checksum(u + "/data/f", "adler32"))
run("xattr-status", lambda: ctx.getxattr(u + "/data/f", "user.status"))
run("xattr-type", lambda: ctx.getxattr(u + "/data/f", "srm.type"))
run("xattr-spacetoken", lambda: ctx.getxattr(u + "/data/f", "spacetoken"))
run("xattr-unknown", lambda: ctx.getxattr(u + "/data/f", "user.foo"))
run("read", lambda: ctx.open(u + "/data/f", "r").read(100))
run("read-missing", lambda: ctx.open(u + "/nope", "r"))
run("write-exists", lambda: ctx.open(u + "/data/f", "w"))
srm.set_locality("/data/f", "NEARLINE")
run("bol-sync", lambda: ctx.bring_online(u + "/data/f", 10, 60, False)[0])
run("bol-lost-list", lambda: (srm.set_locality("/data/f", "LOST"),
    ctx.bring_online([u + "/data/f"], 10, 60, True)[0])[1])
srm.set_locality("/data/sub/a", "ONLINE_AND_NEARLINE")  # a path gfal2 has not cached
run("archive", lambda: ctx.archive_poll(u + "/data/sub/a"))
srm.set_locality("/data/f", "ONLINE")
run("copy", lambda: ctx.filecopy(u + "/data/f", u + "/data/c"))
run("copy-missing", lambda: ctx.filecopy(u + "/nope", u + "/data/c2"))
wire = sorted({body.decode() for op, body in srm.log if op not in ("srmPing",)})
out["wire"] = [w.split("<SOAP-ENV:Body")[1] for w in wire]
print(json.dumps(out))
srm.stop()
os._exit(0)
"""


def _docker(*args: str, check: bool = True) -> str:
    done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=600)
    if check and done.returncode:
        raise AssertionError(done.stderr)
    return done.stdout


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available")
def test_parity_with_gfal2() -> None:
    name = f"xgfal-srm-interop-{uuid.uuid4().hex[:8]}"
    _docker(
        # The package alone: src/ also holds the gfal2 shim, which would
        # shadow the real gfal2 and compare this package with itself.
        "run", "-d", "--name", name,
        "-v", f"{ROOT / 'src' / 'xgfalclient'}:/xgfal/src/xgfalclient:ro",
        "--entrypoint", "sleep", IMAGE, "infinity",
    )  # fmt: skip
    try:
        results = {}
        for impl in ("g", "x"):
            text = _docker("exec", name, "python3", "-c", DRIVER, impl)
            line = text.strip().splitlines()[-1]
            line = re.sub(r"localhost:\d+", "localhost:PORT", line)
            results[impl] = json.loads(re.sub(r"xgfal-\d+", "TOKEN", line))
    finally:
        _docker("rm", "-f", name, check=False)
    theirs, ours = results["g"], results["x"]
    for key, expected in theirs.items():
        if key == "wire":
            continue
        if key in KNOWN:
            continue
        assert ours[key] == expected, (key, ours[key], expected)
    # Every request gfal2 made, this makes byte for byte; beyond them, only the
    # core's own srmLs of a copy's destination (its overwrite check) and srmRm
    # of a failed copy's destination (its clean-up).
    missing = set(theirs["wire"]) - set(ours["wire"])
    assert not missing, missing
    extra = set(ours["wire"]) - set(theirs["wire"])
    assert all("<srm2:srmLs>" in body or "<srm2:srmRm>" in body for body in extra), extra


@pytest.fixture
def dcache(monkeypatch: pytest.MonkeyPatch) -> str:
    url = os.environ.get("XGFAL_SRM_URL")
    if not url:
        pytest.skip("XGFAL_SRM_URL not set")
    monkeypatch.setenv("X509_USER_PROXY", os.environ["XGFAL_SRM_PROXY"])
    monkeypatch.setenv("X509_CERT_DIR", os.environ["XGFAL_SRM_CERTDIR"])
    return url.rstrip("/")


def test_dcache(dcache: str, tmp_path: Path) -> None:
    ctx = xgfalclient.creat_context()
    ctx.set_opt_string_list("SRM PLUGIN", "TURL_3RD_PARTY_PROTOCOLS", ["https"])
    ctx.set_opt_string_list("SRM PLUGIN", "TURL_PROTOCOLS", ["https"])
    base = f"{dcache}/xgfal-{uuid.uuid4().hex[:8]}"
    ctx.mkdir_rec(base + "/sub", 0o755)
    assert ctx.stat(base).is_dir()
    local = tmp_path / "f"
    local.write_bytes(b"hello dcache\n" * 1000)
    ctx.filecopy(f"file://{local}", base + "/f")
    assert ctx.stat(base + "/f").st_size == 13000
    assert sorted(ctx.listdir(base)) == ["f", "sub"]
    assert ctx.checksum(base + "/f", "adler32")
    ctx.rename(base + "/f", base + "/g")
    back = tmp_path / "back"
    ctx.filecopy(base + "/g", f"file://{back}")
    assert back.read_bytes() == local.read_bytes()
    with ctx.open(base + "/g", "r") as handle:
        assert handle.read(5) == "hello"
    assert ctx.getxattr(base + "/g", "user.status") in ("ONLINE", "ONLINE_AND_NEARLINE")
    assert ctx.getxattr(base + "/g", "srm.type") == "dCache"
    ctx.unlink(base + "/g")
    ctx.rmdir(base + "/sub")
    ctx.rmdir(base)
