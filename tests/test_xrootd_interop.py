"""The ``root://`` plugin against a real ``xrootd``, side by side with real gfal2.

A throwaway container from ``gfal-ref:latest`` (AlmaLinux 9: xrootd 5.9.7,
gfal2 2.23.5 with its xrootd plugin, Python 3.9) runs an ``xrootd`` and, next
to it, a driver that performs the same operations through ``gfal2`` and
through ``xgfalclient`` - bind-mounted, with ``xrdclient`` - and reports both.
Every answer must be identical except the few in :data:`KNOWN`, where gfal2
is wrong on purpose-free grounds and this package deliberately is not.

A second container serves GSI only, with a host certificate from the test
PKI, to show that a proxy found the way gfal2 finds one authenticates.

Skipped unless ``XGFAL_INTEROP=1``. Run as a script for a report::

    python tests/test_xrootd_interop.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
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

#: Differences from gfal2 that are deliberate, and why.
KNOWN = {
    # gfal2_xrootd_set_error reports the stale global errno, not the code it
    # was handed: EILSEQ, EINPROGRESS... where the message says otherwise.
    "chmod missing": "gfal2 reports a stale errno (EILSEQ); the message's ENOENT is used",
    "listdir file": "gfal2 reports a stale errno; ENOTDIR is used",
    "cks partial": "gfal2 reports a stale errno; ENOTSUP is used",
    "setxattr": "gfal2 reports a stale errno; ENOSYS is used",
    # readdirpp: gfal2 sets no file-type bit, yet reports DT_REG.
    "readpp": "an entry's mode keeps S_IFREG so that its d_type is DT_REG",
}

SERVER_CONFIG = """\
all.export /
oss.localroot /data
xrootd.chksum max 4 adler32 md5 crc32c crc32
all.role server
ofs.tpc pgm /usr/bin/xrdcp --server
xrd.port 1094
"""

GSI_CONFIG = """\
all.export /
oss.localroot /data
all.role server
xrd.port 1095
xrootd.seclib libXrdSec.so
sec.protocol gsi -certdir:/pki/certificates -cert:/pki/hostcert.pem -key:/pki/hostkey.pem \
 -gridmap:/dev/null -gmapopt:10 -dlgpxy:0
sec.protbind * only gsi
"""

START = """\
set -e
mkdir -p /data /etc/xrd
useradd -m xrd 2>/dev/null || true
chown xrd /data
cat > /etc/xrd/x.cfg <<'EOF'
{config}EOF
su xrd -s /bin/bash -c "xrootd -b -l /tmp/xrd.log -c /etc/xrd/x.cfg"
"""

#: Runs inside the container: each case through gfal2 and through xgfalclient.
DRIVER = r"""
import errno, hashlib, json, os, sys
sys.path[:0] = ["/src/xgfalclient/src", "/src/xrdclient/src"]
import gfal2
import xgfalclient

B = "root://localhost:1094/"
B2 = "root://127.0.0.1:1094/"
open("/tmp/src.bin", "wb").write(os.urandom(3 * 1024 * 1024 + 5))


def run(mod, tag):
    ctx = mod.creat_context()
    out = {}
    R, R2 = B + "/" + tag, B2 + "/" + tag

    def t(label, fn, *a):
        try:
            r = fn(*a)
            r = str(r) if type(r).__name__ == "Stat" else r
            out[label] = ["ok", repr(r).replace(tag, "T")]
        except mod.GError as e:
            out[label] = ["err", e.code, e.message.replace(tag, "T")]

    def mode(url):
        info = ctx.stat(url)
        return (info.st_size, oct(info.st_mode), info.st_nlink, info.st_uid)

    t("mkdir", ctx.mkdir, R, 0o755)
    t("mkdir exist", ctx.mkdir, R, 0o755)
    t("mkdir_rec", ctx.mkdir_rec, R + "/a/b", 0o755)
    t("mkdir_rec exist", ctx.mkdir_rec, R + "/a/b", 0o755)
    f = ctx.open(R + "/f.txt", "w"); f.write("hello world\n"); del f
    t("stat file", mode, R + "/f.txt")
    t("stat dir", mode, R)
    t("stat unnormalised", mode, "root://localhost:1094/" + tag + "/f.txt")
    t("stat missing", ctx.stat, R + "/nofile")
    t("lstat", lambda: oct(ctx.lstat(R + "/f.txt").st_mode))
    t("access F", ctx.access, R + "/f.txt", os.F_OK)
    t("access RW", ctx.access, R + "/f.txt", os.R_OK | os.W_OK)
    t("access X", ctx.access, R + "/f.txt", os.X_OK)
    t("access missing", ctx.access, R + "/nofile", os.F_OK)
    t("chmod 644", ctx.chmod, R + "/f.txt", 0o644)
    t("stat after chmod", mode, R + "/f.txt")
    t("chmod missing", ctx.chmod, R + "/nofile", 0o600)
    t("listdir", lambda: sorted(ctx.listdir(R)))
    t("listdir missing", ctx.listdir, R + "/nodir")
    t("listdir file", ctx.listdir, R + "/f.txt")

    def readpp():
        d = ctx.opendir(R)
        seen = []
        while True:
            e, s = d.readpp()
            if e is None:
                return sorted(seen)
            seen.append((e.d_name, e.d_type, oct(s.st_mode), s.st_size))

    t("readpp", readpp)
    for alg in ["adler32", "ADLER32", "md5", "crc32c", "crc32", "sha1", "CRC32C"]:
        t("cks " + alg, ctx.checksum, R + "/f.txt", alg)
    t("cks partial", ctx.checksum, R + "/f.txt", "adler32", 2, 3)
    t("cks missing", ctx.checksum, R + "/nofile", "adler32")
    t("listxattr", ctx.listxattr, R + "/f.txt")
    for x in ["user.status", "xroot.cksum", "user.foo"]:
        t("getxattr " + x, ctx.getxattr, R + "/f.txt", x)
    t("getxattr missing status", ctx.getxattr, R + "/nofile", "user.status")
    t("getxattr missing cksum", ctx.getxattr, R + "/nofile", "xroot.cksum")
    t("getxattr xattr keys", lambda: sorted(
        k.split("=")[0] for k in ctx.getxattr(R + "/f.txt", "xroot.xattr").split("&")))
    t("getxattr spacetoken keys", lambda: sorted(json.loads(ctx.getxattr(R, "spacetoken"))))
    t("setxattr", ctx.setxattr, R + "/f.txt", "user.foo", "bar", 0)
    t("rename", ctx.rename, R + "/f.txt", R + "/g.txt")
    t("rename missing", ctx.rename, R + "/f.txt", R + "/h.txt")
    t("rmdir nonempty", ctx.rmdir, R + "/a")
    t("rmdir file", ctx.rmdir, R + "/g.txt")
    t("rmdir missing", ctx.rmdir, R + "/nodir")
    t("unlink dir", ctx.unlink, R + "/a")
    t("unlink missing", ctx.unlink, R + "/nofile")
    t("unlink list", lambda: [str(e) for e in ctx.unlink([R + "/g.txt", R + "/nofile"])])
    t("readlink", ctx.readlink, R + "/a")
    t("symlink", ctx.symlink, R + "/a", R + "/l")
    t("open r missing", ctx.open, R + "/missing", "r")
    t("open r dir", ctx.open, R + "/a", "r")

    def io():
        f = ctx.open(R + "/io", "w"); f.write("0123456789"); del f
        f = ctx.open(R + "/io", "r")
        r = [f.read(4), f.read(100), f.read(5), f.lseek(2, 0), f.read(3), f.pread(5, 3),
             f.read(2), f.lseek(-2, 2), f.read(10)]
        try:
            f.write("x")
        except mod.GError as e:
            r.append((e.code, e.message))
        del f
        f = ctx.open(R + "/io", "rw"); r += [f.read(3), f.write("AB")]; del f
        f = ctx.open(R + "/io", "r"); r.append(f.read(100)); del f
        f = ctx.open(R + "/np/deep/x", "w"); f.write("z"); del f
        r.append(mode(R + "/np/deep/x"))
        return r

    t("io", io)
    t("bring_online", lambda: ctx.bring_online(R + "/io", 0, 10, True)[0])
    t("bring_online missing", lambda: ctx.bring_online(R + "/nofile", 0, 10, True)[0])
    t("bring_online_poll bogus", lambda: [
        str(x) for x in ctx.bring_online_poll([R + "/io", R + "/nofile"], "bogus")])
    t("release", ctx.release, R + "/io", "")
    t("archive_poll", ctx.archive_poll, R + "/io")
    t("abort", lambda: [str(e) for e in ctx.abort_bring_online([R + "/io"], "bogus")])

    def copy(label, s, d, **kw):
        events = []
        p = ctx.transfer_parameters()
        p.event_callback = lambda e: events.append(
            [e.side, e.domain, e.stage, e.description]
            if e.stage == "TRANSFER:TYPE" else [e.side, e.domain, e.stage])
        for k, v in kw.items():
            if k == "checksum":
                p.set_checksum(mod.checksum_mode.target, "ADLER32", v)
            else:
                setattr(p, k, v)
        try:
            ctx.filecopy(p, s, d)
            result = "ok"
        except mod.GError as e:
            result = ["err", e.code]
        # Only what the plugin says: its own domain, and the transfer itself.
        mine = [e for e in events if e[1] == "xroot" and e[2].startswith("TRANSFER")]
        out["copy " + label] = [result, mine]

    digest = lambda path: hashlib.md5(open(path, "rb").read()).hexdigest()
    copy("upload", "file:///tmp/src.bin", R + "/up.bin")
    copy("download", R + "/up.bin", "file:///tmp/down_%s.bin" % tag, nbstreams=4)
    out["download intact"] = digest("/tmp/down_%s.bin" % tag) == digest("/tmp/src.bin")
    copy("tpc", R + "/up.bin", R2 + "/tpc.bin")
    t("tpc size", lambda: ctx.stat(R + "/tpc.bin").st_size)
    copy("tpc parent", R + "/up.bin", R2 + "/new/deep/tpc.bin", create_parent=True)
    copy("missing source", R + "/nothere", "file:///tmp/x_%s.bin" % tag)
    copy("tpc no parent", R + "/up.bin", R2 + "/new2/deep/tpc.bin")
    copy("tpc missing source", R + "/nothere", R2 + "/nothere.bin")
    copy("tpc bad checksum", R + "/up.bin", R2 + "/bad.bin", checksum="deadbeef")
    copy("tpc exists", R + "/up.bin", R2 + "/tpc.bin")
    return out


report = {"gfal2": run(gfal2, "sbs_gfal2"), "ours": run(xgfalclient, "sbs_ours")}
json.dump(report, open("/io/report.json", "w"), indent=1)
"""

GSI_DRIVER = r"""
import json, sys
sys.path[:0] = ["/src/xgfalclient/src", "/src/xrdclient/src"]
import gfal2, xgfalclient
out = {}
for name, mod in (("gfal2", gfal2), ("ours", xgfalclient)):
    ctx = mod.creat_context()
    try:
        ctx.mkdir_rec("root://localhost:1095//gsi_" + name, 0o755)
        out[name] = ["ok", ctx.stat("root://localhost:1095//gsi_" + name).st_mode]
    except mod.GError as e:
        out[name] = ["err", e.code, e.message]
json.dump(out, open("/io/gsi.json", "w"))
"""


def _xrdclient_src() -> Path:
    import xrdclient

    return Path(xrdclient.__file__).resolve().parent.parent


def _docker(*args: str, check: bool = True, timeout: float = 600) -> str:
    done = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=timeout
    )
    return done.stdout


@contextmanager
def serving() -> Iterator[tuple[str, Path]]:
    """A container with a stock xrootd on 1094 and both source trees mounted."""
    name = f"xgfal-xrootd-interop-{os.getpid()}"
    with tempfile.TemporaryDirectory() as io_dir:
        _docker(
            "run", "-d", "--rm", "--name", name,
            "-p", "127.0.0.1::1094",
            "-e", "PYTHONPYCACHEPREFIX=/tmp/pyc",
            # The package alone: src/ also holds the gfal2 shim, which would
            # shadow the real gfal2 and compare this package with itself.
            "-v", f"{ROOT / 'src' / 'xgfalclient'}:/src/xgfalclient/src/xgfalclient:ro",
            "-v", f"{_xrdclient_src()}:/src/xrdclient/src:ro",
            "-v", f"{io_dir}:/io",
            IMAGE, "sleep", "infinity",
        )  # fmt: skip
        try:
            _docker("exec", name, "bash", "-c", START.format(config=SERVER_CONFIG))
            time.sleep(1)
            yield name, Path(io_dir)
        finally:
            _docker("rm", "-f", name, check=False)


@pytest.fixture(scope="module")
def container() -> Iterator[tuple[str, Path]]:
    with serving() as box:
        yield box


def run_driver(container: tuple[str, Path]) -> dict[str, dict[str, Any]]:
    name, io_dir = container
    (io_dir / "driver.py").write_text(DRIVER)
    _docker("exec", name, "python3", "/io/driver.py", timeout=900)
    return json.loads((io_dir / "report.json").read_text())  # type: ignore[no-any-return]


def differences(report: dict[str, dict[str, Any]]) -> dict[str, tuple[Any, Any]]:
    theirs, ours = report["gfal2"], report["ours"]
    return {
        label: (theirs.get(label), ours.get(label))
        for label in sorted(set(theirs) | set(ours))
        if theirs.get(label) != ours.get(label)
    }


@pytest.mark.timeout(1200)
def test_side_by_side_with_gfal2(container: tuple[str, Path]) -> None:
    report = run_driver(container)
    assert report["ours"]["download intact"] is True
    found = differences(report)
    unexpected = {label: pair for label, pair in found.items() if label not in KNOWN}
    assert not unexpected, json.dumps(unexpected, indent=1)


@pytest.mark.timeout(600)
def test_from_this_interpreter_through_the_port(
    container: tuple[str, Path], tmp_path: Path
) -> None:
    """The plugin on this machine's Python, against the container's xrootd."""
    import xgfalclient

    name, _ = container
    port = _docker("port", name, "1094").strip().rsplit(":", 1)[1]
    base = f"root://127.0.0.1:{port}//host_side"
    payload = os.urandom(5 << 20)
    (tmp_path / "src").write_bytes(payload)
    with xgfalclient.creat_context() as ctx:
        ctx.mkdir_rec(base, 0o755)
        params = ctx.transfer_parameters()
        params.set_checksum(xgfalclient.checksum_mode.both, "adler32", "")
        ctx.filecopy(params, f"file://{tmp_path}/src", base + "/f")
        assert ctx.stat(base + "/f").st_size == len(payload)
        ctx.filecopy(ctx.transfer_parameters(), base + "/f", f"file://{tmp_path}/back")
        assert (tmp_path / "back").read_bytes() == payload
        assert ctx.listdir(base) == ["f"]
        assert ctx.unlink(base + "/f") == 0
        assert ctx.rmdir(base) == 0


@pytest.mark.timeout(600)
def test_gsi_with_a_proxy_found_as_gfal2_finds_it(tmp_path: Path) -> None:
    from xgfalclient.testing.pki import create_pki

    create_pki(tmp_path / "pki")
    name = f"xgfal-xrootd-gsi-{os.getpid()}"
    io_dir = tmp_path / "io"
    io_dir.mkdir()
    (io_dir / "gsi.py").write_text(GSI_DRIVER)
    _docker(
        "run", "-d", "--rm", "--name", name,
        "-e", "PYTHONPYCACHEPREFIX=/tmp/pyc",
        "-e", "X509_USER_PROXY=/pki/x509up_rfc",
        "-e", "X509_CERT_DIR=/pki/certificates",
        "-v", f"{ROOT / 'src'}:/src/xgfalclient/src:ro",
        "-v", f"{_xrdclient_src()}:/src/xrdclient/src:ro",
        "-v", f"{tmp_path / 'pki'}:/pki-ro:ro",
        "-v", f"{io_dir}:/io",
        IMAGE, "sleep", "infinity",
    )  # fmt: skip
    try:
        # xrootd insists the host key belongs to its own user and nobody else.
        prepare = (
            "cp -r /pki-ro /pki && useradd -m xrd 2>/dev/null; "
            "chown -R xrd /pki && chmod 600 /pki/hostkey.pem /pki/x509up_rfc && "
            + START.format(config=GSI_CONFIG)
        )
        _docker("exec", name, "bash", "-c", prepare)
        time.sleep(1)
        _docker("exec", "-u", "xrd", name, "python3", "/io/gsi.py", timeout=300)
        result = json.loads((io_dir / "gsi.json").read_text())
    finally:
        _docker("rm", "-f", name, check=False)
    assert result["ours"] == result["gfal2"]
    assert result["ours"][0] == "ok"


if __name__ == "__main__":
    with serving() as box:
        result = differences(run_driver(box))
    for label, (theirs, ours) in result.items():
        print(f"== {label}" + (f"  (known: {KNOWN[label]})" if label in KNOWN else ""))
        print(f"   gfal2: {theirs}\n   ours:  {ours}")
    print(f"{len(result)} differences")
    sys.exit(1 if set(result) - set(KNOWN) else 0)
