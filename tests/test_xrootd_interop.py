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
        # The package alone, so that ``import gfal2`` is the real one.
        "-v", f"{ROOT / 'src' / 'xgfalclient'}:/src/xgfalclient/src/xgfalclient:ro",
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


#: Two GSI servers for a delegated pull ("TPC lite"). The destination asks
#: for a proxy at login (``-dlgpxy:1``), keeps it with the session
#: (``-exppxy:=creds``) and hands it to the pull (``fcreds``); ``gsi`` without
#: a ``?`` makes delegation compulsory, so a pull that works is one that
#: delegated. The source knows nothing of TPC: in TPC lite it is only read,
#: by the destination's ``xrdcp`` with the delegated proxy.
LITE_SECURITY = """\
xrootd.seclib libXrdSec.so
sec.protocol gsi -certdir:/pki/certificates -cert:/pki/hostcert.pem -key:/pki/hostkey.pem \
 -gridmap:/dev/null -gmapopt:10 -dlgpxy:{dlgpxy} -exppxy:=creds
sec.protbind * only gsi
"""
LITE_SOURCE = "all.export /\noss.localroot /data/src\nall.role server\nxrd.port 1096\n"
LITE_DESTINATION = (
    "all.export /\noss.localroot /data/dst\nall.role server\nxrd.port 1095\n"
    "ofs.tpc fcreds gsi =X509_USER_PROXY autorm pgm /usr/bin/xrdcp --server\n"
)

LITE_START = """\
set -e
cp -r /pki-ro /pki
useradd -m xrd 2>/dev/null || true
mkdir -p /data/src /data/dst /etc/xrd
head -c 3145733 /dev/urandom > /data/src/src.bin
chown -R xrd /pki /data
chmod 600 /pki/hostkey.pem /pki/x509up_rfc
cat > /etc/xrd/src.cfg <<'EOF'
{source}EOF
cat > /etc/xrd/dst.cfg <<'EOF'
{destination}EOF
# The user's own proxy stays out of the servers' environment: the pull has
# the delegated one or nothing.
for name in src dst; do
  su xrd -s /bin/bash -c \
    "env -u X509_USER_PROXY xrootd -b -n $name -l /tmp/$name.log -c /etc/xrd/$name.cfg"
done
"""

LITE_DRIVER = r"""
import hashlib, json, sys
sys.path[:0] = ["/src/xgfalclient/src", "/src/xrdclient/src"]
name, tag = sys.argv[1:3]
mod = __import__(name)
ctx = mod.creat_context()
S = "root://localhost:1096//"
D = "root://localhost:1095//" + tag + "_"
out = {}


def copy(label, src, dst, **kw):
    events = []
    p = ctx.transfer_parameters()
    p.event_callback = lambda e: events.append(
        [e.side, e.domain, e.stage, e.description]
        if e.stage in ("TRANSFER:TYPE", "TRANSFER:EXIT") else [e.side, e.domain, e.stage])
    for k, v in kw.items():
        setattr(p, k, v)
    try:
        ctx.filecopy(p, src, dst)
        result = "ok"
    except mod.GError as e:
        result = ["err", e.code, e.message]
    mine = [e for e in events if e[1] == "xroot" and e[2].startswith("TRANSFER")]
    out[label] = json.loads(json.dumps([result, mine]).replace(tag + "_", "T_"))


def digest(path):
    try:
        return hashlib.md5(open(path, "rb").read()).hexdigest()
    except OSError as e:
        return str(e.errno)


copy("lite", S + "src.bin", D + "lite.bin")
out["lite intact"] = digest("/data/dst/" + tag + "_lite.bin") == digest("/data/src/src.bin")
copy("lite exists", S + "src.bin", D + "lite.bin")
copy("lite overwrite", S + "src.bin", D + "lite.bin", overwrite=True)
copy("lite missing source", S + "nothere", D + "missing.bin")
copy("undelegated", S + "src.bin", D + "plain.bin", proxy_delegation=False)
json.dump(out, open("/io/lite_%s.json" % tag, "w"))
"""


#: Where a delegated pull deliberately differs from gfal2's, and why.
KNOWN_LITE = {
    # gfal-copy exports XrdSecGSIDELEGPROXY=1, and XrdSecgsi reads it once, at
    # the process's first GSI login, so --no-delegation still hands the
    # destination a proxy; XrdCl's own "0" for the job comes too late. The
    # proxy is not delegated here when proxy_delegation is off.
    "undelegated": "proxy_delegation=False delegates nothing, whatever the environment",
}


@pytest.mark.timeout(900)
def test_a_delegated_pull_is_tpc_lite_as_in_gfal2(tmp_path: Path) -> None:
    """``root`` to ``root`` with delegation, through gfal2 and through this package.

    Each run is a process of its own, because XrdSecgsi reads
    ``XrdSecGSIDELEGPROXY`` once per process. gfal2 runs as ``gfal-copy`` sets
    it up (``XrdSecGSIDELEGPROXY=1``): without it, its bindings never delegate
    - the source's login loads XrdSecgsi before XrdCl turns delegation on for
    the destination's - and a destination that insists on delegation refuses
    every pull. This package runs both with and without the variable, and a
    pull does the same either way: the destination's login delegates
    exactly when ``proxy_delegation`` says so, as XrdCl means it to.
    """
    from xgfalclient.testing.pki import create_pki

    create_pki(tmp_path / "pki")
    name = f"xgfal-xrootd-lite-{os.getpid()}"
    io_dir = tmp_path / "io"
    io_dir.mkdir()
    (io_dir / "lite.py").write_text(LITE_DRIVER)
    _docker(
        "run", "-d", "--rm", "--name", name,
        "-e", "PYTHONPYCACHEPREFIX=/tmp/pyc",
        "-e", "X509_USER_PROXY=/pki/x509up_rfc",
        "-e", "X509_CERT_DIR=/pki/certificates",
        "-v", f"{ROOT / 'src' / 'xgfalclient'}:/src/xgfalclient/src/xgfalclient:ro",
        "-v", f"{_xrdclient_src()}:/src/xrdclient/src:ro",
        "-v", f"{tmp_path / 'pki'}:/pki-ro:ro",
        "-v", f"{io_dir}:/io",
        IMAGE, "sleep", "infinity",
    )  # fmt: skip
    runs = {
        "theirs": ("gfal2", "1"),
        "ours": ("xgfalclient", "1"),
        "ours_noenv": ("xgfalclient", ""),
    }
    try:
        start = LITE_START.format(
            source=LITE_SOURCE + LITE_SECURITY.format(dlgpxy=0),
            destination=LITE_DESTINATION + LITE_SECURITY.format(dlgpxy=1),
        )
        _docker("exec", name, "bash", "-c", start)
        time.sleep(2)
        for tag, (client, delegate) in runs.items():
            env = ["-e", f"XrdSecGSIDELEGPROXY={delegate}"] if delegate else []
            _docker(
                "exec", "-u", "xrd", *env, name, "python3", "/io/lite.py", client, tag, timeout=600
            )
        found = {tag: json.loads((io_dir / f"lite_{tag}.json").read_text()) for tag in runs}
        log = _docker("exec", name, "bash", "-c", "cat /tmp/*.log /tmp/*/*.log", check=False)
    finally:
        _docker("rm", "-f", name, check=False)
    theirs, ours = found["theirs"], found["ours"]
    report = json.dumps(found, indent=1)
    assert ours["lite"][0] == "ok", log
    assert ours["lite intact"] is True
    assert theirs["lite intact"] is True, report
    assert found["ours_noenv"] == ours, report
    unexpected = {k for k in set(ours) | set(theirs) if ours.get(k) != theirs.get(k)} - set(
        KNOWN_LITE
    )
    assert not unexpected, report
    # Not delegated, the pull is refused by a destination that insists.
    assert "no delegated credentials for tpc (destination)" in ours["undelegated"][0][2]


#: A destination whose pull crawls (``xrdcp --xrate``), so that a copy can be
#: stopped while the destination is still pulling.
SLOW_CONFIG = """\
all.export /
oss.localroot /data
all.role server
ofs.tpc pgm /usr/bin/xrdcp --server --xrate 1m
xrd.port 1094
xrootd.trace fs
"""

SLOW_DRIVER = r"""
import json, os, sys, threading, time
sys.path[:0] = ["/src/xgfalclient/src", "/src/xrdclient/src"]
name, tag = sys.argv[1:3]
mod = __import__(name)
out = {}


def copy(label, cancel=False, timeout=0):
    ctx = mod.creat_context()
    events = []
    p = ctx.transfer_parameters()
    p.event_callback = lambda e: events.append([e.side, e.domain, e.stage, e.description])
    p.timeout = timeout
    if cancel:
        threading.Timer(3, ctx.cancel).start()
    dst = "%s_%s.bin" % (tag, label)
    try:
        ctx.filecopy(p, "root://localhost:1094//big.bin", "root://127.0.0.1:1094//" + dst)
        result = "ok"
    except mod.GError as e:
        result = ["err", e.code, e.message]
    time.sleep(3)  # a pull left running would still be writing
    mine = [e for e in events if e[1] == "xroot"]
    out[label] = json.loads(json.dumps(
        [result, mine, os.path.exists("/data/" + dst)]).replace(tag + "_", "T_"))


copy("cancel", cancel=True)
copy("timeout", timeout=3)
json.dump(out, open("/io/slow_%s.json" % tag, "w"))
"""


@pytest.mark.timeout(900)
def test_a_stopped_pull_stops_at_the_destination_as_in_gfal2(tmp_path: Path) -> None:
    """A cancelled or timed-out pull: XrdCl's ``ofs.tpc cancel``, gfal2's error, nothing left.

    gfal2's XrdCl sends the destination ``Fcntl("ofs.tpc cancel")`` when the
    context is cancelled, and reports the destination's answer; a pull out
    of time is XrdCl's expired ``kXR_sync``, whose errno gfal2 maps to
    ``ESTALE`` where this package says ``ETIMEDOUT`` (see the module).
    """
    name = f"xgfal-xrootd-slow-{os.getpid()}"
    io_dir = tmp_path / "io"
    io_dir.mkdir()
    (io_dir / "slow.py").write_text(SLOW_DRIVER)
    _docker(
        "run", "-d", "--rm", "--name", name,
        "-e", "PYTHONPYCACHEPREFIX=/tmp/pyc",
        "-v", f"{ROOT / 'src' / 'xgfalclient'}:/src/xgfalclient/src/xgfalclient:ro",
        "-v", f"{_xrdclient_src()}:/src/xrdclient/src:ro",
        "-v", f"{io_dir}:/io",
        IMAGE, "sleep", "infinity",
    )  # fmt: skip
    try:
        start = START.format(config=SLOW_CONFIG).replace(
            "chown xrd /data", "head -c 20000000 /dev/urandom > /data/big.bin\nchown -R xrd /data"
        )
        _docker("exec", name, "bash", "-c", start)
        time.sleep(1)
        found = {}
        logs = {}
        for tag, client in (("theirs", "gfal2"), ("ours", "xgfalclient")):
            _docker("exec", name, "python3", "/io/slow.py", client, tag, timeout=300)
            found[tag] = json.loads((io_dir / f"slow_{tag}.json").read_text())
            logs[tag] = _docker("exec", name, "cat", "/tmp/xrd.log")
    finally:
        _docker("rm", "-f", name, check=False)
    theirs, ours = found["theirs"], found["ours"]
    report = json.dumps(found, indent=1)
    assert ours["cancel"] == theirs["cancel"], report
    assert ours["cancel"][0][:2] == ["err", 125], report  # ECANCELED
    assert "destination file prematurely closed" in ours["cancel"][0][2]
    # The same words and events; only the errno differs, deliberately.
    assert theirs["timeout"][0][1] == 116 and ours["timeout"][0][1] == 110, report
    assert ours["timeout"][0][2] == theirs["timeout"][0][2], report
    assert ours["timeout"][1:] == theirs["timeout"][1:], report
    for label in ("cancel", "timeout"):
        assert ours[label][2] is False and theirs[label][2] is False, report  # nothing left
    # The destination heard the cancel on the pull's handle: once for gfal2's
    # cancel, and for each of this package's stops.
    theirs_log = logs["theirs"]
    ours_log = logs["ours"][len(theirs_log) :]
    assert theirs_log.count("query Qopaqug rc=0") == 1, theirs_log
    assert ours_log.count("query Qopaqug rc=0") == 2, ours_log


if __name__ == "__main__":
    with serving() as box:
        result = differences(run_driver(box))
    for label, (theirs, ours) in result.items():
        print(f"== {label}" + (f"  (known: {KNOWN[label]})" if label in KNOWN else ""))
        print(f"   gfal2: {theirs}\n   ours:  {ours}")
    print(f"{len(result)} differences")
    sys.exit(1 if set(result) - set(KNOWN) else 0)
