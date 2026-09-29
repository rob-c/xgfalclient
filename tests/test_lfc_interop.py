"""The ``lfc`` plugin against a real EL7 LFC, side by side with EL7 gfal2.

LFC left gfal2 after 2.22 and has no EL9 build, so the reference is the
last EL7 stack, from the CentOS vault and the EPEL 7 archive: ``lfcdaemon``
1.13.0 on MariaDB, and gfal2 2.22.2 with ``gfal2-plugin-lfc`` and
``python2-gfal2``. Three containers share the network ``xgfal-lfc-net``:

``xgfal-lfc-server``
    the LFC, with a host certificate from a throwaway test PKI, the test
    user's DN mapped to the ``xgfal`` VO in ``/etc/lcgdm-mapfile``, and the
    two client containers in its ``TRUST`` list (for the ID mechanism);
``xgfal-lfc-client``
    EL7 gfal2, the behaviour reference;
``xgfal-lfc-py``
    ``gfal-ref:latest`` for its Python 3.9, running this checkout.

The same driver runs every gfal2 operation the old plugin had through both
clients, each in its own directory, and the answers must match except for
:data:`KNOWN`. The driver is then run again against the in-process
:class:`~xgfalclient.testing.lfc.LFCServer` (inside the Python container),
which must answer exactly as the real server did.

Skipped unless ``XGFAL_INTEROP=1``; ``XGFAL_KEEP=1`` leaves the containers
up. Run as a script for a report::

    python tests/test_lfc_interop.py
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
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

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "xgfal-lfc-el7:latest"
PYIMAGE = "gfal-ref:latest"
NETWORK = "xgfal-lfc-net"
SERVER = "xgfal-lfc-server"
CLIENT = "xgfal-lfc-client"
PYCLIENT = "xgfal-lfc-py"
FQDN = f"{SERVER}.{NETWORK}"

#: Where gfal2 and this client differ on purpose.
KNOWN = {
    "checksum md5": "gfal2 answers with the stored Adler-32 whatever algorithm is asked; ENOTSUP",
    "readpp": "gfal2's readdir leaves d_type 0; the type is taken from the entry's mode",
    "open none": "same EBADF; the message names the missing replicas",
}

REPO = """\
[base]
baseurl=https://vault.centos.org/7.9.2009/os/x86_64/
gpgcheck=0
[updates]
baseurl=https://vault.centos.org/7.9.2009/updates/x86_64/
gpgcheck=0
[extras]
baseurl=https://vault.centos.org/7.9.2009/extras/x86_64/
gpgcheck=0
[epel]
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
"""

DOCKERFILE = """\
FROM --platform=linux/amd64 centos:7
RUN rm -f /etc/yum.repos.d/*.repo
COPY el7.repo /etc/yum.repos.d/el7.repo
RUN yum -y --setopt=tsflags= install lfc-server-mysql lfc mariadb-server gfal2-all \\
    gfal2-plugin-lfc gfal2-plugin-mock python2-gfal2 which procps-ng && yum clean all
"""

SIGNING_POLICY = """\
access_id_CA X509 '/DC=org/DC=xgfal/CN=xgfal Test CA'
pos_rights globus CA:sign
cond_subjects globus '"/DC=org/DC=xgfal/*"'
"""

SERVER_SETUP = r"""
set -e
mysql_install_db --user=mysql >/dev/null 2>&1
(mysqld_safe --user=mysql >/var/log/mysqld-safe.log 2>&1 &)
for i in $(seq 60); do mysqladmin ping >/dev/null 2>&1 && break; sleep 1; done
mysql < /usr/share/lcgdm/create_lfc_tables_mysql.sql
mysql -e "GRANT ALL ON cns_db.* TO 'lfc'@'localhost' IDENTIFIED BY 'lfcpw'; FLUSH PRIVILEGES;"
echo 'lfc/lfcpw@localhost' > /etc/NSCONFIG; chown lfcmgr /etc/NSCONFIG; chmod 600 /etc/NSCONFIG
mkdir -p /etc/grid-security/lfcmgr /etc/grid-security/certificates /var/log/lfc
cp /lab/pki/hostcert.pem /etc/grid-security/lfcmgr/lfccert.pem
cp /lab/pki/hostkey.pem /etc/grid-security/lfcmgr/lfckey.pem
chown -R lfcmgr:lfcmgr /etc/grid-security/lfcmgr /var/log/lfc
chmod 400 /etc/grid-security/lfcmgr/lfckey.pem
cp /lab/pki/certificates/* /etc/grid-security/certificates/
echo '"/DC=org/DC=xgfal/OU=People/CN=Test User" xgfal' > /etc/lcgdm-mapfile
echo "LFC TRUST xgfal-lfc-client.xgfal-lfc-net xgfal-lfc-py.xgfal-lfc-net" > /etc/shift.conf
su lfcmgr -s /bin/bash -c "GLOBUS_THREAD_MODEL=pthread \
 X509_USER_CERT=/etc/grid-security/lfcmgr/lfccert.pem \
 X509_USER_KEY=/etc/grid-security/lfcmgr/lfckey.pem \
 /usr/sbin/lfcdaemon -t 20 -c /etc/NSCONFIG -l /var/log/lfc/log"
export CSEC_MECH=ID LFC_HOST=localhost LFC_CONRETRY=0
for i in $(seq 30); do lfc-ls -ld / >/dev/null 2>&1 && break; sleep 1; done
lfc-mkdir -p /grid
lfc-chmod 777 /grid
"""

#: The operations, runnable by python2 with gfal2 and python3 with xgfalclient.
DRIVER = r"""
from __future__ import print_function
import json, os, sys
IMPL, HOST, BASE = sys.argv[1], sys.argv[2], "/grid/" + sys.argv[3]
os.environ["LFC_HOST"] = HOST
if IMPL == "gfal2":
    import gfal2
    ctx = gfal2.creat_context()
else:
    import xgfalclient as gfal2
    from xgfalclient.plugins.lfc import LFCPlugin
    ctx = gfal2.creat_context()
    ctx.add_plugin(LFCPlugin)
ROOT = "lfc://" + HOST + BASE
results = []

def st(info):
    return {"mode": oct(info.st_mode).replace("o", ""), "nlink": info.st_nlink,
            "size": info.st_size, "uid": info.st_uid, "gid": info.st_gid, "ino": info.st_ino}

def clean(value):
    if isinstance(value, (list, tuple)):
        return [clean(item) for item in value]
    if type(value).__name__ in ("str", "unicode", "bytes"):
        try:
            if isinstance(value, bytes) and bytes is not str:
                value = value.decode("utf-8")
            json.dumps(value)
        except (UnicodeError, ValueError):
            return "RAW:" + repr(value)
        if chr(0) in value:
            return "RAW:" + repr(value)
    return value

def run(name, fn, *args):
    try:
        value = fn(*args)
        if hasattr(value, "st_mode"):
            value = st(value)
        results.append([name, "ok", clean(value)])
    except gfal2.GError as exc:
        results.append([name, "err", exc.code, clean(str(getattr(exc, "message", exc)))])
    except Exception as exc:
        results.append([name, "exc", type(exc).__name__, clean(str(exc))])

def readpp(url):
    d = ctx.opendir(url)
    out = []
    while True:
        ent, info = d.readpp()
        if ent is None:
            break
        out.append([ent.d_name, ent.d_type, oct(info.st_mode).replace("o", ""), info.st_size])
    return sorted(out)

def read_all(url):
    # Bytes read: python2's str is bytes, python3's is decoded (surrogateescape),
    # and the mock's content is not text.
    data = ctx.open(url, "r").read(100)
    return len(data if isinstance(data, bytes) else data.encode("utf-8", "surrogateescape"))

def copy(src, dst):
    return ctx.filecopy(ctx.transfer_parameters(), src, dst)

def guid_stat(url):
    return st(ctx.stat("guid:" + ctx.getxattr(url, "user.guid")))

MOCK = "mock://se.example.org/data" + BASE + "/f?size=12&checksum=0000abcd"
MOCK2 = "mock://se2.example.org/data" + BASE + "/f?size=12&checksum=0000abcd"
MOCK3 = "mock://se3.example.org/data" + BASE + "/f?size=99&checksum=0000abcd"
F = ROOT + "/d/f"
run("mkdir", ctx.mkdir, ROOT, 0o755)
run("mkdir d", ctx.mkdir, ROOT + "/d", 0o755)
run("mkdir exists", ctx.mkdir, ROOT + "/d", 0o755)
run("mkdir no parent", ctx.mkdir, ROOT + "/x/y", 0o755)
run("stat dir", ctx.stat, ROOT + "/d")
run("mkdir_rec", ctx.mkdir_rec, ROOT + "/d/a/b/c", 0o755)
run("mkdir_rec again", ctx.mkdir_rec, ROOT + "/d/a/b/c", 0o755)
run("stat deep", ctx.stat, ROOT + "/d/a/b/c")
run("stat missing", ctx.stat, ROOT + "/missing")
run("lstat missing", ctx.lstat, ROOT + "/missing")
run("register", ctx.setxattr, F, "user.replicas", "+" + MOCK, 0)
run("register again", ctx.setxattr, F, "user.replicas", "+" + MOCK, 0)
run("register second", ctx.setxattr, F, "user.replicas", "+" + MOCK2, 0)
run("register bad size", ctx.setxattr, F, "user.replicas", "+" + MOCK3, 0)
run("register no host", ctx.setxattr, F, "user.replicas", "+file:///tmp/x", 0)
run("register bad op", ctx.setxattr, F, "user.replicas", "*x", 0)
run("stat file", ctx.stat, F)
run("replicas", ctx.getxattr, F, "user.replicas")
run("guid length", lambda url: len(ctx.getxattr(url, "user.guid")), F)
run("chksumtype", ctx.getxattr, F, "user.chksumtype")
run("checksum xattr", ctx.getxattr, F, "user.checksum")
run("comment empty", ctx.getxattr, F, "user.comment")
run("set comment", ctx.setxattr, F, "user.comment", "hello there", 0)
run("comment", ctx.getxattr, F, "user.comment")
run("xattr unknown", ctx.getxattr, F, "user.status")
run("setxattr unknown", ctx.setxattr, F, "user.guid", "x", 0)
run("listxattr file", ctx.listxattr, F)
run("listxattr dir", ctx.listxattr, ROOT + "/d")
run("checksum adler", ctx.checksum, F, "ADLER32")
run("checksum md5", ctx.checksum, F, "MD5")
run("unregister", ctx.setxattr, F, "user.replicas", "-" + MOCK2, 0)
run("replicas after", ctx.getxattr, F, "user.replicas")
run("unregister missing", ctx.setxattr, F, "user.replicas", "-" + MOCK2, 0)
run("open", read_all, F)
run("mkfile none", ctx.setxattr, ROOT + "/d/e", "user.replicas", "+" + MOCK2, 0)
run("unregister only", ctx.setxattr, ROOT + "/d/e", "user.replicas", "-" + MOCK2, 0)
run("open none", read_all, ROOT + "/d/e")
run("listdir", lambda url: sorted(ctx.listdir(url)), ROOT + "/d")
run("readpp", readpp, ROOT + "/d")
run("listdir missing", ctx.listdir, ROOT + "/nope")
run("listdir file", ctx.listdir, F)
run("symlink", ctx.symlink, F, ROOT + "/d/link")
run("symlink exists", ctx.symlink, F, ROOT + "/d/link")
run("readlink", ctx.readlink, ROOT + "/d/link")
run("readlink file", ctx.readlink, F)
run("lstat link", ctx.lstat, ROOT + "/d/link")
run("stat link", ctx.stat, ROOT + "/d/link")
run("stat through file", ctx.stat, F + "/x")
run("stat long name", ctx.stat, ROOT + "/" + "n" * 300)
run("guid stat", guid_stat, F)
run("guid missing", ctx.stat, "guid:00000000-0000-0000-0000-000000000000")
run("lfn stat", ctx.stat, "lfn:" + BASE + "//d/")
run("chmod", ctx.chmod, F, 0o600)
run("stat chmod", ctx.stat, F)
run("access r", ctx.access, F, os.R_OK)
run("access x", ctx.access, F, os.X_OK)
run("access missing", ctx.access, ROOT + "/missing", os.F_OK)
run("chmod missing", ctx.chmod, ROOT + "/missing", 0o600)
run("rename", ctx.rename, F, ROOT + "/d/g")
run("rename missing", ctx.rename, F, ROOT + "/d/h")
run("rmdir not empty", ctx.rmdir, ROOT + "/d")
run("rmdir file", ctx.rmdir, ROOT + "/d/g")
run("unlink dir", ctx.unlink, ROOT + "/d/a")
run("unlink link", ctx.unlink, ROOT + "/d/link")
run("unlink", ctx.unlink, ROOT + "/d/g")
run("unlink missing", ctx.unlink, ROOT + "/d/g")
run("copy register", copy, MOCK, ROOT + "/d/copied")
run("copy stat", ctx.stat, ROOT + "/d/copied")
run("copy existing", copy, MOCK2, ROOT + "/d/copied")
run("copy replicas", ctx.getxattr, ROOT + "/d/copied", "user.replicas")
run("rmdir deep", ctx.rmdir, ROOT + "/d/a/b/c")
run("rmdir missing", ctx.rmdir, ROOT + "/d/a/b/c")
print(json.dumps(results))
"""

#: Starts the in-process LFC in the Python container and runs a script at it;
#: ``HOST`` and ``PORT`` in the arguments become the server's.
IN_PROCESS = r"""
import os, subprocess, sys
from xgfalclient.testing.lfc import LFCServer, USER_DN
from xgfalclient.testing.pki import create_pki
pki = create_pki("/tmp/lfc-pki")
os.environ.update(pki.environment())
with LFCServer(host="localhost", gsi=pki.server_context(), mapfile={USER_DN: "xgfal"}) as lfc:
    lfc.mkdir("/grid", 0o777)
    args = [arg.replace("HOSTPORT", lfc.hostport).replace("HOST", lfc.host)
            .replace("PORT", str(lfc.port)) for arg in sys.argv[1:]]
    out = subprocess.check_output([sys.executable] + args, env=os.environ)
    sys.stdout.write(out.decode())
"""

#: Raw wire checks the in-process server must reproduce.
PROBE = r"""
import json, os, ssl, sys
from xgfalclient.plugins.lfc import client, wire
from xgfalclient.plugins.lfc.csec import GSIMechanism
tls = ssl.create_default_context(capath=os.environ["X509_CERT_DIR"])
tls.check_hostname = False
tls.load_cert_chain(os.environ["X509_USER_PROXY"])
out = {}
for sessions in (False, True):
    server = client.Server(sys.argv[1], int(sys.argv[2]), lambda: [GSIMechanism(tls)],
                           sessions=sessions)
    conn = server.connect()
    body = client._ids().hyper(0).string("/grid").string("").bytes()
    opened = conn.call(wire.MAGIC, wire.OPENDIR, body)
    fileid = opened.reader().hyper()
    batch = conn.call(wire.MAGIC, wire.READDIR,
                      client._ids().word(1).word(62).hyper(fileid).word(1).bytes())
    closed = conn.call(wire.MAGIC, wire.CLOSEDIR)
    if closed.final:
        conn = server.connect()
    bad = conn.call(wire.MAGIC, 99, client._ids().bytes())
    out[str(sessions)] = [opened.status, opened.final, batch.status, batch.final,
                          closed.status, closed.final, bad.status, bad.final, bad.errors]
    if not bad.final:
        end = conn.call(wire.MAGIC, wire.ENDSESS, client._ids().bytes())
        out[str(sessions)] += [end.status, end.final]
    out["ping"] = server.ping()
print(json.dumps(out))
"""


def docker(*args: str, check: bool = True, timeout: float = 600) -> str:
    done = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and done.returncode:
        raise RuntimeError(f"docker {' '.join(args[:3])}: {done.stderr.strip()[-2000:]}")
    return done.stdout


def ensure_image(lab: Path) -> None:
    if docker("images", "-q", IMAGE).strip():
        return
    (lab / "build").mkdir(exist_ok=True)
    (lab / "build" / "el7.repo").write_text(REPO)
    (lab / "build" / "Dockerfile").write_text(DOCKERFILE)
    docker("build", "-t", IMAGE, str(lab / "build"), timeout=3600)


def make_pki(lab: Path) -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from xgfalclient.testing.pki import create_pki, subject_hash

    pki = create_pki(
        lab / "pki", hosts=(FQDN, SERVER, "localhost"), host_cn=FQDN, key_slots=(0, 1, 2)
    )
    name = subject_hash(pki.ca.subject.encoded())
    (lab / "pki" / "certificates" / f"{name}.signing_policy").write_text(SIGNING_POLICY)


def start(name: str, image: str, lab: Path, *extra: str) -> None:
    docker("rm", "-f", name, check=False)
    docker(
        "run", "-d", "--name", name, "--hostname", f"{name}.{NETWORK}",
        "--dns-search", NETWORK, "--network", NETWORK, "--network-alias", f"{name}.{NETWORK}",
        "-v", f"{lab}:/lab", *extra, image, "sleep", "infinity",
    )  # fmt: skip


@contextmanager
def serving() -> Iterator[Path]:
    """The three containers, up and initialised; yields the shared directory."""
    lab = Path(tempfile.mkdtemp(prefix="xgfal-lfc-", dir="/tmp"))
    ensure_image(lab)
    make_pki(lab)
    (lab / "driver.py").write_text(DRIVER)
    (lab / "inprocess.py").write_text(IN_PROCESS)
    (lab / "probe.py").write_text(PROBE)
    (lab / "setup.sh").write_text(SERVER_SETUP)
    docker("network", "create", NETWORK, check=False)
    start(SERVER, IMAGE, lab, "--platform", "linux/amd64")
    start(CLIENT, IMAGE, lab, "--platform", "linux/amd64")
    start(PYCLIENT, PYIMAGE, lab, "-v", f"{ROOT / 'src'}:/x/src:ro")
    try:
        docker("exec", SERVER, "bash", "/lab/setup.sh", timeout=300)
        yield lab
    finally:
        if os.environ.get("XGFAL_KEEP") != "1":
            for name in (SERVER, CLIENT, PYCLIENT):
                docker("rm", "-f", name, check=False)
            docker("network", "rm", NETWORK, check=False)
            shutil.rmtree(lab, ignore_errors=True)


def credentials() -> list[str]:
    return [
        "-e", "X509_USER_PROXY=/lab/pki/x509up_rfc",
        "-e", "X509_CERT_DIR=/lab/pki/certificates",
        "-e", "LFC_CONRETRY=0",
    ]  # fmt: skip


def run_gfal2(prefix: str, *env: str) -> list[Any]:
    out = docker(
        "exec", *credentials(), *env, CLIENT, "python2", "/lab/driver.py", "gfal2", FQDN, prefix
    )
    return list(json.loads(out))


def run_xgfal(prefix: str, *env: str) -> list[Any]:
    out = docker(
        "exec", *credentials(), "-e", "PYTHONPATH=/x/src", *env, PYCLIENT,
        "python3", "/lab/driver.py", "xgfal", FQDN, prefix,
    )  # fmt: skip
    return list(json.loads(out))


def in_process(*args: str) -> Any:
    out = docker(
        "exec", "-e", "PYTHONPATH=/x/src", "-e", "LFC_CONRETRY=0", PYCLIENT,
        "python3", "/lab/inprocess.py", *args,
    )  # fmt: skip
    return json.loads(out)


def normalise(results: list[Any], prefix: str) -> dict[str, Any]:
    text = json.dumps(results).replace(f"/grid/{prefix}", "/grid/P")
    text = re.sub(r"localhost:[0-9]+", "HOST", text.replace(FQDN, "HOST"))
    found = {}
    for entry in json.loads(text):
        found[entry[0]] = entry[1:]
    return found


def differences(theirs: dict[str, Any], ours: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    return {
        label: (theirs.get(label), ours.get(label))
        for label in theirs
        if theirs.get(label) != ours.get(label)
    }


def fresh() -> str:
    return "t" + uuid.uuid4().hex[:8]


@pytest.fixture(scope="module")
def lab() -> Iterator[Path]:
    with serving() as box:
        yield box


def test_side_by_side_with_gfal2(lab: Path) -> None:
    ref, mine = fresh(), fresh()
    theirs = normalise(run_gfal2(ref), ref)
    ours = normalise(run_xgfal(mine), mine)
    found = differences(theirs, ours)
    assert set(found) <= set(KNOWN), {k: v for k, v in found.items() if k not in KNOWN}
    assert ours["open none"][1] == theirs["open none"][1]  # the same errno, at least
    assert len(ours) == len(theirs) > 70


def test_in_process_server_matches_the_real_one(lab: Path) -> None:
    real, fake = fresh(), fresh()
    against_real = normalise(run_xgfal(real), real)
    against_fake = normalise(in_process("/lab/driver.py", "xgfal", "HOSTPORT", fake), fake)
    found = differences(against_real, against_fake)
    assert not found, found


def test_wire_details_match(lab: Path) -> None:
    real = json.loads(
        docker(
            "exec",
            *credentials(),
            "-e",
            "PYTHONPATH=/x/src",
            PYCLIENT,
            "python3",
            "/lab/probe.py",
            FQDN,
            "5010",
        )
    )
    assert real["False"][:6] == [0, False, 0, False, 1015, True]  # CLOSEDIR ends with SEINTERNAL
    assert real["True"][:6] == [0, False, 0, False, 1015, False]
    assert real["True"][6:] == [1022, False, ["NS003 - illegal function 99"], 0, True]
    assert real["ping"] == "1.13.0-1"
    assert in_process("/lab/probe.py", "HOST", "PORT") == real


def test_id_mechanism_from_a_trusted_host(lab: Path) -> None:
    prefix = fresh()
    ours = normalise(run_xgfal(prefix, "-e", "CSEC_MECH=ID"), prefix)
    theirs = normalise(run_gfal2(prefix + "r", "-e", "CSEC_MECH=ID"), prefix + "r")
    assert ours["stat dir"][1]["uid"] == 0  # root, as the server treats trusted ID clients
    found = differences(theirs, ours)
    assert set(found) <= set(KNOWN), found


if __name__ == "__main__":
    started = time.monotonic()
    with serving():
        ref, mine = fresh(), fresh()
        theirs = normalise(run_gfal2(ref), ref)
        ours = normalise(run_xgfal(mine), mine)
    result = differences(theirs, ours)
    same = len(theirs) - len(result)
    for label, (gfal2, xgfal) in result.items():
        print(f"== {label}" + (f"  (known: {KNOWN[label]})" if label in KNOWN else ""))
        print(f"   gfal2: {gfal2}\n   ours:  {xgfal}")
    elapsed = time.monotonic() - started
    print(f"{same} of {len(theirs)} identical, {len(result)} differ ({elapsed:.0f}s)")
    sys.exit(1 if set(result) - set(KNOWN) else 0)
