"""Byte-for-byte parity of the ``gfal-*`` commands with gfal2-util 1.9.1.

Both run in the ``gfal-ref:latest`` image, so the filesystem, clock, users and
Python (3.9) are the same: the real ``gfal-<cmd>`` there, and this package's
``python3 -m xgfalclient.cli <cmd>`` from a bind mount of ``src``. Every case
starts from a fresh fixture tree whose files have a fixed mtime, so nothing
needs masking but what is genuinely variable: event timestamps, staging
tokens, ``ctime``, ``-V``'s list of plugins and tracebacks' bodies.

Skipped unless ``XGFAL_INTEROP=1``. Run as a script for a report::

    python tests/test_cli_parity.py [case-name-substring...]
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

IMAGE = "gfal-ref:latest"
ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.interop

W = "file:///work/d"
M = "mock://host/path"

#: (name, [argv...], stdin) - argv[0] is the command without ``gfal-`` (or a
#: tool with an ``_`` in its name, run as it is), after any ``NAME=value``
#: environment settings; several argvs run in sequence against the same
#: fixture tree.
CASES: list[tuple[str, list[list[str]], str]] = []


def case(name: str, *commands: list[str], stdin: str = "") -> None:
    CASES.append((name, list(commands), stdin))


for _command in (
    "archivepoll",
    "bringonline",
    "cat",
    "chmod",
    "copy",
    "evict",
    "legacy-bringonline",
    "legacy-register",
    "legacy-replicas",
    "legacy-unregister",
    "ls",
    "mkdir",
    "rename",
    "rm",
    "save",
    "stat",
    "sum",
    "token",
    "xattr",
):
    case(f"help-{_command}", [_command, "--help"])
    case(f"usage-{_command}", [_command, "--no-such-option"])

# -- common -----------------------------------------------------------------------
case("version", ["ls", "-V"])
case("version-copy", ["copy", "--version"])
case("ls-colors-stat", ["LS_COLORS=di=1:a=b=c", "stat", f"{W}/a.txt"])
case("ls-colors-help", ["LS_COLORS=a=b=c:x=y=z", "rm", "--help"])
case("ls-colors-ls", ["LS_COLORS=di=01;34:a=b=c", "ls", "--color=always", W])
case("gfal2_version", ["gfal2_version"])
case("gfal_srm_ifce_version", ["gfal_srm_ifce_version", "--help"])

# -- ls ---------------------------------------------------------------------------
case("ls", ["ls", W])
case("ls-a", ["ls", "-a", W])
case("ls-l", ["ls", "-l", W])
case("ls-la", ["ls", "-la", W])
case("ls-ld", ["ls", "-ld", W])
case("ls-l-file", ["ls", "-l", f"{W}/a.txt"])
case("ls-relative", ["ls", "d"])
case("ls-absolute", ["ls", "/work/d/sub"])
case("ls-iso", ["ls", "-l", "--time-style=iso", W])
case("ls-long-iso", ["ls", "-l", "--time-style", "long-iso", W])
case("ls-full-iso", ["ls", "-l", "--time-style", "full-iso", W])
case("ls-full-time", ["ls", "-l", "--full-time", W])
case("ls-human", ["ls", "-lH", W])
case("ls-color", ["ls", "-l", "--color=always", W])
case("ls-color-short", ["ls", "--color", "always", W])
case("ls-missing", ["ls", f"{W}/nope"])
case("ls-bad-style", ["ls", "--time-style", "nope", W])
case("ls-mock-dir", ["ls", f"{M}?list=a:10,b:20"])
case("ls-mock-file-l", ["ls", "-l", f"{M}?size=10"])
case("ls-mock-errno", ["ls", f"{M}?errno=13"])
case("ls-proto", ["ls", "nope://host/x"])
case("ls-define-bad", ["ls", "-D", "CORE:X", W])
case("ls-define-nogroup", ["ls", "-D", "X=1", W])
case("ls-define-ok", ["ls", "-D", "CORE:NAMESPACE_TIMEOUT=10", "-D", "X:Y=a,b", "-D", "X:Z=yes", W])
case("ls-client-info", ["ls", "-C", "a=b", "-C", "c", "-C", "x=y=z", "-4", "-6", "-t", "0", W])
case("ls-verbose", ["ls", "-vvv", f"{W}/a.txt"])

# -- stat / sum / cat -------------------------------------------------------------
case("stat-file", ["stat", f"{W}/a.txt"])
case("stat-dir", ["stat", f"{W}/sub"])
case("stat-missing", ["stat", f"{W}/nope"])
case("stat-mock", ["stat", f"{M}?size=10"])
case("stat-mock-errno", ["stat", f"{M}?errno=13"])
case("stat-noargs", ["stat"])
case("sum-adler32", ["sum", f"{W}/a.txt", "ADLER32"])
case("sum-adler32-lower", ["sum", f"{W}/a.txt", "adler32"])
case("sum-md5", ["sum", f"{W}/a.txt", "MD5"])
case("sum-crc32", ["sum", f"{W}/a.txt", "CRC32"])
case("sum-sha1", ["sum", f"{W}/a.txt", "SHA1"])
case("sum-missing", ["sum", f"{W}/nope", "ADLER32"])
case("sum-mock", ["sum", f"{M}?checksum=abcd", "ADLER32"])
case("sum-noalg", ["sum", f"{W}/a.txt"])
case("cat", ["cat", f"{W}/a.txt"])
case("cat-two", ["cat", f"{W}/a.txt", f"{W}/sub/b"])
case("cat-bytes", ["cat", "-b", f"{W}/a.txt"])
case("cat-missing", ["cat", f"{W}/nope"])
case("cat-dir", ["cat", f"{W}/sub"])

# -- namespace ------------------------------------------------------------------
case("mkdir", ["mkdir", f"{W}/m"], ["ls", "-ld", f"{W}/m"])
case("mkdir-exists", ["mkdir", f"{W}/sub"])
case("mkdir-p", ["mkdir", "-p", f"{W}/m/n/o"], ["ls", "-d", f"{W}/m/n/o"])
case("mkdir-p-exists", ["mkdir", "-p", f"{W}/sub"])
case("mkdir-noparent", ["mkdir", f"{W}/m/n/o"])
case("mkdir-mode", ["mkdir", "-m", "700", f"{W}/m"], ["stat", f"{W}/m"])
case("mkdir-mode-0", ["mkdir", "-m", "0", f"{W}/m"], ["stat", f"{W}/m"])
case("mkdir-mode-bad", ["mkdir", "-m", "999", f"{W}/m"], ["stat", f"{W}/m"])
case("mkdir-many", ["mkdir", f"{W}/m1", f"{W}/m2"], ["ls", W])
case("rename", ["rename", f"{W}/a.txt", f"{W}/z.txt"], ["ls", W])
case("rename-missing", ["rename", f"{W}/nope", f"{W}/z.txt"])
case("chmod", ["chmod", "600", f"{W}/a.txt"], ["stat", f"{W}/a.txt"])
case("chmod-bad", ["chmod", "xyz", f"{W}/a.txt"])
case("chmod-missing", ["chmod", "600", f"{W}/nope"])
case("save", ["save", f"{W}/s"], ["cat", f"{W}/s"], stdin="saved data\n")
case("save-overwrite", ["save", f"{W}/a.txt"], ["cat", f"{W}/a.txt"], stdin="new\n")
case("save-baddir", ["save", f"{W}/nope/s"], stdin="x\n")

# -- rm -------------------------------------------------------------------------
case("rm", ["rm", f"{W}/a.txt"], ["ls", W])
case("rm-dir", ["rm", f"{W}/sub"])
case("rm-r", ["rm", "-r", f"{W}/sub"], ["ls", W])
case("rm-R-dry", ["rm", "-R", "--dry-run", f"{W}/sub"], ["ls", W])
case("rm-missing-then-ok", ["rm", f"{W}/nope", f"{W}/a.txt"])
case("rm-none", ["rm"])
case("rm-bulk-r", ["rm", "--bulk", "-r", f"{W}/a.txt"])
case("rm-bulk", ["rm", "--bulk", f"{W}/a.txt", f"{W}/nope"])
case("rm-bulk-dry", ["rm", "--bulk", "--dry-run", f"{W}/a.txt"])
case("rm-from-file", ["rm", "--from-file", "/work/list"], ["ls", W])
case("rm-from-file-and-args", ["rm", "--from-file", "/work/list", f"{W}/a.txt"])
case("rm-from-file-missing", ["rm", "--from-file", "/work/nolist"])
case("rm-just-delete", ["rm", "--just-delete", f"{W}/a.txt"])
case("rm-mock-errno", ["rm", f"{M}?errno=13"])
case("rm-relative", ["rm", "d/a.txt"])

# -- copy -----------------------------------------------------------------------
case("copy", ["copy", f"{W}/a.txt", f"{W}/o"], ["cat", f"{W}/o"])
case("copy-exists", ["copy", f"{W}/a.txt", f"{W}/sub/b"])
case("copy-force", ["copy", "-f", f"{W}/a.txt", f"{W}/sub/b"], ["cat", f"{W}/sub/b"])
case("copy-into-dir", ["copy", f"{W}/a.txt", f"{W}/sub"], ["ls", f"{W}/sub"])
case("copy-into-dir-slash", ["copy", f"{W}/a.txt", f"{W}/sub/"])
case("copy-into-dir-exists", ["copy", f"{W}/a.txt", f"{W}/sub"], ["copy", f"{W}/a.txt", f"{W}/sub"])
case("copy-dir-new", ["copy", f"{W}/sub", f"{W}/sub2"], ["ls", f"{W}/sub2"])
case("copy-dir-exists", ["copy", f"{W}/sub", f"{W}/sub/deep"])
case(
    "copy-dir-r-exists",
    ["copy", "-r", f"{W}/sub", f"{W}/sub2"],
    ["copy", "-r", f"{W}/sub", f"{W}/sub2"],
)
case(
    "copy-dir-r-abort",
    ["copy", "-r", f"{W}/sub", f"{W}/s2"],
    ["copy", "-r", "--abort-on-failure", f"{W}/sub", f"{W}/s2"],
)
case("copy-dir-over-file", ["copy", "-f", f"{W}/sub", f"{W}/a.txt"])
case("copy-dry-run", ["copy", "--dry-run", f"{W}/a.txt", f"{W}/o"], ["ls", W])
case("copy-dry-run-r", ["copy", "--dry-run", "-r", f"{W}/sub", f"{W}/o"], ["ls", W])
case("copy-missing", ["copy", f"{W}/nope", f"{W}/o"])
case("copy-parent", ["copy", "-p", f"{W}/a.txt", f"{W}/x/y/z"], ["cat", f"{W}/x/y/z"])
case("copy-noparent", ["copy", f"{W}/a.txt", f"{W}/x/y/z"])
case("copy-stdout", ["copy", f"{W}/a.txt", "-"])
case("copy-stdout-just", ["copy", "--just-copy", f"{W}/a.txt", "-"])
case("copy-devnull", ["copy", f"{W}/a.txt", "file:///dev/null"])
case("copy-relative", ["copy", "d/a.txt", "o"], ["cat", "/work/o"])
case("copy-chain", ["copy", f"{W}/a.txt", f"{W}/c1", f"{W}/sub", f"{W}/c3"], ["ls", W])
case("copy-chain-ls", ["copy", f"{W}/a.txt", f"{W}/c1", f"{W}/sub", f"{W}/c3"], ["ls", f"{W}/sub"])
case("copy-nosrc", ["copy", f"{W}/a.txt"])
case("copy-noargs", ["copy"])
case("copy-from-file", ["copy", "--from-file", "/work/list", f"{W}/sub"], ["ls", f"{W}/sub"])
case("copy-from-file-and-src", ["copy", "--from-file", "/work/list", f"{W}/a.txt", f"{W}/o"])
case("copy-from-file-missing", ["copy", "--from-file", "/work/nolist", f"{W}/o"])
case("copy-K", ["copy", "-K", "ADLER32", f"{W}/a.txt", f"{W}/o"])
case("copy-K-value", ["copy", "-K", "ADLER32:084b021f", f"{W}/a.txt", f"{W}/o"])
case("copy-K-bad", ["copy", "-K", "ADLER32:deadbeef", f"{W}/a.txt", f"{W}/o"], ["ls", W])
case("copy-K-md5", ["copy", "-K", "MD5", "--checksum-mode", "source", f"{W}/a.txt", f"{W}/o"])
case(
    "copy-K-target",
    ["copy", "-K", "ADLER32:084b021f", "--checksum-mode", "target", f"{W}/a.txt", f"{W}/o"],
)
case("copy-K-unsupported", ["copy", "-K", "SHA1", f"{W}/a.txt", f"{W}/o"])
case("copy-just", ["copy", "--just-copy", f"{W}/a.txt", f"{W}/o"])
case("copy-just-exists", ["copy", "--just-copy", f"{W}/a.txt", f"{W}/sub/b"], ["cat", f"{W}/sub/b"])
case(
    "copy-knobs",
    [
        "copy",
        "-n",
        "4",
        "--tcp-buffersize",
        "65536",
        "-s",
        "S",
        "-S",
        "D",
        "-T",
        "60",
        "--disable-cleanup",
        "--no-delegation",
        "--evict",
        "--scitag",
        "65",
        "--copy-mode",
        "streamed",
        f"{W}/a.txt",
        f"{W}/o",
    ],
)
case("copy-copy-mode-pull", ["copy", "--copy-mode", "pull", f"{W}/a.txt", f"{W}/o"])
case("copy-copy-mode-bad", ["copy", "--copy-mode", "nope", f"{W}/a.txt", f"{W}/o"])
case("copy-mock", ["copy", f"{M}/src?size=10&time=0", f"{M}/dst?size_post=10&time=0"])
case(
    "copy-mock-errno",
    ["copy", f"{M}/src?size=10&time=0", f"{M}/dst?size_post=10&time=0&transfer_errno=5"],
)
case("copy-mock-exists", ["copy", f"{M}/src?size=10&time=0", f"{M}/dst?size_pre=4&time=0"])
case("copy-verbose", ["copy", "-v", f"{W}/a.txt", f"{W}/o"])
case("copy-verbose-K", ["copy", "-v", "-K", "ADLER32", f"{W}/a.txt", f"{W}/o"])
case(
    "copy-verbose-mock",
    ["copy", "-v", "-f", f"{M}/src?size=10&time=0", f"{M}/dst?size_post=10&time=0"],
)
case("copy-mock-force", ["copy", "-f", f"{M}/src?size=10&time=0", f"{M}/dst?size_post=10&time=0"])
case("copy-same", ["copy", f"{W}/a.txt", f"{W}/a.txt"])
case("copy-mode", ["copy", f"{W}/a.txt", f"{W}/o"], ["ls", "-l", f"{W}/o"])
case("copy-mock-to-file", ["copy", f"{M}/src?size=10", f"{W}/o"], ["ls", "-l", f"{W}/o"])

# -- xattr / token / tape ----------------------------------------------------------
case("xattr-mock-get", ["xattr", f"{M}?size=1", "user.status"])
case("xattr-mock-get-bad", ["xattr", f"{M}?size=1", "user.nope"])
case("xattr-mock-list", ["xattr", f"{M}?size=1"])
case("xattr-file-set-empty", ["xattr", f"{W}/a.txt", "user.x="])
case("token-mock", ["token", f"{M}?size=1"])
case("ls-mock-dir-l", ["ls", "-l", f"{M}?list=a:0644:10,b:040755:3,c"])
case("rm-mock-bulk-errno", ["rm", "--bulk", f"{M}/b?errno=13"])
case("mkdir-mock-rd-path", ["mkdir", f"{M}/a/?rd_path={M}/a/"])
case("xattr-mock-get-value", ["xattr", f"{M}?user.guid=g", "user.guid"])
case("copy-mock-late-errno", ["copy", "-f", f"{M}/s?size=1", f"{M}/d?time=1&transfer_errno=5"])
case("token-validity", ["token", "--validity=-1", f"{M}?size=1"])
case("bringonline", ["bringonline", f"{M}?size=1"])
case("bringonline-errno", ["bringonline", f"{M}?staging_errno=22"])
case("bringonline-poll", ["bringonline", "--polling-timeout", "4", f"{M}?staging_time=1"])
case("bringonline-none", ["bringonline"])
case("bringonline-both", ["bringonline", "--from-file", "/work/mlist", f"{M}?size=1"])
case("bringonline-from-file", ["bringonline", "--from-file", "/work/mlist"])
case("archivepoll", ["archivepoll", f"{M}?size=1"])
case("archivepoll-errno", ["archivepoll", f"{M}?archiving_errno=22"])
case("archivepoll-poll", ["archivepoll", "--polling-timeout", "3", f"{M}?archiving_time=1"])
case("archivepoll-none", ["archivepoll"])
case("evict", ["evict", f"{M}?size=1"])
case("evict-errno", ["evict", f"{M}?release_errno=22", "tok"])

# -- legacy -----------------------------------------------------------------------
case("legacy-replicas-file", ["legacy-replicas", f"{W}/a.txt"])
case("legacy-replicas-none", ["legacy-replicas"])
case("legacy-register-missing", ["legacy-register", f"{W}/nope", f"{W}/a.txt"])
case("legacy-bringonline", ["legacy-bringonline", f"{M}?size=1"])
case("legacy-bringonline-none", ["legacy-bringonline"])

#: Cases whose outputs differ for a reason outside the CLI (a plugin or the
#: core behaving differently from gfal2), with the reason.
KNOWN: dict[str, str] = {
    # The config-directory and credential lines match gfal2's; what follows
    # them describes gfal2's C internals - scanning /usr/lib64/gfal2-plugins,
    # dlopen()ing every .so up front, davix's set-up - where we load only the
    # Python module a URL needs, and log that instead.
    "ls-verbose": "gfal2 logs loading its C plugins and davix; we log the modules we load",
}

# The driver, run with the image's python3 (3.9).
DRIVER = r"""
import json, os, subprocess, sys

def reset():
    subprocess.run(["rm", "-rf", "/work"], check=True)
    os.makedirs("/work/d/sub/deep")
    files = {"a.txt": "hello\n", "sub/b": "x\n", "sub/deep/c": "y\n", ".hidden": "",
             "big": "z" * 5000}
    for name, text in files.items():
        with open("/work/d/" + name, "w") as handle:
            handle.write(text)
    with open("/work/list", "w") as handle:
        handle.write("file:///work/d/a.txt\n\nfile:///work/d/big\n")
    with open("/work/mlist", "w") as handle:
        handle.write("mock://host/a?size=1\nmock://host/b?staging_errno=2\n")
    subprocess.run("find /work -exec touch -h -d '2020-01-02 03:04:05' {} +", shell=True,
                   check=True)

def run(side, commands, stdin):
    reset()
    results = []
    for argv in commands:
        settings = {}
        while "=" in argv[0]:
            key, value = argv[0].split("=", 1)
            settings[key] = value
            argv = argv[1:]
        if side == "ref":
            full = [argv[0] if "_" in argv[0] else "gfal-" + argv[0]] + argv[1:]
            env = dict(os.environ, **settings)
        else:
            full = ["python3", "-m", "xgfalclient.cli"] + argv
            env = dict(os.environ, PYTHONPATH="/src", **settings)
        proc = subprocess.run(full, input=stdin.encode(), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, cwd="/work", env=env, timeout=120)
        results.append([proc.returncode, proc.stdout.decode("utf-8", "replace"),
                        proc.stderr.decode("utf-8", "replace")])
    return results

cases = json.load(open("/io/cases.json"))
report = {}
for name, commands, stdin in cases:
    report[name] = {"ref": run("ref", commands, stdin), "ours": run("ours", commands, stdin)}
json.dump(report, open("/io/report.json", "w"))
"""

_MASKS = [
    (re.compile(r"\[\d{13}\]"), "[TIMESTAMP]"),
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "<UUID>"),
    (re.compile(r"^Change: .*$", re.M), "Change: <CTIME>"),
    # times of files the case itself created (the fixtures are all 2020-01-02)
    (re.compile(r"^(Access|Modify): (?!2020-01-02).*$", re.M), r"\1: <NOW>"),
    (re.compile(r" [A-Z][a-z]{2} [ \d]\d \d\d:\d\d "), " <NOW> "),
    # -V: the version line is compared; the plugin list is ours (more plugins)
    (re.compile(r"^(gfal2-util version [^\n]*)(?:\n\t[^\n]*)+", re.M), r"\1\n<PLUGINS>"),
    (
        re.compile(
            r"^(Exception in thread [^\n]*\n)?Traceback \(most recent call last\):\n(?:[ \t].*\n)*",
            re.M,
        ),
        "<TRACEBACK>\n",
    ),
]


def mask(text: str) -> str:
    for pattern, replacement in _MASKS:
        text = pattern.sub(replacement, text)
    return text


def run_parity(names: list[str] | None = None) -> dict[str, dict[str, list[list[object]]]]:
    selected = [c for c in CASES if not names or any(n in c[0] for n in names)]
    with tempfile.TemporaryDirectory() as io_dir:
        Path(io_dir, "cases.json").write_text(json.dumps(selected))
        Path(io_dir, "driver.py").write_text(DRIVER)
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                f"xgfal-cli-parity-{os.getpid()}",
                "-e",
                "COLUMNS=80",
                "-e",
                "TZ=UTC",
                "-v",
                f"{ROOT / 'src'}:/src:ro",
                "-v",
                f"{io_dir}:/io",
                IMAGE,
                "python3",
                "/io/driver.py",
            ],
            check=True,
            timeout=1800,
        )
        return json.loads(Path(io_dir, "report.json").read_text())  # type: ignore[no-any-return]


def differences(report: dict[str, dict[str, list[list[object]]]]) -> dict[str, str]:
    import difflib

    found: dict[str, str] = {}
    for name, sides in report.items():
        ref = [[rc, mask(str(out)), mask(str(err))] for rc, out, err in sides["ref"]]
        ours = [[rc, mask(str(out)), mask(str(err))] for rc, out, err in sides["ours"]]
        if ref == ours:
            continue
        lines = []
        for index, (r, o) in enumerate(zip(ref, ours)):
            for label, a, b in (("rc", r[0], o[0]), ("stdout", r[1], o[1]), ("stderr", r[2], o[2])):
                if a != b:
                    diff = difflib.unified_diff(
                        str(a).splitlines(),
                        str(b).splitlines(),
                        "gfal2-util",
                        "xgfalclient",
                        lineterm="",
                        n=1,
                    )
                    lines.append(f"  [{index}] {label}:\n    " + "\n    ".join(diff))
        found[name] = "\n".join(lines)
    return found


@pytest.mark.skipif(os.environ.get("XGFAL_INTEROP") != "1", reason="XGFAL_INTEROP=1 not set")
@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available")
@pytest.mark.timeout(1800)
def test_parity_with_gfal2_util() -> None:
    found = differences(run_parity())
    unexpected = {name: diff for name, diff in found.items() if name not in KNOWN}
    assert not unexpected, "\n".join(f"{name}:\n{diff}" for name, diff in unexpected.items())


if __name__ == "__main__":
    result = differences(run_parity(sys.argv[1:]))
    total = len([c for c in CASES if not sys.argv[1:] or any(n in c[0] for n in sys.argv[1:])])
    for name, diff in result.items():
        print(f"== {name}" + (f"  (known: {KNOWN[name]})" if name in KNOWN else ""))
        print(diff)
    print(f"{total - len(result)}/{total} cases identical; {len(result)} differ")
