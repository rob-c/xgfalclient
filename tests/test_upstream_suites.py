"""Upstream's own tests, run against gfal2 and against this package.

python3-gfal2 1.13.1 ships functional tests (``test/functional``, driven by a
base URL in ``TEST_SRM_BASE`` and friends) and a unit test; gfal2-util 1.9.1
ships functional tests that shell out to ``gfal-*``. Both run here in the
``gfal-ref:latest`` image, once with the real toolkit and once with this
package's ``gfal2`` shim (``src`` mounted on ``PYTHONPATH``), and every test
that passes with gfal2 must pass here too.

The gfal2-python tests are Python 2 (``except E, e``, ``0755``, tabs mixed
with spaces): a file that does not compile under Python 3 has its tabs
expanded as Python 2 read them and, if that is not enough, goes through
``lib2to3`` - the same port for both sides. They also run a second time with
the one Python-2-era API use modernised (``e.code()`` -> ``e.code``), since
as shipped that ``TypeError`` hides most of what they check. They run
against ``file://``, the image's xrootd server (``root://``) and its XrdHttp
(``dav://``). gfal2-util's run against gfal2's scripts, against
``python -m xgfalclient.cli`` and against gfal2's scripts importing the
``gfal2_util`` shim.

Skipped unless ``XGFAL_INTEROP=1`` and the upstream source trees are named
by ``XGFAL_GFAL2_PYTHON_SRC`` and ``XGFAL_GFAL2_UTIL_SRC`` (checkouts of
gfal2-python v1.13.1 and gfal2-util v1.9.1). Run as a script for the table::

    python tests/test_upstream_suites.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

IMAGE = "gfal-ref:latest"
ROOT = Path(__file__).resolve().parent.parent
PYTHON_SRC = os.environ.get("XGFAL_GFAL2_PYTHON_SRC", "")
UTIL_SRC = os.environ.get("XGFAL_GFAL2_UTIL_SRC", "")

pytestmark = [
    pytest.mark.interop,
    pytest.mark.skipif(os.environ.get("XGFAL_INTEROP") != "1", reason="XGFAL_INTEROP=1 not set"),
    pytest.mark.skipif(
        not (PYTHON_SRC and UTIL_SRC),
        reason="XGFAL_GFAL2_PYTHON_SRC / XGFAL_GFAL2_UTIL_SRC not set",
    ),
]

#: Runs one base URL's worth of the (ported) gfal2-python tests in the
#: current interpreter and prints ``{test: "pass" | "FAIL" | "ERROR"}``.
RUNNER = r"""
import io, json, os, subprocess, sys, time, unittest
func, base = sys.argv[1:3]
sys.path.insert(0, func)
os.chdir(func)
os.environ.update(TEST_SRM_BASE=base + "/", TEST_FILE_CONTENT="Hello world",
                  TEST_SRM_LSTAT_VALID=base + "/teststat0011",
                  TEST_SRM_READ_VALID=base + "/testread0011")
results = {}

class Result(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test); results[test.id()] = "pass"
    def addFailure(self, test, err):
        super().addFailure(test, err); results[test.id()] = "FAIL"
    def addError(self, test, err):
        super().addError(test, err); results[test.id()] = "ERROR"

for name in ("test_gfal2_lstat", "test_gfal2_stat", "test_gfal2_open", "test_gfal2_mkrmdir",
             "test_gfal2_listdir", "test_gfal2_rename", "test_gfal2_link", "test_gfal2_xattr"):
    suite = unittest.defaultTestLoader.loadTestsFromName(name)
    unittest.TextTestRunner(stream=io.StringIO(), resultclass=Result).run(suite)

import gfal2
ctx = gfal2.creat_context()
victim = base + "/unlink_me_%s" % time.time()
handle = ctx.open(victim, "w"); handle.write(b"x"); del handle
code = subprocess.run([sys.executable, "test_gfal2_unlink.py", victim],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
try:
    ctx.stat(victim); gone = False
except gfal2.GError as exc:
    gone = exc.code == 2
results["test_gfal2_unlink.py"] = "pass" if code == 0 and gone else "FAIL"
code = subprocess.run([sys.executable, "test_gfal2_copy.py", base + "/testread0011",
                       base + "/copy_%s" % time.time()],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
results["test_gfal2_copy.py"] = "pass" if code == 0 else "FAIL"
print(json.dumps(results))
"""

#: Runs one unittest module in the current interpreter and prints
#: ``{test id: outcome}`` - unittest's ``-v`` output cannot be parsed for a
#: test with a docstring.
MODULE_RUNNER = r"""
import io, json, sys, unittest
sys.path.insert(0, ".")
results = {}

class Result(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test); results[test.id()] = "pass"
    def addFailure(self, test, err):
        super().addFailure(test, err); results[test.id()] = "FAIL"
    def addError(self, test, err):
        super().addError(test, err); results[test.id()] = "ERROR"

suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[1])
unittest.TextTestRunner(stream=io.StringIO(), resultclass=Result).run(suite)
print(json.dumps(results))
"""

#: The driver, run with the image's python3 (3.9).
DRIVER = r"""
import glob, json, os, shutil, subprocess, sys, time

def sh(command):
    subprocess.run(command, shell=True, check=True)

def module(side, directory, name, env):
    proc = subprocess.run([sys.executable, "/io/module_runner.py", name], cwd=directory, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=900)
    lines = proc.stdout.decode().strip().splitlines()
    return json.loads(lines[-1]) if lines else {"(did not run) " + name: "ERROR"}

def port(directory):
    for path in sorted(glob.glob(directory + "/**/*.py", recursive=True)):
        text = open(path).read()
        try:
            compile(text, path, "exec")
            continue
        except SyntaxError:
            pass
        open(path, "w").write(text.expandtabs(8))
        try:
            compile(open(path).read(), path, "exec")
            continue
        except SyntaxError:
            pass
        subprocess.run([sys.executable, "-m", "lib2to3", "-w", "-n", path], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

shutil.copytree("/upstream/python/test", "/work/py")
port("/work/py")
shutil.copytree("/work/py/functional", "/work/pymod")
for path in glob.glob("/work/pymod/*.py"):
    text = open(path).read()
    open(path, "w").write(text.replace("e.code()", "e.code"))

sh("mkdir -p /data /etc/xrd && (useradd -m xrd 2>/dev/null || true) && chown xrd /data")
open("/etc/xrd/x.cfg", "w").write(
    "all.export /\noss.localroot /data\nall.role server\nxrd.port 1094\n"
    "xrd.protocol XrdHttp:8080 libXrdHttp.so\n")
sh("su xrd -s /bin/bash -c 'xrootd -b -l /tmp/xrd.log -c /etc/xrd/x.cfg'")
time.sleep(2)
for root in ("/work/fbase", "/data/gt", "/data/gh"):
    os.makedirs(root)
    for name in ("teststat0011", "testread0011"):
        open(root + "/" + name, "w").write("Hello world")
    sh("chown -R xrd:xrd " + root)  # the tests want a stat with uid != 0
BASES = {"file": "file:///work/fbase", "root": "root://localhost:1094//gt",
         "dav": "dav://localhost:8080/gh"}
SIDES = {"real": dict(os.environ),
         "ours": dict(os.environ, PYTHONPATH="/src:/xrdclient")}

report = {"python": {}, "unit": {}, "util": {}}
for side, env in SIDES.items():
    for label, base in BASES.items():
        for variant, func in (("", "/work/py/functional"), ("-mod", "/work/pymod")):
            proc = subprocess.run([sys.executable, "/io/runner.py", func, base], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=600)
            lines = proc.stdout.decode().strip().splitlines()
            found = json.loads(lines[-1]) if lines else {"(did not run)": "ERROR"}
            for test, outcome in found.items():
                report["python"].setdefault(label + variant + " " + test, {})[side] = outcome
    for test, outcome in module(side, "/work/py/unit", "creat_instance_all", env).items():
        report["unit"].setdefault(test, {})[side] = outcome

# gfal2-util: utils.run_command runs <tests>/../../src/<command>.
for variant, env in (("real", SIDES["real"]), ("ours-cli", SIDES["ours"]),
                     ("ours-scripts", SIDES["ours"])):
    top = "/work/u-" + variant
    shutil.copytree("/upstream/util/test", top + "/test")
    os.makedirs(top + "/src")
    for script in glob.glob("/usr/bin/gfal-*"):
        name = os.path.basename(script)
        target = top + "/src/" + name
        if variant == "ours-cli":
            open(target, "w").write(
                '#!/bin/sh\nexec python3 -m xgfalclient.cli %s "$@"\n' % name)
            os.chmod(target, 0o755)
        else:
            os.symlink(script, target)  # gfal2's scripts; with the shim on PYTHONPATH for ours
    for test, outcome in module(variant, top + "/test/functional", "test_all", env).items():
        report["util"].setdefault(test, {})[variant] = outcome
    sh("rm -rf /tmp/make /tmp/f1_* /tmp/f2_* /tmp/test_*")
json.dump(report, open("/io/report.json", "w"))
"""


def _xrdclient_src() -> Path:
    import xrdclient

    return Path(xrdclient.__file__).resolve().parent.parent


def run_suites() -> dict[str, dict[str, dict[str, str]]]:
    """Both toolkits through upstream's tests: ``{suite: {test: {side: outcome}}}``."""
    with tempfile.TemporaryDirectory() as io_dir:
        Path(io_dir, "driver.py").write_text(DRIVER)
        Path(io_dir, "runner.py").write_text(RUNNER)
        Path(io_dir, "module_runner.py").write_text(MODULE_RUNNER)
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                f"xgfal-upstream-{os.getpid()}",
                "-v",
                f"{ROOT / 'src'}:/src:ro",
                "-v",
                f"{_xrdclient_src()}:/xrdclient:ro",
                "-v",
                f"{PYTHON_SRC}:/upstream/python:ro",
                "-v",
                f"{UTIL_SRC}:/upstream/util:ro",
                "-v",
                f"{io_dir}:/io",
                IMAGE,
                "python3",
                "/io/driver.py",
            ],
            check=True,
            timeout=3600,
        )
        return json.loads(Path(io_dir, "report.json").read_text())  # type: ignore[no-any-return]


def regressions(report: dict[str, dict[str, dict[str, str]]]) -> list[str]:
    """Every test gfal2 passes and one of our sides does not."""
    found = []
    for suite, tests in report.items():
        for test, sides in sorted(tests.items()):
            if sides.get("real") != "pass":
                continue
            for side, outcome in sorted(sides.items()):
                if side != "real" and outcome != "pass":
                    found.append(f"{suite}: {test}: {side} {outcome}")
    return found


@pytest.fixture(scope="module")
def report() -> dict[str, dict[str, dict[str, str]]]:
    return run_suites()


def test_the_harness_ran_every_suite(report: dict[str, dict[str, dict[str, str]]]) -> None:
    passed = {
        suite: sum(sides.get("real") == "pass" for sides in tests.values())
        for suite, tests in report.items()
    }
    # A broken port or fixture would pass vacuously; these are gfal2's own counts.
    assert passed["python"] >= 38 and passed["unit"] == 4 and passed["util"] == 23, passed


def test_whatever_passes_with_gfal2_passes_here(
    report: dict[str, dict[str, dict[str, str]]],
) -> None:
    assert regressions(report) == []


if __name__ == "__main__":
    found: Any = run_suites()
    for suite, tests in found.items():
        for test, sides in sorted(tests.items()):
            cells = " ".join(f"{side}={outcome}" for side, outcome in sorted(sides.items()))
            print(f"{suite:6} {test:70} {cells}")
    problems = regressions(found)
    print("\n".join(problems) or "no regressions")
    sys.exit(1 if problems else 0)
