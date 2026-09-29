"""Head-to-head: the same operations through gfal2-python and through xgfalclient.

Each (library, case) pair runs in a fresh interpreter, so neither pays for
the other's imports or warm connections, and each case is repeated and
reported as a median with its range. Data cases are MiB/s, metadata cases
operations per second; higher is better throughout.

Run it next to the servers - in the same container network - never through
Docker Desktop's port forwarding, which caps any client near 50 MiB/s::

    python3 benchmarks/bench_vs_gfal2.py --base davs://server:8443/data/bench \\
        --size 1024 --repeat 5 --json results.json

``--base`` is a writable directory URL on the server under test; the
harness creates its own files there and removes them afterwards.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time

CASES = ("download", "upload", "stat", "listdir", "checksum")

#: One case, run inside a child interpreter. ``lib`` is gfal2 or xgfalclient.
CHILD = r"""
import json, os, sys, time
lib, case, base, local, size, count = sys.argv[1:7]
size, count = int(size), int(count)
if lib == "xgfalclient":
    import xgfalclient as gfal2
else:
    import gfal2
ctx = gfal2.creat_context()
params = ctx.transfer_parameters()
params.overwrite = True
params.timeout = 3600
remote = base + "/bench.bin"
# gfal2 loads every plugin inside creat_context(), before any timer starts;
# xgfalclient loads a plugin the first time its scheme is used. One untimed
# operation puts both in the same state; that first operation's own cost is
# reported separately as "first_ms".
first = time.perf_counter()
ctx.stat(remote)
first_ms = (time.perf_counter() - first) * 1000
started = time.perf_counter()
if case == "download":
    ctx.filecopy(params, remote, "file://" + local + ".down")
    value = size / (time.perf_counter() - started)
elif case == "upload":
    ctx.filecopy(params, "file://" + local, base + "/bench-up.bin")
    value = size / (time.perf_counter() - started)
elif case == "stat":
    for _ in range(count):
        ctx.stat(remote)
    value = count / (time.perf_counter() - started)
elif case == "listdir":
    for _ in range(count):
        ctx.listdir(base + "/many")
    value = count / (time.perf_counter() - started)
elif case == "checksum":
    for _ in range(count):
        ctx.checksum(remote, "adler32")
    value = count / (time.perf_counter() - started)
print(json.dumps({"value": value, "first_ms": first_ms}))
"""


def run_child(
    lib: str, case: str, base: str, local: str, size_mib: int, count: int
) -> dict[str, float]:
    result = subprocess.run(
        [sys.executable, "-c", CHILD, lib, case, base, local, str(size_mib), str(count)],
        capture_output=True,
        text=True,
        timeout=3600,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{lib} {case} failed:\n{result.stderr[-2000:]}")
    return json.loads(result.stdout.strip().splitlines()[-1])  # type: ignore[no-any-return]


def available(lib: str) -> bool:
    probe = subprocess.run(
        [sys.executable, "-c", f"import {lib}"], capture_output=True, check=False
    )
    return probe.returncode == 0


def prepare(base: str, local: str, size_mib: int, entries: int) -> None:
    """Put the fixtures on the server with xgfalclient (either library would do)."""
    import xgfalclient as gfal2

    ctx = gfal2.creat_context()
    params = ctx.transfer_parameters()
    params.overwrite = True
    ctx.mkdir_rec(base + "/many", 0o755)
    ctx.filecopy(params, "file://" + local, base + "/bench.bin")
    existing = set(ctx.listdir(base + "/many"))
    small = local + ".small"
    with open(small, "wb") as handle:
        handle.write(b"x")
    for index in range(entries):
        name = f"f{index:05d}"
        if name not in existing:
            ctx.filecopy(params, "file://" + small, f"{base}/many/{name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True, help="writable directory URL on the server")
    parser.add_argument("--size", type=int, default=256, help="file size in MiB")
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--count", type=int, default=200, help="operations per metadata run")
    parser.add_argument("--entries", type=int, default=500, help="files in the listed directory")
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--json", help="write the results here too")
    args = parser.parse_args(argv)

    libs = [lib for lib in ("gfal2", "xgfalclient") if available(lib)]
    with tempfile.TemporaryDirectory() as scratch:
        local = os.path.join(scratch, "bench.bin")
        with open(local, "wb") as handle:
            chunk = os.urandom(1 << 20)
            for _ in range(args.size):
                handle.write(chunk)
        prepare(args.base, local, args.size, args.entries)
        results: dict[str, dict[str, list[float]]] = {}
        firsts: dict[str, list[float]] = {lib: [] for lib in libs}
        for case in args.cases.split(","):
            for lib in libs:
                samples = []
                for _ in range(args.repeat):
                    answer = run_child(lib, case, args.base, local, args.size, args.count)
                    samples.append(answer["value"])
                    firsts[lib].append(answer["first_ms"])
                    time.sleep(0.5)
                results.setdefault(case, {})[lib] = samples
        results["first_op"] = firsts
    unit = {"download": "MiB/s", "upload": "MiB/s", "first_op": "ms (lower is better)"}
    print(f"{'case':<10} {'library':<12} {'median':>10} {'min':>10} {'max':>10}  unit")
    for case, by_lib in results.items():
        for lib, samples in by_lib.items():
            print(
                f"{case:<10} {lib:<12} {statistics.median(samples):>10.1f} "
                f"{min(samples):>10.1f} {max(samples):>10.1f}  {unit.get(case, 'ops/s')}"
            )
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(
                {"base": args.base, "size_mib": args.size, "results": results}, handle, indent=2
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
