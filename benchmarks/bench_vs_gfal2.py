"""Head-to-head: the same operations through gfal2-python and through xgfalclient.

Each (library, case) pair runs in a fresh interpreter, so neither pays for
the other's imports or warm connections. Contenders alternate who runs first
in every paired round, and a gated result needs both the requested median
speedup and a one-sided sign-test win. Data cases are MiB/s, metadata cases
operations per second; higher is better throughout.

Run it next to the servers - in the same container network - never through
Docker Desktop's port forwarding, which caps any client near 50 MiB/s::

    python3 benchmarks/bench_vs_gfal2.py --base davs://server:8443/data/bench \\
        --size 1024 --repeat 5 --json results.json

    python3 benchmarks/bench_vs_gfal2.py --base davs://server:8443/data/bench \\
        --repeat 9 --gate --min-ratio 1.10

``--base`` is a writable directory URL on the server under test; the
harness creates or updates its own ``bench*`` fixtures there.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import subprocess
import sys
import tempfile
import time

CASES = ("download", "upload", "stat", "listdir", "checksum")
GATED_CASES = ("download", "upload", "stat", "listdir")

#: One case, run inside a child interpreter. ``lib`` is gfal2 or xgfalclient.
CHILD = r"""
import json, os, sys, time
lib, case, base, local, size, count = sys.argv[1:7]
size, count = int(size), int(count)
if lib == "xgfalclient":
    import xgfalclient as gfal2
else:
    import gfal2
    if gfal2.creat_context.__module__.startswith("xgfalclient"):
        raise RuntimeError("import gfal2 resolved to xgfalclient's shim, not python3-gfal2")
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
    code = f"import {lib} as candidate"
    if lib == "gfal2":
        code += (
            "; import sys; sys.exit(1 if "
            "candidate.creat_context.__module__.startswith('xgfalclient') else 0)"
        )
    probe = subprocess.run([sys.executable, "-c", code], capture_output=True, check=False)
    return probe.returncode == 0


def sign_test(successes: int, trials: int) -> float:
    """One-sided probability of at least ``successes`` fair-coin wins."""
    return float(
        sum(math.comb(trials, count) for count in range(successes, trials + 1)) / 2**trials
    )


def verdict(
    samples: dict[str, list[float]], minimum_ratio: float, alpha: float
) -> dict[str, float | int | bool]:
    """Whether xgfalclient beats native gfal2 reliably and by the requested ratio."""
    ours, reference = samples["xgfalclient"], samples["gfal2"]
    ratio = statistics.median(ours) / statistics.median(reference)
    wins = sum(ours_value > reference_value for ours_value, reference_value in zip(ours, reference))
    probability = sign_test(wins, len(ours))
    return {
        "passed": ratio >= minimum_ratio and probability <= alpha,
        "ratio": ratio,
        "wins": wins,
        "rounds": len(ours),
        "p": probability,
    }


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


def parse_args(argv: list[str] | None) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    """The command line and its parser, kept together so validation can use ``error``."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True, help="writable directory URL on the server")
    parser.add_argument("--size", type=int, default=256, help="file size in MiB")
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--count", type=int, default=200, help="operations per metadata run")
    parser.add_argument("--entries", type=int, default=500, help="files in the listed directory")
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--gate", action="store_true", help="fail unless every gated case wins")
    parser.add_argument(
        "--gate-cases",
        default=",".join(GATED_CASES),
        help="comma-separated cases enforced by --gate (server-side checksum is report-only)",
    )
    parser.add_argument(
        "--min-ratio",
        type=float,
        default=1.05,
        help="minimum median xgfalclient/gfal2 speed ratio for gated cases",
    )
    parser.add_argument("--alpha", type=float, default=0.05, help="sign-test threshold")
    parser.add_argument("--json", help="write the results here too")
    return parser, parser.parse_args(argv)


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Reject nonsensical sample and statistical parameters before doing I/O."""
    for option in ("size", "repeat", "count", "entries"):
        if getattr(args, option) < 1:
            parser.error(f"--{option} must be positive")
    if args.min_ratio <= 1.0:
        parser.error("--min-ratio must be greater than 1")
    if not 0.0 < args.alpha < 1.0:
        parser.error("--alpha must be between 0 and 1")


def selection(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> tuple[list[str], list[str], set[str]]:
    """Available libraries, requested cases and the subset the gate enforces."""
    validate_args(parser, args)
    libs = [lib for lib in ("gfal2", "xgfalclient") if available(lib)]
    if args.gate and libs != ["gfal2", "xgfalclient"]:
        parser.error(
            "--gate needs native python3-gfal2 and xgfalclient; the gfal2 shim is rejected"
        )
    cases = [case.strip() for case in args.cases.split(",") if case.strip()]
    unknown = set(cases) - set(CASES)
    if unknown:
        parser.error(f"unknown cases: {', '.join(sorted(unknown))}")
    gated = {case.strip() for case in args.gate_cases.split(",") if case.strip()}
    missing = gated - set(cases)
    if args.gate and missing:
        parser.error(f"gated cases were not selected: {', '.join(sorted(missing))}")
    return libs, cases, gated


def local_file(path: str, size_mib: int) -> None:
    """Write a source file without allocating the entire benchmark payload."""
    with open(path, "wb") as handle:
        chunk = os.urandom(1 << 20)
        for _ in range(size_mib):
            handle.write(chunk)


def measure(
    args: argparse.Namespace, libs: list[str], cases: list[str]
) -> dict[str, dict[str, list[float]]]:
    """Run paired, rotating rounds and return every raw sample."""
    with tempfile.TemporaryDirectory() as scratch:
        local = os.path.join(scratch, "bench.bin")
        local_file(local, args.size)
        prepare(args.base, local, args.size, args.entries)
        results: dict[str, dict[str, list[float]]] = {}
        firsts: dict[str, list[float]] = {lib: [] for lib in libs}
        for case in cases:
            results[case] = {lib: [] for lib in libs}
            for round_index in range(args.repeat):
                order = libs[round_index % len(libs) :] + libs[: round_index % len(libs)]
                for lib in order:
                    answer = run_child(lib, case, args.base, local, args.size, args.count)
                    results[case][lib].append(answer["value"])
                    firsts[lib].append(answer["first_ms"])
                    time.sleep(0.5)
        results["first_op"] = firsts
        return results


def case_verdicts(
    results: dict[str, dict[str, list[float]]],
    gated: set[str],
    minimum_ratio: float,
    alpha: float,
) -> dict[str, dict[str, float | int | bool]]:
    """Verdicts for cases where both contenders produced samples."""
    return {
        case: verdict(results[case], minimum_ratio, alpha)
        for case in gated
        if set(results[case]) == {"gfal2", "xgfalclient"}
    }


def print_report(
    results: dict[str, dict[str, list[float]]],
    verdicts: dict[str, dict[str, float | int | bool]],
) -> None:
    """Human-readable sample ranges and gate decisions."""
    unit = {"download": "MiB/s", "upload": "MiB/s", "first_op": "ms (lower is better)"}
    print(f"{'case':<10} {'library':<12} {'median':>10} {'min':>10} {'max':>10}  unit")
    for case, by_lib in results.items():
        for lib, samples in by_lib.items():
            print(
                f"{case:<10} {lib:<12} {statistics.median(samples):>10.1f} "
                f"{min(samples):>10.1f} {max(samples):>10.1f}  {unit.get(case, 'ops/s')}"
            )
        outcome = verdicts.get(case)
        if outcome is not None:
            status = "PASS" if outcome["passed"] else "FAIL"
            print(
                f"{'':<10} {'gate':<12} {float(outcome['ratio']):>9.2f}x "
                f"p={float(outcome['p']):.3f} {status}"
            )


def write_report(
    path: str,
    args: argparse.Namespace,
    results: dict[str, dict[str, list[float]]],
    verdicts: dict[str, dict[str, float | int | bool]],
) -> None:
    """Machine-readable raw samples, parameters and verdicts."""
    document = {
        "base": args.base,
        "size_mib": args.size,
        "minimum_ratio": args.min_ratio,
        "alpha": args.alpha,
        "results": results,
        "verdicts": verdicts,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser, args = parse_args(argv)
    libs, cases, gated = selection(parser, args)
    results = measure(args, libs, cases)
    verdicts = case_verdicts(results, gated, args.min_ratio, args.alpha)
    print_report(results, verdicts)
    if args.json:
        write_report(args.json, args, results, verdicts)
    lost = [case for case, outcome in verdicts.items() if not outcome["passed"]]
    return 1 if args.gate and lost else 0


if __name__ == "__main__":
    sys.exit(main())
