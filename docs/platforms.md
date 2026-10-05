# Platforms and deployment packages

Both clients use the [shared platform matrix and package builder](https://rob-c.github.io/xrdclient/platforms/).
It covers AlmaLinux 8/9/10, Ubuntu 24.04/26.04, CentOS Stream 9/10, Fedora 44
and Rawhide, NixOS 26.05 and Homebrew on macOS Intel/Apple Silicon, on both
x86-64 and ARM64.

The Linux jobs build wheels/sdists and RPMs or DEBs, install offline from binary
dependencies, run all installed commands and the full hermetic suites as a
non-root user, and verify removal. GFAL's native package adds only its own
files to Xrd's private runtime and requires the exact matching Xrd release.
This does not alter system Python, trust files or credentials.

Run from a directory containing both source checkouts:

```console
python3 xrdclient/tools/platforms.py --workspace . --platform alma9 --output results
```

The [shared guide](https://rob-c.github.io/xrdclient/platforms/) describes the
native NixOS VM and Homebrew jobs, package rebuild/security-update policy,
artifact inventories, and limitations of container versus full-OS tests.

Python 3.9 is still declared but its botocore/urllib3 dependency conflict
means a clean 3.9 install does not resolve; use 3.10 or newer until the floor
is corrected. AlmaLinux 8/9 and Stream 9 jobs use AppStream Python
3.12 explicitly. Native Kerberos remains an optional extra and may require
compilation on Linux. Private RPM/DEB bundles and custom-tap formulae are not
claims of acceptance into distribution archives or Homebrew Core.

On 2026-10-05, the paired 0.3.0 candidates passed all nine RPM/DEB targets
natively on ARM64 (including Fedora Rawhide on Python 3.15), real-VM installs
on AlmaLinux 9 and Ubuntu 24.04, the Nix package builds with a booted aarch64
NixOS VM test, and Apple Silicon Homebrew installation and tests. x86-64 ran
under emulation locally; the hosted x86-64 runners are the authority for
that architecture. See the shared guide for the exact validation scope,
skipped optional tests and the Python 3.9 limitation.
