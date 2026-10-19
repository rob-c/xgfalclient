# Platforms and deployment packages

Both clients use the [shared platform matrix and package builder](https://rob-c.github.io/xrdclient/platforms/),
which live in [xrd-devtools](https://github.com/rob-c/xrd-devtools) with the
rest of the chain's tooling; `.github/workflows/platforms.yml` here only calls
xrd-devtools' reusable workflow with this commit.
It covers AlmaLinux 8/9/10, Ubuntu 24.04/26.04, CentOS Stream 9/10, Fedora 44
and Rawhide, NixOS 26.05 and Homebrew on macOS Intel/Apple Silicon, on both
x86-64 and ARM64.

The Linux jobs build wheels/sdists and RPMs or DEBs, install offline from binary
dependencies, run all installed commands and the full hermetic suites as a
non-root user, and verify removal. GFAL's native package adds only its own
files to Xrd's private runtime and requires the exact matching Xrd release.
This does not alter system Python, trust files or credentials.

Run from a directory containing the chain's source checkouts and
xrd-devtools:

```console
PYTHONPATH=xrd-devtools/src python3 -m xrddevtools platforms --workspace . --platform alma9 --output results
```

The Nix build of this checkout (`packaging/default.nix`) is xrd-devtools'
expression applied to it; pass both other checkouts:
`nix-build packaging --arg devtoolsSrc ../xrd-devtools --arg xrdclientSrc ../xrdclient`
(or build `xrd-devtools/packaging/nix -A xgfalclient` from the workspace).

The [shared guide](https://rob-c.github.io/xrdclient/platforms/) describes the
native NixOS VM and Homebrew jobs, package rebuild/security-update policy,
artifact inventories, and limitations of container versus full-OS tests.

From 0.4.0 the floor is Python 3.11 (tested 3.11 to 3.14); 0.3.0 was the last
release declaring 3.9 and 0.3.2 the last for 3.10 (the floor 0.3.1 set, since
on 3.9 botocore pins `urllib3<1.27`). AlmaLinux/RHEL 8 and 9 and Stream 9 keep an older
system Python, so their jobs use AppStream Python 3.12 explicitly; AppStream
`python3.11` works too. The system `python3` there (3.6 on EL8, 3.9 on EL9) is
not supported. Native Kerberos remains an optional extra and may require
compilation on Linux. Private RPM/DEB bundles and custom-tap formulae are not
claims of acceptance into distribution archives or Homebrew Core.

On 2026-10-05, the paired 0.3.0 candidates passed all nine RPM/DEB targets
natively on ARM64 (including Fedora Rawhide on Python 3.15), real-VM installs
on AlmaLinux 9 and Ubuntu 24.04, the Nix package builds with a booted aarch64
NixOS VM test, and Apple Silicon Homebrew installation and tests. x86-64 ran
under emulation locally; the hosted x86-64 runners are the authority for
that architecture. Those artifacts predate the 0.4.0 Python floor change:
rebuild and validate the final paired 0.4.0 artifacts before release. See the
shared guide for the exact validation scope and skipped optional tests.
