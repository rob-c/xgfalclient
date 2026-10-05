# Platforms and deployment packages

Both clients use the [shared platform matrix and package builder](https://rob-c.github.io/xrdclient/platforms/).
It covers AlmaLinux 8/9/10, Ubuntu 24.04/26.04, CentOS Stream 9/10, Fedora 44,
NixOS 26.05 and Homebrew on macOS Intel/Apple Silicon.

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
remains a release blocker. AlmaLinux 8/9 and Stream 9 jobs use AppStream Python
3.12 explicitly. Native Kerberos remains an optional extra and may require
compilation on Linux. Private RPM/DEB bundles and custom-tap formulae are not
claims of acceptance into distribution archives or Homebrew Core.

On 2026-10-05, both working-tree candidates passed all eight RPM/DEB
targets, Nix package builds and Intel Homebrew installation tests. These
artifacts carried version 0.2.0 before the development bump to 0.3.0; they
included the pending changes, not just the published 0.2.0 tag. Rebuild and
validate the final paired 0.3.0 artifacts before release. Apple
Silicon and a booted NixOS VM still require CI verification. See the shared
guide for the exact validation scope, skipped optional tests and remaining
Python 3.9 release blocker.
