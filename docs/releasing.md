# Releasing

A release is made from one reviewed commit. The version tag, source version,
built metadata and installed runtime must all agree.

The current candidate is **0.4.0**, requiring `xrdclient==0.4.0` and `xrdcore`, `xrdsec`,
`xrdhttp` `>=0.4.0,<0.5`; the latest
published release is 0.3.2 (`xrdclient==0.3.2`, Python 3.10 floor). Keep a
version's changelog entry `Unreleased` until its release is approved. Python
3.11 is the declared floor; every version from 3.11 to 3.14 must pass. See [Platforms](platforms.md) for outstanding
native-platform checks and the scope of pre-version-bump validation.

## Prepare

1. Work from a clean checkout and review every untracked file.
2. Set `__version__` in `src/xgfalclient/_version.py`. Hatch reads the same
   value; `gfal2.__version__` is a compatibility version and must not be
   changed to the xgfalclient release.
3. Replace `Unreleased` on the version's changelog heading with the date.
4. Run all unit, branch and condition coverage jobs, every supported Python
   version, the strict documentation build and the performance gate.
5. Run the real-service interop suite. For transfer, retry or filesystem
   changes, run both BRIX suites described in [Developing](DEVELOPING.md).
6. Release the libraries (`xrdcore`, then `xrdsec` and `xrdhttp`) and the
   exact-pinned `xrdclient` version first. They supply the shared security,
   parsing and HTTP APIs and must be available on PyPI before xgfalclient is
   tagged. Update the dependency pins when those APIs change.
7. Run the [shared platform/package matrix](platforms.md) with matching
   candidate refs. Build and validate fresh release artifacts, including the exact
   native-package dependency and installed command versions; older
   working-tree packages are not final release artifacts.

## Validate the artifacts

Build into an empty temporary directory and install the wheel, rather than the
source tree, for the final smoke test:

```console
$ release_root=$(mktemp -d)
$ python -m build --outdir "$release_root/dist"
$ twine check --strict "$release_root"/dist/*
$ python -m venv "$release_root/smoke"
$ "$release_root/smoke/bin/python" -m pip install "$release_root"/dist/*.whl
$ "$release_root/smoke/bin/python" - <<'PY'
import importlib.metadata
import gfal2
import gfal2_util
import xgfalclient

assert importlib.metadata.version("xgfalclient") == xgfalclient.VERSION
assert gfal2.get_version() == "2.23.5"
print(xgfalclient.VERSION, gfal2.__version__, gfal2_util.__name__)
PY
```

Inspect the file lists. The wheel must include all three `py.typed` markers
and the generated man pages, and neither artifact may include credentials,
caches, coverage data or local configuration.

## Publish and verify

Push an annotated `v<version>` tag only after every required job is green.
The tag workflow (`.github/workflows/publish.yml`) builds with xrd-devtools'
shared `publish` action (the same steps for every package of the chain; only
the PyPI upload stays in this workflow, as trusted publishing requires). It
rebuilds the artifacts and runs `twine check --strict`, then runs
xrd-devtools' `chain_preflight.py pypi dist/*.whl` (a plain script needing
only `packaging`), which refuses to
continue unless the wheel's exact `xrdclient==` pin and the libraries' lower
bounds are downloadable from PyPI as wheels. Next it installs the wheel with `--only-binary=:all:` from PyPI
alone, never a checkout, and runs `pip check` and the tag, changelog and
gfal2-version checks. Only then does it upload, through PyPI trusted
publishing. The chain's runbook is xrdclient's `docs/releasing.md`
(*Releasing the 0.4.0 chain*, step 4). After publication, install from PyPI in a clean environment and
run one local copy plus one disposable remote transfer before announcing the
release.
