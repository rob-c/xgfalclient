# Releasing

A release is made from one reviewed commit. The version tag, source version,
built metadata and installed runtime must all agree.

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
6. Release the required `xrdclient` version first when the `xrootd` extra's
   lower bound changes.

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
The tag workflow rebuilds and smoke-tests the artifacts, then uses PyPI trusted
publishing. After publication, install from PyPI in a clean environment and
run one local copy plus one disposable remote transfer before announcing the
release.
