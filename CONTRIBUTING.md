# Contributing to xgfalclient

The project has two compatibility targets: the `gfal2` Python API and the
observable behaviour of gfal2/gfal2-util 2.23.5/1.9.1. Improvements must keep
those contracts while preserving a dependency-free core and a faster data
plane.

## Development setup

Use a virtual environment so the replacement `gfal2` package cannot shadow a
system `python3-gfal2` installation.

```console
$ python3 -m venv .venv
$ .venv/bin/python -m pip install -U pip
$ .venv/bin/python -m pip install -e '.[dev,docs,xrootd]'
$ .venv/bin/pytest -q -m 'not interop'
```

The ordinary suite uses in-process protocol servers and blocks accidental
external network access. Real-service tests are marked `interop` and require
`XGFAL_INTEROP=1`.

## Definition of done

A change is ready when:

- its success, failure, cancellation and cleanup paths are tested at the
  public `gfal2` boundary;
- wire changes are exercised against an independent test server and, where
  practical, the reference gfal2 stack;
- line, branch and condition coverage remain complete;
- Ruff, formatting, `mypy --strict` and Complexipy pass without weakening a
  rule or increasing the checked-in complexity snapshot;
- public behaviour, configuration and deliberate compatibility differences
  are documented; and
- transfer-path changes pass the paired performance gate and the relevant
  BRIX fault suite.

The detailed invariants and commands live in
[Developing xgfalclient](docs/DEVELOPING.md).

## Compatibility decisions

Probe the reference container before copying folklore about gfal2 behaviour.
A deliberate safety improvement is welcome, but it needs a focused test and a
prominent note under “Where it differs from gfal2.” Do not silently change an
error code, callback order, return shape or command-line spelling.

Keep production imports in `src/xgfalclient` standard-library-only. Optional
integrations must be lazy and must have a working pure-Python or system-library
path described in the developer guide.

## Documentation and releases

Docstrings explain contracts and non-obvious choices, not syntax. Build the
site with `mkdocs build --strict`; warnings are failures. Add user-visible
changes to [CHANGELOG.md](CHANGELOG.md) in the same pull request.

The artifact and publication checklist is in
[Releasing](docs/releasing.md).
