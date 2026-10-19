# Contributing to xgfalclient

The project has two compatibility targets: the `gfal2` Python API and the
observable behaviour of gfal2/gfal2-util 2.23.5/1.9.1. Improvements must keep
those contracts while preserving a small, vetted dependency set and a faster
data plane.

## Development setup

Use a virtual environment so the replacement `gfal2` package cannot shadow a
system `python3-gfal2` installation. Python 3.11 or later is required; on
AlmaLinux/RHEL 8 or 9, create it with AppStream's `python3.11` (or
`python3.12`) instead of the system `python3`.

```console
$ python3 -m venv .venv
$ .venv/bin/python -m pip install -U pip
$ .venv/bin/python -m pip install -e '.[dev,docs]'
$ .venv/bin/pytest -q -m 'not interop'
```

The ordinary suite uses in-process protocol servers and blocks accidental
external network access. Real-service tests are marked `interop` and require
`XGFAL_INTEROP=1`.

The take-over scorecard and release-metadata gates and the `xrddevtools`
checks come from [xrd-devtools](#xrd-devtools), used from a checkout beside
this one; see also [Developing xgfalclient](docs/DEVELOPING.md#running-the-tests).

## Definition of done

A change is ready when:

- its success, failure, cancellation and cleanup paths are tested at the
  public `gfal2` boundary;
- wire changes are exercised against an independent test server and, where
  practical, the reference gfal2 stack;
- line, branch and condition coverage remain complete;
- Ruff, formatting, `mypy --strict` (tests included) and Complexipy (every
  function at most 15) pass with no rule ignores, snapshots or suppression
  comments, and the suite passes with warnings as errors ([the code
  standard](#the-code-standard)); the take-over scorecard, the
  release-metadata gate and `xrddevtools conformance --repo .` pass;
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

Production imports in `src/xgfalclient` are limited to the standard library,
`xrdclient`, the shared libraries `xrdcore`, `xrdsec` and `xrdhttp`, and the
declared runtime dependencies (`cryptography` and `bcrypt`); adding a dependency is a reviewed decision, not a
convenience. Optional integrations must be lazy and must have a working
default or system-library path described in the developer guide.

## The code standard

<!-- >>> xrddevtools sync: code-standard (generated from xrd-devtools/src/xrddevtools/standard) >>> -->
Every repository of the chain is held to one code standard, and every line
of it is held to the standard: old code passes the same checks as new code.

- **Ruff** selects `E`, `F`, `W`, `I`, `UP`, `B`, `C4`, `SIM`, `RUF`, the
  high-confidence security checks `S102`, `S307`, `S506`, `S602`, `S608`,
  `S609`, `S701` and the banned-API rule `TID251` (see *Banned APIs*), with
  `ignore = []` and no per-file ignores, over `src`, `tests`, `benchmarks`;
  `ruff format` formats it, 100 columns wide.
- **mypy** is strict (Python 3.11) over `src`, `tests`, `benchmarks`. A test
  function may leave its fixtures unannotated where `pyproject.toml` allows
  it, but its body is still checked; only a named third-party module that
  ships no types may be imported untyped, with the reason beside it.
- **complexipy** allows no function above 15, over `src`, `tests`,
  `benchmarks`, with no snapshot of old offenders.
- **Coverage** is 100 % of lines and branches, reached by a test that makes
  each case happen. The only exclusions are `if TYPE_CHECKING:`,
  `@overload`, `raise NotImplementedError`, `\.\.\.$`, `if __name__ ==
  .__main__.:`; there is no `omit`.
- **Every warning is an error** (`filterwarnings = ["error"]`): ours are
  fixed, not filtered.
- **No suppression comment**: no `# noqa`, `# pragma: no cover`, `# fmt:
  off`, `# complexipy: ignore` or `# nosec`. A `# type: ignore[code]` only
  where it cannot be avoided (a test passing a wrongly typed value on
  purpose), with its error code and the reason beside it or just above.
- **No snapshot or baseline** of old findings, for any tool.

The settings behind these rules are the managed blocks of `pyproject.toml`
(between `# >>> xrddevtools sync` markers), and this section is one of the
managed blocks of this file (between `<!-- >>> xrddevtools sync` markers).
`xrddevtools sync` writes them all from the standard, kept once in
xrd-devtools (`src/xrddevtools/standard`); `xrddevtools conformance`, which
CI runs, fails if one is edited by hand. To change the standard, change it
there and run `xrddevtools sync --workspace ..` over every repository.
<!-- <<< xrddevtools sync: code-standard <<< -->

## Banned APIs

<!-- >>> xrddevtools sync: banned-apis (generated from xrd-devtools/src/xrddevtools/standard) >>> -->
Ruff's `TID251` rule refuses the APIs whose job another part of the chain
does, in every tree ruff checks (`src`, `tests`, `benchmarks`), with no
per-file ignore and no `noqa`; the list is
`[tool.ruff.lint.flake8-tidy-imports.banned-api]` in `pyproject.toml`, and
each entry's message names what to use instead. A need for a banned API is
met by the library that owns it growing an API, with its tests - never by an
exception here.

| Banned | Use instead | Why |
|---|---|---|
| `http.client` | HTTP is xrdhttp's: requests through xrdhttp.session.Session; connections, and the http.client types a client names (IncompleteRead, HTTPMessage, ...), through xrdhttp.connection | one pooled session with the chain's redirect, retry, `100-continue` and credential rules; `xrdhttp.connection` re-exports the stdlib's own `http.client` classes, so `except`/`isinstance` mean the same |
| `urllib3`, `requests`, `httpx` | the chain has no third-party HTTP stack: use xrdhttp.session.Session (pooling, redirects, retries; TLS from xrdsec.tls) | one HTTP stack for the whole chain, with its TLS, redirect and retry rules |
| `urllib.request` | use xrdhttp.session.Session: urllib's opener has none of the chain's TLS, redirect or retry rules | urllib's opener knows none of the grid's TLS (CAs, CRLs, proxies) and follows redirects with credentials attached |
| `gssapi` | Kerberos GSS-API is xrdsec.krb5.gss (the xrdsec[krb5] extra), one wrapper for every client | one GSS-API wrapper, behind the `xrdsec[krb5]` extra |
| `krb5` | pykrb5 is not a dependency: credential caches are xrdsec.krb5.caches / xrdsec.krb5.ccache, GSS-API is xrdsec.krb5.gss | the pure-Python ccache, KCM and keyring readers replaced it |
| `ssl.PROTOCOL_TLS`, `ssl.PROTOCOL_TLS_CLIENT`, `ssl.PROTOCOL_TLS_SERVER`, `ssl._create_unverified_context`, `ssl.create_default_context` | TLS contexts are built by xrdsec.tls.client_context (grid CAs, CRLs, proxies, caching); GSI data channels by xrdsec.gsi.gss.data_contexts; tests by xrdsec.testing.pki.PKI.client_context / server_context | grid CAs, CRLs, proxies and context caching in one builder. `ssl.SSLContext` itself is not banned, so annotations still name it: building one needs a `PROTOCOL_*` constant (without one the constructor warns, and warnings are errors), and that is what the ban catches |
| `concurrent.futures.ThreadPoolExecutor` | a fan-out is xrdcore.fanout.run_all (first failure raised, the rest stopped); a long-lived pool is xrdcore.fanout.Pool | the first failure raised as itself and the rest stopped; a long-lived pool made on first use and made again in a forked child |
| `xml.etree.ElementTree.XML`, `xml.etree.ElementTree.XMLParser`, `xml.etree.ElementTree.XMLPullParser`, `xml.etree.ElementTree.fromstring`, `xml.etree.ElementTree.fromstringlist`, `xml.etree.ElementTree.iterparse`, `xml.etree.ElementTree.parse`, `xml.dom.minidom`, `xml.dom.pulldom`, `xml.parsers.expat`, `xml.sax.make_parser`, `xml.sax.parse`, `xml.sax.parseString` | parse XML with xrdcore.safexml.fromstring, which refuses DOCTYPEs and entities | it refuses DOCTYPEs, so no entity is declared, expanded or fetched. Building and writing trees (`ET.Element`, `ET.tostring`) and `xml.sax.saxutils.escape` stay allowed |
| `botocore`, `boto3` | S3 signing and the S3 codec are xrdhttp.s3 (the xrdhttp[s3] extra); only xrdhttp.s3 imports botocore | S3 signing and the S3 codec, behind the `xrdhttp[s3]` extra |
| `xrdarc` | - | the clients share code through the libraries, never through each other |
| `xrdwms` | - | they are built on this repository; the dependency direction never points up |
<!-- <<< xrddevtools sync: banned-apis <<< -->

Where this client still needs the stdlib piece the ban names, the library
offers it: the GridFTP `DCAU` data-channel pair is
`xrdsec.gsi.gss.data_contexts` (re-exported as
`xgfalclient.plugins.gridftp.gsi.data_contexts`), the SRM transport and the
error mapping name `HTTPException`/`HTTPResponse`/`IncompleteRead` through
`xrdhttp.connection`, and the GSI and HTTPS tests build their client
contexts with `PKI.client_context(proxy=..., anonymous=..., check_hostname=...)`
- a fresh context each call, which a test may change, unlike the shared,
cached ones `xrdsec.tls` returns.

## xrd-devtools

<!-- >>> xrddevtools sync: devtools (generated from xrd-devtools/src/xrddevtools/standard) >>> -->
The chain's gates and tools - the take-over scorecard and the
release-metadata and maintainability gates, `xrddevtools conformance`,
`dupes` and `sync`, the release pre-flight and the packaging tools - live in
[xrd-devtools](https://github.com/rob-c/xrd-devtools). It is never uploaded
to PyPI and cannot be a dependency (PyPI refuses direct-URL requirements),
so it is used from a checkout:

- **A developer** keeps it beside this repository (`../xrd-devtools`, the
  workspace layout). pytest's `pythonpath` lists `../xrd-devtools/src`, so
  the gate tests find it with nothing installed; `pip install -e
  ../xrd-devtools` once gives the `xrddevtools` command.
- **CI** checks it out under `.dependencies/xrd-devtools` (the shared
  `candidates` action always does), which `pythonpath` lists too. It loads
  the plugin with `pytest -p xrddevtools.pytest_plugin`, which fails at
  start-up if it cannot be imported, and sets `XRD_DEVTOOLS_REQUIRED=1`, so
  a missing radon or complexipy fails rather than skips. This repository's
  workflows are xrd-devtools' reusable workflows and actions: CI runs only
  once `rob-c/xrd-devtools` exists.
- **Anywhere else** - a wheel-only test environment, a distribution build -
  `pip install -e` a checkout or put its `src` on `PYTHONPATH`. Without one,
  the gate tests (`tests/test_scorecard.py`,
  `tests/test_release_metadata.py`) skip, saying why.
<!-- <<< xrddevtools sync: devtools <<< -->

## Documentation and releases

Docstrings explain contracts and non-obvious choices, not syntax. Build the
site with `mkdocs build --strict`; warnings are failures. Add user-visible
changes to [CHANGELOG.md](CHANGELOG.md) in the same pull request.

The artifact and publication checklist is in
[Releasing](docs/releasing.md).
