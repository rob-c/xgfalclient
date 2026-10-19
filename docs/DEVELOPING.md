# Developing xgfalclient

## What this is

A Python 3, drop-in replacement for the `gfal2` Python bindings
(`python3-gfal2`) and, in `xgfalclient.cli`, for the `gfal-*` commands of
gfal2-util. `import xgfalclient as gfal2` must run existing gfal2 code
unchanged. Required general-purpose dependencies are `bcrypt` and
`cryptography`; list a package only if this project imports it itself
(`asn1crypto` arrives through `xrdsec`, `botocore` through `xrdhttp`). The
shared libraries `xrdcore`, `xrdsec` and `xrdhttp` (`>=0.4.0,<0.5`) carry the
XML declaration checks, the JWT claim decoding, the grid security code and the
HTTP protocol pieces; binary record readers are local standard-library
helpers. The native `gssapi` binding is in the optional `krb5` extra (as
`xrdsec[krb5]`); `xrdclient==0.4.0` is required for `root://`.
Do not add a compiler-dependent package to the default install. CI's
wheel-only resolution and clean-install jobs cover supported platform families.
Python 3.11 is the floor (AppStream `python3.11`/`python3.12` on EL8/EL9);
see [Platforms](platforms.md). pyhanko-certvalidator remains deferred: RFC 3820
proxy and VOMS policy are not WebPKI path validation.

[Architecture](architecture.md) is the module map: how a call flows from
`Gfal2Context` through the plugin registry to a plugin, where each protocol
and test server lives, and which library or xrdclient modules each part relies on.

## Shared core ownership

The dependency is one-way:
`xgfalclient → xrdclient → xrdsec, xrdhttp → xrdcore → general-purpose libraries`,
and xgfalclient imports the three libraries directly. None of them may import
or depend on xgfalclient (xrdsec and xrdhttp do not import each other either).
The exact `xrdclient` pin and the `<0.5` library ranges prevent mixing
incompatible shared APIs. Install the sibling checkouts, in dependency order,
when changing shared code:

```console
$ python -m pip install -e ../xrdcore -e ../xrdsec -e ../xrdhttp -e ../xrdclient -e '.[dev]'
```

| Shared implementation | xgfalclient surface over it |
| --- | --- |
| `xrdsec.voms`: claims, trust policy, diagnostics | `crypto.voms` (alias) |
| `xrdsec.der`: bounded ASN.1 helpers and writers | `crypto.der` (alias) |
| `xrdsec.rsa`: keys, signatures, key import/export | `crypto.rsa` (alias) |
| `xrdsec.aes`: block/CBC/CTR adapters | `crypto.aes` (alias) |
| `xrdsec.ed25519`, `xrdsec.p256` | same names under `crypto` (aliases only: SSH keys use `cryptography` directly) |
| `xrdsec.x509`: certificate inspection, names, the legacy inspection fallback, `certificates_in`, `read_credential_files`, `credential_key`, `proxy_policy`, `legacy_proxy_kind`, `signed_by`, `pem_encode`; the building blocks `extension`, `key_usage`, `public_key_info`, `signature_algorithm` (moved there from here) | `crypto.x509` `Certificate`/`Credential`: gfal2's view (extension values by OID, Globus' strict proxy rules, first non-proxy identity); EC keys load; `proxy_cert_info` |
| `xrdsec.delegation.issue_certificate`: `CertificateBuilder`-based signing (RSA and EC) | `crypto.x509.build_certificate` (the same function) |
| `xrdsec.delegation.parse_proxy_request`, `make_proxy_request`, `sign_globus_request` (`xrdsec.proxies.issue_proxy(profile="globus")`: `globus_gsi_proxy_sign_req`, moved there from `crypto.proxy`) | `crypto.proxy.parse_request`, `sign_request` (`DERError` for every refusal), `make_request` (the same function), `delegation_payload` |
| `xrdsec.gsi.gss`: Globus GSI GSS (TLS in tokens, the turn, delegation, `host/fqdn`); `xrdsec.gsi.httpg`: SRM's httpg connection; `xrdsec.testing.gsi`: the acceptor side | `crypto.gsi` (alias); the GridFTP, LFC, dcap and SRM plugins and their fakes |
| `xrdsec.discovery.GFAL2`/`GFAL2_SEED`, `xrdsec.credentials` (`find_bearer_token(skip_unreadable=True)`, private-file checks), `xrdsec.tokens` (`token_claims`, `check_token`), `xrdsec.tls.client_context(x509_strict=False)` | `creds`: the credential store, option names and precedence, gfal2's debug lines, `GError` codes and messages |
| `xrdsec.testing.pki.BasePKI` | `testing.pki.PKI` (xgfal's types, `/DC=org/DC=xgfal` names) |
| `xrdhttp.testing.StorageServer` (the fake storage element, davix style) | `testing.webdav.WebDAVServer`: the directory root, `url()`/`local()`, gridsite delegation |
| `xrdcore.checksum`, `xrdcore.crc32c`: digests and CRC-32C with its `google-crc32c` probe | `checksum`: gfal2's algorithm set, name aliases, ADLER32 padding and comparison |
| `xrdcore.safexml`: declaration-rejecting XML loading | `_xml` (alias) |
| `xrdcore.report`: the `--json`/`--xml` report | `cli._base`'s `output` |
| `xrdcore.pipeline`: bounded read-ahead and complete chunk writes | streamed copies and XRootD upload read-ahead |
| `xrdcore.fanout.run_all`: thread fan-out, first failure raised as itself, the rest stopped | `plugins.http._ranged`: the segments, buffers and resume of a parallel ranged download |
| `xrdcore.cli`: `silence_stdout`, the shared `ExitCode` 0/1 | `cli._base`: gfal2-util's errno exit statuses (`EINTR`, `ETIMEDOUT`, `GError` codes) |
| `xrdhttp.engine`: bounded redirects, replay policy and failure cleanup | HTTP request/start adapters |
| `xrdhttp.connection`, `xrdhttp.expect`: connections and interim responses | `plugins.http._connection` (alias) and exchanges |
| `xrdhttp.wire`: direct body reads off the socket, `sendfile`/large-TLS-write file bodies, `IdlePool` | `plugins.http._client` responses, exchanges and connection pools |
| `xrdhttp.redirects`: `davix_carries_credentials` (moved there from `_target._may_forward`), `resolve_location` (gfal scheme kept, as `_target._resolve` did) | `plugins.http._client`'s redirect handling |
| `xrdhttp.webdav`: multistatus resources, hrefs, dates, `Digest`/`Repr-Digest` values | `plugins.http._dav`: davix's `stat`, `EIO` parse errors, nested responses |
| `xrdhttp.metalink.parse_metalink` with a `MetalinkPolicy` | `plugins.http._metalink`: davix's policy (every `<url>`, HTTP replicas only) and `Link` discovery |
| `xrdhttp.tape`: discovery document, API version choice, json-c text, path matching | `plugins.http._tape`: gfal2's requests, messages and errno |
| `xrdhttp.tpc`: `follow_markers`, `token_minutes`, `add_token`, `add_streams`, the activity sets | `plugins.http._tpc`, `_token`: davix's headers, credential choice, outcome errors, progress and cancel checks |
| `xrdhttp.s3.codec`, `xrdhttp.s3.sigv4` (`sign`, `presign`): botocore models, multipart XML and signing | `plugins.http._s3`: addressing, credentials, metadata and transport policies |
| `xrdclient.session.bulk` (via `xrdclient.client.bulk`): framing, acknowledgements, deferred replies and stream cleanup | upload progress, numeric errors and WAIT-range replay after settling |

Compatibility modules alias the canonical modules (`sys.modules`), preserving
old imports, exception identities and test hooks without duplicated
implementations; xgfal's own code imports the libraries directly. Where
gfal2/davix and XrdCl genuinely read the same bytes differently, the shared
code takes a small policy rather than being forked: `MetalinkPolicy` (one
`<file>` and any absolute URL, or every `<url>` and HTTP only),
`listed_endpoints(complete=...)` (drop partial tape endpoints, or read them as
empty), the marker reader's per-block callback (what to report, when to
check for a cancel), the `discovery.Search` values (gfal2's and XrdCl's search
orders as data), `skip_unreadable=` (a token file that cannot be read is "no
token" for gfal2), `x509_strict=` (davix never applies Python's RFC 5280
strict checks), `check_hostname=False` (GSI's own DN check), the `globus`
proxy profile and `davix_carries_credentials` beside the strict same-origin
rule. The HTTP clients themselves stay two: davix's path quoting, numeric
errors and the plugin's thread-safe pool are not XrdCl's, so only the pieces
below `http.client` and the protocol rules are shared. Library exceptions
(`xrdcore.errors`) are turned into `GError` where xgfalclient calls the
library.
VOMS accepts a read-only certificate view from either client; their distinct
credential models and proxy rules remain intact. GFAL-only SSH, GridFTP, SRM,
LFC and plugin/error translation stay in xgfalclient. XRootD framing, sessions
and filesystem operations stay in xrdclient. HTTP credentials, connection-pool
ownership and numeric-error policy remain client adapters around the shared
request lifecycle. GFAL retains known-length/spooled uploads; Xrd retains
buffered/chunked uploads. Copy preparation, cleanup, durability, replica recovery
and GFAL event ordering stay with the endpoint/job adapters. The shared pipeline
never retries a write: replay safety must be decided by the adapter.

Both certificate facades use one decoder. Normal X.509 names, keys, validity,
extensions and signatures come from cryptography; one bounded fallback retains
the existing inspection behaviour for incomplete legacy certificates. Inspection
is not certificate-path validation. S3 uses botocore's service models and XML
serializer over the existing HTTP transports, not an SDK client's credential
discovery, retry or TLS policy. Declaration checks precede model decoding.
Copy/complete responses are checked for embedded errors even when HTTP says 200.

Tests live with the code: the libraries' suites (100 % line and branch each)
are the canonical tests of shared code, and a case that only re-tested moved
code belongs there, not here. xgfalclient's suite covers the old import paths
(`tests/test_shared_core.py`), credential interoperability, the protocol
adapters and end-user diagnostics, and its condition-coverage pass also holds
the library modules in `tests/condcov.py`'s `SHARED_MODULES` to the
both-ways rule (that list's comment says why those;
`tests/test_library_decisions.py` takes their few non-gfal2 decisions).
Measure combined `src/` and test LoC separately when changing these
boundaries. Verify read/write overlap, bounded buffers, worker shutdown,
partial writes and representative throughput before acceptance.

Run every affected suite when changing shared code: the library's, then
xrdclient's, xgfalclient's and xrdarc's. CI checks out the coordinated
candidates (xrd-devtools' candidates action, with `packages: xrdcore xrdsec
xrdhttp xrdclient`) as well as installing the built wheels. Release the libraries, then xrdclient,
then update the pins before releasing xgfalclient.

## Hard rules

Error messages are for physicists and people managing a service for the first
time. Say what failed, identify the path or service when known, and give a short,
safe next step. Keep numeric codes, exception types and raw compatibility fields
stable; display wording is not required to reproduce the original bindings.
Use `str(error)` or `error.user_message` for people and `error.message` for the
raw compatibility text. Avoid internal function names and tracebacks in normal
CLI output; `-vvv` provides technical details for unexpected failures.
Never suggest disabling certificate checks, trusting a certificate copied from
an untrusted proxy, or making private keys readable by everyone.
Add Linux/macOS regression cases for the reason, path, code and suggested fix.

1. **Reuse maintained libraries.** Use the declared, maintained
   general-purpose libraries for AWS signing, GSS-API, HTTP pooling/TLS,
   ASN.1 and cryptographic primitives. Keep protocol and policy adapters small;
   do not reintroduce cipher/curve arithmetic or ctypes ABI bindings.
   xrdcore, xrdsec and xrdhttp own the common core; `paramiko` (the
   `sftp` extra, 3.4+ for strict KEX) is the preferred in-process SSH
   transport and `bcrypt` derives OpenSSH key-file passphrases; the built-in
   SSH-2 client in `plugins/sftp/ssh.py` is the last-resort tier (a base
   install's password logins) and the test server's transport - keep it
   small, do not grow it. JWT inspection (`creds.token_claims`, over
   `xrdsec.tokens`) is unverified diagnostics, never a trust decision. Do not substitute a WebPKI verifier for RFC 3820
   proxy or VOMS policy without explicitly testing that policy.
   Ruff's banned-API list (`TID251`) enforces the split: `http.client`,
   hand-built TLS contexts, `gssapi`/`krb5`, `ThreadPoolExecutor`, the XML
   parsers and `botocore` are refused in `src` and `tests` alike, each
   message naming the library API to use (the table and the reasons are
   under "Banned APIs" in the repository's `CONTRIBUTING.md`).
2. **Python 3.11 compatible.** `from __future__ import annotations` in every
   module; Python 3.11 syntax and standard library are available (`X | Y`
   unions, `match`, `slots=True`, `Self`, `tomllib`, `datetime.UTC`), but
   nothing newer. `zip()` names `strict=` explicitly. Interpreter-dependent
   code belongs in the library that owns the feature (the TLS peer chain,
   public from 3.13, is `xrdsec.gsi.gss.peer_chain_der`).
3. **100% line *and* branch coverage** of everything under
   `src/xgfalclient`, enforced by `fail_under = 100`, with no `omit` and no
   `# pragma: no cover`/`no branch`: if a branch cannot be reached by a
   test, the branch is wrong. The only exclusions are the shared
   `exclude_also` list in `pyproject.toml` (`if TYPE_CHECKING:`,
   `@overload`, `raise NotImplementedError`, `...` bodies and
   `if __name__ == "__main__":`).

   Branch coverage sees a line as one decision, so on top of it every
   in-line decision must go both ways too: each `and`/`or` operand that
   decides whether evaluation continues, each `x if c else y`, and each
   comprehension `if`. `XGFAL_CONDCOV=1` turns on `tests/condcov.py`, which
   rewrites the package as it is imported and fails the run on any decision
   seen only one way. It has no exclusion mechanism: a side no test can
   reach is dead code to remove, and a value fixed at import (the Python
   version, the platform) belongs in a function that takes it as a
   parameter.
4. **Tests are hermetic.** No network beyond loopback, no real grid
   services, no ambient credentials (`tests/conftest.py` enforces this
   through xrdsec's `xrdsec.testing.fixtures` plugin, plus its own
   `pytest_xrdsec_hermetic` hook for gfal2's configuration).
   Protocol plugins are tested against in-process servers that live in
   `xgfalclient.testing` (and are therefore covered too). Tests that need a
   real server (docker) are marked `@pytest.mark.interop` and skipped unless
   `XGFAL_INTEROP=1`; they do not count toward coverage.
5. **Errors are `GError(message, errno_code)`**, never a bare `OSError`,
   `ssl.SSLError`, `TimeoutError` or `http.client` exception escaping a
   plugin. Map faithfully: 404 -> `ENOENT`, 403/401 -> `EACCES`, timeouts ->
   `ETIMEDOUT`, refused connection -> `ECONNREFUSED`, and so on
   (`errors.HTTP_ERRNO` for HTTP).
6. **Thread-safe.** A context may be used from several threads at once (FTS
   does). Connection pools must be locked or per-thread.
7. **Fast.** Data paths use large buffers (`CORE:COPY_BUFFERSIZE`, 4 MiB),
   `readinto`/`recv_into` into preallocated memory, `memoryview` slicing,
   and never `bytes` concatenation in a loop. Parallelism where the protocol
   has it (HTTP ranges, GridFTP MODE E). Target: at least gfal2's
   throughput through its Python bindings.
8. **No grandfathered code.** Every check holds for all code, old and new,
   with nothing that lets existing code skip it:
   - `ruff check` over `src`, `tests` and `benchmarks` with the shared rule
     set (`E F W I UP B C4 SIM RUF` and the high-confidence `S` rules),
     `ignore = []` and no `per-file-ignores`; `ruff format --check` clean.
   - `mypy` (`strict = true`) over `src`, `tests` and `benchmarks`, tests
     included with no relaxation.
   - Complexipy: every function at most 15, no snapshot file, no ignore
     markers. Split a hotspot into well-named helpers.
   - pytest runs with `filterwarnings = ["error"]`: a warning (an unclosed
     socket's `ResourceWarning` included) fails the test that caused it.
     Fix the cause; do not filter it.
   - No suppression comments (`# noqa`, `# type: ignore`, `# pragma`,
     `# nosec`, `# fmt: off`). The few irreducible ones carry a specific code
     and a reason on the same or the preceding line.
   - Skips are environmental only (platform, optional dependency or tool
     absent, the interop marker) and say so in their reason.
   - Deprecated names exist only where they mirror gfal2, python3-gfal2 or
     gfal2-util, and their docstrings say which.

   Docstrings explain *why*; match the density of the existing modules.
9. **Distributions are tested artifacts.** Both wheels and source archives
   must pass `twine check --strict`; typed packages carry their `py.typed`
   marker. Python 3.11 through 3.14 are exercised in CI.

## Layout

| Module | Role |
| --- | --- |
| `context.py` | `Gfal2Context`: the gfal2 API, dispatch, `FileType`, `DirectoryType` |
| `plugin.py` | `Plugin` and `PluginFile` base classes - **the contract** |
| `plugins/` | one module (or package) per protocol; registry in `plugins/__init__.py` |
| `transfer.py` | `TransferParameters`, `Transfer`, the copy pipeline, streamed copy |
| `options.py` | the gfal2 key-file configuration with stock defaults |
| `creds.py` | credential store, X.509/token discovery, cached TLS contexts |
| `errors.py` | `GError` and errno helpers |
| `events.py`, `enums.py`, `types.py`, `url.py`, `checksum.py` | small shared pieces |
| `crypto/` | DER, RSA, X.509, gridsite proxy signing (`proxy.py`); `gsi.py` is an alias of `xrdsec.gsi.gss` |
| `testing/` | in-process servers and `pki.py` (throwaway CA/host/user/proxies) |
| `cli/` | the `gfal-*` commands |

## The plugin contract (read `plugin.py`)

* Subclass `Plugin`; set `name`, `schemes`, `option_group`, `priority`,
  `event_domain`, and add a matching `Entry` to `BUILTIN` in
  `plugins/__init__.py`. Plugins are imported lazily, the first time a URL
  with one of the entry's schemes is used, so the entry is the routing table;
  `test_builtin_entries_describe_their_classes` fails if it and the class
  disagree. Keep plugin modules' top-level imports cheap (`ssl`,
  `importlib.metadata` and optional packages belong inside functions). Override only the operations the protocol supports; the
  context detects overrides with `Plugin.implements(op)` and falls through to
  `EPROTONOSUPPORT` otherwise, exactly like gfal2.
* Methods take URL strings and return Python values (the context adds
  gfal2's `0` return codes). `stat` returns `types.Stat`; `opendir` returns
  an iterator of `(name, Stat | None)`; `open` returns a `PluginFile`.
* Tape operations take and return lists: `bring_online(urls, metadata,
  pintime, timeout, is_async) -> (results, token)` where each result is
  `True` (online), `False` (queued) or a `GError`.
* Copies: return `True` from `copy_check(src, dst)` only for pairs the plugin
  moves better than the core's streamed copy (third-party copy, one-request
  upload, parallel download). `copy(transfer)` receives a `transfer.Transfer`:
  the core has already verified the source checksum, handled overwrite and
  parent creation; the plugin moves bytes, emits `transfer.event(...)`
  (`TRANSFER:TYPE` at least), reports `transfer.progress(n)`/`add(n)`, and
  calls `transfer.check()` between chunks (cancellation and timeout).
  As in gfal2's core, `monitor_callback` is never fired for a copy shorter
  than `transfer.MONITOR_INTERVAL`; tests that need a report set it to `0.0`.
  Where gfal2's plugin reports whatever its library reports (each HTTP
  performance marker, XrdCl's last progress call), the plugin passes
  `transfer.progress(n, always=True)`. The core verifies the destination
  checksum and cleans up on failure.
* For the core's streamed copy to work through a plugin, its `open()` must
  support `O_RDONLY` with `readinto`, and `O_WRONLY|O_CREAT|O_TRUNC` with
  `write`; `open(..., size=N)` passes the source size to writers that must
  declare a length (HTTP `PUT`). The upload completes, and reports errors,
  on `close()`.
* Credentials: `self.context.x509(url)`, `self.context.bearer_token(url)`,
  `self.context.ssl_context(url, group=self.option_group)`. For GSI, build a
  context with `check_hostname=False` and use `xrdsec.gsi.gss.SecurityContext`
  (it does GSI's own `host/fqdn` check and delegation); a test server's side
  is `xrdsec.testing.gsi`.
* Options: `self.options.string/integer/boolean/string_list(group, key,
  default)` never raise; `self.option_timeout()` is the plugin's operation
  timeout with the core fallback.
* Identity: `self.context.user_agent_string()` for `User-Agent`,
  `self.context.client_info_string()` for gfal2's `ClientInfo` header.

## Reference behaviour

The real gfal2 2.23.5 stack is in the `gfal-ref:latest` docker image
(AlmaLinux 9: gfal2 + every plugin, python3-gfal2, gfal2-util, xrootd server
with XrdHttp, globus-gridftp-server). Probe it to settle any question of
behaviour, error wording or wire format; set
`ctx.set_opt_integer("HTTP PLUGIN", "LOG_LEVEL", 4)` and attach a
`logging` handler to see davix's requests.

That image's `python3` is 3.9, the only Python its gfal2 bindings are built
for, and this package needs 3.11. The interop harnesses (`XGFAL_INTEROP=1`)
therefore run gfal2's side on the system `python3` and this checkout's side
on AppStream `python3.11`, with `src`, the host's `xrdclient` and its
`xrdcore`, `xrdsec` and `xrdhttp` bind-mounted (the libraries under `/libs`,
on the container's `PYTHONPATH`).
`tests/_interop_image.py` derives the image they need from `gfal-ref:latest`
(and from `gfal-sftp-ref:latest` for sftp) on first use, tagged
`gfal-ref-py311:<recipe hash>`; that first build needs network access for
`dnf` and `pip`, and later runs reuse docker's cache. Where it cannot be
built, provide an image with the same contents: `python3.11` and
`python3.11-pip` from AppStream, then
`python3.11 -m pip install "cryptography>=45" "botocore>=1.35" "bcrypt>=4" "asn1crypto>=1.5.1"`
(plus `"paramiko>=3.4"` for the sftp harness).

When gfal2 does something harmful - it deletes the source of a copy onto
itself when `overwrite` is set - we deliberately differ and say so in a
comment.

## Running the tests

```console
$ .venv/bin/pytest -n auto --cov --cov-report=term-missing
$ XGFAL_CONDCOV=1 .venv/bin/pytest -n auto      # condition coverage; not with --cov
$ .venv/bin/ruff check src tests benchmarks
$ .venv/bin/ruff format --check src tests benchmarks
$ .venv/bin/mypy
$ .venv/bin/complexipy --quiet
$ .venv/bin/xrddevtools conformance --repo .
$ .venv/bin/python -m build && .venv/bin/twine check --strict dist/*
```

`tests/test_scorecard.py` (the take-over scorecard: every one of twelve
measurements better than the median of 39 widely used libraries) and
`xrddevtools` come from [xrd-devtools](https://github.com/rob-c/xrd-devtools),
the repository for what serves the whole chain: the scorecard, the
configuration-conformance and duplicate gates, the release pre-flight and
the platform matrix. It is not on PyPI and cannot be a dependency (PyPI
refuses direct-URL requirements), so it is used from a checkout: pytest's
`pythonpath` finds a sibling `../xrd-devtools` or CI's
`.dependencies/xrd-devtools`; elsewhere `pip install -e` it or put its `src`
on `PYTHONPATH`. Without one the scorecard test skips, saying so (as it does
without radon and complexipy). CI is xrd-devtools' reusable workflows
(`static.yml`, `tests.yml`, `chain.yml`, `platforms.yml`), which load the
plugin with `-p` and set `XRD_DEVTOOLS_REQUIRED=1` so the gate cannot skip
there - and which need `rob-c/xrd-devtools` to exist.

The external BRIX network-fault integration is opt-in. Point the test at a
built proxy; it then exercises streamed reads, positioned reads, WebDAV
uploads and metadata through real mid-body truncations and a temporary
refused endpoint. Further cases keep truncating until self-heal, strip `Range`
as a broken middlebox would, corrupt bodies without changing their length,
and combine tiny segments, jitter, and a silent firewall reap:

```console
$ BRIX_FAULT_PROXY=/path/to/brix-fault-proxy \
    .venv/bin/pytest tests/test_http_brix_fault_proxy.py
```

The external BRIX FUSE integration exercises short and zero-progress I/O,
partial-write `ENOSPC`, torn and silently dropped writes, lying metadata,
repeating stale-handle bursts, live file replacement, volatile writeback,
dishonest `fsync` acknowledgement, and late or post-commit `fsync` failure.
Its durability cases ensure `filecopy` cannot return success while output
bytes remain only in a fallible filesystem cache:

```console
$ BRIX_FAULT_FS=/path/to/brix-fault-fs \
    .venv/bin/pytest tests/test_brix_fault_fs.py
```

The scenarios are xrdclient's shared local-copy conformance suite
(`xrdclient.testing.brix.LocalCopySuite`), run here through a
`Gfal2Context.filecopy` adapter; `tests/test_brix_fault_fs.py` adds only
gfal2's own errno and wording.

Both tools are built by the adjacent `brix-cache/client` project. The suites
are skipped when their environment variable is unset, so normal development
does not require FUSE.

Before publishing a performance-sensitive change, run the paired benchmark
beside the target service with native `python3-gfal2` installed. gfal2's
runs use `--gfal2-python` (by default the benchmark's own interpreter), so a
3.9-only `python3-gfal2` can be measured against xgfalclient on 3.11:

```console
$ .venv/bin/python benchmarks/bench_vs_gfal2.py --gfal2-python /usr/bin/python3 \
    --base davs://server:8443/data/bench --repeat 9 --gate --min-ratio 1.10
```

The gate rejects xgfalclient's own `gfal2` compatibility shim as a reference.
