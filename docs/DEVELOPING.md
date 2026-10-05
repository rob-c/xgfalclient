# Developing xgfalclient

## What this is

A Python 3, drop-in replacement for the `gfal2` Python bindings
(`python3-gfal2`) and, in `xgfalclient.cli`, for the `gfal-*` commands of
gfal2-util. `import xgfalclient as gfal2` must run existing gfal2 code
unchanged. Required general-purpose dependencies are `botocore`,
`PyJWT[crypto]`, `urllib3`, `asn1crypto` and `cryptography`. XML declaration
checks and binary record readers are local standard-library helpers.
Native `gssapi` and `krb5` bindings are in the optional `krb5`
extra; `xrdclient==0.3.0` is required for shared security/parsing and `root://`.
Do not add a compiler-dependent package to the default install. CI's
wheel-only resolution and clean-install jobs cover supported platform families.
Python 3.9 remains the declared compatibility floor, but a clean 3.9 install
does not resolve; the floor is to be corrected; see [Platforms](platforms.md).
Current pyhanko-certvalidator requires Python 3.10 and is deferred rather than
selecting an older validator.

## Shared core ownership

The dependency is one-way: `xgfalclient → xrdclient → general-purpose libraries`.
Keep xrdclient independently installable: it must never import or depend on
xgfalclient. The exact release pin prevents mixing incompatible shared APIs.
Install both sibling checkouts when changing the common core:

```console
$ python -m pip install -e ../xrdclient -e '.[dev]'
```

| Shared implementation in xrdclient | xgfalclient compatibility surface |
| --- | --- |
| `crypto.voms`: claims, trust policy, diagnostics | `crypto.voms` |
| `crypto.der`: bounded ASN.1 helpers and writers | `crypto.der` |
| `crypto.rsa`: keys, signatures, key import/export | `crypto.rsa` |
| `crypto.aes`: block/CBC/CTR adapters | `crypto.aes` |
| `crypto.ed25519`, `crypto.p256` | same names under `crypto` |
| `crypto.x509`: library-backed certificate inspection, names and legacy inspection fallback | `crypto.x509` certificate/credential models and proxy builders |
| `_xml`: declaration-rejecting XML loading | `_xml` |
| `http._engine`: bounded redirects, replay policy and failure cleanup | HTTP request/start adapters |
| `http._connection`, `http.expect`: connections and interim responses | HTTP compatibility path and exchanges |
| `copy._pipeline`: bounded read-ahead and complete chunk writes | streamed copies and XRootD upload read-ahead |
| `session.bulk`: framing, acknowledgements, deferred replies and stream cleanup | upload progress, numeric errors and WAIT-range replay after settling |
| `s3._codec`, `s3.sigv4`: botocore models, multipart XML and signing | addressing, credentials, metadata and transport policies |

Compatibility modules alias the canonical modules, preserving old imports,
exception identities and test hooks without duplicated implementations.
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

Measure combined `src/` and test LoC separately when changing these boundaries,
including new engines and adapters. Preserve fault scenarios and independent
protocol vectors rather than deleting tests to improve the count. Shared HTTP
and pipeline modules retain explicit coverage gates; run both suites and GFAL's
condition-coverage pass. Verify read/write overlap, bounded buffers, worker
shutdown, partial writes and representative throughput before acceptance.

Run both clients' tests when changing shared code. xrdclient tests cover the
common core without installing xgfalclient; xgfalclient tests cover the old import
paths, credential interoperability, protocol adapters and end-user diagnostics.
CI tests the sibling checkout as well as installing both built wheels. Release
xrdclient first, then update the required pin before releasing xgfalclient.

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
   general-purpose libraries for AWS signing, JWTs, GSS-API, HTTP pooling/TLS,
   ASN.1 and cryptographic primitives. Keep protocol and policy adapters small;
   do not reintroduce cipher/curve arithmetic or ctypes ABI bindings.
   `xrdclient` owns the common security/parsing core; `paramiko` remains
   an optional SSH transport. JWT inspection is unverified diagnostics,
   never a trust decision. Do not substitute a WebPKI verifier for RFC 3820
   proxy or VOMS policy without explicitly testing that policy.
2. **Python 3.9 compatible.** `from __future__ import annotations` in every
   module; no `match`; no `X | Y` outside annotations; `dataclass(**SLOTS)`
   from `_compat`, never `slots=True`; no `zip(strict=)`. Version-dependent
   code goes in `_compat.py` only.
3. **100% line *and* branch coverage** of everything under
   `src/xgfalclient`, enforced by `fail_under = 100`. Avoid
   `# pragma: no cover`; if a branch cannot be reached by a test, the branch
   is probably wrong. The only accepted pragma is for code that genuinely
   cannot run on the test platform, with a comment saying why.

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
   services, no ambient credentials (`tests/conftest.py` enforces this).
   Protocol plugins are tested against in-process servers that live in
   `xgfalclient.testing` (and are therefore covered too). Tests that need a
   real server (docker) are marked `@pytest.mark.interop` and skipped unless
   `XGFAL_INTEROP=1`; they do not count toward coverage.
5. **Errors are `GError(message, errno_code)`**, never a bare `OSError`,
   `ssl.SSLError`, `socket.timeout` or `http.client` exception escaping a
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
8. **No quality regressions.** `ruff check` (including the enabled
   high-confidence security rules), `ruff format`, and `mypy --strict` must
   all be clean. New and refactored functions have cognitive complexity at
   most 15. The checked-in Complexipy snapshot freezes older hotspots until
   they are simplified; never raise a value in it. Docstrings explain *why*;
   match the density of the existing modules.
9. **Distributions are tested artifacts.** Both wheels and source archives
   must pass `twine check --strict`; typed packages carry their `py.typed`
   marker. Python 3.9 through 3.14 are exercised in CI.

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
| `crypto/` | DER, RSA, X.509, proxy signing (`proxy.py`), GSI GSSAPI (`gsi.py`) |
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
  context with `check_hostname=False` and use `crypto.gsi.SecurityContext`
  (it does GSI's own `host/fqdn` check and delegation).
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
$ git diff --exit-code -- complexipy-snapshot.json
$ .venv/bin/python -m build && .venv/bin/twine check --strict dist/*
```

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

Both tools are built by the adjacent `brix-cache/client` project. The suites
are skipped when their environment variable is unset, so normal development
does not require FUSE.

Complexipy allows a function already recorded in `complexipy-snapshot.json`
to stay at its current complexity, but rejects a new hotspot or any increase.
When a function is simplified, the tool lowers the snapshot automatically;
commit that improvement. A snapshot change that raises a value is a failed
review, not a way to make CI green.

Before publishing a performance-sensitive change, run the paired benchmark
beside the target service with native `python3-gfal2` installed:

```console
$ .venv/bin/python benchmarks/bench_vs_gfal2.py \
    --base davs://server:8443/data/bench --repeat 9 --gate --min-ratio 1.10
```

The gate rejects xgfalclient's own `gfal2` compatibility shim as a reference.
