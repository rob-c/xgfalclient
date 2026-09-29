# Developing xgfalclient

## What this is

A pure-Python, drop-in replacement for the `gfal2` Python bindings
(`python3-gfal2`) and, in `xgfalclient.cli`, for the `gfal-*` commands of
gfal2-util. `import xgfalclient as gfal2` must run existing gfal2 code
unchanged. The only runtime dependency anywhere is the optional `xrdclient`
(itself pure Python) for `root://`.

## Hard rules

1. **Standard library only** in `src/xgfalclient`. The exceptions are all
   optional and imported lazily: `xrdclient` for the `xrootd` plugin,
   `gssapi` for Kerberos (else `ctypes` into the system `libgssapi_krb5`),
   `paramiko` for one sftp transport tier, and `ctypes` into the `libcrypto`
   that `ssl` already links, for SSH bulk ciphers (else pure Python). No
   `requests`, no `cryptography`, no `lxml`.
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
8. Code style: `ruff check` and `ruff format` clean, `mypy --strict` clean.
   Docstrings explain *why*; match the density of the existing modules.

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
  As in gfal2, `monitor_callback` is never fired for a copy shorter than
  `transfer.MONITOR_INTERVAL`; tests that need a report set it to `0.0`. The
  core verifies the destination checksum and cleans up on failure.
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
$ .venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests
$ .venv/bin/mypy
```
