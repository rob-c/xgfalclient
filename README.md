# xgfalclient

gfal2, in pure Python. A drop-in replacement for the `gfal2` Python bindings
(`python3-gfal2`) and the `gfal-*` commands (gfal2-util), with no C library
underneath and no required dependency outside the standard library.

```python
import xgfalclient as gfal2

with gfal2.creat_context() as ctx:
    print(ctx.stat("davs://se.example.org/store/f.root").st_size)

    params = ctx.transfer_parameters()
    params.overwrite = True
    params.set_checksum(gfal2.checksum_mode.both, "ADLER32", "")
    ctx.filecopy(params, "file:///tmp/f.root", "root://se.example.org//store/f.root")
```

Unmodified code that says `import gfal2` works as it is: the wheel also
installs a `gfal2` module (reporting the bindings' version, 1.13.1, while
`get_version()` reports gfal2 2.23.5) and gfal2-util's `gfal2_util` package;
`xgfalclient.install_as_gfal2()` does the same for one process explicitly.
Because of that, don't install it into a Python environment that also has the
`python3-gfal2` RPM on its path - whichever comes first on `sys.path` wins.
Install it in a virtual environment. On EL9 a `pip install --user` (in
`~/.local`) or a root `pip install` (in `/usr/local`) comes before the RPMs
on `sys.path`, so it takes over every `import gfal2` and also the RPM's own
`/usr/bin/gfal-*`, which run the first `python` that can import `gfal2`.
EL9's pip also has a bug here: a root `pip uninstall xgfalclient` deletes
gfal2-util's `/usr/bin/gfal-*` scripts along with its own.

## Why

gfal2 is the data-management layer FTS, Rucio and DIRAC drive, but using it
from Python means a stack of compiled libraries - gfal2, davix, libXrdCl,
Globus, srm-ifce, gSOAP, CGSI - that must match the interpreter, the
distribution and each other. xgfalclient is the same API and the same
behaviour as one `pip install`, on any Python from 3.9 (what RHEL 9 and
AlmaLinux 9 ship) upwards.

## Install

```console
$ pip install xgfalclient              # everything but root://
$ pip install 'xgfalclient[xrootd]'    # root://, via xrdclient (itself pure Python)
```

## Protocols

As in gfal2, each protocol is a plugin, loaded the first time a URL needs it.

| Scheme | Plugin | Notes |
| --- | --- | --- |
| `http`, `https`, `dav`, `davs` | http | WebDAV, HTTP third-party copy (pull, push, streamed fallback), Link-discovered Metalink replica failover, gridsite delegation, WLCG tape REST API, SE-issued tokens, CDMI QoS |
| `s3`, `s3s` | http | AWS SigV4, multipart upload, pre-signed TPC |
| `gcloud`, `gclouds` | http | service-account V4 signed URLs, as davix does |
| `swift`, `swifts` | http | OpenStack Swift with a configured token (`[SWIFT]`), as davix does |
| `cs3`, `cs3s` | http | CS3 over HTTP with a bearer token |
| `root`, `roots`, `xroot`, `xroots` | xrootd | through xrdclient (pure Python); GSI, tokens, TPC, staging |
| `gsiftp`, `ftp` | gridftp | GSI control channel, MODE E parallel streams, DCAU, third-party copy |
| `srm` | srm | SRM v2.2 over httpg, TURL resolution to the other plugins, BDII endpoint discovery |
| `dcap`, `gsidcap`, `kdcap` | dcap | dCache's native protocol |
| `sftp` | sftp | over the system `ssh`, or a pure-Python SSH-2 transport |
| `lfc` | lfc | the LCG File Catalog (retired from gfal2, kept here) |
| `file` | file | the local filesystem, with gfal2's quirks |
| `mock` | mock | gfal2's test plugin: a storage element described by its URL |

`rfio://` is not supported; neither is it by gfal2 on EL9, which no longer
builds its RFIO plugin.

## Authentication

Everything gfal2 finds, found in the same order: `ctx.cred_set()` per URL
prefix, the `[X509]` and `[BEARER]` options, `X509_USER_PROXY`,
`/tmp/x509up_u<uid>`, `X509_USER_CERT`/`X509_USER_KEY`, `~/.globus`, and
WLCG bearer-token discovery (`BEARER_TOKEN`, `BEARER_TOKEN_FILE`,
`$XDG_RUNTIME_DIR/bt_u<uid>`, `/tmp/bt_u<uid>`). Trust anchors come from
`X509_CERT_DIR` or `/etc/grid-security/certificates`.

GSI is implemented in Python: the TLS handshake carried in GSSAPI tokens,
the delegation byte, and proxy delegation - signing an RFC 3820 proxy for a
server's certificate request - with DER, RSA and X.509 written from scratch.
TLS itself is the standard `ssl` module.

Kerberos (for `kdcap://` and friends) goes through the system
`libgssapi_krb5` via `ctypes`, or the `gssapi` package when installed.

`s3://` is signed with the `[S3]` (or per-host `[S3:<HOST>]`) keys, as davix
does, and `gcloud://` with the service-account JSON from `[GCLOUD]
JSON_AUTH_FILE` or `JSON_AUTH_STRING`.
`sftp://` uses the user's own SSH setup - keys, agent and `~/.ssh/config`
through the system `ssh`, or public keys and a password from the credential
store through the built-in SSH-2 client.

## Configuration

The stock gfal2 defaults are built in, and `$GFAL_CONFIG_DIR` (or an existing
`/etc/gfal2.d`) is layered on top, so a site's gfal2 tuning applies unchanged.
`get_opt_*`/`set_opt_*` behave as GLib key files do, error codes included.
Setting `[HTTP PLUGIN] METALINK=true` enables Davix-compatible recovery for
failed HTTP stats, reads, positioned reads and downloads. Discovery uses the
server's Metalink `Link` or content type, caches the catalogue, and only pays
that network cost after the original endpoint fails.

HTTP `GET`, `HEAD`, `OPTIONS` and `PROPFIND` operations retry connection
failures up to `[CORE] CONN_RETRY` times; streamed and positioned reads resume
from the last byte received, and uploads restart only where replay is safe.
When `CONN_RETRY_INTERVAL` is absent, retries use a 50 ms exponential backoff
capped at one second so a brief outage cannot consume the entire retry count
immediately. Setting the interval explicitly to `0` keeps fail-fast retry
timing. Timeouts and server refusals are not mistaken for broken links.

Completed copies to regular `file://` destinations issue one final durability
barrier before reporting success. Delayed `ENOSPC`/`EIO` from a FUSE cache,
network filesystem or failing disk therefore reaches the caller. The barrier
is outside the transfer loop, so it does not reduce streaming throughput. The
stable size must also match the transferred byte count, catching a cache that
acknowledges `fsync` without publishing its writeback journal.

Read-only local opens and reads recover from transient `EAGAIN`, `EBUSY`,
`EINTR`, `ESTALE`, and `ETIMEDOUT` using `[CORE] CONN_RETRY` and
`CONN_RETRY_INTERVAL`. Only a reader that actually faults downshifts to 4 KiB,
and it reopens only if device, inode, size, and nanosecond timestamps still
identify the same file generation. A replaced source therefore fails with
`ESTALE` instead of producing a mixed-generation copy.

## Command line

`gfal-copy`, `gfal-ls`, `gfal-stat`, `gfal-mkdir`, `gfal-rm`, `gfal-rename`,
`gfal-sum`, `gfal-cat`, `gfal-save`, `gfal-chmod`, `gfal-xattr`,
`gfal-bringonline`, `gfal-archivepoll`, `gfal-evict` and `gfal-token`, with
gfal2-util 1.9.1's options, output and exit codes; the deprecated
`gfal-legacy-register`, `gfal-legacy-unregister`, `gfal-legacy-replicas` (LFC
replicas) and `gfal-legacy-bringonline`; `gfal2_version` and
`gfal_srm_ifce_version`; man pages for all of them; and
`python -m xgfalclient.cli <command>`.

gfal2-util's Python package is there too, for wrappers that run or extend the
commands in-process: `from gfal2_util.shell import Gfal2Shell`, or a
`gfal2_util.base.CommandBase` subclass with `@base.arg`-decorated
`execute_<name>` methods.

## Where it differs from gfal2

Deliberately, and only where gfal2's behaviour is a bug:

* a copy onto itself with `overwrite` set is refused (`EINVAL`); gfal2
  deletes the source;
* a failed copy cleans up its destination whenever `transfer_cleanup` is set,
  including after a destination checksum mismatch;
* a third-party copy is checked even when no checksum was asked for: the two
  servers' checksums are compared afterwards (`[CORE] VERIFY_THIRD_PARTY`,
  on by default), because a destination can report a pull finished that
  never happened - RAL's Echo did, leaving a full-size file of no data -
  and gfal2 then reports success;
* `TransferParameters.timeout = 0` means no limit; gfal2's local copy
  expires at once;
* error codes are the intended ones where gfal2 reports a stale `errno` or
  a raw protocol status (details in each plugin's module docstring);
* `sftp://` checks host keys (accept-new by default; gfal2 checks none) and
  never passes a password to an `ssh` subprocess.
* a `$X509_USER_PROXY` naming a file that is not there is passed over, so
  token-only access still works, and nothing else is presented in its place:
  not `/tmp/x509up_u<uid>`, which in a pilot job is the pilot's identity
  rather than the payload's. gfal2 presents the missing file and fails.

## Performance

Head to head against gfal2 2.23.5's own Python bindings, same machine, same
servers, 512 MiB transfers (medians; details and method in
[docs/performance.md](docs/performance.md)):

| | download | upload | stat | listdir |
| --- | --- | --- | --- | --- |
| `davs://` | **1.39×** | **1.29×** | **5.6×** | **2.4×** |
| `root://` | **5.1×** | **1.39×** | **1.39×** | **1.32×** |
| `gsiftp://` | **1.46×** | **1.21×** | **2.0×** | **1.84×** |
| `gsidcap://` | **1.54×** | **1.34×** | **14×** | |
| `sftp://` | **1.19-1.37×** | gfal2 truncates | | |

Where it is not ahead: the first `root://` operation in a process pays
about 90 ms to import xrdclient (gfal2 pays its plugin loading inside
`creat_context`). gfal2's sftp upload has no number because it silently
truncates the file; ours writes every byte.

## Development

```console
$ python -m venv .venv && .venv/bin/pip install -e '.[dev,xrootd]'
$ .venv/bin/pytest -n auto --cov          # 100% line and branch coverage, enforced
$ XGFAL_CONDCOV=1 .venv/bin/pytest -n auto # every and/or, ternary and filter both ways
$ .venv/bin/ruff check src tests && .venv/bin/mypy
```

Tests are hermetic: every protocol has an in-process server in
`xgfalclient.testing`, and a throwaway grid PKI (`xgfalclient.testing.pki`)
mints CAs, host certificates and proxies at run time. Tests against real
servers in Docker are marked `interop` and run with `XGFAL_INTEROP=1`. See
[the documentation](docs/index.md), [developer guide](docs/DEVELOPING.md),
[security policy](SECURITY.md), [contribution guide](CONTRIBUTING.md) and
[0.2.0 release notes](CHANGELOG.md).

## Licence

LGPL-3.0-or-later.
